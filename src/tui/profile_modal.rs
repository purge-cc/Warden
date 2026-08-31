//! §4.26 Phase 2 — Profiles tab modals (Add / Edit / Delete).
//!
//! Opens over [`crate::tui::app::Leaf::Profiles`] via `a` (Add), `e`
//! (Edit), `d` / Delete (Remove). Submits through the **Phase 1 IPC
//! verbs** — `ProfileCreate` / `ProfileUpdate` / `ProfileDelete` — driven
//! from `tui/mod.rs::submit_profile_modal` via `IpcPoller::send_profile_*`.
//! Unlike the Subnets modal (which writes via CLI `*_inner` helpers and
//! then calls `attempt_reload`), the profile IPC handlers self-reload the
//! daemon (`notify_reload`), so the submit path only refreshes the TUI's
//! offline `loaded_config` cache.
//!
//! ## State machines
//!
//! Add / Edit (one `ProfileForm`, `mode` discriminates):
//! ```text
//! EditingForm(ProfileForm) ──Enter on Submit──▶ Submitted(Ok | Failed)
//!                          ──Esc──▶ closed
//! ```
//!
//! Remove:
//! ```text
//! ConfirmingRemove(RemoveConfirm) ──[y]──▶ Submitted(Ok | Failed)
//!                                 ──[n / Esc]──▶ closed
//! ```
//!
//! ## Capture-at-open invariant
//!
//! `e` / `d` snapshot the focused profile's full v1 field set into the
//! modal at open time ([`OriginalSnapshot`] / [`RemoveConfirm`]).
//! Subsequent renders / refreshes / scrolls cannot invalidate the
//! snapshot; the submit path always diffs against the captured values,
//! never re-reads `loaded_config`. Mirrors the `subnet_modal` precedent.
//!
//! ## Edit form → `ProfileUpdatePatch`
//!
//! The Edit form is a flat 6-mutate-field surface (D4). [`resolve_edit_patch`]
//! is a **pure** function: it diffs the form against [`OriginalSnapshot`]
//! and emits ONE atomic `ProfileUpdatePatch` carrying only the changed
//! fields. Nullable enum fields (`block_response`, `ecs.mode`) get a
//! synthetic `(inherit)` dropdown option = clear-to-inherit; nullable
//! scalars (`blocked_ttl_secs`, ecs prefixes) use an empty text field as
//! the inherit signal.
//!
//! ## Known limitation (D1, deferred — TODO `s-4.26-p2-disc-1`)
//!
//! `EcsPatch`'s `mode` / `source_prefix_*` fields are single-`Option`, so
//! an individual ecs sub-field cannot be cleared back to inherit while the
//! subtree survives — only the whole `ecs` subtree can be cleared (the
//! `clear ecs` toggle). [`resolve_edit_patch`] detects an attempted
//! per-field clear (`Some` → `None` on an existing subtree) and returns a
//! friendly error pointing at the toggle, rather than silently dropping
//! the operator's intent.

use std::collections::BTreeMap;

use crate::config::schema::blocklist::{effective_direction, Blocklist, ListPolicy};
use crate::config::schema::{BlockResponseV1, Id, Profile, ProfileEcsConfig};
use crate::config::settings::EcsMode;
use crate::ipc::protocol::{AdminRulesPatch, EcsPatch, ListPolicyPatch, ProfileUpdatePatch};

/// Synthetic `(inherit)` option at index 0 + the four `BlockResponseV1`
/// variants. Frozen by `tests/frozen_strings_s49_profile_editor_tui.rs`.
pub const BLOCK_RESPONSE_OPTIONS: [&str; 5] =
    ["(inherit)", "zero", "nxdomain", "refused", "soa_nodata"];

/// Synthetic `(inherit)` option at index 0 + the three `EcsMode` variants.
/// Frozen by `tests/frozen_strings_s49_profile_editor_tui.rs`.
pub const ECS_MODE_OPTIONS: [&str; 4] = ["(inherit)", "off", "coarse", "subnet"];

/// The three states the arrow keys walk on a per-list override row, in
/// order. `None` is "declare nothing, inherit this list's own `base`" and
/// is what [`ListPolicyPatch::clear`] carries.
///
/// [`ListPolicy::Ignore`] is deliberately **absent**. It is a fourth
/// reachable state, declared with `i` and a confirm — see
/// [`ProfileForm::press_ignore`] — because arriving at it by brushing an
/// arrow key would make a list inert for this profile with no gate at any
/// layer to notice, which is the silent-unfiltering shape of the
/// 2026-05-07 incident P6 names. `Allow` stays in the cycle: the daemon
/// refuses an unconsented one and says so, and a declared exemption scoped
/// to one profile is the *narrow* form `profile_list_policy.md` §2.5
/// wanted and could not express.
const POLICY_CYCLE: [Option<ListPolicy>; 3] =
    [None, Some(ListPolicy::Deny), Some(ListPolicy::Allow)];

/// The word a per-list override row shows for each direction.
///
/// Deliberately the **same three words** the Lists modal's `nature` row
/// uses (`tui::tabs::lists::edit_form_body`), because they name the same
/// three states one radius apart: `base` is what every profile inherits,
/// this is what one profile declares. An operator who has learned "Block /
/// Allow / Ignore" on one surface must not have to relearn it on the other.
/// Frozen by `tests/frozen_strings_s49_profile_editor_tui.rs`.
pub const LIST_POLICY_BLOCK: &str = "Block";
/// The allow half of [`LIST_POLICY_BLOCK`].
pub const LIST_POLICY_ALLOW: &str = "Allow";
/// The inert half of [`LIST_POLICY_BLOCK`].
pub const LIST_POLICY_IGNORE: &str = "Ignore";

/// Appended to a row whose direction comes from the list's own `base`
/// rather than from an override this profile declares.
///
/// **The unmarked form is the declared one, and that is the right way
/// round.** A declaration is the plain statement; inheritance is the
/// qualified one. The distinction is carried in *text* rather than in
/// colour because colour on a value row states what the value **is**
/// (`modal_form::ValueKind`), and an inherited deny is every bit as much a
/// deny as a declared one — they differ in provenance, not in effect. The
/// effect is what the resolver acts on; the provenance is what survives a
/// change to the list's `base`, and only the operator can act on that.
pub const LIST_POLICY_INHERITED: &str = " (inherited)";

/// Shown in place of the panel when the config declares no
/// `[[blocklists]]` at all — a fresh install before the first
/// `warden blocklist add`.
pub const LIST_PANEL_EMPTY: &str = "add one on the Lists tab";

/// The resting hint under a focused per-list override row.
///
/// Names `[i]` **and** that it takes two presses, because a key legend
/// that advertises one keystroke for a two-keystroke valve teaches the
/// operator that the first press did nothing.
pub const LIST_OVERRIDE_HINT: &str =
    "\u{2190}/\u{2192} Block \u{b7} Allow \u{b7} inherit \u{2014} \
     [i] twice makes this list inert for this profile";

/// Shown while the `ignore` valve is armed on the focused row.
///
/// States the **consequence** ("filters nothing here"), not the mechanic
/// ("sets ignore"): the operator is being asked to authorise an outcome,
/// and the word `ignore` is exactly the one that makes an outcome sound
/// procedural. Also names the way out, so an accidental first press is
/// visibly recoverable rather than something to guess at.
pub const LIST_OVERRIDE_IGNORE_ARMED: &str =
    "\u{26a0} press [i] again and '{id}' filters nothing in this profile \u{2014} an arrow cancels";

/// Shown on a row whose pending policy is `allow` on a remote, unsigned
/// list whose own `[[blocklists]]` row has not declared the consent.
///
/// **It names the CLI verb and not the Lists tab, and that is a measured
/// choice rather than a preference for the terminal.** The TUI's Lists
/// modal can only declare `accept_unsigned_allow` on the way to making the
/// list `base = allow` for *every* profile — `allow_gate_for_modal`
/// (`tui/mod.rs`) returns `Proceed` without consulting the gate whenever
/// `nature != Allow`, and `[K]`'s gate is behind `target == Allow`. So for
/// the common case this panel creates — an `allow` override on a list that
/// stays `base = deny` globally — sending the operator to the Lists tab
/// would send them somewhere that cannot do it, which is the unsatisfiable
/// refusal project rules §Neutrality records this repo already paying for once.
///
/// `run_set_trust` writes the declaration whenever the flag is passed,
/// whatever the list's `base` (`cli/commands/blocklists.rs`), so re-setting
/// an already-`remote-unsigned` list to `remote-unsigned` with the flag is
/// a no-op move that lands the consent. Verified against the compiled clap
/// tree, not against the docs.
///
/// The command is on its own logical line so `hint_or_error_rows` wraps it
/// as a unit instead of folding it into the prose above.
pub const LIST_OVERRIDE_NEEDS_CONSENT: &str =
    "an allow override needs consent on the list's own row:\n  \
     warden blocklist set-trust {id} remote-unsigned --accept-unsigned-allow";

/// Top-level modal lifecycle. `None` on `app.profiles.modal` means no
/// modal is open; a `Some` variant grabs every keystroke until submit
/// lands a [`Stage::Submitted`] outcome or the operator presses Esc.
#[derive(Debug, Clone)]
pub struct ProfileModal {
    pub stage: Stage,
}

// `EditingForm` carries the full `ProfileForm` (~10 String buffers + the
// `OriginalSnapshot`); `ConfirmingRemove` / `Submitted` are small.
// Boxing the large variant to equalize sizes would add a heap alloc +
// deref per keystroke for no measurable benefit — the modal is
// constructed once per operator action, never on a hot path. Mirrors
// the `DeviceModal` precedent in `app.rs`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    /// Add or Edit form. `ProfileForm::mode` selects the title bar, the
    /// visible field set, and the submit dispatch path.
    EditingForm(ProfileForm),
    /// Remove confirmation. Single-key y/n — profile deletes are
    /// backstopped by the daemon validator (refuses if a device / group /
    /// subnet / schedule still references the id), so no typed-phrase
    /// tier is needed here.
    ConfirmingRemove(RemoveConfirm),
    /// Final state — renders the success / error message, closes on the
    /// next keypress.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

/// Form mode discriminator — drives the title bar, the visible field
/// set, and the submit dispatch (`ProfileCreate` vs `ProfileUpdate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit,
}

/// Every field the form can focus, in canonical tab order. Add mode
/// shows only `Id` / `DisplayName` / `Submit`; Edit mode shows the 6
/// MUTATE fields (D4) — `ecs` expands to three rows + a clear toggle —
/// plus `Submit`, and skips `Id` (a profile's id is immutable after
/// creation). [`ProfileForm::visible_fields`] returns the mode-specific
/// slice; `focus_next` / `focus_prev` cycle within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Id,
    DisplayName,
    BlockResponse,
    BlockedTtl,
    BlockAll,
    AdminRules,
    EcsMode,
    EcsPrefixV4,
    EcsPrefixV6,
    EcsClear,
    /// One row of the per-list override panel — the index into
    /// [`ProfileForm::lists_snapshot`], which is the `[[blocklists]]`
    /// vector captured at modal-open time.
    ///
    /// **This replaced `FormField::Tags`, and the replacement is the whole
    /// point of the sprint.** The chip picker that used to sit here read
    /// `profile.tags`, a field that decided which lists a profile enforced
    /// under the tag model and decides nothing after the plp cutover
    /// (`_docs/features/profile_list_policy.md` §2). It rendered inert
    /// history wearing a control's clothes: the operator could edit it and
    /// the submit path refused the change.
    ///
    /// **Why one focus target per list rather than one for the panel.**
    /// A single target holding N rows would have to window them itself,
    /// and this modal's field viewport is **2 rows** at the 80×24 floor
    /// (see the D18 budget note in [`form_body`]) — so the panel would be
    /// clipped and the clipping would be this modal's to implement. As
    /// separate fields, `render_scroll_body` already anchors the focused
    /// row at the bottom of the window and scrolls the rest, which is the
    /// behaviour every other field on this form gets for free.
    ///
    /// The cost is that [`ProfileForm::visible_fields`] can no longer be a
    /// `&'static [FormField]` — the ring's length is the operator's list
    /// count. It returns an owned `Vec`; this is a modal, not the query
    /// path.
    ListOverride(usize),
    Submit,
    /// The Discard button — last in tab order, mirrors `subnet_modal`.
    /// Enter / Space on it closes the modal without saving (same as Esc).
    Cancel,
}

impl FormField {
    const ADD_FIELDS: [FormField; 4] = [
        FormField::Id,
        FormField::DisplayName,
        FormField::Submit,
        FormField::Cancel,
    ];
    /// Edit-mode fields ahead of the per-list override panel.
    ///
    /// Split from the tail because the panel between them is
    /// operator-sized: [`ProfileForm::visible_fields`] splices
    /// `ListOverride(0..n)` in here, where `n` is the number of
    /// `[[blocklists]]` the config carries. A single const array cannot
    /// express that, and the alternative — a fixed maximum — would either
    /// waste ring slots on lists that do not exist or silently drop the
    /// ones past the cap.
    const EDIT_HEAD: [FormField; 9] = [
        FormField::DisplayName,
        FormField::BlockResponse,
        FormField::BlockedTtl,
        FormField::BlockAll,
        FormField::AdminRules,
        FormField::EcsMode,
        FormField::EcsPrefixV4,
        FormField::EcsPrefixV6,
        FormField::EcsClear,
    ];
    /// Edit-mode fields after the panel. Always reachable, however many
    /// lists sit above them — `Ctrl+S` (N14) also saves from anywhere, so
    /// a 64-list config never forces the operator to tab the whole panel
    /// to reach `Save`.
    const EDIT_TAIL: [FormField; 2] = [FormField::Submit, FormField::Cancel];
}

/// Add / Edit form state. Text fields are plain `String` buffers (free
/// typing, validated at submit); dropdowns are `usize` indices into the
/// `*_OPTIONS` consts; toggles are `bool`.
#[derive(Debug, Clone)]
pub struct ProfileForm {
    pub mode: FormMode,
    /// Snapshot of the original profile at modal-open time. `Some` on
    /// Edit (the submit path diffs against it), `None` on Add.
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    /// Profile id. Editable only in Add mode (immutable after creation).
    pub id: String,
    pub display_name: String,
    /// Index into [`BLOCK_RESPONSE_OPTIONS`]. 0 = `(inherit)`.
    pub block_response_idx: usize,
    /// Raw operator input. Empty = inherit from `[server]` defaults.
    pub blocked_ttl_input: String,
    pub block_all: bool,
    /// Comma-separated admin-rule ids as the operator typed them.
    /// Diffed against `original.admin_rules` at submit to build the
    /// `AdminRulesPatch` add/remove delta.
    pub admin_rules_input: String,
    /// Index into [`ECS_MODE_OPTIONS`]. 0 = `(inherit)`.
    pub ecs_mode_idx: usize,
    /// Raw operator input. Empty = inherit `[upstream.ecs]`.
    pub ecs_v4_input: String,
    pub ecs_v6_input: String,
    /// When `true`, the whole `ecs` subtree is reset to inherit
    /// (`EcsPatch.clear`) and the three ecs sub-rows above are ignored.
    pub ecs_clear: bool,
    /// The `[[blocklists]]` the config carries, captured at modal-open
    /// time and ordered by id.
    ///
    /// Snapshotted for the same reason `subnet_modal` snapshots its
    /// profiles: the running config can be reloaded under the modal's
    /// lifetime, and a panel whose rows re-ordered themselves mid-edit
    /// would move the operator's cursor onto a different list than the one
    /// they were looking at. Empty and unused in Add mode — `ProfileCreate`
    /// carries no list policy.
    ///
    /// Whole [`Blocklist`] values rather than a projection because
    /// [`effective_direction`] takes one, and this panel must **ask** that
    /// function rather than re-derive its answer: two copies that disagree
    /// is the D11 class that cost `tag_model_consolidation` a false
    /// negative on a security warning.
    pub lists_snapshot: Vec<Blocklist>,
    /// The draft of `profiles.<id>.lists` this form is editing. Seeded
    /// from the profile's existing overrides in [`Self::new_edit`].
    ///
    /// **It must be seeded, and the sibling precedent points the other
    /// way.** `EditListModal::consent_declared` is deliberately *not*
    /// seeded from its `original`, because a consent the operator did not
    /// type this session must never be fabricated. This field is the
    /// opposite: it is not a declaration being made, it is the operator's
    /// existing declarations being shown back to them. Seeded empty, the
    /// diff in [`resolve_edit_patch`] would read every existing key as
    /// removed and a save that changed the display name would wipe every
    /// override the profile had.
    pub lists_draft: BTreeMap<Id, ListPolicy>,
    /// The [`ListPolicy::Ignore`] valve — the panel row index whose
    /// declaration is armed and awaiting its second `i`.
    ///
    /// `ignore` is reachable from the TUI (it is a state the CLI accepts,
    /// and a state only reachable from one surface recreates the split
    /// this workstream exists to close) but never from a bare arrow:
    /// making a list inert is silent unfiltering, the shape of the
    /// 2026-05-07 incident P6 names. Same two-press register the tag
    /// picker used for `tags_pending_new`, so the idiom is one the
    /// operator has already met on this form.
    pub ignore_armed: Option<usize>,
    /// Inline validation / submit error rendered at the bottom of the
    /// form. Cleared on the next field edit.
    pub error_message: Option<String>,
}

/// Original profile snapshot captured when an Edit modal opens. Holds
/// every MUTATE field so [`resolve_edit_patch`] can diff against it.
#[derive(Debug, Clone)]
pub struct OriginalSnapshot {
    pub id: String,
    pub display_name: String,
    pub block_response: Option<BlockResponseV1>,
    pub blocked_ttl_secs: Option<u32>,
    pub block_all: bool,
    /// Admin-rule ids as plain strings (the `Profile.admin_rules: Vec<Id>`
    /// field, each `Id::as_str().to_string()`).
    pub admin_rules: Vec<String>,
    pub ecs: Option<ProfileEcsConfig>,
    /// `profiles.<id>.lists` as the file had it at open time. Diffed
    /// against [`ProfileForm::lists_draft`] to build the
    /// [`ListPolicyPatch`] map delta.
    pub lists: BTreeMap<Id, ListPolicy>,
}

/// Remove-confirm state. `reference_summary` is informational only — a
/// client-side count computed at open time so the operator sees the
/// blast radius before confirming. The daemon validator is still the
/// authority that *blocks* a delete of a referenced profile.
#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub id: String,
    pub display_name: String,
    pub reference_summary: String,
}

/// Map a `block_response` snapshot value to its dropdown index.
fn block_response_idx_for(v: Option<BlockResponseV1>) -> usize {
    match v {
        None => 0,
        Some(BlockResponseV1::Zero) => 1,
        Some(BlockResponseV1::Nxdomain) => 2,
        Some(BlockResponseV1::Refused) => 3,
        Some(BlockResponseV1::SoaNodata) => 4,
    }
}

/// Map an `ecs.mode` snapshot value to its dropdown index.
fn ecs_mode_idx_for(v: Option<EcsMode>) -> usize {
    match v {
        None => 0,
        Some(EcsMode::Off) => 1,
        Some(EcsMode::Coarse) => 2,
        Some(EcsMode::Subnet) => 3,
    }
}

/// Parse a nullable `u8` prefix field. Empty → `Ok(None)` (inherit);
/// otherwise parse and range-check against `max` (32 for v4, 128 for v6).
fn parse_opt_u8(input: &str, max: u8, label: &str) -> Result<Option<u8>, String> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let n: u8 = t
        .parse()
        .map_err(|_| format!("{label} must be an integer 0..={max}, got '{t}'"))?;
    if n > max {
        return Err(format!("{label} must be 0..={max}, got {n}"));
    }
    Ok(Some(n))
}

impl ProfileForm {
    /// Empty form for `Add`. Focus starts on `Id` so the operator can
    /// type immediately.
    pub fn new_add() -> Self {
        Self {
            mode: FormMode::Add,
            original: None,
            focused: FormField::Id,
            id: String::new(),
            display_name: String::new(),
            block_response_idx: 0,
            blocked_ttl_input: String::new(),
            block_all: false,
            admin_rules_input: String::new(),
            ecs_mode_idx: 0,
            ecs_v4_input: String::new(),
            ecs_v6_input: String::new(),
            ecs_clear: false,
            lists_snapshot: Vec::new(),
            lists_draft: BTreeMap::new(),
            ignore_armed: None,
            error_message: None,
        }
    }

    /// Pre-filled form for `Edit`, capturing the original snapshot. The
    /// `id` is carried for display but is not editable. `lists_snapshot`
    /// is the `[[blocklists]]` vector the override panel reads (see the
    /// field doc on `Self::lists_snapshot`); the caller sorts it by id so
    /// the panel's row order is stable across reloads.
    pub fn new_edit(id: &str, profile: &Profile, lists_snapshot: Vec<Blocklist>) -> Self {
        let snapshot = OriginalSnapshot {
            id: id.to_string(),
            display_name: profile.display_name.clone(),
            block_response: profile.block_response,
            blocked_ttl_secs: profile.blocked_ttl_secs,
            block_all: profile.block_all,
            admin_rules: profile
                .admin_rules
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            ecs: profile.ecs.clone(),
            lists: profile.lists.clone(),
        };
        let ecs = profile.ecs.clone().unwrap_or_default();
        Self {
            mode: FormMode::Edit,
            focused: FormField::DisplayName, // id is not editable
            id: id.to_string(),
            display_name: profile.display_name.clone(),
            block_response_idx: block_response_idx_for(profile.block_response),
            blocked_ttl_input: profile
                .blocked_ttl_secs
                .map(|n| n.to_string())
                .unwrap_or_default(),
            block_all: profile.block_all,
            admin_rules_input: snapshot.admin_rules.join(", "),
            ecs_mode_idx: ecs_mode_idx_for(ecs.mode),
            ecs_v4_input: ecs
                .source_prefix_v4
                .map(|n| n.to_string())
                .unwrap_or_default(),
            ecs_v6_input: ecs
                .source_prefix_v6
                .map(|n| n.to_string())
                .unwrap_or_default(),
            ecs_clear: false,
            lists_draft: profile.lists.clone(),
            lists_snapshot,
            ignore_armed: None,
            error_message: None,
            original: Some(snapshot),
        }
    }

    /// The mode-specific ordered field ring for focus navigation.
    ///
    /// Owned rather than `&'static [FormField]`: in Edit mode the ring
    /// splices one [`FormField::ListOverride`] per configured blocklist
    /// between [`FormField::EDIT_HEAD`] and [`FormField::EDIT_TAIL`], and
    /// that count is the operator's. A config with **zero**
    /// `[[blocklists]]` yields head + tail with no panel rows, which the
    /// ring handles without a special case — nothing indexes
    /// `lists_snapshot` here.
    pub fn visible_fields(&self) -> Vec<FormField> {
        match self.mode {
            FormMode::Add => FormField::ADD_FIELDS.to_vec(),
            FormMode::Edit => FormField::EDIT_HEAD
                .iter()
                .copied()
                .chain((0..self.lists_snapshot.len()).map(FormField::ListOverride))
                .chain(FormField::EDIT_TAIL.iter().copied())
                .collect(),
        }
    }

    /// Move focus forward by one visible field, wrapping at the end.
    pub fn focus_next(&mut self) {
        let fields = self.visible_fields();
        let cur = fields.iter().position(|f| *f == self.focused).unwrap_or(0);
        self.focused = fields[(cur + 1) % fields.len()];
    }

    /// Move focus backward by one visible field, wrapping at the start.
    pub fn focus_prev(&mut self) {
        let fields = self.visible_fields();
        let cur = fields.iter().position(|f| *f == self.focused).unwrap_or(0);
        self.focused = fields[(cur + fields.len() - 1) % fields.len()];
    }

    /// Mutable reference to the buffer behind the focused text field.
    /// `None` for non-text fields (dropdowns, toggles, Submit, and `Id`
    /// when the form is in Edit mode).
    pub fn text_field_buf(&mut self) -> Option<&mut String> {
        // Exhaustive by name, no `_` arm — the repo's own convention where
        // a new variant must be *decided* rather than absorbed
        // (`KIND_TOGGLE_OK_IGNORE` states it for the direction vocabulary).
        // `FormField::ListOverride` reaching a `_ => None` here would look
        // right and read the operator's keystrokes into nothing.
        match self.focused {
            FormField::Id => (self.mode == FormMode::Add).then_some(&mut self.id),
            FormField::DisplayName => Some(&mut self.display_name),
            FormField::BlockedTtl => Some(&mut self.blocked_ttl_input),
            FormField::AdminRules => Some(&mut self.admin_rules_input),
            FormField::EcsPrefixV4 => Some(&mut self.ecs_v4_input),
            FormField::EcsPrefixV6 => Some(&mut self.ecs_v6_input),
            FormField::BlockResponse
            | FormField::BlockAll
            | FormField::EcsMode
            | FormField::EcsClear
            | FormField::ListOverride(_)
            | FormField::Submit
            | FormField::Cancel => None,
        }
    }

    /// Cycle the focused dropdown field. `forward` = `→`, else `←`.
    /// No-op when the focused field is not a dropdown.
    pub fn cycle_dropdown(&mut self, forward: bool) {
        // Exhaustive for the reason spelled out on `text_field_buf`. A `_`
        // arm here is the more dangerous of the two: the `KeyCode::Right`
        // dispatch in `tui/mod.rs` falls through to this function for every
        // field it does not name, so a panel row absorbed by a catch-all
        // would silently cycle whichever dropdown happens to be listed —
        // an edit to a field the operator is not looking at.
        let (idx, len) = match self.focused {
            FormField::BlockResponse => {
                (&mut self.block_response_idx, BLOCK_RESPONSE_OPTIONS.len())
            }
            FormField::EcsMode => (&mut self.ecs_mode_idx, ECS_MODE_OPTIONS.len()),
            FormField::Id
            | FormField::DisplayName
            | FormField::BlockedTtl
            | FormField::BlockAll
            | FormField::AdminRules
            | FormField::EcsPrefixV4
            | FormField::EcsPrefixV6
            | FormField::EcsClear
            | FormField::ListOverride(_)
            | FormField::Submit
            | FormField::Cancel => return,
        };
        *idx = if forward {
            (*idx + 1) % len
        } else {
            (*idx + len - 1) % len
        };
    }

    /// Flip the focused toggle field (`block_all` or `ecs_clear`).
    /// No-op when the focused field is not a toggle.
    pub fn toggle(&mut self) {
        // Exhaustive for the reason spelled out on `text_field_buf`.
        match self.focused {
            FormField::BlockAll => self.block_all = !self.block_all,
            FormField::EcsClear => self.ecs_clear = !self.ecs_clear,
            FormField::Id
            | FormField::DisplayName
            | FormField::BlockResponse
            | FormField::BlockedTtl
            | FormField::AdminRules
            | FormField::EcsMode
            | FormField::EcsPrefixV4
            | FormField::EcsPrefixV6
            | FormField::ListOverride(_)
            | FormField::Submit
            | FormField::Cancel => {}
        }
    }

    /// The panel row index the focus is on, if any.
    pub fn focused_list_row(&self) -> Option<usize> {
        match self.focused {
            FormField::ListOverride(i) if i < self.lists_snapshot.len() => Some(i),
            _ => None,
        }
    }

    /// A throwaway [`Profile`] carrying the draft override map and nothing
    /// else, so the panel can ask [`effective_direction`] its question
    /// instead of answering it.
    ///
    /// [`effective_direction`] reads exactly one field, so every other
    /// value here is inert — and routing through it is the point. The
    /// arithmetic is two lines long and utterly tempting to inline, which
    /// is precisely how `tag_model_consolidation` ended up with
    /// `effective_tags` computed in two places that answered differently
    /// (D11): the validator saw a superset and went silent about devices
    /// the resolver really did leave uncovered.
    fn draft_profile(&self) -> Profile {
        Profile {
            lists: self.lists_draft.clone(),
            ..Default::default()
        }
    }

    /// What this profile does with `list` under the current draft.
    pub fn effective_for(&self, list: &Blocklist) -> ListPolicy {
        effective_direction(&self.draft_profile(), list)
    }

    /// The override this profile *declares* for `list`, or `None` when it
    /// inherits the list's own `base`.
    ///
    /// Not a second answer to [`Self::effective_for`]'s question — a
    /// different question that function deliberately does not expose. An
    /// inherited `deny` and a declared `deny` are the same **effect** and
    /// two different **intentions**: the declared one survives a change to
    /// the list's `base`, the inherited one does not. A panel that flattens
    /// them hides exactly what the operator wrote down.
    ///
    /// Pinned against its sibling by
    /// `a_declared_policy_is_always_the_effective_one`, so the two can
    /// never drift into disagreeing.
    pub fn declared_for(&self, list: &Blocklist) -> Option<ListPolicy> {
        self.lists_draft.get(&list.id).copied()
    }

    /// Step the focused panel row through [`POLICY_CYCLE`].
    /// `forward` = the right arrow.
    ///
    /// From [`ListPolicy::Ignore`] both arrows land on `Deny`, matching the
    /// Lists modal's `nature` row, whose hint already tells the operator
    /// that from `Ignore` the row "is not a choice between the two words it
    /// names — it is a one-way door out". Leaving `Ignore` is the direction
    /// that restores filtering, so it costs nothing.
    pub fn cycle_list_policy(&mut self, forward: bool) {
        let Some(i) = self.focused_list_row() else {
            return;
        };
        // Arming is per-row and per-decision: an arrow is a different
        // decision, so it spends the valve rather than leaving it live
        // under a value the operator has since changed.
        self.ignore_armed = None;
        let id = self.lists_snapshot[i].id.clone();
        let current = self.lists_draft.get(&id).copied();
        let next = if current == Some(ListPolicy::Ignore) {
            Some(ListPolicy::Deny)
        } else {
            let cur = POLICY_CYCLE.iter().position(|p| *p == current).unwrap_or(0);
            let n = POLICY_CYCLE.len();
            POLICY_CYCLE[if forward {
                (cur + 1) % n
            } else {
                (cur + n - 1) % n
            }]
        };
        match next {
            Some(p) => {
                self.lists_draft.insert(id, p);
            }
            None => {
                self.lists_draft.remove(&id);
            }
        }
    }

    /// `i` on a panel row: the first press arms the declaration, the
    /// second writes [`ListPolicy::Ignore`] into the draft.
    ///
    /// Returns `true` when the declaration landed, so the caller can tell
    /// an arming apart from a commit without re-reading the valve.
    ///
    /// Two presses rather than one because the decision is not symmetric
    /// with the others on this row. A `deny` or an `allow` override is a
    /// filtering *choice* the daemon sees, gates where it must, and logs;
    /// `ignore` is this profile silently ceasing to apply the list, with
    /// nothing at any layer to notice. The deliberation has to live here
    /// because here is the only place it can.
    pub fn press_ignore(&mut self) -> bool {
        let Some(i) = self.focused_list_row() else {
            return false;
        };
        if self.ignore_armed == Some(i) {
            let id = self.lists_snapshot[i].id.clone();
            self.lists_draft.insert(id, ListPolicy::Ignore);
            self.ignore_armed = None;
            true
        } else {
            self.ignore_armed = Some(i);
            false
        }
    }

    /// Selected `block_response` value — `None` = `(inherit)`.
    pub fn block_response_selection(&self) -> Option<BlockResponseV1> {
        match self.block_response_idx {
            1 => Some(BlockResponseV1::Zero),
            2 => Some(BlockResponseV1::Nxdomain),
            3 => Some(BlockResponseV1::Refused),
            4 => Some(BlockResponseV1::SoaNodata),
            _ => None,
        }
    }

    /// Selected `ecs.mode` value — `None` = `(inherit)`.
    pub fn ecs_mode_selection(&self) -> Option<EcsMode> {
        match self.ecs_mode_idx {
            1 => Some(EcsMode::Off),
            2 => Some(EcsMode::Coarse),
            3 => Some(EcsMode::Subnet),
            _ => None,
        }
    }

    /// Resolve an `Add` form into `(id, display_name)`. `id` is required;
    /// an empty `display_name` defaults to the id (mirrors `subnet_modal`).
    pub fn try_resolve_add(&self) -> Result<(String, String), String> {
        let id = self.id.trim();
        if id.is_empty() {
            return Err("id is required".into());
        }
        let display = self.display_name.trim();
        let display_name = if display.is_empty() {
            id.to_string()
        } else {
            display.to_string()
        };
        Ok((id.to_string(), display_name))
    }
}

/// Diff an `Edit` form against its captured [`OriginalSnapshot`] and emit
/// ONE atomic [`ProfileUpdatePatch`] carrying only the changed fields.
///
/// Pure — no I/O, no `loaded_config` reads. An all-`None` result means
/// "nothing changed"; the caller short-circuits with an "unchanged"
/// outcome instead of a no-op IPC round-trip.
///
/// Returns `Err` on a parse failure (bad ttl / ecs prefix) or on an
/// attempted per-field ecs clear-to-inherit (the D1 limitation — the
/// operator is told to use the whole-subtree `clear ecs` toggle instead).
pub fn resolve_edit_patch(
    form: &ProfileForm,
    orig: &OriginalSnapshot,
) -> Result<ProfileUpdatePatch, String> {
    let mut patch = ProfileUpdatePatch::default();

    // display_name — plain Option<String>, set only if changed.
    let dn = form.display_name.trim();
    if dn != orig.display_name {
        patch.display_name = Some(dn.to_string());
    }

    // block_response — Option<Option<BlockResponseV1>>. Dropdown idx 0 =
    // (inherit) → Some(None); idx 1..=4 → Some(Some(variant)).
    let br_now = form.block_response_selection();
    if br_now != orig.block_response {
        patch.block_response = Some(br_now);
    }

    // blocked_ttl_secs — Option<Option<u32>>. Empty input = inherit.
    let ttl_now: Option<u32> =
        match form.blocked_ttl_input.trim() {
            "" => None,
            s => Some(s.parse().map_err(|_| {
                format!("blocked_ttl_secs must be a non-negative integer, got '{s}'")
            })?),
        };
    if ttl_now != orig.blocked_ttl_secs {
        patch.blocked_ttl_secs = Some(ttl_now);
    }

    // block_all — Option<bool>, non-nullable.
    if form.block_all != orig.block_all {
        patch.block_all = Some(form.block_all);
    }

    // admin_rules — AdminRulesPatch delta (add/remove vs the snapshot).
    let orig_rules: Vec<&str> = orig.admin_rules.iter().map(String::as_str).collect();
    // Order-preserving de-dup: the operator may type the same id twice
    // (`"rule-c, rule-c"`); keep the first occurrence only so the add
    // delta stays clean instead of carrying a duplicate into the patch.
    let mut now_rules: Vec<String> = Vec::new();
    for entry in form.admin_rules_input.split(',') {
        let trimmed = entry.trim();
        if !trimmed.is_empty() && !now_rules.iter().any(|r| r == trimmed) {
            now_rules.push(trimmed.to_string());
        }
    }
    let add: Vec<String> = now_rules
        .iter()
        .filter(|r| !orig_rules.contains(&r.as_str()))
        .cloned()
        .collect();
    let remove: Vec<String> = orig_rules
        .iter()
        .filter(|r| !now_rules.iter().any(|n| n == *r))
        .map(|s| s.to_string())
        .collect();
    if !add.is_empty() || !remove.is_empty() {
        patch.admin_rules = Some(AdminRulesPatch { add, remove });
    }

    // lists — ListPolicyPatch MAP delta (set/clear vs the snapshot).
    //
    // A map delta, not the set delta `admin_rules` and the retired `tags`
    // field use, and the difference is load-bearing: a set cannot express
    // three states, so `ignore` would be indistinguishable from *absent,
    // therefore inherit `base`* — the exact distinction the whole model
    // rests on. Frozen in `ipc::protocol::ListPolicyPatch`.
    //
    // `set` carries only the keys whose value CHANGED. An override the
    // operator did not touch is not re-sent: this function's contract is
    // "only the changed fields", and re-declaring an untouched policy
    // would make an unrelated edit look like a list-policy decision in the
    // daemon's audit log.
    let mut lists_set: BTreeMap<String, ListPolicy> = BTreeMap::new();
    for (list_id, policy) in &form.lists_draft {
        if orig.lists.get(list_id) != Some(policy) {
            lists_set.insert(list_id.as_str().to_string(), *policy);
        }
    }
    // A key the draft dropped goes back to inheriting `base`. Note this
    // reads the SNAPSHOT, not the config: `lists_draft` is seeded from the
    // snapshot in `new_edit`, so a profile opened and closed untouched
    // produces an empty `set` and an empty `clear` — the whole patch is
    // `None` and the operator's declarations survive. Seeding the draft
    // empty would make this `clear` every key the profile had.
    let lists_clear: Vec<String> = orig
        .lists
        .keys()
        .filter(|list_id| !form.lists_draft.contains_key(*list_id))
        .map(|list_id| list_id.as_str().to_string())
        .collect();
    if !lists_set.is_empty() || !lists_clear.is_empty() {
        patch.lists = Some(ListPolicyPatch {
            set: lists_set,
            clear: lists_clear,
        });
    }

    // ecs — EcsPatch. The `clear` toggle wins outright and resets the
    // whole subtree; otherwise diff the three sub-fields.
    if form.ecs_clear {
        // Clearing an already-absent subtree is a no-op — only emit the
        // patch when the profile actually carries an `ecs` subtree.
        if orig.ecs.is_some() {
            patch.ecs = Some(EcsPatch {
                clear: true,
                ..Default::default()
            });
        }
    } else {
        let mode_now = form.ecs_mode_selection();
        let v4_now = parse_opt_u8(&form.ecs_v4_input, 32, "source_prefix_v4")?;
        let v6_now = parse_opt_u8(&form.ecs_v6_input, 128, "source_prefix_v6")?;
        let orig_ecs = orig.ecs.clone().unwrap_or_default();

        // D1 trap: EcsPatch sub-fields are single-Option, so a field that
        // went Some → None (operator picked `(inherit)` / emptied a
        // prefix on a profile that already had that field set) cannot be
        // expressed. Surface a friendly error instead of silently
        // dropping the intent. Tracked as TODO `s-4.26-p2-disc-1`.
        let per_field_clear = (orig_ecs.mode.is_some() && mode_now.is_none())
            || (orig_ecs.source_prefix_v4.is_some() && v4_now.is_none())
            || (orig_ecs.source_prefix_v6.is_some() && v6_now.is_none());
        if per_field_clear {
            return Err(
                "clearing one ecs field to inherit isn't supported — use the 'clear ecs' \
                 toggle to reset the whole subtree, or set an explicit value"
                    .into(),
            );
        }

        let changed = mode_now != orig_ecs.mode
            || v4_now != orig_ecs.source_prefix_v4
            || v6_now != orig_ecs.source_prefix_v6;
        if changed {
            patch.ecs = Some(EcsPatch {
                mode: mode_now,
                source_prefix_v4: v4_now,
                source_prefix_v6: v6_now,
                clear: false,
            });
        }
    }

    Ok(patch)
}

impl ProfileModal {
    /// Open an Add modal.
    pub fn open_add() -> Self {
        Self {
            stage: Stage::EditingForm(ProfileForm::new_add()),
        }
    }

    /// Open an Edit modal pre-filled from the focused profile.
    /// `lists_snapshot` is the `[[blocklists]]` vector the per-list
    /// override panel reads — see `ProfileForm::lists_snapshot`.
    pub fn open_edit(id: &str, profile: &Profile, lists_snapshot: Vec<Blocklist>) -> Self {
        Self {
            stage: Stage::EditingForm(ProfileForm::new_edit(id, profile, lists_snapshot)),
        }
    }

    /// Open a Remove modal at single-keypress confirm tier.
    /// `reference_summary` is the informational client-side blast-radius
    /// count (the daemon validator is the authority that blocks).
    pub fn open_remove(id: &str, display_name: &str, reference_summary: String) -> Self {
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: id.to_string(),
                display_name: display_name.to_string(),
                reference_summary,
            }),
        }
    }

    /// Mark the modal submitted with the given outcome — the caller
    /// closes it on the next keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    /// Whether the modal is in its terminal submitted state.
    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, Stage::Submitted(_))
    }

    /// Borrow the form when the stage is editing. Test-only.
    #[cfg(test)]
    pub fn form(&self) -> Option<&ProfileForm> {
        match &self.stage {
            Stage::EditingForm(f) => Some(f),
            _ => None,
        }
    }

    /// Mutable counterpart of [`Self::form`]. Test-only.
    #[cfg(test)]
    pub fn form_mut(&mut self) -> Option<&mut ProfileForm> {
        match &mut self.stage {
            Stage::EditingForm(f) => Some(f),
            _ => None,
        }
    }

    /// Borrow the remove-confirm state. Test-only.
    #[cfg(test)]
    pub fn remove(&self) -> Option<&RemoveConfirm> {
        match &self.stage {
            Stage::ConfirmingRemove(r) => Some(r),
            _ => None,
        }
    }
}

// ── Render helpers (called from tui/ui.rs) ───────────────────────────

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{self, Action, ActionKind, ProseRow, ValueKind};

/// Outer modal width. The interior is two columns narrower, and one
/// narrower again while the field region scrolls — [`modal_form::render_modal`]
/// resolves that, so nothing here measures against it by hand.
const MODAL_W: u16 = 70;

// Title-band copy. The literals keep the leading / trailing spaces they
// were coined with because `tests/frozen_strings_s49_profile_editor_tui.rs`
// pins them byte-for-byte; `modal_form::title_band` supplies its own lead,
// so every use site trims them.
const TITLE_ADD: &str = " Add profile ";
const TITLE_EDIT: &str = " Edit profile ";
const TITLE_REMOVE: &str = " Remove profile ";
const TITLE_DONE: &str = " Profile — done ";
const TITLE_FAILED: &str = " Profile — failed ";

/// Nav-key legend. Byte-identical to the `modal_form::keys_line()` copy
/// this surface used before the migration — D7′: chrome, layout and colour
/// change, keying does not.
///
/// N14 stripped the save/cancel clause: the action row now bakes its
/// own key into each button's label (`[Esc] Discard` / `[Enter] Save`),
/// so a blanket "Enter save · Esc cancel" here would be a second,
/// redundant source of the same fact.
const FORM_KEYS: &str = "↹/↑↓ move · ←/→ change";

/// Draw the modal as an overlay centred on the active tab's **content
/// rect** (§4.61 D18) so the header, the menu card and the footer legend
/// stay visible. Branches on the stage: the add/edit form is Archetype F,
/// the confirm and outcome screens are Archetype C.
///
/// Everything geometric belongs to [`modal_form::render_modal`] — the
/// elevated rounded chrome, the height request, the anchor clamp, the
/// two-pass width resolution that keeps rows clear of the scrollbar
/// column, and the focus-following viewport. What is left here is the
/// modal's width and where its real terminal cursor goes.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &ProfileModal) {
    match &modal.stage {
        Stage::EditingForm(form) => {
            let render = modal_form::render_modal(f, anchor, MODAL_W, |w| form_body(form, w));
            if let Some((row, caret)) = render.cursor {
                render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
            }
        }
        Stage::ConfirmingRemove(rc) => {
            let spec = remove_notice(rc);
            modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&spec, w), ())
            });
        }
        Stage::Submitted(outcome) => {
            let spec = outcome_notice(outcome);
            modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&spec, w), ())
            });
        }
    }
}

/// Title + description band copy for the form. On Edit the `id` also
/// rides in the title, where the pinned head keeps it visible however far
/// the field region has scrolled — the Identity row below it is the same
/// value, kept so Add and Edit stay visually parallel (the Lists
/// reference does exactly this).
/// Title + the two description rows for the form. On Edit the `id` also
/// rides in the title, where the pinned head keeps it visible however far
/// the field region has scrolled — the Identity row below it is the same
/// value, kept so Add and Edit stay visually parallel (the Lists
/// reference does exactly this).
///
/// ## Two rows, and what earns a place in them
///
/// §4.65 UX1(c) put a two-line blurb under **each** of the five sections.
/// The operator's report after living with it was that the form now
/// explained itself five times to someone who had understood it once, so
/// 2026-08-07 moved the explaining into the heading: one description, on
/// its own `bg_main` strip under the title, and `section()` everywhere
/// below.
///
/// Ten rows became two, so the copy has to choose. The rule applied: keep
/// what states the **model** — what a profile is, and what makes it
/// actually enforce anything — and let per-field guidance carry the rest.
/// `field_hint` already reaches every row under the cursor, and it has a
/// full three-row help region to say it in ([`HELP_REGION`]), which is
/// more room than a blurb ever had.
///
/// So the sentence about **where a profile's lists come from** survives
/// into both modes — it is the one thing a profile can be silently wrong
/// about, and the panel below is the row that fixes it. (That sentence
/// used to be about the *tags* join, for the same reason: under the tag
/// model an untagged profile enforced nothing. The reason moved with the
/// model; the slot did not.) The id's permanence survives into **Add**
/// only — that is the mode where the field is still editable and the
/// warning can still change a decision — and the ECS / block-response /
/// admin-rule blurbs are gone entirely, every one of them describing a
/// single row that has its own hint.
///
/// Both rows are budgeted: this modal is 70 columns, so the narrow build
/// pass leaves 67 cells and [`modal_form::desc_band2`] spends 2 on the
/// indent. Pinned by `no_desc_row_outruns_the_narrow_build_pass`.
fn band_text(form: &ProfileForm) -> (String, [&'static str; 2]) {
    match form.mode {
        FormMode::Add => (
            TITLE_ADD.trim().to_string(),
            [
                "A policy bundle devices and subnets point at. The id is",
                "permanent. Lists come from profiles.<id>.lists + base.",
            ],
        ),
        FormMode::Edit => (
            format!("{} \u{b7} {}", TITLE_EDIT.trim(), form.id),
            [
                "What this profile blocks, and how it answers when it does.",
                "Lists: profiles.<id>.lists, else that list's own base.",
            ],
        ),
    }
}

/// Build the Archetype-F body: banded head, labelled sections, one row
/// per field, pinned tail. Returns the `ScrollBody` plus the real
/// terminal cursor's target, exactly as
/// `tabs/lists.rs::edit_form_body` does.
///
/// `width` is handed down by [`modal_form::render_modal`] and is already
/// net of the scrollbar column when the field region scrolls — no row
/// here measures the modal for itself.
fn form_body(form: &ProfileForm, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let focus = form.focused;
    let (title, desc) = band_text(form);
    let mut rows = modal_form::FormRows::new_desc2(&title, desc, width);
    let len = |s: &str| s.chars().count() as u16;

    // ── IDENTITY ──────────────────────────────────────────────────────
    // The D18 floor budget, re-derived from scratch on 2026-08-07 — and
    // the number this comment carried was wrong, which is why it is spelled
    // out rather than cited.
    //
    // It read "12 − 3 head − 5 tail", i.e. 4 interior rows. That `5` is the
    // DEFAULT tail (`TailNote::default()`, `HINT_ROWS = 2`), and this modal
    // has not used it since §4.65 UX1(c) gave itself `HELP_REGION`
    // (3 rows, banded). The real tail is `1 spacer + 3 note + 1 keys +
    // 1 action` = **6**, so the field viewport was already 3 rows, not 4.
    //
    // `new_desc2` takes the head from 3 to 4, and `scroll_layout` serves
    // tail first, head second, fields last — so at `avail = 12` the
    // viewport is now **2** rows. Dropping the five two-row blurbs does NOT
    // pay that back: blurbs lived in `fields`, which scrolls, while
    // `view_h` is fixed by head + tail alone. It buys less scrolling, never
    // a taller viewport.
    //
    // Two rows is enough because `render_scroll_body` anchors the focused
    // row at the BOTTOM of the window (`offset = focus + 1 - view_h`), so
    // the focused field and its predecessor are both on screen. That is the
    // property under test, not "fits":
    // `floor_add_keeps_the_action_row_and_the_focused_field_on_screen`.
    //
    // It is also the floor itself. The two-row window was originally sized
    // by the Tags picker, which needed its chip row AND its suggestions row
    // visible together; `plp-s5d` removed that picker, but the floor stays
    // at 2 because the anchoring property above is what the test pins, and
    // it is independent of which field is focused.
    rows.section("Identity");
    if form.mode == FormMode::Add {
        let id_focus = focus == FormField::Id;
        rows.text_field(
            modal_form::value_row(
                "id",
                &form.id,
                id_focus,
                ValueKind::Identity,
                Some("e.g. kids"),
                width,
            ),
            id_focus,
            field_hint(FormField::Id),
            len(&form.id),
        );
    } else {
        // Immutable once created, so it is shown and never focusable —
        // `visible_fields()` leaves `Id` out of the Edit ring entirely.
        rows.line(modal_form::value_row(
            "id",
            &form.id,
            false,
            ValueKind::Identity,
            None,
            width,
        ));
    }
    let dn_focus = focus == FormField::DisplayName;
    rows.text_field(
        modal_form::value_row(
            "display name",
            &form.display_name,
            dn_focus,
            ValueKind::Editable,
            Some("blank = the id"),
            width,
        ),
        dn_focus,
        field_hint(FormField::DisplayName),
        len(&form.display_name),
    );

    if form.mode == FormMode::Add {
        add_preview_sections(&mut rows, width);
        let tail = form_tail_for(&rows, form);
        return rows.finish(tail);
    }

    // ── BLOCKING ──────────────────────────────────────────────────────
    rows.spacer();
    rows.section("Blocking");
    let br_focus = focus == FormField::BlockResponse;
    rows.field(
        modal_form::selector_row(
            "block response",
            BLOCK_RESPONSE_OPTIONS
                .get(form.block_response_idx)
                .copied()
                .unwrap_or(BLOCK_RESPONSE_OPTIONS[0]),
            br_focus,
            width,
        ),
        br_focus,
        field_hint(FormField::BlockResponse),
    );
    let ttl_focus = focus == FormField::BlockedTtl;
    rows.text_field(
        modal_form::value_row(
            "blocked ttl",
            &form.blocked_ttl_input,
            ttl_focus,
            ValueKind::Editable,
            Some("(inherit)"),
            width,
        ),
        ttl_focus,
        field_hint(FormField::BlockedTtl),
        len(&form.blocked_ttl_input),
    );
    // A radio, not a `yes`/`no` selector: each side declares what it
    // *means*, so "block everything" reads red and "no" reads sage
    // without this module naming a colour. ←/→ and Space still flip it.
    let ba_focus = focus == FormField::BlockAll;
    rows.field(
        modal_form::radio_row(
            "block all",
            ("Yes", ValueKind::Blocking),
            ("No", ValueKind::Healthy),
            form.block_all,
            ba_focus,
            width,
        ),
        ba_focus,
        field_hint(FormField::BlockAll),
    );

    // ── POLICY ────────────────────────────────────────────────────────
    // The two read-only rows replace the old always-on footnote at the
    // bottom of the modal. A row below the last *focusable* field is
    // unreachable once the body scrolls — the viewport follows focus and
    // there is no scroll key (D7′) — so the note lives beside the
    // editable rule field it belongs to, where focus brings it on screen.
    rows.spacer();
    rows.section("Policy");
    let ar_focus = focus == FormField::AdminRules;
    rows.text_field(
        modal_form::value_row(
            "admin rules",
            &form.admin_rules_input,
            ar_focus,
            ValueKind::Editable,
            Some("(none)"),
            width,
        ),
        ar_focus,
        field_hint(FormField::AdminRules),
        len(&form.admin_rules_input),
    );
    rows.line(modal_form::state_row(
        "local records",
        "read-only here",
        ValueKind::Caution,
        "  \u{2192} Local DNS tab",
        width,
    ));
    rows.line(modal_form::state_row(
        "rewrite rules",
        "read-only here",
        ValueKind::Caution,
        "  \u{2192} warden rewrite",
        width,
    ));

    // ── ECS ───────────────────────────────────────────────────────────
    // The three sub-fields go inert while the whole-subtree `clear ecs`
    // toggle is on — `resolve_edit_patch` ignores them in that case, so
    // they drop the selector wrap and the caret (Caution, not Editable)
    // without leaving the tab order.
    rows.spacer();
    rows.section("ECS");
    let ecs_dim = form.ecs_clear;
    let ecs_mode_label = ECS_MODE_OPTIONS
        .get(form.ecs_mode_idx)
        .copied()
        .unwrap_or(ECS_MODE_OPTIONS[0]);
    let mode_focus = focus == FormField::EcsMode;
    rows.field(
        if ecs_dim {
            modal_form::value_row(
                "ecs mode",
                ecs_mode_label,
                mode_focus,
                ValueKind::Caution,
                None,
                width,
            )
        } else {
            modal_form::selector_row("ecs mode", ecs_mode_label, mode_focus, width)
        },
        mode_focus,
        field_hint(FormField::EcsMode),
    );
    for (field, label, buf) in [
        (FormField::EcsPrefixV4, "ecs prefix v4", &form.ecs_v4_input),
        (FormField::EcsPrefixV6, "ecs prefix v6", &form.ecs_v6_input),
    ] {
        let focused = focus == field;
        if ecs_dim {
            rows.field(
                modal_form::value_row(
                    label,
                    &inherit_display(buf),
                    focused,
                    ValueKind::Caution,
                    None,
                    width,
                ),
                focused,
                field_hint(field),
            );
        } else {
            rows.text_field(
                modal_form::value_row(
                    label,
                    buf,
                    focused,
                    ValueKind::Editable,
                    Some("(inherit)"),
                    width,
                ),
                focused,
                field_hint(field),
                len(buf),
            );
        }
    }
    let clear_focus = focus == FormField::EcsClear;
    rows.field(
        modal_form::radio_row(
            "clear ecs",
            ("Yes", ValueKind::Caution),
            ("No", ValueKind::Editable),
            form.ecs_clear,
            clear_focus,
            width,
        ),
        clear_focus,
        field_hint(FormField::EcsClear),
    );

    // ── LISTS ─────────────────────────────────────────────────────────
    //
    // The per-list override panel — one focusable row per configured
    // `[[blocklists]]`, showing what this profile does with it and whether
    // that is the profile's own declaration or the list's `base` showing
    // through. Replaces the `profile.tags` chip picker, which decided
    // nothing after the plp cutover and therefore rendered inert history
    // wearing a control's clothes.
    rows.spacer();
    rows.section("Lists");
    if form.lists_snapshot.is_empty() {
        // Not a focus target: there is nothing here to change, and a row
        // in the ring that answers no key is the "offers input it drops on
        // the floor" defect `add_preview_sections` documents. Same
        // `state_row` vocabulary it uses, for the same reason — "something
        // you can see here and change elsewhere".
        rows.line(modal_form::state_row(
            "lists",
            "none configured",
            ValueKind::Caution,
            LIST_PANEL_EMPTY,
            width,
        ));
    } else {
        // ONE draft profile for the whole panel, not one per row: this is
        // the value `effective_direction` is asked about, and building it
        // once keeps the answer identical down the column by construction.
        let draft = form.draft_profile();
        for (i, list) in form.lists_snapshot.iter().enumerate() {
            let row_focus = focus == FormField::ListOverride(i);
            let effective = effective_direction(&draft, list);
            let declared = form.lists_draft.get(&list.id).copied();
            let value = list_policy_value(effective, declared.is_some());
            // `\u{2039} \u{203a}` on focus is `selector_row`'s vocabulary for "a key
            // cycles this". Composed here rather than by calling
            // `selector_row` because that helper hard-codes
            // `ValueKind::Editable`, and this row's colour has to carry the
            // direction: a `Block` that renders the same grey as an `Allow`
            // is a filtering decision the operator has to read a word to
            // learn, on the one surface whose entire job is showing it.
            let shown = if row_focus {
                // Fit the value FIRST, exactly as `selector_row` does and
                // for its reason: `value_row` windows a focused value from
                // the TAIL, so an overrun would eat the opening `\u{2039}` —
                // the marker that says a key cycles this row would be what
                // got cut, rather than the word that overran. Unreachable
                // at 70 columns with these words; the trap is that it stops
                // being unreachable the moment either changes.
                let inner = modal_form::fit(
                    &value,
                    modal_form::value_budget(width, true).saturating_sub(4),
                );
                format!("\u{2039} {inner} \u{203a}")
            } else {
                value
            };
            // Only the focused row's hint is ever shown (`FormRows::field`
            // keeps it on that condition), and the pending-consent variant
            // does two `String::replace`s over ~130 characters. Building
            // one per list on every frame would pay that 64 times over for
            // 63 strings nothing renders.
            let hint = if row_focus {
                list_row_hint(form, i, list, declared)
            } else {
                String::new()
            };
            rows.field(
                modal_form::value_row(
                    list.id.as_str(),
                    &shown,
                    row_focus,
                    policy_value_kind(effective),
                    None,
                    width,
                ),
                row_focus,
                &hint,
            );
        }
    }

    let tail = form_tail_for(&rows, form);
    rows.finish(tail)
}

/// The word (and provenance mark) a panel row shows.
///
/// `declared` is the *provenance*, asked of the draft map; `effective` is
/// the *direction*, asked of [`effective_direction`]. Two questions, two
/// sources, deliberately — see [`ProfileForm::declared_for`].
fn list_policy_value(effective: ListPolicy, declared: bool) -> String {
    let word = match effective {
        ListPolicy::Deny => LIST_POLICY_BLOCK,
        ListPolicy::Allow => LIST_POLICY_ALLOW,
        ListPolicy::Ignore => LIST_POLICY_IGNORE,
    };
    if declared {
        word.to_string()
    } else {
        format!("{word}{LIST_POLICY_INHERITED}")
    }
}

/// Colour for a panel row's value: what the value **is**, per
/// `modal_form::ValueKind`'s rule, and matching the Lists table's own
/// direction palette (`tabs::lists`: error/red for BLOCK, success for
/// ALLOW, muted for IGNORE).
///
/// `Ignore` takes [`ValueKind::Editable`] — the recessive `text_secondary`
/// — rather than `Caution`'s ochre, because an inert row is not a warning,
/// it is an absence of direction, and it has to read as neither of the two
/// words above it. The loud half of P6's "inert is legitimate but never
/// silent" is the reload WARN that names the list; this is the quiet half.
fn policy_value_kind(effective: ListPolicy) -> ValueKind {
    match effective {
        ListPolicy::Deny => ValueKind::Blocking,
        ListPolicy::Allow => ValueKind::Healthy,
        ListPolicy::Ignore => ValueKind::Editable,
    }
}

/// Guidance for the focused panel row, in priority order: an armed
/// `ignore` valve, then a pending `allow` the daemon is going to refuse,
/// then the plain key legend.
///
/// **The consent notice is guidance, never a gate.** It never blocks the
/// save and never asks the operator to confirm anything: the refusal is
/// the daemon's, at the single write path where it can be enforced
/// (`ipc::socket_server`), and a second copy here would be the D11 class
/// this workstream already paid for once. What it buys is that the
/// operator learns *before* spending a save, and — this is the part that
/// matters — learns the one action that actually works.
///
/// It is conditioned on the row's **pending** policy being `Allow`, not on
/// the list being unsigned. `BlocklistTrust` defaults to `RemoteUnsigned`,
/// and every `[[blocklists]]` row on both live hosts omits the key, so an
/// unconditional notice would fire on every row of every profile. A hint
/// that is always on is a hint nobody reads — the failure mode project rules
/// records three separate times for detectors.
///
/// The two fields it reads (`trust`, `accept_unsigned_allow`) are the same
/// two the daemon's gate reads, and both carry identical serde defaults on
/// both sides, so the loaded config and the on-disk row cannot disagree
/// about them. That is what makes reading `loaded_config` safe here, where
/// the retired tag pre-check had to read raw TOML.
fn list_row_hint(
    form: &ProfileForm,
    idx: usize,
    list: &Blocklist,
    declared: Option<ListPolicy>,
) -> String {
    if form.ignore_armed == Some(idx) {
        return LIST_OVERRIDE_IGNORE_ARMED.replace("{id}", list.id.as_str());
    }
    if declared == Some(ListPolicy::Allow)
        && list.trust == crate::config::schema::BlocklistTrust::RemoteUnsigned
        && !list.accept_unsigned_allow
    {
        return LIST_OVERRIDE_NEEDS_CONSENT.replace("{id}", list.id.as_str());
    }
    LIST_OVERRIDE_HINT.to_string()
}

/// What Add shows below Identity: every section Edit has, every field
/// named, **none of them offered** (§4.65 UX1(b)).
///
/// ## Why these are inert and not editable
///
/// `IpcCommand::ProfileCreate { id, display_name, token }` is the whole Add
/// wire (`ipc/protocol.rs`). Eight of Edit's eleven fields have no transport
/// on it, and the only routes to one are a protocol change or a
/// non-atomic create-then-update — neither of which is a layout sprint's
/// to make.
///
/// So the operator's report ("Add opens only the name field") is answered
/// by showing the **shape** of a profile rather than by widening the focus
/// ring. `FormField::ADD_FIELDS` deliberately still holds four entries:
/// putting `BlockResponse` in the ring would give the operator a field to
/// fill that the submit path drops on the floor in silence — which is
/// precisely the defect §4.64 G4 closed on the Devices form, where Promote
/// offered an editable group its wire wrote as `None`. A row that says
/// *when* it becomes available is worth more than a row that takes input
/// and loses it.
///
/// The rows are [`modal_form::state_row`]s, the same vocabulary the Edit
/// form already uses for `local records` / `rewrite rules` — "something you
/// can see here and change elsewhere" — so this borrows an established
/// reading rather than inventing one.
fn add_preview_sections(rows: &mut modal_form::FormRows, width: u16) {
    // Frozen so a reader of one row learns the rule for all of them.
    const LATER: &str = "set after creating";

    let preview = |rows: &mut modal_form::FormRows, label: &str| {
        rows.line(modal_form::state_row(
            label,
            LATER,
            ValueKind::Caution,
            "",
            width,
        ));
    };

    rows.spacer();
    rows.section("Blocking");
    for label in ["block response", "blocked ttl", "block all"] {
        preview(rows, label);
    }

    rows.spacer();
    rows.section("Policy");
    preview(rows, "admin rules");
    // NOT `LATER`. These two are read-only in the Edit form as well —
    // creating the profile does not make them editable here, so
    // "set after creating" would be a promise the next screen breaks.
    // They carry Edit's own copy verbatim, pointer included.
    for (label, note) in [
        ("local records", "  \u{2192} Local DNS tab"),
        ("rewrite rules", "  \u{2192} warden rewrite"),
    ] {
        rows.line(modal_form::state_row(
            label,
            "read-only here",
            ValueKind::Caution,
            note,
            width,
        ));
    }

    rows.spacer();
    rows.section("ECS");
    for label in ["ecs mode", "ecs prefix v4", "ecs prefix v6", "clear ecs"] {
        preview(rows, label);
    }
}

/// The pinned tail: hint-or-error, the key legend, `[Esc] Discard` ·
/// `[Enter] Save`.
///
/// `Save` is the modal's one [`ActionKind::Primary`] and sits right-most;
/// the focus ring still reaches `Submit` before `Cancel`, unchanged (D7′).
fn form_tail_for(
    rows: &modal_form::FormRows,
    form: &ProfileForm,
) -> Vec<ratatui::text::Line<'static>> {
    let actions = [
        Action::new(
            "  [Esc] Discard  ",
            form.focused == FormField::Cancel,
            ActionKind::Neutral,
            field_hint(FormField::Cancel),
        ),
        Action::new(
            "  [Enter] Save  ",
            form.focused == FormField::Submit,
            ActionKind::Primary,
            field_hint(FormField::Submit),
        ),
    ];
    modal_form::form_tail_with_note(
        rows,
        HELP_REGION,
        form.error_message.as_deref(),
        // Belt and braces: `Submit` and `Cancel` render no row of their
        // own, so without a fallback their guidance would come only from
        // the action hints above.
        field_hint(form.focused),
        FORM_KEYS,
        &actions,
    )
}

/// This modal's help region: three rows on a band of their own
/// (§4.65 UX1(c)).
///
/// **Per-call, not an edit to [`modal_form::HINT_ROWS`].** The constant is
/// shared by every Archetype-F modal in `src/tui/` — Lists edit, Rules
/// edit, Subnets, Local DNS, Devices — so raising it here to 3 would have
/// resized the tail on six surfaces at once, each needing its own D18 floor
/// re-verified. That is the blast radius that cost the Devices form its
/// `Save`, `Cancel` and 9 of 13 fields under §4.63 S2a+S2c. Naming the
/// decision here, explicitly, is `_docs/features/tui_ux_batch_2608.md`
/// §3.2's instruction.
///
/// Three rows because this form's hints are the longest in the ecosystem —
/// `EcsClear`'s runs 98 characters against a ~60-cell row, so at
/// [`modal_form::HINT_ROWS`] it was ellipsised mid-sentence on the one
/// field whose guidance carries a hard limitation (D1). The band is what
/// makes three rows read as a help *area* instead of as three loose lines
/// between the fields and the keys.
const HELP_REGION: modal_form::TailNote = modal_form::TailNote {
    rows: 3,
    banded: true,
};

/// Note rows the **Failed** submit notice reserves for the daemon's
/// refusal. See [`outcome_notice`] for why the default 2 is not enough
/// here, and `floor_submit_failure_keeps_the_keys_row_and_names_the_cut`
/// for the measurement.
const LIST_FAILURE_NOTE_ROWS: usize = 8;

/// Pre-resolve a nullable text field to its display string for the inert
/// ecs rows — empty shows the `(inherit)` placeholder the editable rows
/// surface automatically.
fn inherit_display(input: &str) -> String {
    if input.trim().is_empty() {
        "(inherit)".to_string()
    } else {
        input.to_string()
    }
}

/// One-line description of the focused field, shown on the validation
/// line whenever there is no pending error.
fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Id => "short stable key, e.g. kids or guests (immutable on edit)",
        FormField::DisplayName => "human label shown in the table (blank = id)",
        FormField::BlockResponse => {
            "what blocked queries return — ←/→ to change; (inherit) uses [server]"
        }
        FormField::BlockedTtl => "TTL in seconds on blocked answers (blank = inherit)",
        FormField::BlockAll => "block every domain not explicitly allowed — ←/→ or Space toggles",
        FormField::AdminRules => "comma-separated admin-rule ids applied to this profile",
        FormField::EcsMode => "EDNS Client Subnet mode sent upstream — ←/→ to change",
        FormField::EcsPrefixV4 => "ECS source prefix length 0..=32 (blank = inherit)",
        FormField::EcsPrefixV6 => "ECS source prefix length 0..=128 (blank = inherit)",
        // Carries the D1 limitation the modal used to state in a
        // permanent footnote two rows above the frame's bottom edge.
        // Guidance belongs where focus lands, not where it costs every
        // operator two of twelve interior rows.
        FormField::EcsClear => {
            "resets the WHOLE ecs subtree to inherit — individual ecs fields can't be cleared one by one"
        }
        // The resting case only. `form_body` computes the focused panel
        // row's hint itself (`list_row_hint`), because the armed-valve and
        // pending-consent variants name the list and a `&'static str`
        // cannot. Same split the tags picker used for `tags_hint`.
        FormField::ListOverride(_) => LIST_OVERRIDE_HINT,
        FormField::Submit => "Enter saves every change atomically",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The remove confirm as an Archetype-C notice.
///
/// No [`Action`]s: the operator answers with `y` / `n`, which `Tab` never
/// reaches, so a rendered button would advertise a focus target that does
/// not exist. The keys legend carries the whole input contract (D7′), and
/// the chrome loses the `brand_red` border it drew before — red is the
/// title tick and the destructive copy, never a border (D15).
fn remove_notice(rc: &RemoveConfirm) -> modal_form::NoticeSpec {
    modal_form::NoticeSpec {
        hint_rows: None,
        title: TITLE_REMOVE.trim().to_string(),
        desc: format!("{} \u{b7} {}", rc.id, rc.display_name),
        prose: vec![
            ProseRow::emphasis(format!("Remove profile '{}'?", rc.id), ValueKind::Blocking),
            ProseRow::plain(rc.reference_summary.clone()),
            ProseRow::plain("refused while any device, group, subnet or schedule points here"),
        ],
        choices: Vec::new(),
        error: None,
        hint: "the daemon validator decides — this only asks it to delete".into(),
        keys: "[y] confirm \u{b7} [n / Esc] cancel".into(),
        actions: Vec::new(),
    }
}

/// The submit outcome as an Archetype-C notice.
///
/// A failure rides in `error`, not in `prose`: the tail's note region
/// wraps, so a daemon error longer than the modal is wide stays readable
/// instead of being truncated to one line — which is what the flat body
/// did before.
///
/// ## Why the Failed arm buys extra note rows
///
/// [`modal_form::HINT_ROWS`] is **2**, and this modal's longest refusal is
/// no longer a sentence. `profile_list_policy` §4 S4 put the per-profile
/// override write behind a daemon consent gate whose refusal
/// (`IPC_ERROR_OVERRIDE_ALLOW_NEEDS_CONSENT`) is ~590 characters and ends
/// with the verb that fixes it. At 2 rows the operator reads the first
/// ~120 characters — the problem, none of the answer.
///
/// That is not an edge case here. `BlocklistTrust` defaults to
/// `RemoteUnsigned` and every `[[blocklists]]` row on both live hosts
/// omits the key, so the *first* allow override an operator tries is the
/// one that gets refused. A refusal whose recovery is cut off is the
/// unsatisfiable-in-its-own-terms defect project rules §Neutrality records.
///
/// `hint_or_error_rows` does mark the cut and name the residual, so
/// nothing was ever silent — but "run it in the CLI to read it all" is a
/// poor answer when the whole message would fit in rows this notice is
/// otherwise leaving blank. `Failed` renders **no prose**, so the rows
/// come out of a region that is empty on this arm.
///
/// [`LIST_FAILURE_NOTE_ROWS`] is measured at the 80\u{d7}24 floor, not derived
/// — pinned by `floor_submit_failure_keeps_the_keys_row_and_names_the_cut`.
/// The `Ok` arm keeps the default: its message is one short line and the
/// rows it does not need belong to the prose it does render.
fn outcome_notice(outcome: &SubmitOutcome) -> modal_form::NoticeSpec {
    let (title, desc, prose, error) = match outcome {
        SubmitOutcome::Ok(msg) => (
            TITLE_DONE,
            "the daemon reloaded the new configuration",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            TITLE_FAILED,
            "nothing was changed",
            Vec::new(),
            Some(msg.clone()),
        ),
    };
    modal_form::NoticeSpec {
        hint_rows: error.is_some().then_some(LIST_FAILURE_NOTE_ROWS),
        title: title.trim().to_string(),
        desc: desc.to_string(),
        prose,
        choices: Vec::new(),
        error,
        hint: String::new(),
        keys: "[any key] close".into(),
        actions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::blocklist::BlocklistBase;

    use crate::config::schema::BlocklistTrust;

    /// A `[[blocklists]]` row for the override panel's tests.
    ///
    /// Domains use the RFC 2606 `.invalid` TLD: a fixture must not name a
    /// real provider, and `src/` must not carry third-party domain
    /// knowledge in either direction (project rules Rule 10).
    fn mk_list(id: &str, base: BlocklistBase, trust: BlocklistTrust, ack: bool) -> Blocklist {
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: format!("https://lists.invalid/{id}.txt"),
            format: Default::default(),
            update_interval_hours: 12,
            max_entries: 1_000_000,
            enabled: true,
            auth_token_ref: None,
            base,
            trust,
            accept_unsigned_allow: ack,
            max_consecutive_failures: 5,
        }
    }

    /// Two deny-base lists and one allow-base list, id-ordered as
    /// `build_profile_edit_modal` hands them over.
    fn mk_lists() -> Vec<Blocklist> {
        vec![
            mk_list(
                "ads",
                BlocklistBase::Deny,
                BlocklistTrust::RemoteUnsigned,
                false,
            ),
            mk_list("news", BlocklistBase::Allow, BlocklistTrust::Local, false),
            mk_list(
                "social",
                BlocklistBase::Deny,
                BlocklistTrust::RemoteUnsigned,
                false,
            ),
        ]
    }

    fn mk_profile() -> Profile {
        Profile {
            display_name: "Kids".into(),
            block_response: Some(BlockResponseV1::Nxdomain),
            blocked_ttl_secs: Some(60),
            block_all: true,
            admin_rules: vec![
                crate::config::schema::Id::new("rule-a").unwrap(),
                crate::config::schema::Id::new("rule-b").unwrap(),
            ],
            ecs: Some(ProfileEcsConfig {
                mode: Some(EcsMode::Coarse),
                source_prefix_v4: Some(24),
                source_prefix_v6: None,
            }),
            ..Default::default()
        }
    }

    // ── Field navigation ──────────────────────────────────────────────

    #[test]
    fn add_form_cycles_four_fields() {
        let mut f = ProfileForm::new_add();
        assert_eq!(f.focused, FormField::Id);
        f.focus_next();
        assert_eq!(f.focused, FormField::DisplayName);
        f.focus_next();
        assert_eq!(f.focused, FormField::Submit);
        f.focus_next();
        assert_eq!(f.focused, FormField::Cancel, "Discard button is last");
        f.focus_next();
        assert_eq!(f.focused, FormField::Id, "Add form wraps after Cancel");
    }

    #[test]
    fn edit_form_cycles_head_then_every_list_then_tail_skipping_id() {
        let mut f = ProfileForm::new_edit("kids", &mk_profile(), mk_lists());
        assert_eq!(f.focused, FormField::DisplayName, "Edit starts past Id");
        let order = [
            FormField::BlockResponse,
            FormField::BlockedTtl,
            FormField::BlockAll,
            FormField::AdminRules,
            FormField::EcsMode,
            FormField::EcsPrefixV4,
            FormField::EcsPrefixV6,
            FormField::EcsClear,
            // One focus target per configured blocklist, in snapshot order.
            FormField::ListOverride(0),
            FormField::ListOverride(1),
            FormField::ListOverride(2),
            FormField::Submit,
            FormField::Cancel,
            FormField::DisplayName,
        ];
        for expected in order {
            f.focus_next();
            assert_eq!(f.focused, expected);
        }
        // Id is never visited in Edit mode.
        f.focus_prev();
        assert_eq!(f.focused, FormField::Cancel, "prev from DisplayName wraps");
    }

    /// A config with no `[[blocklists]]` must not put a row in the ring
    /// that answers no key — and must not index the empty snapshot.
    #[test]
    fn edit_form_ring_tolerates_zero_configured_lists() {
        let mut f = ProfileForm::new_edit("kids", &mk_profile(), Vec::new());
        let ring = f.visible_fields();
        assert!(
            !ring.iter().any(|x| matches!(x, FormField::ListOverride(_))),
            "no panel rows without lists: {ring:?}"
        );
        // Walk the whole ring twice; a panic here is the regression.
        for _ in 0..(ring.len() * 2) {
            f.focus_next();
        }
        assert_eq!(f.focused, FormField::DisplayName);
        f.focused = FormField::EcsClear;
        f.focus_next();
        assert_eq!(
            f.focused,
            FormField::Submit,
            "with no lists the head runs straight into the tail"
        );
    }

    // ── Edit snapshot capture ─────────────────────────────────────────

    #[test]
    fn edit_modal_captures_full_snapshot_at_open() {
        let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form().unwrap();
        assert_eq!(form.mode, FormMode::Edit);
        let orig = form.original.as_ref().expect("Edit captures a snapshot");
        assert_eq!(orig.id, "kids");
        assert_eq!(orig.display_name, "Kids");
        assert_eq!(orig.block_response, Some(BlockResponseV1::Nxdomain));
        assert_eq!(orig.blocked_ttl_secs, Some(60));
        assert!(orig.block_all);
        assert_eq!(orig.admin_rules, vec!["rule-a", "rule-b"]);
        assert_eq!(orig.ecs.as_ref().unwrap().mode, Some(EcsMode::Coarse));
        // Form buffers pre-filled from the snapshot.
        assert_eq!(form.block_response_idx, 2); // nxdomain
        assert_eq!(form.blocked_ttl_input, "60");
        assert_eq!(form.admin_rules_input, "rule-a, rule-b");
        assert_eq!(form.ecs_mode_idx, 2); // coarse
        assert_eq!(form.ecs_v4_input, "24");
        assert_eq!(form.ecs_v6_input, "");
    }

    // ── resolve_edit_patch — the heart of the modal ───────────────────

    #[test]
    fn resolve_empty_patch_when_nothing_changed() {
        let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form().unwrap();
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(
            patch,
            ProfileUpdatePatch::default(),
            "an untouched Edit form must produce an empty patch"
        );
    }

    #[test]
    fn resolve_block_response_inherit_emits_some_none() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.block_response_idx = 0; // (inherit)
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(
            patch.block_response,
            Some(None),
            "picking (inherit) clears block_response to inherit"
        );
    }

    #[test]
    fn resolve_block_response_set_emits_some_some() {
        let p = Profile {
            block_response: None,
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, vec![]);
        let form = modal.form_mut().unwrap();
        form.block_response_idx = 3; // refused
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(patch.block_response, Some(Some(BlockResponseV1::Refused)));
    }

    #[test]
    fn resolve_blocked_ttl_empty_emits_some_none() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.blocked_ttl_input.clear(); // empty = inherit
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(patch.blocked_ttl_secs, Some(None));
    }

    #[test]
    fn resolve_bad_ttl_returns_err() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.blocked_ttl_input = "abc".into();
        let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
        assert!(err.contains("blocked_ttl_secs"), "got: {err}");
    }

    #[test]
    fn resolve_admin_rules_diff_computes_add_and_remove() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        // snapshot is "rule-a, rule-b" → keep b, drop a, add c.
        form.admin_rules_input = "rule-b, rule-c".into();
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let ar = patch.admin_rules.expect("admin_rules delta present");
        assert_eq!(ar.add, vec!["rule-c"]);
        assert_eq!(ar.remove, vec!["rule-a"]);
    }

    #[test]
    fn resolve_admin_rules_dedups_typed_duplicates() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        // Operator types the same new id twice; the add delta must carry
        // it exactly once, not emit a duplicate into the patch.
        form.admin_rules_input = "rule-a, rule-b, rule-c, rule-c".into();
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let ar = patch.admin_rules.expect("admin_rules delta present");
        assert_eq!(ar.add, vec!["rule-c"]);
        assert!(ar.remove.is_empty());
    }

    // ── plp §4 S4: the per-list override delta ────────────────────────

    #[test]
    fn resolve_lists_delta_sets_a_declared_override() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(2); // social
        form.cycle_list_policy(true); // inherit -> Block (explicit)
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let lp = patch.lists.expect("lists delta present");
        assert_eq!(lp.set.get("social"), Some(&ListPolicy::Deny));
        assert!(lp.clear.is_empty());
    }

    #[test]
    fn resolve_lists_delta_clears_a_withdrawn_override() {
        let p = Profile {
            lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Allow)]),
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0); // ads, currently Allow
        form.cycle_list_policy(true); // Allow -> inherit
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let lp = patch.lists.expect("lists delta present");
        assert!(lp.set.is_empty());
        assert_eq!(lp.clear, vec!["ads"]);
    }

    /// **DoD 4, in the form that can actually fail.**
    ///
    /// "Open and close with Esc leaves the file alone" is vacuous: the
    /// modal never writes, so it passes on a completely broken draft. This
    /// asserts on the SAVE path instead — the one place a seeding bug is
    /// observable — and it is the mutation that matters: seed `lists_draft`
    /// empty in `new_edit` and the diff reads every existing key as
    /// withdrawn, so an operator who opened this profile to rename it
    /// loses every override they had.
    #[test]
    fn an_untouched_profile_with_overrides_emits_no_list_patch() {
        let p = Profile {
            lists: BTreeMap::from([
                (Id::new("ads").unwrap(), ListPolicy::Allow),
                (Id::new("social").unwrap(), ListPolicy::Ignore),
            ]),
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, mk_lists());
        let form = modal.form_mut().unwrap();
        // An edit to an UNRELATED field, so the patch is non-empty and the
        // assertion below cannot pass merely because nothing was sent.
        form.display_name = "Kids (renamed)".into();
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(patch.display_name.as_deref(), Some("Kids (renamed)"));
        assert_eq!(
            patch.lists, None,
            "an untouched panel must not withdraw the operator's own overrides"
        );
    }

    /// `set` carries only what CHANGED. An override the operator did not
    /// touch is not re-declared, so an unrelated edit does not show up in
    /// the daemon's audit log as a list-policy decision.
    #[test]
    fn resolve_lists_delta_omits_an_untouched_declaration() {
        let p = Profile {
            lists: BTreeMap::from([
                (Id::new("ads").unwrap(), ListPolicy::Allow),
                (Id::new("news").unwrap(), ListPolicy::Deny),
            ]),
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(1); // news: Deny -> Allow
        form.cycle_list_policy(true);
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let lp = patch.lists.expect("lists delta present");
        assert_eq!(lp.set.len(), 1, "only the touched row travels: {lp:?}");
        assert_eq!(lp.set.get("news"), Some(&ListPolicy::Allow));
        assert!(lp.clear.is_empty());
    }

    // ── plp §4 S4 / decision D: how `ignore` is reached ───────────────

    /// **DoD 5, the "not from a bare arrow" half.**
    ///
    /// Exhaustive over the starting states AND both directions, walked
    /// long enough to close every cycle. Asserting on the DRAFT rather
    /// than on the effective direction is deliberate: a list whose own
    /// `base` is `ignore` reaches effective `Ignore` through the cycle's
    /// `inherit` step, which is correct — that is the operator's own
    /// standing declaration on the list, and P6 already WARNs about it at
    /// every load. What must never happen is an arrow WRITING `ignore`
    /// into this profile.
    #[test]
    fn no_arrow_ever_declares_ignore() {
        for start in [
            None,
            Some(ListPolicy::Deny),
            Some(ListPolicy::Allow),
            Some(ListPolicy::Ignore),
        ] {
            for forward in [true, false] {
                let p = Profile {
                    lists: start
                        .map(|v| BTreeMap::from([(Id::new("ads").unwrap(), v)]))
                        .unwrap_or_default(),
                    ..mk_profile()
                };
                let mut modal = ProfileModal::open_edit("kids", &p, mk_lists());
                let form = modal.form_mut().unwrap();
                form.focused = FormField::ListOverride(0);
                for step in 0..8 {
                    form.cycle_list_policy(forward);
                    assert_ne!(
                        form.lists_draft.get(&Id::new("ads").unwrap()),
                        Some(&ListPolicy::Ignore),
                        "start={start:?} forward={forward} step={step}: an arrow \
                         declared ignore"
                    );
                }
            }
        }
    }

    /// The arrow cycle still reaches every state it is supposed to, so
    /// the test above cannot pass by the cycle being broken outright.
    #[test]
    fn the_arrow_cycle_reaches_inherit_deny_and_allow() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0);
        let ads = Id::new("ads").unwrap();
        let mut seen = Vec::new();
        for _ in 0..3 {
            form.cycle_list_policy(true);
            seen.push(form.lists_draft.get(&ads).copied());
        }
        assert!(seen.contains(&Some(ListPolicy::Deny)), "{seen:?}");
        assert!(seen.contains(&Some(ListPolicy::Allow)), "{seen:?}");
        assert!(seen.contains(&None), "{seen:?}");
    }

    /// From `ignore` both arrows are a one-way door out, and it opens
    /// toward MORE filtering — the same contract the Lists modal's
    /// `nature` row states in its own hint.
    #[test]
    fn an_arrow_leaves_ignore_toward_deny_in_both_directions() {
        for forward in [true, false] {
            let p = Profile {
                lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Ignore)]),
                ..mk_profile()
            };
            let mut modal = ProfileModal::open_edit("kids", &p, mk_lists());
            let form = modal.form_mut().unwrap();
            form.focused = FormField::ListOverride(0);
            form.cycle_list_policy(forward);
            assert_eq!(
                form.lists_draft.get(&Id::new("ads").unwrap()),
                Some(&ListPolicy::Deny),
                "forward={forward}"
            );
        }
    }

    /// **DoD 5, the "reachable" half.** Two presses, and only two.
    #[test]
    fn two_presses_of_i_declare_ignore_and_one_does_not() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0);
        let ads = Id::new("ads").unwrap();

        assert!(!form.press_ignore(), "the first press only arms");
        assert_eq!(
            form.lists_draft.get(&ads),
            None,
            "arming must not write anything"
        );
        assert!(form.press_ignore(), "the second press commits");
        assert_eq!(form.lists_draft.get(&ads), Some(&ListPolicy::Ignore));
        assert_eq!(form.ignore_armed, None, "committing spends the valve");
    }

    /// Arming is per-ROW. Arming on one list and pressing `i` on another
    /// must arm the second, not commit it — otherwise a stray arm on a row
    /// the operator has left makes the *next* row inert on one keypress.
    #[test]
    fn the_ignore_valve_does_not_carry_across_rows() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0);
        assert!(!form.press_ignore());
        form.focused = FormField::ListOverride(2);
        assert!(
            !form.press_ignore(),
            "a different row re-arms, never commits"
        );
        assert_eq!(form.lists_draft.get(&Id::new("social").unwrap()), None);
    }

    /// An arrow between the two presses cancels the declaration.
    #[test]
    fn an_arrow_spends_the_armed_ignore_valve() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0);
        assert!(!form.press_ignore());
        form.cycle_list_policy(true);
        assert_eq!(form.ignore_armed, None);
        assert!(
            !form.press_ignore(),
            "after an arrow the next `i` arms again rather than committing"
        );
        assert_ne!(
            form.lists_draft.get(&Id::new("ads").unwrap()),
            Some(&ListPolicy::Ignore)
        );
    }

    // ── the two readouts must not drift apart ─────────────────────────

    /// `declared_for` and `effective_for` answer different questions off
    /// the same map, and this pins them against each other: whenever a
    /// policy is DECLARED, it is also the EFFECTIVE one. Inline
    /// `effective_for`'s arithmetic instead of calling
    /// `effective_direction` and this is the assertion that survives to
    /// catch the copy drifting — the D11 class in miniature.
    #[test]
    fn a_declared_policy_is_always_the_effective_one() {
        for declared in [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore] {
            for list in mk_lists() {
                let p = Profile {
                    lists: BTreeMap::from([(list.id.clone(), declared)]),
                    ..mk_profile()
                };
                let modal = ProfileModal::open_edit("kids", &p, mk_lists());
                let form = modal.form().unwrap();
                assert_eq!(form.declared_for(&list), Some(declared));
                assert_eq!(
                    form.effective_for(&list),
                    declared,
                    "list {} base {:?}",
                    list.id.as_str(),
                    list.base
                );
            }
        }
    }

    /// And with nothing declared, the effective direction is the list's
    /// own `base` — including for `base = allow`, which is what makes the
    /// panel a readout rather than a constant.
    #[test]
    fn an_undeclared_list_shows_its_own_base() {
        let modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form().unwrap();
        for list in mk_lists() {
            assert_eq!(form.declared_for(&list), None);
            assert_eq!(form.effective_for(&list), list.base.as_policy());
        }
    }

    // ── the consent guidance is guidance, and it is conditional ───────

    /// The notice fires on a PENDING allow, and only there.
    ///
    /// `BlocklistTrust` defaults to `RemoteUnsigned` and every
    /// `[[blocklists]]` row on both live hosts omits the key, so a notice
    /// keyed on trust alone would be on for every row of every profile —
    /// and a hint that is always on is one nobody reads. The `ads` fixture
    /// is exactly that shape: remote, unsigned, unconsented.
    #[test]
    fn the_consent_notice_only_fires_on_a_pending_allow() {
        let lists = mk_lists();
        let unsigned = &lists[0]; // ads: remote-unsigned, no ack
        let local = &lists[1]; // news: trust = local

        let modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form().unwrap();

        assert_eq!(
            list_row_hint(form, 0, unsigned, None),
            LIST_OVERRIDE_HINT,
            "inheriting a deny costs nothing and must say nothing"
        );
        assert_eq!(
            list_row_hint(form, 0, unsigned, Some(ListPolicy::Deny)),
            LIST_OVERRIDE_HINT,
            "a declared deny narrows what the profile permits"
        );
        assert!(
            list_row_hint(form, 0, unsigned, Some(ListPolicy::Allow)).contains("set-trust"),
            "a pending allow on an unconsented remote list names the fix"
        );
        assert_eq!(
            list_row_hint(form, 1, local, Some(ListPolicy::Allow)),
            LIST_OVERRIDE_HINT,
            "trust = local has nothing to declare"
        );

        let consented = mk_list(
            "ads",
            BlocklistBase::Deny,
            BlocklistTrust::RemoteUnsigned,
            true,
        );
        assert_eq!(
            list_row_hint(form, 0, &consented, Some(ListPolicy::Allow)),
            LIST_OVERRIDE_HINT,
            "a list whose row already declares the consent is done paying"
        );
    }

    /// The notice has to survive the help region intact — the recovery
    /// command is the whole point of it, and it is at the end.
    ///
    /// Measured against the real render, not against a character count:
    /// the region is three banded rows of a 70-column modal and the
    /// arithmetic between those two facts is exactly what a count would
    /// get wrong.
    #[test]
    fn the_consent_notice_survives_the_help_region_whole() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Twice the grid's label column — longer than any list id in a
        // real config, and long enough that a hint budgeted for a short
        // one would be cut here.
        let long = "content-adult-and-gambling-x32";
        let lists = vec![mk_list(
            long,
            BlocklistBase::Deny,
            BlocklistTrust::RemoteUnsigned,
            false,
        )];
        let p = Profile {
            lists: BTreeMap::from([(Id::new(long).unwrap(), ListPolicy::Allow)]),
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, lists);
        modal.form_mut().unwrap().focused = FormField::ListOverride(0);

        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        for needle in ["set-trust", long, "--accept-unsigned-allow"] {
            assert!(
                dump.contains(needle),
                "the recovery command must reach the operator whole \
                 (missing {needle:?}):\n{dump}"
            );
        }
    }

    /// A list id can be four times the grid's label column
    /// (`Id::MAX_LEN` is 64, `GRID_LABEL_W` is 18). Unfitted it shifts the
    /// value column right and runs off the 70-cell modal, where the widget
    /// clips it with no ellipsis — "the operator reads a truncated string
    /// as a complete one", which `modal_form::value_row` says this module
    /// answers everywhere else. `push_row_lead` now fits the label; this
    /// is the fence.
    #[test]
    fn a_list_id_longer_than_the_label_column_does_not_break_the_grid() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let long = "a".repeat(crate::config::schema::Id::MAX_LEN);
        let lists = vec![mk_list(
            &long,
            BlocklistBase::Deny,
            BlocklistTrust::RemoteUnsigned,
            false,
        )];
        let modal = ProfileModal::open_edit("kids", &mk_profile(), lists);
        // Tall enough for the whole body — see the note in
        // `declared_and_inherited_are_distinguishable_on_the_same_direction`.
        let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        let row = dump
            .lines()
            .find(|l| l.contains("aaaa"))
            .expect("the row renders at all");
        assert!(
            row.contains('\u{2026}'),
            "an over-long label announces its own cut:\n{row}"
        );
        // The direction still lands in the value column, which is the
        // property an unfitted label destroys.
        assert!(
            row.contains(LIST_POLICY_BLOCK),
            "the value column survives a 64-character id:\n{row}"
        );
    }

    /// A config with no `[[blocklists]]` renders an explanation, not a
    /// blank section — and not a focusable row that answers no key.
    ///
    /// **Asserted on a full-height render, and the reason is a real
    /// limitation worth stating rather than hiding.** The empty-state row
    /// is not in the focus ring, so nothing ever anchors the viewport on
    /// it; at the 80x24 floor the field window is 2 rows and this row is
    /// below them. That is the same deal every non-focusable row on this
    /// form already takes — the `id` row in Edit mode scrolls away exactly
    /// so — and the alternative is worse: a ring entry that answers no key
    /// is the defect `add_preview_sections` documents. The band under the
    /// title carries the same fact on every render at every size
    /// ("Lists: profiles.<id>.lists, else that list's own base"), so an
    /// operator at the floor is not left without it.
    #[test]
    fn the_empty_panel_says_where_lists_come_from() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let modal = ProfileModal::open_edit("kids", &mk_profile(), Vec::new());
        let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());
        assert!(
            dump.contains("none configured"),
            "an empty panel names its state:\n{dump}"
        );
        assert!(
            dump.contains(LIST_PANEL_EMPTY),
            "and points at the surface that fixes it:\n{dump}"
        );
    }

    /// **The measurement behind [`LIST_FAILURE_NOTE_ROWS`].**
    ///
    /// The daemon's override-consent refusal is ~540 rendered characters
    /// and wraps to **9** rows at this width; the recovery command sits in
    /// rows 5 to 7. At `modal_form::HINT_ROWS` (2) the operator reads the
    /// problem and none of the answer. At 8 the command is whole and the
    /// cut — one row of trailing prose — is named by
    /// `hint_or_error_rows`'s own residual note.
    ///
    /// 8 rather than 9 leaves one interior row unspent at the floor
    /// (head 2 + note 8 + keys 1 = 11 of 12), so a future head change
    /// cannot silently drive the region to zero.
    #[test]
    fn floor_submit_failure_keeps_the_keys_row_and_names_the_cut() {
        let refusal = crate::ipc::errors::IpcError::OverrideAllowNeedsConsent {
            id: "kids".into(),
            list: "privacy-tracking".into(),
        }
        .operator_message();

        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        modal.finish(SubmitOutcome::Failed(refusal));
        let dump = render_at_floor(&modal);

        for needle in [
            "set-trust",
            "privacy-tracking",
            "--accept-unsigned-allow",
            "[any key] close",
        ] {
            assert!(
                dump.contains(needle),
                "the refusal's recovery command and the key legend must both \
                 survive the floor (missing {needle:?}):\n{dump}"
            );
        }
    }

    #[test]
    fn resolve_ecs_clear_toggle_emits_clear_patch() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.ecs_clear = true;
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let ecs = patch.ecs.expect("clear toggle emits an ecs patch");
        assert!(ecs.clear);
        assert_eq!(ecs.mode, None);
        assert_eq!(ecs.source_prefix_v4, None);
    }

    #[test]
    fn resolve_ecs_clear_noop_when_no_original_ecs() {
        let p = Profile {
            ecs: None,
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, vec![]);
        let form = modal.form_mut().unwrap();
        form.ecs_clear = true;
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        assert_eq!(
            patch.ecs, None,
            "clearing an already-absent ecs subtree is a no-op"
        );
    }

    #[test]
    fn resolve_ecs_set_mode_on_fresh_profile_creates_subtree() {
        let p = Profile {
            ecs: None,
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, vec![]);
        let form = modal.form_mut().unwrap();
        form.ecs_mode_idx = 2; // coarse
        let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
        let ecs = patch.ecs.expect("setting a mode creates the subtree");
        assert_eq!(ecs.mode, Some(EcsMode::Coarse));
        assert!(!ecs.clear);
    }

    #[test]
    fn resolve_ecs_per_field_clear_returns_err() {
        // mk_profile has ecs.mode = Some(Coarse). Picking (inherit) on the
        // mode dropdown while the subtree survives is the D1 trap.
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.ecs_mode_idx = 0; // (inherit) — but subtree still has v4=24
        let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
        assert!(
            err.contains("clear ecs"),
            "per-field ecs clear must point at the whole-subtree toggle, got: {err}"
        );
    }

    #[test]
    fn resolve_bad_ecs_prefix_returns_err() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.ecs_v4_input = "99".into(); // > 32
        let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
        assert!(err.contains("source_prefix_v4"), "got: {err}");
    }

    // ── Add resolve + lifecycle ───────────────────────────────────────

    #[test]
    fn add_form_rejects_empty_id() {
        let modal = ProfileModal::open_add();
        let err = modal.form().unwrap().try_resolve_add().unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    #[test]
    fn add_form_defaults_display_name_to_id() {
        let mut modal = ProfileModal::open_add();
        modal.form_mut().unwrap().id = "guests".into();
        let (id, dn) = modal.form().unwrap().try_resolve_add().unwrap();
        assert_eq!(id, "guests");
        assert_eq!(dn, "guests");
    }

    #[test]
    fn modal_finish_transitions_to_submitted() {
        let mut modal = ProfileModal::open_add();
        assert!(!modal.is_submitted());
        modal.finish(SubmitOutcome::Ok("done".into()));
        assert!(modal.is_submitted());
    }

    #[test]
    fn remove_modal_carries_reference_summary() {
        let modal = ProfileModal::open_remove("kids", "Kids", "2 devices reference this".into());
        let rc = modal.remove().unwrap();
        assert_eq!(rc.id, "kids");
        assert_eq!(rc.reference_summary, "2 devices reference this");
    }

    #[test]
    fn dropdown_cycle_wraps_both_directions() {
        let mut f = ProfileForm::new_edit("kids", &mk_profile(), vec![]);
        f.focused = FormField::BlockResponse;
        f.block_response_idx = 0;
        f.cycle_dropdown(false); // backward from 0 wraps to last
        assert_eq!(f.block_response_idx, BLOCK_RESPONSE_OPTIONS.len() - 1);
        f.cycle_dropdown(true); // forward wraps back to 0
        assert_eq!(f.block_response_idx, 0);
    }

    #[test]
    fn toggle_flips_only_the_focused_toggle() {
        let mut f = ProfileForm::new_edit("kids", &mk_profile(), vec![]);
        f.focused = FormField::EcsClear;
        assert!(!f.ecs_clear);
        f.toggle();
        assert!(f.ecs_clear);
        assert!(
            f.block_all,
            "block_all (from mk_profile) untouched by EcsClear toggle"
        );
    }

    // ── Archetype-F body (shared modal_form) ──────────────────────────

    /// Flatten the whole body — pinned head, field region and pinned tail
    /// — into one string for content assertions.
    ///
    /// Deliberately NOT what the operator sees: `render_scroll_body` shows
    /// a *window* onto the field region. Every past instance of the clip
    /// defect had a correct line vector and a wrong render, so anything
    /// about visibility is asserted on the buffer, below.
    fn render_text(form: &ProfileForm, width: u16) -> String {
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

    /// §4.61 Wave 2c changed two affordances here, both by archetype:
    /// the grey `Field │ Value` header is replaced by labelled section
    /// bands, and the drawn `_` caret is replaced by the real terminal
    /// cursor (which `form_body` returns a target for, and
    /// `ModalRender::place_cursor` puts on screen).
    #[test]
    fn add_form_renders_section_band_cursor_target_and_actions() {
        let mut modal = ProfileModal::open_add();
        let form = modal.form_mut().unwrap();
        form.id = "kids".into(); // focus defaults to Id on Add
        let text = render_text(form, 70);
        assert!(text.contains("IDENTITY"), "labelled section band:\n{text}");
        assert!(
            !text.contains("Field") && !text.contains("Value"),
            "the legacy grid header is gone:\n{text}"
        );
        assert!(text.contains('◀'), "active row carries the focus marker");
        assert!(text.contains("Save"), "Save action present");
        assert!(text.contains("Discard"), "Discard action present");

        let (_, cursor) = form_body(form, 70);
        assert_eq!(
            cursor,
            Some((2, 4)),
            "the hardware cursor targets the focused row (2 = the section \
             band's header + hairline; §4.65 UX1(c)'s 2 blurb rows that \
             used to sit under them are gone as of 2026-08-07) at the end \
             of `kids`"
        );
    }

    #[test]
    fn grid_edit_focused_dropdown_is_angle_wrapped() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::BlockResponse; // mk_profile → nxdomain
        let text = render_text(form, 70);
        assert!(
            text.contains("‹ nxdomain ›"),
            "a focused dropdown value is wrapped to signal ←/→ cycles it"
        );
    }

    /// The two booleans moved from a `‹ yes ›` selector to a radio row:
    /// both options stay on screen, and each side declares what it *means*
    /// (`block all` = Yes is `Blocking`, No is `Healthy`), so the colour
    /// comes from the value rather than from this module. ←/→ and Space
    /// still flip it — the key handler is untouched (D7′).
    #[test]
    fn edit_toggle_renders_a_two_option_radio() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::BlockAll; // mk_profile block_all = true
        let text = render_text(form, 70);
        assert!(
            text.contains("● Yes") && text.contains("○ No"),
            "the selected side is filled, the other is hollow:\n{text}"
        );
        form.block_all = false;
        let text = render_text(form, 70);
        assert!(
            text.contains("○ Yes") && text.contains("● No"),
            "flipping the value moves the fill:\n{text}"
        );
    }

    #[test]
    fn grid_inline_error_replaces_the_hint_line() {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.error_message = Some("blocked_ttl_secs must be an integer".into());
        let text = render_text(form, 70);
        assert!(text.contains("⚠ blocked_ttl_secs must be an integer"));
        // The hint for the focused field is suppressed while an error pends.
        assert!(!text.contains("human label shown in the table"));
    }

    #[test]
    fn grid_edit_id_is_read_only_without_caret() {
        let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form().unwrap();
        assert_eq!(form.focused, FormField::DisplayName);
        let text = render_text(form, 70);
        assert!(text.contains("kids"), "id value still shown");
        assert!(!text.contains("kids_"), "read-only id carries no caret");
        assert!(
            !text.contains("(read-only)"),
            "dim styling signals read-only, not literal suffix text"
        );
    }

    #[test]
    fn grid_ecs_rows_lose_selector_wrap_when_cleared() {
        // mk_profile → ecs.mode = coarse. Focused + not cleared = angle
        // wrap; focused + `clear ecs` on = read-only (dimmed), no wrap.
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::EcsMode;
        assert!(
            render_text(form, 70).contains("‹ coarse ›"),
            "live ecs mode is a focusable selector"
        );
        form.ecs_clear = true;
        let cleared = render_text(form, 70);
        assert!(cleared.contains("coarse"), "value still shown");
        assert!(
            !cleared.contains("‹ coarse ›"),
            "a cleared ecs row is inert (read-only), so it drops the selector wrap"
        );
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

    /// The override panel at its tallest — every configured list focused
    /// deep in the ring — must not push Save/Discard off the bottom.
    /// Renders the real `render_overlay`, not the line vector, because
    /// every past instance of that defect had a correct vector and a wrong
    /// render.
    ///
    /// Inherits the job the tags-picker version of this test did: it is
    /// the free proof that the Archetype-F body did not lose a property
    /// the flat body had.
    #[test]
    fn render_overlay_keeps_save_discard_visible_with_a_full_list_panel() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Twelve lists, deeper than any viewport this modal ever gets.
        let lists: Vec<Blocklist> = (0..12)
            .map(|i| {
                mk_list(
                    &format!("list-{i:02}"),
                    BlocklistBase::Deny,
                    BlocklistTrust::RemoteUnsigned,
                    false,
                )
            })
            .collect();
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), lists);
        modal.form_mut().unwrap().focused = FormField::ListOverride(11);

        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            dump.contains("list-11"),
            "the focused row must be on screen:\n{dump}"
        );
        assert!(
            dump.contains("Save") && dump.contains("Discard"),
            "the button row must survive a full panel, not be clipped off \
             the bottom:\n{dump}"
        );
    }

    /// The three words a panel row's value column can hold.
    const DIRECTION_WORDS: [&str; 3] = [LIST_POLICY_BLOCK, LIST_POLICY_ALLOW, LIST_POLICY_IGNORE];

    /// Find the rendered row for `id`: the line where the id appears
    /// **left of** a direction word.
    ///
    /// Not "the line contains the id" — a list id appears in the hint
    /// region too (the armed confirm names it, the consent notice names it
    /// twice), and a hint line would satisfy a substring search while
    /// proving nothing about the row. Not a fixed column cut either:
    /// `VALUE_COL` is an offset inside the modal's inner rect, while a
    /// dump line starts at the terminal's left edge — centring margin plus
    /// border — so a cut at 22 lands mid-label, and slicing there by BYTE
    /// would panic on the `\u{2502}` border rather than return `false`.
    ///
    /// Relative order needs no slicing at all: `str::find` returns byte
    /// offsets, and byte order is character order.
    fn panel_row<'a>(dump: &'a str, id: &str) -> &'a str {
        dump.lines()
            .find(|l| {
                let Some(id_at) = l.find(id) else {
                    return false;
                };
                DIRECTION_WORDS
                    .iter()
                    .filter_map(|w| l.find(w))
                    .any(|word_at| id_at < word_at)
            })
            .unwrap_or_else(|| panic!("no panel row for {id:?} in:\n{dump}"))
    }

    /// The value column of a panel row — everything from its direction
    /// word onward, so two rows can be compared without their labels
    /// (which differ by construction) making the comparison vacuous.
    fn panel_value(row: &str) -> &str {
        let at = DIRECTION_WORDS
            .iter()
            .filter_map(|w| row.find(w))
            .min()
            .unwrap_or_else(|| panic!("no direction word in row: {row:?}"));
        row[at..].trim_end()
    }

    /// **DoD 3.** A profile that declares an override on one list and
    /// inherits on another must render the two differently — and the
    /// discriminating case is two rows with the same *effect*.
    ///
    /// `ads` and `social` are both `base = deny`; the profile declares
    /// `deny` on `ads` only. Same word, same colour, same everything the
    /// resolver acts on. If the panel flattens provenance, these two rows
    /// are byte-identical and the operator cannot see which of them
    /// survives a change to the list's `base`.
    ///
    /// Both directions are asserted on purpose. "The declared row omits
    /// the mark" alone passes a build that marks nothing; "the inherited
    /// row carries it" alone passes one that marks everything. Together
    /// they fail a SWAP of the two arms in `list_policy_value`, which is
    /// the mutation a delete-one-arm mutation cannot reach.
    #[test]
    fn declared_and_inherited_are_distinguishable_on_the_same_direction() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let p = Profile {
            lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Deny)]),
            ..mk_profile()
        };
        let modal = ProfileModal::open_edit("kids", &p, mk_lists());
        // Tall enough for the WHOLE body. `render_modal` asks for
        // `head + fields + tail + 2` rows and `centered_rect` clamps that
        // to the anchor, so a terminal merely taller than the 80x24 floor
        // still cuts the last panel rows — this test failed on 40 with the
        // third list one row below the frame.
        let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        let declared = panel_row(&dump, "ads");
        let inherited = panel_row(&dump, "social");

        assert!(
            declared.contains(LIST_POLICY_BLOCK),
            "a declared deny still reads as a deny:\n{dump}"
        );
        assert!(
            !declared.contains(LIST_POLICY_INHERITED.trim()),
            "a declared override must NOT be marked inherited:\n{declared}"
        );
        assert!(
            inherited.contains(LIST_POLICY_BLOCK)
                && inherited.contains(LIST_POLICY_INHERITED.trim()),
            "an inherited deny must say so:\n{inherited}"
        );
        // The point of the pair, stated directly — on the VALUE columns.
        // Comparing whole lines would be vacuous: the labels are `ads` and
        // `social`, so the lines differ whatever the values say.
        assert_ne!(
            panel_value(declared),
            panel_value(inherited),
            "two rows with the same effect and different provenance must \
             not render the same value:\n{dump}"
        );
        // The third row proves the panel reads `base`, not a constant.
        assert!(
            panel_row(&dump, "news").contains(LIST_POLICY_ALLOW),
            "a base = allow list inherits Allow:\n{dump}"
        );
    }

    // ── §4.61 Wave 2c — fail-before evidence (pre-migration) ──────────
    //
    // Two properties of the CURRENT fixed-body modal, pinned before it is
    // migrated so the defect cannot be mis-attributed to the migration.
    // Both assertions invert in the migration commit.

    /// The tab content rect a Filtering leaf gets at the declared 80×24
    /// floor: 24 − 4 header − 5 menu card − 1 footer legend = 14 rows,
    /// leaving the modal **12 interior rows** (§4.61 §4.2).
    const FLOOR_ANCHOR: Rect = Rect {
        x: 0,
        y: 9,
        width: 80,
        height: 14,
    };

    /// **DoD 5, the reachable half.** The armed `ignore` valve has to be
    /// visible, and it has to name the list.
    ///
    /// The valve's state lives on the form and its copy in a const, but
    /// the WIRING is this module's: `list_row_hint` picks the armed branch
    /// and `form_body` hands the result to `rows.field`. Return the
    /// resting hint there instead and every logic test stays green while
    /// the operator presses `i` twice with nothing on screen having asked
    /// them to — the failure mode a mutation run on the Lists surface
    /// already proved this ecosystem dies of.
    #[test]
    fn the_armed_ignore_valve_is_visible_and_names_the_list() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(2); // social
        assert!(!form.press_ignore(), "the first press only arms");

        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            dump.contains("press [i] again"),
            "the confirm must be on screen before the second press:\n{dump}"
        );
        assert!(
            dump.contains("'social'"),
            "the confirm must name the list it will make inert:\n{dump}"
        );
        // Arming writes nothing.
        assert!(
            panel_row(&dump, "social").contains(LIST_POLICY_BLOCK),
            "an armed row still shows its current policy:\n{dump}"
        );
    }

    fn render_at_floor(modal: &ProfileModal) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render_overlay(f, FLOOR_ANCHOR, modal))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// Was `floor_repro_action_row_dies_at_the_d18_budget` — inverted by
    /// the Wave-2c migration. `ScrollBody` allocates the tail *first*, so
    /// the action row survives a budget the fields do not fit in.
    ///
    /// The two things a clip silently takes away are the action row and
    /// the focused field, so both are asserted **together**: a modal that
    /// keeps Save but scrolls the focused row off screen is just as blind.
    /// Every focusable row is checked, because the field set is variable
    /// and a viewport that works for the first row can fail for the last.
    #[test]
    fn floor_edit_keeps_the_action_row_and_the_focused_field_on_screen() {
        for (field, needle) in [
            (FormField::DisplayName, "display name"),
            (FormField::BlockResponse, "block response"),
            (FormField::BlockedTtl, "blocked ttl"),
            (FormField::BlockAll, "block all"),
            (FormField::AdminRules, "admin rules"),
            (FormField::EcsMode, "ecs mode"),
            (FormField::EcsPrefixV4, "ecs prefix v4"),
            (FormField::EcsPrefixV6, "ecs prefix v6"),
            (FormField::EcsClear, "clear ecs"),
            // The list id in the label column, not the word "Lists" —
            // that would also match the section band one row above it.
            (FormField::ListOverride(0), "ads"),
            (FormField::ListOverride(2), "social"),
        ] {
            let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
            modal.form_mut().unwrap().focused = field;
            let dump = render_at_floor(&modal);
            assert!(
                dump.contains("Save") && dump.contains("Discard"),
                "{field:?}: the action row must survive the 12-row \
                 budget:\n{dump}"
            );
            assert!(
                dump.contains(needle),
                "{field:?}: the focused row must be inside the \
                 viewport:\n{dump}"
            );
        }
    }

    /// Was `floor_add_fits_without_scrolling`, and the inversion is the
    /// point of §4.65 UX1(b)+(c).
    ///
    /// Add used to be two fields in a four-row budget, so "no scrollbar
    /// thumb" was a meaningful property and a stray spacer was the whole
    /// risk. It now carries every section Edit has, so it scrolls at the
    /// floor by construction — asserting it does not would be asserting the
    /// modal is shorter than its spec, and the row count is a function of
    /// the spec.
    ///
    /// The budget behind it moved twice and the second move went the other
    /// way: §4.65 UX1(c) spent rows on five two-line blurbs, and 2026-08-07
    /// took them back but spent one on the two-row heading band. Net at the
    /// D18 floor, the field viewport is **2** rows (`12 − 6 tail − 4 head`),
    /// which is why this asserts the focused row and the action row are on
    /// screen *together* rather than counting either alone.
    ///
    /// What survives the change is the property that actually protects the
    /// operator, and it is the one §4.63 S2a+S2c was filed against on the
    /// Devices form: **the action row and the focused field on screen
    /// together**. A form that keeps `Save` while scrolling the row under
    /// the cursor out of view lets an operator commit blind, and so does
    /// the reverse.
    #[test]
    fn floor_add_keeps_the_action_row_and_the_focused_field_on_screen() {
        for (field, needle) in [
            (FormField::Id, "id"),
            (FormField::DisplayName, "display name"),
        ] {
            let mut modal = ProfileModal::open_add();
            modal.form_mut().unwrap().focused = field;
            let dump = render_at_floor(&modal);
            assert!(
                dump.contains("Save") && dump.contains("Discard"),
                "{field:?}: action row visible:\n{dump}"
            );
            assert!(
                dump.contains(needle),
                "{field:?}: the focused row must be inside the \
                 viewport:\n{dump}"
            );
        }
    }

    /// §4.65 UX1(b): the operator asked why Add shows only the name. It now
    /// shows the whole shape of a profile — and every row the Add wire
    /// cannot carry says so instead of taking input it would drop.
    ///
    /// `IpcCommand::ProfileCreate` carries `id` + `display_name` and
    /// nothing else, so a widened focus ring would reproduce §4.64 G4's
    /// defect: a field the operator fills and the submit path discards in
    /// silence. Both halves are asserted — the sections are **there**, and
    /// the ring is **not** widened.
    #[test]
    fn add_shows_every_section_and_offers_none_it_cannot_carry() {
        let modal = ProfileModal::open_add();
        let form = modal.form().unwrap();
        let text = render_text(form, 62);

        for section in ["IDENTITY", "BLOCKING", "POLICY", "ECS"] {
            assert!(
                text.contains(section),
                "Add must show the {section} section:\n{text}"
            );
        }
        for label in [
            "block response",
            "blocked ttl",
            "block all",
            "admin rules",
            "ecs mode",
            "clear ecs",
        ] {
            assert!(text.contains(label), "Add must name {label}:\n{text}");
        }
        assert_eq!(
            text.matches("set after creating").count(),
            8,
            "every row the Add wire cannot carry, and that a later Edit \
             CAN, states when it becomes available:\n{text}"
        );
        // The two Policy rows Edit cannot set either keep Edit's copy: a
        // row that will never be editable here must not promise it will.
        assert_eq!(
            text.matches("read-only here").count(),
            2,
            "local records / rewrite rules are read-only on both forms, \
             so Add must not say they arrive with the next Edit:\n{text}"
        );

        // The ring is what decides whether a value can be typed and lost.
        assert_eq!(
            FormField::ADD_FIELDS,
            [
                FormField::Id,
                FormField::DisplayName,
                FormField::Submit,
                FormField::Cancel,
            ],
            "widening the Add focus ring puts a field in reach that \
             ProfileCreate cannot transport"
        );
    }

    /// §4.68 DoD, **at the floor**: the two description rows are on screen,
    /// they fill the modal interior with `bg_main` `Rgb(15,15,15)` in teal
    /// `Rgb(13,148,136)`, they are NOT on the title's `Rgb(51,51,51)`, and
    /// `Save` / `Discard` survived the head growing by a row.
    ///
    /// Both modes, and Add is the one that decides this lane: it is the
    /// narrowest budget on the surface. At `avail = 12` the tail takes 6
    /// ([`HELP_REGION`]'s 3 rows, banded, plus spacer + keys + actions) and
    /// the head now takes 4, leaving a **2-row** field viewport.
    ///
    /// Asserting the actions is not ceremony. §4.63 S2a+S2c grew the Devices
    /// form without re-deriving this budget and cost it `Save`, `Cancel` and
    /// 9 of 13 fields — while the focus ring still reached the buttons that
    /// were no longer drawn, so the operator could commit blind.
    /// `render_body_fixed` does not wrap and prints no marker where it cuts.
    #[test]
    fn floor_the_description_band_renders_on_its_own_strip_with_the_actions() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        for (mode, modal) in [
            ("Add", ProfileModal::open_add()),
            (
                "Edit",
                ProfileModal::open_edit("kids", &mk_profile(), vec![]),
            ),
        ] {
            let (_, desc) = band_text(modal.form().unwrap());
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| render_overlay(f, FLOOR_ANCHOR, &modal))
                .unwrap();
            println!("--- {mode} ---");
            modal_form::desc_band2_assert::assert_two_row_band(
                term.backend().buffer(),
                desc,
                &["Save", "Discard"],
            );
        }
    }

    /// Replaces `every_section_carries_its_blurb` (§4.65 UX1(c), retired
    /// 2026-08-07): the explanation is in the heading now, once, on both
    /// field sets — and no section under it carries prose of its own.
    ///
    /// The negative half is the load-bearing one. Nine `section_with_blurb`
    /// call sites became `section`, and a missed one would leave a form
    /// that explains itself twice while every positive needle still passes.
    #[test]
    fn the_heading_explains_the_form_and_no_section_repeats_it() {
        for (mode, modal) in [
            ("Add", ProfileModal::open_add()),
            (
                "Edit",
                ProfileModal::open_edit("kids", &mk_profile(), vec![]),
            ),
        ] {
            let form = modal.form().unwrap();
            let text = render_text(form, 62);
            let (_, desc) = band_text(form);

            for line in desc {
                assert!(
                    text.contains(line),
                    "{mode}: description row missing or clipped: \
                     {line:?}\n{text}"
                );
            }
            // The retired blurbs, verbatim. Any one of them back on screen
            // means a `section_with_blurb` call survived the sweep.
            for gone in [
                "The id is what devices and subnets point at",
                "Block response and ttl shape the answer",
                "Admin rules override the lists, for this profile only.",
                "These change what warden reveals to the upstream",
                "Tags are the join to blocklists: a list applies to this",
            ] {
                assert!(
                    !text.contains(gone),
                    "{mode}: a per-section blurb survived: {gone:?}\n{text}"
                );
            }
        }
    }

    /// A description row that outruns the row is clipped at the rect edge
    /// with no marker — `render_body_fixed` does not wrap. The copy is
    /// written to a budget, so the budget is a test rather than a comment.
    ///
    /// Migrated from `no_blurb_line_outruns_the_narrow_build_pass`, whose
    /// budget was **re-derived rather than carried over**: it said "64-column
    /// modal → 62-cell interior → 61 on the scrollbar pass", but this modal
    /// is [`MODAL_W`] = 70. The old constant was a sibling surface's number,
    /// and it was merely too tight rather than too loose — which is the way
    /// that hides. Take the width from the constant, not from a comment.
    #[test]
    fn no_desc_row_outruns_the_narrow_build_pass() {
        // −2 chrome, −1 for the scrollbar column on the narrow pass,
        // −2 for `desc_band2`'s indent.
        const BUDGET: usize = MODAL_W as usize - 5;
        for modal in [
            ProfileModal::open_add(),
            ProfileModal::open_edit("kids", &mk_profile(), vec![]),
        ] {
            let (_, desc) = band_text(modal.form().unwrap());
            for line in desc {
                let n = line.chars().count();
                assert!(n <= BUDGET, "description row is {n} cells: {line:?}");
            }
        }
    }

    /// §4.65 UX1(c): the help region is three rows on a band of its own.
    ///
    /// Asserted on the rendered buffer's **cells**, not on the line vector:
    /// a `Span`'s background paints only its own characters, so a region
    /// built from unpadded lines would carry the right style on a third of
    /// the row and read as a rendering artefact. That is the same defect
    /// `section_band` pads around.
    #[test]
    fn the_help_region_is_three_banded_rows() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Deliberately no assertion on `HELP_REGION` itself: `assert!`
        // short-circuits, so a constant check placed first is the one that
        // fails and the buffer below never runs. The rendered cells ARE
        // the property; the constant is the mechanism.
        let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let buf = term.backend().buffer().clone();

        // The hint's own text locates the region; the two rows under it are
        // its padding, and all three must be banded edge to edge.
        let hint = field_hint(FormField::DisplayName);
        let needle: String = hint.chars().take(20).collect();
        let (x0, y0) = (0..buf.area.height)
            .find_map(|y| {
                let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
                row.find(&needle).map(|i| (i as u16, y))
            })
            .expect("the focused row's hint reaches the help region");

        let bg = buf[(x0, y0)].bg;
        assert_ne!(
            bg,
            buf[(x0, y0 - 1)].bg,
            "the band must be distinct from the row above it"
        );
        for dy in 0..3u16 {
            let y = y0 + dy;
            // Walk the whole interior, not one cell: a half-painted band
            // is exactly what an unpadded line produces.
            for x in x0..(x0 + 40) {
                assert_eq!(
                    buf[(x, y)].bg,
                    bg,
                    "help-region row {dy} is not banded at column {x}"
                );
            }
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test profile_visual_dump -- --ignored --nocapture"]
    fn profile_visual_dump() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        for (name, modal) in [
            ("add", ProfileModal::open_add()),
            (
                "edit",
                ProfileModal::open_edit("kids", &mk_profile(), vec![]),
            ),
        ] {
            let mut term = Terminal::new(TestBackend::new(80, 44)).unwrap();
            term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
            println!(
                "--- {name}, roomy anchor ---\n{}",
                dump_buffer(term.backend().buffer())
            );
            println!(
                "--- {name}, the 80x24 floor ---\n{}",
                render_at_floor(&modal)
            );
        }
    }

    /// Was `floor_repro_modal_is_full_bleed_at_the_floor` — inverted by
    /// the D18 anchor. The overlay now centres inside the tab content
    /// rect, so the header, the menu card and the footer legend keep
    /// their rows (§4.62 N1: nothing transient may occlude them).
    #[test]
    fn floor_modal_stays_inside_the_content_rect() {
        let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![]);
        let dump = render_at_floor(&modal);
        let rows: Vec<&str> = dump.lines().collect();
        for (y, row) in rows.iter().take(FLOOR_ANCHOR.y as usize).enumerate() {
            assert!(
                row.trim().is_empty(),
                "row {y} is above the anchor and must be untouched:\n{dump}"
            );
        }
        assert!(
            rows[23].trim().is_empty(),
            "row 23 is the footer legend's and must be untouched:\n{dump}"
        );
        assert!(
            rows[9].contains('\u{256d}') && rows[22].contains('\u{2570}'),
            "the frame occupies exactly the anchor's 14 rows:\n{dump}"
        );
    }

    /// The viewport follows focus to the LAST field, on both field sets.
    /// In Edit that is the last per-list override row, whose index is the
    /// operator's list count — derived from `visible_fields()` rather than
    /// written down, so a ring that stops splicing panel rows fails here
    /// instead of quietly asserting about `EcsClear`.
    #[test]
    fn viewport_follows_focus_to_the_last_field() {
        let last_add = *FormField::ADD_FIELDS
            .iter()
            .rfind(|f| !matches!(f, FormField::Submit | FormField::Cancel))
            .unwrap();
        assert_eq!(last_add, FormField::DisplayName);
        let mut modal = ProfileModal::open_add();
        modal.form_mut().unwrap().focused = last_add;
        let dump = render_at_floor(&modal);
        assert!(dump.contains("display name"), "Add's last row:\n{dump}");

        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists());
        let last_edit = *modal
            .form()
            .unwrap()
            .visible_fields()
            .iter()
            .rfind(|f| !matches!(f, FormField::Submit | FormField::Cancel))
            .unwrap();
        assert_eq!(last_edit, FormField::ListOverride(2));
        modal.form_mut().unwrap().focused = last_edit;
        let dump = render_at_floor(&modal);
        assert!(
            dump.contains("social"),
            "the focused panel row is on screen:\n{dump}"
        );
        assert!(
            dump.contains("Save"),
            "with the action row still pinned:\n{dump}"
        );
    }
}
