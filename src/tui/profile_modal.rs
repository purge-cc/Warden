//! Profiles tab modals (Add / Edit / Delete).
//!
//! Opens over [`crate::tui::app::Leaf::Profiles`] via `a` (Add), `e`
//! (Edit), `d` / Delete (Remove). Submits through
//! `ProfileCreate` / `ProfileUpdate` / `ProfileDelete` — driven
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

use std::collections::{BTreeMap, BTreeSet};

use crate::config::schema::blocklist::{effective_direction, Blocklist, ListPolicy};
use crate::config::schema::custom_list::CustomList;
use crate::config::schema::{BlockResponseV1, Id, Profile, ProfileEcsConfig};
use crate::config::settings::EcsMode;
use crate::ipc::protocol::{
    AdminRulesPatch, CustomListMountPatch, EcsPatch, ListPolicyPatch, ProfileUpdatePatch,
};

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
/// layer to notice — the silent-unfiltering hazard an accidental
/// `Ignore` would create. `Allow` stays in the cycle: the daemon
/// refuses an unconsented one and says so, and a declared exemption
/// scoped to one profile is a *narrow* form of that exemption a
/// blanket toggle could not express.
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

/// The word a mounted custom-list row shows.
///
/// **Not a word this panel coins.** `mounted` is already the product's
/// term for the same relation on three neighbouring surfaces — the
/// Profiles detail panel's zero case
/// ([`PROFILE_CUSTOM_LISTS_NONE`](crate::tui::tabs::profiles::PROFILE_CUSTOM_LISTS_NONE)),
/// the Custom Lists leaf's `[m]` key legend, and that leaf's own blurb.
/// An operator who has read any of them must not have to learn a second
/// word here for what they already understand.
pub const CUSTOM_LIST_MOUNTED: &str = "mounted";

/// The checkbox a custom-list row leads with.
///
/// A checkbox and not the sibling panel's word-per-state, because the
/// states are two rather than three and there is no direction to name:
/// what a custom list does to a domain is written on the domain's own
/// line inside the pack. `[ ]` is left bare — the empty box already says
/// "not here", and a second word saying it would be the only row on this
/// form that spells out an absence.
pub const CUSTOM_LIST_BOX_ON: &str = "[x]";
/// The unmounted half of [`CUSTOM_LIST_BOX_ON`].
pub const CUSTOM_LIST_BOX_OFF: &str = "[ ]";

/// Shown in place of the mount panel when the config declares no
/// `[[custom_lists]]` at all.
///
/// Mirrors [`LIST_PANEL_EMPTY`] in shape and points at the leaf that can
/// fix it, because an empty panel that does not say where lists come from
/// leaves the operator with nothing to do and nowhere to go.
pub const CUSTOM_LIST_PANEL_EMPTY: &str = "add one on the Custom Lists tab";

/// The resting hint under a focused custom-list row.
///
/// Names the consequence rather than the mechanic: an operator reading
/// "mounts" learns a verb, an operator reading "its rules apply to this
/// profile" learns what changes for the devices pointing here.
pub const CUSTOM_LIST_MOUNT_HINT: &str =
    "\u{2190}/\u{2192} or Space \u{2014} mounted means this list's rules apply to this profile";

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
/// refusal CLAUDE.md §Neutrality records this repo already paying for once.
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
    /// **This replaced `FormField::Tags`, and the replacement is load-
    /// bearing.** The chip picker that used to sit here read
    /// `profile.tags`, a field that decided which lists a profile
    /// enforced under the tag model and decides nothing under the
    /// per-list policy model. It rendered inert history wearing a
    /// control's clothes: the operator could edit it and the submit
    /// path refused the change.
    ///
    /// **Why one focus target per list rather than one for the panel.**
    /// A single target holding N rows would have to window them itself,
    /// and this modal's field viewport is **2 rows** at the 80×24 floor
    /// (see the row-budget note in [`form_body`]) — so the panel would be
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
    /// One row of the custom-list mount panel — the index into
    /// [`ProfileForm::custom_lists_snapshot`], which is the
    /// `[[custom_lists]]` vector captured at modal-open time.
    ///
    /// **Binary where [`Self::ListOverride`] is three-state, and the
    /// asymmetry belongs to the model rather than to this form.** A
    /// blocklist has a `base` every profile inherits, so an absent key
    /// there means *inherit* and a third token is needed to say *off*. A
    /// custom list inherits nothing: `Profile::custom_lists` is presence
    /// or absence. Nor is there a direction to declare at this level —
    /// each rule inside the pack carries its own.
    ///
    /// One focus target per list, for the reason [`Self::ListOverride`]
    /// gives: `render_scroll_body` already anchors the focused row and
    /// scrolls the rest, which a single target holding N rows would have
    /// to reimplement against a 2-row viewport.
    CustomListMount(usize),
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
    /// lists sit above them — `Ctrl+S` also saves from anywhere, so
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
    /// is the class of bug that once cost a false negative on a security
    /// warning elsewhere in this crate.
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
    /// The `[[custom_lists]]` the config declares, captured at modal-open
    /// time and ordered by id.
    ///
    /// Snapshotted and sorted for the same two reasons as
    /// [`Self::lists_snapshot`]: the running config can be reloaded under
    /// the modal's lifetime, and this panel is a focus ring indexed by
    /// position, so a vector that re-ordered itself mid-edit would move
    /// the operator's cursor onto a different list than the one they were
    /// looking at.
    ///
    /// Whole [`CustomList`] values rather than bare ids because the row
    /// reads the id and the display name from the same value the config
    /// carries — a projection built here would be a second copy to keep
    /// in step.
    pub custom_lists_snapshot: Vec<CustomList>,
    /// The draft of `profiles.<id>.custom_lists` this form is editing.
    /// Seeded from the profile's existing mounts in [`Self::new_edit`].
    ///
    /// A set, not a map: mounting is presence. Seeded for the reason
    /// [`Self::lists_draft`] spells out — seeded empty, the diff in
    /// [`resolve_edit_patch`] would read every existing mount as removed,
    /// and a save that changed the display name would unmount every list
    /// the profile had.
    pub custom_lists_draft: BTreeSet<Id>,
    /// The [`ListPolicy::Ignore`] valve — the panel row index whose
    /// declaration is armed and awaiting its second `i`.
    ///
    /// `ignore` is reachable from the TUI (it is a state the CLI accepts,
    /// and a state only reachable from one surface recreates a
    /// TUI/CLI capability split) but never from a bare arrow:
    /// making a list inert is silent unfiltering. Same two-press register
    /// the tag picker used for `tags_pending_new`, so the idiom is one
    /// the operator has already met on this form.
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
    /// `profiles.<id>.custom_lists` as the file had it at open time.
    /// Diffed against [`ProfileForm::custom_lists_draft`] to build the
    /// [`CustomListMountPatch`] delta.
    ///
    /// A set where the schema field is a `Vec`, because the only question
    /// asked of it is membership. Ordering survives the round trip anyway:
    /// the patch names only what changed, so the handler leaves the
    /// untouched entries where they were.
    pub custom_lists: BTreeSet<Id>,
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
            custom_lists_snapshot: Vec::new(),
            custom_lists_draft: BTreeSet::new(),
            ignore_armed: None,
            error_message: None,
        }
    }

    /// Pre-filled form for `Edit`, capturing the original snapshot. The
    /// `id` is carried for display but is not editable. `lists_snapshot`
    /// is the `[[blocklists]]` vector the override panel reads and
    /// `custom_lists_snapshot` the `[[custom_lists]]` vector the mount
    /// panel reads (see their field docs); the caller sorts both by id so
    /// the panels' row order is stable across reloads.
    ///
    /// **Both catalogues are parameters, while the two drafts are read off
    /// `profile`.** What a profile declares travels with the profile; what
    /// it can declare *about* is the config's, and this form has no
    /// business reaching for it.
    pub fn new_edit(
        id: &str,
        profile: &Profile,
        lists_snapshot: Vec<Blocklist>,
        custom_lists_snapshot: Vec<CustomList>,
    ) -> Self {
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
            custom_lists: profile.custom_lists.iter().cloned().collect(),
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
            custom_lists_draft: snapshot.custom_lists.clone(),
            custom_lists_snapshot,
            ignore_armed: None,
            error_message: None,
            original: Some(snapshot),
        }
    }

    /// The mode-specific ordered field ring for focus navigation.
    ///
    /// Owned rather than `&'static [FormField]`: in Edit mode the ring
    /// splices one [`FormField::ListOverride`] per configured blocklist
    /// and one [`FormField::CustomListMount`] per declared custom list
    /// between [`FormField::EDIT_HEAD`] and [`FormField::EDIT_TAIL`], and
    /// both counts are the operator's. A config with **zero** of either
    /// yields that panel no rows, which the ring handles without a special
    /// case — nothing indexes a snapshot here.
    ///
    /// The mount rows come **after** the override rows, matching the order
    /// the body renders them in. The ring and the body have to agree:
    /// `render_scroll_body` scrolls to the focused field by its position
    /// among the rendered rows, so a ring that ordered the two panels
    /// differently would scroll to the wrong one.
    pub fn visible_fields(&self) -> Vec<FormField> {
        match self.mode {
            FormMode::Add => FormField::ADD_FIELDS.to_vec(),
            FormMode::Edit => FormField::EDIT_HEAD
                .iter()
                .copied()
                .chain((0..self.lists_snapshot.len()).map(FormField::ListOverride))
                .chain((0..self.custom_lists_snapshot.len()).map(FormField::CustomListMount))
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
            | FormField::CustomListMount(_)
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
            | FormField::CustomListMount(_)
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
            // NOT routed here even though it is a two-state control: a
            // mount row lives in its own snapshot, so `toggle` would have
            // to learn a second index space. `toggle_custom_list_mount` is
            // the one mutator, and the dispatch names it explicitly.
            | FormField::CustomListMount(_)
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

    /// The mount-panel row index the focus is on, if any.
    ///
    /// Bounds-checked against the snapshot for the same reason its
    /// blocklist sibling is: the index rides in the [`FormField`] value,
    /// so a stale focus outliving a shorter snapshot would index out of
    /// range rather than simply miss.
    pub fn focused_custom_list_row(&self) -> Option<usize> {
        match self.focused {
            FormField::CustomListMount(i) if i < self.custom_lists_snapshot.len() => Some(i),
            _ => None,
        }
    }

    /// Whether the draft mounts `list` on this profile.
    pub fn mounts(&self, list: &CustomList) -> bool {
        self.custom_lists_draft.contains(&list.id)
    }

    /// Flip the focused mount row.
    ///
    /// One gesture with no confirmation, unlike the `ignore` valve on the
    /// panel above: unmounting narrows what this profile applies and the
    /// row keeps showing the state that gets saved, so there is no silent
    /// outcome to deliberate over. Mounting is the widening direction, and
    /// it is gated where it can be — the daemon refuses a mount naming a
    /// list no `[[custom_lists]]` declares.
    pub fn toggle_custom_list_mount(&mut self) {
        let Some(i) = self.focused_custom_list_row() else {
            return;
        };
        // Spends an armed `ignore` for the reason `cycle_list_policy`
        // spends it: this is a different decision, and a confirmation that
        // survives one is a confirmation the operator can spend without
        // having meant to.
        self.ignore_armed = None;
        let id = self.custom_lists_snapshot[i].id.clone();
        if !self.custom_lists_draft.remove(&id) {
            self.custom_lists_draft.insert(id);
        }
    }

    /// A throwaway [`Profile`] carrying the draft override map and nothing
    /// else, so the panel can ask [`effective_direction`] its question
    /// instead of answering it.
    ///
    /// [`effective_direction`] reads exactly one field, so every other
    /// value here is inert — and routing through it is the point. The
    /// arithmetic is two lines long and utterly tempting to inline, which
    /// is precisely how a past `effective_tags` bug ended up computed in
    /// two places that answered differently: the validator saw a
    /// superset and went silent about devices the resolver really did
    /// leave uncovered.
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

    // display_name — plain Option<String>, set only if changed. Blank
    // input means "use the id" — the field's own placeholder promises
    // this ("blank = the id"), mirroring `ProfileForm::try_resolve_add`.
    // Both sides of the diff are normalised through that same rule before
    // comparing: a real on-disk profile can itself carry a blank
    // display_name (`#[serde(default)]`), so comparing the substituted
    // buffer against the RAW original would misread an untouched,
    // already-blank field as an edit — pure navigation would synthesize a
    // patch. Normalising both sides also folds the mirror case: blanking
    // a field whose stored value already equals the id is a no-op, not a
    // write of the same bytes back.
    let dn = form.display_name.trim();
    let dn = if dn.is_empty() { orig.id.as_str() } else { dn };
    let orig_dn = if orig.display_name.is_empty() {
        orig.id.as_str()
    } else {
        orig.display_name.as_str()
    };
    if dn != orig_dn {
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

    // custom_lists — CustomListMountPatch SET delta (mount/remove vs the
    // snapshot).
    //
    // A set delta where `lists` above needs a map, and for the reason the
    // wire type states: mounting is presence, so there is no third state
    // for a set to lose.
    //
    // Diffed against the SNAPSHOT, not the config, exactly as `lists` is:
    // `custom_lists_draft` is seeded from the snapshot in `new_edit`, so a
    // profile opened and closed untouched produces both halves empty and
    // the whole field stays `None`. Seeding the draft empty would make
    // this unmount every list the profile had.
    let mount: Vec<String> = form
        .custom_lists_draft
        .iter()
        .filter(|list_id| !orig.custom_lists.contains(*list_id))
        .map(|list_id| list_id.as_str().to_string())
        .collect();
    let unmount: Vec<String> = orig
        .custom_lists
        .iter()
        .filter(|list_id| !form.custom_lists_draft.contains(*list_id))
        .map(|list_id| list_id.as_str().to_string())
        .collect();
    if !mount.is_empty() || !unmount.is_empty() {
        patch.custom_lists = Some(CustomListMountPatch { mount, unmount });
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
    /// override panel reads and `custom_lists_snapshot` the
    /// `[[custom_lists]]` vector the mount panel reads — see the matching
    /// fields on [`ProfileForm`].
    ///
    /// Both catalogues are required rather than defaulted, deliberately:
    /// an omitted snapshot renders as "none declared", which is
    /// indistinguishable from a config that really declares none. A caller
    /// that could forget one would show an empty panel over a config with
    /// three entries.
    pub fn open_edit(
        id: &str,
        profile: &Profile,
        lists_snapshot: Vec<Blocklist>,
        custom_lists_snapshot: Vec<CustomList>,
    ) -> Self {
        Self {
            stage: Stage::EditingForm(ProfileForm::new_edit(
                id,
                profile,
                lists_snapshot,
                custom_lists_snapshot,
            )),
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
/// this surface used before the migration: chrome, layout and colour
/// change, keying does not.
///
/// The action row bakes its own key into each button's label
/// (`[Esc] Discard` / `[Enter] Save`), so a blanket "Enter save · Esc
/// cancel" here would be a second, redundant source of the same fact.
const FORM_KEYS: &str = "↹/↑↓ move · ←/→ change";

/// Draw the modal as an overlay centred on the active tab's **content
/// rect** so the header, the menu card and the footer legend
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
/// A two-line blurb once sat under **each** of the five sections. The
/// operator's report after living with it was that the form now
/// explained itself five times to someone who had understood it once,
/// so the explaining moved into the heading instead: one description, on
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
    // The minimum-terminal floor budget, re-derived from scratch — the
    // number this comment carried before was wrong, which is why it is
    // spelled out rather than cited.
    //
    // It read "12 − 3 head − 5 tail", i.e. 4 interior rows. That `5` is the
    // DEFAULT tail (`TailNote::default()`, `HINT_ROWS = 2`), and this modal
    // has not used it since it gave itself its own `HELP_REGION`
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

    // ── CUSTOM LISTS ──────────────────────────────────────────────────
    //
    // The mount panel — one focusable row per declared `[[custom_lists]]`,
    // showing whether this profile mounts it. Same grid, same value column
    // and the same `\u{2039} \u{203a}` focus vocabulary as the panel above,
    // because to the operator these are two answers to one question: what
    // does this profile filter with?
    //
    // Below the override panel rather than above it: a blocklist is the
    // subscription every profile starts from, a custom list the exception
    // the operator wrote afterwards.
    rows.spacer();
    rows.section("Custom lists");
    if form.custom_lists_snapshot.is_empty() {
        // Not a focus target, for the reason the sibling empty state gives:
        // a ring entry that answers no key offers input it drops on the
        // floor.
        rows.line(modal_form::state_row(
            "custom lists",
            "none declared",
            ValueKind::Caution,
            CUSTOM_LIST_PANEL_EMPTY,
            width,
        ));
    } else {
        for (i, list) in form.custom_lists_snapshot.iter().enumerate() {
            let row_focus = focus == FormField::CustomListMount(i);
            let mounted = form.custom_lists_draft.contains(&list.id);
            let value = mount_value(mounted);
            let shown = if row_focus {
                // Fit the value FIRST, for the reason the override panel
                // spells out: `value_row` windows a focused value from the
                // TAIL, so an overrun would eat the opening marker — the
                // one glyph that says a key changes this row.
                let inner = modal_form::fit(
                    &value,
                    modal_form::value_budget(width, true).saturating_sub(4),
                );
                format!("\u{2039} {inner} \u{203a}")
            } else {
                value
            };
            rows.field(
                modal_form::value_row(
                    list.id.as_str(),
                    &shown,
                    row_focus,
                    mount_value_kind(mounted),
                    None,
                    width,
                ),
                row_focus,
                CUSTOM_LIST_MOUNT_HINT,
            );
        }
    }

    let tail = form_tail_for(&rows, form);
    rows.finish(tail)
}

/// The checkbox (and word) a mount row shows.
fn mount_value(mounted: bool) -> String {
    if mounted {
        format!("{CUSTOM_LIST_BOX_ON} {CUSTOM_LIST_MOUNTED}")
    } else {
        CUSTOM_LIST_BOX_OFF.to_string()
    }
}

/// Colour for a mount row's value: what the value **is**, per
/// `modal_form::ValueKind`'s rule.
///
/// [`ValueKind::Healthy`] names "allow" on the override panel above, and
/// here it names *active* — the other half of what that kind already
/// covers. The two cannot be confused on the same form because a mount row
/// never shows a direction word: a custom list has no direction, each rule
/// inside the pack carries its own.
///
/// Unmounted takes [`ValueKind::Editable`]'s recessive grey for the reason
/// an ignored blocklist does — an inert row is not a warning, it is an
/// absence, and it must read as neither the active state nor an error.
fn mount_value_kind(mounted: bool) -> ValueKind {
    if mounted {
        ValueKind::Healthy
    } else {
        ValueKind::Editable
    }
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
/// (`ipc::socket_server`), and a second copy here would be exactly the
/// class of two-copies-disagree bug this crate has already paid for
/// once. What it buys is that the
/// operator learns *before* spending a save, and — this is the part that
/// matters — learns the one action that actually works.
///
/// It is conditioned on the row's **pending** policy being `Allow`, not on
/// the list being unsigned. `BlocklistTrust` defaults to `RemoteUnsigned`,
/// and every `[[blocklists]]` row on both live hosts omits the key, so an
/// unconditional notice would fire on every row of every profile. A hint
/// that is always on is a hint nobody reads — the failure mode CLAUDE.md
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
/// named, **none of them offered**.
///
/// ## Why these are inert and not editable
///
/// `IpcCommand::ProfileCreate { id, display_name, token }` is the whole Add
/// wire (`ipc/protocol.rs`). Eight of Edit's eleven fields have no transport
/// on it, and the only routes to one are a protocol change or a
/// non-atomic create-then-update — neither of which belongs in this
/// leaf's layout.
///
/// So the operator's report ("Add opens only the name field") is answered
/// by showing the **shape** of a profile rather than by widening the focus
/// ring. `FormField::ADD_FIELDS` deliberately still holds four entries:
/// putting `BlockResponse` in the ring would give the operator a field to
/// fill that the submit path drops on the floor in silence — the same
/// class of defect once fixed on the Devices form, where Promote
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

/// This modal's help region: three rows on a band of their own.
///
/// **Per-call, not an edit to [`modal_form::HINT_ROWS`].** The constant is
/// shared by every Archetype-F modal in `src/tui/` — Lists edit, Rules
/// edit, Subnets, Local DNS, Devices — so raising it here to 3 would have
/// resized the tail on six surfaces at once, each needing its own
/// minimum-terminal-floor re-verified. That is the blast radius that
/// once cost the Devices form its `Save`, `Cancel` and 9 of 13 fields
/// when its head grew without re-deriving that budget.
///
/// Three rows because this form's hints are the longest in the ecosystem —
/// `EcsClear`'s runs 98 characters against a ~60-cell row, so at
/// [`modal_form::HINT_ROWS`] it was ellipsised mid-sentence on the one
/// field whose guidance carries a hard limitation. The band is what
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
        // A single `&'static str` covers every mount row: unlike the
        // override panel's, this hint has no per-list variant to name — a
        // mount has nothing to warn about and nothing to confirm.
        FormField::CustomListMount(_) => CUSTOM_LIST_MOUNT_HINT,
        FormField::Submit => "Enter saves every change atomically",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The remove confirm as an Archetype-C notice.
///
/// No [`Action`]s: the operator answers with `y` / `n`, which `Tab` never
/// reaches, so a rendered button would advertise a focus target that does
/// not exist. The keys legend carries the whole input contract, and
/// the chrome loses the `brand_red` border it drew before — red is the
/// title tick and the destructive copy, never a border.
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
/// no longer a sentence. The per-profile
/// override write sits behind a daemon consent gate whose refusal
/// (`IPC_ERROR_OVERRIDE_ALLOW_NEEDS_CONSENT`) is ~590 characters and ends
/// with the verb that fixes it. At 2 rows the operator reads the first
/// ~120 characters — the problem, none of the answer.
///
/// That is not an edge case here. `BlocklistTrust` defaults to
/// `RemoteUnsigned` and every `[[blocklists]]` row on both live hosts
/// omits the key, so the *first* allow override an operator tries is the
/// one that gets refused. A refusal whose recovery is cut off is the
/// unsatisfiable-in-its-own-terms defect CLAUDE.md §Neutrality records.
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
#[path = "tests/profile_modal_tests.rs"]
mod tests;
