//! Sprint 43 T5 — TUI scope modal opened from the Query Log tab.
//! Sprint 47 T2 retired the `a` / `d` keybindings and rewired the
//! entry surface to a single `Enter` press (auto-flips Allow vs Deny
//! based on the focused row's `result` status).
//!
//! Renders the SN1 5-entry menu, walks the operator through SN2's
//! tiered confirmation (single keypress for device, typed scope-id for
//! profile / group / subnet, typed `DEFAULT` for default), and submits
//! through `cli::commands::rules::add_inner` — the same R7 single-seat
//! mutation surface used by the CLI verbs. No new IPC verbs.
//!
//! ## State machine
//!
//! ```text
//! Menu  ──Enter──▶ DeviceConfirm ──[y]──▶ Submitted(Ok|Err)
//!     │                          ──[n/Esc]──▶ Menu
//!     ├──▶ TypedConfirm    ──Enter (id matches)──▶ Submitted(...)
//!     │                    ──Esc──▶ Menu
//!     ├──▶ DefaultConfirm  ──Enter (typed "DEFAULT")──▶ Submitted(...)
//!     │                    ──Esc──▶ Menu
//!     └──Esc──▶ closed
//! ```
//!
//! ## Capture-at-render-time invariant (T3 §14.3 pitfall lineage)
//!
//! When `Enter` is pressed, the keyhandler reads the highlighted row's
//! `domain` + `client` directly off the in-memory `query_log.entries`
//! slice — **NOT** by re-tailing the file. The row may scroll out
//! before the operator finishes typing the confirm; the captured
//! snapshot is the source of truth from that moment forward.

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::cli::commands::rules::{
    Action, Scope, RULES_BATCH_DEFAULT_CONFIRM, RULES_BATCH_TYPE_CONFIRM,
};
use crate::tui::modal_form::{
    self, ActionKind, ChoiceNote, ChoiceRow, NoticeSpec, ProseRow, ValueKind,
};

/// Sprint 47 T1 — map a Query Log row's `result` string to the inverse
/// rule action the operator most likely wants from a single keypress.
///
/// `BLOCKED` → `Some(Action::Allow)` (operator is whitelisting).
/// `ALLOWED` / `CACHED` / `STALE` → `Some(Action::Deny)` (blocklist).
/// `LOCAL` / `REFUSED` / `HINFO` / unknown → `None` (status is not
/// actionable from the Query Log; T2's Enter handler surfaces a
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
/// See `_docs/features/query_log_quick_action_ux.md` §3 for the full table.
pub fn inferred_action(result: &str) -> Option<Action> {
    match result {
        "BLOCKED" => Some(Action::Allow),
        "ALLOWED" | "CACHED" | "STALE" => Some(Action::Deny),
        _ => None,
    }
}

/// Indices of the 5 SN1 menu entries — used by the keyhandler so the
/// match arms can read like the design doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMenuEntry {
    Device,
    Profile,
    Group,
    Subnet,
    Default,
}

impl ScopeMenuEntry {
    pub const ALL: [Self; 5] = [
        Self::Device,
        Self::Profile,
        Self::Group,
        Self::Subnet,
        Self::Default,
    ];

    pub fn from_index(idx: usize) -> Option<Self> {
        Self::ALL.get(idx).copied()
    }

    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|&e| e == self)
            .expect("variant is in ALL")
    }
}

/// Where the modal's state machine currently sits. Keys behave
/// differently per stage; the renderer also branches on this.
#[derive(Debug, Clone)]
pub enum ScopeStage {
    /// Pick one of the 5 SN1 entries. `j/k/↑/↓` move; Enter advances.
    Menu,
    /// Single keypress confirm for device scope (SN2 tier 1).
    DeviceConfirm,
    /// Typed scope-id confirm (SN2 tier 2). Operator types the entity
    /// id and presses Enter.
    TypedConfirm {
        chosen: ScopeMenuEntry,
        buffer: String,
    },
    /// Typed `DEFAULT` confirm (SN2 tier 3). The 5-second cooldown
    /// progress bar is parked — Enter on a non-empty buffer that
    /// matches `DEFAULT` exactly submits.
    DefaultConfirm { buffer: String },
    /// Final state — the modal renders the success or error message
    /// then closes on the next keypress.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

/// State bag for the modal lifecycle. Cleared (`= None`) when the
/// modal closes.
#[derive(Debug, Clone)]
pub struct ScopeModal {
    pub action: Action,
    /// Domain captured at row-render time — already non-empty (we open
    /// the modal only when the focused row carries one).
    pub domain: String,
    /// Display string of the matched device (or the source IP fallback).
    /// Surfaced in the modal header for operator orientation.
    pub captured_client: String,
    /// Device id resolved from the captured client, or `None` if the
    /// row's source IP did not map to a known device. When `None`, the
    /// "Just this device" entry is hidden / disabled.
    pub captured_device_id: Option<String>,
    /// Optional pre-filled profile id for entry 2 (resolved from the
    /// captured client's `Resolution`). When `None`, the entry is
    /// disabled and the cursor skips it — the operator cannot pick
    /// "all devices on profile X" without a known X.
    pub captured_profile_id: Option<String>,
    /// Optional pre-resolved group id for entry 3 — the highest-priority
    /// group the captured device belongs to (DM2). `None` when the
    /// device has no group memberships, or when no device matched the
    /// row at all. Disables entry 3.
    pub captured_group_id: Option<String>,
    /// Optional pre-resolved subnet id for entry 4 — the subnet whose
    /// CIDR contains the captured client's IP (longest-prefix match,
    /// SN1). `None` when no subnet matches the client IP. Disables
    /// entry 4.
    pub captured_subnet_id: Option<String>,
    pub menu_cursor: usize,
    pub stage: ScopeStage,
    /// Why the last Enter on a confirm stage did not submit, or `None`
    /// when there is nothing to say. Rides the [`NoticeSpec::error`]
    /// slot, which sits in the pinned tail and displaces the hint — so
    /// it costs no prose row and cannot push the typed line off screen.
    ///
    /// Cleared by every keystroke that changes the buffer and by every
    /// stage transition: a rejection describes one buffer, and a stale
    /// one contradicting what is now on screen is worse than silence.
    pub error: Option<String>,
}

impl ScopeModal {
    /// Open a fresh modal with `action` (Allow or Deny) for the given
    /// row data captured from the Query Log.
    pub fn open(
        action: Action,
        domain: String,
        captured_client: String,
        captured_device_id: Option<String>,
        captured_profile_id: Option<String>,
        captured_group_id: Option<String>,
        captured_subnet_id: Option<String>,
    ) -> Self {
        // Default cursor: first enabled entry in design-doc order
        // (Device → Profile → Group → Subnet → Default). Default is
        // always enabled, so the search always terminates.
        let mut menu_cursor = ScopeMenuEntry::Default.index();
        for entry in ScopeMenuEntry::ALL {
            if !is_entry_disabled(
                entry,
                captured_device_id.is_some(),
                captured_profile_id.is_some(),
                captured_group_id.is_some(),
                captured_subnet_id.is_some(),
            ) {
                menu_cursor = entry.index();
                break;
            }
        }
        Self {
            action,
            domain,
            captured_client,
            captured_device_id,
            captured_profile_id,
            captured_group_id,
            captured_subnet_id,
            menu_cursor,
            stage: ScopeStage::Menu,
            error: None,
        }
    }

    /// Sprint 47 T1 — fallible smart constructor that builds a modal
    /// pre-configured for a Query Log row. Returns `None` when the
    /// row's status is not actionable (LOCAL DNS records, REFUSED /
    /// HINFO upstream rejections, unknown future statuses); T2's
    /// Enter handler surfaces a `last_error` message in that case.
    ///
    /// The action is auto-flipped via [`inferred_action`] so the
    /// operator never has to pick allow vs deny manually — the row's
    /// current state determines the only sensible action.
    pub fn open_for_query_row(
        entry: &crate::ipc::protocol::QueryLogDto,
        captured_client: String,
        captured_device_id: Option<String>,
        captured_profile_id: Option<String>,
        captured_group_id: Option<String>,
        captured_subnet_id: Option<String>,
    ) -> Option<Self> {
        let action = inferred_action(&entry.result)?;
        Some(Self::open(
            action,
            entry.domain.clone(),
            captured_client,
            captured_device_id,
            captured_profile_id,
            captured_group_id,
            captured_subnet_id,
        ))
    }

    /// Whether `entry` is currently unselectable — the captured row
    /// data does not resolve to a target the operator could confirm.
    /// Sprint 48: extended from "only Device" to all four resolved
    /// entries (Device / Profile / Group / Subnet). Default is always
    /// enabled. Used by [`Self::move_cursor`], [`Self::enter_confirm`]
    /// and the renderer's disabled-style branch.
    pub fn is_disabled(&self, entry: ScopeMenuEntry) -> bool {
        is_entry_disabled(
            entry,
            self.captured_device_id.is_some(),
            self.captured_profile_id.is_some(),
            self.captured_group_id.is_some(),
            self.captured_subnet_id.is_some(),
        )
    }

    /// Move the menu cursor up or down, skipping any disabled entry
    /// (Sprint 48: extended beyond Device — Profile / Group / Subnet
    /// also skipped when their captured id is `None`).
    pub fn move_cursor(&mut self, delta: i32) {
        if !matches!(self.stage, ScopeStage::Menu) {
            return;
        }
        let len = ScopeMenuEntry::ALL.len() as i32;
        let mut next = self.menu_cursor as i32 + delta;
        for _ in 0..len {
            if next < 0 {
                next = len - 1;
            }
            if next >= len {
                next = 0;
            }
            let entry = ScopeMenuEntry::from_index(next as usize).unwrap();
            if !self.is_disabled(entry) {
                self.menu_cursor = next as usize;
                return;
            }
            next += delta.signum();
        }
    }

    /// Try to advance from the menu stage to the appropriate confirm
    /// stage. Returns `None` when the focused entry is disabled.
    pub fn enter_confirm(&mut self) -> Option<ScopeMenuEntry> {
        if !matches!(self.stage, ScopeStage::Menu) {
            return None;
        }
        let entry = ScopeMenuEntry::from_index(self.menu_cursor)?;
        if self.is_disabled(entry) {
            return None;
        }
        self.stage = match entry {
            ScopeMenuEntry::Device => ScopeStage::DeviceConfirm,
            ScopeMenuEntry::Default => ScopeStage::DefaultConfirm {
                buffer: String::new(),
            },
            other => ScopeStage::TypedConfirm {
                chosen: other,
                buffer: String::new(),
            },
        };
        self.error = None;
        Some(entry)
    }

    /// The pre-resolved id `entry` would submit against, or `None` for
    /// the two entries that carry no typed id (Device confirms with a
    /// keypress, Default with the literal `DEFAULT`).
    ///
    /// The single source of truth for entry → id. [`Self::ready_to_submit`]
    /// gates on it, [`typed_confirm_notice`] prints it and
    /// [`Self::note_failed_submit`] names it in the rejection — three
    /// readers that must agree by construction. They did not before: the
    /// gate held its own `match` and the renderer had none, so the confirm
    /// screen demanded an id it never showed.
    pub fn chosen_scope_id(&self, entry: ScopeMenuEntry) -> Option<&str> {
        match entry {
            ScopeMenuEntry::Profile => self.captured_profile_id.as_deref(),
            ScopeMenuEntry::Group => self.captured_group_id.as_deref(),
            ScopeMenuEntry::Subnet => self.captured_subnet_id.as_deref(),
            ScopeMenuEntry::Device | ScopeMenuEntry::Default => None,
        }
    }

    /// Push a character into the typed-confirm buffer. No-op outside
    /// typed-confirm stages.
    pub fn push_char(&mut self, c: char) {
        match &mut self.stage {
            ScopeStage::TypedConfirm { buffer, .. } | ScopeStage::DefaultConfirm { buffer } => {
                buffer.push(c);
                self.error = None;
            }
            _ => {}
        }
    }

    /// Backspace handler.
    pub fn backspace(&mut self) {
        match &mut self.stage {
            ScopeStage::TypedConfirm { buffer, .. } | ScopeStage::DefaultConfirm { buffer } => {
                buffer.pop();
                self.error = None;
            }
            _ => {}
        }
    }

    /// Step from any confirm stage back to the menu (Esc).
    pub fn back_to_menu(&mut self) {
        if matches!(
            self.stage,
            ScopeStage::DeviceConfirm
                | ScopeStage::TypedConfirm { .. }
                | ScopeStage::DefaultConfirm { .. }
        ) {
            self.stage = ScopeStage::Menu;
            self.error = None;
        }
    }

    /// Record why an Enter on a confirm stage did not submit.
    ///
    /// Called from the key handler's not-ready branch, which used to
    /// re-stash the modal untouched: the exact-match gate would reject
    /// the buffer and nothing on screen changed, so Enter read as a dead
    /// key. An empty buffer is *not* an error — the operator has not
    /// typed anything yet — so that case clears instead, and Enter stays
    /// quiet until there is something to reject.
    pub fn note_failed_submit(&mut self) {
        let err = match &self.stage {
            ScopeStage::TypedConfirm { chosen, buffer } if !buffer.trim().is_empty() => {
                match self.chosen_scope_id(*chosen) {
                    // Name the id rather than saying "does not match":
                    // the operator is looking at the value they must
                    // reproduce, and a rejection that repeats it turns a
                    // dead end into a one-keystroke correction.
                    Some(id) => Some(format!("that is not '{id}' \u{2014} type the id exactly")),
                    // Unreachable in practice: `enter_confirm` refuses a
                    // disabled entry and an entry without an id is
                    // disabled. Still stated, because the silent branch
                    // is the failure mode this method exists to remove.
                    None => Some("this scope has no id to confirm against".to_string()),
                }
            }
            ScopeStage::DefaultConfirm { buffer } if !buffer.trim().is_empty() => {
                Some("type DEFAULT in capitals to confirm".to_string())
            }
            _ => None,
        };
        self.error = err;
    }

    /// Decide whether the current confirm input is sufficient to
    /// submit. Returns `Some(scope)` ready to feed into `add_inner`,
    /// `None` to keep waiting. Returns owned strings so the caller can
    /// move the [`ScopeModal`] into the submit path without lifetime
    /// drama.
    pub fn ready_to_submit(&self) -> Option<ResolvedScope> {
        match &self.stage {
            ScopeStage::DeviceConfirm => self.captured_device_id.clone().map(ResolvedScope::Device),
            ScopeStage::TypedConfirm { chosen, buffer } => {
                // SN2 tier-2 gate: the operator must type the *resolved*
                // scope id rendered in the menu, mirroring DefaultConfirm's
                // exact-`DEFAULT` match and the prompt's promise ("Type the
                // scope id to confirm"). A non-empty-but-different entry
                // (even one that is itself a valid id) must NOT silently
                // retarget the allow/deny rule to the wrong scope.
                let trimmed = buffer.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let id = self.chosen_scope_id(*chosen)?;
                if trimmed != id {
                    return None;
                }
                match chosen {
                    ScopeMenuEntry::Profile => Some(ResolvedScope::Profile(id.to_string())),
                    ScopeMenuEntry::Group => Some(ResolvedScope::Group(id.to_string())),
                    ScopeMenuEntry::Subnet => Some(ResolvedScope::Subnet(id.to_string())),
                    // Unreachable — `chosen_scope_id` already returned
                    // `None` for both, so the `?` above took this path.
                    ScopeMenuEntry::Device | ScopeMenuEntry::Default => None,
                }
            }
            ScopeStage::DefaultConfirm { buffer } => {
                if buffer.trim() == "DEFAULT" {
                    Some(ResolvedScope::Default)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Mark the modal as submitted with the given outcome — caller
    /// closes it on the next keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = ScopeStage::Submitted(outcome);
    }
}

/// A scope ready to feed into [`crate::cli::commands::rules::add_inner`].
/// Owns its strings so the caller can hand it to an async submit path
/// without lifetime drama.
#[derive(Debug, Clone)]
pub enum ResolvedScope {
    Profile(String),
    Device(String),
    Group(String),
    Subnet(String),
    Default,
}

impl ResolvedScope {
    pub fn as_scope(&self) -> Scope<'_> {
        match self {
            ResolvedScope::Profile(s) => Scope::Profile(s),
            ResolvedScope::Device(s) => Scope::Device(s),
            ResolvedScope::Group(s) => Scope::Group(s),
            ResolvedScope::Subnet(s) => Scope::Subnet(s),
            ResolvedScope::Default => Scope::Default,
        }
    }
}

/// Sprint 48 — pure predicate used by both [`ScopeModal::is_disabled`]
/// and the [`ScopeModal::open`] default-cursor search. Pulled out of
/// `&self` so the constructor can call it before `self` exists.
fn is_entry_disabled(
    entry: ScopeMenuEntry,
    has_device: bool,
    has_profile: bool,
    has_group: bool,
    has_subnet: bool,
) -> bool {
    match entry {
        ScopeMenuEntry::Device => !has_device,
        ScopeMenuEntry::Profile => !has_profile,
        ScopeMenuEntry::Group => !has_group,
        ScopeMenuEntry::Subnet => !has_subnet,
        ScopeMenuEntry::Default => false,
    }
}

/// Split each SN1 entry into its `(title, description)` halves. The
/// title is the bold action line; the description is the secondary
/// explanatory line rendered beneath it in the two-line menu layout.
///
/// Source of truth for the menu copy — [`menu_label`] re-joins the two
/// halves with `" — "` so the single-string callers and the existing
/// unit tests keep their exact, byte-for-byte output.
///
/// Descriptions are stored leading-lowercase so the joined [`menu_label`]
/// form reads as one sentence; the renderer capitalises the first letter
/// for the standalone description line (see `capitalize_first`).
///
/// Sprint 48 — for Profile / Group / Subnet, when the captured id is
/// `None`, the description switches to a parenthetical explaining **why**
/// the entry is unselectable, rather than printing a literal placeholder.
/// Pairs with [`ScopeModal::is_disabled`].
pub fn menu_entry_parts(entry: ScopeMenuEntry, modal: &ScopeModal) -> (String, String) {
    match entry {
        ScopeMenuEntry::Device => match &modal.captured_device_id {
            Some(_) => (
                format!("Just this device ({})", modal.captured_client),
                "affects only this device, even if its profile changes.".into(),
            ),
            None => (
                "Just this device".into(),
                "(no device matched on this row)".into(),
            ),
        },
        ScopeMenuEntry::Profile => match &modal.captured_profile_id {
            Some(pid) => (
                format!("All devices on profile '{pid}'"),
                "every device currently using this profile.".into(),
            ),
            None => (
                "All devices on profile".into(),
                "(no profile resolved for this device)".into(),
            ),
        },
        ScopeMenuEntry::Group => match &modal.captured_group_id {
            Some(gid) => (
                format!("All devices in group '{gid}'"),
                "every device that belongs to this group.".into(),
            ),
            None => (
                "All devices in group".into(),
                "(this device is not in any group)".into(),
            ),
        },
        ScopeMenuEntry::Subnet => match &modal.captured_subnet_id {
            Some(sid) => (
                format!("All devices on subnet '{sid}'"),
                "every device matched by this network range.".into(),
            ),
            None => (
                "All devices on subnet".into(),
                "(this device's IP doesn't match any defined subnet)".into(),
            ),
        },
        ScopeMenuEntry::Default => (
            "Default for unknown devices".into(),
            "affects any new device that joins the network.".into(),
        ),
    }
}

/// Build the operator-facing label for entry `n` in the SN1 menu as a
/// single `"{title} — {description}"` string. Retained for the unit
/// tests and any caller wanting the flat form; the renderer uses
/// [`menu_entry_parts`] directly to draw the two-line layout.
#[allow(dead_code)] // tested by unit tests as the menu-copy guard;
                    // render reads menu_entry_parts halves directly.
pub fn menu_label(entry: ScopeMenuEntry, modal: &ScopeModal) -> String {
    let (title, description) = menu_entry_parts(entry, modal);
    format!("{title} — {description}")
}

/// Title-band copy — Pi-hole-style "Add to allowlist / blocklist"
/// lexicon (Sprint 47 D3). Captures both the operator's intent and the
/// domain, and is deliberately the **same on every stage**: the confirm
/// screens are steps inside one flow about one domain, so a title that
/// changed under the operator would cost them their orientation rather
/// than give them information.
///
/// §4.61 Wave 4a dropped the trailing `— pick the scope:` clause. That
/// half is guidance, not subject, and Archetype C has a description band
/// underneath for exactly that — where each stage can say what *it* is
/// asking. The title keeps the two things that never vary.
pub fn header(modal: &ScopeModal) -> String {
    let list = match modal.action {
        Action::Allow => "allowlist",
        Action::Deny => "blocklist",
    };
    format!("Add to {list} \u{b7} {domain}", domain = modal.domain)
}

/// Bottom-line help text for the current stage.
#[allow(dead_code)] // tested by unit tests; render uses inline strings
                    // tuned per stage rather than the generic helper.
pub fn footer(stage: &ScopeStage) -> String {
    match stage {
        ScopeStage::Menu => "[↑/↓] move   [Enter] select   [Esc] cancel".into(),
        ScopeStage::DeviceConfirm => "[y] confirm   [n / Esc] back".into(),
        ScopeStage::TypedConfirm { .. } => {
            format!(
                "{prompt}[Enter] submit   [Esc] back",
                prompt = RULES_BATCH_TYPE_CONFIRM
            )
        }
        ScopeStage::DefaultConfirm { .. } => {
            format!(
                "{prompt}[Enter] submit   [Esc] back",
                prompt = RULES_BATCH_DEFAULT_CONFIRM
            )
        }
        ScopeStage::Submitted(_) => "[any key] close".into(),
    }
}

/// Uppercase the first alphabetic character of `s` for standalone
/// display on the description line. The descriptions in
/// [`menu_entry_parts`] are stored leading-lowercase so [`menu_label`]'s
/// joined form reads as one sentence; on its own line the description
/// wants a capital. Leading non-letters (e.g. the `(` of a disabled
/// entry's reason) are passed through and the first letter after them
/// is capitalised.
fn capitalize_first(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut done = false;
    for c in s.chars() {
        if !done && c.is_alphabetic() {
            out.extend(c.to_uppercase());
            done = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Truncate `s` to at most `max` columns, appending `…` when clipped.
/// Char-aware (counts scalar values, not bytes) so multi-byte ids do
/// not panic on a byte boundary. Keeps every menu line within the modal
/// width so the `Paragraph`'s wrap never splits a two-line entry.
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

/// Truncate `s` to at most `max` columns keeping the **tail**, marking
/// the cut with a leading `…`. The mirror of [`fit`], for text whose end
/// is the part that matters — see [`input_row`].
fn tail_fit(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::from("\u{2026}");
    out.extend(s.chars().skip(n - (max - 1)));
    out
}

/// Split a CLI confirm prompt into `(warning, prompt)` at its last
/// sentence boundary. A prompt carrying no warning sentence yields an
/// empty first half and is returned whole.
///
/// [`RULES_BATCH_DEFAULT_CONFIRM`] bundles the two because the CLI prints
/// the pair as a single blocking `read_line`; at 76 columns it does not
/// fit a 60-column modal row, and the body does not wrap. Splitting it —
/// rather than restating either half here — keeps the const the single
/// source of truth for both surfaces.
fn split_prompt(prompt: &str) -> (&str, &str) {
    match prompt.rfind(". ") {
        // `". "` is ASCII, so both indices land on char boundaries.
        Some(i) => (&prompt[..=i], &prompt[i + 2..]),
        None => ("", prompt),
    }
}

// ── render (§4.61 Wave 4a — Archetype C via `modal_form`) ─────────────
//
// Every span in this module comes out of `modal_form`; not one colour is
// chosen here. That is the wave's acceptance criterion rather than an
// aesthetic preference — the ecosystem colour rule has exactly one
// implementation, so twelve surfaces cannot drift apart. Pinned by
// `no_hand_rolled_colour_in_this_module` below.
//
// This module is the first consumer of Archetype C. The SN1 menu is a
// `choices` list; the three SN2 confirms and the outcome screen are
// `prose`. The flow between them, and every key that walks it, is
// untouched (D7′) — chrome, layout and colour are all that changed.

/// Modal width, unchanged from the pre-migration overlay. The *height* is
/// no longer a constant: [`modal_form::render_modal`] derives it from the
/// body it is handed and lets `overlay::centered_rect` clamp it to the
/// anchor.
const MODAL_W: u16 = 64;

// Nav-key legends, byte-identical to the strings this modal advertised
// before the migration. D7′ changes chrome, layout and colour and leaves
// the keying alone, so the legend it advertises must not move either.
const KEYS_MENU: &str = "[\u{2191}/\u{2193}] move   [Enter] select   [Esc] cancel";
const KEYS_DEVICE: &str = "[y] confirm   [n / Esc] back";
const KEYS_TYPED: &str = "[Enter] submit   [Esc] back   [Backspace] erase";
const KEYS_DEFAULT: &str = "[Enter] submit   [Esc] back";
const KEYS_DONE: &str = "[any key] close";

/// Draw the scope modal as an Archetype-C overlay anchored on the tab
/// content rect.
///
/// `anchor` is the tab content area (§4.61 D18), never `f.area()`: the
/// header, the menu card and the footer legend stay visible behind the
/// modal. That leaves 12 interior rows at the declared 80×24 floor —
/// 2 head, 2 tail, **8** for content — against a five-entry menu whose
/// field region runs to 10 now that every entry claims a row for its
/// description (§4.65 UX1(a)), which is why
/// every stage here is built on a [`modal_form::ScrollBody`] and rendered
/// through [`modal_form::render_modal`]. It owns the chrome, the height
/// request, the anchor clamp, the two-pass width resolution and the
/// focus-following viewport; `overlay::centered_rect` clamps rather than
/// scrolls, so without that viewport the tail is simply cut while `j`/`k`
/// go on moving the cursor onto the entries that were cut.
///
/// The border accent is deliberately not a parameter any more: chrome
/// stays neutral grey and `brand_red` is never a border (D15). How far a
/// scope reaches is carried by the option's own colour and by the
/// destructive action on the default-scope confirm — in the body, where
/// the operator is reading, not in the frame.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &ScopeModal) {
    modal_form::render_modal(f, anchor, MODAL_W, |w| {
        (modal_form::notice_body(&notice(modal, w), w), ())
    });
}

/// The current stage as an Archetype-C [`NoticeSpec`].
///
/// `width` is the resolved inner width, which
/// [`modal_form::render_modal`] may lower by one column once it knows the
/// body scrolls. It only ever changes how far a string is truncated,
/// never how many rows the body has — a width-dependent row count would
/// silently mis-size the modal between the two build passes.
fn notice(modal: &ScopeModal, width: u16) -> NoticeSpec {
    match &modal.stage {
        ScopeStage::Menu => menu_notice(modal, width),
        ScopeStage::DeviceConfirm => device_confirm_notice(modal),
        ScopeStage::TypedConfirm { chosen, buffer } => {
            typed_confirm_notice(modal, *chosen, buffer, width)
        }
        ScopeStage::DefaultConfirm { buffer } => default_confirm_notice(modal, buffer, width),
        ScopeStage::Submitted(outcome) => outcome_notice(modal, outcome),
    }
}

/// The SN1 menu as an option list.
///
/// **Every entry — choosable or not — states its description on an
/// indented row of its own** ([`ChoiceNote`]), which is §4.65 UX1(a).
///
/// The previous split, and why it did not hold: choosable entries put
/// their description in [`ChoiceRow::detail`], which rides the option's own
/// row ellipsised to the interior width, while the FOCUSED entry's copy
/// went to the tail's hint row in full. Gist on every row, full text for
/// the one the cursor is on. Roughly 85 columns of `label + detail` against
/// 62 means the gist was about 27 cells — the operator reported the menu as
/// "compressed and cut", correctly. A picker exists so its options can be
/// compared *before* the cursor reaches them, so covering exactly one of
/// them is covering the wrong one.
///
/// That is the same argument `s4-63-g5-disabled-option-reason` already
/// won for the disabled entries, where the hint row cannot help at all:
/// [`ScopeModal::move_cursor`] and [`ScopeModal::open`] both skip them, so
/// focus never lands on one. Two of those three needed 65 and 77 columns
/// and rendered no explanation whatsoever. Widening the mechanism rather
/// than adding a second one is `_docs/features/tui_ux_batch_2608.md` §5
/// decision 3.
///
/// **The rows are paid for by dropping the hint row entirely** —
/// `hint_rows: Some(0)`, where §4.63 S1 pinned `Some(1)`. The hint carried
/// the focused entry's description and nothing else, which is now on that
/// entry's own row: keeping it would spend a row of the tightest budget in
/// the ecosystem printing a duplicate. This menu raises no validation
/// error, so nothing else ever needs the region.
///
/// At the D18 floor that leaves **8** field rows against the 10 a
/// five-entry menu now wants, so the body scrolls — it already did at 8
/// rows with three disabled entries, and [`modal_form::render_modal`]'s
/// focus-following viewport is what makes that survivable. See
/// `every_choosable_entry_states_its_description_even_unfocused`.
fn menu_notice(modal: &ScopeModal, width: u16) -> NoticeSpec {
    // Keep `choice_rows`' 2-cell lead and its trailing focus marker out
    // of the label's budget: a label built to the full width would push
    // the marker off the row.
    let label_avail = (width as usize).saturating_sub(4);
    let mut choices = Vec::with_capacity(ScopeMenuEntry::ALL.len());

    for (idx, entry) in ScopeMenuEntry::ALL.iter().enumerate() {
        let (title, desc) = menu_entry_parts(*entry, modal);
        let desc = capitalize_first(&desc);
        choices.push(ChoiceRow {
            label: fit(&title, label_avail),
            // The description is the note row now. Setting it inline as
            // well would print it twice, once truncated.
            detail: None,
            note: Some(if modal.is_disabled(*entry) {
                ChoiceNote::Blocked(desc)
            } else {
                ChoiceNote::Detail(desc)
            }),
            kind: entry_kind(*entry),
            focused: idx == modal.menu_cursor,
        });
    }

    NoticeSpec {
        hint_rows: Some(0),
        title: header(modal),
        desc: "how widely should the rule apply?".to_string(),
        prose: Vec::new(),
        choices,
        error: None,
        hint: String::new(),
        keys: KEYS_MENU.to_string(),
        actions: vec![
            modal_form::Action::new("  Cancel  ", false, ActionKind::Neutral, ""),
            modal_form::Action::new("  Continue  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// Resting colour of a menu entry, chosen by how far the rule would
/// reach: one device is the narrow and easily-undone case, a profile /
/// group / subnet takes a set of devices with it, and the default reaches
/// every unmapped device on the network.
///
/// Disabled-ness is no longer expressed here. It used to be faked with
/// [`ValueKind::Editable`], the most recessed kind the palette offers,
/// because `ChoiceRow` carried no enabled/disabled state — a gap this
/// module recorded for the next Archetype-C consumer and §4.63 S1 closed.
/// [`ChoiceRow::note`] now recesses the label inside `modal_form`, which
/// is where the colour rule belongs; the kind describes what choosing the
/// entry *would* mean and stays honest either way. The cursor still never
/// lands on a disabled entry — `move_cursor` and `open` both skip them.
fn entry_kind(entry: ScopeMenuEntry) -> ValueKind {
    match entry {
        ScopeMenuEntry::Device => ValueKind::Healthy,
        ScopeMenuEntry::Profile | ScopeMenuEntry::Group | ScopeMenuEntry::Subnet => {
            ValueKind::Caution
        }
        ScopeMenuEntry::Default => ValueKind::Blocking,
    }
}

/// SN2 tier 1 — the single-keypress device confirm.
///
/// Two prose rows rather than the one long sentence this used to be: the
/// Archetype-C body does not wrap, and a long domain or device id would
/// have cost that sentence its tail.
fn device_confirm_notice(modal: &ScopeModal) -> NoticeSpec {
    let dev = modal.captured_device_id.as_deref().unwrap_or("?");
    NoticeSpec {
        hint_rows: None,
        title: header(modal),
        desc: "confirm the narrowest scope".to_string(),
        prose: vec![
            ProseRow::plain(format!(
                "Apply the {} rule for '{}'",
                modal.action.slug(),
                modal.domain
            )),
            ProseRow::emphasis(format!("on device '{dev}'"), ValueKind::Healthy),
        ],
        choices: Vec::new(),
        error: None,
        hint: "no other device is affected, even on the same profile".to_string(),
        keys: KEYS_DEVICE.to_string(),
        actions: vec![
            modal_form::Action::new("  [n] Cancel  ", false, ActionKind::Neutral, ""),
            modal_form::Action::new("  [y] Confirm  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// SN2 tier 2 — the typed scope-id confirm for profile / group / subnet.
///
/// The resolved id is deliberately **not** reprinted on this screen.
/// [`ScopeModal::ready_to_submit`] gates on an exact match with the id the
/// menu rendered, and the point of that gate is that the operator retypes
/// it from the entry they chose; putting it back on screen would turn a
/// deliberate act into a copy.
fn typed_confirm_notice(
    modal: &ScopeModal,
    chosen: ScopeMenuEntry,
    buffer: &str,
    width: u16,
) -> NoticeSpec {
    let (scope_label, reach) = match chosen {
        ScopeMenuEntry::Profile => ("profile", "every device on this profile"),
        ScopeMenuEntry::Group => ("group", "every device in this group"),
        ScopeMenuEntry::Subnet => ("subnet", "every device matched by this range"),
        // `enter_confirm` routes only those three here.
        ScopeMenuEntry::Device | ScopeMenuEntry::Default => ("scope", ""),
    };
    let selected = if reach.is_empty() {
        format!("Selected: {scope_label}")
    } else {
        format!("Selected: {scope_label} \u{2014} {reach}.")
    };
    // The id the gate will compare against, on the row above the prompt
    // that asks for it. It lived only in the menu, and `notice` repaints
    // the whole body per stage — so advancing to this screen took the
    // only copy of it away at the exact moment it became required.
    let id_row = format!(
        "{scope_label} id: {id}",
        id = modal.chosen_scope_id(chosen).unwrap_or("\u{2014}")
    );

    NoticeSpec {
        hint_rows: None,
        title: header(modal),
        desc: format!("confirm the {scope_label} scope"),
        // Four rows is the ceiling, not a preference — see
        // [`default_confirm_notice`]. A fifth would scroll the typed line
        // off screen at the D18 floor with no key to bring it back.
        prose: vec![
            ProseRow::plain(selected),
            ProseRow::emphasis(id_row, ValueKind::Identity),
            ProseRow::plain(String::new()),
            input_row(RULES_BATCH_TYPE_CONFIRM, buffer, width),
        ],
        choices: Vec::new(),
        error: modal.error.clone(),
        hint: "the id must match the entry you picked, exactly".to_string(),
        keys: KEYS_TYPED.to_string(),
        actions: vec![
            modal_form::Action::new("  [Esc] Back  ", false, ActionKind::Neutral, ""),
            modal_form::Action::new("  [Enter] Confirm  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// SN2 tier 3 — the typed `DEFAULT` confirm, the widest scope on offer.
///
/// The confirm action is `Destructive`, not `Primary`, which makes this
/// the one stage with no filled button anywhere in it. A filled teal
/// button is the ecosystem's "this is the action" and reads as *press
/// me*; a rule that reaches every unmapped device on the network should
/// not be advertising one.
///
/// Four prose rows, against a field region of **six** at the D18 floor
/// (12 interior − a 2-row head − a 4-row tail: the default `hint_rows`
/// region plus the key legend and the action row). The two spare rows are
/// deliberately unspent: a prose-only body has no focus target, so
/// [`modal_form::ScrollBody::scrollable`] is false, the viewport is pinned
/// at offset 0 and there is no scrollbar to say so — anything that
/// overflows takes the line the operator is typing into with it, silently.
/// §4.63 S1 raised the ceiling from four to six; the copy stays at four.
fn default_confirm_notice(modal: &ScopeModal, buffer: &str, width: u16) -> NoticeSpec {
    let (warning, prompt) = split_prompt(RULES_BATCH_DEFAULT_CONFIRM);
    NoticeSpec {
        hint_rows: None,
        title: header(modal),
        desc: "confirm the widest scope there is".to_string(),
        prose: vec![
            ProseRow::emphasis("Selected: default".to_string(), ValueKind::Blocking),
            ProseRow::plain(warning.to_string()),
            ProseRow::plain(String::new()),
            input_row(prompt, buffer, width),
        ],
        choices: Vec::new(),
        error: modal.error.clone(),
        hint: "devices with a profile of their own are unaffected".to_string(),
        keys: KEYS_DEFAULT.to_string(),
        actions: vec![
            modal_form::Action::new("  [Esc] Back  ", false, ActionKind::Neutral, ""),
            modal_form::Action::new("  [Enter] Confirm  ", false, ActionKind::Destructive, ""),
        ],
    }
}

/// The submit outcome.
///
/// A failure goes in the `error` slot rather than the prose: that region
/// hard-wraps to [`modal_form::HINT_ROWS`] rows, and `add_inner`'s
/// failure strings are the long ones — on a prose row a rejected rule
/// would lose the half of the message that says why.
fn outcome_notice(modal: &ScopeModal, outcome: &SubmitOutcome) -> NoticeSpec {
    let (desc, prose, error) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "the rule is saved to the configuration file",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            "nothing was written \u{2014} close and try again",
            Vec::new(),
            Some(msg.clone()),
        ),
    };
    NoticeSpec {
        hint_rows: None,
        title: header(modal),
        desc: desc.to_string(),
        prose,
        choices: Vec::new(),
        error,
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

/// The live typed-confirm line: the prompt, what the operator has typed
/// so far, and the `_` caret this modal has always drawn.
///
/// [`NoticeSpec`] has no text-input row, so the buffer rides on a prose
/// row (recorded as a gap for the next Archetype-C consumer). Prose
/// truncates on the **right**, which for an input is backwards — a buffer
/// longer than the row would take the caret, and the characters just
/// typed, with it. The pre-migration body spilled onto a second line
/// under `Wrap`; the ecosystem body does not wrap, so the line scrolls
/// horizontally and keeps its end.
fn input_row(prompt: &str, buffer: &str, width: u16) -> ProseRow {
    // `prose_row` prepends a 2-cell indent that counts against `width`.
    let avail = (width as usize).saturating_sub(2);
    ProseRow::emphasis(
        tail_fit(&format!("{prompt}{buffer}_"), avail),
        ValueKind::Editable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(action: Action, with_device: bool) -> ScopeModal {
        // Sprint 48 — keep the legacy signature for the bulk of tests:
        // device + profile resolved, group + subnet absent (the most
        // common Query Log row in practice). Tests that need group or
        // subnet ids call `open_full` directly.
        open_full(
            action,
            if with_device {
                Some("pc-gioele".into())
            } else {
                None
            },
            Some("default".into()),
            None,
            None,
        )
    }

    fn open_full(
        action: Action,
        device_id: Option<String>,
        profile_id: Option<String>,
        group_id: Option<String>,
        subnet_id: Option<String>,
    ) -> ScopeModal {
        ScopeModal::open(
            action,
            "ads.example".into(),
            "iphone".into(),
            device_id,
            profile_id,
            group_id,
            subnet_id,
        )
    }

    #[test]
    fn menu_carries_five_entries_in_design_doc_order() {
        assert_eq!(ScopeMenuEntry::ALL.len(), 5);
        assert_eq!(ScopeMenuEntry::ALL[0], ScopeMenuEntry::Device);
        assert_eq!(ScopeMenuEntry::ALL[1], ScopeMenuEntry::Profile);
        assert_eq!(ScopeMenuEntry::ALL[2], ScopeMenuEntry::Group);
        assert_eq!(ScopeMenuEntry::ALL[3], ScopeMenuEntry::Subnet);
        assert_eq!(ScopeMenuEntry::ALL[4], ScopeMenuEntry::Default);
    }

    #[test]
    fn open_default_cursor_lands_on_device_when_matched() {
        let m = open(Action::Allow, true);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Device.index());
    }

    #[test]
    fn open_default_cursor_skips_device_when_not_matched() {
        let m = open(Action::Allow, false);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Profile.index());
    }

    #[test]
    fn move_cursor_skips_disabled_device_entry() {
        let mut m = open(Action::Allow, false);
        // From Profile (idx 1), moving up should wrap to Default
        // (idx 4) — Device (idx 0) is disabled.
        m.move_cursor(-1);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Default.index());
        m.move_cursor(1);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Profile.index());
    }

    #[test]
    fn enter_device_confirm_advances_state() {
        let mut m = open(Action::Allow, true);
        let entry = m.enter_confirm();
        assert_eq!(entry, Some(ScopeMenuEntry::Device));
        assert!(matches!(m.stage, ScopeStage::DeviceConfirm));
    }

    #[test]
    fn enter_typed_confirm_for_profile() {
        let mut m = open(Action::Deny, true);
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        let entry = m.enter_confirm();
        assert_eq!(entry, Some(ScopeMenuEntry::Profile));
        match m.stage {
            ScopeStage::TypedConfirm {
                chosen: ScopeMenuEntry::Profile,
                buffer,
            } => assert!(buffer.is_empty()),
            other => panic!("expected TypedConfirm(Profile, ''), got {other:?}"),
        }
    }

    #[test]
    fn enter_default_confirm_state() {
        let mut m = open(Action::Deny, true);
        m.menu_cursor = ScopeMenuEntry::Default.index();
        let entry = m.enter_confirm();
        assert_eq!(entry, Some(ScopeMenuEntry::Default));
        assert!(matches!(m.stage, ScopeStage::DefaultConfirm { .. }));
    }

    #[test]
    fn typed_confirm_buffer_collects_input() {
        // Sprint 48: Group entry now requires a captured group id to
        // be enabled. Use `open_full` to give the test a resolved
        // group so `enter_confirm` advances the state machine.
        let mut m = open_full(
            Action::Allow,
            Some("pc-gioele".into()),
            Some("default".into()),
            Some("famiglia".into()),
            None,
        );
        m.menu_cursor = ScopeMenuEntry::Group.index();
        m.enter_confirm();
        m.push_char('i');
        m.push_char('o');
        m.push_char('t');
        match &m.stage {
            ScopeStage::TypedConfirm { buffer, .. } => assert_eq!(buffer, "iot"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn ready_to_submit_device_returns_resolved_device_scope() {
        let mut m = open(Action::Allow, true);
        m.enter_confirm();
        let resolved = m.ready_to_submit().expect("device confirm");
        match resolved {
            ResolvedScope::Device(id) => assert_eq!(id, "pc-gioele"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn ready_to_submit_typed_requires_non_empty_buffer() {
        let mut m = open(Action::Allow, true);
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        m.enter_confirm();
        assert!(m.ready_to_submit().is_none(), "empty buffer rejected");
        // `open` resolves the profile id to "default" — the operator must
        // type it exactly to confirm (SN2 tier-2 id-match gate).
        for c in "default".chars() {
            m.push_char(c);
        }
        match m.ready_to_submit() {
            Some(ResolvedScope::Profile(s)) => assert_eq!(s, "default"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn ready_to_submit_typed_rejects_mismatched_id() {
        // SN2 tier-2: a non-empty buffer that does NOT match the resolved
        // scope id must NOT submit — guards against a typo'd-but-valid id
        // silently retargeting the rule to the wrong scope.
        let mut m = open_full(
            Action::Deny,
            Some("pc-gioele".into()),
            Some("default".into()),
            Some("famiglia".into()),
            None,
        );
        // Wrong (but plausible) profile id → no submit.
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        m.enter_confirm();
        for c in "guest".chars() {
            m.push_char(c);
        }
        assert!(
            m.ready_to_submit().is_none(),
            "mismatched profile id must be rejected"
        );
        // The captured profile id confirms.
        m.back_to_menu();
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        m.enter_confirm();
        for c in "default".chars() {
            m.push_char(c);
        }
        assert!(matches!(
            m.ready_to_submit(),
            Some(ResolvedScope::Profile(_))
        ));
        // Group entry enforces the same gate against `captured_group_id`.
        m.back_to_menu();
        m.menu_cursor = ScopeMenuEntry::Group.index();
        m.enter_confirm();
        for c in "famiglia".chars() {
            m.push_char(c);
        }
        match m.ready_to_submit() {
            Some(ResolvedScope::Group(s)) => assert_eq!(s, "famiglia"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn ready_to_submit_default_requires_typed_default_phrase() {
        let mut m = open(Action::Allow, true);
        m.menu_cursor = ScopeMenuEntry::Default.index();
        m.enter_confirm();
        for c in "default".chars() {
            m.push_char(c);
        }
        assert!(m.ready_to_submit().is_none(), "lowercase rejected");
        // Reset buffer + retry uppercase:
        m.back_to_menu();
        m.menu_cursor = ScopeMenuEntry::Default.index();
        m.enter_confirm();
        for c in "DEFAULT".chars() {
            m.push_char(c);
        }
        match m.ready_to_submit() {
            Some(ResolvedScope::Default) => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn back_to_menu_restores_menu_state() {
        let mut m = open(Action::Allow, true);
        m.enter_confirm();
        m.back_to_menu();
        assert!(matches!(m.stage, ScopeStage::Menu));
    }

    #[test]
    fn header_uses_action_and_domain() {
        let m = open(Action::Allow, true);
        let h = header(&m);
        // Sprint 47 D3: Pi-hole-style lexicon. Allow → "allowlist".
        assert!(h.contains("allowlist"));
        assert!(h.contains("ads.example"));
    }

    #[test]
    fn header_uses_block_for_deny_action() {
        let m = open(Action::Deny, true);
        let h = header(&m);
        // Sprint 47 D3: Pi-hole-style lexicon. Deny → "blocklist".
        assert!(h.contains("blocklist"));
    }

    #[test]
    fn footer_advertises_typed_confirm_prompt() {
        let modal = open(Action::Allow, true);
        let stage = ScopeStage::TypedConfirm {
            chosen: ScopeMenuEntry::Profile,
            buffer: "k".into(),
        };
        let _ = modal; // silence unused
        let f = footer(&stage);
        assert!(f.contains("Type the scope id to confirm:"));
    }

    #[test]
    fn footer_advertises_default_confirm_prompt() {
        let stage = ScopeStage::DefaultConfirm {
            buffer: String::new(),
        };
        let f = footer(&stage);
        assert!(f.contains("Type DEFAULT to confirm:"));
    }

    #[test]
    fn menu_label_for_device_includes_captured_client() {
        let m = open(Action::Allow, true);
        let lbl = menu_label(ScopeMenuEntry::Device, &m);
        assert!(lbl.contains("Just this device"));
        assert!(lbl.contains("iphone"));
    }

    #[test]
    fn menu_label_for_default_carries_design_doc_phrase() {
        let m = open(Action::Allow, true);
        let lbl = menu_label(ScopeMenuEntry::Default, &m);
        assert!(lbl.contains("Default for unknown devices"));
        assert!(lbl.contains("affects any new device"));
    }

    #[test]
    fn submit_finishes_state() {
        let mut m = open(Action::Allow, true);
        m.finish(SubmitOutcome::Ok("done".into()));
        assert!(matches!(
            m.stage,
            ScopeStage::Submitted(SubmitOutcome::Ok(_))
        ));
    }

    // ── Sprint 47 T1 — inferred_action mapping + open_for_query_row +
    //                  Pi-hole lexicon header ────────────────────────

    fn dto(result: &str, domain: &str) -> crate::ipc::protocol::QueryLogDto {
        crate::ipc::protocol::QueryLogDto {
            timestamp: "2026-05-02T10:00:00Z".into(),
            client_ip: "192.0.2.50".into(),
            client_name: Some("iphone".into()),
            domain: domain.into(),
            query_type: "A".into(),
            result: result.into(),
            response_time_us: 1234,
            cname_chain_via: None,
        }
    }

    #[test]
    fn inferred_action_blocked_returns_allow() {
        assert_eq!(inferred_action("BLOCKED"), Some(Action::Allow));
    }

    #[test]
    fn inferred_action_allowed_returns_deny() {
        assert_eq!(inferred_action("ALLOWED"), Some(Action::Deny));
    }

    #[test]
    fn inferred_action_cached_treated_as_allowed_for_blocklisting() {
        // Cache hit on a previously allowed query — same blocklist
        // semantics as plain ALLOWED.
        assert_eq!(inferred_action("CACHED"), Some(Action::Deny));
    }

    #[test]
    fn inferred_action_stale_treated_as_allowed_for_blocklisting() {
        // Stale cache served while upstream is unreachable — still a
        // query the resolver let through, blocklist semantics identical
        // to ALLOWED.
        assert_eq!(inferred_action("STALE"), Some(Action::Deny));
    }

    #[test]
    fn inferred_action_local_returns_none() {
        assert_eq!(inferred_action("LOCAL"), None);
    }

    #[test]
    fn inferred_action_refused_returns_none() {
        assert_eq!(inferred_action("REFUSED"), None);
        assert_eq!(inferred_action("HINFO"), None);
    }

    #[test]
    fn inferred_action_unknown_status_returns_none() {
        // Future-proof: any status the daemon emits in the future
        // (NXDOMAIN, DROPPED, empty, lowercased, mixed-case) falls
        // through to None — the caller surfaces a "not actionable"
        // footer message rather than opening an inappropriate modal.
        // Mapping is case-sensitive on purpose.
        for status in ["NXDOMAIN", "", "FOO", "Servfail", "blocked", "allowed"] {
            assert_eq!(
                inferred_action(status),
                None,
                "expected None for status {status:?}"
            );
        }
    }

    #[test]
    fn open_for_query_row_blocked_returns_allow_modal() {
        let entry = dto("BLOCKED", "ads.example");
        let modal = ScopeModal::open_for_query_row(
            &entry,
            "iphone".into(),
            Some("pc-gioele".into()),
            Some("default".into()),
            None,
            None,
        )
        .expect("BLOCKED row is actionable");
        assert_eq!(modal.action, Action::Allow);
        assert_eq!(modal.domain, "ads.example");
    }

    #[test]
    fn open_for_query_row_allowed_returns_deny_modal() {
        let entry = dto("ALLOWED", "tracker.example");
        let modal = ScopeModal::open_for_query_row(
            &entry,
            "iphone".into(),
            Some("pc-gioele".into()),
            Some("default".into()),
            None,
            None,
        )
        .expect("ALLOWED row is actionable");
        assert_eq!(modal.action, Action::Deny);
        assert_eq!(modal.domain, "tracker.example");
    }

    #[test]
    fn open_for_query_row_local_returns_none() {
        let entry = dto("LOCAL", "router.lan");
        let modal = ScopeModal::open_for_query_row(&entry, "router".into(), None, None, None, None);
        assert!(modal.is_none(), "LOCAL rows must not open a modal");
    }

    // ── Sprint 48 — disabled placeholder cleanup ──────────────────────

    #[test]
    fn menu_label_for_profile_when_unmapped_shows_descriptive_text() {
        // Pre-S48 wording was "All devices on profile '<type below>' —
        // every device currently using this profile.", which read as a
        // typo. Post-S48 the entry is disabled and the label explains
        // why instead of printing a placeholder.
        let m = open_full(Action::Allow, None, None, None, None);
        let lbl = menu_label(ScopeMenuEntry::Profile, &m);
        assert!(
            !lbl.contains("<type below>"),
            "old placeholder leaked: {lbl:?}"
        );
        assert!(
            lbl.contains("no profile resolved for this device"),
            "missing descriptive text: {lbl:?}"
        );
        assert!(m.is_disabled(ScopeMenuEntry::Profile));
    }

    #[test]
    fn menu_label_for_group_with_id_includes_group_id() {
        let m = open_full(
            Action::Allow,
            Some("pc-gioele".into()),
            Some("default".into()),
            Some("famiglia".into()),
            None,
        );
        let lbl = menu_label(ScopeMenuEntry::Group, &m);
        assert!(
            lbl.contains("'famiglia'"),
            "expected resolved group id in label: {lbl:?}"
        );
        assert!(
            !lbl.contains("<group_id>"),
            "old placeholder leaked: {lbl:?}"
        );
        assert!(!m.is_disabled(ScopeMenuEntry::Group));
    }

    #[test]
    fn menu_label_for_group_with_no_group_shows_descriptive_text() {
        // Pre-S48 wording printed the literal `<group_id>` regardless
        // of whether a group resolved. Post-S48 the entry is disabled
        // when no group was captured.
        let m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        let lbl = menu_label(ScopeMenuEntry::Group, &m);
        assert!(
            !lbl.contains("<group_id>"),
            "old placeholder leaked: {lbl:?}"
        );
        assert!(
            lbl.contains("not in any group"),
            "missing descriptive text: {lbl:?}"
        );
        assert!(m.is_disabled(ScopeMenuEntry::Group));
    }

    #[test]
    fn menu_label_for_subnet_with_id_includes_subnet_id() {
        let m = open_full(
            Action::Allow,
            Some("pc".into()),
            Some("default".into()),
            None,
            Some("vlan-marketing".into()),
        );
        let lbl = menu_label(ScopeMenuEntry::Subnet, &m);
        assert!(
            lbl.contains("'vlan-marketing'"),
            "expected resolved subnet id in label: {lbl:?}"
        );
        assert!(!lbl.contains("<cidr>"), "old placeholder leaked: {lbl:?}");
        assert!(!m.is_disabled(ScopeMenuEntry::Subnet));
    }

    #[test]
    fn menu_label_for_subnet_with_no_subnet_shows_descriptive_text() {
        let m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        let lbl = menu_label(ScopeMenuEntry::Subnet, &m);
        assert!(!lbl.contains("<cidr>"), "old placeholder leaked: {lbl:?}");
        assert!(
            lbl.contains("doesn't match any defined subnet"),
            "missing descriptive text: {lbl:?}"
        );
        assert!(m.is_disabled(ScopeMenuEntry::Subnet));
    }

    #[test]
    fn cursor_skips_all_disabled_entries() {
        // Only Profile + Default enabled (no device, no group, no
        // subnet). Cursor lands on Profile by default and `move_cursor`
        // bounces only between Profile and Default.
        let mut m = open_full(Action::Allow, None, Some("default".into()), None, None);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Profile.index());
        m.move_cursor(1);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Default.index());
        m.move_cursor(1);
        assert_eq!(
            m.menu_cursor,
            ScopeMenuEntry::Profile.index(),
            "must wrap around skipping Group + Subnet"
        );
        m.move_cursor(-1);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Default.index());
    }

    #[test]
    fn enter_confirm_rejects_disabled_profile_entry() {
        let mut m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        assert!(
            m.enter_confirm().is_none(),
            "Enter on disabled Profile must not advance the state machine"
        );
        assert!(matches!(m.stage, ScopeStage::Menu));
    }

    #[test]
    fn enter_confirm_rejects_disabled_group_entry() {
        let mut m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        m.menu_cursor = ScopeMenuEntry::Group.index();
        assert!(m.enter_confirm().is_none());
        assert!(matches!(m.stage, ScopeStage::Menu));
    }

    #[test]
    fn enter_confirm_rejects_disabled_subnet_entry() {
        let mut m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        m.menu_cursor = ScopeMenuEntry::Subnet.index();
        assert!(m.enter_confirm().is_none());
        assert!(matches!(m.stage, ScopeStage::Menu));
    }

    #[test]
    fn open_default_cursor_falls_through_to_default_when_only_default_enabled() {
        // Worst-case: nothing resolved at all. Default is the only
        // enabled entry, so the cursor must land on it.
        let m = open_full(Action::Allow, None, None, None, None);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Default.index());
        assert!(!m.is_disabled(ScopeMenuEntry::Default));
    }

    #[test]
    fn header_for_allow_says_add_to_allowlist() {
        let m = open(Action::Allow, true);
        let h = header(&m);
        assert!(
            h.contains("allowlist"),
            "expected Pi-hole lexicon, got {h:?}"
        );
        // Regression guard: pre-S47 wording was "Allow '...' — pick
        // the scope:" — the bare "Allow '" prefix must not return.
        assert!(!h.contains("Allow '"), "old wording leaked: {h:?}");
    }

    #[test]
    fn header_for_deny_says_add_to_blocklist() {
        let m = open(Action::Deny, true);
        let h = header(&m);
        assert!(
            h.contains("blocklist"),
            "expected Pi-hole lexicon, got {h:?}"
        );
        // Regression guard: pre-S47 wording was "Block '...' — pick
        // the scope:" — the bare "Block '" prefix must not return.
        assert!(!h.contains("Block '"), "old wording leaked: {h:?}");
    }

    // ── two-line radio menu refactor — parts split / capitalize / fit ──

    #[test]
    fn menu_entry_parts_join_equals_menu_label() {
        // The renderer reads (title, desc) directly; menu_label must
        // stay the byte-identical " — " join so every legacy substring
        // assertion above keeps passing.
        let m = open_full(
            Action::Allow,
            Some("pc".into()),
            Some("default".into()),
            Some("famiglia".into()),
            Some("vlan-marketing".into()),
        );
        for entry in ScopeMenuEntry::ALL {
            let (title, desc) = menu_entry_parts(entry, &m);
            assert_eq!(format!("{title} — {desc}"), menu_label(entry, &m));
            // The title (action half) never carries the separator.
            assert!(!title.contains(" — "), "title leaked separator: {title:?}");
        }
    }

    #[test]
    fn menu_entry_parts_title_and_desc_are_distinct_halves() {
        let m = open(Action::Allow, true);
        let (title, desc) = menu_entry_parts(ScopeMenuEntry::Device, &m);
        assert_eq!(title, "Just this device (iphone)");
        assert_eq!(
            desc,
            "affects only this device, even if its profile changes."
        );
    }

    #[test]
    fn capitalize_first_uppercases_leading_letter() {
        assert_eq!(
            capitalize_first("affects only this device."),
            "Affects only this device."
        );
        assert_eq!(capitalize_first("every device"), "Every device");
    }

    #[test]
    fn capitalize_first_skips_leading_non_letters() {
        // Disabled-entry reasons start with '(' — capitalise the first
        // real letter and leave the paren in place.
        assert_eq!(
            capitalize_first("(no device matched on this row)"),
            "(No device matched on this row)"
        );
    }

    #[test]
    fn capitalize_first_empty_is_noop() {
        assert_eq!(capitalize_first(""), "");
    }

    #[test]
    fn fit_passes_through_when_short_enough() {
        assert_eq!(fit("hello", 10), "hello");
        assert_eq!(fit("hello", 5), "hello");
    }

    #[test]
    fn fit_truncates_with_ellipsis_when_too_long() {
        assert_eq!(fit("hello world", 5), "hell…");
        // The ellipsis itself occupies one column.
        assert_eq!(fit("hello world", 5).chars().count(), 5);
    }

    #[test]
    fn fit_zero_width_is_empty() {
        assert_eq!(fit("anything", 0), "");
    }

    #[test]
    fn fit_is_char_aware_not_byte_aware() {
        // Multi-byte scalar values must not panic on a byte boundary.
        let out = fit("café-società-naïve", 6);
        assert_eq!(out.chars().count(), 6);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn render_menu_paints_the_ecosystem_focus_grammar() {
        // Was `render_menu_paints_radio_dots_two_lines_and_bar`. §4.61
        // Wave 4a retired this module's local radio-dot vocabulary — a
        // `◉`/`○` column and a hand-rolled highlight bar — in favour of
        // Archetype C's shared focus grammar: an emerald `▌` rule, a
        // `bg_highlight` bar and a `◀` marker, three "you are here"
        // signals of which only one is colour. Those dots were chrome
        // this module drew for itself, which is exactly what the
        // migration removes, so the two dot assertions are replaced.
        // Every other assertion is kept verbatim: the label, the
        // description, the key legend and the focus bar all still have
        // to be on screen. §4.65 UX1(a) moved the description back onto
        // the option — its own indented row this time, not the label's
        // leftovers — so this assertion now proves the note row rather
        // than the hint row; the hint row no longer exists here.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Device + profile resolved → cursor lands on Device.
        //
        // One draw, two views of it: the string dump for the copy
        // assertions and the buffer for the focus bar. Rendering twice
        // would let the two halves disagree about what they are
        // describing.
        let modal = open(Action::Allow, true);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let buf = term.backend().buffer().clone();
        let dump = dump_buffer(&buf);

        // Exactly one focused option. `◀` is unique to a focused
        // `choice_row` here, where `▌` is not — the title band draws one
        // too — so the marker is the needle that cannot double-count.
        assert_eq!(
            dump.matches('\u{25c0}').count(),
            1,
            "exactly one focused option marker expected:\n{dump}"
        );
        assert!(
            !dump.contains('\u{25c9}') && !dump.contains('\u{25cb}'),
            "the local radio-dot chrome must be gone:\n{dump}"
        );

        assert!(dump.contains("Just this device"), "option label missing");
        assert!(
            dump.contains("Affects only this device"),
            "the focused entry's description must reach its note row:\n{dump}"
        );
        assert!(dump.contains("] move"), "key legend missing:\n{dump}");

        // The focus bar survived the migration. Asserted as "this row is
        // painted differently from the one above it" rather than against
        // a named colour, so the test does not re-couple this module to
        // the palette it no longer imports — which is the whole point of
        // `no_hand_rolled_colour_in_this_module`.
        let marker_row = (0..buf.area.height)
            .find(|&y| (0..buf.area.width).any(|x| buf[(x, y)].symbol() == "\u{25c0}"))
            .expect("focused option marker rendered");
        assert!(
            marker_row > 0
                && (0..buf.area.width)
                    .any(|x| buf[(x, marker_row)].bg != buf[(x, marker_row - 1)].bg),
            "the focused option must carry a highlight bar:\n{dump}"
        );
    }

    #[test]
    fn no_hand_rolled_colour_in_this_module() {
        // §4.61 Wave 4a's acceptance criterion, as a test rather than a
        // claim in a commit message. A surface that reaches for the
        // theme directly is a surface that will drift from the other
        // eleven — R1 is that every wave re-derives the colour rule
        // locally. Needles are split so this assertion cannot match
        // itself.
        let src = include_str!("scope_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in scope_modal.rs — the colour belongs in modal_form"
            );
        }
    }

    #[test]
    fn tail_fit_keeps_the_end_not_the_beginning() {
        // The mirror of `fit`: an input line's caret and the characters
        // just typed live at the END, so that is the half that survives.
        assert_eq!(tail_fit("hello", 10), "hello");
        assert_eq!(tail_fit("hello world", 5), "\u{2026}orld");
        assert_eq!(tail_fit("hello world", 5).chars().count(), 5);
        assert_eq!(tail_fit("anything", 0), "");
    }

    #[test]
    fn tail_fit_is_char_aware_not_byte_aware() {
        let out = tail_fit("café-società-naïve", 6);
        assert_eq!(out.chars().count(), 6);
        assert!(out.starts_with('\u{2026}'));
    }

    #[test]
    fn split_prompt_separates_the_warning_from_the_prompt() {
        // The default-scope const bundles both because the CLI prints it
        // as one `read_line`; at 76 columns it cannot share a modal row.
        let (warning, prompt) = split_prompt(RULES_BATCH_DEFAULT_CONFIRM);
        assert_eq!(
            warning,
            "This affects every unknown device on your network."
        );
        assert_eq!(prompt, "Type DEFAULT to confirm: ");
        // Reassembly is lossless — the split cannot quietly drop copy.
        assert_eq!(format!("{warning} {prompt}"), RULES_BATCH_DEFAULT_CONFIRM);
    }

    #[test]
    fn split_prompt_passes_through_a_prompt_with_no_warning() {
        let (warning, prompt) = split_prompt(RULES_BATCH_TYPE_CONFIRM);
        assert!(warning.is_empty());
        assert_eq!(prompt, RULES_BATCH_TYPE_CONFIRM);
    }

    // ── §4.61 Wave 4a: the 80×24 floor ───────────────────────────────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect this overlay anchors on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
    // 12-row interior. `overlay::centered_rect` CLAMPS rather than
    // scrolls, so a body taller than that is silently cut at the bottom
    // while `j`/`k` still move the cursor onto the rows that were cut —
    // the operator then confirms blind. These render the real
    // `render_overlay` into a backend the size of that content rect.

    /// Row-per-line dump. The newline matters: without it a substring can
    /// straddle a row boundary and match text that is not on any single
    /// rendered row — the false green the wave brief warns about.
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

    fn render_overlay_in(modal: &ScopeModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    #[test]
    fn floor_keeps_the_action_row_and_the_focused_entry_on_screen_together() {
        // The two things a clip silently takes away. Asserted on the
        // rendered buffer, never on the line vector: the vector was
        // correct in every past instance of this defect
        // (`lists-modal-min-height-clip`) — only the render was wrong.
        //
        // The cursor sits on the LAST entry, which is the case a body
        // that only ever renders page one cannot survive: the negative
        // assertion below pins that the viewport actually scrolled.
        //
        // The modal is the three-disabled one on purpose. §4.63 S1 grew
        // the field region from 4 rows to 7 (a 2-row head, a 3-row tail),
        // so the two-disabled menu now FITS and would prove nothing about
        // scrolling; three disabled entries put 8 rows in 7 and the
        // viewport has to move.
        let mut m = open_full(Action::Allow, Some("pc-gioele".into()), None, None, None);
        m.menu_cursor = ScopeMenuEntry::Default.index();
        let dump = render_overlay_in(&m, 80, 14);

        // Clip-proving needle first — `assert!` short-circuits, and this
        // is the row the pre-migration body loses at the floor.
        assert!(
            dump.contains("[\u{2191}/\u{2193}] move"),
            "the key legend is cut at the 80x24 floor:\n{dump}"
        );
        assert!(
            dump.contains("Default for unknown devices"),
            "the focused entry is off-screen:\n{dump}"
        );
        assert!(
            !dump.contains("Just this device"),
            "a 4-row viewport cannot be showing both ends of the menu:\n{dump}"
        );
        assert!(
            dump.contains('\u{25c0}'),
            "the focus marker must be on screen with the action row:\n{dump}"
        );
        assert!(
            dump.contains("Continue"),
            "action row cut at the floor — Enter still reaches it:\n{dump}"
        );
    }

    /// Pins `s4-63-g5-disabled-option-reason`.
    ///
    /// An entry the operator cannot pick must say why, and the two
    /// affordances that cover an *enabled* entry both structurally miss
    /// this case: the hint row only ever shows the FOCUSED entry's copy,
    /// and [`ScopeModal::move_cursor`] / [`ScopeModal::open`] both skip
    /// disabled entries — so focus can never land on one. Widening the
    /// modal is not available either: at the declared 80-column floor it
    /// is already full-bleed.
    ///
    /// Measured before the fix at the 62-column interior: profile needs
    /// 65 columns and subnet 77, so two of the three rendered with no
    /// explanation at all while `choice_row` dropped their reason whole.
    /// The pre-migration two-line layout showed all three.
    #[test]
    fn all_three_disabled_entries_state_their_reason_at_the_floor() {
        // Device matched, nothing else resolved → profile, group and
        // subnet are all disabled.
        let m = open_full(Action::Allow, Some("pc-gioele".into()), None, None, None);
        assert!(m.is_disabled(ScopeMenuEntry::Profile));
        assert!(m.is_disabled(ScopeMenuEntry::Group));
        assert!(m.is_disabled(ScopeMenuEntry::Subnet));

        let dump = render_overlay_in(&m, 80, 14);
        for (entry, needle) in [
            ("profile", "profile resolved for this device"),
            ("group", "not in any group"),
            ("subnet", "match any defined subnet"),
        ] {
            assert!(
                dump.contains(needle),
                "the {entry} entry is unselectable and says nothing about \
                 why at the 80x24 floor:\n{dump}"
            );
        }
    }

    /// Pins §4.65 UX1(a).
    ///
    /// The needle is deliberately the **profile** entry's description while
    /// the cursor sits on **device**. Asserting the focused entry's
    /// description instead would pass on the pre-fix build — the tail's
    /// hint row already carried that one in full, which is exactly the
    /// partial compensation the operator reported as insufficient. The
    /// property is "an option I am *not* standing on explains itself"; a
    /// test that measures the focused one measures the old mechanism.
    ///
    /// Measured on the pre-fix build: label `All devices on profile
    /// 'family'` is 31 cells, leaving the inline detail 27 of the 62-cell
    /// interior against a 41-character sentence — so the tail was cut and
    /// this needle was absent.
    ///
    /// At the floor the field region is 8 rows against the menu's 10, so
    /// entries 1-4 are in view and `Default` is not. That is why the
    /// all-five assertion lives in
    /// `every_choosable_entry_states_its_description_at_a_roomy_size` and
    /// this one names a needle the floor viewport can actually hold.
    #[test]
    fn every_choosable_entry_states_its_description_even_unfocused() {
        let m = open_all_resolved(Action::Allow);
        assert_eq!(m.menu_cursor, ScopeMenuEntry::Device.index());
        assert!(!m.is_disabled(ScopeMenuEntry::Profile));

        let dump = render_overlay_in(&m, 80, 14);
        assert!(
            dump.contains("Every device currently using this profile."),
            "an unfocused choosable entry must state its description \
             whole at the 80x24 floor:\n{dump}"
        );
    }

    /// The companion to the above at a height that fits the whole menu:
    /// every one of the five entries explains itself at once.
    ///
    /// Deliberately **not** at the floor. Ten field rows do not fit eight,
    /// and a test that demanded they did would be asserting the modal is
    /// shorter than it is — the row count is a function of the spec, so the
    /// honest floor property is the one above plus
    /// `floor_keeps_the_action_row_and_the_focused_entry_on_screen_together`.
    #[test]
    fn every_choosable_entry_states_its_description_at_a_roomy_size() {
        let m = open_all_resolved(Action::Allow);
        let dump = render_overlay_in(&m, 80, 24);
        for needle in [
            "Affects only this device, even if its profile changes.",
            "Every device currently using this profile.",
            "Every device that belongs to this group.",
            "Every device matched by this network range.",
            "Affects any new device that joins the network.",
        ] {
            assert!(
                dump.contains(needle),
                "description cut or dropped: {needle:?}\n{dump}"
            );
        }
    }

    /// The hint row is gone (`hint_rows: Some(0)`), and the row it freed is
    /// what pays for the five description rows. A duplicate of the focused
    /// entry's copy would cost a row of the tightest budget in the
    /// ecosystem to print something already on screen two rows above.
    #[test]
    fn the_focused_description_is_not_printed_twice() {
        let m = open_all_resolved(Action::Allow);
        let dump = render_overlay_in(&m, 80, 24);
        assert_eq!(
            dump.matches("Affects only this device, even if its profile changes.")
                .count(),
            1,
            "the focused entry's description is on screen twice:\n{dump}"
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
        let m = open(Action::Allow, true);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, anchor, &m)).unwrap();
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
    fn floor_default_confirm_keeps_the_typed_line_and_the_action_row_together() {
        // The tallest confirm: four prose rows against a field region of
        // six at the D18 floor. This stage has no `choices`, so nothing in
        // the field region can take focus, `ScrollBody::scrollable` is
        // false and no scrollbar is drawn — if the prose ever outgrows the
        // region the line the operator is typing into is cut away with no
        // key to bring it back and no affordance saying it happened. This
        // pins the ceiling.
        let mut m = open(Action::Allow, true);
        m.menu_cursor = ScopeMenuEntry::Default.index();
        m.enter_confirm();
        for c in "DEFA".chars() {
            m.push_char(c);
        }
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("Type DEFAULT to confirm: DEFA_"),
            "the typed line and its caret must be on screen:\n{dump}"
        );
        assert!(
            dump.contains("This affects every unknown device"),
            "the warning half of the prompt must survive the split:\n{dump}"
        );
        assert!(
            dump.contains("[Enter] Confirm"),
            "action row cut at the floor:\n{dump}"
        );
    }

    #[test]
    fn floor_typed_confirm_keeps_the_typed_line_and_the_action_row_together() {
        let mut m = open(Action::Deny, true);
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        m.enter_confirm();
        for c in "defa".chars() {
            m.push_char(c);
        }
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("Type the scope id to confirm: defa_"),
            "the typed line and its caret must be on screen:\n{dump}"
        );
        assert!(
            dump.contains("[Enter] Confirm"),
            "action row cut at the floor:\n{dump}"
        );
        // Reversed from Wave 4a, which asserted the id must NOT be
        // reprinted here ("the gate is retyping the id from the entry you
        // chose"). That model is a recall test, not a confirmation: the
        // id is a machine-resolved slug, the menu row holding it is
        // repainted away by `notice` on Enter, and the tier-3 gate one
        // stage over prints the very word it demands. The tighter tier
        // cannot be the one that hides its answer.
        //
        // Asserted at the floor, not just at 80x24 — the id row is the
        // newest of the four prose rows and the first thing a fifth would
        // scroll off screen.
        assert!(
            dump.contains("profile id: default"),
            "the confirm screen must show the id it asks the operator to type:\n{dump}"
        );
    }

    /// A modal with all four ids resolved, so any entry can be driven.
    fn open_all_resolved(action: Action) -> ScopeModal {
        open_full(
            action,
            Some("pc-gioele".into()),
            Some("family".into()),
            Some("kids".into()),
            Some("lan-home".into()),
        )
    }

    fn confirm_stage_for(entry: ScopeMenuEntry, action: Action) -> ScopeModal {
        let mut m = open_all_resolved(action);
        m.menu_cursor = entry.index();
        assert_eq!(m.enter_confirm(), Some(entry));
        m
    }

    #[test]
    fn typed_confirm_shows_the_id_for_every_typed_scope() {
        // The defect this whole change exists for: `notice` repaints the
        // body per stage, so advancing off the menu took the only copy of
        // the id with it — and the screen that replaced it demanded that
        // id back. Checked for all three tier-2 entries, because the id
        // came from a different `captured_*` field in each and the
        // renderer had a `match` for none of them.
        for (entry, needle) in [
            (ScopeMenuEntry::Profile, "profile id: family"),
            (ScopeMenuEntry::Group, "group id: kids"),
            (ScopeMenuEntry::Subnet, "subnet id: lan-home"),
        ] {
            let m = confirm_stage_for(entry, Action::Deny);
            let dump = render_overlay_in(&m, 80, 24);
            assert!(
                dump.contains(needle),
                "{entry:?} confirm must show {needle:?}:\n{dump}"
            );
        }
    }

    #[test]
    fn chosen_scope_id_is_the_id_ready_to_submit_accepts() {
        // The accessor and the gate are the pair that drifted apart —
        // the gate held its own `match`, the renderer had none. Pin both
        // directions: what the accessor names is what the gate takes,
        // and the two entries with no typed id stay `None`.
        let m = open_all_resolved(Action::Allow);
        for entry in [
            ScopeMenuEntry::Profile,
            ScopeMenuEntry::Group,
            ScopeMenuEntry::Subnet,
        ] {
            let id = m
                .chosen_scope_id(entry)
                .unwrap_or_else(|| panic!("{entry:?} must resolve an id"))
                .to_string();
            let mut typed = confirm_stage_for(entry, Action::Allow);
            for c in id.chars() {
                typed.push_char(c);
            }
            let resolved = typed
                .ready_to_submit()
                .unwrap_or_else(|| panic!("{entry:?} must submit on {id:?}"));
            let got = match resolved {
                ResolvedScope::Profile(v)
                | ResolvedScope::Group(v)
                | ResolvedScope::Subnet(v)
                | ResolvedScope::Device(v) => v,
                ResolvedScope::Default => panic!("{entry:?} resolved to Default"),
            };
            assert_eq!(got, id, "{entry:?} submitted a different id");
        }
        assert!(m.chosen_scope_id(ScopeMenuEntry::Device).is_none());
        assert!(m.chosen_scope_id(ScopeMenuEntry::Default).is_none());
    }

    #[test]
    fn note_failed_submit_names_the_expected_id() {
        let mut m = confirm_stage_for(ScopeMenuEntry::Subnet, Action::Deny);
        for c in "lanhome".chars() {
            m.push_char(c);
        }
        assert!(m.ready_to_submit().is_none(), "typo must not submit");
        m.note_failed_submit();
        let err = m.error.as_deref().expect("a rejected buffer must explain");
        assert!(
            err.contains("lan-home"),
            "the rejection must name the id: {err:?}"
        );
    }

    #[test]
    fn note_failed_submit_is_quiet_until_something_is_typed() {
        // Enter on an untouched buffer is not a mistake — the operator
        // has not answered yet. An error here would fire before they
        // could possibly be wrong.
        let mut m = confirm_stage_for(ScopeMenuEntry::Subnet, Action::Deny);
        m.note_failed_submit();
        assert!(m.error.is_none(), "empty buffer must not be an error");
    }

    #[test]
    fn note_failed_submit_on_default_confirm_asks_for_capitals() {
        // The not-ready branch in `handle_scope_modal_key` is not
        // stage-scoped, so tier 3 shared the silent path: a lowercase
        // `default` is rejected by `ready_to_submit` with nothing said.
        let mut m = confirm_stage_for(ScopeMenuEntry::Default, Action::Deny);
        for c in "default".chars() {
            m.push_char(c);
        }
        assert!(m.ready_to_submit().is_none());
        m.note_failed_submit();
        let err = m.error.as_deref().expect("lowercase must be explained");
        assert!(err.contains("DEFAULT"), "must name the phrase: {err:?}");
    }

    #[test]
    fn editing_the_buffer_clears_a_stale_rejection() {
        // A rejection describes one buffer. Left standing over the next
        // keystroke it contradicts what is on screen, which is worse than
        // the silence it replaced.
        let mut m = confirm_stage_for(ScopeMenuEntry::Group, Action::Allow);
        m.push_char('x');
        m.note_failed_submit();
        assert!(m.error.is_some());
        m.push_char('y');
        assert!(m.error.is_none(), "a keystroke must clear the rejection");

        m.note_failed_submit();
        assert!(m.error.is_some());
        m.backspace();
        assert!(m.error.is_none(), "backspace must clear the rejection");
    }

    #[test]
    fn leaving_the_stage_clears_a_stale_rejection() {
        let mut m = confirm_stage_for(ScopeMenuEntry::Group, Action::Allow);
        m.push_char('x');
        m.note_failed_submit();
        m.back_to_menu();
        assert!(m.error.is_none(), "Esc must clear the rejection");

        m.push_char('x'); // no-op on the menu stage
        m.note_failed_submit();
        m.error = Some("stale".into());
        m.menu_cursor = ScopeMenuEntry::Subnet.index();
        m.enter_confirm();
        assert!(m.error.is_none(), "a new confirm stage starts clean");
    }

    #[test]
    fn a_rejected_scope_id_reaches_the_screen_and_takes_the_hint_slot() {
        // `NoticeSpec::error` rides the pinned tail, where it displaces
        // the hint — so it costs no prose row and cannot push the typed
        // line off screen. Asserted at the floor for that reason.
        let mut m = confirm_stage_for(ScopeMenuEntry::Subnet, Action::Deny);
        for c in "lanhome".chars() {
            m.push_char(c);
        }
        m.note_failed_submit();
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("type the id exactly"),
            "the rejection must be on screen:\n{dump}"
        );
        assert!(
            !dump.contains("the id must match the entry you picked"),
            "the error takes the hint slot, it does not stack with it:\n{dump}"
        );
        assert!(
            dump.contains("Type the scope id to confirm: lanhome_"),
            "the typed line must survive the error row:\n{dump}"
        );
        assert!(
            dump.contains("subnet id: lan-home"),
            "the id row must survive the error row:\n{dump}"
        );
    }

    #[test]
    fn a_long_typed_buffer_scrolls_left_and_keeps_the_caret() {
        // `prose_row` truncates on the right. Without `tail_fit` an
        // over-long buffer would push the caret — and everything just
        // typed — off the end of the row, and the pre-migration `Wrap`
        // that used to spill onto a second line is gone.
        let mut m = open(Action::Allow, true);
        m.menu_cursor = ScopeMenuEntry::Profile.index();
        m.enter_confirm();
        for c in "x".repeat(200).chars() {
            m.push_char(c);
        }
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("xxx_"),
            "the caret must stay visible at the end of a long buffer:\n{dump}"
        );
        assert!(
            dump.contains('\u{2026}'),
            "the horizontal scroll must be marked:\n{dump}"
        );
        // Rows are clipped, never wrapped: the action row is still there.
        assert!(
            dump.contains("[Enter] Confirm"),
            "a long buffer must not push the action row off:\n{dump}"
        );
    }

    #[test]
    fn floor_outcome_screens_keep_their_message_and_close_action() {
        let mut ok = open(Action::Allow, true);
        ok.finish(SubmitOutcome::Ok("allow rule added for ads.example".into()));
        let dump = render_overlay_in(&ok, 80, 14);
        assert!(dump.contains("allow rule added"), "outcome lost:\n{dump}");
        assert!(dump.contains("Close"), "close action cut:\n{dump}");

        // A failure rides the `error` slot, which hard-wraps — the long
        // `add_inner` rejections used to run off a single line.
        let mut bad = open(Action::Deny, true);
        bad.finish(SubmitOutcome::Failed(
            "rule not added: profile 'default' already carries an allow \
             for this domain — remove it first"
                .into(),
        ));
        let dump = render_overlay_in(&bad, 80, 14);
        assert!(
            dump.contains('\u{26a0}'),
            "a failure carries the ⚠ affordance:\n{dump}"
        );
        assert!(
            dump.contains("remove it first"),
            "the tail of the message must survive the wrap:\n{dump}"
        );
    }

    /// Was `a_disabled_entry_shows_its_reason_only_when_the_row_can_hold_it`,
    /// which pinned G5 as a KNOWN DEFECT with two negative assertions and
    /// an instruction to invert them when a disabled-aware `ChoiceRow`
    /// landed. §4.63 S1 landed it; they are inverted here and the
    /// simultaneous-at-the-floor case lives in
    /// `all_three_disabled_entries_state_their_reason_at_the_floor`.
    #[test]
    fn every_disabled_entry_states_its_reason_in_full() {
        let m = open_full(Action::Allow, Some("pc".into()), None, None, None);
        let dump = render_overlay_in(&m, 80, 24);

        // The three measured 65 / 58 / 77 columns against a 62-column
        // body. All three now render whole, on a row of their own when
        // the option's line cannot hold them.
        for needle in [
            "(No profile resolved for this device)",
            "(This device is not in any group)",
            "(This device's IP doesn't match any defined subnet)",
        ] {
            assert!(dump.contains(needle), "reason cut or dropped:\n{dump}");
        }
        // The options themselves stay listed: an operator must be able to
        // see that a scope exists as well as why it is unavailable.
        for label in [
            "All devices on profile",
            "All devices in group",
            "All devices on subnet",
        ] {
            assert!(dump.contains(label), "{label} missing entirely:\n{dump}");
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test scope_visual_dump -- --ignored --nocapture"]
    fn scope_visual_dump() {
        let mut m = open_full(
            Action::Allow,
            Some("pc-gioele".into()),
            Some("default".into()),
            Some("famiglia".into()),
            Some("vlan-marketing".into()),
        );
        println!(
            "--- menu, roomy anchor ---\n{}",
            render_overlay_in(&m, 100, 40)
        );
        println!(
            "--- menu, the 80x24 floor (14-row content rect) ---\n{}",
            render_overlay_in(&m, 80, 14)
        );
        m.menu_cursor = ScopeMenuEntry::Default.index();
        println!(
            "--- same, cursor on the last entry ---\n{}",
            render_overlay_in(&m, 80, 14)
        );
        // Nothing but the device resolved → three disabled entries, the
        // shape §4.63 S1's G5 was measured on and the one every row-budget
        // number in `_docs/features/tui_modal_contract_v1.md` came off.
        let disabled = open_full(Action::Allow, Some("pc-gioele".into()), None, None, None);
        println!("--- three disabled entries, the 80x24 floor ---");
        for (i, l) in render_overlay_in(&disabled, 80, 14).lines().enumerate() {
            println!("{i:>2}|{l}|");
        }
        let mut dev = open(Action::Deny, true);
        dev.enter_confirm();
        println!(
            "--- device confirm ---\n{}",
            render_overlay_in(&dev, 80, 14)
        );
        let mut typed = open(Action::Deny, true);
        typed.menu_cursor = ScopeMenuEntry::Profile.index();
        typed.enter_confirm();
        for c in "defa".chars() {
            typed.push_char(c);
        }
        println!(
            "--- typed confirm ---\n{}",
            render_overlay_in(&typed, 80, 14)
        );
        let mut def = open(Action::Deny, true);
        def.menu_cursor = ScopeMenuEntry::Default.index();
        def.enter_confirm();
        println!(
            "--- default confirm ---\n{}",
            render_overlay_in(&def, 80, 14)
        );
        let mut bad = open(Action::Deny, true);
        bad.finish(SubmitOutcome::Failed(
            "rule not added: profile 'default' already carries an allow for this domain — remove it first".into(),
        ));
        println!(
            "--- submit failure ---\n{}",
            render_overlay_in(&bad, 80, 14)
        );
    }
}
