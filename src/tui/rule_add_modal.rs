//! Rules tab — "add rule" modal (`a` keybinding), wave2/rules-add-key.
//!
//! Today the Rules tab has no create path — an admin rule can only be
//! added via the Query Log's scope modal (`scope_modal.rs`, opened with
//! `Enter` on a focused row) or the `warden` CLI verbs. This module adds
//! a direct create path from the Rules tab itself: `[a]` opens a form
//! (Domain / Action / Scope), and submit fires through the SAME R7
//! single-seat mutation surface as every other add path —
//! `cli::commands::rules::add_inner` — so there is exactly one place in
//! the codebase that writes a new `[[admin_rules]]` row + entity
//! reference. No new IPC verb, no new write path.
//!
//! Scope choices reuse `app::ScopeChoice` (Default / Profile / Device)
//! and `tabs::rules::build_scope_options`, the same snapshot the Rules
//! edit modal already uses — one source of truth for "what scopes can
//! an operator pick from this tab".
//!
//! ## Fence note (see REPORT.md)
//!
//! The async submit path here calls `super::poll_active_leaf` and
//! `super::load_v1_config` — private free functions defined at the
//! `crate::tui` module root. Rust's privacy rules make module-private
//! items visible to descendant modules, and `rule_add_modal` is a
//! descendant of `tui`, so this is a legal, ordinary same-crate call —
//! not a change to either function's signature or visibility.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::Frame;
use std::path::Path;

use crate::filter::rules::RuleAction;
use crate::tui::app::{App, ScopeChoice};
use crate::tui::ipc_poller::IpcPoller;
use crate::tui::modal_form::{self, Action, ActionKind, ValueKind};
use crate::tui::tabs::rules::build_scope_options;

// ── frozen strings ───────────────────────────────────────────────────

/// Modal title, pinned by `tests/frozen_strings_tui_rules_add.rs`.
pub const ADD_RULE_MODAL_TITLE: &str = " Add rule ";
pub const LABEL_DOMAIN: &str = "Domain";
pub const LABEL_ACTION: &str = "Action";
pub const LABEL_SCOPE: &str = "Scope";
// N14: the save/cancel clause is gone. Neither action on this row is a
// Tab target (see `form_body`'s comment on `actions`), so each button
// bakes its own key into its label instead — `keys_legend()` no longer
// needs to carry either key, and a second, dead `ADD_RULE_HINT_2` const
// that once carried "Esc cancel" (word `cancel`, which §3.1 now
// forbids) was deleted rather than repointed: it had no render call
// site, only this file's frozen-strings test kept it alive.
pub const ADD_RULE_HINT_1: &str =
    "  Tab/\u{2191}\u{2193} move  \u{2022}  \u{2190}/\u{2192} change action/scope";
/// Placeholder shown in the Domain field before the operator types
/// anything.
pub const DOMAIN_PLACEHOLDER: &str = "(type a domain, e.g. ads.example.com)";
/// Rules-tab empty-state lead hint (DoD: "leads with `[a] add rule`").
/// Rendered ahead of the Query Log / CLI secondary hints in
/// `tabs::rules::render_empty_state`.
pub const RULES_EMPTY_ADD_HINT: &str = "  [a] add rule — create one directly from this tab.";

// ── modal state ───────────────────────────────────────────────────────

/// Tab-cycle focus targets in [`RuleAddModal`]. Mirrors
/// `app::RuleEditFocus`'s cycle contract minus the delete button (this
/// modal only ever creates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddFocus {
    Domain,
    Action,
    Scope,
}

impl AddFocus {
    const ORDER: [AddFocus; 3] = [AddFocus::Domain, AddFocus::Action, AddFocus::Scope];

    pub fn next(self) -> AddFocus {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> AddFocus {
        let len = Self::ORDER.len();
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + len - 1) % len]
    }
}

/// Open-state for the Rules-tab add modal. Lifecycle mirrors
/// `app::RuleEditModal`: `Some` in `app.rules.add_modal` while open,
/// `None` otherwise, submitted/cancelled paths both clear it.
#[derive(Debug, Clone)]
pub struct RuleAddModal {
    pub domain: String,
    pub action: RuleAction,
    pub scope_choice: ScopeChoice,
    /// Snapshot of pickable scopes taken at modal-open time (mirrors the
    /// edit modal's capture-at-open invariant — a config refresh mid-form
    /// cannot surprise the operator with a vanished scope).
    pub scope_options: Vec<ScopeChoice>,
    pub focus: AddFocus,
    pub error_message: Option<String>,
    pub status_message: Option<String>,
    pub submitting: bool,
}

impl RuleAddModal {
    /// Open a fresh, blank modal. Defaults to `RuleAction::Block` (the
    /// primary purge-warden use case) and the first available scope
    /// option (falling back to `Default` when nothing is configured —
    /// submit will then surface add_inner's own "no default profile"
    /// error rather than crash).
    pub fn open(app: &App) -> Self {
        let scope_options = build_scope_options(app);
        let scope_choice = scope_options
            .first()
            .cloned()
            .unwrap_or(ScopeChoice::Default);
        Self {
            domain: String::new(),
            action: RuleAction::Block,
            scope_choice,
            scope_options,
            focus: AddFocus::Domain,
            error_message: None,
            status_message: None,
            submitting: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        if self.focus == AddFocus::Domain {
            self.domain.push(c);
            self.error_message = None;
        }
    }

    pub fn backspace(&mut self) {
        if self.focus == AddFocus::Domain {
            self.domain.pop();
            self.error_message = None;
        }
    }

    pub fn toggle_action(&mut self) {
        self.action = match self.action {
            RuleAction::Block => RuleAction::Allow,
            RuleAction::Allow => RuleAction::Block,
        };
        self.error_message = None;
    }

    /// Cycle `scope_choice` through `scope_options` in `dir` (+1 / -1).
    /// Wraps. No-op if `scope_options` is empty. Mirrors
    /// `tabs::rules::cycle_scope_choice`.
    pub fn cycle_scope(&mut self, dir: i32) {
        if self.scope_options.is_empty() {
            return;
        }
        let len = self.scope_options.len() as i32;
        let current_idx = self
            .scope_options
            .iter()
            .position(|c| c == &self.scope_choice)
            .map(|i| i as i32)
            .unwrap_or(0);
        let next_idx = (current_idx + dir).rem_euclid(len) as usize;
        self.scope_choice = self.scope_options[next_idx].clone();
        self.error_message = None;
    }
}

/// Pure fn: modal fields → the validated (domain, action, scope) payload
/// ready to feed `cli::commands::rules::add_inner`. Only checks the
/// domain is non-empty after trimming — real domain syntax validation
/// belongs to `add_inner`'s own `validate_domain` call, so this stays a
/// thin, easily-testable gate rather than a second source of truth for
/// "what is a valid domain".
pub fn build_submit_payload(
    modal: &RuleAddModal,
) -> Result<(String, RuleAction, ScopeChoice), String> {
    let domain = modal.domain.trim();
    if domain.is_empty() {
        return Err("domain is required".to_string());
    }
    Ok((domain.to_string(), modal.action, modal.scope_choice.clone()))
}

// ── key handling ─────────────────────────────────────────────────────

/// Drive the add-modal's state machine on each keypress. Gated in
/// `tui::mod::handle_key` (mirrors the `app.rules.edit_modal` gate at
/// mod.rs:516-519) so every keystroke routes here while the modal is
/// open, instead of leaking into the global keybindings (`q`, `1-5`,
/// `Tab`, …).
pub async fn handle_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) {
    let Some(mut modal) = app.rules.add_modal.take() else {
        return;
    };
    if modal.submitting && !matches!(key.code, KeyCode::Esc) {
        app.rules.add_modal = Some(modal);
        return;
    }

    // Ctrl+S submits regardless of focus — mirrors the edit modal's
    // Ctrl+S-from-anywhere convention (`handle_rule_edit_form_key`).
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        submit(app, modal, poller, config_path).await;
        return;
    }

    // N14: Enter submits too. Neither action on this row is a Tab
    // target (see `form_body`), so the button bakes in its own key
    // (`[Enter] Save`) rather than relying on focus + the field-default
    // Enter meaning — the key must therefore actually save, or the
    // label lies. Kept as an early return, same shape as Ctrl+S above,
    // so `modal` is consumed once and the ordinary match below never
    // sees Enter.
    if matches!(key.code, KeyCode::Enter) {
        submit(app, modal, poller, config_path).await;
        return;
    }

    match key.code {
        KeyCode::Esc => {
            // Modal simply closes — nothing has been written yet.
            return;
        }
        // §4.63 nav-grammar: Up/Down MOVE FOCUS, Left/Right cycle the
        // focused field's value — the grammar every other form modal was
        // converted to in s3b. This handler was the third outlier and the
        // last one where Up/Down did not move focus.
        //
        // An addition, not a swap: Tab and BackTab keep working. The
        // operator who learned Tab here loses nothing; the one who
        // reached for an arrow key stops being ignored.
        KeyCode::Tab | KeyCode::Down => {
            modal.focus = modal.focus.next();
            modal.error_message = None;
        }
        KeyCode::BackTab | KeyCode::Up => {
            modal.focus = modal.focus.prev();
            modal.error_message = None;
        }
        KeyCode::Left | KeyCode::Right => match modal.focus {
            AddFocus::Domain => {}
            AddFocus::Action => modal.toggle_action(),
            AddFocus::Scope => {
                let dir = if matches!(key.code, KeyCode::Right) {
                    1
                } else {
                    -1
                };
                modal.cycle_scope(dir);
            }
        },
        KeyCode::Backspace => modal.backspace(),
        KeyCode::Char(c) => modal.push_char(c),
        _ => {}
    }
    app.rules.add_modal = Some(modal);
}

/// Fire the resolved (domain, action, scope) into `add_inner` + reload.
/// Mirrors `submit_scope_modal` / `submit_rule_edit_modal` in
/// `tui::mod`: on `Applied`, refreshes `loaded_config` and re-polls the
/// active leaf so the new row shows up in the table on the very next
/// frame, then requests the daemon reload (HR2 single shared reload).
async fn submit(app: &mut App, mut modal: RuleAddModal, poller: &IpcPoller, config_path: &Path) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use crate::cli::commands::rules::{
        add_inner, Action as CliAction, ChangeOutcome, NoOpReason, Scope,
    };

    let (domain, rule_action, scope_choice) = match build_submit_payload(&modal) {
        Ok(payload) => payload,
        Err(e) => {
            modal.error_message = Some(e);
            app.rules.add_modal = Some(modal);
            return;
        }
    };
    let cli_action = match rule_action {
        RuleAction::Allow => CliAction::Allow,
        RuleAction::Block => CliAction::Deny,
    };
    let scope_id: String = match &scope_choice {
        ScopeChoice::Default => String::new(),
        ScopeChoice::Profile(id) | ScopeChoice::Device(id) => id.clone(),
    };
    let scope = match &scope_choice {
        ScopeChoice::Default => Scope::Default,
        ScopeChoice::Profile(_) => Scope::Profile(scope_id.as_str()),
        ScopeChoice::Device(_) => Scope::Device(scope_id.as_str()),
    };

    modal.submitting = true;
    modal.status_message = Some("adding\u{2026}".into());
    app.rules.add_modal = Some(modal.clone());

    let outcome = add_inner(config_path, scope, cli_action, &domain, None, None);

    match outcome {
        Ok(ChangeOutcome::Applied(report)) => {
            app.rules.add_modal = None;
            app.status_ok(format!(
                "{}: rule '{}' added",
                cli_action.slug(),
                report.rule_id
            ));
            app.loaded_config = super::load_v1_config(config_path);
            super::poll_active_leaf(app, poller).await;
            let reload_outcome = attempt_reload(poller.socket_path()).await;
            match reload_outcome {
                ReloadOutcome::Reloaded => {}
                ReloadOutcome::DaemonUnreachable => {
                    app.status_err(
                        "rule saved on disk — daemon not running, will activate on next start"
                            .into(),
                    );
                }
                ReloadOutcome::NoToken { .. } => {
                    app.status_err(
                        "rule saved on disk but no admin token is available to request a reload"
                            .into(),
                    );
                }
                ReloadOutcome::ReloadFailed(msg) => {
                    app.status_err(format!("rule saved but daemon rejected reload: {msg}"));
                }
            }
        }
        Ok(ChangeOutcome::NoOp(NoOpReason::AlreadyPresent { rule_id })) => {
            app.rules.add_modal = None;
            app.status_ok(format!(
                "{} rule already present (id: {rule_id}) — no-op",
                cli_action.slug()
            ));
        }
        Err(e) => {
            if let Some(m) = app.rules.add_modal.as_mut() {
                m.submitting = false;
                m.status_message = None;
                m.error_message = Some(format!("add failed: {e}"));
            }
        }
    }
}

// ── render (§4.61 Wave 3b — Archetype F) ──────────────────────────────
//
// Every colour below comes from `modal_form`. A locally-built foreground
// style, a full-border block or a direct reach into the theme's brand red
// is R1 — the twelve-surfaces-each-re-deriving-the-colour-rule drift the
// workstream exists to end. Pinned by
// `no_hand_rolled_colour_in_this_module`, which greps this file's own
// source; the needles are spelled out there, deliberately not here, so
// the guard cannot match the comment that describes it.

/// Modal width, matching the rest of the Archetype-F ecosystem
/// (`tabs/lists.rs`, `subnet_modal.rs`).
const MODAL_W: u16 = 64;

/// Nav-key legend: [`ADD_RULE_HINT_1`] minus its own two-cell indent,
/// which [`modal_form::nav_keys_line`] re-adds — so the migrated legend
/// row renders byte-identical to the pre-migration hint row. §4.61 D7′
/// changes chrome, layout and colour and leaves the keying — and the
/// copy that advertises it — alone.
fn keys_legend() -> &'static str {
    ADD_RULE_HINT_1.trim_start()
}

/// One-line guidance for the focused field, shown on the tail's hint row
/// whenever there is no pending error. Per-field guidance is what
/// Archetype F gives a form in exchange for the second static hint line
/// the grid layout used to carry.
fn field_hint(f: AddFocus) -> &'static str {
    match f {
        AddFocus::Domain => "the domain this rule matches, e.g. ads.example.com",
        AddFocus::Action => "Block drops the answer, Allow overrides every blocklist \u{2014} \u{2191}/\u{2193} to change",
        AddFocus::Scope => {
            "who it applies to: the default profile, one profile, or one device \u{2014} \u{2191}/\u{2193} to change"
        }
    }
}

/// The transient "we are talking to the config right now" message, if any.
///
/// It goes to [`modal_form::form_tail_with_status`]'s own slot — its own
/// row, in the theme's neutral status colour — and the focused field keeps
/// its guidance underneath. Before §4.63 S1 Archetype F's tail offered
/// only `error` and `hint`, so this was handed to *every* row in place of
/// its hint: the status wore the hint's muted italic and the guidance for
/// the field the operator was standing on disappeared for the duration of
/// the submit. An error still wins over both.
fn transient_status(modal: &RuleAddModal) -> Option<&str> {
    modal.status_message.as_deref().or({
        if modal.submitting {
            Some("adding\u{2026}")
        } else {
            None
        }
    })
}

/// The scope picker's display value.
fn scope_text(modal: &RuleAddModal) -> String {
    if modal.scope_options.is_empty() {
        format!("{} (no other scopes available)", modal.scope_choice.label())
    } else {
        modal.scope_choice.label()
    }
}

/// The two description rows for the add form, on their own `bg_main`
/// strip under the title band ([`modal_form::desc_band2`], 2026-08-07).
///
/// Not the title's `bg_highlight` — teal on it is 3.37:1 against a 4.5:1
/// prose bar, and no contrast gate covers the pair. See `desc_band2`.
///
/// Row 2 states the precedence, which no single field's hint owns: it is a
/// property of the rule against **every** loaded list, not of `Action` or
/// `Scope` alone. It is the same sentence `tabs/rules::EDIT_DESC` carries,
/// deliberately — an operator meets the same fact in the same words whether
/// they are creating the rule or changing it.
///
/// Budget per row is [`MODAL_W`] − 5 = **59**: −2 chrome, −1 for the
/// scrollbar column on the narrow build pass, −2 for the band's indent.
/// `render_body_fixed` does not wrap, so an over-long row is cut at the
/// rect edge with no marker. Pinned by
/// `no_desc_row_outruns_the_narrow_build_pass`.
const ADD_DESC: [&str; 2] = [
    "create an admin rule and attach it to a scope",
    "admin rules outrank every blocklist, for that scope only",
];

/// Build the add form as an Archetype-F [`modal_form::ScrollBody`] —
/// pinned head, scrolling field region, pinned tail — plus the real
/// cursor target (field-region row index + caret offset) for the Domain
/// field when it holds focus.
///
/// The head is **4** rows ([`ADD_DESC`] is two of them). `scroll_layout`
/// serves the tail first and the head second, so at the D18 floor's 12
/// interior rows that comes out of the field viewport: with this modal's
/// default 5-row tail (spacer + 2 note + keys + actions) the viewport went
/// 4 rows → **3**.
///
/// Nothing here branches on `width`: [`modal_form::render_modal`] sizes
/// the chrome from a first build and may call this again one column
/// narrower, so a width-dependent *row count* would silently mis-size
/// the modal. Width may only change a row's content.
fn form_body(modal: &RuleAddModal, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let status = transient_status(modal);
    let hint = field_hint;

    let mut rows = modal_form::FormRows::new_desc2(ADD_RULE_MODAL_TITLE.trim(), ADD_DESC, width);

    rows.section("Rule");
    let domain = modal.focus == AddFocus::Domain;
    // The `_` caret of the old grid is gone — the focused text field
    // hosts the real terminal cursor, as the operator-validated Lists
    // reference does. No truncation on an editable value, also matching
    // the reference: cutting what the operator is typing is worse than
    // letting the modal edge cut it.
    rows.text_field(
        modal_form::value_row(
            LABEL_DOMAIN,
            &modal.domain,
            domain,
            ValueKind::Identity,
            Some(DOMAIN_PLACEHOLDER),
            width,
        ),
        domain,
        hint(AddFocus::Domain),
        modal.domain.chars().count() as u16,
    );
    rows.spacer();

    rows.section("Policy");
    let action = modal.focus == AddFocus::Action;
    rows.field(
        modal_form::radio_row(
            LABEL_ACTION,
            ("Block", ValueKind::Blocking),
            ("Allow", ValueKind::Healthy),
            matches!(modal.action, RuleAction::Block),
            action,
            width,
        ),
        action,
        hint(AddFocus::Action),
    );
    let scope = modal.focus == AddFocus::Scope;
    rows.field(
        modal_form::selector_row(LABEL_SCOPE, &scope_text(modal), scope, width),
        scope,
        hint(AddFocus::Scope),
    );

    // Neither action is a Tab target: this modal's focus ring is the
    // three fields, and Esc / Enter (N14) discard and save from
    // anywhere. Both therefore carry their key IN the label, the same
    // way `subnet_modal::remove_notice` does — an unkeyed button that
    // focus never reaches tells the operator nothing about how to press
    // it. Ctrl+S still works (`handle_key`) but is no longer advertised
    // here: N14 keeps it to one mention on the modal surface, and Enter
    // is that mention now.
    //
    // This is load-bearing for `Esc`, not decoration. Archetype F's tail
    // has one legend row, the legend is `ADD_RULE_HINT_1` verbatim, and
    // that string does not mention Esc — so without the label the only
    // way to close this modal would appear nowhere on screen. Pinned by
    // `esc_and_enter_are_discoverable_without_focus`.
    let actions = [
        Action::new("  [Esc] Discard  ", false, ActionKind::Neutral, ""),
        Action::new("  [Enter] Save  ", false, ActionKind::Primary, ""),
    ];

    let tail = modal_form::form_tail_with_status(
        &rows,
        status,
        modal.error_message.as_deref(),
        "",
        keys_legend(),
        &actions,
    );
    rows.finish(tail)
}

/// Draw the add-rule modal anchored on the tab content rect.
///
/// `anchor` is the Rules tab's content area (§4.61 D18), never
/// `f.area()`: the header, the menu card and the footer legend stay
/// visible behind it. That leaves a 12-row interior at the declared
/// 80×24 floor against a body of 16, which is why this is a
/// [`modal_form::ScrollBody`] rendered through
/// [`modal_form::render_modal`] — `overlay::centered_rect` clamps rather
/// than scrolls, so without the focus-following viewport the tail would
/// simply be cut while `Tab` went on reaching the rows that were cut.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &RuleAddModal) {
    let render = modal_form::render_modal(f, anchor, MODAL_W, |w| form_body(modal, w));
    if let Some((row, caret)) = render.cursor {
        render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_modal() -> RuleAddModal {
        RuleAddModal {
            domain: String::new(),
            action: RuleAction::Block,
            scope_choice: ScopeChoice::Default,
            scope_options: vec![ScopeChoice::Default],
            focus: AddFocus::Domain,
            error_message: None,
            status_message: None,
            submitting: false,
        }
    }

    // ── §4.63 nav grammar, driven through the production handler ───────
    //
    // The existing tests below exercise `AddFocus::next`/`prev` directly.
    // Those pass whether or not any key is WIRED to them — which is
    // exactly the state this modal was in: `focus.next()` was correct and
    // reachable only from Tab, and Up/Down cycled values instead. The DoD
    // therefore asks for real `KeyCode`s through `handle_key`, so these
    // drive the handler.

    /// A poller pointed at a socket that does not exist.
    ///
    /// Sound for these tests because every key under test returns from the
    /// `match` before any IPC is attempted; only Ctrl+S reaches the wire,
    /// and none of these send it.
    fn dead_poller(dir: &std::path::Path) -> IpcPoller {
        IpcPoller::new(&dir.join("ghost.sock"))
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    async fn drive(modal: RuleAddModal, keys: &[KeyCode]) -> RuleAddModal {
        let dir = tempfile::tempdir().unwrap();
        let poller = dead_poller(dir.path());
        let cfg = dir.path().join("config.toml");
        let mut app = App::new();
        app.rules.add_modal = Some(modal);
        for code in keys {
            handle_key(&mut app, k(*code), &poller, &cfg).await;
        }
        app.rules
            .add_modal
            .expect("modal stays open across nav keys")
    }

    #[tokio::test]
    async fn down_and_up_move_focus_through_the_handler() {
        let m = drive(blank_modal(), &[KeyCode::Down]).await;
        assert_eq!(
            m.focus,
            AddFocus::Action,
            "Down must MOVE FOCUS, not cycle the focused value"
        );

        let m = drive(m, &[KeyCode::Up]).await;
        assert_eq!(m.focus, AddFocus::Domain, "Up is the mirror of Down");
    }

    /// The conversion is an ADDITION. An operator with Tab in their
    /// fingers must lose nothing.
    #[tokio::test]
    async fn tab_and_backtab_still_move_focus() {
        let m = drive(blank_modal(), &[KeyCode::Tab]).await;
        assert_eq!(m.focus, AddFocus::Action);
        let m = drive(m, &[KeyCode::BackTab]).await;
        assert_eq!(m.focus, AddFocus::Domain);
    }

    #[tokio::test]
    async fn left_and_right_cycle_the_focused_value() {
        // Focus Action, then flip it. Block -> Allow.
        let m = drive(blank_modal(), &[KeyCode::Down, KeyCode::Right]).await;
        assert_eq!(m.focus, AddFocus::Action, "Right must not move focus");
        assert!(
            matches!(m.action, RuleAction::Allow),
            "Right must cycle the focused field's value"
        );
        let m = drive(m, &[KeyCode::Left]).await;
        assert!(matches!(m.action, RuleAction::Block), "Left is the mirror");
    }

    /// The defect in its original form: on the old handler, Up/Down on the
    /// Action row toggled Block/Allow. If that ever comes back, focus will
    /// sit still and the action will flip — this asserts both halves, so a
    /// partial revert cannot pass.
    #[tokio::test]
    async fn down_on_the_action_row_moves_on_and_leaves_the_action_alone() {
        let m = drive(blank_modal(), &[KeyCode::Down]).await;
        assert_eq!(m.focus, AddFocus::Action);
        let m = drive(m, &[KeyCode::Down]).await;
        assert_eq!(m.focus, AddFocus::Scope, "Down moved on from Action");
        assert!(
            matches!(m.action, RuleAction::Block),
            "Down must no longer toggle the action"
        );
    }

    // ── AddFocus cycling ───────────────────────────────────────────

    #[test]
    fn focus_next_cycles_domain_action_scope_and_wraps() {
        assert_eq!(AddFocus::Domain.next(), AddFocus::Action);
        assert_eq!(AddFocus::Action.next(), AddFocus::Scope);
        assert_eq!(AddFocus::Scope.next(), AddFocus::Domain);
    }

    #[test]
    fn focus_prev_is_the_mirror_of_next() {
        assert_eq!(AddFocus::Domain.prev(), AddFocus::Scope);
        assert_eq!(AddFocus::Scope.prev(), AddFocus::Action);
        assert_eq!(AddFocus::Action.prev(), AddFocus::Domain);
    }

    // ── field mutators ─────────────────────────────────────────────

    #[test]
    fn push_char_only_writes_when_domain_focused() {
        let mut m = blank_modal();
        m.focus = AddFocus::Action;
        m.push_char('x');
        assert_eq!(m.domain, "", "char must not leak into domain off-focus");

        m.focus = AddFocus::Domain;
        m.push_char('a');
        m.push_char('d');
        m.push_char('s');
        assert_eq!(m.domain, "ads");
    }

    #[test]
    fn backspace_only_pops_when_domain_focused() {
        let mut m = blank_modal();
        m.domain = "ads.example".into();
        m.focus = AddFocus::Scope;
        m.backspace();
        assert_eq!(m.domain, "ads.example", "backspace must no-op off-focus");

        m.focus = AddFocus::Domain;
        m.backspace();
        assert_eq!(m.domain, "ads.exampl");
    }

    #[test]
    fn toggle_action_flips_block_and_allow() {
        let mut m = blank_modal();
        assert_eq!(m.action, RuleAction::Block);
        m.toggle_action();
        assert_eq!(m.action, RuleAction::Allow);
        m.toggle_action();
        assert_eq!(m.action, RuleAction::Block);
    }

    #[test]
    fn cycle_scope_wraps_through_options() {
        let mut m = blank_modal();
        m.scope_options = vec![
            ScopeChoice::Default,
            ScopeChoice::Profile("default".into()),
            ScopeChoice::Device("iphone".into()),
        ];
        m.scope_choice = ScopeChoice::Default;
        m.cycle_scope(1);
        assert_eq!(m.scope_choice, ScopeChoice::Profile("default".into()));
        m.cycle_scope(1);
        assert_eq!(m.scope_choice, ScopeChoice::Device("iphone".into()));
        m.cycle_scope(1);
        assert_eq!(m.scope_choice, ScopeChoice::Default, "must wrap forward");
        m.cycle_scope(-1);
        assert_eq!(m.scope_choice, ScopeChoice::Device("iphone".into()));
    }

    #[test]
    fn cycle_scope_is_noop_when_no_options() {
        let mut m = blank_modal();
        m.scope_options = Vec::new();
        m.scope_choice = ScopeChoice::Default;
        m.cycle_scope(1);
        assert_eq!(m.scope_choice, ScopeChoice::Default);
    }

    // ── build_submit_payload (pure fn, DoD-required unit test) ──────

    #[test]
    fn build_submit_payload_rejects_empty_domain() {
        let m = blank_modal();
        let err = build_submit_payload(&m).expect_err("blank domain must be rejected");
        assert_eq!(err, "domain is required");
    }

    #[test]
    fn build_submit_payload_rejects_whitespace_only_domain() {
        let mut m = blank_modal();
        m.domain = "   ".into();
        assert!(build_submit_payload(&m).is_err());
    }

    #[test]
    fn build_submit_payload_trims_and_carries_action_and_scope() {
        let mut m = blank_modal();
        m.domain = "  ads.example.com  ".into();
        m.action = RuleAction::Allow;
        m.scope_choice = ScopeChoice::Device("iphone".into());
        let (domain, action, scope) = build_submit_payload(&m).expect("valid payload");
        assert_eq!(domain, "ads.example.com");
        assert_eq!(action, RuleAction::Allow);
        assert_eq!(scope, ScopeChoice::Device("iphone".into()));
    }

    // ── render smoke test ────────────────────────────────────────────

    /// One string per buffer row, so an assertion can tell "on screen"
    /// from "somewhere in the line vector" — and so a test can reason
    /// about which rows were painted at all.
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

    fn render_overlay_in(modal: &RuleAddModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    #[test]
    fn render_overlay_paints_title_and_fields_without_panicking() {
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        let content = render_overlay_in(&m, 80, 24);

        assert!(content.contains("Add rule"), "title missing");
        assert!(content.contains(LABEL_DOMAIN), "domain label missing");
        assert!(content.contains(LABEL_ACTION), "action label missing");
        assert!(content.contains(LABEL_SCOPE), "scope label missing");
        assert!(content.contains("ads.example.com"), "typed domain missing");
    }

    // ── §4.61 Wave 3b: the 80×24 floor ───────────────────────────────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect this overlay anchors on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
    // 12-row interior. `overlay::centered_rect` CLAMPS rather than
    // scrolls, so a body taller than that is cut at the bottom while
    // `Tab` still moves focus onto the rows that were cut. These render
    // the real `render_overlay` into a backend the size of that rect.

    #[test]
    fn floor_keeps_the_action_row_and_the_focused_field_on_screen_together() {
        // The two things a clip silently takes away, plus the proof the
        // viewport actually engaged.
        //
        // Fail-before: the pre-migration body was 10 fixed rows in an
        // 11-row interior, so it fitted the floor whole — every needle
        // below except the last one passed on HEAD. `!contains(Domain)`
        // is the assertion that could not: on a flat body the first
        // field is on screen no matter where focus sits, so a clip
        // further down would be invisible to a positive-only test.
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        m.focus = AddFocus::Scope; // the last field
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("Save"),
            "action row cut at the 80x24 floor — Tab still reaches it:\n{dump}"
        );
        assert!(
            dump.contains("Discard"),
            "Discard cut at the floor:\n{dump}"
        );
        assert!(
            dump.contains("\u{2039} default \u{203a}"),
            "the focused scope row is off-screen:\n{dump}"
        );
        assert!(
            dump.contains('\u{25c0}'),
            "the focus marker must be on screen with the action row:\n{dump}"
        );
        assert!(
            !dump.contains(LABEL_DOMAIN),
            "a 3-row viewport cannot be showing both ends of the form:\n{dump}"
        );
    }

    /// §4.68 DoD, **at the floor**: the two description rows are on screen,
    /// they fill the modal interior with `bg_main` `Rgb(15,15,15)` in teal
    /// `Rgb(13,148,136)`, they are NOT on the title's `Rgb(51,51,51)`, and
    /// the action row survived the head growing.
    #[test]
    fn floor_the_description_band_renders_on_its_own_strip_with_the_actions() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &m)).unwrap();
        modal_form::desc_band2_assert::assert_two_row_band(
            term.backend().buffer(),
            ADD_DESC,
            &["Save", "Discard"],
        );
    }

    /// The copy ships at a width, so the width is a test rather than a
    /// comment. `render_body_fixed` does not wrap and prints no marker
    /// where it cuts.
    #[test]
    fn no_desc_row_outruns_the_narrow_build_pass() {
        // −2 chrome, −1 for the scrollbar column on the narrow pass,
        // −2 for `desc_band2`'s indent.
        const BUDGET: usize = MODAL_W as usize - 5;
        for line in ADD_DESC {
            let n = line.chars().count();
            assert!(n <= BUDGET, "description row is {n} cells: {line:?}");
        }
    }

    #[test]
    fn floor_first_field_is_reachable_and_the_action_row_survives_with_it() {
        // The mirror: focus on the *first* field. The viewport sits at
        // the top, and the pinned tail still holds the action row — the
        // half of the `ScrollBody` contract that has nothing to do with
        // scrolling.
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        m.focus = AddFocus::Domain;
        let dump = render_overlay_in(&m, 80, 14);

        assert!(
            dump.contains("ads.example.com"),
            "the focused domain value is off-screen:\n{dump}"
        );
        assert!(dump.contains("Save"), "action row cut:\n{dump}");
    }

    #[test]
    fn overlay_is_confined_to_the_anchor_rect() {
        // D18: the anchor is the tab content rect, so the header, the
        // menu card and the footer legend stay visible behind the modal.
        // Anchoring on `f.area()` instead paints over all three.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let anchor = ratatui::layout::Rect {
            x: 0,
            y: 9,
            width: 80,
            height: 14,
        };
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
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
    fn focused_text_field_hosts_the_real_cursor() {
        // The `_` caret's replacement, matching the Lists reference.
        // Placed at VALUE_COL + the value's char length, in the
        // viewport's coordinate space, so it tracks the scrolled field
        // region rather than a fixed body offset.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        m.focus = AddFocus::Domain;

        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &m)).unwrap();
        let pos = term.get_cursor_position().unwrap();

        let dump = dump_buffer(term.backend().buffer());
        let row = dump
            .lines()
            .nth(pos.y as usize)
            .expect("cursor row is inside the buffer");
        let before: String = row.chars().take(pos.x as usize).collect();
        assert!(
            before.ends_with("ads.example.com"),
            "cursor must sit just past the typed value, got column {} on {row:?}",
            pos.x
        );
        assert!(
            !dump.contains("ads.example.com_"),
            "the `_` caret is the cursor's job"
        );
    }

    /// The same property with a fixture past the value budget, which is
    /// the only version that could ever have failed.
    ///
    /// The test above uses a 15-character domain and therefore passed
    /// identically on the build where a focused editable lost its cursor
    /// entirely — it was never wrong, it was **short**. A legal DNS name
    /// reaches 253 characters, so this fixture is reachable, not
    /// contrived, and typing one past roughly 38 used to leave the
    /// operator with no caret at all: `value_row` kept the head, the
    /// caret column kept climbing, and `place_cursor` silently declined
    /// to set it once `x` passed the modal edge.
    #[test]
    fn a_domain_past_the_value_budget_keeps_its_cursor_on_the_tail() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut m = blank_modal();
        // Head and tail are lexically distinct on purpose: a fixture of
        // repeated characters cannot tell which end survived, and that is
        // exactly how the shared `value_row` cut went unnoticed.
        m.domain = "head-of-a-very-long-name.filler.filler.filler.example.tail-marker".into();
        m.focus = AddFocus::Domain;

        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &m)).unwrap();
        let pos = term.get_cursor_position().unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            pos.x > 0 && pos.y > 0,
            "no cursor was placed — the operator types blind at {pos:?}\n{dump}"
        );
        let row = dump
            .lines()
            .nth(pos.y as usize)
            .expect("cursor row is inside the buffer");
        let before: String = row.chars().take(pos.x as usize).collect();
        assert!(
            before.ends_with("tail-marker"),
            "the cursor is not at the end of what is being typed, got column {} on {row:?}",
            pos.x
        );
        assert!(
            !row.contains("head-of-a-very-long-name"),
            "the row kept the head, so the caret and the text disagree: {row:?}"
        );
    }

    #[test]
    fn esc_and_enter_are_discoverable_without_focus() {
        // The pre-migration form carried two hint lines; Archetype F's
        // tail carries one, and the one it carries (`ADD_RULE_HINT_1`)
        // does not mention Esc or Enter. Neither action is a Tab target,
        // so neither can advertise its key by being focused. If the
        // labels lose their keys, the only way to save or close this
        // modal appears nowhere on screen — which is precisely the
        // class of silent operator-facing loss this wave exists to
        // prevent.
        //
        // Was `esc_and_ctrl_s_are_discoverable_without_focus`: N14 moved
        // the advertised save key from Ctrl+s to Enter (still on the
        // button, since focus still never reaches it) and Ctrl+s itself
        // dropped off this surface — it still works, but §3.1 keeps it
        // to one mention on the modal and the global footer owns that
        // mention now, not this overlay.
        let dump = render_overlay_in(&blank_modal(), 80, 24);
        assert!(dump.contains("Esc"), "no way to discard is shown:\n{dump}");
        assert!(dump.contains("Enter"), "no way to save is shown:\n{dump}");
    }

    #[test]
    fn transient_status_survives_without_a_status_message_of_its_own() {
        // `submitting` alone, with no `status_message`, is a real state:
        // `submit` sets both but a caller need not. The synthesised
        // "adding…" must still reach its slot.
        //
        // Was `transient_status_takes_the_hint_row_while_submitting`,
        // which asserted the status REPLACED the focused row's hint.
        // That was pinning the workaround, not a requirement — see
        // `transient_status_has_its_own_slot_and_leaves_the_field_hint_alone`.
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        m.submitting = true;
        let dump = render_overlay_in(&m, 80, 24);

        assert!(
            dump.contains("adding\u{2026}"),
            "the in-flight status must reach the operator:\n{dump}"
        );
    }

    /// Pins `s4-63-form-transient-status-slot` (add half).
    ///
    /// Before the fix the in-flight message had no home: Archetype F's
    /// tail offered `error` (⚠ + error colour) and `hint` (muted italic)
    /// and nothing else, so `form_body` passed the status in place of
    /// EVERY row's hint. Two losses, both silent — the status wore the
    /// hint's muted italic instead of the colour the pre-migration status
    /// row had, and the guidance for the field the operator is actually
    /// standing on disappeared for the duration of the submit.
    #[test]
    fn transient_status_has_its_own_slot_and_leaves_the_field_hint_alone() {
        use crate::tui::theme::T;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        m.submitting = true;
        m.status_message = Some("adding\u{2026}".into());

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &m)).unwrap();
        let buf = term.backend().buffer().clone();
        let dump = dump_buffer(&buf);

        assert!(
            dump.contains("adding\u{2026}"),
            "the in-flight status must reach the operator:\n{dump}"
        );
        assert!(
            dump.contains("the domain this rule matches"),
            "the focused field's guidance must survive the submit — the \
             status has its own row:\n{dump}"
        );

        // Its own slot means its own colour. Read off the buffer: the
        // style is the half of this defect a substring assertion cannot
        // see, and the half that made the pre-migration row legible.
        let row = dump
            .lines()
            .position(|l| l.contains("adding\u{2026}"))
            .expect("just asserted it is on screen") as u16;
        let styled = (0..buf.area.width)
            .map(|x| buf[(x, row)].clone())
            .find(|c| c.symbol() == "a")
            .expect("the status text is painted");
        assert_eq!(
            styled.fg, T.info,
            "the status wears the hint's colour — it is still riding the \
             hint slot:\n{dump}"
        );
        assert!(
            !styled.modifier.contains(ratatui::style::Modifier::ITALIC),
            "italic is the hint's affordance, not the status's:\n{dump}"
        );
    }

    #[test]
    fn error_message_wins_over_the_status_and_carries_the_warning_glyph() {
        // `hint_or_error_rows` checks the error slot first, so an error
        // must beat a stale status. The real failure copy comes from
        // `submit`'s `format!("add failed: {e}")`.
        let mut m = blank_modal();
        m.status_message = Some("adding\u{2026}".into());
        m.error_message = Some("add failed: domain is required".into());
        let dump = render_overlay_in(&m, 80, 24);

        assert!(
            dump.contains('\u{26a0}'),
            "a failure carries the ⚠ affordance:\n{dump}"
        );
        assert!(
            dump.contains("add failed: domain is required"),
            "the error text is missing:\n{dump}"
        );
        assert!(
            !dump.contains("adding\u{2026}"),
            "a stale status must not outrank an error:\n{dump}"
        );
    }

    #[test]
    fn no_hand_rolled_colour_in_this_module() {
        // §4.61 Wave 3b's acceptance criterion as a test rather than a
        // claim in a commit message. A surface that reaches for the
        // theme directly is a surface that will drift from the other
        // eleven — R1 is that every wave re-derives the colour rule
        // locally. Needles are split so this assertion cannot match
        // itself.
        let src = include_str!("rule_add_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
            concat!("Borders", "::ALL"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in rule_add_modal.rs — the colour belongs in modal_form"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test rule_add_visual_dump -- --ignored --nocapture"]
    fn rule_add_visual_dump() {
        let mut m = blank_modal();
        m.domain = "ads.example.com".into();
        println!("--- roomy anchor ---\n{}", render_overlay_in(&m, 100, 40));
        println!(
            "--- the 80x24 floor (14-row content rect) ---\n{}",
            render_overlay_in(&m, 80, 14)
        );
        m.focus = AddFocus::Scope;
        println!(
            "--- same, focus on the last field ---\n{}",
            render_overlay_in(&m, 80, 14)
        );
    }
}
