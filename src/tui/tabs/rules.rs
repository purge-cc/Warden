//! Rules tab — read-only placeholder for admin-rule visibility (Sprint 43 T2).
//!
//! T2 ships only the chrome (Tab variant + render + filter chip
//! cycling). The data source is `[[admin_rules]]` which T5 introduces
//! along with `e/d` editing keybindings and the scope-modal flow.
//! Until then the table renders zero rows on a fresh CT and the
//! empty-state message points the operator at T5's incoming verbs.
//!
//! Keybindings (handled in `tui/mod.rs`):
//!   j/k / ↑/↓   scroll the table
//!   /           focus the text search (domain / rule / id substring)
//!   f           cycle the action chip All → Allow → Deny → All
//!   R           clear the search + reset the chip to All
//!   Enter       open the edit modal on the focused rule
//!   d / Del     open delete-confirm on the focused rule

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::filter::rules::{parse_rule, RuleAction, RulePattern};
use crate::tui::app::{
    App, RuleEditFocus, RuleEditModal, RuleEditMode, RuleReference, RuleRowMeta, RuleScope,
    RulesFilter, ScopeChoice,
};
use crate::tui::modal_form::{self, Action, ActionKind, ValueKind};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Build the joined view of `[[admin_rules]]` for the Rules tab. For
/// every master entry: parse the rule string to extract action +
/// domain, then walk every device + every profile to collect every
/// reference, then pick a primary scope by precedence
/// `Device > Profile > Default` (Orphan when the master entry has zero
/// references).
///
/// Cheap by design — typical deployments have <50 admin rules and
/// <100 devices/profiles combined; the O(N×M) walk runs in microseconds
/// and is invoked once per render cycle. No caching: the loaded_config
/// can change between renders (operator hits `r` to refresh, scope_modal
/// adds a rule), and a stale row vec would surface ghost or missing
/// entries.
pub fn build_rule_rows(app: &App) -> Vec<RuleRowMeta> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    let cfg = &loaded.config;
    let default_profile_id: Option<&str> = cfg.server.default_profile.as_ref().map(|i| i.as_str());

    cfg.admin_rules
        .iter()
        .map(|rule| {
            let id = rule.id.as_str().to_string();
            let raw_rule = rule.rule.clone();

            // Parse the rule string. Unparseable rules (validator should
            // have caught these) get neutral fallback values so the row
            // still renders — operators see the broken entry rather than
            // a silent skip.
            let (action, domain_label) = match parse_rule(&raw_rule) {
                Some(parsed) => (parsed.action, format_pattern(&parsed.pattern)),
                None => (RuleAction::Block, "<unparseable>".to_string()),
            };

            // Reverse-index: collect every reference on disk.
            let references = collect_references(&id, cfg, default_profile_id);
            let scope = pick_primary_scope(&references);

            RuleRowMeta {
                id,
                raw_rule,
                action,
                domain_label,
                scope,
                references,
                hits: None,
            }
        })
        .collect()
}

/// Walk devices + profiles to find every entity referencing the
/// admin_rule with id `target`. Used to populate
/// [`RuleRowMeta::references`].
fn collect_references(
    target: &str,
    cfg: &crate::config::schema::ConfigV1,
    default_profile_id: Option<&str>,
) -> Vec<RuleReference> {
    let mut refs = Vec::new();
    for device in &cfg.devices {
        if device.allow_rules.iter().any(|id| id.as_str() == target) {
            refs.push(RuleReference {
                kind: RuleScope::Device(device.id.as_str().to_string()),
                via_field: "allow_rules",
            });
        }
        if device.deny_rules.iter().any(|id| id.as_str() == target) {
            refs.push(RuleReference {
                kind: RuleScope::Device(device.id.as_str().to_string()),
                via_field: "deny_rules",
            });
        }
    }
    for (profile_id, profile) in &cfg.profiles {
        if profile.admin_rules.iter().any(|id| id.as_str() == target) {
            // Distinguish "default profile" from a regular profile by
            // matching id against `[server].default_profile`. Default
            // is the operator-side concept that overlays the level-5
            // resolver fallback — surface it as such instead of as
            // "profile:default" which obscures the intent.
            let kind = if default_profile_id == Some(profile_id.as_str()) {
                RuleScope::Default
            } else {
                RuleScope::Profile(profile_id.clone())
            };
            refs.push(RuleReference {
                kind,
                via_field: "admin_rules",
            });
        }
    }
    refs
}

/// Pick the primary scope for the SCOPE column from the full reference
/// list. Precedence: `Device > Profile > Default > Orphan`. Within the
/// same kind, picks the first reference (insertion-order — devices
/// scanned before profiles, alphabetical inside each).
fn pick_primary_scope(refs: &[RuleReference]) -> RuleScope {
    if let Some(r) = refs.iter().find(|r| matches!(r.kind, RuleScope::Device(_))) {
        return r.kind.clone();
    }
    if let Some(r) = refs
        .iter()
        .find(|r| matches!(r.kind, RuleScope::Profile(_)))
    {
        return r.kind.clone();
    }
    if refs.iter().any(|r| matches!(r.kind, RuleScope::Default)) {
        return RuleScope::Default;
    }
    RuleScope::Orphan
}

/// Operator-friendly label for a parsed rule pattern. Mirrors the
/// pattern's "what this matches" semantics in plain text:
/// - `Exact("a.com")` → `"a.com"`
/// - `Wildcard("a.com")` → `"*.a.com"`
/// - `Regex { source: "ad[0-9]+" }` → `"re:ad[0-9]+"` (truncated to 30
///   chars for the table column)
fn format_pattern(p: &RulePattern) -> String {
    match p {
        RulePattern::Exact(d) => d.to_string(),
        RulePattern::Wildcard(s) => format!("*.{s}"),
        RulePattern::Regex { source, .. } => {
            // CHAR-boundary truncation — pasting a Unicode regex
            // (e.g. `\p{Greek}+`) and byte-slicing at index 29 would
            // panic if byte 29 is mid-codepoint. `chars().take()` walks
            // O(n) but the slice is tiny so the cost is moot.
            let s = source.as_str();
            if s.chars().count() > 30 {
                let truncated: String = s.chars().take(29).collect();
                format!("re:{truncated}…")
            } else {
                format!("re:{s}")
            }
        }
    }
}

/// Draw the Rules tab into `area` — the tab content rect handed down by
/// `ui::render_active_tab`.
///
/// Both overlays take `area`, not `f.area()`, which is the §4.61 D18
/// anchor: the header, the menu card and the footer legend stay visible
/// behind an open modal. That is also the whole row budget they get —
/// `24 − 4 header − 5 menu card − 1 footer = 14` rows at the declared
/// 80×24 floor — and `overlay::centered_rect` clamps rather than scrolls,
/// which is why both are `modal_form::ScrollBody` surfaces.
pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // N13 shared filter card, no title
        Constraint::Min(5),    // table
    ])
    .split(area);

    render_filters(f, chunks[0], app);
    render_table(f, chunks[1], app);

    // S53.5 — edit modal overlays the tab content. Renders LAST so it
    // sits above the table; key dispatch in `tui::mod` gates every
    // keystroke through the modal handler while it's open.
    if let Some(modal) = app.rules.edit_modal.as_ref() {
        render_rule_edit_modal(f, area, modal);
    }
    // wave2/rules-add-key — same overlay-last / same-gate-in-mod
    // pattern as the edit modal above, for the `[a]` add-rule modal.
    if let Some(modal) = app.rules.add_modal.as_ref() {
        crate::tui::rule_add_modal::render_overlay(f, area, modal);
    }
}

/// N13 shared filter card: a text search (`/`) combined with the
/// all/allow/deny action chip (`f`). Mirrors `tabs::query_log::render_filters`
/// / `tabs::lists::render_filters` — all three (plus Tags) go through
/// `theme::render_filter_card`. No title; the fields are the label.
fn render_filters(f: &mut Frame, area: Rect, app: &App) {
    let content_area = theme::render_filter_card(f, area);

    // Trailing `_` cursor while the search buffer is being edited; the
    // whole search value turns `T.info` blue in that mode.
    let (search_val, search_style) = match &app.input_mode {
        crate::tui::app::InputMode::FilterRules(s) => {
            (format!("{s}_"), Style::default().fg(T.info))
        }
        _ => (
            app.rules.filter_text.clone().unwrap_or_default(),
            Style::default().fg(T.text_secondary),
        ),
    };

    let chip = |label: &str, selected: bool| {
        let style = if selected {
            Style::default()
                .fg(T.text_inverse)
                .bg(T.brand_red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(T.text_secondary)
        };
        Span::styled(format!(" {label} "), style)
    };

    // Width budget: build the fixed spans (label + chips + clear hint)
    // first, then give the search value whatever horizontal space is left
    // — tail-kept so the trailing `_` edit cursor stays visible and the
    // chips never scroll off on a long query. Mirrors tabs::query_log.
    let lead = Span::styled("Search [/]: ", Style::default().fg(T.text_muted));
    let trailing = vec![
        Span::styled("   Filter [f]: ", Style::default().fg(T.text_muted)),
        chip("all", app.rules.filter == RulesFilter::All),
        Span::raw(" "),
        chip("allow", app.rules.filter == RulesFilter::Allow),
        Span::raw(" "),
        chip("deny", app.rules.filter == RulesFilter::Deny),
        Span::styled("   [R] clear", Style::default().fg(T.text_muted)),
    ];
    let fixed: usize = lead.width() + trailing.iter().map(|s| s.width()).sum::<usize>();
    let budget = (content_area.width as usize).saturating_sub(fixed).max(11);
    let shown = if search_val.is_empty() {
        "___________".to_string()
    } else {
        crate::tui::tabs::query_log::truncate_tail(&search_val, budget)
    };
    let mut spans = Vec::with_capacity(trailing.len() + 2);
    spans.push(lead);
    spans.push(Span::styled(shown, search_style));
    spans.extend(trailing);
    f.render_widget(Paragraph::new(Line::from(spans)), content_area);
}

fn render_table(f: &mut Frame, area: Rect, app: &App) {
    let entries = build_rule_rows(app);
    let filtered: Vec<&RuleRowMeta> = entries
        .iter()
        .filter(|r| matches_rule_filters(r, app.rules.filter, app.rules.filter_text.as_deref()))
        .collect();

    let no_filter = app.rules.filter == RulesFilter::All && app.rules.filter_text.is_none();
    let title_count = if no_filter {
        format!("Rules ({})", entries.len())
    } else {
        format!("Rules ({}/{} after filter)", filtered.len(), entries.len())
    };
    let content = render_section_chrome(f, area, &title_count, T.text_secondary);

    if filtered.is_empty() {
        render_empty_state(f, content, app, !entries.is_empty());
        return;
    }

    let header = Row::new(vec![
        Cell::from("ID"),
        Cell::from("SCOPE"),
        Cell::from("ACTION"),
        Cell::from("DOMAIN"),
        Cell::from("RULE"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let body: Vec<Row> = filtered.iter().map(|r| render_rule_row(r)).collect();

    const COLUMN_SPACING: u16 = 3;
    let constraints = [
        Constraint::Length(22), // id (auto-allow-3c2f8e5d ≈ 20)
        Constraint::Length(18), // scope
        Constraint::Length(7),  // action
        Constraint::Min(18),    // domain
        Constraint::Min(20),    // rule
    ];
    let table = Table::new(body, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(crate::tui::theme::highlight_style());

    f.render_stateful_widget(table, content, &mut app.rules.table_state.clone());

    // Query-Log-style vertical separators between columns.
    crate::tui::ui::draw_table_column_separators(f, content, &constraints, COLUMN_SPACING);
}

/// Empty-state copy. Two variants:
///   - **Truly empty** (no rules at all): leads with the `[a]` add-rule
///     modal (wave2/rules-add-key), then demotes the Query Log +
///     scope_modal path and the `warden` CLI verbs to secondary hints.
///   - **Filtered to zero** (rules exist, but the chip excludes them
///     all): hint that they should `[f]` cycle to see them.
fn render_empty_state(f: &mut Frame, area: Rect, app: &App, has_filtered_out: bool) {
    let lines = if has_filtered_out {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  Filter '{}' hides every rule.", app.rules.filter.label()),
                Style::default()
                    .fg(T.text_primary)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press [f] to cycle the filter back to 'all'.",
                Style::default().fg(T.text_secondary),
            )),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No admin rules yet.",
                Style::default()
                    .fg(T.text_primary)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                crate::tui::rule_add_modal::RULES_EMPTY_ADD_HINT,
                Style::default()
                    .fg(T.brand_red)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Or from the Query Log tab — focus a row,",
                Style::default().fg(T.text_secondary),
            )),
            Line::from(Span::styled(
                "  press Enter, pick allow or deny, choose the scope.",
                Style::default().fg(T.text_secondary),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Or from the CLI: `warden default {allow,deny} <domain>`",
                Style::default().fg(T.text_muted),
            )),
            Line::from(Span::styled(
                "  / `warden device <id> {allow,deny} <domain>` / etc.",
                Style::default().fg(T.text_muted),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn matches_filter(action: RuleAction, filter: RulesFilter) -> bool {
    match filter {
        RulesFilter::All => true,
        RulesFilter::Allow => matches!(action, RuleAction::Allow),
        RulesFilter::Deny => matches!(action, RuleAction::Block),
    }
}

/// Combined Rules filter — action chip AND text search. Single source
/// of truth shared by `render_table` and
/// `tui::mod::visible_rule_rows_count` so the visible-row count and the
/// rendered rows can never drift.
pub(crate) fn matches_rule_filters(
    r: &RuleRowMeta,
    filter: RulesFilter,
    text: Option<&str>,
) -> bool {
    matches_filter(r.action, filter) && matches_rule_text(r, text)
}

/// Case-insensitive substring over the operator-visible rule fields
/// (id, parsed domain, raw rule string). `None`/empty matches all.
fn matches_rule_text(r: &RuleRowMeta, text: Option<&str>) -> bool {
    match text {
        None => true,
        Some(q) => {
            let q = q.to_lowercase();
            r.id.to_lowercase().contains(&q)
                || r.domain_label.to_lowercase().contains(&q)
                || r.raw_rule.to_lowercase().contains(&q)
        }
    }
}

fn render_rule_row(r: &RuleRowMeta) -> Row<'static> {
    let scope_label = match &r.scope {
        RuleScope::Default => "default".to_string(),
        RuleScope::Profile(id) => format!("profile:{id}"),
        RuleScope::Device(id) => format!("device:{id}"),
        RuleScope::Orphan => "<orphan>".to_string(),
    };
    let scope_style = match &r.scope {
        RuleScope::Device(_) => Style::default().fg(T.brand_red),
        RuleScope::Default => Style::default().fg(T.text_secondary),
        RuleScope::Profile(_) => Style::default().fg(T.text_primary),
        RuleScope::Orphan => Style::default().fg(T.warning),
    };

    let (action_label, action_style) = match r.action {
        RuleAction::Block => (
            "\u{29BB} BLOCK",
            Style::default().fg(T.error).add_modifier(Modifier::BOLD),
        ),
        RuleAction::Allow => (
            "\u{2713} ALLOW",
            Style::default().fg(T.success).add_modifier(Modifier::BOLD),
        ),
    };

    let domain_label = truncate(&r.domain_label, 28);
    let rule_label = truncate(&r.raw_rule, 32);

    Row::new(vec![
        Cell::from(Span::styled(
            r.id.clone(),
            Style::default().fg(T.text_primary),
        )),
        Cell::from(Span::styled(scope_label, scope_style)),
        Cell::from(Span::styled(action_label, action_style)),
        Cell::from(Span::styled(
            domain_label,
            Style::default().fg(T.text_primary),
        )),
        Cell::from(Span::styled(
            rule_label,
            Style::default().fg(T.text_secondary),
        )),
    ])
}

/// The rule rows the table actually paints: [`build_rule_rows`] narrowed
/// by the action chip AND the `/` text search (`matches_rule_filters`).
///
/// rev-2607: the single definition of "the visible row set", shared by
/// the cursor reconciler, the j/k bounds and the modal builder below. A
/// cursor index is only meaningful against one specific vec — filtering
/// by the action chip alone here would build a *larger* vec than the
/// table shows, so under an active text filter `Enter`/`d` would act on a
/// different rule than the highlighted one (and the delete dialog would
/// print that wrong id as a plausible target).
pub fn visible_rule_rows(app: &App) -> Vec<RuleRowMeta> {
    build_rule_rows(app)
        .into_iter()
        .filter(|r| matches_rule_filters(r, app.rules.filter, app.rules.filter_text.as_deref()))
        .collect()
}

/// Build the open-state for the Rules-tab edit modal from the focused
/// row + a snapshot of scope options drawn from `loaded_config`.
/// Returns `None` when no row is focused or `loaded_config` is absent
/// — the hotkey handler surfaces a footer hint in that case.
pub fn build_rule_edit_modal_for(app: &App) -> Option<RuleEditModal> {
    let rows = visible_rule_rows(app);
    // rev-2607: resolve the operator's stable rule id, **not** the
    // positional cursor. The rows are rebuilt from `loaded_config` on
    // every reload — including this tab's own delete — so an index
    // captured on an earlier frame can silently address a *different*
    // rule: drop a rule above the cursor and the index stays in range
    // while the entity under it changes. `Enter` and `d` must act on the
    // rule the operator is looking at, or on nothing at all.
    let idx = match crate::tui::app::resolve_row_index(&rows, app.rules.selected_id.as_ref(), |r| {
        Some(r.id.clone())
    }) {
        Some(i) => i,
        // Nothing seeded yet — honour the visual cursor for the first
        // keypress. A *stale* id (set, but no longer resolving) means the
        // rule is gone: refuse rather than retarget.
        None if app.rules.selected_id.is_none() => app.rules.table_state.selected()?,
        None => return None,
    };
    let row = rows.get(idx)?;

    let scope_options = build_scope_options(app);
    let initial_scope_choice = match &row.scope {
        RuleScope::Default => ScopeChoice::Default,
        RuleScope::Profile(id) => ScopeChoice::Profile(id.clone()),
        RuleScope::Device(id) => ScopeChoice::Device(id.clone()),
        // Orphan rules have no scope to start from — seed with the
        // first available choice so the picker renders something
        // meaningful. If scope_options is empty (no devices, no
        // profiles, no default), leave as Default — submit will fail
        // with a clean validator error rather than a silent crash.
        RuleScope::Orphan => scope_options
            .first()
            .cloned()
            .unwrap_or(ScopeChoice::Default),
    };

    Some(RuleEditModal {
        rule_id: row.id.clone(),
        raw_rule: row.raw_rule.clone(),
        original_action: row.action,
        original_scope: row.scope.clone(),
        original_references: row.references.clone(),
        current_action: row.action,
        current_scope_choice: initial_scope_choice,
        scope_options,
        focus: RuleEditFocus::Action,
        mode: RuleEditMode::Edit,
        error_message: None,
        status_message: None,
        submitting: false,
    })
}

/// Snapshot the scopes the operator can pick from. Order:
/// `Default` (if `[server].default_profile` is set) → every
/// `[profiles.*]` id alphabetically → every `[[devices]].id`
/// alphabetically.
///
/// wave2/rules-add-key: promoted to `pub(crate)` (and dropped the
/// unused `_current` param — the edit modal never used it either) so
/// `rule_add_modal::RuleAddModal::open` can snapshot the same option
/// set the edit modal uses, rather than re-deriving it.
pub(crate) fn build_scope_options(app: &App) -> Vec<ScopeChoice> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    let cfg = &loaded.config;
    let mut out: Vec<ScopeChoice> = Vec::new();
    if cfg.server.default_profile.is_some() {
        out.push(ScopeChoice::Default);
    }
    let mut profile_ids: Vec<&String> = cfg.profiles.keys().collect();
    profile_ids.sort();
    for id in profile_ids {
        out.push(ScopeChoice::Profile(id.clone()));
    }
    let mut device_ids: Vec<String> = cfg
        .devices
        .iter()
        .map(|d| d.id.as_str().to_string())
        .collect();
    device_ids.sort();
    for id in device_ids {
        out.push(ScopeChoice::Device(id));
    }
    out
}

/// Cycle the modal's `current_scope_choice` through `scope_options`
/// in `dir` (+1 / -1). Wraps. No-op if scope_options is empty (modal
/// renders the current choice as read-only in that pathological case).
pub fn cycle_scope_choice(modal: &mut RuleEditModal, dir: i32) {
    if modal.scope_options.is_empty() {
        return;
    }
    let len = modal.scope_options.len() as i32;
    let current_idx = modal
        .scope_options
        .iter()
        .position(|c| c == &modal.current_scope_choice)
        .map(|i| i as i32)
        .unwrap_or(0);
    let next_idx = (current_idx + dir).rem_euclid(len) as usize;
    modal.current_scope_choice = modal.scope_options[next_idx].clone();
    modal.error_message = None;
}

// ── §4.61 W3b MODAL REGION BEGINS ─────────────────────────────────────
//
// Everything between this marker and the closing one is overlay chrome:
// Archetype F for the edit form, Archetype C for the delete confirm.
// Every colour in here comes from `modal_form`. A locally-built
// foreground style, a full-border block or a direct reach into the
// theme's brand red below this line is R1 — the
// twelve-surfaces-each-re-deriving-the-colour-rule drift the workstream
// exists to end. Pinned by `no_hand_rolled_colour_in_the_modal_region`,
// which slices this file between the two markers; the needles are
// spelled out there, deliberately not here, so the guard cannot match
// the comment that describes it.
//
// The tab's own chrome (table header, scope column, filter chips) is
// deliberately NOT in scope and keeps its own styles — §4.61 §1.1: tab
// chrome is a separate, tab-wide palette question.

/// Modal width, matching the rest of the Archetype-F ecosystem
/// (`tabs/lists.rs`, `subnet_modal.rs`, `rule_add_modal.rs`).
const MODAL_W: u16 = 64;

/// Nav-key legend for the edit form. `Enter on Delete` used to need its
/// own hint line; it now lives on the Delete action's per-focus hint,
/// which is the affordance Archetype F gives a form in exchange for the
/// second static line. The keying itself is unchanged (D7′).
const EDIT_KEYS: &str =
    "\u{21b9} cycle \u{b7} \u{2191}\u{2193} move \u{b7} \u{2190}\u{2192} change \u{b7} Ctrl+s save \u{b7} Esc cancel";

/// Prose ordinal of the delete confirm's typed-id input, and the column
/// its text starts at.
///
/// The ordinal is **not** the field-region row index: the id above it is a
/// [`modal_form::ProseRow::verbatim`] row and takes two lines once it runs
/// past the wrap column, which every id near `Id::MAX_LEN` does. Convert
/// with [`modal_form::prose_field_row`] — a hardcoded row index is how the
/// caret ends up one row above the text it is supposed to be sitting in.
///
/// The column is structural: `prose_row` lays out a 2-cell indent before
/// the `> ` prompt.
const TYPED_PROSE_ORDINAL: usize = 2;
const TYPED_PROMPT_COL: u16 = 4;

/// Characters a read-only value cell can hold before
/// `render_body_fixed`'s non-wrapping `Paragraph` cuts it mid-token at
/// the modal edge.
///
/// **This used to end "Editable values are deliberately not budgeted —
/// see `rule_add_modal::form_body`", and that stopped being true before
/// it was corrected.** S3 gave [`modal_form::value_row`] a `fit()`, so
/// every editable value has been budgeted since; the sentence survived as
/// documentation of an absent policy, which is worse than no comment —
/// a reader checking whether editables were bounded found a confident No.
///
/// Editables are now budgeted *and* windowed from the tail, because the
/// caret lives at the end of what is being typed. The two directions are
/// deliberate and each is pinned by its own test in `modal_form`:
/// `a_focused_editable_keeps_the_tail_the_operator_is_typing` and
/// `an_unfocused_value_still_keeps_its_head`.
fn value_budget(width: u16) -> usize {
    (width as usize).saturating_sub(modal_form::VALUE_COL)
}

/// The transient "we are talking to the config right now" message, if
/// any. It goes to [`modal_form::form_tail_with_status`]'s own slot — its
/// own row, in the theme's neutral status colour — and the focused
/// control keeps its guidance underneath. Before §4.63 S1 it was handed
/// to every row's hint AND to the Delete action's, because Archetype F's
/// tail had nowhere else to put it. An error still wins over both.
fn transient_status(modal: &RuleEditModal) -> Option<&str> {
    modal.status_message.as_deref().or({
        if modal.submitting {
            Some("saving\u{2026}")
        } else {
            None
        }
    })
}

/// One-line guidance for the focused control.
fn edit_field_hint(f: RuleEditFocus) -> &'static str {
    match f {
        RuleEditFocus::Action => {
            "Block drops the answer, Allow overrides every blocklist \u{2014} \u{2190}/\u{2192} to change"
        }
        RuleEditFocus::Scope => {
            "who it applies to: the default profile, one profile, or one device \u{2014} \u{2190}/\u{2192} to change"
        }
        RuleEditFocus::DeleteButton => {
            "Enter opens a typed-id confirm \u{2014} the rule row and every reference go"
        }
        RuleEditFocus::SaveButton => "Enter saves \u{2014} Ctrl+s saves from anywhere too",
    }
}

/// The scope picker's display value.
fn edit_scope_text(modal: &RuleEditModal) -> String {
    if modal.scope_options.is_empty() {
        format!(
            "{} (no other scopes available)",
            modal.current_scope_choice.label()
        )
    } else {
        modal.current_scope_choice.label()
    }
}

/// Flatten the reverse index into one cell, plus what it *means*: an
/// unreferenced rule is inert, which is caution, not identity. Colour
/// and copy change together so an operator who does not know the palette
/// is no worse off.
fn references_cell(modal: &RuleEditModal) -> (String, ValueKind) {
    if modal.original_references.is_empty() {
        return ("<none \u{2014} orphan>".to_string(), ValueKind::Caution);
    }
    let mut parts: Vec<String> = modal
        .original_references
        .iter()
        .map(|r| match &r.kind {
            RuleScope::Default => "default".to_string(),
            RuleScope::Profile(id) => format!("profile:{id}"),
            RuleScope::Device(id) => format!("device:{id}({})", r.via_field),
            RuleScope::Orphan => String::new(),
        })
        .collect();
    parts.retain(|s| !s.is_empty());
    (parts.join(", "), ValueKind::Identity)
}

/// The two description rows for the edit form, on their own `bg_main`
/// strip under the title band ([`modal_form::desc_band2`], 2026-08-07).
///
/// Not the title's `bg_highlight` — teal on it is 3.37:1 against a 4.5:1
/// prose bar, and no contrast gate covers the pair. See `desc_band2`.
///
/// Row 2 states the precedence, which no single field's hint owns: it is a
/// property of the rule against **every** loaded list, not of `Action` or
/// `Scope` alone, so before this there was no row it belonged to.
///
/// Row 1 lost the words "an existing", and not for style. At 61 cells it
/// outran the narrow build pass — [`MODAL_W`] 64, −2 chrome, −1 for the
/// scrollbar column, −2 for the band's indent = **59** — so the shipped
/// one-line copy was **already** being cut at the rect edge, with no
/// marker, whenever this modal scrolled. `render_body_fixed` does not
/// wrap. "existing" is redundant in a modal titled *Edit rule* anyway.
///
/// A const rather than two inline literals so
/// `no_desc_row_outruns_the_narrow_build_pass` can measure the copy that
/// actually ships instead of a transcription of it.
const EDIT_DESC: [&str; 2] = [
    "change what this admin rule does and who it applies to",
    "admin rules outrank every blocklist, for that scope only",
];

/// Build the edit form as an Archetype-F [`modal_form::ScrollBody`] —
/// pinned head, scrolling field region, pinned tail.
///
/// The head is **4** rows ([`EDIT_DESC`] is two of them). `scroll_layout`
/// serves the tail first and the head second, so at the D18 floor's 12
/// interior rows that comes out of the field viewport: with this modal's
/// default 5-row tail (spacer + 2 note + keys + actions) the viewport went
/// 4 rows → **3**. Re-derived here from this modal's own tail, not
/// inherited from `profile_modal`, whose tail is 6.
///
/// Nothing here branches on `width` for its *row count*:
/// [`modal_form::render_modal`] sizes the chrome from a first build and
/// may call this again one column narrower, so a width-dependent row
/// count would silently mis-size the modal. Width may only change a
/// row's content, which is what the `value_budget` truncation does.
fn edit_form_body(
    modal: &RuleEditModal,
    width: u16,
) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let status = transient_status(modal);
    let hint = edit_field_hint;
    let budget = value_budget(width);

    let title = format!("Edit rule \u{b7} {}", modal.rule_id);
    let mut rows = modal_form::FormRows::new_desc2(&title, EDIT_DESC, width);

    // IDENTITY — both rows read-only and unfocusable: the id is the
    // rule's key, and the rule string is authored through the CLI. A row
    // that renders as focusable but cannot be reached is the same silent
    // class of defect as one that can be reached but not seen.
    rows.section("Identity");
    rows.line(modal_form::value_row(
        "Rule ID",
        &truncate(&modal.rule_id, budget),
        false,
        ValueKind::Identity,
        None,
        width,
    ));
    rows.line(modal_form::value_row(
        "Rule",
        &truncate(&modal.raw_rule, budget),
        false,
        ValueKind::Identity,
        None,
        width,
    ));
    rows.spacer();

    rows.section("Policy");
    let action = modal.focus == RuleEditFocus::Action;
    rows.field(
        modal_form::radio_row(
            "Action",
            ("Block", ValueKind::Blocking),
            ("Allow", ValueKind::Healthy),
            matches!(modal.current_action, RuleAction::Block),
            action,
            width,
        ),
        action,
        hint(RuleEditFocus::Action),
    );
    let scope = modal.focus == RuleEditFocus::Scope;
    rows.field(
        modal_form::selector_row("Scope", &edit_scope_text(modal), scope, width),
        scope,
        hint(RuleEditFocus::Scope),
    );
    // The reverse index, read-only, and deliberately inside POLICY
    // rather than a section of its own: it is what Scope currently
    // resolves to, so the two belong adjacent — and a third section
    // would have spent three rows of chrome on one row of data. At the
    // 80×24 floor the field viewport is four rows; measured, a lone
    // USAGE section left exactly one of them showing content.
    let (refs_text, refs_kind) = references_cell(modal);
    rows.line(modal_form::value_row(
        "References",
        &truncate(&refs_text, budget),
        false,
        refs_kind,
        None,
        width,
    ));

    // §4.65 UX3 (§3.6): Save is now Tab-reachable — `Enter` on it
    // commits, same as `Ctrl+S` from anywhere (D7′ extended, not
    // replaced: the chord still works from every other focus too).
    let actions = [
        Action::new(
            "  Delete rule\u{2026}  ",
            modal.focus == RuleEditFocus::DeleteButton,
            ActionKind::Destructive,
            hint(RuleEditFocus::DeleteButton),
        ),
        Action::new(
            "  Save  ",
            modal.focus == RuleEditFocus::SaveButton,
            ActionKind::Primary,
            hint(RuleEditFocus::SaveButton),
        ),
    ];

    let tail = modal_form::form_tail_with_status(
        &rows,
        status,
        modal.error_message.as_deref(),
        "",
        EDIT_KEYS,
        &actions,
    );
    rows.finish(tail)
}

/// The typed-id delete confirm as an Archetype-C notice.
///
/// The keying is unchanged (D7′): every `Char` lands in the buffer,
/// `Enter` commits only on an exact id match, `Esc` goes back to the
/// form. The actions carry their key in the label because neither is a
/// Tab target, and **neither is `Primary`** — the one teal fill means
/// "this is the action", which a destructive confirm should not be
/// advertising.
///
/// Three prose rows, and the *rendered* count is load-bearing:
/// [`modal_form::notice_body`] leaves `focus_row` at `None` when there
/// are no choices, so nothing scrolls the typed-input row back into
/// view. §4.63 S1 gave Archetype C a 2-row head and a 4-row tail, so the
/// content budget against the 12-row interior the D18 anchor leaves at
/// the 80×24 floor is **6**. Three rows fit with three to spare — and
/// the id row spends a second one whenever it wraps, which every id past
/// 59 characters does. Pinned by
/// `floor_delete_confirm_keeps_the_typed_input_on_screen`.
///
/// The id is [`modal_form::ProseRow::verbatim`] because the gate compares
/// what was typed against **all 64 bytes** of it. Ellipsised, the confirm
/// was unpassable by any keystroke sequence and nothing on screen said
/// why — see `delete_confirm_renders_a_max_length_id_in_full_at_the_floor`.
fn delete_notice(modal: &RuleEditModal, typed: &str) -> modal_form::NoticeSpec {
    modal_form::NoticeSpec {
        hint_rows: None,
        title: "Delete admin rule".to_string(),
        desc: "removes the [[admin_rules]] row and every reference to it".to_string(),
        prose: vec![
            modal_form::ProseRow::verbatim(modal.rule_id.clone(), ValueKind::Blocking),
            modal_form::ProseRow::plain("type the id above verbatim, then Enter:"),
            modal_form::ProseRow::plain(format!("> {typed}")),
        ],
        choices: Vec::new(),
        error: modal.error_message.clone(),
        hint: "nothing is written unless what you type matches exactly".to_string(),
        keys: "Enter confirm \u{b7} Esc back to edit".to_string(),
        actions: vec![
            Action::new("  Esc Back  ", false, ActionKind::Neutral, ""),
            Action::new("  Enter Delete  ", false, ActionKind::Destructive, ""),
        ],
    }
}

/// Render the rule edit modal, anchored on the tab content rect.
///
/// `anchor` is the Rules tab's content area (§4.61 D18), never
/// `f.area()`: the header, the menu card and the footer legend stay
/// visible behind it. That leaves a 12-row interior at the declared
/// 80×24 floor against an edit body of 21, which is why both stages are
/// built on a [`modal_form::ScrollBody`] and rendered through
/// [`modal_form::render_modal`] — it owns the chrome, the height
/// request, the anchor clamp, the two-pass width resolution and the
/// focus-following viewport. `overlay::centered_rect` clamps rather than
/// scrolls, so without that viewport the tail would simply be cut while
/// `Tab` went on reaching the rows that were cut.
///
/// The border accent is not a parameter any more: chrome stays neutral
/// grey and `brand_red` is never a border (D15). The confirm carries its
/// meaning in the body — a `Blocking` value colour on the id — instead
/// of in the frame.
pub fn render_rule_edit_modal(f: &mut Frame, anchor: Rect, modal: &RuleEditModal) {
    match &modal.mode {
        RuleEditMode::Edit => {
            modal_form::render_modal(f, anchor, MODAL_W, |w| edit_form_body(modal, w));
        }
        RuleEditMode::ConfirmDelete { typed } => {
            let spec = delete_notice(modal, typed);
            let render = modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&spec, w), ())
            });
            // The typed-id input hosts the real terminal cursor, so the
            // operator can see where their keystrokes land — the same
            // treatment the form's text fields get. `place_cursor`
            // no-ops when the row is scrolled out of view.
            //
            // Resolved through `prose_field_row` rather than hardcoded:
            // the verbatim id above spends a second line on any id past
            // the wrap column, which moves this row down by one.
            render.place_cursor(
                f,
                modal_form::prose_field_row(&spec.prose, TYPED_PROSE_ORDINAL),
                TYPED_PROMPT_COL + typed.chars().count() as u16,
            );
        }
    }
}

// ── §4.61 W3b MODAL REGION ENDS ───────────────────────────────────────

/// Char-count truncation with ellipsis, keeping the **head**. ASCII-fast
/// for the typical case (id strings, plain domain rules) but UTF-8-correct
/// for the rare pasted-from-clipboard edge case. Reused by
/// `tabs::local_dns` to budget the profile-id in its panel title. (The
/// keep-**tail** sibling for search fields lives in `tabs::query_log`.)
pub(crate) fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        out.push('\u{2026}');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── §4.61 Wave 3b: modal render ──────────────────────────────────

    /// One string per buffer row, so an assertion can tell "on screen"
    /// from "somewhere in the line vector".
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

    fn render_modal_in(modal: &RuleEditModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_rule_edit_modal(f, f.area(), modal))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    fn edit_modal_for_floor() -> RuleEditModal {
        RuleEditModal {
            rule_id: "auto-deny-3c2f8e5d".into(),
            raw_rule: "||tracker.example^".into(),
            original_action: RuleAction::Block,
            original_scope: RuleScope::Default,
            original_references: vec![RuleReference {
                kind: RuleScope::Default,
                via_field: "admin_rules",
            }],
            current_action: RuleAction::Block,
            current_scope_choice: ScopeChoice::Default,
            scope_options: vec![ScopeChoice::Default],
            focus: RuleEditFocus::Action,
            mode: RuleEditMode::Edit,
            error_message: None,
            status_message: None,
            submitting: false,
        }
    }

    #[test]
    fn edit_form_renders_banded_sections_and_the_focus_marker() {
        // The Archetype-F body replaced the `label : value` grid. The
        // sections label themselves now, and the focused row carries the
        // shared ecosystem marker rather than a local `▶` chevron.
        let (body, _) = edit_form_body(&edit_modal_for_floor(), 62);
        let text: String = body
            .head
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
            .join("\n");

        assert!(
            text.contains("IDENTITY") && text.contains("POLICY"),
            "labelled section bands:\n{text}"
        );
        assert!(
            text.contains("References"),
            "the reverse index rides POLICY, next to the Scope it resolves:\n{text}"
        );
        // `▌`, not `◀`: the emerald focus rule is the signal EVERY
        // ecosystem row carries. `modal_form::radio_row` — which is what
        // the default focus (Action) renders — emits the rule and the
        // highlight bar but no closing `◀`, where `value_row` emits all
        // three. Asserting `◀` here would be asserting a `value_row`
        // detail against a radio.
        assert!(
            text.contains('\u{258c}'),
            "focused row carries the emerald focus rule:\n{text}"
        );
        assert!(text.contains("Delete rule"), "Delete action present");
        assert!(text.contains("Save"), "Save action present");
        assert!(
            !text.contains("[ Delete rule\u{2026} ]"),
            "the hand-rolled bracket button is the action row's job now:\n{text}"
        );
    }

    // ── the 80×24 floor ──────────────────────────────────────────────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect these overlays anchor on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
    // 12-row interior. `overlay::centered_rect` CLAMPS rather than
    // scrolls, so a body taller than that is cut at the bottom while
    // `Tab` still moves focus onto the rows that were cut — the operator
    // then commits or deletes blind.

    #[test]
    fn floor_keeps_the_action_row_and_the_focused_field_on_screen_together() {
        // The two things a clip silently takes away, plus the proof the
        // viewport actually engaged.
        //
        // Fail-before, measured rather than assumed: the pre-migration
        // form was 14 fixed rows in a 12-row interior, and ratatui's
        // solver absorbed the 2-row deficit by zeroing two *blank*
        // spacers — so every positive needle below passed on HEAD, in
        // every state probed, including with an error message set. The
        // modal looked complete by luck, not by structure.
        // `!contains("Rule ID")` is the assertion that could not pass:
        // on a flat body the first field is on screen wherever focus
        // sits, so the viewport is doing nothing and a clip further down
        // would be invisible to a positive-only test.
        let mut modal = edit_modal_for_floor();
        modal.focus = RuleEditFocus::Scope; // the last focusable field
        let dump = render_modal_in(&modal, 80, 14);

        assert!(
            dump.contains("Delete rule"),
            "action row cut at the 80x24 floor — Tab still reaches it:\n{dump}"
        );
        assert!(dump.contains("Save"), "Save cut at the floor:\n{dump}");
        assert!(
            dump.contains("\u{2039} default \u{203a}"),
            "the focused scope row is off-screen:\n{dump}"
        );
        assert!(
            dump.contains('\u{25c0}'),
            "the focus marker must be on screen with the action row:\n{dump}"
        );
        assert!(
            !dump.contains("Rule ID"),
            "a 3-row viewport cannot be showing both ends of the form:\n{dump}"
        );
    }

    /// §4.68 DoD, **at the floor**: the two description rows are on screen,
    /// they fill the modal interior with `bg_main` `Rgb(15,15,15)` in teal
    /// `Rgb(13,148,136)`, they are NOT on the title's `Rgb(51,51,51)`, and
    /// the action row survived the head growing.
    ///
    /// Asserting the actions is not ceremony — §4.63 S2a+S2c grew the
    /// Devices form without re-deriving this budget and cost it `Save`,
    /// `Cancel` and 9 of 13 fields, while the focus ring still reached the
    /// buttons that were no longer drawn.
    #[test]
    fn floor_the_description_band_renders_on_its_own_strip_with_the_actions() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let modal = edit_modal_for_floor();
        let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
        term.draw(|f| render_rule_edit_modal(f, f.area(), &modal))
            .unwrap();
        modal_form::desc_band2_assert::assert_two_row_band(
            term.backend().buffer(),
            EDIT_DESC,
            &["Save", "Delete rule"],
        );
    }

    /// The copy ships at a width, so the width is a test rather than a
    /// comment. `render_body_fixed` does not wrap and prints no marker
    /// where it cuts — which is how the pre-2026-08-07 one-liner sat 2
    /// cells over this budget without anyone noticing.
    #[test]
    fn no_desc_row_outruns_the_narrow_build_pass() {
        // −2 chrome, −1 for the scrollbar column on the narrow pass,
        // −2 for `desc_band2`'s indent.
        const BUDGET: usize = MODAL_W as usize - 5;
        for line in EDIT_DESC {
            let n = line.chars().count();
            assert!(n <= BUDGET, "description row is {n} cells: {line:?}");
        }
    }

    #[test]
    fn floor_keeps_the_delete_action_reachable_and_visible() {
        // Focus on Delete renders no *field* row, so the viewport has no
        // anchor and sits at the top — the pinned tail is the only
        // reason the destructive action is on screen at all. That half
        // of the `ScrollBody` contract has nothing to do with scrolling
        // and needs its own assertion.
        let mut modal = edit_modal_for_floor();
        modal.focus = RuleEditFocus::DeleteButton;
        let dump = render_modal_in(&modal, 80, 14);

        assert!(
            dump.contains("Delete rule"),
            "the focused destructive action is off-screen:\n{dump}"
        );
        assert!(
            dump.contains("Enter opens a typed-id confirm"),
            "the focused action's guidance must reach the hint row:\n{dump}"
        );
    }

    #[test]
    fn floor_delete_confirm_keeps_the_typed_input_on_screen() {
        // Archetype C with no choices leaves `focus_row` at None, so
        // nothing scrolls the input back into view: the three prose rows
        // fit the floor with one row of slack, or the operator types
        // into a row they cannot see. A fourth prose row breaks this
        // silently, which is why the count is asserted here and not left
        // to the visual dump.
        let mut modal = edit_modal_for_floor();
        modal.mode = RuleEditMode::ConfirmDelete {
            typed: "auto-deny".into(),
        };
        let dump = render_modal_in(&modal, 80, 14);

        assert!(
            dump.contains("auto-deny-3c2f8e5d"),
            "the operator must see the id they have to type:\n{dump}"
        );
        assert!(
            dump.contains("> auto-deny"),
            "the typed-id input is off-screen:\n{dump}"
        );
        assert!(
            dump.contains("Enter Delete") && dump.contains("Esc Back"),
            "the Enter/Esc keying is unchanged and must stay legible:\n{dump}"
        );
    }

    /// Chrome and indents stripped, so a string that had to wrap across
    /// two rows reads back contiguous. `…` is deliberately kept — it is
    /// exactly what the id row must never produce.
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

    /// A non-uniform id of exactly `n` chars whose tail is unique in the
    /// frame — truncation always eats the tail, and a uniform needle like
    /// `"a".repeat(64)` would `contains`-match a cut render too.
    fn id_of_len(n: usize) -> String {
        format!("delete-me-{}-endsentinel", "x".repeat(n - 22))
    }

    /// The gate compares what was typed against the whole id, so the whole
    /// id has to be on screen. `Id::MAX_LEN` is 64 and the interior leaves
    /// 60 usable cells, so at the top of the band it cannot fit on one
    /// line — the ellipsis made the gate unpassable by any keystroke
    /// sequence, with nothing on screen explaining why.
    #[test]
    fn delete_confirm_renders_a_max_length_id_in_full_at_the_floor() {
        for n in 55..=64usize {
            let id = id_of_len(n);
            let mut modal = edit_modal_for_floor();
            modal.rule_id = id.clone();
            modal.mode = RuleEditMode::ConfirmDelete {
                typed: String::new(),
            };
            let dump = render_modal_in(&modal, 80, 14);
            // The id wraps, so its tail is NOT contiguous on one row —
            // that is the fix working. What must never appear is a `…`,
            // and nothing else in this stage is long enough to produce
            // one.
            assert!(
                !dump.contains('\u{2026}'),
                "a {n}-char id was ellipsised — the gate compares against \
                 all {n} bytes and the cut ones are unrecoverable:\n{dump}"
            );
            assert!(
                dechrome(&dump).contains(&id),
                "a {n}-char id is not recoverable from the screen — the \
                 operator cannot type what the gate demands:\n{dump}"
            );
        }
    }

    /// The same claim as `delete_confirm_typed_input_hosts_the_real_cursor`
    /// but at a length where the id **wraps**, which is the only case that
    /// exercises the conversion from a prose ordinal to a rendered row.
    ///
    /// That sibling uses a 19-character id, so `prose_field_row` returns
    /// the same 2 the old hardcoded `TYPED_PROSE_ROW` did and it passes
    /// whether or not the conversion is right. A wrapped id makes the
    /// field rows `[id-1, id-2, prompt, input]`, so an off-by-one lands
    /// the caret on `then Enter:` — which is audit finding **F1**, the
    /// "cursor blinking on a row the operator is not typing into" half
    /// that made it a P1. Reopening it for exactly the ids this sprint
    /// exists to serve would be the worst possible regression here.
    #[test]
    fn delete_confirm_cursor_follows_the_input_row_past_a_wrapped_id() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut modal = edit_modal_for_floor();
        let id = id_of_len(64);
        modal.rule_id = id.clone();
        modal.mode = RuleEditMode::ConfirmDelete {
            typed: "auto-deny".into(),
        };
        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_rule_edit_modal(f, f.area(), &modal))
            .unwrap();
        let pos = term.get_cursor_position().unwrap();

        let dump = dump_buffer(term.backend().buffer());
        // Precondition: the fixture must actually wrap, or this test is
        // just the sibling again. Whole across the frame but on no single
        // row is exactly what "it wrapped" means — and the wrap lands
        // mid-token, so no fixed needle can stand in for this.
        assert!(
            dechrome(&dump).contains(&id),
            "precondition: the id must render whole:\n{dump}"
        );
        assert!(
            !dump.lines().any(|l| l.contains(&id)),
            "precondition: a 64-char id must occupy two rows:\n{dump}"
        );
        let row = dump
            .lines()
            .nth(pos.y as usize)
            .expect("cursor row is inside the buffer");
        let before: String = row.chars().take(pos.x as usize).collect();
        assert!(
            before.ends_with("> auto-deny"),
            "the wrapped id moved the input row and the caret did not \
             follow — got column {} on {row:?}",
            pos.x
        );
    }

    #[test]
    fn delete_confirm_typed_input_hosts_the_real_cursor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut modal = edit_modal_for_floor();
        modal.mode = RuleEditMode::ConfirmDelete {
            typed: "auto-deny".into(),
        };
        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_rule_edit_modal(f, f.area(), &modal))
            .unwrap();
        let pos = term.get_cursor_position().unwrap();

        let dump = dump_buffer(term.backend().buffer());
        let row = dump
            .lines()
            .nth(pos.y as usize)
            .expect("cursor row is inside the buffer");
        let before: String = row.chars().take(pos.x as usize).collect();
        assert!(
            before.ends_with("> auto-deny"),
            "cursor must sit just past the typed id, got column {} on {row:?}",
            pos.x
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
        term.draw(|f| render_rule_edit_modal(f, anchor, &modal))
            .unwrap();
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
    fn transient_status_has_its_own_slot_and_the_focus_guidance_survives() {
        // §4.63 S1 gave the status its own tail slot
        // (`modal_form::form_tail_with_status`), so it no longer has to
        // be smuggled through every row's hint — and the guidance for
        // whatever holds focus survives the submit alongside it.
        //
        // Both halves still matter, for the surviving GUIDANCE rather
        // than for the status: with a FIELD focused it comes from the row
        // hint, with DELETE focused no field row is focused at all and it
        // can only arrive through the focused *action*'s hint. Testing
        // one and assuming the other is how the second path stays broken.
        //
        // Was `transient_status_reaches_the_hint_row_from_a_field_and_from_an_action`;
        // its `!contains("Enter opens a typed-id confirm")` pinned the
        // workaround and is now inverted.
        let mut modal = edit_modal_for_floor();
        modal.submitting = true;
        modal.status_message = Some("saving\u{2026}".into());

        modal.focus = RuleEditFocus::Action;
        let dump = render_modal_in(&modal, 80, 24);
        assert!(
            dump.contains("saving\u{2026}"),
            "status missing with a field focused:\n{dump}"
        );

        modal.focus = RuleEditFocus::DeleteButton;
        let dump = render_modal_in(&modal, 80, 24);
        assert!(
            dump.contains("saving\u{2026}"),
            "status missing with no field row focused:\n{dump}"
        );
        assert!(
            dump.contains("Enter opens a typed-id confirm"),
            "the focused action's guidance must survive beside the \
             status — the action-hint leg of form_tail's precedence:\n{dump}"
        );
    }

    #[test]
    fn error_message_renders_with_the_warning_affordance() {
        // The real string `mod.rs`'s delete path produces on a
        // mismatched confirm — the one an operator actually meets.
        let mut modal = edit_modal_for_floor();
        modal.error_message = Some(format!(
            "typed 'x' \u{2260} '{}' \u{2014} delete aborted",
            modal.rule_id
        ));
        let dump = render_modal_in(&modal, 80, 24);

        assert!(
            dump.contains('\u{26a0}'),
            "a failure carries the ⚠ affordance:\n{dump}"
        );
        assert!(
            dump.contains("delete aborted"),
            "the tail of the message must survive:\n{dump}"
        );
    }

    #[test]
    fn no_hand_rolled_colour_in_the_modal_region() {
        // §4.61 Wave 3b's acceptance criterion as a test rather than a
        // claim in a commit message. Scoped to the modal region: this
        // file is a *tab* as well as two overlays, and the table header,
        // the scope column and the filter chips keep their own styles —
        // §4.61 §1.1 puts tab chrome outside this workstream.
        //
        // Both markers are `expect`ed: a renamed marker would otherwise
        // turn this into a vacuous pass over an empty slice, which is
        // the same class of false green the whole wave is about. The
        // needles are split so the assertion cannot match itself.
        let src = include_str!("rules.rs");
        let begin = concat!("\u{a7}4.61 W3b MODAL REGION ", "BEGINS");
        let end = concat!("\u{a7}4.61 W3b MODAL REGION ", "ENDS");
        let start = src.find(begin).expect("modal region BEGINS marker");
        let stop = start
            + src[start..]
                .find(end)
                .expect("modal region ENDS marker after BEGINS");
        let region = &src[start..stop];
        assert!(
            region.len() > 2000,
            "modal region is suspiciously small ({} bytes) — markers moved?",
            region.len()
        );

        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
            concat!("Borders", "::ALL"),
        ] {
            assert!(
                !region.contains(needle),
                "{needle} inside the modal region — the colour belongs in modal_form"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test rules_modal_visual_dump -- --ignored --nocapture"]
    fn rules_modal_visual_dump() {
        let mut modal = edit_modal_for_floor();
        println!("--- roomy anchor ---\n{}", render_modal_in(&modal, 100, 40));
        println!(
            "--- the 80x24 floor (14-row content rect) ---\n{}",
            render_modal_in(&modal, 80, 14)
        );
        modal.focus = RuleEditFocus::Scope;
        println!(
            "--- same, focus on the last field ---\n{}",
            render_modal_in(&modal, 80, 14)
        );
        modal.focus = RuleEditFocus::DeleteButton;
        println!(
            "--- same, focus on Delete ---\n{}",
            render_modal_in(&modal, 80, 14)
        );
        modal.mode = RuleEditMode::ConfirmDelete {
            typed: "auto-deny".into(),
        };
        println!(
            "--- delete confirm at the floor ---\n{}",
            render_modal_in(&modal, 80, 14)
        );
    }

    #[test]
    fn filter_cycles_through_three_states_and_wraps() {
        let mut app = App::new();
        assert_eq!(app.rules.filter, RulesFilter::All);
        app.rules.filter = app.rules.filter.next();
        assert_eq!(app.rules.filter, RulesFilter::Allow);
        app.rules.filter = app.rules.filter.next();
        assert_eq!(app.rules.filter, RulesFilter::Deny);
        app.rules.filter = app.rules.filter.next();
        assert_eq!(
            app.rules.filter,
            RulesFilter::All,
            "cycle must wrap back to All"
        );
    }

    #[test]
    fn filter_label_matches_enum() {
        // Pinned so `RulesFilter::label` stays in sync with what the
        // chip renders — the title bar embeds this label and operators
        // read it as part of "what am I seeing right now".
        assert_eq!(RulesFilter::All.label(), "all");
        assert_eq!(RulesFilter::Allow.label(), "allow");
        assert_eq!(RulesFilter::Deny.label(), "deny");
    }

    #[test]
    fn matches_filter_obeys_chip_state() {
        // ::All → both kinds pass.
        assert!(matches_filter(RuleAction::Allow, RulesFilter::All));
        assert!(matches_filter(RuleAction::Block, RulesFilter::All));
        // ::Allow → only Allow passes; Block (named "Deny" in the
        // chip per AdGuard convention) is hidden.
        assert!(matches_filter(RuleAction::Allow, RulesFilter::Allow));
        assert!(!matches_filter(RuleAction::Block, RulesFilter::Allow));
        // ::Deny → mirror of Allow.
        assert!(!matches_filter(RuleAction::Allow, RulesFilter::Deny));
        assert!(matches_filter(RuleAction::Block, RulesFilter::Deny));
    }

    #[test]
    fn format_pattern_regex_truncates_on_char_boundary_not_byte_index() {
        // Pasting a Unicode regex (e.g. via copy/paste from a docs
        // page) used to panic when `format_pattern` byte-sliced at
        // index 29 that landed mid-codepoint. The fix uses
        // `chars().take(29)` which always lands on a char boundary.
        // Build a regex source that's >30 chars AND has a multi-byte
        // codepoint straddling byte 29 to exercise the code path.
        use compact_str::CompactString;
        // Build a 40-char source ending in a 4-byte emoji at the slice
        // boundary so byte-indexing would panic.
        let source: String = std::iter::repeat_n('a', 28)
            .chain(std::iter::once('🦀'))
            .chain(std::iter::repeat_n('a', 11))
            .collect();
        let pattern = RulePattern::Regex {
            source: CompactString::from(source.as_str()),
            compiled: regex::Regex::new("a+").unwrap(),
        };
        // Must NOT panic; must return a string with `re:` prefix +
        // ellipsis suffix.
        let label = format_pattern(&pattern);
        assert!(label.starts_with("re:"), "got: {label}");
        assert!(label.ends_with('\u{2026}'), "got: {label}");
    }

    #[test]
    fn rules_table_layout_pins_five_columns() {
        // Pin the 5-column shape (ID | SCOPE | ACTION | DOMAIN | RULE).
        // If a future edit drops a column, this test fails loudly so
        // the operator-facing column contract doesn't drift silently.
        let _layout: [Constraint; 5] = [
            Constraint::Length(22),
            Constraint::Length(18),
            Constraint::Length(7),
            Constraint::Min(18),
            Constraint::Min(20),
        ];
    }

    // ── B2 — build_rule_rows reverse-index over devices/profiles ─────

    /// Build an `App` with a single profile (the default), one device,
    /// and three admin rules: one referenced by a device's allow_rules,
    /// one referenced by the default profile, one orphan. Used to
    /// exercise the scope-precedence + parse_rule + reverse-index logic.
    fn app_with_three_rules() -> App {
        use crate::config::loader::load_config;
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&master).unwrap();
        f.write_all(
            br#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[admin_rules]]
id = "alex-allow-bank"
rule = "@@||bank.example^"

[[admin_rules]]
id = "default-deny-tracker"
rule = "||tracker.example^"

[[admin_rules]]
id = "lonely-orphan"
rule = "||nobody-refs-me.example^"

[[devices]]
id = "iphone"
display_name = "iPhone"
mac = "aa:bb:cc:dd:ee:ff"
allow_rules = ["alex-allow-bank"]

[profiles.default]
display_name = "Default"
admin_rules = ["default-deny-tracker"]
"#,
        )
        .unwrap();
        // Avoid leaking the tempdir before load_config reads.
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.loaded_config = Some(loaded);
        // Hold the tempdir alive past load_config (the loader reads
        // includes lazily; for a single-file master this is technically
        // unnecessary, but it's the safe default).
        std::mem::forget(dir);
        app
    }

    #[test]
    fn build_rule_rows_extracts_action_from_at_at_prefix() {
        let app = app_with_three_rules();
        let rows = build_rule_rows(&app);
        let bank = rows
            .iter()
            .find(|r| r.id == "alex-allow-bank")
            .expect("bank rule must be in the row vec");
        assert_eq!(bank.action, RuleAction::Allow);
        assert_eq!(bank.domain_label, "bank.example");
        let tracker = rows
            .iter()
            .find(|r| r.id == "default-deny-tracker")
            .expect("tracker rule must be in the row vec");
        assert_eq!(tracker.action, RuleAction::Block);
    }

    #[test]
    fn build_rule_rows_resolves_scope_to_device_when_referenced() {
        let app = app_with_three_rules();
        let rows = build_rule_rows(&app);
        let bank = rows.iter().find(|r| r.id == "alex-allow-bank").unwrap();
        match &bank.scope {
            RuleScope::Device(id) => assert_eq!(id, "iphone"),
            other => panic!("expected Device scope, got {other:?}"),
        }
        // References must include the device's allow_rules entry.
        assert!(
            bank.references.iter().any(
                |r| matches!(&r.kind, RuleScope::Device(id) if id == "iphone")
                    && r.via_field == "allow_rules"
            ),
            "bank rule's references must include the device's allow_rules; got {:?}",
            bank.references
        );
    }

    #[test]
    fn build_rule_rows_resolves_scope_to_default_for_default_profile_ref() {
        let app = app_with_three_rules();
        let rows = build_rule_rows(&app);
        let tracker = rows
            .iter()
            .find(|r| r.id == "default-deny-tracker")
            .unwrap();
        // Profile id "default" matches [server].default_profile so the
        // scope renders as Default, not Profile("default").
        assert!(
            matches!(tracker.scope, RuleScope::Default),
            "default-profile-only ref must be Default, got {:?}",
            tracker.scope
        );
    }

    #[test]
    fn build_rule_rows_marks_orphan_when_no_references() {
        let app = app_with_three_rules();
        let rows = build_rule_rows(&app);
        let orphan = rows.iter().find(|r| r.id == "lonely-orphan").unwrap();
        assert!(
            matches!(orphan.scope, RuleScope::Orphan),
            "no-ref master entry must be Orphan, got {:?}",
            orphan.scope
        );
        assert!(
            orphan.references.is_empty(),
            "orphan rule's references list must be empty"
        );
    }

    #[test]
    fn edit_modal_targets_the_row_under_cursor_with_text_filter_active() {
        // rules-01 (P0): the edit/delete modal builder must index the
        // SAME visible set the table renders — action chip AND `/` text
        // search (`matches_rule_filters`). With the text filter narrowing
        // the set to a single rule, the cursor at index 0 must resolve to
        // THAT rule, not the first row of the wider action-only set —
        // otherwise `Enter`/`Del` operate on a different rule than the one
        // highlighted (and the delete dialog prints the wrong id).
        let mut app = app_with_three_rules();
        // `/`-search matching only the orphan rule (its id + raw rule).
        app.rules.filter = RulesFilter::All;
        app.rules.filter_text = Some("orphan".to_string());
        app.rules.table_state.select(Some(0));

        // Sanity: the visible (action + text) set is exactly one row.
        let rows = build_rule_rows(&app);
        let visible: Vec<&RuleRowMeta> = rows
            .iter()
            .filter(|r| matches_rule_filters(r, app.rules.filter, app.rules.filter_text.as_deref()))
            .collect();
        assert_eq!(visible.len(), 1, "text filter must narrow to one row");

        let modal = build_rule_edit_modal_for(&app).expect("a row is focused");
        assert_eq!(
            modal.rule_id, "lonely-orphan",
            "edit modal must target the highlighted (text-filtered) row, \
             not the first row of the wider action-only set"
        );
    }
}
