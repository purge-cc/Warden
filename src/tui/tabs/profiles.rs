//! Profiles tab — master/detail view of the v1 `[profiles]` map.
//!
//! The master list (left) shows every configured profile with summary
//! columns; the side-card (right) drills into the focused profile — the 6
//! MUTATE fields plus an offline "What it blocks" summary: the effective
//! blocklists it resolves to through
//! [`effective_direction`](crate::config::schema::effective_direction) —
//! each list's `base` as overridden by `profiles.<id>.lists` — a total
//! domain count, and a demoted local-records / rewrites pointer.
//!
//! ## Data source
//!
//! [`App::loaded_config`] — the offline v1 master + includes, refreshed
//! at TUI startup, on `r`, and after every successful modal submit. Same
//! offline-backed pattern as Subnets / Local DNS: the daemon is NOT
//! consulted for the list, which avoids a stale view while the operator
//! stages edits that haven't hot-reloaded yet. Profile *references* (the
//! side-card ref-count + the delete pre-check) are computed against the
//! same `loaded_config`'s `devices` / `groups` / `subnets` / `schedules`.
//!
//! ## Selection model
//!
//! [`ProfilesState::selected_id`](crate::tui::app::ProfilesState::selected_id)
//! is the operator-stable selection key — the profile's id (its
//! `BTreeMap` key). It survives list refreshes and
//! modal-driven CRUD; resolving it back to a row index every render
//! keeps the cursor on the same logical profile.
//!
//! ## Mutation
//!
//! Add / Edit / Delete open [`crate::tui::profile_modal::ProfileModal`]
//! and submit through the Phase 1 IPC verbs — see `tui/mod.rs`.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;
use std::cmp::Ordering;

use crate::config::loader::LoadedConfig;
use crate::config::schema::{Blocklist, Profile};
use crate::config::settings::EcsMode;
use crate::lists::status::BlocklistStatusDto;
use crate::profiles::profile::resolve_profile_blocklist_ids;
use crate::tui::app::{App, Leaf};
use crate::tui::detail_panel;
use crate::tui::format::count as humanize_domains;
use crate::tui::modal_form::{self, ValueKind};
use crate::tui::mouse::{self, MouseAction, SortOrder};
use crate::tui::profile_modal;
use crate::tui::theme::{self, CardRole, T};

/// The shared master/detail floor: 60 list cells, one gutter, 42 detail.
const NARROW_THRESHOLD: u16 = 108;
const COLUMN_SPACING: u16 = 2;
const HEADERS: [&str; 5] = ["ID", "DISPLAY NAME", "LISTS", "BLOCK-ALL", "ECS"];

/// One stable profile identity and its captured display data. Rendering and
/// input index this single sorted vector, never the map's declaration order.
#[derive(Debug, Clone)]
pub struct ProfileRow {
    pub id: String,
    pub profile: Profile,
}

pub fn display_row_key(row: &ProfileRow) -> &str {
    &row.id
}

pub fn index_of_display_key(rows: &[ProfileRow], selected: Option<&str>) -> Option<usize> {
    let selected = selected?;
    rows.iter().position(|row| row.id == selected)
}

/// Whether the editing stage is hosted by the wide yellow detail card.
/// Confirmations and outcomes deliberately remain centered overlays.
pub fn inline_editor_visible(_viewport_width: u16, app: &App) -> bool {
    app.active_leaf == Leaf::Profiles
        && app
            .profiles
            .modal
            .as_ref()
            .is_some_and(|modal| matches!(modal.stage, profile_modal::Stage::EditingForm(_)))
}

// ── Public render entry point ────────────────────────────────────────

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    if app.loaded_config.is_none() {
        render_no_config(f, area);
        return;
    }
    let profiles = build_display_rows(app);

    if profiles.is_empty() {
        render_empty_master_detail(f, area, app);
        return;
    }

    let detail_key = index_of_display_key(&profiles, app.profiles.selected_id.as_deref())
        .and_then(|index| profiles.get(index))
        .or_else(|| profiles.first())
        .map(|row| row.id.as_str())
        .unwrap_or_default();
    detail_panel::prepare(app, Leaf::Profiles, detail_key);

    if inline_editor_visible(area.width, app) && area.width < NARROW_THRESHOLD {
        profile_modal::render_inline_editor(f, area, app.profiles.modal.as_ref().unwrap());
        return;
    }

    if area.width < NARROW_THRESHOLD {
        // Right enters the focused document at narrow widths; Left/Esc
        // restores this identity-stable master list.
        if detail_panel::focused(app, Leaf::Profiles) {
            let loaded = app.loaded_config.as_ref().expect("checked above");
            render_detail(f, area, app, loaded, &profiles);
        } else {
            render_master(f, area, app, &profiles);
        }
        return;
    }

    let cols = proportional_columns(area);

    render_master(f, cols[0], app, &profiles);
    if inline_editor_visible(area.width, app) {
        profile_modal::render_inline_editor(f, cols[1], app.profiles.modal.as_ref().unwrap());
    } else {
        let loaded = app.loaded_config.as_ref().expect("checked above");
        render_detail(f, cols[1], app, loaded, &profiles);
    }
}

fn proportional_columns(area: Rect) -> [Rect; 2] {
    let left = (u32::from(area.width) * 42 / 100) as u16;
    [
        Rect::new(area.x, area.y, left, area.height),
        Rect::new(
            area.x + left.saturating_sub(1),
            area.y,
            area.width.saturating_sub(left).saturating_add(1),
            area.height,
        ),
    ]
}

// ── Master pane ──────────────────────────────────────────────────────

fn render_master(f: &mut Frame, area: Rect, app: &mut App, profiles: &[ProfileRow]) {
    let subtitle = format!("{} Policy Bundles \u{00b7} Stable IDs", profiles.len());
    let body = theme::filled_card(
        f.buffer_mut(),
        area,
        "PROFILES",
        &subtitle,
        CardRole::Analytics,
    );
    let constraints = profile_constraints();
    let columns = crate::tui::ui::table_column_rects(body, &constraints, COLUMN_SPACING, 0);
    let sort = app.mouse.sort(Leaf::Profiles);
    let header = Row::new(HEADERS.iter().enumerate().map(|(index, label)| {
        Cell::from(sort_header(label, index, sort)).style(theme::table_heading_style(
            sort.is_some_and(|order| order.column == index),
        ))
    }))
    .style(theme::table_heading_style(false));

    let rows: Vec<Row> = profiles
        .iter()
        .map(|row| master_row(&row.id, &row.profile))
        .collect();

    // Resolve `selected_id` back to a row index every frame — modal CRUD
    // moves rows in/out, so an index from the previous frame is stale.
    // The scroll offset persists regardless (see `tabs::subnets::render_master`
    // for why that is safe across a row-count change).
    let selected = index_of_display_key(profiles, app.profiles.selected_id.as_deref())
        .or_else(|| (!rows.is_empty()).then_some(0));

    let table = Table::new(rows, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    super::render_table(f, body, table, &mut app.profiles.table_state, selected);
    for (index, rect) in columns.iter().enumerate() {
        mouse::register(app, *rect, MouseAction::Sort(Leaf::Profiles, index));
    }
    let offset = app.profiles.table_state.offset();
    for (visible, index) in (0..profiles.len())
        .skip(offset)
        .take(body.height.saturating_sub(1) as usize)
        .enumerate()
    {
        mouse::register(
            app,
            Rect::new(body.x, body.y + 1 + visible as u16, body.width, 1),
            MouseAction::Row(Leaf::Profiles, index),
        );
    }
}

fn master_row(id: &str, p: &Profile) -> Row<'static> {
    let block_all = if p.block_all {
        Cell::from(Span::styled(
            "yes",
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Cell::from(Span::styled("no", Style::default().fg(T.text_muted)))
    };
    Row::new(vec![
        Cell::from(id.to_string()),
        Cell::from(p.display_name.clone()),
        Cell::from((p.lists.len() + p.custom_lists.len()).to_string()),
        block_all,
        Cell::from(ecs_summary(p)),
    ])
}

fn profile_constraints() -> [Constraint; HEADERS.len()] {
    [
        Constraint::Min(12),
        Constraint::Min(14),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(8),
    ]
}

fn sort_header(label: &str, index: usize, sort: Option<SortOrder>) -> String {
    match sort.filter(|sort| sort.column == index) {
        Some(sort) if sort.descending => format!("{label} ▼"),
        Some(_) => format!("{label} ▲"),
        None => label.to_string(),
    }
}

/// The sole display sequence for Profiles. Numeric columns use their native
/// values and every equal sort falls back to the immutable profile id.
pub fn build_display_rows(app: &App) -> Vec<ProfileRow> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    let mut rows: Vec<ProfileRow> = loaded
        .config
        .profiles
        .iter()
        .map(|(id, profile)| ProfileRow {
            id: id.clone(),
            profile: profile.clone(),
        })
        .collect();
    if let Some(sort) = app.mouse.sort(Leaf::Profiles) {
        rows.sort_by(|left, right| {
            let order = match sort.column {
                0 => left.id.cmp(&right.id),
                1 => left
                    .profile
                    .display_name
                    .to_lowercase()
                    .cmp(&right.profile.display_name.to_lowercase()),
                2 => (left.profile.lists.len() + left.profile.custom_lists.len())
                    .cmp(&(right.profile.lists.len() + right.profile.custom_lists.len())),
                3 => left.profile.block_all.cmp(&right.profile.block_all),
                4 => ecs_summary(&left.profile).cmp(&ecs_summary(&right.profile)),
                _ => Ordering::Equal,
            };
            let order = if sort.descending {
                order.reverse()
            } else {
                order
            };
            order.then_with(|| left.id.cmp(&right.id))
        });
    }
    rows
}

// ── Detail pane (side-card) ──────────────────────────────────────────

fn render_detail(
    f: &mut Frame,
    area: Rect,
    app: &App,
    loaded: &LoadedConfig,
    profiles: &[ProfileRow],
) {
    let selection = index_of_display_key(profiles, app.profiles.selected_id.as_deref())
        .and_then(|index| profiles.get(index))
        .or_else(|| profiles.first());

    let Some(selection) = selection else {
        return;
    };
    let id = &selection.id;
    let profile = &selection.profile;
    let subtitle = format!("{id} \u{00b7} Policy Bundle");
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "PROFILE DETAILS",
        &subtitle,
        CardRole::History,
    );

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(24);

    lines.extend(modal_form::section_band_with_role(
        "Identity",
        content.width,
        CardRole::Summary,
    ));
    lines.push(modal_form::value_row(
        "id",
        id,
        false,
        ValueKind::Identity,
        None,
        content.width,
    ));
    lines.push(modal_form::value_row(
        "display name",
        &profile.display_name,
        false,
        ValueKind::Editable,
        None,
        content.width,
    ));
    lines.push(Line::default());
    lines.extend(modal_form::section_band_with_role(
        "Blocking",
        content.width,
        CardRole::Summary,
    ));
    let response = block_response_label(profile);
    lines.push(modal_form::value_row(
        "block response",
        &response,
        false,
        ValueKind::Blocking,
        None,
        content.width,
    ));
    let ttl = blocked_ttl_label(profile);
    lines.push(modal_form::value_row(
        "blocked ttl",
        &ttl,
        false,
        ValueKind::Editable,
        None,
        content.width,
    ));
    lines.push(modal_form::value_row(
        "block all",
        if profile.block_all { "yes" } else { "no" },
        false,
        if profile.block_all {
            ValueKind::Blocking
        } else {
            ValueKind::Healthy
        },
        None,
        content.width,
    ));
    lines.push(Line::default());
    lines.extend(modal_form::section_band_with_role(
        "ECS & Privacy",
        content.width,
        CardRole::Summary,
    ));
    let ecs = ecs_detail_label(profile);
    lines.push(modal_form::value_row(
        "ecs",
        &ecs,
        false,
        ValueKind::Identity,
        None,
        content.width,
    ));

    // "What it blocks" summary — offline: resolve the profile's effective
    // blocklists through `effective_direction` (each list's `base` as
    // overridden by `profiles.<id>.lists`; `profile.tags` decides nothing).
    lines.push(Line::default());
    lines.extend(modal_form::section_band_with_role(
        "What it blocks",
        content.width,
        CardRole::Analytics,
    ));
    let summary = profile_blocks_summary(profile, &loaded.config.blocklists, &app.lists.entries);
    push_blocks_summary(&mut lines, &summary, profile, app.operator_catalog.as_ref());

    lines.push(Line::default());
    lines.extend(modal_form::section_band_with_role(
        "References",
        content.width,
        CardRole::Summary,
    ));
    lines.push(modal_form::value_row(
        "referenced by",
        &reference_summary(loaded, id),
        false,
        ValueKind::Identity,
        None,
        content.width,
    ));

    let detail = Rect::new(
        content.x,
        content.y,
        content.width,
        content.height.saturating_sub(1),
    );
    detail_panel::render(f, detail, app, Leaf::Profiles, id, lines);
    if content.height > 0 {
        let footer = Rect::new(content.x, content.bottom() - 1, content.width, 1);
        let actions = [modal_form::Action::new(
            "  Edit  ",
            false,
            modal_form::ActionKind::Primary,
            "Enter edits this profile",
        )
        .on_key(crossterm::event::KeyCode::Enter)];
        f.render_widget(
            Paragraph::new(modal_form::action_row(&actions, footer.width)),
            footer,
        );
        for (rect, key) in modal_form::action_regions(&actions, footer) {
            mouse::register(app, rect, MouseAction::Key(key.code));
        }
    }
}

fn render_empty_master_detail(f: &mut Frame, area: Rect, app: &App) {
    if area.width < NARROW_THRESHOLD {
        let body = theme::filled_card(
            f.buffer_mut(),
            area,
            "PROFILES",
            "Configured Policy Bundles",
            CardRole::Analytics,
        );
        render_empty(f, body);
        return;
    }
    let cols = proportional_columns(area);
    let body = theme::filled_card(
        f.buffer_mut(),
        cols[0],
        "PROFILES",
        "Configured Policy Bundles",
        CardRole::Analytics,
    );
    render_empty(f, body);
    if inline_editor_visible(area.width, app) {
        profile_modal::render_inline_editor(f, cols[1], app.profiles.modal.as_ref().unwrap());
    } else {
        let detail = theme::filled_card(
            f.buffer_mut(),
            cols[1],
            "PROFILE DETAILS",
            "Select a Policy Bundle",
            CardRole::History,
        );
        f.render_widget(
            Paragraph::new(Span::styled(
                "  add a profile to inspect its policy and mounts",
                Style::default().fg(T.text_muted),
            )),
            detail,
        );
    }
}

// ── Profile reference counting ───────────────────────────────────────

/// Per-entity-class counts of how many config entries name `profile_id`.
/// Devices carry `Option<Id>`; groups / subnets / schedules carry a
/// mandatory `Id`. Used by the side-card ref line AND the Delete modal's
/// client-side pre-check (`reference_summary`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProfileRefCounts {
    pub devices: usize,
    pub groups: usize,
    pub subnets: usize,
    pub schedules: usize,
}

impl ProfileRefCounts {
    pub fn total(&self) -> usize {
        self.devices + self.groups + self.subnets + self.schedules
    }
}

/// Count every device / group / subnet / schedule in `loaded` that
/// references `profile_id`. Offline — no IPC, no daemon round-trip.
pub fn count_profile_refs(loaded: &LoadedConfig, profile_id: &str) -> ProfileRefCounts {
    let cfg = &loaded.config;
    ProfileRefCounts {
        devices: cfg
            .devices
            .iter()
            .filter(|d| d.profile.as_ref().map(|p| p.as_str()) == Some(profile_id))
            .count(),
        groups: cfg
            .groups
            .iter()
            .filter(|g| g.profile.as_str() == profile_id)
            .count(),
        subnets: cfg
            .subnets
            .iter()
            .filter(|s| s.profile.as_str() == profile_id)
            .count(),
        schedules: cfg
            .schedules
            .iter()
            .filter(|s| s.profile.as_str() == profile_id)
            .count(),
    }
}

/// Human-readable reference summary for the side-card + the Delete
/// modal's pre-check line. `"nothing — safe to delete"` when unreferenced.
pub fn reference_summary(loaded: &LoadedConfig, profile_id: &str) -> String {
    let c = count_profile_refs(loaded, profile_id);
    if c.total() == 0 {
        return "nothing — safe to delete".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    if c.devices > 0 {
        parts.push(format!("{} device(s)", c.devices));
    }
    if c.groups > 0 {
        parts.push(format!("{} group(s)", c.groups));
    }
    if c.subnets > 0 {
        parts.push(format!("{} subnet(s)", c.subnets));
    }
    if c.schedules > 0 {
        parts.push(format!("{} schedule(s)", c.schedules));
    }
    parts.join(", ")
}

// ── Label helpers ────────────────────────────────────────────────────

/// Master-list ECS column — terse: `off` / `coarse` / `subnet` /
/// `inherit` (the explicit per-profile `mode`), or `—` when the profile
/// has no `ecs` subtree at all.
fn ecs_summary(profile: &Profile) -> String {
    match &profile.ecs {
        None => "\u{2014}".to_string(),
        Some(cfg) => ecs_mode_label(cfg.mode).to_string(),
    }
}

/// Side-card ECS line — the full subtree, or `(inherit)` when absent.
fn ecs_detail_label(profile: &Profile) -> String {
    match &profile.ecs {
        None => "(inherit upstream)".to_string(),
        Some(cfg) => {
            let mut s = format!("mode={}", ecs_mode_label(cfg.mode));
            if let Some(v4) = cfg.source_prefix_v4 {
                s.push_str(&format!(" v4=/{v4}"));
            }
            if let Some(v6) = cfg.source_prefix_v6 {
                s.push_str(&format!(" v6=/{v6}"));
            }
            s
        }
    }
}

fn ecs_mode_label(mode: Option<EcsMode>) -> &'static str {
    match mode {
        None => "inherit",
        Some(EcsMode::Off) => "off",
        Some(EcsMode::Coarse) => "coarse",
        Some(EcsMode::Subnet) => "subnet",
    }
}

fn block_response_label(profile: &Profile) -> String {
    match profile.block_response {
        None => "(inherit)".to_string(),
        Some(v) => format!("{v:?}").to_lowercase(),
    }
}

fn blocked_ttl_label(profile: &Profile) -> String {
    match profile.blocked_ttl_secs {
        None => "(inherit)".to_string(),
        Some(n) => format!("{n}s"),
    }
}

// ── "What it blocks" summary ──────────────────────────────────────────
//
// The Profiles detail pane summarises the effective blocklists a profile
// resolves to via `effective_direction` (offline — no daemon round-trip)
// plus a total domain count. The operator-facing literals below are frozen
// by `tests/frozen_strings_tui_t1.rs` (reached through the `pub use` in
// `src/tui/mod.rs`); land any copy change in the same commit as the docs.

/// Section header above the summary block.
pub const PROFILE_LABEL_WHAT_IT_BLOCKS: &str = "What it blocks";
/// KV label for the resolved-lists line.
pub const PROFILE_LABEL_BLOCKLISTS: &str = "Blocklists";
/// KV label for the demoted local-records / rewrites line.
pub const PROFILE_LABEL_ALSO: &str = "Also";
/// Blocklists-line value when `block_all` supersedes list filtering.
pub const PROFILE_BLOCKS_ALL_QUERIES: &str = "(all queries blocked)";
/// Blocklists-line value when the profile resolves to zero lists.
pub const PROFILE_BLOCKS_NONE: &str =
    "none — this profile blocks nothing via lists (set one to Block in this profile's editor)";
/// Count-line value when the list poll has not landed yet.
pub const PROFILE_BLOCKS_LOADING: &str = "(loading…)";
/// Count-line suffix when ≥1 resolved list has no polled count.
pub const PROFILE_BLOCKS_PARTIAL: &str = "(partial)";

/// KV label for the custom-lists mount line, sibling of `Blocklists`.
/// Counts come from the daemon-owned operator-policy catalogue. The config
/// snapshot only says what a profile mounts; it is not an authoritative pack
/// parse and must not be presented as one.
pub const PROFILE_LABEL_CUSTOM_LISTS: &str = "Custom lists";
/// Custom-lists-line value when the profile mounts zero custom lists —
/// not an error, since most profiles will have none.
pub const PROFILE_CUSTOM_LISTS_NONE: &str = "none mounted";
/// Mount metadata has not landed, so rules/validation counts are unknown.
pub const PROFILE_CUSTOM_LISTS_UNAVAILABLE: &str = "catalog unavailable";

/// Domain-count state of the "What it blocks" summary. Kept distinct from
/// the resolved-list vector so the renderer picks the right count-line copy:
/// `block_all` and an empty resolution suppress the line, an unpolled daemon
/// shows `(loading…)`, and a landed poll shows the summed upper bound —
/// flagged `(partial)` when a resolved list is missing from the poll.
///
/// The loading vs partial boundary is `entries.is_empty()` (poll never
/// landed), NOT "every resolved count is absent" — a landed poll that simply
/// lacks *this* profile's lists is `partial` (`~0 domains (partial)`), not
/// `loading`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BlocksCount {
    /// `block_all = true` — list filtering is bypassed entirely.
    BlockAll,
    /// `resolve_profile_blocklist_ids` returned empty — no list's
    /// effective direction blocks for this profile, so it filters
    /// nothing via lists.
    NoLists,
    /// Lists resolved, but `app.lists.entries` is empty (poll not landed).
    Loading,
    /// At least one list resolved and the poll has landed. `sum` is the
    /// upper-bound domain total (lists overlap; no dedup). `partial` is set
    /// when ≥1 resolved list had no polled entry (excluded from `sum`).
    Counted { sum: u64, partial: bool },
}

/// Offline summary of what a profile blocks — the data the detail pane
/// renders under "What it blocks". Pure output of [`profile_blocks_summary`]
/// so every branch is unit-testable without a running daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlocksSummary {
    /// Mirrors `profile.block_all` — hoisted so the renderer branches once.
    block_all: bool,
    /// Resolved lists in daemon (lexicographic-id) order: display name
    /// (fallback id) + polled domain count when known. Empty for `block_all`
    /// and for a profile whose every list resolves to `ignore`.
    lists: Vec<(String, Option<u64>)>,
    /// Count-line state (see [`BlocksCount`]).
    count: BlocksCount,
}

/// Compose the offline "What it blocks" summary for `profile`. Reuses the
/// daemon's canonical direction predicate via
/// [`resolve_profile_blocklist_ids`] — which reads
/// [`effective_direction`](crate::config::schema::effective_direction), the
/// list's `base` as overridden by `profiles.<id>.lists` — then
/// joins each resolved id to its display name (from `blocklists`) and its
/// polled domain count (from `entries`, the ~30 s Lists poll payload).
///
/// Pure — no `App`, no IPC — so it is unit-tested directly.
fn profile_blocks_summary(
    profile: &Profile,
    blocklists: &[Blocklist],
    entries: &[BlocklistStatusDto],
) -> BlocksSummary {
    if profile.block_all {
        // block_all supersedes list filtering — skip resolution entirely.
        return BlocksSummary {
            block_all: true,
            lists: Vec::new(),
            count: BlocksCount::BlockAll,
        };
    }

    let ids = resolve_profile_blocklist_ids(profile, blocklists);
    let lists: Vec<(String, Option<u64>)> = ids
        .iter()
        .map(|id| {
            let name = blocklists
                .iter()
                .find(|b| &b.id == id)
                .map(|b| b.display_name.clone())
                .unwrap_or_else(|| id.as_str().to_string());
            let count = entries
                .iter()
                .find(|e| e.id.as_deref() == Some(id.as_str()))
                .map(|e| e.entries);
            (name, count)
        })
        .collect();

    let count = if lists.is_empty() {
        BlocksCount::NoLists
    } else if entries.is_empty() {
        // Poll has not landed — names are known, counts are not.
        BlocksCount::Loading
    } else {
        let sum = lists.iter().filter_map(|(_, c)| *c).sum();
        let partial = lists.iter().any(|(_, c)| c.is_none());
        BlocksCount::Counted { sum, partial }
    };

    BlocksSummary {
        block_all: false,
        lists,
        count,
    }
}

/// Render the resolved-list names: all when ≤5, else the first 5 + a
/// `(+K more)` overflow tag. Pure — the renderer + unit test share it.
fn render_list_names(names: &[String]) -> String {
    const MAX: usize = 5;
    if names.len() <= MAX {
        names.join(", ")
    } else {
        format!("{} (+{} more)", names[..MAX].join(", "), names.len() - MAX)
    }
}

/// The count line shown under Blocklists, or `None` when suppressed
/// (`block_all` / no lists). `~` marks the sum as an overlap upper bound.
fn count_line(count: &BlocksCount) -> Option<String> {
    match count {
        BlocksCount::BlockAll | BlocksCount::NoLists => None,
        BlocksCount::Loading => Some(format!("~ {PROFILE_BLOCKS_LOADING}")),
        BlocksCount::Counted { sum, partial } => {
            let base = format!("~{} domains", humanize_domains(*sum));
            Some(if *partial {
                format!("{base} {PROFILE_BLOCKS_PARTIAL}")
            } else {
                base
            })
        }
    }
}

/// The value on the Blocklists line: joined names, or the `block_all` /
/// empty sentinel sentence.
fn blocklists_value(summary: &BlocksSummary) -> String {
    if summary.block_all {
        return PROFILE_BLOCKS_ALL_QUERIES.to_string();
    }
    if summary.lists.is_empty() {
        return PROFILE_BLOCKS_NONE.to_string();
    }
    let names: Vec<String> = summary.lists.iter().map(|(n, _)| n.clone()).collect();
    render_list_names(&names)
}

/// Push the "What it blocks" summary block into the detail-pane line list.
fn push_blocks_summary(
    lines: &mut Vec<Line<'static>>,
    summary: &BlocksSummary,
    profile: &Profile,
    catalog: Option<&crate::tui::operator_policy::PolicyCatalog>,
) {
    // Blocklists line — names, or a block_all / empty sentence.
    let value = blocklists_value(summary);
    let value_color = if summary.block_all {
        T.brand_red
    } else if summary.lists.is_empty() {
        T.text_muted
    } else {
        T.text_primary
    };
    lines.push(kv_str(PROFILE_LABEL_BLOCKLISTS, &value, value_color));

    // Indented domain-count line — only when it carries information. This
    // is a continuation of Blocklists, not a line of its own, so Custom
    // lists must sit after it, not between it and its parent.
    if let Some(count) = count_line(&summary.count) {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::raw(format!("{:<14}", "")),
            Span::styled(count, Style::default().fg(T.text_muted)),
        ]));
    }

    // Custom lists are siblings of Blocklists, after its count-line
    // continuation. Keep each mount on an atomic logical row so a narrow
    // detail pane cannot wrap `(missing)` into an unreadable fragment.
    lines.extend(custom_lists_lines(profile, catalog));

    // Demoted local-records / rewrites pointer.
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            format!("{:<14}", PROFILE_LABEL_ALSO),
            Style::default().fg(T.text_muted),
        ),
        Span::styled(
            format!(
                "Local records {} \u{00b7} Rewrites {}",
                profile.local_records.len(),
                profile.rewrite_rules.len()
            ),
            Style::default().fg(T.text_muted),
        ),
    ]));
}

/// One `custom_lists` mount, resolved against catalogue metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CustomListMount {
    /// Present in the daemon catalogue — counts include validation rows.
    Present {
        id: String,
        rules: usize,
        malformed: usize,
    },
    /// The profile names an id absent from the store. The validator
    /// refuses this on load; the TUI also renders configs that bypassed it.
    Missing { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CustomListMounts {
    Unavailable,
    Resolved(Vec<CustomListMount>),
}

/// Resolve a profile's declared mounts against the catalogue, preserving the
/// profile's order. A missing catalogue is not treated as an empty one.
fn resolve_custom_list_mounts(
    profile: &Profile,
    catalog: Option<&crate::tui::operator_policy::PolicyCatalog>,
) -> CustomListMounts {
    if profile.custom_lists.is_empty() {
        return CustomListMounts::Resolved(Vec::new());
    }
    let Some(catalog) = catalog else {
        return CustomListMounts::Unavailable;
    };
    CustomListMounts::Resolved(
        profile
            .custom_lists
            .iter()
            .map(
                |id| match catalog.lists.iter().find(|list| list.id == id.as_str()) {
                    Some(list) => CustomListMount::Present {
                        id: id.as_str().to_string(),
                        rules: list.rule_count,
                        malformed: list.invalid_rows,
                    },
                    None => CustomListMount::Missing {
                        id: id.as_str().to_string(),
                    },
                },
            )
            .collect(),
    )
}

/// Build the `Custom lists` KV rows. Each mount is coloured on its own —
/// present in `text_primary`, missing in `T.error` — and occupies one row so
/// the status remains intact when the detail pane is narrow.
fn custom_lists_lines(
    profile: &Profile,
    catalog: Option<&crate::tui::operator_policy::PolicyCatalog>,
) -> Vec<Line<'static>> {
    let mounts = resolve_custom_list_mounts(profile, catalog);
    let CustomListMounts::Resolved(mounts) = mounts else {
        return vec![kv_str(
            PROFILE_LABEL_CUSTOM_LISTS,
            PROFILE_CUSTOM_LISTS_UNAVAILABLE,
            T.warning,
        )];
    };
    if mounts.is_empty() {
        return vec![kv_str(
            PROFILE_LABEL_CUSTOM_LISTS,
            PROFILE_CUSTOM_LISTS_NONE,
            T.text_secondary,
        )];
    }

    mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| {
            let value = match mount {
                CustomListMount::Present {
                    id,
                    rules,
                    malformed,
                } => Span::styled(
                    if *malformed == 0 {
                        format!("{id} ({rules} rules)")
                    } else {
                        format!("{id} ({rules} rules, {malformed} malformed)")
                    },
                    Style::default().fg(T.text_primary),
                ),
                CustomListMount::Missing { id } => {
                    Span::styled(format!("{id} (missing)"), Style::default().fg(T.error))
                }
            };
            kv(
                if index == 0 {
                    PROFILE_LABEL_CUSTOM_LISTS
                } else {
                    ""
                },
                value,
            )
        })
        .collect()
}

fn kv(label: &'static str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{label:<14}"), Style::default().fg(T.text_muted)),
        value,
    ])
}

fn kv_str(label: &'static str, value: &str, color: Color) -> Line<'static> {
    kv(
        label,
        Span::styled(value.to_string(), Style::default().fg(color)),
    )
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "PROFILES",
        "Configuration Unavailable",
        CardRole::Analytics,
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "  could not load config — fix it and press r to retry",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
}

pub fn render_info_overlay(f: &mut Frame, area: Rect, app: &App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return;
    };
    if !app.profiles.info_open {
        return;
    }
    let rows = build_display_rows(app);
    let Some(selected) = index_of_display_key(&rows, app.profiles.selected_id.as_deref())
        .and_then(|index| rows.get(index))
        .or_else(|| rows.first())
    else {
        return;
    };
    let profile = &selected.profile;
    let inherited = profile
        .lists
        .iter()
        .map(|(id, policy)| format!("{}={}", id.as_str(), policy.wire_str()))
        .collect::<Vec<_>>();
    let mounts = profile
        .custom_lists
        .iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>();
    let prose = vec![
        modal_form::ProseRow::emphasis(
            format!("ID              {}", selected.id),
            ValueKind::Identity,
        ),
        modal_form::ProseRow::plain(format!("Display         {}", profile.display_name)),
        modal_form::ProseRow::plain(format!("Block response  {}", block_response_label(profile))),
        modal_form::ProseRow::plain(format!("Blocked TTL     {}", blocked_ttl_label(profile))),
        modal_form::ProseRow::plain(format!(
            "Block all       {}",
            if profile.block_all { "yes" } else { "no" }
        )),
        modal_form::ProseRow::plain(format!("ECS             {}", ecs_detail_label(profile))),
        modal_form::ProseRow::verbatim(
            format!(
                "List overrides  {}",
                if inherited.is_empty() {
                    "None".to_string()
                } else {
                    inherited.join(", ")
                }
            ),
            ValueKind::Identity,
        ),
        modal_form::ProseRow::verbatim(
            format!(
                "Custom mounts   {}",
                if mounts.is_empty() {
                    "None".to_string()
                } else {
                    mounts.join(", ")
                }
            ),
            ValueKind::Identity,
        ),
        modal_form::ProseRow::plain(format!(
            "Referenced by    {}",
            reference_summary(loaded, &selected.id)
        )),
    ];
    let spec = modal_form::NoticeSpec {
        title: "Profile Details".into(),
        desc: "Effective filter policy and references".into(),
        prose,
        keys: "[Enter / i / Esc] close".into(),
        actions: vec![modal_form::Action::new(
            "  [Esc] Close  ",
            false,
            modal_form::ActionKind::Neutral,
            "",
        )
        .on_key(crossterm::event::KeyCode::Esc)],
        ..Default::default()
    };
    modal_form::render_modal(f, area, 78, |width| {
        (modal_form::notice_body(&spec, width), ())
    });
}

fn render_empty(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "  no profiles configured.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  press `a` to add one.",
            Style::default().fg(T.text_muted),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::schema::{ConfigV1, Id, Profile};
    use crate::operator_rules::{Capabilities, ListDetail, Metadata, TransportLimits};
    use crate::tui::app::{Leaf, Section};
    use crate::tui::operator_policy::PolicyCatalog;

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    #[tokio::test]
    async fn painted_edit_button_has_an_exact_mouse_target() {
        use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let mut app = App::known_standalone_for_test();
        app.active_leaf = Leaf::Profiles;
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles: mk_profiles(),
            ..Default::default()
        }));
        app.profiles.selected_id = Some("default".into());
        mouse::reset(&app);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(164, 36)).unwrap();
        terminal.draw(|f| render(f, f.area(), &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let (x, y) = (0..36)
            .find_map(|y| {
                let row: String = (0..164).map(|x| buffer[(x, y)].symbol()).collect();
                row.find(" Edit ").map(|x| (x as u16, y))
            })
            .expect("painted Edit button");
        let click = |column| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row: y,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(
            mouse::action(&app, click(x)),
            Some(MouseAction::Key(KeyCode::Enter))
        );
        assert_eq!(
            mouse::action(&app, click(x + 5)),
            Some(MouseAction::Key(KeyCode::Enter))
        );
        assert_ne!(
            mouse::action(&app, click(x - 1)),
            Some(MouseAction::Key(KeyCode::Enter))
        );
        assert_ne!(
            mouse::action(&app, click(x + 6)),
            Some(MouseAction::Key(KeyCode::Enter))
        );
        let temp = tempfile::tempdir().unwrap();
        let poller = crate::tui::ipc_poller::IpcPoller::new(&temp.path().join("absent.sock"));
        let config = temp.path().join("config.toml");
        crate::tui::handle_key(
            &mut app,
            crossterm::event::KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
            &poller,
            &config,
        )
        .await;
        let sort_before = app.mouse.sort(Leaf::Profiles);
        crate::tui::handle_mouse(&mut app, click(x), &poller, &config).await;
        assert_eq!(
            app.mouse.sort(Leaf::Profiles),
            sort_before,
            "Edit must not activate the focused sort column"
        );
        assert!(app.profiles.modal.is_some());
    }

    fn mk_profiles() -> BTreeMap<String, Profile> {
        let mut m = BTreeMap::new();
        m.insert("default".to_string(), Profile::default());
        m.insert(
            "kids".to_string(),
            Profile {
                display_name: "Kids".into(),
                block_all: true,
                ..Default::default()
            },
        );
        m
    }

    fn loaded_with(cfg: ConfigV1) -> LoadedConfig {
        LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        }
    }

    fn custom_list_catalog(lists: Vec<(&str, usize, usize)>) -> PolicyCatalog {
        PolicyCatalog {
            capabilities: Capabilities {
                contract_version: crate::operator_rules::CONTRACT_VERSION,
                schema_version: 5,
                operator_rule_grammar: 1,
                operations: Vec::new(),
                semantic_hash: true,
                activation_ack: true,
                cluster_artifact: false,
                limits: TransportLimits::IPC,
            },
            metadata: Metadata {
                contract_version: crate::operator_rules::CONTRACT_VERSION,
                schema_version: 5,
                config_revision: "config-r1".into(),
                desired_operator_policy_hash: String::new(),
                active_policy: None,
                activation_in_sync: true,
                lists: lists.len(),
                mounted_lists: 0,
                orphan_packs: 0,
            },
            lists: lists
                .into_iter()
                .map(|(id, rules, malformed)| ListDetail {
                    id: id.to_string(),
                    display_name: id.to_string(),
                    description: String::new(),
                    config_revision: "config-r1".into(),
                    pack_revision: format!("{id}-r1"),
                    bytes: 0,
                    rule_count: rules,
                    invalid_rows: malformed,
                    profiles: Vec::new(),
                })
                .collect(),
            orphan_packs: Vec::new(),
        }
    }

    // ── Leaf wiring ──────────────────────────────────────────────────

    #[test]
    fn profiles_leaf_is_wired_to_the_filters_section() {
        // Not `Leaf::Profiles.index() == 5`, `Leaf::ALL[5] == Leaf::Profiles`
        // or `Leaf::ALL.len() == 10`/`11` — three hand-transcribed constants
        // that were correct only for as long as nobody inserted a leaf ahead
        // of Profiles, and which the compiler could not protect. `Leaf::ALL`
        // is now flattened from `app::LAYOUT`, so a leaf index is not
        // writable by hand at all, and its length is whatever the table says.
        // Re-pinning them here would recreate the very drift the refactor
        // removed; asserting the leaf's WIRING is what this file actually
        // cares about.
        assert_eq!(Leaf::Profiles.section(), Section::Filters);
        assert_eq!(Section::Filters.leaves()[0], Leaf::Profiles);
        assert_eq!(Section::Filters.default_leaf(), Leaf::Profiles);
        assert!(!Section::Network.leaves().contains(&Leaf::Profiles));
        assert_eq!(Leaf::from_mnemonic('p'), Some(Leaf::Profiles));
        assert_eq!(Leaf::Profiles.label(), "Profiles");
    }

    // ── master_rows / selection ───────────────────────────────────────

    #[test]
    fn master_rows_one_per_profile() {
        let profiles = mk_profiles();
        let mut app = App::new();
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        }));
        let rows = build_display_rows(&app);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn display_row_index_hits_and_misses() {
        let profiles = mk_profiles();
        let mut app = App::new();
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        }));
        let rows = build_display_rows(&app);
        assert_eq!(index_of_display_key(&rows, Some("default")), Some(0));
        assert_eq!(index_of_display_key(&rows, Some("kids")), Some(1));
        assert_eq!(index_of_display_key(&rows, Some("ghost")), None);
        assert_eq!(index_of_display_key(&rows, None), None);
    }

    #[test]
    fn display_rows_sort_numeric_list_counts_and_keep_selection_by_id() {
        let mut profiles = mk_profiles();
        profiles.get_mut("default").unwrap().custom_lists = vec![id("one")];
        profiles.get_mut("kids").unwrap().custom_lists = vec![id("one"), id("two")];
        let mut app = App::new();
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        }));
        app.mouse.toggle_sort(Leaf::Profiles, 2);
        let ascending = build_display_rows(&app);
        assert_eq!(
            ascending
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["default", "kids"]
        );

        app.profiles.selected_id = Some("kids".to_string());
        app.mouse.toggle_sort(Leaf::Profiles, 2);
        let descending = build_display_rows(&app);
        assert_eq!(
            index_of_display_key(&descending, app.profiles.selected_id.as_deref()),
            Some(0),
            "the immutable id follows its row when a numeric sort reverses"
        );
    }

    #[test]
    fn display_name_sort_uses_unicode_case_and_keeps_id_ties_ascending() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "zeta".to_string(),
            Profile {
                display_name: "Äther".into(),
                ..Default::default()
            },
        );
        profiles.insert(
            "alpha".to_string(),
            Profile {
                display_name: "äther".into(),
                ..Default::default()
            },
        );
        let mut app = App::new();
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        }));

        app.mouse.toggle_sort(Leaf::Profiles, 1);
        for descending in [false, true] {
            let rows = build_display_rows(&app);
            assert_eq!(
                rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["alpha", "zeta"],
                "Unicode-equivalent display names retain an ascending immutable-id tie"
            );
            if !descending {
                app.mouse.toggle_sort(Leaf::Profiles, 1);
            }
        }
    }

    #[test]
    fn solved_profile_headers_match_the_mouse_click_gutters() {
        let body = Rect::new(5, 7, 80, 1);
        let columns =
            crate::tui::ui::table_column_rects(body, &profile_constraints(), COLUMN_SPACING, 0);
        assert_eq!(columns.first().unwrap().x, body.x);
        assert!(columns.last().unwrap().right() <= body.right());
        assert!(columns
            .windows(2)
            .all(|pair| pair[0].right().saturating_add(COLUMN_SPACING) == pair[1].x));
    }

    #[test]
    fn profile_editor_is_modal_when_narrow_and_inline_when_wide() {
        let mut app = App::new();
        app.profiles.modal = Some(profile_modal::ProfileModal::open_add());
        assert!(!inline_editor_visible(NARROW_THRESHOLD, &app));
        app.active_leaf = Leaf::Profiles;
        assert!(inline_editor_visible(NARROW_THRESHOLD - 1, &app));
        assert!(inline_editor_visible(NARROW_THRESHOLD, &app));
    }

    // ── reference counting ────────────────────────────────────────────

    #[test]
    fn count_profile_refs_spans_all_four_entity_classes() {
        // `Device` carries no `Default` impl + a dozen fields, so build
        // the fixture via TOML — the same pattern the Local DNS tab
        // tests use. A device + a subnet both reference "kids".
        let toml_src = r#"
schema_version = 5

[upstream]
servers = ["1.1.1.1"]

[profiles.default]

[profiles.kids]
display_name = "Kids"
block_all = true

[[devices]]
id = "phone"
display_name = "Phone"
ip = "10.10.1.50"
profile = "kids"

[[subnets]]
id = "lan"
display_name = "LAN"
cidrs = ["10.0.0.0/24"]
profile = "kids"
"#;
        let cfg = toml::from_str::<ConfigV1>(toml_src).unwrap();
        let loaded = loaded_with(cfg);

        let c = count_profile_refs(&loaded, "kids");
        assert_eq!(c.devices, 1);
        assert_eq!(c.subnets, 1);
        assert_eq!(c.groups, 0);
        assert_eq!(c.schedules, 0);
        assert_eq!(c.total(), 2);

        let unref = count_profile_refs(&loaded, "default");
        assert_eq!(unref.total(), 0);
        assert_eq!(
            reference_summary(&loaded, "default"),
            "nothing — safe to delete"
        );
        assert!(reference_summary(&loaded, "kids").contains("1 device(s)"));
        assert!(reference_summary(&loaded, "kids").contains("1 subnet(s)"));
    }

    // ── label helpers ─────────────────────────────────────────────────

    #[test]
    fn ecs_summary_distinguishes_absent_from_explicit() {
        let none = Profile::default();
        assert_eq!(ecs_summary(&none), "\u{2014}");
        let coarse = Profile {
            ecs: Some(crate::config::schema::ProfileEcsConfig {
                mode: Some(EcsMode::Coarse),
                source_prefix_v4: None,
                source_prefix_v6: None,
            }),
            ..Default::default()
        };
        assert_eq!(ecs_summary(&coarse), "coarse");
    }

    #[test]
    fn block_response_label_inherits_when_none() {
        assert_eq!(block_response_label(&Profile::default()), "(inherit)");
        let p = Profile {
            block_response: Some(crate::config::schema::BlockResponseV1::Nxdomain),
            ..Default::default()
        };
        assert_eq!(block_response_label(&p), "nxdomain");
    }

    // ── render-doesn't-panic ──────────────────────────────────────────

    #[test]
    fn render_runs_with_no_loaded_config() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        term.draw(|f| render(f, Rect::new(0, 0, 80, 20), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(content.contains("PROFILES"));
    }

    #[test]
    fn render_runs_with_profiles_loaded() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 24);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let cfg = ConfigV1 {
            profiles: mk_profiles(),
            ..Default::default()
        };
        app.loaded_config = Some(loaded_with(cfg));
        app.profiles.selected_id = Some("kids".to_string());
        term.draw(|f| render(f, Rect::new(0, 0, 120, 24), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(content.contains("PROFILES"));
        assert!(content.contains("kids"));
        // Side-card "What it blocks" summary renders for the selected profile.
        assert!(content.contains("WHAT IT BLOCKS"));
    }

    // ── "What it blocks" summary — pure composition (tui-wave1) ────────

    /// Config fixture: three blocklists, and three profiles that reach
    /// different subsets of them through their own `lists` overrides.
    /// `kids` overrides `adult-full` to `ignore` and inherits the other
    /// two, so it resolves to exactly `ads-basic` + `mal-core`; `default`
    /// ignores all three and resolves to nothing; `locked` is on
    /// `block_all`, which supersedes list resolution entirely.
    fn mk_blocks_config() -> ConfigV1 {
        let toml_src = r#"
schema_version = 5

[upstream]
servers = ["1.1.1.1"]

# `plp-s3`: the shapes these tests need are unchanged — one profile
# reaching two of the three lists, one reaching none, one on `block_all` —
# but the mechanism that produces them is the per-profile override, not
# tag intersection. `plp-s5d` dropped the `tags` arrays that used to sit
# here: the summary was the last thing reading them, and it no longer
# does.
[profiles.default]
lists = { ads-basic = "ignore", mal-core = "ignore", adult-full = "ignore" }

[profiles.kids]
display_name = "Kids"
lists = { adult-full = "ignore" }

[profiles.locked]
display_name = "Locked"
block_all = true

[[blocklists]]
id = "ads-basic"
display_name = "Ads Basic"
url = "https://lists.example/ads.txt"

[[blocklists]]
id = "mal-core"
display_name = "Malware Core"
url = "https://lists.example/mal.txt"

[[blocklists]]
id = "adult-full"
display_name = "Adult"
url = "https://lists.example/adult.txt"
"#;
        toml::from_str::<ConfigV1>(toml_src).unwrap()
    }

    fn dto(id: &str, entries: u64) -> BlocklistStatusDto {
        BlocklistStatusDto {
            id: Some(id.to_string()),
            entries,
            ..Default::default()
        }
    }

    #[test]
    fn summary_resolves_effective_direction_and_sums_domains() {
        let cfg = mk_blocks_config();
        let kids = &cfg.profiles["kids"];
        let entries = vec![dto("ads-basic", 100_000), dto("mal-core", 52_000)];

        let s = profile_blocks_summary(kids, &cfg.blocklists, &entries);

        assert!(!s.block_all);
        // Resolver sorts ids lexicographically: ads-basic < mal-core.
        let names: Vec<&str> = s.lists.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["Ads Basic", "Malware Core"]);
        // `adult-full` never resolves — this profile overrides it to `ignore`.
        assert!(!names.contains(&"Adult"));
        assert_eq!(
            s.count,
            BlocksCount::Counted {
                sum: 152_000,
                partial: false
            }
        );
    }

    #[test]
    fn summary_block_all_supersedes_lists() {
        let cfg = mk_blocks_config();
        let locked = &cfg.profiles["locked"];
        // Even with polled entries for a list it inherits, block_all wins.
        let entries = vec![dto("ads-basic", 100_000)];

        let s = profile_blocks_summary(locked, &cfg.blocklists, &entries);

        assert!(s.block_all);
        assert_eq!(s.count, BlocksCount::BlockAll);
        assert!(s.lists.is_empty());
    }

    #[test]
    fn summary_all_lists_ignored_resolves_nothing() {
        let cfg = mk_blocks_config();
        let default = &cfg.profiles["default"];
        let entries = vec![dto("ads-basic", 100_000)];

        let s = profile_blocks_summary(default, &cfg.blocklists, &entries);

        assert!(!s.block_all);
        assert!(s.lists.is_empty());
        assert_eq!(s.count, BlocksCount::NoLists);
    }

    #[test]
    fn summary_loading_when_lists_never_polled() {
        let cfg = mk_blocks_config();
        let kids = &cfg.profiles["kids"];
        // Empty entries slice == the daemon poll has not landed yet.
        let s = profile_blocks_summary(kids, &cfg.blocklists, &[]);

        assert_eq!(s.lists.len(), 2, "names still shown while loading");
        assert_eq!(s.count, BlocksCount::Loading);
    }

    #[test]
    fn summary_partial_when_one_resolved_list_absent() {
        let cfg = mk_blocks_config();
        let kids = &cfg.profiles["kids"];
        // Poll happened (non-empty) but only ads-basic has a count.
        let entries = vec![dto("ads-basic", 100_000)];

        let s = profile_blocks_summary(kids, &cfg.blocklists, &entries);

        assert_eq!(
            s.count,
            BlocksCount::Counted {
                sum: 100_000,
                partial: true
            }
        );
    }

    // ── render-string helpers (pure) ──────────────────────────────────
    // `humanize_domains` is `tui::format::count` (aliased above) — its
    // magnitude-scaling behavior is tested there, not here.

    #[test]
    fn list_names_line_truncates_past_five() {
        let five = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        assert_eq!(render_list_names(&five), "a, b, c, d, e");

        let mut seven = five.clone();
        seven.push("f".to_string());
        seven.push("g".to_string());
        assert_eq!(render_list_names(&seven), "a, b, c, d, e (+2 more)");
    }

    #[test]
    fn count_line_renders_each_state() {
        assert_eq!(count_line(&BlocksCount::BlockAll), None);
        assert_eq!(count_line(&BlocksCount::NoLists), None);
        assert_eq!(count_line(&BlocksCount::Loading).unwrap(), "~ (loading…)");
        assert_eq!(
            count_line(&BlocksCount::Counted {
                sum: 152_340,
                partial: false
            })
            .unwrap(),
            "~152K domains"
        );
        assert_eq!(
            count_line(&BlocksCount::Counted {
                sum: 100_000,
                partial: true
            })
            .unwrap(),
            "~100K domains (partial)"
        );
    }

    #[test]
    fn render_shows_resolved_lists_and_domain_count() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut app = App::new();
        app.loaded_config = Some(loaded_with(mk_blocks_config()));
        // `kids` inherits ads-basic + mal-core and overrides adult-full to
        // `ignore`, so it resolves to the first two; a landed poll gives
        // both a domain count → 100k + 52k = 152k.
        app.lists.entries = vec![dto("ads-basic", 100_000), dto("mal-core", 52_000)];
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 120, 30), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }

        assert!(content.contains("WHAT IT BLOCKS"));
        assert!(content.contains("Ads Basic"));
        assert!(content.contains("Malware Core"));
        assert!(content.contains("152K domains"));
        // The demoted pointer.
        assert!(content.contains("Also"));

        // `plp-s5d`: the `Tags` KV line is gone from the side-card.
        //
        // **This negative is not vacuous, and the assertion above is what
        // makes it so.** The Tags line sat BETWEEN the domain count and
        // the `Also` pointer, so a terminal too short to reach it would
        // also have cut `Also` — and `Also` is asserted present two lines
        // up. An absence proven on a buffer that never rendered the region
        // is the deletion-lane trap the brief names; this one renders the
        // region and finds nothing there.
        assert!(
            !content.contains("ads, malware"),
            "the Tags KV line still renders the profile's tag slugs:\n{content}"
        );
    }

    // ── Custom lists mount line ─────────────────────────────────────────

    #[test]
    fn custom_list_mounts_resolve_present_and_missing() {
        let profile = Profile {
            custom_lists: vec![id("videogames"), id("ghost-list")],
            ..Default::default()
        };
        let catalog = custom_list_catalog(vec![("videogames", 3, 1)]);

        let mounts = resolve_custom_list_mounts(&profile, Some(&catalog));

        // Declaration order is preserved.
        assert_eq!(
            mounts,
            CustomListMounts::Resolved(vec![
                CustomListMount::Present {
                    id: "videogames".to_string(),
                    rules: 3,
                    malformed: 1,
                },
                CustomListMount::Missing {
                    id: "ghost-list".to_string(),
                },
            ])
        );
    }

    #[test]
    fn custom_list_mounts_empty_when_profile_mounts_none() {
        let profile = Profile::default();
        assert_eq!(
            resolve_custom_list_mounts(&profile, None),
            CustomListMounts::Resolved(Vec::new())
        );
    }

    /// The indented domain-count line is a continuation of Blocklists, not
    /// a row of its own — Custom lists must sit after it, never between it
    /// and its parent. A presence-only check (both labels somewhere on
    /// screen) would pass under any ordering; this pins the three rows as
    /// consecutive, in this exact sequence.
    #[test]
    fn custom_lists_row_follows_the_blocklists_count_line_not_precedes_it() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut cfg = mk_blocks_config();
        cfg.profiles.get_mut("kids").unwrap().custom_lists = vec![id("videogames")];
        let loaded = loaded_with(cfg);

        let mut app = App::new();
        app.active_leaf = Leaf::Profiles;
        // Landed poll on both lists `kids` resolves to, so the indented
        // count line renders (same fixture as
        // `render_shows_resolved_lists_and_domain_count`).
        app.lists.entries = vec![dto("ads-basic", 100_000), dto("mal-core", 52_000)];
        app.loaded_config = Some(loaded);
        app.operator_catalog = Some(custom_list_catalog(vec![("videogames", 3, 1)]));
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 120, 30), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        let blocklists_y = rows
            .iter()
            .position(|r| r.contains(PROFILE_LABEL_BLOCKLISTS))
            .expect("Blocklists row renders");
        let custom_lists_y = rows
            .iter()
            .position(|row| row.contains(PROFILE_LABEL_CUSTOM_LISTS))
            .expect("Custom lists row renders before the detail viewport ends");
        let blocklists_body = rows[blocklists_y..custom_lists_y].join("\n");
        assert!(
            blocklists_body.contains("152K domains"),
            "the wrapped Blocklists continuation lost its domain count:\n{}",
            rows.join("\n")
        );
        assert!(
            blocklists_y < custom_lists_y,
            "Custom lists must follow the complete wrapped Blocklists value:\n{}",
            rows.join("\n")
        );
        assert!(detail_panel::focus(&app, Leaf::Profiles));
        assert!(detail_panel::handle_detail_key(
            &mut app,
            crossterm::event::KeyCode::End
        ));
        term.draw(|f| render(f, Rect::new(0, 0, 120, 30), &mut app))
            .unwrap();
        let tail = term.backend().to_string();
        for token in ["videogames", "(3", "rules,", "malformed)"] {
            assert!(tail.contains(token), "missing {token:?} after End:\n{tail}");
        }
    }

    #[test]
    fn render_shows_custom_lists_present_and_missing_with_color() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(160, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "kids".to_string(),
            Profile {
                display_name: "Kids".into(),
                custom_lists: vec![id("videogames"), id("ghost-list")],
                ..Default::default()
            },
        );
        let loaded = loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        });

        let mut app = App::new();
        app.active_leaf = Leaf::Profiles;
        app.loaded_config = Some(loaded);
        app.operator_catalog = Some(custom_list_catalog(vec![("videogames", 3, 1)]));
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 160, 30), &mut app))
            .unwrap();
        assert!(detail_panel::focus(&app, Leaf::Profiles));
        assert!(detail_panel::handle_detail_key(
            &mut app,
            crossterm::event::KeyCode::End
        ));
        term.draw(|f| render(f, Rect::new(0, 0, 160, 30), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        let content = rows.join("\n");

        assert!(content.contains(PROFILE_LABEL_CUSTOM_LISTS));
        for token in [
            "videogames",
            "(3",
            "rules,",
            "malformed)",
            "ghost-list",
            "(missing)",
        ] {
            assert!(
                content.contains(token),
                "mount token {token:?} not rendered from catalogue metadata after End:\n{content}"
            );
        }

        // A whole-line colour would hide the dangling reference among the
        // valid ones — each mount must carry its own colour.
        let find_cell = |needle: &str| {
            let (y, row) = rows
                .iter()
                .enumerate()
                .find(|(_, row)| row.contains(needle))
                .unwrap_or_else(|| panic!("{needle:?} must remain reachable after End"));
            let x = row[..row.find(needle).unwrap()].chars().count() as u16;
            (x, y as u16)
        };
        let present = find_cell("videogames");
        let missing = find_cell("ghost-list");
        assert_eq!(buf[present].fg, T.text_primary);
        assert_eq!(buf[missing].fg, T.error);
    }

    #[test]
    fn render_shows_none_mounted_in_secondary_colour_not_error() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 24);
        let mut term = Terminal::new(backend).unwrap();

        let mut app = App::new();
        app.active_leaf = Leaf::Profiles;
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles: mk_profiles(),
            ..Default::default()
        }));
        app.operator_catalog = Some(custom_list_catalog(Vec::new()));
        // "default" mounts no custom lists (`Profile::default()`).
        app.profiles.selected_id = Some("default".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 120, 24), &mut app))
            .unwrap();
        assert!(detail_panel::focus(&app, Leaf::Profiles));
        assert!(detail_panel::handle_detail_key(
            &mut app,
            crossterm::event::KeyCode::End
        ));
        term.draw(|f| render(f, Rect::new(0, 0, 120, 24), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        let (row_y, row) = rows
            .iter()
            .enumerate()
            .find(|(_, row)| row.contains(PROFILE_CUSTOM_LISTS_NONE))
            .expect("zero-mount sentinel remains reachable after End");
        let value_x = row[..row.find(PROFILE_CUSTOM_LISTS_NONE).unwrap()]
            .chars()
            .count() as u16;
        let fg = buf[(value_x, row_y as u16)].fg;
        assert_eq!(
            fg, T.text_secondary,
            "empty mounts must render in the secondary colour, not as a warning"
        );
        assert_ne!(fg, T.error);
    }

    #[test]
    fn render_custom_lists_row_stays_legible_in_a_narrow_detail_pane() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        // Just above `NARROW_THRESHOLD` so the side-card still renders, but
        // the 62% split is narrow enough to expose status fragmentation.
        let width = NARROW_THRESHOLD + 5;
        let backend = TestBackend::new(width, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "kids".to_string(),
            Profile {
                display_name: "Kids".into(),
                custom_lists: vec![id("videogames"), id("ghost-list")],
                ..Default::default()
            },
        );
        let loaded = loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        });

        let mut app = App::new();
        app.loaded_config = Some(loaded);
        app.operator_catalog = Some(custom_list_catalog(vec![("videogames", 3, 1)]));
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, width, 30), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        let content = rows.join("\n");

        let row_y = rows
            .iter()
            .position(|r| r.contains(PROFILE_LABEL_CUSTOM_LISTS))
            .expect(
                "Custom lists row renders — a width below NARROW_THRESHOLD \
                 would drop the whole detail pane instead",
            );
        let label_row = &rows[row_y];

        // The second mount belongs on its own continuation row. Keeping a
        // mount atomic prevents Paragraph wrapping from splitting its status
        // into `(m` / `issing)` fragments.
        assert!(
            !label_row.contains("(missing)"),
            "the missing mount must use a continuation row:\n{content}"
        );

        assert!(
            rows.iter()
                .any(|row| row.contains("videogames (3 rules, 1 malformed)")),
            "the valid mount summary must remain readable on one row:\n{content}"
        );
        assert!(
            rows.iter().any(|row| row.contains("ghost-list (missing)")),
            "the dangling mount warning must remain readable on one row:\n{content}"
        );
    }

    /// The `TAGS` master column is gone — header AND cell.
    ///
    /// **The terminal is 200 wide, and that width is the test.** The
    /// master pane is 38% of the frame, and the five surviving columns
    /// need `12 + 14 + 6 + 10 + 8` plus four spacers = 54 cells; at the
    /// 120 this file's other render test uses, the pane is ~45 and the
    /// header truncates after `RULES`. A bare `!contains("TAGS")` would
    /// then have passed on a buffer that never rendered the region TAGS
    /// occupied — green for the wrong reason, which is the deletion-lane
    /// trap. Measured: written at 120 first, and it failed on the `ECS`
    /// anchor rather than passing vacuously.
    ///
    /// So `ECS` is asserted present: it is the right-most surviving
    /// column, sitting exactly where `TAGS` used to follow it, and its
    /// presence is what proves the buffer reached that far.
    #[test]
    fn master_table_has_no_tags_column() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(200, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut app = App::new();
        app.loaded_config = Some(loaded_with(mk_blocks_config()));
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 200, 30), &mut app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }

        assert!(
            content.contains("BLOCK-ALL"),
            "master header did not render"
        );
        assert!(
            content.contains("ECS"),
            "master header truncated before TAGS"
        );
        assert!(
            !content.contains("TAGS"),
            "the master table still carries a TAGS column:\n{content}"
        );
    }
}
