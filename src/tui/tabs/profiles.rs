//! Profiles tab — master/detail view of the v1 `[profiles]` map.
//!
//! §4.26 Phase 2: the 4th Network leaf (locked decision D3). The master
//! list (left) shows every configured profile with summary columns; the
//! side-card (right) drills into the focused profile — the 6 MUTATE
//! fields plus an offline "What it blocks" summary (tui-wave1): the
//! effective blocklists it resolves to through
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

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use std::collections::BTreeMap;

use crate::config::custom_list::CustomListStore;
use crate::config::loader::LoadedConfig;
use crate::config::schema::{Blocklist, Profile};
use crate::config::settings::EcsMode;
use crate::lists::status::BlocklistStatusDto;
use crate::profiles::profile::resolve_profile_blocklist_ids;
use crate::tui::app::App;
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Below this width the master/detail split collapses to master-only.
/// Mirrors the Subnets tab threshold — the side-card needs ≥40 cells for
/// the KV rows + the "What it blocks" summary to stay legible.
const NARROW_THRESHOLD: u16 = 100;

// ── Public render entry point ────────────────────────────────────────

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    let profiles = &loaded.config.profiles;
    let title = format!("Profiles ({})", profiles.len());
    let outer = render_section_chrome(f, area, &title, T.text_secondary);

    if profiles.is_empty() {
        render_empty(f, outer);
        return;
    }

    if outer.width < NARROW_THRESHOLD {
        // Single-column fallback: master list only. The operator still
        // sees every profile; the detail card returns when they widen.
        render_master(f, outer, app, profiles);
        return;
    }

    let cols = Layout::horizontal([
        Constraint::Percentage(38),
        Constraint::Length(1),
        Constraint::Percentage(62),
    ])
    .split(outer);

    render_master(f, cols[0], app, profiles);
    render_detail(f, cols[2], app, loaded, profiles);
    draw_v_divider(f, cols[1]);
}

// ── Master pane ──────────────────────────────────────────────────────

fn render_master(f: &mut Frame, area: Rect, app: &App, profiles: &BTreeMap<String, Profile>) {
    let header = Row::new(vec![
        Cell::from("ID"),
        Cell::from("DISPLAY NAME"),
        Cell::from("RULES"),
        Cell::from("BLOCK-ALL"),
        Cell::from("ECS"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = master_rows(profiles);

    // Resolve `selected_id` back to a row index every frame — modal CRUD
    // moves rows in/out, so an index from the previous frame is stale.
    let mut table_state = TableState::default();
    if let Some(idx) = resolve_selected_index(profiles, app.profiles.selected_id.as_deref()) {
        table_state.select(Some(idx));
    } else if !rows.is_empty() {
        table_state.select(Some(0));
    }
    // No manual offset copy — a stale offset desyncs the viewport from the
    // freshly-resolved index when a rename/CRUD jumps rows; let ratatui
    // derive the scroll offset from `select()`. (prof-03; mirrors sub-01)

    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Min(14),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .row_highlight_style(theme::highlight_style());

    f.render_stateful_widget(table, area, &mut table_state);
}

/// Build the master list rows — one per profile, in `BTreeMap` key
/// order (stable across frames).
fn master_rows(profiles: &BTreeMap<String, Profile>) -> Vec<Row<'static>> {
    profiles
        .iter()
        .map(|(id, p)| {
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
                Cell::from(id.clone()),
                Cell::from(p.display_name.clone()),
                Cell::from(p.admin_rules.len().to_string()),
                block_all,
                Cell::from(ecs_summary(p)),
            ])
        })
        .collect()
}

/// Resolve `selected_id` back to its index in the master row list.
/// `None` when the key no longer matches any profile (e.g. just
/// deleted) — the caller falls back to row 0.
pub fn resolve_selected_index(
    profiles: &BTreeMap<String, Profile>,
    selected: Option<&str>,
) -> Option<usize> {
    let key = selected?;
    profiles.keys().position(|id| id == key)
}

// ── Detail pane (side-card) ──────────────────────────────────────────

fn render_detail(
    f: &mut Frame,
    area: Rect,
    app: &App,
    loaded: &LoadedConfig,
    profiles: &BTreeMap<String, Profile>,
) {
    let selection = app
        .profiles
        .selected_id
        .as_deref()
        .and_then(|key| profiles.get_key_value(key));

    let Some((id, profile)) = selection else {
        let para = Paragraph::new(Span::styled(
            " select a profile on the left",
            Style::default().fg(T.text_muted),
        ));
        f.render_widget(para, area);
        return;
    };

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(24);

    // ── MUTATE fields (D4) ──
    lines.push(kv_str("Id", id, T.text_primary));
    lines.push(kv_str(
        "Display name",
        &profile.display_name,
        T.text_primary,
    ));
    lines.push(kv_str(
        "Block response",
        &block_response_label(profile),
        T.text_primary,
    ));
    lines.push(kv_str(
        "Blocked TTL",
        &blocked_ttl_label(profile),
        T.text_primary,
    ));
    lines.push(kv(
        "Block all",
        if profile.block_all {
            Span::styled(
                "yes",
                Style::default()
                    .fg(T.brand_red)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("no", Style::default().fg(T.text_muted))
        },
    ));
    lines.push(kv_str(
        "Admin rules",
        &admin_rules_label(profile),
        T.text_primary,
    ));
    lines.push(kv_str("ECS", &ecs_detail_label(profile), T.text_primary));

    lines.push(divider_line());

    // ── "What it blocks" summary (tui-wave1 profiles-summary) ──
    // Offline: resolve the profile's effective blocklists through the
    // daemon's own predicate and sum their polled domain counts. Replaces
    // the former read-only drill-out pointer block — the collections it
    // pointed at now surface as the demoted "Also" line.
    //
    // **This comment said "via tag intersection" until `plp-s4c`, and it
    // had been wrong since S3.** `resolve_profile_blocklist_ids`
    // (`profiles/profile.rs`) has read `effective_direction` — the list's
    // `base` as overridden by `profiles.<id>.lists` — since the plp
    // cutover; `profile.tags` decides nothing. The CODE was migrated and
    // the sentence describing it was not, which is the failure mode a
    // doc-comment has that a test does not: it cannot go red.
    //
    // `plp-s5d` took the first of the two surfaces s4c reported: the
    // `Tags` KV line is gone, along with `BlocksSummary::tags` that fed
    // it and the `TAGS` master column, which showed the operator a count
    // of something that had stopped deciding anything.
    //
    // `PROFILE_BLOCKS_NONE` was the second, and `plp-s5f` closed it with
    // its pin in `tests/frozen_strings_tui_t1.rs`, in one commit — which
    // is what this comment asked for ("it retires with them in
    // `plp-s5f`/`plp-s5g` or not at all", because editing the const alone
    // turns a lane owning neither test nor doc red on both).
    //
    // It used to send an operator with no effective lists to "add tags in
    // the Tags tab": a tab `plp-s5d` deleted, reached by a verb that
    // already refused. That is a rendered string — `blocklists_value`
    // returns it whenever a profile resolves to zero lists — so it was not
    // stale prose but a dead end shown to an operator mid-task. It now
    // names the per-list override rows in the profile editor, which are
    // where the direction is actually set (`profile_modal.rs`
    // `LIST_OVERRIDE_HINT`).
    //
    // **The catalog mirror is NOT closed** and is reported rather than
    // touched: `_catalog/**` belongs to no lane this agent owns.
    let summary = profile_blocks_summary(profile, &loaded.config.blocklists, &app.lists.entries);
    push_blocks_summary(&mut lines, &summary, profile, &loaded.custom_lists);

    lines.push(divider_line());

    // ── Reference count (also the delete pre-check input) ──
    lines.push(kv_str(
        "Referenced by",
        &reference_summary(loaded, id),
        T.text_secondary,
    ));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
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

fn admin_rules_label(profile: &Profile) -> String {
    if profile.admin_rules.is_empty() {
        return "(none)".to_string();
    }
    profile
        .admin_rules
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

// ── "What it blocks" summary (tui-wave1 profiles-summary) ────────────
//
// The Profiles detail pane summarises the effective blocklists a profile
// resolves to via tag intersection (offline — no daemon round-trip) plus a
// total domain count. The operator-facing literals below are frozen by
// `tests/frozen_strings_tui_t1.rs` (reached through the `pub use` in
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
/// Counts come from `LoadedConfig::custom_lists` — the store already
/// parsed at config load — never from re-reading pack files.
pub const PROFILE_LABEL_CUSTOM_LISTS: &str = "Custom lists";
/// Custom-lists-line value when the profile mounts zero custom lists —
/// not an error, since most profiles will have none.
pub const PROFILE_CUSTOM_LISTS_NONE: &str = "none mounted";

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
    /// No tag intersects any list — the profile blocks nothing via lists.
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

/// Humanise a domain count to a compact magnitude string: `950`, `152k`,
/// `2.5M`. The sums are overlap upper bounds, so precision past the leading
/// digits is noise.
fn humanize_domains(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{}k", n / 1_000)
    } else {
        n.to_string()
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
    custom_list_store: &CustomListStore,
) {
    lines.push(Line::from(Span::styled(
        format!(" {PROFILE_LABEL_WHAT_IT_BLOCKS}"),
        Style::default()
            .fg(T.text_secondary)
            .add_modifier(Modifier::BOLD),
    )));

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

    // Custom lists line — sibling of Blocklists, after its count-line
    // continuation.
    lines.push(custom_lists_line(profile, custom_list_store));

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

/// One `custom_lists` mount, resolved against the loaded [`CustomListStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum CustomListMount {
    /// Present in the store — counts read off the already-compiled pack.
    Present {
        id: String,
        allow: usize,
        deny: usize,
    },
    /// The profile names an id absent from the store. The validator
    /// refuses this on load; the TUI also renders configs that bypassed it.
    Missing { id: String },
}

/// Resolve a profile's `custom_lists` ids against the loaded store, in the
/// profile's own declaration order. Pure — unit-tested directly, same
/// shape as [`profile_blocks_summary`].
fn resolve_custom_list_mounts(profile: &Profile, store: &CustomListStore) -> Vec<CustomListMount> {
    profile
        .custom_lists
        .iter()
        .map(|id| match store.get(id) {
            Some(compiled) => CustomListMount::Present {
                id: id.as_str().to_string(),
                allow: compiled.allow.len(),
                deny: compiled.deny.len(),
            },
            None => CustomListMount::Missing {
                id: id.as_str().to_string(),
            },
        })
        .collect()
}

/// Build the `Custom lists` KV line. Each mount is coloured on its own —
/// present in `text_primary`, missing in `T.error` — so one dangling
/// reference among several valid mounts doesn't paint the whole line as
/// broken, and doesn't hide inside a single flat colour either.
fn custom_lists_line(profile: &Profile, store: &CustomListStore) -> Line<'static> {
    let mounts = resolve_custom_list_mounts(profile, store);
    if mounts.is_empty() {
        return kv_str(
            PROFILE_LABEL_CUSTOM_LISTS,
            PROFILE_CUSTOM_LISTS_NONE,
            T.text_secondary,
        );
    }

    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            format!("{:<14}", PROFILE_LABEL_CUSTOM_LISTS),
            Style::default().fg(T.text_muted),
        ),
    ];
    for (i, mount) in mounts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(", ", Style::default().fg(T.text_muted)));
        }
        spans.push(match mount {
            CustomListMount::Present { id, allow, deny } => Span::styled(
                format!("{id} ({allow} allow, {deny} deny)"),
                Style::default().fg(T.text_primary),
            ),
            CustomListMount::Missing { id } => {
                Span::styled(format!("{id} (missing)"), Style::default().fg(T.error))
            }
        });
    }
    Line::from(spans)
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

fn divider_line() -> Line<'static> {
    Line::from(Span::styled(
        "\u{2500}".repeat(40),
        Style::default().fg(T.text_muted),
    ))
}

/// Paint a 1-cell-wide vertical separator for every row of `area`.
/// Mirrors the Subnets tab's master/detail gutter.
fn draw_v_divider(f: &mut Frame, area: Rect) {
    let style = Style::default().fg(T.text_muted);
    let buf = f.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        if area.x < buf.area.right() && y < buf.area.bottom() {
            buf.set_string(area.x, y, "\u{2502}", style);
        }
    }
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Profiles", T.text_secondary);
    f.render_widget(
        Paragraph::new(Span::styled(
            "  could not load config — fix it and press r to retry",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
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
    use super::*;
    use crate::config::custom_list::CompiledCustomList;
    use crate::config::schema::{ConfigV1, Id, Profile};
    use crate::tui::app::{Leaf, Section};

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
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

    // ── Leaf wiring (§4.26 P2 renumber) ───────────────────────────────

    #[test]
    fn profiles_leaf_is_wired_to_the_filters_section() {
        // §4.67-a deleted this test's original body. It used to assert
        // `Leaf::Profiles.index() == 5`, `Leaf::ALL[5] == Leaf::Profiles` and
        // `Leaf::ALL.len() == 10`/`11` — three hand-transcribed constants
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
        let rows = master_rows(&profiles);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn resolve_selected_index_hits_and_misses() {
        let profiles = mk_profiles();
        // BTreeMap order: "default" (0), "kids" (1).
        assert_eq!(resolve_selected_index(&profiles, Some("default")), Some(0));
        assert_eq!(resolve_selected_index(&profiles, Some("kids")), Some(1));
        assert_eq!(resolve_selected_index(&profiles, Some("ghost")), None);
        assert_eq!(resolve_selected_index(&profiles, None), None);
    }

    // ── reference counting ────────────────────────────────────────────

    #[test]
    fn count_profile_refs_spans_all_four_entity_classes() {
        // `Device` carries no `Default` impl + a dozen fields, so build
        // the fixture via TOML — the same pattern the Local DNS tab
        // tests use. A device + a subnet both reference "kids".
        let toml_src = r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[profiles.default]

[profiles.kids]
display_name = "Kids"
block_all = true

[[devices]]
id = "phone"
display_name = "Phone"
ip = "192.0.2.50"
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
        let app = App::new();
        term.draw(|f| render(f, Rect::new(0, 0, 80, 20), &app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(content.contains("Profiles"));
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
        term.draw(|f| render(f, Rect::new(0, 0, 120, 24), &app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(content.contains("Profiles (2)"));
        assert!(content.contains("kids"));
        // Side-card "What it blocks" summary renders for the selected profile.
        assert!(content.contains("What it blocks"));
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
schema_version = 3

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

    #[test]
    fn humanize_domains_scales_by_magnitude() {
        assert_eq!(humanize_domains(950), "950");
        assert_eq!(humanize_domains(152_340), "152k");
        assert_eq!(humanize_domains(2_500_000), "2.5M");
    }

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
            "~152k domains"
        );
        assert_eq!(
            count_line(&BlocksCount::Counted {
                sum: 100_000,
                partial: true
            })
            .unwrap(),
            "~100k domains (partial)"
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

        term.draw(|f| render(f, Rect::new(0, 0, 120, 30), &app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                content.push_str(buf[(x, y)].symbol());
            }
        }

        assert!(content.contains("What it blocks"));
        assert!(content.contains("Ads Basic"));
        assert!(content.contains("Malware Core"));
        assert!(content.contains("152k domains"));
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

    fn mk_custom_list_store() -> CustomListStore {
        let mut store = CustomListStore::new();
        store.insert(
            id("videogames"),
            CompiledCustomList {
                allow: vec!["a.example".into(), "b.example".into()],
                deny: vec!["c.example".into()],
                skipped: 0,
            },
        );
        store
    }

    #[test]
    fn custom_list_mounts_resolve_present_and_missing() {
        let profile = Profile {
            custom_lists: vec![id("videogames"), id("ghost-list")],
            ..Default::default()
        };
        let store = mk_custom_list_store();

        let mounts = resolve_custom_list_mounts(&profile, &store);

        // Declaration order is preserved — same as `admin_rules_label`.
        assert_eq!(
            mounts,
            vec![
                CustomListMount::Present {
                    id: "videogames".to_string(),
                    allow: 2,
                    deny: 1,
                },
                CustomListMount::Missing {
                    id: "ghost-list".to_string(),
                },
            ]
        );
    }

    #[test]
    fn custom_list_mounts_empty_when_profile_mounts_none() {
        let profile = Profile::default();
        let store = mk_custom_list_store();
        assert!(resolve_custom_list_mounts(&profile, &store).is_empty());
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
        let mut loaded = loaded_with(cfg);
        loaded.custom_lists = mk_custom_list_store();

        let mut app = App::new();
        // Landed poll on both lists `kids` resolves to, so the indented
        // count line renders (same fixture as
        // `render_shows_resolved_lists_and_domain_count`).
        app.lists.entries = vec![dto("ads-basic", 100_000), dto("mal-core", 52_000)];
        app.loaded_config = Some(loaded);
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 120, 30), &app))
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
        let count_row = &rows[blocklists_y + 1];
        assert!(
            count_row.contains("152k domains"),
            "row right after Blocklists is not its count-line continuation:\n{}",
            rows.join("\n")
        );
        assert!(
            !count_row.contains(PROFILE_LABEL_CUSTOM_LISTS),
            "Custom lists landed on the count line's row instead of after it:\n{}",
            rows.join("\n")
        );
        let custom_lists_row = &rows[blocklists_y + 2];
        assert!(
            custom_lists_row.contains(PROFILE_LABEL_CUSTOM_LISTS),
            "Custom lists is not the row immediately after the count line:\n{}",
            rows.join("\n")
        );
        assert!(custom_lists_row.contains("videogames (2 allow, 1 deny)"));
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
        let mut loaded = loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        });
        loaded.custom_lists = mk_custom_list_store();

        let mut app = App::new();
        app.loaded_config = Some(loaded);
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 160, 30), &app))
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
        assert!(
            content.contains("videogames (2 allow, 1 deny)"),
            "present mount not rendered as id (N allow, M deny):\n{content}"
        );
        assert!(
            content.contains("ghost-list (missing)"),
            "dangling mount not rendered as id (missing):\n{content}"
        );

        // A whole-line colour would hide the dangling reference among the
        // valid ones — each mount must carry its own colour.
        let row_y = rows
            .iter()
            .position(|r| r.contains(PROFILE_LABEL_CUSTOM_LISTS))
            .expect("Custom lists row renders");
        let row = &rows[row_y];
        // `find` returns a BYTE offset; the frame's left border + gutter
        // divider are multi-byte glyphs, so the column is the CHAR count
        // up to that offset, not the byte offset itself.
        let present_x = row[..row.find("videogames").expect("present id renders")]
            .chars()
            .count() as u16;
        let missing_x = row[..row.find("ghost-list").expect("missing id renders")]
            .chars()
            .count() as u16;
        assert_eq!(buf[(present_x, row_y as u16)].fg, T.text_primary);
        assert_eq!(buf[(missing_x, row_y as u16)].fg, T.error);
    }

    #[test]
    fn render_shows_none_mounted_in_secondary_colour_not_error() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 24);
        let mut term = Terminal::new(backend).unwrap();

        let mut app = App::new();
        app.loaded_config = Some(loaded_with(ConfigV1 {
            profiles: mk_profiles(),
            ..Default::default()
        }));
        // "default" mounts no custom lists (`Profile::default()`).
        app.profiles.selected_id = Some("default".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, 120, 24), &app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let rows: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        let row_y = rows
            .iter()
            .position(|r| r.contains(PROFILE_LABEL_CUSTOM_LISTS))
            .expect("Custom lists row renders");
        let row = &rows[row_y];
        assert!(
            row.contains(PROFILE_CUSTOM_LISTS_NONE),
            "zero-mount row does not show the none-mounted sentinel:\n{row}"
        );
        // Byte offset -> char offset (same border/gutter skew as above).
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
        // the 62% split leaves it tight enough that the value must wrap
        // rather than fit on one physical row.
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
        let mut loaded = loaded_with(ConfigV1 {
            profiles,
            ..Default::default()
        });
        loaded.custom_lists = mk_custom_list_store();

        let mut app = App::new();
        app.loaded_config = Some(loaded);
        app.profiles.selected_id = Some("kids".to_string());

        term.draw(|f| render(f, Rect::new(0, 0, width, 30), &app))
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

        // Confirm this width actually forces a wrap — the whole point of
        // the test. If the full value fit on one physical row, a
        // truncation bug in a narrower pane would slip past every
        // assertion below it.
        assert!(
            !label_row.contains("(missing)"),
            "value fit on one row — this width does not exercise the wrap:\n{content}"
        );

        // `Wrap { trim: false }` on the side-card Paragraph must carry the
        // overflow onto the next row, not drop it. Checked per token rather
        // than as one contiguous phrase: a legitimate wrap point between
        // tokens (e.g. between "(2" and "allow,") would break a combined-
        // phrase match without the row actually losing anything.
        for token in [
            "videogames",
            "(2",
            "allow,",
            "deny)",
            "ghost-list",
            "(missing)",
        ] {
            assert!(
                content.contains(token),
                "token {token:?} missing from a narrow detail pane — silent truncation:\n{content}"
            );
        }
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

        term.draw(|f| render(f, Rect::new(0, 0, 200, 30), &app))
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
