//! Lists tab — per-blocklist runtime visibility (Sprint 43 T2).
//!
//! Data source: `app.lists.entries` populated by the IPC
//! `BlocklistStats { source_id: None }` poll (see `tui::mod::poll_active_leaf`,
//! 30 s default cadence per the design's fallback poll). Cross-joins the
//! runtime stats with the v1 schema (base / trust / format) read from
//! `app.loaded_config` so each row can show its policy direction at a
//! glance, dim trusted-local rows, and announce the auto-detected wire
//! format alongside the entry counts.
//!
//! Keybindings (handled in `tui/mod.rs`):
//!   j/k / ↑/↓   scroll the table
//!   /           focus the text search (id / display / URL substring)
//!   f           cycle the direction chip All → Block → Allow → All
//!   R           clear the search + reset the direction chip
//!   Enter       open the Sprint 53 edit modal on the focused list
//!   K           toggle the focused list's `base` between deny and allow
//!               (S50 T4)
//!
//! **Two corrections, both to claims that had gone false in place.**
//!
//! This list carried `p  open the profile-assignment modal (Sprint 43 T3)`.
//! That modal was unmounted by rev-2606 — this file says so itself, at the
//! `create-category / move-category / list-profile assignment modals were
//! unmounted` note further down — and the only `KeyCode::Char('p')` handler
//! in all of `src/tui/` is `tui/mod.rs:947`, a **global** pause toggle. So
//! the header taught a keybinding that does something else on this very
//! tab. `README.md` and `_catalog/PRODUCT.md` carried the same dead claim
//! key-by-key and were repaired by `plp-s5g2`.
//!
//! `f` and `K` said `kind`. The TOML key has been `base` since `plp-s3b`;
//! the Rust field is still `ListsKindFilter`, which is why the wording
//! survived the rename sweep. What they DO is unchanged — the chip cycles
//! three states and `K` flips the direction — so this is a wording repair,
//! verified against the handlers, not a behaviour note.
//!
//! `LISTS_TAB_EMPTY` is one of the SN3 frozen strings (§2 of
//! `_docs/features/lists_management.md`), pinned by `tests/frozen_strings_s43.rs`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::schema::validator::{inert_blocklists, InertListReason};
use crate::config::schema::{BlocklistBase, BlocklistFormat, BlocklistTrust};
use crate::lists::status::BlocklistStatusDto;
use crate::tui::app;
use crate::tui::app::{App, EditField, EditListModal, EditModalMode, IntervalChoice};
use crate::tui::format::count as format_count;
use crate::tui::modal_form;
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Frozen empty-state message — SN3 in `_docs/features/lists_management.md`.
/// Pinned byte-for-byte by S43 T6's `tests/frozen_strings_s43.rs` (R3).
pub const LISTS_TAB_EMPTY: &str =
    "No blocklists configured. Run `warden blocklist add <id> --url <url>` to add one.";

/// Joined view of a list's runtime stats and its v1 schema fields.
/// Built per render in [`build_grouped_rows`]; cheap-clone (small
/// strings, Copy enums) so the cursor handler can borrow a snapshot
/// independent of the live `app.loaded_config`.
#[derive(Debug, Clone)]
pub struct ListRowMeta {
    pub dto: BlocklistStatusDto,
    pub display_name: String,
    /// `None` when the source has no canonical id (raw URL, not in the
    /// v1 catalog) — kind/trust/format derived from defaults in that
    /// case. The kind toggle hotkey refuses to fire when the canonical
    /// id is missing (no T3 mutation surface).
    pub canonical_id: Option<String>,
    pub base: BlocklistBase,
    pub trust: BlocklistTrust,
    /// `None` when the schema entry is missing for this source. We
    /// render `—` in the FORMAT column so the operator sees the join
    /// gap explicitly rather than guessing at a wire format.
    pub format: Option<BlocklistFormat>,
    pub used_by_profiles: Vec<String>,
    /// §4.7 Phase 2 T2: `true` when `now - dto.last_refresh_at`
    /// exceeds `lists.staleness_threshold_secs` (default 24 h).
    /// Computed at row-build time so the renderer is pure. Suppresses
    /// the badge automatically when `last_refresh_at` is `None`.
    pub is_stale: bool,
    /// `_docs/features/tag_model_consolidation.md` §3.3: `Some(reason)`
    /// when this list is installed, enabled, and visible — but filters
    /// nothing. Mirrors, rather than re-derives, the WARN-only
    /// predicates already in `config::schema::validator`:
    /// Delegates to `config::schema::validator::inert_blocklists` — the
    /// same detector `warden status` renders (`cli/commands/status.rs`)
    /// — rather than re-deriving the predicate here, so the TUI badge,
    /// `warden status`, and the journal WARN can never disagree about
    /// which lists are inert.
    ///
    /// `None` when the schema entry is missing (orphan row — nothing to
    /// judge) or the list genuinely has effect.
    pub inert_reason: Option<String>,
}

/// Build the flat row vec for the current app state — one row per
/// managed blocklist, in `app.lists.entries` order, narrowed by the
/// operator's search text + kind chip.
pub fn build_grouped_rows(app: &App) -> Vec<ListRowMeta> {
    if app.lists.entries.is_empty() {
        return Vec::new();
    }

    // One fleet-wide pass through the canonical detector, then a cheap
    // per-row lookup in `build_meta` — see `ListRowMeta::inert_reason`.
    let inert_by_id: std::collections::HashMap<&str, InertListReason> = app
        .loaded_config
        .as_ref()
        .map(|lc| inert_blocklists(&lc.config).into_iter().collect())
        .unwrap_or_default();

    // Dedup on `canonical_id` — the daemon's runtime
    // `merge_sources_with_blocklists` bridge synthesises one registry
    // slot for the slug-form source AND another for the [[blocklists]]
    // URL even when both resolve back to the same canonical id, so
    // without this collapse the table shows every managed list twice.
    // Within a duplicate group we prefer the row that fetched cleanly
    // and carries the higher entry count — that's the "live" copy the
    // operator wants to interact with; the failing twin is daemon
    // bookkeeping noise, not a separate list.
    let raw_metas: Vec<ListRowMeta> = app
        .lists
        .entries
        .iter()
        .map(|dto| build_meta(app, dto, &inert_by_id))
        .collect();
    let collapsed = collapse_by_canonical_id(raw_metas);
    collapsed
        .into_iter()
        // Query-Log-style filter (search text + kind chip), client-side.
        .filter(|m| list_meta_matches(m, &app.lists))
        .collect()
}

fn build_meta(
    app: &App,
    dto: &BlocklistStatusDto,
    inert_by_id: &std::collections::HashMap<&str, InertListReason>,
) -> ListRowMeta {
    // The IPC handler's `id_lookup` only resolves slug-form sources via
    // `slug_to_id` — URL-form sources synthesised by the daemon's
    // runtime `merge_sources_with_blocklists` bridge come back with
    // `id = None` even when a `[[blocklists]]` entry already owns that
    // URL. Fallback here so URL-form rows map back to their canonical
    // entry (and the regular Edit modal works) instead of being mis-
    // classified as orphans that the Promote/Discard flow can't fix.
    let canonical_id = dto.id.clone().or_else(|| {
        let lc = app.loaded_config.as_ref()?;
        lc.config
            .blocklists
            .iter()
            .find(|b| b.url == dto.source)
            .map(|b| b.id.as_str().to_string())
    });
    let cfg_entry = app.loaded_config.as_ref().and_then(|lc| {
        let cid = canonical_id.as_deref()?;
        lc.config.blocklists.iter().find(|b| b.id.as_str() == cid)
    });

    let display_name = cfg_entry
        .map(|b| b.display_name.clone())
        .unwrap_or_else(|| "—".to_string());
    let base = cfg_entry.map(|b| b.base).unwrap_or_default();
    let trust = cfg_entry.map(|b| b.trust).unwrap_or_default();
    let format = cfg_entry.map(|b| b.format);
    let used_by_profiles = used_by_for(app, dto)
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    // §4.7 Phase 2 T2: precompute the stale flag against the loaded
    // config's threshold (or the 24 h default when the config has
    // not been loaded yet — TUI startup race).
    let threshold_secs = app
        .loaded_config
        .as_ref()
        .map(|lc| lc.config.lists.staleness_threshold_secs)
        .unwrap_or(86_400);
    let is_stale = is_stale_for_dto(dto, threshold_secs, OffsetDateTime::now_utc());
    let inert_reason = cfg_entry.and_then(|b| {
        inert_by_id
            .get(b.id.as_str())
            .map(|reason| reason.message(b.id.as_str()))
    });

    ListRowMeta {
        dto: dto.clone(),
        display_name,
        canonical_id,
        base,
        trust,
        format,
        used_by_profiles,
        is_stale,
        inert_reason,
    }
}

/// §4.7 Phase 2 T2: pure stale predicate exercised both at row-build
/// time (above) and from unit tests. Returns `true` when:
/// - `dto.last_refresh_at` is `Some(ts)` parseable as RFC 3339, AND
/// - `now - ts > threshold_secs`.
///
/// Returns `false` on:
/// - `last_refresh_at == None` (no successful refresh ever — operator
///   already sees `never` in the status column, badge would be
///   redundant)
/// - clock skew (`ts` in the future, negative age) — treat as fresh
///   to avoid surprising the operator with a stale badge that goes
///   away when the clock fixes itself
/// - parse failure (corrupted timestamp) — defensive fall-through.
pub fn is_stale_for_dto(
    dto: &BlocklistStatusDto,
    threshold_secs: u64,
    now: OffsetDateTime,
) -> bool {
    let Some(ts_str) = dto.last_refresh_at.as_deref() else {
        return false;
    };
    let Ok(ts) = OffsetDateTime::parse(ts_str, &Rfc3339) else {
        return false;
    };
    let age = now - ts;
    if age.is_negative() {
        return false;
    }
    age.whole_seconds() as u64 > threshold_secs
}

/// Collapse runtime metas with the same `canonical_id` into one row.
/// Rows whose `canonical_id` is `None` are kept verbatim — every true
/// orphan is unique by source string. Within a duplicate group the
/// "winner" is the row most likely to be useful to the operator:
///   1. `last_outcome == "ok"` beats anything else
///   2. higher `entries` beats lower (live copy outranks the empty twin)
///   3. ties fall back to insertion order (first-seen wins)
pub fn collapse_by_canonical_id(metas: Vec<ListRowMeta>) -> Vec<ListRowMeta> {
    let mut out: Vec<ListRowMeta> = Vec::with_capacity(metas.len());
    let mut id_to_idx: std::collections::HashMap<String, usize> = Default::default();

    for meta in metas {
        let Some(id) = meta.canonical_id.clone() else {
            out.push(meta);
            continue;
        };
        match id_to_idx.get(&id).copied() {
            None => {
                id_to_idx.insert(id, out.len());
                out.push(meta);
            }
            Some(existing_idx) => {
                if prefer_winner(&meta, &out[existing_idx]) {
                    out[existing_idx] = meta;
                }
            }
        }
    }
    out
}

/// True when `candidate` should replace `current` in the deduped row
/// vec. Encodes the ranking documented on [`collapse_by_canonical_id`].
fn prefer_winner(candidate: &ListRowMeta, current: &ListRowMeta) -> bool {
    let cand_ok = candidate.dto.last_outcome == "ok";
    let curr_ok = current.dto.last_outcome == "ok";
    if cand_ok != curr_ok {
        return cand_ok;
    }
    candidate.dto.entries > current.dto.entries
}

/// Move the cursor to the next row in the given direction (`+1` for
/// j/down, `-1` for k/up). N4: **clamps** at both ends — walking off the
/// last/first row is a no-op, never a teleport to the other end. Mirrors
/// the Devices D9 helper, with one deliberate difference: this always
/// returns `Some` for a non-empty `rows` (`None` only when the row vec
/// is empty itself), even at the boundary. Devices may return `None` at
/// a boundary because every call site there is `if let Some(idx) = ...`;
/// `mod::move_lists_cursor` calls `app.lists.table_state.select(next)`
/// **unconditionally**, so a boundary `None` here would deselect the row
/// instead of leaving the cursor in place. Every row is selectable
/// (see [`ListRowMeta::is_selectable`]), so there is no header-skipping
/// loop to run — a plain clamp is the whole function.
pub fn next_selectable_index(
    rows: &[ListRowMeta],
    current: Option<usize>,
    dir: i32,
) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    let len = rows.len() as i32;
    let start = current.map(|i| i as i32).unwrap_or(-dir.signum());
    Some((start + dir).clamp(0, len - 1) as usize)
}

/// rev-2607: the stable selection key of a row, matching the `key_of`
/// contract of [`crate::tui::app::resolve_row_index`].
///
/// Keyed on `canonical_id` when the source maps back to a
/// `[[blocklists]]` entry, else on the source string. That pair is total
/// and collision-free over the row set: [`collapse_by_canonical_id`]
/// leaves at most one row per canonical id, and every row it keeps
/// verbatim (`canonical_id == None`) is a true orphan, unique by source.
/// The two key spaces are prefixed so a canonical id can never alias an
/// orphan's source string.
pub fn row_key(row: &ListRowMeta) -> Option<String> {
    Some(row.selection_key())
}

impl ListRowMeta {
    /// This row's stable selection key — see [`row_key`].
    pub fn selection_key(&self) -> String {
        match &self.canonical_id {
            Some(id) => format!("id:{id}"),
            None => format!("src:{}", self.dto.source),
        }
    }

    /// Always `true` — every row in the flat Lists table is selectable
    /// now that the category-grouping header rows are gone. Kept as a
    /// method (rather than inlined at call sites) so `reconcile_lists_selection`
    /// in `tui::mod` — outside this file's ownership for this pass —
    /// keeps compiling unchanged.
    pub fn is_selectable(&self) -> bool {
        true
    }
}

/// Return the focused list row. Single source of truth for "what list
/// is selected?" — the `[m]`/`[k]` hotkeys + the existing `p`
/// modal-builder all route through this helper.
///
/// rev-2607: resolves the operator's stable `selected_id`, **not** the
/// positional cursor. `app.lists.entries` is rewritten by a background
/// poll on a timer, so an index captured on an earlier frame can address
/// a different list — or none — by the time a key is pressed. A key that
/// no longer resolves means the list is *gone*: return `None` (the caller
/// shows its "focus a list row first" hint) rather than silently
/// retargeting the action onto whatever row now occupies that slot.
pub fn focused_list(app: &App) -> Option<ListRowMeta> {
    let rows = build_grouped_rows(app);
    let idx =
        match crate::tui::app::resolve_row_index(&rows, app.lists.selected_id.as_ref(), row_key) {
            Some(i) => i,
            // Nothing seeded yet — honour the visual cursor so the very first
            // keypress after `handle_lists_key` places it still works.
            None if app.lists.selected_id.is_none() => app.lists.table_state.selected()?,
            None => return None,
        };
    rows.get(idx).cloned()
}

// ── Render ───────────────────────────────────────────────────────────

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    if app.lists.entries.is_empty() {
        render_empty(f, area, app);
        render_overlays(f, area, app);
        return;
    }

    let grouped = build_grouped_rows(app);
    let inert_count = grouped.iter().filter(|m| m.inert_reason.is_some()).count();

    // N13: shared filter-card frame on top, table below — no interior
    // title (the fields are the label), height 3.
    // Sprint 53 (decision L8): the pre-S53 drill-down split-pane was
    // removed — the edit modal supersedes it. Overlays/modals still
    // anchor on the full tab area, not the table sub-rect.
    //
    // §3.3 tag-model-consolidation: the inert-summary claims 0 rows
    // when there's nothing to say — a clean fleet keeps the original
    // 2-chunk layout so "no inert lists" reads as "no summary noise",
    // not as a blank reserved block. When there IS something to say,
    // it gets 3 wrapped rows: reusing the formatters verbatim (§3.3)
    // means two or more reasons routinely overflow a single line, and
    // truncating mid-sentence ("...the list applies to ") is worse
    // than a few blank rows on the common one-reason case.
    // `tui-blind-to-corpus-refusal`: a standing corpus refusal outranks
    // the inert summary and gets its own band ABOVE the filters card.
    // Position is the point — the inert summary says some lists filter
    // nothing, this says *none of them do*, and a reader who stops at
    // the first warning must hit the worse one.
    //
    // Composed rather than branched: with two optional bands a nested
    // `if` is four arms that repeat the same three renders, and the next
    // band makes it eight. The constraint vector carries the same
    // information without the combinatorics.
    let refusal = app
        .daemon_status
        .as_ref()
        .and_then(|s| s.lists_corpus_refusal.as_ref());
    let mut constraints = Vec::with_capacity(4);
    if refusal.is_some() {
        constraints.push(Constraint::Length(3)); // corpus-refusal band (wraps)
    }
    constraints.push(Constraint::Length(3)); // N13 shared filter card, no title
    if inert_count > 0 {
        constraints.push(Constraint::Length(3)); // inert-list summary (wraps)
    }
    constraints.push(Constraint::Min(5)); // table
    let chunks = Layout::vertical(constraints).split(area);

    let mut next = 0;
    if let Some(r) = refusal {
        render_corpus_refusal(f, chunks[next], r, app);
        next += 1;
    }
    render_filters(f, chunks[next], app);
    next += 1;
    if inert_count > 0 {
        render_inert_summary(f, chunks[next], &grouped);
        next += 1;
    }
    render_table(f, chunks[next], app, &grouped);
    render_overlays(f, area, app);
}

/// `tui-blind-to-corpus-refusal`: the band that says the last reload
/// installed **nothing**.
///
/// Wording tracks `warden status`'s `format_lists_lines` deliberately,
/// down to the word *fetched*: this is the one state where the tab's own
/// `N/N` health reading is simultaneously true and useless, because every
/// source really did fetch and none of them are serving. An operator who
/// reads the two surfaces should not have to reconcile two vocabularies
/// for one outcome.
///
/// `novel_by_source` is named as the *largest contributor* and flagged
/// order-dependent, exactly as the CLI flags it — it is a diagnostic
/// about merge order, never an input to the refusal itself.
fn render_corpus_refusal(
    f: &mut Frame,
    area: Rect,
    refusal: &crate::lists::status::CorpusRefusal,
    app: &App,
) {
    let installed = app
        .daemon_status
        .as_ref()
        .map(|s| s.domain_count)
        .unwrap_or(0);
    // Zero installed is not "a smaller corpus" — it is no corpus, and the
    // daemon is answering every query unfiltered. It gets said outright.
    let serving = if installed == 0 {
        "NOTHING IS INSTALLED — DNS IS ANSWERING UNFILTERED".to_string()
    } else {
        "serving the previous generation".to_string()
    };
    let mut text = format!(
        "\u{26a0} CORPUS REFUSED — NOT INSTALLED: {} unique domains exceeds \
         max_total_domains {}; {serving}",
        refusal.unique, refusal.ceiling
    );
    if let Some((source, novel)) = refusal.novel_by_source.first() {
        text.push_str(&format!(
            " · largest contributor: {source} (+{novel} domains no other list \
             supplies; order-dependent)"
        ));
    }
    let para = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(T.error).add_modifier(Modifier::BOLD),
    )))
    .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

/// §3.3 tag-model-consolidation: one line naming every inert list on
/// screen, reusing the exact WARN text `build_meta` already attached
/// via [`ListRowMeta::inert_reason`] (never re-derived here). Only
/// called when `rows` contains at least one inert entry — see [`render`].
fn render_inert_summary(f: &mut Frame, area: Rect, rows: &[ListRowMeta]) {
    let reasons: Vec<&str> = rows
        .iter()
        .filter_map(|m| m.inert_reason.as_deref())
        .collect();
    debug_assert!(
        !reasons.is_empty(),
        "render_inert_summary called with zero inert rows"
    );
    let lede = if reasons.len() == 1 {
        "1 list is filtering nothing:".to_string()
    } else {
        format!("{} lists are filtering nothing:", reasons.len())
    };
    let text = format!("⚠ {lede} {}", reasons.join(" · "));
    let para = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(T.warning),
    )))
    .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_overlays(f: &mut Frame, area: Rect, app: &App) {
    // S53 follow-up — catalog picker renders BELOW the edit modal so a
    // (theoretical) collision lands the form-mutation surface highest.
    // Event-gates in `tui::mod.rs` make collisions unreachable in
    // practice; ordering documents the intent.
    if let Some(modal) = app.lists.catalog_picker.as_ref() {
        render_catalog_picker(f, area, modal);
    }
    // The `K`-hotkey consent gate. Same notice, same strings, same
    // geometry as the editor's stage — an operator who reaches this
    // decision by hotkey and one who reaches it by Ctrl+S must be
    // looking at the same screen.
    if let Some(confirm) = app.lists.kind_confirm.as_ref() {
        render_unsigned_allow_confirm(
            f,
            area,
            &confirm.list_id,
            &confirm.typed,
            confirm.error.clone(),
        );
    }
    // Sprint 53 — edit modal renders LAST so it sits above the others
    // when (impossibly) two modal slots fire on the same render. The
    // event-gate in `tui::mod.rs` makes that case unreachable, but the
    // ordering here documents the intent.
    if let Some(modal) = app.lists.edit_modal.as_ref() {
        match &modal.mode {
            EditModalMode::Edit | EditModalMode::Promote { .. } | EditModalMode::Add => {
                // Promote and Add share the form layout —
                // `render_edit_modal` branches on `modal.mode` for the
                // title, editable List ID row, button label, and hints.
                render_edit_modal(f, area, modal);
            }
            EditModalMode::ConfirmDelete { typed } => {
                // S53.7 cascade-aware delete UX: surface the profiles
                // that will lose the reference IN the prompt so the
                // operator sees the cost of confirming before they
                // type the id. Empty Vec → "no refs" path renders.
                let cascade_targets = compute_cascade_targets(app, &modal.blocklist_id);
                render_delete_confirm(f, area, modal, typed.as_str(), &cascade_targets)
            }
            EditModalMode::ConfirmUnsignedAllow { typed } => render_unsigned_allow_confirm(
                f,
                area,
                &modal.blocklist_id,
                typed.as_str(),
                modal.error_message.clone(),
            ),
        }
    }
}

/// N13 shared filter card: a text search (`/`) combined with the
/// all/block/allow kind chip (`f` — `k` is taken by scroll-up). Mirrors
/// `tabs::query_log::render_filters` / `tabs::rules::render_filters` —
/// all three (plus Tags) go through `theme::render_filter_card`.
fn render_filters(f: &mut Frame, area: Rect, app: &App) {
    let content_area = theme::render_filter_card(f, area);

    let (search_val, search_style) = match &app.input_mode {
        app::InputMode::FilterLists(s) => (format!("{s}_"), Style::default().fg(T.info)),
        _ => (
            app.lists.filter_text.clone().unwrap_or_default(),
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

    let kind = app.lists.kind_filter;
    // Width budget: build the fixed spans (label + chips + clear hint)
    // first, then give the search value whatever horizontal space is left
    // — tail-kept so the trailing `_` edit cursor stays visible and the
    // chips never scroll off on a long query. Mirrors tabs::query_log.
    let lead = Span::styled("Search [/]: ", Style::default().fg(T.text_muted));
    let trailing = vec![
        Span::styled("   Kind [f]: ", Style::default().fg(T.text_muted)),
        chip("all", kind == app::ListsKindFilter::All),
        Span::raw(" "),
        chip("block", kind == app::ListsKindFilter::Block),
        Span::raw(" "),
        chip("allow", kind == app::ListsKindFilter::Allow),
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

/// Client-side Lists filter: kind chip AND case-insensitive text search
/// over id / display name / source URL. Applied in [`build_grouped_rows`].
fn list_meta_matches(meta: &ListRowMeta, state: &app::ListsState) -> bool {
    let kind_ok = match state.kind_filter {
        app::ListsKindFilter::All => true,
        app::ListsKindFilter::Block => matches!(meta.base, BlocklistBase::Deny),
        app::ListsKindFilter::Allow => matches!(meta.base, BlocklistBase::Allow),
    };
    if !kind_ok {
        return false;
    }
    match state.filter_text.as_deref() {
        None => true,
        Some(q) => {
            let q = q.to_lowercase();
            let id = meta.canonical_id.as_deref().unwrap_or(&meta.dto.source);
            id.to_lowercase().contains(&q)
                || meta.display_name.to_lowercase().contains(&q)
                || meta.dto.source.to_lowercase().contains(&q)
        }
    }
}

/// Total managed lists after canonical-id collapse, ignoring the
/// operator filter — the denominator in the "M/N after filter" title.
pub(crate) fn total_list_count(app: &App) -> usize {
    if app.lists.entries.is_empty() {
        return 0;
    }
    // Count only cares about the post-collapse length, not inert
    // status — skip the detector pass.
    let raw: Vec<ListRowMeta> = app
        .lists
        .entries
        .iter()
        .map(|d| build_meta(app, d, &std::collections::HashMap::new()))
        .collect();
    collapse_by_canonical_id(raw).len()
}

fn render_empty(f: &mut Frame, area: Rect, app: &App) {
    let content = render_section_chrome(f, area, "Lists", T.text_secondary);

    let waiting = app.daemon_status.is_none();
    let line = if waiting {
        Span::styled("  waiting for daemon...", Style::default().fg(T.text_muted))
    } else {
        Span::styled(
            format!("  {LISTS_TAB_EMPTY}"),
            Style::default().fg(T.text_secondary),
        )
    };
    f.render_widget(Paragraph::new(line).wrap(Wrap { trim: false }), content);
}

fn render_table(f: &mut Frame, area: Rect, app: &App, grouped: &[ListRowMeta]) {
    let shown = grouped.len();
    let total = total_list_count(app);
    let no_filter =
        app.lists.filter_text.is_none() && app.lists.kind_filter == app::ListsKindFilter::All;
    let title = if no_filter {
        format!("Lists ({total})")
    } else {
        format!("Lists ({shown}/{total} after filter)")
    };
    let content = render_section_chrome(f, area, &title, T.text_secondary);

    let header = Row::new(vec![
        Cell::from(""), // inert badge gutter — deliberately unlabeled, see render_inert_summary
        Cell::from("ID"),
        Cell::from("KIND"),
        Cell::from("DISPLAY"),
        Cell::from("FORMAT"),
        Cell::from("ENTRIES"),
        Cell::from("STATUS"),
        Cell::from("LAST UPDATE"),
        Cell::from("USED BY"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = grouped.iter().cloned().map(render_list_row).collect();

    const COLUMN_SPACING: u16 = 3;
    let constraints = [
        // §3.3 tag-model-consolidation: fixed-width gutter, independent
        // of DISPLAY's content — a long display_name must never be able
        // to truncate the inert badge away (Table cells don't wrap).
        Constraint::Length(2),  // inert badge
        Constraint::Length(20), // id
        Constraint::Length(8),  // kind badge
        Constraint::Min(16),    // display name
        Constraint::Length(10), // format
        Constraint::Length(9),  // entries
        Constraint::Length(10), // status
        Constraint::Length(20), // last update (fits "MM-DD HH:MM · Stale" = 19; lists-01)
        Constraint::Min(16),    // used_by_profiles
    ];
    let table = Table::new(rows, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    f.render_stateful_widget(table, content, &mut app.lists.table_state.clone());

    // Query-Log-style vertical separators between columns.
    crate::tui::ui::draw_table_column_separators(f, content, &constraints, COLUMN_SPACING);
}

fn render_list_row(meta: ListRowMeta) -> Row<'static> {
    // Trust=Local rows dim the whole row (operator scans for trusted
    // local entries by colour, no extra column needed). RemoteUnsigned
    // is nominal; Signed is reserved (validator refuses it) — if a
    // Signed row ever lands we paint it warning-yellow as a defensive
    // beacon so the operator notices the validator gap.
    let row_fg = match meta.trust {
        BlocklistTrust::Local => T.text_muted,
        BlocklistTrust::RemoteUnsigned => T.text_primary,
        BlocklistTrust::Signed => T.warning,
    };
    let row_style = Style::default().fg(row_fg);

    let id_label = meta
        .canonical_id
        .clone()
        .unwrap_or_else(|| meta.dto.source.clone());

    let (kind_label, kind_color) = match meta.base {
        BlocklistBase::Deny => ("\u{25A3} BLOCK", T.error),
        BlocklistBase::Allow => ("\u{25A1} ALLOW", T.success),
        // `base = "ignore"` is legitimate but inert (P6). Muted, not
        // coloured: the row must not read as either direction, because it
        // is neither. The reload WARN that names the list is the loud
        // half; this is the quiet half that stops the badge from lying.
        BlocklistBase::Ignore => ("\u{25A6} IGNORE", T.text_muted),
    };
    // Trust=Local dims the whole row including the kind badge so the
    // operator's eye still reads "this is a trusted local list" before
    // resolving the BLOCK/ALLOW direction. When trust is nominal the
    // kind colour wins.
    let kind_style = if matches!(meta.trust, BlocklistTrust::Local) {
        row_style
    } else {
        Style::default().fg(kind_color)
    };

    let format_label = meta
        .format
        .map(|f| format_label_for(f).to_string())
        .unwrap_or_else(|| "—".to_string());

    // ENTRIES column shows the operator-intuitive metric: how many
    // parsed lines this list contributed (`parsed_ok`), NOT the
    // post-dedup novelty count (`entries`). The schema-level `entries`
    // field is intentionally "unique domains added to the merged map"
    // (`ListStatus::entries` doc), which is a useful diagnostic but
    // confusing as a primary display: a 4K-domain list whose contents
    // all overlap with a previously-loaded list would render "8" and
    // the operator concludes the list is broken. `parsed_ok` matches
    // the count operators see in the source file's "Total Entries"
    // header on lists.purge.cc and what they expect to see in the
    // TUI. Falls back to `entries` only when the parser has no
    // pre-dedup count yet (NeverFetched state).
    let entries_display = if meta.dto.parsed_ok > 0 {
        meta.dto.parsed_ok
    } else {
        meta.dto.entries
    };
    let entries = format_count(entries_display);
    let (status_label, status_color) = status_of(&meta.dto);
    let status_style = if matches!(meta.trust, BlocklistTrust::Local) {
        row_style
    } else {
        Style::default().fg(status_color)
    };
    let last_update = meta
        .dto
        .fetched_at
        .as_deref()
        .map(format_short_timestamp)
        .unwrap_or_else(|| "<never>".to_string());

    // §4.7 Phase 2 T2: append a non-alarm `· Stale` chip in
    // `T.text_muted` when the list has not had a successful refresh
    // within the configured `lists.staleness_threshold_secs` window.
    // Composed as a multi-span Line so the timestamp keeps its base
    // row colour and only the badge picks up the muted tone — an
    // alarm-coloured badge would over-signal a condition that often
    // means "daemon was off overnight", not "list is broken".
    let last_update_cell: Cell<'static> = if meta.is_stale {
        Cell::from(Line::from(vec![
            Span::styled(last_update, row_style),
            Span::styled(" · Stale", Style::default().fg(T.text_muted)),
        ]))
    } else {
        Cell::from(Span::styled(last_update, row_style))
    };

    let users_label = if meta.used_by_profiles.is_empty() {
        "<none>".to_string()
    } else {
        meta.used_by_profiles.join(", ")
    };
    let users_style = if meta.used_by_profiles.is_empty() {
        Style::default().fg(T.text_muted)
    } else {
        row_style
    };

    // §3.3 tag-model-consolidation: fixed gutter cell, independent of
    // every other column's width so a long id/display never truncates
    // it away. Blank (not just unstyled) when the list has effect.
    let inert_cell = if meta.inert_reason.is_some() {
        Cell::from(Span::styled("⚠", Style::default().fg(T.warning)))
    } else {
        Cell::from("")
    };

    Row::new(vec![
        inert_cell,
        Cell::from(Span::styled(id_label, row_style)),
        Cell::from(Span::styled(kind_label, kind_style)),
        Cell::from(Span::styled(meta.display_name, row_style)),
        Cell::from(Span::styled(format_label, row_style)),
        Cell::from(Span::styled(entries, row_style)),
        Cell::from(Span::styled(status_label, status_style)),
        last_update_cell,
        Cell::from(Span::styled(users_label, users_style)),
    ])
}

/// Short label for the format column. Title-cases AdGuard for visual
/// distinction (the parser is the AdGuard Home rule format, the TUI
/// label matches the brand the operator typed `format = "adguard"`
/// against in the TOML).
fn format_label_for(f: BlocklistFormat) -> &'static str {
    match f {
        BlocklistFormat::Domains => "domains",
        BlocklistFormat::Adguard => "AdGuard",
        BlocklistFormat::Hosts => "hosts",
    }
}

fn status_of(s: &BlocklistStatusDto) -> (String, ratatui::style::Color) {
    let raw = s.last_outcome.as_str();
    if raw == "ok" {
        ("ok".to_string(), T.success)
    } else if raw == "never_fetched" {
        ("never".to_string(), T.text_muted)
    } else if raw.starts_with("failed: ") {
        ("failed".to_string(), T.error)
    } else {
        (raw.to_string(), T.warning)
    }
}

/// Profiles this blocklist actually reaches — the set that loses its
/// domains if the list is deleted or turned off.
///
/// Sorted by profile id (the key operators reference from the CLI),
/// borrowed against `loaded_config`. Empty when the list is not found or
/// no config is loaded.
///
/// ## This asked the wrong question until `plp-s4c`, and the wrong answer
/// ## was `[]`
///
/// It used to be `profiles_matching_blocklist_tags`: profiles whose
/// `tags` intersect the list's `tags`. That was the `lists_categories_v2`
/// model, and `profile_list_policy` §2 retired it — which lists a profile
/// enforces is now the list's `base` as overridden by
/// `profiles.<id>.lists`, and `profile.tags` decides nothing.
///
/// **The failure was not merely stale: it was fail-open on a destructive
/// confirm.** The old body bailed to `Vec::new()` whenever the LIST had no
/// tags, and matched only profiles that carried tags of their own. The
/// design doc's §1.1 measurement of both live hosts is zero tagged
/// profiles, so the delete confirm rendered its benign copy — no
/// "unblocks its domains for N profiles" block at all — for a list every
/// profile was enforcing. The operator typed the id having been shown
/// nothing.
///
/// The predicate is now
/// [`resolve_profile_blocklist_ids`](crate::profiles::profile::resolve_profile_blocklist_ids),
/// the daemon's
/// own, rather than a second formulation of it. One question, one answer:
/// the profiles named here are exactly the profiles whose "What it
/// blocks" side-card line shrinks, because that line is built from the
/// same function. Two copies that disagree is the D11 class
/// `tag_model_consolidation` records, and this surface is where a
/// disagreement costs the most.
///
/// **Note what it deliberately is NOT.** `run_remove_silent`'s cascade
/// rewrites the profiles that carry an *override* for the list
/// (`p.lists.keys()`); this is the wider set that *depends* on it,
/// override or inherited `base`. The two numbers can legitimately differ
/// — the confirm states the cost ("unblocks its domains for N profiles"),
/// the post-delete status states the bookkeeping ("cascaded refs from N
/// profiles"). Their copy keeps them apart on purpose.
fn profiles_using_blocklist<'a>(app: &'a App, blocklist_id: &str) -> Vec<&'a str> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    let Some(bl) = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == blocklist_id)
    else {
        return Vec::new();
    };
    let mut ids: Vec<&str> = loaded
        .config
        .profiles
        .iter()
        .filter(|(_, p)| {
            crate::profiles::profile::resolve_profile_blocklist_ids(p, &loaded.config.blocklists)
                .contains(&bl.id)
        })
        .map(|(id, _)| id.as_str())
        .collect();
    ids.sort_unstable();
    ids
}

fn used_by_for<'a>(app: &'a App, s: &BlocklistStatusDto) -> Vec<&'a str> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    // Resolve the canonical id: slug-form DTOs carry it directly;
    // URL-form rows (daemon-synthesised) resolve via the [[blocklists]]
    // url match, mirroring `build_meta`'s fallback so a URL-form row
    // still reports the profiles that enforce it.
    let canonical = s.id.clone().or_else(|| {
        loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.url == s.source)
            .map(|b| b.id.as_str().to_string())
    });
    match canonical {
        Some(id) => profiles_using_blocklist(app, &id),
        None => Vec::new(),
    }
}

fn format_short_timestamp(rfc3339: &str) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    match OffsetDateTime::parse(rfc3339, &Rfc3339) {
        Ok(ts) => format!(
            "{:02}-{:02} {:02}:{:02}",
            u8::from(ts.month()),
            ts.day(),
            ts.hour(),
            ts.minute()
        ),
        Err(_) => rfc3339.to_string(),
    }
}

// ── Sprint 53 — list edit modal (60×22 centered, 11 fields + delete) ─

/// Build the Sprint 53 edit modal from the focused row + the cached
/// schema entry.
///
/// `Ok(None)` when the cursor is on a header, no row is selected, the
/// row has no canonical id (raw URL — no `[[blocklists]]` entry to
/// edit), or the `loaded_config` is missing (can't surface schema fields
/// without it). The caller falls through to the Promote builder on that.
///
/// `Err` is a **different** outcome and must not be folded into the
/// first: it means the entity file backing an entry we can see in the
/// loaded config could not be read. Falling through to Promote there
/// would offer to create a list that already exists. The honest response
/// is to open nothing and say so.
pub fn build_edit_modal_for(
    app: &App,
    config_path: &std::path::Path,
) -> Result<Option<EditListModal>, String> {
    let Some(meta) = focused_list(app) else {
        return Ok(None);
    };
    let Some(canonical_id) = meta.canonical_id.clone() else {
        return Ok(None);
    };
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Ok(None);
    };
    let Some(blist) = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == canonical_id.as_str())
        .cloned()
    else {
        return Ok(None);
    };
    // **This call survives `plp-s5d` for its OTHER two answers, and the
    // value it returns is now deliberately discarded.**
    //
    // It used to seed the tag picker from the file rather than from
    // `blist.tags`, because the loader has already promoted an untagged
    // deny-list to `["uncategorized"]` by then. There is no picker any
    // more, so the tags are dropped on the floor — but `Ok(None)` and
    // `Err` are not about tags at all: they say "the loaded config knows
    // this id and the file does not", and "the file could not be read".
    //
    // Deleting the whole call with the picker would have taken that check
    // with it, silently: `submit_edit_modal` upserts by id, so an edit
    // opened against a list the file no longer carries would APPEND it
    // back — resurrecting an entry the operator (or another writer) had
    // removed. Cheap to keep, and nothing would have gone red.
    //
    // `plp-s5a` did what the note here asked for: `file_tags_of` retired
    // with the `tags` field, and this call was re-pointed at
    // `blocklist_entry_exists` rather than deleted with it.
    match crate::cli::commands::blocklists::blocklist_entry_exists(
        config_path,
        canonical_id.as_str(),
        None,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(format!(
                "list '{canonical_id}' is in the running config but not in any config file — reload, then edit"
            ))
        }
        Err(e) => return Err(format!("cannot read the config file for '{canonical_id}': {e}")),
    }
    Ok(build_edit_modal_from_blocklist(canonical_id, blist))
}

/// Promote-orphan modal builder. Only fires when the focused row is a
/// List but has no matching `[[blocklists]]` entry (raw URL in
/// `[lists].sources`, or a slug whose canonical id was never declared).
/// Pre-fills `url` from the source string when it parses as one,
/// suggests a kebab-case id derived from the slug, and leaves
/// `display_name` blank for the operator to fill. Save creates a v1
/// entry + drops the orphan from `[lists].sources`.
pub fn build_promote_modal_for(app: &App) -> Option<EditListModal> {
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, Id};
    use crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES;

    let meta = focused_list(app)?;
    // Refuse when this row already has a managed `[[blocklists]]` entry —
    // those go through `build_edit_modal_for` (Edit mode).
    if let Some(canonical_id) = meta.canonical_id.as_deref() {
        if let Some(loaded) = app.loaded_config.as_ref() {
            if loaded
                .config
                .blocklists
                .iter()
                .any(|b| b.id.as_str() == canonical_id)
            {
                return None;
            }
        }
    }

    let source = meta.dto.source.clone();
    let (url_seed, id_seed) = if source.starts_with("http://") || source.starts_with("https://") {
        (source.clone(), suggest_id_from_url(&source))
    } else {
        // Legacy slug-form (e.g. "privacy/ads"). The slug itself is not
        // a URL the daemon can fetch — make the operator fill it in.
        (String::new(), source.replace('/', "-"))
    };
    // Validate the seed; if it doesn't parse, fall back to empty so the
    // operator types one without the form refusing to render.
    let id_seed = Id::new(&id_seed)
        .map(|_| id_seed)
        .unwrap_or_else(|_| String::new());

    // Synthetic original — Promote mode never reads `original` for
    // round-trip behavior, but `submit_edit_modal` consults
    // `original.max_entries` and `original.trust` to fill schema
    // defaults. Use the daemon-wide defaults so the new entry shapes
    // exactly like one freshly added via `warden blocklist add`.
    let original = Blocklist {
        id: Id::new("placeholder").expect("static placeholder is valid"),
        display_name: String::new(),
        url: String::new(),
        format: BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: DEFAULT_MAX_LIST_ENTRIES as u64,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        // A synthetic placeholder has never declared anything, least of all
        // consent to an unsigned allow-list. `false` is the only honest
        // seed: the operator must tick it on a real entry before the
        // validator lets a remote allow-list load.
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    };

    Some(EditListModal {
        blocklist_id: id_seed,
        mode: EditModalMode::Promote { source },
        display_name: String::new(),
        url: url_seed,
        nature: BlocklistBase::Deny,
        enabled: true,
        interval: IntervalChoice::H12,
        interval_custom_buf: String::new(),
        format: BlocklistFormat::Domains,
        auth_token_ref: String::new(),
        skip_head_check: false,
        original,
        focus: EditField::ListId,
        advanced_expanded: false,
        error_message: None,
        status_message: None,
        submitting: false,
        // Asked and answered in THIS session — nothing has been asked
        // yet.
        consent_declared: false,
    })
}

/// Build the purge.cc catalog picker modal. Snapshots the offline
/// fallback catalog (17ish curated lists, no network call so the modal
/// opens instantly even when the daemon's live catalog fetch hasn't
/// landed) and cross-references each entry's URL against the loaded v1
/// `[[blocklists]]` to compute the `already_active` flag once. The
/// table_state seeds on the first non-active row so Enter on the first
/// keystroke lands on something subscribable.
///
/// Async hotkey path — populate the picker from the cached catalog
/// (refresh on demand if stale or absent). The cache TTL is intentionally
/// short (5 min) so an operator who's added a list outside the TUI session
/// sees their catalog reflect the change shortly. Network failures fall
/// back to the merged hardcoded entries — the picker never opens empty.
pub async fn build_catalog_picker_modal_async(app: &mut App) -> app::CatalogPickerModal {
    use crate::lists::catalog::Catalog;
    use std::time::{Duration, Instant};

    const CACHE_TTL: Duration = Duration::from_secs(300);

    let cache_fresh = app
        .catalog_cache
        .as_ref()
        .map(|c| c.fetched_at.elapsed() < CACHE_TTL)
        .unwrap_or(false);

    if !cache_fresh {
        // Build a one-off reqwest client. Cheap relative to the catalog
        // fetch itself; sharing one across calls would require stashing
        // it on App which adds lifetime noise for an action that fires
        // at most every 5 minutes.
        let client = match reqwest::Client::builder()
            .user_agent(concat!("purge-warden/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "could not build reqwest client; using hardcoded catalog");
                let catalog = Catalog::fallback();
                return build_catalog_picker_modal_from(app, &catalog);
            }
        };
        let catalog = Catalog::fetch_unified(&client).await;
        app.catalog_cache = Some(app::CatalogCache {
            fetched_at: Instant::now(),
            catalog,
        });
    }

    // SAFETY: catalog_cache is Some after the refresh path above, or
    // we returned early via the fallback arm.
    let catalog = &app.catalog_cache.as_ref().unwrap().catalog;
    build_catalog_picker_modal_from(app, catalog)
}

/// mod-04: placeholder picker shown while a catalog fetch runs on a
/// background task. Empty table + a "Loading…" status so the operator
/// gets immediate, responsive feedback (Esc closes); the real rows land
/// when `UiJob::CatalogFetched` is applied.
pub fn loading_catalog_picker_modal() -> app::CatalogPickerModal {
    app::CatalogPickerModal {
        rows: Vec::new(),
        table_state: ratatui::widgets::TableState::default(),
        focus: app::CatalogPickerFocus::Table,
        error_message: None,
        status_message: Some("Loading catalog from purge.cc\u{2026}".to_string()),
        submitting: false,
    }
}

/// Shared row-building logic — called by both the sync and async
/// constructors with whichever `Catalog` snapshot they have on hand.
/// Each row's [`app::CatalogRowState`] baseline is computed here, so the
/// cache can hold a raw `Catalog` (no per-app-state cross-product baked
/// in) and the picker still re-renders correctly when `loaded_config`
/// changes between cache hits.
///
/// **One flat table, no section grouping.** The predecessor sorted rule
/// packs after domain lists and emitted a header per non-empty group.
/// `rules.purge.cc` is retired and `lists.purge.cc/index.json` is the
/// only channel [`crate::lists::catalog::Catalog::fetch_unified`] reads,
/// so the second group can no longer be populated and the first one's
/// header would be chrome naming the whole table. Nothing filters on
/// `format` here on purpose: the index is the single source of truth, and
/// a defensive `format == Domains` filter would hide a `hosts` list
/// purge.cc may legitimately publish.
pub fn build_catalog_picker_modal_from(
    app: &App,
    catalog: &crate::lists::catalog::Catalog,
) -> app::CatalogPickerModal {
    use crate::config::schema::{Blocklist, BlocklistBase};
    use crate::lists::source_key::canonical_url_key;
    use std::collections::HashMap;

    // Index `[[blocklists]]` by CANONICAL url, not byte-exactly:
    // `…/ads.txt` and `…/ads.txt/` are one source (they share a cache
    // file and its ETag), and it is the key the add path dedups on. A
    // byte comparison would show a subscribed list as free and then
    // collide at write time.
    let subscribed: HashMap<String, &Blocklist> = app
        .loaded_config
        .as_ref()
        .map(|lc| {
            lc.config
                .blocklists
                .iter()
                .map(|b| (canonical_url_key(&b.url), b))
                .collect()
        })
        .unwrap_or_default();

    let mut rows: Vec<app::CatalogPickerRow> = catalog
        .entries()
        .iter()
        .map(|e| {
            let existing = subscribed.get(&canonical_url_key(&e.url)).copied();
            let original = match existing {
                Some(b) => app::CatalogRowState::Subscribed { enabled: b.enabled },
                None => app::CatalogRowState::NotSubscribed,
            };
            let catalog_id = e.id();
            app::CatalogPickerRow {
                // An already-subscribed row keeps the EXISTING entry's
                // id so Save upserts it in place; only a fresh
                // subscription derives one from the catalog id.
                canonical_id: existing
                    .map(|b| b.id.as_str().to_string())
                    .unwrap_or_else(|| catalog_id.replace('/', "-")),
                url: e.url.clone(),
                display_name: format!(
                    "{}: {}",
                    capitalize_first(&e.scope),
                    capitalize_first(&e.name)
                ),
                scope: e.scope.clone(),
                topic: e.topic.clone().unwrap_or_default(),
                entry_count: e.entries,
                updated_at: e.updated_at.clone(),
                staged_enabled: original.is_on(),
                staged_kind: existing.map(|b| b.base).unwrap_or(BlocklistBase::Deny),
                original,
                format: e.format,
                catalog_id,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then_with(|| a.catalog_id.cmp(&b.catalog_id))
    });

    let mut table_state = ratatui::widgets::TableState::default();
    table_state.select((!rows.is_empty()).then_some(0));

    app::CatalogPickerModal {
        rows,
        table_state,
        focus: app::CatalogPickerFocus::Table,
        error_message: None,
        status_message: None,
        submitting: false,
    }
}

/// Title-case the first character — catalog scopes/names arrive in
/// lowercase from the catalog JSON; the picker DISPLAY column reads
/// better with proper sentence case.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Move the picker cursor by `dir` (+1 / -1), wrapping at both ends.
///
/// Every row is selectable now. The predecessor skipped already-active
/// rows because `Enter` on one was refused; they are toggleable in the
/// table, so skipping them would put a third of the catalog out of reach.
pub fn cycle_catalog_picker(modal: &mut app::CatalogPickerModal, dir: i32) {
    if modal.rows.is_empty() {
        modal.table_state.select(None);
        return;
    }
    let len = modal.rows.len() as i32;
    let start = modal
        .table_state
        .selected()
        .map(|i| i as i32)
        .unwrap_or(-dir.signum());
    modal
        .table_state
        .select(Some((start + dir).rem_euclid(len) as usize));
}

/// Carry the operator's staged edits across a picker rebuild.
///
/// The catalog fetch runs on a background task, so `UiJob::CatalogFetched`
/// lands an entirely new row vector on a modal the operator has been
/// toggling for however long the fetch took. Rebuilding without this is
/// silent data loss: the ticks simply revert, with no error and no
/// keystroke to blame.
///
/// Matched by `catalog_id`, which survives a re-fetch; a row that
/// disappeared upstream drops its staged edit along with itself. The
/// `original` baseline always comes from the FRESH build — it is the
/// config's state, not the operator's intent.
pub fn merge_catalog_picker_state(
    fresh: &mut app::CatalogPickerModal,
    previous: &app::CatalogPickerModal,
) {
    use std::collections::HashMap;
    let staged: HashMap<&str, (bool, crate::config::schema::BlocklistBase)> = previous
        .rows
        .iter()
        .filter(|r| r.is_dirty())
        .map(|r| (r.catalog_id.as_str(), (r.staged_enabled, r.staged_kind)))
        .collect();
    for row in fresh.rows.iter_mut() {
        if let Some(&(enabled, kind)) = staged.get(row.catalog_id.as_str()) {
            row.staged_enabled = enabled;
            row.staged_kind = kind;
        }
    }
    fresh.focus = previous.focus;
    fresh.error_message = previous.error_message.clone();
    if let Some(idx) = previous.table_state.selected() {
        fresh.table_state.select(Some(idx));
    }
    clamp_catalog_cursor(fresh);
}

/// Pull the cursor back inside `rows` after a rebuild.
///
/// The catalog is re-fetched on a background task and re-crossed against
/// `loaded_config`, so the row vector is replaced under a cursor the
/// operator has already moved. An index past the end renders no focus bar
/// at all and `Space` then toggles nothing — the silent-cursor-drift class
/// the 2026-07-12 TUI audit found on Lists and Rules.
pub fn clamp_catalog_cursor(modal: &mut app::CatalogPickerModal) {
    if modal.rows.is_empty() {
        modal.table_state.select(None);
        return;
    }
    let last = modal.rows.len() - 1;
    let clamped = modal.table_state.selected().unwrap_or(0).min(last);
    modal.table_state.select(Some(clamped));
}

/// Width every Lists modal asks for. `render_modal` clamps it to the
/// anchor, so at the declared 80-column floor the modal is full-bleed and
/// the interior is 62 columns — 61 once a scrollbar claims the last one.
const MODAL_W: u16 = 64;

// ── purge.cc catalog picker — the table ───────────────────────────────
//
// The picker is the one Lists surface that is a *grid*: six facts per row
// over seventeen rows, which as an Archetype-C option list cost two rows
// per already-subscribed entry and buried ENTRIES / UPDATED — two fields
// `index.json` publishes and the operator picks on. It keeps Archetype C's
// chrome (title band, description band, note/keys/action tail) and
// replaces the option list with fixed-width columns ruled by `│`.
//
// Column rules are drawn INLINE, as a span between cells. `ui::
// draw_table_column_separators` — the Query Log look — paints into the
// frame buffer after a ratatui `Table` renders, keyed to that widget's
// own column layout; this body is `Vec<Line>` through
// `modal_form::render_scroll_body`, which scrolls. A buffer-painted rule
// would sit still while the rows moved under it.

/// Width the catalog picker asks for. Wider than [`MODAL_W`] because six
/// columns do not fit in 62 cells; `overlay::centered_rect` clamps it to
/// the anchor, so an 80-column terminal degrades instead of overflowing,
/// and [`catalog_cols`] drops columns from there.
///
/// Sized to the CONTENT, not to the anchor: 68 leaves a 66-cell interior,
/// which is exactly `catalog_overhead(true, true)` (46) plus TOPIC at its
/// [`CAT_TOPIC_MAX`] of 20 — and 65 with a scrollbar, which TOPIC absorbs
/// at 19. Asking for the full 78 the floor anchor allows would render the
/// same table with a dozen dead cells to the right of ON.
const CATALOG_MODAL_W: u16 = 68;

/// Cells before the first column: the focus rule (or its blank stand-in)
/// plus one space, matching the ecosystem's 2-cell row lead.
const CAT_LEAD: usize = 2;
/// Inter-column gap. The rule glyph is the middle cell, so the rule row
/// can put `┼` at the same offset.
const CAT_SEP: &str = " \u{2502} ";
const CAT_SEP_W: usize = 3;
const CAT_W_SCOPE: usize = 8;
const CAT_W_ENTRIES: usize = 8;
const CAT_W_UPDATED: usize = 5;
const CAT_W_KIND: usize = 5;
const CAT_W_ON: usize = 3;
const CAT_TOPIC_MIN: usize = 6;
/// TOPIC absorbs the slack, but only up to here — past it the table drifts
/// away from the ON column the operator is aiming at.
const CAT_TOPIC_MAX: usize = 20;

/// Which columns fit at `width`, and how wide TOPIC gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CatalogCols {
    topic: usize,
    entries: bool,
    updated: bool,
}

/// Cells everything-but-TOPIC costs at a given column set.
fn catalog_overhead(entries: bool, updated: bool) -> usize {
    let ncols = 4 + usize::from(entries) + usize::from(updated);
    CAT_LEAD
        + CAT_W_SCOPE
        + CAT_W_KIND
        + CAT_W_ON
        + if entries { CAT_W_ENTRIES } else { 0 }
        + if updated { CAT_W_UPDATED } else { 0 }
        + CAT_SEP_W * (ncols - 1)
}

/// Fit the columns into `width`, dropping UPDATED first and ENTRIES
/// second. Both are context; SCOPE / TOPIC / KIND / ON are what the row
/// *is* and what the operator changes, so they never drop.
fn catalog_cols(width: usize) -> CatalogCols {
    for (entries, updated) in [(true, true), (true, false), (false, false)] {
        let overhead = catalog_overhead(entries, updated);
        if width >= overhead + CAT_TOPIC_MIN {
            return CatalogCols {
                topic: (width - overhead).min(CAT_TOPIC_MAX),
                entries,
                updated,
            };
        }
    }
    CatalogCols {
        topic: CAT_TOPIC_MIN,
        entries: false,
        updated: false,
    }
}

/// ENTRIES cell. `0` is what [`crate::lists::catalog::Catalog::fallback`]
/// reports for every list — it carries no counts — so it renders as
/// "unknown", never as a number an offline operator would read as a fact
/// about the list.
fn catalog_entries_cell(n: u64) -> String {
    if n == 0 {
        "\u{2014}".to_string()
    } else {
        format_count(n)
    }
}

/// UPDATED cell: `MM-DD`, or `—` when the catalog carries no timestamp
/// (the offline fallback) or an unparseable one.
fn catalog_updated_cell(rfc3339: &str) -> String {
    match OffsetDateTime::parse(rfc3339, &Rfc3339) {
        Ok(ts) => format!("{:02}-{:02}", u8::from(ts.month()), ts.day()),
        Err(_) => "\u{2014}".to_string(),
    }
}

/// ON cell — three states, three glyphs. `[ ]` and `[·]` both mean "not
/// filtering", but only the second has a `[[blocklists]]` entry behind it,
/// and ticking them writes different TOML.
fn catalog_on_cell(row: &app::CatalogPickerRow) -> (&'static str, ratatui::style::Color) {
    if row.staged_enabled {
        ("[\u{2713}]", T.success)
    } else if row.original.is_subscribed() {
        ("[\u{b7}]", T.warning)
    } else {
        ("[ ]", T.text_muted)
    }
}

/// Left-pad-to-width, truncating with `…` when the text overruns.
fn cat_cell(text: &str, width: usize) -> String {
    format!("{:<width$}", super::rules::truncate(text, width))
}

/// Right-aligned variant for the numeric column.
fn cat_cell_right(text: &str, width: usize) -> String {
    format!("{:>width$}", super::rules::truncate(text, width))
}

/// The two pinned rows that name the columns: labels, then the `─┼─` rule.
///
/// **They live in `ScrollBody.head`, not in the fields.** At the 80×24
/// floor the field region is about five rows against seventeen lists, so a
/// header in the scrolling region leaves the operator with unlabelled
/// columns of numbers the moment they press `j` twice.
fn catalog_header_rows(cols: CatalogCols) -> [Line<'static>; 2] {
    let mut labels = String::from("  ");
    let mut rule = String::from("  ");
    let mut push = |label: &str, width: usize, right: bool, first: bool| {
        if !first {
            labels.push_str(CAT_SEP);
            rule.push_str("\u{2500}\u{253c}\u{2500}");
        }
        labels.push_str(&if right {
            cat_cell_right(label, width)
        } else {
            cat_cell(label, width)
        });
        rule.push_str(&"\u{2500}".repeat(width));
    };
    push("SCOPE", CAT_W_SCOPE, false, true);
    push("TOPIC", cols.topic, false, false);
    if cols.entries {
        push("ENTRIES", CAT_W_ENTRIES, true, false);
    }
    if cols.updated {
        push("UPD.", CAT_W_UPDATED, false, false);
    }
    push("KIND", CAT_W_KIND, false, false);
    push("ON", CAT_W_ON, false, false);

    [
        Line::from(Span::styled(labels, Style::default().fg(T.warden_teal))),
        Line::from(Span::styled(rule, Style::default().fg(T.border_subtle))),
    ]
}

/// One data row.
///
/// On the focus bar every semantic hue collapses to `text_primary`:
/// `bg_highlight` is the lightest surface the theme paints and sinks each
/// of them below the 3:1 large-text floor (the frozen colour rule in
/// `modal_form`'s module docs). The meaning returns when focus leaves.
fn catalog_row_line(
    row: &app::CatalogPickerRow,
    cols: CatalogCols,
    focused: bool,
) -> Line<'static> {
    let bg = focused.then_some(T.bg_highlight);
    let paint = move |fg: ratatui::style::Color| {
        let base = Style::default().fg(if focused { T.text_primary } else { fg });
        match bg {
            Some(b) => base.bg(b),
            None => base,
        }
    };
    let sep_style = paint(T.border_subtle);

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(16);
    if focused {
        spans.push(Span::styled(
            "\u{258c}".to_string(),
            Style::default().fg(T.emerald_ping).bg(T.bg_highlight),
        ));
        spans.push(Span::styled(" ".to_string(), paint(T.text_primary)));
    } else {
        spans.push(Span::styled("  ".to_string(), Style::default()));
    }

    let sep = |spans: &mut Vec<Span<'static>>| {
        spans.push(Span::styled(CAT_SEP.to_string(), sep_style));
    };

    spans.push(Span::styled(
        cat_cell(&row.scope, CAT_W_SCOPE),
        paint(T.text_secondary),
    ));
    sep(&mut spans);
    spans.push(Span::styled(
        cat_cell(&row.topic, cols.topic),
        paint(T.text_primary),
    ));
    if cols.entries {
        sep(&mut spans);
        spans.push(Span::styled(
            cat_cell_right(&catalog_entries_cell(row.entry_count), CAT_W_ENTRIES),
            paint(T.text_secondary),
        ));
    }
    if cols.updated {
        sep(&mut spans);
        spans.push(Span::styled(
            cat_cell(&catalog_updated_cell(&row.updated_at), CAT_W_UPDATED),
            paint(T.text_muted),
        ));
    }
    sep(&mut spans);
    let (kind_label, kind_fg) = match row.staged_kind {
        BlocklistBase::Allow => ("Allow", T.success),
        BlocklistBase::Deny => ("Block", T.red_glow),
        // Not reachable from the catalog picker today (it stages Deny or
        // Allow only), but spelled out rather than caught by a `_` arm:
        // a catch-all here is exactly how a third direction would render
        // as one of the other two the day the picker gains it (S4c).
        BlocklistBase::Ignore => ("Ignore", T.text_muted),
    };
    spans.push(Span::styled(
        cat_cell(kind_label, CAT_W_KIND),
        paint(kind_fg),
    ));
    sep(&mut spans);
    let (on_label, on_fg) = catalog_on_cell(row);
    // Bold, not a hue: a staged row has to stand out on the focus bar too,
    // where every hue is flattened to `text_primary`.
    let mut on_style = paint(on_fg);
    if row.is_dirty() {
        on_style = on_style.add_modifier(Modifier::BOLD);
    }
    spans.push(Span::styled(cat_cell(on_label, CAT_W_ON), on_style));

    Line::from(spans)
}

/// One-line inventory for the description band: catalog size, how much of
/// it the operator already has, and what Save would write.
///
/// Says "subscribed", not "already active", so a needle aimed at a row
/// cannot match this line instead — a non-discriminating needle would pass
/// with the rows gone.
fn catalog_desc(modal: &app::CatalogPickerModal) -> String {
    if modal.rows.is_empty() {
        return "nothing loaded from the catalog yet".to_string();
    }
    let subscribed = modal
        .rows
        .iter()
        .filter(|r| r.original.is_subscribed())
        .count();
    let mut parts = vec![
        format!("{} lists", modal.rows.len()),
        format!("{subscribed} subscribed"),
    ];
    let dirty = modal.dirty_count();
    if dirty > 0 {
        parts.push(format!("{dirty} pending"));
    }
    parts.join(" \u{b7} ")
}

/// Build the picker body: Archetype-C chrome around a fixed-width table.
fn catalog_body(modal: &app::CatalogPickerModal, width: u16) -> modal_form::ScrollBody {
    use app::CatalogPickerFocus;

    let cols = catalog_cols(width as usize);
    let table_focused = modal.focus == CatalogPickerFocus::Table;
    let selected = modal.table_state.selected();

    let mut head = vec![
        modal_form::title_band("Browse purge.cc catalog", width),
        modal_form::desc_band(&catalog_desc(modal), width),
    ];
    let mut fields: Vec<Line<'static>> = Vec::with_capacity(modal.rows.len());
    let mut focus_row = None;
    if modal.rows.is_empty() {
        fields.push(modal_form::prose_row(
            &modal_form::ProseRow::plain("no catalog entries to show"),
            width,
        ));
    } else {
        head.extend(catalog_header_rows(cols));
        for (idx, row) in modal.rows.iter().enumerate() {
            let focused = table_focused && selected == Some(idx);
            if focused {
                focus_row = Some(idx);
            }
            fields.push(catalog_row_line(row, cols, focused));
        }
    }

    let dirty = modal.dirty_count();
    let hint = modal
        .status_message
        .clone()
        .or_else(|| modal.submitting.then(|| "saving\u{2026}".to_string()))
        .unwrap_or_else(|| match dirty {
            0 => "no pending changes".to_string(),
            1 => "1 pending change \u{b7} Ctrl+s save \u{b7} Esc discard".to_string(),
            n => format!("{n} pending changes \u{b7} Ctrl+s save \u{b7} Esc discard"),
        });
    let mut tail = modal_form::hint_or_error_rows(
        modal.error_message.as_deref(),
        &hint,
        width,
        modal_form::HINT_ROWS,
    );
    tail.push(modal_form::nav_keys_line(
        "\u{2191}\u{2193}/jk move \u{b7} Space toggle \u{b7} Tab actions \u{b7} Ctrl+s save",
    ));
    tail.push(modal_form::action_row(
        &[
            modal_form::Action::new(
                "  Cancel  ",
                modal.focus == CatalogPickerFocus::Cancel,
                modal_form::ActionKind::Neutral,
                "close without writing",
            ),
            modal_form::Action::new(
                "  Save  ",
                modal.focus == CatalogPickerFocus::Save,
                modal_form::ActionKind::Primary,
                "write every pending change",
            ),
        ],
        width,
    ));

    modal_form::ScrollBody {
        head,
        fields,
        tail,
        focus_row,
        scrollable: !modal.rows.is_empty(),
    }
}

/// Render the catalog picker, anchored on the tab content rect.
///
/// Chrome, sizing, the clamp and the focus-following viewport are all
/// [`modal_form::render_modal`]'s. Nothing here places a cursor: the
/// picker's "you are here" is the focus bar on the selected row, and the
/// selection lives in `modal.table_state`, which `mod.rs` still owns.
pub fn render_catalog_picker(f: &mut Frame, area: Rect, modal: &app::CatalogPickerModal) {
    modal_form::render_modal(f, area, CATALOG_MODAL_W, |w| (catalog_body(modal, w), ()));
}

/// Build the "Add new list" modal — same form layout as Promote but
/// with no source string to clean up at save. All buffers start blank,
/// the synthetic `original` snapshot only carries the schema defaults
/// the save pipeline reads (`max_entries`, `trust`). Cursor lands on
/// List ID because it's the first thing the operator must type.
///
/// Sprint C T5 of `lists_categories_v2`: the chip picker pre-loads the
/// `uncategorized` sentinel for `base = Deny` (D12 + D2: deny without an
/// explicit tag would otherwise hit the validator's auto-promote pass
/// at reload time anyway, so showing the operator the chip up-front
/// keeps the contract visible). `base = Allow` stays empty per D2 —
/// auto-applying a chip would silently make every device's allow rule
/// fire, a security risk.
pub fn build_add_modal() -> EditListModal {
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, Id};
    use crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES;

    let original = Blocklist {
        id: Id::new("placeholder").expect("static placeholder is valid"),
        display_name: String::new(),
        url: String::new(),
        format: BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: DEFAULT_MAX_LIST_ENTRIES as u64,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        // A synthetic placeholder has never declared anything, least of all
        // consent to an unsigned allow-list. `false` is the only honest
        // seed: the operator must tick it on a real entry before the
        // validator lets a remote allow-list load.
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    };

    EditListModal {
        blocklist_id: String::new(),
        mode: EditModalMode::Add,
        display_name: String::new(),
        url: String::new(),
        nature: BlocklistBase::Deny,
        enabled: true,
        interval: IntervalChoice::H12,
        interval_custom_buf: String::new(),
        format: BlocklistFormat::Domains,
        auth_token_ref: String::new(),
        // No default chip. It used to seed `[uncategorized]` as a D12
        // convenience for the deny case, where it changed nothing —
        // an untagged deny-list is auto-promoted to exactly that at
        // load. On the allow case it changed everything: an operator
        // who set Nature to Allow and never opened the tag picker got
        // that sentinel written to the file as if they had chosen it,
        // and a profile carrying `uncategorized` hands the exemption to
        // every device under it. The convenience was worth nothing on
        // one branch and a silent grant on the other.
        skip_head_check: false,
        original,
        focus: EditField::ListId,
        advanced_expanded: false,
        error_message: None,
        status_message: None,
        submitting: false,
        // Asked and answered in THIS session — nothing has been asked
        // yet.
        consent_declared: false,
    }
}

/// Best-effort kebab-case id from a URL: take the last path segment,
/// strip the file extension, lowercase, replace non-alphanumerics with
/// hyphens. The result is then validated by `Id::new` at save time —
/// this helper just gives the operator a starting point.
fn suggest_id_from_url(url: &str) -> String {
    let tail = url.rsplit('/').find(|s| !s.is_empty()).unwrap_or(url);
    let stem = tail.rsplit_once('.').map(|(s, _)| s).unwrap_or(tail);
    let mut out = String::with_capacity(stem.len());
    let mut last_was_dash = false;
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !out.is_empty() {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn build_edit_modal_from_blocklist(
    canonical_id: String,
    blist: crate::config::schema::Blocklist,
) -> Option<EditListModal> {
    let interval = IntervalChoice::from_hours(blist.update_interval_hours);
    let interval_custom_buf = if matches!(interval, IntervalChoice::Custom) {
        blist.update_interval_hours.to_string()
    } else {
        String::new()
    };
    Some(EditListModal {
        blocklist_id: canonical_id,
        mode: EditModalMode::Edit,
        display_name: blist.display_name.clone(),
        url: blist.url.clone(),
        nature: blist.base,
        enabled: blist.enabled,
        skip_head_check: false,
        interval,
        interval_custom_buf,
        format: blist.format,
        auth_token_ref: blist.auth_token_ref.clone().unwrap_or_default(),
        original: blist,
        focus: EditField::DisplayName,
        advanced_expanded: false,
        error_message: None,
        status_message: None,
        submitting: false,
        // Asked and answered in THIS session — nothing has been asked
        // yet.
        consent_declared: false,
    })
}

// ── Variant-A modal-ecosystem redesign ──────────────────────────────
// The Lists edit modal is the operator-validated reference for Archetype
// F: banded title + one-line description, named sections, a per-field
// focus hint and a Delete / Cancel / Save action row, while keeping
// Lists' own interaction model (↹/↑↓ move · ←/→ change values · Ctrl+S
// save) and its real terminal cursor (D7′).
//
// §4.63 S3b moved value-cycling off ↑↓ and onto ←/→, freeing ↑↓ to alias
// Tab. This comment described the grammar from before that change; the
// keying itself lives in `mod.rs::handle_edit_mode_key`.
//
// Every row, colour and layout decision now lives in `modal_form`'s
// ecosystem layer — §4.61 Wave 1 lifted them out of here so the other
// eleven modal surfaces inherit one implementation instead of eleven
// drifting copies. What stays in this file is the Lists-specific
// *mapping*: which field is which, what each one is called, what its
// hint says, and how a `BlocklistTrust` becomes a state row.
//
// Do not reintroduce a local `Style::default().fg(...)` here. If a row
// cannot be expressed through a `modal_form` helper, the helper is
// incomplete — extend it there (§4.61 R1).

/// Modal title + the two description rows, keyed by mode.
///
/// Went from one row to two on 2026-08-07, on their own `bg_main` strip
/// under the title band ([`modal_form::desc_band2`] — not the title's
/// `bg_highlight`, which puts teal at 3.37:1 against a 4.5:1 prose bar
/// with no gate covering the pair). The first row of each pair is
/// the shipped copy verbatim; the second states the two things this modal
/// can be silently wrong about, and which no single field's hint owns
/// because they are joins to things outside it:
///
/// - **nature is the direction** — the same published file is BLOCK for one
///   operator and ALLOW for another, and nothing in the file says which;
/// - **direction is inherited, and per-profile overridable** — a list's
///   `base` applies to every profile that does not name it in its own
///   `lists` table. `plp-s5d` rewrote this line: it used to say "tags are
///   the join to profiles — an untagged allow-list installs, looks
///   healthy, and reaches no device at all", which stopped being true at
///   the `plp-s3` cutover and was still on screen.
///
/// Budgeted to [`MODAL_W`] − 5: −2 chrome, −1 for the scrollbar column on
/// the narrow build pass, −2 for the band's indent. `render_body_fixed`
/// does not wrap, so an over-long row is cut at the rect edge. Pinned by
/// `no_desc_row_outruns_the_narrow_build_pass`.
fn edit_band_text(modal: &EditListModal) -> (String, [&'static str; 2]) {
    match &modal.mode {
        EditModalMode::Add => (
            "Add list".to_string(),
            [
                "Subscribe to a remote list of domains to block or allow.",
                "Nature sets direction; each profile may override it.",
            ],
        ),
        EditModalMode::Promote { .. } => (
            "Promote source".to_string(),
            [
                "Adopt this orphan source as a managed blocklist.",
                "It keeps its domains; you choose its nature.",
            ],
        ),
        _ => (
            format!("Edit list \u{b7} {}", modal.blocklist_id),
            [
                "Change where this list comes from and how Warden treats it.",
                "Nature sets direction; each profile may override it.",
            ],
        ),
    }
}

/// Contextual one-line help for the focused field — the "small guide"
/// for operators who touch a blocklist only occasionally. Mirrors the
/// Devices form's `focus_hint`.
///
/// Takes `nature` because two of these fields mean different things on
/// either side of the Block/Allow switch, and a hint that is right half
/// the time teaches the operator to stop reading hints.
fn edit_focus_hint(focus: EditField, mode: &EditModalMode, nature: BlocklistBase) -> &'static str {
    match focus {
        EditField::ListId => "Internal short name; lower-case, no spaces.",
        EditField::DisplayName => "The name shown in dashboards, stats and logs.",
        EditField::Url => "Full https:// address of the list file to download.",
        EditField::Advanced => "Enter shows or hides format, refresh and token.",
        EditField::Nature => match nature {
            // The hint has to change with the state, because from `Ignore`
            // the row is not a choice between the two words it names — it
            // is a one-way door out.
            BlocklistBase::Ignore => {
                "Inert: no profile applies this list. \u{2190}/\u{2192} moves it to Block."
            }
            _ => "Block refuses these domains; Allow permits them anyway.",
        },
        EditField::Enabled => "Inactive lists stay on disk but filter nothing.",
        EditField::Interval => "How often Warden re-downloads this list.",
        EditField::Format => "File layout; auto-detected from the URL.",
        EditField::AuthTokenRef => "Stored-token name for a private list. Rarely needed.",
        // The three action rows name Enter themselves. The nav legend has
        // room for the four keys that work everywhere in the form and not
        // for a fifth that only means something on a button — and the
        // footer's canonical form grammar (`ui.rs::modal_form_hints`)
        // leaves Enter out for the same reason. Without this, Enter would
        // be a key that works and appears nowhere on screen.
        EditField::DeleteButton => match mode {
            EditModalMode::Promote { .. } => "Enter discards this orphan source from the config.",
            _ => "Enter removes this list from disk (asks you to confirm).",
        },
        EditField::Cancel => "Enter discards changes and closes.",
        EditField::Save => "Enter writes the changes and closes.",
    }
}

/// The Lists-specific half of the trust row: map a [`BlocklistTrust`] to
/// the state name, its meaning, and the plain-language note that has to
/// travel with it. The rendering is [`modal_form::state_row`]'s.
///
/// W2.1 re-validation is deferred, so this is read-only: static info the
/// operator can see here but not change here.
fn edit_trust_row(trust: BlocklistTrust, width: u16) -> Line<'static> {
    let (state, kind, note) = match trust {
        BlocklistTrust::Local => ("local", modal_form::ValueKind::Healthy, ""),
        BlocklistTrust::Signed => ("signed", modal_form::ValueKind::Healthy, ""),
        BlocklistTrust::RemoteUnsigned => (
            "remote-unsigned",
            modal_form::ValueKind::Caution,
            " \u{2014} contents unverified",
        ),
    };
    modal_form::state_row("trust", state, kind, note, width)
}

/// Build the modal body as a [`modal_form::ScrollBody`] — pinned head,
/// scrolling field region, pinned tail — plus the real-cursor target
/// (index **within the field region** + value char length) for the focused
/// text field, if any.
///
/// The field region is `lines` below; every index the caller receives is
/// relative to it, not to the rendered frame, because how many of those
/// rows are on screen is the renderer's decision.
fn edit_form_body(
    modal: &EditListModal,
    width: u16,
) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    use modal_form::ValueKind;

    let (title, desc) = edit_band_text(modal);
    let hint = |field: EditField| edit_focus_hint(field, &modal.mode, modal.nature);
    let is_new = matches!(
        modal.mode,
        EditModalMode::Promote { .. } | EditModalMode::Add
    );
    // The head is 4 rows, not 3 — `new_desc2` carries two description rows.
    // `scroll_layout` serves tail first, head second, so at the D18 floor's
    // 12 interior rows that comes out of the field viewport: this modal's
    // tail is the default 5 (spacer + 2 note + keys + actions), so the
    // viewport went 4 rows -> 3. Re-derived here, not inherited from
    // profile_modal, whose tail is 6.
    let mut rows = modal_form::FormRows::new_desc2(&title, desc, width);

    // IDENTITY
    rows.section("Identity");
    let dn_focus = modal.focus == EditField::DisplayName;
    rows.text_field(
        modal_form::value_row(
            "display name",
            &modal.display_name,
            dn_focus,
            ValueKind::Editable,
            Some("e.g. Ads & trackers"),
            width,
        ),
        dn_focus,
        hint(EditField::DisplayName),
        modal.display_name.chars().count() as u16,
    );
    if is_new {
        let id_focus = modal.focus == EditField::ListId;
        rows.text_field(
            modal_form::value_row(
                "list id",
                &modal.blocklist_id,
                id_focus,
                ValueKind::Identity,
                Some("short-name"),
                width,
            ),
            id_focus,
            hint(EditField::ListId),
            modal.blocklist_id.chars().count() as u16,
        );
    } else {
        rows.line(modal_form::value_row(
            "list id",
            &modal.blocklist_id,
            false,
            ValueKind::Identity,
            None,
            width,
        ));
    }
    rows.spacer();

    // SOURCE
    rows.section("Source");
    let url_focus = modal.focus == EditField::Url;
    rows.text_field(
        modal_form::value_row(
            "url",
            &modal.url,
            url_focus,
            ValueKind::Identity,
            Some("https://example.org/hosts.txt"),
            width,
        ),
        url_focus,
        hint(EditField::Url),
        modal.url.chars().count() as u16,
    );
    rows.line(edit_trust_row(modal.original.trust, width));
    let adv_focus = modal.focus == EditField::Advanced;
    rows.field(
        modal_form::collapse_row(
            "Advanced",
            "   format \u{b7} refresh \u{b7} token",
            modal.advanced_expanded,
            adv_focus,
            width,
        ),
        adv_focus,
        hint(EditField::Advanced),
    );
    if modal.advanced_expanded {
        let fmt = match modal.format {
            BlocklistFormat::Domains => "domains",
            BlocklistFormat::Adguard => "adguard",
            BlocklistFormat::Hosts => "hosts",
        };
        let fmt_focus = modal.focus == EditField::Format;
        rows.field(
            modal_form::selector_row("  format", fmt, fmt_focus, width),
            fmt_focus,
            hint(EditField::Format),
        );
        let interval_focus = modal.focus == EditField::Interval;
        if matches!(modal.interval, IntervalChoice::Custom) {
            // Two rows, one focus: the selector paints as focused so the
            // pair reads as a unit, but the caret — and therefore the
            // viewport anchor — belongs to the hours field below it.
            rows.line(modal_form::selector_row(
                "  update period",
                "custom",
                interval_focus,
                width,
            ));
            rows.text_field(
                modal_form::value_row(
                    "    hours",
                    &modal.interval_custom_buf,
                    interval_focus,
                    ValueKind::Editable,
                    Some("e.g. 8"),
                    width,
                ),
                interval_focus,
                hint(EditField::Interval),
                modal.interval_custom_buf.chars().count() as u16,
            );
        } else {
            rows.field(
                modal_form::selector_row(
                    "  update period",
                    modal.interval.label(),
                    interval_focus,
                    width,
                ),
                interval_focus,
                hint(EditField::Interval),
            );
        }
        let auth_focus = modal.focus == EditField::AuthTokenRef;
        rows.text_field(
            modal_form::value_row(
                "  auth token",
                &modal.auth_token_ref,
                auth_focus,
                ValueKind::Editable,
                Some("(none)"),
                width,
            ),
            auth_focus,
            hint(EditField::AuthTokenRef),
            modal.auth_token_ref.chars().count() as u16,
        );
    }
    rows.spacer();

    // FILTERING
    rows.section("Filtering");
    let nature_focus = modal.focus == EditField::Nature;
    // A RADIO IS A TWO-STATE WIDGET AND `base` HAS THREE. `radio_row` takes
    // one bool, so `Ignore` would have to render as "Allow selected" — a
    // row that states the opposite of what the file says, on the field that
    // decides whether domains are blocked. The seed (`nature: blist.base`)
    // preserves `Ignore` through a save, so the form would keep claiming
    // Allow for a list that permits nothing, indefinitely.
    //
    // So the third state gets the cycler instead: `‹ Ignore ›`, honest about
    // both the value and the fact that ←/→ move it. The three-state picker
    // with its own affordance is S4c (`profile_list_policy.md` §4); until
    // then this is a truthful readout of a state the migration can produce
    // and the arrows can only leave.
    let nature_row = if matches!(modal.nature, BlocklistBase::Ignore) {
        modal_form::selector_row("nature", "Ignore", nature_focus, width)
    } else {
        modal_form::radio_row(
            "nature",
            ("Block", ValueKind::Blocking),
            ("Allow", ValueKind::Healthy),
            matches!(modal.nature, BlocklistBase::Deny),
            nature_focus,
            width,
        )
    };
    rows.field(nature_row, nature_focus, hint(EditField::Nature));
    let enabled_focus = modal.focus == EditField::Enabled;
    rows.field(
        modal_form::radio_row(
            "active",
            ("Yes", ValueKind::Healthy),
            ("No", ValueKind::Blocking),
            modal.enabled,
            enabled_focus,
            width,
        ),
        enabled_focus,
        hint(EditField::Enabled),
    );

    // [Delete|Discard] · Cancel · Save. Delete drops out in Add mode —
    // nothing to delete yet.
    let mut actions: Vec<modal_form::Action> = Vec::with_capacity(3);
    if !matches!(modal.mode, EditModalMode::Add) {
        let del_label = match modal.mode {
            EditModalMode::Promote { .. } => "  Discard  ",
            _ => "  Delete  ",
        };
        actions.push(modal_form::Action::new(
            del_label,
            modal.focus == EditField::DeleteButton,
            modal_form::ActionKind::Destructive,
            hint(EditField::DeleteButton),
        ));
    }
    actions.push(modal_form::Action::new(
        "  Cancel  ",
        modal.focus == EditField::Cancel,
        modal_form::ActionKind::Neutral,
        hint(EditField::Cancel),
    ));
    actions.push(modal_form::Action::new(
        "  Save  ",
        modal.focus == EditField::Save,
        modal_form::ActionKind::Primary,
        hint(EditField::Save),
    ));

    let tail = modal_form::form_tail(
        &rows,
        modal.error_message.as_deref(),
        // Belt and braces: a focus state that renders no row at all — a
        // field hidden behind the collapsed Advanced toggle — still gets
        // its guidance, from the same table the rows drew theirs from.
        edit_focus_hint(modal.focus, &modal.mode, modal.nature),
        // §4.63 S3b gave every form modal one navigation grammar: ↑↓ alias
        // Tab to move focus, ←/→ change the focused value. The legend had
        // never named ←/→ — a key the operator cannot discover is lost.
        // Word-for-word the footer's `modal_form_hints`, so the two
        // discovery surfaces cannot disagree.
        "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} change \
         \u{b7} Ctrl+s save \u{b7} Esc cancel",
        &actions,
    );
    rows.finish(tail)
}

/// Render the redesigned Lists edit modal (Variant A) — the Archetype-F
/// reference surface.
///
/// Everything geometric is [`modal_form::render_modal`]'s: the
/// elevated rounded chrome, the height request, the clamp, the two-pass
/// width resolution that keeps rows clear of the scrollbar column, and the
/// focus-following viewport. What is left here is the modal's width and
/// where its real terminal cursor goes.
fn render_edit_modal(f: &mut Frame, area: Rect, modal: &EditListModal) {
    let render = modal_form::render_modal(f, area, MODAL_W, |w| edit_form_body(modal, w));
    if let Some((row, value_len)) = render.cursor {
        render.place_cursor(f, row, modal_form::VALUE_COL as u16 + value_len);
    }
}

/// Render the typed-id confirm screen. Same 60×22 outer geometry; the
/// inner body becomes a 4-line warning + a single text input where the
/// operator must type the list id verbatim before `Enter` proceeds with
/// the destructive op.
/// Profiles that will lose this list's coverage if it is deleted — see
/// [`profiles_using_blocklist`], which is the daemon's own predicate and
/// not a second copy of it.
///
/// Drives the cascade-aware delete confirm (S53.7): the operator sees
/// what stops being blocked *before* typing the id.
///
/// **Two dead doc-comments stood above this until `plp-s4c` and both
/// described surfaces that no longer existed** — one said it walked
/// "`loaded_config.profiles` … whose `blocklists` array still references"
/// the id (`Profile.blocklists` was removed in `lists_categories_v2`), the
/// next said it was "the tag-intersection set" (retired by
/// `profile_list_policy` §2). Two generations of prose survived two
/// generations of the model, stacked, on a function guarding a
/// destructive confirm. Neither could fail a build.
pub fn compute_cascade_targets(app: &App, blocklist_id: &str) -> Vec<String> {
    profiles_using_blocklist(app, blocklist_id)
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

/// Column the typed buffer starts at, measured from the inner-left edge.
/// Structural, not measured: [`modal_form::prose_row`] lays out a 2-cell
/// indent and the row's own text opens with `"> "`.
const TYPED_PROMPT_COL: u16 = 4;

/// The Archetype-C body of the typed-id delete confirm.
///
/// ## Why the row count is the load-bearing part
///
/// This stage tells the operator to type the id, so the row carrying what
/// they typed has to be on screen — and before §4.63 S2a it was not. The
/// hand-rolled predecessor asked `centered_rect` for 22 rows, got the
/// 14-row D18 anchor **clamped** back at it, then cut its own `Paragraph`
/// at `inner.height - 4`; the input landed at line index 8 or 9 and fell
/// off, while an unconditional `set_cursor_position` left a cursor
/// blinking on the empty row below it. That is audit finding **F1**,
/// pinned by `floor_delete_confirm_keeps_the_typed_input_on_screen`.
///
/// So the budget is a contract, not a note. At the 80×24 floor the D18
/// anchor leaves a 12-row interior; head 2 + tail 3 leaves **7** rows of
/// prose, against a worst case of 7:
///
/// | cascade targets | prose rows | + a wrapped id |
/// |---|---|---|
/// | none | 3 — id, prompt, input | 4 |
/// | 1..=4 | 5 — + warning, names | 6 |
/// | > 4 | 6 — + `+ N more` | **7** |
///
/// The right-hand column is the one that binds. The id row is
/// [`modal_form::ProseRow::verbatim`], so it renders as **two** lines for
/// any id past the wrap column — 59 characters against `Id::MAX_LEN` 64 —
/// and the worst case lands exactly on the budget with nothing to spare.
/// A row added anywhere here cuts the input the operator is typing into,
/// silently, since there is no focus target to scroll it back.
///
/// The tail spends nothing on a key legend because the two action labels
/// *are* the keys (`Esc Back`, `Enter Delete`) — a second row restating
/// them is what would have to be paid for out of the input row.
///
/// `+ N more` keeps a row of its own rather than riding the names row:
/// [`modal_form::prose_row`] ellipsises, so four joined profile ids at the
/// interior width would routinely swallow the count — a silent truncation,
/// which is the same defect class as F1.
fn delete_notice(
    modal: &EditListModal,
    typed: &str,
    cascade_targets: &[String],
) -> modal_form::NoticeSpec {
    // Verbatim, not emphasis: the gate compares what was typed against
    // **all 64 bytes** of the id, and `prose_row`'s ellipsis made that
    // unpassable by any keystroke sequence — the missing characters were
    // not recoverable from the display. See
    // `delete_confirm_renders_a_max_length_id_in_full_at_the_floor`.
    let mut prose = vec![modal_form::ProseRow::verbatim(
        modal.blocklist_id.clone(),
        modal_form::ValueKind::Blocking,
    )];

    // When `cascade_targets` is non-empty the operator MUST see which
    // profiles lose their coverage BEFORE typing the id — confirming with
    // a hidden cascade is exactly what the "Use --cascade" CLI hint could
    // not surface from the TUI.
    if !cascade_targets.is_empty() {
        let count = cascade_targets.len();
        let plural = if count == 1 { "" } else { "s" };
        prose.push(modal_form::ProseRow::emphasis(
            // lists-08b: v2-accurate copy. Deleting the list does NOT
            // rewrite the profiles (they associate by shared tags, not by
            // enumerating ids); it stops the list's domains from being
            // blocked for every profile that matches it via a tag.
            format!("unblocks its domains for {count} profile{plural}:"),
            modal_form::ValueKind::Caution,
        ));
        let visible = cascade_targets.iter().take(4).cloned().collect::<Vec<_>>();
        prose.push(modal_form::ProseRow::plain(format!(
            "  {}",
            visible.join(", ")
        )));
        if cascade_targets.len() > visible.len() {
            prose.push(modal_form::ProseRow::plain(format!(
                "  + {} more",
                cascade_targets.len() - visible.len()
            )));
        }
    }

    prose.push(modal_form::ProseRow::plain(
        "type the id above verbatim, then Enter:",
    ));
    prose.push(modal_form::ProseRow::plain(format!("> {typed}")));

    modal_form::NoticeSpec {
        title: "Delete list".to_string(),
        desc: "removes the [[blocklists]] entry from disk".to_string(),
        prose,
        choices: Vec::new(),
        error: modal.error_message.clone(),
        hint: if modal.submitting {
            "deleting\u{2026}".to_string()
        } else {
            "nothing is written unless what you type matches exactly".to_string()
        },
        hint_rows: None,
        // Deliberately empty — see `delete_notice`'s budget table. The
        // action labels below carry their own keys.
        keys: String::new(),
        actions: vec![
            modal_form::Action::new("  Esc Back  ", false, modal_form::ActionKind::Neutral, ""),
            modal_form::Action::new(
                "  Enter Delete  ",
                false,
                modal_form::ActionKind::Destructive,
                "",
            ),
        ],
    }
}

/// Render the typed-id delete confirm, anchored on the tab content rect.
///
/// Everything geometric belongs to [`modal_form::render_modal`]: the
/// chrome, the height request, the clamp to the anchor, the two-pass width
/// resolution and the viewport. The border carries no meaning — `brand_red`
/// is never a border (D15) — so the destructive weight sits on the id
/// itself, in `ValueKind::Blocking`.
/// §4.63 F4: what the typed-id delete gate says when the buffer does not
/// match.
///
/// A function rather than a `format!` at the call site so the handler
/// (`tui::mod::handle_confirm_delete_key`) and the render test that proves
/// the text reaches the buffer read the SAME wording. Two copies of a
/// refusal string drift, and the one that drifts is always the one nothing
/// renders.
///
/// [`LIST_DELETE_CONFIRM_FAILED`] stays the lede instead of being replaced.
/// It lives in `cli/commands/blocklists.rs`, which this sprint does not
/// own; keeping it means its byte-for-byte frozen pin still guards a
/// string that is genuinely on screen, rather than one no surface emits.
///
/// [`LIST_DELETE_CONFIRM_FAILED`]: crate::cli::commands::blocklists::LIST_DELETE_CONFIRM_FAILED
pub fn delete_confirm_mismatch_message(typed: &str, expected: &str) -> String {
    format!(
        "{}: typed '{}' does not match '{}'",
        crate::cli::commands::blocklists::LIST_DELETE_CONFIRM_FAILED,
        typed,
        expected
    )
}

fn render_delete_confirm(
    f: &mut Frame,
    area: Rect,
    modal: &EditListModal,
    typed: &str,
    cascade_targets: &[String],
) {
    let spec = delete_notice(modal, typed, cascade_targets);
    // The input is always the LAST prose row, so its ordinal tracks the
    // variable height of the cascade block for free — but the ordinal is
    // not the field-region row index: the verbatim id above spends a
    // second line on any id past the wrap column. `prose_field_row`
    // converts, and is width-free so the caret cannot diverge from the
    // render.
    let typed_row = modal_form::prose_field_row(&spec.prose, spec.prose.len().saturating_sub(1));
    let render = modal_form::render_modal(f, area, MODAL_W, |w| {
        (modal_form::notice_body(&spec, w), ())
    });
    // The typed buffer hosts the real terminal cursor so the operator can
    // see where their keystrokes land. `place_cursor` no-ops when that row
    // is out of the viewport — the guard the hand-rolled path lacked, and
    // half of what made F1 a P1 rather than a cosmetic cut.
    render.place_cursor(
        f,
        typed_row,
        TYPED_PROMPT_COL + typed.chars().count() as u16,
    );
}

// ── the unsigned-allow consent gate ─────────────────────────────────
//
// Every string below is frozen and pinned byte-for-byte in
// `tests/frozen_strings_tui_allow_consent.rs`. They are the operator's
// entire view of a decision that has no undo affordance and leaves
// nothing on screen afterwards, so wording drift is a real defect and
// not a style question.
//
// They are also deliberately NOT the validator's frozen string. That one
// is ~300 characters and speaks TOML ("set accept_unsigned_allow =
// true"), which is the right answer for a config diagnostic and the
// wrong one for someone standing in front of a form. Dropped into this
// body it would also overrun the prose ceiling and be cut with nothing
// on screen saying so.

// `LIST_ALLOW_NEEDS_TAG` and `KIND_TOGGLE_NEEDS_TAG` stood here — the
// modal's and the `[K]` toast's version of "an allow list needs a tag".
//
// Both are gone with the gate that raised them. `profile_list_policy`
// §2.5 retired `AllowDirectionGates::needs_tag`: an allow-direction list
// is inherited by every profile that does not override it, tagged or not,
// so the premise ("this one reaches nobody") stopped being true. The same
// sprint stopped `warden blocklist tag add` from writing tags at all, so
// an operator refused by these would have been sent to a verb that also
// refuses — the unsatisfiable refusal project rules §Neutrality records this
// repo already paying for once.
//
// Deleted rather than left pinned: a frozen string with no emitter tests
// the string, not the product, and can only ever fail for the wrong
// reason.

/// Names the change, in the operator's terms, not the schema's.
pub const UNSIGNED_ALLOW_CONFIRM_TITLE: &str = "Turn this into an allow list?";

/// What "allow" means here, for an operator who has met the word once.
pub const UNSIGNED_ALLOW_CONFIRM_DESC: &str =
    "it would permit these domains instead of blocking them";

/// First risk row. "cannot verify" rather than "unsigned": the operator
/// did not choose a trust level, they typed a URL.
pub const UNSIGNED_ALLOW_CONFIRM_RISK_1: &str =
    "warden cannot verify this source: whoever controls";

/// Second risk row. The two clauses that make this different from any
/// other setting — *any* domain, and *again at every refresh*.
pub const UNSIGNED_ALLOW_CONFIRM_RISK_2: &str = "the URL can unblock any domain, at every refresh.";

/// Word-for-word the delete gate's prompt. The two typed confirms in
/// this modal ask for the same thing and must not phrase it differently.
pub const UNSIGNED_ALLOW_CONFIRM_PROMPT: &str = "type the id above verbatim, then Enter:";

/// Shares the delete gate's reassurance for the same reason: nothing has
/// been written yet, and an operator who is not sure should be able to
/// read that off the screen rather than infer it.
pub const UNSIGNED_ALLOW_CONFIRM_HINT: &str =
    "nothing is written unless what you type matches exactly";

/// Shown in the error slot when Enter arrives on a buffer that does not
/// match. Displaces the hint, so it costs no row.
///
/// The stage stays open on a mismatch. A gate that silently re-stashed
/// the state would be indistinguishable from a dead key, and one that
/// bounced back to the form would make a typo cost a re-submit.
pub const UNSIGNED_ALLOW_CONFIRM_MISMATCH: &str =
    "that is not the list id \u{2014} type it exactly to accept";

/// Success toast for the save that carried a fresh consent, in place of
/// the generic `LIST_EDIT_OK`.
///
/// The consent is recorded once and then applies at every refresh, and
/// nothing on the Lists tab marks the moment it was granted. Naming the
/// standing WARN here is the one chance to tell the operator that the
/// exposure did not end when the modal closed — and it is also where
/// they will next see it, in the log.
pub const LIST_ALLOW_CONSENT_SAVED: &str =
    "List '{id}' is now an allow list; warden warns about it at every load";

/// Substitute `{id}` into [`LIST_ALLOW_CONSENT_SAVED`].
pub fn format_list_allow_consent_saved(id: &str) -> String {
    LIST_ALLOW_CONSENT_SAVED.replace("{id}", id)
}

/// Success toast for a direction change that needed no consent — a
/// local list, one whose file already consents, or the way back to
/// blocking.
///
/// Two constants rather than one with a `{kind}` slot, because the slot
/// wanted an article and the wire token cannot supply one: the first
/// draft read *"is now a allow list"*. Saying "block" rather than the
/// wire's "deny" is also deliberate — the row badge and the Nature
/// field both say Block, and the toast that follows the keypress should
/// use the word the operator just pressed a key next to.
pub const KIND_TOGGLE_OK_BLOCK: &str = "List '{id}' is now a block list; reload triggered";

/// The allow half of [`KIND_TOGGLE_OK_BLOCK`].
pub const KIND_TOGGLE_OK_ALLOW: &str = "List '{id}' is now an allow list; reload triggered";

/// Unreachable from `[K]` today — see [`format_kind_toggle_ok`]. Present
/// so the match is exhaustive by name rather than by `_`.
pub const KIND_TOGGLE_OK_IGNORE: &str = "List '{id}' is now inert; reload triggered";

/// Pick the right half and substitute `{id}`.
pub fn format_kind_toggle_ok(id: &str, base: BlocklistBase) -> String {
    match base {
        BlocklistBase::Deny => KIND_TOGGLE_OK_BLOCK,
        BlocklistBase::Allow => KIND_TOGGLE_OK_ALLOW,
        // `[K]` never *produces* Ignore — it is a one-way exit out of it
        // (see `mod.rs`, the `[K]` handler). Kept as an arm rather than a
        // `_` so a future toggle that does produce it fails to compile
        // instead of announcing the wrong word.
        BlocklistBase::Ignore => KIND_TOGGLE_OK_IGNORE,
    }
    .replace("{id}", id)
}

/// Build the typed-id consent notice.
///
/// **Row budget**, same contract as [`delete_notice`]: at the 80×24
/// floor the D18 anchor leaves a 12-row interior; head 2 + tail 3
/// (`keys` is empty — the action labels *are* the keys) leaves **7**
/// prose rows. This spends 5, or 6 when the id wraps —
/// [`modal_form::ProseRow::verbatim`] costs a second line past the wrap
/// column, and it has to be verbatim because the gate compares all of
/// `Id::MAX_LEN`. One row is left unspent on purpose.
///
/// **The 7 is measured, not derived.** Adding rows to this vector and
/// re-running `floor_unsigned_allow_confirm_keeps_every_row_it_promises`
/// puts the cliff between the 7th and the 8th: at 7 the frame is intact,
/// at 8 the typed input and the action row are gone with no scrollbar
/// and no ellipsis to say so.
///
/// Takes the id / buffer / error rather than a modal, because the same
/// decision is reachable from two hosts — `Ctrl+S` in the editor and the
/// `K` hotkey on the table — and the operator must not be able to tell
/// which one they came through. One builder is also the only way the
/// copy stays in one place; two would drift inside a sprint.
pub(crate) fn unsigned_allow_notice(
    list_id: &str,
    typed: &str,
    error: Option<String>,
) -> modal_form::NoticeSpec {
    let prose = vec![
        modal_form::ProseRow::verbatim(list_id.to_string(), modal_form::ValueKind::Blocking),
        modal_form::ProseRow::emphasis(
            UNSIGNED_ALLOW_CONFIRM_RISK_1,
            modal_form::ValueKind::Caution,
        ),
        modal_form::ProseRow::emphasis(
            UNSIGNED_ALLOW_CONFIRM_RISK_2,
            modal_form::ValueKind::Caution,
        ),
        modal_form::ProseRow::plain(UNSIGNED_ALLOW_CONFIRM_PROMPT),
        modal_form::ProseRow::plain(format!("> {typed}")),
    ];

    modal_form::NoticeSpec {
        title: UNSIGNED_ALLOW_CONFIRM_TITLE.to_string(),
        desc: UNSIGNED_ALLOW_CONFIRM_DESC.to_string(),
        prose,
        choices: Vec::new(),
        error,
        hint: UNSIGNED_ALLOW_CONFIRM_HINT.to_string(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            modal_form::Action::new("  Esc Back  ", false, modal_form::ActionKind::Neutral, ""),
            modal_form::Action::new(
                "  Enter Accept  ",
                false,
                // D15: the weight belongs on the action that carries the
                // risk, not on the border. Accepting is the one.
                modal_form::ActionKind::Destructive,
                "",
            ),
        ],
    }
}

/// Render the typed-id consent gate. Geometry is
/// [`modal_form::render_modal`]'s, exactly as for the delete gate.
pub(crate) fn render_unsigned_allow_confirm(
    f: &mut Frame,
    area: Rect,
    list_id: &str,
    typed: &str,
    error: Option<String>,
) {
    let spec = unsigned_allow_notice(list_id, typed, error);
    let typed_row = modal_form::prose_field_row(&spec.prose, spec.prose.len().saturating_sub(1));
    let render = modal_form::render_modal(f, area, MODAL_W, |w| {
        (modal_form::notice_body(&spec, w), ())
    });
    render.place_cursor(
        f,
        typed_row,
        TYPED_PROMPT_COL + typed.chars().count() as u16,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::validator::format_base_ignore_list_is_inert;
    use crate::lists::status::{BlocklistStatusDto, ListStatus, ParsedCounts};
    use crate::tui::app::App;
    use crate::tui::modal_form::ValueKind;

    // ── SN3 frozen-string pin ────────────────────────────────────────

    #[test]
    fn lists_tab_empty_string_matches_sn3() {
        assert_eq!(
            LISTS_TAB_EMPTY,
            "No blocklists configured. Run `warden blocklist add <id> --url <url>` to add one."
        );
    }

    // ── existing helper coverage ────────────────────────────────────

    // `used_by_returns_profiles_referencing_canonical_id` was dropped in
    // Sprint A.5 when `Profile.blocklists` went away, and the note left
    // here promised a tag-aware replacement. `plp-s4c` closes it against
    // the model that actually shipped: "uses" is `effective_direction`,
    // not tag intersection — see `profiles_using_blocklist`.

    #[test]
    fn used_by_is_empty_when_id_missing() {
        let app = App::new();
        let dto = BlocklistStatusDto {
            source: "https://raw.example/list.txt".into(),
            id: None,
            entries: 0,
            ..Default::default()
        };
        assert!(used_by_for(&app, &dto).is_empty());
    }

    // ── plp-s4c: USED BY + cascade follow `effective_direction` ─────

    /// A config in the shape the two live hosts are actually in — and the
    /// shape the retired predicate answered `[]` for.
    ///
    /// `home` declares an override, `guest` inherits, `off` opts out with
    /// `ignore`. **No profile carries a tag and `blocked` carries none
    /// either**, which is deliberate: §1.1 of the design doc measured zero
    /// tagged profiles on both hosts, so tag intersection returns the
    /// empty set for every row of this fixture. A test written against the
    /// old predicate cannot pass here for the right reason.
    fn app_with_overridden_lists_and_profiles() -> App {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "home"

[profiles.home]
display_name = "Home"
lists = { blocked = "deny" }

[profiles.guest]
display_name = "Guest"

[profiles.off]
display_name = "Off"
lists = { blocked = "ignore", inert = "ignore" }

[[blocklists]]
id = "blocked"
display_name = "Blocked"
url = "https://example.com/blocked.txt"

[[blocklists]]
id = "inert"
display_name = "Inert"
url = "https://example.com/inert.txt"
base = "ignore"
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.loaded_config = Some(loaded);
        app
    }

    /// The regression this replaces: with no tags anywhere, the old
    /// predicate returned `[]` and the "USED BY" column read empty for a
    /// list every profile was enforcing.
    #[test]
    fn used_by_resolves_profiles_that_enforce_the_list() {
        let app = app_with_overridden_lists_and_profiles();
        let dto = BlocklistStatusDto {
            source: "https://example.com/blocked.txt".into(),
            id: Some("blocked".into()),
            ..Default::default()
        };
        // `home` declares deny, `guest` inherits base = deny; `off`
        // declares ignore and is correctly absent.
        assert_eq!(used_by_for(&app, &dto), vec!["guest", "home"]);
    }

    #[test]
    fn used_by_resolves_url_form_dto_via_canonical_fallback() {
        let app = app_with_overridden_lists_and_profiles();
        // id = None (URL-form row) must still resolve via the url match.
        let dto = BlocklistStatusDto {
            source: "https://example.com/blocked.txt".into(),
            id: None,
            ..Default::default()
        };
        assert_eq!(used_by_for(&app, &dto), vec!["guest", "home"]);
    }

    /// A `base = "ignore"` list is enforced by nobody, so nobody loses it
    /// — the one case where the benign delete copy is the honest one.
    #[test]
    fn used_by_empty_for_a_list_no_profile_enforces() {
        let app = app_with_overridden_lists_and_profiles();
        let dto = BlocklistStatusDto {
            source: "https://example.com/inert.txt".into(),
            id: Some("inert".into()),
            ..Default::default()
        };
        assert!(used_by_for(&app, &dto).is_empty());
    }

    /// **The delete confirm must not go quiet on an untagged config.**
    ///
    /// This is the fence on the fail-open: the fixture has zero tags, so
    /// the retired `profiles_matching_blocklist_tags` answers `[]` for
    /// `blocked` and the confirm renders its benign copy for a list two
    /// profiles enforce. Restore the tag predicate and this goes red.
    #[test]
    fn compute_cascade_targets_names_the_profiles_that_lose_coverage() {
        let app = app_with_overridden_lists_and_profiles();
        assert_eq!(
            compute_cascade_targets(&app, "blocked"),
            vec!["guest".to_string(), "home".to_string()],
            "an untagged config must still surface who loses the list"
        );
        // Enforced by nobody → benign copy, honestly.
        assert!(compute_cascade_targets(&app, "inert").is_empty());
        // Unknown id → empty (no panic, benign copy).
        assert!(compute_cascade_targets(&app, "does-not-exist").is_empty());
    }

    /// The prompt and the side-card must never disagree about who uses a
    /// list: both are built from `resolve_profile_blocklist_ids`, and this
    /// pins that they stay one answer rather than two.
    #[test]
    fn the_confirm_and_the_side_card_agree_on_who_uses_a_list() {
        let app = app_with_overridden_lists_and_profiles();
        let loaded = app.loaded_config.as_ref().unwrap();
        for list_id in ["blocked", "inert"] {
            let id = crate::config::schema::Id::new(list_id).unwrap();
            let from_side_card: Vec<String> = loaded
                .config
                .profiles
                .iter()
                .filter(|(_, p)| {
                    crate::profiles::profile::resolve_profile_blocklist_ids(
                        p,
                        &loaded.config.blocklists,
                    )
                    .contains(&id)
                })
                .map(|(k, _)| k.to_string())
                .collect();
            assert_eq!(
                compute_cascade_targets(&app, list_id),
                from_side_card,
                "list {list_id}"
            );
        }
    }

    #[test]
    fn status_of_renders_each_outcome_branch() {
        let s_ok = BlocklistStatusDto {
            last_outcome: "ok".into(),
            ..Default::default()
        };
        let (label, _) = status_of(&s_ok);
        assert_eq!(label, "ok");

        let s_never = BlocklistStatusDto {
            last_outcome: "never_fetched".into(),
            ..Default::default()
        };
        let (label, _) = status_of(&s_never);
        assert_eq!(label, "never");

        let s_failed = BlocklistStatusDto {
            last_outcome: "failed: HTTP 502".into(),
            ..Default::default()
        };
        let (label, _) = status_of(&s_failed);
        assert_eq!(label, "failed", "table label strips the reason");
    }

    #[test]
    fn format_short_timestamp_round_trips_rfc3339() {
        let s = format_short_timestamp("2026-04-25T14:02:33Z");
        assert_eq!(s, "04-25 14:02");
    }

    // ── flat row cursor movement ─────────────────────────────────────
    //
    // Sprint A.5 (lc2_v2 foundation) dropped the three category-aware
    // grouping tests:
    //   - build_grouped_rows_emits_one_header_per_category_then_lists
    //   - build_grouped_rows_uncategorized_omitted_when_every_list_has_a_category
    //   - build_grouped_rows_kind_and_format_are_joined_from_loaded_config
    //
    // Sprint A removed the [[categories]] entity + Blocklist.category
    // field; the v1-shape helpers `app_with_two_categories_*` are no
    // longer parseable under deny_unknown_fields. The filtering-cleanup
    // pass then removed the grouping-header row model entirely — the
    // Lists tab renders a flat row-per-list table, so cursor movement is
    // plain clamped increment/decrement (no headers to skip). N4
    // (2026-08-24) replaced the wrap with a clamp; see
    // `next_selectable_index`'s doc comment for why this one, unlike
    // Devices, never returns `None` at the boundary.

    #[test]
    fn next_selectable_index_clamps_at_both_ends() {
        let rows = vec![test_meta("a"), test_meta("b"), test_meta("c")];
        assert_eq!(next_selectable_index(&rows, None, 1), Some(0));
        assert_eq!(next_selectable_index(&rows, Some(0), 1), Some(1));
        // N4: from the last row, forward clamps — no wrap to row 0.
        assert_eq!(next_selectable_index(&rows, Some(2), 1), Some(2));
        // N4: from the first row, backward clamps — no wrap to the last.
        assert_eq!(next_selectable_index(&rows, Some(0), -1), Some(0));
    }

    #[test]
    fn next_selectable_index_returns_none_when_rows_empty() {
        let rows: Vec<ListRowMeta> = Vec::new();
        assert_eq!(next_selectable_index(&rows, None, 1), None);
        assert_eq!(next_selectable_index(&rows, Some(0), 1), None);
    }

    #[test]
    fn render_list_row_uses_parsed_ok_for_entries_display() {
        // Repro of the user's privacy/devices confusion: list with
        // 4043 parsed lines but only 8 unique-after-dedup. The ENTRIES
        // column must show the operator-intuitive 4043 (matches the
        // catalog file's "Total Entries: 4043" header), not the 8
        // post-dedup value that was rendered pre-fix.
        let dto = BlocklistStatusDto {
            parsed_ok: 4043,
            entries: 8,
            last_outcome: "ok".into(),
            ..Default::default()
        };
        let meta = ListRowMeta {
            dto,
            display_name: "Privacy: Devices".into(),
            canonical_id: Some("privacy-devices".into()),
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            format: Some(BlocklistFormat::Domains),
            used_by_profiles: Vec::new(),
            is_stale: false,
            inert_reason: None,
        };
        let row = render_list_row(meta);
        let rendered = row_text(&row);
        assert!(
            rendered.contains("4.0K") || rendered.contains("4043"),
            "ENTRIES column must surface parsed_ok (4043), not the post-dedup novelty count (8); rendered: {rendered}"
        );
        assert!(
            !rendered.contains(" 8 "),
            "post-dedup `entries=8` must NOT leak to display when parsed_ok > 0; rendered: {rendered}"
        );
    }

    // Sprint A.5 (lc2_v2 foundation) dropped
    // `focused_list_returns_none_on_header_row` — the v1-shape helper
    // `app_with_two_categories_and_three_lists` is no longer parseable.
    // Cursor-guard semantics survive in `next_selectable_index_*` above
    // and Sprint C's tag-aware grouping will re-pin the focused-list
    // path against the new layout.

    // ── Sprint 50 T4 — kind badge presence ─────────────────────────

    #[test]
    fn render_list_row_carries_kind_badge_block_for_block_kind() {
        let mut meta = test_meta("a");
        meta.base = BlocklistBase::Deny;
        let row = render_list_row(meta);
        let rendered = row_text(&row);
        assert!(
            rendered.contains("\u{25A3} BLOCK"),
            "block kind must surface `▣ BLOCK`; got: {rendered}"
        );
    }

    #[test]
    fn render_list_row_carries_kind_badge_allow_for_allow_kind() {
        let mut meta = test_meta("a");
        meta.base = BlocklistBase::Allow;
        meta.trust = BlocklistTrust::Local; // W2.1 — allow requires local trust.
        let row = render_list_row(meta);
        let rendered = row_text(&row);
        assert!(
            rendered.contains("\u{25A1} ALLOW"),
            "allow kind must surface `▢ ALLOW`; got: {rendered}"
        );
    }

    #[test]
    fn render_list_row_format_column_shows_autodetected_label() {
        let mut meta = test_meta("a");
        meta.format = Some(BlocklistFormat::Adguard);
        let row = render_list_row(meta);
        assert!(
            row_text(&row).contains("AdGuard"),
            "format column must surface `AdGuard` for the AdGuard variant"
        );
    }

    #[test]
    fn render_list_row_format_column_shows_em_dash_when_unknown() {
        let mut meta = test_meta("a");
        meta.format = None;
        let row = render_list_row(meta);
        assert!(
            row_text(&row).contains('\u{2014}'),
            "missing format must render as `—` (em dash)"
        );
    }

    // rev-2606 §11 (mod-06 / lists-08b): the create-category,
    // move-category, and list↔profile assignment modals were unmounted —
    // categories are gone in v2 and tag assignment ships via the
    // edit-modal chip picker + Tags tab. Their builder tests went with
    // them (build_create_category_modal_starts_empty,
    // build_move_category_modal_returns_none_*, build_assignment_modal_*).

    #[test]
    fn build_row_uses_canonical_id_when_present_does_not_panic() {
        let mut app = App::new();
        let now = time::OffsetDateTime::now_utc();
        let status = ListStatus::from_refresh(123, ParsedCounts::default(), None, now);
        let dto = BlocklistStatusDto::from_status(
            "privacy/ads".into(),
            Some("privacy-ads".into()),
            &status,
        );
        let empty_inert = std::collections::HashMap::new();
        let _row = render_list_row(build_meta(&app, &dto, &empty_inert));
        let mut dto2 = BlocklistStatusDto {
            source: "raw-url".into(),
            id: None,
            entries: 0,
            ..Default::default()
        };
        dto2.last_outcome = "never_fetched".into();
        app.lists.entries = vec![dto2];
        let dto_ref = &app.lists.entries[0].clone();
        let _row2 = render_list_row(build_meta(&app, dto_ref, &empty_inert));
    }

    // ── fixtures ────────────────────────────────────────────────────

    fn test_meta(id: &str) -> ListRowMeta {
        ListRowMeta {
            dto: BlocklistStatusDto {
                source: id.into(),
                id: Some(id.into()),
                entries: 1,
                last_outcome: "ok".into(),
                ..Default::default()
            },
            display_name: id.to_string(),
            canonical_id: Some(id.to_string()),
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            format: Some(BlocklistFormat::Domains),
            used_by_profiles: Vec::new(),
            is_stale: false,
            inert_reason: None,
        }
    }

    fn row_text(row: &Row) -> String {
        // ratatui doesn't expose Row's cells via a public iterator, so
        // we route through the Debug repr — sufficient for substring
        // checks on the rendered Span content. (Used only by the kind
        // badge / format column tests; brittleness is bounded by the
        // few substrings we look for.)
        format!("{row:?}")
    }

    // Sprint A.5 (lc2_v2 foundation) dropped the v1-shape helpers
    // `app_with_two_categories_and_three_lists` and
    // `app_with_two_categories_no_orphans` — they constructed
    // [[categories]] + Blocklist.category= which `deny_unknown_fields`
    // refuses post-Sprint-A. All callers were the bucket-T4 tests
    // dropped above. Sprint C reintroduces equivalent fixtures shaped
    // around the tag-chip surface.

    // ── Sprint 53 follow-up — dedup by canonical_id ──────────────────

    /// Repro of the screenshot the user sent: each managed list shows
    /// up twice in the table because the daemon's
    /// `merge_sources_with_blocklists` bridge spawns one registry slot
    /// for the slug-form `[lists].sources` entry AND one for the
    /// `[[blocklists]].url`. Both resolve to the same canonical id once
    /// the URL→id fallback in `build_meta` lands. `build_grouped_rows`
    /// must collapse those into one row apiece, picking the live copy
    /// (last_outcome=ok with higher entries) over the failed twin.
    #[test]
    fn build_grouped_rows_collapses_canonical_id_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();

        let mut app = App::new();
        app.loaded_config = Some(loaded);
        // Simulate the daemon's runtime registry: one slug-form slot +
        // one URL-form slot (added by merge_sources_with_blocklists).
        // The URL twin failed to fetch, the slug twin is healthy.
        app.lists.entries = vec![
            BlocklistStatusDto {
                source: "privacy/ads".into(),
                id: Some("privacy-ads".into()),
                entries: 2_400_000,
                last_outcome: "ok".into(),
                ..Default::default()
            },
            BlocklistStatusDto {
                source: "https://lists.purge.cc/privacy/ads.txt".into(),
                id: None, // resolved client-side via build_meta fallback
                entries: 0,
                last_outcome: "failed: HTTP 404".into(),
                ..Default::default()
            },
        ];

        let rows = build_grouped_rows(&app);
        assert_eq!(
            rows.len(),
            1,
            "duplicates must collapse to one row per canonical id"
        );
        assert_eq!(rows[0].dto.entries, 2_400_000, "live copy wins");
        assert_eq!(rows[0].dto.last_outcome, "ok");
    }

    // ── Sprint 53 follow-up — URL→id fallback in build_meta ──────────

    /// Repro of the live CT misclassification: the daemon's runtime
    /// `merge_sources_with_blocklists` bridge synthesises a registry
    /// slot for every `[[blocklists]].url`. The IPC handler's
    /// `id_lookup` only resolves slug-form sources — URL-form ones come
    /// back with `id = None`. Without this client-side fallback those
    /// rows render as orphans (DISPLAY = "—", FORMAT = "—") and the
    /// "Discard source" path in the Promote modal fails because the URL
    /// was never in the on-disk `[lists].sources` array.
    #[test]
    fn build_meta_falls_back_to_url_match_when_dto_id_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[blocklists]]
id = "security-malicious"
display_name = "Security: malicious"
url = "https://lists.purge.cc/security/malicious.txt"

[profiles.default]
display_name = "Default"
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.loaded_config = Some(loaded);
        let dto = BlocklistStatusDto {
            source: "https://lists.purge.cc/security/malicious.txt".into(),
            id: None, // IPC could not resolve via slug_to_id
            entries: 0,
            ..Default::default()
        };
        let meta = build_meta(&app, &dto, &std::collections::HashMap::new());
        assert_eq!(
            meta.canonical_id.as_deref(),
            Some("security-malicious"),
            "URL-form source must map to its [[blocklists]] id via the fallback"
        );
        assert_eq!(
            meta.display_name, "Security: malicious",
            "schema fields must populate from the resolved entry, not stay '—'"
        );
        assert_eq!(meta.format, Some(BlocklistFormat::Domains));
    }

    // ── Sprint 53 — list edit modal builder + state transitions ──────
    //
    // Sprint A.5 (lc2_v2 foundation) dropped two S53 edit-modal tests:
    //   - s53_build_edit_modal_for_focused_list_pre_fills_all_fields
    //   - s53_build_edit_modal_returns_none_on_header_row
    //
    // Both rely on `app_with_two_categories_and_three_lists` (no longer
    // parseable with deny_unknown_fields rejecting [[categories]] /
    // category=). Sprint C re-pins the modal pre-fill against the new
    // tag-chip widget; cursor-guard semantics survive in the two
    // remaining tests below.

    // ── surface-5m: modal builders must read the shared default ──────
    //
    // `build_promote_modal_for` and `build_add_modal` used to hardcode
    // `max_entries: 5_000_000` — a stale copy of a daemon-wide default
    // that was raised to 10M. Since the fail-closed corpus guard change,
    // exceeding `max_entries` refuses the source whole (previous
    // generation kept) instead of truncating it, so a list added from
    // the TUI that holds more than 5M domains silently vanishes on the
    // next refresh. These pin both builders to the single source of
    // truth (`crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES`) so
    // raising the schema default propagates here with no further edit.

    #[test]
    fn add_modal_max_entries_reads_the_shared_default_not_a_copy() {
        let modal = build_add_modal();
        assert_eq!(
            modal.original.max_entries,
            crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES as u64
        );
    }

    #[test]
    fn promote_modal_max_entries_reads_the_shared_default_not_a_copy() {
        let mut app = App::new();
        app.lists.entries = vec![BlocklistStatusDto {
            source: "https://raw.example/orphan.txt".into(),
            id: None,
            entries: 0,
            ..Default::default()
        }];
        app.lists.table_state.select(Some(0));
        let modal = build_promote_modal_for(&app).expect("orphan row must build a Promote modal");
        assert_eq!(
            modal.original.max_entries,
            crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES as u64
        );
    }

    #[test]
    fn s53_build_edit_modal_returns_none_when_no_canonical_id() {
        let mut app = App::new();
        app.lists.entries = vec![BlocklistStatusDto {
            source: "https://raw.example/list.txt".into(),
            id: None,
            entries: 0,
            ..Default::default()
        }];
        app.lists.table_state.select(Some(1));
        // No canonical id is `Ok(None)` — the Promote fall-through — and
        // must never be reported as an unreadable file, which is the
        // outcome that suppresses the fall-through.
        let got = build_edit_modal_for(&app, std::path::Path::new("/nonexistent/config.toml"));
        assert!(
            matches!(got, Ok(None)),
            "expected the Promote fall-through, got {:?}",
            got.map(|o| o.map(|m| m.blocklist_id))
        );
    }

    #[test]
    fn s53_edit_field_tab_cycle_wraps_through_button_row() {
        // Variant-A redesign: the Edit-mode collapsed cycle ends on the
        // Save button (button row Delete → Cancel → Save), not the old
        // inline Delete row. Walk the full cycle once and land back on
        // DisplayName — guards against a forgotten variant in `cycle()`.
        let mut f = EditField::DisplayName;
        let len = EditField::cycle(&EditModalMode::Edit, false).len();
        for _ in 0..len {
            f = f.next();
        }
        assert_eq!(f, EditField::DisplayName);
        // Backward from the first field wraps to the last button (Save).
        assert_eq!(EditField::DisplayName.prev(), EditField::Save);
        // Forward from the last button wraps back to DisplayName.
        assert_eq!(EditField::Save.next(), EditField::DisplayName);
    }

    #[test]
    fn s53_interval_choice_round_trips_known_presets_and_custom_fallback() {
        for h in [1u32, 2, 6, 12, 24, 48] {
            let c = IntervalChoice::from_hours(h);
            assert_eq!(c.hours(), Some(h));
        }
        // Off-preset hours collapse to Custom (operator-supplied buffer
        // carries the actual value).
        assert!(matches!(
            IntervalChoice::from_hours(7),
            IntervalChoice::Custom
        ));
        assert!(IntervalChoice::Custom.hours().is_none());
    }

    // Sprint C T5 of `lists_categories_v2`: the legacy
    // `cycle_category` helper (and its companion test
    // `s53_cycle_category_with_no_declared_categories_collapses_to_none`)
    // is gone — Category is no longer an entity, the modal renders a
    // multi-select tag chip widget instead. The new picker behaviour
    // is pinned by the `lc2_c_t5_*` tests further down.

    /// The picker still groups by kind and still emits a header per non-empty
    /// group — that code is untouched by the rules retirement
    /// (`build_catalog_picker_modal_from`). What changed is the *input*: with
    /// `rules.purge.cc` gone the catalog carries only domain lists, so exactly
    /// one header comes out.
    ///
    /// This replaces `catalog_picker_renders_two_section_headers_when_both_
    /// fallbacks_present`, which asserted the two-header shape. Deleting it
    /// outright rather than narrowing it would have left the catalog → header
    /// path with no test at all: `picker_modal()` further down hand-builds its
    /// rows, so it pins the *rendering* of headers and never the fact that the
    /// builder emits them.
    /// Successor to `catalog_picker_emits_one_section_header_now_that_only_
    /// lists_remain`, which asserted the one-header shape after the rules
    /// retirement. Deleting it outright would have left the catalog →
    /// builder path with no test at all: the fixture further down hand-builds
    /// its rows, so it pins the *rendering* and never what the builder emits.
    ///
    /// The property inverts with the table: there must be **no** grouping at
    /// all, and — the part that could regress silently — an `adguard`-stamped
    /// entry must still appear, in plain scope order, rather than being
    /// filtered out or sorted into a section of its own. `index.json` is the
    /// single source of truth; a defensive `format == Domains` filter here
    /// would hide a `hosts` list purge.cc may legitimately publish.
    #[test]
    fn catalog_picker_renders_one_flat_table_even_for_an_adguard_entry() {
        use crate::lists::catalog::{Catalog, CatalogEntry};

        let entry = |scope: &str, topic: &str, format: BlocklistFormat| CatalogEntry {
            scope: scope.to_string(),
            topic: Some(topic.to_string()),
            name: topic.to_string(),
            url: format!("https://lists.purge.cc/{topic}.txt"),
            entries: 10,
            updated_at: "2026-08-01T04:03:13Z".to_string(),
            format,
        };
        let catalog = Catalog::from_entries(vec![
            entry("security", "malicious", BlocklistFormat::Domains),
            entry("privacy", "rulepack", BlocklistFormat::Adguard),
            entry("privacy", "ads", BlocklistFormat::Domains),
        ]);

        let modal = build_catalog_picker_modal_from(&App::new(), &catalog);
        assert_eq!(
            modal
                .rows
                .iter()
                .map(|r| r.catalog_id.as_str())
                .collect::<Vec<_>>(),
            vec!["privacy/ads", "privacy/rulepack", "security/malicious"],
            "one flat table sorted by (scope, id) — no format grouping, nothing filtered"
        );

        let s = render_picker_in(&modal, 100, 24);
        for banner in ["Domain lists", "Rule packs"] {
            assert!(
                !s.contains(banner),
                "section chrome `{banner}` is back — there is one group now:\n{s}"
            );
        }
    }

    // `plp-s5d` removed the whole chip-picker test block that sat here —
    // 17 tests across three families:
    //
    //  * the §4.65 UX2b collector tests (`collector_offers_*`,
    //    `collector_ignores_labels_of_the_metadata_kinds`,
    //    `collector_drops_a_declared_tag_id_that_is_not_a_valid_slug`),
    //    which pinned `collect_known_tag_slugs`;
    //  * the suggestion-filter / focus-cycle tests
    //    (`lc2_c_t5_filter_suggestions_*`, `lc2_c_t5_cycle_picker_focus_*`);
    //  * the §4.65 UX2 two-Enter valve tests
    //    (`a_typed_slug_outside_the_union_needs_a_second_enter`,
    //    `a_typed_slug_inside_the_union_attaches_on_the_first_enter`,
    //    `the_valve_rearms_when_the_buffer_changes_under_it`,
    //    `a_highlighted_suggestion_never_raises_the_confirm`, and the
    //    `commit_tag_picker` round-trips).
    //
    // Every one of them tested a function this lane deleted, so there is
    // no substitute to point at: the guarantees left with the picker.
    // `add_modal_seeds_no_tag_so_none_is_ever_written_unchosen` went with
    // them and is the one worth naming separately — it pinned that the Add
    // modal does not pre-seed `uncategorized` into the picker, and the
    // property it protected is now enforced by construction, because
    // `build_blocklist_value` writes no `tags` key at all. See the note
    // there for why NOT writing it is the safe direction.

    #[test]
    fn stale_badge_renders_when_threshold_exceeded() {
        let now = OffsetDateTime::now_utc();
        let two_days_ago = now - time::Duration::hours(48);
        let dto = BlocklistStatusDto {
            source: "privacy/ads".into(),
            id: Some("privacy-ads".into()),
            last_outcome: "ok".into(),
            last_refresh_at: Some(two_days_ago.format(&Rfc3339).unwrap()),
            ..Default::default()
        };

        // 24 h threshold, last refresh 48 h ago → stale.
        assert!(
            is_stale_for_dto(&dto, 86_400, now),
            "48h-old refresh against 24h threshold must be flagged stale"
        );

        // Render integration: the rendered row must contain "Stale".
        let meta = ListRowMeta {
            dto,
            display_name: "Privacy: Ads".into(),
            canonical_id: Some("privacy-ads".into()),
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            format: Some(BlocklistFormat::Domains),
            used_by_profiles: Vec::new(),
            is_stale: true,
            inert_reason: None,
        };
        let rendered = row_text(&render_list_row(meta));
        assert!(
            rendered.contains("Stale"),
            "row text must surface the Stale badge: {rendered}"
        );
    }

    /// §4.7 Phase 2 T2: when the most recent successful refresh is
    /// inside the window, the predicate returns `false` and the row
    /// renders without any badge. Also covers the `None` (never
    /// refreshed) case — badge suppressed by design, the existing
    /// `never` status column already carries that signal.
    #[test]
    fn stale_badge_absent_when_within_threshold() {
        let now = OffsetDateTime::now_utc();
        let one_hour_ago = now - time::Duration::hours(1);
        let fresh_dto = BlocklistStatusDto {
            source: "privacy/ads".into(),
            id: Some("privacy-ads".into()),
            last_outcome: "ok".into(),
            last_refresh_at: Some(one_hour_ago.format(&Rfc3339).unwrap()),
            ..Default::default()
        };
        assert!(
            !is_stale_for_dto(&fresh_dto, 86_400, now),
            "1h-old refresh against 24h threshold must NOT be stale"
        );

        let never_refreshed_dto = BlocklistStatusDto {
            source: "privacy/ads".into(),
            id: Some("privacy-ads".into()),
            last_outcome: "never_fetched".into(),
            last_refresh_at: None,
            ..Default::default()
        };
        assert!(
            !is_stale_for_dto(&never_refreshed_dto, 86_400, now),
            "None last_refresh_at must suppress the badge (operator sees `never` in status)"
        );

        // Render integration: fresh row must NOT contain "Stale".
        let meta = ListRowMeta {
            dto: fresh_dto,
            display_name: "Privacy: Ads".into(),
            canonical_id: Some("privacy-ads".into()),
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            format: Some(BlocklistFormat::Domains),
            used_by_profiles: Vec::new(),
            is_stale: false,
            inert_reason: None,
        };
        let rendered = row_text(&render_list_row(meta));
        assert!(
            !rendered.contains("Stale"),
            "fresh row text must NOT include the Stale badge: {rendered}"
        );
    }

    // ── rev-2607: the stable selection key ──────────────────────────

    #[test]
    fn row_key_keys_on_canonical_id_or_source() {
        // A managed row keys on its canonical id; a true orphan (no
        // `[[blocklists]]` entry) keys on its source string. Both spaces
        // are prefixed, so a list whose id is `x` can never collide with
        // an orphan whose source string happens to be `x`.
        let managed = meta_with(Some("oisd"), "https://example.test/oisd.txt");
        let orphan = meta_with(None, "oisd");
        assert_eq!(row_key(&managed), Some("id:oisd".to_string()));
        assert_eq!(row_key(&orphan), Some("src:oisd".to_string()));
    }

    fn meta_with(canonical_id: Option<&str>, source: &str) -> ListRowMeta {
        ListRowMeta {
            dto: BlocklistStatusDto {
                source: source.to_string(),
                id: canonical_id.map(|s| s.to_string()),
                ..Default::default()
            },
            display_name: "—".into(),
            canonical_id: canonical_id.map(|s| s.to_string()),
            base: BlocklistBase::default(),
            trust: BlocklistTrust::default(),
            format: None,
            used_by_profiles: Vec::new(),
            is_stale: false,
            inert_reason: None,
        }
    }

    // ── inert-list badge ────────────────────────────────────────────
    //
    // Mirrors `validator.rs`'s inert-list predicate (never re-derives it):
    // a list whose `base` is `ignore` and which no profile overrides to
    // anything else. The fixtures below load through the real
    // `config::loader::load_config`, so what they assert is what an
    // operator's config would actually produce.
    //
    // This comment used to describe TWO predicates — "allow-list with no
    // tags" and "tags reach no device/profile/subnet" — and said the loader
    // "also runs `auto_promote_blocklists`", so a `base = deny` fixture
    // needed explicit tags to keep that pass a no-op. All three premises
    // died with the tag model: both predicates lost their subject, and the
    // promotion pass does not exist anywhere in `src/`. Rewritten rather
    // than deleted because the *invariant* it protects is still live and is
    // the reason these fixtures go through the loader at all — the badge
    // must not re-derive a rule the validator owns.

    fn dto_for(id: &str, url: &str) -> BlocklistStatusDto {
        BlocklistStatusDto {
            source: url.to_string(),
            id: Some(id.to_string()),
            entries: 10,
            last_outcome: "ok".into(),
            ..Default::default()
        }
    }

    /// One profile ("home", tags=["ads"]), one deny list tagged "ads".
    /// Every list has effect — the zero-inert control fixture.
    fn app_with_no_inert_lists() -> App {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "home"

[profiles.home]
display_name = "Home"
tags = ["ads"]

[[blocklists]]
id = "healthy"
display_name = "Healthy List"
url = "https://example.com/healthy.txt"
tags = ["ads"]
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.lists.entries = vec![dto_for("healthy", "https://example.com/healthy.txt")];
        app.loaded_config = Some(loaded);
        app
    }

    /// Same "home" profile plus a healthy control list and a `base =
    /// "ignore"` list.
    ///
    /// **`plp-s5d` rewrote this fixture, and the rewrite is a correction
    /// rather than a rename.** It used to build an untagged allow-list and
    /// a list tagged with a slug nobody carries, because
    /// `inert_blocklists` produced `AllowListNoTags` / `TagsMatchNothing`.
    /// `plp-s5b` retired both variants — an allow-direction list is now
    /// inherited by every profile that does not override it, so calling it
    /// inert asserted the opposite of the truth — and `BaseIgnore` is the
    /// only reason the predicate emits. A fixture that cannot produce the
    /// surviving variant tests nothing.
    ///
    /// The `mycompany` allow-list is KEPT, with its assertion inverted to
    /// `None`: it is the control arm that proves the retirement, and
    /// without it this file would have no test noticing if the old
    /// dead-premise variant came back.
    fn app_with_two_inert_lists() -> App {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "home"

[profiles.home]
display_name = "Home"
tags = ["ads"]

[[blocklists]]
id = "healthy"
display_name = "Healthy List"
url = "https://example.com/healthy.txt"
tags = ["ads"]

[[blocklists]]
id = "mycompany"
display_name = "My Company Allow"
url = "https://example.com/mycompany.txt"
base = "allow"
trust = "local"
tags = []

[[blocklists]]
id = "orphaned"
display_name = "Ignored List"
url = "https://example.com/orphaned.txt"
base = "ignore"
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.lists.entries = vec![
            dto_for("healthy", "https://example.com/healthy.txt"),
            dto_for("mycompany", "https://example.com/mycompany.txt"),
            dto_for("orphaned", "https://example.com/orphaned.txt"),
        ];
        app.loaded_config = Some(loaded);
        app
    }

    #[test]
    fn inert_reason_flags_base_ignore_and_not_an_untagged_allow_list() {
        let app = app_with_two_inert_lists();
        let rows = build_grouped_rows(&app);
        let reason_for = |id: &str| {
            rows.iter()
                .find(|m| m.canonical_id.as_deref() == Some(id))
                .and_then(|m| m.inert_reason.clone())
        };
        assert_eq!(
            reason_for("healthy"),
            None,
            "a deny list the profile does not override must not be flagged inert"
        );
        // **The control arm.** An untagged allow-list is reached by every
        // profile that does not override it, so it is NOT inert. This
        // asserted the opposite until `plp-s5b`, and the assertion is kept
        // inverted rather than deleted so a revival of the dead-premise
        // variant goes red here.
        assert_eq!(
            reason_for("mycompany"),
            None,
            "an untagged allow-list is inherited, not inert"
        );
        assert_eq!(
            reason_for("orphaned"),
            Some(format_base_ignore_list_is_inert("orphaned")),
            "base = ignore is the one reason the predicate still emits"
        );
    }

    #[test]
    fn inert_reason_none_when_only_a_group_tag_reaches_the_list() {
        // Regression for the exact bug lane `cli-write-paths` found in
        // validator.rs's `check_tag_intersections`: a list reached only
        // through `group.tags` (no device/profile/subnet carries the
        // tag directly) must NOT be flagged inert. Now exercises
        // `validator::inert_blocklists` directly via `build_grouped_rows`,
        // so this is a live regression guard, not a copy that can drift.
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "home"

[profiles.home]
display_name = "Home"

[[groups]]
id = "iot"
display_name = "IoT"
profile = "home"
tags = ["iot-only"]

[[blocklists]]
id = "group-reached"
display_name = "Group Reached"
url = "https://example.com/group-reached.txt"
tags = ["iot-only"]
"#,
        )
        .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let mut app = App::new();
        app.lists.entries = vec![dto_for(
            "group-reached",
            "https://example.com/group-reached.txt",
        )];
        app.loaded_config = Some(loaded);

        let rows = build_grouped_rows(&app);
        let meta = rows
            .iter()
            .find(|m| m.canonical_id.as_deref() == Some("group-reached"))
            .unwrap();
        assert_eq!(
            meta.inert_reason, None,
            "a list reached only via a group tag must not be flagged inert"
        );
    }

    #[test]
    fn inert_reason_is_none_when_schema_entry_missing() {
        // Orphan row: DTO with no matching `[[blocklists]]` entry —
        // nothing to judge, must not be flagged.
        let app = App::new();
        let dto = dto_for("ghost", "https://example.com/ghost.txt");
        let meta = build_meta(&app, &dto, &std::collections::HashMap::new());
        assert_eq!(meta.inert_reason, None);
    }

    #[test]
    fn row_text_shows_warning_glyph_only_on_inert_rows() {
        let app = app_with_two_inert_lists();
        let rows = build_grouped_rows(&app);
        for row in rows {
            let inert = row.inert_reason.is_some();
            let id = row.canonical_id.clone().unwrap();
            let text = row_text(&render_list_row(row));
            assert_eq!(
                text.contains('\u{26A0}'),
                inert,
                "row \"{id}\" badge glyph presence must match inert_reason: {text}"
            );
        }
    }

    #[test]
    fn inert_badge_survives_a_long_display_name() {
        // The badge lives in its own fixed-width gutter column
        // (`Constraint::Length(2)`), independent of DISPLAY — a long
        // name must truncate itself, never the badge next to it.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut meta = test_meta("longname");
        meta.display_name = "X".repeat(200);
        meta.inert_reason = Some("dummy reason for the long-name regression test".to_string());

        let app = App::new();
        let backend = TestBackend::new(170, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_table(f, f.area(), &app, std::slice::from_ref(&meta));
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            dump.contains('\u{26A0}'),
            "badge glyph must survive a 200-char display_name:\n{dump}"
        );
    }

    #[test]
    fn render_shows_no_badge_and_no_summary_when_fleet_is_healthy() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = app_with_no_inert_lists();
        let backend = TestBackend::new(170, 16);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, f.area(), &app);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            !dump.contains('\u{26A0}'),
            "a healthy fleet must render no inert badge:\n{dump}"
        );
        assert!(
            !dump.contains("filtering nothing"),
            "a healthy fleet must render no summary noise:\n{dump}"
        );
    }

    #[test]
    fn render_shows_badge_and_pinned_summary_when_fleet_has_inert_lists() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = app_with_two_inert_lists();
        let backend = TestBackend::new(170, 16);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, f.area(), &app);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            dump.contains('\u{26A0}'),
            "an inert fleet must render the badge glyph:\n{dump}"
        );
        // `plp-s5d`: ONE, not two. The fixture used to carry an untagged
        // allow-list and a tags-match-nothing list; `plp-s5b` retired both
        // reasons, so only the `base = ignore` list is inert now. The lede
        // is singular, which is itself the pin — a count that silently
        // tracked the fixture would not notice a reason coming back.
        assert!(
            dump.contains("1 list is filtering nothing:"),
            "summary lede must be pinned exactly:\n{dump}"
        );
        // Word-wrap pads every wrapped row out to the paragraph's full
        // width and `dump_buffer` joins rows with `\n`, so a formatter
        // sentence that wraps mid-phrase no longer appears as one
        // contiguous substring even though every word is genuinely on
        // screen — collapsing whitespace runs first checks the same
        // claim (full sentence, reused verbatim) without depending on
        // exactly where the wrap fell.
        let normalized = dump.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            normalized.contains(&format_base_ignore_list_is_inert("orphaned")),
            "summary must reuse the base-ignore formatter verbatim:\n{dump}"
        );
        // The control arm again: the untagged allow-list must NOT appear
        // in the summary.
        //
        // **Scoped to the summary, and that is the whole correction.** This
        // used to scan the entire screen dump, which also contains the Lists
        // TABLE — and `mycompany` is legitimately a row in it. The assertion
        // therefore asked "is this string anywhere on screen", when what it
        // means is "is this list named as filtering nothing".
        //
        // It passed anyway until the tab-removal cascade changed the layout:
        // with two inert reasons the summary wrapped further, pushed the
        // table down, and the row fell off a 16-row terminal. A control arm
        // that holds because its subject scrolled out of view is not a
        // control arm — it is a coincidence with an assertion attached, and
        // it fails the first time the layout moves for an unrelated reason.
        let summary = normalized.split("Lists (").next().unwrap_or(&normalized);
        assert!(
            !summary.contains("mycompany"),
            "an untagged allow-list is inherited, not inert — it must not be \
             listed as filtering nothing:\n{dump}"
        );
    }

    // ── Variant-A modal-ecosystem redesign: render contract ─────────
    // These pin the new banded/sectioned modal_form-style layout that
    // supersedes the flat 20-row hand-rolled grid.

    fn render_edit_modal_to_string(modal: &EditListModal) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_edit_modal(f, f.area(), modal))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    // `plp-s5d` removed the four §4.65 UX2 render tests that sat here
    // (`the_tags_suggestions_row_renders_with_its_key_named`,
    // `the_armed_valve_shows_the_confirm_without_hiding_the_near_miss`,
    // `the_unarmed_picker_shows_no_confirm`,
    // `the_tags_suggestions_row_is_absent_when_tags_is_not_focused`).
    //
    // They were a well-built set — each one existed because its sibling
    // could otherwise pass for the wrong reason, and the last two are
    // there purely so the first two are measuring a state CHANGE and not
    // permanent chrome. All four render the tag chip picker, which this
    // lane deleted; there is no substitute surface, so the guarantees go
    // with it rather than being retargeted.

    #[test]
    fn section_header_carries_a_full_width_background_band() {
        let [header, _rule] = modal_form::section_band("Identity", 60);
        // First span = the teal, bold label on the bg_surface band.
        let first = &header.spans[0];
        assert_eq!(
            first.style.bg,
            Some(T.bg_surface),
            "section header label must sit on a background band"
        );
        assert!(first.content.contains("IDENTITY"));
        // Last span = trailing pad, also banded → the band fills the row.
        let last = header.spans.last().unwrap();
        assert_eq!(
            last.style.bg,
            Some(T.bg_surface),
            "the band must fill the full row width"
        );
    }

    // `plp-s5d` removed
    // `edit_modal_focused_tags_row_does_not_overflow_with_inline_hint`.
    // It pinned that the tags row's old inline "(type / ↑↓ pick / …)" hint
    // stayed dropped, because it used to overflow the modal body and clip
    // mid-word. The row it guarded is gone, so the overflow it guarded
    // against is unreachable.
    //
    // **No substitute, and the honest version of that matters here.** The
    // first draft of this note claimed the property was "still covered for
    // every surviving field" by a ring-wide sweep. There is no such test:
    // `no_desc_row_outruns_the_narrow_build_pass` bounds the description
    // band only, and the ring-wide sweep that does exist
    // (`emerald_marks_exactly_one_row_whatever_holds_focus`) measures focus
    // colour, not
    // width. A per-field overflow guard existed for exactly one field —
    // this one — and it leaves with the field.

    /// A render test, because a handler test cannot see this.
    ///
    /// The nature row is built inside the body function; every state
    /// transition into and out of `Ignore` is exercised by handler tests
    /// that never look at a cell. `radio_row` takes ONE bool, so the naive
    /// wiring renders `Ignore` as "Allow selected" — the form asserting the
    /// opposite of the file, on the field that decides whether domains get
    /// blocked. That defect is invisible to everything except the buffer.
    #[test]
    fn edit_modal_never_renders_base_ignore_as_allow() {
        let mut modal = build_add_modal();
        modal.nature = BlocklistBase::Ignore;
        let s = render_edit_modal_to_string(&modal);
        assert!(
            s.contains("Ignore"),
            "an inert list must say so on the nature row:\n{s}"
        );

        // The discriminating half: the two-way radio must be GONE, not
        // merely joined by the word. Asserting only on "Ignore" passes on a
        // render that shows `Block ● Allow` with "Ignore" printed elsewhere.
        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !flat.contains("Block") && !flat.contains("Allow"),
            "the two-state radio must not render for a three-state value:\n{s}"
        );

        // Control arm: the ordinary states still get the radio, so this
        // test cannot pass by the row having disappeared altogether.
        let mut deny = build_add_modal();
        deny.nature = BlocklistBase::Deny;
        let flat_deny = render_edit_modal_to_string(&deny)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat_deny.contains("Block") && flat_deny.contains("Allow"),
            "Deny must still render the Block/Allow radio:\n{flat_deny}"
        );
    }

    /// The hint under the nature row is the only thing that tells an
    /// operator the arrows are a one-way door out of `Ignore`.
    #[test]
    fn the_nature_hint_states_what_ignore_means_and_where_the_arrows_go() {
        let h = edit_focus_hint(
            EditField::Nature,
            &EditModalMode::Edit,
            BlocklistBase::Ignore,
        );
        assert!(h.contains("Inert"), "the hint must name the state: {h:?}");
        assert!(
            h.contains("Block"),
            "the hint must name where the arrows lead: {h:?}"
        );
        assert_ne!(
            h,
            edit_focus_hint(EditField::Nature, &EditModalMode::Edit, BlocklistBase::Deny),
            "the Ignore hint must differ from the binary one"
        );
    }

    #[test]
    fn edit_modal_renders_three_named_sections() {
        let s = render_edit_modal_to_string(&build_add_modal());
        for section in ["IDENTITY", "SOURCE", "FILTERING"] {
            assert!(s.contains(section), "missing section {section}:\n{s}");
        }
    }

    /// **DoD 3 for this modal: a RENDER assertion, not a row count.**
    ///
    /// The other two guards on this form are line-vector arithmetic
    /// (`collapsed_modal_holds_its_row_budget`, 25 -> 24). Those are
    /// mutation-sensitive — a returning row breaks the sum — but they
    /// cannot see the *buffer*, and every past instance of a clip defect
    /// in this file had a correct vector and a wrong render.
    ///
    /// **The positive pair is what makes the negative non-vacuous.**
    /// `nature` and `active` are the rows that bracketed the tags picker:
    /// it sat between them in the FILTERING section. Asserting both are on
    /// screen proves the buffer rendered the region the picker occupied,
    /// so its absence is a removal rather than something below the fold —
    /// the deletion-lane trap this sprint is full of. 100x44 is the same
    /// backend the sibling render tests use, comfortably taller than the
    /// 24-row body.
    #[test]
    fn edit_modal_renders_no_tags_row_between_nature_and_active() {
        let s = render_edit_modal_to_string(&build_add_modal());
        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(
            flat.contains("nature"),
            "the row above where tags sat did not render:\n{s}"
        );
        assert!(
            flat.contains("active"),
            "the row below where tags sat did not render:\n{s}"
        );
        assert!(
            !flat.contains("tags"),
            "the tags chip-picker row is still rendered by the Lists edit \
             modal:\n{s}"
        );
    }

    #[test]
    fn edit_modal_collapsed_hides_advanced_fields_behind_toggle() {
        // build_add_modal starts collapsed.
        let s = render_edit_modal_to_string(&build_add_modal());
        assert!(s.contains("Advanced"), "advanced toggle absent:\n{s}");
        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !flat.contains("auth token"),
            "auth-token field must be hidden when collapsed:\n{s}"
        );
    }

    #[test]
    fn edit_modal_expanded_reveals_advanced_fields() {
        let mut modal = build_add_modal();
        modal.advanced_expanded = true;
        let s = render_edit_modal_to_string(&modal);
        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("auth token"), "auth-token revealed:\n{s}");
        assert!(s.to_lowercase().contains("format"), "format revealed:\n{s}");
    }

    #[test]
    fn edit_modal_add_mode_has_cancel_and_save_but_no_delete_button() {
        let s = render_edit_modal_to_string(&build_add_modal());
        assert!(s.contains("Save"), "Save button absent:\n{s}");
        assert!(s.contains("Cancel"), "Cancel button absent:\n{s}");
        assert!(
            !s.contains("Delete"),
            "Add mode must not offer a Delete button:\n{s}"
        );
    }

    #[test]
    fn edit_modal_edit_mode_offers_delete_button() {
        let mut modal = build_add_modal();
        modal.mode = EditModalMode::Edit;
        modal.blocklist_id = "privacy-ads".into();
        let s = render_edit_modal_to_string(&modal);
        assert!(
            s.contains("Delete"),
            "Edit mode must offer a Delete button:\n{s}"
        );
    }

    /// Row-by-row cell-symbol dump — no ANSI ever enters a `TestBackend`
    /// `Buffer` (styling is a separate `Style` field per cell, not
    /// interleaved escape codes), so this is a faithful plain-text
    /// reconstruction of what's on screen. Mirrors `dashboard.rs`'s
    /// helper of the same shape.
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

    // ── tui-blind-to-corpus-refusal ────────────────────────────────────
    //
    // Every test below renders to a buffer and asserts on cells. That is
    // not stylistic: the defect being fixed is *what the operator sees*,
    // and a test that set `daemon_status` and then asserted on
    // `app.daemon_status` would pass whether or not a single glyph
    // reached the screen.

    /// A `DaemonStatus` carrying a standing refusal.
    ///
    /// `lists_active == lists_total` and both non-zero **on purpose** —
    /// that is the whole defect. Every source fetched, so the health
    /// fraction is truthfully `8/8` while nothing is being served.
    fn status_with_refusal(domain_count: usize) -> crate::tui::app::DaemonStatus {
        crate::tui::app::DaemonStatus {
            domain_count,
            lists_active: 8,
            lists_total: 8,
            lists_corpus_refusal: Some(crate::lists::status::CorpusRefusal {
                unique: 14_200_000,
                ceiling: 14_000_000,
                novel_by_source: vec![("privacy-ads".to_string(), 2_100_000)],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn lists_tab_names_the_corpus_refusal_in_the_rendered_buffer() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = app_with_no_inert_lists();
        app.daemon_status = Some(status_with_refusal(500_000));

        let backend = TestBackend::new(170, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            dump.contains("CORPUS REFUSED"),
            "a refused corpus must be visible without leaving the TUI:\n{dump}"
        );
        assert!(
            dump.contains("14000000"),
            "the band must name the ceiling that was exceeded — a refusal the \
             operator cannot act on is only half a diagnostic:\n{dump}"
        );
        assert!(
            dump.contains("privacy-ads"),
            "the largest contributor is the one field that says what to remove:\n{dump}"
        );
    }

    /// The worst state the daemon has: up, listening, filtering nothing.
    ///
    /// Distinguished from the previous-generation case because a bare `0`
    /// beside a refusal reads as an ordinary counter.
    #[test]
    fn zero_installed_domains_under_a_refusal_says_unfiltered() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = app_with_no_inert_lists();
        app.daemon_status = Some(status_with_refusal(0));

        let backend = TestBackend::new(170, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            dump.contains("UNFILTERED"),
            "zero installed domains under a refusal means DNS is answering \
             unfiltered, and that must be said outright:\n{dump}"
        );
    }

    /// Same fixture, refusal swapped for `None` — the arms differ by one
    /// field, so a band that rendered unconditionally fails here while
    /// every assertion above still passes.
    #[test]
    fn a_healthy_corpus_renders_no_refusal_band() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = app_with_no_inert_lists();
        app.daemon_status = Some(crate::tui::app::DaemonStatus {
            domain_count: 500_000,
            lists_active: 8,
            lists_total: 8,
            lists_corpus_refusal: None,
            ..Default::default()
        });

        let backend = TestBackend::new(170, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            !dump.contains("CORPUS REFUSED"),
            "a healthy corpus must not raise a refusal band:\n{dump}"
        );
        assert!(
            !dump.contains("UNFILTERED"),
            "a healthy corpus must not claim DNS is unfiltered:\n{dump}"
        );
    }

    /// The band must not cost the table its rows.
    ///
    /// It is inserted above a layout that was already tuned to a 24-row
    /// floor, so the arithmetic is worth pinning: at the declared minimum
    /// the list the operator came here to read must still be on screen.
    #[test]
    fn the_refusal_band_does_not_push_the_table_off_an_80x24_screen() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = app_with_no_inert_lists();
        app.daemon_status = Some(status_with_refusal(0));

        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        assert!(
            dump.contains("CORPUS REFUSED"),
            "the band must survive the 80x24 floor:\n{dump}"
        );
        assert!(
            dump.contains("Healthy List"),
            "the band must not evict the table it sits above:\n{dump}"
        );
    }

    // ── palette spec v1 ────────────────────────────────────────────────

    /// Like [`render_edit_modal_to_string`] but hands back the buffer, so
    /// a test can read per-cell *style*. `dump_buffer` throws styling away.
    fn render_edit_modal_to_buffer(modal: &EditListModal) -> ratatui::buffer::Buffer {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_edit_modal(f, f.area(), modal))
            .unwrap();
        term.backend().buffer().clone()
    }

    fn flatten(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn emerald_marks_exactly_one_row_whatever_holds_focus() {
        // Spec §8 acceptance check 2. Stated as "at most once per frame",
        // but a raw span count is the wrong unit — the focused row legally
        // carries a rule, a marker and a dot. The checkable invariant is
        // that emerald never appears on two different ROWS, because it is
        // the answer to "where am I" and two answers make it a lie.
        for focus in [
            EditField::DisplayName,
            EditField::ListId,
            EditField::Url,
            EditField::Advanced,
            EditField::Nature,
            EditField::Enabled,
            EditField::Cancel,
            EditField::Save,
        ] {
            let mut modal = build_add_modal();
            modal.focus = focus;
            let buf = render_edit_modal_to_buffer(&modal);
            let mut rows = std::collections::BTreeSet::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    if buf[(x, y)].fg == T.emerald_ping {
                        rows.insert(y);
                    }
                }
            }
            assert!(
                rows.len() <= 1,
                "focus {focus:?} lit emerald on rows {rows:?} — focus must have one answer"
            );
        }
    }

    #[test]
    fn trust_state_drives_both_colour_and_explanation() {
        // Spec §8 acceptance check 4: toggling trust must change colour
        // AND show/hide the plain-language tail. Colour alone tells an
        // operator who has not read the palette guide nothing.
        let unsigned = edit_trust_row(BlocklistTrust::RemoteUnsigned, 62);
        let text = flatten(&unsigned);
        assert!(
            text.contains("contents unverified"),
            "unsigned trust must explain itself: {text}"
        );
        assert!(
            unsigned
                .spans
                .iter()
                .any(|s| s.style.fg == Some(T.scope_content)),
            "unsigned trust must read as caution"
        );

        for verified in [BlocklistTrust::Local, BlocklistTrust::Signed] {
            let row = edit_trust_row(verified, 62);
            let text = flatten(&row);
            assert!(
                !text.contains("unverified"),
                "{verified:?} must not carry the caution tail: {text}"
            );
            assert!(
                row.spans
                    .iter()
                    .any(|s| s.style.fg == Some(T.scope_security)),
                "{verified:?} must read as healthy"
            );
        }
    }

    #[test]
    fn trust_tail_is_dropped_not_clipped_when_it_does_not_fit() {
        // The body does not wrap, so an over-wide line is cut mid-word
        // rather than reflowed. An explanation that cannot fit is worth
        // less than a clean row.
        let narrow = edit_trust_row(BlocklistTrust::RemoteUnsigned, 30);
        let text = flatten(&narrow);
        assert!(!text.contains("unverified"), "tail must drop: {text}");
        assert!(
            text.contains("remote-unsigned"),
            "the state itself must survive: {text}"
        );
    }

    #[test]
    fn radio_rows_colour_by_meaning_not_by_slot() {
        // Spec §8 acceptance check 3: colour derives from the state enum,
        // never from which side of the row a word sits on. Same widget,
        // same positions, opposite selection ⇒ the colours swap sides.
        let nature = |left_selected| {
            modal_form::radio_row(
                "nature",
                ("Block", ValueKind::Blocking),
                ("Allow", ValueKind::Healthy),
                left_selected,
                false,
                62,
            )
        };
        let blocking = nature(true);
        assert!(blocking
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.red_glow) && s.content.contains("Block")));
        assert!(blocking
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.text_disabled) && s.content.contains("Allow")));

        let allowing = nature(false);
        assert!(allowing
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.scope_security) && s.content.contains("Allow")));
        assert!(allowing
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.text_disabled) && s.content.contains("Block")));
    }

    #[test]
    fn semantic_colour_never_rides_the_focus_bar() {
        // Every semantic hue falls under WCAG's 3:1 large-text floor
        // against bg_highlight (red_glow 2.62, slate 3.60, teal 3.37), so
        // a focused row renders text_primary and gets its meaning back the
        // moment focus leaves. Pinned in
        // theme::tests::focus_bar_admits_only_high_contrast_foregrounds.
        let focused_radio = modal_form::radio_row(
            "nature",
            ("Block", ValueKind::Blocking),
            ("Allow", ValueKind::Healthy),
            true,
            true,
            62,
        );
        assert!(
            focused_radio
                .spans
                .iter()
                .all(|s| s.style.fg != Some(T.red_glow)),
            "red_glow measures 2.62:1 on the focus bar"
        );

        let at_rest =
            modal_form::value_row("url", "https://x/y", false, ValueKind::Identity, None, 62);
        assert!(
            at_rest
                .spans
                .iter()
                .any(|s| s.style.fg == Some(T.scope_privacy)),
            "a url is identity-coloured at rest"
        );
        let focused =
            modal_form::value_row("url", "https://x/y", true, ValueKind::Identity, None, 62);
        assert!(
            focused
                .spans
                .iter()
                .all(|s| s.style.fg != Some(T.scope_privacy)),
            "slate measures 3.60:1 on the focus bar"
        );
        assert!(focused
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.text_primary)));
    }

    #[test]
    fn focus_rule_replaces_the_indent_so_the_value_column_never_shifts() {
        // The rule eats the 2-cell lead rather than adding to it. If it
        // ever adds, every value jogs right on focus AND the hardware
        // cursor (which is placed at modal_form::VALUE_COL) lands off the text.
        // Cells, not bytes: the focus rule `▌` is 3 bytes of UTF-8 but one
        // column, and every column constant here is in cells.
        let col = |line: &Line<'static>| {
            let s = flatten(line);
            let at = s.find("VALUE").unwrap();
            s[..at].chars().count()
        };
        let at_rest = modal_form::value_row("url", "VALUE", false, ValueKind::Identity, None, 62);
        let focused = modal_form::value_row("url", "VALUE", true, ValueKind::Identity, None, 62);
        assert_eq!(
            col(&at_rest),
            col(&focused),
            "value column shifted on focus"
        );
        assert_eq!(
            col(&at_rest),
            modal_form::VALUE_COL,
            "cursor placement maths depends on this column"
        );
    }

    #[test]
    fn save_is_the_only_filled_button() {
        // Spec §4: one filled button per modal, and destructive actions
        // are outlined — a filled red beside a filled primary is how an
        // operator deletes the list they meant to save.
        let row = modal_form::action_row(
            &[
                modal_form::Action::new(
                    "  Delete  ",
                    true,
                    modal_form::ActionKind::Destructive,
                    "",
                ),
                modal_form::Action::new("  Cancel  ", false, modal_form::ActionKind::Neutral, ""),
                modal_form::Action::new("  Save  ", false, modal_form::ActionKind::Primary, ""),
            ],
            62,
        );
        let filled: Vec<_> = row.spans.iter().filter(|s| s.style.bg.is_some()).collect();
        assert_eq!(filled.len(), 1, "exactly one button may be filled");
        assert_eq!(filled[0].style.bg, Some(T.warden_teal));
        assert!(filled[0].content.contains("Save"));
        assert!(
            row.spans.iter().all(|s| s.style.bg != Some(T.brand_red)),
            "a focused Delete must not become a red slab"
        );
    }

    #[test]
    fn button_row_width_is_identical_focused_and_unfocused() {
        // The focus marker occupies one cell either way, so gaining focus
        // must not reflow the row.
        let build = |focused| {
            modal_form::action_row(
                &[
                    modal_form::Action::new(
                        "  Cancel  ",
                        focused,
                        modal_form::ActionKind::Neutral,
                        "",
                    ),
                    modal_form::Action::new(
                        "  Save  ",
                        !focused,
                        modal_form::ActionKind::Primary,
                        "",
                    ),
                ],
                62,
            )
        };
        assert_eq!(
            flatten(&build(true)).chars().count(),
            flatten(&build(false)).chars().count()
        );
    }

    #[test]
    fn collapsed_modal_holds_its_row_budget() {
        // The palette spec asked for 1.9x line-height. `ui.rs` declares
        // MIN_HEIGHT 24 and this modal already needs 26 rows with
        // Advanced collapsed; a blank row between every field would push
        // it past 37 and need a 41-row terminal. The spacing was rejected
        // to hold this number — so pin it, or it will creep back.
        //
        // 24 → 25 on 2026-08-07: `new_desc2` made the head 4 rows instead
        // of 3. That is the whole delta and it is deliberate — the number
        // exists to catch *creep*, so it moves when a change owns the row
        // and stays put otherwise.
        //
        // 25 → 24 on `plp-s5d`: the tags chip-picker row left the FIELD
        // region. Same rule as above, in the cheap direction — a change
        // that owns the row moves the number. The head is unchanged at 4,
        // which is why that half is asserted separately: it localises any
        // future move to the half that actually shifted.
        let (body, _) = edit_form_body(&build_add_modal(), 62);
        let total = body.head.len() + body.fields.len() + body.tail.len();
        assert_eq!(total, 24, "collapsed body grew to {total} rows (+2 frame)");
        assert_eq!(
            body.head.len(),
            4,
            "title band + 2 description rows + spacer"
        );
    }

    /// Render the modal into an arbitrarily sized anchor — the point of the
    /// viewport work is what happens when the anchor is too short, so tests
    /// need to choose that size.
    fn render_edit_modal_in(modal: &EditListModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_edit_modal(f, f.area(), modal))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    #[test]
    fn button_row_survives_the_declared_minimum_terminal() {
        // THE regression. `ui.rs` declares MIN_HEIGHT 24; at that size a leaf
        // tab's content area is ~14 rows, and the modal wants 26. Before the
        // viewport it rendered flat and was simply cut after `trust` — Save
        // and Cancel were off-screen while Tab still moved focus onto them,
        // so the operator committed or discarded blind. Verified against the
        // shipped v0.24.3/v0.24.4 binaries at 80x24 before the fix.
        let s = render_edit_modal_in(&build_add_modal(), 80, 14);
        assert!(s.contains("Save"), "Save unreachable at 80x24:\n{s}");
        assert!(s.contains("Cancel"), "Cancel unreachable at 80x24:\n{s}");
        // And the title must survive too — you have to know what you're editing.
        assert!(s.contains("Add list"), "title band lost:\n{s}");
    }

    /// §4.68 DoD, **at the floor**: the two description rows are on screen,
    /// they carry the title band's `Rgb(51,51,51)` in teal
    /// `Rgb(13,148,136)`, and `Save` / `Cancel` survived the head growing.
    ///
    /// All three modes, because `edit_band_text` gives each its own copy
    /// and a mode whose second row was never written would otherwise ship
    /// a half-empty band. Promote is built by hand — `build_add_modal`
    /// only reaches `Add`.
    #[test]
    fn floor_the_description_band_renders_on_its_own_strip_with_the_actions() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut promote = build_add_modal();
        promote.mode = EditModalMode::Promote {
            source: "https://example.invalid/orphan.txt".into(),
        };
        let mut edit = build_add_modal();
        edit.mode = EditModalMode::Edit;
        edit.blocklist_id = "privacy-ads".into();

        for (name, modal) in [
            ("Add", build_add_modal()),
            ("Promote", promote),
            ("Edit", edit),
        ] {
            let (_, desc) = edit_band_text(&modal);
            let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
            term.draw(|f| render_edit_modal(f, f.area(), &modal))
                .unwrap();
            println!("--- {name} ---");
            modal_form::desc_band2_assert::assert_two_row_band(
                term.backend().buffer(),
                desc,
                &["Save", "Cancel"],
            );
        }
    }

    /// The copy ships at a width, so the width is a test rather than a
    /// comment. `render_body_fixed` does not wrap and prints no marker
    /// where it cuts.
    #[test]
    fn no_desc_row_outruns_the_narrow_build_pass() {
        // −2 chrome, −1 for the scrollbar column on the narrow pass,
        // −2 for `desc_band2`'s indent.
        const BUDGET: usize = MODAL_W as usize - 5;
        let mut promote = build_add_modal();
        promote.mode = EditModalMode::Promote {
            source: "https://example.invalid/orphan.txt".into(),
        };
        let mut edit = build_add_modal();
        edit.mode = EditModalMode::Edit;
        for modal in [build_add_modal(), promote, edit] {
            let (_, desc) = edit_band_text(&modal);
            for line in desc {
                let n = line.chars().count();
                assert!(n <= BUDGET, "description row is {n} cells: {line:?}");
            }
        }
    }

    #[test]
    fn viewport_scrolls_to_whatever_holds_focus() {
        // Focus on the last field must be visible in a short modal, and
        // focus on the first must scroll back. A viewport that only ever
        // shows page one would pass the test above and still be unusable.
        let mut modal = build_add_modal();
        modal.focus = EditField::Enabled;
        let bottom = render_edit_modal_in(&modal, 80, 14);
        assert!(
            bottom.contains("active"),
            "focused last field is off-screen:\n{bottom}"
        );

        modal.focus = EditField::DisplayName;
        let top = render_edit_modal_in(&modal, 80, 14);
        assert!(
            top.contains("display name"),
            "focused first field is off-screen:\n{top}"
        );
        assert!(
            !top.contains("active"),
            "short viewport cannot be showing both ends at once:\n{top}"
        );
    }

    #[test]
    fn scrollbar_appears_only_when_the_field_region_overflows() {
        let tall = render_edit_modal_in(&build_add_modal(), 80, 44);
        assert!(
            !tall.contains('\u{2588}'),
            "no scrollbar when everything fits:\n{tall}"
        );
        let short = render_edit_modal_in(&build_add_modal(), 80, 14);
        assert!(
            short.contains('\u{2588}'),
            "overflowing field region must show a scrollbar:\n{short}"
        );
    }

    #[test]
    fn tail_is_trimmed_from_the_front_so_the_buttons_outlive_the_hints() {
        // Squeezed hard, the modal drops guidance before it drops controls.
        let s = render_edit_modal_in(&build_add_modal(), 80, 8);
        assert!(
            s.contains("Save"),
            "buttons must be the last thing cut:\n{s}"
        );
    }

    #[test]
    fn scroll_body_allocates_tail_before_head_and_fields() {
        // Unit-level pin on the allocation order, independent of the Lists
        // modal's particular row counts.
        let body = modal_form::ScrollBody {
            head: vec![Line::from("HEAD1"), Line::from("HEAD2")],
            fields: (0..20).map(|i| Line::from(format!("F{i}"))).collect(),
            tail: vec![Line::from("HINT"), Line::from("BUTTONS")],
            focus_row: Some(19),
            scrollable: true,
        };
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(20, 6)).unwrap();
        let mut view = None;
        term.draw(|f| view = Some(modal_form::render_scroll_body(f, f.area(), &body)))
            .unwrap();
        let out = dump_buffer(term.backend().buffer());
        let view = view.unwrap();
        assert!(out.contains("BUTTONS"), "tail served first:\n{out}");
        assert!(out.contains("HEAD1"), "head served second:\n{out}");
        assert!(out.contains("F19"), "viewport follows focus_row:\n{out}");
        assert_eq!(view.head_h, 2);
        assert_eq!(view.view_h, 2, "6 rows - 2 tail - 2 head");
        assert_eq!(view.offset, 18, "scrolled so field 19 is the last visible");
        // The predicate the renderer's width decision depends on must agree
        // with what the renderer actually did — one rule, not two.
        assert!(modal_form::will_scroll(6, 2, 20, 2));
        assert!(!modal_form::will_scroll(44, 2, 20, 2));
    }

    #[test]
    #[ignore = "visual aid: cargo test visual_dump -- --ignored --nocapture"]
    fn visual_dump() {
        let mut modal = build_add_modal();
        modal.display_name = "Ads & trackers".into();
        modal.blocklist_id = "ads-trackers".into();
        modal.url = "https://example.org/hosts.txt".into();
        modal.focus = EditField::Url;
        println!("{}", render_edit_modal_to_string(&modal));
        println!("--- squeezed to a 14-row anchor (the 80x24 case) ---");
        println!("{}", render_edit_modal_in(&modal, 80, 14));
        modal.focus = EditField::Enabled;
        println!("--- same, focus on the last field ---");
        println!("{}", render_edit_modal_in(&modal, 80, 14));
    }

    // ── §4.63 S2a — the two remaining Lists overlays ──────────────────
    //
    // `render_delete_confirm` and `render_catalog_picker` are private, so
    // every render assertion about them has to live in this file (F5: the
    // absence of exactly these tests is why F1 shipped and survived).
    //
    // All of them render at **80×14** — the D18 content rect at the
    // declared floor, not an 80×24 frame. `overlay::centered_rect` and
    // `render_modal` both CLAMP to the anchor, so a surface that renders
    // complete against `f.area()` proves nothing about the real anchor.

    fn render_delete_confirm_in(
        modal: &EditListModal,
        typed: &str,
        cascade: &[String],
        w: u16,
        h: u16,
    ) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_delete_confirm(f, f.area(), modal, typed, cascade))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    fn delete_modal_for(id: &str) -> EditListModal {
        let mut modal = build_add_modal();
        modal.blocklist_id = id.to_string();
        modal
    }

    /// F1 (P1). The stage says `type the id`; the row it means was off
    /// screen for every list with ≥1 cascade target — i.e. every list that
    /// is actually filtering something.
    ///
    /// The needle is the operator's PARTIAL buffer, never the id: the id
    /// also appears in the header line six rows higher, so
    /// `contains(&modal.blocklist_id)` passes with the input row clipped.
    /// That was the auditor's first instinct and it is a false green. Do
    /// not "simplify" it back.
    #[test]
    fn floor_delete_confirm_keeps_the_typed_input_on_screen() {
        let modal = delete_modal_for("steven-black-hosts");
        let s = render_delete_confirm_in(&modal, "ZZQQ", &["kids".to_string()], 80, 14);
        assert!(
            s.contains("ZZQQ"),
            "told to type the id, but the input row is off screen:\n{s}"
        );
    }

    /// **The binding case of [`delete_notice`]'s row table — and it only
    /// became reachable in `plp-s4c`.**
    ///
    /// That table calls `>4 targets + a wrapped id` seven prose rows
    /// against a seven-row interior: "the worst case lands exactly on the
    /// budget with nothing to spare". Nothing exercised it. The test above
    /// passes ONE target (five rows) and its sibling passes NONE (four,
    /// with the wrap), so the arm the comment calls binding had never been
    /// rendered.
    ///
    /// It was not reachable in practice either: `compute_cascade_targets`
    /// used to bail to `[]` whenever the list had no tags, which on the two
    /// live hosts is every list — so the confirm was ALWAYS the benign
    /// three-row case. Repairing that predicate is what put a household
    /// config, with more profiles than the `take(4)` cutoff, on the
    /// seven-row path as its normal state.
    ///
    /// So the fence lands in the same commit as the reach. Both halves of
    /// the worst case together: five targets **and** an `Id::MAX_LEN` id
    /// that spends two lines, at the 80x24 floor.
    #[test]
    fn floor_delete_confirm_survives_five_targets_and_a_max_length_id() {
        let modal = delete_modal_for(&"a".repeat(crate::config::schema::Id::MAX_LEN));
        let targets: Vec<String> = ["kids", "guests", "iot", "office", "media"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let s = render_delete_confirm_in(&modal, "ZZQQ", &targets, 80, 14);
        assert!(
            s.contains("ZZQQ"),
            "told to type the id, but the input row is off screen at the \
             worst case the row table names:\n{s}"
        );
        assert!(
            s.contains("+ 1 more"),
            "the residual count must not be swallowed either — it is the \
             row `delete_notice` keeps separate precisely so it cannot \
             be:\n{s}"
        );
    }

    /// Chrome and indents stripped, so a string that had to wrap across
    /// two rows reads back contiguous. `…` is deliberately kept.
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
    /// frame — truncation always eats the tail.
    fn id_of_len(n: usize) -> String {
        format!("delete-me-{}-endsentinel", "x".repeat(n - 22))
    }

    /// The gate compares what was typed against the whole id, so the whole
    /// id has to be on screen. `Id::MAX_LEN` is 64 against 60 usable
    /// cells; the ellipsis made the gate unpassable by any keystroke
    /// sequence, silently.
    ///
    /// Unlike `floor_delete_confirm_keeps_the_typed_input_on_screen` the
    /// needle here IS the id — but recovered from the whole de-chromed
    /// frame, so the header occurrence six rows up cannot stand in for it:
    /// the header is `title_band`, which `fit`s, and a 64-char id never
    /// survives it whole.
    #[test]
    fn delete_confirm_renders_a_max_length_id_in_full_at_the_floor() {
        for n in 55..=64usize {
            let id = id_of_len(n);
            let modal = delete_modal_for(&id);
            let s = render_delete_confirm_in(&modal, "", &[], 80, 14);
            // The id wraps, so its tail is NOT contiguous on one row —
            // that is the fix working. What must never appear is a `…`,
            // and nothing else in this stage is long enough to produce
            // one.
            assert!(
                !s.contains('\u{2026}'),
                "a {n}-char id was ellipsised — the gate compares against \
                 all {n} bytes and the cut ones are unrecoverable:\n{s}"
            );
            assert!(
                dechrome(&s).contains(&id),
                "a {n}-char id is not recoverable from the screen — the \
                 operator cannot type what the gate demands:\n{s}"
            );
        }
    }

    fn render_unsigned_allow_confirm_in(
        list_id: &str,
        typed: &str,
        error: Option<String>,
        w: u16,
        h: u16,
    ) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_unsigned_allow_confirm(f, f.area(), list_id, typed, error.clone()))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// Everything the consent gate says has to be on screen at the
    /// declared floor.
    ///
    /// This body is `scrollable: false` — no `choices`, so no focus
    /// target, so the viewport is pinned at offset 0 and **no scrollbar
    /// is drawn**. Anything past the budget is cut with nothing on
    /// screen admitting it. A row added to `unsigned_allow_notice` would
    /// take the input line the operator is typing into, silently.
    #[test]
    fn floor_unsigned_allow_confirm_keeps_every_row_it_promises() {
        let s = render_unsigned_allow_confirm_in("content-gambling", "ZZQQ", None, 80, 14);
        for needle in [
            UNSIGNED_ALLOW_CONFIRM_TITLE,
            UNSIGNED_ALLOW_CONFIRM_RISK_1,
            UNSIGNED_ALLOW_CONFIRM_RISK_2,
            UNSIGNED_ALLOW_CONFIRM_PROMPT,
        ] {
            assert!(s.contains(needle), "cut at the floor: {needle:?}\n{s}");
        }
        assert!(s.contains("ZZQQ"), "the typed buffer is cut:\n{s}");
        assert!(
            s.contains("Enter Accept"),
            "the action row lost its place:\n{s}"
        );
    }

    /// The error displaces the hint rather than adding a row, so a
    /// mismatch must not push the input off the bottom. The buffer is
    /// what the operator is fixing — losing it is worse than losing the
    /// message about it.
    #[test]
    fn floor_unsigned_allow_confirm_survives_the_mismatch_error() {
        let s = render_unsigned_allow_confirm_in(
            "content-gambling",
            "ZZQQ",
            Some(UNSIGNED_ALLOW_CONFIRM_MISMATCH.to_string()),
            80,
            14,
        );
        assert!(s.contains("ZZQQ"), "the error pushed the input off:\n{s}");
        assert!(
            s.contains("Enter Accept"),
            "the error pushed the action row off:\n{s}"
        );
    }

    /// Same gate as the delete confirm, same reason: the operator has to
    /// type all of `Id::MAX_LEN`, so all of it has to be recoverable
    /// from the screen. `prose_row` ellipsises; `ProseRow::verbatim`
    /// wraps.
    #[test]
    fn unsigned_allow_confirm_renders_a_max_length_id_in_full_at_the_floor() {
        for n in 55..=64usize {
            let id = id_of_len(n);
            let s = render_unsigned_allow_confirm_in(&id, "", None, 80, 14);
            assert!(
                !s.contains('\u{2026}'),
                "a {n}-char id was ellipsised — the gate compares against all \
                 {n} bytes and the cut ones are unrecoverable:\n{s}"
            );
            assert!(
                dechrome(&s).contains(&id),
                "a {n}-char id is not recoverable from the screen:\n{s}"
            );
        }
    }

    /// The empty-cascade path is the one a casual check exercises, which
    /// is why the defect survived. Pin it as a passing companion.
    #[test]
    fn floor_delete_confirm_keeps_the_input_with_no_cascade_targets() {
        let modal = delete_modal_for("steven-black-hosts");
        let s = render_delete_confirm_in(&modal, "ZZQQ", &[], 80, 14);
        assert!(s.contains("ZZQQ"), "no-cascade input row is cut:\n{s}");
    }

    /// The widest body this stage can build: >4 targets adds the `+ N more`
    /// row. It is the case a local `body_area.height` patch would have
    /// left cut.
    #[test]
    fn floor_delete_confirm_keeps_the_input_with_more_than_four_targets() {
        let modal = delete_modal_for("steven-black-hosts");
        let targets: Vec<String> = ["kids", "guests", "work", "iot", "media", "lab"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let s = render_delete_confirm_in(&modal, "ZZQQ", &targets, 80, 14);
        assert!(
            s.contains("ZZQQ"),
            "the `+ N more` layout cuts the input row:\n{s}"
        );
        assert!(
            s.contains("+ 2 more"),
            "the collapsed-target count must survive on its own row:\n{s}"
        );
    }

    /// Groundwork for **F4** (`s4-63-f4-lists-delete-refusal-names-expected-id`),
    /// which is NOT implemented here — its mismatch arm lives in
    /// `src/tui/mod.rs` and a sibling owns that file this sprint.
    ///
    /// F4's root cause is that a mismatch bounces `mode` back to `Edit`,
    /// which puts the error on a stage that is no longer being rendered.
    /// Whoever fixes it has to know whether staying in `ConfirmDelete` is
    /// affordable — so pin the two facts that decide it: this stage renders
    /// an error at all, and it does so in the tail's already-reserved note
    /// region, meaning a longer message naming both ids costs **zero**
    /// extra rows and the input row survives beside it.
    #[test]
    fn floor_delete_confirm_shows_a_refusal_without_costing_the_input_row() {
        let mut modal = delete_modal_for("steven-black-hosts");
        // Deliberately longer than one row: an error wraps across HINT_ROWS
        // rather than pushing the body, which is why `hint_rows` is None.
        modal.error_message =
            Some("typed 'ZZQQ' does not match 'steven-black-hosts' — nothing deleted".to_string());
        let s = render_delete_confirm_in(&modal, "ZZQQ", &["kids".to_string()], 80, 14);
        assert!(
            s.contains("does not match"),
            "the stage cannot show a refusal at the floor:\n{s}"
        );
        assert!(
            s.contains("> ZZQQ"),
            "the refusal cost the input row it refers to:\n{s}"
        );
    }

    /// §4.63 F4. The neighbouring S2a test proves the stage *can* render a
    /// refusal — but with a hand-written string, so it says nothing about
    /// what the handler actually produces. This one renders the real
    /// message, and asserts the part that was missing: the EXPECTED id.
    ///
    /// Both ids must survive at the 80x14 floor with a cascade target,
    /// which is the geometry F1 was filed against — a refusal that only
    /// fits on a wide terminal is not a refusal the operator gets.
    #[test]
    fn the_delete_refusal_names_both_ids_in_the_rendered_buffer_at_the_floor() {
        let mut modal = delete_modal_for("steven-black-hosts");
        modal.error_message = Some(delete_confirm_mismatch_message(
            "ZZQQ",
            "steven-black-hosts",
        ));
        let s = render_delete_confirm_in(&modal, "ZZQQ", &["kids".to_string()], 80, 14);

        // The message WRAPS across the two reserved rows — that is the
        // design (S2a measured it), and it means no contiguous substring
        // of the refusal survives in the raw dump: the buffer really
        // reads `... does` / `not match ...` on separate lines. Asserting
        // on the raw dump would fail against a correct render, so
        // normalise the frame to one whitespace-collapsed line first.
        let flat = s
            .replace(['\u{2502}', '\u{2551}'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        // ONE needle, and it is the whole phrase. The bare expected id is
        // not usable as a needle here — it also appears in the verbatim
        // header six rows up, so `contains(id)` passes with the refusal
        // entirely absent. The phrase can only have come from the refusal.
        assert!(
            flat.contains("typed 'ZZQQ' does not match 'steven-black-hosts'"),
            "the refusal must name BOTH the typed and the expected id — \
             Lists was the last typed-confirm gate that refused without \
             saying what it wanted:\n{s}"
        );
        assert!(
            s.contains("> ZZQQ"),
            "naming both ids must not cost the input row — the whole point \
             of staying in ConfirmDelete is that the operator can correct \
             the buffer in place:\n{s}"
        );
    }

    /// Both halves of the cursor invariant, in one test so neither can be
    /// kept without the other.
    ///
    /// Placing the cursor is only half the job: the predecessor placed it
    /// unconditionally, so when the input row was cut the operator watched
    /// a cursor blink on an apparently empty row while their keystrokes
    /// went nowhere visible. `place_cursor` no-ops on a row outside the
    /// viewport — this pins that we actually get that behaviour, not just
    /// that we call the function.
    #[test]
    fn delete_confirm_puts_the_cursor_on_the_typed_row_or_nowhere() {
        use ratatui::backend::Backend;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let modal = delete_modal_for("steven-black-hosts");
        let cascade = ["kids".to_string()];

        // On screen: the cursor sits on the typed row, one cell past the
        // last character the operator typed.
        let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
        term.draw(|f| render_delete_confirm(f, f.area(), &modal, "ZZQQ", &cascade))
            .unwrap();
        let dump = dump_buffer(term.backend().buffer());
        let typed_y = dump
            .lines()
            .position(|l| l.contains("> ZZQQ"))
            .expect("precondition: the typed row is on screen") as u16;
        let pos = term.backend_mut().get_cursor_position().unwrap();
        assert_eq!(pos.y, typed_y, "cursor is not on the typed row:\n{dump}");
        let row = dump.lines().nth(typed_y as usize).unwrap();
        assert_eq!(
            row.chars().nth(pos.x as usize),
            Some(' '),
            "cursor should trail the buffer, not sit inside it:\n{dump}"
        );

        // Squeezed past the point where the input fits: the viewport keeps
        // the first rows, the typed row is gone, and no cursor is drawn.
        let mut term = Terminal::new(TestBackend::new(80, 10)).unwrap();
        term.draw(|f| render_delete_confirm(f, f.area(), &modal, "ZZQQ", &cascade))
            .unwrap();
        let dump = dump_buffer(term.backend().buffer());
        assert!(
            !dump.contains("ZZQQ"),
            "precondition: this anchor must actually clip the input:\n{dump}"
        );
        assert_eq!(
            term.backend_mut().get_cursor_position().unwrap(),
            ratatui::layout::Position { x: 0, y: 0 },
            "a clipped input row must not host the cursor:\n{dump}"
        );
    }

    /// The cursor claim at the two lengths the sibling above cannot see: an
    /// id that **wraps**, and the widest body this stage can build.
    ///
    /// `delete_confirm_puts_the_cursor_on_the_typed_row_or_nowhere` uses an
    /// 18-character id, so `prose_field_row` returns exactly what the old
    /// `prose.len() - 1` returned and it passes whether or not the
    /// conversion is right.
    ///
    /// The second case is this stage's worst case and it has **zero
    /// slack**: a wrapped id (2) + the cascade warning, names and
    /// `+ N more` (3) + prompt (1) + input (1) = 7 rows against a 7-row
    /// budget. The input is the last visible row, so an off-by-one does
    /// not put the caret on the wrong row — it puts it outside the
    /// viewport, where `place_cursor` no-ops and the cursor **vanishes**.
    #[test]
    fn delete_confirm_cursor_follows_the_input_row_past_a_wrapped_id() {
        use ratatui::backend::Backend;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let id = id_of_len(64);
        let probe = |cascade: &[String]| {
            let modal = delete_modal_for(&id);
            let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
            term.draw(|f| render_delete_confirm(f, f.area(), &modal, "ZZQQ", cascade))
                .unwrap();
            let dump = dump_buffer(term.backend().buffer());
            let pos = term.backend_mut().get_cursor_position().unwrap();
            (dump, pos)
        };

        for cascade in [
            Vec::new(),
            ["kids", "guests", "work", "iot", "media", "lab"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ] {
            let (dump, pos) = probe(&cascade);
            // Precondition: the fixture must actually wrap. Whole across
            // the frame but on no single row is exactly what that means —
            // and the wrap lands mid-token, so no fixed needle can stand
            // in for it.
            assert!(
                dechrome(&dump).contains(&id),
                "precondition: the id must render whole:\n{dump}"
            );
            assert!(
                !dump.lines().any(|l| l.contains(&id)),
                "precondition: a 64-char id must occupy two rows:\n{dump}"
            );
            let typed_y = dump
                .lines()
                .position(|l| l.contains("> ZZQQ"))
                .unwrap_or_else(|| {
                    panic!(
                        "the wrapped id pushed the input row off screen with \
                         {} cascade target(s):\n{dump}",
                        cascade.len()
                    )
                }) as u16;
            assert_eq!(
                pos.y,
                typed_y,
                "the wrapped id moved the input row and the caret did not \
                 follow ({} cascade target(s)):\n{dump}",
                cascade.len()
            );
        }
    }

    // ── the catalog picker ────────────────────────────────────────────

    fn picker_entry(id: &str, original: app::CatalogRowState) -> app::CatalogPickerRow {
        let (scope, topic) = id.split_once('/').unwrap();
        app::CatalogPickerRow {
            catalog_id: id.to_string(),
            canonical_id: id.replace('/', "-"),
            url: format!("https://lists.purge.cc/{topic}.txt"),
            display_name: format!("Test: {id}"),
            scope: scope.to_string(),
            topic: topic.to_string(),
            entry_count: 100,
            updated_at: "2026-08-01T04:03:13Z".to_string(),
            staged_enabled: original.is_on(),
            staged_kind: BlocklistBase::Deny,
            original,
            format: BlocklistFormat::Domains,
        }
    }

    /// Three rows covering all three ON states, cursor on the first — the
    /// shape `build_catalog_picker_modal_from` produces, minus the
    /// 17-entry catalog.
    fn picker_modal() -> app::CatalogPickerModal {
        let rows = vec![
            picker_entry("privacy/ads", app::CatalogRowState::NotSubscribed),
            picker_entry(
                "privacy/tracking",
                app::CatalogRowState::Subscribed { enabled: true },
            ),
            picker_entry(
                "security/malicious",
                app::CatalogRowState::Subscribed { enabled: false },
            ),
        ];
        let mut table_state = ratatui::widgets::TableState::default();
        table_state.select(Some(0));
        app::CatalogPickerModal {
            rows,
            table_state,
            focus: app::CatalogPickerFocus::Table,
            error_message: None,
            status_message: None,
            submitting: false,
        }
    }

    fn render_picker_to_buffer(
        modal: &app::CatalogPickerModal,
        w: u16,
        h: u16,
    ) -> ratatui::buffer::Buffer {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_catalog_picker(f, f.area(), modal))
            .unwrap();
        term.backend().buffer().clone()
    }

    fn render_picker_in(modal: &app::CatalogPickerModal, w: u16, h: u16) -> String {
        dump_buffer(&render_picker_to_buffer(modal, w, h))
    }

    /// Visual aid for the table's column budget — the thing no assertion
    /// reads well. Shows the real 17-entry catalog at the 80×24 floor
    /// (where the field region scrolls and the scrollbar claims a column)
    /// and at a roomy size.
    ///
    /// `cargo test catalog_visual_dump -- --ignored --nocapture`
    #[test]
    #[ignore = "visual aid: cargo test catalog_visual_dump -- --ignored --nocapture"]
    fn catalog_visual_dump() {
        use crate::lists::catalog::Catalog;
        let mut modal = build_catalog_picker_modal_from(&App::new(), &Catalog::fallback());
        modal.rows[0].staged_enabled = true;
        modal.rows[1].original = app::CatalogRowState::Subscribed { enabled: true };
        modal.rows[1].staged_enabled = true;
        modal.rows[2].original = app::CatalogRowState::Subscribed { enabled: false };
        for (w, h) in [(80u16, 24u16), (120, 30)] {
            println!("--- catalog picker, {w}x{h} ---");
            println!("{}", render_picker_in(&modal, w, h));
        }
    }

    /// F6. The predecessor asked its `Layout::vertical` for 13 minimum rows
    /// against the 12 the D18 anchor leaves, and ratatui resolves that by
    /// shrinking — the status/error row and the hint were the ones that
    /// died, while the table's `Min(8)` survived. So the needle is the
    /// status text, never the table.
    #[test]
    fn floor_catalog_picker_keeps_its_status_row_on_screen() {
        let mut modal = picker_modal();
        modal.status_message = Some("saving 2 change(s)\u{2026}".to_string());
        modal.submitting = true;
        let s = render_picker_in(&modal, 80, 14);
        assert!(
            s.contains("saving 2 change(s)"),
            "the in-flight status is squeezed off the picker:\n{s}"
        );
    }

    #[test]
    fn floor_catalog_picker_keeps_its_error_row_on_screen() {
        let mut modal = picker_modal();
        modal.error_message = Some("validator: nothing written".to_string());
        let s = render_picker_in(&modal, 80, 14);
        assert!(
            s.contains("validator: nothing written"),
            "the refusal is squeezed off the picker:\n{s}"
        );
    }

    /// `Space` is the only way to stage a row and `Ctrl+S` the only way to
    /// commit one; neither is discoverable from the action labels, so the
    /// legend naming them is load-bearing. Pin it alongside both buttons.
    #[test]
    fn floor_catalog_picker_advertises_its_keys_and_its_actions() {
        let s = render_picker_in(&picker_modal(), 80, 14);
        assert!(
            s.contains("Space toggle") && s.contains("Ctrl+s save"),
            "the key legend is squeezed off the picker:\n{s}"
        );
        assert!(
            s.contains("Save") && s.contains("Cancel"),
            "the action row is squeezed off the picker:\n{s}"
        );
    }

    /// The description band's inventory. "subscribed" is the word, never
    /// "active": the ON column is one row away and a needle matching both
    /// would pass with the count gone.
    #[test]
    fn catalog_picker_desc_counts_the_catalog_and_the_pending_writes() {
        let mut modal = picker_modal();
        // Asserted on `catalog_desc` itself, not on the frame: the hint
        // band one row down reads "no pending changes", so a `contains`
        // needle for "pending" over the whole dump matches THAT and passes
        // with the description band's counter gone.
        assert_eq!(catalog_desc(&modal), "3 lists \u{b7} 2 subscribed");

        modal.rows[0].staged_enabled = true;
        assert_eq!(
            catalog_desc(&modal),
            "3 lists \u{b7} 2 subscribed \u{b7} 1 pending"
        );

        let s = render_picker_in(&modal, 80, 14);
        assert!(
            s.contains("3 lists \u{b7} 2 subscribed \u{b7} 1 pending"),
            "the inventory never reached the description band:\n{s}"
        );
    }

    /// The three ON states are three glyphs. `[ ]` and `[·]` both mean "not
    /// filtering" and would be indistinguishable if either lost its glyph —
    /// but ticking them writes different TOML (a new entry vs `enabled =
    /// true` on an existing one), so the operator has to be able to tell
    /// them apart before pressing Space.
    #[test]
    fn catalog_picker_on_column_distinguishes_all_three_states() {
        let modal = picker_modal();
        let glyphs: Vec<&str> = modal.rows.iter().map(|r| catalog_on_cell(r).0).collect();
        assert_eq!(
            glyphs,
            vec!["[ ]", "[\u{2713}]", "[\u{b7}]"],
            "not-subscribed / subscribed-on / subscribed-off must not collide"
        );

        let s = render_picker_in(&modal, 80, 20);
        for glyph in &glyphs {
            assert!(
                s.contains(glyph),
                "`{glyph}` never reached the screen:\n{s}"
            );
        }
    }

    /// A staged row has to be visible as staged. Bold, not a hue: on the
    /// focus bar every hue collapses to `text_primary`, so a colour-only
    /// marker would vanish on exactly the row the operator just toggled.
    #[test]
    fn catalog_picker_marks_a_staged_row_with_a_modifier_not_a_hue() {
        let mut modal = picker_modal();
        modal.rows[0].staged_enabled = true;
        assert!(modal.rows[0].is_dirty());

        let clean = catalog_row_line(&modal.rows[1], catalog_cols(74), true);
        let dirty = catalog_row_line(&modal.rows[0], catalog_cols(74), true);
        let bold = |l: &Line<'static>| {
            l.spans
                .iter()
                .any(|s| s.style.add_modifier.contains(Modifier::BOLD))
        };
        assert!(bold(&dirty), "a staged row must carry the BOLD marker");
        assert!(
            !bold(&clean),
            "control arm: an untouched row must not be bold"
        );
    }

    /// D15 and the ecosystem chrome rule, read off this file's source. Both
    /// overlays drew their own all-sided `Block` with a `brand_red` frame
    /// until §4.63 S2a; `modal_form::render_chrome_in` owns every modal
    /// frame now, and chrome stays neutral grey.
    ///
    /// `brand_red` itself is NOT banned here — it is still the tag chip's
    /// background (`render_chip_picker`) and the inert-row glyph, both of
    /// which are data, not chrome.
    ///
    /// Both needles are assembled from fragments and neither appears whole
    /// anywhere above, including in this comment: a source-scanning
    /// assertion that can match its own text is a test that passes on
    /// itself. This one caught exactly that on its first run.
    #[test]
    fn no_hand_rolled_modal_chrome_left_in_this_file() {
        let src = include_str!("lists.rs");
        let borders = concat!("Borders", "::ALL");
        assert!(
            !src.contains(borders),
            "a hand-rolled modal frame is back — `modal_form::render_modal` owns modal chrome"
        );
        let border_style = concat!("border_style", "(");
        assert!(
            !src.contains(border_style),
            "D15: a border may not carry colour — chrome stays neutral grey"
        );
    }

    /// The three-row fixture above fits without scrolling, so it cannot see
    /// the thing that matters for a 17-entry catalog: the viewport follows
    /// focus, and the tail is served BEFORE the fields, so the action row
    /// survives the squeeze that the rows lose.
    #[test]
    fn floor_catalog_picker_scrolls_the_real_catalog_to_the_focused_row() {
        use crate::lists::catalog::Catalog;
        let app = App::new();
        let mut modal = build_catalog_picker_modal_from(&app, &Catalog::fallback());

        let last = modal.rows.len() - 1;
        modal.table_state.select(Some(last));
        let wanted = modal.rows[last].topic.clone();

        let s = render_picker_in(&modal, 80, 14);
        assert!(
            s.contains(&wanted),
            "the viewport did not follow focus to `{wanted}`:\n{s}"
        );
        assert!(
            s.contains("Save"),
            "the action row lost its place to the row list:\n{s}"
        );
    }

    /// The column header is the reason the table is readable at all, and at
    /// the 80×24 floor the field region is about five rows against
    /// seventeen lists. In `ScrollBody.fields` it would scroll away on the
    /// second `j`, leaving unlabelled columns of numbers; `head` is pinned.
    ///
    /// The needle is the header row WITH the focused row's topic: asserting
    /// "SCOPE is on screen" alone passes on an unscrolled picker, which is
    /// the state that never had the bug.
    #[test]
    fn floor_catalog_picker_pins_the_column_header_while_scrolled_to_the_end() {
        use crate::lists::catalog::Catalog;
        let mut modal = build_catalog_picker_modal_from(&App::new(), &Catalog::fallback());
        let last = modal.rows.len() - 1;
        modal.table_state.select(Some(last));
        let wanted = modal.rows[last].topic.clone();

        let s = render_picker_in(&modal, 80, 14);
        assert!(
            s.contains(&wanted),
            "precondition: the viewport must be scrolled to the last row:\n{s}"
        );
        assert!(
            s.contains("SCOPE") && s.contains("TOPIC") && s.contains("ON"),
            "the column header scrolled away with the rows above it:\n{s}"
        );
    }

    /// Column rules have to line up between the header rule and every data
    /// row, or the table reads as noise. Positions are counted in
    /// CHARACTERS — `│` is three bytes, so a byte offset reports every
    /// column past the first in the wrong place.
    #[test]
    fn catalog_picker_column_rules_align_with_the_header() {
        let cols = catalog_cols(74);
        let [_, rule] = catalog_header_rows(cols);
        let at = |line: &Line<'static>, glyph: char| -> Vec<usize> {
            line.spans
                .iter()
                .flat_map(|s| s.content.chars())
                .enumerate()
                .filter(|(_, c)| *c == glyph)
                .map(|(i, _)| i)
                .collect()
        };
        let want = at(&rule, '\u{253c}');
        assert_eq!(want.len(), 5, "six columns means five rules: {want:?}");

        for (idx, row) in picker_modal().rows.iter().enumerate() {
            for focused in [false, true] {
                assert_eq!(
                    at(&catalog_row_line(row, cols, focused), '\u{2502}'),
                    want,
                    "row {idx} (focused={focused}) does not line up with the header rule"
                );
            }
        }
    }

    /// `Catalog::fallback` — what an operator with no egress sees — carries
    /// `entries: 0` and an empty `updated_at` for every list. Rendering
    /// those verbatim would tell them all seventeen lists are empty, and no
    /// test written against the live catalog would ever notice.
    #[test]
    fn catalog_picker_renders_absent_metadata_as_a_dash_not_a_zero() {
        use crate::lists::catalog::Catalog;
        assert_eq!(catalog_entries_cell(0), "\u{2014}");
        assert_eq!(catalog_updated_cell(""), "\u{2014}");
        assert_eq!(catalog_entries_cell(6_857_129), "6.9M");
        assert_eq!(catalog_updated_cell("2026-08-01T04:03:13Z"), "08-01");

        let modal = build_catalog_picker_modal_from(&App::new(), &Catalog::fallback());
        let line = catalog_row_line(&modal.rows[0], catalog_cols(74), false);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains('\u{2014}'),
            "the offline fallback must read as unknown, not as zero: {text:?}"
        );
        assert!(
            !text.contains(" 0 "),
            "a bare 0 reads as a fact about the list: {text:?}"
        );
    }

    /// The cursor indexes a vector the background catalog fetch replaces
    /// wholesale. Past the end there is no focus bar and `Space` toggles
    /// nothing — silently. Same class the 2026-07-12 TUI audit found on
    /// Lists and Rules.
    #[test]
    fn catalog_picker_clamps_a_cursor_left_past_the_end_of_a_shorter_rebuild() {
        let mut modal = picker_modal();
        modal.table_state.select(Some(11));
        clamp_catalog_cursor(&mut modal);
        assert_eq!(modal.table_state.selected(), Some(modal.rows.len() - 1));

        modal.rows.clear();
        clamp_catalog_cursor(&mut modal);
        assert_eq!(
            modal.table_state.selected(),
            None,
            "an empty table has no row to point at"
        );
    }

    /// The catalog re-fetch lands a fresh row vector on a modal the
    /// operator has been ticking for however long the fetch took. Losing
    /// their staged rows there is data loss with no error and no keystroke
    /// to blame — the worst shape a TUI bug takes.
    ///
    /// The baseline still comes from the FRESH build: `original` is the
    /// config's state, not the operator's intent.
    #[test]
    fn catalog_picker_rebuild_keeps_staged_ticks_but_refreshes_the_baseline() {
        let mut previous = picker_modal();
        previous.rows[0].staged_enabled = true;
        previous.focus = app::CatalogPickerFocus::Save;
        previous.table_state.select(Some(2));

        let mut fresh = picker_modal();
        // The list the operator staged got subscribed elsewhere meanwhile.
        fresh.rows[0].original = app::CatalogRowState::Subscribed { enabled: true };

        merge_catalog_picker_state(&mut fresh, &previous);

        assert!(
            fresh.rows[0].staged_enabled,
            "the operator's tick must survive the rebuild"
        );
        assert_eq!(
            fresh.rows[0].original,
            app::CatalogRowState::Subscribed { enabled: true },
            "the baseline must come from the fresh build, not the stale modal"
        );
        assert!(
            !fresh.rows[0].is_dirty(),
            "with the config caught up there is nothing left to write"
        );
        assert_eq!(fresh.focus, app::CatalogPickerFocus::Save);
        assert_eq!(fresh.table_state.selected(), Some(2));
    }

    /// KIND is rendered but not editable: `base = allow` on a catalog row
    /// is refused by the validator (`ALLOW_LIST_REQUIRES_LOCAL_TRUST` — an
    /// allow-direction list needs `trust = local`, which only a local file
    /// import supplies), and `write_value_validated` validates the whole
    /// tree, so one allow row would sink the entire batch. Pin the column's
    /// presence and its value; the key handler's silence is pinned in
    /// `mod.rs`.
    #[test]
    fn catalog_picker_kind_column_renders_block_for_every_catalog_row() {
        use crate::lists::catalog::Catalog;
        let modal = build_catalog_picker_modal_from(&App::new(), &Catalog::fallback());
        assert!(
            modal
                .rows
                .iter()
                .all(|r| r.staged_kind == BlocklistBase::Deny),
            "a catalog row cannot be staged as allow"
        );

        let s = render_picker_in(&modal, 80, 20);
        assert!(
            s.contains("KIND"),
            "the KIND column header is missing:\n{s}"
        );
        assert!(s.contains("Block"), "the KIND value is missing:\n{s}");
        assert!(
            !s.contains("Allow"),
            "no catalog row may render as allow:\n{s}"
        );
    }

    /// UPDATED drops before ENTRIES, and SCOPE / TOPIC / KIND / ON never
    /// drop: the first two are context, the last four are what the row IS
    /// and what the operator changes.
    #[test]
    fn catalog_cols_degrade_context_first_and_never_the_controls() {
        let wide = catalog_cols(100);
        assert!(wide.entries && wide.updated);
        assert!(wide.topic <= CAT_TOPIC_MAX, "TOPIC must not run away");

        let narrow = catalog_cols(catalog_overhead(true, true) + CAT_TOPIC_MIN - 1);
        assert!(
            narrow.entries && !narrow.updated,
            "UPDATED is the first column to go: {narrow:?}"
        );

        let tighter = catalog_cols(catalog_overhead(true, false) + CAT_TOPIC_MIN - 1);
        assert!(
            !tighter.entries && !tighter.updated,
            "ENTRIES goes second: {tighter:?}"
        );

        for w in 10..=120usize {
            let cols = catalog_cols(w);
            assert!(
                cols.topic >= CAT_TOPIC_MIN,
                "TOPIC collapsed below its floor at width {w}"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test s2a_visual_dump -- --ignored --nocapture"]
    fn s2a_visual_dump() {
        let modal = delete_modal_for("steven-black-hosts");
        for (label, cascade) in [
            ("no cascade", vec![]),
            ("1 target", vec!["kids".to_string()]),
            (
                "6 targets (+ N more)",
                ["kids", "guests", "work", "iot", "media", "lab"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
        ] {
            println!("--- delete confirm, {label}, 80x14 (the D18 floor) ---");
            println!(
                "{}",
                render_delete_confirm_in(&modal, "ZZQQ", &cascade, 80, 14)
            );
        }
        // What F4's refusal would look like once it names both ids.
        let mut refused = delete_modal_for("steven-black-hosts");
        refused.error_message =
            Some("typed 'ZZQQ' does not match 'steven-black-hosts' — nothing deleted".to_string());
        println!("--- delete confirm, refusal + 1 target, 80x14 ---");
        println!(
            "{}",
            render_delete_confirm_in(&refused, "ZZQQ", &["kids".to_string()], 80, 14)
        );
        println!("--- catalog picker, 80x14 (the D18 floor) ---");
        println!("{}", render_picker_in(&picker_modal(), 80, 14));
        println!("--- catalog picker, 80x24 anchor ---");
        println!("{}", render_picker_in(&picker_modal(), 80, 24));
    }

    #[test]
    fn no_raw_colour_literals_outside_the_token_module() {
        // Spec §8 acceptance check 1. Three refined-palette hexes lived
        // here because theme.rs still held the old Tailwind values; the
        // tokens now hold the refined trio, so there is no excuse left.
        // Needle is split so this assertion does not match itself.
        let needle = concat!("Color", "::Rgb(");
        assert!(
            !include_str!("lists.rs").contains(needle),
            "raw RGB literal in lists.rs — add a named token to theme.rs instead"
        );
    }
}
