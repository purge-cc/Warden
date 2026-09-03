//! Lists tab — per-blocklist runtime visibility.
//!
//! Owns the Lists tab's table, row-building (`ListRowMeta` /
//! `build_grouped_rows`), and every list-related modal (edit / add /
//! delete confirm / catalog picker / unsigned-allow consent) — state
//! and rendering only. Does not own persistence: `tui/mod.rs`
//! dispatches keystrokes to the actual config-write path
//! (`cli::commands::blocklists`); this file builds the values and
//! states those calls act on.
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
//!   Enter       open the edit modal on the focused list
//!   K           toggle the focused list's `base` between deny and allow
//!
//! `f` and `K` cycle/toggle the list's *direction* — TOML key `base`,
//! though the Rust type is still named `ListsKindFilter` (the naming
//! survived a rename from `kind` to `base`). What they DO matches the
//! current name regardless: the chip cycles three states and `K` flips
//! the direction.
//!
//! `LISTS_TAB_EMPTY` is a frozen string, pinned byte-for-byte by
//! `tests/frozen_strings_s43.rs`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Widget, Wrap};
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

/// Frozen empty-state message, pinned byte-for-byte by
/// `tests/frozen_strings_s43.rs`.
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
    /// id is missing.
    pub canonical_id: Option<String>,
    pub base: BlocklistBase,
    pub trust: BlocklistTrust,
    /// `None` when the schema entry is missing for this source. We
    /// render `—` in the FORMAT column so the operator sees the join
    /// gap explicitly rather than guessing at a wire format.
    pub format: Option<BlocklistFormat>,
    pub used_by_profiles: Vec<String>,
    /// `true` when `now - dto.last_refresh_at` exceeds
    /// `lists.staleness_threshold_secs` (default 24 h). Computed at
    /// row-build time so the renderer is pure. Suppresses the badge
    /// automatically when `last_refresh_at` is `None`.
    pub is_stale: bool,
    /// `Some(reason)` when this list is installed, enabled, and visible — but filters
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

    // Precompute the stale flag against the loaded config's threshold
    // (or the 24 h default when the config has not been loaded yet —
    // TUI startup race).
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

/// Pure stale predicate exercised both at row-build
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
/// j/down, `-1` for k/up). **Clamps** at both ends — walking off the
/// last/first row is a no-op, never a teleport to the other end. Mirrors
/// `devices::next_selectable_index`, with one deliberate difference: this always
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

/// The stable selection key of a row, matching the `key_of`
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
    /// method (rather than inlined at call sites) so
    /// `reconcile_lists_selection` in `tui::mod` keeps compiling
    /// unchanged.
    pub fn is_selectable(&self) -> bool {
        true
    }
}

/// Return the focused list row. Single source of truth for "what list
/// is selected?" — the `[m]`/`[k]` hotkeys + the existing `p`
/// modal-builder all route through this helper.
///
/// Resolves the operator's stable `selected_id`, **not** the
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

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    if app.lists.entries.is_empty() {
        render_empty(f, area, app);
        render_overlays(f, area, app);
        return;
    }

    let grouped = build_grouped_rows(app);
    let inert_count = grouped.iter().filter(|m| m.inert_reason.is_some()).count();

    // Shared filter-card frame on top, table below — no interior
    // title (the fields are the label), height 3.
    // The drill-down split-pane this tab used to have was removed —
    // the edit modal supersedes it. Overlays/modals still anchor on
    // the full tab area, not the table sub-rect.
    //
    // The inert-summary claims 0 rows when there's nothing to say — a
    // clean fleet keeps the original 2-chunk layout so "no inert lists"
    // reads as "no summary noise", not as a blank reserved block. When
    // there IS something to say, its height is measured against the
    // real paragraph (`alert_band_height`), not guessed: reusing the
    // formatters verbatim means two or more reasons routinely need more
    // than one wrapped line, and a fixed height either clips the tail
    // of a long summary or wastes rows on a short one. Same reasoning
    // for the corpus-refusal band below it.
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
    let refusal_para = refusal.map(|r| corpus_refusal_paragraph(r, app));
    let inert_para = (inert_count > 0).then(|| inert_summary_paragraph(&grouped));

    let mut constraints = Vec::with_capacity(4);
    if let Some(p) = &refusal_para {
        constraints.push(Constraint::Length(alert_band_height(p, area.width)));
    }
    constraints.push(Constraint::Length(3)); // shared filter card, no title
    if let Some(p) = &inert_para {
        constraints.push(Constraint::Length(alert_band_height(p, area.width)));
    }
    constraints.push(Constraint::Min(5)); // table
    let chunks = Layout::vertical(constraints).split(area);

    let mut next = 0;
    if let Some(p) = refusal_para {
        f.render_widget(p, chunks[next]);
        next += 1;
    }
    render_filters(f, chunks[next], app);
    next += 1;
    if let Some(p) = inert_para {
        f.render_widget(p, chunks[next]);
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
fn corpus_refusal_paragraph(
    refusal: &crate::lists::status::CorpusRefusal,
    app: &App,
) -> Paragraph<'static> {
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
    Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(T.error).add_modifier(Modifier::BOLD),
    )))
    .wrap(Wrap { trim: false })
}

/// One line naming every inert list on screen, reusing the exact WARN
/// text `build_meta` already attached via [`ListRowMeta::inert_reason`]
/// (never re-derived here). Only called when `rows` contains at least
/// one inert entry — see [`render`].
fn inert_summary_paragraph(rows: &[ListRowMeta]) -> Paragraph<'static> {
    let reasons: Vec<&str> = rows
        .iter()
        .filter_map(|m| m.inert_reason.as_deref())
        .collect();
    debug_assert!(
        !reasons.is_empty(),
        "inert_summary_paragraph called with zero inert rows"
    );
    let lede = if reasons.len() == 1 {
        "1 list is filtering nothing:".to_string()
    } else {
        format!("{} lists are filtering nothing:", reasons.len())
    };
    let text = format!("⚠ {lede} {}", reasons.join(" · "));
    Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(T.warning),
    )))
    .wrap(Wrap { trim: false })
}

/// Alert-band row cap: past this many wrapped rows the table's own
/// `Min(5)` starts losing ground to it. Capped, not scrolled — beyond
/// this the paragraph's own tail clips, the same degrade a fixed height
/// already accepted, just bounded by measurement instead of by luck.
const ALERT_BAND_MAX_ROWS: u16 = 5;

/// Exact wrapped-row count for an optional alert band above the table:
/// renders a clone of the same paragraph into a disposable scratch
/// buffer and counts the rows it actually touched, so the layout
/// constraint can never drift from what this exact paragraph renders.
/// (`Paragraph::line_count` would do this directly, but ratatui gates it
/// behind the unstable `rendered-line-info` feature, not enabled here.)
/// See [`ALERT_BAND_MAX_ROWS`].
fn alert_band_height(para: &Paragraph<'static>, width: u16) -> u16 {
    let scratch = Rect::new(0, 0, width.max(1), ALERT_BAND_MAX_ROWS);
    let mut buf = ratatui::buffer::Buffer::empty(scratch);
    para.clone().render(scratch, &mut buf);
    let touched = (0..scratch.height)
        .filter(|&y| (0..scratch.width).any(|x| buf[(x, y)].symbol() != " "))
        .count() as u16;
    touched.max(1)
}

fn render_overlays(f: &mut Frame, area: Rect, app: &App) {
    // Catalog picker renders BELOW the edit modal so a (theoretical)
    // collision lands the form-mutation surface highest.
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
    // Edit modal renders LAST so it sits above the others
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
                // Surface the profiles that will lose the reference IN
                // the prompt so the operator sees the cost of
                // confirming before they type the id. Empty Vec →
                // "no refs" path renders.
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

/// Shared filter card: a text search (`/`) combined with the
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

fn render_table(f: &mut Frame, area: Rect, app: &mut App, grouped: &[ListRowMeta]) {
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
        // Fixed-width gutter, independent of DISPLAY's content — a
        // long display_name must never be able to truncate the inert
        // badge away (Table cells don't wrap).
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

    // Selection is already reconciled onto `app.lists.table_state` before
    // render runs (`reconcile_lists_selection`); render only needs to
    // keep painting it without resetting the viewport.
    let selected = app.lists.table_state.selected();
    super::render_table(f, content, table, &mut app.lists.table_state, selected);

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
    // Reads `last_refresh_at` (last SUCCESS), not `fetched_at` (last
    // attempt) — the same field `meta.is_stale` was computed from, so this
    // cell and the `· Stale` badge below can never disagree. A list that
    // has only ever failed has no successful timestamp to show and renders
    // `<never>`, identically to one that was never attempted; the STATUS
    // column (driven by `last_outcome`) is what tells those two apart.
    let last_update = meta
        .dto
        .last_refresh_at
        .as_deref()
        .map(format_short_timestamp)
        .unwrap_or_else(|| "<never>".to_string());

    // Append a non-alarm `· Stale` chip in `T.text_muted` when the
    // list has not had a successful refresh within the configured
    // `lists.staleness_threshold_secs` window.
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

    // Fixed gutter cell, independent of every other column's width so
    // a long id/display never truncates it away. Blank (not just
    // unstyled) when the list has effect.
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
/// ## This asked the wrong question, and the wrong answer was `[]`
///
/// It used to be `profiles_matching_blocklist_tags`: profiles whose
/// `tags` intersect the list's `tags`. That was the old tag-based
/// model; which lists a profile enforces is now the list's `base` as
/// overridden by `profiles.<id>.lists`, and `profile.tags` decides
/// nothing.
///
/// **The failure was not merely stale: it was fail-open on a destructive
/// confirm.** The old body bailed to `Vec::new()` whenever the LIST had no
/// tags, and matched only profiles that carried tags of their own.
/// Measured against both live hosts: zero tagged profiles, so the
/// delete confirm rendered its benign copy — no "unblocks its domains
/// for N profiles" block at all — for a list every profile was
/// enforcing. The operator typed the id having been shown nothing.
///
/// The predicate is now
/// [`resolve_profile_blocklist_ids`](crate::profiles::profile::resolve_profile_blocklist_ids),
/// the daemon's
/// own, rather than a second formulation of it. One question, one answer:
/// the profiles named here are exactly the profiles whose "What it
/// blocks" side-card line shrinks, because that line is built from the
/// same function. Two copies of the same predicate that can disagree
/// is the failure class here, and this surface is where a
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

// ── List edit modal (60×22 centered, 11 fields + delete) ────────────

/// Build the list edit modal from the focused row + the cached
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
    // This call outlived the tag picker it was originally written for;
    // the value it returns is now deliberately discarded.
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
    // The call is now re-pointed at `blocklist_entry_exists` rather
    // than the retired `file_tags_of` it originally called.
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
/// at all and `Space` then toggles nothing.
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
/// Builds a blank Add modal, `base = Deny` as the default nature.
/// Seeds no default tag chip on either branch: an untagged deny-list
/// is auto-promoted to `[uncategorized]` at load anyway, so a default
/// chip would change nothing on the deny case; on the allow case it
/// would silently grant every device under a profile carrying
/// `uncategorized` an exemption the operator never chose.
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
        // No default chip on either branch — see this function's doc
        // comment for why.
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
// save) and its real terminal cursor.
//
// Value-cycling moved off ↑↓ and onto ←/→, freeing ↑↓ to alias Tab;
// the keying itself lives in `mod.rs::handle_edit_mode_key`.
//
// Every row, colour and layout decision lives in `modal_form`'s
// ecosystem layer, so the other eleven modal surfaces inherit one
// implementation instead of eleven drifting copies. What stays in
// this file is the Lists-specific *mapping*: which field is which,
// what each one is called, what its hint says, and how a
// `BlocklistTrust` becomes a state row.
//
// Do not reintroduce a local `Style::default().fg(...)` here. If a row
// cannot be expressed through a `modal_form` helper, the helper is
// incomplete — extend it there.

/// Modal title + the two description rows, keyed by mode.
///
/// Renders as two rows, on their own `bg_main` strip
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
///   `lists` table.
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
        // Matches `render_list_row`'s treatment, not Local's: the validator
        // refuses `trust = signed` outright (`TrustSignedNotYetSupported`),
        // so a row wearing it can only exist via a bug elsewhere. Reading
        // it as Healthy would tell the operator the opposite of the truth.
        BlocklistTrust::Signed => (
            "signed",
            modal_form::ValueKind::Caution,
            " \u{2014} validator refuses this",
        ),
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
    // `scroll_layout` serves tail first, head second, so at the 80×24
    // floor's 12 interior rows that comes out of the field viewport: this modal's
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
    // So the third state gets the cycler instead: `‹ Ignore ›`, honest
    // about both the value and the fact that ←/→ move it — a truthful
    // readout of a state the migration can produce and the arrows can
    // only leave.
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
        // Every form modal shares one navigation grammar: ↑↓ alias Tab
        // to move focus, ←/→ change the focused value. The legend must
        // name ←/→ — a key the operator cannot discover is lost.
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
/// Drives the cascade-aware delete confirm: the operator sees what
/// stops being blocked *before* typing the id.
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
/// they typed has to be on screen — and the hand-rolled predecessor got
/// this wrong. It asked `centered_rect` for 22 rows, got the 14-row
/// fixed anchor **clamped** back at it, then cut its own `Paragraph`
/// at `inner.height - 4`; the input landed at line index 8 or 9 and fell
/// off, while an unconditional `set_cursor_position` left a cursor
/// blinking on the empty row below it. Pinned by
/// `floor_delete_confirm_keeps_the_typed_input_on_screen`.
///
/// So the budget is a contract, not a note. At the 80×24 floor the
/// fixed anchor leaves a 12-row interior; head 2 + tail 3 leaves **7** rows of
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
            // Deleting the list does NOT rewrite the profiles — each
            // profile resolves this list's effect itself
            // (`resolve_profile_blocklist_ids` / `effective_direction`).
            // Removing the `[[blocklists]]` entry just leaves nothing left
            // to resolve, so the list's domains stop being blocked for
            // every profile that was resolving it.
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

/// What the typed-id delete gate says when the buffer does not match.
///
/// A function rather than a `format!` at the call site so the handler
/// (`tui::mod::handle_confirm_delete_key`) and the render test that proves
/// the text reaches the buffer read the SAME wording. Two copies of a
/// refusal string drift, and the one that drifts is always the one nothing
/// renders.
///
/// [`LIST_DELETE_CONFIRM_FAILED`] stays the lede instead of being replaced.
/// It lives in `cli/commands/blocklists.rs`; keeping it means its
/// byte-for-byte frozen pin still guards a string that is genuinely on
/// screen, rather than one no surface emits.
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

/// Render the typed-id delete confirm, anchored on the tab content rect.
///
/// Everything geometric belongs to [`modal_form::render_modal`]: the
/// chrome, the height request, the clamp to the anchor, the two-pass width
/// resolution and the viewport. The border carries no meaning — `brand_red`
/// is never a border — so the destructive weight sits on the id
/// itself, in `ValueKind::Blocking`.
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
// retired `AllowDirectionGates::needs_tag`: an allow-direction list
// is inherited by every profile that does not override it, tagged or not,
// so the premise ("this one reaches nobody") stopped being true. The same
// change stopped `warden blocklist tag add` from writing tags at all, so
// an operator refused by these would have been sent to a verb that also
// refuses — the unsatisfiable refusal CLAUDE.md §Neutrality records this
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
/// floor the fixed anchor leaves a 12-row interior; head 2 + tail 3
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
                // The weight belongs on the action that carries the
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
#[path = "../tests/lists.rs"]
mod tests;
