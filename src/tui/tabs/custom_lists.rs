//! Custom Lists tab — the `[[custom_lists]]` entities and the pack files
//! behind them.
//!
//! Left pane: one row per declared list, with its allow / deny / skipped
//! counts and how many profiles mount it.
//!
//! ```text
//! Custom Lists (2)
//!   ID          A   D   S   USED BY
//! ▸ videogames  32  2   0   1
//! · casa         0  4   1   —
//! ```
//!
//! `▸` marks the cursor of the focused pane, `·` the resting cursor of the
//! other one.
//!
//! Right pane: the selected list's file, **one row per rule**. Comments and
//! blank lines are not rows — they enforce nothing, and the question this
//! pane answers is what the list does. A line the grammar REFUSED is a row,
//! labelled `SKIPPED`: the left pane shows those as a bare `S` count, so
//! this is the only surface where a degraded file is legible.
//!
//! ## Why the counts come from the store, not from a file read
//!
//! [`crate::config::loader::LoadedConfig::custom_lists`] is the compiled
//! store, built once per config load. This pane costs no I/O.
//!
//! ## What no surface here may ever do
//!
//! Never rebuild a pack file from rendered rows. The rows are a strict
//! SUBSET of the file — comments and blanks never become rows at all — so a
//! save that round-tripped them would delete the operator's own prose
//! outright. `write_pack` would refuse anyway at the first refused line,
//! where reading is permissive: it skips and counts. `add_rule` and
//! `remove_rule` are the only writers this leaf may reach for, and both
//! preserve order, comments and broken lines.
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_custom_lists_key` (`m` opens the mount picker,
//!   `a`/`e`/`d` open the list modal)
//! - Form:  `tui::custom_list_modal` (`CustomListModal` + `MountPicker`)
//! - State: `app::CustomListsState` (cursor, focus, `pack`, two table viewports)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::config::custom_list::CompiledCustomList;
use crate::config::loader::LoadedConfig;
use crate::config::schema::{CustomList, Id};
use crate::config::write_lock::ConfigWriteLock;
use crate::tui::app::{App, CustomListsFocus, PackRow, PackRowAction};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Width of the list pane.
///
/// 34, not 24: `USED BY` has to be readable **before** `d` is pressed.
/// Deleting a list a profile still mounts is the destructive gesture here,
/// and a column the operator must scroll to is one they do not read.
const LISTS_W: u16 = 34;

/// Below this inner width the split collapses to the list pane alone.
///
/// The rule pane needs `#` plus a raw rule plus a domain plus an action to
/// say anything; squeezed under this it shows truncated rules, which is
/// worse than not showing it. At the declared 80x24 floor the inner rect is
/// ~76 columns, so the collapsed layout is the floor's normal state rather
/// than an edge case.
const SPLIT_THRESHOLD: u16 = 86;

/// Columns `render_section_chrome` consumes before the leaf sees its rect:
/// one border cell and one padding cell on each side.
const CHROME_W: u16 = 4;

/// `ACTION` for a line that carries no rule.
///
/// Kept for exhaustiveness over `PackRowAction`: comments and blanks are
/// filtered out before they become rows, so no row in this pane paints it.
pub const ACTION_NONE: &str = "\u{2014}";

/// `ACTION` for a line the reader refused.
///
/// Named rather than blank: the list pane's `S` column COUNTS these, and
/// this pane is the only place they can be seen.
pub const ACTION_SKIPPED: &str = "SKIPPED";

/// Shown in the rule pane when no list is selected.
pub const NO_SELECTION: &str = " select a list";

/// Does a terminal this wide actually paint the rule pane?
///
/// Takes the **viewport** width because the render loop is the only caller
/// that knows it, and the tab body spans the full width.
pub fn rules_pane_is_painted(viewport_width: u16) -> bool {
    viewport_width.saturating_sub(CHROME_W) >= SPLIT_THRESHOLD
}

/// Cursor glyph of the focused pane, and of the resting one.
///
/// Two **glyphs**, not two colours. A `TestBackend` buffer compared through
/// `to_string()` discards every style, so a colour-only focus cue is
/// invisible to exactly the test meant to prove focus is drawn. Both are
/// two cells, so the columns do not shift when focus moves.
pub const CURSOR_FOCUSED: &str = "\u{25b8} ";
pub const CURSOR_RESTING: &str = "\u{00b7} ";

/// Shown in `USED BY` for a list no profile mounts.
///
/// Not an error, and never coloured as one: a list can legitimately exist
/// before it is mounted. It does mean the list filters nothing, which is
/// why the row is dimmed rather than silent.
pub const USED_BY_NONE: &str = "\u{2014}";

/// One row of the left pane, resolved from the config plus the store.
///
/// **One builder, two consumers, deliberately.** [`render`] draws these and
/// highlights one; the key handler resolves which row `e`, `d` and `m` act
/// on. Two independent derivations would let the operator delete a row
/// other than the highlighted one with nothing on screen saying so.
pub struct ListRow<'a> {
    pub entity: &'a CustomList,
    pub allow: usize,
    pub deny: usize,
    pub skipped: usize,
    /// Profiles that mount this list.
    pub used_by: usize,
}

impl ListRow<'_> {
    /// A list nothing mounts filters nothing, whatever it contains.
    pub fn is_inert(&self) -> bool {
        self.used_by == 0
    }
}

/// The left pane's rows, in config order.
pub fn list_rows(loaded: &LoadedConfig) -> Vec<ListRow<'_>> {
    loaded
        .config
        .custom_lists
        .iter()
        .map(|entity| {
            // A declared list with no compiled entry cannot normally reach
            // here — `build_store` is all-or-nothing, so an unreadable pack
            // fails the whole load and the TUI has no config at all. Default
            // to zeroes rather than hide the row: a row missing from a table
            // is a worse diagnostic than a row of noughts.
            let compiled = loaded.custom_lists.get(&entity.id);
            let empty = CompiledCustomList::default();
            let c = compiled.unwrap_or(&empty);
            ListRow {
                entity,
                allow: c.allow.len(),
                deny: c.deny.len(),
                skipped: c.skipped,
                used_by: loaded
                    .config
                    .profiles
                    .values()
                    .filter(|p| p.custom_lists.contains(&entity.id))
                    .count(),
            }
        })
        .collect()
}

/// Index of `selected_id` among the current rows, or `None` when the
/// anchor no longer resolves.
pub fn resolve_selected_index(rows: &[ListRow<'_>], selected_id: Option<&str>) -> Option<usize> {
    let want = selected_id?;
    rows.iter().position(|r| r.entity.id.as_str() == want)
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    let rows = list_rows(loaded);
    let title = format!("Custom Lists ({})", rows.len());
    let outer = render_section_chrome(f, area, &title, T.text_secondary);

    if rows.is_empty() {
        render_empty(f, outer);
        return;
    }

    let focus = app.custom_lists.focus;

    if outer.width < SPLIT_THRESHOLD {
        render_lists_pane(
            f,
            outer,
            &rows,
            focus,
            app.custom_lists.selected_id.as_deref(),
            &mut app.custom_lists.table_state,
        );
        return;
    }

    // Devices' proportions inverted: there are few lists and many rules.
    let cols = Layout::horizontal([
        Constraint::Length(LISTS_W),
        Constraint::Length(1),
        Constraint::Min(50),
    ])
    .split(outer);

    render_lists_pane(
        f,
        cols[0],
        &rows,
        focus,
        app.custom_lists.selected_id.as_deref(),
        &mut app.custom_lists.table_state,
    );
    draw_v_divider(f, cols[1]);
    render_rules_pane(f, cols[2], app);
}

// ── Right pane: the selected list's file ─────────────────────────────

/// The rule pane, on the shape of `devices::render_card_panel`.
///
/// **The title is what answers "is this list selected?".** With a single
/// row a highlight has no unhighlighted neighbour to contrast against, so
/// the cursor reads as ambiguous. Devices does not solve that with a
/// stronger marker — it names the selection in the panel title, in
/// `T.brand_red`, and shows its content. Naming it here does the same job;
/// a louder cursor would be treating the symptom.
fn render_rules_pane(f: &mut Frame, area: Rect, app: &mut App) {
    let pack = app.custom_lists.pack.as_ref();
    let title = match pack {
        Some(p) => format!("Rules \u{00b7} {}", p.id),
        None => "Rules".to_string(),
    };
    let content = render_section_chrome(f, area, &title, T.brand_red);

    let Some(pack) = pack else {
        render_muted(f, content, NO_SELECTION);
        return;
    };
    if let Some(err) = pack.error.as_deref() {
        render_pack_error(f, content, err);
        return;
    }
    if pack.rows.is_empty() {
        render_no_rules(
            f,
            content,
            app.custom_lists.focus == CustomListsFocus::Rules,
        );
        return;
    }

    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("RULE"),
        Cell::from("DOMAIN"),
        Cell::from("ACTION"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let body: Vec<Row> = pack.rows.iter().map(rule_row).collect();

    let selected =
        Some(resolve_line_index(&pack.rows, app.custom_lists.selected_line).unwrap_or(0));

    let table = Table::new(
        body,
        [
            Constraint::Length(4),
            Constraint::Min(24),
            Constraint::Min(20),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .highlight_symbol(cursor_glyph(
        app.custom_lists.focus == CustomListsFocus::Rules,
    ))
    .row_highlight_style(theme::highlight_style());

    super::render_table(
        f,
        content,
        table,
        &mut app.custom_lists.rules_table_state,
        selected,
    );
}

/// **Comments and refused lines are rows, not omissions.**
///
/// The raw column is not redundant with `DOMAIN` precisely because of
/// these: a comment has no domain, and a refused line has no parse. This
/// pane is the only surface where a degraded file is legible at all —
/// everywhere else those lines are a bare count.
fn rule_row(r: &PackRow) -> Row<'static> {
    Row::new(vec![
        Cell::from(r.number.to_string()).style(Style::default().fg(T.text_muted)),
        Cell::from(r.raw.clone()).style(raw_style(r.action)),
        Cell::from(r.domain.clone().unwrap_or_default())
            .style(Style::default().fg(T.text_secondary)),
        Cell::from(action_text(r.action)).style(Style::default().fg(action_color(r.action))),
    ])
}

pub fn action_text(action: PackRowAction) -> &'static str {
    match action {
        PackRowAction::Allow => "Allow",
        PackRowAction::Deny => "Deny",
        PackRowAction::None => ACTION_NONE,
        PackRowAction::Skipped => ACTION_SKIPPED,
    }
}

fn action_color(action: PackRowAction) -> Color {
    match action {
        PackRowAction::Allow => T.success,
        PackRowAction::Deny => T.error,
        PackRowAction::None => T.text_muted,
        PackRowAction::Skipped => T.warning,
    }
}

fn raw_style(action: PackRowAction) -> Style {
    match action {
        // A comment is structure, not noise — but it is not a rule either.
        PackRowAction::None => Style::default().fg(T.text_muted),
        PackRowAction::Skipped => Style::default().fg(T.warning),
        _ => Style::default().fg(T.text_primary),
    }
}

/// Turn the reader's views into rows: **rules and refusals, nothing else**.
///
/// Comments and blanks are dropped — they enforce nothing and this pane
/// lists what the file does. A line the grammar refused is kept, with its
/// raw text, because the list pane reports those only as an `S` count.
///
/// **This is the single projection the leaf has, and that is the whole
/// point.** The renderer and the key handler both read `PackView::rows`, so
/// filtering here cannot desync the painted table from the cursor; a filter
/// applied at draw time would leave the cursor stepping onto rows nobody
/// can see.
///
/// `number` stays the 1-based FILE line, so surviving rows are deliberately
/// non-contiguous: it is the number an operator types into their editor,
/// and the anchor [`resolve_line_index`] resolves.
pub fn rows_from_views(views: &[crate::config::custom_list::PackLineView]) -> Vec<PackRow> {
    use crate::config::custom_list::PackLine;
    views
        .iter()
        .filter_map(|v| {
            let (domain, action) = match &v.parsed {
                Ok(PackLine::Allow(d)) => (Some(d.to_string()), PackRowAction::Allow),
                Ok(PackLine::Deny(d)) => (Some(d.to_string()), PackRowAction::Deny),
                Ok(PackLine::Blank) => return None,
                Err(_) => (None, PackRowAction::Skipped),
            };
            Some(PackRow {
                number: v.number,
                raw: v.raw.clone(),
                domain,
                action,
            })
        })
        .collect()
}

/// Index of the row carrying file line `line`, or `None` when the anchor no
/// longer resolves — a deleted line, or a shorter file.
pub fn resolve_line_index(rows: &[PackRow], line: Option<usize>) -> Option<usize> {
    let want = line?;
    rows.iter().position(|r| r.number == want)
}

fn render_pack_error(f: &mut Frame, area: Rect, err: &str) {
    let lines = vec![
        Line::from(Span::styled(
            "  the file could not be read.",
            Style::default().fg(T.error),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(T.text_secondary),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_v_divider(f: &mut Frame, area: Rect) {
    let buf = f.buffer_mut();
    let style = Style::default().fg(T.border_subtle);
    for row in 0..area.height {
        buf.set_string(area.x, area.y + row, "\u{2502}", style);
    }
}

// ── Left pane: the declared lists ────────────────────────────────────

fn render_lists_pane(
    f: &mut Frame,
    area: Rect,
    rows: &[ListRow<'_>],
    focus: CustomListsFocus,
    selected_id: Option<&str>,
    table_state: &mut TableState,
) {
    let header = Row::new(vec![
        Cell::from(""),
        Cell::from("ID"),
        Cell::from("A"),
        Cell::from("D"),
        Cell::from("S"),
        Cell::from("USED BY"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let body: Vec<Row> = rows
        .iter()
        .map(|r| {
            // The gutter says "this list enforces nothing", which the counts
            // cannot: a list with 32 rules that no profile mounts looks
            // busiest of all.
            let gutter = if r.is_inert() { "\u{00b7}" } else { "" };
            let id_style = if r.is_inert() {
                Style::default().fg(T.text_muted)
            } else {
                Style::default().fg(T.text_primary)
            };
            Row::new(vec![
                Cell::from(gutter).style(Style::default().fg(T.text_muted)),
                Cell::from(r.entity.id.as_str().to_string()).style(id_style),
                Cell::from(r.allow.to_string()).style(Style::default().fg(T.success)),
                Cell::from(r.deny.to_string()).style(Style::default().fg(T.error)),
                Cell::from(r.skipped.to_string()).style(skipped_style(r.skipped)),
                Cell::from(used_by_text(r.used_by)).style(Style::default().fg(T.text_secondary)),
            ])
        })
        .collect();

    // Re-resolve the anchor every frame rather than carrying an index: a
    // config reload can add, remove or reorder entries, and an index minted
    // last frame then points at a different list.
    let selected = Some(resolve_selected_index(rows, selected_id).unwrap_or(0));

    let table = Table::new(
        body,
        [
            Constraint::Length(1),
            Constraint::Min(12),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .highlight_symbol(cursor_glyph(focus == CustomListsFocus::Lists))
    .row_highlight_style(theme::highlight_style());

    super::render_table(f, area, table, table_state, selected);
}

/// Nonzero skipped is a defect the operator should see; zero is the
/// ordinary case and must not shout.
fn skipped_style(skipped: usize) -> Style {
    if skipped > 0 {
        Style::default().fg(T.warning)
    } else {
        Style::default().fg(T.text_muted)
    }
}

pub fn used_by_text(used_by: usize) -> String {
    if used_by == 0 {
        USED_BY_NONE.to_string()
    } else {
        used_by.to_string()
    }
}

fn cursor_glyph(focused: bool) -> &'static str {
    if focused {
        CURSOR_FOCUSED
    } else {
        CURSOR_RESTING
    }
}

// ── Writing a pack ───────────────────────────────────────────────────

/// Why a pack could not be reached or written.
#[derive(Debug, thiserror::Error)]
pub enum PackAccessError {
    /// The loaded config has no parent directory. Unreachable through the
    /// loader, which refuses such a master outright — named rather than
    /// unwrapped so a future caller holding a hand-built `LoadedConfig`
    /// gets a diagnostic instead of a panic on a key press.
    #[error("the loaded config has no parent directory, so packs/ cannot be located")]
    NoConfigRoot,
    #[error(transparent)]
    Write(#[from] crate::config::custom_list::PackWriteError),
    /// Another writer holds the tree, or the config directory is not
    /// writable. Carries the message flattened rather than the error:
    /// it names the lock path and what to check, which an operator
    /// hitting it needs, and `anyhow::Error` is not a `std` error so it
    /// cannot be a `#[source]`.
    #[error("{0}")]
    Lock(String),
}

/// The operator's own ceiling on a pack file.
///
/// Read from the config, never assumed: a write above the configured cap
/// produces a file `read_pack` then refuses, and `build_store` is
/// all-or-nothing — so the next reload fails the whole config, not just
/// this list.
pub fn max_pack_bytes(loaded: &LoadedConfig) -> u64 {
    loaded.config.custom_list_limits.max_file_bytes
}

fn pack_file(loaded: &LoadedConfig, id: &Id) -> Result<std::path::PathBuf, PackAccessError> {
    let root = loaded
        .master_path
        .parent()
        .ok_or(PackAccessError::NoConfigRoot)?;
    Ok(crate::config::custom_list::pack_path(root, id))
}

/// Claim the config tree for one pack write. **The only seat that takes
/// this lock for a pack.**
///
/// The lock covers the config **directory**, so a pack write and a
/// `[[custom_lists]]` promotion serialise against each other rather than
/// only against their own kind.
///
/// **The guard must be dead before a config promotion runs.** `flock`
/// attaches to the open file description and not to the process, so a
/// promotion contends with a guard this process is still holding and
/// stalls for the whole lock deadline before failing. A caller doing both
/// scopes this one closed first.
pub fn claim_tree(loaded: &LoadedConfig) -> Result<ConfigWriteLock, PackAccessError> {
    crate::config::write_lock::acquire(&loaded.master_path)
        .map_err(|e| PackAccessError::Lock(format!("{e:#}")))
}

/// Append one rule. **The only way this leaf grows a pack.**
///
/// The choke point is the point. `write_pack` validates every line and
/// rejects the whole file on the first bad one, so a surface that rebuilt a
/// pack from what it had drawn would either refuse a file that loaded
/// cleanly or silently drop the operator's comments and every line the
/// reader had skipped. `add_rule` appends and touches nothing else.
///
/// Serialised on the tree write lock, because the append is a
/// read-modify-write: two of them reading the same pre-state each rewrite
/// from it, and the second drops the first operator's rule silently.
pub fn append_rule(
    loaded: &LoadedConfig,
    id: &Id,
    domain: &str,
    allow: bool,
) -> Result<crate::config::custom_list::AddOutcome, PackAccessError> {
    let path = pack_file(loaded, id)?;
    let lock = claim_tree(loaded)?;
    Ok(crate::config::custom_list::add_rule(
        &lock,
        &path,
        domain,
        allow,
        max_pack_bytes(loaded),
    )?)
}

/// Replace the rule on one file line. **The only way this leaf edits one.**
///
/// Not remove-then-add: `remove_rule` matches the domain and ignores the
/// direction, so a flip composed from the two primitives would take the
/// opposite direction of the same domain with it — a rule the operator
/// never touched.
///
/// `expect` is the rule the pane RENDERED on that line. The pack view is
/// re-read when the selection changes, so any write it did not see moves
/// the numbering; the writer refuses on the mismatch rather than editing
/// whatever now sits there.
pub fn replace_rule(
    loaded: &LoadedConfig,
    id: &Id,
    line: usize,
    expect: (&str, bool),
    domain: &str,
    allow: bool,
) -> Result<(), PackAccessError> {
    let path = pack_file(loaded, id)?;
    let lock = claim_tree(loaded)?;
    Ok(crate::config::custom_list::replace_rule_at_line(
        &lock,
        &path,
        line,
        expect,
        domain,
        allow,
        max_pack_bytes(loaded),
    )?)
}

/// Drop `domain` from a pack — **in both directions**.
///
/// `remove_rule` matches on the domain alone, so a domain present as both
/// an allow and a deny loses both lines in one call. Every confirm that
/// reaches here has to say so: the row under the cursor shows one direction
/// and nothing on it hints at the other.
pub fn delete_rule(loaded: &LoadedConfig, id: &Id, domain: &str) -> Result<bool, PackAccessError> {
    let path = pack_file(loaded, id)?;
    let lock = claim_tree(loaded)?;
    Ok(crate::config::custom_list::remove_rule(
        &lock,
        &path,
        domain,
        max_pack_bytes(loaded),
    )?)
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_empty(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "  no custom lists declared.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  a custom list is a file you write yourself — allow and deny",
            Style::default().fg(T.text_muted),
        )),
        Line::from(Span::styled(
            "  rules together, mounted on the profiles you choose.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        // **Offered only because `a` is bound.** This read `[a] create one`
        // for a whole release while no handler existed: the operator
        // pressed it, nothing happened, and the reasonable conclusion was
        // that the tab was broken. The row and its handler travel together.
        Line::from(Span::styled(
            "  [a] create one",
            Style::default().fg(T.text_secondary),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

/// The rule pane's empty state.
///
/// Not "the file is empty": a pack holding only comments and blanks has
/// bytes in it and still enforces nothing, and this pane lists only the
/// lines that carry a rule.
///
/// The offered key depends on `focused` because `a` is bound per pane —
/// on the list pane it adds a LIST. A hint that named `a` unconditionally
/// would send the operator to the wrong modal from the state they are
/// actually in.
fn render_no_rules(f: &mut Frame, area: Rect, focused: bool) {
    let hint = if focused {
        "  [a] add a rule"
    } else {
        "  [\u{2192}] then [a] to add a rule"
    };
    let lines = vec![
        Line::from(Span::styled(
            "  no rules in this list.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(hint, Style::default().fg(T.text_secondary))),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn render_muted(f: &mut Frame, area: Rect, text: &str) {
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(T.text_muted),
        ))),
        area,
    );
}

fn render_no_config(f: &mut Frame, area: Rect) {
    let outer = render_section_chrome(f, area, "Custom Lists", T.text_secondary);
    render_muted(f, outer, "  no configuration loaded.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::custom_list::CustomListStore;
    use crate::config::schema::{ConfigV1, Id, Profile};
    use compact_str::CompactString;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn entity(id: &str) -> CustomList {
        CustomList {
            id: Id::new(id).unwrap(),
            display_name: String::new(),
            description: String::new(),
        }
    }

    fn compiled(allow: &[&str], deny: &[&str], skipped: usize) -> CompiledCustomList {
        CompiledCustomList {
            allow: allow.iter().map(|d| CompactString::new(d)).collect(),
            deny: deny.iter().map(|d| CompactString::new(d)).collect(),
            skipped,
        }
    }

    fn profile_mounting(ids: &[&str]) -> Profile {
        Profile {
            custom_lists: ids.iter().map(|i| Id::new(*i).unwrap()).collect(),
            ..Default::default()
        }
    }

    fn loaded(
        entities: Vec<CustomList>,
        store: Vec<(&str, CompiledCustomList)>,
        profiles: Vec<(&str, Profile)>,
    ) -> LoadedConfig {
        let mut compiled_store = CustomListStore::new();
        for (id, c) in store {
            compiled_store.insert(Id::new(id).unwrap(), c);
        }
        LoadedConfig {
            config: ConfigV1 {
                custom_lists: entities,
                profiles: profiles
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                ..Default::default()
            },
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: compiled_store,
        }
    }

    /// A screen dump with every style discarded — which is exactly why the
    /// focus cue has to be a glyph.
    fn screen(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, f.area(), app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn app_with(loaded: LoadedConfig) -> App {
        let mut app = App::new();
        app.active_leaf = crate::tui::app::Leaf::CustomLists;
        app.loaded_config = Some(loaded);
        app
    }

    #[test]
    fn counts_come_from_the_store_and_used_by_from_the_profiles() {
        let l = loaded(
            vec![entity("videogames"), entity("casa")],
            vec![
                ("videogames", compiled(&["a.example"], &["b.example"], 0)),
                ("casa", compiled(&[], &["c.example"], 2)),
            ],
            vec![
                ("kids", profile_mounting(&["videogames"])),
                ("guest", profile_mounting(&["videogames"])),
                ("default", profile_mounting(&[])),
            ],
        );
        let rows = list_rows(&l);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].allow, rows[0].deny, rows[0].skipped), (1, 1, 0));
        assert_eq!(rows[0].used_by, 2, "two profiles mount videogames");
        assert_eq!((rows[1].allow, rows[1].deny, rows[1].skipped), (0, 1, 2));
        assert_eq!(rows[1].used_by, 0);
    }

    /// A list nothing mounts enforces nothing, however many rules it holds.
    /// The counts cannot say that — a 32-rule list mounted by nobody reads
    /// as the busiest row in the table.
    #[test]
    fn a_list_no_profile_mounts_is_inert_however_many_rules_it_has() {
        let l = loaded(
            vec![entity("orphan")],
            vec![(
                "orphan",
                compiled(&["a.example", "b.example"], &["c.example"], 0),
            )],
            vec![("kids", profile_mounting(&[]))],
        );
        let rows = list_rows(&l);
        assert!(rows[0].is_inert());
        assert_eq!(used_by_text(rows[0].used_by), USED_BY_NONE);
    }

    #[test]
    fn the_anchor_resolves_by_id_and_reports_a_dangling_one() {
        let l = loaded(
            vec![entity("a"), entity("b")],
            vec![("a", compiled(&[], &[], 0)), ("b", compiled(&[], &[], 0))],
            vec![],
        );
        let rows = list_rows(&l);
        assert_eq!(resolve_selected_index(&rows, Some("b")), Some(1));
        assert_eq!(resolve_selected_index(&rows, Some("gone")), None);
        assert_eq!(resolve_selected_index(&rows, None), None);
    }

    /// Order is the config's, so the row the cursor rests on does not move
    /// when the store's `BTreeMap` would have sorted it elsewhere.
    #[test]
    fn rows_keep_config_order_not_the_stores_sort_order() {
        let l = loaded(
            vec![entity("zulu"), entity("alpha")],
            vec![
                ("zulu", compiled(&[], &[], 0)),
                ("alpha", compiled(&[], &[], 0)),
            ],
            vec![],
        );
        let rows = list_rows(&l);
        assert_eq!(rows[0].entity.id.as_str(), "zulu");
        assert_eq!(rows[1].entity.id.as_str(), "alpha");
    }

    // ── Render ───────────────────────────────────────────────────────

    #[test]
    fn the_table_paints_the_id_the_counts_and_the_used_by_dash() {
        let l = loaded(
            vec![entity("videogames"), entity("orphan")],
            vec![
                (
                    "videogames",
                    compiled(&["a.example"], &["b.example", "c.example"], 1),
                ),
                ("orphan", compiled(&[], &[], 0)),
            ],
            vec![("kids", profile_mounting(&["videogames"]))],
        );
        let out = screen(&mut app_with(l), 80, 12);
        assert!(out.contains("Custom Lists (2)"), "title; got:\n{out}");
        assert!(out.contains("videogames"), "id; got:\n{out}");
        assert!(out.contains("USED BY"), "header; got:\n{out}");
        assert!(
            out.contains(USED_BY_NONE),
            "a list nobody mounts shows the dash, not a bare 0; got:\n{out}"
        );
    }

    /// The cursor is drawn as a **glyph**, not as a colour.
    ///
    /// This dump discards every style, so a colour-only cue would leave a
    /// build that paints no cursor at all looking identical.
    ///
    /// It does **not** yet pin a focus *distinction*: there is one pane and
    /// one focus variant, so the resting glyph is unreachable. The name
    /// says only what the assertion proves.
    #[test]
    fn the_cursor_is_a_glyph_a_style_blind_dump_can_see() {
        let l = loaded(
            vec![entity("videogames")],
            vec![("videogames", compiled(&[], &[], 0))],
            vec![],
        );
        let mut app = app_with(l);
        app.custom_lists.selected_id = Some("videogames".to_string());
        let out = screen(&mut app, 80, 12);
        assert!(
            out.contains(CURSOR_FOCUSED.trim_end()),
            "the focused pane must draw {CURSOR_FOCUSED:?}; got:\n{out}"
        );
    }

    /// An empty config is the state every box is in before the first list,
    /// so it has to say what a custom list *is* — and must not offer a key
    /// that does nothing.
    ///
    /// **`[a] create one` is back, and the history is the point.** It
    /// shipped once while no `a` handler existed, so the only witness to
    /// this assertion was the phantom affordance it was meant to guard.
    /// The key is bound now, which is what makes the row honest — and
    /// `every_key_the_custom_lists_leaf_advertises_is_bound` is what keeps
    /// the two travelling together rather than this string.
    #[test]
    fn the_empty_state_explains_the_concept_and_offers_the_bound_key() {
        let out = screen(&mut app_with(loaded(vec![], vec![], vec![])), 80, 12);
        assert!(out.contains("no custom lists declared"), "got:\n{out}");
        assert!(
            out.contains("a file you write yourself"),
            "the empty state must say what a custom list IS; got:\n{out}"
        );
        assert!(
            out.contains("[a] create one"),
            "`a` is bound now, so the empty state must offer it; got:\n{out}"
        );
    }

    // ── Rule pane ────────────────────────────────────────────────────

    fn views(lines: &[&str]) -> Vec<crate::config::custom_list::PackLineView> {
        use crate::config::custom_list::parse_pack_line;
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| crate::config::custom_list::PackLineView {
                number: i + 1,
                raw: (*l).to_string(),
                parsed: parse_pack_line(l),
            })
            .collect()
    }

    fn app_with_pack(lines: &[&str]) -> App {
        let l = loaded(
            vec![entity("videogames")],
            vec![("videogames", compiled(&[], &[], 0))],
            vec![],
        );
        let mut app = app_with(l);
        app.custom_lists.selected_id = Some("videogames".to_string());
        app.custom_lists.pack = Some(crate::tui::app::PackView {
            id: "videogames".to_string(),
            rows: rows_from_views(&views(lines)),
            error: None,
        });
        app
    }

    /// **The pane lists rules; a refusal is still a rule, only broken.**
    ///
    /// The two are not one class. A comment enforces nothing and the
    /// operator wrote it, so hiding it costs nothing. A refused line is
    /// reported everywhere else as a bare `S` count, so hiding it would
    /// leave a degraded file with no surface that names the bad lines —
    /// which is why the raw column is not redundant with DOMAIN.
    #[test]
    fn comments_are_dropped_and_refused_lines_survive() {
        let out = screen(
            &mut app_with_pack(&[
                "# ---- Mojang ----",
                "@@||minecraft.net^",
                "",
                "||tracking.example.com^",
                "this line is not a rule",
            ]),
            120,
            14,
        );
        assert!(out.contains("Rules"), "the pane must render; got:\n{out}");
        assert!(
            !out.contains("Mojang"),
            "a comment must not reach the screen; got:\n{out}"
        );
        assert!(
            out.contains("this line is not a rule"),
            "a refused line must be visible, not filtered away; got:\n{out}"
        );
        assert!(
            out.contains(ACTION_SKIPPED),
            "a refused line must be labelled {ACTION_SKIPPED}; got:\n{out}"
        );
        assert!(out.contains("Allow"), "got:\n{out}");
        assert!(out.contains("Deny"), "got:\n{out}");
    }

    /// A file with bytes in it is not an empty file, and saying so of a
    /// pack that holds only comments is a different claim from the true
    /// one: it enforces nothing.
    #[test]
    fn a_pack_of_only_comments_reads_as_ruleless_not_as_an_empty_file() {
        let out = screen(&mut app_with_pack(&["# a custom list", ""]), 120, 12);
        assert!(
            out.contains("no rules in this list"),
            "the empty state must say there are no rules; got:\n{out}"
        );
        assert!(
            !out.contains("the file is empty"),
            "a file with bytes in it is not empty; got:\n{out}"
        );
    }

    /// Rule order is file order — never allow-then-deny — and `number` is
    /// the FILE line, so dropping a comment and a blank leaves the
    /// surviving numbers non-contiguous. That gap is the property worth
    /// pinning: it is what an operator repairing the file by hand types
    /// into their editor, and what `resolve_line_index` anchors on.
    #[test]
    fn rows_are_rules_only_and_keep_their_file_line_numbers() {
        let rows = rows_from_views(&views(&["# head", "||a.example^", "", "@@||b.example^"]));
        assert_eq!(rows.len(), 2, "a comment and a blank are not rules");
        assert_eq!(
            rows.iter().map(|r| r.number).collect::<Vec<_>>(),
            vec![2, 4],
            "the numbers are file lines, so they skip what was filtered"
        );
        assert_eq!(rows[0].action, PackRowAction::Deny);
        assert_eq!(rows[1].action, PackRowAction::Allow);
        assert_eq!(rows[0].domain.as_deref(), Some("a.example"));
        assert!(
            rows.iter().all(|r| r.action != PackRowAction::None),
            "no row may carry the no-rule action"
        );
    }

    /// **The title is what answers "is this list selected?".** With one row
    /// the highlight has no unhighlighted neighbour to contrast against, so
    /// naming the selection is the fix — the same thing Devices does.
    #[test]
    fn the_rule_pane_names_the_selected_list_in_its_title() {
        let out = screen(&mut app_with_pack(&["||a.example^"]), 120, 12);
        assert!(
            out.contains("Rules \u{00b7} videogames"),
            "the title must name the selection; got:\n{out}"
        );
    }

    /// No selection is not an error state; it reads like Devices' own.
    #[test]
    fn with_no_selection_the_rule_pane_invites_one() {
        let l = loaded(
            vec![entity("videogames")],
            vec![("videogames", compiled(&[], &[], 0))],
            vec![],
        );
        let out = screen(&mut app_with(l), 120, 12);
        assert!(out.contains(NO_SELECTION.trim()), "got:\n{out}");
    }

    /// An unreadable FILE is not an unparseable LINE. Collapsing the two
    /// would make "cannot be read" look like "has no rules".
    #[test]
    fn an_unreadable_file_says_so_instead_of_rendering_as_empty() {
        let mut app = app_with_pack(&[]);
        app.custom_lists.pack = Some(crate::tui::app::PackView {
            id: "videogames".to_string(),
            rows: Vec::new(),
            error: Some("permission denied".to_string()),
        });
        let out = screen(&mut app, 120, 12);
        assert!(out.contains("could not be read"), "got:\n{out}");
        assert!(out.contains("permission denied"), "got:\n{out}");
    }

    /// Below the split threshold the rule pane is not painted at all, so
    /// the focus must never rest there. At the 80-column floor that is the
    /// normal state.
    #[test]
    fn the_split_collapses_at_the_eighty_column_floor() {
        assert!(
            !rules_pane_is_painted(80),
            "at the declared floor the rule pane must not be promised"
        );
        assert!(rules_pane_is_painted(120), "a wide terminal splits");
        let out = screen(&mut app_with_pack(&["||a.example^"]), 80, 12);
        assert!(
            !out.contains("Rules \u{00b7}"),
            "the collapsed layout must not paint a rule pane; got:\n{out}"
        );
        assert!(
            out.contains("USED BY"),
            "the list pane survives; got:\n{out}"
        );
    }

    /// At the declared floor the table still shows the columns `d` depends
    /// on. A cell that truncates does so in silence, so this reads the
    /// buffer rather than the row vector.
    #[test]
    fn used_by_survives_the_eighty_column_floor() {
        let l = loaded(
            vec![entity("videogames")],
            vec![("videogames", compiled(&[], &[], 0))],
            vec![("kids", profile_mounting(&["videogames"]))],
        );
        let out = screen(&mut app_with(l), 80, 24);
        assert!(
            out.contains("USED BY"),
            "USED BY must be readable before `d` is safe; got:\n{out}"
        );
    }

    /// A `LoadedConfig` rooted in a real directory, so `packs/` and the
    /// tree write lock both resolve under `dir`.
    ///
    /// Built as a struct literal rather than through `load_config`: the
    /// writers below read only `master_path` and the byte cap, and a TOML
    /// fixture would tie these tests to schema fields they never touch.
    fn loaded_at(dir: &std::path::Path) -> LoadedConfig {
        let mut l = loaded(vec![entity("videogames")], vec![], vec![]);
        l.master_path = dir.join("config.toml");
        l
    }

    /// An empty pack for `videogames`, plus the comment line a real one
    /// carries — appends must not eat it.
    fn seed_pack(dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::create_dir_all(dir.join("packs")).unwrap();
        let pack = dir.join("packs").join("videogames.txt");
        std::fs::write(&pack, "# hand-written\n").unwrap();
        pack
    }

    /// **Concurrent appends to one pack must not lose each other.**
    ///
    /// `add_rule` is a read-modify-write: it reads the whole file, appends
    /// one line and rewrites it. The write is atomic, so no reader ever
    /// sees a torn file — but atomicity says nothing about staleness. Two
    /// writers that both read the pre-state each rewrite from it, and the
    /// second erases the first operator's rule with no error on either
    /// side. Serialising on the tree write lock is what closes it.
    #[test]
    fn concurrent_appends_to_one_pack_all_land() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 4;

        let dir = tempfile::tempdir().unwrap();
        let pack = seed_pack(dir.path());
        let l = loaded_at(dir.path());
        let id = Id::new("videogames").unwrap();

        std::thread::scope(|s| {
            for t in 0..THREADS {
                let (l, id) = (&l, &id);
                s.spawn(move || {
                    for n in 0..PER_THREAD {
                        append_rule(l, id, &format!("d{t}x{n}.example.com"), false)
                            .expect("every append must land");
                    }
                });
            }
        });

        let text = std::fs::read_to_string(&pack).unwrap();
        let rules = text.lines().filter(|l| l.starts_with("||")).count();
        assert_eq!(
            rules,
            THREADS * PER_THREAD,
            "a lost update dropped {} rule(s); file:\n{text}",
            THREADS * PER_THREAD - rules
        );
        assert!(
            text.contains("# hand-written"),
            "the operator's comment must survive every append; got:\n{text}"
        );
    }

    /// The removal half of the same race: interleaved appends and removals
    /// must leave the file agreeing with the calls that were made.
    #[test]
    fn a_removal_concurrent_with_appends_does_not_resurrect_rules() {
        const THREADS: usize = 6;

        let dir = tempfile::tempdir().unwrap();
        let pack = seed_pack(dir.path());
        let l = loaded_at(dir.path());
        let id = Id::new("videogames").unwrap();

        // Present before the race, and removed during it by one thread.
        append_rule(&l, &id, "doomed.example.com", false).unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                delete_rule(&l, &id, "doomed.example.com").expect("the removal must land");
            });
            for t in 0..THREADS {
                let (l, id) = (&l, &id);
                s.spawn(move || {
                    append_rule(l, id, &format!("k{t}.example.com"), false)
                        .expect("every append must land");
                });
            }
        });

        let text = std::fs::read_to_string(&pack).unwrap();
        for t in 0..THREADS {
            assert!(
                text.contains(&format!("||k{t}.example.com^")),
                "append k{t} was lost; file:\n{text}"
            );
        }
        assert!(
            !text.contains("doomed.example.com"),
            "a concurrent append rewrote the removal away; file:\n{text}"
        );
    }
}
