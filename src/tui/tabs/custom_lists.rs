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
//! ## Why the counts come from the store, not from a file read
//!
//! [`crate::config::loader::LoadedConfig::custom_lists`] is the compiled
//! store, built once per config load. This pane costs no I/O.
//!
//! ## What no surface here may ever do
//!
//! Never rebuild a pack file from rendered rows. Reading is permissive —
//! an unparseable line is skipped and counted — while `write_pack` refuses
//! the whole write at the first invalid line. A save that round-tripped
//! rendered rows would therefore either fail on a file that loaded
//! cleanly, or "repair" it by deleting the operator's comments and every
//! line the reader had skipped. `add_rule` and `remove_rule` are the only
//! writers this leaf may reach for, and both preserve order, comments and
//! broken lines.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::config::custom_list::CompiledCustomList;
use crate::config::loader::LoadedConfig;
use crate::config::schema::{CustomList, Id};
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

/// `ACTION` for a line that carries no rule — a comment or a blank.
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

pub fn render(f: &mut Frame, area: Rect, app: &App) {
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

    if outer.width < SPLIT_THRESHOLD {
        render_lists_pane(f, outer, app, &rows);
        return;
    }

    // Devices' proportions inverted: there are few lists and many rules.
    let cols = Layout::horizontal([
        Constraint::Length(LISTS_W),
        Constraint::Length(1),
        Constraint::Min(50),
    ])
    .split(outer);

    render_lists_pane(f, cols[0], app, &rows);
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
fn render_rules_pane(f: &mut Frame, area: Rect, app: &App) {
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
        render_muted(f, content, "  the file is empty.");
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

    let mut state = TableState::default();
    state.select(Some(
        resolve_line_index(&pack.rows, app.custom_lists.selected_line).unwrap_or(0),
    ));

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

    f.render_stateful_widget(table, content, &mut state);
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

/// Turn the reader's views into rows, **keeping every line**.
///
/// One row per line of the file, in file order. Comments, blanks and lines
/// the grammar refused all survive with their raw text: dropping them would
/// make this pane agree with `read_pack`, which is exactly the reader that
/// cannot show a degraded file.
pub fn rows_from_views(views: &[crate::config::custom_list::PackLineView]) -> Vec<PackRow> {
    use crate::config::custom_list::PackLine;
    views
        .iter()
        .map(|v| {
            let (domain, action) = match &v.parsed {
                Ok(PackLine::Allow(d)) => (Some(d.to_string()), PackRowAction::Allow),
                Ok(PackLine::Deny(d)) => (Some(d.to_string()), PackRowAction::Deny),
                Ok(PackLine::Blank) => (None, PackRowAction::None),
                Err(_) => (None, PackRowAction::Skipped),
            };
            PackRow {
                number: v.number,
                raw: v.raw.clone(),
                domain,
                action,
            }
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

fn render_lists_pane(f: &mut Frame, area: Rect, app: &App, rows: &[ListRow<'_>]) {
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
    let mut state = TableState::default();
    state.select(Some(
        resolve_selected_index(rows, app.custom_lists.selected_id.as_deref()).unwrap_or(0),
    ));

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
    .highlight_symbol(cursor_glyph(
        app.custom_lists.focus == CustomListsFocus::Lists,
    ))
    .row_highlight_style(theme::highlight_style());

    f.render_stateful_widget(table, area, &mut state);
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

/// Append one rule. **The only way this leaf grows a pack.**
///
/// The choke point is the point. `write_pack` validates every line and
/// rejects the whole file on the first bad one, so a surface that rebuilt a
/// pack from what it had drawn would either refuse a file that loaded
/// cleanly or silently drop the operator's comments and every line the
/// reader had skipped. `add_rule` appends and touches nothing else.
pub fn append_rule(
    loaded: &LoadedConfig,
    id: &Id,
    domain: &str,
    allow: bool,
) -> Result<crate::config::custom_list::AddOutcome, PackAccessError> {
    let path = pack_file(loaded, id)?;
    Ok(crate::config::custom_list::add_rule(
        &path,
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
    Ok(crate::config::custom_list::remove_rule(
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
    fn screen(app: &App, w: u16, h: u16) -> String {
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
        let out = screen(&app_with(l), 80, 12);
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
        let out = screen(&app, 80, 12);
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
        let out = screen(&app_with(loaded(vec![], vec![], vec![])), 80, 12);
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

    /// **The whole reason the raw column is not redundant with DOMAIN.**
    ///
    /// `read_pack` returns compiled rules and reports a comment or a broken
    /// line as nothing at all — the list pane can only show `S` as a count.
    /// This pane is the one surface where a degraded file is legible, so
    /// every line of the file has to reach it: comments with `—`, refused
    /// lines with `SKIPPED`, both carrying their original text.
    #[test]
    fn comments_and_refused_lines_are_rows_not_omissions() {
        let out = screen(
            &app_with_pack(&[
                "# ---- Mojang ----",
                "@@||minecraft.net^",
                "||tracking.example.com^",
                "this line is not a rule",
            ]),
            120,
            14,
        );
        assert!(out.contains("Rules"), "the pane must render; got:\n{out}");
        assert!(
            out.contains("# ---- Mojang ----"),
            "a comment must survive to the screen with its text; got:\n{out}"
        );
        assert!(
            out.contains("this line is not a rule"),
            "a refused line must be visible, not filtered away; got:\n{out}"
        );
        assert!(
            out.contains(ACTION_SKIPPED),
            "a refused line must be labelled {ACTION_SKIPPED}; got:\n{out}"
        );
        assert!(
            out.contains(ACTION_NONE),
            "a comment's ACTION must read as no rule; got:\n{out}"
        );
        assert!(out.contains("Allow"), "got:\n{out}");
        assert!(out.contains("Deny"), "got:\n{out}");
    }

    /// One row per line of the file, in file order — never allow-then-deny.
    /// The line number is the anchor an operator repairing the file by hand
    /// types into their editor, so it has to match the file.
    #[test]
    fn rows_keep_file_order_and_one_based_line_numbers() {
        let rows = rows_from_views(&views(&["# head", "||a.example^", "", "@@||b.example^"]));
        assert_eq!(rows.len(), 4, "one row per line, blanks included");
        assert_eq!(
            rows.iter().map(|r| r.number).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(rows[1].action, PackRowAction::Deny);
        assert_eq!(rows[3].action, PackRowAction::Allow);
        assert_eq!(rows[0].domain, None, "a comment has no domain");
        assert_eq!(rows[1].domain.as_deref(), Some("a.example"));
    }

    /// **The title is what answers "is this list selected?".** With one row
    /// the highlight has no unhighlighted neighbour to contrast against, so
    /// naming the selection is the fix — the same thing Devices does.
    #[test]
    fn the_rule_pane_names_the_selected_list_in_its_title() {
        let out = screen(&app_with_pack(&["||a.example^"]), 120, 12);
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
        let out = screen(&app_with(l), 120, 12);
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
        let out = screen(&app, 120, 12);
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
        let out = screen(&app_with_pack(&["||a.example^"]), 80, 12);
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
        let out = screen(&app_with(l), 80, 24);
        assert!(
            out.contains("USED BY"),
            "USED BY must be readable before `d` is safe; got:\n{out}"
        );
    }
}
