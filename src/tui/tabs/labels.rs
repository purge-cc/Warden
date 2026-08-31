//! Labels tab — the `[[labels]]` vocabulary (§4.66 L2, extended by L5).
//!
//! Left card: the kinds with their counts. Right card: the entries of
//! the selected kind, with how many entities actually use each. `Tab` /
//! `←` / `→` move focus between the two cards; `↑` / `↓` move inside the
//! focused one (§4.68 UX8).
//!
//! The menu lists the kinds [`menu_kinds`] yields — **three**, not the
//! enum's four; see that function for why the narrowing cannot live in
//! [`LabelKind::valid_values`]. The fourth, `tag`, is not offered here and
//! is not shown anywhere else either — `plp-s5d` removed the surfaces that
//! consumed it. `LabelKind::Tag` itself belongs to `plp-s5a`.
//!
//! ## Why a registry existed here for tags — and why it no longer does
//!
//! The argument this section carried is kept, because it is what a future
//! session would cite to bring the kind back. It ran: a tag needs no
//! registry, because `collect_known_tag_slugs` derives the vocabulary the
//! pickers use — but that derivation inserts **only what is attached**, so
//! it answers *autocomplete*, never *naming a tag before anything uses
//! it*, which was the operator's actual request. Hence a declared
//! vocabulary. `device_grouping_v1.md` §12.9 carries both measurements.
//!
//! A second lesson from the same paragraph, and it outlives the feature:
//! the enumeration of carriers read "blocklists / devices / profiles /
//! subnets" until §4.65 UX2b found the missing `groups` walk. The sentence
//! was written to *defend* the derivation's completeness while the
//! derivation was incomplete, and no test disagreed — **prose counting a
//! set is a claim, not a check.**
//!
//! `plp-s5d` removed both the pickers and their derivation. There is no
//! autocomplete left to feed and nothing that reads a tag, so the whole
//! argument is now historical: `menu_kinds` had already stopped offering
//! the Tags bucket, and `usage_count` no longer counts one.
//!
//! `owner` / `device-type` / `department` are a different case for a
//! different reason: they are free text on `[[devices]]`, read by nothing,
//! and have **no** derived vocabulary anywhere at all.
//!
//! ## The USED column counts two different things
//!
//! For the three metadata kinds: `Device.owner` is free text
//! (`"Alex"`); `Label.id` is an `Id` (`"alex"`). They can never be
//! equal, so the count goes through [`Label::matches_value`], which
//! accepts **id or display_name**.
//!
//! `tag` used to be the second thing: `TagSlug`s counted across five
//! carrier entities, delegated to `cli::commands::tags::collect_tag_usage`
//! so the TUI and the CLI could not disagree. `plp-s5d` dropped that — see
//! [`usage_count`] — and no `Tag` row reaches this tab anyway.
//!
//! A count of 0 means "nothing uses this value", not "this label is
//! broken": a device carrying an undeclared metadata value is legal and
//! WARNs at load.
//!
//! ```text
//! Labels (3)                       (focus on the kind menu)
//!   KIND            │   ID          NAME        DESCRIPTION      USED
//!   ▸ Owners      2 │ · alex     Alex     Personal kit        4
//!     Device types 1│   emanuela    Emanuela    —                   2
//!     Departments  0│
//! ```
//!
//! `▸` marks the cursor of the **focused** pane, `·` the resting cursor
//! of the other one. Pressing `→` swaps them.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::config::schema::{Label, LabelKind};
use crate::tui::app::{App, LabelsFocus};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Below this width the split collapses to the entry table alone — the
/// kind menu is three rows and the table is the part that carries data.
const NARROW_THRESHOLD: u16 = 90;

/// Width of the left kind-menu column.
const MENU_W: u16 = 22;

/// Columns `render_section_chrome` consumes before the leaf sees its
/// rect: one border cell and one padding cell on each side.
const CHROME_W: u16 = 4;

/// Does a terminal this wide actually paint the kind menu?
///
/// **The focus must never rest on a pane the layout does not draw**, and
/// at the D18 floor of 80×24 this leaf has only one pane: the rect
/// reaching [`render`] is 76 columns, below [`NARROW_THRESHOLD`], so the
/// split collapses to the entry table. A `KindMenu` focus there is
/// unhonourable — `↑`/`↓` would change the whole table's *contents*
/// while the operator, seeing only a table, expects its rows to move.
///
/// Lowering the threshold was the other candidate fix and was rejected:
/// it would squeeze a 22-column menu into 76 and overturn a deliberate
/// decision that carries its own comment. Clamping the focus leaves that
/// decision intact.
///
/// Takes the **viewport** width because the caller in the render loop is
/// the only place that knows it, and the tab body spans the full width
/// (`layout_chunks` splits vertically only).
pub fn menu_is_painted(viewport_width: u16) -> bool {
    viewport_width.saturating_sub(CHROME_W) >= NARROW_THRESHOLD
}

/// The kinds this leaf offers, and the **only** list any part of it may
/// enumerate — the menu, the empty-state hint, and the key handler all
/// read this one function.
///
/// ## Why `tag` is not here, and why the filter lives in the TUI
///
/// §4.68 UX8 narrowed this because the operator saw "Tags" in two places
/// — this registry and a separate Tags tab — and asked the registry to
/// stop claiming it. The two were not duplicates: a tag was an **open**
/// set defined by use, derived from what entities actually carried, while
/// these three are a **closed** vocabulary that exists only because
/// someone declared it.
///
/// `plp-s5d` deleted the Tags tab and the derivation behind it, so only
/// the closed half survives. The narrowing stands on its own terms — a
/// `tag` declares nothing this tab can administer — and is now enforced
/// by the same `device_field()` rule stated below rather than by the
/// existence of somewhere else to look.
///
/// **The filter cannot live in [`LabelKind::valid_values`].** That
/// function has two other consumers — the `--kind` help of
/// `warden label add` and the validator's unknown-kind suggestion — and
/// both must keep offering `tag`, because declaring a tag from the CLI
/// stays legal. Narrowing it at the source would silently delete a CLI
/// affordance. So the narrowing is a **view** concern and lives here.
///
/// Derived rather than spelled out: a kind is a Labels-registry kind iff
/// it supplies a `[[devices]]` field. That is the same distinction the
/// module doc draws — `owner`/`device-type`/`department` are free text on
/// a device and have no derived vocabulary anywhere, `tag` has one. A new
/// device-metadata kind therefore arrives here for free, and a second
/// use-derived kind stays out for the same reason `tag` does.
pub fn menu_kinds() -> Vec<LabelKind> {
    LabelKind::ALL.to_vec()
}

/// Named so the empty state can point at the verb that makes the first one.
/// L2 is read-plus-declare; there is no other way to seed a vocabulary.
///
/// Built from [`menu_kinds`] — the same list the menu draws — so the tab
/// can never tell an operator to declare a kind it refuses to show them.
/// `empty_hint_names_every_menu_kind` and `empty_hint_and_menu_agree` pin
/// both halves of that.
pub fn empty_hint() -> String {
    let kinds: Vec<&str> = menu_kinds().iter().map(|k| k.as_str()).collect();
    format!("  warden label add <id> --kind <{}>", kinds.join("|"))
}

/// Human label for a kind in the left menu. Plural, because the row is a
/// bucket rather than a single value.
///
pub fn kind_menu_label(kind: LabelKind) -> &'static str {
    match kind {
        LabelKind::Owner => "Owners",
        LabelKind::DeviceType => "Device types",
        LabelKind::Department => "Departments",
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    let labels = &loaded.config.labels;
    let title = format!("Labels ({})", labels.len());
    let outer = render_section_chrome(f, area, &title, T.text_secondary);

    if outer.width < NARROW_THRESHOLD {
        render_entries(f, outer, app, loaded, labels);
        return;
    }

    let cols = Layout::horizontal([
        Constraint::Length(MENU_W),
        Constraint::Length(1),
        Constraint::Min(30),
    ])
    .split(outer);

    render_kind_menu(f, cols[0], app, labels);
    draw_v_divider(f, cols[1]);
    render_entries(f, cols[2], app, loaded, labels);
}

// ── Left card: the kinds ─────────────────────────────────────────────

fn render_kind_menu(f: &mut Frame, area: Rect, app: &App, labels: &[Label]) {
    let selected = app.labels.selected_kind;
    let pane_focused = app.labels.focus == LabelsFocus::KindMenu;
    let lines: Vec<Line> = menu_kinds()
        .iter()
        .map(|k| {
            let n = labels.iter().filter(|l| l.kind == *k).count();
            let focused = *k == selected;
            // Two distinct glyphs, not two colours. A `TestBackend`
            // buffer compared via `to_string()` discards every style, so
            // a colour-only focus cue is invisible to exactly the test
            // that is supposed to prove focus is drawn — it would pass on
            // a build showing no focus at all. Both markers are 2 cells
            // so the column does not shift when focus moves.
            let marker = match (focused, pane_focused) {
                (true, true) => "\u{25b8} ",  // ▸ selected, pane has the cursor
                (true, false) => "\u{00b7} ", // · selected, cursor is elsewhere
                (false, _) => "  ",
            };
            let style = if focused {
                Style::default()
                    .fg(if pane_focused {
                        T.brand_red
                    } else {
                        T.text_secondary
                    })
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(T.text_secondary)
            };
            Line::from(vec![
                Span::styled(format!("{marker}{:<13}", kind_menu_label(*k)), style),
                Span::styled(format!("{n:>3}"), Style::default().fg(T.text_muted)),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), area);
}

// ── Right card: the entries of the selected kind ──────────────────────

fn render_entries(
    f: &mut Frame,
    area: Rect,
    app: &App,
    loaded: &crate::config::loader::LoadedConfig,
    labels: &[Label],
) {
    let kind = app.labels.selected_kind;
    let rows_data = rows_for_kind(labels, kind);

    if rows_data.is_empty() {
        render_empty_for_kind(f, area, kind, labels.is_empty());
        return;
    }

    let header = Row::new(vec![
        Cell::from("ID"),
        Cell::from("NAME"),
        Cell::from("DESCRIPTION"),
        Cell::from("USED"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = rows_data
        .iter()
        .map(|l| {
            let used = usage_count(loaded, l);
            Row::new(vec![
                Cell::from(l.id.as_str().to_string()),
                Cell::from(l.display_name.clone()),
                Cell::from(l.description.clone().unwrap_or_else(|| "—".to_string())),
                Cell::from(used.to_string()),
            ])
        })
        .collect();

    // Re-resolve the anchor every frame rather than carrying an index: a
    // config reload can add, remove or reorder entries, and an index from
    // the previous frame then points at a different label. Mirrors Groups
    // and Profiles.
    let mut state = TableState::default();
    if let Some(idx) = resolve_selected_index(&rows_data, app.labels.selected_id.as_deref()) {
        state.select(Some(idx));
    } else if !rows.is_empty() {
        state.select(Some(0));
    }

    // Mirror of the kind menu's marker, for the same reason: the glyph
    // carries the focus, not the colour, so a style-blind buffer dump can
    // still tell the two states apart. Both are 2 cells wide, so the
    // columns stay put when focus moves.
    let symbol = if app.labels.focus == LabelsFocus::Entries {
        "\u{25b8} "
    } else {
        "\u{00b7} "
    };

    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Min(14),
            Constraint::Min(16),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .highlight_symbol(symbol)
    .row_highlight_style(theme::highlight_style());

    f.render_stateful_widget(table, area, &mut state);
}

/// How many entities use this label's value.
///
/// For the kinds with a [`device_field`](LabelKind::device_field) it is
/// devices matched via [`Label::matches_value`] — id **or** display_name,
/// because the two sets never intersect on their own.
///
/// **the retired `LabelKind::Tag` returns 0, and `plp-s5d` is where that changed.**
/// It used to delegate to
/// `collect_tag_usage` (removed with `cli::commands::tags` in `plp-s5a`) —
/// the same collector `warden tags list` uses, so the TUI and the CLI
/// could not report different numbers — and `plp-s5c` deletes that
/// collector with the rest of `cli::commands::tags`.
///
/// **Returning 0 is not a silent loss here, and the reason is worth
/// checking rather than assuming.** A `Tag` label is already unreachable
/// from this tab: [`menu_kinds`] filters on `device_field().is_some()`, so
/// the left menu has not offered a Tags bucket since that narrowing, and
/// no rendered row can reach this branch. It survives only as the
/// non-`device_field` arm of a total match over a variant `plp-s5a` owns.
///
/// **Reported, not fixed here:** an operator whose config still declares
/// `[[labels]]` rows with `kind = "tag"` sees nothing about them in this
/// tab — not an empty bucket, not a notice. That predates this lane (the
/// `menu_kinds` narrowing did it) and is not this lane's to change, but it
/// is the shape of a silent drop and belongs in the S5 handoff.
pub fn usage_count(loaded: &crate::config::loader::LoadedConfig, label: &Label) -> usize {
    loaded
        .config
        .devices
        .iter()
        .filter(|d| {
            let field = match label.kind {
                LabelKind::Owner => d.owner.as_deref(),
                LabelKind::DeviceType => d.device_type.as_deref(),
                LabelKind::Department => d.department.as_deref(),
            };
            field.is_some_and(|v| label.matches_value(v))
        })
        .count()
}

/// The rows of one vocabulary, in the order the table paints them.
///
/// **One implementation, two consumers, on purpose.** [`render_entries`]
/// draws these rows and highlights one of them; `mod.rs::focused_label`
/// resolves which row `e` and `d` act on. If those two derived their row
/// set separately — a different filter, a different order — the operator
/// would edit or delete a row other than the one under the highlight, and
/// nothing on screen would say so. §4.68 UX8 named this hazard for this
/// sprint in advance: *"innocuo finché read-only, portante appena arriva
/// la CRUD"*.
pub fn rows_for_kind(labels: &[Label], kind: LabelKind) -> Vec<&Label> {
    labels.iter().filter(|l| l.kind == kind).collect()
}

/// Index of `selected_id` among the currently shown entries, or `None`
/// when the anchor no longer resolves.
pub fn resolve_selected_index(rows: &[&Label], selected_id: Option<&str>) -> Option<usize> {
    let want = selected_id?;
    rows.iter().position(|l| l.id.as_str() == want)
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_empty_for_kind(f: &mut Frame, area: Rect, kind: LabelKind, whole_vocab_empty: bool) {
    let mut lines = vec![Line::from(Span::styled(
        format!("  no {} declared.", kind_menu_label(kind).to_lowercase()),
        Style::default().fg(T.text_muted),
    ))];

    if whole_vocab_empty {
        // Worth saying once, on a config that has never had a vocabulary:
        // declaring one is optional, and nothing breaks without it.
        //
        // It used to branch on the kind: telling a Tags-row operator that
        // "these device fields stay free text" would have been false, since
        // a tag was neither a device field nor free text. `plp-s5a` removed
        // that kind, so every kind reaching here governs a device field and
        // one sentence is true for all of them.
        let (why_a, why_b) = (
            "  a vocabulary is optional — without one these device fields",
            "  stay free text, exactly as they are today.",
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            why_a,
            Style::default().fg(T.text_muted),
        )));
        lines.push(Line::from(Span::styled(
            why_b,
            Style::default().fg(T.text_muted),
        )));
    }

    lines.push(Line::from(""));
    // §4.66 L7: the dashboard can declare now, so the empty state leads
    // with the key. The CLI line stays underneath, unchanged and pinned —
    // it is what an operator scripting the box needs.
    //
    // Unconditional since `plp-s5a`. It used to be gated on the same
    // discriminator `menu_kinds` used, so the Tags state would not promise
    // `a` for a kind the leaf refused to focus; with that kind gone, every
    // kind the menu can select is one `a` can declare.
    lines.push(Line::from(Span::styled(
        "  press [a] to declare one.",
        Style::default().fg(T.text_secondary),
    )));
    lines.push(Line::from(Span::styled(
        empty_hint(),
        Style::default().fg(T.text_secondary),
    )));
    f.render_widget(Paragraph::new(lines), area);
}

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Labels", T.text_secondary);
    f.render_widget(
        Paragraph::new(Span::styled(
            "  could not load config — fix it and press r to retry",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
}

/// Paint a 1-cell-wide vertical separator. Mirrors Profiles/Groups.
fn draw_v_divider(f: &mut Frame, area: Rect) {
    let style = Style::default().fg(T.text_muted);
    let buf = f.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        if area.x < buf.area.right() && y < buf.area.bottom() {
            buf.set_string(area.x, y, "\u{2502}", style);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::loader::LoadedConfig;
    use crate::config::schema::{ConfigV1, Device, Id};

    fn label(id: &str, kind: LabelKind, display: &str) -> Label {
        Label {
            id: Id::new(id).unwrap(),
            kind,
            display_name: display.to_string(),
            description: None,
        }
    }

    fn loaded(labels: Vec<Label>, devices: Vec<Device>) -> LoadedConfig {
        LoadedConfig {
            config: ConfigV1 {
                labels,
                devices,
                ..Default::default()
            },
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        }
    }

    fn device(id: &str, field: Option<&str>, kind: LabelKind) -> Device {
        let v = field.map(|s| s.to_string());
        Device {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            ip: None,
            mac: None,
            mac_aliases: Vec::new(),
            profile: None,
            groups: Vec::new(),
            owner: if kind == LabelKind::Owner {
                v.clone()
            } else {
                None
            },
            device_type: if kind == LabelKind::DeviceType {
                v.clone()
            } else {
                None
            },
            department: if kind == LabelKind::Department {
                v
            } else {
                None
            },
            notes: None,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    /// The constraint that makes this column non-obvious: the device value
    /// and the label id can never be equal, so a naive `id == value` count
    /// would report 0 for a label that is in use everywhere.
    #[test]
    fn usage_counts_by_display_name_not_only_by_id() {
        let l = label("alex", LabelKind::Owner, "Alex");
        let lc = loaded(
            vec![l.clone()],
            vec![
                device("a", Some("Alex"), LabelKind::Owner),
                device("b", Some("Alex"), LabelKind::Owner),
            ],
        );
        assert_eq!(
            usage_count(&lc, &l),
            2,
            "devices carry the display name; counting ids alone would say 0"
        );
    }

    #[test]
    fn usage_counts_the_id_form_too() {
        let l = label("alex", LabelKind::Owner, "Alex");
        let lc = loaded(
            vec![l.clone()],
            vec![device("a", Some("alex"), LabelKind::Owner)],
        );
        assert_eq!(usage_count(&lc, &l), 1);
    }

    #[test]
    fn a_value_no_label_declares_counts_for_nobody() {
        // `Persona` vs `Personal` is the real drift on the live boxes. An
        // undeclared value is legal and must not be attributed to a
        // near-neighbour.
        let l = label("personal", LabelKind::Department, "Personal");
        let lc = loaded(
            vec![l.clone()],
            vec![device("a", Some("Persona"), LabelKind::Department)],
        );
        assert_eq!(
            usage_count(&lc, &l),
            0,
            "no fuzzy matching — a typo is a different value, not this one"
        );
    }

    #[test]
    fn selection_resolves_by_id_not_by_index() {
        let a = label("a", LabelKind::Owner, "A");
        let b = label("b", LabelKind::Owner, "B");
        let rows = vec![&a, &b];
        assert_eq!(resolve_selected_index(&rows, Some("b")), Some(1));
        assert_eq!(resolve_selected_index(&rows, Some("gone")), None);
    }

    /// Rendered-buffer test: a line-vector assertion passes even when the
    /// text is clipped off screen, which is exactly what an empty state
    /// exists to prevent.
    #[test]
    fn the_empty_state_names_the_cli_and_says_the_vocabulary_is_optional() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(70, 10)).unwrap();
        term.draw(|f| render_empty_for_kind(f, f.area(), LabelKind::Owner, true))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("warden label add"),
            "must name the verb that makes the first one; got:\n{dump}"
        );
        assert!(
            dump.contains("optional"),
            "a config with no vocabulary is not broken, and must not read as broken; got:\n{dump}"
        );
    }

    #[test]
    fn every_kind_has_a_menu_label() {
        for k in LabelKind::ALL {
            assert!(!kind_menu_label(k).is_empty(), "{k:?} has no menu label");
        }
    }

    /// The hint is derived, so a kind added to the menu cannot leave the
    /// operator reading a command line that omits it.
    ///
    /// Re-pointed from `LabelKind::ALL` to [`menu_kinds`] in §4.68 UX8.
    /// On its own that would be tautological — one list feeding both
    /// sides can never disagree with itself — so the two tests below
    /// carry the halves that can actually fail.
    #[test]
    fn empty_hint_names_every_menu_kind() {
        let hint = empty_hint();
        for k in menu_kinds() {
            assert!(hint.contains(k.as_str()), "{k} missing from: {hint}");
        }
    }

    /// §4.68 UX8: the hint must not name a kind the menu does not paint.
    ///
    /// **INVERTED by `plp-s5a`, and the inversion is the record.** The
    /// second assertion used to read `LabelKind::valid_values().contains("tag")`
    /// — *"the CLI's own enumeration must be untouched; `warden label add
    /// --kind tag` stays legal, and this test fails loudly if a future
    /// session narrows the schema instead of the view"*. §4.68 had narrowed
    /// only the view, and this pinned the gap shut.
    ///
    /// The operator then decided to narrow the schema, which is what
    /// `plp-s5a` does: `LabelKind::Tag` is gone, so `--kind tag` is refused
    /// by `parse_kind` and no longer enumerated. Kept and inverted rather
    /// than deleted — a deletion sprint that leaves its old pins standing
    /// is this repo's neutrality-#5 scar, and a test that quietly
    /// disappears takes the record of the old rule with it.
    #[test]
    fn neither_the_hint_nor_the_cli_enumeration_offers_the_retired_tag_kind() {
        let hint = empty_hint();
        assert!(
            !hint.contains("tag"),
            "the menu has no Tags row; the hint must not send them there: {hint}"
        );
        assert!(
            !LabelKind::valid_values().contains("tag"),
            "the schema is narrowed now, not just the view — `--kind tag` \
             must not be offered anywhere: {}",
            LabelKind::valid_values()
        );
    }

    #[test]
    fn menu_kinds_offers_the_three_declared_vocabularies() {
        let kinds = menu_kinds();
        assert_eq!(
            kinds,
            vec![
                LabelKind::Owner,
                LabelKind::DeviceType,
                LabelKind::Department
            ],
            "three closed vocabularies — every kind there is since \
             `plp-s5a` retired `tag`"
        );
    }

    /// The anti-split-brain pin the two lists exist for: what the menu
    /// **paints** and what the hint **names** must be the same set. A
    /// containment check against a shared const cannot fail; this one
    /// compares the rendered buffer against the rendered string.
    #[test]
    fn menu_and_hint_enumerate_the_same_kinds() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let labels = vec![label("alex", LabelKind::Owner, "Alex")];
        let mut app = App::new();
        app.loaded_config = Some(loaded(labels.clone(), Vec::new()));

        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let dump = term.backend().to_string();

        let hint = empty_hint();
        for k in menu_kinds() {
            assert!(
                dump.contains(kind_menu_label(k)),
                "{k} is in the hint but the menu does not paint it:\n{dump}"
            );
            assert!(hint.contains(k.as_str()), "{k} missing from: {hint}");
        }
        assert!(
            !dump.contains("Tags"),
            "the kind menu must not carry a Tags row:\n{dump}"
        );
    }

    // ── §4.68 UX8: the focus marker is drawn where it is claimed ──────
    //
    // Geometry, so the coordinates below are derived and not guessed.
    // `render_section_chrome` returns `x = 2, y = 2` (block border +
    // one padding column, title row consumed). The two-pane split is
    // `[Length(MENU_W), Length(1), Min(30)]`, so the kind menu's marker
    // column is x=2 and the entry table's is x = 2 + 22 + 1 = 25. The
    // table's first data row is one below its header: y=3.
    const MENU_MARK_X: u16 = 2;
    const TABLE_MARK_X: u16 = 25;

    fn focus_app(focus: LabelsFocus) -> App {
        let mut app = App::new();
        app.loaded_config = Some(loaded(
            vec![
                label("alex", LabelKind::Owner, "Alex"),
                label("emanuela", LabelKind::Owner, "Emanuela"),
            ],
            Vec::new(),
        ));
        app.labels.focus = focus;
        app.labels.selected_id = Some("alex".to_string());
        app
    }

    /// Read `len` cells starting at `(x, y)` straight out of the buffer.
    ///
    /// Deliberately not `to_string()`: that flattens the whole screen and
    /// a `contains` on it proves only that the glyph exists *somewhere*.
    /// The claim under test is positional — the marker is on the pane
    /// that has focus — so the assertion has to be positional too.
    fn span_at(
        term: &ratatui::Terminal<ratatui::backend::TestBackend>,
        x: u16,
        y: u16,
        len: u16,
    ) -> String {
        let buf = term.backend().buffer();
        (x..x + len)
            .map(|i| buf.cell((i, y)).map_or(" ", |c| c.symbol()).to_string())
            .collect()
    }

    fn draw(app: &App, w: u16, h: u16) -> ratatui::Terminal<ratatui::backend::TestBackend> {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, f.area(), app)).unwrap();
        term
    }

    #[test]
    fn the_cursor_marks_the_kind_menu_when_the_kind_menu_has_focus() {
        let term = draw(&focus_app(LabelsFocus::KindMenu), 100, 24);
        assert_eq!(
            span_at(&term, MENU_MARK_X, 2, 8),
            "\u{25b8} Owners",
            "the focused pane's cursor is the filled marker"
        );
        assert_eq!(
            span_at(&term, TABLE_MARK_X, 3, 2),
            "\u{00b7} ",
            "the unfocused table keeps a resting cursor, not the live one"
        );
    }

    /// Differential twin of the test above. Both markers must move
    /// together: a build that draws `▸` on both panes, or on neither,
    /// fails exactly one of the pair.
    #[test]
    fn the_cursor_marks_the_entries_when_the_entries_have_focus() {
        let term = draw(&focus_app(LabelsFocus::Entries), 100, 24);
        assert_eq!(
            span_at(&term, TABLE_MARK_X, 3, 10),
            "\u{25b8} alex    ",
            "the focused pane's cursor is the filled marker"
        );
        assert_eq!(
            span_at(&term, MENU_MARK_X, 2, 8),
            "\u{00b7} Owners",
            "the menu keeps its selected kind visible, but resting"
        );
    }

    /// **The D18 floor is 80×24, and at 80 columns this leaf has only one
    /// pane.** `NARROW_THRESHOLD = 90` collapses the split to the entry
    /// table — a deliberate call with its own comment, since the table is
    /// the part that carries data. So the two-pane assertions above run
    /// at 100 wide and this one pins what the floor actually shows.
    ///
    /// Worth a test rather than a comment: the focus model must not make
    /// the narrow layout paint a menu marker for a menu that is not
    /// there.
    #[test]
    fn at_the_eighty_column_floor_the_split_collapses_to_the_table() {
        // `Entries` is what the state actually holds at this width:
        // `clamp_labels_focus_to_layout` runs before every draw, because
        // the focus must not rest on a pane the layout omits. Rendering
        // `KindMenu` here would be staging a state production cannot
        // reach.
        let term = draw(&focus_app(LabelsFocus::Entries), 80, 24);
        let dump = term.backend().to_string();
        assert!(
            !dump.contains("Device types"),
            "below NARROW_THRESHOLD the kind menu is not painted:\n{dump}"
        );
        assert!(
            dump.contains("alex"),
            "the entry table is the pane that survives the collapse:\n{dump}"
        );
        assert!(
            dump.contains("\u{25b8} alex"),
            "the surviving pane carries the live cursor, not the resting \
             one — at this width there is nothing else it could be:\n{dump}"
        );
    }

    /// [`menu_is_painted`] is the predicate the clamp keys off, so its
    /// boundary is worth pinning directly: 80 is the D18 floor and must
    /// be false, and the first width that paints the menu must be true.
    #[test]
    fn the_menu_is_not_painted_at_the_floor_but_is_when_wide() {
        assert!(!menu_is_painted(80), "the D18 floor collapses the split");
        assert!(
            !menu_is_painted(NARROW_THRESHOLD + CHROME_W - 1),
            "one column short of the threshold still collapses"
        );
        assert!(
            menu_is_painted(NARROW_THRESHOLD + CHROME_W),
            "the first width whose inner rect reaches the threshold"
        );
        assert!(menu_is_painted(100), "a comfortable terminal");
    }

    // `plp-s5d` removed `a_tag_counts_carriers_not_device_metadata`.
    //
    // It was the §4.66 L5 discriminator: a fixture whose device `owner`
    // reads `kids` while its `tags` do NOT, so a tag routed through
    // `matches_value` reports 1 and the correct carrier walk reports 0.
    // The carrier walk was `collect_tag_usage`, which `plp-s5c` deletes;
    // `usage_count` now returns 0 for every `LabelKind::Tag` and there is
    // no second count left to tell apart from the first.
    //
    // **Its twin below survives and is the half that still discriminates**
    // — `a_metadata_label_does_not_count_tag_carriers` asserts the reverse
    // leak, that a device carrying the tag `kids` does not inflate an
    // `owner` label named `kids`. That direction is unaffected by this
    // lane and is what keeps the metadata branch honest.

    /// §4.66 L7 — the twin of `tui_never_reaches_the_printing_tag_helper`
    /// (`tabs/tags.rs`), for the verbs this sprint made reachable.
    ///
    /// **Read that test's comments for the reasoning; it is not repeated
    /// here.** The one thing worth restating is the shape of the skip,
    /// because getting it wrong is what made the tags scanner blind for
    /// two sprints: a scanner that `break`s at the first `#[cfg(test)]`
    /// reads **11%** of `src/tui/mod.rs` — which carries 26 top-level test
    /// modules — and the offending call sites lived in the other 89%. The
    /// column-0 `#[cfg(test)]` … `}` pair delimits a top-level test
    /// module; an indented one is an attribute on a single item and stays
    /// scanned. That holds because `cargo fmt --check` is a gate.
    ///
    /// The needle is the **call** — `labels::run_add(` — never the bare
    /// name: `label_modal.rs` and `mod.rs` deliberately name these verbs
    /// in prose to say they must not be used, and a needle that also
    /// matches prose is how a detector dies.
    ///
    /// One list, read by the scanner **and** by its negative control. Two
    /// lists that "must stay in sync" are one commit away from not being.
    const FORBIDDEN: [&str; 5] = [
        "labels::run_add(",
        "labels::run_set(",
        "labels::run_remove(",
        "labels::run_list(",
        "labels::run_show(",
    ];

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum ScanState {
        Normal,
        Classifying,
        SkippingBlock,
    }

    /// Same shape and rationale as `tui/mod.rs`'s `split_leading_attr` —
    /// an independent copy, not shared code. The two scanners check
    /// different properties for different reasons (this one bounds a
    /// forbidden-call scan across a whole subtree; `mod.rs`'s bounds a
    /// key-handling regex scan of one file), and sharing now would mean
    /// inventing a cross-file visibility surface for logic the
    /// already-planned test-file-split is about to reshuffle anyway.
    fn split_leading_attr(line: &str) -> Option<(&str, &str)> {
        let rest = line.strip_prefix('#')?.strip_prefix('[')?;
        let bytes = rest.as_bytes();
        let mut depth: i32 = 1;
        let mut in_string = false;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'"' => in_string = !in_string,
                b'[' if !in_string => depth += 1,
                b']' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((&rest[..i], rest[i + 1..].trim_start()));
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn cfg_inner_predicate(attr: &str) -> Option<&str> {
        attr.strip_prefix("cfg(")?.strip_suffix(')')
    }

    /// True when `test` appears as a bare predicate token inside a
    /// `cfg(...)` attribute's predicate text. False for `feature = "test"`
    /// (string value) and `not(test)` (compiles OUTSIDE test builds).
    /// Panics on any other combination of `not(` with `test` — a real
    /// cfg-expression parser is out of scope, and a loud failure beats a
    /// silent wrong classification.
    fn cfg_predicate_names_test(predicate: &str) -> bool {
        let mut masked = String::with_capacity(predicate.len());
        let mut in_string = false;
        for c in predicate.chars() {
            if c == '"' {
                in_string = !in_string;
                masked.push(' ');
            } else if in_string {
                masked.push(' ');
            } else {
                masked.push(c);
            }
        }
        let no_ws: String = masked.chars().filter(|c| !c.is_whitespace()).collect();
        if no_ws == "not(test)" {
            return false;
        }
        let has_test_token = masked
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|tok| tok == "test");
        if !has_test_token {
            return false;
        }
        assert!(
            !no_ws.contains("not("),
            "cfg predicate {predicate:?} combines `not(` with a `test` token in \
             a shape other than exactly `not(test)` — this needs a real \
             cfg-expression parser to classify correctly, not this heuristic"
        );
        true
    }

    /// Column-0 gate + attribute recognition, mirroring `tui/mod.rs`'s
    /// `is_test_cfg_marker`. Returns the marker's own tail so the caller
    /// can tell a bare declaration (`mod t;`) apart from a block opener
    /// (`mod t {`).
    fn is_test_cfg_marker(line: &str) -> Option<&str> {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let (attr, tail) = split_leading_attr(line)?;
        let predicate = cfg_inner_predicate(attr)?;
        cfg_predicate_names_test(predicate).then_some(tail)
    }

    fn classify_tail(tail: &str) -> ScanState {
        if tail.is_empty() {
            ScanState::Classifying
        } else if tail.ends_with('{') {
            ScanState::SkippingBlock
        } else if tail.ends_with(';') {
            ScanState::Normal
        } else {
            ScanState::Classifying
        }
    }

    /// One file's worth of the scan: skip every test-cfg item (block or
    /// bare declaration, same 3-state walk as `tui/mod.rs`'s
    /// `strip_test_items`) and record a `path:line: text` hit for every
    /// `FORBIDDEN` needle found in what's left. Pulled out of `scan` so it
    /// is testable against fixture strings, not only real files on disk.
    fn scan_source(hits: &mut Vec<String>, path_label: &str, src: &str) {
        let mut state = ScanState::Normal;
        for (i, line) in src.lines().enumerate() {
            state = match state {
                ScanState::Normal => {
                    if let Some(tail) = is_test_cfg_marker(line) {
                        classify_tail(tail)
                    } else {
                        if FORBIDDEN.iter().any(|n| line.contains(n)) {
                            hits.push(format!("{path_label}:{}: {}", i + 1, line.trim()));
                        }
                        ScanState::Normal
                    }
                }
                ScanState::Classifying => {
                    if line.starts_with("#[") {
                        match split_leading_attr(line) {
                            Some((_, tail)) => classify_tail(tail),
                            None => panic!(
                                "attribute at {path_label}:{}: {line:?} did not \
                                 close its brackets on one physical line",
                                i + 1
                            ),
                        }
                    } else {
                        classify_tail(line.trim_end())
                    }
                }
                ScanState::SkippingBlock => {
                    if line == "}" {
                        ScanState::Normal
                    } else {
                        ScanState::SkippingBlock
                    }
                }
            };
        }
        assert_eq!(
            state,
            ScanState::Normal,
            "scan of {path_label} ended in {state:?} at EOF — a test item's \
             closing brace or semicolon was never found"
        );
    }

    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src/tui must be readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                // `src/tui/tests/` holds `#[path]`-relocated `#[cfg(test)]`
                // module bodies: the cfg marker lives on the `mod` item back
                // in the file that declares it, not in these files, so a
                // plain recursive scan would read every line here as
                // production code and misfire on any test fixture that
                // happens to contain a FORBIDDEN call.
                if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                    continue;
                }
                scan(&path, hits);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("readable .rs file");
            scan_source(hits, &path.display().to_string(), &src);
        }
    }

    #[test]
    fn tui_never_reaches_a_printing_labels_helper() {
        let mut hits = Vec::new();
        scan(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui"),
            &mut hits,
        );
        assert!(
            hits.is_empty(),
            "the Labels tab must drive `labels::{{add,set,remove}}_inner`, never a \
             helper that prints — a `println!` under raw mode + alternate screen \
             staircases across the frame and outlives every redraw:\n{}",
            hits.join("\n")
        );
    }

    /// Proves the `tests/` directory skip added for the `#[path]` test-file
    /// move: a FORBIDDEN call inside `<dir>/tests/*.rs` must not surface,
    /// while the same call one level up still does.
    #[test]
    fn scan_skips_the_tests_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("tests").join("moved.rs"),
            "labels::run_add(x)\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("sibling.rs"), "labels::run_add(x)\n").unwrap();

        let mut hits = Vec::new();
        scan(dir.path(), &mut hits);

        assert_eq!(
            hits.len(),
            1,
            "expected exactly the sibling.rs hit, tests/ should be skipped: {hits:?}"
        );
        assert!(hits[0].contains("sibling.rs"), "hit was: {:?}", hits[0]);
    }

    // `scan_source` fixture table — mirrors `tui/mod.rs`'s
    // `strip_test_items` fixtures. Single-line escaped strings only: a raw
    // multi-line block would place fixture content at real column 0
    // inside whichever file hosts it, which this scanner (recursing over
    // all of `src/tui`) would then read as if it were real code.

    #[test]
    fn scan_source_finds_a_forbidden_call_in_production_code() {
        let mut hits = Vec::new();
        scan_source(
            &mut hits,
            "fixture",
            "PROD_BEFORE\nlabels::run_add(x)\nPROD_AFTER\n",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn scan_source_resumes_correctly_after_a_bare_mod_declaration() {
        // The fix for the bare-declaration gap: before this fix, a bare
        // `mod t;` (no closing brace of its own) would leave the scanner
        // skipping past FORBIDDEN_AFTER looking for some unrelated `}`,
        // silently blinding the scan to everything past it.
        let mut hits = Vec::new();
        let src = "#[cfg(test)]\nmod t;\nlabels::run_add(x)\n";
        scan_source(&mut hits, "fixture", src);
        assert_eq!(
            hits.len(),
            1,
            "a call after a bare `mod t;` declaration must still be seen: {hits:?}"
        );
    }

    #[test]
    fn scan_source_does_not_scan_inside_an_ordinary_test_module() {
        let mut hits = Vec::new();
        let src = "#[cfg(test)]\nmod t {\nlabels::run_add(x)\n}\n";
        scan_source(&mut hits, "fixture", src);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_source_does_not_scan_inside_a_cfg_all_test_module() {
        // The fix for the exact-string-spelling gap: `editor_failure_tests`
        // in `tui/mod.rs` is spelled exactly this way. Before this fix, a
        // module gated like this was left unskipped, so a legitimate
        // reference to a FORBIDDEN name inside its own test code would have
        // been reported as a false positive.
        let mut hits = Vec::new();
        let src = "#[cfg(all(test, unix))]\nmod t {\nlabels::run_add(x)\n}\n";
        scan_source(&mut hits, "fixture", src);
        assert!(hits.is_empty());
    }

    #[test]
    #[should_panic(expected = "did not close its brackets")]
    fn scan_source_panics_on_a_multiline_attribute_it_cannot_classify() {
        let mut hits = Vec::new();
        scan_source(
            &mut hits,
            "fixture",
            "#[cfg(test)]\n#[cfg(\n    unix\n)]\nmod t {\n}\n",
        );
    }

    #[test]
    #[should_panic(expected = "ended in")]
    fn scan_source_panics_on_an_unclosed_marker_at_eof() {
        let mut hits = Vec::new();
        scan_source(&mut hits, "fixture", "#[cfg(test)]\nmod t {\nTEST_BODY\n");
    }

    /// The negative control. A guard that cannot fire is
    /// indistinguishable from a guard that passes — and this one is the
    /// more brittle of the pair, because the seam it protects is *new*:
    /// `labels::run_add` and `add_inner` differ by six characters.
    #[test]
    fn the_printing_labels_needle_matches_a_real_call() {
        let call = "        match crate::cli::commands::labels::run_add(config_path, ...) {";
        assert!(call.contains("labels::run_add("));

        // The prose that names the verb — three real lines from this
        // sprint's own sources — must NOT fire.
        for prose in [
            "//! `cli::commands::labels::{add_inner, set_inner, remove_inner}` — the",
            "    // **Mai** `labels::run_add` / `run_set` / `run_remove`: stampano.",
            "/// - Add → `add_inner` once.",
        ] {
            assert!(
                !FORBIDDEN.iter().any(|n| prose.contains(n)),
                "the needle matched prose, not a call: {prose}"
            );
        }

        // The seam itself must not be caught by its own guard.
        let seam = "        match add_inner(config_path, &resolved.id, form.kind, ...) {";
        assert!(!FORBIDDEN.iter().any(|n| seam.contains(n)));
    }
}
