//! Master render function — draws header, tab bar, active tab, and overlays.

use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Tabs};
use ratatui::Frame;

use crate::tui::app::{App, Leaf, Section};
use crate::tui::theme::{framed_block_colored, T};
use crate::tui::wordmark;
use crate::tui::{help, tabs};

/// Minimum terminal size to render the full layout.
const MIN_WIDTH: u16 = 80;
const MIN_HEIGHT: u16 = 24;

/// In-bounds rect for the "terminal too small"
/// guard message, clamped to `area`. The message is centred at
/// `(x=2, y=height/2)` with a 4-cell horizontal margin — fine on any
/// real terminal, but on a degenerate buffer (height 0, width ≤ 3) the
/// raw `Rect::new(2, …)` can extend past the buffer edge and panic when
/// ratatui writes it. Intersecting with `area` returns the drawable
/// overlap; an empty result means there is nowhere to draw and the
/// caller skips the render.
fn too_small_msg_rect(area: Rect) -> Rect {
    let y = area.height / 2;
    Rect::new(2, y, area.width.saturating_sub(4), 1).intersection(area)
}

/// The four vertical slots every frame is built from: header, menu
/// card, tab content, footer. Factored out of [`render`] so the toast
/// geometry tests can assert against the *real* rects rather
/// than a hand-derived copy of them — a copy would stay self-consistent
/// while the layout drifted underneath it, which is exactly the class of
/// bug this guards against.
///
/// Index 2 is the toast anchor; 1 and 3 are the two surfaces nothing
/// transient may occlude.
fn layout_chunks(area: Rect, app: &App) -> std::rc::Rc<[Rect]> {
    Layout::vertical([
        Constraint::Length(4), // header — 1 blank pad row + 3-row wordmark
        Constraint::Length(menu_card_height(app)), // unified menu card (3 or 5)
        Constraint::Min(10),   // tab content
        Constraint::Length(1), // footer
    ])
    .split(area)
}

pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();

    // Terminal too small guard
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let msg = Paragraph::new(Span::styled(
            format!(
                "Terminal too small ({}\u{00d7}{}). Resize to at least {MIN_WIDTH}\u{00d7}{MIN_HEIGHT}.",
                area.width, area.height
            ),
            Style::default().fg(T.warning),
        ));
        // Center vertically, clamped to the frame. On a 0-row
        // terminal (`stty rows 0`, a 1-col tmux pane) the hand-built
        // rect would claim a row/column that does not exist and panic in
        // `Buffer::set_stringn`; intersecting with `area` yields the
        // drawable overlap, empty when there is nowhere to draw.
        let r = too_small_msg_rect(area);
        if !r.is_empty() {
            f.render_widget(msg, r);
        }
        return;
    }

    // A single card hosts both the section row and (on
    // multi-leaf sections) a sub-tab row separated by a U+2500 divider.
    // Card height is 3 on singleton sections (Dashboard / Query Log)
    // and 5 on multi-leaf sections (Network / Filters / Configuration) —
    // see `menu_card_height` for the contract. The chunk count is now
    // a constant 4 (header / menu_card / content / footer); the dynamic
    // height lives inside the menu_card constraint instead of branching
    // the chunk list.
    let chunks = layout_chunks(area, app);

    render_header(f, chunks[0], app);
    render_menu_card(f, chunks[1], app);
    render_active_tab(f, chunks[2], app);
    render_footer(f, chunks[3], app);

    // Transient action feedback floats over the tab content,
    // never over the footer legend or the menu card — the two permanent
    // orientation surfaces. It is scoped to `chunks[2]`, so containment
    // in that rect is what keeps it off both.
    //
    // Order matters twice. After `render_active_tab`, because the toast
    // reads the tab's own focus-bar highlight back out of the buffer to
    // avoid landing on the operator's cursor. Before the modal
    // block below, because a modal must draw over the toast.
    //
    // `visible_status` only filters an expired message for display
    // here; the tick does the actual dropping.
    // And NOT only the section-jump
    // popup — see `tab_dispatched_overlay_open`. The invariant two
    // paragraphs up ("a modal must draw over the toast") holds for every
    // overlay dispatched from the modal block below, because those run
    // after this line. It did not hold for the overlays a *tab* draws
    // inside `render_active_tab`, because that ran at the top of this
    // function, before the toast.
    if !tab_dispatched_overlay_open(app) {
        if let Some(status) = app.visible_status() {
            crate::tui::toast::render(f, chunks[2], status);
        }
    }

    // Help overlay (on top of everything)
    if app.show_help {
        help::render(f, app.active_leaf);
    }

    // Query Log rule picker — drawn ABOVE the help overlay
    // so an accidental `?` while the modal is open doesn't hide it.
    if let Some(modal) = app.query_log_rule_modal.as_ref() {
        crate::tui::query_log_rule_modal::render_overlay(f, chunks[2], modal);
    }

    // Local DNS modal overlay (Add / Remove / Edit).
    // Drawn after the rule picker so cross-tab modal collisions (which
    // shouldn't happen in normal use — both modals belong to specific
    // tabs) land the freshly-opened one on top.
    if let Some(modal) = app.local_dns.modal.as_ref() {
        crate::tui::local_dns_modal::render_overlay(f, chunks[2], modal);
    }

    // Settings restore picker modal overlay — only ever Some while on the
    // Settings tab (opened via `R`). Same single-open gate as the others.
    if let Some(modal) = app.settings.restore_modal.as_ref() {
        crate::tui::backup_restore_modal::render_overlay(f, chunks[2], modal);
    }

    // Settings backup confirm modal overlay — only ever Some while on
    // the Settings tab (opened via `b`). Parallel to the restore overlay.
    if let Some(modal) = app.settings.backup_modal.as_ref() {
        crate::tui::backup_restore_modal::render_backup_overlay(f, chunks[2], modal);
    }

    // Subnets modal overlay (Add / Edit / Delete). Same gate
    // pattern as the Local DNS modal — only one tab modal can be open
    // at a time so cross-modal z-order is moot in practice.
    if let Some(modal) = app.subnets.modal.as_ref() {
        crate::tui::subnet_modal::render_overlay(f, chunks[2], modal);
    }

    // Groups modal overlay (Add / Edit / Delete). Same
    // single-open-tab-modal pattern as Subnets.
    if let Some(modal) = app.groups.modal.as_ref() {
        crate::tui::group_modal::render_overlay(f, chunks[2], modal);
    }

    // Labels modal overlay (Add / Edit / Delete). Same
    // single-open-tab-modal pattern as Groups.
    if let Some(modal) = app.labels.modal.as_ref() {
        crate::tui::label_modal::render_overlay(f, chunks[2], modal);
    }

    // Custom Lists modals. Same single-open-tab-modal pattern.
    if let Some(modal) = app.custom_lists.modal.as_ref() {
        crate::tui::custom_list_modal::render_overlay(f, chunks[2], modal);
    }
    if let Some(picker) = app.custom_lists.mount_picker.as_ref() {
        crate::tui::custom_list_modal::render_mount_picker(f, chunks[2], picker);
    }

    // Profiles modal overlay (Add / Edit / Delete). Same
    // single-open-tab-modal pattern as Subnets / Local DNS.
    if let Some(modal) = app.profiles.modal.as_ref() {
        crate::tui::profile_modal::render_overlay(f, chunks[2], modal);
    }

    // Resolver modal overlay — drawn after the per-tab
    // modals so a `s` keystroke that fires while a tab modal is open
    // (which is gated out at the input layer) cannot end up under it.
    if let Some(modal) = app.resolver_modal.as_ref() {
        crate::tui::resolver_modal::render_overlay(f, chunks[2], modal);
    }

    // Welcome banner overlay — drawn last so it lands on
    // top of everything else on first launch. The handle_key path
    // dismisses it on any keypress before any other modal/handler gets
    // to consume the event, so this draw order also matches the input
    // priority (top z-index ↔ first handler wins).
    if let Some(banner) = app.welcome_banner.as_ref() {
        crate::tui::welcome_banner::render_overlay(f, banner, area);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    // Header is pure branding: 3 rows of block-letter wordmark, no
    // frame, no chrome. The RUNNING pill lives in the System panel's
    // "Status" row and the version lives in the footer's bottom-left
    // slot. The `app` ref is kept unused so future
    // header-level signals can plug in without touching the call site.
    let _ = app;

    let purge = wordmark::PURGE_COMPACT;
    let warden = wordmark::WARDEN_COMPACT;
    // 1 leading + 19 PURGE + 3 gap + 25 WARDEN = 48 cells
    let wm_width: u16 = 48;

    // Beta-status tag riding the wordmark's top row (superscript feel):
    // amber = caution, telling operators this is a pre-1.0 build that may
    // still have bugs. 2-space gap keeps it clear of the WARDEN glyphs.
    // Not BOLD so it stays visually smaller than the wordmark. The version
    // number itself lives in the footer, so this is a status flag, not a
    // version string. Its width is added to the render rect below —
    // otherwise the span would be clipped to the wordmark's 48 cells.
    const BETA_TAG: &str = "  Beta Version";
    let beta_tag_width = BETA_TAG.chars().count() as u16;

    let red = Style::default()
        .fg(T.brand_red)
        .add_modifier(Modifier::BOLD);
    let white = Style::default()
        .fg(T.text_primary)
        .add_modifier(Modifier::BOLD);
    let amber = Style::default().fg(T.warning);

    // Zip the two wordmark consts so the row count follows the data
    // (`[&str; 3]`) instead of a hardcoded `0..3`: a future resize of
    // either const can no longer out-of-bounds-panic the render path.
    // `enumerate()` lets the beta tag ride row 0 only.
    let wm_lines: Vec<Line> = purge
        .iter()
        .zip(warden.iter())
        .enumerate()
        .map(|(i, (p, w))| {
            let mut spans = vec![
                Span::raw(" "),
                Span::styled(p.to_string(), red),
                Span::raw("   "),
                Span::styled(w.to_string(), white),
            ];
            if i == 0 {
                spans.push(Span::styled(BETA_TAG, amber));
            }
            Line::from(spans)
        })
        .collect();

    // Tight sub-rect of the wordmark's exact width — keeps Paragraph
    // from interpreting trailing empty cells. Clamp to area.width so
    // tiny terminals still render (clipped) instead of overflowing.
    // One blank pad row above the wordmark (agio): the header slot is 4
    // rows, the wordmark occupies the lower 3 (drawn at y+1).
    // `saturating_sub(1)` keeps a degenerate 0/1-row slot from claiming a
    // row that isn't there.
    let w = (wm_width + beta_tag_width).min(area.width);
    let wm_height = area.height.saturating_sub(1).min(3);
    let wm_area = Rect::new(area.x, area.y + 1, w, wm_height);
    f.render_widget(Paragraph::new(wm_lines), wm_area);
}

/// Unified menu card — replaces the two stacked cards
/// (top-level section bar + sub-tab strip) shipped earlier. A single
/// outer frame in `T.text_primary` hosts up to two horizontal rows
/// separated by a thin U+2500 divider in `T.text_muted`. The colour
/// delta between border and divider is the cue: the brilliant outer
/// border reads as "container", the muted divider as "this belongs
/// to that". Operators see one widget with two rows instead of two
/// peer cards.
///
/// Card height is 3 (top border + section row + bottom border) on
/// singleton sections and 5 (adds divider + leaf row) on multi-leaf
/// sections — driven by `menu_card_height`. The two values must agree
/// or ratatui will leave a blank gap or clip the divider; the
/// `menu_card_height_*` tests pin that contract.
/// Section nav visibility. Every section is always visible except
/// the cluster-gated `Section::Cluster`, hidden from the bar (and the numeric
/// hotkey) unless `cluster_visible()`. Always-true on a default build (no
/// `Section::Cluster` variant exists to hide).
fn section_visible(section: Section, app: &App) -> bool {
    #[cfg(feature = "cluster")]
    if matches!(section, Section::Cluster) {
        return app.cluster_visible();
    }
    #[cfg(not(feature = "cluster"))]
    let _ = (section, app);
    true
}

/// Sub-tab title with the leaf's `g <letter>`
/// mnemonic underlined **in place** inside its own label — `Profiles`
/// underlines the `P`, `Lists` the `i`, `Devices` the `v`. Costs zero
/// columns, which is why it beat a bracketed `[p]` suffix: the Filters
/// row would have grown 31 → 47 cols.
///
/// The four leaves whose mnemonic is not their initial (deVices, lIsts,
/// rUles, sEttings) were previously unguessable — the letters existed
/// only in the `?` help screen. This surfaces them in the chrome.
///
/// Falls back to an unstyled label if the mnemonic is absent from the
/// label. That is a broken invariant (pinned by
/// `every_mnemonic_occurs_in_its_leaf_label`), but a missing underline is
/// cosmetic and a panic on the render path is not.
fn leaf_title_line(leaf: Leaf) -> Line<'static> {
    let label = leaf.label();
    let Some(off) = leaf.mnemonic_offset() else {
        return Line::from(label);
    };
    let ch_len = label[off..]
        .chars()
        .next()
        .map(char::len_utf8)
        .unwrap_or_default();
    let mut spans = Vec::with_capacity(3);
    if off > 0 {
        spans.push(Span::raw(&label[..off]));
    }
    spans.push(Span::styled(
        &label[off..off + ch_len],
        Style::default().add_modifier(Modifier::UNDERLINED),
    ));
    if off + ch_len < label.len() {
        spans.push(Span::raw(&label[off + ch_len..]));
    }
    Line::from(spans)
}

fn render_menu_card(f: &mut Frame, area: Rect, app: &App) {
    let card = framed_block_colored(T.text_primary);
    let inner = card.inner(area);
    f.render_widget(card, area);

    let active_section = app.active_leaf.section();
    let leaves = active_section.leaves();
    let multi_leaf = leaves.len() >= 2;

    // Row 0: section bar — top-level entries with the brand-red active
    // highlight following the active leaf's owning section. The
    // Cluster section is runtime-filtered out unless `cluster_visible()`, so
    // the highlight index is the active section's position WITHIN the visible
    // list, not its absolute `index()`.
    let visible_sections: Vec<Section> = Section::ALL
        .iter()
        .copied()
        .filter(|s| section_visible(*s, app))
        .collect();
    let section_row = Rect::new(inner.x, inner.y, inner.width, 1);
    let section_titles: Vec<Line> = visible_sections
        .iter()
        .map(|s| Line::from(s.label()))
        .collect();
    let active_section_idx = visible_sections
        .iter()
        .position(|s| *s == active_section)
        .unwrap_or(0);
    let section_tabs = Tabs::new(section_titles)
        .select(active_section_idx)
        .style(Style::default().fg(T.text_secondary))
        .highlight_style(
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" | ");
    f.render_widget(section_tabs, section_row);

    if multi_leaf {
        // Row 1: thin horizontal divider — U+2500 box-drawing
        // horizontal repeated full inner width. Held in `text_muted`
        // so it reads as quieter than the outer border (which is in
        // `text_primary`); the brightness delta is what produces the
        // "principal / subordinate" hierarchy.
        let divider_row = Rect::new(inner.x, inner.y + 1, inner.width, 1);
        let divider_str: String = "\u{2500}".repeat(inner.width as usize);
        let divider = Paragraph::new(Line::from(Span::styled(
            divider_str,
            Style::default().fg(T.text_muted),
        )));
        f.render_widget(divider, divider_row);

        // Row 2: sub-tab strip for the active section's leaves.
        // Quieter ` · ` divider — it lives inside the active section's
        // bracket so the eye doesn't need a hard separator.
        let leaf_row = Rect::new(inner.x, inner.y + 2, inner.width, 1);
        let leaf_titles: Vec<Line> = leaves.iter().map(|l| leaf_title_line(*l)).collect();
        let active_idx = leaves
            .iter()
            .position(|l| *l == app.active_leaf)
            .unwrap_or(0);
        let leaf_tabs = Tabs::new(leaf_titles)
            .select(active_idx)
            .style(Style::default().fg(T.text_secondary))
            .highlight_style(
                Style::default()
                    .fg(T.brand_red)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" \u{00b7} ");
        f.render_widget(leaf_tabs, leaf_row);
    }
}

/// Outer height of the unified menu card for the active leaf. Returns
/// 3 on singleton sections (Dashboard / Query Log) and 5 on multi-leaf
/// sections (Network / Filters / Configuration). The value MUST equal the
/// number of rows `render_menu_card` actually paints, otherwise
/// ratatui's vertical Layout leaves a blank gap below the card or
/// clips the divider — neither degrades into a friendly mode.
fn menu_card_height(app: &App) -> u16 {
    if section_has_subtabs(app.active_leaf.section()) {
        5
    } else {
        3
    }
}

/// Whether the active section needs a sub-tab row inside the menu
/// card. Renamed from the former `should_render_subtab_strip`
/// — the predicate now drives card height (3 vs 5) instead of the
/// visibility of a separate strip card.
pub(crate) fn section_has_subtabs(section: Section) -> bool {
    section.leaves().len() >= 2
}

/// Render the Gauge-Anatomy chrome (white frame + bold colored title
/// as the first interior row) and return the content sub-rect ready
/// for a table or paragraph. Single source of truth so the 9 leaf
/// tabs stay column-aligned with the menu card above (first title
/// glyph at column `area.x + 2`, matching the menu card's first tab
/// glyph after the rounded border + ratatui's default Tabs padding).
pub(crate) fn render_section_chrome(
    f: &mut Frame,
    area: Rect,
    title: &str,
    title_color: Color,
) -> Rect {
    let block = framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let padded_x = inner.x.saturating_add(1);
    let padded_w = inner.width.saturating_sub(2);

    let title_area = Rect {
        x: padded_x,
        y: inner.y,
        width: padded_w,
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            title.to_string(),
            Style::default()
                .fg(title_color)
                .add_modifier(Modifier::BOLD),
        )),
        title_area,
    );

    Rect {
        x: padded_x,
        y: inner.y.saturating_add(1),
        width: padded_w,
        height: inner.height.saturating_sub(1),
    }
}

/// Paint mid-gap vertical column separators (`│`, muted) across a table
/// content rect — the Query Log column-divider look. Re-runs ratatui
/// 0.29's own column layout (`Layout::horizontal(widths).flex(Flex::Start)
/// .spacing(..)`) on `area` so the separators land exactly in the
/// inter-column gaps regardless of how many flexible (`Min`) columns the
/// table has (hand-deriving only works for a single flex column). The
/// caller MUST give the table the same `.column_spacing(spacing)`, and
/// `spacing` must be ≥ 2 so there is a gap cell to paint into.
///
/// Run AFTER the table render so the glyphs paint over the empty spacing
/// cells rather than under them.
pub(crate) fn draw_table_column_separators(
    f: &mut Frame,
    area: Rect,
    constraints: &[Constraint],
    spacing: u16,
) {
    // Split the columns on a ZERO-ORIGIN rect, exactly as ratatui's
    // `Table::get_columns_widths` does (it lays the columns out on
    // `Rect::new(0, 0, width, 1)` and then offsets by the table's x).
    // Splitting on `area` directly (x = area.x) can diverge by a cell
    // from the Table under an over-constrained layout, because ratatui's
    // hash-seeded constraint solver distributes the squeeze differently
    // for a different absolute origin — which leaves the separators off
    // the real column edges at tight widths (e.g. the 80x24 minimum).
    // Matching the origin guarantees identical column rects, so the
    // glyphs always land in the inter-column gaps.
    let cols = Layout::horizontal(constraints.iter().copied())
        .flex(Flex::Start)
        .spacing(spacing)
        .split(Rect::new(0, 0, area.width, 1));
    let style = Style::default().fg(T.text_muted);
    let area_right = area.x.saturating_add(area.width);
    let buf = f.buffer_mut();
    let buf_right = buf.area.right();
    let buf_bottom = buf.area.bottom();
    for pair in cols.windows(2) {
        // Mid-gap: table x + end of the left column + half the spacing.
        let sep_x = area
            .x
            .saturating_add(pair[0].x)
            .saturating_add(pair[0].width)
            .saturating_add(spacing / 2);
        if sep_x >= area_right {
            break;
        }
        for row in 0..area.height {
            let y = area.y + row;
            if sep_x < buf_right && y < buf_bottom {
                buf.set_string(sep_x, y, "\u{2502}", style);
            }
        }
    }
}

fn render_active_tab(f: &mut Frame, area: Rect, app: &mut App) {
    match app.active_leaf {
        Leaf::Dashboard => tabs::dashboard::render(f, area, app),
        Leaf::QueryLog => tabs::query_log::render(f, area, app),
        Leaf::Devices => tabs::devices::render(f, area, app),
        Leaf::Subnets => tabs::subnets::render(f, area, app),
        Leaf::LocalDns => tabs::local_dns::render(f, area, app),
        Leaf::Profiles => tabs::profiles::render(f, area, app),
        Leaf::Lists => tabs::lists::render(f, area, app),
        Leaf::CustomLists => tabs::custom_lists::render(f, area, app),
        Leaf::Rules => tabs::rules::render(f, area, app),
        Leaf::Settings => tabs::settings::render(f, area, app),
        Leaf::File => tabs::file::render(f, area, app),
        Leaf::Logs => tabs::logs::render(f, area, app),
        Leaf::Groups => tabs::groups::render(f, area, app),
        Leaf::Labels => tabs::labels::render(f, area, app),
        #[cfg(feature = "cluster")]
        Leaf::Cluster => tabs::cluster::render(f, area, app),
    }
}

/// True when an overlay drawn **inside `render_active_tab`** is open.
///
/// The Settings section-jump popup was once flagged as "the ONE modal
/// the toast draws over". It is not one; enumerating rather than
/// trusting that
/// turns up **six**, none of which `ui.rs` dispatches:
///
/// | overlay | drawn at |
/// |---|---|
/// | `file.section_jump` | `tabs/file.rs:71` |
/// | `rules.edit_modal` | `tabs/rules.rs:196` |
/// | `rules.add_modal` | `tabs/rules.rs:201` |
/// | `lists.catalog_picker` | `tabs/lists.rs::render_overlays` |
/// | `lists.kind_confirm` | `tabs/lists.rs::render_overlays` |
/// | `lists.edit_modal` | `tabs/lists.rs::render_overlays` |
///
/// **Why suppress the toast rather than move six dispatches into the
/// modal block.** Moving them is the tidier end state and is what the
/// task's own step 2 prefers, but it is six call sites across three tab
/// modules plus their anchoring rects, and it changes what each overlay
/// is anchored *to* — `render_overlays` receives the tab's area, the
/// modal block passes `chunks[2]`. That is a refactor with real
/// regression surface, and it would not make the outcome any different
/// for the operator: the invariant being restored is "the modal wins",
/// and a toast that never paints is indistinguishable from one painted
/// over. Suppression delivers the invariant without moving anything.
///
/// **The cost is a hand-maintained list**, the same trade `CLAUDE.md`
/// makes for the thirteen hot-path lock sites and for §Neutrality's
/// benign-hit classes: a predicate wide enough to catch every overlay
/// automatically would also catch things that are not overlays. A
/// seventh tab-drawn overlay needs a row here, and
/// `every_tab_dispatched_overlay_suppresses_the_toast` is what makes
/// forgetting visible.
fn tab_dispatched_overlay_open(app: &App) -> bool {
    app.file.section_jump.is_some()
        || app.rules.edit_modal.is_some()
        || app.rules.add_modal.is_some()
        || app.lists.catalog_picker.is_some()
        || app.lists.kind_confirm.is_some()
        || app.lists.edit_modal.is_some()
}

/// Test seam over [`render_footer`]: the footer's key legend only becomes
/// text once it is drawn, so a guard that checks what it advertises has to
/// render it.
#[cfg(test)]
pub(crate) fn render_footer_for_test(f: &mut Frame, area: Rect, app: &App) {
    render_footer(f, area, app);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    // The footer is a pure key-hint + transient-
    // message line. The `polling … Ns ● healthy` and `daemon
    // unreachable` paths were retired — RUNNING/DISCONNECTED in the
    // header pill already carries the connection state, and the poll
    // cadence is developer info the operator doesn't consume.
    //
    // Priority on the left slot when present: startup warning >
    // paused > tab-specific key hints.
    //
    // The transient action status is NOT in that chain
    // — it renders as a toast over the tab content instead
    // (`toast::render`). It shared `cols[1]` with the key hints, so
    // every reported outcome blanked the "what can I press on this tab"
    // cluster, which for Lists is `[a] add [e] edit [d] delete [b]
    // browse …` — the discovery surface for the very screen the
    // operator is working on. That is the wrong trade at any duration,
    // which is why the fix moves the message rather than shortening it.
    //
    // The startup warning and `paused` keep their priority: they are
    // *states*, not events. A state is a legitimate legend replacement
    // because it persists and is itself the current context.
    let tab_hints = tab_hints_for(app);
    // Only the key-hint legend is a list of droppable hints. The startup
    // warning and `paused` are prose in the same slot, and `elide_hints`
    // would treat either as one indivisible group and drop it whole —
    // replacing a state the operator needs with a bare marker. They keep
    // the old clip behaviour, which for them is correct: the warning is
    // already a headline chosen to fit (see the comment below), and
    // `paused` is 10 cells.
    let left_is_legend = app.startup_warning.is_none() && !app.paused;
    // The HEADLINE, never the full warning. This column is
    // `Constraint::Min(20)` and the `Paragraph` below carries no `.wrap()`,
    // so ratatui clips whatever does not fit — with no ellipsis, so a
    // truncated sentence is indistinguishable from a complete one. The full
    // text ran ~260 characters and lost its entire remedy to that clip on a
    // 210-column terminal. The detail now lives on the startup notice
    // overlay, which wraps; this slot carries only what fits intact.
    //
    // No "press X for details" pointer: the notice re-shows on every launch
    // while the state is bad (unlike the once-per-operator welcome), so the
    // detail is never more than a relaunch away, and a key binding that
    // exists only in one rare state is worse than the state being visible.
    let left = if let Some(ref warn) = app.startup_warning {
        Line::from(vec![
            Span::styled(" \u{25cc} ", Style::default().fg(T.warning)),
            Span::styled(warn.headline.clone(), Style::default().fg(T.warning)),
        ])
    } else if app.paused {
        Line::from(vec![
            Span::styled(
                " || paused",
                Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  press [p] to resume", Style::default().fg(T.text_muted)),
        ])
    } else {
        // No breadcrumb prefix (`<Section> ▸ <Leaf>`) here.
        // The active section + leaf are already visible in the menu
        // card at the top of every frame,
        // so repeating the path in the footer would be duplicate chrome.
        // Footer-left now carries only tab-specific key hints.
        Line::from(tab_hints)
    };

    // Version sits in the leftmost slot, moved out of the header
    // to keep the wordmark area free of runtime chrome.
    // Format ` vX.Y.Z ` in muted gray so it stays unobtrusive but
    // always visible — until `plan_footer` decides the width cannot
    // afford chrome, which at the 80-column floor it cannot.
    let version_text = concat!(" v", env!("CARGO_PKG_VERSION"), " ");
    let version_w = version_text.len() as u16;

    // `s-tui-footer-legend-clipped-at-80-cols`: the slot widths are now
    // derived from what the three clusters actually need at THIS width,
    // rather than from a `Min(20)` that silently clipped whatever the
    // other two left behind. See `plan_footer` for the give-up order.
    let plan = if left_is_legend {
        plan_footer(area.width, version_w, hint_width(&left.spans))
    } else {
        // A state in the left slot does not get to strip the globals.
        FooterPlan {
            show_version: true,
            compact_globals: false,
        }
    };
    let globals = if plan.compact_globals {
        global_hints_compact()
    } else {
        global_hints()
    };
    let globals_w = hint_width(&globals);
    let version_w = if plan.show_version { version_w } else { 0 };

    let cols = Layout::horizontal([
        Constraint::Length(version_w),
        Constraint::Min(0),
        Constraint::Length(globals_w),
    ])
    .split(area);

    // Elide against the width the legend was ACTUALLY given, not against
    // the plan's estimate — the layout solver is the authority on how the
    // cells were split, and a marker computed against anything else can
    // still overrun.
    let left = if left_is_legend {
        Line::from(elide_hints(left.spans, cols[1].width))
    } else {
        left
    };

    if plan.show_version {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                version_text,
                Style::default().fg(T.text_muted),
            ))),
            cols[0],
        );
    }
    f.render_widget(Paragraph::new(left), cols[1]);
    f.render_widget(
        Paragraph::new(Line::from(globals)).alignment(Alignment::Right),
        cols[2],
    );
}

/// Common key-span constructor. Bracket chars in muted gray, the key
/// itself in accent white, the label in muted gray. Matches the
/// pre-S41.1 styling contract.
fn key_span(k: &'static str, label: &'static str) -> [Span<'static>; 4] {
    [
        Span::styled("[", Style::default().fg(T.text_muted)),
        Span::styled(k, Style::default().fg(T.text_primary)),
        Span::styled("] ", Style::default().fg(T.text_muted)),
        Span::styled(label, Style::default().fg(T.text_muted)),
    ]
}

/// Global keybind hints — always rendered on the right of the footer,
/// regardless of tab. `[r] refresh  [p] pause  [s] resolver  [?] help  [q] quit`.
fn global_hints() -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.extend(key_span("r", "refresh"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("p", "pause"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("s", "resolver"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("?", "help"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("q", "quit"));
    spans.push(Span::raw(" "));
    spans
}

/// The global cluster with the labels dropped — `[r] [p] [s] [?] [q]`.
///
/// 20 cells against the labelled cluster's 57. Used only when the full
/// footer does not fit (see [`plan_footer`]); at any comfortable width the
/// labelled form is what renders.
///
/// The keys survive and the words go, rather than the reverse, because a
/// key the operator can still see is recoverable — `?` is on it and opens
/// the help overlay, which carries every one of these verbs in full. A
/// dropped *key* is not recoverable from anywhere on screen.
fn global_hints_compact() -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    for k in ["r", "p", "s", "?", "q"] {
        spans.push(Span::styled("[", Style::default().fg(T.text_muted)));
        spans.push(Span::styled(k, Style::default().fg(T.text_primary)));
        spans.push(Span::styled("] ", Style::default().fg(T.text_muted)));
    }
    spans
}

/// What the footer gives up, in order, when `width` cannot hold it whole.
///
/// `s-tui-footer-legend-clipped-at-80-cols`: at the declared 80-column
/// floor the three slots want 9 + 45 + 57 = 111 cells, and the leaf legend
/// is the one that lost — `Constraint::Min(20)` handed it 20 cells and the
/// `Paragraph` clipped it mid-token to `[Enter] edit  [a] a`, with no
/// ellipsis, so a cut legend was indistinguishable from a complete one.
///
/// The ladder inverts what used to happen, and the order is the argument:
///
/// 1. **the version goes first.** It is chrome. Nothing is navigable by it.
/// 2. **then the global labels**, to [`global_hints_compact`] — all five
///    keys stay, only the words go, and `[?]` reaches the help overlay
///    where the words live.
/// 3. **the leaf legend elides last**, at whole-hint granularity with a
///    marker ([`elide_hints`]) — never mid-token.
///
/// That order follows the same argument that moved
/// the transient status off this row: the leaf legend is the first-launch
/// discovery surface *for the tab the operator is on*. The globals are
/// five keys that never change and are one `?` away. Spending the
/// tab-specific surface to preserve the universal one is backwards, and
/// spending it silently is the actual defect.
struct FooterPlan {
    show_version: bool,
    compact_globals: bool,
}

fn plan_footer(width: u16, version_w: u16, leaf_w: u16) -> FooterPlan {
    let full_globals = hint_width(&global_hints());
    if version_w + leaf_w + full_globals <= width {
        return FooterPlan {
            show_version: true,
            compact_globals: false,
        };
    }
    if leaf_w + full_globals <= width {
        return FooterPlan {
            show_version: false,
            compact_globals: false,
        };
    }
    // Still short: keep the version off and compact the globals. If even
    // this does not fit, `elide_hints` marks the remainder — there is no
    // width at which the legend is silently cut again.
    FooterPlan {
        show_version: false,
        compact_globals: true,
    }
}

/// Trim `spans` to `budget` cells by dropping **whole hints** from the
/// right, appending `\u{2026}` when anything was dropped.
///
/// The unit is the hint, not the character, which is the entire point:
/// `[Enter] edit  [a] a` is a cut that reads as a complete legend for a
/// key `a` that does something starting with "a". Dropping `[a] add`
/// outright and saying so cannot be misread.
///
/// Hints are the 4-span groups [`key_span`] emits, separated by
/// [`Span::raw`] gaps; the scan walks the gaps rather than assuming a
/// fixed stride, so a leaf that pushes an odd separator still splits
/// correctly.
fn elide_hints(spans: Vec<Span<'static>>, budget: u16) -> Vec<Span<'static>> {
    if hint_width(&spans) <= budget {
        return spans;
    }
    const MARKER: &str = "\u{2026}";
    // Group into hints: a run of spans ending just before a pure-whitespace
    // separator span.
    let mut groups: Vec<Vec<Span<'static>>> = Vec::new();
    let mut current: Vec<Span<'static>> = Vec::new();
    for span in spans {
        let is_sep = !span.content.is_empty() && span.content.trim().is_empty();
        if is_sep {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
        } else {
            current.push(span);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }

    let sep_w = 2u16;
    let marker_w = MARKER.chars().count() as u16;
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut used = 0u16;
    for group in groups {
        let group_w = hint_width(&group);
        let with_sep = if out.is_empty() {
            group_w
        } else {
            group_w + sep_w
        };
        // Reserve room for the marker: an elided legend that fills the
        // budget exactly and drops the marker is back to a silent cut.
        if used + with_sep + 1 + marker_w > budget {
            break;
        }
        if !out.is_empty() {
            out.push(Span::raw("  "));
            used += sep_w;
        }
        out.extend(group);
        used += group_w;
    }
    out.push(Span::raw(" "));
    out.push(Span::styled(MARKER, Style::default().fg(T.warning)));
    out
}

/// True when a **multi-field form** modal is on screen — the overlays
/// whose handlers move focus on Up/Down and cycle the focused field's
/// value on Left/Right.
///
/// Deliberately narrower than "any modal is open". The confirm screens
/// (`ConfirmDelete`, `ConfirmingRemove`), the vertical pickers (Devices'
/// field popup, the Lists catalog picker, the restore picker, the scope
/// menu) and the single-input lookups (resolver, tag create/rename) have
/// no field-to-field focus and no values to cycle, so the form legend
/// would be wrong for them and they keep the leaf's own hints.
///
/// `rules.add_modal` **used to be excluded on purpose** and no longer is.
/// Its handler was a nav-grammar outlier — Up/Down cycled values
/// and Left/Right was unbound — so advertising the shared grammar there
/// would have advertised a dead key, and the exclusion was the honest
/// encoding of that. Converting the
/// handler to the shared grammar removed the exclusion in the same change.
fn form_modal_open(app: &App) -> bool {
    use crate::tui::app::{DeviceModal, EditModalMode, RuleEditMode};

    if app
        .devices
        .modal
        .as_ref()
        // A form with its popup picker open routes Up/Down to the popup
        // and has nothing to cycle — that is the picker's grammar, not
        // the form's.
        .is_some_and(|m| matches!(m, DeviceModal::Form(f) if f.picker.is_none()))
    {
        return true;
    }
    if app
        .subnets
        .modal
        .as_ref()
        .is_some_and(|m| matches!(m.stage, crate::tui::subnet_modal::Stage::EditingForm(_)))
    {
        return true;
    }
    // Ungated, unlike its neighbours:
    // `RuleAddModal` has no confirm or picker stage — its only state is
    // the form — so there is no sub-state in which the shared legend
    // would advertise a key that does nothing.
    if app.rules.add_modal.is_some() {
        return true;
    }
    if app
        .profiles
        .modal
        .as_ref()
        .is_some_and(|m| matches!(m.stage, crate::tui::profile_modal::Stage::EditingForm(_)))
    {
        return true;
    }
    // Gated on `EditingForm` for the same reason as its
    // neighbours: the y/n remove confirm has no field-to-field focus and
    // nothing to cycle, so the form legend would advertise keys that do
    // nothing there.
    if app
        .groups
        .modal
        .as_ref()
        .is_some_and(|m| matches!(m.stage, crate::tui::group_modal::Stage::EditingForm(_)))
    {
        return true;
    }
    // Gated on `EditingForm` like its neighbours.
    //
    // **Two keys in `modal_form_hints` are approximate here, and joining
    // anyway is the deliberate call.** A label has no selector field, so
    // `←→ change` cycles nothing, and this modal saves on Enter rather
    // than `Ctrl+s` — exactly as Groups does, where
    // `ctrl_s_does_not_save_the_group_modal` pins it. The alternative was
    // a fourth, Labels-only footer grammar: one leaf answering a shared
    // question differently is worse than a shared answer that is loose. The
    // modal's own `KEYS` legend, one row above the footer, is exact.
    if app
        .labels
        .modal
        .as_ref()
        .is_some_and(|m| matches!(m.stage, crate::tui::label_modal::Stage::EditingForm(_)))
    {
        return true;
    }
    if app
        .local_dns
        .modal
        .as_ref()
        .is_some_and(|m| matches!(m.stage, crate::tui::local_dns_modal::Stage::EditingForm(_)))
    {
        return true;
    }
    if app
        .lists
        .edit_modal
        .as_ref()
        // Both typed-id gates are excluded: neither is a form, and the
        // form grammar would advertise Tab / ←→ / Ctrl+S keys that do
        // nothing there while omitting the two that do.
        .is_some_and(|m| {
            !matches!(
                m.mode,
                EditModalMode::ConfirmDelete { .. } | EditModalMode::ConfirmUnsignedAllow { .. }
            )
        })
    {
        return true;
    }
    if app
        .rules
        .edit_modal
        .as_ref()
        .is_some_and(|m| matches!(m.mode, RuleEditMode::Edit))
    {
        return true;
    }
    false
}

/// The one navigation grammar every form modal answers to. Mirrors the
/// `Modal forms` block in the `?` overlay (`help::build_blocks`) — when
/// one changes the other must too, or the two discovery surfaces
/// disagree.
fn modal_form_hints() -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    spans.extend(key_span("\u{2191}\u{2193}", "move"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("\u{2190}\u{2192}", "change"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("Ctrl+s", "save"));
    spans.push(Span::raw("  "));
    spans.extend(key_span("Esc", "discard"));
    spans
}

/// Tab-specific keybind hints. Rendered on the left of the footer so
/// the operator always sees the shortcuts relevant to the active tab.
/// Empty for tabs whose only keys are in the global cluster.
fn tab_hints_for(app: &App) -> Vec<Span<'static>> {
    // Every modal overlay is drawn into `chunks[2]`, so the
    // footer stays visible underneath one. That made the leaf's CRUD
    // cluster (`[a] add  [e] edit  [d] delete`) the advertised legend
    // while a form was open — keys that do nothing there. Swap in the
    // form's own grammar instead, so the one surface that is always on
    // screen names the keys that actually work.
    if form_modal_open(app) {
        return modal_form_hints();
    }

    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    match app.active_leaf {
        Leaf::Dashboard => {
            spans.extend(key_span(
                "d",
                if app.dashboard.show_daily {
                    "hourly"
                } else {
                    "daily"
                },
            ));
        }
        Leaf::Devices => {
            // Promote is reached via Enter on an unmapped row (the
            // unified-list flow dispatches contextually based on row
            // variant) so the dedicated `p` was retired — it collided
            // with the global `[p] pause`. Add `a` is the no-MAC
            // fallback for unmapped rows ARP can't resolve.
            //
            // `[G] group-by` left the footer — it still works,
            // it now lives only in `?`. Four verbs never fit a CRUD
            // cluster at the 80-col floor; group-by is the one that
            // isn't a CRUD verb.
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        Leaf::LocalDns => {
            // Surface the three modal openers in the
            // footer so operators discover them without the `?`
            // overlay. Mirrors the Devices cluster.
            //
            // `[o] panel` left the footer along with the two-panel
            // model itself; either way the
            // footer only has room for the CRUD cluster.
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        Leaf::Profiles => {
            // The three modal openers — mirrors the
            // Devices / Local DNS clusters.
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        Leaf::Lists => {
            // The edit modal is the primary mutation surface;
            // surface `[Enter] edit` first so operators discover it
            // without trial-and-error. `a` opens the form modal in Add
            // mode (universal add for any URL). None of these keys
            // collide with the global cluster (r/p/?/q/s) — pinned by
            // `lists_footer_no_collision_with_global_cluster`.
            //
            // `[B] purge.cc` and `[K] kind` left the footer —
            // both still work, both now live only in `?`. The `c`
            // create-category + `m` move-category
            // hints were removed earlier still, with the dead modals.
            spans.extend(key_span("Enter", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("a", "add"));
        }
        Leaf::Rules => {
            // Rules tab is interactive: Enter opens the
            // edit modal on the focused row, [d] short-circuits to
            // delete confirm. No collisions with the global cluster
            // (r/p/?/q/s).
            //
            // `[f] filter` left the footer — it still cycles the
            // chip, it now lives only in `?`.
            spans.extend(key_span("Enter", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        Leaf::QueryLog => {
            // Contextual Enter hint that auto-flips with
            // the selected row's status (BLOCKED → allowlist, ALLOWED
            // → blocklist, neutral statuses → muted "not actionable").
            // Empty Query Log or no selection → no hint at all.
            spans.extend(query_log_hint_spans(app));
        }
        Leaf::Settings => {
            // Backup/Restore actions on the Settings tab used to be
            // bound but invisible because Settings fell
            // into the `_ =>` catch-all below and the footer painted empty
            // here. Mirrors the cluster idiom of Devices/Profiles/Tags.
            // `Ctrl+r` reload stays in the `?` overlay (no tab footer in
            // this codebase shows a Ctrl chord); arrow motion needs no
            // footer hint at all. Uppercase `R` dodges the global
            // `[r]` refresh — same case-distinction Tags already uses.
            spans.extend(key_span("b", "backup"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("R", "restore"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("t", "tracking"));
        }
        // Contextual to the focused pane, and the arrows are
        // named. The old footer read the vim letters for kind and for
        // select, never an arrow key — which is why the operator who
        // reported this leaf as "VIM navigation" had no reason to try
        // one. The arrows worked even then; the footer was the reason
        // nobody knew.
        //
        // Which arrow is offered depends on where the cursor is, for the
        // reason `Leaf::Groups` below states: an affordance is only
        // useful where it applies. On the menu the move is rightwards,
        // on the table leftwards.
        Leaf::Labels => {
            // The three openers. All three are shown from
            // either pane, and that is accurate: `a` reads the focused
            // kind, `e`/`d` read the focused row, and none of them
            // requires the operator to cross over first. None collides
            // with the global cluster (r/p/s/?/q).
            //
            // The `↑↓` / `←→` motion cluster left the footer —
            // both still work (Left/Right stay real bindings here),
            // they now live only in `?`.
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        // The three openers, shown from either pane: `e` and `d` read the
        // focused list row, `a` reads the focused pane. None collides with
        // the global cluster (r/p/s/?/q).
        // **Only keys that are BOUND may appear here.** A legend naming a
        // dead key is worse than no legend: the operator presses it,
        // nothing happens, and they conclude the product is broken — where
        // an unadvertised key is merely one they do not reach for. `a`,
        // `e` and `d` belong here the day their handlers do, not before.
        // Contextual to the focused pane. The verbs act on the LIST, so
        // advertising them while the rule pane has the cursor would name
        // keys that do not apply where the operator is looking — the same
        // reason the footer swaps for an open modal.
        Leaf::CustomLists => match app.custom_lists.focus {
            crate::tui::app::CustomListsFocus::Lists => {
                spans.extend(key_span("a", "add"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("e", "edit"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("d", "delete"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("m", "mount"));
                // No arrow row: this cluster plus the global one already
                // fills 80 columns, and arrow motion needs no footer hint
                // — it lives in `?` like every other leaf's.
            }
            // The rule pane's own verbs. `a` and `d` mean something
            // different here than on the list pane, which is exactly why
            // the legend has to follow the focus rather than name both.
            crate::tui::app::CustomListsFocus::Rules => {
                spans.extend(key_span("a", "add rule"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("e", "edit rule"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("d", "remove rule"));
                spans.push(Span::raw("  "));
                spans.extend(key_span("Esc", "lists"));
            }
        },
        // Full CRUD. The three openers go on the footer rather
        // than only in `?` for the reason Subnets already learned — on a
        // populated tab an affordance that lives only in the help overlay
        // is undiscoverable.
        // The vim-style `select` motion hint left the footer —
        // arrow motion needs no footer hint, and those letters are
        // deleted outright, not just unadvertised.
        Leaf::Groups => {
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
        // The document's own keys. `e` moved here with the
        // viewer — it edits the file, not a setting.
        Leaf::File => {
            spans.extend(key_span("/", "jump"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
        }
        // The two filter affordances. Scrolling is arrow
        // motion, which needs no footer hint; `R` is documented in
        // `?` next to the two keys that make it meaningful.
        Leaf::Logs => {
            spans.extend(key_span("/", "search"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("f", "level"));
        }
        // Read-only roster; the only tab key is row
        // selection via the arrows, which needs no footer hint.
        #[cfg(feature = "cluster")]
        Leaf::Cluster => {}
        Leaf::Subnets => {
            // Subnets is full CRUD + promote, but the affordance used to
            // live only in the `?` overlay and the zero-state prompt, so
            // on a populated tab it was undiscoverable. Surface the three
            // modal openers here; promote-candidate stays in `?` (it's
            // Enter on a `[suggested]` row, contextual not a fixed key).
            //
            // Subnets was the last variant reaching the old `_` fallthrough
            // (which only documented "footer stays uncluttered"); every
            // Leaf now has an explicit arm, so no catch-all remains.
            spans.extend(key_span("a", "add"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("e", "edit"));
            spans.push(Span::raw("  "));
            spans.extend(key_span("d", "delete"));
        }
    }
    spans
}

/// Query Log footer hint cluster — picks the verb based on the focused
/// row's `result` via [`crate::tui::query_log_rule_modal::inferred_action`]:
///
/// | inferred_action       | hint                                  |
/// |-----------------------|---------------------------------------|
/// | `Some(Action::Allow)` | `[Enter] allowlist this query`        |
/// | `Some(Action::Deny)`  | `[Enter] blocklist this query`        |
/// | `None`                | `[Enter] (not actionable on this row)` (muted) |
/// | no selection / empty  | empty Vec (footer stays clean)        |
///
/// The neutral case dims the whole cluster via `T.text_muted` so the
/// operator sees at a glance that pressing Enter on this row is a
/// no-op — the brand-red key paint is reserved for actionable rows.
fn query_log_hint_spans(app: &App) -> Vec<Span<'static>> {
    use crate::cli::commands::rules::Action;
    use crate::tui::query_log_rule_modal::inferred_action;

    let Some(idx) = app.query_log.table_state.selected() else {
        return Vec::new();
    };
    let Some(entry) = app.query_log.entries.get(idx) else {
        return Vec::new();
    };

    match inferred_action(&entry.result) {
        Some(Action::Allow) => key_span("Enter", "allowlist this query").to_vec(),
        Some(Action::Deny) => key_span("Enter", "blocklist this query").to_vec(),
        None => muted_hint("Enter", "(not actionable on this row)"),
    }
}

/// Variant of [`key_span`] that paints the whole cluster — brackets,
/// key, and label — in `T.text_muted`. Used for hints that surface a
/// no-op so the operator's eye registers them as non-actionable
/// before they press the key.
fn muted_hint(k: &'static str, label: &'static str) -> Vec<Span<'static>> {
    let muted = Style::default().fg(T.text_muted);
    vec![
        Span::styled("[", muted),
        Span::styled(k, muted),
        Span::styled("] ", muted),
        Span::styled(label, muted),
    ]
}

/// Display cells occupied by `spans`.
///
/// Counted per `char`, not per byte: the form legend carries `↑↓` and
/// `←→`, which are 3 bytes and 1 cell each, so a byte sum overstates it
/// by 8 and elides a legend that fits. Single-width by construction —
/// every glyph the footer paints is ASCII or a single-cell arrow; a
/// wide grapheme here would need `unicode-width`, and the test below
/// is what fails if one arrives.
fn hint_width(spans: &[Span<'_>]) -> u16 {
    spans
        .iter()
        .map(|s| s.content.chars().count())
        .sum::<usize>()
        .min(u16::MAX as usize) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    /// Concatenate a span list into the raw display string. Used by the
    /// footer hint tests to pin the visible text regardless of styling.
    fn spans_to_string(spans: &[Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    // The too-small guard rect must never extend
    // past the frame, even on degenerate buffer dimensions a real pty
    // can produce (`stty rows 0`, a 1-col pane). The panic vector is a
    // 0-row buffer, which `TestBackend` cannot construct, so drive the
    // pure rect math directly.
    #[test]
    fn too_small_msg_rect_never_escapes_the_frame() {
        // 0-row buffer with room horizontally: the raw rect would be
        // (2,0,75,1) — height 1 over 0 rows, an out-of-bounds write.
        // Clamped, there is nowhere to draw.
        assert!(too_small_msg_rect(Rect::new(0, 0, 79, 0)).is_empty());
        // Fully degenerate.
        assert!(too_small_msg_rect(Rect::new(0, 0, 0, 0)).is_empty());
        // Narrow: x=2 past a 2-col edge, width saturates to 0.
        assert!(too_small_msg_rect(Rect::new(0, 0, 2, 10)).is_empty());
        // Roomy but sub-minimum (79×23): in-bounds and non-empty.
        let area = Rect::new(0, 0, 79, 23);
        let r = too_small_msg_rect(area);
        assert!(!r.is_empty());
        assert!(r.right() <= area.right());
        assert!(r.bottom() <= area.bottom());
    }

    /// Read the footer back as plain text. ratatui splits a styled line
    /// across cells, so a `contains()` on any single span silently
    /// misses; concatenating the rendered symbols is the only honest
    /// read of "what does the operator actually see".
    ///
    /// 160 columns, not 80: the left slot is `Constraint::Min(20)`
    /// 160 columns, not 80, and still deliberately so: these tests pin
    /// whether the legend is *rendered at all*, which is a different
    /// question from whether it fits.
    ///
    /// This doc used to end "at the 80-col floor the Lists legend already
    /// clips mid-hint (`[Enter] edit  [a] a`) — pre-existing and
    /// orthogonal". That was true when written and is no longer:
    /// `s-tui-footer-legend-clipped-at-80-cols` closed it. The floor now
    /// has its own tests below, at exactly 80, because a legend that fits
    /// at 160 proves nothing about the width the product declares it
    /// supports.
    const FOOTER_TEST_COLS: u16 = 160;

    /// The declared minimum width. Pinned as its own constant so a test
    /// that means "at the floor" cannot drift to a width that happens to
    /// pass.
    const FOOTER_FLOOR_COLS: u16 = 80;

    fn footer_text_at(app: &App, cols: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(cols, 1)).unwrap();
        term.draw(|f| render_footer(f, f.area(), app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..cols).map(|x| buf[(x, 0)].symbol()).collect()
    }

    fn footer_text(app: &App) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(FOOTER_TEST_COLS, 1)).unwrap();
        term.draw(|f| render_footer(f, f.area(), app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..FOOTER_TEST_COLS)
            .map(|x| buf[(x, 0)].symbol())
            .collect()
    }

    // The footer's left slot belongs to the tab keyboard
    // legend, permanently. Before this the transient status shared
    // `cols[1]` with `tab_hints_for` and won, so the moment any action
    // reported an outcome the operator lost `[Enter] edit  [a] add  [B]
    // purge.cc  [K] kind` — the discovery surface for the screen they
    // were on — and on six leaves never got it back.
    //
    // The severity styling did not disappear, it moved: it is now
    // the toast's contract, pinned by
    // `toast::tests::toast_styles_success_green_and_error_red`.
    // ── The toast draws over the section-jump popup ─────────────────────

    fn full_frame(app: &mut App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, app)).unwrap();
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

    /// The named defect, end to end through the real `render`.
    ///
    /// A render test and not a handler test, necessarily: the bug was
    /// purely an ordering of two draw calls. Every piece of model state
    /// here — the popup is open, a status is live — is identical before
    /// and after the fix. Only the buffer differs.
    #[test]
    fn a_live_toast_does_not_paint_over_the_section_jump_popup() {
        let mut app = App::new();
        app.active_leaf = Leaf::File;
        app.file.section_jump = Some(String::new());
        app.status_ok("config saved to disk".to_string());

        let frame = full_frame(&mut app, 120, 30);
        assert!(
            !frame.contains("config saved to disk"),
            "the toast painted over an open overlay:\n{frame}"
        );
    }

    /// The control arm, and the one that stops the fix from becoming
    /// "the toast never renders". Same status, no overlay.
    #[test]
    fn a_live_toast_still_renders_with_no_overlay_open() {
        let mut app = App::new();
        app.active_leaf = Leaf::File;
        app.status_ok("config saved to disk".to_string());

        let frame = full_frame(&mut app, 120, 30);
        assert!(
            frame.contains("config saved to disk"),
            "suppressing the toast under an overlay must not suppress it \
             everywhere:\n{frame}"
        );
    }

    /// Enumerates all six. The predicate is a hand-maintained list, so
    /// this is what makes a forgotten seventh visible — a new tab-drawn
    /// overlay that nobody adds to `tab_dispatched_overlay_open` will not
    /// fail this test, but a *removed* one will, and the table in that
    /// function's doc is what a reader checks against.
    /// Names the overlay so a failure says which one, and opens it.
    type OpenOverlay = (&'static str, Box<dyn Fn(&mut App)>);

    #[test]
    fn every_tab_dispatched_overlay_suppresses_the_toast() {
        let open: Vec<OpenOverlay> = vec![
            (
                "file.section_jump",
                Box::new(|a: &mut App| a.file.section_jump = Some(String::new())),
            ),
            (
                "rules.add_modal",
                Box::new(|a: &mut App| {
                    a.rules.add_modal = Some(crate::tui::rule_add_modal::RuleAddModal::open(a))
                }),
            ),
            (
                "lists.edit_modal",
                Box::new(|a: &mut App| a.lists.edit_modal = Some(tabs::lists::build_add_modal())),
            ),
            (
                "lists.catalog_picker",
                Box::new(|a: &mut App| {
                    a.lists.catalog_picker = Some(crate::tui::app::CatalogPickerModal {
                        rows: Vec::new(),
                        table_state: Default::default(),
                        focus: crate::tui::app::CatalogPickerFocus::Table,
                        error_message: None,
                        status_message: None,
                        submitting: false,
                    })
                }),
            ),
        ];
        for (name, open_it) in open {
            let mut app = App::new();
            open_it(&mut app);
            assert!(
                tab_dispatched_overlay_open(&app),
                "{name} is drawn inside render_active_tab, so it must \
                 suppress the toast"
            );
        }

        // And nothing open means nothing suppressed.
        assert!(!tab_dispatched_overlay_open(&App::new()));
    }

    // ── s-tui-footer-legend-clipped-at-80-cols ─────────────────────────
    //
    // All four render to a buffer at exactly `FOOTER_FLOOR_COLS` and
    // assert on cells. A handler-level assertion could not see this
    // defect at all: `tab_hints_for` returned the whole legend before the
    // fix and returns the whole legend after it — the loss happened in
    // ratatui's clip, downstream of everything a handler test can reach.

    #[test]
    fn lists_legend_is_not_cut_mid_hint_at_the_80_column_floor() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let footer = footer_text_at(&app, FOOTER_FLOOR_COLS);

        // The exact byte sequence the defect produced. `[a] a` is a
        // truncation of `[a] add` that reads as a complete hint for a key
        // that does something beginning with "a", which is why it is
        // worse than a dropped hint and worth pinning literally.
        assert!(
            !footer.contains("[a] a "),
            "legend still cut mid-token at {FOOTER_FLOOR_COLS} cols: {footer:?}"
        );
        // This leaf's footer shrunk to two hints — `[B] purge.cc`
        // and `[K] kind` moved to `?` (they are not dropped, just no
        // longer footer-resident), so this test no longer pins them.
        for hint in ["[Enter] edit", "[a] add"] {
            assert!(
                footer.contains(hint),
                "hint {hint:?} lost at the declared floor: {footer:?}"
            );
        }
    }

    /// Every global key survives the floor, even when its label does not.
    ///
    /// The compaction is only defensible while the keys stay: a key on
    /// screen is recoverable through `[?]`, a key that is gone is not.
    #[test]
    fn every_global_key_survives_the_80_column_floor() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let footer = footer_text_at(&app, FOOTER_FLOOR_COLS);
        for key in ["[r]", "[p]", "[s]", "[?]", "[q]"] {
            assert!(
                footer.contains(key),
                "global key {key:?} dropped at the floor: {footer:?}"
            );
        }
    }

    /// The control arm. Without it, a footer that compacted at EVERY
    /// width would satisfy both tests above while regressing the common
    /// case, and nothing would say so.
    #[test]
    fn a_wide_footer_keeps_the_labelled_globals_and_the_version() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let footer = footer_text_at(&app, FOOTER_TEST_COLS);
        assert!(
            footer.contains("[r] refresh"),
            "labels must not be spent at a width that can afford them: {footer:?}"
        );
        assert!(
            footer.contains(concat!("v", env!("CARGO_PKG_VERSION"))),
            "the version must survive a wide footer: {footer:?}"
        );
        assert!(
            !footer.contains('\u{2026}'),
            "nothing is elided at 160 cells: {footer:?}"
        );
    }

    /// A legend too long for the floor even after the version and the
    /// global labels are spent must SAY it was shortened.
    ///
    /// Drives `elide_hints` directly with a budget no real leaf reaches,
    /// because the property — never a silent cut — has to hold at widths
    /// the current set of leaves happens not to produce.
    #[test]
    fn an_overlong_legend_is_marked_elided_never_silently_cut() {
        let mut spans: Vec<Span<'static>> = Vec::new();
        spans.extend(key_span("Enter", "edit"));
        spans.push(Span::raw("  "));
        spans.extend(key_span("a", "add"));
        spans.push(Span::raw("  "));
        spans.extend(key_span("B", "purge.cc"));

        let out = elide_hints(spans, 20);
        let text: String = out.iter().map(|s| s.content.as_ref()).collect();

        assert!(
            text.contains('\u{2026}'),
            "an elided legend must be marked: {text:?}"
        );
        // Cells, via the real `hint_width` — it counts chars now, so the
        // function under test is no longer worth routing around. Asserting
        // through the same helper `elide_hints` budgets against is what
        // actually pins the on-screen width; a second, independent count
        // here would just be the same arithmetic duplicated.
        let cells = hint_width(&out);
        assert!(
            cells <= 20,
            "the marked legend must still fit its budget: {text:?} ({cells} cells)"
        );
        assert!(
            !text.contains("[B]"),
            "a hint is dropped whole or kept whole: {text:?}"
        );
        assert!(
            text.contains("[Enter] edit"),
            "elision runs right-to-left, so the first hint survives: {text:?}"
        );
    }

    #[test]
    fn footer_keeps_tab_hints_while_a_status_is_live() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let quiet = footer_text(&app);
        assert!(
            quiet.contains("[a] add"),
            "baseline legend missing: {quiet}"
        );

        app.status_ok("list 'privacy/ads' saved".to_string());
        let live = footer_text(&app);
        assert!(
            live.contains("[Enter] edit") && live.contains("[a] add"),
            "the tab legend must survive a live status; got: {live}"
        );
        assert!(
            !live.contains("list 'privacy/ads' saved"),
            "the status must render as a toast, not in the footer; got: {live}"
        );

        // An error is no more entitled to the legend than a success.
        app.status_err("refresh failed: connection refused".to_string());
        let live_err = footer_text(&app);
        assert!(
            live_err.contains("[a] add"),
            "an error must not displace the legend either; got: {live_err}"
        );
    }

    // Against the REAL layout, not a hand-derived rect. Both
    // menu-card heights, at the declared 80×24 floor, with and without a
    // focus band forcing the fallback: the toast must stay inside
    // the content chunk and touch neither the menu card nor the footer.
    #[test]
    fn toast_never_touches_the_footer_or_the_menu_card() {
        use crate::tui::toast;

        let area = Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT);
        // Dashboard is a singleton section (3-row card), Lists a
        // multi-leaf one (5-row card) — the two shapes the content rect
        // can take. Pinned so this covers both, not one twice.
        let mut heights = Vec::new();
        for leaf in [Leaf::Dashboard, Leaf::Lists] {
            let mut app = App::new();
            app.active_leaf = leaf;
            let chunks = layout_chunks(area, &app);
            assert_eq!(chunks.len(), 4, "{leaf:?}: header/menu/content/footer");
            heights.push(menu_card_height(&app));
            let content = chunks[2];

            // No focus band, and a band on the first table row (which
            // sends the toast to the bottom-right). Both must hold.
            let bands = [
                None,
                Some(Rect::new(content.x, content.y + 2, content.width, 1)),
            ];
            for band in bands {
                let long = "x".repeat(200);
                let r = toast::toast_rect(content, toast::desired_width(&long), band)
                    .unwrap_or_else(|| panic!("{leaf:?}: a toast must fit at 80×24"));
                assert_eq!(
                    r.intersection(content),
                    r,
                    "{leaf:?}: toast {r:?} escaped the content rect {content:?}"
                );
                assert!(
                    !r.intersects(chunks[1]),
                    "{leaf:?}: toast {r:?} hits the menu card {:?}",
                    chunks[1]
                );
                assert!(
                    !r.intersects(chunks[3]),
                    "{leaf:?}: toast {r:?} hits the footer {:?}",
                    chunks[3]
                );
            }
        }
        assert_eq!(heights, vec![3, 5], "both card shapes must be exercised");
    }

    // …and the half a rect test cannot reach: that `render` actually
    // hands the toast `chunks[2]` and not `area`. Rendering the same
    // frame with and without a live status and diffing the buffers
    // isolates exactly the cells the toast owns — no marker colour to
    // mistake for someone else's, which matters because `bg_elevated`
    // is not unique in a real frame.
    #[test]
    fn a_live_toast_repaints_only_content_area_cells() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        for leaf in [Leaf::Dashboard, Leaf::Lists] {
            let mut app = App::new();
            app.active_leaf = leaf;
            let area = Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT);
            let content = layout_chunks(area, &app)[2];

            let mut quiet_term = Terminal::new(TestBackend::new(MIN_WIDTH, MIN_HEIGHT)).unwrap();
            quiet_term.draw(|f| render(f, &mut app)).unwrap();
            let quiet = quiet_term.backend().buffer().clone();

            app.status_ok("list 'privacy/ads' saved".to_string());
            let mut loud_term = Terminal::new(TestBackend::new(MIN_WIDTH, MIN_HEIGHT)).unwrap();
            loud_term.draw(|f| render(f, &mut app)).unwrap();
            let loud = loud_term.backend().buffer().clone();

            let mut changed = 0usize;
            for y in 0..MIN_HEIGHT {
                for x in 0..MIN_WIDTH {
                    if quiet.cell((x, y)) != loud.cell((x, y)) {
                        changed += 1;
                        assert!(
                            content.contains(ratatui::layout::Position { x, y }),
                            "{leaf:?}: the toast repainted ({x},{y}), outside the content \
                             rect {content:?} — the footer legend and menu card are off limits"
                        );
                    }
                }
            }
            assert!(changed > 0, "{leaf:?}: the toast must render *somewhere*");
        }
    }

    // N4 — `startup_warning` and `paused` keep their footer priority.
    // They are *states*, not events: they persist, and a state is
    // legitimately the current context the legend can defer to.
    #[test]
    fn footer_states_still_outrank_the_tab_hints() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        app.startup_warning = Some(crate::cli::config_discovery::DiscoveryWarning {
            headline: "no config file found, using defaults".to_string(),
            // The footer must render the headline ALONE. A detail long enough
            // to be clipped is the point of the fixture: if the renderer ever
            // reaches for `one_line()` again, this row goes back to losing its
            // tail to the column edge and the assertion below catches it.
            detail: "Searched: ./config.toml, /etc/purge-warden/config.toml. Run                      `warden init` to create one."
                .to_string(),
        });
        let warned = footer_text(&app);
        assert!(warned.contains("no config file found"));
        assert!(!warned.contains("[a] add"));

        app.startup_warning = None;
        app.paused = true;
        let paused = footer_text(&app);
        assert!(paused.contains("paused"));
        assert!(!paused.contains("[a] add"));
    }

    // The mnemonic underline is an SGR-4
    // attribute. `tmux capture-pane -p` STRIPS it, so a plain pty smoke
    // passes identically whether the underline renders or not; only
    // `capture-pane -pe` sees it, and even then a naive grep for
    // `\033\[[0-9;]*4[;m]` false-positives on `\033[34m` (blue fg).
    // This buffer-level test is the always-on proof.
    #[test]
    fn subtab_strip_underlines_exactly_the_mnemonic_char_of_each_leaf() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.active_leaf = Leaf::Profiles; // Filters section, 4 leaves
        let mut term = Terminal::new(TestBackend::new(80, 5)).unwrap();
        term.draw(|f| render_menu_card(f, f.area(), &app)).unwrap();
        let buffer = term.backend().buffer().clone();

        // Card rows: 0 border, 1 section bar, 2 divider, 3 leaf strip.
        let underlined: Vec<String> = (0..80)
            .map(|x| &buffer[(x, 3)])
            .filter(|c| c.modifier.contains(Modifier::UNDERLINED))
            .map(|c| c.symbol().to_string())
            .collect();

        // Profiles→P, Lists→i, Custom Lists→t, Rules→u. Exactly one cell per
        // leaf, in strip order. A stray extra hit means a span boundary is
        // wrong.
        //
        // The `t` is the one worth reading: `mnemonic_offset` CALCULATES the
        // underline position rather than taking it as a constant, so this is
        // what proves it landed on the `t` of "Cus**t**om" and not on some
        // other cell of a two-word label.
        assert_eq!(
            underlined,
            vec!["P", "i", "t", "u"],
            "sub-tab strip must underline exactly one mnemonic char per leaf"
        );
    }

    #[test]
    fn configuration_subtab_strip_underlines_all_four_leaves() {
        // Twin of the test above, on the section that gained a strip.
        // Settings used to be a singleton and painted no sub-tab
        // row at all, so nothing covered the underline there — and `e` is the
        // hardest mnemonic to place, being neither leaf's initial.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.active_leaf = Leaf::Settings; // Configuration section, 5 leaves
        let mut term = Terminal::new(TestBackend::new(80, 5)).unwrap();
        term.draw(|f| render_menu_card(f, f.area(), &app)).unwrap();
        let buffer = term.backend().buffer().clone();

        let underlined: Vec<String> = (0..80)
            .map(|x| &buffer[(x, 3)])
            .filter(|c| c.modifier.contains(Modifier::UNDERLINED))
            .map(|c| c.symbol().to_string())
            .collect();

        // Settings→e (the second strong consonant rule: `s` is taken by
        // Subnets, so sEttings underlines its `e`).
        // `logs-tab`: Log Messages→M. Every letter of "Logs" is already a
        // mnemonic or the `g` prefix, so the leaf is labelled "Log
        // Messages" and takes the free `m` at the second word's initial —
        // this row is where that decision becomes visible to an operator.
        //
        // FOUR leaves: the Tags→T entry is gone with the
        // tab, and Log Messages→M was added. Taking either side of
        // that alone would have resurrected the Tags leaf or
        // deleted the Logs one.
        assert_eq!(
            underlined,
            vec!["b", "e", "F", "M"],
            "Configuration sub-tab strip must underline exactly one mnemonic char per leaf"
        );
    }

    #[test]
    fn underline_survives_highlight_style_on_the_active_leaf() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // ratatui 0.29 `Tabs` patches the selected title with
        // `highlight_style`. `Style::patch` unions modifiers, so UNDERLINED
        // should survive alongside the BOLD highlight — but "should" is not
        // proof, and the active leaf is the one span where the two collide.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists; // mnemonic 'i', mid-word, and active
        let mut term = Terminal::new(TestBackend::new(80, 5)).unwrap();
        term.draw(|f| render_menu_card(f, f.area(), &app)).unwrap();
        let buffer = term.backend().buffer().clone();

        let cell = (0..80)
            .map(|x| &buffer[(x, 3)])
            .find(|c| c.modifier.contains(Modifier::UNDERLINED) && c.symbol() == "i")
            .expect("active leaf `Lists` must still underline its `i`");
        assert!(
            cell.modifier.contains(Modifier::BOLD),
            "active leaf must keep the BOLD highlight as well as the underline"
        );
        assert_eq!(
            cell.fg, T.brand_red,
            "active leaf keeps the brand-red highlight colour"
        );
    }

    #[test]
    fn global_hints_carry_the_five_always_on_keys() {
        let rendered = spans_to_string(&global_hints());
        assert!(rendered.contains("[r] refresh"));
        assert!(rendered.contains("[p] pause"));
        assert!(rendered.contains("[s] resolver"));
        assert!(rendered.contains("[?] help"));
        assert!(rendered.contains("[q] quit"));
    }

    // ── The footer advertises the modal nav grammar ─────────────────────
    //
    // Modal overlays draw into `chunks[2]`; the footer is `chunks[3]` and
    // stays visible under one. These pin that the legend under an open
    // form names the keys that work there, and that closing the form puts
    // the leaf cluster back.

    #[test]
    fn footer_swaps_to_the_modal_grammar_while_a_form_is_open() {
        use crate::tui::app::{DeviceFormState, DeviceModal};
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;

        let leaf_hints = spans_to_string(&tab_hints_for(&app));
        assert!(
            leaf_hints.contains("[a] add"),
            "precondition: the Devices leaf cluster; got: {leaf_hints}"
        );

        app.devices.modal = Some(DeviceModal::Form(DeviceFormState::new_add()));
        let modal_hints = spans_to_string(&tab_hints_for(&app));
        for expected in [
            "\u{2191}\u{2193}] move",
            "\u{2190}\u{2192}] change",
            "[Ctrl+s] save",
            "[Esc] discard",
        ] {
            assert!(
                modal_hints.contains(expected),
                "open form must advertise `{expected}`; got: {modal_hints}"
            );
        }
        assert!(
            !modal_hints.contains("[a] add"),
            "the leaf cluster is dead while a form is open; got: {modal_hints}"
        );

        app.devices.modal = None;
        assert!(
            spans_to_string(&tab_hints_for(&app)).contains("[a] add"),
            "closing the form must restore the leaf cluster"
        );
    }

    #[test]
    fn footer_keeps_leaf_hints_for_confirms_and_pickers() {
        use crate::tui::app::{DeviceModal, EditModalMode};
        // A y/n confirm has no field focus and nothing to cycle.
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;
        app.devices.modal = Some(DeviceModal::DeleteConfirm {
            id: "kids-tablet".into(),
            display_name: "Kids tablet".into(),
        });
        assert!(
            spans_to_string(&tab_hints_for(&app)).contains("[a] add"),
            "a delete confirm must not claim the form grammar"
        );

        // Same for the Lists typed-id confirm screen.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let mut modal = tabs::lists::build_add_modal();
        modal.mode = EditModalMode::ConfirmDelete {
            typed: String::new(),
        };
        app.lists.edit_modal = Some(modal);
        assert!(
            spans_to_string(&tab_hints_for(&app)).contains("[a] add"),
            "the typed-id confirm must not claim the form grammar"
        );

        // A form whose popup picker is open routes Up/Down to the popup
        // and has nothing to cycle — that is the picker's grammar, not
        // the form's. This arm is easy to "simplify" away by a reader who
        // cannot see why it is there, so pin it.
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;
        let mut form = crate::tui::app::DeviceFormState::new_add();
        form.picker = Some(crate::tui::app::FieldPicker {
            target: crate::tui::app::DeviceFormField::Profile,
            options: vec!["default".into(), "kids".into()],
            cursor: 0,
            multi: false,
            selected: Vec::new(),
        });
        app.devices.modal = Some(DeviceModal::Form(form));
        assert!(
            spans_to_string(&tab_hints_for(&app)).contains("[a] add"),
            "a form with its popup picker open must not claim the form grammar"
        );

        // Non-form stages of the Tier-1 trio: the confirm and the
        // terminal Submitted screen both close on any key.
        let mut app = App::new();
        app.active_leaf = Leaf::Subnets;
        app.subnets.modal = Some(crate::tui::subnet_modal::SubnetModal {
            stage: crate::tui::subnet_modal::Stage::ConfirmingRemove(
                crate::tui::subnet_modal::RemoveConfirm {
                    id: "lan".into(),
                    display_name: "LAN".into(),
                    cidrs: vec!["10.10.1.0/24".into()],
                },
            ),
        });
        assert!(
            spans_to_string(&tab_hints_for(&app)).contains("[a] add"),
            "the Subnets remove confirm must not claim the form grammar"
        );
    }

    /// The inversion of this test IS the deliverable.
    ///
    /// It used to assert the opposite — that the Rules ADD modal must
    /// **not** advertise ←/→, because its handler bound value-cycling to
    /// Up/Down and left Left/Right dead. That assertion was correct then
    /// and existed precisely to make the divergence visible rather than
    /// let it rot silently. So it had to be **flipped, not deleted**:
    /// deleting it would have removed the only thing watching this modal's
    /// grammar at the moment the grammar changed.
    #[test]
    fn the_converted_add_rule_modal_advertises_the_shared_form_grammar() {
        let mut app = App::new();
        app.active_leaf = Leaf::Rules;
        app.rules.add_modal = Some(crate::tui::rule_add_modal::RuleAddModal::open(&app));
        let hints = spans_to_string(&tab_hints_for(&app));
        assert!(
            hints.contains("change"),
            "the converted add-rule modal must advertise \u{2190}/\u{2192}; got: {hints}"
        );
    }

    #[test]
    fn tab_hints_for_dashboard_toggle_label_matches_state() {
        let mut app = App::new();
        app.active_leaf = Leaf::Dashboard;
        app.dashboard.show_daily = false;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(rendered.contains("[d] daily"));

        app.dashboard.show_daily = true;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(rendered.contains("[d] hourly"));
    }

    #[test]
    fn tab_hints_for_subnets_carries_crud_cluster() {
        // Subnets graduated from the "no footer key" cohort (Onda-1): the
        // add/edit/delete openers are now surfaced in the footer so the
        // affordance isn't buried in the `?` overlay or the zero-state.
        // Promote-candidate stays contextual (Enter on a `[suggested]`
        // row), not a fixed footer key.
        let mut app = App::new();
        app.active_leaf = Leaf::Subnets;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(rendered.contains("[a] add"), "got: {rendered}");
        assert!(rendered.contains("[e] edit"), "got: {rendered}");
        assert!(rendered.contains("[d] delete"), "got: {rendered}");
    }

    /// The three openers reach the footer.
    ///
    /// The `↑↓`/`←→` motion cluster this test used to check
    /// preceded them is footer-gone entirely now,
    /// so "motion before mutation" no longer applies; `?` carries the
    /// motion grammar instead.
    ///
    /// The cluster is checked against the global one: no shared
    /// letter. That is asserted against `global_hints()` rather than
    /// against a hardcoded list, so moving a key into the global cluster
    /// reddens this instead of silently colliding.
    #[test]
    fn labels_footer_carries_the_crud_cluster_without_colliding() {
        let mut app = App::new();
        app.active_leaf = Leaf::Labels;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(rendered.contains("[a] add"), "got: {rendered}");
        assert!(rendered.contains("[e] edit"), "got: {rendered}");
        assert!(rendered.contains("[d] delete"), "got: {rendered}");

        let globals = spans_to_string(&global_hints());
        for pat in ["[a]", "[e]", "[d]"] {
            assert!(
                !globals.contains(pat),
                "global cluster must NOT also bind `{pat}` (collides with \
                 Labels); got: {globals}"
            );
        }
    }

    /// **Measured, not assumed** — and re-derived, not from an earlier
    /// formula that no longer holds.
    ///
    /// An earlier formula defined the budget as
    /// `80 - version_w - hint_width(&global_hints())`
    /// — the full five-key labelled cluster — which presupposes
    /// `global_hints()` also shrinking to `[?] help  [q] quit`. That
    /// shrink is frozen out
    /// (`every_global_key_survives_the_80_column_floor` stays). Against
    /// the frozen five-key cluster that formula gives a
    /// 14-cell budget nothing here fits under — Devices alone is 30
    /// cells. Weakening the *property* to fit the stale formula would be
    /// exactly the "weaken it to stay green" this file forbids, so the
    /// budget is re-derived from what [`plan_footer`] actually guarantees
    /// instead of from that stale arithmetic.
    ///
    /// [`plan_footer`]'s ladder gives the leaf legend a middle-column width
    /// of 14, 23 or 60 cells depending on which branch fires — and the
    /// three branch thresholds are exactly 14, 23 and "anything else", so
    /// whichever branch a leaf's width lands it in, that branch's width is
    /// always `>=` the leaf's own width. The worst case across all three
    /// branches is 60 — `80 - hint_width(&global_hints_compact())` — so a
    /// leaf under that bound never reaches [`elide_hints`]'s marked
    /// truncation, for any leaf width whatsoever. That is the load-bearing
    /// property `every_leaf_footer_fits_at_80_cols` was named for: not "the
    /// legend never gets shorter than it needs" but "the legend never
    /// silently elides".
    ///
    /// Was `the_labels_footer_overflows_the_eighty_column_floor_like_groups`,
    /// which pinned that overflow as *expected*. This test is the fix
    /// for that overflow; the assertion inverts rather than sitting beside
    /// the old one, per this file's own rule that a red test gets rewritten
    /// into its replacement, not left standing next to it.
    ///
    /// The 60-cell budget alone leaves slack over every current leaf (Tags
    /// and Settings, the widest, are 38) — a leaf could grow two more
    /// short-labelled hints and still fit under it, so width is necessary
    /// but not sufficient here. This test also counts hint
    /// *groups* per leaf against the rule that footer-left shows at most
    /// **four** tab verbs — the same way [`elide_hints`] groups spans
    /// (runs between whitespace-only separator spans), so a leaf that grows
    /// a fifth verb without ever exceeding the width budget still goes red.
    #[test]
    fn every_leaf_footer_fits_at_80_cols() {
        let budget = 80u16.saturating_sub(hint_width(&global_hints_compact()));

        for leaf in Leaf::ALL {
            let mut app = App::new();
            app.active_leaf = leaf;
            let hints = tab_hints_for(&app);

            let w = hint_width(&hints);
            assert!(
                w <= budget,
                "{leaf:?}'s footer legend ({w} cells) exceeds the 80-column \
                 floor's worst-case budget ({budget} cells) and risks \
                 silent elision; shrink it"
            );

            let mut groups = 0usize;
            let mut in_group = false;
            for span in &hints {
                let is_sep = !span.content.is_empty() && span.content.trim().is_empty();
                if is_sep {
                    in_group = false;
                } else if !in_group {
                    groups += 1;
                    in_group = true;
                }
            }
            assert!(
                groups <= 4,
                "{leaf:?}'s footer carries {groups} verb(s), over the \
                 four-verb cap; move the extra one into `?`"
            );

            // The two checks above are a proxy for the real defect (a
            // silent clip), same as this section's opening comment says
            // of the four pre-existing 80-col tests. Render the actual
            // floor and confirm no leaf ever shows the elision marker.
            let footer = footer_text_at(&app, FOOTER_FLOOR_COLS);
            assert!(
                !footer.contains('\u{2026}'),
                "{leaf:?}'s footer elided at the 80-column floor: {footer:?}"
            );
        }
    }

    /// chrome-01: `modal_form_hints()` is reached only through
    /// `form_modal_open`, which no `App::new()` satisfies — so the loop
    /// in `every_leaf_footer_fits_at_80_cols` above never exercises the
    /// one hint set an operator sees while a form modal is actually open.
    /// Drive it directly against the same worst-case budget.
    #[test]
    fn modal_form_hints_survive_the_60_cell_budget_unelided() {
        let budget = 80u16.saturating_sub(hint_width(&global_hints_compact()));
        let elided = elide_hints(modal_form_hints(), budget);
        let text = spans_to_string(&elided);
        assert!(
            !text.contains('\u{2026}'),
            "the modal-form legend ({} cells) must fit the {budget}-cell \
             floor budget unelided: {text:?}",
            hint_width(&modal_form_hints())
        );
        assert!(
            text.contains("[Esc] discard"),
            "the modal's own exit key must survive at the floor: {text:?}"
        );
    }

    #[test]
    fn lists_footer_drops_kind_affordance_and_dead_modals() {
        // The `c` create-category + `m`
        // move-category hints were removed with the dead modals.
        //
        // `[K] kind` left the
        // footer too. It still toggles BLOCK ↔ ALLOW; it now lives only
        // in `?`, alongside `[B] purge.cc`.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let rendered = spans_to_string(&tab_hints_for(&app));
        for gone in ["[K] kind", "[c] category", "[m] move"] {
            assert!(
                !rendered.contains(gone),
                "Lists footer must NOT surface removed hint `{gone}`; got: {rendered}"
            );
        }
    }

    #[test]
    fn lists_footer_carries_enter_edit_affordance() {
        // Enter is the primary edit gesture but used to have no
        // footer hint, so operators kept thinking it was a no-op. Pin
        // the affordance so future refactors don't quietly drop it.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            rendered.contains("[Enter] edit"),
            "Lists footer must surface `[Enter] edit`; got: {rendered}"
        );
    }

    #[test]
    fn lists_footer_no_collision_with_global_cluster() {
        // Defence in depth: every Lists hotkey letter MUST NOT overlap
        // with the global cluster. If a future change moves a global
        // key into this letter space, this
        // test catches the collision before operators do.
        //
        // `B` and `K` left the footer (they still bind, in `?`
        // only), so only `a` remains to check here.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let lists_hints = spans_to_string(&tab_hints_for(&app));
        let global_hints = spans_to_string(&global_hints());
        assert!(
            lists_hints.contains("[a]"),
            "Lists footer must surface `[a]`; got: {lists_hints}"
        );
        assert!(
            !global_hints.contains("[a]"),
            "global cluster must NOT also bind `[a]` (collides with Lists tab); got: {global_hints}"
        );
    }

    #[test]
    fn lists_footer_carries_add_and_drops_catalog_affordance() {
        // Pins `[a] add` (the universal form) alongside
        // `[B] purge.cc` (the curated catalog browser). The
        // catalog hint has left the footer — it still opens the browser, it
        // now lives only in `?` — so `[a] add` is the surviving half.
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            rendered.contains("[a] add"),
            "Lists footer must surface `[a] add`; got: {rendered}"
        );
        assert!(
            !rendered.contains("[B] purge.cc"),
            "Lists footer must NOT surface `[B] purge.cc`; got: {rendered}"
        );
    }

    #[test]
    fn rules_footer_carries_edit_delete_cluster() {
        // Rules tab was promoted from placeholder to interactive.
        // Pin the two hints so future refactors can't drop them;
        // operators rely on the footer to discover the affordances.
        //
        // `[f] filter` left the footer — it still cycles the
        // chip, it now lives only in `?`.
        let mut app = App::new();
        app.active_leaf = Leaf::Rules;
        let rendered = spans_to_string(&tab_hints_for(&app));
        for hint in ["[Enter] edit", "[d] delete"] {
            assert!(
                rendered.contains(hint),
                "Rules footer must surface `{hint}`; got: {rendered}"
            );
        }
        assert!(
            !rendered.contains("[f] filter"),
            "Rules footer must NOT surface `[f] filter`; got: {rendered}"
        );
    }

    // ── Unified menu card ────────────────────────────────────────────

    #[test]
    fn section_has_subtabs_only_on_multi_leaf_sections() {
        // Network and Filters each carry ≥2 leaves and pull
        // a sub-tab row inside the unified card. Dashboard and Query Log
        // are the singleton sections and skip both the divider and the
        // sub-tab row — the menu card collapses to 3 rows on those tabs.
        //
        // Configuration took Tags in, so the section Settings
        // used to own alone is now multi-leaf and DOES paint a strip. That
        // flips this assertion, and with it the card height on the
        // Settings tab from 3 to 5 — the value must match what
        // `render_menu_card` actually paints or ratatui clips the border.
        assert!(!section_has_subtabs(Section::Dashboard));
        assert!(!section_has_subtabs(Section::QueryLog));
        assert!(section_has_subtabs(Section::Network));
        assert!(section_has_subtabs(Section::Filters));
        assert!(section_has_subtabs(Section::Configuration));
    }

    #[test]
    fn menu_card_height_is_3_on_singleton_sections() {
        // The card collapses to 3 rows (top border + section row +
        // bottom border) when the active section has only one leaf.
        // This value MUST match the number of rows `render_menu_card`
        // paints on those sections — a 1-row mismatch would either
        // leave a blank gap below the card or clip the bottom border.
        // Settings dropped off this list — its section gained Tags,
        // so it now pays the 5-row card. Dashboard and Query Log are the last
        // two singletons.
        let mut app = App::new();
        for leaf in [Leaf::Dashboard, Leaf::QueryLog] {
            app.active_leaf = leaf;
            assert_eq!(
                menu_card_height(&app),
                3,
                "{leaf:?} is in a singleton section; card height must be 3"
            );
        }
    }

    #[test]
    fn menu_card_height_is_5_on_multi_leaf_sections() {
        // The card grows to 5 rows on multi-leaf sections: top border
        // + section row + divider row + sub-tab row + bottom border.
        // Pin every leaf in Network, Filters and Configuration so a future
        // leaf promotion that accidentally lands somewhere outside those
        // sections (e.g. a new singleton) trips this test instead
        // of silently shipping a clipped chrome.
        let mut app = App::new();
        for leaf in [
            Leaf::Devices,
            Leaf::Subnets,
            Leaf::LocalDns,
            Leaf::Profiles,
            Leaf::Lists,
            Leaf::Rules,
            // Tags moved to Configuration and took Settings into
            // multi-leaf territory with it. Both belong here now.
            Leaf::Settings,
        ] {
            app.active_leaf = leaf;
            assert_eq!(
                menu_card_height(&app),
                5,
                "{leaf:?} is in a multi-leaf section; card height must be 5"
            );
        }
    }

    // `lc2_c_t6_tags_footer_carries_new_describe_delete_cluster` is gone
    // along with the
    // Tags tab's footer. It pinned the shrink to three CRUD verbs
    // AND, in its second half, that none of the surviving letters collided
    // with the global cluster (r/p/?/q/s) — the half worth naming, because
    // a footer verb that shadows a global key is a silent capture. That
    // check still runs for every other leaf's footer in this module.
    //
    // It had also drifted: the fixture set `active_leaf = Leaf::Labels`,
    // so by the end it was asserting on the LABELS footer under a name
    // promising Tags — which is why its failure here read as
    // "[a] add [e] edit [d] delete" rather than "[a] new tag".

    #[test]
    fn settings_footer_carries_backup_restore_cluster() {
        // Pin the four Settings-tab verbs in the
        // footer so the discoverability gap that landed with the initial
        // Backup/Restore feature can never silently reappear. `R` is
        // uppercase to dodge the global `[r]` refresh — same case-distinct
        // pattern Tags already uses for `[R] rename`.
        let mut app = App::new();
        app.active_leaf = Leaf::Settings;
        let rendered = spans_to_string(&tab_hints_for(&app));
        for hint in ["[b] backup", "[R] restore", "[t] tracking"] {
            assert!(
                rendered.contains(hint),
                "Settings footer must surface `{hint}`; got: {rendered}"
            );
        }
        // Defence in depth: none of the four Settings letters collide
        // with the global cluster (r/p/?/q/s). Case-sensitive — uppercase
        // `[R]` is the Settings restore verb and must remain distinct
        // from the lowercase `[r]` global refresh.
        let global = spans_to_string(&global_hints());
        for pat in ["[b]", "[R]", "[t]"] {
            assert!(
                !global.contains(pat),
                "global cluster must NOT also bind `{pat}` (collides with Settings tab); got: {global}"
            );
        }
    }

    #[test]
    fn lc2_c_t6_tags_leaf_reachable_via_t_mnemonic() {
        // Sprint C T6 of `lists_categories_v2`: pin the `g t` mnemonic
        // so a future leaf addition can't silently displace Tags from
        // the table. Lowercase `t` was free pre-T6 (Settings reuses
        // `e`, Subnets owns `s`) so the natural letter is unambiguous.
    }

    #[test]
    fn tab_hints_for_devices_carries_mapping_keys() {
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;
        let rendered = spans_to_string(&tab_hints_for(&app));
        // Pin the cluster operators rely on so a future cleanup can't
        // silently drop one of them. Ordered front-to-back as they
        // render — `a` first because Add is the answer when Promote
        // refuses (no ARP MAC). Promote has no dedicated key here:
        // Enter dispatches contextually based on the focused row's
        // variant, freeing `p` for the global pause.
        for key in ["[a] add", "[e] edit", "[d] delete"] {
            assert!(
                rendered.contains(key),
                "Devices footer must surface `{key}`; got: {rendered}"
            );
        }
        // `[G] group-by` left the footer — it still cycles, it
        // now lives only in `?`.
        assert!(
            !rendered.contains("[G] group-by"),
            "Devices footer must NOT carry `[G] group-by`; got: {rendered}"
        );
        // Defensive: `[p] promote` is retired — the global
        // `[p] pause` lives in the right cluster and pressing `p` on
        // Devices must fall through to it.
        assert!(
            !rendered.contains("[p] promote"),
            "Devices footer must NOT carry `[p] promote` (collides with global pause); got: {rendered}"
        );
    }

    // ── Query Log footer hint conditional on row status ─────────────────

    /// Build a Query Log app state with one entry whose `result` is the
    /// given status, focus row 0, and switch the active leaf to
    /// `QueryLog`. Returns the prepared `App` ready for `tab_hints_for`.
    fn app_with_query_log_row(result: &str) -> App {
        use crate::ipc::protocol::QueryLogDto;
        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        app.query_log.entries = vec![QueryLogDto {
            timestamp: "2026-05-02T12:00:00Z".into(),
            client_ip: "10.10.1.50".into(),
            client_name: None,
            domain: "example.com".into(),
            query_type: "A".into(),
            result: result.into(),
            response_time_us: 250,
            cname_chain_via: None,
        }];
        app.query_log.table_state.select(Some(0));
        app
    }

    #[test]
    fn tab_hints_for_query_log_blocked_row_says_allowlist() {
        // BLOCKED → operator wants to whitelist the domain. Footer must
        // verb the action ("allowlist") not the inverse ("blocklist") —
        // the auto-flip is the whole point of the S47 redesign.
        let app = app_with_query_log_row("BLOCKED");
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            rendered.contains("[Enter] allowlist this query"),
            "BLOCKED row must surface `[Enter] allowlist this query`; got: {rendered}"
        );
        assert!(
            !rendered.contains("blocklist"),
            "BLOCKED row must NOT mention `blocklist` (auto-flip would be wrong); got: {rendered}"
        );
    }

    #[test]
    fn tab_hints_for_query_log_allowed_row_says_blocklist() {
        // ALLOWED → operator wants to blocklist. Symmetric to the
        // BLOCKED case — the verb flips per the status mapping.
        let app = app_with_query_log_row("ALLOWED");
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            rendered.contains("[Enter] blocklist this query"),
            "ALLOWED row must surface `[Enter] blocklist this query`; got: {rendered}"
        );
        assert!(
            !rendered.contains("allowlist"),
            "ALLOWED row must NOT mention `allowlist`; got: {rendered}"
        );
    }

    #[test]
    fn tab_hints_for_query_log_neutral_row_says_not_actionable() {
        // LOCAL → no rule action available (local DNS records are
        // managed in the Local DNS tab). Footer must say so without
        // surfacing either verb — pressing Enter is a no-op and the
        // hint must communicate that up-front.
        let app = app_with_query_log_row("LOCAL");
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            rendered.contains("not actionable"),
            "LOCAL row must surface a `not actionable` hint; got: {rendered}"
        );
        for verb in ["allowlist", "blocklist"] {
            assert!(
                !rendered.contains(verb),
                "neutral row must NOT mention `{verb}`; got: {rendered}"
            );
        }
    }

    #[test]
    fn tab_hints_for_query_log_no_selection_emits_no_enter_hint() {
        // Empty Query Log (or a stale selection that points off the
        // entries vec) → the footer leaves the left cluster blank.
        // Pin the absence of any `[Enter]` cluster so a future change
        // that defaults to "(not actionable)" on no-selection — making
        // it indistinguishable from a neutral row — trips this test.
        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        // Default state: entries empty, table_state.selected() == None.
        let rendered = spans_to_string(&tab_hints_for(&app));
        assert!(
            !rendered.contains("[Enter]"),
            "Query Log with no selection must emit no Enter hint; got: {rendered}"
        );
    }
}
