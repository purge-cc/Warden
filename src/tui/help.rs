//! Help overlay — keybindings shown on `?`.
//!
//! Layout: each section is a two-column `Table` (key on the left,
//! description on the right) so a long description wraps inside the
//! description cell without dragging into the key column. Section
//! titles render as styled paragraphs above each table; vertical
//! spacers carry the breathing room. Block heights are computed from
//! the wrapped row count so the popup grows with its content rather
//! than guessing a fixed height.
//!
//! **Height vs the 80×24 floor.** The full block list needs 37-49 rows
//! depending on the active leaf; `ui::render` refuses to draw at all
//! below a 24-row terminal, a 22-row interior after the border. Content
//! that size cannot fit that floor by any layout choice — the fix needs
//! either scrolling or losing rows, and [`fit_blocks`] is the honest
//! half of that choice reachable from this file: it keeps only whole
//! blocks from the front (`build_blocks` puts the per-leaf section
//! first for exactly this reason) and the border title reports the cut
//! in numbers rather than letting `Layout::vertical` silently squeeze
//! whichever block loses the constraint solver's tie.
//!
//! **What this does not do.** A real fix scrolls: a stored offset,
//! `↑`/`↓`/`PgUp`/`PgDn` bound while the overlay is open, and a
//! `Scrollbar` drawn against it. That needs an arm in `mod.rs`'s
//! `dispatched_from_help` match (`mod.rs:908-925`) — today any key but
//! `?`/`Esc`/`q`/`Ctrl+C` closes the overlay and falls through to the
//! leaf underneath, by design (`mod.rs:888-891`: "deliberately NO
//! second dispatch table"). This module cannot add that arm, so the
//! shared sections below the per-leaf one stay unreachable at the floor
//! until whoever owns `mod.rs` next wires the scroll.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::app::Leaf;
use crate::tui::overlay::centered_rect;
use crate::tui::theme::T;

const POPUP_W: u16 = 70;
const KEY_COL_W: u16 = 20;
const COL_SPACING: u16 = 1;
/// Width available to the description cell once the borders, key
/// column, and column spacing are subtracted from the popup width.
/// Drives both the word-wrap helper and the Table column constraint.
const DESC_COL_W: u16 = POPUP_W - 2 - KEY_COL_W - COL_SPACING;

pub fn render(f: &mut Frame, active_leaf: Leaf) {
    let area = f.area();
    let blocks = build_blocks(active_leaf);

    // Popup height grows with the content, clamped to the real frame by
    // `centered_rect`. `fit_blocks` is what keeps that clamp honest: it
    // decides, in whole blocks, how much of `blocks` the clamped popup
    // can actually hold — instead of handing every block's full height
    // to `Layout::vertical` and letting the constraint solver silently
    // squeeze whichever ones lose the tie.
    let content_h = blocks.iter().map(HelpBlock::height).sum::<u16>();
    let popup = centered_rect(area, POPUP_W, content_h + 2);
    let inner_budget = popup.height.saturating_sub(2);
    let fit = fit_blocks(&blocks, inner_budget);

    f.render_widget(Clear, popup);

    // `?` uses the modal ecosystem's chrome — rounded, neutral accent,
    // raised surface — instead of a square red-bordered reference card.
    // The ecosystem colour rule bans
    // the brand's red tone on a border outright ("reads as an error
    // state") and reserves it for the brand tick + destructive actions,
    // neither of which this overlay has. Mirrors
    // `modal_form::render_chrome_in`.
    //
    // The title doubles as the overflow tell. Below the terminal-size
    // floor `fit.hidden` is never zero, and this count — not a scroll,
    // see the module doc — is the honest half of that hazard reachable
    // from this file alone.
    let title = if fit.hidden > 0 {
        format!(
            " Help — showing {}/{content_h} rows, resize to see the rest ",
            fit.used
        )
    } else {
        " Help — press ? or Esc to close ".to_string()
    };
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(T.text_primary))
        .style(Style::default().bg(T.bg_elevated))
        .title_style(
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        )
        .title(title);
    let inner = outer.inner(popup);
    f.render_widget(outer, popup);

    let shown = &blocks[..fit.shown];
    let constraints: Vec<Constraint> = shown
        .iter()
        .map(|b| Constraint::Length(b.height()))
        .collect();
    let chunks = Layout::vertical(constraints).split(inner);

    for (rect, blk) in chunks.iter().zip(shown.iter()) {
        blk.render(f, *rect);
    }
}

/// How much of `blocks` fits in `budget` rows.
#[derive(Debug, Clone, Copy)]
struct HelpFit {
    /// Number of leading blocks that fit whole.
    shown: usize,
    /// Rows those blocks occupy.
    used: u16,
    /// Rows left out — the ones a cut fell on.
    hidden: u16,
}

/// Walk `blocks` front to back, keeping whole blocks only, until the next
/// one would exceed `budget`. Never a partial row: a cut always lands on
/// a section boundary, not mid-table.
fn fit_blocks(blocks: &[HelpBlock], budget: u16) -> HelpFit {
    let mut used = 0u16;
    let mut shown = 0usize;
    for b in blocks {
        let h = b.height();
        if used + h > budget {
            break;
        }
        used += h;
        shown += 1;
    }
    let total: u16 = blocks.iter().map(HelpBlock::height).sum();
    HelpFit {
        shown,
        used,
        hidden: total.saturating_sub(used),
    }
}

/// One row of the help table.
///
/// `pub(crate)` so the copy is reachable from a test rather than only
/// from a renderer: the `?` overlay once kept offering to
/// make a new tag long after the verb was renamed, because
/// every guard on that wording tested the *modal* and none could see
/// this table. Operator-facing copy that no test can read is copy that
/// drifts.
///
/// The removed sentence is deliberately not quoted verbatim anywhere in
/// `src/` — the acceptance check for it is a literal grep, and a
/// detector that reports its own post-mortem is one nobody reads twice.
/// `tabs::tags::tests::tags_help_never_promises_tag_creation` is the
/// durable guard; the grep is only its proxy.
pub(crate) struct HelpRow {
    pub(crate) key: &'static str,
    pub(crate) desc: &'static str,
}

/// A vertical block in the popup. Each block reports its rendered
/// height so the outer layout can place it without overlap.
enum HelpBlock {
    Title(&'static str),
    Spacer,
    Rows(Vec<HelpRow>),
}

impl HelpBlock {
    fn height(&self) -> u16 {
        match self {
            HelpBlock::Title(_) | HelpBlock::Spacer => 1,
            HelpBlock::Rows(rows) => rows
                .iter()
                .map(|r| word_wrap(r.desc, DESC_COL_W as usize).len() as u16)
                .sum(),
        }
    }

    fn render(&self, f: &mut Frame, area: Rect) {
        match self {
            HelpBlock::Title(text) => {
                // `warden_teal` marks static info — section
                // headers, read-only values. These are section headers.
                let para = Paragraph::new(Line::from(Span::styled(
                    *text,
                    Style::default()
                        .fg(T.warden_teal)
                        .add_modifier(Modifier::BOLD),
                )));
                f.render_widget(para, area);
            }
            HelpBlock::Spacer => {}
            HelpBlock::Rows(rows) => {
                let table_rows: Vec<Row<'_>> = rows
                    .iter()
                    .map(|r| {
                        let lines = word_wrap(r.desc, DESC_COL_W as usize);
                        let height = lines.len() as u16;
                        let desc_text = Text::from(
                            lines.into_iter().map(Line::from).collect::<Vec<Line<'_>>>(),
                        );
                        Row::new(vec![
                            Cell::from(Span::styled(
                                format!("  {}", r.key),
                                Style::default().fg(T.info).add_modifier(Modifier::BOLD),
                            )),
                            Cell::from(desc_text),
                        ])
                        .height(height)
                    })
                    .collect();

                let table = Table::new(
                    table_rows,
                    [
                        Constraint::Length(KEY_COL_W),
                        Constraint::Length(DESC_COL_W),
                    ],
                )
                .column_spacing(COL_SPACING);

                f.render_widget(table, area);
            }
        }
    }
}

/// Build the ordered list of blocks for the popup: shared sections
/// (Navigation / Mnemonics / Global) followed by the per-leaf section.
fn build_blocks(active_leaf: Leaf) -> Vec<HelpBlock> {
    let mut blocks = vec![
        HelpBlock::Title(" Navigation"),
        HelpBlock::Spacer,
        HelpBlock::Rows(vec![
            HelpRow {
                key: "1-5",
                desc: "Jump to section (Dashboard/Query Log/Network/Filters/Configuration)",
            },
            HelpRow {
                key: "[ / ]",
                desc: "Cycle leaves within the active section",
            },
            // The linear cycle count tracks `Leaf::ALL.len()`,
            // which the `cluster` build grows by one. Pinned by
            // `navigation_block_leaf_count_matches_leaf_all_len`, which is
            // why a leaf coming or going shows up here as a number change
            // rather than as prose nobody re-read. The gated string is the
            // dangerous half: the default suite cannot see it, so it has
            // gone green while wrong before.
            #[cfg(not(feature = "cluster"))]
            HelpRow {
                key: "Tab / Shift+Tab",
                desc: "Cycle ALL 14 leaves linearly",
            },
            #[cfg(feature = "cluster")]
            HelpRow {
                key: "Tab / Shift+Tab",
                desc: "Cycle ALL 15 leaves linearly",
            },
            HelpRow {
                key: "g <letter>",
                desc: "Direct jump to a leaf (mnemonic table below)",
            },
        ]),
        HelpBlock::Spacer,
        // One navigation grammar for every modal form, stated
        // once here instead of per-modal. Before this the arrows meant
        // "move focus" in four forms and "change the value" in three, and
        // neither reading was advertised anywhere the operator could find
        // it. Kept to three non-wrapping rows — the overlay's height is
        // the sum of its blocks and already crowds an 80x24 terminal.
        HelpBlock::Title(" Modal forms  (add / edit dialogs)"),
        HelpBlock::Spacer,
        HelpBlock::Rows(vec![
            HelpRow {
                key: "Up/Down or Tab",
                desc: "Move between fields (any modal form)",
            },
            // The desc, not a fourth row. The block is
            // deliberately three rows (the overlay already crowds 80×24)
            // and a row's height is `word_wrap(desc, DESC_COL_W)`, so the
            // copy has to stay inside 47 cells or it costs the row a
            // fourth line anyway.
            //
            // The clause used to read "on tags, pick a suggestion". The
            // Suggestions row went with the tags fields in `plp-s5d` —
            // `grep -rn Suggestions src/tui/` returns nothing — so that
            // half named a widget the operator cannot find. Left/Right
            // itself is still live on every picker and toggle.
            HelpRow {
                key: "Left/Right",
                desc: "Change the value on a picker or toggle",
            },
            HelpRow {
                key: "Ctrl+s / Esc",
                desc: "Save the form / discard and close",
            },
        ]),
        HelpBlock::Spacer,
        HelpBlock::Title(" Mnemonics  (g + letter)"),
        HelpBlock::Spacer,
        HelpBlock::Rows(vec![
            HelpRow {
                key: "g d / g q",
                desc: "Dashboard / Query Log",
            },
            // Grouped by owning section so the
            // help mirrors the menu card. Network lost Profiles; Filters
            // leads with it and lists its leaves in strip order.
            // The Configuration row regroups with its section; the
            // sub-tab strip underlines each letter inside its own label.
            //
            // **Two rows per section, and the width is the reason.** The key
            // cell is rendered as `format!("  {key}")` inside a
            // `Length(KEY_COL_W)` column, so a key has 18 cells, not 20 —
            // and a table cell truncates in SILENCE. Three leaves fit on one
            // row (`g v / g s / g l` is 15); four do not (`g p / g i / g t /
            // g u` is 21), so `Filters` and every section that grows past
            // three leaves splits instead of losing its last letter.
            //
            // The block used to list nine of thirteen letters for exactly
            // this reason — `g o`, `g f` and `g m` were dropped rather than
            // truncated. Splitting the rows is what lets it be complete, and
            // `mnemonic_block_lists_every_mnemonic_letter` now derives the
            // expected set from `from_mnemonic` so it cannot silently go
            // partial again.
            HelpRow {
                key: "g v / g s",
                desc: "Devices / Subnets   (Network)",
            },
            HelpRow {
                key: "g o / g l",
                desc: "Groups / Local DNS   (Network)",
            },
            HelpRow {
                key: "g p / g i",
                desc: "Profiles / Lists   (Filters)",
            },
            HelpRow {
                key: "g t / g u",
                desc: "Custom Lists / Rules   (Filters)",
            },
            HelpRow {
                key: "g b / g e",
                desc: "Labels / Settings   (Configuration)",
            },
            HelpRow {
                key: "g f / g m",
                desc: "File / Log Messages   (Configuration)",
            },
            #[cfg(feature = "cluster")]
            HelpRow {
                key: "g c",
                desc: "Cluster",
            },
        ]),
        HelpBlock::Spacer,
        HelpBlock::Title(" Global"),
        HelpBlock::Spacer,
        HelpBlock::Rows(vec![
            HelpRow {
                key: "r",
                desc: "Force refresh + reload daemon",
            },
            HelpRow {
                key: "p",
                desc: "Pause / resume",
            },
            HelpRow {
                key: "s",
                desc: "Open Resolver modal (source-IP lookup)",
            },
            HelpRow {
                key: "?",
                desc: "Toggle this help",
            },
            HelpRow {
                key: "q / Ctrl+C",
                desc: "Quit",
            },
        ]),
    ];

    // The per-leaf section leads rather than trails: it is the one block
    // that changes with the active leaf, and the one the operator opened
    // `?` to find. `render` cuts from the back when the popup does not
    // fit the terminal (`fit_blocks`), so a cut lands on one of the four
    // shared sections above, never on this one.
    let mut leading = vec![
        HelpBlock::Title(per_leaf_header(active_leaf)),
        HelpBlock::Spacer,
        HelpBlock::Rows(per_leaf_rows(active_leaf)),
        HelpBlock::Spacer,
    ];
    leading.append(&mut blocks);
    leading
}

fn per_leaf_header(leaf: Leaf) -> &'static str {
    match leaf {
        Leaf::Dashboard => " Dashboard Keybindings",
        Leaf::QueryLog => " Query Log Keybindings",
        Leaf::Devices => " Devices Keybindings",
        Leaf::Subnets => " Subnets Keybindings",
        Leaf::Groups => " Groups Keybindings",
        Leaf::Labels => " Labels Keybindings",
        Leaf::LocalDns => " Local DNS Keybindings",
        Leaf::Profiles => " Profiles Keybindings",
        Leaf::Lists => " Lists Keybindings",
        Leaf::CustomLists => " Custom Lists Keybindings",
        Leaf::Rules => " Rules Keybindings",
        Leaf::Settings => " Settings Keybindings",
        Leaf::File => " File Keybindings",
        Leaf::Logs => " Log Messages Keybindings",
        #[cfg(feature = "cluster")]
        Leaf::Cluster => " Cluster Keybindings",
    }
}

/// The per-leaf keybinding table the `?` overlay renders.
///
/// `pub(crate)` for the same reason as [`HelpRow`].
/// `tabs::tags::tests::tags_help_never_promises_tag_creation`
/// reads it directly, which is stronger than an `include_str!` grep:
/// it asserts on the *data* this leaf actually renders, so it neither
/// false-positives on another leaf's legitimate "Create" nor survives
/// a reword that keeps the promise.
pub(crate) fn per_leaf_rows(leaf: Leaf) -> Vec<HelpRow> {
    match leaf {
        Leaf::Dashboard => vec![HelpRow {
            key: "d",
            desc: "Toggle hourly / daily chart",
        }],
        Leaf::QueryLog => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll table",
            },
            // Jump-to-bottom is
            // `End`, not the vim-style `G`.
            HelpRow {
                key: "End",
                desc: "Jump to bottom",
            },
            // Bound-and-undocumented is the one state wrong in both
            // directions — it fires and nothing names it. A binding that
            // exists only in the code is not a feature; it is a
            // landmine.
            HelpRow {
                key: "PgUp/PgDn",
                desc: "Scroll; at the table edge, page newer / older",
            },
            HelpRow {
                key: "/",
                desc: "Filter by domain (substring)",
            },
            HelpRow {
                key: "c",
                desc: "Filter by client (substring)",
            },
            // `qlog-advanced-filter-form`. The card's `Adv [f]` chip is
            // the other half of this, and it is allowed to disappear on a
            // narrow terminal while inactive — which is precisely when a
            // first-time operator needs the key named. So it is named here.
            HelpRow {
                key: "f",
                desc: "Advanced search (client name / IP / subnet, glob)",
            },
            HelpRow {
                key: "b",
                desc: "Toggle blocked-only",
            },
            HelpRow {
                key: "t",
                desc: "Cycle time filter (off/1h/6h/24h)",
            },
            HelpRow {
                key: "R",
                desc: "Reset all filters",
            },
            HelpRow {
                key: "Esc",
                desc: "Cancel the current filter edit",
            },
            HelpRow {
                key: "Enter",
                desc: "Allowlist / blocklist focused row (auto-flip on status)",
            },
        ],
        Leaf::Devices => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Move cursor (skips group headers)",
            },
            HelpRow {
                key: "Enter",
                desc: "Edit (mapped) or Promote (unmapped)",
            },
            HelpRow {
                key: "a / e / d",
                desc: "Add / Edit / Delete (mapped rows)",
            },
            HelpRow {
                key: "G",
                desc: "Cycle group-by (none / owner / dept / profile)",
            },
            HelpRow {
                key: "/",
                desc: "Filter the list by subnet (CIDR)",
            },
            HelpRow {
                key: "R",
                desc: "Clear the subnet filter",
            },
        ],
        Leaf::Subnets => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll list",
            },
            HelpRow {
                key: "a",
                desc: "Add a subnet",
            },
            HelpRow {
                key: "e",
                desc: "Edit the focused subnet",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Delete the focused subnet (tiered confirm)",
            },
            HelpRow {
                key: "Enter",
                desc: "Promote the focused auto-discovered candidate to a configured subnet",
            },
        ],
        Leaf::LocalDns => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll focused panel",
            },
            HelpRow {
                key: "o",
                desc: "Switch focus Global ⇄ Profile",
            },
            HelpRow {
                key: "n / N",
                desc: "Next / previous profile (Profile panel)",
            },
            HelpRow {
                key: "a",
                desc: "Add a local DNS record",
            },
            HelpRow {
                key: "e",
                desc: "Edit the focused row",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove the focused row (tiered confirm)",
            },
        ],
        Leaf::Profiles => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll list",
            },
            HelpRow {
                key: "a",
                desc: "Add a profile (id + display name)",
            },
            HelpRow {
                key: "e",
                desc: "Edit the focused profile (6 mutable fields)",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Delete the focused profile (refuses if still referenced)",
            },
        ],
        // The pane the keys act on is the one with the ▸ cursor, and the
        // footer names it. `a` and `d` mean different things on each side,
        // so the rows say which side they belong to rather than leaving the
        // operator to infer it from the focus they may not have noticed.
        // Every row here must name a key the leaf's handler actually
        // binds. The `?` overlay is the surface an operator opens TO LEARN
        // the keys, so a dead letter listed here is a defect, not a
        // preview — pinned by `every_key_the_custom_lists_leaf_advertises_
        // is_bound`.
        Leaf::CustomLists => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Move inside the focused pane",
            },
            HelpRow {
                key: "Enter/Right",
                desc: "Give the rule pane the cursor",
            },
            HelpRow {
                key: "Left/Esc",
                desc: "Return to the list pane",
            },
            HelpRow {
                key: "a",
                desc: "Add: a list on the left pane, a rule on the right",
            },
            HelpRow {
                key: "e",
                desc: "Edit the selected list's name and description",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove: the list (refused while mounted), or the rule",
            },
            HelpRow {
                key: "m",
                desc: "Mount / unmount the list on profiles (Space toggles, Enter saves)",
            },
        ],
        Leaf::Lists => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll list",
            },
            HelpRow {
                key: "Enter",
                desc: "Edit the focused list (or promote the focused catalog candidate)",
            },
            HelpRow {
                key: "a",
                desc: "Add a new blocklist by URL",
            },
            HelpRow {
                key: "B",
                desc: "Browse the purge.cc catalog (Space toggles, Ctrl+s saves)",
            },
            HelpRow {
                key: "K",
                desc: "Toggle list kind (BLOCK ↔ ALLOW)",
            },
            // Live filter-card keys.
            HelpRow {
                key: "/",
                desc: "Search lists by id / name / URL",
            },
            HelpRow {
                key: "f",
                desc: "Cycle kind filter (all / block / allow)",
            },
            HelpRow {
                key: "R",
                desc: "Clear the search text + kind filter",
            },
        ],
        Leaf::Rules => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll list",
            },
            HelpRow {
                key: "a",
                desc: "Add a new rule (domain / action / scope)",
            },
            HelpRow {
                key: "Enter",
                desc: "Edit the focused rule",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Delete the focused rule (typed-id confirm)",
            },
            HelpRow {
                key: "/",
                desc: "Search rules by text",
            },
            HelpRow {
                key: "f",
                desc: "Cycle filter (all / allow / deny)",
            },
            HelpRow {
                key: "R",
                desc: "Clear the search text + filter",
            },
        ],
        // Two panes, navigated on the axis they are drawn.
        // The vocabulary list stops at `department` — `tag` is declared
        // from the CLI and lives on the Tags tab, which is the derived
        // view of what entities actually carry.
        //
        // `a` works on an empty vocabulary too — it is the only
        // TUI path that declares the first value, and empty is the state
        // both live boxes are actually in.
        Leaf::Labels => vec![
            HelpRow {
                key: "Left/Right",
                desc: "Move focus between the kind menu and the entries",
            },
            HelpRow {
                key: "Up/Down",
                desc: "Move inside the focused pane (kind, or entry)",
            },
            // There is no `h`/`l` alias for Left/Right — it is deleted
            // outright, not just unadvertised, so there is no alias row
            // left to list.
            HelpRow {
                key: "a",
                desc: "Declare a value in the selected kind",
            },
            HelpRow {
                key: "e",
                desc: "Edit the selected entry",
            },
            HelpRow {
                key: "d",
                desc: "Remove the selected entry (refused while devices use it)",
            },
        ],
        // `a` works on an empty list too — it is the only TUI
        // path that creates the first group.
        Leaf::Groups => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Select a group",
            },
            HelpRow {
                key: "a",
                desc: "Add a group",
            },
            HelpRow {
                key: "e",
                desc: "Edit the selected group",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove the selected group",
            },
        ],
        // The document's keys moved to Leaf::File with the
        // viewer. What is left is what Settings administers.
        Leaf::File => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll config viewer",
            },
            HelpRow {
                key: "/",
                desc: "Jump to a config section",
            },
            HelpRow {
                key: "e",
                desc: "Open in $EDITOR",
            },
        ],
        // `logs-tab`: every binding `handle_logs_key` answers to has a row
        // here. Non-negotiable — an undocumented binding is a feature only
        // its author can find.
        Leaf::Logs => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll one message",
            },
            HelpRow {
                key: "PgUp/PgDn",
                desc: "Scroll one page",
            },
            HelpRow {
                key: "Home/End",
                desc: "Jump to newest / oldest fetched",
            },
            HelpRow {
                key: "/",
                desc: "Search message text and module",
            },
            HelpRow {
                key: "f",
                desc: "Cycle level: all / errors / warnings / info",
            },
            HelpRow {
                key: "R",
                desc: "Clear the search and the level filter",
            },
        ],
        Leaf::Settings => vec![
            HelpRow {
                key: "t",
                desc: "Open the Tracking form",
            },
            HelpRow {
                key: "b",
                desc: "Back up the config tree",
            },
            HelpRow {
                key: "R",
                desc: "Restore config from a backup",
            },
            HelpRow {
                key: "Ctrl+r",
                desc: "Reload daemon config",
            },
        ],
        #[cfg(feature = "cluster")]
        Leaf::Cluster => vec![HelpRow {
            key: "Up/Down",
            desc: "Select a roster node (primary only)",
        }],
    }
}

/// Word-wrap `s` into lines that each fit within `width` columns.
/// Splits on whitespace; a word longer than `width` is broken at the
/// column boundary (rare for the help strings, but the fallback keeps
/// the cell from overflowing). Always returns at least one line so a
/// row built from the result has height ≥ 1.
fn word_wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            if word.chars().count() <= width {
                current.push_str(word);
            } else {
                let head: String = word.chars().take(width).collect();
                let tail: String = word.chars().skip(width).collect();
                lines.push(head);
                current = tail;
            }
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flatten_rows(rows: &[HelpRow]) -> String {
        rows.iter()
            .map(|r| format!("{} {}", r.key, r.desc))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn query_log_help_block_advertises_enter_not_a_d() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::QueryLog));

        assert!(
            blob.contains("Enter"),
            "Query Log help must advertise Enter as the row-action key; got:\n{blob}"
        );
        let lower = blob.to_lowercase();
        assert!(
            lower.contains("allowlist") && lower.contains("blocklist"),
            "Query Log help must mention both allowlist and blocklist semantics; got:\n{blob}"
        );
        assert!(
            !blob.contains("a / d"),
            "regression: 'a / d' binding must not reappear in help overlay; got:\n{blob}"
        );
        assert!(
            !blob.contains("Allow / Deny scope modal"),
            "regression: pre-S47 'Allow / Deny scope modal' wording must not reappear; got:\n{blob}"
        );
    }

    #[test]
    fn query_log_help_block_preserves_other_bindings() {
        let rows = per_leaf_rows(Leaf::QueryLog);
        let blob = flatten_rows(&rows);

        // Structural checks, not `blob.contains`, for the two renamed
        // keys: "End" and "Up" are common enough substrings elsewhere in
        // this blob that a `contains` would not discriminate a real miss
        // from an accidental hit.
        assert!(
            rows.iter()
                .any(|r| r.key == "Up/Down" && r.desc == "Scroll table"),
            "scroll binding Up/Down must remain; got:\n{blob}"
        );
        assert!(
            rows.iter()
                .any(|r| r.key == "End" && r.desc == "Jump to bottom"),
            "End jump-to-bottom must remain (not the vim-style G); got:\n{blob}"
        );
        assert!(
            blob.contains("Filter by domain"),
            "/ filter-by-domain binding must remain; got:\n{blob}"
        );
        assert!(
            blob.contains("Reset all filters"),
            "R/Esc reset must remain; got:\n{blob}"
        );
    }

    /// The `?` overlay is where an operator looks for a key
    /// they cannot see. The one modal navigation grammar has to be named
    /// there, on every leaf, or the change is invisible: the keys work
    /// and nothing on screen says so.
    #[test]
    fn build_blocks_advertises_the_modal_form_grammar_on_every_leaf() {
        for leaf in Leaf::ALL {
            let blocks = build_blocks(leaf);
            let blob: String = blocks
                .iter()
                .filter_map(|b| match b {
                    HelpBlock::Rows(rows) => Some(flatten_rows(rows)),
                    _ => None,
                })
                .collect();
            for needle in ["Up/Down or Tab", "Left/Right"] {
                assert!(
                    blob.contains(needle),
                    "`{needle}` must appear in the help overlay on {leaf:?}; got: {blob}"
                );
            }
            let has_title = blocks
                .iter()
                .any(|b| matches!(b, HelpBlock::Title(t) if t.contains("Modal forms")));
            assert!(
                has_title,
                "the `Modal forms` section is missing on {leaf:?}"
            );
        }
    }

    #[test]
    fn build_blocks_includes_resolver_global_hotkey() {
        // Post-S52 review: `s` must appear in the Global section so
        // operators see it inside `?` even before noticing the footer.
        let blocks = build_blocks(Leaf::Dashboard);
        let has_resolver = blocks.iter().any(|b| match b {
            HelpBlock::Rows(rows) => rows
                .iter()
                .any(|r| r.key == "s" && r.desc.contains("Resolver modal")),
            _ => false,
        });
        assert!(
            has_resolver,
            "Help overlay must list `s` → Resolver modal in Global section"
        );
    }

    #[test]
    fn word_wrap_keeps_short_string_on_one_line() {
        let lines = word_wrap("short text", 40);
        assert_eq!(lines, vec!["short text".to_string()]);
    }

    #[test]
    fn word_wrap_breaks_long_string_within_column_width() {
        let lines = word_wrap(
            "Jump to section (Dashboard/Query Log/Network/Filters/Configuration)",
            DESC_COL_W as usize,
        );
        assert!(
            lines.len() >= 2,
            "navigation row description must wrap to >=2 lines; got: {lines:?}"
        );
        for line in &lines {
            assert!(
                line.chars().count() <= DESC_COL_W as usize,
                "wrapped line exceeds column width: {:?} ({} chars)",
                line,
                line.chars().count()
            );
        }
    }

    #[test]
    fn word_wrap_returns_one_empty_line_for_empty_input() {
        assert_eq!(word_wrap("", 40), vec!["".to_string()]);
    }

    #[test]
    fn every_leaf_has_a_per_leaf_header_and_at_least_one_row() {
        // Iterate Leaf::ALL so any future leaf addition
        // automatically requires both a per-leaf header and at least one
        // row. A loop that hardcodes the leaf list can silently miss a
        // newly-added leaf.
        for leaf in Leaf::ALL {
            let header = per_leaf_header(leaf);
            assert!(
                header.contains("Keybindings"),
                "{leaf:?}: per-leaf header must include 'Keybindings'; got {header:?}"
            );
            assert!(
                !per_leaf_rows(leaf).is_empty(),
                "{leaf:?}: per-leaf rows must not be empty"
            );
        }
    }

    /// The keys of the Mnemonics block, one entry per rendered row.
    ///
    /// Scoped to that block on purpose: a blob built from every row's key
    /// AND description matches `"g b"` inside prose, so it cannot tell a
    /// documented letter from a mentioned one.
    fn mnemonic_block_keys() -> Vec<&'static str> {
        let blocks = build_blocks(Leaf::Dashboard);
        let title = blocks
            .iter()
            .position(|b| matches!(b, HelpBlock::Title(t) if t.contains("Mnemonics")))
            .expect("the overlay has a Mnemonics block");
        blocks[title..]
            .iter()
            .find_map(|b| match b {
                HelpBlock::Rows(rows) => Some(rows.iter().map(|r| r.key).collect()),
                _ => None,
            })
            .expect("the Mnemonics title is followed by its rows")
    }

    /// Every letter `from_mnemonic` answers to is documented.
    ///
    /// **The name promised this; the body did not deliver it.** It asserted
    /// two hardcoded substrings, so a block listing nine letters of
    /// thirteen passed — and it searched descriptions too, where `"g b"`
    /// occurs as prose, so a row could satisfy it without the key existing.
    /// Both halves are closed: the expected set is derived from
    /// `from_mnemonic`, and the haystack is the block's key column, split
    /// into whole tokens rather than matched as a substring.
    ///
    /// Derived also means it covers the `cluster` build's extra letter
    /// without a second list to keep in step.
    #[test]
    fn mnemonic_block_lists_every_mnemonic_letter() {
        let keys = mnemonic_block_keys();
        for ch in 'a'..='z' {
            let Some(leaf) = Leaf::from_mnemonic(ch) else {
                continue;
            };
            let want = format!("g {ch}");
            assert!(
                keys.iter().any(|k| k.split(" / ").any(|t| t == want)),
                "mnemonic block must document `{want}` -> {leaf:?}; keys are {keys:?}"
            );
        }
    }

    /// No key is wider than the column that draws it.
    ///
    /// A `Table` cell truncates in silence, and the key is rendered with a
    /// two-space indent, so the budget is `KEY_COL_W - 2`. This is the
    /// guard that makes a four-leaf section split its row instead of
    /// quietly losing its last letter.
    #[test]
    fn no_help_key_overflows_the_key_column() {
        for leaf in Leaf::ALL {
            for blk in build_blocks(leaf) {
                let HelpBlock::Rows(rows) = blk else { continue };
                for r in rows {
                    let rendered = format!("  {}", r.key);
                    assert!(
                        rendered.chars().count() <= KEY_COL_W as usize,
                        "{leaf:?}: key {:?} renders as {} cells, over KEY_COL_W {KEY_COL_W}",
                        r.key,
                        rendered.chars().count()
                    );
                }
            }
        }
    }

    /// The new row survives to the screen, whole.
    ///
    /// A row-vector assertion cannot see truncation — the vector is correct
    /// either way and the defect lives in how the widget draws it. This
    /// reads the cells back.
    #[test]
    fn the_filters_mnemonic_row_paints_without_truncation() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        // Tall enough that the overlay is not clamped, so the assertion
        // fails on truncation rather than on the row being off-screen.
        let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
        term.draw(|f| render(f, Leaf::CustomLists)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut screen = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                screen.push_str(buf[(x, y)].symbol());
            }
            screen.push('\n');
        }
        assert!(
            screen.contains("g t / g u"),
            "the Filters mnemonic row must paint whole; got:\n{screen}"
        );
        assert!(
            screen.contains("Custom Lists / Rules"),
            "its description must paint too; got:\n{screen}"
        );
    }

    /// Lists help_rows must advertise the full current
    /// binding set. This once drifted: the Lists rows still described a
    /// stale "Toggle drill-down detail" Enter behaviour and missed
    /// the five mutation hotkeys (a/B/c/m/K). The footer hint
    /// cluster in `ui::tab_hints_for` already advertised them but the
    /// `?` overlay had not caught up.
    #[test]
    fn lists_help_advertises_current_binding_set() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::Lists));
        // Each binding row in flatten_rows is `{key} {desc}`, joined by
        // `\n`. So a single-letter key like `a` appears as `\na ` or at
        // blob start; multi-char keys like `Enter` survive a contains-
        // check directly. The live filter-card keys
        // (`/`, `f`, `R`) must be present.
        for needle in ["Enter", "\na ", "\nB ", "\nK ", "\n/ ", "\nf ", "\nR "] {
            assert!(
                blob.contains(needle),
                "Lists help must advertise [{}] binding; got blob:\n{blob}",
                needle.trim()
            );
        }
        // The unmounted category/assignment keys must NOT be
        // advertised any more (they dead-ended in refusal stubs).
        for gone in ["\nc ", "\nm ", "\np ", "Space / x"] {
            assert!(
                !blob.contains(gone),
                "Lists help must NOT advertise removed binding [{}]; got blob:\n{blob}",
                gone.trim()
            );
        }
        // Stale wording must NOT reappear.
        assert!(
            !blob.contains("Toggle drill-down detail"),
            "regression: stale 'Toggle drill-down detail' Enter wording must not reappear; got:\n{blob}"
        );
    }

    /// Rules help_rows must advertise the interactive
    /// bindings, not just the scroll binding + [f].
    #[test]
    fn rules_help_advertises_enter_and_delete() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::Rules));
        assert!(
            blob.contains("Enter"),
            "Rules help must advertise [Enter] edit; got:\n{blob}"
        );
        assert!(
            blob.contains("Delete") || blob.contains(" d "),
            "Rules help must advertise [d/Delete] delete; got:\n{blob}"
        );
        let lower = blob.to_lowercase();
        assert!(
            lower.contains("typed-id") || lower.contains("typed id"),
            "Rules delete row must mention typed-id confirm pattern; got:\n{blob}"
        );
    }

    /// Coverage backstop: the `?` overlay is the
    /// authoritative key reference, and it can drift — the Lists/Rules
    /// filter-card keys (`/` search, `f` chip, `R` clear) can be bound in
    /// `handle_lists_key` / `handle_rules_key` but never advertised. Pin
    /// all three on BOTH leaves so a future filter-key change that
    /// forgets the help overlay trips here instead of shipping a `?`
    /// reference that lies by omission. (Paired with the negative
    /// assertions in `lists_help_advertises_current_binding_set`, which
    /// guard the advertised-but-dead direction for removed keys.)
    #[test]
    fn lists_and_rules_help_advertise_live_filter_keys() {
        for leaf in [Leaf::Lists, Leaf::Rules] {
            let blob = flatten_rows(&per_leaf_rows(leaf));
            for needle in ["\n/ ", "\nf ", "\nR "] {
                assert!(
                    blob.contains(needle),
                    "{leaf:?} help must advertise live filter key [{}]; got:\n{blob}",
                    needle.trim()
                );
            }
        }
    }

    /// Subnets help_rows must advertise the interactive
    /// bindings, not just the scroll binding.
    #[test]
    fn subnets_help_advertises_add_edit_delete_promote() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::Subnets));
        let lower = blob.to_lowercase();
        assert!(
            lower.contains("add"),
            "Subnets help must mention add; got:\n{blob}"
        );
        assert!(
            lower.contains("edit"),
            "Subnets help must mention edit; got:\n{blob}"
        );
        assert!(
            lower.contains("delete"),
            "Subnets help must mention delete; got:\n{blob}"
        );
        assert!(
            blob.contains("Enter"),
            "Subnets help must mention [Enter] promote; got:\n{blob}"
        );
        assert!(
            lower.contains("promote"),
            "Subnets help must explain Enter as promote-candidate; got:\n{blob}"
        );
    }

    /// Settings help_rows must advertise the
    /// Tracking-form opener `[t]`, not just the
    /// scroll binding + [e] + [Ctrl+r].
    #[test]
    fn settings_help_advertises_tracking_form_opener() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::Settings));
        let lower = blob.to_lowercase();
        // Single-letter `t` row appears as `\nt ` after flatten join (or
        // at blob start, defensively).
        assert!(
            blob.contains("\nt ") || blob.starts_with("t "),
            "Settings help must advertise [t] binding; got:\n{blob}"
        );
        assert!(
            lower.contains("tracking"),
            "Settings [t] row must mention Tracking form; got:\n{blob}"
        );
    }

    /// The navigation-block leaf count must match `Leaf::ALL.len()`.
    /// A hardcoded count in the navigation block can drift silently the
    /// moment a leaf is added.
    #[test]
    fn navigation_block_leaf_count_matches_leaf_all_len() {
        let blocks = build_blocks(Leaf::Dashboard);
        let mut nav_blob = String::new();
        let mut iter = blocks.iter();
        while let Some(block) = iter.next() {
            if let HelpBlock::Title(t) = block {
                if t.contains("Navigation") {
                    // Spacer + Rows follow.
                    if let Some(HelpBlock::Spacer) = iter.next() {}
                    if let Some(HelpBlock::Rows(rows)) = iter.next() {
                        nav_blob = rows
                            .iter()
                            .map(|r| format!("{} {}", r.key, r.desc))
                            .collect::<Vec<_>>()
                            .join("\n");
                    }
                    break;
                }
            }
        }
        let expected = format!("{} leaves", Leaf::ALL.len());
        assert!(
            nav_blob.contains(&expected),
            "navigation block must say `Cycle ALL {} leaves` matching Leaf::ALL.len() = {}; got:\n{nav_blob}",
            Leaf::ALL.len(),
            Leaf::ALL.len()
        );
    }

    /// A render-level guard, not just a source-grep.
    /// The grep can see the red border and the brand-red titles come back;
    /// it cannot see the rounded border type or the raised surface simply
    /// failing to be added, since neither has a banned token to catch.
    /// Rendering the real popup and reading the buffer closes that gap —
    /// mirrors the `render_chrome_in_*` tests in `modal_form.rs`.
    #[test]
    fn help_overlay_wears_the_modal_ecosystem_not_an_error_square() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(80, 40)).unwrap();
        term.draw(|f| render(f, Leaf::Dashboard)).unwrap();
        let buf = term.backend().buffer().clone();
        let area = buf.area;

        // A rounded top-left corner ('\u{256d}') only exists if
        // `BorderType::Rounded` was actually set — the default `Plain`
        // border draws '\u{250c}' there instead, so this cell's mere
        // presence proves the border type, and its colours prove the
        // chrome rule's other two properties in the same read.
        let (cx, cy) = (0..area.width)
            .flat_map(|x| (0..area.height).map(move |y| (x, y)))
            .find(|&(x, y)| buf[(x, y)].symbol() == "\u{256d}")
            .expect("help popup must draw a rounded top-left corner, not a square one");
        let corner = &buf[(cx, cy)];
        assert_eq!(
            corner.fg, T.text_primary,
            "help popup border must be the neutral accent"
        );
        assert_eq!(
            corner.bg, T.bg_elevated,
            "help popup must sit on the elevated surface, not bare Clear"
        );

        let has_teal_title = (0..area.width)
            .flat_map(|x| (0..area.height).map(move |y| (x, y)))
            .any(|(x, y)| {
                let cell = &buf[(x, y)];
                cell.fg == T.warden_teal && cell.modifier.contains(Modifier::BOLD)
            });
        assert!(
            has_teal_title,
            "section titles (e.g. ` Navigation`) must render in warden_teal"
        );
    }

    /// tui-infra-01, achievable half: at the declared 80×24 floor every
    /// leaf's content overflows (37-49 rows needed against a 22-row
    /// interior — this repo's own measured numbers), so every leaf must
    /// hit the truncation branch, and what IS shown must actually be on
    /// screen rather than merely claimed. A revert to the old
    /// full-height `Layout::vertical` (no `fit_blocks`, no title count)
    /// fails this on the last assertion: the fallback title never
    /// contains "showing N/".
    #[test]
    fn every_leaf_declares_its_truncation_honestly_at_the_80x24_floor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        const FLOOR_INNER: u16 = 22; // 24-row terminal minus the 2-row border

        for leaf in Leaf::ALL {
            let blocks = build_blocks(leaf);
            let fit = fit_blocks(&blocks, FLOOR_INNER);
            assert!(
                fit.hidden > 0,
                "{leaf:?}: this leaf's content now fits the 80x24 floor — \
                 update this test's premise instead of leaving it green by accident"
            );

            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| render(f, leaf)).unwrap();
            let buf = term.backend().buffer().clone();
            let mut screen = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    screen.push_str(buf[(x, y)].symbol());
                }
                screen.push('\n');
            }

            // Every row inside the fitted budget must actually be on
            // screen — a byte count claiming "shown" is not evidence,
            // the pixels are.
            for b in &blocks[..fit.shown] {
                if let HelpBlock::Rows(rows) = b {
                    for r in rows {
                        assert!(
                            screen.contains(r.key),
                            "{leaf:?}: {:?} is inside the fitted budget but not on screen:\n{screen}",
                            r.key
                        );
                    }
                }
            }

            // The row-content loop above is a no-op if `fit.shown` lands
            // on Title+Spacer alone — this closes that gap so a budget
            // too small for any keybindings fails loudly instead of
            // reading as "every shown row is on screen" (vacuously true
            // of zero rows).
            assert!(
                blocks[..fit.shown]
                    .iter()
                    .any(|b| matches!(b, HelpBlock::Rows(_))),
                "{leaf:?}: fitted budget holds no keybinding rows — the \
                 overlay would paint a header and blank space"
            );

            // The per-leaf section leads, so it must always survive the cut.
            let header = per_leaf_header(leaf).trim();
            assert!(
                screen.contains(header),
                "{leaf:?}: per-leaf header must survive the cut; got:\n{screen}"
            );

            // The cut must be declared, with numbers that add up — not a
            // silent clip with nothing on screen to say so.
            let expect_used = format!("showing {}/", fit.used);
            assert!(
                screen.contains(&expect_used),
                "{leaf:?}: overlay must report its own truncation ({expect_used}); got:\n{screen}"
            );
        }
    }
}
