//! Scrollable keyboard reference using the shared modal chrome.
//!
//! Page keys move through the reference while ordinary shortcuts still execute
//! their active-screen action. Headings and the close hint remain visible.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::tui::app::Leaf;
use crate::tui::modal_form;
use crate::tui::theme::T;

const POPUP_W: u16 = 70;
const KEY_COL_W: u16 = 20;
const COL_SPACING: u16 = 1;
/// Width used by the wrapping unit tests for the nominal modal width.
#[cfg(test)]
const DESC_COL_W: u16 = POPUP_W - 2 - KEY_COL_W - COL_SPACING;

#[cfg(test)]
pub fn render(f: &mut Frame, active_leaf: Leaf) {
    let mut offset = 0;
    render_scrolled(f, active_leaf, &mut offset);
}

/// Render the complete help document with a caller-owned vertical offset.
/// Only the body rows scroll; the paired heading and navigation hint remain
/// visible at every position. The offset is clamped in-place so stale state
/// after a leaf change cannot expose a blank help pane.
#[cfg(test)]
pub fn render_scrolled(f: &mut Frame, active_leaf: Leaf, offset: &mut usize) {
    render_in(f, f.area(), active_leaf, offset);
}

#[cfg(test)]
pub fn render_in(f: &mut Frame, area: Rect, active_leaf: Leaf, offset: &mut usize) {
    render_with_app(f, area, active_leaf, offset, None);
}

pub fn render_for_app(f: &mut Frame, area: Rect, app: &crate::tui::App, offset: &mut usize) {
    render_with_app(f, area, app.active_leaf, offset, Some(app));
}

fn render_with_app(
    f: &mut Frame,
    area: Rect,
    active_leaf: Leaf,
    offset: &mut usize,
    app: Option<&crate::tui::App>,
) {
    let requested = *offset;
    let rendered = modal_form::render_modal(f, area, POPUP_W, |width| {
        let mut body = body_for_width(active_leaf, width, app);
        let (_, view, _) = modal_form::scroll_layout(
            area.height.saturating_sub(2) as usize,
            body.head.len(),
            body.fields.len(),
            body.tail.len(),
        );
        let page = requested.min(body.fields.len().saturating_sub(view));
        body.focus_row = view.checked_sub(1).map(|last| page + last);
        (body, ())
    });
    *offset = rendered.view.offset;
}

fn body_for_width(
    active_leaf: Leaf,
    width: u16,
    app: Option<&crate::tui::App>,
) -> modal_form::ScrollBody {
    modal_form::ScrollBody {
        action_hits: Vec::new(),
        field_hits: Vec::new(),
        head: vec![
            modal_form::title_band("HELP", width),
            modal_form::desc_band("Keyboard commands · arrows execute the active leaf", width),
        ],
        fields: help_lines(active_leaf, width, app),
        tail: vec![modal_form::nav_keys_line(
            "PgUp/PgDn scroll · Home/End jump · ?/Esc close",
        )],
        focus_row: None,
        scrollable: true,
    }
}

fn help_lines(active_leaf: Leaf, width: u16, app: Option<&crate::tui::App>) -> Vec<Line<'static>> {
    let desc_width = width.saturating_sub(KEY_COL_W + COL_SPACING) as usize;
    let mut lines = Vec::new();
    for block in build_blocks(active_leaf, app) {
        match block {
            HelpBlock::Title(text) => lines.push(Line::from(Span::styled(
                text,
                Style::default()
                    .fg(T.warden_teal)
                    .add_modifier(Modifier::BOLD),
            ))),
            HelpBlock::Spacer => lines.push(Line::default()),
            HelpBlock::Rows(rows) => {
                for row in rows {
                    let wrapped = word_wrap(row.desc, desc_width.max(1));
                    for (index, desc) in wrapped.into_iter().enumerate() {
                        let key = if index == 0 { row.key } else { "" };
                        let key = crate::tui::text::pad(&format!("  {key}"), KEY_COL_W as usize);
                        lines.push(Line::from(vec![
                            Span::styled(
                                key,
                                Style::default().fg(T.info).add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(" "),
                            Span::raw(desc),
                        ]));
                    }
                }
            }
        }
    }
    lines
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

impl HelpBlock {}

/// Build the ordered list of blocks for the popup: shared sections
/// (Navigation / Mnemonics / Global) followed by the per-leaf section.
fn build_blocks(active_leaf: Leaf, app: Option<&crate::tui::App>) -> Vec<HelpBlock> {
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
                desc: "Cycle 12 visible leaves linearly",
            },
            #[cfg(feature = "cluster")]
            HelpRow {
                key: "Tab / Shift+Tab",
                desc: "Cycle up to 13 visible leaves linearly",
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
                key: "g t",
                desc: "Custom Lists   (Filters)",
            },
            HelpRow {
                key: "g b / g e",
                desc: "Labels / Settings   (Configuration)",
            },
            HelpRow {
                key: "g m",
                desc: "Log Messages   (Configuration)",
            },
            #[cfg(feature = "cluster")]
            HelpRow {
                key: "g n",
                desc: "Nodes   (Configuration)",
            },
        ]),
        HelpBlock::Spacer,
        HelpBlock::Title(" Global"),
        HelpBlock::Spacer,
        HelpBlock::Rows(vec![
            HelpRow {
                key: "T",
                desc: "Cycle theme (Warden, Tokyo Night, Gruvbox, Everforest, Dracula)",
            },
            HelpRow {
                key: "Mouse",
                desc: "Click menus, rows, column headings and dialog controls",
            },
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
                desc: "Focus sortable column headings",
            },
            HelpRow {
                key: "Shift+S",
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

    // Start with the active screen's shortcuts; common navigation follows.
    let rows = app
        .map(contextual_rows)
        .unwrap_or_else(|| per_leaf_rows(active_leaf));
    #[cfg(feature = "cluster")]
    if let Some(app) = app {
        if !crate::tui::nodes::policy_access(app).editable {
            for block in &mut blocks {
                if let HelpBlock::Rows(rows) = block {
                    for row in rows {
                        if row.key == "r" {
                            row.desc = "Refresh views (daemon reload suppressed on replica)";
                        }
                    }
                }
            }
        }
    }
    let mut leading = vec![
        HelpBlock::Title(per_leaf_header(active_leaf)),
        HelpBlock::Spacer,
        HelpBlock::Rows(rows),
        HelpBlock::Spacer,
    ];
    leading.append(&mut blocks);
    leading
}

fn contextual_rows(app: &crate::tui::App) -> Vec<HelpRow> {
    let rows = per_leaf_rows(app.active_leaf);
    #[cfg(feature = "cluster")]
    let mut rows = rows;
    #[cfg(feature = "cluster")]
    {
        if !crate::tui::nodes::policy_access(app).editable {
            rows.retain(|row| !help_row_mutates_policy(app.active_leaf, row.key));
        }
        if app.active_leaf == Leaf::Nodes {
            rows.retain(|row| match row.key {
                "a" => crate::tui::nodes::can_add_node(app),
                "Enter / e" => crate::tui::nodes::controls_available(app),
                "d" => crate::tui::nodes::can_remove_node(app),
                "u" => crate::tui::nodes::control_status_for_display(app)
                    .is_some_and(|status| !status.operations.is_empty()),
                _ => true,
            });
        }
    }
    rows
}

#[cfg(feature = "cluster")]
fn help_row_mutates_policy(leaf: Leaf, keys: &str) -> bool {
    if leaf == Leaf::Settings && keys == "Ctrl+r" {
        return true;
    }
    keys.split('/')
        .map(str::trim)
        .filter_map(|key| match key {
            "Enter" => Some(crossterm::event::KeyCode::Enter),
            "Delete" => Some(crossterm::event::KeyCode::Delete),
            "a" => Some(crossterm::event::KeyCode::Char('a')),
            "e" => Some(crossterm::event::KeyCode::Char('e')),
            "d" => Some(crossterm::event::KeyCode::Char('d')),
            "m" => Some(crossterm::event::KeyCode::Char('m')),
            "p" => Some(crossterm::event::KeyCode::Char('p')),
            "B" => Some(crossterm::event::KeyCode::Char('B')),
            "K" => Some(crossterm::event::KeyCode::Char('K')),
            "R" => Some(crossterm::event::KeyCode::Char('R')),
            _ => None,
        })
        .any(|key| crate::tui::nodes::mutation_key(leaf, key))
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
        Leaf::Nodes => " Nodes Keybindings",
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
        Leaf::Dashboard => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll dashboard",
            },
            HelpRow {
                key: "PgUp/PgDn",
                desc: "Scroll a page",
            },
            HelpRow {
                key: "Home/End",
                desc: "Jump to first / last row",
            },
        ],
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
                desc: "Open the Domain filter window (case-insensitive substring)",
            },
            HelpRow {
                key: "c",
                desc: "Pick one or more exact clients (OR); search by name or IP",
            },
            HelpRow {
                key: "f",
                desc: "Focus filter chips; arrows move, Enter opens, Esc leaves",
            },
            HelpRow {
                key: "b",
                desc: "Toggle blocked-only",
            },
            HelpRow {
                key: "t",
                desc: "Choose period (available history / 1h / 3h / 6h / 24h)",
            },
            HelpRow {
                key: "R",
                desc: "Reset all filters",
            },
            HelpRow {
                key: "Alt+D/C/B/T/F",
                desc: "Clear domain / client / result / period / more filters only",
            },
            HelpRow {
                key: "i",
                desc: "Read full focused query detail (Enter remains rule action)",
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
                key: "i / Esc",
                desc: "Open full details / return to the device table",
            },
            HelpRow {
                key: "f",
                desc: "Focus the Subnet filter chip; Enter opens",
            },
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
                desc: "Move through the subnet list; scroll the Clients view",
            },
            HelpRow {
                key: "i",
                desc: "Open full subnet details and clients",
            },
            HelpRow {
                key: "c",
                desc: "Open the sortable Clients view",
            },
            HelpRow {
                key: "s",
                desc: "Focus client sort headers in the Clients view",
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
                desc: "Edit a configured subnet or promote the focused auto-discovered candidate",
            },
        ],
        Leaf::LocalDns => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Move through every record and scope",
            },
            HelpRow {
                key: "a",
                desc: "Add a local DNS record",
            },
            HelpRow {
                key: "Enter / e",
                desc: "Edit the focused row",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove the focused row (tiered confirm)",
            },
            HelpRow {
                key: "i / Esc",
                desc: "Open / close record details and audit history",
            },
        ],
        Leaf::Profiles => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Scroll list",
            },
            HelpRow {
                key: "a",
                desc: "Add a complete profile draft",
            },
            HelpRow {
                key: "Enter / e",
                desc: "Edit the focused profile",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Delete the focused profile (refuses if still referenced)",
            },
            HelpRow {
                key: "Right",
                desc: "Open the profile detail panel",
            },
            HelpRow {
                key: "Esc",
                desc: "Return from the detail panel to the profile list",
            },
            HelpRow {
                key: "i",
                desc: "Inspect the focused profile",
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
                key: "v",
                desc: "Switch between the list and rule panes",
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
                key: "Enter / e",
                desc: "Edit the selected list or rule",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove: the list (refused while mounted), or the rule",
            },
            HelpRow {
                key: "m",
                desc: "Mount / unmount the list on profiles",
            },
            HelpRow {
                key: "i",
                desc: "Inspect the selected list or rule",
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
                desc: "Add from the purge.cc catalog or a URL",
            },
            HelpRow {
                key: "e",
                desc: "Edit the focused subscription",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove the focused subscription",
            },
            HelpRow {
                key: "i",
                desc: "Inspect the focused subscription",
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
                desc: "Focus filter chips; arrows move, Enter changes",
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
                key: "f",
                desc: "Focus the category column",
            },
            HelpRow {
                key: "Up/Down",
                desc: "Select a category or label; scroll details",
            },
            // There is no `h`/`l` alias for Left/Right — it is deleted
            // outright, not just unadvertised, so there is no alias row
            // left to list.
            HelpRow {
                key: "Left/Right",
                desc: "Move between categories, labels and details",
            },
            HelpRow {
                key: "a",
                desc: "Declare a value in the selected kind",
            },
            HelpRow {
                key: "Enter / e",
                desc: "Enter the label list, or edit its selected entry",
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
                key: "Enter / e",
                desc: "Edit the selected group",
            },
            HelpRow {
                key: "d / Delete",
                desc: "Remove the selected group",
            },
            HelpRow {
                key: "i / Esc",
                desc: "Open / close full group details",
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
                desc: "Select one message",
            },
            HelpRow {
                key: "PgUp/PgDn",
                desc: "Move one page",
            },
            HelpRow {
                key: "Home/End",
                desc: "Jump to newest / oldest fetched",
            },
            HelpRow {
                key: "f",
                desc: "Focus filters; Tab/arrows move, Enter opens, Delete clears",
            },
            HelpRow {
                key: "Enter",
                desc: "Open complete message",
            },
            HelpRow {
                key: "i",
                desc: "Open complete message",
            },
        ],
        Leaf::Settings => vec![
            HelpRow {
                key: "Up/Down · Enter",
                desc: "Select a setting and open its action",
            },
            HelpRow {
                key: "i",
                desc: "Inspect the selected setting",
            },
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
        Leaf::Nodes => vec![
            HelpRow {
                key: "Up/Down",
                desc: "Select a node by stable identity",
            },
            HelpRow {
                key: "/ / R",
                desc: "Search roster / clear search",
            },
            HelpRow {
                key: "o / O",
                desc: "Cycle sort column / reverse order",
            },
            HelpRow {
                key: "u",
                desc: "Resume or cancel a recoverable Nodes operation",
            },
            HelpRow {
                key: "a",
                desc: "Add a node with destination name, IP, and association token",
            },
            HelpRow {
                key: "Enter / e",
                desc: "Edit selected node name, IP, or Nodes HTTPS port",
            },
            HelpRow {
                key: "d",
                desc: "Remove selected remote node; this node cannot be removed",
            },
        ],
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

    fn buffer_contains(buf: &ratatui::buffer::Buffer, needle: &str) -> bool {
        (0..buf.area.height).any(|y| {
            let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            line.contains(needle)
        })
    }

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
            rows.iter()
                .any(|row| row.key == "/" && row.desc.contains("Domain filter window")),
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
            let blocks = build_blocks(leaf, None);
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
        let blocks = build_blocks(Leaf::Dashboard, None);
        let has_resolver = blocks.iter().any(|b| match b {
            HelpBlock::Rows(rows) => rows
                .iter()
                .any(|r| r.key == "Shift+S" && r.desc.contains("Resolver modal")),
            _ => false,
        });
        assert!(
            has_resolver,
            "Help overlay must list `Shift+S` → Resolver modal in Global section"
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
        let blocks = build_blocks(Leaf::Dashboard, None);
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
            if !leaf.is_menu_leaf() {
                continue;
            }
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
            for blk in build_blocks(leaf, None) {
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
            screen.contains("g t") && !screen.contains("g u"),
            "the Filters mnemonic row must paint whole; got:\n{screen}"
        );
        assert!(
            screen.contains("Custom Lists") && !screen.contains("Custom Lists / Rules"),
            "its description must paint too; got:\n{screen}"
        );
    }

    /// Lists help_rows must advertise the full current
    /// binding set. This once drifted: the Lists rows still described a
    /// stale "Toggle drill-down detail" Enter behaviour and missed
    /// the mutation hotkeys. The source chooser owns catalog-vs-URL after
    /// `a`, so the retired direct-catalog `B` binding must stay absent.
    #[test]
    fn lists_help_advertises_current_binding_set() {
        let blob = flatten_rows(&per_leaf_rows(Leaf::Lists));
        // Each binding row in flatten_rows is `{key} {desc}`, joined by
        // `\n`. So a single-letter key like `a` appears as `\na ` or at
        // blob start; multi-char keys like `Enter` survive a contains-
        // check directly. The live filter-card keys
        // (`/`, `f`, `R`) must be present.
        for needle in ["Enter", "\na ", "\nK ", "\n/ ", "\nf ", "\nR "] {
            assert!(
                blob.contains(needle),
                "Lists help must advertise [{}] binding; got blob:\n{blob}",
                needle.trim()
            );
        }
        // The unmounted category/assignment keys must NOT be
        // advertised any more (they dead-ended in refusal stubs).
        for gone in ["\nB ", "\nc ", "\nm ", "\np ", "Space / x"] {
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
        let blocks = build_blocks(Leaf::Dashboard, None);
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
        let expected = format!(
            "{} visible leaves",
            Leaf::ALL.iter().filter(|leaf| leaf.is_menu_leaf()).count()
        );
        assert!(
            nav_blob.contains(&expected),
            "navigation block must say `Cycle ALL {} leaves` matching Leaf::ALL.len() = {}; got:\n{nav_blob}",
            Leaf::ALL.len(),
            Leaf::ALL.len()
        );
    }

    /// A render-level guard for the shared square modal chrome.
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

        // The shared modal renderer owns the plain square border.
        let (cx, cy) = (0..area.width)
            .flat_map(|x| (0..area.height).map(move |y| (x, y)))
            .find(|&(x, y)| buf[(x, y)].symbol() == "┌")
            .expect("help popup must draw a square modal border");
        let corner = &buf[(cx, cy)];
        assert_eq!(
            corner.fg, T.text_primary,
            "help popup border must be the neutral accent"
        );
        assert_eq!(
            corner.bg, T.bg_elevated,
            "help popup must sit on the elevated surface"
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

    /// At the 80×24 floor the complete help document remains reachable by
    /// scrolling to its final page.
    #[test]
    fn every_leaf_scrolls_to_the_end_at_the_80x24_floor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        for leaf in Leaf::ALL {
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            let mut offset = usize::MAX;
            term.draw(|f| render_scrolled(f, leaf, &mut offset))
                .unwrap();
            let buf = term.backend().buffer().clone();
            assert!(buffer_contains(&buf, "HELP"));
            assert!(
                buffer_contains(&buf, "Quit"),
                "{leaf:?}: end page lost global commands"
            );
            assert!(offset < usize::MAX, "{leaf:?}: offset was not clamped");
        }
    }
}
