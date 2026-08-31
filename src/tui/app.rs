//! Application state for the TUI.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::widgets::{ListState, TableState};

use crate::config::loader::LoadedConfig;
use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat};
#[cfg(feature = "cluster")]
use crate::ipc::protocol::ClusterStatusDto;
use crate::ipc::protocol::{
    AdvancedClientFilterDto, DeviceViewDto, QueryLogDto, QueryLogFileState, TimeBucketDto,
};
use crate::lists::status::BlocklistStatusDto;
use crate::tracking::query_log::QueryLogCursor;
use crate::tui::query_log_filter_modal::QueryLogFilterModal;

// ── Sections + Leaves ───────────────────────────────────────────────────────
//
// Sprint 45 T1: the flat 9-tab menu was renamed `Tab` → `Leaf` and grouped
// under a 4-entry `Section` enum (Overview / Network / Filtering / Settings).
//
// Sprint 46 T1: post-S45 UX review promoted Dashboard and Query Log out of
// the artificial "Overview" hub to top-level. The `Section` enum is now
// 5-entry — Dashboard / QueryLog / Network / Filtering / Settings — with
// three singleton sections (Dashboard / QueryLog / Settings) that render no
// sub-tab strip. The mnemonic table + linear `Tab`/`Shift+Tab` cycle stay
// identical to S45; only the top-level shape changes. See
// `_docs/features/tui_menu_ux_refinement.md` §2.1 for the authoritative spec.
//
// §4.67-a (2026-08-05): `Filtering` → `Filters`, `Settings` → `Configuration`,
// and `Leaf::Tags` re-homed from the first to the second. The IA rule in force
// since 2026-07-24 split the world into two questions — "who is on the wire"
// (Network) and "what policy applies" (Filtering). A vocabulary registry
// answers neither, so Tags sat in Filtering for want of a better box. The
// third question — "what elements exist to be reused" — is `Configuration`,
// which also maps 1:1 onto `warden config …`.
//
// The same pass replaced five hand-maintained sources of truth with the
// `LAYOUT` table below.

/// Expands the shared body of [`LAYOUT`], plus any `cfg`-gated tail rows.
///
/// `#[cfg]` cannot sit on an element of an array literal — an attribute in
/// expression position needs `stmt_expr_attributes`, which is unstable. That
/// is why the pre-§4.67-a code carried two entire `Leaf::ALL` arrays. Gating
/// the whole `const` is the stable shape; this macro keeps the five core rows
/// written exactly once regardless of how many `const`s that costs.
macro_rules! layout_table {
    ($($tail:expr),* $(,)?) => {
        &[
            (Section::Dashboard, &[Leaf::Dashboard] as &[Leaf]),
            (Section::QueryLog, &[Leaf::QueryLog]),
            // §4.64 G1: Groups sits second, right after Devices — the order the
            // operator asked for. `default_leaf(Network)` stays Devices.
            (
                Section::Network,
                &[Leaf::Devices, Leaf::Groups, Leaf::Subnets, Leaf::LocalDns],
            ),
            // §4.67-a MN6: order is Profiles, Lists, Rules — the 2026-07-24
            // decision that a profile is the policy hub an operator tuning
            // filtering reaches for, while lists are background-synced content
            // with the lowest daily interaction rate. Putting lists first
            // would put the download ledger in front of the policy.
            // Custom Lists sits between Lists and Rules: the two natures of
            // "a list" stay adjacent, and inserting there does not move where
            // `4` lands, because a section always lands on its leftmost leaf.
            (
                Section::Filters,
                &[
                    Leaf::Profiles,
                    Leaf::Lists,
                    Leaf::CustomLists,
                    Leaf::Rules,
                ],
            ),
            // §4.67-a MN5: Tags is vocabulary, not policy. Settings keeps its
            // own leaf here — it carries the Tracking form and backup/restore
            // (`b` / `R`), so the section rename does not retire it.
            // §4.67-b MN3: File is APPENDED, not prepended. `default_leaf`
            // does not read this row, but the `[`/`]` cycle does, and putting
            // the viewer before Settings would move where that cycle lands
            // for no operator-visible gain.
            // `logs-tab`: Logs is APPENDED for the same reason File was —
            // the operator's rule is that a section lands on its LEFTMOST
            // leaf, so anything but the tail would move where `5` lands.
            // Configuration keeps landing on Labels.
            (
                Section::Configuration,
                &[Leaf::Labels, Leaf::Settings, Leaf::File, Leaf::Logs],
            ),
            $($tail),*
        ]
    };
}

/// **Single source of truth for the TUI navigation hierarchy** (§4.67-a).
///
/// Row order is the section bar's left-to-right order; within a row, leaf
/// order is the sub-tab strip's left-to-right order. Everything ordered about
/// navigation is derived from this table: [`Section::ALL`],
/// [`Section::index`], [`Section::leaves`], [`Leaf::ALL`], [`Leaf::index`] and
/// [`Leaf::section`].
///
/// Before this table the same information was hand-written in five places that
/// had to agree. `each_section_is_a_contiguous_in_order_slice_of_all` exists
/// precisely because they could drift, and `tabs/profiles.rs` asserted a
/// hardcoded `Leaf::ALL[5]` the compiler could not protect. Both are gone:
/// contiguity is now true by construction, and a leaf index is no longer
/// writable by hand anywhere.
///
/// Adding a leaf is one row edit here plus `label()` / `mnemonic()` /
/// `from_mnemonic()`. `layout_covers_every_variant` fails the build if a new
/// enum variant is not also given a home in this table.
#[cfg(not(feature = "cluster"))]
const LAYOUT: &[(Section, &[Leaf])] = layout_table!();

/// §4.11-4b — `cluster`-build variant: the Cluster section is appended LAST so
/// section indices 0-4, numeric hotkeys 1-5, and the linear `Tab` cycle order
/// of the first ten leaves are byte-identical to the default build. The
/// section bar runtime-filters it out when `!cluster_visible()`.
#[cfg(feature = "cluster")]
const LAYOUT: &[(Section, &[Leaf])] = layout_table!((Section::Cluster, &[Leaf::Cluster]));

/// Total navigable leaves across every [`LAYOUT`] row — the length of
/// [`Leaf::ALL`]. Derived, never written by hand.
const LEAF_COUNT: usize = {
    let mut total = 0;
    let mut i = 0;
    while i < LAYOUT.len() {
        total += LAYOUT[i].1.len();
        i += 1;
    }
    total
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Dashboard,
    QueryLog,
    Network,
    /// §4.67-a: renamed from `Filtering`. Label only — nothing persists a
    /// section name, so the rename costs no migration.
    Filters,
    /// §4.67-a: renamed from `Settings`, and no longer a singleton. It hosted
    /// `Leaf::Tags` alongside `Leaf::Settings` when that was written;
    /// `plp-s5d` deleted the Tags leaf, and the section now holds Labels,
    /// Settings, File and Logs.
    Configuration,
    /// §4.11-4b (CS9) — top-level cluster monitoring section (decision 4).
    /// Compile-gated behind `cluster` AND runtime-hidden from the nav unless
    /// `[cluster].enabled` (`App::cluster_visible`). Appended last so the
    /// existing section indices + numeric hotkeys are unchanged.
    #[cfg(feature = "cluster")]
    Cluster,
}

impl Section {
    /// Render order of the section bar — derived from [`LAYOUT`].
    pub const ALL: [Section; LAYOUT.len()] = {
        let mut out = [Section::Dashboard; LAYOUT.len()];
        let mut i = 0;
        while i < LAYOUT.len() {
            out[i] = LAYOUT[i].0;
            i += 1;
        }
        out
    };

    /// Position in [`Section::ALL`], i.e. the numeric hotkey minus one.
    ///
    /// Falls back to 0 rather than panicking if `self` has no [`LAYOUT`] row —
    /// structurally impossible (`layout_covers_every_variant` pins it) and a
    /// panic here would be on the render path.
    pub fn index(self) -> usize {
        Section::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn label(self) -> &'static str {
        match self {
            Section::Dashboard => "1 Dashboard",
            Section::QueryLog => "2 Query Log",
            Section::Network => "3 Network",
            Section::Filters => "4 Filters",
            Section::Configuration => "5 Configuration",
            #[cfg(feature = "cluster")]
            Section::Cluster => "6 Cluster",
        }
    }

    /// First leaf rendered when the section is selected via numeric hotkey
    /// or `g` mnemonic. Stable across launches — operator hops follow this.
    ///
    /// Deliberately NOT derived from [`LAYOUT`]. The landing leaf is a UX
    /// choice, not a structural fact: `Configuration` leads with **Labels**
    /// in the strip (it led with Tags until §4.66 L2 prepended the registry)
    /// but lands on Settings, because `5` has meant "Settings" for the whole
    /// life of the product and a section rename does not move the operator's
    /// muscle memory.
    ///
    /// That drift is the argument, not an aside: this row has been prepended
    /// **twice** since §4.67-a. A derived landing leaf would have changed
    /// where `5` goes on both occasions, silently.
    pub fn default_leaf(self) -> Leaf {
        // Operator rule (2026-08-24): entering a section ALWAYS lands on its
        // leftmost leaf, so the landing is predictable instead of decided
        // per-section. Derived from [`LAYOUT`] rather than restated, because a
        // hand-written match is a second source of truth for something the
        // table already orders — and it had already drifted: every section
        // landed leftmost except `Configuration`, which landed on the THIRD
        // leaf.
        //
        // **What this retires, kept because the reasoning is the precedent.**
        // The divergence was deliberate, not an oversight: §4.67-a argued that
        // `5` had meant "Settings" for the life of the product and that moving
        // a section boundary must not move the operator's muscle memory. That
        // was a *proxy* for the operator's preference. The operator has since
        // stated the preference directly, and chose the leftmost landing
        // knowing it moves `5` off Settings — a stated preference outranks an
        // inferred one. The ORDER rationale is untouched and still lives with
        // the order, in `layout_table!`.
        //
        // `leaves()` is empty only for a `Section` with no `LAYOUT` row, which
        // `layout_covers_every_variant` already makes a build error. The
        // fallback keeps this infallible without inventing a third answer.
        self.leaves().first().copied().unwrap_or(Leaf::Dashboard)
    }

    /// Leaves of this section in sub-tab strip order — derived from [`LAYOUT`].
    ///
    /// Returns an empty slice for a section with no `LAYOUT` row rather than
    /// panicking; see [`Section::index`] for why. `next_in_section` /
    /// `prev_in_section` guard against the empty case.
    pub fn leaves(self) -> &'static [Leaf] {
        LAYOUT
            .iter()
            .find(|(section, _)| *section == self)
            .map(|(_, leaves)| *leaves)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    Dashboard,
    QueryLog,
    Devices,
    Subnets,
    /// §4.64 G1: read-only view of `[[groups]]`. A group is POLICY, not
    /// vocabulary — `profile` is required and `priority` resolves which
    /// single profile a multi-group device gets (DM2), while `tags` are
    /// UNIONED across every group. G2 makes this leaf writable.
    Groups,
    /// Sprint 44: Local DNS Scoping v2 — global + per-profile static
    /// records. Master/detail tab with in-tab Add / Edit / Delete
    /// modals (tiered confirm) and an audit-history side-card.
    LocalDns,
    /// §4.26 Phase 2: Profile Editor v1 — the 4th Network leaf (D3).
    /// Offline-backed master/detail tab over `[profiles]`; Add / Edit /
    /// Delete drive the Phase 1 IPC verbs (`ProfileCreate` /
    /// `ProfileUpdate` / `ProfileDelete`) directly.
    Profiles,
    /// Sprint 43 T2: per-blocklist visibility — counts, last update,
    /// fetch outcome, used-by-profiles. Consumes
    /// `IpcCommand::BlocklistStats { source_id: None }`.
    Lists,
    /// The `[[custom_lists]]` entities and the pack files behind them —
    /// operator-authored rule files carrying allow and deny together.
    ///
    /// A leaf of its own rather than a row on [`Leaf::Lists`]: four of that
    /// tab's nine columns answer "how did the download go?", a question a
    /// local file never has.
    CustomLists,
    /// Sprint 43 T2: read-only placeholder for admin rules. T5 wires
    /// the data source (`[[admin_rules]]`) and `e`/`d` keybindings.
    Rules,
    Settings,
    /// §4.66 L2: the `[[labels]]` vocabulary — owner / device-type /
    /// department. Declaring is optional: without a vocabulary those device
    /// fields stay free text, which is what every config does today.
    Labels,
    /// §4.67-b MN3: the master config file as a *document* — read-only
    /// syntax-coloured TOML, `/` section jump, `e` to open it in `$EDITOR`.
    /// Split out of `Leaf::Settings`, which had been rendering either the
    /// Tracking form or this viewer from one 854-line module. The two are
    /// different jobs: Settings administers the configuration (tracking
    /// knobs, backup, restore), File shows the bytes on disk.
    File,
    /// `logs-tab`: the daemon's own recent `tracing` events, read over
    /// `IpcCommand::DaemonLogs` from an in-process ring buffer. Answers
    /// "what has the daemon been saying" — distinct from `Leaf::QueryLog`,
    /// which answers "what did clients ask for". Labelled **Log Messages**
    /// so the two are not read as the same thing at a glance.
    Logs,
    /// §4.11-4b (CS9) — cluster monitoring leaf, sole leaf of the top-level
    /// `Section::Cluster`. Compile-gated behind `cluster` + runtime-hidden
    /// from `Tab`/`g`/numeric nav unless `[cluster].enabled`. Appended last
    /// so leaf indices 0-9 and the mnemonic table are unchanged.
    #[cfg(feature = "cluster")]
    Cluster,
}

impl Leaf {
    // 2026-04-29: TopDomains tab retired — the same data now renders
    // inline on the Dashboard's bottom row as two of the three ranked
    // cards. Numeric hotkeys 5..8 shifted down by one accordingly.
    // 2026-05-01 (S44 T3): LocalDns inserted at hotkey 5 between
    // Subnets (4) and Resolver (now 6); Settings shifts from 8 to 9.
    // 2026-05-01 (S45 T1): renamed `Tab` → `Leaf`, grouped under
    // `Section`. Linear order preserved so `Tab`/`Shift+Tab` cycling
    // walks all 10 leaves identically to pre-S45.
    // 2026-05-14 (§4.26 P2): Leaf::Profiles inserted at index 5 between
    // LocalDns (4) and Lists (now 6); Rules/Tags/Settings shift down one.
    // 2026-08-05 (§4.67-a): the array is gone — `ALL` is now FLATTENED from
    // `LAYOUT` at compile time, so the linear `Tab` order and the per-section
    // `]` order cannot disagree. They had to agree before too (`Tab` walks
    // this array while `]` walks `leaves()`, and a divergence means the same
    // section cycles differently depending on which key you press); the
    // difference is that agreement used to be a test and is now a
    // construction. Leaf indices are not operator-visible — S46 dropped the
    // numeric prefixes from `label()`.
    /// Linear `Tab` / `Shift+Tab` cycle order: every [`LAYOUT`] row's leaves,
    /// concatenated left to right. Under `cluster` the gated Cluster leaf is
    /// last, so indices 0-9 are identical to the default build; the cycle
    /// skips it at runtime when `!cluster_visible()` (see
    /// `next_visible`/`prev_visible` in mod.rs).
    pub const ALL: [Leaf; LEAF_COUNT] = {
        let mut out = [Leaf::Dashboard; LEAF_COUNT];
        let mut k = 0;
        let mut row = 0;
        while row < LAYOUT.len() {
            let leaves = LAYOUT[row].1;
            let mut i = 0;
            while i < leaves.len() {
                out[k] = leaves[i];
                k += 1;
                i += 1;
            }
            row += 1;
        }
        out
    };

    /// Position in [`Leaf::ALL`]. O(n) with n ≤ 11, called on a key press —
    /// not worth optimising. Falls back to 0 rather than panicking if `self`
    /// has no [`LAYOUT`] row; see [`Section::index`].
    pub fn index(self) -> usize {
        Leaf::ALL.iter().position(|l| *l == self).unwrap_or(0)
    }

    pub fn label(self) -> &'static str {
        // Post-S46: leaves no longer carry a numeric prefix. Pre-S45 the
        // 1-9 numerics doubled as direct hotkeys; S45 grouped the leaves
        // under sections and S46 promoted Dashboard/Query Log to the top
        // level — leaves are now reached via section hotkeys (1-5) +
        // `[`/`]` cycle or `g <letter>` mnemonics, never by the leaf's
        // own number. The leftover digits in the sub-tab strip read as a
        // false promise of a hotkey that no longer exists, so they're
        // dropped.
        match self {
            Leaf::Dashboard => "Dashboard",
            Leaf::QueryLog => "Query Log",
            // S42 T5 — variant now matches the tab label and data model
            // naming. S33 had renamed only the label; the variant stayed
            // `Clients` to avoid churning the Sprint 22 modal-form
            // fields. T5 finishes the rename end-to-end.
            Leaf::Devices => "Devices",
            Leaf::Subnets => "Subnets",
            Leaf::Groups => "Groups",
            Leaf::LocalDns => "Local DNS",
            Leaf::Profiles => "Profiles",
            Leaf::Lists => "Lists",
            Leaf::CustomLists => "Custom Lists",
            Leaf::Rules => "Rules",
            Leaf::Settings => "Settings",
            Leaf::File => "File",
            // Not "Logs": every letter of that word is already a mnemonic
            // (`l` LocalDns, `o` Groups, `s` Subnets) or the `g` prefix
            // itself, so a leaf labelled "Logs" could not carry an
            // underlined letter — `every_mnemonic_occurs_in_its_leaf_label`
            // would fail. "Log Messages" keeps the operator's own word
            // ("tutti i messaggi"), takes the free `m` at a word initial,
            // and reads distinctly next to "Query Log".
            Leaf::Logs => "Log Messages",
            Leaf::Labels => "Labels",
            #[cfg(feature = "cluster")]
            Leaf::Cluster => "Cluster",
        }
    }

    /// Sprint 45 T1: home section for grouped navigation. Drives the
    /// breadcrumb in the footer and the sub-tab strip highlight.
    /// Sprint 46 T1: Dashboard and QueryLog now map to their own
    /// singleton sections — the `Overview` hub was retired so the two
    /// most-used leaves sit at top level.
    /// §4.67-a: derived from [`LAYOUT`] instead of a parallel match, so a
    /// re-home is one row edit and cannot half-land.
    ///
    /// Falls back to the first section rather than panicking if `self` has no
    /// `LAYOUT` row — this is on the footer's render path, and a wrong
    /// breadcrumb degrades where a panic does not.
    /// `layout_covers_every_variant` pins the fallback as unreachable.
    pub fn section(self) -> Section {
        LAYOUT
            .iter()
            .find(|(_, leaves)| leaves.contains(&self))
            .map(|(section, _)| *section)
            .unwrap_or(Section::ALL[0])
    }

    pub fn next(self) -> Leaf {
        Leaf::ALL[(self.index() + 1) % Leaf::ALL.len()]
    }

    /// Sprint 45 T3: `g <letter>` direct-jump mnemonic table. Returns
    /// `Some(leaf)` for a known mnemonic, `None` otherwise — the caller
    /// (`handle_key`) then drains `pending_goto` and falls through to
    /// the normal handler so the second key still gets a chance to
    /// fire its tab-local binding. Letters that collide with a leaf's
    /// own initial (Devices, Lists, Rules, Settings) reuse the second
    /// strong consonant, e.g. `v` for deVices, `i` for lIsts. The full
    /// table is pinned in the design doc §4.
    pub fn from_mnemonic(ch: char) -> Option<Leaf> {
        match ch {
            'd' => Some(Leaf::Dashboard),
            'q' => Some(Leaf::QueryLog),
            'v' => Some(Leaf::Devices),
            's' => Some(Leaf::Subnets),
            // §4.64 G1: `g` is the PREFIX of the `g <letter>` sequence and can
            // never be a leaf's own mnemonic, so Groups takes `o` (grOups).
            'o' => Some(Leaf::Groups),
            'l' => Some(Leaf::LocalDns),
            // §4.26 Phase 2: `p` is free in the mnemonic table (the
            // global `[p] pause` lives in a separate keyspace — mnemonics
            // only fire after the `g` prefix), so it's the natural letter
            // for Profiles.
            'p' => Some(Leaf::Profiles),
            'i' => Some(Leaf::Lists),
            'u' => Some(Leaf::Rules),
            // `c` belongs to the cluster leaf under that feature, and `l` is
            // LocalDns — so Custom Lists takes the `t` of "Cus**t**om", which
            // keeps the underline inside its own label.
            't' => Some(Leaf::CustomLists),
            'e' => Some(Leaf::Settings),
            // §4.67-b MN3: `f` verified free against the whole table and is
            // the initial of "File" — no second-consonant workaround needed.
            'f' => Some(Leaf::File),
            // `logs-tab`: `m` verified free against the whole table and is
            // the initial of the second word of "Log Messages".
            'm' => Some(Leaf::Logs),
            // §4.66 L2: `l` is LocalDns and `g` is the sequence prefix, so
            // Labels takes `b` (laBels) — the second-strong-consonant rule
            // this table has used since S45.
            'b' => Some(Leaf::Labels),
            // §4.11-4b — `c` is free in the mnemonic table (Devices owns `v`,
            // Cache has no leaf). The `g c` jump is itself gated at the
            // dispatch site so it no-ops when the Cluster section is hidden.
            #[cfg(feature = "cluster")]
            'c' => Some(Leaf::Cluster),
            _ => None,
        }
    }

    /// 2026-07-24 (IA Option B): inverse of [`Leaf::from_mnemonic`]. The
    /// sub-tab strip underlines this character inside the leaf's own label
    /// so the `g <letter>` jump is discoverable from the chrome instead of
    /// only from the `?` help screen — the mnemonics were previously
    /// unguessable for the four leaves whose letter is not the initial
    /// (deVices, lIsts, rUles, sEttings).
    ///
    /// INVARIANT: the returned character must occur in `self.label()`
    /// (case-insensitively), otherwise the underline silently no-ops.
    /// Pinned by `every_mnemonic_occurs_in_its_leaf_label`.
    pub fn mnemonic(self) -> char {
        match self {
            Leaf::Dashboard => 'd',
            Leaf::QueryLog => 'q',
            Leaf::Devices => 'v',
            Leaf::Subnets => 's',
            Leaf::Groups => 'o',
            Leaf::LocalDns => 'l',
            Leaf::Profiles => 'p',
            Leaf::Lists => 'i',
            Leaf::CustomLists => 't',
            Leaf::Rules => 'u',
            Leaf::Settings => 'e',
            Leaf::File => 'f',
            Leaf::Logs => 'm',
            Leaf::Labels => 'b',
            #[cfg(feature = "cluster")]
            Leaf::Cluster => 'c',
        }
    }

    /// Byte offset of [`Leaf::mnemonic`] within [`Leaf::label`], matched
    /// case-insensitively at the first occurrence. `None` only if the
    /// invariant above is broken — callers render the label unstyled
    /// rather than panicking, since a missing underline is a cosmetic
    /// regression and a panic on the render path is not.
    pub fn mnemonic_offset(self) -> Option<usize> {
        let (label, want) = (self.label(), self.mnemonic());
        label
            .char_indices()
            .find(|(_, c)| c.eq_ignore_ascii_case(&want))
            .map(|(i, _)| i)
    }

    pub fn prev(self) -> Leaf {
        Leaf::ALL[(self.index() + Leaf::ALL.len() - 1) % Leaf::ALL.len()]
    }

    /// Sprint 45 T2: cycle to the next leaf within the same section,
    /// wrapping at the section boundary. Bound to `]`. On a single-leaf
    /// section (Dashboard / Query Log) this is a no-op — the modulo
    /// collapses to 0.
    ///
    /// The `is_empty` guard covers a leaf with no [`LAYOUT`] row: `leaves()`
    /// returns `&[]` there and `% 0` would panic on a key press.
    pub fn next_in_section(self) -> Leaf {
        let leaves = self.section().leaves();
        if leaves.is_empty() {
            return self;
        }
        let cur = leaves.iter().position(|l| *l == self).unwrap_or(0);
        leaves[(cur + 1) % leaves.len()]
    }

    /// Sprint 45 T2: cycle to the previous leaf within the same section.
    /// Bound to `[`. No-op on the singleton sections (Dashboard / Query Log).
    pub fn prev_in_section(self) -> Leaf {
        let leaves = self.section().leaves();
        if leaves.is_empty() {
            return self;
        }
        let cur = leaves.iter().position(|l| *l == self).unwrap_or(0);
        leaves[(cur + leaves.len() - 1) % leaves.len()]
    }
}

// ── Input mode (for filter text entry) ──────────────────────────────────────

#[derive(Debug, Clone)]
pub enum InputMode {
    Normal,
    FilterDomain(String),
    FilterClient(String),
    /// Lists tab Query-Log-style search buffer (focused with `/`).
    FilterLists(String),
    /// Rules tab Query-Log-style search buffer (focused with `/`).
    FilterRules(String),
    /// Devices tab subnet filter buffer (focused with `/`).
    ///
    /// Lane C built the read side and could not wire this: `InputMode`
    /// lives in `app.rs`, which was the wave's serialisation point and
    /// owned by another lane. Added by the integrator together with the
    /// keybinding and the `build_filtered_rows` switch — see the note on
    /// `tabs::devices::build_filtered_rows` for why those three cannot be
    /// split across commits.
    FilterDevicesSubnet(String),
    /// Log Messages tab search buffer (focused with `/`). Same
    /// `drive_text_input` path as Lists and Rules; `R` clears, which is
    /// free on this leaf.
    ///
    /// The sibling `FilterTags(String)` that landed beside this one on
    /// `main` is deliberately NOT carried across: `plp-s5d` deleted the
    /// Tags tab, so an input mode for it would be a variant nothing can
    /// ever enter.
    FilterLogs(String),
}

// ── Per-tab state ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DashboardState {
    pub show_daily: bool,
}

#[derive(Debug, Clone)]
pub struct QueryLogState {
    pub table_state: TableState,
    /// qlog-06: stable per-entry selection key `(timestamp, domain,
    /// client_ip)`. The Query Log is a sliding tail refreshed every 3s,
    /// so a bare `TableState` index slides onto a different row when the
    /// window shifts; anchoring on this key keeps the cursor — and the
    /// Enter→scope-modal capture — on the row the operator is looking at.
    /// `None` until the first scroll seeds it.
    pub selected_key: Option<(String, String, String)>,
    pub entries: Vec<QueryLogDto>,
    pub filter_domain: Option<String>,
    pub filter_client: Option<String>,
    pub blocked_only: bool,
    /// Sprint 41 time preset: cycles Off → 1h → 6h → 24h with the `t`
    /// key. Rendered on row 3 of the Filters panel; threaded to the
    /// daemon as `since_secs` via the IPC poller.
    pub since: SincePreset,
    /// Daemon-reported `tracking.query_log_enabled` at the time of the
    /// last successful poll. Drives the Sprint 37 empty-state picker
    /// together with `file_state`.
    pub logging_enabled: bool,
    pub file_state: QueryLogFileState,
    /// `qlog-paging-cursor`: the cursor used to request each page the
    /// operator has visited, indexed by page. `page_cursors[0]` is
    /// always `None` — page 0 is the live tail — and the invariant is
    /// restored by [`QueryLogState::reset_paging`], never by hand.
    ///
    /// A stack rather than a "walk forward" mode on the daemon: paging
    /// back toward newer rows re-requests a cursor the operator already
    /// used, so the walker only ever needs to go one direction. The log
    /// is append-only, so a stored offset stays valid across the 3 s
    /// poll and a paged-back view does not drift under its own refresh.
    pub page_cursors: Vec<Option<QueryLogCursor>>,
    /// Which entry of `page_cursors` the current view came from. `0` is
    /// the live tail.
    pub page_index: usize,
    /// Resume point reported by the last successful poll. `None` means
    /// the current page is the oldest retained — `PgDn` at the bottom
    /// has nowhere to go.
    pub next_cursor: Option<QueryLogCursor>,
    /// `qlog-advanced-filter-form`: the Tier-1 client predicates the
    /// operator has APPLIED. Default-empty, and an empty one compiles to
    /// no predicate at all — which is what makes the form additive rather
    /// than a fifth control every existing operator has to learn.
    pub advanced: AdvancedClientFilterDto,
    /// The form while it is open. `None` when closed; the draft inside is
    /// discarded on Esc, so `advanced` above only ever changes on Apply.
    pub advanced_modal: Option<QueryLogFilterModal>,
}

impl QueryLogState {
    /// The cursor to send for the page currently being viewed.
    pub fn current_cursor(&self) -> Option<QueryLogCursor> {
        self.page_cursors.get(self.page_index).cloned().flatten()
    }

    /// Return to the live tail and forget every stored cursor.
    ///
    /// **Every filter mutation must call this**, and that is the whole
    /// reason the method exists. Filters are applied *during* the walk,
    /// so a page boundary is a function of the predicate set that
    /// produced it. Re-using a cursor minted under the old filters
    /// serves rows that do not belong to the filters now displayed —
    /// silently wrong data in a surface operators use to decide what to
    /// block.
    /// The advanced filter to send, or `None` when the form is unused.
    /// Collapsing an all-blank form to `None` here means the daemon never
    /// compiles a predicate for an operator who has not opened it.
    pub fn advanced_for_request(&self) -> Option<AdvancedClientFilterDto> {
        (!self.advanced.is_empty()).then(|| self.advanced.clone())
    }

    pub fn reset_paging(&mut self) {
        self.page_cursors.clear();
        self.page_cursors.push(None);
        self.page_index = 0;
        self.next_cursor = None;
    }

    /// Step one page older. Returns `false` when the daemon reported no
    /// resume point, i.e. the current page is the oldest retained.
    pub fn page_older(&mut self) -> bool {
        if self.page_index + 1 >= self.page_cursors.len() {
            let Some(next) = self.next_cursor.clone() else {
                return false;
            };
            self.page_cursors.push(Some(next));
        }
        self.page_index += 1;
        true
    }

    /// Step one page newer. Returns `false` when already on the live tail.
    pub fn page_newer(&mut self) -> bool {
        if self.page_index == 0 {
            return false;
        }
        self.page_index -= 1;
        true
    }
}

impl Default for QueryLogState {
    fn default() -> Self {
        Self {
            table_state: TableState::default(),
            selected_key: None,
            entries: Vec::new(),
            filter_domain: None,
            filter_client: None,
            blocked_only: false,
            since: SincePreset::Off,
            // Optimistic defaults: the first successful poll overwrites
            // both. Until then the tab renders as if the writer is on
            // and the file is healthy — benign when the daemon is up.
            logging_enabled: true,
            file_state: QueryLogFileState::Ok,
            // The `page_cursors[0] == None` invariant is established here
            // and maintained only through `reset_paging`.
            page_cursors: vec![None],
            page_index: 0,
            next_cursor: None,
            advanced: AdvancedClientFilterDto::default(),
            advanced_modal: None,
        }
    }
}

/// Time-window preset for the Query Log tab's Sprint 41 filter. Cycles
/// with the `t` key through four discrete states — free-form input was
/// rejected in favour of a single-keystroke UX (design doc §3.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SincePreset {
    #[default]
    Off,
    LastHour,
    Last6Hours,
    Last24Hours,
}

impl SincePreset {
    pub fn next(self) -> Self {
        match self {
            Self::Off => Self::LastHour,
            Self::LastHour => Self::Last6Hours,
            Self::Last6Hours => Self::Last24Hours,
            Self::Last24Hours => Self::Off,
        }
    }

    /// Short label for the compact `Time: [<label>]` row. Fixed 4-char
    /// inner width so the surrounding line does not reflow as the
    /// preset rotates. Frozen — pinned by the query_log tests.
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => " off",
            Self::LastHour => " 1h ",
            Self::Last6Hours => " 6h ",
            Self::Last24Hours => "24h ",
        }
    }

    /// The duration as seconds, for the IPC `since_secs` field. `None`
    /// in `Off` state so the daemon applies no cutoff.
    pub fn as_secs(self) -> Option<u64> {
        match self {
            Self::Off => None,
            Self::LastHour => Some(3_600),
            Self::Last6Hours => Some(21_600),
            Self::Last24Hours => Some(86_400),
        }
    }
}

/// Grouping mode for the Devices tab mapped table. Cycles with `g`.
///
/// Grouping is implemented as a sort order — contiguous rows share the
/// same group key. No visual separators; operators see the grouping
/// emerge from the column content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceGroupBy {
    #[default]
    None,
    Owner,
    Department,
    Profile,
}

impl DeviceGroupBy {
    pub fn next(self) -> Self {
        match self {
            Self::None => Self::Owner,
            Self::Owner => Self::Department,
            Self::Department => Self::Profile,
            Self::Profile => Self::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Owner => "owner",
            Self::Department => "department",
            Self::Profile => "profile",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DevicesState {
    /// Cursor position in the unified mapped+unmapped list. The list
    /// merges both sets into a single Vec<DeviceRow> at render time;
    /// see `tui::tabs::devices` for the row enum and the navigation
    /// helper that skips group-header rows.
    pub table_state: TableState,
    pub group_by: DeviceGroupBy,
    /// dev-03: operator's stable selection key — the mapped device id
    /// (or its name slug for a pre-S44 id-less DTO), or the unmapped
    /// device's IP. Resolved to a row index every frame so a background
    /// `GetAllDevices` poll that reshuffles the list can't drift the
    /// cursor onto a different device. `None` until the first interaction
    /// seeds it; `table_state` is the visual cache kept in step with it.
    pub selected_id: Option<String>,
    /// Active modal overlay for add/edit/delete/promote on this tab.
    /// `None` when no modal is open. Sprint 23 s23-tui-devices-modal-form.
    pub modal: Option<DeviceModal>,
    /// Operator's subnet filter over the device list — a CIDR string
    /// (`192.0.2.0/24`). `None` means no filter.
    ///
    /// Declared HERE, by the wave's integrator, so the lane that implements
    /// the filter never has to edit `app.rs`: all nineteen tab state structs
    /// live in this file, so it is the wave's serialisation point and exactly
    /// one lane may own it.
    pub filter_subnet: Option<String>,
}

/// The kind of work an open modal is doing. The state machine for a
/// form (Add/Edit/Promote) and a delete confirmation are different
/// enough that they live in separate variants instead of a single
/// "is this a confirm" flag — pattern matches in the renderer and
/// key handler stay exhaustive that way.
#[derive(Debug, Clone)]
// Form carries ~250 bytes of String fields; DeleteConfirm is 24.
// Boxing Form to equalize variant sizes would add a heap alloc +
// deref per key press for no measurable benefit — the modal is
// constructed at most once per user action, never on a hot path.
#[allow(clippy::large_enum_variant)]
pub enum DeviceModal {
    /// Add/Edit/Promote share the same field set; the discriminant
    /// drives the title bar, the submit button label, and which IPC
    /// command the submit handler emits.
    Form(DeviceFormState),
    /// Yes/no confirmation before sending `DeviceRemove` over IPC.
    /// Carries the target's stable v1 id (used as the IPC key — the
    /// display name can diverge from `slug(name)` after a rename) and
    /// the friendly display name for the prompt. Sprint 23 design
    /// decision: delete is a modal, not a key chord.
    DeleteConfirm { id: String, display_name: String },
}

/// Discriminator for `DeviceFormState` — controls labels, submit
/// behavior, and which fields are editable. `Promote` is `Add` with
/// the IP locked (it came from the unmapped row the user selected)
/// and a `mac_hint` already populated from ARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFormMode {
    Add,
    Edit,
    Promote,
}

/// Editable fields exposed by the client form, in tab order. Keep in
/// sync with `DeviceFormState::field_buf` and with
/// `DeviceFormState::FIELDS` so the renderer and the key handler agree
/// on the focus index → field mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFormField {
    Ip,
    Mac,
    /// Comma-separated extra MACs that also belong to this device.
    /// Populated by the operator when they notice a MAC-rotating device
    /// (iOS private Wi-Fi address, Android/Samsung randomisation); the
    /// resolver matches any listed alias during ARP lookup.
    MacAliases,
    Name,
    Profile,
    /// Group memberships — a `Vec<Id>` in the schema and, since §4.64 G4,
    /// a multi-select in the form too (Edit only; the Add wire carries a
    /// single id). Only the highest-priority group's **profile** applies
    /// (DM2). Dropping one is a policy change, not a display detail — it
    /// changes which groups a device belongs to, and `priority` decides
    /// which of those groups' profiles wins.
    Group,
    Owner,
    Device,
    Department,
    /// Free-form operator memo — not consulted by the resolver.
    Notes,
    /// Bare DNS name this device answers to. Empty = unset, which is the
    /// default: a device only becomes resolvable when the operator says so.
    NetworkName,
    /// Typed `"true"` / `"false"`, parsed at submit — mirrors the CLI's
    /// `network_name_wildcard <true|false>`. Text rather than a checkbox
    /// because this form has no non-text field to reuse, and inventing one
    /// widget for one field would put the focus ring, the caret rules and
    /// the row renderer each on a second code path.
    NetworkNameWildcard,
}

/// What currently holds focus inside the client form modal. Widened from
/// a bare [`DeviceFormField`] so the Cancel / Save buttons are reachable
/// by the same `↑↓` / `Tab` ring the fields use, instead of being
/// keyboard-invisible affordances the operator can only trigger by
/// pressing Enter from somewhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFormFocus {
    Field(DeviceFormField),
    Cancel,
    Save,
}

impl DeviceFormFocus {
    /// The focused field, or `None` when focus sits on a button. Call
    /// sites that only make sense for a field — typing, buffer access,
    /// opening the picker — gate on this rather than matching inline.
    pub fn field(self) -> Option<DeviceFormField> {
        match self {
            DeviceFormFocus::Field(f) => Some(f),
            DeviceFormFocus::Cancel | DeviceFormFocus::Save => None,
        }
    }
}

/// State of a client add/edit/promote form modal. Each field is a
/// plain `String` (free typing), validated client-side at submit time.
/// Validation errors land in `error_message` for in-modal display so
/// operators see the message attached to the form they just submitted
/// rather than a transient toast.
#[derive(Debug, Clone)]
pub struct DeviceFormState {
    pub mode: DeviceFormMode,
    /// mod-03: the stable IPC id of the device an Edit form was opened
    /// on, captured at modal-open. The Edit submit patches THIS id rather
    /// than re-deriving the target from the live cursor — a 5s poll can
    /// reshuffle the row set under an open modal, so re-resolution at
    /// submit could land the patch on a different device. `None` for
    /// Add / Promote forms (no pre-existing entity).
    pub original_id: Option<String>,
    pub focused: DeviceFormFocus,
    pub name: String,
    pub ip: String,
    pub mac: String,
    /// Comma-separated list of additional MACs this device uses.
    /// Parsed at submit via `is_macish` for fast local validation;
    /// the daemon re-validates canonically with `is_valid_mac`.
    pub mac_aliases: String,
    pub profile: String,
    /// Comma-separated group ids, in the order the file carries them.
    /// Empty means "no direct group membership". Parsed into a `Vec` at
    /// submit, exactly like [`Self::mac_aliases`] — the schema's
    /// `Device.groups` is a `Vec<Id>` and the form must be able to hold
    /// all of it. (`plp-s5d`: this named `Self::tags`, which the same
    /// lane removed. `cargo doc -D rustdoc::broken_intra_doc_links` is
    /// the ONLY gate leg that sees a link like this go stale — clippy,
    /// fmt and the test suite were all green on it.)
    ///
    /// **Never typed.** The Group row is select-only
    /// (`is_select_only_field`), so this buffer is only ever written by
    /// the picker, which offers ids that exist. The plural name is not
    /// cosmetic: while this field was called `group`, the Edit submit
    /// wrapped it in a one-element `Vec` and every extra membership the
    /// operator had set from the CLI was destroyed on the next Save —
    /// §4.64 G4.
    pub groups: String,
    pub owner: String,
    pub device_type: String,
    pub department: String,
    /// Free-form operator memo. Single-line for now (multi-line would
    /// need a textarea primitive that this TUI doesn't yet have).
    pub notes: String,
    /// Bare network name, as typed. Empty means "no resolvable name",
    /// which the Edit submit sends as an explicit clear.
    pub network_name: String,
    /// `"true"` / `"false"` as typed, parsed at submit. Empty on an Add
    /// form; an Edit form always carries the device's concrete current
    /// state, because `edit_form_from` renders the DTO's bool.
    pub network_name_wildcard: String,
    /// Error message shown at the bottom of the modal — set on a
    /// failed submit (validation or IPC error). Cleared when the user
    /// edits any field.
    pub error_message: Option<String>,
    /// Set on a Promote form: the original name field is empty
    /// (operator must type a friendly name) but the IP is locked. The
    /// renderer uses this to mark the IP field as non-editable.
    pub ip_locked: bool,
    /// Set on a Promote form alongside `ip_locked`: the MAC was
    /// resolved from the ARP snapshot of the unmapped row, so it
    /// belongs to the device's identity and must not be edited.
    /// Editing here would let an operator silently rebind the
    /// observed traffic to a different MAC, undoing the
    /// IP-only-is-bypassable guard.
    pub mac_locked: bool,
    /// True while a submit is in flight — disables Enter to prevent
    /// double-submission and keeps the modal open while the IPC call
    /// resolves. Toggled back to false on response.
    pub submitting: bool,
    /// Snapshot of configured profile ids (BTreeMap key order = sorted),
    /// taken at modal-open from `app.loaded_config`. Drives the Profile
    /// field's popup radio picker. Empty when no config is loaded.
    pub profiles_snapshot: Vec<String>,
    /// Snapshot of configured group ids (config order), taken at
    /// modal-open. Drives the Group field's popup radio picker.
    pub groups_snapshot: Vec<String>,
    /// §4.66 L3: the `[[labels]]` vocabulary for the three metadata fields,
    /// one snapshot per kind, taken at modal-open.
    ///
    /// These hold **display names**, not ids, and that is the whole point.
    /// `Device.owner` is free text (`"Alex"`) while `Label.id` is an `Id`
    /// (`"alex"`), so the two can never be equal — the intersection is
    /// empty by construction. `Label::matches_value` accepts id **or**
    /// display_name, so writing the display name is what silences the
    /// unknown-value WARN while staying readable in the Devices table.
    ///
    /// Empty when no vocabulary is declared for that kind, which leaves the
    /// field free-text: `open_field_picker` no-ops on an empty list rather
    /// than trapping the operator in an empty popup.
    pub owners_snapshot: Vec<String>,
    pub device_types_snapshot: Vec<String>,
    pub departments_snapshot: Vec<String>,
    /// Open popup-radio picker when the operator is choosing a value for a
    /// select-only field (Profile / Group / the three metadata kinds).
    /// `None` in normal field-editing mode.
    pub picker: Option<FieldPicker>,
}

/// State for the device-form popup picker (Profile / Group / the three
/// metadata kinds). `options` is cloned from the matching snapshot at open;
/// `cursor` indexes the highlighted row.
#[derive(Debug, Clone)]
pub struct FieldPicker {
    pub target: DeviceFormField,
    pub options: Vec<String>,
    pub cursor: usize,
    /// Multi-select mode: Space toggles, Enter commits the whole
    /// selection. Only the Group picker on an **Edit** form sets it —
    /// the Add wire (`ClientConfig.group`) is a singular `Option<String>`,
    /// so offering multi-select there would write one id and drop the
    /// rest: the very silent loss §4.64 G4 closes, re-opened in another
    /// mode.
    pub multi: bool,
    /// Chosen ids in **selection order**, seeded from the field's current
    /// value (i.e. the file's order) and appended to as the operator
    /// toggles. Never rebuilt from `options`, so a Save the operator did
    /// not intend as a reorder does not produce one. Empty and unused
    /// when `multi` is false.
    pub selected: Vec<String>,
}

impl DeviceFormState {
    /// Field tab order, and the source `focus_ring` filters to build the
    /// modal's focus sequence. IP + MAC + MAC aliases cluster at the top
    /// as the identity block (locked on Promote). The metadata block
    /// follows: Name, Profile, Group, Owner, Type, Department, Notes.
    /// The renderer does NOT read this list — it lays rows out
    /// from `devices::{IDENTITY_FIELDS, ASSIGNMENT_FIELDS}`, and a test
    /// asserts every entry here appears in exactly one of those.
    pub const FIELDS: [DeviceFormField; 12] = [
        DeviceFormField::Ip,
        DeviceFormField::Mac,
        DeviceFormField::MacAliases,
        DeviceFormField::Name,
        DeviceFormField::Profile,
        DeviceFormField::Group,
        DeviceFormField::Owner,
        DeviceFormField::Device,
        DeviceFormField::Department,
        DeviceFormField::Notes,
        DeviceFormField::NetworkName,
        DeviceFormField::NetworkNameWildcard,
    ];

    /// Empty form for `Add`. Focus starts on the first editable field
    /// (`Ip` per the new ordering) so the operator can type
    /// immediately without first pressing Tab.
    pub fn new_add() -> Self {
        Self {
            mode: DeviceFormMode::Add,
            original_id: None,
            focused: DeviceFormFocus::Field(DeviceFormField::Ip),
            name: String::new(),
            ip: String::new(),
            mac: String::new(),
            mac_aliases: String::new(),
            profile: "default".into(),
            groups: String::new(),
            owner: String::new(),
            device_type: String::new(),
            department: String::new(),
            notes: String::new(),
            network_name: String::new(),
            network_name_wildcard: String::new(),
            error_message: None,
            ip_locked: false,
            mac_locked: false,
            submitting: false,
            profiles_snapshot: Vec::new(),
            groups_snapshot: Vec::new(),
            owners_snapshot: Vec::new(),
            device_types_snapshot: Vec::new(),
            departments_snapshot: Vec::new(),
            picker: None,
        }
    }

    /// Pre-filled form for `Edit`. The keybindings layer pulls the
    /// values from the focused mapped row.
    #[allow(clippy::too_many_arguments)]
    pub fn new_edit(
        name: String,
        ip: String,
        mac: String,
        mac_aliases: String,
        profile: String,
        groups: String,
        owner: String,
        device_type: String,
        department: String,
        notes: String,
        network_name: String,
        network_name_wildcard: String,
    ) -> Self {
        Self {
            mode: DeviceFormMode::Edit,
            original_id: None,
            focused: DeviceFormFocus::Field(DeviceFormField::Name),
            name,
            ip,
            mac,
            mac_aliases,
            profile,
            groups,
            owner,
            device_type,
            department,
            notes,
            network_name,
            network_name_wildcard,
            error_message: None,
            ip_locked: false,
            mac_locked: false,
            submitting: false,
            profiles_snapshot: Vec::new(),
            groups_snapshot: Vec::new(),
            owners_snapshot: Vec::new(),
            device_types_snapshot: Vec::new(),
            departments_snapshot: Vec::new(),
            picker: None,
        }
    }

    /// Pre-filled form for `Promote`. IP comes from the unmapped row;
    /// MAC comes from the row's ARP-resolved value. Both are locked
    /// because they ARE the device's identity — promoting an unmapped
    /// row is fundamentally "rename + tag" with the (ip, mac) tuple
    /// already pinned by what we observed on the wire.
    pub fn new_promote(ip: String, mac: String) -> Self {
        Self {
            mode: DeviceFormMode::Promote,
            original_id: None,
            focused: DeviceFormFocus::Field(DeviceFormField::Name),
            name: String::new(),
            ip,
            mac,
            mac_aliases: String::new(),
            profile: "default".into(),
            groups: String::new(),
            owner: String::new(),
            device_type: String::new(),
            department: String::new(),
            notes: String::new(),
            network_name: String::new(),
            network_name_wildcard: String::new(),
            error_message: None,
            ip_locked: true,
            mac_locked: true,
            submitting: false,
            profiles_snapshot: Vec::new(),
            groups_snapshot: Vec::new(),
            owners_snapshot: Vec::new(),
            device_types_snapshot: Vec::new(),
            departments_snapshot: Vec::new(),
            picker: None,
        }
    }

    /// Attach the configured profile + group id snapshots (read from
    /// `app.loaded_config` at modal-open) so the Profile / Group fields can
    /// offer a popup radio picker instead of free-text entry. Chained onto
    /// the `new_*` constructors at the open sites.
    pub fn with_options(mut self, profiles: Vec<String>, groups: Vec<String>) -> Self {
        self.profiles_snapshot = profiles;
        self.groups_snapshot = groups;
        self
    }

    /// §4.66 L3: seed the three metadata pickers from the `[[labels]]`
    /// vocabulary. Additive to [`Self::with_options`] so the existing call
    /// sites keep working unchanged.
    pub fn with_label_vocab(
        mut self,
        owners: Vec<String>,
        device_types: Vec<String>,
        departments: Vec<String>,
    ) -> Self {
        self.owners_snapshot = owners;
        self.device_types_snapshot = device_types;
        self.departments_snapshot = departments;
        self
    }

    /// mod-03: pin the stable IPC id captured at modal-open (Edit forms).
    /// The submit patches this id verbatim instead of re-resolving the
    /// target from the live cursor, which a background poll can move under
    /// the open modal. Chained onto `new_edit` at the open site.
    pub fn with_original_id(mut self, id: Option<String>) -> Self {
        self.original_id = id;
        self
    }

    /// Every focusable stop in visual order: the unlocked fields first
    /// (locked ones are skipped — Promote pins ip + mac), then the two
    /// action buttons. Rebuilt per call because `is_locked` depends on
    /// the form mode. Always holds at least the two buttons, so the
    /// modulo arithmetic in `focus_next` / `focus_prev` cannot divide by
    /// zero even if every field were locked.
    fn focus_ring(&self) -> Vec<DeviceFormFocus> {
        let mut ring: Vec<DeviceFormFocus> = Self::FIELDS
            .iter()
            .copied()
            .filter(|f| !self.is_locked(*f))
            .map(DeviceFormFocus::Field)
            .collect();
        ring.push(DeviceFormFocus::Cancel);
        ring.push(DeviceFormFocus::Save);
        ring
    }

    /// Move focus forward by one stop, wrapping at the end. Bound to
    /// `Tab` and `↓`.
    pub fn focus_next(&mut self) {
        let ring = self.focus_ring();
        self.focused = match ring.iter().position(|s| *s == self.focused) {
            Some(cur) => ring[(cur + 1) % ring.len()],
            // Focus sits on a stop the ring does not contain — reachable if
            // a field is locked while focused. Snap to the first live stop.
            // Treating it as index 0 and advancing would silently skip that
            // first stop instead.
            None => ring[0],
        };
    }

    /// Move focus backward by one stop. Bound to `Shift-Tab` and `↑`.
    pub fn focus_prev(&mut self) {
        let ring = self.focus_ring();
        self.focused = match ring.iter().position(|s| *s == self.focused) {
            Some(cur) => ring[(cur + ring.len() - 1) % ring.len()],
            // See `focus_next`: snap, do not step off a phantom index.
            None => ring[0],
        };
    }

    /// Whether the given field is read-only in the current form mode.
    /// Tab navigation skips locked fields; the renderer dims them and
    /// the key handler refuses keystrokes on them.
    /// §4.64 G4: Group is locked on **Promote** because the promote wire
    /// has no group field — `handle_device_promote` writes the device
    /// with `group: None` by design ("the operator can assign one later
    /// via Edit"). The row was editable anyway, so anything the operator
    /// chose there was dropped without a word: the same silent loss G4
    /// closed on the Edit path, one mode over. Locked, not hidden — a row
    /// that vanishes reads as a bug, a row that says when it becomes
    /// available reads as an instruction.
    pub fn is_locked(&self, field: DeviceFormField) -> bool {
        (self.ip_locked && field == DeviceFormField::Ip)
            || (self.mac_locked && field == DeviceFormField::Mac)
            || (self.mode == DeviceFormMode::Promote && field == DeviceFormField::Group)
    }

    /// Slug-derived v1 id preview from the current name. Read-only, and
    /// used on **Add / Promote only**: the renderer shows it as the first
    /// row of the Identity section so the operator can see what id will
    /// land in `[[devices]]` when they submit. On Edit the id is immutable
    /// and comes from `original_id` instead — it does not follow the name,
    /// and rendering this there would show a value the submit never uses.
    pub fn id_preview(&self) -> String {
        crate::cli::commands::target::slug_id(&self.name).unwrap_or_default()
    }

    /// Mutable access to the buffer behind a given field. Used by the
    /// key handler to push/pop characters on Backspace / Char(c).
    pub fn field_buf(&mut self, field: DeviceFormField) -> &mut String {
        match field {
            DeviceFormField::Name => &mut self.name,
            DeviceFormField::Ip => &mut self.ip,
            DeviceFormField::Mac => &mut self.mac,
            DeviceFormField::MacAliases => &mut self.mac_aliases,
            DeviceFormField::Profile => &mut self.profile,
            DeviceFormField::Group => &mut self.groups,
            DeviceFormField::Owner => &mut self.owner,
            DeviceFormField::Device => &mut self.device_type,
            DeviceFormField::Department => &mut self.department,
            DeviceFormField::Notes => &mut self.notes,
            DeviceFormField::NetworkName => &mut self.network_name,
            DeviceFormField::NetworkNameWildcard => &mut self.network_name_wildcard,
        }
    }
}

/// §4.68 UX8: which of the Labels leaf's two panes has the cursor.
///
/// The leaf is drawn as two side-by-side cards, so it is navigated on
/// that axis: `←` / `→` move **between** the cards, `↑` / `↓` move
/// **inside** the focused one. `Tab` is deliberately not one of them —
/// it stays the global leaf cycle. Before this existed there was no
/// focus at all — `h`/`l` cycled the kind menu and `j`/`k` the table,
/// unconditionally, which meant the vertical menu was walked with a
/// horizontal key. That mismatch is what an operator reported as
/// "VIM navigation"; `h`/`l` was the only such pair in the whole TUI.
/// Those four aliases were **deleted** TUI-wide by N3 (2026-08-24) and
/// are not rebound (N11) — only the arrows reach this focus today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LabelsFocus {
    KindMenu,
    Entries,
}

/// §4.67-b MN3: everything the [`Leaf::File`] document viewer needs, split
/// out of `SettingsState`. The config *text* lives here; the config as an
/// administered thing (tracking knobs, backups) stays on `SettingsState`.
/// §4.66 L2: cursor state of the Labels leaf. `selected_kind` is which
/// vocabulary the left menu has focused; `selected_id` anchors the row in
/// the right table by **id**, not index — a config reload can add, remove
/// or reorder entries.
#[derive(Debug, Clone)]
pub struct LabelsState {
    pub selected_kind: crate::config::schema::LabelKind,
    pub selected_id: Option<String>,
    /// §4.68 UX8: which pane `↑`/`↓` scroll. See [`LabelsFocus`].
    pub(crate) focus: LabelsFocus,
    /// §4.66 L7: the open Add / Edit / Delete modal, or `None`. While it
    /// is `Some` it grabs every keystroke — the gate sits in `handle_key`
    /// ahead of the per-leaf dispatch, next to the Groups one.
    pub(crate) modal: Option<crate::tui::label_modal::LabelModal>,
    /// Whether the last frame actually drew the kind menu.
    ///
    /// **The key handler cannot compute this and must not guess it.** It
    /// never sees the viewport width; `clamp_labels_focus_to_layout` runs
    /// in the render loop, which does, and writes the answer here. Without
    /// it the two-pane key model is applied to a one-pane screen: below
    /// `NARROW_THRESHOLD` the clamp pins focus to the table **every
    /// frame**, so `←` cannot hold `KindMenu` long enough for the next
    /// `↑`/`↓` to reach it and the kind becomes unreachable. That was
    /// harmless while the leaf only read; with `a` writing into the
    /// focused kind it meant two of the three vocabularies could not be
    /// authored at the product's declared 80×24 minimum.
    ///
    /// Starts `true` so the first keystroke of a session that has not
    /// rendered yet behaves like the wide layout, which is the common
    /// case; the first frame corrects it either way.
    pub(crate) menu_painted: bool,
}

impl Default for LabelsState {
    fn default() -> Self {
        Self {
            modal: None,
            menu_painted: true,
            // Owner is the kind an operator reaches for first: it is the
            // one that names a person rather than a category.
            selected_kind: crate::config::schema::LabelKind::Owner,
            selected_id: None,
            // The menu, not the table: the kind decides what the table
            // even contains, so it is the choice that comes first.
            focus: LabelsFocus::KindMenu,
        }
    }
}

/// Which pane of the Custom Lists leaf `↑`/`↓` scroll, and which one `a`
/// and `d` act on.
///
/// Both panes are always **populated** — the rule pane follows the list
/// cursor with no keystroke, which is the answer to "which list holds this
/// domain". Focus decides who *acts*, not who *renders*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustomListsFocus {
    Lists,
    Rules,
}

/// One line of a pack file as the rule pane draws it.
///
/// Held on the app rather than re-read per frame: the renderer takes
/// `&App`, so a file read on the draw path would run at the frame rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackRow {
    /// 1-based file line — the anchor an operator repairing the file by
    /// hand types into their editor.
    pub number: usize,
    /// The line exactly as it sits on disk.
    pub raw: String,
    /// `None` for a comment, a blank, or a line that did not parse.
    pub domain: Option<String>,
    pub action: PackRowAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackRowAction {
    Allow,
    Deny,
    /// Comment or blank — carries no rule and never did.
    None,
    /// The reader refused this line, so it enforces nothing. Visible only
    /// here: every other surface reports these as a bare count.
    Skipped,
}

/// The pack file currently loaded into the rule pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackView {
    /// Which list these rows came from, so a stale view is detectable.
    pub id: String,
    pub rows: Vec<PackRow>,
    /// Why the file could not be read, when it could not. A broken LINE is
    /// a row; a broken FILE is this.
    pub error: Option<String>,
}

/// Cursor and pane state of the Custom Lists leaf.
///
/// Both cursors are **content anchors**, not indices: the list cursor is an
/// id and the rule cursor is a file line number, so a reload that adds or
/// removes rows above them does not silently move what `d` deletes.
#[derive(Debug, Clone)]
pub struct CustomListsState {
    pub selected_id: Option<String>,
    /// 1-based file line the rule pane's cursor rests on.
    pub selected_line: Option<usize>,
    pub(crate) focus: CustomListsFocus,
    /// Open profile picker for `m`, or `None`. While it is `Some` it grabs
    /// every keystroke — the gate sits in `handle_key` ahead of the
    /// per-leaf dispatch, next to the Labels one.
    pub(crate) mount_picker: Option<crate::tui::custom_list_modal::MountPicker>,
    /// Open Add / Edit / Remove modal, or `None`. While it is `Some` it
    /// grabs every keystroke — the gate sits in `handle_key` ahead of the
    /// per-leaf dispatch, next to the Labels one.
    pub(crate) modal: Option<crate::tui::custom_list_modal::CustomListModal>,
    /// Lines of the selected list's pack, reloaded when the selection
    /// changes or a write lands. `None` before the first load.
    pub pack: Option<PackView>,
    /// Whether the last frame actually drew the rule pane.
    ///
    /// **The key handler cannot compute this and must not guess it.** It
    /// never sees the viewport width; the render loop does and writes the
    /// answer here. Without it a `Rules` focus could rest on a pane the
    /// layout does not paint, and `d` would act on rows nobody can see.
    /// Same mechanism as `LabelsState::menu_painted`, for the same reason.
    ///
    /// Starts `true` so the first keystroke of a session that has not
    /// rendered yet behaves like the wide layout; the first frame corrects
    /// it either way.
    pub(crate) rules_pane_painted: bool,
}

impl Default for CustomListsState {
    fn default() -> Self {
        Self {
            selected_id: None,
            selected_line: None,
            // The list pane: which list is the choice that decides what the
            // other pane even contains.
            focus: CustomListsFocus::Lists,
            mount_picker: None,
            modal: None,
            pack: None,
            rules_pane_painted: true,
        }
    }
}

/// §4.64 G1: cursor state of the Groups leaf. The anchor is the group
/// **id**, not a row index: an index survives a config reload that
/// reorders or removes rows and then points at the wrong group.
#[derive(Debug, Clone, Default)]
pub struct GroupsState {
    pub selected_id: Option<String>,
    /// §4.64 G2: the Add / Edit / Delete modal. `None` = closed; a `Some`
    /// grabs every keystroke until submit lands or Esc closes it, exactly
    /// as `SubnetsState::modal` does.
    pub modal: Option<crate::tui::group_modal::GroupModal>,
}

#[derive(Debug, Clone, Default)]
pub struct FileState {
    /// Selection cursor of the pre-`tui-wave1` permanent "Sections"
    /// sidebar. The sidebar is gone — `/` replaced it — so this is
    /// seeded once at startup and never read. Carried across the split
    /// verbatim rather than dropped: retiring it is a separate change
    /// with its own diff, not a side effect of a move.
    pub sections_state: ListState,
    pub config_text: String,
    pub sections: Vec<String>,
    pub scroll_offset: u16,
    /// tui-wave1/settings-sidebar: on-demand section-jump popup, opened
    /// with `/` now that the permanent left "Sections" sidebar is gone.
    /// `None` = closed; `Some(filter)` = open with the current
    /// type-to-filter buffer (starts empty on open).
    pub section_jump: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SettingsState {
    /// Sprint 39: interactive Tracking panel state. `None` when not
    /// in form mode — the landing view is rendered instead.
    /// `Some` when the operator pressed `t` from the Settings tab;
    /// the pane renders the form until Esc.
    pub tracking_panel: Option<TrackingPanelState>,
    /// Restore picker modal, opened with `R`. `Some` grabs every
    /// keystroke (gated in `handle_key`) until the operator restores,
    /// cancels, or dismisses the outcome.
    pub restore_modal: Option<crate::tui::backup_restore_modal::RestoreModal>,
    /// Backup confirm + result modal, opened with `b`. Same single-open
    /// gate as `restore_modal`; replaces the prior silent backup that
    /// routed both outcomes into the red `last_error` footer.
    pub backup_modal: Option<crate::tui::backup_restore_modal::BackupModal>,
    /// Sprint 5: cached auto-backup engine state for the Settings tab's
    /// status line + failure banner. Refreshed on tab-entry / config
    /// reload, not per-render (the render fn has no `config_path`).
    pub auto_backup: AutoBackupView,
}

/// Sprint 5: snapshot of the Sprint 4 auto-backup engine state, read
/// from `<backup_dir>/.auto_state` + the newest `list_backups` entry.
/// Surfaced read-only on the Settings tab (Q4 status line, Q5 banner).
#[derive(Debug, Clone, Default)]
pub struct AutoBackupView {
    /// Newest archive timestamp, if any — drives `Last auto-backup:
    /// <date> (<age>)`. `None` ⇒ the "never" state.
    pub last_archive: Option<time::OffsetDateTime>,
    /// `consecutive_failures` from `.auto_state`; `> 0` shows the banner.
    pub consecutive_failures: u32,
    /// The most recent failure message, when the last outcome was an
    /// error (the banner's `<reason>`).
    pub last_error: Option<String>,
    /// The Q5 auto-disable latch — drives the stronger disabled banner.
    pub disabled: bool,
}

/// Sprint 39: state for the Settings tab's interactive Tracking
/// form — mirrors the three `TrackingPatch` fields plus local UI
/// state (focus, retention-input buffer, last submit feedback).
#[derive(Debug, Clone)]
pub struct TrackingPanelState {
    pub query_log_enabled: bool,
    pub log_mode: crate::config::settings::LogMode,
    pub retention_days: u32,
    /// Raw digit buffer while the operator is typing in the
    /// retention input. Committed to `retention_days` when the
    /// operator moves focus away or submits.
    pub retention_input: String,
    pub focus: TrackingFocus,
    /// Last submit feedback — success message or daemon error.
    /// Rendered in the panel footer; cleared when any key fires
    /// another edit.
    pub submit_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackingFocus {
    Enabled,
    Mode,
    Retention,
}

impl TrackingFocus {
    pub fn next(self) -> Self {
        match self {
            Self::Enabled => Self::Mode,
            Self::Mode => Self::Retention,
            Self::Retention => Self::Enabled,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Enabled => Self::Retention,
            Self::Mode => Self::Enabled,
            Self::Retention => Self::Mode,
        }
    }
}

impl TrackingPanelState {
    /// Build a panel populated from the on-disk config. Called when
    /// the operator presses `t` in the Settings tab — fresh read so
    /// a config edit via `$EDITOR` is reflected without re-entering
    /// the tab.
    pub fn from_config(tracking: &crate::config::settings::TrackingConfig) -> Self {
        Self {
            query_log_enabled: tracking.query_log_enabled,
            log_mode: tracking.log_mode.clone(),
            retention_days: tracking.retention_days,
            retention_input: tracking.retention_days.to_string(),
            focus: TrackingFocus::Enabled,
            submit_message: None,
        }
    }

    /// Build the IPC patch representing the currently-displayed
    /// state. Every field is sent as `Some(…)` — the daemon treats
    /// the patch as a full "set to these values" rather than a
    /// diff, which matches the TUI's "this is what I see, apply it"
    /// mental model.
    pub fn to_patch(&self) -> crate::ipc::protocol::TrackingPatch {
        crate::ipc::protocol::TrackingPatch {
            query_log_enabled: Some(self.query_log_enabled),
            retention_days: Some(self.retention_days),
            log_mode: Some(self.log_mode.clone()),
        }
    }
}

// ── Daemon status snapshot ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DaemonStatus {
    #[allow(dead_code)] // will be displayed in status details
    pub pid: u32,
    pub listen: String,
    pub upstream_mode: String,
    pub upstream_count: usize,
    pub domain_count: usize,
    pub cache_entries: u64,
    pub list_count: usize,
    pub uptime_secs: u64,
    /// §4.19 — daemon binary version string. Empty when polling a
    /// pre-§4.19 daemon; the dashboard hides the version chip in that
    /// case rather than rendering "v" with no number.
    pub version: String,
    /// §4.19 — configured weighted cache capacity. 0 when polling a
    /// pre-§4.19 daemon; the dashboard's existing `cache_capacity`
    /// extrapolation is the legacy fallback in that case.
    pub cache_cap: u64,
    /// §4.19 — number of blocklist sources whose most recent refresh
    /// succeeded. 0 when polling a pre-§4.19 daemon (or when no
    /// sources are configured).
    pub lists_active: u32,
    /// §4.19 — total number of configured blocklist sources. 0 when
    /// polling a pre-§4.19 daemon; `list_count` above is the legacy
    /// fallback.
    pub lists_total: u32,
    /// §4.13 — resource-budget sample (RSS / VSZ / fd count / CPU%)
    /// plus the configured `rss_warn_mb` threshold. `None` until the
    /// daemon's sampler produces its first snapshot, or when polling
    /// a pre-§4.13 daemon, or on non-Linux daemon targets.
    pub resource_budget: Option<crate::resource_budget::ResourceBudgetSnapshot>,
    /// The standing corpus refusal, when the last reload cycle produced
    /// more unique domains than `max_total_domains` and was therefore
    /// **not installed**. `None` when the corpus installed normally.
    ///
    /// Carried because a refusal is invisible in every other counter on
    /// this struct, and worse than invisible: `lists_active` /
    /// `lists_total` describe *fetching*, so a refused cycle reports a
    /// perfectly truthful `N/N` while the daemon serves the previous
    /// generation — or, past the hard cap with no previous generation,
    /// nothing at all. `warden status` has refused to call that state
    /// "active" since the corpus-ceiling sprint; this field is what lets
    /// the TUI stop doing so too (`tui-blind-to-corpus-refusal`).
    pub lists_corpus_refusal: Option<crate::lists::status::CorpusRefusal>,
    /// Number of sources whose most recent refresh hit `max_entries` and
    /// dropped entries on the floor.
    ///
    /// The **second** blind spot of the same shape, found by the check
    /// `tui-blind-to-corpus-refusal` step 5 asked for: a truncated source
    /// is *also* active, so it too is invisible in `lists_active`, and
    /// before this the TUI carried no notion of list truncation at all.
    /// Weaker than a refusal — the corpus did install, just short — so it
    /// annotates the counts rather than replacing them.
    pub lists_truncated: u32,
}

/// Daemon-reported tracking metrics mirrored into TUI state.
///
/// The numeric scalars (`queries_total`, `blocked_total`, `*_pct`,
/// `*_rate`, `*_24h`, `*_delta_1h`, `cache_negative_hits`) are
/// currently unread by the dashboard — the 4-window gauges aggregate
/// directly from `hourly`/`daily` buckets. They remain on the struct
/// because the IPC deserializer populates them and the upcoming
/// spacing redesign of the other dashboard components may surface
/// them again. `#[allow(dead_code)]` is applied at the struct level
/// to acknowledge the gap without per-field noise.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct TrackingData {
    pub queries_total: u64,
    pub blocked_total: u64,
    pub blocked_pct: f64,
    pub cache_hit_rate: f64,
    pub cache_negative_hits: u64,
    pub top_blocked: Vec<crate::ipc::protocol::DomainCount>,
    pub top_queried: Vec<crate::ipc::protocol::DomainCount>,
    pub hourly: Vec<TimeBucketDto>,
    pub daily: Vec<TimeBucketDto>,
    /// 24h rolling averages (0–100) computed daemon-side from hourly
    /// buckets. Stay at 0.0 when the daemon has less than one hour of
    /// data — gauges render the under-label as muted "collecting…" in
    /// that case instead of lying about a trend.
    pub cache_hit_rate_24h: f64,
    pub blocked_pct_24h: f64,
    /// 1h deltas in percentage points (positive = most recent hour was
    /// higher than the one before). Rendered as ↑/↓/— arrows next to
    /// the 24h average in each gauge's under-label.
    pub cache_hit_rate_delta_1h: f64,
    pub blocked_pct_delta_1h: f64,
    /// §4.6 per-`TypeBucket` query counts in canonical order
    /// (`A, AAAA, TXT, PTR, NS, SOA, SRV, SVCB, HTTPS, Other`).
    /// Drives the Dashboard QTYPE distribution widget.
    pub qtype_distribution: [u64; crate::tracking::TYPE_BUCKET_COUNT],
    /// Sprint E per-`TypeBucket` BLOCKED query counts in the same
    /// canonical order. Drives the second (red) bar of the QTYPE
    /// chart card. Defaults to all-zero when the daemon is pre-Sprint-E
    /// (the wire field has `#[serde(default = "zero_qtype_distribution")]`).
    pub qtype_blocked_distribution: [u64; crate::tracking::TYPE_BUCKET_COUNT],
    /// Sprint F — same shape as `qtype_distribution` but summed over
    /// the trailing 24 hourly buckets (rolling window). Drives the
    /// QTYPE chart card so blocked bars stay proportional to live
    /// activity. Defaults to all-zero when the daemon is pre-Sprint-F.
    pub qtype_distribution_24h: [u64; crate::tracking::TYPE_BUCKET_COUNT],
    /// Sprint F — same shape as `qtype_blocked_distribution` but
    /// summed over the trailing 24 hourly buckets. Drives the Blocked
    /// bar of the QTYPE chart card.
    pub qtype_blocked_distribution_24h: [u64; crate::tracking::TYPE_BUCKET_COUNT],
    /// Sprint §4.4 P1 — number of domains currently in the prefetch
    /// pool (promoted by the hit-frequency tracker). Drives the
    /// Dashboard's `Prefetch  pool N` row. The IPC field is `u32` —
    /// pool size is bounded at `max_pool_size` (default 1024) so
    /// 32 bits is plenty.
    pub prefetch_pool_size: u32,
    /// Sprint §4.4 P1 — cumulative promotion events. The TUI uses the
    /// inter-poll delta to derive `prefetch_promotions_per_min` below.
    pub prefetch_promotions_total: u64,
    /// Sprint §4.4 P1 — cumulative demotion events. Currently unused
    /// at render time but kept on TrackingData so the IPC destructure
    /// stays exhaustive and a future extension (e.g. churn warning)
    /// has the data without another wire change.
    pub prefetch_demotions_total: u64,
    /// Sprint §4.4 P2 — promotions-per-minute derived client-side from
    /// the inter-poll delta of `prefetch_promotions_total`. Computed
    /// inside `IpcPoller::fetch_tracking_stats` using a wall-clock
    /// `Instant` snapshot kept on the poller. `0.0` until the second
    /// poll provides a baseline; renderer shows `collecting…` while it
    /// is `0.0` AND `prefetch_pool_size == 0 && prefetch_promotions_total == 0`.
    pub prefetch_promotions_per_min: f64,
    /// Sprint C Dashboard v2 — daemon-resolved per-list block counts
    /// (top-5, ranked desc). Empty until the daemon has seen at least
    /// one Tier 1 `BlockSource::List(bit)`. Pre-Sprint-B daemons send
    /// nothing for this field; the IPC-side `#[serde(default)]` makes
    /// the empty vec graceful → "collecting…" placeholder on render.
    pub top_blocked_lists: Vec<crate::ipc::protocol::ListBlockCount>,
    /// 24h-rolling Top-N by block count (per-domain). Drives the
    /// row-4 wide-branch `Top Blocked Domains (24h)` card. Empty on
    /// pre-Sprint-N daemons → `collecting…` placeholder.
    pub top_blocked_24h: Vec<crate::ipc::protocol::DomainCount>,
    /// 24h-rolling Top-N by query count (per-domain). Drives the
    /// narrow-branch `Top Domains (24h)` card.
    pub top_queried_24h: Vec<crate::ipc::protocol::DomainCount>,
    /// 24h-rolling Top-5 lists by block count. Drives the row-4
    /// `Top Lists (24h)` card.
    pub top_blocked_lists_24h: Vec<crate::ipc::protocol::ListBlockCount>,
}

/// Severity of the transient footer status line (ui-01). Before this,
/// `App` carried a single `last_error: Option<String>` that every modal
/// submit wrote its *outcome* into — success ("added subnet x"),
/// neutral ("rule unchanged") and error alike — and the footer rendered
/// all of them red with an `✕`, so successful mutations read as
/// failures. The severity lets the footer style each correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusSeverity {
    /// A mutation succeeded — green `✓`.
    Ok,
    /// A failure or refusal — red `✕`.
    Error,
    /// Neutral / informational (a no-op, a not-actionable row) — muted.
    Info,
}

/// §4.62 N3 — how long a non-sticky status stays on screen. `Ok` and
/// `Info` share it; `Error` is sticky (see [`StatusSeverity::ttl`]).
pub const STATUS_TTL: Duration = Duration::from_secs(4);

impl StatusSeverity {
    /// §4.62 N3 — time-to-live by severity. `None` means sticky: the
    /// message stays until the operator dismisses it with a keystroke.
    ///
    /// Asymmetric on purpose. An error the operator did not read is a
    /// lost error; a success they did not read costs nothing.
    pub fn ttl(self) -> Option<Duration> {
        match self {
            StatusSeverity::Ok | StatusSeverity::Info => Some(STATUS_TTL),
            StatusSeverity::Error => None,
        }
    }
}

/// What raised a status — the operator, or the background poller.
///
/// N3 ("an error the operator did not read is a lost error") was written
/// about *action* errors: I pressed Save and it failed. Background poll
/// health is a different animal. By N4's own state/event split a poll
/// failure is a **state** — it describes a condition that either holds
/// or does not, and the header RUNNING/DISCONNECTED pill is already its
/// permanent surface. Making it sticky would leave a red toast reporting
/// a failure that recovered two seconds later, on an idle dashboard,
/// forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOrigin {
    /// Raised by something the operator did. Obeys N3 in full.
    Action,
    /// Raised by a background poll. Sticky while the condition holds —
    /// but cleared the moment a poll succeeds, with no keystroke
    /// required. See [`App::clear_poll_status`].
    Poll,
}

/// A transient status message plus its severity, rendered as an
/// auto-expiring toast over the tab content (ui-01, §4.62 N1).
///
/// §4.62 N2: `shown_at` is what decouples the message lifetime from the
/// poll cadence. Before it, clearing happened only in the success arms
/// of `poll_active_leaf`, so the effective lifetime was 2 s on Dashboard
/// and *never* on the six leaves that don't poll (Tags, Subnets, Rules,
/// Profiles, Settings, Cluster) — the operator's "non è chiaro dopo
/// quanto tempo la notifica sparisca". Expiry is now evaluated on the
/// render path and on `Event::Tick`, both of which run on every leaf.
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub severity: StatusSeverity,
    pub text: String,
    /// Who raised it. Decides whether a recovering poll may retire it
    /// without the operator's acknowledgement.
    pub origin: StatusOrigin,
    /// Monotonic stamp of when this message was raised. `Instant`, not
    /// wall clock: a NTP step or a suspend/resume must not resurrect or
    /// prematurely kill a toast.
    pub shown_at: Instant,
}

impl StatusLine {
    /// Whether this message has outlived its severity's TTL as of `now`.
    /// Sticky severities (`Error`) never expire — only a keystroke
    /// dismisses them.
    ///
    /// `saturating_duration_since` rather than `-`: `now` is caller-
    /// supplied (the tests pass a future instant) and an earlier `now`
    /// must read as "0 elapsed", not panic.
    pub fn is_expired_at(&self, now: Instant) -> bool {
        match self.severity.ttl() {
            Some(ttl) => now.saturating_duration_since(self.shown_at) >= ttl,
            None => false,
        }
    }
}

/// Resolve a stable selection key to a row index by scanning the current
/// rows (dev-03 / qlog-06). The cross-tab pattern — subnets / profiles /
/// cluster each store a stable key and re-resolve it to an index every
/// frame — that keeps a cursor on the entity the operator chose even
/// after a background poll rebuilds and re-sorts the list underneath it.
/// `key_of` returns `None` for non-selectable rows (e.g. group headers).
pub(crate) fn resolve_row_index<T, K, F>(rows: &[T], key: Option<&K>, key_of: F) -> Option<usize>
where
    K: PartialEq,
    F: Fn(&T) -> Option<K>,
{
    let key = key?;
    rows.iter().position(|r| key_of(r).as_ref() == Some(key))
}

/// A result delivered back to the UI loop from a background task
/// (mod-04). The loop applies it via `apply_job_result` and redraws, so
/// long-running work (remote HTTP) never blocks the render/input path.
pub enum UiJob {
    /// A purge.cc catalog fetch finished — refresh the cache and the open
    /// picker. Carries the owned catalog so the spawned task touches no
    /// `App` state.
    CatalogFetched(crate::lists::catalog::Catalog),
    /// A Settings → restore finished (tui-02). The archive extraction runs on
    /// the blocking pool and the daemon reload on a spawned task, so the event
    /// loop keeps rendering the "restoring…" card throughout; the terminal
    /// outcome comes home through here. Owned `SubmitOutcome` — same rule as
    /// above, the task never touches `App`.
    RestoreFinished(crate::tui::backup_restore_modal::SubmitOutcome),
    /// A Settings → backup finished (tui-14). The exact mirror of
    /// `RestoreFinished`: the tar+gzip runs on the blocking pool, so the event
    /// loop keeps rendering the "backing up…" card throughout.
    ///
    /// `auto_backup` carries the refreshed Settings-tab snapshot, recomputed on
    /// the blocking thread *after* the archive lands. It rides along in the
    /// payload rather than being recomputed here because that refresh is itself
    /// sync filesystem work (readdir + a small JSON read) — running it on the
    /// render thread would put back on the loop exactly what this job took off.
    /// `None` when the blocking task died and the snapshot could not be taken:
    /// the existing view is then left untouched rather than fabricated.
    BackupFinished {
        outcome: crate::tui::backup_restore_modal::SubmitOutcome,
        auto_backup: Option<AutoBackupView>,
    },
}

// ── Top-level app state ─────────────────────────────────────────────────────

pub struct App {
    pub active_leaf: Leaf,
    pub paused: bool,
    pub show_help: bool,
    /// N8 — did the leaf handler recognise the key it was just handed?
    ///
    /// Set **only** by the terminal `_` arm of a per-leaf key handler, read
    /// **only** by the `?`-overlay fall-through in `handle_key`. Nothing
    /// else may consult it: it is meaningful for exactly one keystroke,
    /// between the reset at the top of `handle_key` and the help branch's
    /// check after dispatch.
    ///
    /// **Why a flag and not a `fn is_bound(leaf, key) -> bool`.** N8 needs
    /// two things that pull against each other: a listed key must run its
    /// action and close the overlay, and an unbound key must leave the
    /// overlay open so a typo cannot mutate the tab underneath. Answering
    /// "is this key bound here?" by prediction means a second table of the
    /// bindings, which the spec forbids by name — that is how `?`
    /// advertised a dead Tags verb for three sprints. The live match arms
    /// are the source of truth, and their `_` arm is the one place in the
    /// codebase that already knows the answer. This field is that arm
    /// reporting it, not a copy of it.
    ///
    /// Known imprecision, deliberate: a key swallowed by a *nested* `_`
    /// arm deeper inside a handler reports as handled, so help closes with
    /// nothing visible happening. Narrower than the alternative's failure
    /// mode (a stale table that runs the WRONG action), and it cannot
    /// silently drift out of date.
    pub leaf_key_unhandled: bool,
    pub input_mode: InputMode,
    /// Sprint 45 T3: one-shot `g <letter>` mnemonic dispatch. Set to
    /// `true` after the operator presses `g`; the next event reads the
    /// mnemonic table (`Leaf::from_mnemonic`) and either jumps to the
    /// matching leaf or — on an unknown letter — silently clears the
    /// flag and falls through to the active leaf's normal handler.
    pub pending_goto: bool,

    // Data
    pub daemon_status: Option<DaemonStatus>,
    pub tracking: TrackingData,
    /// Full device view — mapped (from `[[devices]]` config joined with
    /// live stats) and unmapped (observed but never configured). Populated
    /// by the IPC `GetAllDevices` poll on Dashboard and Devices tabs.
    /// `None` before the first successful fetch.
    pub device_view: Option<DeviceViewDto>,
    pub connected: bool,
    /// Transient action feedback + its severity (ui-01), rendered as an
    /// auto-expiring toast over the tab content (§4.62 N1). Set by
    /// `status_ok` / `status_err` / `status_info`; dropped by its TTL on
    /// the tick (`expire_status`), by a keystroke when sticky
    /// (`dismiss_sticky_status`), or explicitly via `clear_status`.
    ///
    /// It no longer lives in the footer: the footer's left slot is the
    /// tab keyboard legend, which is the discovery surface for the whole
    /// screen and must never be traded for an event (§4.62 N4).
    pub last_status: Option<StatusLine>,
    /// Non-fatal message emitted before the TUI started (e.g. "no config
    /// file found, using defaults"). Shown in the footer when no active
    /// error is present so it doesn't get lost in the alt-screen buffer.
    pub startup_warning: Option<crate::cli::config_discovery::DiscoveryWarning>,

    /// Set by a key handler that changed *what should be fetched* rather
    /// than what is displayed, so the render loop polls on the next tick
    /// instead of waiting out the active leaf's interval.
    ///
    /// Paging needs it and filter edits do not: a filter change lands
    /// within one 3 s tick and the operator is still typing, whereas
    /// `PgDn` is a discrete request whose answer is the whole point of
    /// the keystroke. Cleared by the loop that consumes it.
    pub force_poll: bool,

    // Per-tab state
    pub dashboard: DashboardState,
    pub query_log: QueryLogState,
    pub devices: DevicesState,
    pub subnets: SubnetsState,
    pub local_dns: LocalDnsState,
    pub profiles: ProfilesState,
    pub lists: ListsState,
    pub rules: RulesState,
    pub settings: SettingsState,
    pub groups: GroupsState,
    pub labels: LabelsState,
    pub custom_lists: CustomListsState,
    pub file: FileState,
    /// `logs-tab`: the Log Messages viewer's rows, filters and scroll.
    pub logs: LogsState,

    /// Offline view of the on-disk v1 configuration, loaded at TUI
    /// startup and refreshed on `r`. Used by the Subnets tab (list
    /// source), the Resolver modal (build `ProfileResolver` on
    /// demand), and the Devices tab (source-file annotation per row).
    /// `None` if the config doesn't parse — the tabs render a friendly
    /// "load failed" state in that case. S33 addition.
    pub loaded_config: Option<LoadedConfig>,

    /// Sprint 43 T5: scope modal lifecycle. Opened from the Query Log
    /// tab via `a` (allow) / `d` (deny). `Some` while the operator
    /// walks the SN1 menu + SN2 confirm; `None` otherwise.
    pub scope_modal: Option<crate::tui::scope_modal::ScopeModal>,

    /// Sprint 43 T6: one-shot welcome banner shown on the first launch
    /// after an upgrade to a version not yet recorded in
    /// `~/.config/purge-warden/seen_versions`. `Some` with banner
    /// state until the operator dismisses it; the dismissal records
    /// the version on disk so subsequent launches show `None`.
    pub welcome_banner: Option<crate::tui::welcome_banner::WelcomeBanner>,

    /// mod-02: shared with the event-reader thread to pause it across the
    /// Settings-tab `$EDITOR` handoff. While `reader_suspended` is set the
    /// reader stops touching the tty (so the editor owns input cleanly and no
    /// stolen byte replays against the TUI), acking via `reader_parked` once it
    /// has reached the park point. Cloned into `spawn_event_reader`; the `e`
    /// handler toggles them around the blocking editor spawn.
    pub reader_suspended: Arc<AtomicBool>,
    /// mod-02: reader-thread ack for `reader_suspended` — `true` once the reader
    /// has parked and is no longer reading the tty. The editor handoff waits on
    /// this (bounded) before leaving raw mode so no in-flight read consumes a byte.
    pub reader_parked: Arc<AtomicBool>,

    /// Sprint 52: source-IP resolver modal. Opened from any leaf via
    /// the global hotkey `s`; pre-fills from QueryLog/Devices when the
    /// active leaf has a focused row. `None` when closed.
    pub resolver_modal: Option<crate::tui::resolver_modal::ResolverModal>,

    /// S53.3: cached purge.cc catalog snapshot. Populated on the first
    /// `[B]` press; subsequent opens within the 5-min TTL skip the
    /// network round-trip. Lives on `App` (not on `ListsState`) so a
    /// tab refresh / poll doesn't accidentally invalidate it.
    pub catalog_cache: Option<CatalogCache>,
    /// mod-04: sender for background-job results (the catalog fetch). Set
    /// once at startup in `run_app`; `None` in tests and other non-loop
    /// contexts, where the catalog open falls back to the inline await.
    pub job_tx: Option<tokio::sync::mpsc::UnboundedSender<UiJob>>,

    /// §4.11-4b (CS9) — live cluster view (`IpcCommand::ClusterStatus`),
    /// polled on the heartbeat cadence when `[cluster].enabled`. `None` on a
    /// standalone node or while the first poll is in flight. Drives both the
    /// dashboard System-card dot and the Cluster tab.
    #[cfg(feature = "cluster")]
    pub cluster_status: Option<ClusterStatusDto>,
    /// §4.11-4b — Cluster tab roster cursor. Operator-stable selection keyed
    /// by node name (survives roster reordering / stale-eviction).
    #[cfg(feature = "cluster")]
    pub cluster: ClusterState,
}

impl App {
    /// Set a success status (green `✓` toast). ui-01.
    pub fn status_ok(&mut self, text: String) {
        self.last_status = Some(StatusLine {
            severity: StatusSeverity::Ok,
            text,
            shown_at: Instant::now(),
            origin: StatusOrigin::Action,
        });
    }

    /// Set an error / refusal status (red `✕`). ui-01.
    ///
    /// Action-origin: this is the outcome of something the operator did,
    /// so it is sticky until they acknowledge it (N3). Background
    /// pollers must use [`Self::status_err_poll`] instead.
    pub fn status_err(&mut self, text: String) {
        self.last_status = Some(StatusLine {
            severity: StatusSeverity::Error,
            text,
            shown_at: Instant::now(),
            origin: StatusOrigin::Action,
        });
    }

    /// Set an error raised by a background poll rather than by an
    /// operator action. Same red `✕`, different lifetime: it is retired
    /// by [`Self::clear_poll_status`] as soon as a poll succeeds, so a
    /// recovered blip does not leave a permanent false alarm on an idle
    /// dashboard.
    pub fn status_err_poll(&mut self, text: String) {
        self.last_status = Some(StatusLine {
            severity: StatusSeverity::Error,
            text,
            shown_at: Instant::now(),
            origin: StatusOrigin::Poll,
        });
    }

    /// Set a neutral / informational status (muted). ui-01.
    pub fn status_info(&mut self, text: String) {
        self.last_status = Some(StatusLine {
            severity: StatusSeverity::Info,
            text,
            shown_at: Instant::now(),
            origin: StatusOrigin::Action,
        });
    }

    /// Clear the transient status line.
    pub fn clear_status(&mut self) {
        self.last_status = None;
    }

    /// Retire a status raised by a background poll, leaving an operator
    /// action's outcome untouched. Returns `true` when it cleared one.
    ///
    /// Called once at the *start* of `poll_active_leaf`, not in its
    /// success arms. A poll error describes a condition; if the
    /// condition still holds, the failing arm re-raises it later in the
    /// same pass, before anything renders. So the message survives
    /// exactly as long as the failure does, and a recovery retires it
    /// with no keystroke. Clearing per-success-arm instead would let a
    /// later arm's failure be erased by an earlier arm's success,
    /// depending on join order.
    ///
    /// This is the narrow version of the blanket `clear_status()` the
    /// poll arms used to call. The blanket form is what made the poll
    /// cadence the de-facto message lifetime (B2), and it would still
    /// wipe an action error after 2s on Dashboard — the loss N3 forbids.
    pub fn clear_poll_status(&mut self) -> bool {
        if self
            .last_status
            .as_ref()
            .is_some_and(|s| s.origin == StatusOrigin::Poll)
        {
            self.last_status = None;
            return true;
        }
        false
    }

    /// §4.62 N2 — the status the toast renderer should paint as of
    /// `now`, or `None` if it has expired. Read-only: the render path
    /// takes `&App`, so expiry there is a *filter*, not a mutation.
    /// [`Self::expire_status`] does the actual dropping on the tick.
    pub fn visible_status_at(&self, now: Instant) -> Option<&StatusLine> {
        self.last_status.as_ref().filter(|s| !s.is_expired_at(now))
    }

    /// [`Self::visible_status_at`] against the current clock.
    pub fn visible_status(&self) -> Option<&StatusLine> {
        self.visible_status_at(Instant::now())
    }

    /// §4.62 N2 — drop the status if it has outlived its TTL as of
    /// `now`. Returns `true` when something was actually cleared.
    ///
    /// The bool matters: the caller is the 33 ms tick, and repainting
    /// unconditionally would hold the render loop at ~30 FPS forever on
    /// a box that is also serving DNS.
    pub fn expire_status_at(&mut self, now: Instant) -> bool {
        if self
            .last_status
            .as_ref()
            .is_some_and(|s| s.is_expired_at(now))
        {
            self.last_status = None;
            return true;
        }
        false
    }

    /// [`Self::expire_status_at`] against the current clock.
    pub fn expire_status(&mut self) -> bool {
        self.expire_status_at(Instant::now())
    }

    /// §4.62 N3 — dismiss a sticky (`Error`) status. Called for every
    /// key the operator presses; `Ok`/`Info` are left to their TTL so a
    /// success toast is not stolen by an unrelated arrow key.
    ///
    /// N6: this never consumes the keystroke. The caller runs it as a
    /// side effect and then dispatches the key normally, so the toast
    /// surface is structurally incapable of gating input.
    pub fn dismiss_sticky_status(&mut self) -> bool {
        if self
            .last_status
            .as_ref()
            .is_some_and(|s| s.severity.ttl().is_none())
        {
            self.last_status = None;
            return true;
        }
        false
    }

    /// The current status text, regardless of severity. Convenience for
    /// readers (tests, render helpers) that only need the message.
    pub fn status_text(&self) -> Option<&str> {
        self.last_status.as_ref().map(|s| s.text.as_str())
    }

    /// §4.11-4b — the single runtime gate for every cluster TUI surface
    /// (dashboard dot, Cluster tab nav, cluster poll). `true` only when built
    /// with the `cluster` feature AND the loaded config has
    /// `[cluster].enabled = true`; always `false` on a default build.
    pub fn cluster_visible(&self) -> bool {
        #[cfg(feature = "cluster")]
        {
            self.loaded_config
                .as_ref()
                .is_some_and(|lc| lc.config.cluster.enabled)
        }
        #[cfg(not(feature = "cluster"))]
        {
            false
        }
    }

    pub fn new() -> Self {
        Self {
            active_leaf: Leaf::Dashboard,
            paused: false,
            show_help: false,
            leaf_key_unhandled: false,
            input_mode: InputMode::Normal,
            pending_goto: false,
            daemon_status: None,
            tracking: TrackingData::default(),
            device_view: None,
            connected: false,
            last_status: None,
            startup_warning: None,
            dashboard: DashboardState::default(),
            force_poll: false,
            query_log: QueryLogState::default(),
            devices: DevicesState::default(),
            subnets: SubnetsState::default(),
            local_dns: LocalDnsState::default(),
            profiles: ProfilesState::default(),
            lists: ListsState::default(),
            rules: RulesState::default(),
            settings: SettingsState::default(),
            groups: GroupsState::default(),
            labels: LabelsState::default(),
            custom_lists: CustomListsState::default(),
            file: FileState::default(),
            logs: LogsState::default(),
            loaded_config: None,
            scope_modal: None,
            welcome_banner: None,
            reader_suspended: Arc::new(AtomicBool::new(false)),
            reader_parked: Arc::new(AtomicBool::new(false)),
            resolver_modal: None,
            catalog_cache: None,
            job_tx: None,
            #[cfg(feature = "cluster")]
            cluster_status: None,
            #[cfg(feature = "cluster")]
            cluster: ClusterState::default(),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

// ── Cluster tab state (§4.11-4b) ────────────────────────────────────────────
//
// Read-only roster view. The cursor is operator-stable: `selected_name`
// carries the focused node's display name (roster `RosterEntryDto.name`), so
// the selection survives the heartbeat re-sampling the roster, stale-eviction
// reordering, or a peer dropping out. The renderer resolves it back to a row
// index every frame (same idiom as `SubnetsState.selected_id`). Empty on a
// secondary (no roster) — that view renders the single sync-state card.

#[cfg(feature = "cluster")]
#[derive(Debug, Clone, Default)]
pub struct ClusterState {
    /// Focused node's name (the single source of truth for the roster cursor;
    /// `None` until the first key seeds it). The renderer resolves it back to
    /// a row index each frame and builds a transient `TableState` from it, so
    /// the highlight follows the node even when the roster reorders.
    pub selected_name: Option<String>,
}

// ── Subnets tab state (S33 + S51) ──────────────────────────────────────────
//
// S33 shipped a single read-only TableState. S51 grew the tab into a
// master/detail layout: the master list mixes configured subnets with
// auto-discovered candidate buckets, so the cursor now tracks both
// shapes. `selected_id` is the operator-stable selection key — it
// survives sort changes and refreshes, where a row index would not.

#[derive(Debug, Clone, Default)]
pub struct SubnetsState {
    pub table_state: TableState,
    /// Operator's stable selection key. For a configured subnet this
    /// is the entity id; for a discovered candidate it's the canonical
    /// CIDR string (e.g. `10.99.0.0/24`). `None` until the first
    /// render places the cursor on an existing row.
    pub selected_id: Option<String>,
    /// Active modal lifecycle (Add / Edit / Delete). `None` while the
    /// tab is in normal navigation mode; `Some` while the operator is
    /// editing a form, confirming a removal, or has just received the
    /// submit outcome and not yet dismissed the modal. S51 T3.
    pub modal: Option<crate::tui::subnet_modal::SubnetModal>,
}

// ── Profiles tab state (§4.26 Phase 2) ──────────────────────────────────────
//
// Profile Editor v1 — the 4th Network leaf (D3). Offline-backed
// master/detail tab: the master list reads `[profiles]` from
// `app.loaded_config`, the side-card drills into the focused profile.
// Add / Edit / Delete drive the Phase 1 IPC verbs (`ProfileCreate` /
// `ProfileUpdate` / `ProfileDelete`) directly — no new daemon surface.
// Structurally a clone of `SubnetsState` minus the candidate-discovery
// machinery: `selected_id` is the operator-stable selection key (the
// profile's id, its `BTreeMap` key in `ConfigV1::profiles`).

#[derive(Debug, Clone, Default)]
pub struct ProfilesState {
    pub table_state: TableState,
    /// Operator-stable selection key — the profile's id. `None` until
    /// the first render / keystroke seeds the cursor on an existing row.
    pub selected_id: Option<String>,
    /// Active modal lifecycle (Add / Edit / Delete). `None` while the
    /// tab is in normal navigation mode.
    pub modal: Option<crate::tui::profile_modal::ProfileModal>,
}

// ── Local DNS tab state (S44 T3) ────────────────────────────────────────────

// N6 (2026-08-24) removed `LocalDnsPanel` from this module.
//
// It used to sit here, doc-commented *"Cycles via `Tab` (forward) /
// `BackTab` (backward)"* — which was **already false** when N6 found it:
// `ldns_04_tab_still_cycles_leaf` pins `Tab` as the global leaf cycle, and
// the panel switch had been `o` since rev-2606 §11. A comment describing a
// key binding that a test forbids is the shape of rot this wave keeps
// finding; recorded here rather than deleted silently.
//
// There is no panel to switch any more. The two stacked tables are one
// list with non-selectable group headers, Devices-style, so `o`, `n` and
// `N` are unbound and `↑`/`↓` walk every record in both scopes.

/// Local DNS tab state. One cursor over the unified record list.
///
/// The `a` / `d`|`Delete` / `e` keypresses open modal-driven mutations
/// against `cli::commands::local_dns::add_inner` / `remove_inner` (R7
/// single-seat); the open modal lives on [`Self::modal`].
#[derive(Debug, Clone, Default)]
pub struct LocalDnsState {
    /// Visual cursor into the row vector built by
    /// [`tabs::local_dns::build_rows`](crate::tui::tabs::local_dns::build_rows),
    /// which interleaves group headers with records. Headers are not
    /// selectable; the handler skips them.
    pub table_state: TableState,
    /// Operator-stable selection key — `(scope, domain)`, the same tuple
    /// the audit side-card already addresses a record by.
    ///
    /// The visual index is not the identity: a config reload, an add, or
    /// a delete reshuffles the rows, and an index-only cursor silently
    /// re-points at whatever moved into that slot. Same reasoning as
    /// `SubnetsState::selected_id` / `ProfilesState::selected_id`.
    ///
    /// Scope is the audit-log spelling — `"global"` or `"profile:<id>"` —
    /// so it round-trips through
    /// [`tabs::local_dns::row_key`](crate::tui::tabs::local_dns::row_key)
    /// without a second vocabulary. Domain is stored lowercased: domains
    /// are case-normalised at ingestion (design rule 3) but the on-disk
    /// record need not be, and a key that disagrees with itself on case
    /// loses the cursor on reload.
    pub selected_id: Option<(String, String)>,
    /// Cached snapshot of `(scope, domain) → hits` from the daemon.
    /// `None` before the first IPC poll wires the field through (T3:
    /// the wire is not yet implemented; field is reserved so a
    /// follow-up adds the IpcCommand without struct churn).
    #[allow(dead_code)]
    pub hits_snapshot: Option<Vec<(String, String, u64)>>,
    /// Active modal lifecycle (Add / Remove / Edit). `None` when the
    /// tab is in normal navigation mode; `Some` while the operator is
    /// editing a form, confirming a removal, or has just received the
    /// submit outcome and not yet dismissed the modal.
    pub modal: Option<crate::tui::local_dns_modal::LocalDnsModal>,
    /// Open audit-history side-card (`s44-tui-modal-audit-history`).
    /// `None` while the side-card is closed; `Some` carries the loaded
    /// audit slice for the focused row. Refreshed on Enter (open) and on
    /// any cursor move while open so the card follows the cursor; cleared
    /// on Esc.
    pub audit_view: Option<LocalDnsAuditView>,
}

/// Loaded audit-history slice rendered by the Local DNS side-card.
///
/// Carries the `(scope_tag, target_id, domain)` tuple the slice was
/// loaded against alongside the actual records, so the renderer can
/// detect a stale view (focused row moved) without re-reading the audit
/// log on every frame.
#[derive(Debug, Clone)]
pub struct LocalDnsAuditView {
    /// Audit `scope` field — `"global"` or `"profile"`.
    pub scope_tag: String,
    /// Audit `target_id` field — `"global"` or the profile id.
    pub target_id: String,
    /// Lowercased domain the slice was filtered against.
    pub domain: String,
    /// Newest-first matches (capped at 10 by the loader). Empty when no
    /// audit history exists for the focused record yet — the renderer
    /// shows a friendly empty-state line in that case.
    pub entries: Vec<crate::config::audit::AuditRecord>,
}

// ── Lists tab state (S43 T2) ────────────────────────────────────────────────

/// Sprint 43 T2: state for the new Lists visibility tab.
///
/// Populated on every `Leaf::Lists` poll cycle (default 30 s, see
/// `POLL_LISTS` in `tui::mod`). `entries` is the raw payload from
/// `IpcCommand::BlocklistStats { source_id: None }`; `table_state`
/// drives `↑`/`↓` row selection. `Enter` opens the Sprint 53
/// [`EditListModal`] (60×22 centered) so the operator can edit every
/// metadata field or delete the list with a typed-id confirm — the
/// pre-S53 split-pane drill-down was removed (decision L8).
/// The reverse-lookup "used by profiles" annotation is computed at
/// render time against the cached `app.loaded_config` — no separate
/// IPC call.
///
/// Sprint 50 T4: post-grouping refactor, the cursor `table_state.selected()`
/// indexes into the grouped row vector built by
/// `tabs::lists::build_grouped_rows` (which interleaves category headers
/// with list rows), NOT into `entries` directly. The ↑/↓ handler skips
/// header rows via `tabs::lists::next_selectable_index`.
///
/// rev-2606 §11 (mod-06 / lists-08b): the `[c]` create-category, `[m]`
/// move-category, and `[p]` list↔profile assignment modals were
/// unmounted — categories are gone in v2 and tag assignment ships via
/// the edit-modal chip picker + Tags tab; `[K]` still toggles kind
/// directly without a modal.
///
/// Sprint 53: ENTER on a list row now opens the [`EditListModal`] (60×22
/// centered overlay) where every metadata field is editable in-place
/// and a typed-id Delete confirm tears the list out of the catalog. The
/// pre-S53 `show_detail` split-pane was removed — the modal supersedes
/// it (decision L8 in `_docs/features/lists_edit_modal.md`).
#[derive(Debug, Clone, Default)]
pub struct ListsState {
    pub table_state: TableState,
    /// rev-2607: operator's stable selection key — the row's canonical id,
    /// or its source string when it has none (see
    /// [`crate::tui::tabs::lists::row_key`]). `entries` is rewritten by the
    /// 30 s Lists poll *and* by the Dashboard poll arm, so a bare
    /// `TableState` index drifts past the end — or onto a *different* list
    /// when one above the cursor disappears — with no keypress at all.
    /// Reconciled to a row index before every draw
    /// (`reconcile_lists_selection`); `table_state` is the visual cache kept
    /// in step with it. `None` until the first row is seeded.
    pub selected_id: Option<String>,
    pub entries: Vec<BlocklistStatusDto>,
    /// Query-Log-style filter card. `filter_text` is the committed
    /// case-insensitive substring matched over list id / display name /
    /// source URL (focused with `/`, `None` = no text filter);
    /// `kind_filter` is the all/block/allow chip cycled with `f`. Both
    /// applied client-side in [`crate::tui::tabs::lists::build_grouped_rows`].
    pub filter_text: Option<String>,
    pub kind_filter: ListsKindFilter,
    pub edit_modal: Option<EditListModal>,
    /// Sprint 53 follow-up — purge.cc catalog picker opened by the
    /// `[B]` hotkey on the Lists tab. Operator browses the curated
    /// catalog (offline-safe via [`crate::lists::catalog::Catalog::fallback`])
    /// as a table, toggles the ON column on any number of rows, and
    /// commits the lot with one Save: a single `upsert`-per-row pass over
    /// one TOML document, one validated write, one reload.
    pub catalog_picker: Option<CatalogPickerModal>,
    /// The `K` hotkey's half of the unsigned-allow consent gate.
    ///
    /// A separate slot rather than a mode on `edit_modal`: the hotkey
    /// fires straight off the table with no form open, and borrowing the
    /// editor's state machine would mean synthesising an `EditListModal`
    /// whose buffers nobody filled — every one of which the save path
    /// would then be entitled to write. The two hosts share the notice
    /// builder and the strings, not the state.
    pub kind_confirm: Option<KindConfirm>,
}

/// Open-state for the `K`-hotkey consent gate.
///
/// Deliberately minimal. The commit path is
/// [`crate::cli::commands::blocklists::run_set_kind_with_ack`], which
/// re-reads the file and re-runs both gates for itself — so this holds
/// what the operator is typing and nothing that could go stale.
#[derive(Debug, Clone)]
pub struct KindConfirm {
    /// Canonical `[[blocklists]].id` the operator must type back.
    pub list_id: String,
    /// What they have typed so far.
    pub typed: String,
    /// Mismatch message. Displaces the notice's hint, so it costs no row.
    pub error: Option<String>,
}

/// Open-state for the purge.cc catalog picker. Built at modal-open time
/// from a `Catalog` snapshot crossed against the live
/// `loaded_config.blocklists`, so each row's *original* state is stable
/// across the modal's lifetime (no flicker when a poll lands) and the
/// save path has a fixed baseline to diff against.
///
/// The rows are a flat table now. The predecessor interleaved section
/// headers (`── Domain lists (16) ──`, `── Rule packs (AdGuard, 17) ──`)
/// because the catalog carried two channels; `rules.purge.cc` was retired
/// and `lists.purge.cc/index.json` is the only source, so there is one
/// group and a header for it would be chrome naming the whole table.
#[derive(Debug, Clone)]
pub struct CatalogPickerModal {
    pub rows: Vec<CatalogPickerRow>,
    pub table_state: TableState,
    /// Which region owns the keyboard: the row table or one of the two
    /// footer actions.
    pub focus: CatalogPickerFocus,
    pub error_message: Option<String>,
    pub status_message: Option<String>,
    /// `true` while the batch write + reload is in flight; blocks
    /// re-entrant Save presses.
    pub submitting: bool,
}

impl CatalogPickerModal {
    /// Rows whose staged state differs from the state captured at modal
    /// open — i.e. what Save would write. Drives the pending-changes
    /// counter and the "nothing to do" short-circuit.
    pub fn dirty_rows(&self) -> impl Iterator<Item = &CatalogPickerRow> {
        self.rows.iter().filter(|r| r.is_dirty())
    }

    /// How many rows Save would write.
    pub fn dirty_count(&self) -> usize {
        self.dirty_rows().count()
    }
}

/// Which region of the catalog picker owns the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatalogPickerFocus {
    /// The row table — `↑↓`/`jk` move, `Space` toggles ON.
    #[default]
    Table,
    /// The footer `Save` action — `Enter` commits.
    Save,
    /// The footer `Cancel` action — `Enter` closes without writing.
    Cancel,
}

/// What a catalog row looked like in `[[blocklists]]` when the modal
/// opened. Save diffs the staged state against **this**, never against a
/// bare boolean: "subscribed but disabled" and "not subscribed" both
/// render an unticked box, so a diff that lost the distinction would
/// either silently no-op or add a duplicate entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogRowState {
    /// No `[[blocklists]]` entry shares this catalog URL.
    NotSubscribed,
    /// An entry exists; `enabled` is its current flag.
    Subscribed { enabled: bool },
}

impl CatalogRowState {
    /// Whether a `[[blocklists]]` entry exists for this row at all.
    pub fn is_subscribed(&self) -> bool {
        matches!(self, CatalogRowState::Subscribed { .. })
    }

    /// The ON-column value this state renders as: subscribed **and**
    /// enabled.
    pub fn is_on(&self) -> bool {
        matches!(self, CatalogRowState::Subscribed { enabled: true })
    }
}

/// One catalog entry, plus the staged edits the operator has made to it
/// and the baseline those edits are diffed against.
#[derive(Debug, Clone)]
pub struct CatalogPickerRow {
    /// Catalog id form `"<scope>/<topic>"` (e.g. `"privacy/ads"`).
    pub catalog_id: String,
    /// Canonical kebab-case id used for the `[[blocklists]]` entry
    /// (e.g. `"privacy-ads"`). For an already-subscribed row this is the
    /// **existing** entry's id, so Save upserts it instead of creating a
    /// twin under a derived name.
    pub canonical_id: String,
    pub url: String,
    /// Human label from the catalog (`name`), e.g. `"DoH Resolvers"`.
    /// Written as `display_name` on a newly-created entry.
    pub display_name: String,
    /// Catalog `scope` — the SCOPE column and the primary sort key.
    pub scope: String,
    /// Catalog `topic` — the TOPIC column. Empty for a scope-only id.
    pub topic: String,
    /// Catalog metadata domain count. **`0` means "not reported"**, not
    /// "empty list": [`crate::lists::catalog::Catalog::fallback`] builds
    /// every entry with `entries: 0`, so the ENTRIES column renders `—`
    /// rather than a zero an offline operator would read as a fact.
    pub entry_count: u64,
    /// Catalog `updated_at`, RFC 3339. Empty for the offline fallback —
    /// the UPDATED column renders `—` for it.
    pub updated_at: String,
    /// State of this catalog entry in `[[blocklists]]` when the modal
    /// opened. The Save diff's baseline.
    pub original: CatalogRowState,
    /// Operator's staged ON value. Seeded from `original.is_on()`.
    pub staged_enabled: bool,
    /// Operator's staged direction. Seeded from the existing entry's
    /// `base`, else [`BlocklistBase::Deny`].
    ///
    /// **Read-only in the UI today** — no key mutates it. The column
    /// renders it and Save writes from this field rather than a
    /// constant, so making the cell interactive is a key binding, not a
    /// restructure. `base = allow` on a catalog row is refused by the
    /// validator regardless (`ALLOW_LIST_REQUIRES_LOCAL_TRUST`: an
    /// allow-direction list needs `trust = local`, which only a local
    /// file import can supply).
    pub staged_kind: BlocklistBase,
    /// Wire format the save path writes as `format = "…"`. `Domains` for
    /// every `lists.purge.cc` entry today; carried per-row so an index
    /// that starts declaring `hosts` keeps parsing correctly.
    pub format: BlocklistFormat,
}

impl CatalogPickerRow {
    /// True when Save would write this row.
    pub fn is_dirty(&self) -> bool {
        self.staged_enabled != self.original.is_on()
    }
}

/// Cached purge.cc catalog snapshot stored on `App` so subsequent
/// `[B]` openings within the same TUI session don't re-fetch on every
/// keystroke. TTL is intentionally short (5 minutes): operators may
/// add lists outside the TUI session, and we want the picker to reflect
/// upstream catalog updates without forcing a TUI restart.
pub struct CatalogCache {
    pub fetched_at: std::time::Instant,
    pub catalog: crate::lists::catalog::Catalog,
}

// ── Sprint 53 — Lists tab edit modal ───────────────────────────────────────
//
// `EditListModal` carries the buffers the operator types into while a 60×22
// centered modal is open; submit reuses the S35/S36/S50 write pipeline
// (`cli::commands::target::*` + `cli::commands::ipc_reload::attempt_reload`)
// verbatim, so no new write helpers exist. Two-step Delete with typed-id
// confirm acts as a deliberation gate; `validate_or_revert` is the
// referential-integrity guardrail that rolls the file back when removing
// the list would dangle a profile or rule reference.
//
// L1 — `id` is read-only (immutable in schema). L2 — `trust` is read-only
// (W2.1 re-validation deferred). See `_docs/features/lists_edit_modal.md` §5.

/// Open-state for a Sprint 53 list edit modal. Built from the focused
/// row by [`crate::tui::tabs::lists::build_edit_modal_for`]. The buffers
/// hold local edits until `Ctrl+S` commits via the shared write pipeline,
/// or `Esc` discards them.
#[derive(Debug, Clone)]
pub struct EditListModal {
    /// Stable list id captured at modal open. Read-only in the modal
    /// (L1) — every save / delete uses this id to find the row in the
    /// `[[blocklists]]` array.
    pub blocklist_id: String,
    /// Edit vs. typed-id confirm screen. `Esc` from `ConfirmDelete` falls
    /// back to `Edit` (no destructive action).
    pub mode: EditModalMode,

    // Edit-mode buffers (one per editable field).
    pub display_name: String,
    pub url: String,
    pub nature: BlocklistBase,
    pub enabled: bool,
    /// Sprint C T5 of `lists_categories_v2`: operator opted out of the
    /// §6.1 gate-3 reachability probe via the modal's advanced
    /// affordance. CLI `--skip-head-check` is the symmetric path. The
    /// catalog subscribe flow always sets this to `true` since rows
    /// are pre-validated by the catalog publisher.
    pub skip_head_check: bool,
    pub interval: IntervalChoice,
    /// Custom interval buffer — populated only when `interval ==
    /// IntervalChoice::Custom`. Numeric string the operator types in.
    pub interval_custom_buf: String,
    pub format: BlocklistFormat,
    /// Empty string means "no auth_token_ref" — saved as `None` in the
    /// schema entry. Non-empty saves as `Some(String)`.
    pub auth_token_ref: String,

    /// Snapshot of the blocklist as it was at modal open. Lets the
    /// renderer label read-only fields (`trust`) and lets the save flow
    /// detect "no-op save" or rebuild fields the modal does not edit.
    pub original: Blocklist,

    // UI state.
    pub focus: EditField,
    /// SOURCE-section Advanced panel. Collapsed (`false`, the open
    /// default) hides Format / Interval / AuthTokenRef from BOTH the
    /// render and the Tab cycle. Toggled by Enter/→ while
    /// `focus == EditField::Advanced`.
    pub advanced_expanded: bool,
    pub error_message: Option<String>,
    pub status_message: Option<String>,
    /// `true` while the save / delete IPC + write is in flight; blocks
    /// re-entrant submits, mirroring the S43 T3 assignment-modal pattern.
    pub submitting: bool,

    /// The operator typed this list's id into the
    /// [`EditModalMode::ConfirmUnsignedAllow`] stage during **this**
    /// modal session, accepting that a remote unsigned publisher can
    /// unblock any domain it adds.
    ///
    /// Deliberately not seeded from `original.accept_unsigned_allow`:
    /// this field means "asked and answered here", and the save path ORs
    /// it with the file's own declaration rather than conflating the
    /// two. A consent already in the TOML is preserved because it was
    /// declared, not because this session declared it — and `Esc` out of
    /// the confirm must leave a previously-consenting list exactly as it
    /// was.
    pub consent_declared: bool,
}

/// Three-screen state machine for the list edit modal. `Edit` is the
/// default rendering mode for an existing `[[blocklists]]` entry (every
/// editable buffer + a Delete button). `ConfirmDelete` swaps the body
/// to a typed-id input — only an exact match commits the destructive
/// op (L5). `Promote` is the orphan-source flow added after S53: the
/// row is in `[lists].sources` but has no `[[blocklists]]` entry, so
/// `id` becomes editable, `url` is pre-filled when the source is itself
/// a URL, and Ctrl+S creates a new v1 entry + removes the legacy source
/// string in one shared reload.
#[derive(Debug, Clone)]
pub enum EditModalMode {
    /// Default mode — buffers editable, focus cycles via Tab / Shift-Tab.
    Edit,
    /// Typed-id confirm screen reached via Tab → Delete → Enter. The
    /// buffer holds whatever the operator has typed so far; only
    /// `typed == EditListModal::blocklist_id` permits the destructive
    /// step on Enter. Mismatch returns to `Edit` with a frozen-string
    /// error in the footer.
    ConfirmDelete { typed: String },
    /// Typed-id consent screen, reached from `Ctrl+S` when the save
    /// would make this a `base = allow` list on a source warden cannot
    /// verify. Same shape as [`Self::ConfirmDelete`] and the same bar,
    /// for a reason: deleting a list costs the operator one list, while
    /// an unsigned allow-list lets whoever controls the URL unblock any
    /// domain they add to it, at every refresh, with nothing on screen
    /// afterwards to mark the moment it was granted.
    ///
    /// `Esc` returns to `Edit` with `consent_declared` untouched. Only
    /// `typed == EditListModal::blocklist_id` on `Enter` sets it.
    ConfirmUnsignedAllow { typed: String },
    /// Promote-orphan mode. `source` is the raw string that lives in
    /// `[lists].sources` and that the save flow must remove after the
    /// new v1 entry lands. The Tab cycle starts on `EditField::ListId`
    /// (the operator must pick a canonical id) and the Delete button at
    /// the end of the cycle is repurposed as a "discard source"
    /// shortcut — Enter on it removes the orphan from `[lists].sources`
    /// without creating a v1 entry.
    Promote { source: String },
    /// Add-from-scratch mode opened by the `[a]` hotkey on the Lists
    /// tab. All fields start blank, focus lands on `EditField::ListId`,
    /// and Ctrl+S runs the same `run_add` pipeline as Promote — minus
    /// the source-removal step (there is no orphan source to clean
    /// up). The bottom-row Delete-button focus stays in the cycle but
    /// renders as "Cancel" so the operator has an explicit Tab-target
    /// for "back out without saving" alongside the global Esc.
    Add,
}

/// Field-focus enumeration for `Tab` / `Shift-Tab` cycling. Read-only
/// fields in Edit mode (`id`, `trust`) are skipped via the mode-aware
/// [`Self::next_in`] / [`Self::prev_in`] helpers — `id` becomes
/// focusable in `Promote` mode where the operator must pick the
/// canonical id; `trust` stays read-only everywhere (W2.1 re-validation
/// deferred). Mirrors Devices Rule D7 (locked fields skipped in Tab
/// navigation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    /// Promote-only — operator picks the canonical `[[blocklists]].id`.
    /// In Edit mode this variant is never reached because `EDIT_ORDER`
    /// excludes it.
    ListId,
    DisplayName,
    Url,
    /// SOURCE-section "▸ Advanced" collapse toggle. Enter/→ flips
    /// [`EditListModal::advanced_expanded`], revealing / hiding Format,
    /// Interval and AuthTokenRef. Always in the cycle; the three fields
    /// it governs are in the cycle only while expanded.
    Advanced,
    Nature,
    Enabled,
    Interval,
    Format,
    AuthTokenRef,
    /// Button-row destructive action. In Edit mode `Enter` here flips
    /// `mode` into `ConfirmDelete`. In Promote mode the same focus is
    /// repurposed as a "discard orphan source" shortcut (Enter removes
    /// the source from `[lists].sources` without creating a v1 entry).
    /// Absent from the cycle in Add mode — nothing to delete.
    DeleteButton,
    /// Button-row "Cancel" — `Enter` closes the modal, discarding
    /// buffers (same effect as Esc, reachable by Tab).
    Cancel,
    /// Button-row "Save" — `Enter` submits (same effect as Ctrl+S).
    Save,
}

impl EditField {
    /// The focus cycle for a given `(mode, advanced_expanded)`. Read-only
    /// rows (`ListId` in Edit, `trust` everywhere) never appear. `ListId`
    /// leads in Add / Promote where the operator must pick the canonical
    /// id. The SOURCE `Advanced` toggle is always present; the three
    /// fields it governs (Format, Interval, AuthTokenRef) appear only
    /// while `advanced_expanded`. The button row (Delete, Cancel, Save)
    /// anchors the tail — Delete is dropped in Add mode (nothing to
    /// delete). Variant-A modal-ecosystem redesign; supersedes the old
    /// static `ORDER` / `PROMOTE_ORDER` constants.
    pub fn cycle(mode: &EditModalMode, advanced_expanded: bool) -> Vec<EditField> {
        let mut v: Vec<EditField> = Vec::with_capacity(13);
        // IDENTITY
        if matches!(mode, EditModalMode::Promote { .. } | EditModalMode::Add) {
            v.push(EditField::ListId);
        }
        v.push(EditField::DisplayName);
        // SOURCE
        v.push(EditField::Url);
        v.push(EditField::Advanced);
        if advanced_expanded {
            v.push(EditField::Format);
            v.push(EditField::Interval);
            v.push(EditField::AuthTokenRef);
        }
        // FILTERING
        v.push(EditField::Nature);
        v.push(EditField::Enabled);
        // BUTTON ROW
        if !matches!(mode, EditModalMode::Add) {
            v.push(EditField::DeleteButton);
        }
        v.push(EditField::Cancel);
        v.push(EditField::Save);
        v
    }

    /// Next focus in the `(mode, advanced_expanded)` cycle. A focus no
    /// longer in the cycle (e.g. an Advanced field the instant the panel
    /// collapses) falls back to the first entry.
    pub fn next_in(self, mode: &EditModalMode, advanced_expanded: bool) -> EditField {
        let order = Self::cycle(mode, advanced_expanded);
        let i = order.iter().position(|f| *f == self).unwrap_or(0);
        order[(i + 1) % order.len()]
    }

    pub fn prev_in(self, mode: &EditModalMode, advanced_expanded: bool) -> EditField {
        let order = Self::cycle(mode, advanced_expanded);
        let len = order.len();
        let i = order.iter().position(|f| *f == self).unwrap_or(0);
        order[(i + len - 1) % len]
    }

    /// Edit-mode, collapsed-panel convenience wrappers — the modal's
    /// state on open. New call sites that know the live modal state
    /// should call [`Self::next_in`] / [`Self::prev_in`] directly.
    pub fn next(self) -> EditField {
        self.next_in(&EditModalMode::Edit, false)
    }

    pub fn prev(self) -> EditField {
        self.prev_in(&EditModalMode::Edit, false)
    }
}

/// Update-interval picker — six fixed presets plus a `Custom` slot that
/// reveals a numeric input. The schema accepts any `u32` hours; the
/// presets are pure UX scaffolding (L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntervalChoice {
    H1,
    H2,
    H6,
    H12,
    H24,
    H48,
    Custom,
}

impl IntervalChoice {
    pub const ORDER: [IntervalChoice; 7] = [
        IntervalChoice::H1,
        IntervalChoice::H2,
        IntervalChoice::H6,
        IntervalChoice::H12,
        IntervalChoice::H24,
        IntervalChoice::H48,
        IntervalChoice::Custom,
    ];

    /// Map a stored `u32` hours value back to a preset (or fall through
    /// to `Custom`). Used by the modal builder to pre-fill the picker
    /// from the existing `Blocklist.update_interval_hours`.
    pub fn from_hours(h: u32) -> IntervalChoice {
        match h {
            1 => IntervalChoice::H1,
            2 => IntervalChoice::H2,
            6 => IntervalChoice::H6,
            12 => IntervalChoice::H12,
            24 => IntervalChoice::H24,
            48 => IntervalChoice::H48,
            _ => IntervalChoice::Custom,
        }
    }

    /// Preset hours for the fixed slots; `None` for `Custom` (caller
    /// reads the operator-supplied buffer instead).
    pub fn hours(self) -> Option<u32> {
        match self {
            IntervalChoice::H1 => Some(1),
            IntervalChoice::H2 => Some(2),
            IntervalChoice::H6 => Some(6),
            IntervalChoice::H12 => Some(12),
            IntervalChoice::H24 => Some(24),
            IntervalChoice::H48 => Some(48),
            IntervalChoice::Custom => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            IntervalChoice::H1 => "1h",
            IntervalChoice::H2 => "2h",
            IntervalChoice::H6 => "6h",
            IntervalChoice::H12 => "12h",
            IntervalChoice::H24 => "24h",
            IntervalChoice::H48 => "48h",
            IntervalChoice::Custom => "Custom…",
        }
    }

    pub fn next(self) -> IntervalChoice {
        let i = Self::ORDER.iter().position(|c| *c == self).unwrap_or(0);
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> IntervalChoice {
        let len = Self::ORDER.len();
        let i = Self::ORDER.iter().position(|c| *c == self).unwrap_or(0);
        Self::ORDER[(i + len - 1) % len]
    }
}

// ── Rules tab state (S43 T2 placeholder) ────────────────────────────────────

/// Sprint 43 T2: state for the new Rules placeholder tab.
///
/// Read-only in T2 — no admin_rules data source exists yet (T5 wires
/// the `[[admin_rules]]` schema + `e/d` keybindings). For now the
/// state carries only the navigation cursor; the renderer surfaces an
/// empty-state explainer that points the operator at T5's incoming
/// commands.
#[derive(Debug, Clone, Default)]
pub struct RulesState {
    pub table_state: TableState,
    /// rev-2607: operator's stable selection key — the `[[admin_rules]]`
    /// id. The rows are rebuilt from `loaded_config` on every reload
    /// (including this tab's own delete), so a bare `TableState` index can
    /// point past the end, or at a *different* rule when one above the
    /// cursor is removed. Resolved against the **filtered** row vec — the
    /// one the table paints and `build_rule_edit_modal_for` indexes — before
    /// every draw (`reconcile_rules_selection`). `None` until seeded.
    pub selected_id: Option<String>,
    /// Filter chip cycle: All → Allow → Deny → All. Cycled with `f`.
    /// S53.4 promotes this from a placeholder chip to a live filter
    /// applied against [`Self::entries`].
    pub filter: RulesFilter,
    /// S53.4 — joined view of `[[admin_rules]]` master entries with
    /// reverse-indexed scope (which device/profile points at each id)
    /// and parsed action/domain extracted from the AdGuard rule
    /// string. Rebuilt on every render from `loaded_config` (cheap
    /// for the typical <50-rule deployment, no caching).
    pub entries: Vec<RuleRowMeta>,
    /// Query-Log-style text search (focused with `/`, `None` = no text
    /// filter). Committed case-insensitive substring matched over rule
    /// id / domain / raw rule; combined (AND) with [`Self::filter`] (the
    /// action chip). Applied client-side in `render_table` +
    /// `visible_rule_rows_count`.
    pub filter_text: Option<String>,
    /// S53.5 — open edit modal lifecycle. `Some` while the operator is
    /// editing/deleting a rule from the Rules tab; `None` otherwise.
    pub edit_modal: Option<RuleEditModal>,
    /// wave2/rules-add-key — open add-rule modal lifecycle. `Some` while
    /// the operator is creating a new rule via `[a]`; `None` otherwise.
    /// Mirrors `edit_modal`'s Option-lifecycle contract.
    pub add_modal: Option<crate::tui::rule_add_modal::RuleAddModal>,
}

/// Open-state for the Rules tab edit modal (S53.5). The modal lets
/// the operator flip Allow ↔ Deny, move the rule between scopes
/// (Default / Profile / Device), or delete it via typed-id confirm.
/// The rule string itself is **read-only** — to change the domain the
/// operator deletes + recreates via Query Log or CLI (the current
/// design intentionally avoids in-place edit because a typo in the
/// AdGuard syntax would silently bypass the validator).
#[derive(Debug, Clone)]
pub struct RuleEditModal {
    /// Snapshot of the row being edited — id is immutable, raw_rule
    /// is read-only, action/scope are the "before" state used by
    /// submit's diff.
    pub rule_id: String,
    pub raw_rule: String,
    pub original_action: crate::filter::rules::RuleAction,
    pub original_scope: RuleScope,
    pub original_references: Vec<RuleReference>,

    /// Operator-typed mutations. On submit, diffed against the
    /// original_* fields to compute the minimal write set.
    pub current_action: crate::filter::rules::RuleAction,
    pub current_scope_choice: ScopeChoice,

    /// Available scopes the picker cycles through. Snapshotted at
    /// modal-open from `loaded_config` so a refresh during the form's
    /// lifetime cannot surprise the operator with a missing
    /// device/profile.
    pub scope_options: Vec<ScopeChoice>,

    pub focus: RuleEditFocus,
    pub mode: RuleEditMode,
    pub error_message: Option<String>,
    pub status_message: Option<String>,
    /// `true` while the IPC + write is in flight. Mirrors the S53
    /// list-edit-modal pattern.
    pub submitting: bool,
}

/// Tab-cycle focus targets in [`RuleEditModal`]. Read-only fields
/// (id, raw_rule) are deliberately absent — the cycler never lands on
/// them.
///
/// `SaveButton` is an *addition* to the interaction model (§4.65 UX3
/// §3.6 / D7′-extended), not a replacement of the `Ctrl+S`-from-
/// anywhere contract: the chord still commits from any focus, this
/// just gives the keyboard a second, discoverable route to the same
/// outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEditFocus {
    Action,
    Scope,
    DeleteButton,
    SaveButton,
}

impl RuleEditFocus {
    pub const ORDER: [RuleEditFocus; 4] = [
        RuleEditFocus::Action,
        RuleEditFocus::Scope,
        RuleEditFocus::DeleteButton,
        RuleEditFocus::SaveButton,
    ];

    pub fn next(self) -> RuleEditFocus {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> RuleEditFocus {
        let len = Self::ORDER.len();
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + len - 1) % len]
    }
}

/// Two-screen state machine for the rule edit modal — mirrors
/// [`EditModalMode`] for the list edit modal. `Edit` is the default
/// (form is mutable, Ctrl+S saves); `ConfirmDelete` swaps the body to
/// a typed-id confirm prompt and only an exact match commits the
/// destructive op.
#[derive(Debug, Clone)]
pub enum RuleEditMode {
    Edit,
    ConfirmDelete { typed: String },
}

/// One scope choice in the edit-modal picker. Mirrors [`RuleScope`]
/// minus the `Orphan` variant (orphans have no scope to start from —
/// the modal seeds with the first available choice).
///
/// `Device` carries only the id, not the allow/deny field — the field
/// is derived at submit time from the (possibly flipped) action:
/// Allow → `device.allow_rules`, Deny → `device.deny_rules`. This
/// keeps the picker simple for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeChoice {
    Default,
    Profile(String),
    Device(String),
}

impl ScopeChoice {
    /// Operator-facing label rendered in the picker. Mirrors the
    /// SCOPE column in the table for visual consistency.
    pub fn label(&self) -> String {
        match self {
            ScopeChoice::Default => "default".to_string(),
            ScopeChoice::Profile(id) => format!("profile:{id}"),
            ScopeChoice::Device(id) => format!("device:{id}"),
        }
    }
}

/// Joined view of one `[[admin_rules]]` entry: schema fields + parsed
/// action/domain (via [`crate::filter::rules::parse_rule`]) + scope
/// resolved by walking devices/profiles for references.
///
/// **Scope semantics**: a rule referenced by
/// `[profiles.<X>].admin_rules` renders as `Profile(X)` even when the
/// operator originally created it via `warden group <Y> allow ...`
/// (the CLI walks `group→profile` and writes the ref into the
/// resolved profile — the original "group" intent only survives in
/// the audit log, which the TUI does not consult). `Group`/`Subnet`
/// variants are intentionally absent from [`RuleScope`] for this
/// reason.
#[derive(Debug, Clone)]
pub struct RuleRowMeta {
    pub id: String,
    pub raw_rule: String,
    pub action: crate::filter::rules::RuleAction,
    /// Operator-friendly domain extracted from the rule pattern.
    /// `Exact("example.com")` → `"example.com"`.
    /// `Wildcard("ads.example.com")` → `"*.ads.example.com"`.
    /// `Regex { source }` → `"re:<source>"` (truncated at 30 chars).
    pub domain_label: String,
    /// "Primary" scope for the SCOPE column. When a rule is referenced
    /// by multiple entities, precedence is `Device > Profile > Default`
    /// — the most specific layer wins so the operator sees where the
    /// rule has the tightest reach.
    pub scope: RuleScope,
    /// Every entity that points at this rule's id. Used by the Phase C
    /// edit modal to show full context; in Phase B it's read only by
    /// the SCOPE column logic.
    pub references: Vec<RuleReference>,
    /// Per-rule hit counter — `None` until a future sprint wires
    /// per-rule telemetry (today's filter engine counters are per-source
    /// only). Renders as `—` in the HITS column.
    pub hits: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleScope {
    /// Referenced by `[profiles.<id>].admin_rules` where `<id>`
    /// matches `[server].default_profile`. Most "global" of the four.
    Default,
    Profile(String),
    Device(String),
    /// Master entry with zero references — the rule string lives on
    /// disk but no entity activates it. Surfaces silent garbage that
    /// the operator can clean up.
    Orphan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleReference {
    pub kind: RuleScope,
    /// `"allow_rules"` / `"deny_rules"` / `"admin_rules"` — the field
    /// name on the entity that holds the ref. Useful for the edit
    /// modal's "where does this rule live" hint.
    pub via_field: &'static str,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RulesFilter {
    #[default]
    All,
    Allow,
    Deny,
}

impl RulesFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Allow,
            Self::Allow => Self::Deny,
            Self::Deny => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// `logs-tab`: severity chip on the Log Messages filter card. Cycled
/// with `f`, exactly like [`ListsKindFilter`].
///
/// The chips are named after **levels**, not after what an operator might
/// hope a level means. INFO is not "updates": a list refresh, a boot line
/// and a profile reload are all INFO, and labelling that chip "Updates"
/// would promise a semantic filter the source cannot deliver. The honest
/// second dimension is the `target` (the emitting module), which the
/// `/` search already matches against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogsLevelFilter {
    #[default]
    All,
    Error,
    Warn,
    Info,
}

impl LogsLevelFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Error,
            Self::Error => Self::Warn,
            Self::Warn => Self::Info,
            Self::Info => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Error => "errors",
            Self::Warn => "warnings",
            Self::Info => "info",
        }
    }

    /// What travels in `IpcCommand::DaemonLogs.level`. `All` sends `None`
    /// — the daemon then keeps every level rather than being handed a
    /// three-way OR it has no vocabulary for.
    pub fn as_wire(self) -> Option<crate::tracking::log_ring::LogLevel> {
        use crate::tracking::log_ring::LogLevel;
        match self {
            Self::All => None,
            Self::Error => Some(LogLevel::Error),
            Self::Warn => Some(LogLevel::Warn),
            Self::Info => Some(LogLevel::Info),
        }
    }
}

/// `logs-tab`: what the last poll of `IpcCommand::DaemonLogs` did.
///
/// An empty `entries` has FOUR readings — never fetched, fetched and the
/// daemon has said nothing, fetched and nothing matched the filters, and
/// the fetch itself failed (the poll's error arm clears `entries`). Three
/// of those are claims about the daemon and one is a claim about the
/// connection; rendering them all as "no messages captured yet" tells an
/// operator watching a live daemon that it has said nothing, which is the
/// exact dishonesty the scout report rejected a cheaper data source over.
///
/// Tracked explicitly rather than inferred from `capacity == 0`: that
/// reading gets "never fetched" right but not "failed **after** a
/// successful fetch", where the capacity from the earlier success is
/// still sitting in state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogsFetch {
    /// No `DaemonLogs` response has come back yet this session.
    #[default]
    Never,
    Ok,
    /// The last poll errored. The footer carries the message; the pane
    /// must not pretend to describe the daemon.
    Failed,
}

/// `logs-tab`: everything the Log Messages viewer holds.
///
/// Both filters are sent to the daemon and applied during its walk of the
/// ring — NOT applied here over a fetched page. Filtering client-side
/// would search only the newest `limit` rows and quietly present that as
/// "the errors", which is the exact defect the query log's cursor design
/// exists to avoid.
#[derive(Debug, Clone, Default)]
pub struct LogsState {
    /// Newest first, as the daemon returns them.
    pub entries: Vec<crate::ipc::protocol::DaemonLogDto>,
    pub level_filter: LogsLevelFilter,
    /// `/` search buffer, committed. `None` = no search.
    pub filter_text: Option<String>,
    /// Line offset into `entries`, in the same convention `FileState`
    /// uses for the config document.
    pub scroll_offset: u16,
    /// Events the daemon dropped because a producer found the ring's lock
    /// held. Rendered so a gap is visible rather than silent.
    pub dropped: u64,
    /// Ring capacity, so the footer can say "of at most N" instead of
    /// implying the daemon kept everything it ever said.
    pub capacity: usize,
    /// Outcome of the last poll — see [`LogsFetch`]. Drives which of the
    /// four empty states the pane renders.
    pub fetch: LogsFetch,
}

/// Lists tab kind chip — mirrors [`RulesFilter`] but over blocklist
/// kind (block vs allow) rather than rule action. Cycled with `f`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ListsKindFilter {
    #[default]
    All,
    Block,
    Allow,
}

impl ListsKindFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Block,
            Self::Block => Self::Allow,
            Self::Allow => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

// `plp-s5d` removed the Tags-manager state that stood here — `TagsState`,
// `TagsFilterChip`, `TagMembers`, `TagsRow` and `TagsModal` — with the
// `Leaf::Tags` tab they backed. Tags decide nothing after the `plp-s3`
// cutover, so a CRUD surface over the implicit tag registry had nothing
// left to administer.

#[cfg(test)]
mod tests {
    use super::*;

    // ── §4.62 status TTL (B2 / N2 / N3) ──────────────────────────────

    /// The six leaves with no poll of their own. Before N2 a status set
    /// on any of them lived until the operator navigated away or fired
    /// another action — the "never" column of
    /// `tui_notification_surface_v1.md` §1 B2, and the mechanism behind
    /// *"non è chiaro dopo quanto tempo la notifica sparisca"*.
    const NEVER_POLLING_LEAVES: &[Leaf] =
        &[Leaf::Subnets, Leaf::Rules, Leaf::Profiles, Leaf::Settings];

    // B2 — a success message set on a leaf that never polls must still
    // be gone after its TTL. The expiry is deliberately leaf-agnostic;
    // the loop pins that it stays that way.
    #[test]
    fn ok_status_expires_on_a_leaf_that_never_polls() {
        for &leaf in NEVER_POLLING_LEAVES {
            let mut app = App::new();
            app.active_leaf = leaf;
            let t0 = Instant::now();
            app.status_ok("subnet saved".to_string());
            app.last_status.as_mut().unwrap().shown_at = t0;

            assert!(
                app.visible_status_at(t0 + Duration::from_secs(1)).is_some(),
                "{leaf:?}: the toast must still be up 1s in"
            );
            assert!(
                app.visible_status_at(t0 + STATUS_TTL).is_none(),
                "{leaf:?}: the toast must be gone at the TTL"
            );
            assert!(
                app.expire_status_at(t0 + STATUS_TTL),
                "{leaf:?}: the tick must drop it"
            );
            assert!(app.last_status.is_none(), "{leaf:?}: and it must be gone");
        }
    }

    // Info shares the Ok TTL.
    #[test]
    fn info_status_expires_on_the_ok_ttl() {
        let mut app = App::new();
        let t0 = Instant::now();
        app.status_info("nothing to do".to_string());
        app.last_status.as_mut().unwrap().shown_at = t0;
        assert!(app.visible_status_at(t0 + STATUS_TTL).is_none());
    }

    // N3 — an error the operator did not read is a lost error, so it
    // outlives the Ok TTL and waits for a keystroke.
    #[test]
    fn error_status_survives_the_ok_ttl() {
        let mut app = App::new();
        let t0 = Instant::now();
        app.status_err("refresh failed: connection refused".to_string());
        app.last_status.as_mut().unwrap().shown_at = t0;

        let long_after = t0 + STATUS_TTL * 100;
        assert!(
            app.visible_status_at(long_after).is_some(),
            "an Error must not expire on the Ok TTL"
        );
        assert!(
            !app.expire_status_at(long_after),
            "the tick must never drop a sticky Error"
        );

        // …until a key acts on the tab.
        assert!(app.dismiss_sticky_status());
        assert!(app.last_status.is_none());
    }

    // N3 — dismissal is scoped to sticky severities. A stray arrow key
    // must not steal a success toast the operator is mid-read of; those
    // have a TTL of their own.
    #[test]
    fn keystroke_dismissal_leaves_non_sticky_statuses_alone() {
        let mut app = App::new();
        app.status_ok("list saved".to_string());
        assert!(!app.dismiss_sticky_status());
        assert!(app.last_status.is_some());

        app.status_info("nothing to do".to_string());
        assert!(!app.dismiss_sticky_status());
        assert!(app.last_status.is_some());
    }

    // A poll error describes a *condition*. Once the daemon answers
    // again the condition is gone, so the message must go with it —
    // without the operator pressing anything. Otherwise a two-second
    // IPC blip leaves a red toast on an idle dashboard forever,
    // reporting a failure that already recovered.
    #[test]
    fn poll_raised_error_does_not_outlive_a_successful_poll() {
        let mut app = App::new();
        app.status_err_poll("connection refused".to_string());
        assert!(app.last_status.is_some(), "the blip must be visible");

        // The next pass starts by retiring it; the failure arms do not
        // re-raise, because the fetch succeeded.
        assert!(app.clear_poll_status(), "a recovered poll must retire it");
        assert!(
            app.visible_status().is_none(),
            "no keystroke should be needed to clear a recovered poll error"
        );
    }

    // …and the other half of the pair, which is what stops the fix
    // above from degenerating back into the blanket `clear_status()`
    // that made the poll cadence the message lifetime (B2): an error
    // the operator *caused* is not the poller's to retire.
    #[test]
    fn action_raised_error_survives_a_successful_poll() {
        let mut app = App::new();
        app.status_err("save failed: permission denied".to_string());

        assert!(
            !app.clear_poll_status(),
            "a poll must not retire an action's error"
        );
        assert_eq!(
            app.status_text(),
            Some("save failed: permission denied"),
            "the operator must still see what their action did"
        );
        // It is still theirs to dismiss.
        assert!(app.dismiss_sticky_status());
    }

    // Successes and info are action-origin too — a poll pass must not
    // eat the "list saved" toast the operator is mid-read of.
    #[test]
    fn poll_does_not_retire_action_successes() {
        let mut app = App::new();
        app.status_ok("list 'privacy/ads' saved".to_string());
        assert!(!app.clear_poll_status());
        assert!(app.last_status.is_some());

        app.status_info("nothing to do".to_string());
        assert!(!app.clear_poll_status());
        assert!(app.last_status.is_some());
    }

    // The tick calls `expire_status` at 33ms. It must report whether it
    // changed anything, or the render loop repaints at ~30 FPS forever
    // on a box that is also answering DNS.
    #[test]
    fn expire_status_only_reports_true_when_it_cleared_something() {
        let mut app = App::new();
        assert!(!app.expire_status(), "nothing to expire");

        let t0 = Instant::now();
        app.status_ok("saved".to_string());
        app.last_status.as_mut().unwrap().shown_at = t0;
        assert!(!app.expire_status_at(t0), "not yet due");
        assert!(app.expire_status_at(t0 + STATUS_TTL), "due now");
        assert!(!app.expire_status_at(t0 + STATUS_TTL), "already gone");
    }

    // A `now` behind `shown_at` (a caller-supplied instant, not the
    // monotonic clock going backwards) must read as "0 elapsed", not
    // panic on the subtraction.
    #[test]
    fn expiry_tolerates_a_now_before_shown_at() {
        let mut app = App::new();
        let t0 = Instant::now() + Duration::from_secs(60);
        app.status_ok("saved".to_string());
        app.last_status.as_mut().unwrap().shown_at = t0;
        assert!(app.visible_status_at(Instant::now()).is_some());
    }

    // ── DeviceFormState navigation + lifecycle (Sprint 23 modal) ──

    #[test]
    fn add_form_starts_focused_on_ip() {
        // Field order put Ip + Mac at the top (identity block); the
        // operator types those first on Add, so default focus follows
        // FIELDS[0].
        let f = DeviceFormState::new_add();
        assert_eq!(f.focused, DeviceFormFocus::Field(DeviceFormField::Ip));
        assert_eq!(f.mode, DeviceFormMode::Add);
        assert!(!f.ip_locked);
        assert!(!f.mac_locked);
        assert!(!f.submitting);
        assert!(f.error_message.is_none());
    }

    #[test]
    fn promote_form_locks_ip_and_mac() {
        let f = DeviceFormState::new_promote("10.0.0.42".into(), "AA:BB:CC:DD:EE:FF".into());
        assert!(f.ip_locked);
        assert!(
            f.mac_locked,
            "promote form locks MAC too — it's the wire identity, not editable metadata"
        );
        assert_eq!(f.ip, "10.0.0.42");
        assert_eq!(f.mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(f.mode, DeviceFormMode::Promote);
    }

    #[test]
    fn with_options_populates_picker_snapshots() {
        let f = DeviceFormState::new_add()
            .with_options(vec!["default".into(), "kids".into()], vec!["media".into()]);
        assert_eq!(
            f.profiles_snapshot,
            vec!["default".to_string(), "kids".to_string()]
        );
        assert_eq!(f.groups_snapshot, vec!["media".to_string()]);
        assert!(f.picker.is_none(), "no picker open on a freshly built form");
    }

    #[test]
    fn focus_next_walks_field_order_then_the_buttons_and_wraps() {
        let mut f = DeviceFormState::new_add();
        // Expected order from FIELDS constant — identity block first
        // (Ip, Mac, MacAliases), then the metadata block, and finally the
        // two action buttons, which the ring now includes so the operator
        // can reach Save/Cancel with ↓ instead of only via Enter/Esc.
        let order = [
            DeviceFormFocus::Field(DeviceFormField::Ip),
            DeviceFormFocus::Field(DeviceFormField::Mac),
            DeviceFormFocus::Field(DeviceFormField::MacAliases),
            DeviceFormFocus::Field(DeviceFormField::Name),
            DeviceFormFocus::Field(DeviceFormField::Profile),
            DeviceFormFocus::Field(DeviceFormField::Group),
            DeviceFormFocus::Field(DeviceFormField::Owner),
            DeviceFormFocus::Field(DeviceFormField::Device),
            DeviceFormFocus::Field(DeviceFormField::Department),
            DeviceFormFocus::Field(DeviceFormField::Notes),
            DeviceFormFocus::Field(DeviceFormField::NetworkName),
            DeviceFormFocus::Field(DeviceFormField::NetworkNameWildcard),
            DeviceFormFocus::Cancel,
            DeviceFormFocus::Save,
        ];
        // Verify default focus matches FIELDS[0].
        assert_eq!(f.focused, order[0]);
        for expected in order.iter().skip(1) {
            f.focus_next();
            assert_eq!(f.focused, *expected);
        }
        // Wraps from Save back to Ip
        f.focus_next();
        assert_eq!(f.focused, DeviceFormFocus::Field(DeviceFormField::Ip));
    }

    #[test]
    fn focus_prev_walks_backwards_and_wraps_through_the_buttons() {
        let mut f = DeviceFormState::new_add();
        // Stepping back off the first field now lands on Save, not Notes —
        // the buttons sit at the tail of the ring.
        f.focus_prev();
        assert_eq!(f.focused, DeviceFormFocus::Save);
        f.focus_prev();
        assert_eq!(f.focused, DeviceFormFocus::Cancel);
        f.focus_prev();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::NetworkNameWildcard),
            "the last field in FIELDS, which the two net-name stops now end"
        );
    }

    #[test]
    fn locked_fields_stay_skipped_with_the_buttons_in_the_ring() {
        // Promote locks ip + mac, so MacAliases is the first live field.
        // Stepping back off it must cross the ring boundary onto Save
        // rather than landing on a locked field.
        let mut f = DeviceFormState::new_promote("10.0.0.1".into(), "MAC".into());
        f.focused = DeviceFormFocus::Field(DeviceFormField::MacAliases);
        f.focus_prev();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Save,
            "with Ip and Mac locked, stepping back off the first live field wraps to Save"
        );
        // And forward from Save lands on the first live field, not Ip.
        f.focus_next();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::MacAliases),
            "the wrap-forward target is the first UNLOCKED field"
        );
    }

    /// Focus can sit on a stop the ring excludes — a locked field. Moving
    /// from there must land on the first LIVE stop, not skip past it.
    #[test]
    fn focus_off_a_locked_field_snaps_to_the_first_live_stop() {
        let mut f = DeviceFormState::new_promote("10.0.0.1".into(), "MAC".into());
        // Ip is locked on Promote, so it is not in the ring at all.
        f.focused = DeviceFormFocus::Field(DeviceFormField::Ip);
        f.focus_next();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::MacAliases),
            "lands on the first unlocked field, not the one after it"
        );

        f.focused = DeviceFormFocus::Field(DeviceFormField::Mac);
        f.focus_prev();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::MacAliases),
            "same snap walking backwards"
        );
    }

    #[test]
    fn focus_field_accessor_unwraps_only_field_variants() {
        assert_eq!(
            DeviceFormFocus::Field(DeviceFormField::Name).field(),
            Some(DeviceFormField::Name)
        );
        assert_eq!(DeviceFormFocus::Save.field(), None);
        assert_eq!(DeviceFormFocus::Cancel.field(), None);
    }

    #[test]
    fn promote_form_focus_skips_locked_ip_and_mac() {
        let mut f = DeviceFormState::new_promote("10.0.0.1".into(), "MAC".into());
        // Promote starts at Name; next should skip the locked Ip + Mac
        // and the always-editable MacAliases is the FIRST stop walking
        // back, then forward we wrap to MacAliases too.
        // From Name → next wraps through the order, skipping Ip + Mac.
        f.focus_next();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::Profile),
            "after Name the next selectable field is Profile"
        );
        // Back from Profile → Name (skipping nothing in between)
        f.focus_prev();
        assert_eq!(f.focused, DeviceFormFocus::Field(DeviceFormField::Name));
        // Back again from Name → MacAliases (Mac and Ip are locked, skipped)
        f.focus_prev();
        assert_eq!(
            f.focused,
            DeviceFormFocus::Field(DeviceFormField::MacAliases),
            "Mac is locked on Promote; focus_prev skips it"
        );
    }

    #[test]
    fn field_buf_writes_propagate_to_named_field() {
        let mut f = DeviceFormState::new_add();
        f.field_buf(DeviceFormField::Name).push_str("sam-laptop");
        f.field_buf(DeviceFormField::Ip).push_str("192.168.1.42");
        f.field_buf(DeviceFormField::Department)
            .push_str("famiglia");
        assert_eq!(f.name, "sam-laptop");
        assert_eq!(f.ip, "192.168.1.42");
        assert_eq!(f.department, "famiglia");
    }

    /// The two §net-name fields must be reachable through the SAME buffer
    /// accessor every other field uses. `field_buf` is the only way the key
    /// handler writes a character, so a variant added to the enum but not to
    /// that match arm compiles, takes focus, and silently swallows typing.
    #[test]
    fn field_buf_writes_propagate_to_network_name_field() {
        let mut f = DeviceFormState::new_add();
        f.field_buf(DeviceFormField::NetworkName)
            .push_str("desktop-1");
        f.field_buf(DeviceFormField::NetworkNameWildcard)
            .push_str("true");
        assert_eq!(f.network_name, "desktop-1");
        assert_eq!(f.network_name_wildcard, "true");
    }

    #[test]
    fn edit_form_preserves_prefilled_values() {
        let f = DeviceFormState::new_edit(
            "tablet".into(),
            "192.168.1.50".into(),
            "AA:BB".into(),
            "AA:BB:CC:DD:EE:01,AA:BB:CC:DD:EE:02".into(),
            "kids".into(),
            "kids-group".into(),
            "Sam".into(),
            "iPad".into(),
            "famiglia".into(),
            "compleanno: gennaio".into(),
            "tablet".into(),
            "false".into(),
        );
        assert_eq!(f.mode, DeviceFormMode::Edit);
        assert_eq!(f.network_name, "tablet");
        assert_eq!(f.network_name_wildcard, "false");
        assert_eq!(f.name, "tablet");
        assert_eq!(f.profile, "kids");
        assert_eq!(f.groups, "kids-group");
        assert_eq!(f.notes, "compleanno: gennaio");
        assert_eq!(f.department, "famiglia");
        assert_eq!(
            f.mac_aliases, "AA:BB:CC:DD:EE:01,AA:BB:CC:DD:EE:02",
            "edit form preserves the aliases string exactly as passed"
        );
        assert!(!f.ip_locked, "edit form leaves IP editable");
    }

    #[test]
    fn delete_confirm_modal_carries_target_id_and_display_name() {
        let modal = DeviceModal::DeleteConfirm {
            id: "ghost-tablet".into(),
            display_name: "Ghost Tablet".into(),
        };
        match modal {
            DeviceModal::DeleteConfirm { id, display_name } => {
                assert_eq!(id, "ghost-tablet");
                assert_eq!(display_name, "Ghost Tablet");
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Sprint 45 T2 / Sprint 46 T1: grouped section/leaf navigation ─

    #[test]
    fn section_all_carries_five_entries_with_numeric_labels() {
        // S46 T1 reshape: 5 sections in render order. Dashboard and
        // QueryLog were promoted out of the retired `Overview` hub.
        // The labels carry the numeric chrome prefix consumed by the
        // top bar Tabs widget (chrome-side strips it for the breadcrumb).
        // §4.11-4b: the `cluster` build appends a 6th section (`6 Cluster`),
        // runtime-hidden unless `[cluster].enabled`; the default build is
        // unchanged at 5.
        #[cfg(not(feature = "cluster"))]
        assert_eq!(Section::ALL.len(), 5);
        #[cfg(feature = "cluster")]
        assert_eq!(Section::ALL.len(), 6);
        assert_eq!(Section::Dashboard.label(), "1 Dashboard");
        assert_eq!(Section::QueryLog.label(), "2 Query Log");
        assert_eq!(Section::Network.label(), "3 Network");
        // §4.67-a: "4 Filtering" → "4 Filters", "5 Settings" →
        // "5 Configuration". The numeric prefix is chrome consumed by the
        // top-bar Tabs widget, so the hotkeys 1-5 are unmoved.
        assert_eq!(Section::Filters.label(), "4 Filters");
        assert_eq!(Section::Configuration.label(), "5 Configuration");
        #[cfg(feature = "cluster")]
        assert_eq!(Section::Cluster.label(), "6 Cluster");
    }

    #[test]
    fn dashboard_section_is_singleton() {
        // S46 T1: Dashboard is its own top-level section with itself
        // as the sole leaf. `default_leaf` and `leaves()` both return
        // Leaf::Dashboard so `[`/`]` cycling collapses to a no-op and
        // the chrome can skip the sub-tab row.
        assert_eq!(Section::Dashboard.default_leaf(), Leaf::Dashboard);
        assert_eq!(Section::Dashboard.leaves(), &[Leaf::Dashboard]);
    }

    #[test]
    fn query_log_section_is_singleton() {
        // S46 T1: Query Log shares the singleton pattern with Dashboard
        // and Settings. Pinning it as a structural test catches a
        // future refactor that accidentally re-buries it under a hub.
        assert_eq!(Section::QueryLog.default_leaf(), Leaf::QueryLog);
        assert_eq!(Section::QueryLog.leaves(), &[Leaf::QueryLog]);
    }

    #[test]
    fn leaf_labels_carry_no_numeric_prefix() {
        // Post-S46 leaves are reached via section hotkeys (1-5) +
        // `[`/`]` cycle or `g <letter>` mnemonics, never by a leaf's own
        // number. A `"3 Devices"` label would falsely promise a `3`
        // hotkey that today jumps to Network (the section), not the
        // leaf. Pin every label so a future edit can't silently
        // re-introduce the legacy numeric prefix.
        for leaf in Leaf::ALL {
            let label = leaf.label();
            let first = label.chars().next().unwrap_or(' ');
            assert!(
                !first.is_ascii_digit(),
                "leaf {leaf:?} label {label:?} starts with a digit; the numeric prefix was retired in S46"
            );
        }
    }

    #[test]
    fn network_section_carries_four_leaves_in_render_order() {
        // S52 collapsed Resolver into a global modal; §4.26 Phase 2 added
        // Profiles as a 4th destination. 2026-07-24 (IA Option B) moved
        // Profiles out to Filtering. §4.64 G1 then added Groups — a group
        // IS "who is on the wire" (a membership list of devices), which is
        // the same test §4.66 answered the opposite way for the Labels
        // registry. Groups sits second, right after Devices, per the
        // operator's own menu note. The render order is the sub-tab strip's
        // left-to-right order.
        assert_eq!(
            Section::Network.leaves(),
            &[Leaf::Devices, Leaf::Groups, Leaf::Subnets, Leaf::LocalDns]
        );
        assert_eq!(Section::Network.default_leaf(), Leaf::Devices);
    }

    #[test]
    fn filters_section_is_profiles_lists_custom_lists_rules() {
        // 2026-07-24 (IA Option B). Filters owns the whole policy story and
        // leads with it — a Profile is the hub an operator tuning filtering
        // reaches for, and landing on Lists would put the download ledger in
        // front of the policy.
        // §4.67-a MN5/MN6: Tags left for Configuration (it is vocabulary, not
        // policy), leaving the three leaves that are policy: what applies
        // (Profiles), what it resolves to (Lists), what overrides it (Rules).
        // Custom Lists was inserted between Lists and Rules; the landing
        // leaf is unchanged, which is the property this asserts.
        assert_eq!(Section::Filters.default_leaf(), Leaf::Profiles);
        assert_eq!(
            Section::Filters.leaves(),
            &[Leaf::Profiles, Leaf::Lists, Leaf::CustomLists, Leaf::Rules]
        );
    }

    /// The operator's rule as a build-time guard rather than prose.
    ///
    /// This exists because the rule it enforces was ALREADY stated in a comment
    /// and had ALREADY been violated by one section — a comment cannot fail a
    /// build. Adding a section, or reordering a `LAYOUT` row, now cannot
    /// silently reintroduce a landing that is not leftmost.
    #[test]
    fn every_section_lands_on_its_leftmost_leaf() {
        for section in Section::ALL {
            let leaves = section.leaves();
            assert!(
                !leaves.is_empty(),
                "{section:?} has no LAYOUT row — `layout_covers_every_variant` \
                 should have caught this first"
            );
            assert_eq!(
                section.default_leaf(),
                leaves[0],
                "{section:?} must land on its LEFTMOST leaf ({:?}), not {:?}",
                leaves[0],
                section.default_leaf()
            );
        }
    }

    #[test]
    fn configuration_section_holds_labels_tags_settings_file_and_lands_on_labels() {
        // §4.67-a MN1/MN4/MN5. Configuration answers the third IA question —
        // "what elements exist to be reused" — which is why Tags leads the
        // strip. `default_leaf` deliberately does NOT follow: `5` has meant
        // "Settings" for the life of the product, and §4.67-a moves a section
        // boundary, not the operator's muscle memory. Settings itself stays a
        // leaf because it carries the Tracking form and backup/restore.
        // §4.67-b MN3 appended File — the row is what `[`/`]` walks.
        // §4.66 L2 put Labels FIRST: it is the registry the other two
        // vocabulary-ish leaves read from, and `default_leaf` deliberately
        // does not follow the row order — `5` has meant Settings for the
        // life of the product.
        // `logs-tab` appended Log Messages. `default_leaf` still does not
        // follow the row order — the section lands on Labels.
        assert_eq!(
            Section::Configuration.leaves(),
            &[Leaf::Labels, Leaf::Settings, Leaf::File, Leaf::Logs]
        );
        // Was `Leaf::Settings` until 2026-08-24. Flipped on operator
        // authority, not by refactor drift: see `default_leaf` for why a
        // stated preference retires the muscle-memory argument. Landing on
        // Labels also happens to answer the operator's separate report that
        // they could not find where owner / device-type / department are
        // declared — Labels is that registry, and now it is what the section
        // opens on.
        //
        // The two `Leaf::Tags` assertions that sat here on `main` are gone
        // with the leaf itself (`plp-s5d`), not because they were wrong.
        assert_eq!(Section::Configuration.default_leaf(), Leaf::Labels);
    }

    #[test]
    fn layout_covers_every_variant() {
        // §4.67-a. `Section::leaves` and `Leaf::section` fall back instead of
        // panicking — they run on the render path, where a wrong breadcrumb
        // degrades and a panic does not. That safety costs a silent failure
        // mode: a variant with no LAYOUT row reports the wrong section and
        // gets an empty leaf slice, and NOTHING else would tell you.
        //
        // The two `match`es below are the trip-wire: adding a variant makes
        // them non-exhaustive, so the build breaks HERE, in the test whose
        // subject is LAYOUT coverage, rather than at runtime. The length
        // assertions catch the other direction — a variant given a LAYOUT row
        // but not listed here.
        // `allow` not `expect`: the `mut` is live only under `cluster`, and
        // an `expect` would go red on the build where it IS needed.
        #[allow(unused_mut)]
        let mut sections = vec![
            Section::Dashboard,
            Section::QueryLog,
            Section::Network,
            Section::Filters,
            Section::Configuration,
        ];
        // `#[cfg]` on a STATEMENT is stable; on an array/vec element it is
        // not. Same constraint that shapes `LAYOUT` itself.
        #[cfg(feature = "cluster")]
        sections.push(Section::Cluster);

        for section in &sections {
            match section {
                Section::Dashboard
                | Section::QueryLog
                | Section::Network
                | Section::Filters
                | Section::Configuration => {}
                #[cfg(feature = "cluster")]
                Section::Cluster => {}
            }
            assert!(
                LAYOUT.iter().any(|(s, _)| s == section),
                "{section:?} has no LAYOUT row: leaves() would return &[] and the section \
                 would vanish from the nav bar"
            );
        }
        assert_eq!(
            sections.len(),
            Section::ALL.len(),
            "a LAYOUT row exists for a Section this test does not list"
        );

        #[allow(unused_mut)]
        let mut leaves = vec![
            Leaf::Dashboard,
            Leaf::QueryLog,
            Leaf::Devices,
            Leaf::Subnets,
            Leaf::LocalDns,
            Leaf::Profiles,
            Leaf::Lists,
            Leaf::CustomLists,
            Leaf::Rules,
            Leaf::Settings,
            Leaf::File,
            Leaf::Logs,
            Leaf::Groups,
            Leaf::Labels,
        ];
        #[cfg(feature = "cluster")]
        leaves.push(Leaf::Cluster);

        for leaf in &leaves {
            match leaf {
                Leaf::Dashboard
                | Leaf::QueryLog
                | Leaf::Devices
                | Leaf::Subnets
                | Leaf::LocalDns
                | Leaf::Profiles
                | Leaf::Lists
                | Leaf::CustomLists
                | Leaf::Rules
                | Leaf::Settings
                | Leaf::File
                | Leaf::Logs
                | Leaf::Groups
                | Leaf::Labels => {}
                #[cfg(feature = "cluster")]
                Leaf::Cluster => {}
            }
            assert!(
                LAYOUT.iter().any(|(_, ls)| ls.contains(leaf)),
                "{leaf:?} has no LAYOUT row: section() would report the wrong section and \
                 the leaf would be absent from the Tab cycle"
            );
        }
        assert_eq!(
            leaves.len(),
            Leaf::ALL.len(),
            "a LAYOUT row exists for a Leaf this test does not list"
        );
    }

    #[test]
    fn every_leaf_appears_in_layout_exactly_once() {
        // A leaf listed in two LAYOUT rows would make `section()` return the
        // first row silently while `Leaf::ALL` grew a duplicate — the linear
        // `Tab` cycle would then visit it twice and `index()` would resolve to
        // the earlier copy. Cheap to pin, invisible otherwise.
        for leaf in Leaf::ALL {
            let homes = LAYOUT.iter().filter(|(_, ls)| ls.contains(&leaf)).count();
            assert_eq!(homes, 1, "{leaf:?} appears in {homes} LAYOUT rows, want 1");
        }
    }

    #[test]
    fn each_section_is_a_contiguous_in_order_slice_of_all() {
        // The linear `Tab` cycle walks `Leaf::ALL`; the `]` cycle walks
        // `Section::leaves()`. If a section's leaves are not a contiguous
        // in-order run of ALL, the same section cycles in two different
        // orders depending on which key the operator presses — and `Tab`
        // re-enters a section it already left. Prose-only invariant until
        // 2026-07-24; pinned here so the NEXT reorder trips a test instead
        // of shipping.
        //
        // §4.67-a demoted this from a safety net to a tautology: both sides
        // are now flattened from the same `LAYOUT` rows, so contiguity holds
        // by construction. Kept deliberately — it costs nothing, it is the
        // executable statement of WHY `Leaf::ALL` may not be hand-ordered,
        // and it goes red again the day someone reintroduces a second source.
        for section in Section::ALL {
            let leaves = section.leaves();
            let start = Leaf::ALL
                .iter()
                .position(|l| *l == leaves[0])
                .expect("section's first leaf must exist in Leaf::ALL");
            assert_eq!(
                &Leaf::ALL[start..start + leaves.len()],
                leaves,
                "{section:?} leaves are not a contiguous in-order slice of Leaf::ALL"
            );
        }
    }

    #[test]
    fn every_mnemonic_occurs_in_its_leaf_label() {
        // The sub-tab strip underlines `mnemonic()` inside `label()`. If a
        // future leaf picks a letter its label does not contain, the
        // underline silently no-ops and the discoverability fix quietly
        // stops working for that leaf. A pty smoke only catches this with
        // `tmux capture-pane -pe` (plain `-p` strips SGR), so this is the
        // cheap always-on guard.
        for leaf in Leaf::ALL {
            assert!(
                leaf.mnemonic_offset().is_some(),
                "leaf {:?} mnemonic {:?} does not occur in its label {:?}",
                leaf,
                leaf.mnemonic(),
                leaf.label()
            );
        }
    }

    #[test]
    fn mnemonic_round_trips_through_from_mnemonic() {
        // `mnemonic()` is the declared inverse of `from_mnemonic()`; a
        // drift between the two would underline the wrong character while
        // the jump still worked, which is worse than no underline.
        for leaf in Leaf::ALL {
            assert_eq!(
                Leaf::from_mnemonic(leaf.mnemonic()),
                Some(leaf),
                "mnemonic {:?} for {:?} does not round-trip",
                leaf.mnemonic(),
                leaf
            );
        }
    }

    #[test]
    fn every_leaf_maps_back_to_its_owning_section() {
        // Round-trip pin: the breadcrumb in render_footer relies on
        // section() never panicking and always returning the section
        // whose leaves() list contains `self`.
        for leaf in Leaf::ALL {
            let section = leaf.section();
            assert!(
                section.leaves().contains(&leaf),
                "leaf {:?} reports section {:?} but is not in that section's leaves",
                leaf,
                section
            );
        }
    }

    #[test]
    fn next_in_section_wraps_within_network() {
        // §4.64 G1 inserted Groups between Devices and Subnets, so the
        // ring is four long. Local DNS is still last — `]` on it must wrap
        // to Devices, not fall through into the next section.
        assert_eq!(Leaf::Devices.next_in_section(), Leaf::Groups);
        assert_eq!(Leaf::Groups.next_in_section(), Leaf::Subnets);
        assert_eq!(Leaf::Subnets.next_in_section(), Leaf::LocalDns);
        assert_eq!(Leaf::LocalDns.next_in_section(), Leaf::Devices);
        assert_eq!(Leaf::Devices.prev_in_section(), Leaf::LocalDns);
        assert_eq!(Leaf::Groups.prev_in_section(), Leaf::Devices);
        assert_eq!(Leaf::LocalDns.prev_in_section(), Leaf::Subnets);
    }

    #[test]
    fn next_in_section_wraps_within_filters() {
        // §4.67-a: Filters is the 3-leaf section (Tags left for
        // Configuration). Twin of the Network cycle test — the wrap is where
        // an off-by-one in `leaves()` would leak the operator into another
        // section. `]` on Rules must land back on Profiles, not on Tags.
        assert_eq!(Leaf::Profiles.next_in_section(), Leaf::Lists);
        assert_eq!(Leaf::Lists.next_in_section(), Leaf::CustomLists);
        assert_eq!(Leaf::CustomLists.next_in_section(), Leaf::Rules);
        assert_eq!(Leaf::Rules.next_in_section(), Leaf::Profiles);
        assert_eq!(Leaf::Profiles.prev_in_section(), Leaf::Rules);
    }

    #[test]
    fn next_in_section_wraps_within_configuration() {
        // §4.67-a gave the Settings section a second leaf, so `[`/`]` there
        // is not a no-op. §4.67-b MN3: three. §4.66 L2: four.
        //
        // **A ring of FOUR, and the number is a merge.** `plp-s5d` removed
        // `Leaf::Tags` with the tab; `logs-tab` added `Leaf::Logs`. The ring
        // is Labels → Settings → File → Logs → Labels. Taking either side of
        // the conflict whole would have put Tags back or dropped Logs, and
        // both compile.

        assert_eq!(Leaf::Labels.next_in_section(), Leaf::Settings);
        assert_eq!(Leaf::Settings.next_in_section(), Leaf::File);
        assert_eq!(Leaf::File.next_in_section(), Leaf::Logs);
        assert_eq!(Leaf::Logs.next_in_section(), Leaf::Labels);
        assert_eq!(Leaf::Labels.prev_in_section(), Leaf::Logs);
        assert_eq!(Leaf::Logs.prev_in_section(), Leaf::File);
        assert_eq!(Leaf::Settings.prev_in_section(), Leaf::Labels);
        assert_eq!(Leaf::File.prev_in_section(), Leaf::Settings);
        // The letter Tags freed has been taken by Custom Lists. This line
        // asserted `t` was still unbound, and was RIGHT when written — it
        // is kept, inverted, because a letter being free is a fact about a
        // moment and this is where the next lane will come looking.
        assert_eq!(Leaf::from_mnemonic('t'), Some(Leaf::CustomLists));
    }

    #[test]
    fn next_in_section_is_noop_for_single_leaf_section() {
        // Dashboard and Query Log are the remaining single-leaf sections;
        // cycling within one is a structural no-op so the operator pressing
        // `[`/`]` there doesn't surprise-jump elsewhere. (Settings held this
        // role until §4.67-a gave it Tags for company.)
        for leaf in [Leaf::Dashboard, Leaf::QueryLog] {
            assert_eq!(leaf.next_in_section(), leaf);
            assert_eq!(leaf.prev_in_section(), leaf);
        }
    }

    // ── Variant-A modal-ecosystem redesign: dynamic focus cycle ─────
    // The SOURCE section hides Format / Interval / AuthTokenRef behind
    // an "Advanced" collapse; Delete / Cancel / Save anchor a button
    // row. The cycle adapts to (mode, advanced_expanded).

    #[test]
    fn edit_cycle_collapsed_skips_advanced_fields_but_keeps_toggle() {
        let c = EditField::cycle(&EditModalMode::Edit, false);
        assert!(c.contains(&EditField::Advanced));
        assert!(!c.contains(&EditField::Format));
        assert!(!c.contains(&EditField::Interval));
        assert!(!c.contains(&EditField::AuthTokenRef));
        // Button row order: Delete → Cancel → Save.
        let d = c
            .iter()
            .position(|f| *f == EditField::DeleteButton)
            .unwrap();
        let ca = c.iter().position(|f| *f == EditField::Cancel).unwrap();
        let s = c.iter().position(|f| *f == EditField::Save).unwrap();
        assert!(d < ca && ca < s, "button order Delete<Cancel<Save");
    }

    #[test]
    fn edit_cycle_expanded_reveals_advanced_fields_right_after_toggle() {
        let c = EditField::cycle(&EditModalMode::Edit, true);
        let adv = c.iter().position(|f| *f == EditField::Advanced).unwrap();
        let fmt = c.iter().position(|f| *f == EditField::Format).unwrap();
        assert!(adv < fmt, "Format revealed immediately after Advanced");
        assert!(c.contains(&EditField::Interval));
        assert!(c.contains(&EditField::AuthTokenRef));
    }

    #[test]
    fn add_mode_cycle_leads_with_list_id_and_has_no_delete() {
        let c = EditField::cycle(&EditModalMode::Add, false);
        assert_eq!(c.first(), Some(&EditField::ListId));
        assert!(
            !c.contains(&EditField::DeleteButton),
            "nothing to delete in Add"
        );
        assert!(c.contains(&EditField::Cancel));
        assert!(c.contains(&EditField::Save));
    }

    #[test]
    fn tab_from_advanced_depends_on_expansion() {
        // Expanded: Tab descends into the first revealed field.
        assert_eq!(
            EditField::Advanced.next_in(&EditModalMode::Edit, true),
            EditField::Format
        );
        // Collapsed: Tab skips straight past the hidden fields to Nature.
        assert_eq!(
            EditField::Advanced.next_in(&EditModalMode::Edit, false),
            EditField::Nature
        );
    }

    // ── Sprint 45 T3: g <letter> mnemonic dispatch ──────────────────

    #[test]
    fn mnemonic_table_covers_every_leaf_exactly_once() {
        // Each of the 10 leaves has a unique mnemonic letter — no
        // collisions, no orphans. S52 dropped `g r` (Resolver) when
        // the leaf was promoted to a global modal (`s` from anywhere);
        // §4.26 Phase 2 added `g p` (Profiles).
        #[cfg(not(feature = "cluster"))]
        let pairs: [(char, Leaf); 14] = [
            ('d', Leaf::Dashboard),
            ('q', Leaf::QueryLog),
            ('v', Leaf::Devices),
            ('s', Leaf::Subnets),
            ('o', Leaf::Groups),
            ('l', Leaf::LocalDns),
            ('p', Leaf::Profiles),
            ('i', Leaf::Lists),
            ('t', Leaf::CustomLists),
            ('u', Leaf::Rules),
            ('e', Leaf::Settings),
            ('f', Leaf::File),
            ('b', Leaf::Labels),
            ('m', Leaf::Logs),
        ];
        // §4.11-4b — the `cluster` build adds `g c` → Cluster as one more
        // mnemonic; the inverse coverage check below then also sees that
        // leaf in `Leaf::ALL`.
        //
        // **FOURTEEN and FIFTEEN, and the number has already been a merge
        // of two changes that landed in parallel.** `plp-s5d` removed
        // `('t', Leaf::Tags)` when the tab went; `logs-tab` added
        // `('m', Leaf::Logs)`. Taking either side of the conflict whole
        // would have resurrected the Tags mnemonic or dropped the Logs
        // one, and BOTH mistakes compile. `t` is taken again now, by
        // Custom Lists — the letter being free was a fact about one
        // moment, not a property of the letter.
        //
        // **The cluster array is gated and the default build cannot see
        // it.** `cargo check --all-targets` and the entire default suite
        // were green once while this line was wrong; only
        // `--features cluster` catches it. That is why the feature configs
        // are a gate leg and not an afterthought.
        #[cfg(feature = "cluster")]
        let pairs: [(char, Leaf); 15] = [
            ('d', Leaf::Dashboard),
            ('q', Leaf::QueryLog),
            ('v', Leaf::Devices),
            ('s', Leaf::Subnets),
            ('o', Leaf::Groups),
            ('l', Leaf::LocalDns),
            ('p', Leaf::Profiles),
            ('i', Leaf::Lists),
            ('t', Leaf::CustomLists),
            ('u', Leaf::Rules),
            ('e', Leaf::Settings),
            ('f', Leaf::File),
            ('b', Leaf::Labels),
            ('m', Leaf::Logs),
            ('c', Leaf::Cluster),
        ];
        for (ch, expected) in pairs {
            assert_eq!(
                Leaf::from_mnemonic(ch),
                Some(expected),
                "mnemonic g{ch} must map to {expected:?}"
            );
        }
        // Inverse: every Leaf::ALL variant is reachable via some mnemonic.
        for leaf in Leaf::ALL {
            assert!(
                pairs.iter().any(|(_, l)| *l == leaf),
                "leaf {leaf:?} is not reachable via any g<letter> mnemonic"
            );
        }
    }

    #[test]
    fn no_mnemonic_jumps_outside_leaf_all() {
        // §4.67-a closes the one route by which `app.active_leaf` could hold a
        // leaf that has no LAYOUT row: `from_mnemonic` is a hand-written match,
        // so `g <letter>` is the only setter that does not read LAYOUT. A leaf
        // reachable only that way would render with the fallback section and an
        // empty sub-tab strip — degraded, silent, and hard to trace back here.
        for ch in 'a'..='z' {
            if let Some(leaf) = Leaf::from_mnemonic(ch) {
                assert!(
                    Leaf::ALL.contains(&leaf),
                    "mnemonic g{ch} jumps to {leaf:?}, which is not in LAYOUT"
                );
            }
        }
    }

    #[test]
    fn unknown_mnemonic_returns_none() {
        // Anything not in the §4 table — uppercase letters, digits,
        // punctuation, common typos — must return None so the caller
        // drains pending_goto and falls through to the active leaf's
        // handler instead of swallowing the keystroke silently.
        assert_eq!(Leaf::from_mnemonic('x'), None);
        assert_eq!(Leaf::from_mnemonic('D'), None, "uppercase isn't aliased");
        assert_eq!(Leaf::from_mnemonic('1'), None);
        assert_eq!(
            Leaf::from_mnemonic('g'),
            None,
            "g g re-arms instead of jumping"
        );
        assert_eq!(Leaf::from_mnemonic(' '), None);
    }

    #[test]
    fn app_starts_with_pending_goto_cleared() {
        let app = App::new();
        assert!(
            !app.pending_goto,
            "pending_goto starts false — operator hasn't pressed g yet"
        );
    }
}
