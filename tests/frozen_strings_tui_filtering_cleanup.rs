//! Filtering-cleanup pass — Rules HITS column + Lists category
//! grouping deletion, pinned by source inspection.
//!
//! `tabs::rules` and `tabs::lists` are private modules (`mod tabs;` in
//! `src/tui/mod.rs`), so an external integration test cannot import
//! their render functions directly. This file follows the established
//! `include_str!` source-grep idiom used by
//! `tests/frozen_strings_s49_profile_editor_tui.rs` (see that file's
//! header comment) instead of promoting the module to `pub`.
//!
//! Pins two facts:
//! - Rules table header is exactly ID · SCOPE · ACTION · DOMAIN · RULE
//!   (no HITS column — `rule.hits` was always `None`, never wired).
//! - Lists tab has no category-grouping header row model left
//!   (`ListRow::Header`, `canonical_category_id`, `category_order`,
//!   `UNCATEGORIZED_LABEL` are all gone) — the table renders a flat
//!   row per blocklist.

fn rules_src() -> &'static str {
    include_str!("../src/tui/tabs/rules.rs")
}

fn lists_src() -> &'static str {
    include_str!("../src/tui/tabs/lists.rs")
}

#[test]
fn rules_table_header_is_five_columns_no_hits() {
    let src = rules_src();
    let needle = "let header = Row::new(vec![\n        Cell::from(\"ID\"),\n        Cell::from(\"SCOPE\"),\n        Cell::from(\"ACTION\"),\n        Cell::from(\"DOMAIN\"),\n        Cell::from(\"RULE\"),\n    ])";
    assert!(
        src.contains(needle),
        "tabs/rules.rs header row must be exactly ID · SCOPE · ACTION · \
         DOMAIN · RULE, in that order, with no HITS cell"
    );
    assert!(
        !src.contains("HITS"),
        "tabs/rules.rs must not reference a HITS column anywhere — \
         rule.hits was always None, never wired to real telemetry"
    );
}

#[test]
fn lists_tab_has_no_category_grouping_machinery() {
    let src = lists_src();
    for needle in [
        "ListRow::Header",
        "canonical_category_id",
        "category_order",
        "UNCATEGORIZED_LABEL",
        "LISTS_TAB_CATEGORY_HEADER",
        "format_lists_tab_category_header",
    ] {
        assert!(
            !src.contains(needle),
            "tabs/lists.rs must not reference `{needle}` — v2 (Sprint A) \
             removed the Category entity; the grouping-header row model \
             built on it is dead code that must be deleted, not left \
             unreachable"
        );
    }
}

#[test]
fn lists_build_grouped_rows_returns_a_flat_row_vec() {
    let src = lists_src();
    assert!(
        src.contains("pub fn build_grouped_rows(app: &App) -> Vec<ListRowMeta>"),
        "tabs/lists.rs::build_grouped_rows must return a flat \
         Vec<ListRowMeta> — one row per blocklist, no header rows \
         interleaved"
    );
}
