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

// `used_by_returns_profiles_referencing_canonical_id` no longer
// applies: "uses" is defined by `effective_direction`, not tag
// intersection — see `profiles_using_blocklist`.

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

// ── USED BY + cascade follow `effective_direction` ───────────────

/// A config in a realistic zero-tag shape — the shape the retired
/// predicate answered `[]` for.
///
/// `home` declares an override, `guest` inherits, `off` opts out with
/// `ignore`. **No profile carries a tag and `blocked` carries none
/// either**, which is deliberate: zero tagged profiles is the
/// realistic operator config, so tag intersection returns the
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
// No category-grouping header rows exist any more — the
// `[[categories]]` entity and `Blocklist.category` field are gone,
// and the Lists tab renders a flat row-per-list table. Cursor
// movement is plain clamped increment/decrement (no headers to
// skip); see `next_selectable_index`'s doc comment for why this
// one, unlike Devices, never returns `None` at the boundary.

#[test]
fn next_selectable_index_clamps_at_both_ends() {
    let rows = vec![test_meta("a"), test_meta("b"), test_meta("c")];
    assert_eq!(next_selectable_index(&rows, None, 1), Some(0));
    assert_eq!(next_selectable_index(&rows, Some(0), 1), Some(1));
    // From the last row, forward clamps — no wrap to row 0.
    assert_eq!(next_selectable_index(&rows, Some(2), 1), Some(2));
    // From the first row, backward clamps — no wrap to the last.
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

// `focused_list_returns_none_on_header_row` no longer applies —
// there are no more header rows to test against. Cursor-guard
// semantics survive in `next_selectable_index_*` above.

// ── Kind badge presence ──────────────────────────────────────────

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
    meta.trust = BlocklistTrust::Local; // allow requires local trust.
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

// The create-category, move-category, and list↔profile assignment
// modals were unmounted — categories and tags are retired entirely;
// a list's direction is now edited as `base` in the edit modal, with
// no separate chip picker or Tags tab. Their builder tests went with
// them (build_create_category_modal_starts_empty,
// build_move_category_modal_returns_none_*, build_assignment_modal_*).

#[test]
fn build_row_uses_canonical_id_when_present_does_not_panic() {
    let mut app = App::new();
    let now = time::OffsetDateTime::now_utc();
    let status = ListStatus::from_refresh(123, ParsedCounts::default(), None, now);
    let dto =
        BlocklistStatusDto::from_status("privacy/ads".into(), Some("privacy-ads".into()), &status);
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

// ── Dedup by canonical_id ──────────────────────────────────────

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

// ── URL→id fallback in build_meta ────────────────────────────────

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

// ── List edit modal builder + state transitions ──────────────────

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

// The chip picker's tests were removed along with the picker
// itself — every one of them tested a function this lane deleted,
// so there is no substitute to point at: the guarantees left with
// the picker. One is worth naming: it pinned that the Add modal
// does not pre-seed `uncategorized` into the picker. That property
// is now enforced by construction instead, because
// `build_blocklist_value` writes no `tags` key at all.

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

/// When the most recent successful refresh is
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

/// A list that has been attempted, but never once succeeded: `fetched_at`
/// is recent (the failed attempt), `last_refresh_at` is `None`. Before
/// this fix the LAST UPDATE cell read `fetched_at` while the badge read
/// `last_refresh_at`, so the row could show a plausible-looking recent
/// timestamp with no `Stale` badge next to it — reading as fresh when
/// nothing has ever actually loaded. Both must now agree: no timestamp,
/// no badge: the operator relies on STATUS ("failed") instead.
#[test]
fn last_update_and_stale_badge_agree_when_never_succeeded() {
    let now = OffsetDateTime::now_utc();
    let five_minutes_ago = now - time::Duration::minutes(5);
    let dto = BlocklistStatusDto {
        source: "privacy/ads".into(),
        id: Some("privacy-ads".into()),
        last_outcome: "failed: HTTP 502".into(),
        fetched_at: Some(five_minutes_ago.format(&Rfc3339).unwrap()),
        last_refresh_at: None,
        ..Default::default()
    };
    let is_stale = is_stale_for_dto(&dto, 86_400, now);
    assert!(
        !is_stale,
        "no successful refresh ever happened — nothing to call stale"
    );

    let attempted_at_text = format_short_timestamp(dto.fetched_at.as_deref().unwrap());
    let meta = ListRowMeta {
        dto,
        display_name: "Privacy: Ads".into(),
        canonical_id: Some("privacy-ads".into()),
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        format: Some(BlocklistFormat::Domains),
        used_by_profiles: Vec::new(),
        is_stale,
        inert_reason: None,
    };
    let rendered = row_text(&render_list_row(meta));
    assert!(
        rendered.contains("<never>"),
        "cell must not fabricate a success timestamp from a failed attempt: {rendered}"
    );
    assert!(
        !rendered.contains(&attempted_at_text),
        "the failed attempt's timestamp must not leak into LAST UPDATE: {rendered}"
    );
    assert!(
        !rendered.contains("Stale"),
        "badge must agree with the cell — neither claims a success occurred: {rendered}"
    );
}

// ── The stable selection key ──────────────────────────────────────

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
/// **This fixture's rewrite is a correction rather than a rename.**
/// It used to build an untagged allow-list and a list tagged with a
/// slug nobody carries, because `inert_blocklists` produced
/// `AllowListNoTags` / `TagsMatchNothing`. Both variants were
/// retired — an allow-direction list is now inherited by every
/// profile that does not override it, so calling it inert asserted
/// the opposite of the truth — and `BaseIgnore` is the only reason
/// the predicate emits. A fixture that cannot produce the
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

/// Two lists that are actually inert (`base = "ignore"` on both),
/// unlike `app_with_two_inert_lists` whose second slot is now a
/// control arm proving a retired reason stays retired (see its doc
/// comment). Exists so the summary band's plural shape and its
/// wrapped-height math get exercised by at least one test.
fn app_with_two_genuinely_inert_lists() -> App {
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
id = "orphaned-a"
display_name = "Ignored List A"
url = "https://example.com/orphaned-a.txt"
base = "ignore"

[[blocklists]]
id = "orphaned-b"
display_name = "Ignored List B"
url = "https://example.com/orphaned-b.txt"
base = "ignore"
"#,
    )
    .unwrap();
    let loaded =
        crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let mut app = App::new();
    app.lists.entries = vec![
        dto_for("healthy", "https://example.com/healthy.txt"),
        dto_for("orphaned-a", "https://example.com/orphaned-a.txt"),
        dto_for("orphaned-b", "https://example.com/orphaned-b.txt"),
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
    // asserted the opposite once, and the assertion is kept
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

    let mut app = App::new();
    let backend = TestBackend::new(170, 8);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        render_table(f, f.area(), &mut app, std::slice::from_ref(&meta));
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

    let mut app = app_with_no_inert_lists();
    let backend = TestBackend::new(170, 16);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        render(f, f.area(), &mut app);
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

    let mut app = app_with_two_inert_lists();
    let backend = TestBackend::new(170, 16);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        render(f, f.area(), &mut app);
    })
    .unwrap();

    let dump = dump_buffer(term.backend().buffer());
    assert!(
        dump.contains('\u{26A0}'),
        "an inert fleet must render the badge glyph:\n{dump}"
    );
    // ONE, not two. The fixture used to carry an untagged
    // allow-list and a tags-match-nothing list; both reasons were
    // retired, so only the `base = ignore` list is inert now. The lede
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

/// The band above must not silently drop the second reason. A fixed
/// 3-row band fit exactly one reason at the 80-col floor and clipped
/// the tail of the second; `alert_band_height` measures the real
/// paragraph instead, so both must survive here.
#[test]
fn inert_summary_band_fits_two_reasons_at_the_80_col_floor() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = app_with_two_genuinely_inert_lists();
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
    let dump = dump_buffer(term.backend().buffer());
    let normalized = dump.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        normalized.contains("2 lists are filtering nothing:"),
        "plural lede must be pinned exactly:\n{dump}"
    );
    assert!(
        normalized.contains(&format_base_ignore_list_is_inert("orphaned-a")),
        "first reason must not be clipped:\n{dump}"
    );
    assert!(
        normalized.contains(&format_base_ignore_list_is_inert("orphaned-b")),
        "second reason must not be clipped — this is the row a fixed \
         3-row band used to lose:\n{dump}"
    );
    assert!(
        dump.contains("Healthy List"),
        "the band must not evict the table it sits above:\n{dump}"
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

// Four render tests that exercised the tag chip picker were removed
// with it; there is no substitute surface, so the guarantees go
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

// A test that pinned the tags row's old inline "(type / ↑↓ pick / …)"
// hint staying dropped (it used to overflow the modal body and clip
// mid-word) was removed with the row it guarded — the overflow it
// guarded against is unreachable now.
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
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
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
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
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
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
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
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
    let dump = dump_buffer(term.backend().buffer());
    // Word-wrap pads every row out to the paragraph's width, so a
    // sentence that wraps mid-phrase no longer reads as one
    // contiguous substring of the raw dump even though every word
    // is on screen — same normalization as the inert-summary tests.
    let normalized = dump.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        dump.contains("CORPUS REFUSED"),
        "the band must survive the 80x24 floor:\n{dump}"
    );
    assert!(
        normalized.contains("privacy-ads"),
        "the trailing largest-contributor clause must not be clipped \
         at the 80-col floor — a fixed-height band used to lose it:\n{dump}"
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
    // Stated as "at most once per frame",
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
    // Toggling trust must change colour
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

    let local = edit_trust_row(BlocklistTrust::Local, 62);
    let text = flatten(&local);
    assert!(
        !text.contains("unverified") && !text.contains("unexpected"),
        "Local must not carry a caution tail: {text}"
    );
    assert!(
        local
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.scope_security)),
        "Local must read as healthy"
    );

    // Signed is deliberately NOT grouped with Local above: the
    // validator refuses `trust = signed`, so a row wearing it can only
    // exist via a bug elsewhere (`render_list_row` paints it the same
    // way, as a defensive beacon). It must read as caution, the same
    // colour as RemoteUnsigned, not Local's reassuring healthy green.
    let signed = edit_trust_row(BlocklistTrust::Signed, 62);
    let text = flatten(&signed);
    assert!(
        text.contains("validator refuses"),
        "Signed must explain why it is alarming: {text}"
    );
    assert!(
        signed
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.scope_content)),
        "Signed must read as caution, matching render_list_row's warning treatment"
    );
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
    // Colour derives from the state enum,
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

    let at_rest = modal_form::value_row("url", "https://x/y", false, ValueKind::Identity, None, 62);
    assert!(
        at_rest
            .spans
            .iter()
            .any(|s| s.style.fg == Some(T.scope_privacy)),
        "a url is identity-coloured at rest"
    );
    let focused = modal_form::value_row("url", "https://x/y", true, ValueKind::Identity, None, 62);
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
    // One filled button per modal, and destructive actions
    // are outlined — a filled red beside a filled primary is how an
    // operator deletes the list they meant to save.
    let row = modal_form::action_row(
        &[
            modal_form::Action::new("  Delete  ", true, modal_form::ActionKind::Destructive, ""),
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
                modal_form::Action::new("  Cancel  ", focused, modal_form::ActionKind::Neutral, ""),
                modal_form::Action::new("  Save  ", !focused, modal_form::ActionKind::Primary, ""),
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
    // 24 → 25 when `new_desc2` made the head 4 rows instead of 3.
    // That is the whole delta and it is deliberate — the number
    // exists to catch *creep*, so it moves when a change owns the row
    // and stays put otherwise.
    //
    // 25 → 24 when the tags chip-picker row left the FIELD region.
    // Same rule as above, in the cheap direction — a change that
    // owns the row moves the number. The head is unchanged at 4,
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

/// **At the floor**: the two description rows are on screen,
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

// ── The two remaining Lists overlays ──────────────────────────────
//
// `render_delete_confirm` and `render_catalog_picker` are private, so
// every render assertion about them has to live in this file —
// without these tests, an input row silently falling off the
// bottom of the floor-sized modal (see `delete_notice`'s doc
// comment) ships and survives unnoticed.
//
// All of them render at **80×14** — the fixed content rect at the
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

/// **The binding case of [`delete_notice`]'s row table — and until
/// this test, nothing rendered it.**
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

/// The neighbouring test proves the stage *can* render a
/// refusal — but with a hand-written string, so it says nothing about
/// what the handler actually produces. This one renders the real
/// message, and asserts the part that was missing: the EXPECTED id.
///
/// Both ids must survive at the 80x14 floor with a cascade target —
/// a refusal that only fits on a wide terminal is not a refusal the
/// operator gets.
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

/// The predecessor asked its `Layout::vertical` for 13 minimum rows
/// against the 12 the fixed anchor leaves, and ratatui resolves that by
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

/// The ecosystem chrome rule, read off lists.rs's source. Both
/// overlays used to draw their own all-sided `Block` with a
/// `brand_red` frame; `modal_form::render_chrome_in` owns every
/// modal frame now, and chrome stays neutral grey.
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
    let src = include_str!("../tabs/lists.rs");
    let borders = concat!("Borders", "::ALL");
    assert!(
        !src.contains(borders),
        "a hand-rolled modal frame is back — `modal_form::render_modal` owns modal chrome"
    );
    let border_style = concat!("border_style", "(");
    assert!(
        !src.contains(border_style),
        "a border may not carry colour — chrome stays neutral grey"
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
/// nothing — silently.
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
        println!("--- delete confirm, {label}, 80x14 (the fixed floor) ---");
        println!(
            "{}",
            render_delete_confirm_in(&modal, "ZZQQ", &cascade, 80, 14)
        );
    }
    // What the typed-id refusal would look like once it names both ids.
    let mut refused = delete_modal_for("steven-black-hosts");
    refused.error_message =
        Some("typed 'ZZQQ' does not match 'steven-black-hosts' — nothing deleted".to_string());
    println!("--- delete confirm, refusal + 1 target, 80x14 ---");
    println!(
        "{}",
        render_delete_confirm_in(&refused, "ZZQQ", &["kids".to_string()], 80, 14)
    );
    println!("--- catalog picker, 80x14 (the fixed floor) ---");
    println!("{}", render_picker_in(&picker_modal(), 80, 14));
    println!("--- catalog picker, 80x24 anchor ---");
    println!("{}", render_picker_in(&picker_modal(), 80, 24));
}

#[test]
fn no_raw_colour_literals_outside_the_token_module() {
    // Three refined-palette hexes lived
    // here because theme.rs still held the old Tailwind values; the
    // tokens now hold the refined trio, so there is no excuse left.
    // Needle is split so this assertion does not match itself.
    let needle = concat!("Color", "::Rgb(");
    assert!(
        !include_str!("../tabs/lists.rs").contains(needle),
        "raw RGB literal in lists.rs — add a named token to theme.rs instead"
    );
}

/// Discipline pin for the extract-test-blocks move: `lists.rs`'s
/// `#[cfg(test)] mod tests { ... }` now lives here via `#[path]`.
/// Scans the raw production source for a marker that still opens a
/// brace-delimited `mod` block — distinct from a standalone
/// `#[cfg(test)] fn` helper, which also opens a brace but is not this
/// shape — so a future rebase or merge that pastes a test module back
/// into `lists.rs` fails here instead of silently regrowing the file
/// this move just shrank.
#[test]
fn no_test_module_remains_inline_in_lists_rs() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "lists.rs",
        include_str!("../tabs/lists.rs"),
    );
}
