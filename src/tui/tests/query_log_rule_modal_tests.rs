use super::*;

fn rows() -> Vec<ListRow> {
    vec![
        ListRow::new(
            "exceptions".into(),
            "exceptions".into(),
            vec!["default".into(), "guests".into()],
        ),
        ListRow::new("minecraft".into(), "minecraft".into(), vec!["kids".into()]),
        ListRow::new("triage".into(), "triage".into(), Vec::new()),
    ]
}

fn open_picker(action: Action) -> QueryLogRuleModal {
    QueryLogRuleModal::open(action, "dl.flathub.org".into(), "tv-salotto".into(), rows())
}

fn dto(result: &str, domain: &str) -> crate::ipc::protocol::QueryLogDto {
    crate::ipc::protocol::QueryLogDto {
        timestamp: "2026-05-02T10:00:00Z".into(),
        client_ip: "10.10.1.50".into(),
        client_name: Some("iphone".into()),
        domain: domain.into(),
        query_type: "A".into(),
        result: result.into(),
        response_time_us: 900,
        cname_chain_via: None,
    }
}

// ── inferred_action — moved here unchanged with the module rename ─────

#[test]
fn inferred_action_blocked_returns_allow() {
    assert_eq!(inferred_action("BLOCKED"), Some(Action::Allow));
}

#[test]
fn inferred_action_allowed_returns_deny() {
    assert_eq!(inferred_action("ALLOWED"), Some(Action::Deny));
}

#[test]
fn inferred_action_cached_treated_as_allowed_for_blocklisting() {
    // Both are cache-path outcomes for a query the resolver already let
    // through, so the operator's intent is identical to plain ALLOWED.
    assert_eq!(inferred_action("CACHED"), Some(Action::Deny));
}

#[test]
fn inferred_action_stale_treated_as_allowed_for_blocklisting() {
    assert_eq!(inferred_action("STALE"), Some(Action::Deny));
}

#[test]
fn inferred_action_local_returns_none() {
    assert_eq!(inferred_action("LOCAL"), None);
}

#[test]
fn inferred_action_refused_returns_none() {
    assert_eq!(inferred_action("REFUSED"), None);
    assert_eq!(inferred_action("HINFO"), None);
}

#[test]
fn inferred_action_unknown_status_returns_none() {
    // A future daemon-emitted status must fall through to "not
    // actionable", never to a wrong action.
    assert_eq!(inferred_action("DROPPED"), None);
    assert_eq!(inferred_action(""), None);
}

#[test]
fn open_for_query_row_blocked_returns_allow_picker() {
    let m = QueryLogRuleModal::open_for_query_row(
        &dto("BLOCKED", "ads.example"),
        "iphone".into(),
        rows(),
    )
    .expect("BLOCKED is actionable");
    assert_eq!(m.action, Action::Allow);
    assert_eq!(m.domain, "ads.example");
}

#[test]
fn open_for_query_row_allowed_returns_deny_picker() {
    let m = QueryLogRuleModal::open_for_query_row(
        &dto("ALLOWED", "tracker.example"),
        "iphone".into(),
        rows(),
    )
    .expect("ALLOWED is actionable");
    assert_eq!(m.action, Action::Deny);
}

#[test]
fn open_for_query_row_local_returns_none() {
    assert!(QueryLogRuleModal::open_for_query_row(
        &dto("LOCAL", "nas.lan"),
        "iphone".into(),
        rows()
    )
    .is_none());
}

// ── the picker's selection model ──────────────────────────────────────

#[test]
fn the_picker_opens_with_nothing_selected() {
    // A default that writes into the wrong list is worse than one more
    // keystroke, and the picker cannot know which list a domain belongs
    // in. Mutating `selected: false` to `true` in `ListRow::new` fails
    // here.
    let m = open_picker(Action::Allow);
    assert!(m.selected_ids().is_empty());
    assert!(m.rows.iter().all(|r| !r.selected));
}

#[test]
fn space_toggles_the_focused_row_only() {
    let mut m = open_picker(Action::Allow);
    m.toggle();
    assert_eq!(m.selected_ids(), vec!["exceptions".to_string()]);
    m.move_cursor(1);
    m.toggle();
    assert_eq!(
        m.selected_ids(),
        vec!["exceptions".to_string(), "minecraft".to_string()]
    );
    // And back off again — the mark is a toggle, not a latch.
    m.toggle();
    assert_eq!(m.selected_ids(), vec!["exceptions".to_string()]);
}

#[test]
fn selected_ids_follow_draw_order_not_click_order() {
    // The report is read against the rows on screen, so the write order
    // has to be the drawn order regardless of which mark came first.
    let mut m = open_picker(Action::Allow);
    m.cursor = 2;
    m.toggle();
    m.cursor = 0;
    m.toggle();
    assert_eq!(
        m.selected_ids(),
        vec!["exceptions".to_string(), "triage".to_string()]
    );
}

#[test]
fn the_cursor_wraps_in_both_directions() {
    let mut m = open_picker(Action::Allow);
    m.move_cursor(-1);
    assert_eq!(m.cursor, 2);
    m.move_cursor(1);
    assert_eq!(m.cursor, 0);
}

#[test]
fn cursor_and_toggle_are_inert_with_no_lists() {
    let mut m = QueryLogRuleModal::open(Action::Allow, "d".into(), "c".into(), Vec::new());
    m.move_cursor(1);
    m.toggle();
    assert_eq!(m.cursor, 0);
    assert!(m.selected_ids().is_empty());
}

#[test]
fn a_row_states_where_its_list_is_mounted() {
    let r = rows();
    assert_eq!(r[0].mount_note(), "\u{2192} profiles: default, guests");
    assert_eq!(r[1].mount_note(), "\u{2192} profiles: kids");
}

#[test]
fn a_list_no_profile_mounts_says_so_in_the_frozen_words() {
    // The whole point of the row: writing into an unmounted list is
    // legal and silent, so the picker declares it at the moment the
    // operator would otherwise find out days later.
    assert_eq!(rows()[2].mount_note(), NOT_MOUNTED);
    assert_eq!(NOT_MOUNTED, "no profile \u{2014} filters nothing");
}

#[test]
fn an_unmounted_list_is_still_choosable() {
    // `ChoiceNote::Blocked` would recess the label AND make the row
    // unselectable. A staging list is exactly the list an operator
    // means to write into before mounting it, so the note has to be
    // `Detail`.
    let m = open_picker(Action::Allow);
    let spec = pick_notice(&m, 62);
    let unmounted = &spec.choices[2];
    assert!(
        !unmounted.note.as_ref().unwrap().blocks(),
        "an unmounted list must stay selectable"
    );
}

#[test]
fn a_marked_row_shows_a_filled_box() {
    let mut m = open_picker(Action::Allow);
    m.toggle();
    let spec = pick_notice(&m, 62);
    assert!(spec.choices[0].label.starts_with("[x] "));
    assert!(spec.choices[1].label.starts_with("[ ] "));
}

#[test]
fn enter_with_nothing_marked_says_why() {
    // The picker opens at zero selections, so an empty Enter is routine
    // — and a silent one reads as a dead key.
    let mut m = open_picker(Action::Allow);
    m.note_no_selection();
    assert_eq!(m.error.as_deref(), Some(NO_SELECTION));
    // Marking something clears it: a rejection describes one selection,
    // and a stale one contradicting the screen is worse than silence.
    m.toggle();
    assert!(m.error.is_none());
}

#[test]
fn header_names_the_action_and_the_domain() {
    assert_eq!(
        header(&open_picker(Action::Allow)),
        "Add ALLOW for  dl.flathub.org"
    );
    assert_eq!(
        header(&open_picker(Action::Deny)),
        "Add DENY for  dl.flathub.org"
    );
}

// ── the create-a-list detour ──────────────────────────────────────────

#[test]
fn n_opens_the_custom_lists_add_form() {
    let mut m = open_picker(Action::Allow);
    m.begin_new_list("/etc/purge-warden/packs".into());
    assert!(matches!(m.stage, Stage::NewList(_)));
    // Esc grants nothing and takes nothing.
    m.cancel_new_list();
    assert!(matches!(m.stage, Stage::Picking));
    assert!(m.selected_ids().is_empty());
}

#[test]
fn a_created_list_comes_back_marked_and_under_the_cursor() {
    // Not a preselected default: the operator created this list, in this
    // flow, for this rule. Dropping back to zero after that is the
    // footgun.
    let mut m = open_picker(Action::Allow);
    m.toggle(); // exceptions
    m.begin_new_list("packs".into());
    let mut after = rows();
    after.push(ListRow::new("staging".into(), "staging".into(), Vec::new()));
    m.adopt_lists(after, Some("staging"));
    assert!(matches!(m.stage, Stage::Picking));
    assert_eq!(m.cursor, 3);
    assert_eq!(
        m.selected_ids(),
        vec!["exceptions".to_string(), "staging".to_string()],
        "the marks made before the detour must survive it"
    );
}

#[test]
fn adopt_lists_drops_a_mark_whose_list_is_gone() {
    let mut m = open_picker(Action::Allow);
    m.cursor = 1;
    m.toggle(); // minecraft
    m.adopt_lists(vec![rows()[0].clone()], None);
    assert!(m.selected_ids().is_empty());
    assert_eq!(m.cursor, 0);
}

// ── render ────────────────────────────────────────────────────────────

/// Row-per-line dump. The newline matters: without it a substring can
/// straddle a row boundary and match text that is not on any single
/// rendered row.
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

fn render_overlay_in(modal: &QueryLogRuleModal, w: u16, h: u16) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
    dump_buffer(term.backend().buffer())
}

/// The modal's interior, row by row, with the frame and the trailing pad
/// stripped.
///
/// Asserting on the raw dump instead lets the frame glyph sit between
/// `trim_start` and the text, which is how a row-leads-with-the-id
/// assertion reads the border rather than the content.
fn modal_rows(dump: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|l| {
            let a = l.find('\u{2502}')?;
            let b = l.rfind('\u{2502}')?;
            if b <= a {
                return None;
            }
            Some(l[a + '\u{2502}'.len_utf8()..b].trim_end().to_string())
        })
        .collect()
}

#[test]
fn every_frozen_row_reaches_the_screen_whole() {
    // The two defects this pins were both visible in a rendered dump and
    // both survived a handler test, a spec test and four green gates:
    // the note broke mid-word (`on. M` / `ount it from`) because the only
    // wrapping `prose_rows` offers is a hard character chunk, and the key
    // legend ran off the frame (`[Esc] canc`) because `nav_keys_line`
    // does not truncate — the row is clipped, unmarked.
    //
    // Both widths, because the modal is 64 columns whatever the terminal
    // is: the 80-column case proves the copy, the 64-column case proves
    // it against the narrowest interior the ecosystem hands a row.
    for w in [80u16, 64] {
        let dump = render_overlay_in(&open_picker(Action::Allow), w, 40);
        let rows = modal_rows(&dump);
        for want in MOUNT_NOTE_ROWS.iter().chain(std::iter::once(&KEYS_PICK)) {
            assert!(
                rows.iter().any(|r| r.trim() == *want),
                "at {w} columns no row is exactly {want:?} — it was cut or \
                 re-wrapped:\n{dump}"
            );
        }
        assert!(
            !rows.iter().any(|r| r.contains('\u{2026}')),
            "a row was ellipsised at {w} columns:\n{dump}"
        );
    }
}

#[test]
fn the_mount_note_is_split_where_a_reader_would_split_it() {
    // The rows are the author's line breaks, so rejoining them on single
    // spaces has to give the sentence back. A split that landed mid-word
    // — which is exactly what the renderer's own wrap does — would put
    // the space inside a word and fail here, and a dropped clause would
    // fail here too.
    assert_eq!(
        MOUNT_NOTE_ROWS.join(" "),
        "A custom list only filters the profiles it is mounted on. \
         Mount it from Filters → Profiles, or with [m] on Filters → Custom Lists."
    );
    assert!(
        MOUNT_NOTE_ROWS
            .iter()
            .all(|r| !r.starts_with(' ') && !r.ends_with(' ')),
        "a row carrying its own padding would double the join's space"
    );
}

#[test]
fn every_row_states_its_mount_state_even_unfocused() {
    // A picker exists so its options can be compared BEFORE the cursor
    // reaches them. The inline `detail` slot is ellipsised at the
    // interior width, which is why the mount state rides its own note
    // row instead.
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    for needle in ["profiles: default, guests", "profiles: kids", "no profile"] {
        assert!(
            dump.contains(needle),
            "{needle} missing from an unfocused row:\n{dump}"
        );
    }
}

#[test]
fn the_focus_marker_is_unique() {
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    assert_eq!(
        dump.matches('\u{25c0}').count(),
        1,
        "exactly one focused option marker expected:\n{dump}"
    );
}

#[test]
fn a_refusal_reaches_the_screen() {
    // `hint_rows: Some(0)` buys content rows and swallows the error
    // whole — `hint_or_error_rows` emits nothing for a zero budget. This
    // is the test that catches that pin.
    let mut m = open_picker(Action::Allow);
    m.note_no_selection();
    let dump = render_overlay_in(&m, 80, 40);
    assert!(
        dump.contains(NO_SELECTION),
        "the refusal must be on screen:\n{dump}"
    );
}

#[test]
fn the_empty_state_offers_the_way_out() {
    // An operator with zero custom lists must not find a picker with
    // nothing in it and no exit.
    let m = QueryLogRuleModal::open(
        Action::Allow,
        "dl.flathub.org".into(),
        "tv-salotto".into(),
        Vec::new(),
    );
    let dump = render_overlay_in(&m, 80, 40);
    assert!(dump.contains("[n] new list"), "no way out:\n{dump}");
    assert!(dump.contains("no custom lists"), "{dump}");
}

#[test]
fn the_report_names_every_list_and_leads_with_its_id() {
    // Three of five succeeding does not collapse into one toast, and a
    // long refusal must lose its tail rather than its identity.
    let mut m = open_picker(Action::Allow);
    m.finish(vec![
        RuleReport {
            id: "exceptions".into(),
            outcome: RuleOutcome::Added,
        },
        RuleReport {
            id: "minecraft".into(),
            outcome: RuleOutcome::AlreadyPresent,
        },
        RuleReport {
            id: "triage".into(),
            outcome: RuleOutcome::Failed("custom list file packs/triage.txt does not exist".into()),
        },
    ]);
    let dump = render_overlay_in(&m, 80, 40);
    for (id, verdict) in [
        ("exceptions", "rule added"),
        ("minecraft", "already present"),
        ("triage", "does not exist"),
    ] {
        let rows = modal_rows(&dump);
        let row = rows
            .iter()
            .find(|l| l.contains(id))
            .unwrap_or_else(|| panic!("{id} missing from the report:\n{dump}"));
        assert!(
            row.trim_start().starts_with(id),
            "the id must lead the row: {row:?}"
        );
        assert!(row.contains(verdict), "{id}: {row:?}\n{dump}");
    }
    assert!(
        dump.contains("1 of 3 lists did not accept it"),
        "the headline must count the refusals:\n{dump}"
    );
}

#[test]
fn already_present_is_reported_as_an_outcome_not_a_failure() {
    // Idempotence is the pack writers' contract; reporting a no-op as an
    // error sends the operator looking for a line that is not there.
    let mut m = open_picker(Action::Allow);
    m.finish(vec![RuleReport {
        id: "exceptions".into(),
        outcome: RuleOutcome::AlreadyPresent,
    }]);
    let dump = render_overlay_in(&m, 80, 40);
    assert!(dump.contains("written to every list you marked"), "{dump}");
    assert!(!dump.contains("did not accept"), "{dump}");
}

#[test]
fn floor_keeps_the_action_row_and_the_focused_row_on_screen_together() {
    // The two things a clip silently takes away. Asserted on the
    // rendered buffer, never on the line vector: the vector was correct
    // in every past instance of this defect — only the render was wrong.
    let mut m = open_picker(Action::Allow);
    m.cursor = m.rows.len() - 1;
    let dump = render_overlay_in(&m, 80, 14);
    assert!(
        dump.contains("triage"),
        "the focused row must be in the viewport:\n{dump}"
    );
    assert!(
        dump.contains("Confirm"),
        "the action row must survive the clamp:\n{dump}"
    );
}

#[test]
fn overlay_is_confined_to_the_anchor_rect() {
    // The anchor is the tab content rect, so the header, the menu card
    // and the footer legend stay visible behind the modal. Anchoring on
    // `f.area()` instead paints over all three.
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let anchor = Rect {
        x: 0,
        y: 9,
        width: 80,
        height: 14,
    };
    let m = open_picker(Action::Allow);
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| render_overlay(f, anchor, &m)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    for (y, row) in dump.lines().enumerate() {
        let outside = y < anchor.y as usize || y >= (anchor.y + anchor.height) as usize;
        if outside {
            assert!(
                row.trim().is_empty(),
                "row {y} is outside the anchor but was painted: {row:?}\n{dump}"
            );
        }
    }
}

#[test]
fn the_create_form_is_drawn_by_the_custom_lists_modal() {
    // Two routes to one form. Rendering a second copy here is how the
    // two drift into looking different.
    let mut m = open_picker(Action::Allow);
    m.begin_new_list("/etc/purge-warden/packs".into());
    let dump = render_overlay_in(&m, 80, 40);
    assert!(
        dump.contains("/etc/purge-warden/packs"),
        "the add-list form's path row must be on screen:\n{dump}"
    );
    assert!(
        !dump.contains("no profile"),
        "the picker must not be drawn underneath the form:\n{dump}"
    );
}

// ── module hygiene ────────────────────────────────────────────────────

#[test]
fn no_hand_rolled_colour_in_this_module() {
    // A surface that reaches for the theme directly is a surface that
    // will drift from the other eleven. Needles are split so this
    // assertion cannot match itself.
    let src = include_str!("../query_log_rule_modal.rs");
    for needle in [
        concat!("Style::default()", ".fg("),
        concat!("Color", "::Rgb("),
        concat!("T", ".brand_red"),
    ] {
        assert!(
            !src.contains(needle),
            "{needle} in query_log_rule_modal.rs — the colour belongs in modal_form"
        );
    }
}

#[test]
fn this_surface_writes_no_admin_rule() {
    // The Query Log's route to `[[admin_rules]]` is gone: the rule lands
    // in a pack file the operator owns. A `use` of the rules writer
    // creeping back in is the regression this pins — `add_inner` itself
    // is alive and still reached from the Rules tab.
    // Comment lines are skipped: this module's own doc names
    // `[[admin_rules]]` to say the picker does NOT write one, and a scan
    // that read its own prose would be red on the sentence that states
    // the invariant.
    let src: String = include_str!("../query_log_rule_modal.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["add_inner", "Scope::", "admin_rules"] {
        assert!(
            !src.contains(needle),
            "{needle} is back in query_log_rule_modal.rs"
        );
    }
}

#[test]
fn fit_passes_through_when_short_enough() {
    assert_eq!(fit("hello", 10), "hello");
    assert_eq!(fit("hello", 5), "hello");
}

#[test]
fn fit_truncates_with_ellipsis_when_too_long() {
    assert_eq!(fit("hello world", 5), "hell\u{2026}");
    assert_eq!(fit("hello world", 5).chars().count(), 5);
}

#[test]
fn fit_zero_width_is_empty() {
    assert_eq!(fit("hello", 0), "");
}

#[test]
fn fit_is_char_aware_not_byte_aware() {
    // A multi-byte id must not panic on a byte boundary.
    assert_eq!(fit("àèìòù", 3).chars().count(), 3);
}

#[test]
fn no_inline_test_module_remains_in_query_log_rule_modal() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "query_log_rule_modal.rs",
        include_str!("../query_log_rule_modal.rs"),
    );
}

#[test]
#[ignore = "visual smoke — run with --ignored --nocapture"]
fn picker_visual_dump() {
    let mut m = open_picker(Action::Allow);
    m.toggle();
    println!("--- picker ---\n{}", render_overlay_in(&m, 80, 24));
    m.note_no_selection();
    println!("--- refused ---\n{}", render_overlay_in(&m, 64, 24));
    m.finish(vec![
        RuleReport {
            id: "exceptions".into(),
            outcome: RuleOutcome::Added,
        },
        RuleReport {
            id: "triage".into(),
            outcome: RuleOutcome::Failed("pack file does not exist".into()),
        },
    ]);
    println!("--- report ---\n{}", render_overlay_in(&m, 80, 24));
}
