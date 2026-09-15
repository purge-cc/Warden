use super::*;

fn rows() -> Vec<ListRow> {
    vec![
        ListRow::new(
            "exceptions".into(),
            "exceptions".into(),
            vec!["default".into(), "guests".into()],
        )
        .with_description("Exceptions for everyday services".into()),
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
    let mut m = open_picker(Action::Allow);
    m.cursor = 2;
    m.toggle();
    assert_eq!(m.selected_ids(), vec!["triage".to_string()]);
    let dump = render_overlay_in(&m, 80, 40);
    assert!(dump.contains("[x] triage"), "{dump}");
    assert!(dump.contains("No Profiles · Filters Nothing"), "{dump}");
}

#[test]
fn a_marked_row_shows_a_filled_box() {
    let mut m = open_picker(Action::Allow);
    m.toggle();
    let dump = render_overlay_in(&m, 80, 40);
    assert!(dump.contains("[x] exceptions"), "{dump}");
    assert!(dump.contains("[ ] minecraft"), "{dump}");
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
fn header_names_the_action() {
    assert_eq!(header(&open_picker(Action::Allow)), "Add ALLOW Rule");
    assert_eq!(header(&open_picker(Action::Deny)), "Add DENY Rule");
}

#[test]
fn picker_focus_cycles_across_list_and_all_three_actions() {
    let mut modal = open_picker(Action::Allow);
    assert_eq!(modal.focus, 0);
    modal.focus_next();
    assert_eq!(modal.focus, 1);
    modal.focus_next();
    assert_eq!(modal.focus, 2);
    modal.focus_next();
    assert_eq!(modal.focus, 3);
    modal.focus_next();
    assert_eq!(modal.focus, 0);
    modal.focus_prev();
    assert_eq!(modal.focus, 3);
}

#[test]
fn empty_picker_focus_cycles_across_empty_state_and_two_actions() {
    let mut modal = QueryLogRuleModal::open(Action::Allow, "d".into(), "c".into(), Vec::new());
    assert_eq!(modal.focus, 0);
    modal.focus_prev();
    assert_eq!(modal.focus, 1);
    modal.focus_next();
    assert_eq!(modal.focus, 0);

    let dump = render_overlay_in(&modal, 80, 40);
    assert!(dump.contains("Cancel"));
    assert!(dump.contains("New List"));
    assert!(!dump.contains("Confirm"));
}

#[test]
fn pointer_confirm_focuses_confirm_before_dispatching_enter() {
    let mut modal = open_picker(Action::Allow);
    modal.focus = 1;
    modal.focus_pointer_action(KeyCode::Enter);
    assert_eq!(modal.focus, 3);

    modal.focus_pointer_action(KeyCode::Char('n'));
    assert_eq!(modal.focus, 2);
    modal.focus_pointer_action(KeyCode::Esc);
    assert_eq!(modal.focus, 1);
}

#[test]
fn picker_body_uses_the_reference_26_row_geometry() {
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    let rows = modal_rows(&dump);
    assert_eq!(
        rows.len(),
        24,
        "26 outer rows means 24 interior rows\n{dump}"
    );
    for line in dump.lines().filter(|line| line.matches('│').count() == 2) {
        let columns: Vec<_> = line
            .chars()
            .enumerate()
            .filter_map(|(column, ch)| (ch == '│').then_some(column))
            .collect();
        assert_eq!(columns[1] - columns[0] + 1, 68, "{line:?}");
    }
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

#[test]
fn report_scroll_is_bounded_and_finish_resets_it() {
    let mut modal = open_picker(Action::Allow);
    let reports = (0..8)
        .map(|index| RuleReport {
            id: format!("list-{index}"),
            outcome: RuleOutcome::Added,
        })
        .collect();
    modal.finish(reports);
    modal.scroll_report(-1);
    assert_eq!(modal.report_scroll, 0);
    modal.report_end();
    assert_eq!(modal.report_scroll, 4);
    modal.scroll_report(1);
    assert_eq!(modal.report_scroll, 4);
    modal.report_home();
    assert_eq!(modal.report_scroll, 0);
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

fn render_buffer(modal: &QueryLogRuleModal, w: u16, h: u16) -> ratatui::buffer::Buffer {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
    term.backend().buffer().clone()
}

fn render_overlay_in(modal: &QueryLogRuleModal, w: u16, h: u16) -> String {
    dump_buffer(&render_buffer(modal, w, h))
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
fn picker_uses_the_compact_reference_structure() {
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    for text in [
        "ADD ALLOW RULE",
        "Choose Custom Lists for This Rule",
        "Domain",
        "dl.flathub.org",
        "Client",
        "tv-salotto",
        "CUSTOM LISTS",
        "0 Selected",
        "1–3 of 3 Lists",
        "Cancel",
        "New List",
        "Confirm",
    ] {
        assert!(dump.contains(text), "missing {text:?}:\n{dump}");
    }
    for legacy in ["which lists?", "the rule is written", "[space] select"] {
        assert!(!dump.contains(legacy), "legacy copy {legacy:?}:\n{dump}");
    }
}

#[test]
fn the_long_mount_contract_is_not_rendered_in_the_compact_picker() {
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    for row in [
        "A custom list only filters the profiles it is mounted on.",
        "Mount it from Filters → Profiles, or with [m] on",
        "Filters → Custom Lists.",
    ] {
        assert!(!dump.contains(row), "legacy mount prose remains:\n{dump}");
    }
    assert!(dump.contains("Profiles: default, guests"), "{dump}");
}

#[test]
fn picker_range_follows_the_cursor_in_six_row_pages() {
    let rows = (0..8)
        .map(|index| ListRow::new(format!("list-{index}"), format!("List {index}"), Vec::new()))
        .collect();
    let mut modal = QueryLogRuleModal::open(
        Action::Deny,
        "telemetry.example".into(),
        "living-room".into(),
        rows,
    );
    modal.cursor = 7;
    let dump = render_overlay_in(&modal, 80, 40);
    assert!(dump.contains("3–8 of 8 Lists"), "{dump}");
    assert!(!dump.contains("[ ] List 1"), "{dump}");
    assert!(dump.contains("[ ] List 7"), "{dump}");
}

#[test]
fn report_range_scrolls_without_losing_failure_text() {
    let mut modal = open_picker(Action::Allow);
    modal.finish(
        (0..8)
            .map(|index| RuleReport {
                id: format!("list-{index}"),
                outcome: if index == 7 {
                    RuleOutcome::Failed("permission denied".into())
                } else {
                    RuleOutcome::Added
                },
            })
            .collect(),
    );
    modal.report_end();
    let dump = render_overlay_in(&modal, 80, 40);
    assert!(dump.contains("8 Lists · 1 Failed · 3–8 of 8"), "{dump}");
    assert!(dump.contains("list-7"), "{dump}");
    assert!(dump.contains("permission denied"), "{dump}");
}

#[test]
fn a_long_single_failure_is_wrapped_and_reaches_the_end_viewport() {
    let final_marker = "FINAL-RECOVERY-COMMAND";
    let mut modal = open_picker(Action::Allow);
    modal.finish(vec![RuleReport {
        id: "exceptions".into(),
        outcome: RuleOutcome::Failed(format!(
            "{}\n{final_marker}",
            "permission denied while validating the retained operation plan; ".repeat(16)
        )),
    }]);
    let first = render_overlay_in(&modal, 80, 40);
    assert!(
        !first.contains(final_marker),
        "marker should begin below the first viewport\n{first}"
    );
    modal.report_end();
    let end = render_overlay_in(&modal, 80, 40);
    assert!(
        end.contains(final_marker),
        "wrapped failure tail is unreachable:\n{end}"
    );
    assert!(end.contains("1 Lists · 1 Failed · 1–1 of 1"), "{end}");
}

#[test]
fn every_row_states_its_mount_state_even_unfocused() {
    // A picker exists so its options can be compared BEFORE the cursor
    // reaches them. The inline `detail` slot is ellipsised at the
    // interior width, which is why the mount state rides its own note
    // row instead.
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    for needle in [
        "Profiles: default, guests",
        "Profiles: kids",
        "No Profiles · Filters Nothing",
    ] {
        assert!(
            dump.contains(needle),
            "{needle} missing from an unfocused row:\n{dump}"
        );
    }
}

#[test]
fn only_the_focused_list_has_a_highlight() {
    let buffer = render_buffer(&open_picker(Action::Allow), 80, 40);
    let mut focused = Vec::new();
    for y in 0..buffer.area.height {
        let line = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>();
        if line.contains("[ ]")
            && (0..buffer.area.width).any(|x| buffer[(x, y)].bg == crate::tui::theme::T.warden_teal)
        {
            focused.push(line);
        }
    }
    assert_eq!(focused.len(), 1);
    assert!(focused[0].contains("exceptions"));
    assert!(!dump_buffer(&buffer).contains('◀'));
}

#[test]
fn selected_unfocused_list_uses_the_resting_selected_style() {
    let mut modal = open_picker(Action::Allow);
    modal.toggle();
    modal.move_cursor(1);
    let buffer = render_buffer(&modal, 80, 40);
    let selected_y = (0..buffer.area.height)
        .find(|&y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .contains("[x] exceptions")
        })
        .expect("selected row");
    assert!((0..buffer.area.width).any(|x| {
        let cell = &buffer[(x, selected_y)];
        cell.bg == crate::tui::theme::T.bg_highlight && cell.fg == crate::tui::theme::T.warden_teal
    }));
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
    assert!(
        dump.contains("Press n to Create One"),
        "no way out:\n{dump}"
    );
    assert!(dump.contains("No Custom Lists"), "{dump}");
    for action in ["Cancel", "New List"] {
        assert!(dump.contains(action), "missing {action}:\n{dump}");
    }
    assert!(
        !dump.contains("Confirm"),
        "empty picker cannot confirm:\n{dump}"
    );
}

#[test]
fn the_empty_state_and_new_list_action_survive_the_terminal_floor() {
    let modal = QueryLogRuleModal::open(
        Action::Allow,
        "dl.flathub.org".into(),
        "tv-salotto".into(),
        Vec::new(),
    );
    let dump = render_overlay_in(&modal, 80, 14);
    assert!(dump.contains("No Custom Lists"), "{dump}");
    assert!(dump.contains("New List"), "{dump}");
}

#[test]
fn a_multiline_single_failure_reaches_the_end_at_the_terminal_floor() {
    let marker = "FINAL-RECOVERY-COMMAND";
    let mut modal = open_picker(Action::Allow);
    modal.finish(vec![RuleReport {
        id: "exceptions".into(),
        outcome: RuleOutcome::Failed(format!(
            "validation failed\n{}\n{marker}",
            "retained operation plan detail ".repeat(12)
        )),
    }]);

    let first = render_overlay_in(&modal, 80, 14);
    assert!(!first.contains(marker), "{first}");
    modal.report_end();
    let end = render_overlay_in(&modal, 80, 14);
    assert!(end.contains(marker), "{end}");
    assert!(end.contains("Close"), "{end}");
}

#[test]
fn the_report_names_every_list_and_leads_with_its_id() {
    // Mixed outcomes stay attributed to their lists rather than collapsing
    // into one toast.
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
        ("exceptions", "Rule Added"),
        ("minecraft", "Already Present"),
        ("triage", "does not exist"),
    ] {
        let rows = modal_rows(&dump);
        let index = rows
            .iter()
            .position(|line| line.contains(id))
            .unwrap_or_else(|| panic!("{id} missing from the report:\n{dump}"));
        assert!(
            rows[index].trim_start().starts_with(id),
            "the id must lead the row: {:?}",
            rows[index]
        );
        assert!(
            rows.get(index + 1).is_some_and(|row| row.contains(verdict)),
            "{id}: {:?}\n{dump}",
            rows.get(index + 1)
        );
    }
    assert!(dump.contains("3 Lists · 1 Failed · 1–3 of 3"), "{dump}");
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
    assert!(dump.contains("1 Lists · 0 Failed"), "{dump}");
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
fn custom_lists_heading_uses_the_blue_summary_band() {
    let buffer = render_buffer(&open_picker(Action::Allow), 80, 40);
    let heading_y = (0..buffer.area.height)
        .find(|&y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .contains("CUSTOM LISTS")
        })
        .expect("CUSTOM LISTS heading");
    assert!((0..buffer.area.width)
        .any(|x| buffer[(x, heading_y)].bg == crate::tui::theme::T.card_summary_title_bg));
}

#[test]
fn focused_list_description_occupies_the_compact_footer() {
    let dump = render_overlay_in(&open_picker(Action::Allow), 80, 40);
    assert!(dump.contains("Exceptions for everyday services"), "{dump}");
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
