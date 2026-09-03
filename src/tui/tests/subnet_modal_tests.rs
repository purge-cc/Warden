use super::*;
use crate::config::schema::Id;

fn mk_subnet(id: &str) -> Subnet {
    Subnet {
        id: Id::new(id).unwrap(),
        display_name: "Display".into(),
        cidrs: vec!["10.0.0.0/24".into()],
        profile: Id::new("default").unwrap(),
        priority: 0,
    }
}

// ── Form-field navigation ─────────────────────────────────────────

#[test]
fn s51_form_field_next_cycles_through_seven_in_order() {
    let mut f = FormField::Id;
    let order = [
        FormField::DisplayName,
        FormField::Cidrs,
        FormField::Profile,
        FormField::Priority,
        FormField::Submit,
        FormField::Cancel,
        FormField::Id,
    ];
    for expected in order {
        f = f.next();
        assert_eq!(f, expected);
    }
}

#[test]
fn s51_form_field_prev_walks_backwards_and_wraps() {
    let f = FormField::Id;
    // Cancel (the Discard button) is now the last field, so Id wraps
    // back to it.
    assert_eq!(f.prev(), FormField::Cancel);
    assert_eq!(FormField::DisplayName.prev(), FormField::Id);
}

// ── try_resolve validation ────────────────────────────────────────

#[test]
fn s51_form_resolve_rejects_empty_id() {
    let modal = SubnetModal::open_add(vec!["default".into()], 0);
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(err.contains("id"), "empty id must error: {err}");
}

#[test]
fn s51_form_resolve_rejects_empty_cidrs() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan".into();
    // cidrs left empty
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(err.contains("CIDR"), "empty CIDRs must error: {err}");
}

#[test]
fn s51_form_resolve_rejects_invalid_priority() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan".into();
    form.cidrs = "10.0.0.0/24".into();
    form.priority_input = "not-a-number".into();
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(err.contains("priority"), "bad priority must error: {err}");
}

#[test]
fn s51_form_resolve_defaults_display_name_to_id() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan".into();
    form.cidrs = "10.0.0.0/24".into();
    // display_name left empty
    let resolved = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(resolved.display_name, "lan");
}

#[test]
fn s51_form_resolve_splits_comma_separated_cidrs() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan".into();
    form.cidrs = "10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24".into();
    let resolved = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(resolved.cidrs.len(), 3);
    assert_eq!(resolved.cidrs[0], "10.0.0.0/24");
    assert_eq!(resolved.cidrs[2], "10.2.0.0/24");
}

#[test]
fn s51_form_resolve_passes_wildcard_through_to_add_inner() {
    // The form does NOT pre-validate CIDRs — that happens inside
    // `add_inner` via `Cidr::parse_friendly` so wildcards survive
    // the modal layer and the operator sees the same friendly
    // error/success path the CLI does.
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan-99".into();
    form.cidrs = "10.99.0.*".into();
    let resolved = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(resolved.cidrs, vec!["10.99.0.*".to_string()]);
}

// ── Promote-from-suggestion ───────────────────────────────────────

#[test]
fn s51_promote_prefills_cidr_and_synthesises_display_name() {
    let modal = SubnetModal::open_promote("10.14.0.0/24", vec!["default".into()], 0);
    let form = modal.form().unwrap();
    assert_eq!(form.cidrs, "10.14.0.0/24");
    assert_eq!(form.display_name, "lan-10-14-0");
    assert!(
        form.id.is_empty(),
        "id must remain empty so the operator picks it consciously"
    );
}

#[test]
fn s51_synthesise_display_name_v6() {
    let name = synthesise_display_name("2001:db8::/64");
    assert_eq!(name, "lan6-2001-db8-0-0");
}

#[test]
fn s51_synthesise_display_name_falls_back_on_garbage() {
    assert_eq!(synthesise_display_name("not-a-cidr"), "lan-discovered");
}

// ── Edit modal ────────────────────────────────────────────────────

#[test]
fn s51_edit_modal_captures_snapshot_at_open() {
    let s = mk_subnet("lan");
    let modal = SubnetModal::open_edit(&s, vec!["default".into(), "kids".into()]);
    let form = modal.form().unwrap();
    assert_eq!(form.mode, FormMode::Edit);
    assert_eq!(form.id, "lan");
    assert_eq!(form.cidrs, "10.0.0.0/24");
    assert!(
        form.original.is_some(),
        "Edit captures the original snapshot"
    );
    let orig = form.original.as_ref().unwrap();
    assert_eq!(orig.id, "lan");
    assert_eq!(orig.profile, "default");
}

#[test]
fn s51_edit_modal_falls_back_to_first_profile_when_unknown() {
    let mut s = mk_subnet("lan");
    s.profile = Id::new("ghost").unwrap();
    let modal = SubnetModal::open_edit(&s, vec!["default".into()]);
    // ghost not in snapshot → drop to slot 0 (default)
    assert_eq!(modal.form().unwrap().profile_idx, 0);
}

// ── Remove modal ──────────────────────────────────────────────────

#[test]
fn s51_remove_modal_carries_subnet_metadata() {
    let s = mk_subnet("lan");
    let modal = SubnetModal::open_remove(&s);
    let rc = modal.remove().unwrap();
    assert_eq!(rc.id, "lan");
    assert_eq!(rc.cidrs, vec!["10.0.0.0/24".to_string()]);
}

// ── Lifecycle ─────────────────────────────────────────────────────

#[test]
fn s51_modal_finish_transitions_to_submitted() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    assert!(!modal.is_submitted());
    modal.finish(SubmitOutcome::Ok("done".into()));
    assert!(modal.is_submitted());
}

// ── Grid render (shared modal_form) ───────────────────────────────

/// Flatten the whole body — head, field region, tail — into one
/// string for content assertions.
///
/// The *line vector*, deliberately: it is enough for "is this row
/// composed correctly", and useless for "is this row on screen".
/// Every past instance of `lists-modal-min-height-clip` had a correct
/// vector and a wrong render, which is why the floor tests below
/// assert on the rendered buffer instead.
fn render_text(form: &AddForm, width: u16) -> String {
    let (body, _) = form_body(form, width);
    body.head
        .iter()
        .chain(body.fields.iter())
        .chain(body.tail.iter())
        .map(|l| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn s51_form_renders_banded_sections_and_the_active_marker() {
    // §4.61 Wave 2a replaced the grey `Field │ Value` grid with the
    // banded, labelled-section Archetype-F body. Two assertions from
    // the grid era had to change with it, and both are behaviour:
    //
    //  - the "Field"/"Value" header is gone — sections label
    //    themselves now (IDENTITY / RANGE / POLICY);
    //  - the `_` caret is gone — a focused text field hosts the real
    //    terminal cursor, as the operator-validated Lists modal
    //    does. `focused_text_field_hosts_the_real_cursor` below is
    //    the replacement assertion, and it has to be made against a
    //    rendered frame, not a line vector.
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.id = "lan".into(); // focus defaults to Id on Add
    let text = render_text(form, 60);

    assert!(
        text.contains("IDENTITY") && text.contains("RANGE") && text.contains("POLICY"),
        "labelled section bands:\n{text}"
    );
    assert!(!text.contains("lan_"), "the `_` caret is the cursor's job");
    assert!(text.contains("lan"), "the focused value still renders");
    assert!(text.contains('◀'), "active row carries the focus marker");
    assert!(text.contains("Save"), "Save action present");
    assert!(text.contains("Discard"), "Discard action present");
}

#[test]
fn focused_text_field_hosts_the_real_cursor() {
    // The `_` caret's replacement. Placed at VALUE_COL + the value's
    // char length, in the viewport's coordinate space — so it tracks
    // the scrolled field region rather than a fixed body offset.
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    modal.form_mut().unwrap().id = "lan".into();

    let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let pos = term.get_cursor_position().unwrap();

    let dump = dump_buffer(term.backend().buffer());
    // Located by the focus marker, not by the value: exactly one row
    // carries `◀`, whereas "lan" also hides inside the display-name
    // placeholder ("blank = the id") two rows below.
    let row = dump
        .lines()
        .position(|l| l.contains('\u{25c0}'))
        .expect("the focused row must be on screen") as u16;
    assert!(
        dump.lines().nth(row as usize).unwrap().contains("lan"),
        "the focused row is the id row:\n{dump}"
    );
    assert_eq!(pos.y, row, "cursor must sit on the focused row:\n{dump}");
    // Modal is 64 wide and centred in 100 columns → inner left edge
    // is 18 + 1 border; the caret lands VALUE_COL + len("lan") in.
    let inner_x = (100 - 64) / 2 + 1;
    assert_eq!(
        pos.x,
        inner_x + modal_form::VALUE_COL as u16 + 3,
        "cursor must sit at the end of the typed value:\n{dump}"
    );
}

#[test]
fn s51_grid_form_focused_selector_is_wrapped_in_angle_brackets() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::Profile;
    let text = render_text(form, 60);
    assert!(
        text.contains("‹ default ›"),
        "a focused selector value is wrapped to signal ←/→ cycles it"
    );
}

#[test]
fn s51_grid_form_inline_error_replaces_the_hint_line() {
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.error_message = Some("at least one CIDR is required".into());
    let text = render_text(form, 60);
    assert!(
        text.contains("⚠ at least one CIDR is required"),
        "error shows inline"
    );
    // The hint for the (default-focused) Id field is suppressed while
    // an error is pending.
    assert!(!text.contains("short stable key"));
}

#[test]
fn s51_grid_form_edit_id_is_read_only_without_caret() {
    let s = mk_subnet("lan");
    let modal = SubnetModal::open_edit(&s, vec!["default".into()]);
    let form = modal.form().unwrap();
    // Edit focus starts on Display name; the Id row shows the id
    // verbatim with no `_` caret and no literal "(read-only)" text —
    // the dim ReadOnly styling is the affordance.
    assert_eq!(form.focused, FormField::DisplayName);
    let text = render_text(form, 60);
    assert!(text.contains("lan"), "id value still shown");
    assert!(!text.contains("lan_"), "read-only id carries no caret");
    assert!(
        !text.contains("(read-only)"),
        "dim styling signals read-only, not literal suffix text"
    );
}

#[test]
fn s51_subnet_suggested_tag_byte_frozen() {
    // The integration assertion lives in
    // `tests/frozen_strings_s51.rs`; this in-file echo lets a
    // same-file regression surface during `cargo test --lib`
    // without requiring the integration cohort.
    use crate::tui::tabs::subnets::SUBNET_SUGGESTED_TAG;
    assert_eq!(SUBNET_SUGGESTED_TAG, " [suggested]");
    assert_eq!(SUBNET_SUGGESTED_TAG.len(), 12);
}

// ── §3.5 tag-model-consolidation: populated tags field ────────────

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

// ── §4.61 Wave 2a: the 80×24 floor ───────────────────────────────
//
// `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
// content rect this overlay anchors on (D18) is
// `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
// 12-row interior. `overlay::centered_rect` CLAMPS rather than
// scrolls, so a body taller than that is silently cut at the bottom
// while `Tab` still moves focus onto the rows that were cut — the
// operator then commits or discards blind. These render the real
// `render_overlay` into a backend the size of that content rect.

fn render_overlay_in(modal: &SubnetModal, w: u16, h: u16) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
    dump_buffer(term.backend().buffer())
}

// `plp-s5d` removed `ux2_the_armed_valve_is_visible_in_the_subnets_modal`
// with the tags picker it tested. The §4.65 UX2 valve — a typed slug
// waiting on a second `Enter` — was a property of the chip picker, and
// this modal no longer has one. There is NO substitute assertion here
// on purpose: the guarantee left with the surface rather than moving
// to another one, and saying so beats a renamed test that pins
// nothing. The shared valve itself still lives in
// `tabs::lists::commit_tag_picker` and is tested there.

fn edit_modal_for_floor() -> SubnetModal {
    let s = mk_subnet("lan");
    let mut modal = SubnetModal::open_edit(&s, vec!["default".into()]);
    let form = modal.form_mut().unwrap();
    form.display_name = "Guest WiFi".into();
    form.cidrs = "10.0.0.0/24".into();
    form.priority_input = "77".into();
    modal
}

#[test]
fn floor_keeps_the_action_row_and_the_focused_field_on_screen_together() {
    // The two things a clip silently takes away. Asserted on the
    // rendered buffer, never on the line vector: the vector was
    // correct in every past instance of this defect
    // (`lists-modal-min-height-clip`) — only the render was wrong.
    let mut modal = edit_modal_for_floor();
    modal.form_mut().unwrap().focused = FormField::Priority;
    let dump = render_overlay_in(&modal, 80, 14);

    assert!(
        dump.contains("Save"),
        "action row cut at the 80x24 floor — Tab still reaches it:\n{dump}"
    );
    assert!(
        dump.contains("Discard"),
        "Discard cut at the floor:\n{dump}"
    );
    assert!(
        dump.contains("77"),
        "the focused field's value is off-screen:\n{dump}"
    );
    assert!(
        dump.contains('\u{25c0}'),
        "the focus marker must be on screen with the action row:\n{dump}"
    );
}

#[test]
fn floor_viewport_follows_focus_onto_the_last_field() {
    // `plp-s5d`: Tags WAS the last editable field on Edit; with the
    // picker gone, Priority is. The property under test is unchanged —
    // the viewport must scroll to the last field and therefore scroll
    // the *first* one out. Without that second half the assertion
    // passes on a body that only ever renders page one.
    let mut modal = edit_modal_for_floor();
    modal.form_mut().unwrap().focused = FormField::Priority;
    let dump = render_overlay_in(&modal, 80, 14);

    assert!(
        dump.contains("77"),
        "focused last field is off-screen:\n{dump}"
    );
    assert!(
        dump.contains("Save"),
        "action row cut while focus sits on the last field:\n{dump}"
    );
    assert!(
        !dump.contains("Guest WiFi"),
        "a 4-row viewport cannot be showing both ends of the form:\n{dump}"
    );
}

#[test]
fn floor_add_mode_keeps_the_action_row_and_the_focused_field_together() {
    // Add is a different body from Edit — `id` is a focusable text
    // field — so the row count and the viewport arithmetic differ.
    // (Before `plp-s5d` the Edit body also carried two tags rows Add
    // never had; that difference is gone, the `id` one is not.) Add is
    // also the
    // most-travelled path here (promote-from-suggestion opens it),
    // so it gets its own floor assertion rather than riding on
    // Edit's.
    //
    // No fail-before: the pre-migration Add body was exactly 12
    // lines and fitted the 12-row interior by luck. This pins
    // behaviour that already works.
    let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
    modal.form_mut().unwrap().focused = FormField::Profile; // last Add field
    let dump = render_overlay_in(&modal, 80, 14);

    assert!(
        dump.contains("\u{2039} default \u{203a}"),
        "focused profile row is off-screen:\n{dump}"
    );
    assert!(dump.contains("Save"), "action row cut in Add mode:\n{dump}");
    assert!(
        !dump.contains("display name"),
        "the viewport must have scrolled past the first field:\n{dump}"
    );
}

#[test]
fn floor_remove_confirm_shows_the_entity_and_the_key_legend() {
    // The destructive stage. It fits the floor with one row of
    // slack (13 requested against 14), which is exactly the margin
    // worth pinning rather than leaving to the visual dump.
    let modal = SubnetModal {
        stage: Stage::ConfirmingRemove(RemoveConfirm {
            id: "lan".into(),
            display_name: "Guest WiFi".into(),
            cidrs: vec!["10.0.0.0/24".into()],
        }),
    };
    let dump = render_overlay_in(&modal, 80, 14);

    assert!(
        dump.contains("lan (Guest WiFi)"),
        "the operator must see which subnet they are removing:\n{dump}"
    );
    assert!(
        dump.contains("[y] confirm") && dump.contains("[y] Remove"),
        "the y/n keying is unchanged and must stay legible:\n{dump}"
    );
}

#[test]
fn submit_failure_wraps_instead_of_clipping_at_one_line() {
    // A real long failure from `mod.rs::submit_subnet_modal`. It used
    // to render as a single non-wrapping line and lost its tail;
    // routing it through `NoticeSpec::error` hard-wraps it to
    // HINT_ROWS. Pins the fix so it cannot silently regress by moving
    // the message back into the prose region.
    //
    // `plp-s5d` swapped the specimen. It was the partial-failure copy
    // ("subnet fields saved (…) but the tag change failed: …"), which
    // this lane deleted along with the two-write tag path that emitted
    // it. A wrap test pinned to a string the product can no longer
    // produce is a test that measures nothing, so the specimen is now
    // a validator refusal carried up from `set_fields_inner` — a
    // message this path still emits, and still long enough to wrap.
    // Length matters, not just content: the notice hard-wraps to
    // HINT_ROWS and then truncates with "+N more". The retired
    // specimen was 103 chars and fitted; a first attempt at this one
    // ran to 118 and lost its tail, failing this very assertion. Kept
    // at ~102 so it still spans more than one row without overflowing
    // the budget the neighbouring clip test pins.
    let long = "edit failed: subnet \"lan\" overlaps subnet \"guest\" and \
                neither declares a priority — reopen to retry it";
    let modal = SubnetModal {
        stage: Stage::Submitted(SubmitOutcome::Failed(long.into())),
    };
    let dump = render_overlay_in(&modal, 80, 14);

    assert!(
        dump.contains('\u{26a0}'),
        "a failure carries the ⚠ affordance:\n{dump}"
    );
    assert!(
        dump.contains("reopen to retry it"),
        "the tail of the message must survive the wrap:\n{dump}"
    );
}

#[test]
fn overlay_is_confined_to_the_anchor_rect() {
    // D18: the anchor is the tab content rect, so the header, the
    // menu card and the footer legend stay visible behind the modal.
    // Anchoring on `f.area()` instead paints over all three.
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let anchor = Rect {
        x: 0,
        y: 9,
        width: 80,
        height: 14,
    };
    let modal = edit_modal_for_floor();
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| render_overlay(f, anchor, &modal)).unwrap();
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
fn no_hand_rolled_colour_in_this_module() {
    // §4.61 Wave 2a's acceptance criterion, as a test rather than a
    // claim in a commit message. A surface that reaches for the
    // theme directly is a surface that will drift from the other
    // eleven — and R1 is that every wave re-derives the colour rule
    // locally. Needles are split so this assertion cannot match
    // itself.
    let src = include_str!("../subnet_modal.rs");
    for needle in [
        concat!("Style::default()", ".fg("),
        concat!("Color", "::Rgb("),
        concat!("T", ".brand_red"),
    ] {
        assert!(
            !src.contains(needle),
            "{needle} in subnet_modal.rs — the colour belongs in modal_form"
        );
    }
}

#[test]
#[ignore = "visual aid: cargo test subnet_visual_dump -- --ignored --nocapture"]
fn subnet_visual_dump() {
    let mut modal = edit_modal_for_floor();
    modal.form_mut().unwrap().focused = FormField::Cidrs;
    println!(
        "--- roomy anchor ---\n{}",
        render_overlay_in(&modal, 100, 40)
    );
    println!(
        "--- the 80x24 floor (14-row content rect) ---\n{}",
        render_overlay_in(&modal, 80, 14)
    );
    modal.form_mut().unwrap().focused = FormField::Priority;
    println!(
        "--- same, focus on the last field ---\n{}",
        render_overlay_in(&modal, 80, 14)
    );
    modal.form_mut().unwrap().focused = FormField::Submit;
    println!(
        "--- same, focus on Save (no field row focused) ---\n{}",
        render_overlay_in(&modal, 80, 14)
    );
    let rc = RemoveConfirm {
        id: "lan".into(),
        display_name: "Guest WiFi".into(),
        cidrs: vec!["10.0.0.0/24".into()],
    };
    println!(
        "--- remove confirm (Archetype C) ---\n{}",
        render_overlay_in(
            &SubnetModal {
                stage: Stage::ConfirmingRemove(rc)
            },
            80,
            14
        )
    );
    println!(
        "--- submit failure (Archetype C) ---\n{}",
        render_overlay_in(
            &SubnetModal {
                stage: Stage::Submitted(SubmitOutcome::Failed(
                    "edit failed: subnet \"lan\" overlaps subnet \"guest\" and neither declares a priority — reopen to retry it".into()
                ))
            },
            80,
            14
        )
    );
}

/// The clip-guard: the tallest this modal's content can get must not
/// push Save/Discard off the bottom.
///
/// **`plp-s5d` retargeted this from the tags picker to `cidrs`, and
/// the retarget is the point.** The picker was the tallest field
/// (chips + a type-ahead buffer + a suggestions row), so deleting it
/// would have deleted the only test driving this modal's body past
/// its slack — the clip-guard would have gone green forever by having
/// nothing tall left to guard against, which is the deletion-lane
/// trap. `cidrs` is the surviving unbounded field (free text, one
/// comma-separated line), so the guarantee keeps a subject.
///
/// No spaces in the filler — `Wrap` cannot break at a word boundary,
/// so it hard-wraps character-by-character. A short value does not
/// reliably overflow the slack.
#[test]
fn render_overlay_keeps_save_discard_visible_with_an_overlong_cidrs_field() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let s = mk_subnet("lan");
    let mut modal = SubnetModal::open_edit(&s, vec!["default".into()]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::Cidrs;
    form.cidrs = "x".repeat(300);

    let backend = TestBackend::new(100, 24);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        render_overlay(f, f.area(), &modal);
    })
    .unwrap();

    let dump = dump_buffer(term.backend().buffer());
    assert!(
        dump.contains("xxxx"),
        "the overlong field must actually be rendering — without this \
         the Save/Discard assertion below passes on a short body:\n{dump}"
    );
    assert!(
        dump.contains("Save") && dump.contains("Discard"),
        "the button row must survive an overlong field, not be clipped off the bottom:\n{dump}"
    );
}

#[test]
fn no_inline_test_module_remains_in_subnet_modal() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "subnet_modal.rs",
        include_str!("../subnet_modal.rs"),
    );
}
