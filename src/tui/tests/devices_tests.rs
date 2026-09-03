//! `devices.rs`'s test module, relocated here because its code region
//! (~1,486 lines) passes the size trigger for moving to `src/tui/tests/`
//! and it needs no `include_str!` self-scan of its own source — the two
//! conditions the test-placement rule keys on. Tests that fail either
//! condition (need a private item only reachable in-file, or slice their
//! own file's bytes, as `rules.rs` and `lists.rs` do for their modal-region
//! colour guard) stay where they are.
//!
//! Reached from `tabs/devices.rs` via `#[path]`; `super` here is
//! `tabs::devices`, exactly as if this module were still inline.

use super::*;

fn mk_mapped(name: &str, ip: &str, owner: Option<&str>) -> MappedDeviceDto {
    MappedDeviceDto {
        ip: ip.into(),
        name: name.into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        mac_aliases: vec![],
        profile: "default".into(),
        owner: owner.map(|s| s.into()),
        device_type: None,
        department: None,
        queries: 0,
        queries_today: 0,
        blocked: 0,
        blocked_24h: 0,
        cache_hits: 0,
        last_seen: 0,
        online: false,
        vendor: None,
        groups: Vec::new(),
        notes: None,
        network_name: None,
        network_name_wildcard: false,
        id: None,
        hourly_queries: Vec::new(),
        unfiltered: false,
    }
}

fn mk_unmapped(ip: &str) -> UnmappedDeviceDto {
    UnmappedDeviceDto {
        ip: ip.into(),
        mac: None,
        queries: 0,
        queries_today: 0,
        blocked: 0,
        blocked_24h: 0,
        last_seen: 0,
        online: false,
        vendor: None,
        hourly_queries: Vec::new(),
    }
}

// mem2608-s3 / F-P, fifth site. queries=100, blocked=60, cache_hits=20.
//
// Pre-fix the denominator was `queries`: 20/100 = 20.0%. The cacheable
// denominator is queries-blocked = 40: 20/40 = 50.0%. The two are far
// apart on purpose — a fixture where they differ only in the last decimal
// would pass against either form and pin nothing.
//
// The `Blocked` assertion is the CONTROL ARM, and it is why this test is
// worth more than an equality check on one number. `block_pct` is
// correctly computed over ALL queries and must stay that way, so a change
// that "fixed" both ratios would be an overreach — and would still satisfy
// the cache assertion on its own. Pinning 60.0% is what makes that
// overreach fail instead of passing quietly.
#[test]
fn cache_rate_excludes_blocked_queries_but_block_rate_does_not() {
    let mut d = mk_mapped("dev", "192.0.2.10", None);
    d.queries = 100;
    d.blocked = 60;
    d.cache_hits = 20;

    let text: String = mapped_card_lines(&d, 0)
        .iter()
        .map(|l| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        text.contains("20  (50.0%)"),
        "cache rate must divide by cacheable (queries - blocked = 40), not by all 100 \
             queries: otherwise a device shows its WORST cache rate precisely when filtering \
             works best. got:\n{text}"
    );
    assert!(
        !text.contains("20  (20.0%)"),
        "cache rate still divides by total queries — the pre-fix form. got:\n{text}"
    );
    assert!(
        text.contains("60  (60.0%)"),
        "block rate must stay over ALL queries — it is not part of the cache-rate family, \
             and widening this fix to cover it would be an overreach. got:\n{text}"
    );
}

// dev-03: build_rows is name-sorted and rebuilt every poll. A device
// inserted ahead of the selected one shifts its index, but the stable
// key must still resolve to the SAME device — not whatever now sits
// at the old index. This is the selection-drift the bare TableState
// index suffered.
#[test]
fn selection_anchors_to_device_key_across_poll_reshuffle() {
    let view = DeviceViewDto {
        mapped: vec![
            mk_mapped("bravo", "10.0.0.2", None),
            mk_mapped("charlie", "10.0.0.3", None),
        ],
        unmapped: vec![],
    };
    let rows = build_rows(&view, DeviceGroupBy::None);
    let charlie_idx = rows
        .iter()
        .position(|r| matches!(r, DeviceRow::Mapped(m) if m.name == "charlie"))
        .unwrap();
    let key = row_key(&rows[charlie_idx]);

    // A poll inserts "alpha", which name-sorts first and pushes
    // charlie down a row.
    let view2 = DeviceViewDto {
        mapped: vec![
            mk_mapped("alpha", "10.0.0.1", None),
            mk_mapped("bravo", "10.0.0.2", None),
            mk_mapped("charlie", "10.0.0.3", None),
        ],
        unmapped: vec![],
    };
    let rows2 = build_rows(&view2, DeviceGroupBy::None);
    let resolved = crate::tui::app::resolve_row_index(&rows2, key.as_ref(), row_key).unwrap();
    assert_ne!(
        resolved, charlie_idx,
        "the insertion should have shifted charlie's index"
    );
    match &rows2[resolved] {
        DeviceRow::Mapped(m) => assert_eq!(m.name, "charlie"),
        other => panic!("stable key resolved to the wrong row: {other:?}"),
    }
    // A bare positional index would now point at the wrong device.
    if let DeviceRow::Mapped(m) = &rows2[charlie_idx] {
        assert_ne!(m.name, "charlie");
    }
}

fn subnet_filter_fixture() -> DeviceViewDto {
    DeviceViewDto {
        mapped: vec![
            mk_mapped("alpha", "10.10.1.5", None),
            mk_mapped("bravo", "10.10.1.9", None),
            mk_mapped("charlie", "10.10.2.5", None),
        ],
        unmapped: vec![mk_unmapped("10.10.1.20"), mk_unmapped("10.10.3.1")],
    }
}

fn mapped_names(rows: &[DeviceRow]) -> Vec<&str> {
    rows.iter()
        .filter_map(|r| match r {
            DeviceRow::Mapped(m) => Some(m.name.as_str()),
            _ => None,
        })
        .collect()
}

fn unmapped_ips(rows: &[DeviceRow]) -> Vec<&str> {
    rows.iter()
        .filter_map(|r| match r {
            DeviceRow::Unmapped(u) => Some(u.ip.as_str()),
            _ => None,
        })
        .collect()
}

// Before `build_filtered_rows` existed, the only row builder was
// `build_rows`, which has no filter parameter — it always returns
// every device, so a caller had no way to narrow the list to one
// CIDR at all. This pins the narrowing itself: with the filter set,
// only alpha/bravo (10.10.1.0/24) and their unmapped sibling survive
// — charlie (10.10.2.5) and the unmapped 10.10.3.1 must not.
#[test]
fn subnet_filter_narrows_to_matching_cidr() {
    let view = subnet_filter_fixture();
    let (rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, Some("10.10.1.0/24"));

    assert_eq!(status, SubnetFilterStatus::Active);
    assert_eq!(mapped_names(&rows), vec!["alpha", "bravo"]);
    assert_eq!(unmapped_ips(&rows), vec!["10.10.1.20"]);
}

// Clearing the filter (`None`) must restore every row — the DoD's
// "clearing it restores every row" bullet. Also pins that `None`
// produces exactly what `build_rows` alone would.
#[test]
fn subnet_filter_none_restores_every_row() {
    let view = subnet_filter_fixture();
    let (filtered_rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, None);
    let (baseline_rows, _) = build_filtered_rows(&view, DeviceGroupBy::None, Some("10.10.1.0/24"));
    assert_ne!(
        filtered_rows.len(),
        baseline_rows.len(),
        "sanity: the filtered fixture must actually drop rows, or this test proves nothing"
    );

    assert_eq!(status, SubnetFilterStatus::Inactive);
    assert_eq!(filtered_rows, build_rows(&view, DeviceGroupBy::None));
    assert_eq!(
        mapped_names(&filtered_rows),
        vec!["alpha", "bravo", "charlie"]
    );
    assert_eq!(
        unmapped_ips(&filtered_rows),
        vec!["10.10.1.20", "10.10.3.1"]
    );
}

// An unparseable CIDR must not read as "zero devices in this
// subnet" — that is silent data loss. The full list stays visible
// and the status flags the failure so the card can say so.
#[test]
fn subnet_filter_invalid_cidr_keeps_every_row_visible() {
    let view = subnet_filter_fixture();
    let (rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, Some("not-a-cidr"));

    assert_eq!(status, SubnetFilterStatus::Invalid);
    assert_eq!(rows, build_rows(&view, DeviceGroupBy::None));
}

fn dump(buf: &ratatui::buffer::Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

// A default-width TestBackend can't see this bug — the content_area is
// wide enough there that an unbudgeted value never reaches the note or
// the clear hint.
//
// 80 cols (the product's declared floor) is narrow enough to still
// demonstrate the bug against this value: the fixed spans alone (lead
// + Invalid note + clear hint) are ~60 cells, so an *unbudgeted* ~55-
// char value would push the total past even a generous content_area.
// It must NOT be narrower than that: below ~73 cols the fixed spans
// alone exceed content_area, and no amount of value-truncation can
// make them fit — that is a real, separate limit of this fix (the
// note text itself isn't budgeted), not something this test asserts.
#[test]
fn subnet_filter_card_survives_a_long_value_at_narrow_width() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut app = App::new();
    app.input_mode = crate::tui::app::InputMode::FilterDevicesSubnet(
        "this-is-a-much-longer-typed-value-than-any-real-cidr".to_string(),
    );
    let mut term = Terminal::new(TestBackend::new(80, 3)).unwrap();
    term.draw(|f| render_subnet_filter_card(f, f.area(), &app, SubnetFilterStatus::Invalid))
        .unwrap();
    let content = dump(term.backend().buffer());

    assert!(
        content.contains("[R] clear"),
        "clear hint pushed off screen by an unbudgeted value:\n{content}"
    );
    assert!(
        content.contains("invalid CIDR"),
        "invalid-CIDR note pushed off screen by an unbudgeted value:\n{content}"
    );
}

// ── F7 · the row budget at the declared floor ────────────────────
//
// Three anchors exist for this modal and only one of them is
// production's, so a test that picks the wrong one measures nothing:
//
//   f.area()            the whole frame — what the audit's repro used
//   the D18 content rect  what `ui.rs:498` hands `devices::render`
//   `cols[0]`           the LIST column — what `render` actually
//                       anchors the modal on (chrome-v2 D6), a
//                       sub-rect of the content rect
//
// These helpers go through `render`, so the anchor is `cols[0]`
// derived by the same `Layout` the operator's terminal derives it
// with. A backend of 80×14 therefore reproduces the Network/Filtering
// content rect at `MIN_WIDTH 80` × `MIN_HEIGHT 24` exactly:
// 24 − 4 header − 5 menu card − 1 footer = 14.

/// Render the whole tab — list, side card, modal — at `w`×`h` with
/// `modal` open, exactly as `ui.rs` drives it.
fn render_tab_at(w: u16, h: u16, modal: DeviceModal) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut app = App::new();
    app.device_view = Some(DeviceViewDto {
        mapped: vec![mk_mapped("kitchen-tv", "10.10.1.50", Some("dweller"))],
        unmapped: vec![mk_unmapped("10.10.1.77")],
    });
    app.devices.modal = Some(modal);
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
    dump(term.backend().buffer())
}

/// A form of `mode` whose focus sits on the LAST field in the ring,
/// carrying a needle no other row can produce.
///
/// `notes` is deliberate: it is the bottom of the second section, so
/// it is the first thing a bottom-cut takes and the last thing a
/// focus-tracking viewport has to fetch. The value is the needle
/// rather than the label, per the `"tags"`-matched-the-band trap —
/// a label needle can match a section band or a hint.
fn form_focused_on_last_field(mode: DeviceFormMode) -> DeviceFormState {
    let mut form = match mode {
        DeviceFormMode::Add => DeviceFormState::new_add(),
        DeviceFormMode::Edit => edit_form("Kitchen TV", Some("kitchen-tv")),
        DeviceFormMode::Promote => {
            DeviceFormState::new_promote("10.10.1.77".into(), "aa:bb:cc:dd:ee:ff".into())
        }
    };
    form.notes = "ZZQQ".to_string();
    form.focused = DeviceFormFocus::Field(DeviceFormField::Notes);
    form
}

/// The two things a clip can silently take, asserted **together**.
///
/// Needles chosen to discriminate, not merely to match:
///
/// - `"  Save  "` with its padding, never bare `Save` — the nav
///   legend already says `Enter open/save`, so a substring match on
///   the word would pass with the action row cut clean off.
/// - `"ZZQQ"`, the operator's own buffer in the focused field, never
///   the label `notes` — `assert!(contains("notes"))` would also
///   match a hint or a band.
/// - the legend itself, so a failure says *which* row was missing
///   instead of leaving both candidates open.
fn assert_action_row_and_focus_on_screen(out: &str, mode: DeviceFormMode) {
    assert!(
        out.contains("  Save  "),
        "{mode:?}: the action row's Save is off screen \
             (bare \"Save\" would have matched the nav legend):\n{out}"
    );
    assert!(
        out.contains("  Cancel  "),
        "{mode:?}: the action row's Cancel is off screen:\n{out}"
    );
    assert!(
        out.contains("ZZQQ"),
        "{mode:?}: the FOCUSED field's value is off screen while Tab \
             still reaches it \u{2014} the operator types blind:\n{out}"
    );
}

/// **F7.** At the declared floor the form must still show the action
/// row and the focused field simultaneously, in all three stages.
///
/// Fails before the Archetype-F migration: `render_chrome_in(…, 28, …)`
/// asks for 28 rows, `centered_rect` clamps to 14, and
/// `render_body_fixed` has no viewport — so the body is cut after 12
/// rows while `DeviceFormFocus::Save` stays in the ring. The operator
/// commits or discards blind.
#[test]
fn floor_form_keeps_its_action_row_and_focused_field_in_every_mode() {
    for mode in [
        DeviceFormMode::Add,
        DeviceFormMode::Edit,
        DeviceFormMode::Promote,
    ] {
        let out = render_tab_at(80, 14, DeviceModal::Form(form_focused_on_last_field(mode)));
        assert_action_row_and_focus_on_screen(&out, mode);
    }
}

/// This file owns the **tab**, not only the modal. The migration
/// rewrote its imports and its shared row vocabulary, so pin the three
/// tab-level affordances the modal work could plausibly have broken:
/// the side detail card, the group-by header rows (`G`), and the
/// promote-unmapped path's read-only pins.
#[test]
fn the_tab_itself_still_renders_card_grouping_and_the_promote_path() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    // Side card + group-by headers, no modal open.
    let mut app = App::new();
    app.device_view = Some(DeviceViewDto {
        mapped: vec![
            mk_mapped("kitchen-tv", "10.10.1.50", Some("dweller")),
            mk_mapped("study-pi", "10.10.1.51", Some("ada")),
        ],
        unmapped: vec![mk_unmapped("10.10.1.77")],
    });
    app.devices.group_by = DeviceGroupBy::Owner;
    // 160 wide, not 100: the identity column is `Constraint::Min(15)` and
    // flexes, so at 100 cols the header row truncates to
    // `── Owner: edoar` and an assertion on the owner's name would fail
    // for a reason that has nothing to do with grouping.
    let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
    let out = dump(term.backend().buffer());
    assert!(
        out.contains("group: owner"),
        "group-by in the title:\n{out}"
    );
    assert!(
        out.contains("Owner: ada") && out.contains("Owner: dweller"),
        "grouping must insert one header row per owner:\n{out}"
    );
    // The card renders the highlighted row's full field set; `Status` is
    // a card-only label, so it discriminates the card from the table.
    assert!(out.contains("Status"), "side detail card:\n{out}");

    // Promote pins ip + mac from the ARP snapshot — both inert.
    let promote = DeviceFormState::new_promote("10.10.1.77".into(), "aa:bb:cc:dd:ee:ff".into());
    let out = render_tab_at(80, 30, DeviceModal::Form(promote));
    assert!(
        out.contains("PROMOTE UNMAPPED CLIENT"),
        "promote title band:\n{out}"
    );
    assert!(
        out.contains("10.10.1.77") && out.contains("aa:bb:cc:dd:ee:ff"),
        "the pinned ip and mac render:\n{out}"
    );
}

/// Write `v` into `field`'s buffer. Test-only: production never needs a
/// setter, because `tui::mod`'s key handler owns the buffers directly.
fn set_field(form: &mut DeviceFormState, field: DeviceFormField, v: &str) {
    let slot = match field {
        DeviceFormField::Name => &mut form.name,
        DeviceFormField::Ip => &mut form.ip,
        DeviceFormField::Mac => &mut form.mac,
        DeviceFormField::MacAliases => &mut form.mac_aliases,
        DeviceFormField::Profile => &mut form.profile,
        DeviceFormField::Group => &mut form.groups,
        DeviceFormField::Owner => &mut form.owner,
        DeviceFormField::Device => &mut form.device_type,
        DeviceFormField::Department => &mut form.department,
        DeviceFormField::Notes => &mut form.notes,
        DeviceFormField::NetworkName => &mut form.network_name,
        DeviceFormField::NetworkNameWildcard => &mut form.network_name_wildcard,
    };
    *slot = v.to_string();
}

/// The ecosystem colour rule, asserted against the rendered buffer.
///
/// The sibling surfaces pin this with a file-wide source scan
/// (`subnet_modal::no_hand_rolled_colour_in_this_module`), which cannot
/// work here: this file owns the **tab** as well as the modal, and the
/// list rows and the detail card hand-roll colour legitimately — §1.1 of
/// the design doc rules those out of scope explicitly. So this asserts
/// the same rule one level down, on the pixels, which is the stronger
/// form anyway: whatever the source does, the modal must *render*
/// teal for static structure, emerald for the one live focus, and a
/// neutral frame.
#[test]
fn the_form_renders_the_teal_emerald_colour_rule() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    form.notes = "ZZQQ".to_string();
    form.focused = DeviceFormFocus::Field(DeviceFormField::Notes);
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(form));
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    let buf = term.backend().buffer();
    let out = dump(buf);

    // Column lookups by CHARACTER, never `str::find` — the frame's `│`
    // is 3 UTF-8 bytes and a byte offset lands 2 cells right.
    let col_in = |row: u16, glyph: char| {
        out.lines()
            .nth(row as usize)
            .unwrap()
            .chars()
            .position(|c| c == glyph)
            .map(|c| c as u16)
    };
    let row_with = |needle: &str| {
        out.lines()
            .position(|l| l.contains(needle))
            .map(|r| r as u16)
            .unwrap_or_else(|| panic!("{needle:?} not on screen:\n{out}"))
    };

    // warden_teal — static structure. Both section headers.
    for band in ["IDENTITY \u{b7} NETWORK", "ASSIGNMENTS & METADATA"] {
        let row = row_with(band);
        let x = col_in(row, band.chars().next().unwrap()).unwrap();
        assert_eq!(
            buf[(x, row)].fg,
            T.warden_teal,
            "section band {band:?} must be warden_teal:\n{out}"
        );
    }

    // emerald_ping — the ONE live focus, on the focused row's rule.
    let focus_row = row_with("ZZQQ");
    let rule_x = col_in(focus_row, '\u{258c}')
        .unwrap_or_else(|| panic!("the focused row draws no \u{258c} rule:\n{out}"));
    assert_eq!(
        buf[(rule_x, focus_row)].fg,
        T.emerald_ping,
        "the focused row's rule must be emerald_ping:\n{out}"
    );
    // ...and it is the ONLY emerald rule in the field region: "the one
    // live focus" is a cardinality claim, not just a colour one.
    let emerald_rules = (0..buf.area.height)
        .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
        .filter(|&(x, y)| buf[(x, y)].symbol() == "\u{258c}" && buf[(x, y)].fg == T.emerald_ping)
        .count();
    assert_eq!(
        emerald_rules, 1,
        "exactly one emerald focus rule may be on screen:\n{out}"
    );

    // Save is the modal's one filled action: warden_teal fill, inverse
    // label. Cancel is colour-only, so nothing else carries that fill.
    let action_row = row_with("  Save  ");
    let save_x = out
        .lines()
        .nth(action_row as usize)
        .unwrap()
        .chars()
        .collect::<String>()
        .find("  Save  ")
        .map(|b| {
            // ASCII-only prefix here, so byte == char, but derive it the
            // safe way regardless.
            out.lines().nth(action_row as usize).unwrap()[..b]
                .chars()
                .count() as u16
        })
        .unwrap();
    let fill = &buf[(save_x + 2, action_row)];
    assert_eq!(
        (fill.bg, fill.fg),
        (T.warden_teal, T.text_inverse),
        "Save is the one ActionKind::Primary — teal fill, inverse label:\n{out}"
    );

    // The frame stays neutral grey (D15).
    let top = row_with("\u{256d}");
    let left = col_in(top, '\u{256d}').unwrap();
    let right = col_in(top, '\u{256e}').unwrap();
    for x in left..=right {
        assert_eq!(
            buf[(x, top)].fg,
            T.text_primary,
            "border cell ({x},{top}) is not the neutral frame:\n{out}"
        );
    }
}

/// **The invariant, not a sample of it.** `floor_form_keeps_…` above
/// pins the *last* field, which is the worst case for a bottom-cut — but
/// the guarantee `ScrollBody` exists to provide is that **no** focusable
/// target is ever off screen, so walk every stop in every stage.
///
/// A per-stop unique needle is what makes this buffer-level rather than
/// a re-derivation of `scroll_layout` in the test. Recomputing the
/// renderer's own arithmetic and comparing it to itself would pass
/// whether or not the widget honoured it — the failure mode that let a
/// wrapping bug ship here with every unit test green.
#[test]
fn no_focusable_target_is_ever_off_screen_at_the_floor() {
    for mode in [
        DeviceFormMode::Add,
        DeviceFormMode::Edit,
        DeviceFormMode::Promote,
    ] {
        let base = form_focused_on_last_field(mode);

        for field in DeviceFormState::FIELDS {
            // A locked row is not in the ring (`focus_ring` filters it),
            // so it is not a focusable target and cannot be a defect.
            if base.is_locked(field) {
                continue;
            }
            let mut form = base.clone();
            set_field(&mut form, field, "ZQ7X");
            form.focused = DeviceFormFocus::Field(field);

            let out = render_tab_at(80, 14, DeviceModal::Form(form));
            assert!(
                out.contains("ZQ7X"),
                "{mode:?}/{field:?}: the focused field is off screen at the \
                     floor while Tab still reaches it:\n{out}"
            );
            assert!(
                out.contains("  Save  "),
                "{mode:?}/{field:?}: the action row is off screen at the \
                     floor:\n{out}"
            );
        }

        // The two action stops. Their own row is pinned by
        // `scroll_layout`, so what matters is that focus on an action
        // does not cost the field region its viewport.
        for stop in [DeviceFormFocus::Cancel, DeviceFormFocus::Save] {
            let mut form = base.clone();
            form.focused = stop;
            let out = render_tab_at(80, 14, DeviceModal::Form(form));
            assert!(
                out.contains("  Save  ") && out.contains("  Cancel  "),
                "{mode:?}/{stop:?}: the action row is off screen at the floor:\n{out}"
            );
        }
    }
}

/// The control arm. Passes before *and* after the migration — which is
/// what makes the 80×14 arm above evidence rather than decoration: it
/// proves the defect is the row budget and not the fixture.
#[test]
fn control_arm_form_is_complete_when_the_terminal_has_room() {
    for mode in [
        DeviceFormMode::Add,
        DeviceFormMode::Edit,
        DeviceFormMode::Promote,
    ] {
        let out = render_tab_at(80, 30, DeviceModal::Form(form_focused_on_last_field(mode)));
        assert_action_row_and_focus_on_screen(&out, mode);
    }
}

fn render_picker_at(w: u16, h: u16, picker: &FieldPicker) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| {
        render_field_picker(f, ratatui::layout::Rect::new(0, 0, w, h), picker);
    })
    .unwrap();
    dump(term.backend().buffer())
}

/// The picker's cursor row must be marked with the **ecosystem** focus
/// grammar, not the retired `●`/`○` radio pair: an emerald `▌` rule
/// replacing the lead indent, and a `◀` marker closing the row.
#[test]
fn field_picker_renders_options_with_cursor_marker() {
    let picker = FieldPicker {
        target: DeviceFormField::Profile,
        options: vec!["default".into(), "kids".into(), "guest".into()],
        cursor: 1,
        multi: false,
        selected: Vec::new(),
    };
    let out = render_picker_at(60, 20, &picker);
    assert!(out.contains("Select profile"), "title missing:\n{out}");
    assert!(
        out.contains("default") && out.contains("kids") && out.contains("guest"),
        "options missing:\n{out}"
    );
    assert!(
        out.contains('\u{258c}'),
        "focus rule \u{258c} missing:\n{out}"
    );
    assert!(
        out.contains('\u{25c0}'),
        "focus marker \u{25c0} missing:\n{out}"
    );
    // The marker must be on the CURSOR's row, not merely somewhere on
    // screen — the whole point of a cursor.
    let cursor_row = out
        .lines()
        .find(|l| l.contains("kids"))
        .expect("the cursor's option renders");
    assert!(
        cursor_row.contains('\u{258c}') && cursor_row.contains('\u{25c0}'),
        "focus grammar landed on a row other than the cursor's:\n{out}"
    );
}

/// §4.64 G4: the multi-select picker must show membership on EVERY
/// row and advertise the key that changes it. The focus grammar says
/// "here"; it cannot also say "chosen", and a picker where the
/// operator cannot see what is selected is how a Save silently drops
/// a group — which is the defect G4 closed.
#[test]
fn multi_picker_boxes_every_row_and_names_the_toggle_key() {
    let picker = FieldPicker {
        target: DeviceFormField::Group,
        options: vec!["phones".into(), "kids".into(), "iot".into()],
        cursor: 0,
        multi: true,
        selected: vec!["phones".into(), "iot".into()],
    };
    let out = render_picker_at(60, 20, &picker);
    assert!(out.contains("Select groups"), "plural title:\n{out}");
    for (name, want) in [
        ("phones", "[\u{00d7}]"),
        ("kids", "[ ]"),
        ("iot", "[\u{00d7}]"),
    ] {
        let row = out
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("option {name} missing:\n{out}"));
        assert!(
            row.contains(want),
            "row for {name} must carry {want}:\n{out}"
        );
    }
    assert!(
        out.contains("[Space] toggle"),
        "the toggle key must be named — nothing else reveals it:\n{out}"
    );
}

/// The single-select picker keeps its bare labels: a checkbox there
/// would promise a multiple choice the field cannot hold.
#[test]
fn single_picker_draws_no_checkboxes() {
    let picker = FieldPicker {
        target: DeviceFormField::Group,
        options: vec!["phones".into(), "kids".into()],
        cursor: 0,
        multi: false,
        selected: Vec::new(),
    };
    let out = render_picker_at(60, 20, &picker);
    assert!(!out.contains("[\u{00d7}]") && !out.contains("[ ]"), "{out}");
    assert!(out.contains("[Enter] select"), "{out}");
}

/// The side card names every membership. It used to name the first
/// and add `+N more (CLI)` — a hint that now points the operator at
/// the wrong tool, since the Edit modal holds the whole list.
#[test]
fn side_card_group_line_lists_every_membership() {
    let line = group_line(&["phones".to_string(), "kids".to_string()]);
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    assert!(text.contains("phones") && text.contains("kids"), "{text}");
    assert!(
        !text.contains("(CLI)"),
        "the CLI-only claim is false since G4:\n{text}"
    );
}

/// An empty option list is pure prose, so `notice_body` marks it
/// unscrollable and draws no bar — a scrollbar there would advertise a
/// control no keystroke can operate.
#[test]
fn field_picker_with_no_options_says_so_and_draws_no_scrollbar() {
    let picker = FieldPicker {
        target: DeviceFormField::Group,
        options: Vec::new(),
        cursor: 0,
        multi: false,
        selected: Vec::new(),
    };
    let out = render_picker_at(60, 20, &picker);
    assert!(out.contains("Select group"), "title missing:\n{out}");
    assert!(out.contains("(none configured)"), "empty copy:\n{out}");
    assert!(
        !out.contains('\u{2588}'),
        "a prose-only body must draw no scrollbar thumb:\n{out}"
    );
}

/// The picker is nested inside an Archetype-F form and takes the SAME
/// anchor, so it must land concentrically inside it rather than
/// covering it edge to edge — and it must still show its option list
/// and its key legend at the declared floor.
#[test]
fn floor_nested_picker_stays_inside_its_parent_form() {
    let mut form =
        DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    form.picker = Some(FieldPicker {
        target: DeviceFormField::Profile,
        options: form.profiles_snapshot.clone(),
        cursor: 1,
        multi: false,
        selected: Vec::new(),
    });
    let out = render_tab_at(80, 14, DeviceModal::Form(form));

    assert!(
        out.contains("Select profile"),
        "the picker is off screen at the floor:\n{out}"
    );
    assert!(
        out.contains("kids"),
        "the cursor's option is off screen at the floor:\n{out}"
    );
    assert!(
        out.contains("[Enter] select"),
        "the key legend is off screen at the floor:\n{out}"
    );
    // PICKER_W 46 < MODAL_W 60 on a shared anchor, so the form's own
    // frame must survive on both sides of the popup. Its title band is
    // the discriminating needle: the picker cannot produce it.
    assert!(
        out.contains("ADD CLIENT"),
        "the parent form's frame was covered edge to edge:\n{out}"
    );
}

// rev-2607 (#14): the group-header divider must size its dash fill
// by display *characters*, not UTF-8 *bytes* — the label comes from
// operator-supplied owner/department/profile strings.
#[test]
fn group_header_dash_count_uses_chars_not_bytes() {
    // "日本" is 2 chars but 6 UTF-8 bytes. A byte-length bug would
    // subtract 4 extra columns it shouldn't, coming out short
    // relative to a same-char-count ASCII label ("ab").
    assert_eq!(
        group_header_dash_count("\u{65e5}\u{672c}", 40),
        group_header_dash_count("ab", 40),
        "a 2-char multi-byte label must yield the same dash_count as a 2-char ASCII label"
    );
    // Pin the actual number too: width 40, 2-char label, fixed
    // "── {label} " overhead of 4 columns → 40 - (2 + 4) = 34.
    assert_eq!(group_header_dash_count("\u{65e5}\u{672c}", 40), 34);
}

/// `picker_popup_size` and its two floor/clamp tests are gone with the
/// Archetype-C migration: the popup no longer sizes itself from its
/// content, `render_modal` derives its height from the spec's row count
/// and `centered_rect` does the clamping. What those tests protected —
/// "a one-option list must not collapse to a sliver" — is now
/// structural: head 2 + tail 1 is the floor whatever the option count.
#[test]
fn one_option_picker_is_still_a_readable_dialog() {
    let picker = FieldPicker {
        target: DeviceFormField::Profile,
        options: vec!["default".into()],
        cursor: 0,
        multi: false,
        selected: Vec::new(),
    };
    let out = render_picker_at(80, 30, &picker);
    assert!(out.contains("Select profile"), "title band:\n{out}");
    assert!(out.contains("default"), "the single option:\n{out}");
    assert!(out.contains("[Enter] select"), "the key legend:\n{out}");
}

/// Build an Edit form with every field named, so a render assertion
/// can tell one column from another.
fn edit_form(name: &str, original_id: Option<&str>) -> DeviceFormState {
    DeviceFormState::new_edit(
        name.to_string(),
        "10.10.1.50".to_string(),
        "a4:5e:60:11:22:33".to_string(),
        String::new(),
        "kids".to_string(),
        "living-room".to_string(),
        "dweller".to_string(),
        "tv".to_string(),
        String::new(),
        String::new(),
        // Deliberately NOT the `original_id` the callers pass
        // ("kitchen-tv"): Edit does not render the id, so a fixture
        // that echoed it here would make `out.contains("kitchen-tv")`
        // succeed off the net-name row and quietly prove the opposite
        // of what an id-preview assertion means to check.
        "kitchentv-net".to_string(),
        "false".to_string(),
    )
    .with_original_id(original_id.map(|s| s.to_string()))
}

/// Render a form modal into an 80x30 backend and flatten the buffer.
/// `dump` drops styling, which is what we want — ratatui splits styled
/// text across spans, so asserting on raw cells is unreliable.
fn render_form_to_string(form: DeviceFormState) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(form));
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    dump(term.backend().buffer())
}

/// The destructive confirm shares the form's frame — white, rounded,
/// banded — so the two read as one family. Red stays on the `y Delete`
/// button, the actionable destructive element; the banded title is
/// neutral like every other band.
#[test]
fn delete_confirm_uses_the_shared_frame_with_red_only_on_the_button() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::DeleteConfirm {
        id: "kitchen-tv".to_string(),
        display_name: "Kitchen TV".to_string(),
    });
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    let buf = term.backend().buffer();
    let out = dump(buf);
    assert!(out.contains("DELETE CLIENT"), "banded title:\n{out}");
    assert!(out.contains("Kitchen TV"), "names the target:\n{out}");
    assert!(out.contains('\u{256d}'), "rounded frame:\n{out}");
    assert!(
        out.contains("  y  Delete  ") && out.contains("  n  Cancel  "),
        "both actions offered, with their keys:\n{out}"
    );

    // The claim in this test's name, actually asserted — but NOT as a
    // colour-equality check, because it cannot be one: `theme.rs` pins
    // `brand_red` and `red_glow` to the SAME `Color::Rgb(220, 38, 38)`
    // (`:140` / `:143`, asserted at `:431-432`). So "is this red cell
    // the brand tick or destructive data?" is unanswerable from a
    // rendered buffer, and an assertion phrased that way is a false
    // result waiting to happen.
    //
    // What IS answerable, and is what D15 actually forbids: no cell of
    // the modal's BORDER RING may be red. That is also the DoD's own
    // wording — "brand_red appears on no border".
    //
    // `chars().position`, NOT `str::find` — `find` returns a BYTE offset
    // and the frame's `│` is 3 bytes, so it would report every column
    // two cells right of where it is. Same trap as
    // `group_header_dash_count_uses_chars_not_bytes`.
    let row_at = |y: u16| out.lines().nth(y as usize).unwrap();
    let col_of = |y: u16, glyph: char| row_at(y).chars().position(|c| c == glyph).unwrap() as u16;
    let top = out
        .lines()
        .position(|l| l.contains('\u{256d}'))
        .expect("the top frame renders") as u16;
    let bottom = out
        .lines()
        .position(|l| l.contains('\u{2570}'))
        .expect("the bottom frame renders") as u16;
    let left = col_of(top, '\u{256d}');
    let right = col_of(top, '\u{256e}');

    for y in top..=bottom {
        for x in [left, right] {
            assert_eq!(
                buf[(x, y)].fg,
                T.text_primary,
                "border cell ({x},{y}) is not the neutral frame \u{2014} D15:\n{out}"
            );
        }
    }
    for x in left..=right {
        for y in [top, bottom] {
            assert_eq!(
                buf[(x, y)].fg,
                T.text_primary,
                "border cell ({x},{y}) is not the neutral frame \u{2014} D15:\n{out}"
            );
        }
    }

    // Red belongs to exactly two things here: the row that names the
    // target, and the action that destroys it.
    let name_row = out
        .lines()
        .position(|l| l.contains("Kitchen TV"))
        .expect("the target names itself") as u16;
    assert_eq!(
        buf[(left + 3, name_row)].fg,
        T.red_glow,
        "the target's name must render in the destructive kind:\n{out}"
    );
    // And it must be an outline, never a fill — a filled red beside a
    // filled primary is how an operator deletes what they meant to keep.
    let delete_row = out
        .lines()
        .position(|l| l.contains("  y  Delete  "))
        .expect("the action row renders") as u16;
    let delete_col = out.lines().nth(delete_row as usize).unwrap();
    let start = delete_col.find("  y  Delete  ").unwrap() as u16;
    assert_eq!(
        buf[(start + 2, delete_row)].bg,
        T.bg_elevated,
        "the destructive action is outlined by colour, never filled:\n{out}"
    );
}

#[test]
fn edit_modal_id_row_shows_original_id_not_slug_of_name() {
    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    form.name = "Living Room Pi".to_string();
    let out = render_form_to_string(form);
    assert!(out.contains("kitchen-tv"), "frozen id must render:\n{out}");
    assert!(
        !out.contains("living-room-pi"),
        "slug(name) must NOT be shown as the id on Edit:\n{out}"
    );
}

/// Add has no entity yet, so the id row previews what the submit will
/// derive from the name.
#[test]
fn add_modal_id_row_previews_slug_of_name() {
    let mut form = DeviceFormState::new_add();
    form.name = "Living Room Pi".to_string();
    let out = render_form_to_string(form);
    assert!(
        out.contains("living-room-pi"),
        "Add previews the derived id:\n{out}"
    );
}

/// The action row must actually reach the screen. Caught by CT pty
/// smoke: the body is laid out to exactly fill the modal, so a single
/// wrapped line pushes the last row off the bottom.
/// Every focusable field must be rendered exactly once. Catches the
/// drift the old two-list layout allowed: adding a field to
/// `DeviceFormState::FIELDS` without giving it a row leaves it
/// reachable by Tab but invisible, and the cursor lands nowhere.
#[test]
fn every_focusable_field_is_rendered_exactly_once() {
    for field in DeviceFormState::FIELDS {
        let hits = IDENTITY_FIELDS.iter().filter(|(f, _)| *f == field).count()
            + ASSIGNMENT_FIELDS
                .iter()
                .filter(|(f, _)| *f == field)
                .count();
        assert_eq!(
            hits, 1,
            "{field:?} appears {hits} times across the two sections, expected exactly 1"
        );
    }
}

#[test]
fn modal_renders_the_action_buttons() {
    let out = render_form_to_string(edit_form("Kitchen TV", Some("kitchen-tv")));
    assert!(out.contains("Save"), "Save button missing:\n{out}");
    assert!(out.contains("Cancel"), "Cancel button missing:\n{out}");
}

/// Every region's row count must be **fixed** — independent of which
/// stop holds focus, and independent of the width.
///
/// Two distinct properties, both load-bearing:
///
/// - *Focus-independence.* Each stop carries a different hint, and a
///   hint wider than the body used to wrap, shifting everything below
///   it. Testing only the default focus once missed two hints that were
///   61 and 63 cells wide.
/// - *Width-independence* (contract §2.1). `render_modal` calls the
///   builder twice — at `width - 2`, then again at `width - 3` if the
///   body scrolls, because the scrollbar claims the last column. A row
///   count that flips between the two silently mis-sizes the modal, and
///   no assertion on the line vector alone can see it.
#[test]
fn form_body_holds_its_row_and_width_budget_at_every_focus_stop() {
    // head  = title band, desc band, spacer
    // fields= 2 section band + 1 id + 3 identity
    //       + 1 spacer + 2 section band + 9 assignments
    // tail  = spacer, HINT_ROWS (2), key legend, action row
    //
    // 19 -> 18 on `plp-s5d`: the Tags row left ASSIGNMENT_FIELDS, so
    // the assignment block is 9 rows, not 10. That one row also moves
    // two other assertions in this file — see the centring note on
    // `modal_border_is_rounded_and_not_brand_red`.
    const HEAD: usize = 3;
    const FIELDS: usize = 18;
    const TAIL: usize = 5;

    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    let mut stops = vec![DeviceFormFocus::Cancel, DeviceFormFocus::Save];
    stops.extend(DeviceFormState::FIELDS.map(DeviceFormFocus::Field));

    for stop in stops {
        form.focused = stop;
        // Both widths `render_modal` can pass, for the same spec.
        for width in [58u16, 57] {
            let (body, _) = form_body(&form, width);
            assert_eq!(
                (body.head.len(), body.fields.len(), body.tail.len()),
                (HEAD, FIELDS, TAIL),
                "row budget changed with focus on {stop:?} at width {width}"
            );
            for (i, line) in body
                .head
                .iter()
                .chain(body.fields.iter())
                .chain(body.tail.iter())
                .enumerate()
            {
                let w: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
                assert!(
                    w <= width as usize,
                    "focus {stop:?}: line {i} is {w} cells, over the {width}-cell inner width"
                );
            }
        }
    }
}

/// A long validation error must stay readable — wrapped across the
/// reserved rows, and ellipsised if it still does not fit, so a cut
/// message always looks cut. It used to be hard-truncated mid-word.
#[test]
fn a_long_validation_error_wraps_instead_of_being_silently_cut() {
    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    form.error_message = Some(
        "mac alias \"aa:bb\" doesn't look like a MAC \u{2014} expected XX:XX:XX:XX:XX:XX"
            .to_string(),
    );
    let out = render_form_to_string(form);
    assert!(out.contains("mac alias"), "error head shown:\n{out}");
    assert!(
        out.contains("XX:XX:XX:XX:XX:XX"),
        "the actionable half of the message survives:\n{out}"
    );
}

/// The cursor's row must actually be the focused field's row. Pins the
/// mapping end-to-end, so reordering or inserting a field cannot move
/// the caret onto a neighbour without a test noticing.
#[test]
fn cursor_row_always_belongs_to_the_focused_field() {
    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    for (field, label) in IDENTITY_FIELDS.iter().chain(ASSIGNMENT_FIELDS.iter()) {
        form.focused = DeviceFormFocus::Field(*field);
        let (body, cursor) = form_body(&form, 58);
        let Some((row, _)) = cursor else {
            // Pickers and locked rows legitimately take no cursor.
            continue;
        };
        // The row is an index into the FIELD REGION, not the whole
        // body — `render_scroll_body` scrolls that region under a
        // pinned head, and `place_cursor` adds `head_h` back.
        let text: String = body.fields[row]
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            text.contains(label),
            "cursor row {row} does not hold {label:?}, it holds {text:?}"
        );
    }
}

#[test]
fn modal_renders_both_section_headers() {
    let out = render_form_to_string(edit_form("Kitchen TV", Some("kitchen-tv")));
    assert!(out.contains("IDENTITY"), "identity section header:\n{out}");
    assert!(
        out.contains("ASSIGNMENTS"),
        "assignments section header:\n{out}"
    );
}

/// Red is an accent, never the frame. The old form drew a square
/// brand_red border; the shared chrome is a rounded text_primary one.
#[test]
fn modal_border_is_rounded_and_not_brand_red() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(edit_form("Kitchen TV", Some("kt"))));
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    let buf = term.backend().buffer();
    // `plp-s5d`: the body lost the Tags row, so it is 3+18+5 = 26
    // rows → 28 with the frame. Centred in 80x30 that puts the box at
    // y = (30-28)/2 = 1, one row LOWER than the 29-row box it replaced
    // (which floored to 0). Probing the old (10, 0) now finds blank
    // space above the frame, which is what the first run reported.
    let corner = &buf[(10, 1)];
    assert_eq!(corner.symbol(), "\u{256d}", "rounded corner, not square");
    assert_eq!(
        corner.fg, T.text_primary,
        "white frame — red is an accent only"
    );
}

/// Promote pins ip + mac from the ARP snapshot; both must render
/// read-only, which in this grid means no caret can appear on them.
#[test]
fn promote_mode_renders_ip_and_mac_read_only() {
    let form = DeviceFormState::new_promote("10.10.1.77".into(), "aa:bb:cc:dd:ee:ff".into());
    let out = render_form_to_string(form);
    assert!(out.contains("10.10.1.77") && out.contains("aa:bb:cc:dd:ee:ff"));
    assert!(
        !out.contains("10.10.1.77_"),
        "a locked field takes no caret:\n{out}"
    );
}

/// The real terminal cursor must land on the caret cell. Uses a field
/// in the SECOND section on purpose — a first-section-only test would
/// pass even with the body-origin offset wrong.
#[test]
fn cursor_lands_on_the_focused_value_tail_in_the_second_section() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    form.focused = DeviceFormFocus::Field(DeviceFormField::Owner);
    form.owner = "dweller".to_string();
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(form));
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    let pos = term.get_cursor_position().unwrap();
    // Modal is MODAL_W=60 wide, body 3+18+5=26 rows → 28 with the
    // frame, centred in 80×30 → box at (10, 1), so inner is (11, 2).
    // (`plp-s5d`: was 27/29 and box at (10, 0) while the Tags row was
    // in the assignment block. `x` is unaffected — the width did not
    // change.)
    //
    // x: the ecosystem rows carry no `│` rule, so the value column is
    // VALUE_COL = 2 lead + GRID_LABEL_W 18 + 2 gap = 22 — one cell left
    // of the retired grid's GRID_RULE_COL + 2 = 23. "dweller" is 7
    // chars → 11 + 22 + 7 = 40.
    assert_eq!(pos.x, 40, "cursor sits at the value tail");
    // y: `place_cursor` works in FIELD-REGION coordinates and adds the
    // pinned head back. `owner` is field index 12 (2 section band + id
    // + 3 identity + spacer + 2 section band + name/profile/group) —
    // unchanged by `plp-s5d`, because Tags sat AFTER owner in the
    // block. What moved is the box: the inner origin is now y=2, so
    // 2 + 3 + 12 = 17.
    assert_eq!(pos.y, 17, "cursor row follows the second section's offset");
}

/// A picker-backed field opens a popup instead of accepting keystrokes,
/// so it must NOT claim the hardware cursor.
#[test]
fn picker_field_does_not_take_the_cursor() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(form));
    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    // Assert on the model, not the backend: TestBackend's cursor
    // defaults to (0,0), so a buffer-level check here passes even when
    // the cursor was never suppressed.
    let mut f2 = edit_form("Kitchen TV", Some("kitchen-tv"));
    f2.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    assert!(
        form_body(&f2, 58).1.is_none(),
        "a picker field opens a popup and has no insertion point"
    );
}

#[test]
fn form_with_open_picker_renders_overlay_without_panic() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new();
    let mut form =
        DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
    form.picker = Some(FieldPicker {
        target: DeviceFormField::Profile,
        options: form.profiles_snapshot.clone(),
        cursor: 0,
        multi: false,
        selected: Vec::new(),
    });
    app.devices.modal = Some(DeviceModal::Form(form));

    let backend = TestBackend::new(80, 30);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
    })
    .unwrap();
    let out = dump(term.backend().buffer());
    assert!(
        out.contains("Select profile"),
        "picker overlay missing over form:\n{out}"
    );
}

#[test]
fn build_rows_no_grouping_emits_mapped_then_unmapped_with_one_header() {
    let view = DeviceViewDto {
        mapped: vec![
            mk_mapped("b", "10.0.0.1", None),
            mk_mapped("a", "10.0.0.2", None),
        ],
        unmapped: vec![mk_unmapped("10.0.0.99")],
    };
    let rows = build_rows(&view, DeviceGroupBy::None);
    // Sort by name with no grouping → "a", "b", header, unmapped row.
    assert_eq!(rows.len(), 4);
    assert!(matches!(&rows[0], DeviceRow::Mapped(m) if m.name == "a"));
    assert!(matches!(&rows[1], DeviceRow::Mapped(m) if m.name == "b"));
    assert!(matches!(&rows[2], DeviceRow::GroupHeader(h) if h == "Unmapped"));
    assert!(matches!(&rows[3], DeviceRow::Unmapped(u) if u.ip == "10.0.0.99"));
}

#[test]
fn build_rows_owner_grouping_inserts_owner_headers() {
    let view = DeviceViewDto {
        mapped: vec![
            mk_mapped("phone", "10.0.0.2", Some("Family")),
            mk_mapped("laptop", "10.0.0.1", Some("Dweller")),
        ],
        unmapped: vec![],
    };
    let rows = build_rows(&view, DeviceGroupBy::Owner);
    assert_eq!(rows.len(), 4);
    assert!(matches!(&rows[0], DeviceRow::GroupHeader(h) if h == "Owner: Dweller"));
    assert!(matches!(&rows[1], DeviceRow::Mapped(m) if m.name == "laptop"));
    assert!(matches!(&rows[2], DeviceRow::GroupHeader(h) if h == "Owner: Family"));
    assert!(matches!(&rows[3], DeviceRow::Mapped(m) if m.name == "phone"));
}

#[test]
fn next_selectable_index_skips_headers_forward() {
    let rows = vec![
        DeviceRow::GroupHeader("a".into()),
        DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
        DeviceRow::GroupHeader("b".into()),
        DeviceRow::Mapped(mk_mapped("y", "10.0.0.2", None)),
    ];
    // Fresh start → first selectable.
    assert_eq!(next_selectable_index(&rows, None, 1), Some(1));
    // From row 1, next forward → row 3 (skipping header at idx 2).
    assert_eq!(next_selectable_index(&rows, Some(1), 1), Some(3));
    // N4: from row 3 (last selectable), forward clamps — no wrap
    // back to row 1.
    assert_eq!(next_selectable_index(&rows, Some(3), 1), None);
}

#[test]
fn next_selectable_index_skips_headers_backward() {
    let rows = vec![
        DeviceRow::GroupHeader("a".into()),
        DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
        DeviceRow::GroupHeader("b".into()),
        DeviceRow::Mapped(mk_mapped("y", "10.0.0.2", None)),
    ];
    // From row 3 backward → row 1.
    assert_eq!(next_selectable_index(&rows, Some(3), -1), Some(1));
    // N4: from row 1 (first selectable), backward clamps — no wrap
    // to row 3. Row 0 is a header, so there is nothing left to land
    // on without leaving `[0, len)`.
    assert_eq!(next_selectable_index(&rows, Some(1), -1), None);
}

// §4.19 drain of `backlog-tui-clients-focus-refactor`: the original
// concern (focus_unmapped split-panel boolean + missing view_len guard
// on `k`) was eliminated by the S45/S46 unified-list refactor. These
// two tests pin the post-refactor shape so a future split-panel revival
// would surface immediately.
#[test]
fn unified_list_walk_visits_all_selectable_rows_no_headers() {
    let view = DeviceViewDto {
        mapped: vec![
            mk_mapped("phone", "10.0.0.1", Some("Family")),
            mk_mapped("laptop", "10.0.0.2", Some("Dweller")),
        ],
        unmapped: vec![mk_unmapped("10.0.0.99")],
    };
    let rows = build_rows(&view, DeviceGroupBy::Owner);
    let selectable_count = rows.iter().filter(|r| r.is_selectable()).count();
    assert!(
        selectable_count >= 3,
        "expected ≥3 selectable rows, got {selectable_count}"
    );

    let mut visited = Vec::new();
    let mut cursor = next_selectable_index(&rows, None, 1).unwrap();
    visited.push(cursor);
    while visited.len() < selectable_count {
        cursor = next_selectable_index(&rows, Some(cursor), 1).unwrap();
        visited.push(cursor);
    }
    for &idx in &visited {
        assert!(
            rows[idx].is_selectable(),
            "cursor landed on non-selectable row at idx {idx}"
        );
    }
    let mut sorted = visited.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        visited.len(),
        "unified walk visited the same row twice before reaching the end"
    );
    // N4: the walk clamps at the last selectable row instead of
    // wrapping back to the first.
    assert_eq!(
        next_selectable_index(&rows, Some(*visited.last().unwrap()), 1),
        None,
        "expected a clamp at the last selectable row, not a wrap-around"
    );
}

#[test]
fn unified_list_navigation_safe_on_empty_view() {
    // Empty rows must yield None (no panic) — protects the
    // `if let Some(idx) = ...` guard in handle_devices_key.
    let rows: Vec<DeviceRow> = Vec::new();
    assert_eq!(next_selectable_index(&rows, None, 1), None);
    assert_eq!(next_selectable_index(&rows, None, -1), None);
}

#[test]
fn current_selection_snaps_off_a_header() {
    let rows = vec![
        DeviceRow::GroupHeader("a".into()),
        DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
    ];
    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(0)); // pointing at the header
    assert_eq!(current_selection(&state, &rows), Some(1));
}

#[test]
fn modal_form_variant_constructs_via_state_helper() {
    // Pinned so dead-code analysis sees DeviceModal::Form being
    // constructed, not just matched on. The keybindings task wires
    // the live constructors at the key handler layer.
    let modal = DeviceModal::Form(DeviceFormState::new_add());
    match modal {
        DeviceModal::Form(form) => assert_eq!(form.mode, DeviceFormMode::Add),
        _ => panic!("wrong variant"),
    }
}

/// Sprint C T4 (§8.1 list row badge): the row renderer appends
/// `[⚠ UNFILTERED]` to the identity span chain when the device
/// opted out via D14, so the operator spots it from the list
/// without having to open the card.
#[test]
fn render_mapped_row_unfiltered_device_adds_warning_badge() {
    let mut dto = mk_mapped("guest-laptop", "10.0.0.50", None);
    dto.unfiltered = true;
    let row = render_mapped_row(&dto, 0);
    let cells = row_cells_text(&row);
    assert!(
        cells[0].contains("[\u{26a0} UNFILTERED]"),
        "identity column must carry the warning badge — got {:?}",
        cells[0],
    );
}

/// Sprint C T4 regression pin: filtered devices keep the legacy
/// row shape — no badge, just dot + name. A future regression
/// that always emits the badge would surface here.
#[test]
fn render_mapped_row_filtered_device_no_badge() {
    let dto = mk_mapped("worker", "10.0.0.42", None);
    let row = render_mapped_row(&dto, 0);
    let cells = row_cells_text(&row);
    assert!(
        !cells[0].contains("UNFILTERED"),
        "filtered device must NOT show the badge — got {:?}",
        cells[0],
    );
}

/// Helper: render every cell of a Row to a flat string by
/// concatenating its spans' content. Test-local — production
/// code uses ratatui's renderer directly.
fn row_cells_text(row: &ratatui::widgets::Row<'_>) -> Vec<String> {
    // ratatui doesn't expose Row's internal cells publicly, so
    // we re-render via Debug. The Debug impl of Row prints the
    // span content verbatim, which is enough for shape pins.
    let dbg = format!("{row:?}");
    // Single-element vec — the Debug string carries every cell.
    vec![dbg]
}

/// Discipline pin for the test-file split: `tabs/devices.rs` carries no
/// inline test module. It was the one relocated file left without this,
/// so a rebase could regrow it there and nothing would say so.
#[test]
fn no_inline_test_module_remains_in_devices() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "devices.rs",
        include_str!("../tabs/devices.rs"),
    );
}
