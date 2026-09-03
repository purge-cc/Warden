use super::*;
use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto, UnmappedDeviceDto};

fn app_with_view(mapped: Vec<MappedDeviceDto>, unmapped: Vec<UnmappedDeviceDto>) -> App {
    let mut app = App::new();
    app.device_view = Some(DeviceViewDto { mapped, unmapped });
    app.active_leaf = Leaf::Devices;
    app
}

fn mk_mapped(name: &str, ip: &str) -> MappedDeviceDto {
    MappedDeviceDto {
        ip: ip.into(),
        name: name.into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: Some("Operator".into()),
        device_type: Some("ThinkPad".into()),
        department: Some("home".into()),
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

/// §4.64 G4: a mapped device carrying the memberships the daemon
/// serves — `MappedDeviceDto.groups` is `dev.groups.clone()`, i.e.
/// the file's order, never truncated and never sorted.
// Local to this module: the shared `key_char` / `dummy_poller` live in
// sibling test modules and are not in scope here.
fn seam_key_char(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn seam_key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn seam_poller() -> IpcPoller {
    IpcPoller::new(Path::new("/tmp/purge-warden-seam-nonexistent-socket.sock"))
}

/// The integration seam lane C could not build: `/` opens the buffer,
/// Enter commits it, `R` clears. Fails before the seam commit because
/// `InputMode::FilterDevicesSubnet` did not exist and nothing wrote
/// `filter_subnet` — the lane shipped the read side only.
#[tokio::test]
async fn slash_commits_the_subnet_filter_and_capital_r_clears_it() {
    let mut app = app_with_view(vec![mk_mapped("edo-laptop", "10.10.1.14")], Vec::new());
    let poller = seam_poller();

    handle_key(
        &mut app,
        seam_key_char('/'),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        matches!(app.input_mode, InputMode::FilterDevicesSubnet(_)),
        "`/` on Devices must focus the subnet buffer"
    );
    for c in "10.10.1.0/24".chars() {
        handle_key(&mut app, seam_key_char(c), &poller, Path::new("/dev/null")).await;
    }
    handle_key(
        &mut app,
        seam_key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert_eq!(app.devices.filter_subnet.as_deref(), Some("10.10.1.0/24"));
    assert!(matches!(app.input_mode, InputMode::Normal));

    handle_key(
        &mut app,
        seam_key_char('R'),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert_eq!(app.devices.filter_subnet, None, "`R` must clear the filter");
}

/// **The hazard lane C documented and could not close.** The row set
/// `Enter` / `e` / `d` resolve against must be the row set on SCREEN.
/// Wiring the key without switching the handler's `build_rows` call to
/// `build_filtered_rows` lets a stale index open the edit or delete
/// modal on a device the operator cannot see — a delete confirm naming
/// the wrong device.
///
/// Built to fail loudly: the fixture puts the out-of-filter device
/// FIRST, so an unfiltered row set resolves index 0 to exactly the
/// device that must be invisible. Asserting only "returns something"
/// would pass either way.
#[tokio::test]
async fn row_actions_resolve_against_the_filtered_rows_not_the_full_list() {
    // `build_rows` SORTS — measured, not assumed: the first draft of this
    // fixture relied on insertion order and the control arm resolved to
    // the wrong device. The out-of-filter name is chosen to sort FIRST so
    // index 0 is genuinely the device that must become invisible.
    let mut app = app_with_view(
        vec![
            mk_mapped("aaa-other-subnet", "10.99.0.5"),
            mk_mapped("edo-laptop", "10.10.1.14"),
        ],
        Vec::new(),
    );
    app.devices.table_state.select(Some(0));

    // Unfiltered, index 0 is the 10.99 device — the control that makes
    // the assertion below discriminating rather than tautological.
    match selected_device_row(&app) {
        Some(tabs::devices::DeviceRow::Mapped(m)) => assert_eq!(m.name, "aaa-other-subnet"),
        other => panic!("expected the 10.99 device unfiltered, got {other:?}"),
    }

    app.devices.filter_subnet = Some("10.10.1.0/24".into());
    match selected_device_row(&app) {
        Some(tabs::devices::DeviceRow::Mapped(m)) => assert_eq!(
            m.name, "edo-laptop",
            "row actions must resolve against the visible rows; resolving to \
                 aaa-other-subnet means a delete confirm can name a device that \
                 is not on screen"
        ),
        other => panic!("expected the filtered device, got {other:?}"),
    }
}

fn mk_mapped_with_groups(groups: Vec<&str>) -> MappedDeviceDto {
    MappedDeviceDto {
        groups: groups.into_iter().map(String::from).collect(),
        id: Some("edo-laptop".into()),
        ..mk_mapped("edo-laptop", "192.168.1.42")
    }
}

fn mk_unmapped(ip: &str, mac: Option<&str>) -> UnmappedDeviceDto {
    UnmappedDeviceDto {
        ip: ip.into(),
        mac: mac.map(|m| m.into()),
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

// mod-03: the Edit form pins the device's stable IPC id when it
// opens, so a subsequent rename — or a background poll that
// reshuffles the device list under the open modal — can't change
// which device the submit patches.
#[test]
fn edit_form_captures_stable_id_at_open_independent_of_name_edit() {
    let mut row = mk_mapped("kitchen-pi", "10.0.0.5");
    row.id = Some("dev-kitchen".to_string());
    let mut form = edit_form_from(&row);
    assert_eq!(form.original_id.as_deref(), Some("dev-kitchen"));
    // Operator renames the device in the form.
    form.name = "living-room-pi".to_string();
    assert_eq!(
        form.original_id.as_deref(),
        Some("dev-kitchen"),
        "captured id must survive a name edit — the submit targets the original device"
    );
}

// mod-03: a pre-S44 id-less DTO falls back to the slug of the
// ORIGINAL name (captured at open), not the post-edit name, so a
// rename still can't retarget the patch.
#[test]
fn edit_form_falls_back_to_original_name_slug_when_id_absent() {
    let mut row = mk_mapped("Office Laptop", "10.0.0.6");
    row.id = None;
    let form = edit_form_from(&row);
    let expected = crate::cli::commands::target::slug_id("Office Laptop").unwrap();
    assert_eq!(form.original_id.as_deref(), Some(expected.as_str()));
}

#[test]
fn build_edit_form_pulls_focused_mapped_row_fields() {
    let mut app = app_with_view(vec![mk_mapped("laptop", "192.168.1.42")], vec![]);
    // Unified list: row 0 is the only mapped device. With no
    // unmapped tail there's no `── Unmapped ──` header.
    app.devices.table_state.select(Some(0));
    let form = build_edit_form(&app).expect("focused row exists");
    assert_eq!(form.mode, DeviceFormMode::Edit);
    assert_eq!(form.name, "laptop");
    assert_eq!(form.ip, "192.168.1.42");
    assert_eq!(form.mac, "AA:BB:CC:DD:EE:FF");
    assert_eq!(form.profile, "default");
    assert_eq!(form.owner, "Operator");
}

#[test]
fn build_edit_form_returns_none_when_view_missing() {
    let app = App::new(); // device_view = None
    assert!(build_edit_form(&app).is_none());
}

#[test]
fn device_form_option_lists_reads_profiles_and_groups() {
    use crate::config::loader::LoadedConfig;
    use crate::config::schema::{ConfigV1, Group, Id, Profile};
    use std::collections::BTreeMap;

    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), Profile::default());
    profiles.insert("kids".to_string(), Profile::default());
    let groups = vec![Group {
        id: Id::new("media").unwrap(),
        display_name: "Media".into(),
        profile: Id::new("default").unwrap(),
        priority: 0,
        devices: Vec::new(),
    }];
    let cfg = ConfigV1 {
        profiles,
        groups,
        ..Default::default()
    };
    let mut app = App::new();
    app.loaded_config = Some(LoadedConfig {
        config: cfg,
        master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
        files_loaded: Vec::new(),
        total_bytes: 0,
        provenance: Default::default(),
        custom_lists: Default::default(),
    });

    let (profile_ids, group_ids) = device_form_option_lists(&app);
    // BTreeMap key order is sorted.
    assert_eq!(profile_ids, vec!["default".to_string(), "kids".to_string()]);
    assert_eq!(group_ids, vec!["media".to_string()]);
}

#[test]
fn device_form_option_lists_empty_when_no_config() {
    let app = App::new(); // loaded_config = None
    let (profiles, groups) = device_form_option_lists(&app);
    assert!(profiles.is_empty() && groups.is_empty());
}

/// `↓` / `↑` are bound as aliases of Tab / Shift-Tab in the devices
/// form arm. This pins the ring transition the binding depends on;
/// the binding itself is exercised by the pty smoke, since driving
/// the async key handler needs the whole app fixture.
#[test]
fn arrow_key_ring_transitions_match_tab() {
    let mut form = DeviceFormState::new_add();
    form.focused = DeviceFormFocus::Field(DeviceFormField::Ip);
    form.focus_next();
    assert_eq!(form.focused, DeviceFormFocus::Field(DeviceFormField::Mac));
    form.focus_prev();
    assert_eq!(form.focused, DeviceFormFocus::Field(DeviceFormField::Ip));
}

#[test]
fn select_only_fields_are_profile_and_group() {
    // §4.66 L3 made the predicate form-aware; Profile and Group are
    // unconditional, so an empty form is the right fixture here.
    let form = DeviceFormState::new_add();
    assert!(is_select_only_field(&form, DeviceFormField::Profile));
    assert!(is_select_only_field(&form, DeviceFormField::Group));
    assert!(!is_select_only_field(&form, DeviceFormField::Name));
    assert!(!is_select_only_field(&form, DeviceFormField::Ip));
}

#[test]
fn open_field_picker_seeds_cursor_on_current_value() {
    let mut form = DeviceFormState::new_add().with_options(
        vec!["default".into(), "kids".into(), "guest".into()],
        vec![],
    );
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    form.profile = "guest".into();
    open_field_picker(&mut form);
    let picker = form.picker.expect("picker opened");
    assert_eq!(picker.target, DeviceFormField::Profile);
    assert_eq!(picker.options, vec!["default", "kids", "guest"]);
    assert_eq!(picker.cursor, 2, "cursor seeds on the current value");
}

#[test]
fn l3_metadata_fields_are_select_only_once_a_vocabulary_exists() {
    // §4.66 L3: the three metadata fields join the picker cohort — but
    // only where a vocabulary was actually declared. The empty case is
    // the sibling test `l3_empty_vocabulary_leaves_the_field_TYPEABLE`.
    let form = DeviceFormState::new_add().with_label_vocab(
        vec!["Operator".into()],
        vec!["Laptop".into()],
        vec!["Studio".into()],
    );
    for f in [
        DeviceFormField::Owner,
        DeviceFormField::Device,
        DeviceFormField::Department,
    ] {
        assert!(
            is_select_only_field(&form, f),
            "{f:?} must be picker-driven so the operator stops retyping"
        );
    }
}

#[test]
fn l3_picker_offers_display_names_not_ids() {
    // The constraint that decides this sprint: `Device.owner` is free
    // text ("Operator") while `Label.id` is an `Id` ("operator"), so the
    // two sets never intersect. `matches_value` accepts either, and the
    // display name is the one that also reads correctly in the table.
    use crate::config::loader::LoadedConfig;
    use crate::config::schema::{ConfigV1, Id, Label, LabelKind};

    let cfg = ConfigV1 {
        labels: vec![Label {
            id: Id::new("operator").unwrap(),
            kind: LabelKind::Owner,
            display_name: "Operator".to_string(),
            description: None,
        }],
        ..Default::default()
    };
    let mut app = App::new();
    app.loaded_config = Some(LoadedConfig {
        config: cfg,
        master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
        files_loaded: Vec::new(),
        total_bytes: 0,
        provenance: Default::default(),
        custom_lists: Default::default(),
    });

    let (owners, types, depts) = device_form_label_vocab(&app);
    assert_eq!(owners, vec!["Operator".to_string()]);
    assert!(types.is_empty(), "a kind with no vocabulary stays empty");
    assert!(depts.is_empty());
}

#[test]
fn l3_empty_vocabulary_leaves_the_field_typeable_not_merely_picker_free() {
    // REGRESSION GUARD. The first cut of L3 marked these three fields
    // select-only UNCONDITIONALLY. `field_accepts_typing` is the negation
    // of that predicate, and `open_field_picker` no-ops on an empty list —
    // so with no vocabulary the field could neither be typed into NOR
    // picked from. Dead, on every config that has not declared labels,
    // which today is all of them.
    //
    // The original test asserted only `picker.is_none()` and passed
    // happily on the broken build — it measured the MECHANISM (no popup
    // opens) instead of the PROPERTY (the operator can enter a value).
    // The name says which one this asserts.
    let mut form = DeviceFormState::new_add();
    for f in [
        DeviceFormField::Owner,
        DeviceFormField::Device,
        DeviceFormField::Department,
    ] {
        assert!(
            !is_select_only_field(&form, f),
            "{f:?} must NOT be select-only with an empty vocabulary"
        );
        assert!(
            field_accepts_typing(&form, f),
            "{f:?} must stay typeable with an empty vocabulary"
        );
    }
    form.focused = DeviceFormFocus::Field(DeviceFormField::Owner);
    open_field_picker(&mut form);
    assert!(
        form.picker.is_none(),
        "an empty vocabulary must not trap the operator in an empty popup"
    );
}

#[test]
fn l3_the_metadata_picker_offers_a_way_to_clear() {
    // Making a field select-only REMOVES typing, so everything that used
    // to be done by typing needs an equivalent in the picker — including
    // emptying the field. Without this the operator can set an owner and
    // never unset it.
    let mut form = DeviceFormState::new_add().with_label_vocab(
        vec!["Operator".into(), "Member".into()],
        Vec::new(),
        Vec::new(),
    );
    form.focused = DeviceFormFocus::Field(DeviceFormField::Owner);
    form.owner = "Operator".into();
    open_field_picker(&mut form);
    let picker = form.picker.as_ref().expect("vocabulary is non-empty");
    assert_eq!(
        picker.options.first().map(String::as_str),
        Some(""),
        "the clear option must lead the list"
    );
    assert_eq!(picker.options.len(), 3, "clear + the two declared owners");
    // The cursor must land on the CURRENT value, not on the clear row —
    // otherwise Enter-without-thinking wipes the field.
    assert_eq!(picker.options[picker.cursor], "Operator");
}

#[test]
fn l3_no_clear_row_when_there_is_no_vocabulary() {
    // A popup containing only "clear" is a worse affordance than plain
    // typing, and the field is free text in that case anyway.
    assert!(with_clear_option(&[]).is_empty());
}

#[test]
fn l3_a_declared_vocabulary_flips_the_field_to_picker_driven() {
    // The other half: once a kind HAS a vocabulary, the field becomes
    // select-only so the operator picks instead of retyping. Per-kind,
    // not all-or-nothing — declaring owners must not freeze departments.
    let form =
        DeviceFormState::new_add().with_label_vocab(vec!["Operator".into()], Vec::new(), Vec::new());
    assert!(is_select_only_field(&form, DeviceFormField::Owner));
    assert!(
        !is_select_only_field(&form, DeviceFormField::Department),
        "a kind with no vocabulary must stay free text even when a sibling has one"
    );
}

#[test]
fn open_field_picker_noop_when_no_options() {
    let mut form = DeviceFormState::new_add(); // empty snapshots
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    open_field_picker(&mut form);
    assert!(form.picker.is_none(), "no picker when nothing to choose");
}

#[test]
fn picker_enter_writes_selection_and_closes() {
    let mut form =
        DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    form.profile = "default".into();
    open_field_picker(&mut form);
    handle_form_picker_key(&mut form, KeyCode::Down); // → "kids"
    handle_form_picker_key(&mut form, KeyCode::Enter);
    assert!(form.picker.is_none(), "Enter closes the picker");
    assert_eq!(form.profile, "kids", "selection written to the field");
}

#[test]
fn picker_esc_closes_without_change() {
    let mut form =
        DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
    form.profile = "default".into();
    open_field_picker(&mut form);
    handle_form_picker_key(&mut form, KeyCode::Down); // move cursor
    handle_form_picker_key(&mut form, KeyCode::Esc);
    assert!(form.picker.is_none());
    assert_eq!(form.profile, "default", "Esc leaves the field unchanged");
}

// ── §4.64 G4: the Group field is a multi-select ───────────────────

/// An Edit form seeded from a device in two groups, opened on the
/// Group row, offers a MULTI picker with both already selected.
#[test]
fn g4_group_picker_on_edit_is_multi_and_seeds_every_membership() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "kids"]))
        .with_options(vec!["default".into()], vec!["phones".into(), "kids".into()]);
    assert_eq!(form.groups, "phones,kids", "the form holds ALL of them");
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    let picker = form.picker.expect("picker opened");
    assert!(picker.multi, "Edit must offer multi-select");
    assert_eq!(picker.selected, vec!["phones", "kids"]);
}

/// Toggling a third group APPENDS it. The two ids the file already
/// carried keep their positions — DM2 resolves by priority so the
/// order is inert, and rewriting it would put a diff in the
/// operator's config that no operator action asked for.
#[test]
fn g4_space_toggle_appends_and_never_reorders() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "kids"])).with_options(
        vec!["default".into()],
        // Snapshot order deliberately DISAGREES with the file's order:
        // a commit rebuilt from `options` would come out "iot,kids,
        // phones" and this test is the thing that says so.
        vec!["iot".into(), "kids".into(), "phones".into()],
    );
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    // Cursor starts on "phones" (the first membership); walk to "iot".
    let picker = form.picker.as_mut().unwrap();
    picker.cursor = 0;
    assert_eq!(picker.options[0], "iot");
    handle_form_picker_key(&mut form, KeyCode::Char(' '));
    handle_form_picker_key(&mut form, KeyCode::Enter);
    assert!(form.picker.is_none(), "Enter commits and closes");
    assert_eq!(
        form.groups, "phones,kids,iot",
        "the new membership lands at the END"
    );
}

/// Toggling a selected row off removes exactly it.
#[test]
fn g4_space_toggle_off_removes_only_that_membership() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "kids"]))
        .with_options(vec!["default".into()], vec!["phones".into(), "kids".into()]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    form.picker.as_mut().unwrap().cursor = 1; // "kids"
    handle_form_picker_key(&mut form, KeyCode::Char(' '));
    handle_form_picker_key(&mut form, KeyCode::Enter);
    assert_eq!(form.groups, "phones");
}

/// Esc grants nothing and revokes nothing — same rule the Lists
/// consent gate follows.
#[test]
fn g4_esc_leaves_the_membership_buffer_untouched() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "kids"]))
        .with_options(vec!["default".into()], vec!["phones".into(), "kids".into()]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    handle_form_picker_key(&mut form, KeyCode::Char(' '));
    handle_form_picker_key(&mut form, KeyCode::Esc);
    assert_eq!(form.groups, "phones,kids");
}

/// A membership the config no longer declares stays VISIBLE in the
/// picker. The submit carries it either way (the buffer holds it), so
/// hiding it would mean the operator cannot see — or remove — what
/// they are about to re-save.
#[test]
fn g4_a_stale_membership_is_offered_not_hidden() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "deleted-group"]))
        .with_options(vec!["default".into()], vec!["phones".into()]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    let picker = form.picker.expect("picker opened");
    assert_eq!(picker.options, vec!["phones", "deleted-group"]);
    assert_eq!(picker.selected, vec!["phones", "deleted-group"]);
}

/// The other end of the same rule as the `parse_form` refusal: the
/// Add wire (`ClientConfig.group`) is a single `Option<String>`, so
/// Add must never hand the operator a widget that can express two.
#[test]
fn g4_add_form_group_picker_stays_single_select() {
    let mut form = DeviceFormState::new_add()
        .with_options(vec!["default".into()], vec!["phones".into(), "kids".into()]);
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    assert!(
        !form.picker.as_ref().unwrap().multi,
        "Add carries one group on the wire"
    );
    handle_form_picker_key(&mut form, KeyCode::Char(' '));
    handle_form_picker_key(&mut form, KeyCode::Down);
    handle_form_picker_key(&mut form, KeyCode::Enter);
    assert_eq!(form.groups, "kids", "Space is inert; Enter replaces");
}

/// Belt and braces for the same wire: even if a multi-valued buffer
/// reached an Add form some other way, the submit refuses rather than
/// silently keeping the first — that silent keep IS the G4 defect.
#[test]
fn g4_add_submit_refuses_a_multi_group_buffer_instead_of_truncating() {
    let mut form = DeviceFormState::new_add();
    form.name = "new-phone".into();
    form.ip = "192.168.1.9".into();
    form.groups = "phones,kids".into();
    let err = parse_form(&form).expect_err("must refuse");
    assert!(err.contains("one group"), "{err}");
}

/// The Promote form's Group row was editable while the promote wire
/// carried no group at all — `handle_device_promote` writes
/// `group: None` by design — so a group chosen there was dropped
/// without a word. Locked now: `focus_ring` filters `is_locked`, so
/// the row cannot take focus and the picker cannot be opened on it.
#[test]
fn g4_promote_form_cannot_offer_a_group_the_wire_will_not_carry() {
    let mut form = DeviceFormState::new_promote("192.168.1.9".into(), "AA:BB:CC:DD:EE:09".into())
        .with_options(vec!["default".into()], vec!["phones".into()]);
    assert!(form.is_locked(DeviceFormField::Group));
    assert!(
        {
            // Walk the ring rather than reading it: `focus_ring` is
            // private, and what matters is the observable behaviour —
            // Tab never lands on the row.
            form.focused = DeviceFormFocus::Field(DeviceFormField::Name);
            let mut seen = Vec::new();
            for _ in 0..DeviceFormState::FIELDS.len() + 3 {
                form.focus_next();
                seen.push(form.focused);
            }
            !seen.contains(&DeviceFormFocus::Field(DeviceFormField::Group))
        },
        "a locked row must be out of the tab order"
    );
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    open_field_picker(&mut form);
    handle_form_picker_key(&mut form, KeyCode::Enter);
    assert!(
        form.groups.is_empty(),
        "nothing may write a field the submit drops"
    );
    // The Edit form is the other arm: same field, not locked.
    assert!(!edit_form_from(&mk_mapped_with_groups(vec![])).is_locked(DeviceFormField::Group));
}

/// The defect itself, at the builder: a rename must carry BOTH ids
/// into the patch. The file-level twin lives in `socket_server.rs`
/// (`tui_edit_of_a_two_group_device_keeps_both_memberships_in_the_file`)
/// — this one localises a failure to the TUI half of the chain.
#[test]
fn g4_edit_patch_carries_the_whole_membership_list() {
    let mut form = edit_form_from(&mk_mapped_with_groups(vec!["phones", "kids"]));
    form.name = "work-thinkpad".into();
    let patch = device_update_patch(&form).expect("form parses");
    assert_eq!(
        patch.groups,
        Some(vec!["phones".to_string(), "kids".to_string()]),
        "DevicePatch.groups is a FULL-LIST replacement — a short list deletes"
    );
}

#[test]
fn build_edit_form_returns_none_when_focused_row_is_unmapped() {
    // Auto-snap will move the cursor to the unmapped row when
    // there are no mapped rows; build_edit_form must refuse it
    // because Edit only applies to mapped devices.
    let mut app = app_with_view(
        vec![],
        vec![mk_unmapped("10.0.0.99", Some("AA:BB:CC:DD:EE:99"))],
    );
    // Unified list: [Header("Unmapped"), Unmapped]. select(0)
    // points at the header; current_selection snaps forward to 1.
    app.devices.table_state.select(Some(0));
    assert!(build_edit_form(&app).is_none());
}

#[test]
fn build_promote_form_uses_arp_mac_from_focused_unmapped_row() {
    let mut app = app_with_view(
        vec![],
        vec![mk_unmapped("10.0.0.99", Some("AA:BB:CC:DD:EE:99"))],
    );
    // [Header("Unmapped"), Unmapped] — current_selection snaps
    // off the header to row 1.
    app.devices.table_state.select(Some(0));
    let form = build_promote_form(&app).expect("focused unmapped row with mac");
    assert_eq!(form.mode, DeviceFormMode::Promote);
    assert_eq!(form.ip, "10.0.0.99");
    assert_eq!(form.mac, "AA:BB:CC:DD:EE:99");
    assert!(form.ip_locked, "promote form locks the IP field");
}

#[test]
fn build_promote_form_refuses_when_arp_has_no_mac() {
    let mut app = app_with_view(vec![], vec![mk_unmapped("10.0.0.50", None)]);
    app.devices.table_state.select(Some(0));
    let err = build_promote_form(&app).unwrap_err();
    assert!(err.contains("MAC"), "error must explain why: {err}");
    assert!(err.contains("10.0.0.50"), "error must name the IP: {err}");
    assert!(
        err.contains("ping"),
        "error must give a recovery hint: {err}"
    );
    assert!(
        err.contains("DHCP"),
        "error must explain WHY MAC is required: {err}"
    );
}

#[test]
fn build_promote_form_refuses_when_arp_mac_is_empty_string() {
    // ARP entry exists but is an empty string. The handler must
    // treat it the same as None — empty MAC fails the pin
    // requirement just like no MAC at all.
    let mut app = app_with_view(vec![], vec![mk_unmapped("10.0.0.50", Some(""))]);
    app.devices.table_state.select(Some(0));
    let err = build_promote_form(&app).unwrap_err();
    assert!(err.contains("MAC"));
}

#[test]
fn build_promote_form_refuses_when_focused_row_is_mapped() {
    // The unified list auto-snaps to the first selectable row.
    // With only a mapped device present, that's a Mapped row,
    // and `p` (promote) must refuse it with a typed error rather
    // than silently misinterpreting it as unmapped.
    let mut app = app_with_view(vec![mk_mapped("laptop", "192.168.1.42")], vec![]);
    app.devices.table_state.select(Some(0));
    let err = build_promote_form(&app).unwrap_err();
    assert!(
        err.contains("not an unmapped device"),
        "expected typed refusal, got: {err}"
    );
}

#[test]
fn focused_mapped_name_returns_the_row_name() {
    let mut app = app_with_view(vec![mk_mapped("alpha", "1.1.1.1")], vec![]);
    app.devices.table_state.select(Some(0));
    assert_eq!(focused_mapped_name(&app).as_deref(), Some("alpha"));
}

#[test]
fn focused_mapped_name_returns_none_when_view_missing() {
    let app = App::new();
    assert!(focused_mapped_name(&app).is_none());
}

// ── parse_form: client-side validation at submit time ────────

#[test]
fn parse_form_happy_path_returns_typed_values() {
    let mut form = DeviceFormState::new_add();
    form.name = "edo-laptop".into();
    form.ip = "192.168.1.42".into();
    form.profile = "default".into();
    form.mac_aliases = "AA:BB:CC:DD:EE:01,AA:BB:CC:DD:EE:02".into();
    form.owner = "Operator".into();
    let p = parse_form(&form).unwrap();
    assert_eq!(p.name, "edo-laptop");
    assert_eq!(p.ip.to_string(), "192.168.1.42");
    assert_eq!(p.mac_aliases.len(), 2);
    assert_eq!(p.owner.as_deref(), Some("Operator"));
}

#[test]
fn parse_form_rejects_empty_name() {
    let mut form = DeviceFormState::new_add();
    form.ip = "192.168.1.42".into();
    let err = parse_form(&form).unwrap_err();
    assert!(err.contains("name"), "got: {err}");
}

#[test]
fn parse_form_rejects_unparseable_ip_with_value_in_message() {
    let mut form = DeviceFormState::new_add();
    form.name = "x".into();
    form.ip = "not-an-ip".into();
    let err = parse_form(&form).unwrap_err();
    assert!(err.contains("not-an-ip"), "got: {err}");
}

/// **`plp-s5d` retargeted these two from `tags` to `mac_aliases`.**
///
/// The Tags field is gone, but neither test was really about tags: the
/// form has three comma-separated list fields sharing one parse shape
/// (`split(',')`, trim, skip empties, validate each item, name the
/// offender in the error). Deleting them would have dropped the only
/// coverage of that shape rather than the coverage of one field, which
/// is why they moved instead.
///
/// `mac_aliases` is the closest twin: it validates per item and its
/// refusal quotes the offending entry, exactly as the tag parse did.
#[test]
fn parse_form_rejects_an_invalid_list_item_and_names_it() {
    let mut form = DeviceFormState::new_add();
    form.name = "x".into();
    form.ip = "192.168.1.1".into();
    form.mac_aliases = "BAD".into();
    let err = parse_form(&form).unwrap_err();
    assert!(
        err.contains("BAD"),
        "the refusal must quote the offender: {err}"
    );
}

#[test]
fn parse_form_skips_empty_list_segments() {
    // ",AA:BB:CC:DD:EE:01,," → one alias, no errors: a trailing or
    // doubled comma is forgiven rather than parsed as an empty item.
    let mut form = DeviceFormState::new_add();
    form.name = "x".into();
    form.ip = "192.168.1.1".into();
    form.mac_aliases = ",AA:BB:CC:DD:EE:01,,".into();
    let p = parse_form(&form).unwrap();
    assert_eq!(p.mac_aliases.len(), 1);
}

#[test]
fn parse_form_treats_empty_optional_fields_as_none() {
    let mut form = DeviceFormState::new_add();
    form.name = "x".into();
    form.ip = "192.168.1.1".into();
    form.owner = "   ".into(); // whitespace only
    let p = parse_form(&form).unwrap();
    assert!(p.owner.is_none(), "whitespace owner is None");
}

// ── §net-name: the two device-form fields, read → parse → patch ──

/// The whole read side, end to end: the DTO the daemon serves must
/// arrive in the form's buffers, and the wildcard must render as a
/// CONCRETE token. A blank wildcard buffer parses to `None`, which the
/// patch forwards as leave-alone — so a device whose wildcard is
/// `false` would become un-turn-off-able through the modal.
#[test]
fn edit_form_prefills_both_network_name_fields_from_the_dto() {
    let dto = MappedDeviceDto {
        network_name: Some("desktop-1".into()),
        network_name_wildcard: true,
        ..mk_mapped("edo-laptop", "192.168.1.42")
    };
    let form = edit_form_from(&dto);
    assert_eq!(form.network_name, "desktop-1");
    assert_eq!(
        form.network_name_wildcard, "true",
        "the wildcard buffer must be concrete, never blank"
    );

    let unset = edit_form_from(&mk_mapped("edo-laptop", "192.168.1.42"));
    assert_eq!(unset.network_name, "");
    assert_eq!(unset.network_name_wildcard, "false");
}

#[test]
fn parse_form_carries_network_name_and_wildcard() {
    let mut form = edit_form_from(&mk_mapped("desktop-1", "10.10.1.50"));
    form.network_name = "desktop-1".into();
    form.network_name_wildcard = "TRUE".into(); // case-insensitive
    let parsed = parse_form(&form).unwrap();
    assert_eq!(parsed.network_name.as_deref(), Some("desktop-1"));
    assert_eq!(parsed.network_name_wildcard, Some(true));
}

#[test]
fn parse_form_rejects_bad_wildcard_text() {
    let mut form = edit_form_from(&mk_mapped("desktop-1", "10.10.1.50"));
    form.network_name_wildcard = "sideways".into();
    let err = parse_form(&form).unwrap_err();
    assert!(
        err.contains("sideways"),
        "the refusal must quote what was typed: {err}"
    );
}

/// An empty Network Name on an Edit form is an explicit CLEAR, not a
/// leave-alone. `DevicePatch.network_name` is `Option<Option<String>>`
/// and the two arms mean opposite things: `Some(None)` erases the
/// name, `None` keeps whatever the file has. The form always holds the
/// operator's whole intent, so it must never emit the second.
#[test]
fn edit_patch_clears_the_network_name_when_the_field_is_emptied() {
    let dto = MappedDeviceDto {
        network_name: Some("desktop-1".into()),
        network_name_wildcard: false,
        ..mk_mapped("edo-laptop", "192.168.1.42")
    };
    let mut form = edit_form_from(&dto);
    form.network_name.clear();
    let patch = device_update_patch(&form).expect("form parses");
    assert_eq!(
        patch.network_name,
        Some(None),
        "an emptied field erases the name; None here would silently keep it"
    );
}

/// The shape the daemon's validator REFUSES: name cleared while the
/// wildcard stays on. The TUI deliberately does not pre-check this —
/// the invariant is the validator's, and duplicating it here would
/// leave the error-surfacing path (`submit_form`'s `Err` arm, which
/// writes `error_message` and re-shows the modal) never exercised, and
/// the two copies free to drift.
///
/// So this pins the BUILDER only: the patch must actually carry the
/// refusable combination rather than quietly dropping half of it. The
/// file-level twin belongs in `socket_server.rs`, next to the other
/// `device_update_patch` round trips.
#[test]
fn edit_patch_carries_wildcard_without_name_for_the_daemon_to_refuse() {
    let dto = MappedDeviceDto {
        network_name: Some("desktop-1".into()),
        network_name_wildcard: true,
        ..mk_mapped("edo-laptop", "192.168.1.42")
    };
    let mut form = edit_form_from(&dto);
    form.network_name.clear(); // wildcard buffer still "true"
    let patch = device_update_patch(&form).expect("the TUI does not pre-refuse this");
    assert_eq!(patch.network_name, Some(None));
    assert_eq!(patch.network_name_wildcard, Some(true));
}

/// Emptying the wildcard buffer on an Edit form must NOT parse to
/// `None`. Nothing stops the operator doing it — the field is
/// free-text (`is_select_only_field` falls through to `false`), so
/// Backspace reaches it — and `None` travels to the daemon as
/// **leave-alone**, i.e. a Save that reports success and changes
/// nothing.
///
/// The two fields would otherwise disagree about what empty means:
/// emptying Network Name clears it, emptying Wildcard would silently
/// keep it. Same silent-drop class as the Add-wire guard below.
#[test]
fn parse_form_refuses_an_emptied_wildcard_on_an_edit_form() {
    let dto = MappedDeviceDto {
        network_name: Some("desktop-1".into()),
        network_name_wildcard: true,
        ..mk_mapped("edo-laptop", "192.168.1.42")
    };
    let mut form = edit_form_from(&dto);
    form.network_name_wildcard.clear();
    let err = parse_form(&form).unwrap_err();
    assert!(
        err.contains("network_name_wildcard"),
        "an emptied wildcard must refuse, not silently leave-alone: {err}"
    );
}

/// The Add and Promote wires (`ClientConfig` / `PromoteFields`) carry
/// no network name, so a typed one would vanish on a Save that reports
/// success. Refuse instead, exactly as the `groups.len() > 1` gate
/// eleven lines above does, and for the same reason.
#[test]
fn parse_form_refuses_a_network_name_the_add_wire_cannot_carry() {
    let mut form = DeviceFormState::new_add();
    form.name = "desktop-1".into();
    form.ip = "10.10.1.50".into();
    form.profile = "default".into();

    // Untouched: both buffers empty, nothing to complain about.
    assert!(parse_form(&form).is_ok(), "an untouched Add form is silent");

    form.network_name = "desktop-1".into();
    assert!(parse_form(&form).unwrap_err().contains("network name"));

    // The wildcard alone is just as unsendable as the name.
    form.network_name.clear();
    form.network_name_wildcard = "true".into();
    assert!(parse_form(&form).unwrap_err().contains("network name"));
}
