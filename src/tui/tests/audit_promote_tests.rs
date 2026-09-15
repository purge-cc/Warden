use super::*;

fn promote_form() -> DeviceFormState {
    let mut form = DeviceFormState::new_promote("192.0.2.2".into(), "02:00:00:00:00:01".into());
    form.name = "Laptop".into();
    form
}

#[test]
fn promotion_focus_never_offers_values_that_cannot_be_saved() {
    let mut form = promote_form();
    for _ in 0..DeviceFormState::FIELDS.len() + 2 {
        assert!(!matches!(
            form.focused,
            DeviceFormFocus::Field(DeviceFormField::MacAliases | DeviceFormField::Notes)
        ));
        form.focus_next();
    }
}

#[tokio::test]
async fn promotion_cannot_type_or_paste_unsupported_values_even_with_stale_focus() {
    let dir = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&dir.path().join("unused.sock"));
    for field in [DeviceFormField::MacAliases, DeviceFormField::Notes] {
        let mut form = promote_form();
        form.focused = DeviceFormFocus::Field(field);
        let mut app = App::known_standalone_for_test();
        app.active_leaf = Leaf::Devices;
        app.devices.modal = Some(DeviceModal::Form(form));
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
            &poller,
            &dir.path().join("unused.toml"),
        )
        .await;
        handle_paste(&mut app, "extra value".into());
        let Some(DeviceModal::Form(form)) = app.devices.modal.as_mut() else {
            panic!("form stays open");
        };
        assert!(form.field_buf(field).is_empty());
    }
}

#[test]
fn promotion_refuses_unsupported_payload_before_ipc() {
    for field in [DeviceFormField::MacAliases, DeviceFormField::Notes] {
        let mut form = promote_form();
        *form.field_buf(field) = match field {
            DeviceFormField::MacAliases => "02:00:00:00:00:02".into(),
            _ => "Keep this note".into(),
        };
        assert!(
            parse_form(&form).is_err(),
            "a populated {field:?} must not be silently discarded"
        );
    }
    assert!(parse_form(&promote_form()).is_ok());
}

#[test]
fn add_and_edit_keep_notes_and_aliases_available() {
    for mode in [DeviceFormMode::Add, DeviceFormMode::Edit] {
        let mut form = DeviceFormState::new_add();
        form.mode = mode;
        form.name = "Laptop".into();
        form.ip = "192.0.2.2".into();
        form.mac_aliases = "02:00:00:00:00:02".into();
        form.notes = "Keep this note".into();
        if mode == DeviceFormMode::Edit {
            form.network_name_wildcard = "false".into();
        }
        assert!(!form.is_locked(DeviceFormField::MacAliases));
        assert!(!form.is_locked(DeviceFormField::Notes));
        let parsed = parse_form(&form).expect("supported fields pass validation");
        assert_eq!(parsed.mac_aliases, ["02:00:00:00:00:02"]);
        assert_eq!(parsed.notes.as_deref(), Some("Keep this note"));
    }
}

#[test]
fn promotion_explains_unavailable_fields_in_the_rendered_form() {
    let mut app = App::new();
    app.active_leaf = Leaf::Devices;
    app.devices.modal = Some(DeviceModal::Form(promote_form()));
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 45)).expect("test backend");
    terminal
        .draw(|frame| tabs::devices::render(frame, frame.area(), &mut app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let lines: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        })
        .collect();
    for label in ["Aliases", "Notes"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains(label) && line.contains("after saving, via Edit")),
            "{label} must explain how it becomes editable: {lines:?}"
        );
    }
}
