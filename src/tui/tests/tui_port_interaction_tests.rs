use super::*;
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

#[tokio::test]
async fn settings_outcomes_keep_long_failures_reachable_before_closing() {
    use backup_restore_modal::{BackupModal, RestoreModal, RestoreStage, SubmitOutcome};
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let path = temp.path().join("config.toml");
    for backup in [false, true] {
        let mut app = App::known_standalone_for_test();
        app.active_leaf = Leaf::Settings;
        let failure = format!("{}\nFINAL FAILURE DETAIL", "Validation detail\n".repeat(40));
        if backup {
            app.settings.backup_modal = Some(BackupModal::Submitted {
                msg: failure,
                ok: false,
            });
        } else {
            app.settings.restore_modal = Some(RestoreModal {
                stage: RestoreStage::Submitted(SubmitOutcome::Failed(failure)),
            });
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        assert!(app.settings.report_max_scroll.get() > 0);
        handle_key(&mut app, KeyCode::End.into(), &poller, &path).await;
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        click_text(terminal.backend().buffer(), "FINAL FAILURE DETAIL");
        assert!(app.settings.backup_modal.is_some() || app.settings.restore_modal.is_some());
        handle_key(&mut app, KeyCode::Home.into(), &poller, &path).await;
        assert_eq!(app.settings.report_scroll, 0);
        handle_key(&mut app, KeyCode::Enter.into(), &poller, &path).await;
        assert!(app.settings.backup_modal.is_none() && app.settings.restore_modal.is_none());
    }
}

#[tokio::test]
async fn query_picker_mouse_actions_override_the_previous_button_focus() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let path = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::QueryLog;
    let mut modal = query_log_rule_modal::QueryLogRuleModal::open(
        crate::cli::commands::rules::Action::Allow,
        "example.test".into(),
        "127.0.0.1".into(),
        vec![query_log_rule_modal::ListRow::new(
            "test".into(),
            "Test list".into(),
            vec!["default".into()],
        )],
    );
    modal.focus = 1;
    app.query_log_rule_modal = Some(modal);
    let mut terminal = Terminal::new(TestBackend::new(125, 36)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let confirm = click_text(terminal.backend().buffer(), "Confirm");
    handle_mouse(&mut app, confirm, &poller, &path).await;
    let modal = app
        .query_log_rule_modal
        .as_mut()
        .expect("picker stays open");
    assert_eq!(
        modal.error.as_deref(),
        Some(query_log_rule_modal::NO_SELECTION)
    );
    modal.focus = 2;
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let row = click_text(terminal.backend().buffer(), "Test list");
    handle_mouse(&mut app, row, &poller, &path).await;
    let modal = app
        .query_log_rule_modal
        .as_ref()
        .expect("picker stays open");
    assert_eq!(modal.focus, 0);
    assert!(modal.rows[0].selected);
}

#[tokio::test]
async fn source_picker_click_selects_then_buttons_confirm_or_cancel() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Lists;
    app.lists.import_source = Some(0);
    assert_eq!(mouse_focus::choice(&mut app, 1), None);
    assert_eq!(app.lists.import_source, Some(1));
    assert!(app.lists.edit_modal.is_none());
    handle_key(&mut app, KeyCode::Tab.into(), &poller, &config).await;
    assert_eq!(app.lists.import_source_focus, 1);
    handle_key(&mut app, KeyCode::Enter.into(), &poller, &config).await;
    assert!(app.lists.import_source.is_none());
    assert!(app.lists.edit_modal.is_none());

    app.lists.import_source = Some(1);
    app.lists.import_source_focus = 0;
    handle_key(&mut app, KeyCode::BackTab.into(), &poller, &config).await;
    assert_eq!(app.lists.import_source_focus, 2);
    handle_key(&mut app, KeyCode::Enter.into(), &poller, &config).await;
    assert!(app.lists.import_source.is_none());
    assert!(app.lists.edit_modal.is_some());
}

#[tokio::test]
async fn lowercase_s_sorts_and_shift_s_opens_resolver_through_the_dispatcher() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Labels;
    mouse::register(
        &app,
        ratatui::layout::Rect::new(1, 3, 10, 1),
        mouse::MouseAction::Sort(Leaf::Labels, 0),
    );
    handle_key(&mut app, KeyCode::Char('s').into(), &poller, &config).await;
    assert!(app.resolver_modal.is_none());
    handle_key(&mut app, KeyCode::Enter.into(), &poller, &config).await;
    assert_eq!(app.mouse.sort(Leaf::Labels).unwrap().column, 0);
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT),
        &poller,
        &config,
    )
    .await;
    assert!(app.resolver_modal.is_some());
    handle_key(&mut app, KeyCode::Esc.into(), &poller, &config).await;
    assert!(app.resolver_modal.is_none());
    assert_eq!(app.active_leaf, Leaf::Labels);
}

fn click_text(buffer: &Buffer, text: &str) -> MouseEvent {
    let needle: Vec<char> = text.chars().collect();
    for y in (buffer.area.y..buffer.area.bottom()).rev() {
        let row: Vec<char> = (buffer.area.x..buffer.area.right())
            .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
            .collect();
        if let Some(x) = row.windows(needle.len()).position(|cells| cells == needle) {
            return MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: buffer.area.x + x as u16,
                row: y,
                modifiers: KeyModifiers::NONE,
            };
        }
    }
    panic!("Missing clickable text: {text}");
}

#[tokio::test]
async fn filter_apply_click_works_while_discard_has_keyboard_focus() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.filter_domain = Some("before.example".into());
    app.input_mode = InputMode::FilterDomain("after.example".into());
    app.query_log.domain_focus = query_log_controls::FilterFocus::Discard;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Apply");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    assert_eq!(
        app.query_log.filter_domain.as_deref(),
        Some("after.example")
    );
    assert!(matches!(app.input_mode, InputMode::Normal));
    assert!(app.force_poll);
}

#[tokio::test]
async fn filter_discard_click_keeps_the_applied_value_and_page() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.filter_domain = Some("before.example".into());
    app.input_mode = InputMode::FilterDomain("after.example".into());
    app.query_log.domain_focus = query_log_controls::FilterFocus::Apply;
    app.force_poll = false;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Discard");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    assert_eq!(
        app.query_log.filter_domain.as_deref(),
        Some("before.example")
    );
    assert!(matches!(app.input_mode, InputMode::Normal));
    assert!(!app.force_poll);
}

#[tokio::test]
async fn a_visible_selector_arrow_uses_the_same_value_change_as_the_keyboard() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Subnets;
    let mut modal = subnet_modal::SubnetModal::open_add(vec!["first".into(), "second".into()], 0);
    let subnet_modal::Stage::EditingForm(form) = &mut modal.stage else {
        panic!("add form");
    };
    form.focused = subnet_modal::FormField::Profile;
    app.subnets.modal = Some(modal);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "›");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    let subnet_modal::Stage::EditingForm(form) = &app.subnets.modal.as_ref().unwrap().stage else {
        panic!("form stays open");
    };
    assert_eq!(form.profile_option_label(), "second");
}

#[test]
fn resizing_below_the_floor_discards_old_modal_hit_regions() {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.input_mode = InputMode::FilterDomain("value".into());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Apply");
    assert!(mouse::action(&app, click).is_some());
    let mut small = Terminal::new(TestBackend::new(60, 15)).unwrap();
    small.draw(|frame| ui::render(frame, &mut app)).unwrap();
    assert_eq!(mouse::action(&app, click), None);
}

#[tokio::test]
async fn clicking_an_unfocused_field_routes_typing_to_that_field() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Subnets;
    app.subnets.modal = Some(subnet_modal::SubnetModal::open_add(
        vec!["default".into()],
        0,
    ));
    let mut terminal = Terminal::new(TestBackend::new(100, 35)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Name");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    handle_key(
        &mut app,
        KeyCode::Char('N').into(),
        &poller,
        &temp.path().join("config.toml"),
    )
    .await;
    let subnet_modal::Stage::EditingForm(form) = &app.subnets.modal.as_ref().unwrap().stage else {
        panic!("form remains open")
    };
    assert_eq!(form.display_name, "N");
    assert_eq!(form.id, "");
}

#[tokio::test]
async fn clicking_a_device_picker_option_uses_the_captured_option() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Devices;
    let mut form = DeviceFormState::new_add();
    form.picker = Some(app::FieldPicker {
        target: app::DeviceFormField::Profile,
        options: vec!["first".into(), "second".into()],
        cursor: 0,
        multi: false,
        selected: vec![],
    });
    app.devices.modal = Some(DeviceModal::Form(form));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "second");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    let DeviceModal::Form(form) = app.devices.modal.as_ref().unwrap() else {
        panic!("form remains open")
    };
    assert!(
        form.picker.is_some(),
        "option click must retain the draft selector"
    );
    assert_ne!(form.profile, "second");
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Apply");
    handle_mouse(&mut app, click, &poller, &temp.path().join("config.toml")).await;
    let DeviceModal::Form(form) = app.devices.modal.as_ref().unwrap() else {
        panic!("Apply must retain the parent form")
    };
    assert!(!form.submitting);
    assert!(form.picker.is_none());
    assert_eq!(form.profile, "second");
}

#[tokio::test]
async fn period_option_click_changes_the_draft_until_apply() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let path = temp.path().join("config.toml");
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    filter_chips::activate(&mut app, 2);
    let previous = app.query_log.since;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Last 3 hours");
    handle_mouse(&mut app, click, &poller, &path).await;
    assert_eq!(app.query_log.since, previous);
    assert_eq!(app.query_log.period_draft, app::SincePreset::Last3Hours);
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let click = click_text(terminal.backend().buffer(), "Apply");
    handle_mouse(&mut app, click, &poller, &path).await;
    assert_eq!(app.query_log.since, app::SincePreset::Last3Hours);
    assert!(!app.query_log.period_menu);
}

#[test]
fn blue_filter_heading_and_controls_precede_the_query_table() {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let buffer = terminal.backend().buffer();
    let title = click_text(buffer, "QUERY FILTERS");
    let table = click_text(buffer, "QUERY LOG");
    let filter = click_text(buffer, "Domain");
    assert!(filter.column >= title.column);
    assert!(title.row < filter.row && filter.row < table.row);
}

#[tokio::test]
async fn policy_navigation_preserves_the_hidden_draft_and_recovery_dialog() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Devices;
    let mut form = app::DeviceFormState::new_add();
    form.name = "Unsaved name".into();
    let initial_focus = form.focused;
    app.devices.modal = Some(app::DeviceModal::Form(form));
    app.operator_policy = Some(operator_policy::PolicyDialog {
        id: 42,
        origin: operator_policy::PolicyOrigin::Recovery,
        workflow: None,
        adapter: None,
        preparing: false,
        preparation_error: Some("Daemon unavailable; recovery retained".into()),
        prefix_outcome: None,
        discard_operations: None,
    });
    let expected_leaf = next_visible_leaf(&app);
    assert!(
        !handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &poller,
            &temp.path().join("config.toml"),
        )
        .await
    );
    assert_eq!(app.active_leaf, expected_leaf);
    assert_eq!(app.operator_policy.as_ref().unwrap().id, 42);
    let Some(app::DeviceModal::Form(form)) = &app.devices.modal else {
        panic!("navigation must retain the hidden draft");
    };
    assert_eq!(form.focused, initial_focus);
    assert_eq!(form.name, "Unsaved name");
    assert!(
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            &poller,
            &temp.path().join("config.toml"),
        )
        .await
    );
}

#[tokio::test]
async fn help_paging_keeps_the_underlying_table_selection() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    app.profiles.table_state.select(Some(2));
    app.show_help = true;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    for key in [KeyCode::End, KeyCode::PageUp, KeyCode::Home] {
        assert!(
            !handle_key(
                &mut app,
                KeyEvent::new(key, KeyModifiers::NONE),
                &poller,
                &temp.path().join("config.toml"),
            )
            .await
        );
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        assert!(app.show_help);
        assert_eq!(app.profiles.table_state.selected(), Some(2));
        assert!(app.help_scroll < usize::MAX);
        if key == KeyCode::End {
            assert!(app.help_scroll > 0);
        }
    }
    assert_eq!(app.help_scroll, 0);
}

#[test]
fn settings_actions_keep_mouse_hits_on_their_rendered_rows() {
    for (width, height) in [(80, 24), (125, 36)] {
        let mut app = App::new();
        app.active_leaf = Leaf::Settings;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        for (index, label) in ["Tracking", "Backup", "Restore"].into_iter().enumerate() {
            let mut event = click_text(terminal.backend().buffer(), label);
            event.column = 2;
            event.row = (0..height)
                .find(|y| {
                    (0..(width.min(42)))
                        .map(|x| terminal.backend().buffer()[(x, *y)].symbol())
                        .collect::<String>()
                        .trim()
                        == label
                })
                .expect("setting row is visible");
            assert_eq!(
                mouse::action(&app, event),
                Some(mouse::MouseAction::Row(Leaf::Settings, index)),
                "{label} at {width}x{height}"
            );
        }
    }
}

#[tokio::test]
async fn tracking_mouse_controls_capture_input_and_discard_the_draft() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Settings;
    app.settings.tracking_panel = Some(app::TrackingPanelState::from_config(&Default::default()));
    let mut terminal = Terminal::new(TestBackend::new(164, 46)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let hidden = click_text(terminal.backend().buffer(), "Backup");
    assert_eq!(
        mouse::action(&app, hidden),
        None,
        "underlying settings rows cannot receive clicks"
    );
    let enabled = click_text(terminal.backend().buffer(), "Enabled");
    handle_mouse(&mut app, enabled, &poller, &path).await;
    assert!(
        !app.settings
            .tracking_panel
            .as_ref()
            .unwrap()
            .query_log_enabled
    );
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let mode = click_text(terminal.backend().buffer(), "Mode");
    handle_mouse(&mut app, mode, &poller, &path).await;
    assert!(matches!(
        app.settings.tracking_panel.as_ref().unwrap().log_mode,
        crate::config::settings::LogMode::BlockedOnly
    ));
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let retention = click_text(terminal.backend().buffer(), "Keep Days");
    handle_mouse(&mut app, retention, &poller, &path).await;
    assert_eq!(
        app.settings.tracking_panel.as_ref().unwrap().focus,
        app::TrackingFocus::Retention
    );
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let discard = click_text(terminal.backend().buffer(), "Discard");
    handle_mouse(&mut app, discard, &poller, &path).await;
    assert!(app.settings.tracking_panel.is_none());
    assert!(!path.exists());
}

#[tokio::test]
async fn restore_row_click_selects_and_restore_button_opens_confirmation() {
    use backup_restore_modal::{RestoreModal, RestorePoint, RestoreStage};
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let path = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Settings;
    app.settings.restore_modal = Some(RestoreModal {
        stage: RestoreStage::Picking {
            entries: ["first", "second"]
                .into_iter()
                .map(|name| RestorePoint {
                    path: temp.path().join(name),
                    date: name.into(),
                    age: "recent".into(),
                    size: "1 KiB".into(),
                })
                .collect(),
            selected: 0,
        },
    });
    let mut terminal = Terminal::new(TestBackend::new(125, 36)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let row = click_text(terminal.backend().buffer(), "second");
    handle_mouse(&mut app, row, &poller, &path).await;
    assert!(matches!(
        app.settings.restore_modal.as_ref().unwrap().stage,
        RestoreStage::Picking { selected: 1, .. }
    ));
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let restore = click_text(terminal.backend().buffer(), "Choose");
    handle_mouse(&mut app, restore, &poller, &path).await;
    assert!(
        matches!(&app.settings.restore_modal.as_ref().unwrap().stage, RestoreStage::Confirming { point } if point.date == "second")
    );
}
