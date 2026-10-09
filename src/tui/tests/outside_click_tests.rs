use super::tui_port_interaction_tests::click_text;
use super::*;
use crate::cli::commands::local_dns::LocalRecordScope;
use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::{backend::TestBackend, Terminal};

fn corner() -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    }
}

fn draw(app: &mut App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::render(frame, app)).unwrap();
    terminal
}

#[tokio::test]
async fn outside_click_discards_an_open_filter_menu() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.filter_domain = Some("before.example".into());
    app.input_mode = InputMode::FilterDomain("after.example".into());
    app.force_poll = false;
    let terminal = draw(&mut app, 80, 24);
    let inside = click_text(
        terminal.backend().buffer(),
        "Case-insensitive domain fragment",
    );
    handle_mouse(&mut app, inside, &poller, &config).await;
    assert!(matches!(app.input_mode, InputMode::FilterDomain(_)));
    handle_mouse(&mut app, corner(), &poller, &config).await;
    assert!(matches!(app.input_mode, InputMode::Normal));
    assert_eq!(
        app.query_log.filter_domain.as_deref(),
        Some("before.example")
    );
    assert!(!app.force_poll);
}

#[tokio::test]
async fn outside_click_closes_a_form_picker_but_keeps_the_form() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Devices;
    let mut form = DeviceFormState::new_add();
    form.name = "kept".into();
    form.focused = app::DeviceFormFocus::Field(app::DeviceFormField::Profile);
    form.picker = Some(app::FieldPicker {
        target: app::DeviceFormField::Profile,
        options: vec!["first".into(), "second".into()],
        cursor: 1,
        multi: false,
        selected: vec![],
    });
    app.devices.modal = Some(DeviceModal::Form(form));
    for _ in 0..2 {
        let terminal = draw(&mut app, 120, 40);
        let click = click_text(terminal.backend().buffer(), "IDENTITY & NETWORK");
        handle_mouse(&mut app, click, &poller, &config).await;
        let Some(DeviceModal::Form(form)) = app.devices.modal.as_ref() else {
            panic!("the form is hard and stays open")
        };
        assert!(form.picker.is_none());
        assert_eq!(form.name, "kept");
        assert_ne!(form.profile, "second");
    }
}

#[tokio::test]
async fn outside_click_closes_help_but_an_inside_click_does_not() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::new();
    app.show_help = true;
    let terminal = draw(&mut app, 100, 30);
    let title = click_text(terminal.backend().buffer(), "HELP");
    handle_mouse(&mut app, title, &poller, &config).await;
    assert!(app.show_help);
    draw(&mut app, 100, 30);
    handle_mouse(&mut app, corner(), &poller, &config).await;
    assert!(!app.show_help);
}

#[tokio::test]
async fn outside_click_on_a_local_dns_confirm_follows_its_tier() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    for typed in [false, true] {
        let mut app = App::known_standalone_for_test();
        app.active_leaf = Leaf::LocalDns;
        let record = LocalDnsRecord {
            domain: "nas.home".into(),
            record_type: LocalDnsRecordType::A,
            value: "192.0.2.10".into(),
            match_subdomains: typed,
            ttl_secs: None,
        };
        app.local_dns.modal = Some(local_dns_modal::LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &record,
        ));
        draw(&mut app, 100, 30);
        handle_mouse(&mut app, corner(), &poller, &config).await;
        match app.local_dns.modal.as_ref().map(|modal| &modal.stage) {
            None => assert!(!typed, "the typed tier holds input"),
            Some(local_dns_modal::Stage::ConfirmingRemove(_)) => {
                assert!(typed, "the single-keypress tier is soft")
            }
            Some(other) => panic!("unexpected stage {other:?}"),
        }
    }
}

#[tokio::test]
async fn outside_click_leaves_a_hard_form_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Subnets;
    let mut modal = subnet_modal::SubnetModal::open_add(vec!["default".into()], 0);
    let subnet_modal::Stage::EditingForm(form) = &mut modal.stage else {
        panic!("add form");
    };
    form.display_name = "draft".into();
    app.subnets.modal = Some(modal);
    draw(&mut app, 100, 35);
    handle_mouse(&mut app, corner(), &poller, &config).await;
    let Some(subnet_modal::Stage::EditingForm(form)) =
        app.subnets.modal.as_ref().map(|modal| &modal.stage)
    else {
        panic!("the form stays open");
    };
    assert_eq!(form.display_name, "draft");
}

#[tokio::test]
async fn outside_click_on_help_over_a_form_leaves_both_open() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Devices;
    let mut form = DeviceFormState::new_add();
    form.name = "kept".into();
    form.error_message = Some("save failed".into());
    app.devices.modal = Some(DeviceModal::Form(form));
    app.show_help = true;
    draw(&mut app, 120, 40);
    handle_mouse(&mut app, corner(), &poller, &config).await;
    assert!(app.show_help);
    let Some(DeviceModal::Form(form)) = app.devices.modal.as_ref() else {
        panic!("help's Esc reached the form under it")
    };
    assert_eq!(form.name, "kept");
}

#[tokio::test]
async fn outside_click_while_an_action_is_pending_keeps_its_card() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Settings;
    assert!(actions::reserve_external(
        &mut app,
        actions::Surface::Backup,
        "Creating backup"
    ));
    app.settings.backup_modal = Some(backup_restore_modal::BackupModal::Running {
        dir: temp.path().into(),
    });
    draw(&mut app, 100, 30);
    handle_mouse(&mut app, corner(), &poller, &config).await;
    assert!(app.settings.backup_modal.is_some());
    assert!(!app.pending_action.as_ref().unwrap().detached);
}

#[tokio::test]
async fn a_subscription_detail_that_draws_nothing_leaves_the_tab_clickable() {
    let temp = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&temp.path().join("absent.sock"));
    let config = temp.path().join("config.toml");
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Lists;
    app.lists.detail_id = Some("no-such-row".into());
    let terminal = draw(&mut app, 120, 40);
    assert!(!mouse::overlay_open(&app));
    let slash = KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE);
    handle_key(&mut app, slash, &poller, &config).await;
    assert!(matches!(app.input_mode, InputMode::FilterLists(_)));
    assert!(app.lists.detail_id.is_none());
    app.input_mode = InputMode::Normal;
    let section = click_text(terminal.backend().buffer(), "CONFIGURATION");
    handle_mouse(&mut app, section, &poller, &config).await;
    assert_eq!(app.active_leaf, Leaf::Labels);
}
