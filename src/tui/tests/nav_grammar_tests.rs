use super::*;
use crate::filter::rules::RuleAction;
use crate::tui::app::{
    App, DeviceFormState, DeviceModal, EditField, EditModalMode, RuleEditFocus, RuleEditModal,
    RuleEditMode, RuleScope, ScopeChoice, TrackingFocus, TrackingPanelState,
};

fn k(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A poller pointed at a socket that cannot exist. Every key this
/// module sends is a navigation key, so no handler reaches IPC — a
/// dead path here is the assertion that they don't.
fn poller() -> IpcPoller {
    IpcPoller::new(Path::new("/nonexistent/purge-warden-nav-grammar.sock"))
}

fn cfg() -> &'static Path {
    Path::new("/nonexistent/purge-warden-nav-grammar.toml")
}

// ── focus movement: Down advances, Up returns ────────────────────

#[tokio::test]
async fn subnets_form_moves_focus_on_up_down() {
    use crate::tui::subnet_modal::Stage;
    let mut app = App::new();
    app.subnets.modal = Some(build_subnet_add_modal(&app));

    let focused = |a: &App| match &a.subnets.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => f.focused,
        other => panic!("expected EditingForm, got {other:?}"),
    };
    let start = focused(&app);

    handle_subnet_modal_key(&mut app, k(KeyCode::Down), &poller(), cfg()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Subnets form"
    );

    handle_subnet_modal_key(&mut app, k(KeyCode::Up), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

#[tokio::test]
async fn profiles_form_moves_focus_on_up_down() {
    use crate::tui::profile_modal::Stage;
    let mut app = App::new();
    app.profiles.modal = Some(profile_modal::ProfileModal::open_add());

    let focused = |a: &App| match &a.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => f.focused,
        other => panic!("expected EditingForm, got {other:?}"),
    };
    let start = focused(&app);

    handle_profile_modal_key(&mut app, k(KeyCode::Down), &poller(), cfg()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Profiles form"
    );

    handle_profile_modal_key(&mut app, k(KeyCode::Up), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

#[tokio::test]
async fn local_dns_form_moves_focus_on_up_down() {
    use crate::tui::local_dns_modal::Stage;
    let mut app = App::new();
    app.local_dns.modal = Some(build_local_dns_add_modal(&app).0);

    let focused = |a: &App| match &a.local_dns.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => f.focused,
        other => panic!("expected EditingForm, got {other:?}"),
    };
    let start = focused(&app);

    handle_local_dns_modal_key(&mut app, k(KeyCode::Down), &poller(), cfg()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Local DNS form"
    );

    handle_local_dns_modal_key(&mut app, k(KeyCode::Up), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

#[tokio::test]
async fn devices_form_moves_focus_on_up_down() {
    let mut app = App::new();
    app.devices.modal = Some(DeviceModal::Form(DeviceFormState::new_add()));

    let focused = |a: &App| match a.devices.modal.as_ref().unwrap() {
        DeviceModal::Form(f) => f.focused,
        other => panic!("expected Form, got {other:?}"),
    };
    let start = focused(&app);

    handle_modal_key(&mut app, k(KeyCode::Down), &poller()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Devices form"
    );

    handle_modal_key(&mut app, k(KeyCode::Up), &poller()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

/// §4.65 UX3 (e), extended scope: the Devices form's footer has
/// always advertised "[Ctrl+s] save" (`ui.rs`'s `modal_form_hints`),
/// but before this fix `handle_modal_key`'s `DeviceModal::Form` arm
/// had no `Ctrl+s`/`Ctrl+S` guard at all — `KeyCode::Char(c)` caught
/// the chord and typed a literal `s` into whichever field held
/// focus. Measured on the CT via pty-smoke: with the Name field
/// focused, `Ctrl+S` turned `edo-laptopX` into `edo-laptopXs`.
///
/// This drives the real dispatcher with a genuine `Ctrl+s`/`Ctrl+S`
/// `KeyEvent` (not `handle_form_picker_key` directly, which would
/// only prove the guard works once reached, not that the chord is
/// routed to it — the same "mechanism, not property" gap the ui.rs
/// footer-text test already had: it asserts the label is shown, not
/// that the chord does anything). Two properties: the focused
/// field's buffer must NOT grow, and `submit_form`/`parse_form` must
/// actually have run (proven by the validation error only that path
/// produces — ip/profile are left blank on purpose so submission
/// fails synchronously, no IPC needed).
#[tokio::test]
async fn devices_form_ctrl_s_saves_instead_of_typing_into_the_focused_field() {
    for ctrl_s in [
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Char('S'), KeyModifiers::CONTROL),
    ] {
        let mut form = DeviceFormState::new_add();
        form.focused = DeviceFormFocus::Field(DeviceFormField::Name);
        form.name = "edo-laptopX".into();
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(form));

        handle_modal_key(&mut app, ctrl_s, &poller()).await;

        match app.devices.modal.as_ref().expect("stays open on error") {
            DeviceModal::Form(f) => {
                assert_eq!(
                    f.name, "edo-laptopX",
                    "{ctrl_s:?} must not type into the focused field"
                );
                assert!(
                    f.error_message.is_some(),
                    "{ctrl_s:?} must reach submit_form (validation error expected \
                         from the blank ip/profile); got no error at all, meaning the \
                         chord was silently dropped or never routed"
                );
            }
            other => panic!("expected Form, got {other:?}"),
        }
    }
}

/// §4.64 G4: **Space must reach the picker**, not merely be handled
/// once it gets there. Every other multi-select test calls
/// `handle_form_picker_key` directly, which proves the handler
/// toggles and says nothing about routing — and Space is the one key
/// this dispatcher did not carry before this sprint. `Char(c)` has an
/// arm of its own further down that appends to the focused buffer, so
/// if the `picker.is_some()` branch ever moves below it, Space stops
/// toggling and starts typing a space into the group list.
///
/// Same distinction the L3 regression guard records: mechanism (the
/// handler toggles) versus property (the operator can toggle).
#[tokio::test]
async fn g4_space_reaches_the_group_picker_through_the_real_key_router() {
    let mut app = App::new();
    let form = DeviceFormState::new_edit(
        "edo-laptop".into(),
        "192.168.1.42".into(),
        String::new(),
        String::new(),
        "default".into(),
        "phones".into(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    )
    .with_options(vec!["default".into()], vec!["phones".into(), "kids".into()]);
    let mut form = form;
    form.focused = DeviceFormFocus::Field(DeviceFormField::Group);
    app.devices.modal = Some(DeviceModal::Form(form));

    let groups_of = |a: &App| match a.devices.modal.as_ref().unwrap() {
        DeviceModal::Form(f) => f.groups.clone(),
        other => panic!("expected Form, got {other:?}"),
    };

    // Enter opens the picker, j moves to "kids", Space toggles it on,
    // Enter commits. Every keystroke goes through the event loop's
    // own entry point.
    handle_modal_key(&mut app, k(KeyCode::Enter), &poller()).await;
    handle_modal_key(&mut app, k(KeyCode::Down), &poller()).await;
    handle_modal_key(&mut app, k(KeyCode::Char(' ')), &poller()).await;
    handle_modal_key(&mut app, k(KeyCode::Enter), &poller()).await;

    assert_eq!(
        groups_of(&app),
        "phones,kids",
        "Space must toggle in the picker, not type into the field"
    );
}

#[tokio::test]
async fn tracking_panel_moves_focus_on_up_down() {
    let mut app = App::new();
    app.settings.tracking_panel = Some(TrackingPanelState {
        query_log_enabled: true,
        log_mode: crate::config::settings::LogMode::All,
        retention_days: 7,
        retention_input: "7".into(),
        focus: TrackingFocus::Enabled,
        submit_message: None,
    });

    let focused = |a: &App| a.settings.tracking_panel.as_ref().unwrap().focus;
    let start = focused(&app);

    handle_tracking_panel_key(&mut app, k(KeyCode::Down), &poller()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Tracking form"
    );

    handle_tracking_panel_key(&mut app, k(KeyCode::Up), &poller()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

/// Build a Rules edit modal without touching disk. Two scope choices
/// so the Left/Right cycle below has somewhere to go.
fn rule_edit_modal() -> RuleEditModal {
    RuleEditModal {
        rule_id: "r-1".into(),
        raw_rule: "||ads.example.com^".into(),
        original_action: RuleAction::Block,
        original_scope: RuleScope::Default,
        original_references: Vec::new(),
        current_action: RuleAction::Block,
        current_scope_choice: ScopeChoice::Default,
        scope_options: vec![ScopeChoice::Default, ScopeChoice::Profile("kids".into())],
        focus: RuleEditFocus::Action,
        mode: RuleEditMode::Edit,
        error_message: None,
        status_message: None,
        submitting: false,
    }
}

#[tokio::test]
async fn rules_edit_form_moves_focus_on_up_down() {
    let mut app = App::new();
    app.rules.edit_modal = Some(rule_edit_modal());

    let focused = |a: &App| a.rules.edit_modal.as_ref().unwrap().focus;
    let start = focused(&app);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Down), &poller(), cfg()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Rules edit form"
    );

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Up), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

/// §4.65 UX3 (§3.6): D7′ said Save is deliberately not a Tab target
/// — operators kept tripping over it anyway. This is the extension,
/// not a reversal: Tab now cycles all the way through Save.
#[tokio::test]
async fn rules_edit_form_tab_cycle_reaches_save() {
    let mut app = App::new();
    app.rules.edit_modal = Some(rule_edit_modal());
    let focused = |a: &App| a.rules.edit_modal.as_ref().unwrap().focus;
    assert_eq!(focused(&app), RuleEditFocus::Action);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_eq!(focused(&app), RuleEditFocus::Scope);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_eq!(focused(&app), RuleEditFocus::DeleteButton);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_eq!(
        focused(&app),
        RuleEditFocus::SaveButton,
        "Tab must reach Save — the operator's actual complaint"
    );

    // Wraps back to the top, same as every other focus ring.
    handle_rules_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_eq!(focused(&app), RuleEditFocus::Action);
}

/// Enter on the focused Save button must reach the same commit path
/// as `Ctrl+S` — D7′ extended, not replaced. `poller()`/`cfg()` point
/// at sockets/paths that cannot exist (see the module doc above), so
/// both routes deterministically land on `submit_rule_edit_modal`'s
/// `Err` arm — the "save failed" message is the proof the handler
/// was actually reached, not that it succeeded. Verified by mutation:
/// reverting the `KeyCode::Enter if focus == SaveButton` arm to the
/// old catch-all makes this test fail (no error_message appears,
/// because Enter on Save becomes a no-op again).
#[tokio::test]
async fn rules_edit_form_save_button_enter_takes_the_same_path_as_ctrl_s() {
    let mut app = App::new();
    let mut modal = rule_edit_modal();
    modal.focus = RuleEditFocus::SaveButton;
    app.rules.edit_modal = Some(modal);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Enter), &poller(), cfg()).await;

    let after_enter = app
        .rules
        .edit_modal
        .clone()
        .expect("modal stays open on error");
    assert!(
        after_enter
            .error_message
            .as_deref()
            .unwrap_or_default()
            .starts_with("save failed"),
        "Enter on Save must reach submit_rule_edit_modal, same as Ctrl+s; got: {:?}",
        after_enter.error_message
    );
}

/// D7′ itself must survive the extension: `Ctrl+S` still commits
/// from every focus, including from the newly Tab-reachable Save
/// button and from a field that isn't Save at all.
#[tokio::test]
async fn rules_edit_form_ctrl_s_still_commits_from_anywhere() {
    for focus in [
        RuleEditFocus::Action,
        RuleEditFocus::Scope,
        RuleEditFocus::DeleteButton,
        RuleEditFocus::SaveButton,
    ] {
        let mut app = App::new();
        let mut modal = rule_edit_modal();
        modal.focus = focus;
        app.rules.edit_modal = Some(modal);

        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        handle_rules_edit_modal_key(&mut app, ctrl_s, &poller(), cfg()).await;

        let after = app
            .rules
            .edit_modal
            .clone()
            .expect("modal stays open on error");
        assert!(
            after
                .error_message
                .as_deref()
                .unwrap_or_default()
                .starts_with("save failed"),
            "Ctrl+s must still commit from {focus:?}; got: {:?}",
            after.error_message
        );
    }
}

#[tokio::test]
async fn lists_edit_form_moves_focus_on_up_down() {
    let mut app = App::new();
    app.lists.edit_modal = Some(tabs::lists::build_add_modal());

    let focused = |a: &App| a.lists.edit_modal.as_ref().unwrap().focus;
    let start = focused(&app);

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Down), &poller(), cfg()).await;
    let after_down = focused(&app);
    assert_ne!(
        after_down, start,
        "Down must move focus in the Lists edit form"
    );

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Up), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "Up must move focus back");
}

// `plp-s5d` removed
// `lists_tags_suggestions_are_driven_by_left_right_and_not_by_up_down`.
// It pinned the §4.65 UX2 key contract on the Lists edit modal's chip
// picker — Left/Right walk the suggestions, Down leaves the field and
// clears the picker state — driving the production router rather than
// the cycle helper, precisely so a green test on the helper could not
// hide a dead surface. Both the picker and the router branches are
// gone, so there is nothing left to drive.

// `plp-s5d` removed the three `tags_check_*` tests and their two
// helpers with the Tags tab's Check modal. They pinned that Enter did
// NOT close the modal (the report is what the operator came for), that
// Esc left no stale report behind, and that editing the slug dropped
// the previous verdict rather than showing an answer to a question the
// operator had changed. The modal is gone; there is no surface left to
// hold a stale verdict on.

#[tokio::test]
async fn rules_edit_form_keeps_tab_and_backtab() {
    let mut app = App::new();
    app.rules.edit_modal = Some(rule_edit_modal());
    let focused = |a: &App| a.rules.edit_modal.as_ref().unwrap().focus;
    let start = focused(&app);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_ne!(focused(&app), start, "Tab must still move focus forward");

    handle_rules_edit_modal_key(&mut app, k(KeyCode::BackTab), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "BackTab must still move focus back");
}

#[tokio::test]
async fn lists_edit_form_keeps_tab_and_backtab() {
    let mut app = App::new();
    app.lists.edit_modal = Some(tabs::lists::build_add_modal());
    let focused = |a: &App| a.lists.edit_modal.as_ref().unwrap().focus;
    let start = focused(&app);

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Tab), &poller(), cfg()).await;
    assert_ne!(focused(&app), start, "Tab must still move focus forward");

    handle_lists_edit_modal_key(&mut app, k(KeyCode::BackTab), &poller(), cfg()).await;
    assert_eq!(focused(&app), start, "BackTab must still move focus back");
}

// ── value cycling relocated onto Left/Right ──────────────────────

#[tokio::test]
async fn rules_edit_form_cycles_action_on_left_right() {
    let mut app = App::new();
    app.rules.edit_modal = Some(rule_edit_modal()); // focus = Action

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Right), &poller(), cfg()).await;
    assert!(
        matches!(
            app.rules.edit_modal.as_ref().unwrap().current_action,
            RuleAction::Allow
        ),
        "Right on Action must flip Block -> Allow"
    );

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Left), &poller(), cfg()).await;
    assert!(
        matches!(
            app.rules.edit_modal.as_ref().unwrap().current_action,
            RuleAction::Block
        ),
        "Left on Action must flip back"
    );
}

#[tokio::test]
async fn rules_edit_form_cycles_scope_on_left_right() {
    let mut app = App::new();
    let mut modal = rule_edit_modal();
    modal.focus = RuleEditFocus::Scope;
    app.rules.edit_modal = Some(modal);

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Right), &poller(), cfg()).await;
    let after_right = app
        .rules
        .edit_modal
        .as_ref()
        .unwrap()
        .current_scope_choice
        .clone();
    assert_ne!(
        after_right,
        ScopeChoice::Default,
        "Right on Scope must advance the picker"
    );

    handle_rules_edit_modal_key(&mut app, k(KeyCode::Left), &poller(), cfg()).await;
    assert_eq!(
        app.rules.edit_modal.as_ref().unwrap().current_scope_choice,
        ScopeChoice::Default,
        "Left on Scope must walk back"
    );
}

#[tokio::test]
async fn lists_edit_form_cycles_nature_on_left_right() {
    use crate::config::schema::BlocklistBase;
    let mut app = App::new();
    let mut modal = tabs::lists::build_add_modal();
    modal.focus = EditField::Nature;
    modal.nature = BlocklistBase::Deny;
    app.lists.edit_modal = Some(modal);

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Right), &poller(), cfg()).await;
    assert!(
        matches!(
            app.lists.edit_modal.as_ref().unwrap().nature,
            BlocklistBase::Allow
        ),
        "Right on Nature must toggle Deny -> Allow"
    );

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Left), &poller(), cfg()).await;
    assert!(
        matches!(
            app.lists.edit_modal.as_ref().unwrap().nature,
            BlocklistBase::Deny
        ),
        "Left on Nature must toggle back"
    );
}

#[tokio::test]
async fn lists_edit_form_cycles_format_on_left_right() {
    use crate::config::schema::BlocklistFormat;
    let mut app = App::new();
    let mut modal = tabs::lists::build_add_modal();
    modal.mode = EditModalMode::Add;
    modal.advanced_expanded = true;
    modal.focus = EditField::Format;
    modal.format = BlocklistFormat::Domains;
    app.lists.edit_modal = Some(modal);

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Right), &poller(), cfg()).await;
    assert!(
        matches!(
            app.lists.edit_modal.as_ref().unwrap().format,
            BlocklistFormat::Adguard
        ),
        "Right on Format must advance Domains -> Adguard"
    );

    handle_lists_edit_modal_key(&mut app, k(KeyCode::Left), &poller(), cfg()).await;
    assert!(
        matches!(
            app.lists.edit_modal.as_ref().unwrap().format,
            BlocklistFormat::Domains
        ),
        "Left on Format must walk back"
    );
}

/// The Lists modal draws a real terminal cursor in its text inputs,
/// but `place_cursor` is always fed `VALUE_COL + value_len` — the
/// cursor is pinned to end-of-buffer and there is no intra-field
/// position to move. So Left/Right on a text field is a deliberate
/// no-op. Pin that: a future "arrow keys edit within the buffer"
/// change must land the cursor state too, not silently truncate.
#[tokio::test]
async fn lists_edit_form_left_right_do_not_disturb_a_text_field() {
    let mut app = App::new();
    let mut modal = tabs::lists::build_add_modal();
    modal.focus = EditField::DisplayName;
    modal.display_name = "Privacy: Ads".into();
    app.lists.edit_modal = Some(modal);

    for code in [KeyCode::Left, KeyCode::Right] {
        handle_lists_edit_modal_key(&mut app, k(code), &poller(), cfg()).await;
    }

    let m = app.lists.edit_modal.as_ref().unwrap();
    assert_eq!(
        m.display_name, "Privacy: Ads",
        "Left/Right must not mutate a text buffer"
    );
    assert_eq!(
        m.focus,
        EditField::DisplayName,
        "Left/Right must not move focus off a text field"
    );
}
