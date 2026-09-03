use super::*;

#[test]
fn paste_appends_to_filter_buffer_stripping_control_chars() {
    let mut app = App::new();
    app.input_mode = InputMode::FilterDomain(String::new());
    // Embedded newline/tab must be stripped so the paste can't submit early.
    handle_paste(&mut app, "ads.\nexample\t.com".to_string());
    match &app.input_mode {
        InputMode::FilterDomain(buf) => assert_eq!(buf, "ads.example.com"),
        other => panic!("expected FilterDomain, got {other:?}"),
    }
}

#[test]
fn paste_is_capped_at_max() {
    let mut app = App::new();
    app.input_mode = InputMode::FilterClient(String::new());
    handle_paste(&mut app, "a".repeat(MAX_PASTE + 100));
    match &app.input_mode {
        InputMode::FilterClient(buf) => assert_eq!(buf.chars().count(), MAX_PASTE),
        other => panic!("expected FilterClient, got {other:?}"),
    }
}

#[test]
fn paste_is_inert_in_plain_navigation() {
    // No modal, no filter — a pasted `q`/`1` must reach no actionable
    // buffer (the danger the finding calls out).
    let mut app = App::new();
    assert!(focused_text_buffer(&mut app).is_none());
}

#[test]
fn paste_appends_to_resolver_modal_input() {
    let mut app = App::new();
    app.resolver_modal = Some(resolver_modal::ResolverModal::open_blank());
    handle_paste(&mut app, "10.0.0.5".to_string());
    assert_eq!(
        app.resolver_modal.as_ref().unwrap().input,
        "10.0.0.5".to_string()
    );
}

/// rev-2607 (#12) — repro from the audit: resolve an IP, then paste
/// another. Before the fix, `input` picked up the pasted text
/// (concatenated onto the prior value, same as any text-field
/// paste) but `last_result` kept describing the FIRST query —
/// paste is delivered through `handle_paste` / `focused_text_buffer`,
/// which never runs through `handle_resolver_modal_key` (the only
/// place that used to touch `last_result`/`error`), so the screen
/// kept showing a result for an IP no longer fully in the buffer.
#[test]
fn paste_after_resolve_clears_stale_result() {
    let mut modal = resolver_modal::ResolverModal::open_with("1.2.3.4".into(), "manual");
    modal.last_result = Some(vec!["Source IP:       1.2.3.4".into()]);
    let mut app = App::new();
    app.resolver_modal = Some(modal);

    handle_paste(&mut app, "5.6.7.8".to_string());

    let modal = app.resolver_modal.as_ref().unwrap();
    assert_eq!(
        modal.input, "1.2.3.45.6.7.8",
        "paste still appends verbatim, same as every other text field"
    );
    assert!(
        modal.last_result.is_none(),
        "paste must drop the previous resolve's result — it no longer \
             describes the query now in the buffer"
    );
}

/// Same repro, but starting from an `error` (an invalid-IP resolve)
/// instead of a successful `last_result` — both stale-state fields
/// must be dropped by the same paste.
#[test]
fn paste_after_failed_resolve_clears_stale_error() {
    let mut modal = resolver_modal::ResolverModal::open_with("not-an-ip".into(), "manual");
    modal.error = Some("\"not-an-ip\" is not a valid IP address".into());
    let mut app = App::new();
    app.resolver_modal = Some(modal);

    handle_paste(&mut app, "9.9.9.9".to_string());

    let modal = app.resolver_modal.as_ref().unwrap();
    assert!(
        modal.error.is_none(),
        "paste must drop the previous resolve's error along with last_result"
    );
}

/// Fixing only the paste path would have left the COMMONER route still
/// lying: an operator normally types an IP, they rarely paste one. Any
/// mutation of `input` — typed char or backspace — invalidates the
/// rendered result for exactly the same reason a paste does.
#[test]
fn typing_and_backspace_after_resolve_clear_stale_result() {
    let mut modal = resolver_modal::ResolverModal::open_with("1.2.3.4".into(), "manual");
    modal.last_result = Some(vec!["Source IP:       1.2.3.4".into()]);
    let mut app = App::new();
    app.resolver_modal = Some(modal);

    handle_resolver_modal_key(&mut app, KeyEvent::from(KeyCode::Char('9')));

    let modal = app.resolver_modal.as_ref().unwrap();
    assert_eq!(modal.input, "1.2.3.49", "the typed char still lands");
    assert!(
        modal.last_result.is_none(),
        "typing must drop the previous resolve's result — it no longer \
             describes the query now in the buffer"
    );

    // Same again for backspace, from a fresh resolved state.
    let mut modal = resolver_modal::ResolverModal::open_with("1.2.3.4".into(), "manual");
    modal.last_result = Some(vec!["Source IP:       1.2.3.4".into()]);
    modal.error = Some("stale".into());
    let mut app = App::new();
    app.resolver_modal = Some(modal);

    handle_resolver_modal_key(&mut app, KeyEvent::from(KeyCode::Backspace));

    let modal = app.resolver_modal.as_ref().unwrap();
    assert_eq!(modal.input, "1.2.3.", "the backspace still lands");
    assert!(
        modal.last_result.is_none() && modal.error.is_none(),
        "backspace must drop both the stale result and the stale error"
    );
}

#[test]
fn paste_is_inert_in_subnet_remove_confirm() {
    use crate::config::schema::subnet::Subnet;
    use crate::config::schema::Id;

    let subnet = Subnet {
        id: Id::new("lan").unwrap(),
        display_name: "LAN".into(),
        cidrs: vec!["10.0.0.0/24".into()],
        profile: Id::new("default").unwrap(),
        priority: 0,
    };
    let mut app = App::new();
    app.active_leaf = Leaf::Subnets;
    app.subnets.modal = Some(subnet_modal::SubnetModal::open_remove(&subnet));

    // The single-keypress remove confirm has no text buffer: a pasted `y`
    // must NOT be captured anywhere (and so cannot confirm the destructive
    // remove). The modal stays open in its confirm stage.
    assert!(focused_text_buffer(&mut app).is_none());
    handle_paste(&mut app, "yyyy".to_string());
    assert!(app.subnets.modal.is_some());
}

// ── modals-01: the three arms `focused_text_buffer` was missing ────────

#[test]
fn paste_reaches_rule_add_modal_domain_field() {
    let mut app = App::new();
    app.active_leaf = Leaf::Rules;
    app.rules.add_modal = Some(rule_add_modal::RuleAddModal::open(&app));
    // `RuleAddModal::open` defaults focus to Domain.
    handle_paste(&mut app, "ads.example.com".to_string());
    assert_eq!(
        app.rules.add_modal.as_ref().unwrap().domain,
        "ads.example.com"
    );
}

#[test]
fn paste_is_inert_in_rule_edit_modal() {
    use crate::filter::rules::RuleAction;
    use crate::tui::app::{RuleEditFocus, RuleEditModal, RuleEditMode, RuleScope, ScopeChoice};

    let mut app = App::new();
    app.active_leaf = Leaf::Rules;
    app.rules.edit_modal = Some(RuleEditModal {
        rule_id: "r-1".into(),
        raw_rule: "||ads.example.com^".into(),
        original_action: RuleAction::Block,
        original_scope: RuleScope::Default,
        original_references: Vec::new(),
        current_action: RuleAction::Block,
        current_scope_choice: ScopeChoice::Default,
        scope_options: vec![ScopeChoice::Default],
        focus: RuleEditFocus::Action,
        mode: RuleEditMode::Edit,
        error_message: None,
        status_message: None,
        submitting: false,
    });
    assert!(
        focused_text_buffer(&mut app).is_none(),
        "picker/confirm only — paste must not fall through past this gate"
    );
}

#[test]
fn paste_reaches_custom_list_add_form_id_field() {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_add("packs".into()));
    // `Form::new_add` focuses Id first, and Id is pasteable on Add.
    handle_paste(&mut app, "videogames".to_string());
    match &app.custom_lists.modal.as_ref().unwrap().stage {
        custom_list_modal::Stage::EditingForm(form) => assert_eq!(form.id, "videogames"),
        other => panic!("expected EditingForm, got {other:?}"),
    }
}

#[test]
fn paste_reaches_custom_list_form_display_name_and_description() {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_add("packs".into()));

    if let Some(custom_list_modal::Stage::EditingForm(form)) =
        app.custom_lists.modal.as_mut().map(|m| &mut m.stage)
    {
        form.focused = custom_list_modal::FormField::DisplayName;
    }
    handle_paste(&mut app, "Video games".to_string());

    if let Some(custom_list_modal::Stage::EditingForm(form)) =
        app.custom_lists.modal.as_mut().map(|m| &mut m.stage)
    {
        assert_eq!(form.display_name, "Video games");
        form.focused = custom_list_modal::FormField::Description;
    }
    handle_paste(&mut app, "the kids' allowances".to_string());

    match &app.custom_lists.modal.as_ref().unwrap().stage {
        custom_list_modal::Stage::EditingForm(form) => {
            assert_eq!(form.description, "the kids' allowances");
        }
        other => panic!("expected EditingForm, got {other:?}"),
    }
}

#[test]
fn paste_reaches_custom_list_add_rule_domain_field() {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_add_rule(
        "videogames".into(),
    ));
    // `RuleForm::new` focuses Domain first.
    handle_paste(&mut app, "roblox.example.com".to_string());
    match &app.custom_lists.modal.as_ref().unwrap().stage {
        custom_list_modal::Stage::AddingRule(form) => {
            assert_eq!(form.domain, "roblox.example.com");
        }
        other => panic!("expected AddingRule, got {other:?}"),
    }
}

#[test]
fn paste_is_inert_in_custom_list_remove_confirm() {
    use crate::config::schema::{CustomList, Id};

    let entity = CustomList {
        id: Id::new("videogames").unwrap(),
        display_name: "Video games".into(),
        description: "the kids' allowances".into(),
    };
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_remove(
        &entity,
        Vec::new(),
        0,
    ));

    // Same rule as the Lists / Subnets typed gates: buys deliberation,
    // not transcription.
    assert!(focused_text_buffer(&mut app).is_none());
    handle_paste(&mut app, "videogames".to_string());
    match &app.custom_lists.modal.as_ref().unwrap().stage {
        custom_list_modal::Stage::ConfirmingRemove(rc) => {
            assert!(
                rc.typed.is_empty(),
                "paste must not land in the typed buffer"
            );
        }
        other => panic!("expected ConfirmingRemove, got {other:?}"),
    }
}

#[test]
fn paste_reaches_query_log_filter_name_ip_subnet_fields() {
    use crate::ipc::protocol::AdvancedClientFilterDto;
    use query_log_filter_modal::{Field, QueryLogFilterModal};

    let mut app = App::new();
    app.query_log.advanced_modal = Some(QueryLogFilterModal::open(
        &AdvancedClientFilterDto::default(),
    ));

    // `QueryLogFilterModal::open` defaults focus to NamePattern.
    handle_paste(&mut app, "kids-*".to_string());
    assert_eq!(
        app.query_log
            .advanced_modal
            .as_ref()
            .unwrap()
            .draft
            .name
            .as_deref(),
        Some("kids-*")
    );

    app.query_log.advanced_modal.as_mut().unwrap().focus = Field::IpPattern;
    handle_paste(&mut app, "10.0.0.*".to_string());
    assert_eq!(
        app.query_log
            .advanced_modal
            .as_ref()
            .unwrap()
            .draft
            .ip
            .as_deref(),
        Some("10.0.0.*")
    );

    app.query_log.advanced_modal.as_mut().unwrap().focus = Field::SubnetPattern;
    handle_paste(&mut app, "10.10.1.0/24".to_string());
    assert_eq!(
        app.query_log
            .advanced_modal
            .as_ref()
            .unwrap()
            .draft
            .subnet
            .as_deref(),
        Some("10.10.1.0/24")
    );
}

#[test]
fn paste_is_inert_on_query_log_filter_polarity_and_action_rows() {
    use crate::ipc::protocol::AdvancedClientFilterDto;
    use query_log_filter_modal::{Field, QueryLogFilterModal};

    let mut app = App::new();
    app.query_log.advanced_modal = Some(QueryLogFilterModal::open(
        &AdvancedClientFilterDto::default(),
    ));
    for focus in [
        Field::NamePolarity,
        Field::IpPolarity,
        Field::SubnetPolarity,
        Field::Cancel,
        Field::Apply,
    ] {
        app.query_log.advanced_modal.as_mut().unwrap().focus = focus;
        assert!(
            focused_text_buffer(&mut app).is_none(),
            "{focus:?} has no text buffer to paste into"
        );
    }
}
