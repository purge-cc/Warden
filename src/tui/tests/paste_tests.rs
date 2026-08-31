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
