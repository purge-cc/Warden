use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use base64::Engine;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

use super::*;
use crate::cluster::lifecycle::{LifecycleStatus, NodeRole};
use crate::cluster::membership::SecretString;
use crate::cluster::node_control::{
    BootstrapToken, NodeCapabilities, NodeControlCommand, NodeControlStatus, NodeOperationKind,
    NodeOperationPhase, NodeOperationProgress, NodePeer, NodePeerState,
};
use crate::tui::nodes::{NodeFormKind, NodesDialog};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn endpoint(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 8053)
}
fn membership() -> LifecycleStatus {
    LifecycleStatus {
        node_id: Some("node-self".into()),
        node_name: "kitchen".into(),
        saved_role: NodeRole::Primary,
        active_role: Some(NodeRole::Primary),
        can_edit_policy: true,
        ..LifecycleStatus::default()
    }
}
fn control(operations: Vec<NodeOperationProgress>) -> NodeControlStatus {
    NodeControlStatus {
        membership: membership(),
        control_endpoint: Some(endpoint(1)),
        operations,
        peers: vec![NodePeer {
            node_id: "node-peer".into(),
            name: "office".into(),
            endpoint: endpoint(2),
            role: NodeRole::Secondary,
            state: NodePeerState::Active,
            capabilities: NodeCapabilities {
                protocol_version: 2,
                persistent_management: true,
                endpoint_transition: true,
                durable_detach: true,
            },
            last_seen_at: None,
            last_error: None,
        }],
    }
}
fn ready_app() -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::Nodes;
    app.nodes_status = Some(membership());
    app.node_control_status = Some(control(Vec::new()));
    app
}

#[test]
fn detached_peer_with_an_unresolved_add_remains_visible_for_recovery() {
    let mut app = ready_app();
    let control = app.node_control_status.as_mut().unwrap();
    control.peers[0].state = NodePeerState::Detached;
    control.operations.push(NodeOperationProgress {
        operation_id: "operation-1".into(),
        kind: NodeOperationKind::Add,
        phase: NodeOperationPhase::Cancelled,
        target_node_id: "node-peer".into(),
        message: "Review expired; temporary association authorization was revoked.".into(),
        last_verified_at: None,
        recover_until: Some(1),
        restart_steps: Vec::new(),
    });
    let rows = tabs::nodes::build_rows(&app);
    assert!(rows
        .iter()
        .any(|row| row.id == "node-peer" && row.status == "recovery: detached"));
}

fn synthetic_bootstrap_token() -> (BootstrapToken, u64) {
    let now = 1_700_000_000;
    (
        BootstrapToken {
            version: 2,
            target_node_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            endpoint: endpoint(2),
            fingerprint: "a".repeat(64),
            expires_at: now + 10 * 60,
            secret: SecretString(format!("ps_{}", "b".repeat(64))),
        },
        now,
    )
}

fn legacy_bootstrap_token_encoding(token: &BootstrapToken) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(token).expect("synthetic token serializes"))
}

#[tokio::test]
async fn legacy_members_remain_visible_without_a_management_endpoint() {
    let mut app = ready_app();
    app.node_control_status
        .as_mut()
        .unwrap()
        .membership
        .roster
        .push(crate::cluster::membership::MemberView {
            node_id: "legacy-peer".into(),
            name: "Existing resolver".into(),
            state: crate::cluster::membership::MemberState::Active,
            admitted_at: 1,
            expires_at: None,
            endpoint: None,
            sync: None,
            last_confirmation_secs: Some(3),
            fingerprint: None,
        });
    let rows = tabs::nodes::build_rows(&app);
    let legacy = rows.iter().find(|row| row.id == "legacy-peer").unwrap();
    assert_eq!(legacy.name, "Existing resolver");
    assert_eq!(legacy.endpoint, None);
    assert!(!legacy.management_available);
    app.nodes.selected_id = Some(legacy.id.clone());
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
    assert!(app
        .status_text()
        .is_some_and(|message| message.contains("Upgrade")));
}
fn poller() -> IpcPoller {
    IpcPoller::new(Path::new("/nonexistent/warden-nodes-tests.sock"))
}

#[tokio::test]
async fn nodes_edits_wait_until_saved_membership_is_active() {
    let mut app = ready_app();
    let pending = LifecycleStatus {
        saved_role: NodeRole::Primary,
        active_role: Some(NodeRole::Standalone),
        restart_required: true,
        ..membership()
    };
    app.nodes_status = Some(pending.clone());
    app.node_control_status.as_mut().unwrap().membership = pending;
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
    assert!(!crate::tui::nodes::controls_available(&app));
}

#[test]
fn nodes_is_always_visible_inside_configuration() {
    let app = App::new();
    assert!(Section::Configuration.leaves().contains(&Leaf::Nodes));
    assert_eq!(Leaf::Nodes.section(), Section::Configuration);
    assert!(leaf_visible(Leaf::Nodes, &app));
}

#[tokio::test]
async fn add_edit_and_remove_dispatch_from_the_current_selection() {
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Form(draft)) if draft.kind == NodeFormKind::Add && draft.port == "8053")
    );
    app.nodes.dialog = None;
    app.nodes.selected_id = Some("node-peer".into());
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Form(draft)) if draft.kind == NodeFormKind::Edit && draft.address == "192.0.2.2")
    );
    app.nodes.dialog = None;
    handle_nodes_key(&mut app, key(KeyCode::Char('d')), &poller()).await;
    assert!(
        app.nodes.dialog.is_none(),
        "remove goes straight to the final review request"
    );
}

#[tokio::test]
async fn sorting_keeps_selection_by_stable_node_id_in_both_directions() {
    let mut app = ready_app();
    app.nodes.selected_id = Some("node-peer".into());
    app.nodes.sort = crate::tui::nodes::NodeSort::Name;
    let ascending = tabs::nodes::build_rows(&app);
    assert_eq!(
        ascending.first().map(|row| row.id.as_str()),
        Some("node-self")
    );
    assert!(ascending.iter().any(|row| row.id == "node-peer"));
    handle_nodes_key(&mut app, key(KeyCode::Char('o')), &poller()).await;
    assert_eq!(app.nodes.selected_id.as_deref(), Some("node-peer"));
    handle_nodes_key(&mut app, key(KeyCode::Char('O')), &poller()).await;
    assert_eq!(app.nodes.selected_id.as_deref(), Some("node-peer"));
    assert!(app.nodes.descending);
    let descending = tabs::nodes::build_rows(&app);
    assert_eq!(
        descending.first().map(|row| row.id.as_str()),
        Some("node-self")
    );
    assert!(descending.iter().any(|row| row.id == "node-peer"));
    let selected = descending
        .iter()
        .find(|row| row.id == "node-peer")
        .expect("selected stable node");
    assert_eq!(selected.name, "office");
}

#[test]
fn local_row_survives_missing_control_status_without_reusing_dns_address() {
    let mut app = App::new();
    app.nodes_status = Some(membership());
    let rows = tabs::nodes::build_rows(&app);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_self);
    assert_eq!(rows[0].status, "authority unavailable");
    assert!(rows[0].endpoint.is_none());
}

#[test]
fn completed_departures_do_not_reappear_from_the_legacy_roster() {
    let mut app = ready_app();
    let control = app.node_control_status.as_mut().unwrap();
    control.peers[0].state = NodePeerState::Detached;
    control
        .membership
        .roster
        .push(crate::cluster::membership::MemberView {
            node_id: "node-peer".into(),
            name: "office".into(),
            state: crate::cluster::membership::MemberState::Revoked,
            admitted_at: 1,
            expires_at: None,
            endpoint: None,
            sync: None,
            last_confirmation_secs: None,
            fingerprint: None,
        });
    let rows = tabs::nodes::build_rows(&app);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_self);
}

#[tokio::test]
async fn narrow_right_left_switches_stable_list_and_detail() {
    let mut app = ready_app();
    app.nodes.selected_id = Some("node-peer".into());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    handle_nodes_key(&mut app, key(KeyCode::Right), &poller()).await;
    assert!(detail_panel::focused(&app, Leaf::Nodes));
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let detail = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(detail.contains("NODE DETAILS"), "{detail}");
    assert_eq!(app.nodes.selected_id.as_deref(), Some("node-peer"));
    handle_nodes_key(&mut app, key(KeyCode::Left), &poller()).await;
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let list = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(list.contains("Nodes"));
    assert!(list.contains("office"));
}

#[tokio::test]
async fn standalone_name_only_edit_and_secondary_add_guard_use_fresh_agreement() {
    let mut app = ready_app();
    let mut standalone = membership();
    standalone.saved_role = NodeRole::Standalone;
    standalone.active_role = Some(NodeRole::Standalone);
    app.nodes_status = Some(standalone.clone());
    let mut fresh = control(Vec::new());
    fresh.membership = standalone;
    fresh.control_endpoint = None;
    app.node_control_status = Some(fresh);
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_ref() else {
        panic!("name-only edit")
    };
    assert!(draft.address.is_empty());
    assert!(matches!(
        draft.request(),
        Ok(crate::cluster::node_control::NodeControlCommand::PreviewEdit { endpoint: None, .. })
    ));
    app.nodes.dialog = None;
    let mut secondary = membership();
    secondary.saved_role = NodeRole::Secondary;
    secondary.active_role = Some(NodeRole::Secondary);
    app.nodes_status = Some(secondary.clone());
    app.node_control_status.as_mut().expect("fresh").membership = secondary;
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
}

#[tokio::test]
async fn local_detail_cannot_remove_and_remote_detail_requires_fresh_authority() {
    let mut app = ready_app();
    app.nodes.selected_id = Some("node-self".into());
    handle_nodes_key(&mut app, key(KeyCode::Char('d')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
    assert!(app
        .status_text()
        .is_some_and(|message| message.contains("cannot be removed")));
    app.node_control_status = None;
    app.nodes.selected_id = Some("node-peer".into());
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
}

#[tokio::test]
async fn bootstrap_token_paste_is_complete_masked_and_extractable_after_navigation() {
    let (expected, now) = synthetic_bootstrap_token();
    let encoded = legacy_bootstrap_token_encoding(&expected);
    assert!(
        encoded.len() > MAX_PASTE,
        "the current bootstrap-token encoding must exercise the regression boundary"
    );

    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
        panic!("add form")
    };
    draft.name = "Office".into();
    draft.address = "192.0.2.2".into();
    draft.focus = 2;
    handle_paste(&mut app, encoded.clone());
    handle_nodes_dialog_key(&mut app, key(KeyCode::Tab), &poller()).await;

    let mut terminal = Terminal::new(TestBackend::new(125, 36)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let paint = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(
        !paint.contains(&encoded),
        "association tokens must never be rendered verbatim"
    );
    assert!(paint.contains("••••"));
    let request = match app.nodes.dialog.as_ref() {
        Some(NodesDialog::Form(draft)) => {
            assert_eq!(draft.token, encoded, "paste must not truncate the token");
            draft.request().expect("complete add request")
        }
        _ => panic!("pasting must stay in the add form"),
    };
    let NodeControlCommand::PreviewAdd { token, .. } = request else {
        panic!("add draft must produce a preview-add request")
    };
    assert_eq!(token.0, encoded, "request must retain the exact token");
    assert_eq!(
        BootstrapToken::decode(&token, now).expect("pasted token decodes"),
        expected
    );
}

#[tokio::test]
async fn bootstrap_token_paste_strips_controls_without_changing_the_token() {
    let (expected, now) = synthetic_bootstrap_token();
    let encoded = legacy_bootstrap_token_encoding(&expected);
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
        panic!("add form")
    };
    draft.name = "Office".into();
    draft.address = "192.0.2.2".into();
    draft.focus = 2;

    handle_paste(&mut app, format!("\n{encoded}\t\r"));

    let request = match app.nodes.dialog.as_ref() {
        Some(NodesDialog::Form(draft)) => {
            assert_eq!(draft.token, encoded);
            draft.request().expect("complete add request")
        }
        _ => panic!("pasting must stay in the add form"),
    };
    let NodeControlCommand::PreviewAdd { token, .. } = request else {
        panic!("add draft must produce a preview-add request")
    };
    assert_eq!(BootstrapToken::decode(&token, now).unwrap(), expected);
}

#[tokio::test]
async fn token_paste_rejects_oversize_and_cumulative_overflow_atomically() {
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
        panic!("add form")
    };
    draft.focus = 2;
    draft.token = "test-preserve-this".into();

    handle_paste(&mut app, "x".repeat(4097));
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_ref() else {
        panic!("add form")
    };
    assert_eq!(draft.token, "test-preserve-this");
    assert!(
        draft.error.is_some(),
        "oversize paste must explain its rejection"
    );

    let fill = 4096 - draft.token.len();
    handle_paste(&mut app, "x".repeat(fill));
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_ref() else {
        panic!("add form")
    };
    assert_eq!(draft.token.len(), 4096);
    assert!(draft.error.is_none(), "a token at the exact limit is valid");

    handle_paste(&mut app, "x".into());
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_ref() else {
        panic!("add form")
    };
    assert_eq!(
        draft.token.len(),
        4096,
        "overflow must leave the token intact"
    );
    assert!(
        draft.error.is_some(),
        "cumulative overflow must be reported"
    );
}

#[tokio::test]
async fn other_nodes_text_fields_keep_the_generic_paste_limit() {
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    if let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() {
        draft.advanced = true;
    } else {
        panic!("add form");
    }

    for (focus, payload) in [(0, 'n'), (1, 'a'), (3, 'p')] {
        let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
            panic!("add form")
        };
        draft.focus = focus;
        handle_paste(&mut app, payload.to_string().repeat(MAX_PASTE + 1));
    }
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_ref() else {
        panic!("add form")
    };
    assert_eq!(draft.name.len(), MAX_PASTE);
    assert_eq!(draft.address.len(), MAX_PASTE);
    assert_eq!(draft.port.len(), 4 + MAX_PASTE);
}

#[tokio::test]
async fn resolver_overlay_and_pending_action_own_paste_before_the_node_token() {
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
        panic!("add form")
    };
    draft.focus = 2;
    draft.token = "test-unchanged".into();
    app.resolver_modal = Some(resolver_modal::ResolverModal::open_blank());

    handle_paste(&mut app, "192.0.2.99".into());
    assert_eq!(app.resolver_modal.as_ref().unwrap().input, "192.0.2.99");
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Form(draft)) if draft.token == "test-unchanged")
    );

    app.pending_action = Some(actions::PendingAction {
        id: 1,
        surface: actions::Surface::Nodes,
        label: "test action".into(),
        detached: false,
        written: None,
    });
    handle_paste(&mut app, "must-not-reach-an-overlay-or-token".into());
    assert_eq!(app.resolver_modal.as_ref().unwrap().input, "192.0.2.99");
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Form(draft)) if draft.token == "test-unchanged")
    );
}

#[test]
fn bootstrap_token_writer_round_trips_the_current_encoding() {
    let (expected, now) = synthetic_bootstrap_token();
    let encoded = expected.encode().expect("synthetic token encodes");
    assert_eq!(
        BootstrapToken::decode(&encoded, now).expect("current token encoding decodes"),
        expected
    );
}

#[tokio::test]
async fn resize_preserves_inline_form_and_stable_node_selection() {
    let mut app = ready_app();
    app.nodes.selected_id = Some("node-peer".into());
    handle_nodes_key(&mut app, key(KeyCode::Char('e')), &poller()).await;
    for (width, height) in [(164, 46), (80, 24), (125, 36)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        assert!(matches!(
            app.nodes.dialog.as_ref(),
            Some(NodesDialog::Form(_))
        ));
        assert_eq!(app.nodes.selected_id.as_deref(), Some("node-peer"));
    }
}

#[tokio::test]
async fn recovery_uses_durable_operation_and_stale_control_never_enables_edits() {
    let progress = NodeOperationProgress {
        operation_id: "operation-1".into(),
        kind: NodeOperationKind::Remove,
        phase: NodeOperationPhase::AwaitingDetach,
        target_node_id: "node-peer".into(),
        message: "peer is offline; detach remains pending".into(),
        last_verified_at: None,
        recover_until: Some(1),
        restart_steps: Vec::new(),
    };
    let mut app = ready_app();
    app.node_control_status = Some(control(vec![progress]));
    handle_nodes_key(&mut app, key(KeyCode::Char('u')), &poller()).await;
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Recovery { progress, .. }) if progress.operation_id == "operation-1")
    );
    app.nodes.dialog = None;
    app.apply_node_control_poll_result(Err("unavailable".into()));
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    assert!(app.nodes.dialog.is_none());
    assert!(app
        .status_text()
        .is_some_and(|message| message.contains("authority is unavailable")));
}

#[tokio::test]
async fn cancelled_add_remains_discoverable_when_its_peer_is_detached() {
    let progress = NodeOperationProgress {
        operation_id: "operation-1".into(),
        kind: NodeOperationKind::Add,
        phase: NodeOperationPhase::Cancelled,
        target_node_id: "node-peer".into(),
        message: "Review expired; temporary association authorization was revoked.".into(),
        last_verified_at: None,
        recover_until: Some(1),
        restart_steps: Vec::new(),
    };
    let mut app = ready_app();
    let control = app.node_control_status.as_mut().unwrap();
    control.peers[0].state = NodePeerState::Detached;
    control.operations.push(progress);

    handle_nodes_key(&mut app, key(KeyCode::Char('u')), &poller()).await;

    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Recovery { progress, .. }) if progress.phase == NodeOperationPhase::Cancelled)
    );
    handle_nodes_dialog_key(&mut app, key(KeyCode::Enter), &poller()).await;
    assert!(matches!(
        app.nodes.dialog.as_ref(),
        Some(NodesDialog::Recovery { .. })
    ));
}

#[tokio::test]
async fn cancelled_source_cleanup_with_its_pending_peer_can_be_resumed() {
    let progress = NodeOperationProgress {
        operation_id: "cleanup-operation".into(),
        kind: NodeOperationKind::Add,
        phase: NodeOperationPhase::Cancelled,
        target_node_id: "node-peer".into(),
        message: "Preview cancelled; membership and active policy are unchanged.".into(),
        last_verified_at: None,
        recover_until: Some(1),
        restart_steps: Vec::new(),
    };
    let mut app = ready_app();
    app.node_control_status = Some(control(vec![progress]));
    app.node_control_status.as_mut().unwrap().peers[0].state = NodePeerState::Pending;
    assert!(tabs::nodes::build_rows(&app)
        .iter()
        .any(|row| row.id == "node-peer" && row.status == "recovery: cleanup"));

    handle_nodes_key(&mut app, key(KeyCode::Char('u')), &poller()).await;
    assert!(matches!(
        app.nodes.dialog.as_ref(),
        Some(NodesDialog::Recovery { progress, .. }) if progress.operation_id == "cleanup-operation"
    ));
    handle_nodes_dialog_key(&mut app, key(KeyCode::Enter), &poller()).await;
    assert!(matches!(
        app.nodes.dialog.as_ref(),
        Some(NodesDialog::Recovery { error: Some(_), .. })
    ));
}

#[test]
fn acknowledged_cancelled_add_is_not_presented_as_a_detached_recovery() {
    let mut app = ready_app();
    let control = app.node_control_status.as_mut().unwrap();
    control.peers[0].state = NodePeerState::Detached;
    control.operations.push(NodeOperationProgress {
        operation_id: "completed-cancel".into(),
        kind: NodeOperationKind::Add,
        phase: NodeOperationPhase::Cancelled,
        target_node_id: "node-peer".into(),
        message: "Preview cancelled; membership and active policy are unchanged.".into(),
        last_verified_at: None,
        recover_until: None,
        restart_steps: Vec::new(),
    });
    let rows = tabs::nodes::build_rows(&app);
    assert!(!rows.iter().any(|row| row.id == "node-peer"));
}

#[tokio::test]
async fn review_dispatch_failure_keeps_the_add_form_recoverable() {
    let mut app = ready_app();
    handle_nodes_key(&mut app, key(KeyCode::Char('a')), &poller()).await;
    let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() else {
        panic!("add form")
    };
    draft.address = "192.0.2.2".into();
    draft.token = "token".into();
    draft.focus = draft.visible_fields() + 2;
    handle_nodes_dialog_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        &IpcPoller::new(Path::new("/nonexistent/nodes.sock")),
    )
    .await;
    assert!(
        matches!(app.nodes.dialog.as_ref(), Some(NodesDialog::Form(draft)) if draft.error.is_some() && draft.token == "token")
    );
}
