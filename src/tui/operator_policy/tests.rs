use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use super::adapter::AdapterErrorKind;
use super::*;
use crate::ipc::protocol::{
    CustomListsReadRequest, CustomListsReadResponse, IpcCommand, IpcResponse,
};
use crate::operator_rules::{
    Activation, Capabilities, ErrorCode, ListPage, Metadata, Operation, OperatorRulesError,
    PageRequest, PersistenceState, PlanImpactPage, PlanImpactRow, PlanSummary, Receipt, RuleAction,
    RulePage, TransportLimits, CONTRACT_VERSION,
};

fn capabilities() -> Capabilities {
    Capabilities {
        contract_version: CONTRACT_VERSION,
        schema_version: 5,
        operator_rule_grammar: 1,
        operations: [
            "create_list",
            "set_metadata",
            "add_domain_rule",
            "add_raw_rule",
            "replace_rule",
            "remove_rule",
            "mount",
            "unmount",
            "delete_list",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        semantic_hash: true,
        activation_ack: true,
        cluster_artifact: false,
        limits: TransportLimits::IPC,
    }
}

fn summary(request: &crate::operator_rules::BatchRequest) -> PlanSummary {
    PlanSummary {
        contract_version: CONTRACT_VERSION,
        plan_hash: "b".repeat(64),
        base_config_revision: request.expected_config_revision.clone(),
        candidate_config_revision: "c".repeat(64),
        base_operator_policy_hash: "d".repeat(64),
        candidate_operator_policy_hash: "e".repeat(64),
        semantic_changed: true,
        cosmetic_changed: false,
        changed: true,
        operation_count: request.operations.len(),
        touched_member_count: 2,
        impacted_profile_count: 1,
        impacted_recipient_count: 1,
        warning_count: 0,
        pack_bytes_after: 24,
        rules_after: 1,
    }
}

fn retained_plan(request: &crate::operator_rules::BatchRequest) -> RetainedPlan {
    RetainedPlan {
        plan_ref: "retained-1".into(),
        request_id: request.request_id.clone(),
        summary: summary(request),
        impact_rows: vec![PlanImpactRow {
            kind: "profile".into(),
            value: "default".into(),
        }],
        next_impact_cursor: Some("impact-cursor".into()),
    }
}

fn receipt(request_id: &str, operation_id: &str, activation: &str) -> Receipt {
    Receipt {
        contract_version: CONTRACT_VERSION,
        operation_id: operation_id.into(),
        request_id: request_id.into(),
        changed: true,
        persistence: PersistenceState::Committed,
        config_revision: "c".repeat(64),
        operator_policy_hash: Some("e".repeat(64)),
        activation: Activation {
            state: activation.into(),
            correlation_id: Some("correlation-1".into()),
            reload_outcome: Some(activation.into()),
            active_config_revision: None,
            active_policy_hash: None,
            daemon_instance_id: None,
            superseded_by: None,
        },
        replication: "not_configured".into(),
        audit: "recorded".into(),
        diagnostics: Vec::new(),
    }
}

fn operation() -> Operation {
    Operation::AddDomainRule {
        id: "local".into(),
        domain: "policy.invalid".into(),
        action: RuleAction::Deny,
    }
}

fn remote_error(code: ErrorCode, message: &str) -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::Remote,
        error: OperatorRulesError::new(code, message),
    }
}

fn transport_error(message: &str) -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::Transport,
        error: OperatorRulesError::new(ErrorCode::StorageUnavailable, message),
    }
}

fn spawn_server(
    path: &Path,
    responses: Vec<IpcResponse>,
) -> tokio::task::JoinHandle<Vec<IpcCommand>> {
    let listener = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            requests.push(serde_json::from_str(&line).unwrap());
            let mut encoded = serde_json::to_vec(&response).unwrap();
            encoded.push(b'\n');
            stream.write_all(&encoded).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        requests
    })
}

#[tokio::test]
async fn adapter_sends_typed_revision_bound_inventory_and_rule_pages() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("operator-policy.sock");
    let metadata = Metadata {
        contract_version: CONTRACT_VERSION,
        schema_version: 5,
        config_revision: "a".repeat(64),
        desired_operator_policy_hash: "d".repeat(64),
        active_policy: None,
        activation_in_sync: false,
        lists: 1,
        mounted_lists: 1,
        orphan_packs: 0,
    };
    let server = spawn_server(
        &socket,
        vec![
            IpcResponse::OperatorRulesCapabilities {
                capabilities: capabilities(),
            },
            IpcResponse::CustomListsMetadata {
                metadata: metadata.clone(),
            },
            IpcResponse::CustomListsRead {
                response: CustomListsReadResponse::List(ListPage {
                    contract_version: CONTRACT_VERSION,
                    config_revision: metadata.config_revision.clone(),
                    lists: Vec::new(),
                    next_cursor: Some("inventory-at-revision-a".into()),
                    orphan_packs: Vec::new(),
                }),
            },
            IpcResponse::CustomListsRead {
                response: CustomListsReadResponse::List(ListPage {
                    contract_version: CONTRACT_VERSION,
                    config_revision: metadata.config_revision.clone(),
                    lists: Vec::new(),
                    next_cursor: None,
                    orphan_packs: Vec::new(),
                }),
            },
            IpcResponse::CustomListsRead {
                response: CustomListsReadResponse::Rules(RulePage {
                    contract_version: CONTRACT_VERSION,
                    id: "local".into(),
                    config_revision: metadata.config_revision.clone(),
                    pack_revision: "f".repeat(64),
                    rows: Vec::new(),
                    next_cursor: Some("rules-at-pack-f".into()),
                }),
            },
            IpcResponse::CustomListsRead {
                response: CustomListsReadResponse::Rules(RulePage {
                    contract_version: CONTRACT_VERSION,
                    id: "local".into(),
                    config_revision: metadata.config_revision.clone(),
                    pack_revision: "f".repeat(64),
                    rows: Vec::new(),
                    next_cursor: None,
                }),
            },
        ],
    );

    let adapter = OperatorPolicyAdapter::connect_with_token(&socket, "test-token")
        .await
        .unwrap();
    assert_eq!(adapter.capabilities().limits, TransportLimits::IPC);
    assert_eq!(adapter.metadata().await.unwrap(), metadata);
    let inventory = adapter.inventory(PageRequest::default()).await.unwrap();
    assert_eq!(
        inventory.next_cursor.as_deref(),
        Some("inventory-at-revision-a")
    );
    assert!(adapter.next_inventory(&inventory).await.unwrap().is_some());
    let rules = adapter
        .rules("local".into(), PageRequest::default())
        .await
        .unwrap();
    assert!(adapter.next_rules(&rules).await.unwrap().is_some());

    let requests = server.await.unwrap();
    assert!(matches!(requests[0], IpcCommand::OperatorRulesCapabilities));
    assert!(matches!(requests[1], IpcCommand::CustomListsMetadata));
    assert!(matches!(
        &requests[2],
        IpcCommand::CustomListsRead {
            request: CustomListsReadRequest::List {
                page: PageRequest {
                    cursor: None,
                    limit: None
                }
            },
            token: Some(token)
        } if token == "test-token"
    ));
    assert!(matches!(
        &requests[3],
        IpcCommand::CustomListsRead {
            request: CustomListsReadRequest::List {
                page: PageRequest {
                    cursor: Some(cursor),
                    limit: Some(100)
                }
            },
            token: Some(token)
        } if cursor == "inventory-at-revision-a" && token == "test-token"
    ));
    assert!(matches!(
        &requests[4],
        IpcCommand::CustomListsRead {
            request: CustomListsReadRequest::Rules {
                id,
                page: PageRequest {
                    cursor: None,
                    limit: None
                }
            },
            token: Some(token)
        } if id == "local" && token == "test-token"
    ));
    assert!(matches!(
        &requests[5],
        IpcCommand::CustomListsRead {
            request: CustomListsReadRequest::Rules {
                id,
                page: PageRequest {
                    cursor: Some(cursor),
                    limit: Some(100)
                }
            },
            token: Some(token)
        } if id == "local" && cursor == "rules-at-pack-f" && token == "test-token"
    ));
}

#[tokio::test]
async fn read_rules_rejects_a_first_page_outside_the_requested_revision_fence() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("operator-policy.sock");
    register_test_token(&socket, "test-token");
    let server = spawn_server(
        &socket,
        vec![
            IpcResponse::OperatorRulesCapabilities {
                capabilities: capabilities(),
            },
            IpcResponse::CustomListsRead {
                response: CustomListsReadResponse::Rules(RulePage {
                    contract_version: CONTRACT_VERSION,
                    id: "local".into(),
                    config_revision: "new-config".into(),
                    pack_revision: "new-pack".into(),
                    rows: Vec::new(),
                    next_cursor: None,
                }),
            },
        ],
    );

    let error = read_rules(
        socket,
        "local".into(),
        "captured-config".into(),
        "captured-pack".into(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StaleCursor);
    server.await.unwrap();
}

#[tokio::test]
async fn plan_and_apply_keep_the_same_request_identity_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("operator-policy.sock");
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let plan_attempt = workflow.begin_plan().unwrap();
    let request_id = plan_attempt.request.request_id.clone();
    let plan_summary = summary(&plan_attempt.request);
    let applied = receipt(&request_id, "operation-1", "pending");
    let server = spawn_server(
        &socket,
        vec![
            IpcResponse::OperatorRulesCapabilities {
                capabilities: capabilities(),
            },
            IpcResponse::OperatorRulesPlan {
                plan_ref: "retained-1".into(),
                summary: plan_summary.clone(),
                impact: PlanImpactPage {
                    contract_version: CONTRACT_VERSION,
                    plan_hash: plan_summary.plan_hash.clone(),
                    rows: Vec::new(),
                    next_cursor: None,
                },
            },
            IpcResponse::OperatorRulesApply {
                receipt: applied.clone(),
            },
        ],
    );

    let adapter = OperatorPolicyAdapter::connect_with_token(&socket, "test-token")
        .await
        .unwrap();
    let plan = adapter
        .create_plan(plan_attempt.request.clone(), plan_attempt.page.clone())
        .await
        .unwrap();
    assert_eq!(plan.request_id, request_id);
    assert!(workflow.finish_plan(plan_attempt.ticket, Ok(plan)));
    let apply_attempt = workflow.begin_apply().unwrap();
    let receipt = adapter.apply(&apply_attempt.plan).await.unwrap();
    assert!(workflow.finish_apply(apply_attempt.ticket, Ok(receipt)));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Outcome { receipt, .. }
            if receipt.persistence == PersistenceState::Committed
                && receipt.activation.state == "pending"
    ));

    let requests = server.await.unwrap();
    let IpcCommand::OperatorRulesPlan {
        request: Some(planned),
        ..
    } = &requests[1]
    else {
        panic!("expected plan command")
    };
    let IpcCommand::OperatorRulesApply {
        request_id: applied_id,
        plan_hash,
        ..
    } = &requests[2]
    else {
        panic!("expected apply command")
    };
    assert_eq!(&planned.request_id, applied_id);
    assert_eq!(plan_hash, &plan_summary.plan_hash);
}

#[tokio::test]
async fn unexpected_response_is_a_structured_contract_error() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("operator-policy.sock");
    let server = spawn_server(
        &socket,
        vec![
            IpcResponse::OperatorRulesCapabilities {
                capabilities: capabilities(),
            },
            IpcResponse::Ok {
                message: "wrong response".into(),
            },
        ],
    );
    let adapter = OperatorPolicyAdapter::connect_with_token(&socket, "test-token")
        .await
        .unwrap();
    let error = adapter.inventory(PageRequest::default()).await.unwrap_err();
    assert_eq!(error.kind, AdapterErrorKind::Protocol);
    assert_eq!(error.code(), ErrorCode::UnsupportedContract);
    server.await.unwrap();
}

#[test]
fn stale_impact_requires_refresh_and_a_new_draft_identity() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let plan_attempt = workflow.begin_plan().unwrap();
    let old_request_id = plan_attempt.request.request_id.clone();
    assert!(workflow.finish_plan(
        plan_attempt.ticket,
        Ok(retained_plan(&plan_attempt.request))
    ));
    let impact = workflow.begin_more_impact().unwrap();
    assert!(workflow.finish_more_impact(
        impact.ticket,
        Err(remote_error(
            ErrorCode::StaleCursor,
            "plan impact cursor is stale"
        ))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::RefreshAndRedraft,
            error: Some(error),
            ..
        }) if error.code() == ErrorCode::StaleCursor
    ));

    // Replanning after a revision fence is a new logical intent. Production's
    // controller constructs a new workflow rather than mutating this one.
    let redrafted = OperatorPolicyWorkflow::new("b".repeat(64), vec![operation()]).unwrap();
    let WorkflowState::Draft(redraft) = &redrafted.state else {
        panic!("expected fresh draft")
    };
    assert_ne!(redraft.request.request_id, old_request_id);
}

#[test]
fn uncertain_apply_retries_exact_apply_without_changing_request_identity() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let plan_attempt = workflow.begin_plan().unwrap();
    let request_id = plan_attempt.request.request_id.clone();
    assert!(workflow.finish_plan(
        plan_attempt.ticket,
        Ok(retained_plan(&plan_attempt.request))
    ));
    let apply = workflow.begin_apply().unwrap();
    assert!(workflow.finish_apply(
        apply.ticket,
        Err(transport_error("daemon closed connection without response"))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::RetryExactApply,
            ..
        })
    ));
    let retry = workflow.begin_exact_apply().unwrap();
    assert_eq!(retry.request.request_id, request_id);
    assert!(workflow.finish_exact_apply(
        retry.ticket,
        Ok(receipt(&request_id, "operation-1", "applied"))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Outcome { receipt, .. }
            if receipt.persistence == PersistenceState::Committed
                && receipt.activation.state == "applied"
    ));
}

#[test]
fn expired_plan_on_apply_refreshes_the_draft_instead_of_looping_in_recovery() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    let request_id = planned.request.request_id.clone();
    assert!(workflow.finish_plan(planned.ticket, Ok(retained_plan(&planned.request))));
    let apply = workflow.begin_apply().unwrap();
    assert!(workflow.finish_apply(
        apply.ticket,
        Err(remote_error(
            ErrorCode::PlanConflict,
            "plan is unknown or expired"
        ))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::RefreshAndRedraft,
            draft: Some(draft),
            ..
        }) if draft.request.request_id == request_id
    ));
    assert!(workflow.begin_replay().is_none());
    assert!(workflow.begin_exact_apply().is_none());
}

#[test]
fn unknown_operation_after_submission_stays_recoverable_and_ignores_stale_completions() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    let request_id = planned.request.request_id.clone();
    assert!(workflow.finish_plan(planned.ticket, Ok(retained_plan(&planned.request))));
    let apply = workflow.begin_apply().unwrap();
    let mut pending = receipt(&request_id, "operation-unknown", "pending");
    pending.persistence = PersistenceState::Prepared;
    assert!(workflow.finish_apply(apply.ticket, Ok(pending)));
    let lookup = workflow.begin_operation_lookup().unwrap();
    let foreign = WorkflowTicket {
        generation: lookup.ticket.generation + 1,
    };
    assert!(!workflow.finish_operation_lookup(
        foreign,
        Err(remote_error(ErrorCode::NotFound, "operation is unknown"))
    ));
    assert!(workflow.finish_operation_lookup(
        lookup.ticket,
        Err(remote_error(ErrorCode::NotFound, "operation is unknown"))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::RetryExactApply,
            error: Some(error),
            draft: Some(_),
            plan: Some(_),
            ..
        }) if error.code() == ErrorCode::NotFound
    ));
    let retry = workflow.begin_exact_apply().unwrap();
    assert_eq!(retry.request.request_id, request_id);
}

#[tokio::test]
async fn submitted_journal_survives_quit_with_the_exact_request_and_plan() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    let plan = retained_plan(&planned.request);
    let request = planned.request.clone();
    recovery::begin_submitted(
        config_path.clone(),
        PolicyOrigin::Mount,
        request.clone(),
        plan.clone(),
        None,
        None,
    )
    .await
    .unwrap();

    let loaded = recovery::load(config_path).await.unwrap().unwrap();
    let recovery::JournalState::Submitted {
        request: saved,
        apply,
        operation_id,
        ..
    } = loaded
    else {
        panic!("submitted intent was not retained")
    };
    assert_eq!(saved, request);
    assert_eq!(
        apply.retained_plan(),
        RetainedPlan {
            impact_rows: Vec::new(),
            next_impact_cursor: None,
            ..plan
        }
    );
    assert!(operation_id.is_none());
}

#[tokio::test]
async fn startup_capability_failure_retains_exact_retry_and_forbids_close() {
    // Includes the 0.42.0 `query_rules` origin a journal may still carry.
    for origin in [
        PolicyOrigin::Mount,
        PolicyOrigin::QueryBatch {
            targets: vec![crate::tui::query_rule_batch::HeldTarget {
                domain: "ciao.it".into(),
                action: RuleAction::Deny,
                list_id: "local".into(),
            }],
        },
        PolicyOrigin::QueryRules {
            ids: vec!["local".into()],
            already_present: vec![false],
        },
    ] {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        let socket = root.path().join("missing.sock");
        let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
        let planned = workflow.begin_plan().unwrap();
        recovery::begin_submitted(
            config_path.clone(),
            origin.clone(),
            planned.request.clone(),
            retained_plan(&planned.request),
            None,
            None,
        )
        .await
        .unwrap();

        let (connected, action, error, close_allowed, resumed) =
            super::controller::startup_resume_probe(socket, config_path)
                .await
                .unwrap();
        assert!(!connected);
        assert_eq!(action, RecoveryAction::RetryExactApply, "{origin:?}");
        assert_eq!(error, Some(ErrorCode::StorageUnavailable));
        assert!(!close_allowed);
        assert_eq!(resumed, origin);
    }
}

/// Quitting while a held-rule batch Apply is pending must not claim the
/// rules were not applied: the batch may still commit and resumes on start.
#[tokio::test]
async fn quit_during_pending_query_batch_apply_never_claims_not_applied() {
    use crate::tui::query_rule_batch::{HeldTarget, Review};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let targets = vec![HeldTarget {
        domain: "ciao.it".into(),
        action: RuleAction::Deny,
        list_id: "local".into(),
    }];
    let mut planned = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let attempt = planned.begin_plan().unwrap();
    assert!(planned.finish_plan(attempt.ticket, Ok(retained_plan(&attempt.request))));
    let mut applying = planned.clone();
    let apply = applying.begin_apply().unwrap();
    let mut unresolved = applying.clone();
    assert!(unresolved.finish_apply(
        apply.ticket,
        Err(transport_error("daemon closed connection without response"))
    ));
    for (workflow, pending, busy) in [
        (planned, false, false),
        (applying, true, true),
        (unresolved, true, false),
    ] {
        let mut app = crate::tui::App::known_standalone_for_test();
        app.query_log.held.targets = targets.clone();
        if busy {
            // A running Apply holds the busy footer, so q takes the busy route.
            app.pending_action = Some(crate::tui::actions::PendingAction {
                id: 1,
                surface: crate::tui::actions::Surface::Global,
                label: "Applying policy change".into(),
                detached: false,
                written: None,
            });
        }
        app.operator_policy = Some(PolicyDialog {
            id: 1,
            origin: PolicyOrigin::QueryBatch {
                targets: targets.clone(),
            },
            workflow: Some(workflow),
            adapter: None,
            preparing: false,
            preparation_error: None,
            prefix_outcome: None,
            discard_operations: None,
        });
        assert!(
            !crate::tui::handle_key(
                &mut app,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &crate::tui::IpcPoller::new(Path::new("/tmp/qrb-no.sock")),
                Path::new("/tmp/qrb-config.toml"),
            )
            .await
        );
        assert_eq!(app.query_log.held.review, Some(Review::Quit));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                crate::tui::ui::render(frame, &mut app);
                crate::tui::actions::render_saving(frame, &app);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = buffer
            .content()
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>() + "\n")
            .collect();
        assert!(text.contains("QUIT AND DISCARD HELD RULES?"), "{text}");
        if busy {
            // The confirmation owns the keys: the busy footer keeps only its label.
            let footer = text.lines().nth(23).unwrap_or_default();
            assert!(footer.contains("Applying policy change"), "{footer}");
            assert!(!footer.contains("quit"), "{footer}");
        }
        assert_eq!(text.contains("not applied"), !pending, "{text}");
        assert_eq!(
            text.contains("1 rule held · Apply submitted, outcome unresolved"),
            pending,
            "{text}"
        );
        assert_eq!(
            text.contains("Quitting may not stop it; the next start resolves the outcome."),
            pending,
            "{text}"
        );
    }
}

#[tokio::test]
async fn only_terminal_receipt_evidence_clears_the_journal() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    let request = planned.request.clone();
    recovery::begin_submitted(
        config_path.clone(),
        PolicyOrigin::Mount,
        request.clone(),
        retained_plan(&request),
        None,
        None,
    )
    .await
    .unwrap();
    recovery::observe_receipt(
        config_path.clone(),
        request.request_id.clone(),
        "operation-queued".into(),
        PersistenceState::Prepared,
    )
    .await
    .unwrap();
    assert!(matches!(
        recovery::load(config_path.clone()).await.unwrap(),
        Some(recovery::JournalState::Submitted {
            operation_id: Some(operation_id),
            ..
        }) if operation_id == "operation-queued"
    ));
    recovery::observe_receipt(
        config_path.clone(),
        request.request_id,
        "operation-queued".into(),
        PersistenceState::Aborted,
    )
    .await
    .unwrap();
    assert!(recovery::load(config_path).await.unwrap().is_none());
}

#[tokio::test]
async fn explicit_discard_clears_only_the_exact_never_submitted_mount_suffix() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: false,
    };
    let prefix = ProfilePrefix {
        profile_id: "default".into(),
        patch: Default::default(),
    };
    recovery::begin_property(
        config_path.clone(),
        origin,
        vec![operation()],
        prefix.clone(),
    )
    .await
    .unwrap();
    recovery::property_committed(
        config_path.clone(),
        prefix.clone(),
        "properties saved".into(),
    )
    .await
    .unwrap();
    let committed_origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: true,
    };

    let mut wrong_prefix = prefix.clone();
    wrong_prefix.profile_id = "other".into();
    assert_eq!(
        recovery::discard_property_committed(
            config_path.clone(),
            committed_origin.clone(),
            vec![operation()],
            wrong_prefix,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::RecoveryConflict
    );
    assert!(matches!(
        recovery::load(config_path.clone()).await.unwrap(),
        Some(recovery::JournalState::PropertyCommitted { .. })
    ));

    let wrong_operations = vec![Operation::AddDomainRule {
        id: "local".into(),
        domain: "different.invalid".into(),
        action: RuleAction::Deny,
    }];
    assert_eq!(
        recovery::discard_property_committed(
            config_path.clone(),
            committed_origin.clone(),
            wrong_operations,
            prefix.clone(),
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::RecoveryConflict
    );

    recovery::discard_property_committed(
        config_path.clone(),
        committed_origin,
        vec![operation()],
        prefix,
    )
    .await
    .unwrap();
    assert!(recovery::load(config_path).await.unwrap().is_none());
}

#[tokio::test]
async fn discard_refuses_pending_and_submitted_unknown_intents() {
    let pending_root = tempfile::tempdir().unwrap();
    let pending_path = pending_root.path().join("config.toml");
    let pending_origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: false,
    };
    let prefix = ProfilePrefix {
        profile_id: "default".into(),
        patch: Default::default(),
    };
    recovery::begin_property(
        pending_path.clone(),
        pending_origin.clone(),
        vec![operation()],
        prefix.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        recovery::discard_property_committed(
            pending_path.clone(),
            pending_origin,
            vec![operation()],
            prefix,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::RecoveryConflict
    );
    assert!(matches!(
        recovery::load(pending_path).await.unwrap(),
        Some(recovery::JournalState::PropertyPending { .. })
    ));

    let submitted_root = tempfile::tempdir().unwrap();
    let submitted_path = submitted_root.path().join("config.toml");
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    recovery::begin_submitted(
        submitted_path.clone(),
        PolicyOrigin::Mount,
        planned.request.clone(),
        retained_plan(&planned.request),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        recovery::discard_property_committed(
            submitted_path.clone(),
            PolicyOrigin::Mount,
            vec![operation()],
            ProfilePrefix {
                profile_id: "default".into(),
                patch: Default::default(),
            },
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::RecoveryConflict
    );
    assert!(matches!(
        recovery::load(submitted_path).await.unwrap(),
        Some(recovery::JournalState::Submitted { .. })
    ));
}

#[tokio::test]
async fn corrupt_symlinked_and_over_permissive_journals_are_refused() {
    async fn seeded() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        let prefix = ProfilePrefix {
            profile_id: "default".into(),
            patch: Default::default(),
        };
        recovery::begin_property(
            config_path.clone(),
            PolicyOrigin::ProfileMounts {
                profile_id: "default".into(),
                properties_committed: false,
            },
            vec![operation()],
            prefix,
        )
        .await
        .unwrap();
        let entry = recovery::entry_path(&config_path);
        (root, config_path, entry)
    }

    let (_root, config_path, entry) = seeded().await;
    std::fs::write(&entry, b"{not-json").unwrap();
    assert_eq!(
        recovery::load(config_path).await.unwrap_err().code(),
        ErrorCode::RecoveryConflict
    );

    let (root, config_path, entry) = seeded().await;
    std::fs::remove_file(&entry).unwrap();
    let target = root.path().join("attacker-journal");
    std::fs::write(&target, b"{}").unwrap();
    symlink(&target, &entry).unwrap();
    assert_eq!(
        recovery::load(config_path).await.unwrap_err().code(),
        ErrorCode::StorageUnavailable
    );

    let (_root, config_path, entry) = seeded().await;
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        recovery::load(config_path).await.unwrap_err().code(),
        ErrorCode::StorageUnavailable
    );
}

fn exact_retry_after(error: AdapterError) -> OperatorPolicyWorkflow {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    assert!(workflow.finish_plan(planned.ticket, Ok(retained_plan(&planned.request))));
    let apply = workflow.begin_apply().unwrap();
    assert!(workflow.finish_apply(
        apply.ticket,
        Err(transport_error("daemon closed connection without response"))
    ));
    let retry = workflow.begin_exact_apply().unwrap();
    assert!(workflow.finish_exact_apply(retry.ticket, Err(error)));
    workflow
}

#[test]
fn exact_retry_routes_refusals_by_what_they_prove() {
    for (error, expected) in [
        (
            remote_error(ErrorCode::PlanConflict, "plan is unknown or expired"),
            RecoveryAction::RefreshAndRedraft,
        ),
        (
            remote_error(ErrorCode::RevisionConflict, "precondition is stale"),
            RecoveryAction::RefreshAndRedraft,
        ),
        (
            remote_error(ErrorCode::PolicyOwnedByPrimary, "secondary node"),
            RecoveryAction::ReplayRequest,
        ),
        (
            transport_error("daemon closed connection without response"),
            RecoveryAction::RetryExactApply,
        ),
    ] {
        let code = error.code();
        let workflow = exact_retry_after(error);
        assert!(
            matches!(
                &workflow.state,
                WorkflowState::Recovery(RecoveryState { action, draft: Some(_), .. })
                    if *action == expected
            ),
            "{code:?}"
        );
    }
}

#[test]
fn primary_owned_refusal_on_first_apply_returns_to_a_closable_draft() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    assert!(workflow.finish_plan(planned.ticket, Ok(retained_plan(&planned.request))));
    let apply = workflow.begin_apply().unwrap();
    assert!(workflow.finish_apply(
        apply.ticket,
        Err(remote_error(
            ErrorCode::PolicyOwnedByPrimary,
            "secondary node"
        ))
    ));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::ReturnToDraft,
            ..
        })
    ));
    let dialog = PolicyDialog {
        id: 1,
        origin: PolicyOrigin::Mount,
        workflow: Some(workflow),
        adapter: None,
        preparing: false,
        preparation_error: None,
        prefix_outcome: None,
        discard_operations: None,
    };
    assert!(super::controller::dialog_can_close(&dialog));
}

#[test]
fn only_refusals_the_daemon_returns_before_intent_settle_the_journal() {
    let local = |kind, code| AdapterError {
        kind,
        error: OperatorRulesError::new(code, "local"),
    };
    for (error, first_send, expected) in [
        (
            remote_error(ErrorCode::PolicyOwnedByPrimary, "secondary"),
            true,
            true,
        ),
        (
            remote_error(ErrorCode::PolicyOwnedByPrimary, "secondary"),
            false,
            false,
        ),
        (remote_error(ErrorCode::PlanConflict, "expired"), true, true),
        (
            remote_error(ErrorCode::PlanConflict, "expired"),
            false,
            true,
        ),
        (
            remote_error(ErrorCode::RevisionConflict, "stale"),
            false,
            true,
        ),
        (
            remote_error(ErrorCode::AdmissionRejected, "capacity"),
            true,
            false,
        ),
        (
            remote_error(ErrorCode::IdempotencyConflict, "reused"),
            true,
            false,
        ),
        (transport_error("closed"), true, false),
        (
            local(AdapterErrorKind::Transport, ErrorCode::PlanConflict),
            true,
            false,
        ),
        (
            local(AdapterErrorKind::Protocol, ErrorCode::PlanConflict),
            true,
            false,
        ),
        (
            local(AdapterErrorKind::Protocol, ErrorCode::RevisionConflict),
            true,
            false,
        ),
    ] {
        assert_eq!(
            super::workflow::refused_before_intent(&error, first_send),
            expected,
            "{:?} {:?} first_send={first_send}",
            error.kind,
            error.code()
        );
    }
}

async fn submitted_with(
    config_path: &Path,
    prefix: Option<ProfilePrefix>,
) -> crate::operator_rules::BatchRequest {
    let origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: true,
    };
    if let Some(prefix) = &prefix {
        recovery::begin_property(
            config_path.to_path_buf(),
            PolicyOrigin::ProfileMounts {
                profile_id: "default".into(),
                properties_committed: false,
            },
            vec![operation()],
            prefix.clone(),
        )
        .await
        .unwrap();
        recovery::property_committed(
            config_path.to_path_buf(),
            prefix.clone(),
            "properties saved".into(),
        )
        .await
        .unwrap();
    }
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    recovery::begin_submitted(
        config_path.to_path_buf(),
        origin,
        planned.request.clone(),
        retained_plan(&planned.request),
        prefix,
        Some("properties saved".into()),
    )
    .await
    .unwrap();
    planned.request
}

#[tokio::test]
async fn refused_submission_settles_the_journal_for_a_fresh_plan() {
    let prefix = ProfilePrefix {
        profile_id: "default".into(),
        patch: Default::default(),
    };
    for prefix in [None, Some(prefix)] {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        let request = submitted_with(&config_path, prefix.clone()).await;
        recovery::settle_refused(config_path.clone(), request.request_id)
            .await
            .unwrap();
        match &prefix {
            None => assert!(recovery::load(config_path.clone()).await.unwrap().is_none()),
            Some(_) => assert!(matches!(
                recovery::load(config_path.clone()).await.unwrap(),
                Some(recovery::JournalState::PropertyCommitted { message, .. })
                    if message == "properties saved"
            )),
        }
        // The re-planned request (new identity, same suffix) is accepted.
        let mut workflow = OperatorPolicyWorkflow::new("b".repeat(64), vec![operation()]).unwrap();
        let replanned = workflow.begin_plan().unwrap();
        recovery::begin_submitted(
            config_path,
            PolicyOrigin::ProfileMounts {
                profile_id: "default".into(),
                properties_committed: true,
            },
            replanned.request.clone(),
            retained_plan(&replanned.request),
            prefix,
            Some("properties saved".into()),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn refusal_settles_only_the_exact_unacknowledged_submission() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let request = submitted_with(&config_path, None).await;
    assert_eq!(
        recovery::settle_refused(config_path.clone(), "other-request".into())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    assert!(matches!(
        recovery::load(config_path.clone()).await.unwrap(),
        Some(recovery::JournalState::Submitted {
            operation_id: None,
            ..
        })
    ));

    recovery::observe_receipt(
        config_path.clone(),
        request.request_id.clone(),
        "operation-queued".into(),
        PersistenceState::Prepared,
    )
    .await
    .unwrap();
    assert_eq!(
        recovery::settle_refused(config_path.clone(), request.request_id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::RecoveryConflict
    );
    assert!(matches!(
        recovery::load(config_path).await.unwrap(),
        Some(recovery::JournalState::Submitted {
            operation_id: Some(_),
            ..
        })
    ));
}

#[tokio::test]
async fn primary_owned_refusal_of_a_retry_keeps_the_submitted_intent() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let request = submitted_with(&config_path, None).await;
    let refused = Err(remote_error(ErrorCode::PolicyOwnedByPrimary, "secondary"));
    assert!(
        super::controller::observe_submit(config_path.clone(), &request, &refused, false)
            .await
            .is_none()
    );
    assert!(matches!(
        recovery::load(config_path.clone()).await.unwrap(),
        Some(recovery::JournalState::Submitted {
            operation_id: None,
            ..
        })
    ));
    assert!(
        super::controller::observe_submit(config_path.clone(), &request, &refused, true)
            .await
            .is_none()
    );
    assert!(recovery::load(config_path).await.unwrap().is_none());
}

fn display_name_prefix() -> ProfilePrefix {
    ProfilePrefix {
        profile_id: "default".into(),
        patch: crate::ipc::protocol::ProfileUpdatePatch {
            display_name: Some("Renamed".into()),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn property_update_that_never_reached_the_daemon_clears_the_pending_journal() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let socket = root.path().join("missing.sock");
    register_test_token(&socket, "t");
    let origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: false,
    };
    let (error, properties_committed) = super::controller::prepare_profile_probe(
        socket,
        config_path.clone(),
        origin,
        vec![operation()],
        display_name_prefix(),
    )
    .await
    .unwrap();
    assert!(!properties_committed);
    assert!(
        error.starts_with("profile properties were not applied: "),
        "{error}"
    );
    assert!(error.contains("os error 2"), "{error}");
    assert!(
        !error.contains(crate::ipc::auth_token::NO_TOKEN_FILE_MSG),
        "{error}"
    );
    assert!(recovery::load(config_path.clone()).await.unwrap().is_none());

    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    recovery::begin_submitted(
        config_path,
        PolicyOrigin::Mount,
        planned.request.clone(),
        retained_plan(&planned.request),
        None,
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn abandon_clears_only_the_exact_pending_property_intent() {
    let origin = PolicyOrigin::ProfileMounts {
        profile_id: "default".into(),
        properties_committed: false,
    };
    let other_operation = Operation::AddDomainRule {
        id: "local".into(),
        domain: "different.invalid".into(),
        action: RuleAction::Deny,
    };
    let mut other_prefix = display_name_prefix();
    other_prefix.patch.display_name = Some("Other".into());
    for (expected_origin, expected_operations, expected_prefix) in [
        (
            PolicyOrigin::Mount,
            vec![operation()],
            display_name_prefix(),
        ),
        (origin.clone(), vec![other_operation], display_name_prefix()),
        (origin.clone(), vec![operation()], other_prefix),
    ] {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        recovery::begin_property(
            config_path.clone(),
            origin.clone(),
            vec![operation()],
            display_name_prefix(),
        )
        .await
        .unwrap();
        assert_eq!(
            recovery::abandon_property_pending(
                config_path.clone(),
                expected_origin,
                expected_operations,
                expected_prefix,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::RecoveryConflict
        );
        assert!(matches!(
            recovery::load(config_path).await.unwrap(),
            Some(recovery::JournalState::PropertyPending { .. })
        ));
    }
}
