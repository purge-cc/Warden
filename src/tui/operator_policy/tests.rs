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
fn replay_not_found_remains_unknown_and_returns_to_exact_apply() {
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    let request_id = planned.request.request_id.clone();
    assert!(workflow.finish_plan(planned.ticket, Ok(retained_plan(&planned.request))));
    let apply = workflow.begin_apply().unwrap();
    assert!(workflow.finish_apply(
        apply.ticket,
        Err(remote_error(
            ErrorCode::PlanConflict,
            "retained plan expired"
        ))
    ));
    let replay = workflow.begin_replay().unwrap();
    assert_eq!(replay.request.request_id, request_id);
    assert!(workflow.finish_replay(
        replay.ticket,
        Err(remote_error(
            ErrorCode::NotFound,
            "receipt is not durable yet"
        ))
    ));
    let exact = workflow.begin_exact_apply().unwrap();
    assert_eq!(exact.request.request_id, request_id);
    assert_eq!(exact.plan.request_id, request_id);
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
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("config.toml");
    let socket = root.path().join("missing.sock");
    let mut workflow = OperatorPolicyWorkflow::new("a".repeat(64), vec![operation()]).unwrap();
    let planned = workflow.begin_plan().unwrap();
    recovery::begin_submitted(
        config_path.clone(),
        PolicyOrigin::Mount,
        planned.request.clone(),
        retained_plan(&planned.request),
        None,
        None,
    )
    .await
    .unwrap();

    let (connected, action, error, close_allowed) =
        super::controller::startup_resume_probe(socket, config_path)
            .await
            .unwrap();
    assert!(!connected);
    assert_eq!(action, RecoveryAction::RetryExactApply);
    assert_eq!(error, Some(ErrorCode::StorageUnavailable));
    assert!(!close_allowed);
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
