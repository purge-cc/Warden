//! Drive production dispatch/result application with initialized background jobs.
use super::*;
use jobs::{ReadReason, ReadRequest, ReadResource, ReadTask, ReadValue};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

fn runtime(leaf: Leaf) -> (App, Arc<IpcPoller>, UnboundedReceiver<app::UiJob>) {
    let poller = Arc::new(IpcPoller::new(Path::new("unused-runtime-fixture.sock")));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut app = App::new();
    app.active_leaf = leaf;
    app.job_tx = Some(tx);
    app.read_jobs = Some(jobs::ReadScheduler::new(Arc::clone(&poller)));
    (app, poller, rx)
}

async fn key(app: &mut App, poller: &IpcPoller, code: KeyCode) -> bool {
    let quit = handle_key(
        app,
        KeyEvent::new(code, KeyModifiers::NONE),
        poller,
        Path::new("unused.toml"),
    )
    .await;
    reads::flush_explicit(app);
    quit
}

fn take(app: &mut App) -> ReadTask {
    let mut tasks = app.read_jobs.as_mut().unwrap().take_ready();
    let selected = tasks
        .iter()
        .position(|task| !fixture_side_read(task.resource()))
        .expect("expected one leaf-owned read");
    let task = tasks.swap_remove(selected);
    assert!(
        tasks.iter().all(|task| fixture_side_read(task.resource())),
        "only independent catalog and node-status reads may accompany this fixture"
    );
    task
}

fn fixture_side_read(resource: ReadResource) -> bool {
    match resource {
        ReadResource::OperatorCatalog => true,
        #[cfg(feature = "cluster")]
        ReadResource::NodesStatus | ReadResource::NodeControlStatus => true,
        _ => false,
    }
}

async fn deliver(
    app: &mut App,
    rx: &mut UnboundedReceiver<app::UiJob>,
    task: ReadTask,
    result: Result<ReadValue, String>,
) {
    app.job_tx
        .as_ref()
        .unwrap()
        .send(app::UiJob::ReadFinished(task.complete_for_test(result)))
        .unwrap();
    apply_job_result(app, rx.recv().await.unwrap());
}

fn row(domain: &str) -> crate::ipc::protocol::QueryLogDto {
    crate::ipc::protocol::QueryLogDto {
        timestamp: "2026-09-08T12:00:00Z".into(),
        client_ip: "192.0.2.2".into(),
        client_name: None,
        domain: domain.into(),
        query_type: "A".into(),
        result: "BLOCKED".into(),
        response_time_us: 1,
        cname_chain_via: None,
    }
}

fn page(domain: &str) -> ReadValue {
    ReadValue::QueryLog(ipc_poller::QueryLogPollResult {
        entries: vec![row(domain)],
        logging_enabled: true,
        file_state: crate::ipc::protocol::QueryLogFileState::Ok,
        next_cursor: None,
        cursor_stale: false,
    })
}

fn cursor() -> crate::tracking::query_log::QueryLogCursor {
    crate::tracking::query_log::QueryLogCursor {
        file: "query.log".into(),
        inode: 1,
        offset: 42,
    }
}

#[tokio::test]
async fn runtime_filter_supersedes_inflight_success_and_error_while_paused() {
    for old in [Ok(page("old.test")), Err("obsolete failure".into())] {
        let (mut app, poller, mut rx) = runtime(Leaf::QueryLog);
        app.paused = true;
        poll_active_leaf(&mut app, &poller).await;
        let a = take(&mut app);
        key(&mut app, &poller, KeyCode::Char('f')).await;
        for _ in 0..3 {
            key(&mut app, &poller, KeyCode::Tab).await;
        }
        key(&mut app, &poller, KeyCode::Enter).await;
        assert!(app.query_log.blocked_only);
        assert!(app.query_log.entries.is_empty());
        app.read_jobs.as_mut().unwrap().pause_automatic();
        assert!(app.read_jobs.as_mut().unwrap().take_ready().is_empty());
        deliver(&mut app, &mut rx, a, old).await;
        assert!(app.query_log.entries.is_empty());
        assert!(!app
            .status_text()
            .unwrap_or_default()
            .contains("obsolete failure"));
        let b = take(&mut app);
        deliver(&mut app, &mut rx, b, Ok(page("blocked.test"))).await;
        assert_eq!(app.query_log.entries[0].domain, "blocked.test");
        assert!(app.paused);
    }
}

#[tokio::test]
async fn runtime_double_end_page_down_never_reuses_one_cursor_for_two_pages() {
    let (mut app, poller, mut rx) = runtime(Leaf::QueryLog);
    app.paused = true;
    app.query_log.entries = vec![row("tail.test")];
    app.query_log.next_cursor = Some(cursor());
    key(&mut app, &poller, KeyCode::End).await;
    key(&mut app, &poller, KeyCode::PageDown).await;
    let first = take(&mut app);
    assert_eq!(app.query_log.page_index, 1);
    assert!(app.query_log.entries.is_empty());
    assert!(app.query_log.next_cursor.is_none());
    key(&mut app, &poller, KeyCode::End).await;
    key(&mut app, &poller, KeyCode::PageDown).await;
    assert_eq!(app.query_log.page_index, 1);
    assert_eq!(app.query_log.page_cursors, vec![None, Some(cursor())]);
    assert!(app.read_jobs.as_mut().unwrap().take_ready().is_empty());
    deliver(&mut app, &mut rx, first, Ok(page("older.test"))).await;
    assert_eq!(app.query_log.entries[0].domain, "older.test");
}

#[tokio::test]
async fn runtime_page_down_then_up_rejects_late_page_one() {
    let (mut app, poller, mut rx) = runtime(Leaf::QueryLog);
    app.paused = true;
    app.query_log.entries = vec![row("tail.test")];
    app.query_log.next_cursor = Some(cursor());
    key(&mut app, &poller, KeyCode::End).await;
    key(&mut app, &poller, KeyCode::PageDown).await;
    let older = take(&mut app);
    key(&mut app, &poller, KeyCode::PageUp).await;
    assert_eq!(app.query_log.page_index, 0);
    assert!(app.query_log.entries.is_empty());
    assert!(app.query_log.next_cursor.is_none());
    deliver(&mut app, &mut rx, older, Ok(page("obsolete-older.test"))).await;
    assert!(app.query_log.entries.is_empty());
    let tail = take(&mut app);
    deliver(&mut app, &mut rx, tail, Ok(page("fresh-tail.test"))).await;
    assert_eq!(app.query_log.entries[0].domain, "fresh-tail.test");
}

#[tokio::test]
async fn runtime_devices_subnets_share_one_resource_and_heartbeat_is_independent() {
    let (mut app, poller, mut rx) = runtime(Leaf::Devices);
    poll_active_leaf(&mut app, &poller).await;
    let devices = take(&mut app);
    app.active_leaf = Leaf::Subnets;
    poll_active_leaf(&mut app, &poller).await;
    assert!(app.read_jobs.as_mut().unwrap().take_ready().is_empty());
    poll_heartbeat(&mut app, &poller).await;
    let status = take(&mut app);
    deliver(
        &mut app,
        &mut rx,
        status,
        Ok(ReadValue::Status(Box::default())),
    )
    .await;
    assert!(app.connected);
    deliver(
        &mut app,
        &mut rx,
        devices,
        Err("stale devices error".into()),
    )
    .await;
    assert!(app.connected);
    let subnets = take(&mut app);
    deliver(
        &mut app,
        &mut rx,
        subnets,
        Err("subnets current error".into()),
    )
    .await;
    assert_eq!(app.status_text(), Some("subnets current error"));
}

#[tokio::test]
async fn runtime_poll_errors_recover_per_resource_and_preserve_action_errors() {
    let (mut app, _, mut rx) = runtime(Leaf::Dashboard);
    app.read_jobs
        .as_mut()
        .unwrap()
        .request(ReadRequest::Tracking, ReadReason::Automatic);
    let tracking = take(&mut app);
    deliver(&mut app, &mut rx, tracking, Err("tracking failed".into())).await;
    app.read_jobs
        .as_mut()
        .unwrap()
        .request(ReadRequest::Status, ReadReason::Automatic);
    let status = take(&mut app);
    deliver(
        &mut app,
        &mut rx,
        status,
        Ok(ReadValue::Status(Box::default())),
    )
    .await;
    assert_eq!(app.status_text(), Some("tracking failed"));
    app.read_jobs
        .as_mut()
        .unwrap()
        .invalidate(ReadResource::Tracking);
    reads::refresh_status(&mut app);
    assert_eq!(app.status_text(), Some("tracking failed"));
    app.read_jobs
        .as_mut()
        .unwrap()
        .request(ReadRequest::Tracking, ReadReason::Automatic);
    let recovery = take(&mut app);
    deliver(
        &mut app,
        &mut rx,
        recovery,
        Ok(ReadValue::Tracking(Box::default())),
    )
    .await;
    assert!(app.status_text().is_none());
    app.status_err("save failed".into());
    app.read_jobs
        .as_mut()
        .unwrap()
        .request(ReadRequest::Status, ReadReason::Automatic);
    let status = take(&mut app);
    deliver(&mut app, &mut rx, status, Err("status failed".into())).await;
    assert_eq!(app.status_text(), Some("save failed"));
}

#[tokio::test]
async fn runtime_save_keeps_input_responsive_and_does_not_resurrect_closed_form() {
    let (mut app, poller, mut rx) = runtime(Leaf::Devices);
    app.devices.modal = Some(DeviceModal::Form(DeviceFormState::new_add()));
    let (release, wait) = tokio::sync::oneshot::channel();
    assert!(
        actions::dispatch(
            &mut app,
            actions::Surface::Device,
            "Saving",
            async move {
                wait.await.unwrap();
                "saved device".to_owned()
            },
            |app, attached, message| {
                if attached {
                    app.devices.modal = None;
                }
                app.status_ok(message);
            }
        )
        .await
    );
    assert!(
        !actions::dispatch(
            &mut app,
            actions::Surface::Device,
            "duplicate",
            async { panic!("duplicate must not execute") },
            |_, _, _: ()| {}
        )
        .await
    );
    handle_paste(&mut app, "must not enter form".into());
    let Some(DeviceModal::Form(form)) = &app.devices.modal else {
        panic!("form")
    };
    assert!(form.name.is_empty());
    assert!(
        form.ip.is_empty(),
        "paste must not reach the focused IP field"
    );
    assert!(!key(&mut app, &poller, KeyCode::Esc).await);
    assert!(app.devices.modal.is_none());
    assert!(app.pending_action.is_some());
    key(&mut app, &poller, KeyCode::Tab).await;
    assert_ne!(app.active_leaf, Leaf::Devices);
    assert!(key(&mut app, &poller, KeyCode::Char('q')).await);
    release.send(()).unwrap();
    let completed = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    apply_job_result(&mut app, completed);
    assert!(app.pending_action.is_none());
    assert!(app.devices.modal.is_none());
    assert_eq!(app.status_text(), Some("saved device"));
}

#[tokio::test]
async fn runtime_empty_older_page_refetches_previous_page_while_paused() {
    let (mut app, poller, mut rx) = runtime(Leaf::QueryLog);
    app.paused = true;
    app.query_log.entries = vec![row("tail.test")];
    app.query_log.next_cursor = Some(cursor());
    key(&mut app, &poller, KeyCode::End).await;
    key(&mut app, &poller, KeyCode::PageDown).await;
    assert!(app.query_log.table_state.selected().is_none());
    let older = take(&mut app);
    let ReadValue::QueryLog(mut empty) = page("discard.test") else {
        unreachable!()
    };
    empty.entries.clear();
    deliver(&mut app, &mut rx, older, Ok(ReadValue::QueryLog(empty))).await;
    assert_eq!(app.query_log.page_index, 0);
    assert!(app.query_log.entries.is_empty());
    assert!(reads::flush_explicit(&mut app));
    app.read_jobs.as_mut().unwrap().pause_automatic();
    let previous = take(&mut app);
    deliver(&mut app, &mut rx, previous, Ok(page("refetched-tail.test"))).await;
    assert_eq!(app.query_log.entries[0].domain, "refetched-tail.test");
    assert!(app.paused);
}

#[test]
fn failed_write_keeps_primary_error_alongside_each_reload_failure() {
    use crate::cli::commands::ipc_reload::ReloadOutcome;
    for (reload, detail) in [
        (ReloadOutcome::DaemonUnreachable, "daemon not running"),
        (
            ReloadOutcome::ReloadFailed("bad candidate".into()),
            "bad candidate",
        ),
    ] {
        let mut app = App::new();
        actions::report(
            &mut app,
            actions::WriteResult {
                details: Some(()),
                result: Err("FAILED to restore original record old.home".into()),
                config: None,
                reload: Some(reload),
            },
            "record",
        );
        let status = app.last_status.as_ref().unwrap();
        assert_eq!(status.severity, app::StatusSeverity::Error);
        assert!(status
            .text
            .contains("FAILED to restore original record old.home"));
        assert!(status.text.contains(detail));
        assert!(!status.text.contains("record saved"));
    }
}

#[test]
fn successful_write_is_still_reported_as_saved_when_reload_fails() {
    use crate::cli::commands::ipc_reload::ReloadOutcome;
    for reload in [
        ReloadOutcome::DaemonUnreachable,
        ReloadOutcome::ReloadFailed("rejected".into()),
    ] {
        let mut app = App::new();
        actions::report(
            &mut app,
            actions::WriteResult {
                details: Some(()),
                result: Ok("added old.home".into()),
                config: None,
                reload: Some(reload),
            },
            "record",
        );
        let status = app.last_status.as_ref().unwrap();
        assert_eq!(status.severity, app::StatusSeverity::Error);
        assert!(status.text.contains("added old.home"));
        assert!(status.text.contains("record saved on disk"));
    }
}

#[tokio::test]
async fn runtime_detach_keeps_exact_uor_identity_until_partial_receipt_arrives() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("operator-policy.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (release, wait) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut commands = Vec::new();
        let mut wait = Some(wait);
        for index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            let command: crate::ipc::protocol::IpcCommand = serde_json::from_str(&line).unwrap();
            let response = if index == 0 {
                crate::ipc::protocol::IpcResponse::OperatorRulesCapabilities {
                    capabilities: crate::operator_rules::Capabilities {
                        contract_version: crate::operator_rules::CONTRACT_VERSION,
                        schema_version: 5,
                        operator_rule_grammar: 1,
                        operations: vec!["add_domain_rule".into()],
                        semantic_hash: true,
                        activation_ack: true,
                        cluster_artifact: false,
                        limits: crate::operator_rules::TransportLimits::IPC,
                    },
                }
            } else {
                wait.take().unwrap().await.unwrap();
                let crate::ipc::protocol::IpcCommand::OperatorRulesApply { request_id, .. } =
                    &command
                else {
                    panic!("expected apply command, got {command:?}")
                };
                crate::ipc::protocol::IpcResponse::OperatorRulesApply {
                    receipt: crate::operator_rules::Receipt {
                        contract_version: crate::operator_rules::CONTRACT_VERSION,
                        operation_id: "operation-detached".into(),
                        request_id: request_id.clone(),
                        changed: true,
                        persistence: crate::operator_rules::PersistenceState::Committed,
                        config_revision: "c".repeat(64),
                        operator_policy_hash: Some("e".repeat(64)),
                        activation: crate::operator_rules::Activation {
                            state: "failed".into(),
                            correlation_id: Some("activation-detached".into()),
                            reload_outcome: Some("activation rejected".into()),
                            active_config_revision: None,
                            active_policy_hash: None,
                            daemon_instance_id: None,
                            superseded_by: None,
                        },
                        replication: "not_configured".into(),
                        audit: "recorded".into(),
                        diagnostics: Vec::new(),
                    },
                }
            };
            commands.push(command);
            let mut encoded = serde_json::to_vec(&response).unwrap();
            encoded.push(b'\n');
            stream.write_all(&encoded).await.unwrap();
        }
        commands
    });

    let adapter = operator_policy::OperatorPolicyAdapter::connect_with_token(&socket, "test-token")
        .await
        .unwrap();
    let mut workflow = operator_policy::OperatorPolicyWorkflow::new(
        "a".repeat(64),
        vec![crate::operator_rules::Operation::AddDomainRule {
            id: "local".into(),
            domain: "domain.test".into(),
            action: crate::operator_rules::RuleAction::Allow,
        }],
    )
    .unwrap();
    let planning = workflow.begin_plan().unwrap();
    let request_id = planning.request.request_id.clone();
    let summary = crate::operator_rules::PlanSummary {
        contract_version: crate::operator_rules::CONTRACT_VERSION,
        plan_hash: "b".repeat(64),
        base_config_revision: planning.request.expected_config_revision.clone(),
        candidate_config_revision: "c".repeat(64),
        base_operator_policy_hash: "d".repeat(64),
        candidate_operator_policy_hash: "e".repeat(64),
        semantic_changed: true,
        cosmetic_changed: false,
        changed: true,
        operation_count: 1,
        touched_member_count: 1,
        impacted_profile_count: 0,
        impacted_recipient_count: 0,
        warning_count: 0,
        pack_bytes_after: 24,
        rules_after: 1,
    };
    assert!(workflow.finish_plan(
        planning.ticket,
        Ok(operator_policy::RetainedPlan {
            plan_ref: "plan-detached".into(),
            request_id: request_id.clone(),
            summary,
            impact_rows: Vec::new(),
            next_impact_cursor: None,
        })
    ));

    let recovery_root = tempfile::tempdir().unwrap();
    let recovery_config = recovery_root.path().join("config.toml");
    let (mut app, _, mut rx) = runtime(Leaf::QueryLog);
    app.operator_policy = Some(operator_policy::PolicyDialog {
        id: 1,
        origin: operator_policy::PolicyOrigin::QueryRules {
            ids: vec!["local".into()],
            already_present: vec![false],
        },
        workflow: Some(workflow),
        adapter: Some(adapter),
        preparing: false,
        preparation_error: None,
        prefix_outcome: None,
        discard_operations: None,
    });
    let poller = IpcPoller::new(&socket);
    operator_policy::handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &poller,
        &recovery_config,
    )
    .await;
    actions::detach_presentation(&mut app);
    assert!(app.operator_policy.is_some());
    release.send(()).unwrap();
    apply_job_result(&mut app, rx.recv().await.unwrap());

    let workflow = app
        .operator_policy
        .as_ref()
        .and_then(|dialog| dialog.workflow.as_ref())
        .unwrap();
    assert!(matches!(
        &workflow.state,
        operator_policy::WorkflowState::Outcome { receipt, .. }
            if receipt.persistence == crate::operator_rules::PersistenceState::Committed
                && receipt.activation.state == "failed"
    ));
    let commands = server.await.unwrap();
    assert!(matches!(
        &commands[1],
        crate::ipc::protocol::IpcCommand::OperatorRulesApply {
            request_id: applied,
            ..
        } if applied == &request_id
    ));
    assert!(!commands
        .iter()
        .any(|command| matches!(command, crate::ipc::protocol::IpcCommand::Reload { .. })));
}

#[tokio::test]
async fn runtime_failed_local_dns_compensation_refreshes_and_reloads_after_close() {
    use crate::cli::commands::ipc_reload::ReloadOutcome;
    use crate::cli::commands::local_dns::{remove_inner, LocalRecordScope};
    use crate::config::settings::LocalDnsRecordType;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "default"
[profiles.default]
display_name = "Default"
[[local_dns.records]]
domain = "old.home"
type = "A"
value = "192.0.2.10"
"#,
    )
    .unwrap();
    let (mut app, poller, mut rx) = runtime(Leaf::LocalDns);
    apply_config_snapshot(&mut app, load_config_snapshot(&path));
    let original = app.loaded_config.as_ref().unwrap().config.local_dns.records[0].clone();
    app.local_dns.modal = Some(local_dns_modal::LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &original,
    ));
    let (reload_started_tx, reload_started) = tokio::sync::oneshot::channel();
    let (release_reload, wait_reload) = tokio::sync::oneshot::channel();
    let progress = Some((app.action_serial + 1, app.job_tx.clone().unwrap()));
    actions::dispatch(
        &mut app,
        actions::Surface::LocalDns,
        "Saving record",
        actions::write_with_reload(
            path.clone(),
            async move {
                reload_started_tx.send(()).unwrap();
                wait_reload.await.unwrap();
                ReloadOutcome::DaemonUnreachable
            },
            move |path| {
                // Inject failures at the two add operations after a real durable
                // removal. The production compensation classifier determines
                // changed; success/error text is never used as that predicate.
                remove_inner(
                    path,
                    &LocalRecordScope::Global,
                    "old.home",
                    Some(LocalDnsRecordType::A),
                    None,
                )
                .unwrap();
                let result = local_dns_failed_replacement(
                    anyhow::anyhow!("new add failed"),
                    Err(anyhow::anyhow!("restore disk write failed")),
                );
                assert!(result.changed);
                let local_dns_modal::SubmitOutcome::Failed(error) = result.outcome else {
                    panic!("failure expected")
                };
                (Err(error), result.changed, ())
            },
            progress,
        ),
        |app, attached, result| {
            assert!(!attached);
            actions::report(app, result, "record");
        },
    )
    .await;
    key(&mut app, &poller, KeyCode::Esc).await;
    reload_started.await.unwrap();
    apply_job_result(&mut app, rx.recv().await.unwrap());
    assert!(app
        .pending_action
        .as_ref()
        .unwrap()
        .written
        .as_ref()
        .unwrap()
        .contains("FAILED to restore"));
    assert!(key(&mut app, &poller, KeyCode::Char('q')).await);
    release_reload.send(()).unwrap();
    apply_job_result(&mut app, rx.recv().await.unwrap());
    assert!(app.local_dns.modal.is_none());
    assert!(app
        .loaded_config
        .as_ref()
        .unwrap()
        .config
        .local_dns
        .records
        .is_empty());
    assert!(!app.file.config_text.contains("old.home"));
    let status = app.last_status.as_ref().unwrap();
    assert_eq!(status.severity, app::StatusSeverity::Error);
    for detail in [
        "FAILED to restore",
        "restore disk write failed",
        "daemon not running",
    ] {
        assert!(status.text.contains(detail), "{}", status.text);
    }
}

async fn navigate_during_save_detaches_origin(surface: actions::Surface, leaf: Leaf) {
    for navigation in [
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Char('['),
        KeyCode::Char(']'),
    ] {
        let (mut app, poller, mut rx) = runtime(leaf);
        match surface {
            actions::Surface::Profile => {
                app.profiles.modal = Some(profile_modal::ProfileModal::open_add())
            }
            actions::Surface::Device => {
                app.devices.modal = Some(DeviceModal::Form(DeviceFormState::new_add()))
            }
            _ => unreachable!(),
        }
        let (release, wait) = tokio::sync::oneshot::channel();
        actions::dispatch(
            &mut app,
            surface,
            "Saving",
            async move {
                wait.await.unwrap();
                actions::WriteResult {
                    details: Some(()),
                    config: None,
                    reload: None,
                    result: if surface == actions::Surface::Profile {
                        Err("profile write failed after navigation".into())
                    } else {
                        Ok("device saved after navigation".into())
                    },
                }
            },
            |app, attached, result| {
                assert!(
                    !attached,
                    "navigation must detach before the result arrives"
                );
                actions::report(app, result, "configuration");
            },
        )
        .await;
        let id = app.pending_action.as_ref().unwrap().id;
        assert!(!key(&mut app, &poller, navigation).await);
        assert_ne!(app.active_leaf, leaf);
        assert!(
            app.profiles.modal.is_none(),
            "global overlay must not cover the destination leaf"
        );
        assert!(
            app.devices.modal.is_none(),
            "leaf-owned form must not remain hidden and live"
        );
        let pending = app.pending_action.as_ref().unwrap();
        assert_eq!(
            pending.id, id,
            "navigation must preserve the admitted operation"
        );
        assert!(pending.detached);
        key(&mut app, &poller, KeyCode::Char('a')).await;
        assert_eq!(app.pending_action.as_ref().unwrap().id, id);
        assert!(app.profiles.modal.is_none());
        assert!(app.devices.modal.is_none());
        let back = match navigation {
            KeyCode::Tab => KeyCode::BackTab,
            KeyCode::BackTab => KeyCode::Tab,
            KeyCode::Char('[') => KeyCode::Char(']'),
            KeyCode::Char(']') => KeyCode::Char('['),
            _ => unreachable!(),
        };
        key(&mut app, &poller, back).await;
        assert_eq!(app.active_leaf, leaf);
        assert!(app.pending_action.as_ref().unwrap().detached);
        release.send(()).unwrap();
        let completion = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        apply_job_result(&mut app, completion);
        assert!(app.pending_action.is_none());
        assert!(app.profiles.modal.is_none());
        assert!(app.devices.modal.is_none());
        let status = app.last_status.as_ref().unwrap();
        if surface == actions::Surface::Profile {
            assert_eq!(status.severity, app::StatusSeverity::Error);
            assert_eq!(status.text, "profile write failed after navigation");
        } else {
            assert_eq!(status.severity, app::StatusSeverity::Ok);
            assert_eq!(status.text, "device saved after navigation");
        }
    }
}

#[tokio::test]
async fn runtime_navigation_detaches_global_profile_form_and_retains_late_error() {
    navigate_during_save_detaches_origin(actions::Surface::Profile, Leaf::Profiles).await;
}

#[tokio::test]
async fn runtime_navigation_detaches_device_form_and_retains_late_success() {
    navigate_during_save_detaches_origin(actions::Surface::Device, Leaf::Devices).await;
}
