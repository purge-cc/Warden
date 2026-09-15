//! Isolated regressions for audit R1 and R3–R7. Reload futures are injected;
//! the only socket traffic is the read-only Subnets device-view request.
use super::*;
use crate::ipc::protocol::{DaemonLogDto, DeviceViewDto, IpcCommand, IpcResponse, QueryLogDto};
use crate::operator_rules::{
    Capabilities, ListDetail, Metadata, RuleAction, RuleRow, TransportLimits,
};
use crate::tui::operator_policy::{PolicyCatalog, PolicyRules};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ch(c: char) -> KeyEvent {
    key(KeyCode::Char(c))
}

fn master(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        concat!(
            "schema_version = 5\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "[server]\ndefault_profile = \"default\"\n",
            "[profiles.default]\ndisplay_name = \"Original\"\n",
            "[[custom_lists]]\nid = \"local\"\ndisplay_name = \"Local\"\n",
        ),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("packs")).unwrap();
    std::fs::write(dir.path().join("packs/local.txt"), "||old.example^\n").unwrap();
    path
}

fn ghost(dir: &tempfile::TempDir) -> IpcPoller {
    IpcPoller::new(&dir.path().join("absent.sock"))
}

fn query_entry() -> QueryLogDto {
    QueryLogDto {
        timestamp: "2026-09-08T12:00:00Z".into(),
        client_ip: "192.0.2.2".into(),
        client_name: None,
        domain: "old.example".into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 1,
        cname_chain_via: None,
    }
}

fn custom_list_catalog() -> PolicyCatalog {
    PolicyCatalog {
        capabilities: Capabilities {
            contract_version: crate::operator_rules::CONTRACT_VERSION,
            schema_version: 5,
            operator_rule_grammar: 1,
            operations: vec!["replace_rule".into(), "add_domain_rule".into()],
            semantic_hash: true,
            activation_ack: true,
            cluster_artifact: false,
            limits: TransportLimits::IPC,
        },
        metadata: Metadata {
            contract_version: crate::operator_rules::CONTRACT_VERSION,
            schema_version: 5,
            config_revision: "config-r1".into(),
            desired_operator_policy_hash: "d".repeat(64),
            active_policy: None,
            activation_in_sync: true,
            lists: 1,
            mounted_lists: 0,
            orphan_packs: 0,
        },
        lists: vec![ListDetail {
            id: "local".into(),
            display_name: "Local".into(),
            description: String::new(),
            config_revision: "config-r1".into(),
            pack_revision: "pack-r1".into(),
            bytes: 20,
            rule_count: 1,
            invalid_rows: 0,
            profiles: Vec::new(),
        }],
        orphan_packs: Vec::new(),
    }
}

fn custom_list_rules() -> PolicyRules {
    PolicyRules {
        id: "local".into(),
        config_revision: "config-r1".into(),
        pack_revision: "pack-r1".into(),
        rows: vec![RuleRow {
            line: 1,
            raw: "||old.example^".into(),
            row_ref: "local:pack-r1:1:old".into(),
            rule_key: Some("semantic-hash".into()),
            action: Some(RuleAction::Deny),
            valid: true,
            duplicate: false,
        }],
    }
}

/// Drive the complete dispatcher without allowing a broken search gate to
/// discover credentials when a literal `r` leaks into global refresh.
async fn dispatch(app: &mut App, key: KeyEvent, poller: &IpcPoller, path: &Path) -> bool {
    handle_key_with_reload(app, key, poller, path, async {
        panic!("unexpected reload while entering text")
    })
    .await
}

#[tokio::test]
async fn file_search_captures_shortcuts_paste_and_navigation_until_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    let poller = ghost(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::File;
    refresh_config_caches(&mut app, &path);
    dispatch(&mut app, ch('/'), &poller, &path).await;
    for c in "sqr12345pg?[]".chars() {
        assert!(!dispatch(&mut app, ch(c), &poller, &path).await);
        assert_eq!(app.active_leaf, Leaf::File);
        assert!(app.resolver_modal.is_none());
        assert!(!app.paused && !app.pending_goto && !app.show_help);
        assert!(app.status_text().is_none());
    }
    assert_eq!(app.file.section_jump.as_deref(), Some("sqr12345pg?[]"));
    dispatch(&mut app, key(KeyCode::Tab), &poller, &path).await;
    dispatch(&mut app, key(KeyCode::Esc), &poller, &path).await;
    assert!(app.file.section_jump.is_none());
    dispatch(&mut app, ch('/'), &poller, &path).await;
    handle_paste(&mut app, "ser\nver\t".into());
    assert_eq!(app.file.section_jump.as_deref(), Some("server"));
    dispatch(&mut app, key(KeyCode::Backspace), &poller, &path).await;
    dispatch(&mut app, ch('r'), &poller, &path).await;
    dispatch(&mut app, key(KeyCode::Enter), &poller, &path).await;
    assert!(app.file.section_jump.is_none());
    assert_eq!(
        app.file.scroll_offset,
        file::section_offset(&app.file.config_text, "server").unwrap()
    );
    assert!(dispatch(&mut app, ch('q'), &poller, &path).await);
}

#[tokio::test]
async fn local_dns_paste_matches_keyboard_text_fields_and_ignores_choice_rows() {
    use local_dns_modal::{FormField, Stage};
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    let poller = ghost(&dir);
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::LocalDns;
    refresh_config_caches(&mut app, &path);
    handle_key(&mut app, ch('a'), &poller, &path).await;
    for (field, text) in [
        (FormField::Domain, "nas.example"),
        (FormField::Value, "192.0.2.7"),
        (FormField::Ttl, "120"),
    ] {
        let Stage::EditingForm(form) = &mut app.local_dns.modal.as_mut().unwrap().stage else {
            panic!("form")
        };
        form.focused = field;
        match field {
            FormField::Domain => form.domain.clear(),
            FormField::Value => form.value.clear(),
            FormField::Ttl => form.ttl_input.clear(),
            _ => unreachable!(),
        }
        form.error_message = Some("old error".into());
        handle_paste(&mut app, format!("{text}\r\n"));
        handle_key(&mut app, ch('x'), &poller, &path).await;
        handle_key(&mut app, key(KeyCode::Backspace), &poller, &path).await;
        let Stage::EditingForm(form) = &app.local_dns.modal.as_ref().unwrap().stage else {
            panic!("form")
        };
        let actual = match field {
            FormField::Domain => &form.domain,
            FormField::Value => &form.value,
            FormField::Ttl => &form.ttl_input,
            _ => unreachable!(),
        };
        assert_eq!(actual, text);
        assert!(form.error_message.is_none());
    }
    for field in [
        FormField::RecordType,
        FormField::MatchSubdomains,
        FormField::Profile,
        FormField::Submit,
        FormField::Cancel,
    ] {
        let Stage::EditingForm(form) = &mut app.local_dns.modal.as_mut().unwrap().stage else {
            panic!("form")
        };
        form.focused = field;
        let before = format!("{form:?}");
        handle_paste(&mut app, "y\nq\n".into());
        let Stage::EditingForm(form) = &app.local_dns.modal.as_ref().unwrap().stage else {
            panic!("form")
        };
        assert_eq!(format!("{form:?}"), before);
    }
}

#[test]
fn local_dns_paste_cannot_fill_typed_confirmation_or_hidden_filter() {
    use crate::cli::commands::local_dns::LocalRecordScope;
    use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
    let mut app = App::new();
    app.active_leaf = Leaf::LocalDns;
    let record = LocalDnsRecord {
        domain: "nas.example".into(),
        record_type: LocalDnsRecordType::A,
        value: "192.0.2.7".into(),
        match_subdomains: true,
        ttl_secs: Some(120),
    };
    app.local_dns.modal = Some(local_dns_modal::LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &record,
    ));
    app.input_mode = InputMode::FilterDomain("hidden".into());
    handle_paste(&mut app, "nas.example\ny".into());
    let local_dns_modal::Stage::ConfirmingRemove(confirm) =
        &app.local_dns.modal.as_ref().unwrap().stage
    else {
        panic!("confirm")
    };
    assert!(confirm.buffer.is_empty());
    assert!(matches!(&app.input_mode, InputMode::FilterDomain(text) if text == "hidden"));
}

#[tokio::test]
async fn manual_refresh_updates_document_sections_and_fences_policy_snapshots() {
    for leaf in [Leaf::File, Leaf::CustomLists] {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let mut app = App::known_standalone_for_test();
        app.active_leaf = Leaf::CustomLists;
        refresh_config_caches(&mut app, &path);
        app.operator_catalog = Some(custom_list_catalog());
        app.operator_rules = Some(custom_list_rules());
        reconcile_active_leaf_selection(&mut app);
        let lists = tabs::custom_lists::build_display_rows(&app);
        let selected = tabs::custom_lists::selected_display_row(&app, &lists).unwrap();
        let tabs::custom_lists::CustomListRules::Ready(rows) =
            tabs::custom_lists::display_rule_rows(&app, selected)
        else {
            panic!("matching policy snapshot")
        };
        assert_eq!(rows.len(), 1);
        app.custom_lists.selected_row_ref = Some(("local".into(), rows[0].row_ref.clone()));
        app.active_leaf = leaf;
        let changed = std::fs::read_to_string(&path)
            .unwrap()
            .replace("Original", "Changed")
            + "\n[profiles.extra]\ndisplay_name = \"Extra\"\n";
        std::fs::write(&path, &changed).unwrap();
        handle_key_with_reload(&mut app, ch('r'), &ghost(&dir), &path, async {
            anyhow::bail!("isolated reload failure")
        })
        .await;
        assert_eq!(
            app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
            "Changed"
        );
        assert_eq!(app.file.config_text, changed);
        assert!(app
            .file
            .sections
            .iter()
            .any(|section| section == "profiles.extra"));
        assert!(app.operator_catalog.is_none());
        assert!(app.operator_rules.is_none());
        assert!(app.custom_lists.selected_row_ref.is_none());
        app.active_leaf = Leaf::CustomLists;
        reconcile_active_leaf_selection(&mut app);
        assert_eq!(
            app.loaded_config
                .as_ref()
                .unwrap()
                .config
                .custom_lists
                .len(),
            1,
        );
    }
}

#[tokio::test]
async fn query_log_rule_submit_uses_one_uor_batch_identity_and_no_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    let socket = dir.path().join("operator-policy.sock");
    operator_policy::register_test_token(&socket, "test-token");
    let listener = UnixListener::bind(&socket).unwrap();
    let catalog = custom_list_catalog();
    let server_catalog = catalog.clone();
    let server_rules = custom_list_rules();
    let server = tokio::spawn(async move {
        let mut commands = Vec::new();
        let mut request_id = None;
        for _ in 0..6 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            let command: IpcCommand = serde_json::from_str(&line).unwrap();
            let response = match &command {
                IpcCommand::OperatorRulesCapabilities => IpcResponse::OperatorRulesCapabilities {
                    capabilities: server_catalog.capabilities.clone(),
                },
                IpcCommand::CustomListsMetadata => IpcResponse::CustomListsMetadata {
                    metadata: server_catalog.metadata.clone(),
                },
                IpcCommand::CustomListsRead {
                    request: crate::ipc::protocol::CustomListsReadRequest::List { .. },
                    token: Some(token),
                } => {
                    assert_eq!(token, "test-token");
                    IpcResponse::CustomListsRead {
                        response: crate::ipc::protocol::CustomListsReadResponse::List(
                            crate::operator_rules::ListPage {
                                contract_version: crate::operator_rules::CONTRACT_VERSION,
                                config_revision: server_catalog.metadata.config_revision.clone(),
                                lists: server_catalog.lists.clone(),
                                next_cursor: None,
                                orphan_packs: server_catalog.orphan_packs.clone(),
                            },
                        ),
                    }
                }
                IpcCommand::CustomListsRead {
                    request: crate::ipc::protocol::CustomListsReadRequest::Rules { id, .. },
                    token: Some(token),
                } => {
                    assert_eq!(token, "test-token");
                    IpcResponse::CustomListsRead {
                        response: crate::ipc::protocol::CustomListsReadResponse::Rules(
                            crate::operator_rules::RulePage {
                                contract_version: crate::operator_rules::CONTRACT_VERSION,
                                id: id.clone(),
                                config_revision: server_rules.config_revision.clone(),
                                pack_revision: server_rules.pack_revision.clone(),
                                rows: server_rules.rows.clone(),
                                next_cursor: None,
                            },
                        ),
                    }
                }
                IpcCommand::OperatorRulesPlan {
                    request: Some(request),
                    token: Some(token),
                    ..
                } => {
                    assert_eq!(token, "test-token");
                    request_id = Some(request.request_id.clone());
                    let summary = crate::operator_rules::PlanSummary {
                        contract_version: crate::operator_rules::CONTRACT_VERSION,
                        plan_hash: "b".repeat(64),
                        base_config_revision: request.expected_config_revision.clone(),
                        candidate_config_revision: "c".repeat(64),
                        base_operator_policy_hash: "d".repeat(64),
                        candidate_operator_policy_hash: "e".repeat(64),
                        semantic_changed: true,
                        cosmetic_changed: false,
                        changed: true,
                        operation_count: request.operations.len(),
                        touched_member_count: 1,
                        impacted_profile_count: 0,
                        impacted_recipient_count: 0,
                        warning_count: 0,
                        pack_bytes_after: 32,
                        rules_after: 2,
                    };
                    IpcResponse::OperatorRulesPlan {
                        plan_ref: "plan-1".into(),
                        impact: crate::operator_rules::PlanImpactPage {
                            contract_version: crate::operator_rules::CONTRACT_VERSION,
                            plan_hash: summary.plan_hash.clone(),
                            rows: Vec::new(),
                            next_cursor: None,
                        },
                        summary,
                    }
                }
                IpcCommand::OperatorRulesApply {
                    request_id: applied_id,
                    token: Some(token),
                    ..
                } => {
                    assert_eq!(token, "test-token");
                    assert_eq!(Some(applied_id), request_id.as_ref());
                    IpcResponse::OperatorRulesApply {
                        receipt: crate::operator_rules::Receipt {
                            contract_version: crate::operator_rules::CONTRACT_VERSION,
                            operation_id: "operation-1".into(),
                            request_id: applied_id.clone(),
                            changed: true,
                            persistence: crate::operator_rules::PersistenceState::Committed,
                            config_revision: "c".repeat(64),
                            operator_policy_hash: Some("e".repeat(64)),
                            activation: crate::operator_rules::Activation {
                                state: "failed".into(),
                                correlation_id: Some("activation-1".into()),
                                reload_outcome: Some("reload failed".into()),
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
                }
                other => panic!("unexpected policy command: {other:?}"),
            };
            commands.push(command);
            let mut encoded = serde_json::to_vec(&response).unwrap();
            encoded.push(b'\n');
            stream.write_all(&encoded).await.unwrap();
        }
        commands
    });
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    refresh_config_caches(&mut app, &path);
    app.operator_catalog = Some(catalog);
    let mut modal = query_log_rule_modal::QueryLogRuleModal::open(
        crate::cli::commands::rules::Action::Deny,
        "new.example".into(),
        "192.0.2.2".into(),
        custom_list_rows(&app),
    );
    modal.toggle();
    let poller = IpcPoller::new(&socket);
    action_handlers::query_rules(&mut app, modal, &poller, &path).await;
    assert!(matches!(
        app.operator_policy
            .as_ref()
            .and_then(|dialog| dialog.workflow.as_ref())
            .map(|workflow| &workflow.state),
        Some(operator_policy::WorkflowState::Planned { .. })
    ));
    operator_policy::handle_key(&mut app, key(KeyCode::Enter), &poller, &path).await;
    let commands = server.await.unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|command| matches!(command, IpcCommand::OperatorRulesApply { .. }))
            .count(),
        1
    );
    assert!(!commands
        .iter()
        .any(|command| matches!(command, IpcCommand::Reload { .. })));
    let workflow = app
        .operator_policy
        .as_ref()
        .and_then(|dialog| dialog.workflow.as_ref())
        .unwrap();
    let operator_policy::WorkflowState::Outcome { receipt, .. } = &workflow.state else {
        panic!("the exact request must finish with its receipt");
    };
    assert_eq!(
        receipt.persistence,
        crate::operator_rules::PersistenceState::Committed
    );
    assert_eq!(receipt.activation.state, "failed");
}

#[test]
fn rules_add_hotkey_points_to_custom_lists_without_opening_a_legacy_modal() {
    let mut app = App::new();
    app.active_leaf = Leaf::Rules;

    handle_rules_key(&mut app, ch('a'));

    assert!(app.rules.add_modal.is_none());
    assert_eq!(
        app.status_text(),
        Some(crate::cli::commands::rules::LEGACY_RULES_RETIRED)
    );
}

#[tokio::test]
async fn restored_snapshot_lands_even_when_reload_fails_and_modal_is_closed() {
    use backup_restore_modal::SubmitOutcome;
    for reload_ok in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let archive =
            crate::cli::commands::config::create_backup(&path, Some(&dir.path().join("backups")))
                .unwrap()
                .archive;
        let changed = std::fs::read_to_string(&path)
            .unwrap()
            .replace("Original", "Changed");
        std::fs::write(&path, changed).unwrap();
        std::fs::write(dir.path().join("packs/local.txt"), "||changed.example^\n").unwrap();
        let mut app = App::new();
        app.active_leaf = Leaf::CustomLists;
        refresh_config_caches(&mut app, &path);
        reconcile_active_leaf_selection(&mut app);
        app.profiles.selected_id = Some("removed-profile".into());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        app.job_tx = Some(tx.clone());
        app.read_jobs = Some(jobs::ReadScheduler::new(std::sync::Arc::new(ghost(&dir))));
        app.settings.restore_modal = Some(backup_restore_modal::RestoreModal {
            stage: backup_restore_modal::RestoreStage::Restoring {
                point: backup_restore_modal::RestorePoint {
                    path: archive.clone(),
                    date: "fixture".into(),
                    age: "now".into(),
                    size: "fixture".into(),
                },
            },
        });
        assert!(actions::reserve_external(
            &mut app,
            actions::Surface::Restore,
            "Restoring"
        ));
        // Exercise the real busy input gate before delivering the late result.
        handle_key(&mut app, key(KeyCode::Esc), &ghost(&dir), &path).await;
        assert!(app.settings.restore_modal.is_none());
        assert!(app.pending_action.as_ref().unwrap().detached);
        let restore_path = path.clone();
        let worker = tokio::spawn(async move {
            let (outcome, config, reload_error) =
                execute_restore_with_reload(archive, restore_path, async move {
                    if reload_ok {
                        Ok("reloaded fixture".into())
                    } else {
                        anyhow::bail!("isolated reload failure")
                    }
                })
                .await;
            assert!(
                matches!(&outcome, SubmitOutcome::Ok(message) if reload_ok || message.contains("reload failed"))
            );
            assert!(config.is_some());
            assert_eq!(reload_error.is_none(), reload_ok);
            if !reload_ok {
                assert_eq!(reload_error.as_deref(), Some("isolated reload failure"));
            }
            assert!(tx
                .send(app::UiJob::RestoreFinished {
                    outcome,
                    config,
                    reload_error
                })
                .is_ok());
        });
        let job = tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .unwrap()
            .unwrap();
        worker.await.unwrap();
        assert_eq!(
            load_current_config(&path).unwrap().config.profiles["default"].display_name,
            "Original"
        );
        let restored_text = std::fs::read_to_string(&path).unwrap();
        // Applying the owned snapshot must not read the filesystem again.
        std::fs::rename(&path, dir.path().join("saved-config.toml")).unwrap();
        apply_job_result(&mut app, job);
        assert_eq!(
            app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
            "Original"
        );
        assert_eq!(app.file.config_text, restored_text);
        assert_eq!(app.profiles.selected_id.as_deref(), Some("default"));
        assert!(app.operator_catalog.is_none());
        assert!(app.operator_rules.is_none());
        assert!(app.custom_lists.selected_row_ref.is_none());
        assert!(app.pending_action.is_none());
        assert!(app.settings.restore_modal.is_none());
        let status = app.last_status.as_ref().unwrap();
        assert!(status.text.contains("restored"));
        assert_eq!(
            status.severity,
            if reload_ok {
                app::StatusSeverity::Ok
            } else {
                app::StatusSeverity::Error
            }
        );
        assert_eq!(status.severity.ttl().is_none(), !reload_ok);
        if !reload_ok {
            assert!(status.text.contains("isolated reload failure"));
            assert!(!status.is_expired_at(status.shown_at + Duration::from_secs(60)));
        }
    }
}

#[tokio::test]
async fn failed_restore_preserves_existing_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    let mut app = App::new();
    refresh_config_caches(&mut app, &path);
    let text = app.file.config_text.clone();
    let (outcome, config, reload_error) =
        execute_restore_with_reload(dir.path().join("absent.tar.gz"), path, async {
            panic!("failed restore must not reload")
        })
        .await;
    assert!(matches!(
        outcome,
        backup_restore_modal::SubmitOutcome::Failed(_)
    ));
    assert!(config.is_none());
    apply_job_result(
        &mut app,
        app::UiJob::RestoreFinished {
            outcome,
            config,
            reload_error,
        },
    );
    assert_eq!(app.file.config_text, text);
    assert!(app.loaded_config.is_some());
}

#[tokio::test]
async fn subnets_poll_requests_device_view_and_clears_it_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("devices.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut request)
            .await
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<IpcCommand>(&request).unwrap(),
            IpcCommand::GetAllDevices
        ));
        let response = IpcResponse::DeviceView(DeviceViewDto {
            mapped: vec![],
            unmapped: vec![],
        });
        stream
            .write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes())
            .await
            .unwrap();
    });
    let mut app = App::new();
    app.active_leaf = Leaf::Subnets;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_active_leaf(&mut app, &IpcPoller::new(&socket)),
    )
    .await
    .unwrap();
    assert!(app.device_view.is_some());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    poll_active_leaf(&mut app, &ghost(&dir)).await;
    assert!(app.device_view.is_none());
    assert!(app.status_text().is_some());
}

#[tokio::test]
async fn every_applied_simple_query_filter_clears_old_rows_and_fetches_while_paused() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    for (actions, input, reset_all) in [
        (
            vec![
                ch('f'),
                key(KeyCode::Tab),
                key(KeyCode::Tab),
                key(KeyCode::Tab),
                key(KeyCode::Enter),
            ],
            InputMode::Normal,
            false,
        ),
        // Period is a draft picker; only its Apply action owns the
        // cursor-reset/fetch contract.
        (
            vec![
                ch('f'),
                key(KeyCode::Tab),
                key(KeyCode::Tab),
                key(KeyCode::Enter),
                key(KeyCode::Down),
                key(KeyCode::Enter),
            ],
            InputMode::Normal,
            false,
        ),
        (
            vec![ch('f'), key(KeyCode::End), key(KeyCode::Enter)],
            InputMode::Normal,
            true,
        ),
        (
            vec![key(KeyCode::Enter)],
            InputMode::FilterDomain("new.example".into()),
            false,
        ),
        (
            vec![key(KeyCode::Enter)],
            InputMode::FilterDomain(String::new()),
            false,
        ),
        (
            vec![key(KeyCode::Enter)],
            InputMode::FilterClient("new client".into()),
            false,
        ),
        (
            vec![key(KeyCode::Enter)],
            InputMode::FilterClient(String::new()),
            false,
        ),
    ] {
        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        app.paused = true;
        app.input_mode = input;
        app.query_log.filter_domain = Some("old.example".into());
        app.query_log.filter_client = Some("old client".into());
        app.query_log.entries = vec![query_entry()];
        app.query_log.table_state.select(Some(0));
        app.query_log.selected_key = Some(tabs::query_log::entry_key(&app.query_log.entries[0]));
        app.query_log.page_index = 2;
        for action in actions {
            handle_key(&mut app, action, &ghost(&dir), &path).await;
        }
        assert!(app.paused && app.force_poll);
        assert!(app.query_log.entries.is_empty());
        assert!(app.query_log.selected_key.is_none());
        assert!(app.query_log.table_state.selected().is_none());
        assert_eq!(app.query_log.page_index, 0);
        assert_eq!(app.query_log.page_cursors, vec![None]);
        if reset_all {
            assert!(app.query_log.filter_domain.is_none() && app.query_log.filter_client.is_none());
        }
    }
}

#[tokio::test]
async fn every_applied_logs_filter_clears_old_rows_and_fetches_while_paused() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    for (actions, input) in [
        (
            vec![
                ch('f'),
                key(KeyCode::Right),
                key(KeyCode::Enter),
                key(KeyCode::Down),
                key(KeyCode::Enter),
            ],
            InputMode::Normal,
        ),
        (
            vec![ch('f'), key(KeyCode::End), key(KeyCode::Enter)],
            InputMode::Normal,
        ),
        (
            vec![key(KeyCode::Enter)],
            InputMode::FilterLogs("new message".into()),
        ),
    ] {
        let mut app = App::new();
        app.active_leaf = Leaf::Logs;
        app.paused = true;
        app.input_mode = input;
        app.logs.entries = vec![DaemonLogDto {
            timestamp: "2026-09-08T12:00:00Z".into(),
            level: crate::tracking::log_ring::LogLevel::Info,
            target: "fixture".into(),
            message: "old message".into(),
        }];
        app.logs.fetch = app::LogsFetch::Ok;
        app.logs.capacity = 10;
        app.logs.dropped = 2;
        app.logs.scroll_offset = 5;
        for (index, action) in actions.into_iter().enumerate() {
            let focus_only = index == 0 && action.code == KeyCode::Char('f');
            handle_key(&mut app, action, &ghost(&dir), &path).await;
            if focus_only {
                assert!(!app.force_poll, "focus alone does not mutate a filter");
            }
        }
        assert!(app.paused && app.force_poll);
        assert!(app.logs.entries.is_empty());
        assert_eq!(app.logs.scroll_offset, 0);
        assert_eq!(app.logs.capacity, 0);
        assert_eq!(app.logs.dropped, 0);
        assert_eq!(app.logs.fetch, app::LogsFetch::Never);
    }
}

#[tokio::test]
async fn cancelling_text_filters_keeps_rows_and_does_not_request_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let path = master(&dir);
    for (leaf, input) in [
        (Leaf::QueryLog, InputMode::FilterDomain("draft".into())),
        (Leaf::QueryLog, InputMode::FilterClient("draft".into())),
        (Leaf::Logs, InputMode::FilterLogs("draft".into())),
    ] {
        let mut app = App::new();
        app.active_leaf = leaf;
        app.input_mode = input;
        app.query_log.entries = vec![query_entry()];
        app.logs.entries = vec![DaemonLogDto {
            timestamp: "2026-09-08T12:00:00Z".into(),
            level: crate::tracking::log_ring::LogLevel::Info,
            target: "fixture".into(),
            message: "keep this row".into(),
        }];
        app.paused = true;
        handle_key(&mut app, key(KeyCode::Esc), &ghost(&dir), &path).await;
        assert!(!app.force_poll);
        assert_eq!(app.query_log.entries.len(), 1);
        assert_eq!(app.logs.entries.len(), 1);
        assert!(
            app.query_log.filter_domain.is_none()
                && app.query_log.filter_client.is_none()
                && app.logs.filter_text.is_none()
        );
    }
}
