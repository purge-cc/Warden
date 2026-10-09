use super::*;
use crate::operator_rules::{Capabilities, ListDetail, Metadata};
use crate::tui::{app::Leaf, mouse, operator_policy::PolicyCatalog};
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

fn app() -> App {
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::QueryLog;
    app.operator_catalog = Some(PolicyCatalog {
        capabilities: Capabilities {
            contract_version: CONTRACT_VERSION,
            schema_version: 5,
            operator_rule_grammar: 1,
            operations: vec!["add_domain_rule".into()],
            semantic_hash: true,
            activation_ack: true,
            cluster_artifact: false,
            limits: TransportLimits::IPC,
        },
        metadata: Metadata {
            contract_version: CONTRACT_VERSION,
            schema_version: 5,
            config_revision: "a".repeat(64),
            desired_operator_policy_hash: "b".repeat(64),
            active_policy: None,
            activation_in_sync: true,
            lists: 3,
            mounted_lists: 1,
            orphan_packs: 0,
        },
        lists: (0..3)
            .map(|i| ListDetail {
                id: format!("list-{i}"),
                display_name: format!("List {i}"),
                description: String::new(),
                config_revision: "a".repeat(64),
                pack_revision: "b".repeat(64),
                bytes: 0,
                rule_count: 0,
                invalid_rows: 0,
                profiles: if i == 0 {
                    vec!["household".into()]
                } else {
                    vec![]
                },
            })
            .collect(),
        orphan_packs: vec![],
    });
    app
}

fn ids() -> Vec<String> {
    vec!["list-0".into(), "list-1".into()]
}
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn ghost() -> IpcPoller {
    IpcPoller::new(std::path::Path::new("/tmp/qrb-no.sock"))
}
fn hold_two(app: &mut App) {
    assert_eq!(
        hold(app, "FIRST.example", RuleAction::Deny, ids()).unwrap(),
        2
    );
    assert_eq!(
        hold(app, "second.example", RuleAction::Allow, ids()).unwrap(),
        2
    );
}

#[test]
fn canonical_dedup_and_per_list_conflicts_are_atomic() {
    let mut app = app();
    hold_two(&mut app);
    assert_eq!(
        hold(&mut app, "first.EXAMPLE", RuleAction::Deny, ids()).unwrap(),
        0
    );
    let before = app.query_log.held.targets.clone();
    assert!(hold(
        &mut app,
        "first.example",
        RuleAction::Allow,
        vec!["list-2".into(), "list-0".into()]
    )
    .unwrap_err()
    .contains("Already held as DENY"));
    assert_eq!(
        app.query_log.held.targets, before,
        "earlier new target must not partially stage"
    );
    assert_eq!(
        hold(
            &mut app,
            "first.example",
            RuleAction::Allow,
            vec!["list-2".into()]
        )
        .unwrap(),
        1
    );
    assert_eq!(app.query_log.held.targets[0].domain, "first.example");
    assert!(app.operator_policy.is_none() && app.pending_action.is_none());
    assert!(
        App::new().query_log.held.targets.is_empty(),
        "unsubmitted drafts are session only"
    );
}

#[test]
fn expanded_32_target_boundary_deduplicates_before_admission() {
    let mut app = app();
    for index in 0..15 {
        hold(
            &mut app,
            &format!("{index}.example"),
            RuleAction::Deny,
            ids(),
        )
        .unwrap();
    }
    hold(&mut app, "last.example", RuleAction::Allow, ids()).unwrap();
    assert_eq!(app.query_log.held.targets.len(), 32);
    assert_eq!(
        hold(&mut app, "last.EXAMPLE", RuleAction::Allow, ids()).unwrap(),
        0
    );
    let before = app.query_log.held.targets.clone();
    assert!(hold(&mut app, "new.example", RuleAction::Deny, ids())
        .unwrap_err()
        .contains("32"));
    assert_eq!(app.query_log.held.targets, before);
}

#[test]
fn negotiated_capacity_and_invalid_multiselect_refuse_whole_selection() {
    let mut app = app();
    app.operator_catalog
        .as_mut()
        .unwrap()
        .capabilities
        .limits
        .max_operations = 3;
    hold(&mut app, "first.example", RuleAction::Deny, ids()).unwrap();
    let before = app.query_log.held.targets.clone();
    assert!(hold(&mut app, "second.example", RuleAction::Deny, ids())
        .unwrap_err()
        .contains("3 held"));
    assert!(hold(
        &mut app,
        "second.example",
        RuleAction::Deny,
        vec!["list-2".into(), "deleted".into()]
    )
    .is_err());
    for domain in [
        "",
        "x..example",
        "bad.example\n",
        "@@bad.example",
        "bad.example.",
    ] {
        assert!(hold(&mut app, domain, RuleAction::Allow, ids()).is_err());
    }
    assert_eq!(app.query_log.held.targets, before);
}

#[test]
fn complete_envelope_size_and_capability_are_checked_before_hold() {
    let mut app = app();
    let huge_id = "x".repeat(crate::ipc::protocol::OPERATOR_RULES_MAX_BYTES);
    app.operator_catalog.as_mut().unwrap().lists[0].id = huge_id.clone();
    assert!(
        hold(&mut app, "size.example", RuleAction::Allow, vec![huge_id])
            .unwrap_err()
            .contains("60 KiB")
    );
    assert!(app.query_log.held.targets.is_empty());
    app.operator_catalog
        .as_mut()
        .unwrap()
        .capabilities
        .operations
        .clear();
    assert!(hold(&mut app, "size.example", RuleAction::Allow, ids())
        .unwrap_err()
        .contains("cannot add domain rules"));
}

#[tokio::test]
async fn review_delete_confirm_discard_and_quit_preserve_until_explicit_confirmation() {
    let mut app = app();
    hold_two(&mut app);
    open_review(&mut app);
    handle_key(&mut app, key(KeyCode::End), &ghost()).await;
    handle_key(&mut app, key(KeyCode::Delete), &ghost()).await;
    assert_eq!(app.query_log.held.targets.len(), 3);
    assert!(!app
        .query_log
        .held
        .targets
        .iter()
        .any(|t| t.domain == "second.example" && t.list_id == "list-1"));
    handle_key(&mut app, key(KeyCode::Esc), &ghost()).await;
    assert_eq!(app.query_log.held.targets.len(), 3);
    assert!(!request_quit(&mut app));
    handle_key(&mut app, key(KeyCode::Enter), &ghost()).await;
    assert_eq!(
        app.query_log.held.targets.len(),
        3,
        "default quit choice keeps draft"
    );
    open_review(&mut app);
    handle_key(&mut app, key(KeyCode::Char('D')), &ghost()).await;
    assert_eq!(app.query_log.held.review, Some(Review::Discard));
    handle_key(&mut app, key(KeyCode::Esc), &ghost()).await;
    assert_eq!(app.query_log.held.review, Some(Review::Rules));
    assert_eq!(app.query_log.held.targets.len(), 3);
    handle_key(&mut app, key(KeyCode::Char('D')), &ghost()).await;
    handle_key(&mut app, key(KeyCode::Char('y')), &ghost()).await;
    assert!(app.query_log.held.targets.is_empty());
    hold_two(&mut app);
    assert!(!request_quit(&mut app));
    assert!(handle_key(&mut app, key(KeyCode::Char('y')), &ghost()).await);
    assert!(app.query_log.held.targets.is_empty());
}

fn draw(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::tui::ui::render(frame, app))
        .unwrap();
    terminal.backend().buffer().clone()
}
fn dump(buffer: &Buffer) -> String {
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                + "\n"
        })
        .collect()
}
fn locate(buffer: &Buffer, label: &str) -> (u16, u16) {
    for y in 0..buffer.area.height {
        let row = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>();
        if let Some(byte) = row.find(label) {
            return (row[..byte].chars().count() as u16, y);
        }
    }
    panic!("missing {label}:\n{}", dump(buffer));
}
fn click(x: u16, y: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    }
}

#[tokio::test]
async fn floor_and_wide_card_review_and_mouse_actions_are_reachable() {
    let mut app = app();
    hold_two(&mut app);
    app.query_log
        .entries
        .push(crate::ipc::protocol::QueryLogDto {
            timestamp: "2026-09-30T00:00:00Z".into(),
            client_ip: "192.0.2.1".into(),
            client_name: None,
            domain: "live.example".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 1,
            cname_chain_via: None,
        });
    for (width, height) in [(80, 24), (120, 40), (200, 50)] {
        let buffer = draw(&mut app, width, height);
        let text = dump(&buffer);
        for needle in [
            "HELD RULES",
            "NOT ACTIVE",
            "4 rules held",
            "[v] review",
            "live.example",
        ] {
            assert!(text.contains(needle), "{needle}:\n{text}");
        }
        let (x, y) = locate(&buffer, "HELD RULES");
        assert_eq!(
            mouse::action(&app, click(x, y)),
            Some(mouse::MouseAction::Key(KeyCode::Char('v')))
        );
        crate::tui::handle_mouse(
            &mut app,
            click(x, y),
            &ghost(),
            std::path::Path::new("/tmp/qrb-config.toml"),
        )
        .await;
        assert_eq!(app.query_log.held.review, Some(Review::Rules));
        let buffer = draw(&mut app, width, height);
        let text = dump(&buffer);
        for needle in [
            "NOT ACTIVE",
            "Review all",
            "Discard all",
            "Delete",
            "DENY first.example",
        ] {
            assert!(text.contains(needle), "{needle}:\n{text}");
        }
        assert!(text.contains("Applying can take time"), "{text}");
        handle_key(&mut app, key(KeyCode::End), &ghost()).await;
        let buffer = draw(&mut app, width, height);
        assert!(
            dump(&buffer).contains("filters nothing"),
            "{}",
            dump(&buffer)
        );
        let (x, y) = locate(&buffer, "Remove");
        crate::tui::handle_mouse(
            &mut app,
            click(x, y),
            &ghost(),
            std::path::Path::new("/tmp/qrb-config.toml"),
        )
        .await;
        assert_eq!(app.query_log.held.targets.len(), 3);
        let buffer = draw(&mut app, width, height);
        let (x, y) = locate(&buffer, "Discard all");
        crate::tui::handle_mouse(
            &mut app,
            click(x, y),
            &ghost(),
            std::path::Path::new("/tmp/qrb-config.toml"),
        )
        .await;
        assert_eq!(app.query_log.held.review, Some(Review::Discard));
        let buffer = draw(&mut app, width, height);
        let (x, y) = locate(&buffer, "Keep");
        crate::tui::handle_mouse(
            &mut app,
            click(x, y),
            &ghost(),
            std::path::Path::new("/tmp/qrb-config.toml"),
        )
        .await;
        assert_eq!(app.query_log.held.targets.len(), 3);
        handle_key(&mut app, key(KeyCode::Esc), &ghost()).await;
        hold(&mut app, "second.example", RuleAction::Allow, ids()).unwrap();
    }
}

#[tokio::test]
async fn outside_click_steps_back_through_the_review_and_keeps_held_rules() {
    let config = std::path::Path::new("/tmp/qrb-config.toml");
    let mut app = app();
    hold_two(&mut app);
    app.query_log.held.review = Some(Review::Discard);
    draw(&mut app, 100, 30);
    crate::tui::handle_mouse(&mut app, click(0, 0), &ghost(), config).await;
    assert_eq!(app.query_log.held.review, Some(Review::Rules));
    assert_eq!(app.query_log.held.targets.len(), 4);
    draw(&mut app, 100, 30);
    crate::tui::handle_mouse(&mut app, click(0, 0), &ghost(), config).await;
    assert_eq!(app.query_log.held.review, None);
    assert_eq!(app.query_log.held.targets.len(), 4);
    app.query_log.held.review = Some(Review::Quit);
    draw(&mut app, 100, 30);
    assert!(!crate::tui::handle_mouse(&mut app, click(0, 0), &ghost(), config).await);
    assert_eq!(app.query_log.held.review, None);
    assert_eq!(app.query_log.held.targets.len(), 4);
}

#[tokio::test]
async fn live_row_replacement_search_pause_navigation_and_refresh_keep_captured_targets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "schema_version = 5\n[upstream]\nservers = [\"192.0.2.1:53\"]\n[server]\ndefault_profile = \"household\"\n[profiles.household]\n").unwrap();
    let mut app = app();
    hold_two(&mut app);
    let before = app.query_log.held.targets.clone();
    app.query_log.entries.clear();
    for code in [
        KeyCode::Char('/'),
        KeyCode::Char('v'),
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Char('p'),
        KeyCode::Tab,
        KeyCode::BackTab,
    ] {
        crate::tui::handle_key(&mut app, key(code), &ghost(), &path).await;
        assert_eq!(app.query_log.held.targets, before);
    }
    assert!(app.paused);
    crate::tui::handle_key_with_reload(&mut app, key(KeyCode::Char('r')), &ghost(), &path, async {
        anyhow::bail!("isolated refresh")
    })
    .await;
    assert_eq!(app.query_log.held.targets, before);
    assert!(app.operator_policy.is_none());
}

#[tokio::test]
async fn failed_planning_preserves_targets_and_never_creates_an_active_receipt() {
    let mut app = app();
    hold_two(&mut app);
    let before = app.query_log.held.targets.clone();
    review_all(&mut app, &ghost()).await;
    assert_eq!(app.query_log.held.targets, before);
    assert!(app.query_log.held.receipt.is_none());
    assert!(app
        .operator_policy
        .as_ref()
        .unwrap()
        .preparation_error
        .is_some());
    crate::tui::operator_policy::handle_key(
        &mut app,
        key(KeyCode::Esc),
        &ghost(),
        std::path::Path::new("/tmp/qrb-config.toml"),
    )
    .await;
    assert!(!app.query_log.held.error.as_deref().unwrap().is_empty());
    assert_eq!(app.query_log.held.targets, before);
}

#[cfg(feature = "cluster")]
#[tokio::test]
async fn authority_loss_keeps_local_draft_but_cannot_plan_or_hold() {
    let mut app = app();
    hold_two(&mut app);
    let before = app.query_log.held.targets.clone();
    app.nodes_status = None;
    review_all(&mut app, &ghost()).await;
    assert!(hold(&mut app, "another.example", RuleAction::Allow, ids()).is_err());
    assert_eq!(app.query_log.held.targets, before);
    assert!(app.operator_policy.is_none());
    open_review(&mut app);
    let text = dump(&draw(&mut app, 80, 24));
    assert!(text.contains("Read-only node"), "{text}");
}

#[tokio::test]
async fn new_list_detour_is_immediate_and_separate_from_held_rules() {
    let mut app = app();
    hold_two(&mut app);
    let before = app.query_log.held.targets.clone();
    crate::tui::action_handlers::query_new_list(
        &mut app,
        crate::tui::custom_list_modal::ResolvedForm {
            id: "new-list".into(),
            display_name: "New List".into(),
            description: String::new(),
        },
        &ghost(),
        std::path::Path::new("/tmp/qrb-config.toml"),
    )
    .await;
    assert!(matches!(
        app.operator_policy.as_ref().unwrap().origin,
        crate::tui::operator_policy::PolicyOrigin::QueryNewList { .. }
    ));
    assert_eq!(app.query_log.held.targets, before);
}

#[tokio::test]
async fn pointer_review_all_enters_only_one_frozen_policy_workflow() {
    let mut app = app();
    hold_two(&mut app);
    let before = app.query_log.held.targets.clone();
    open_review(&mut app);
    let buffer = draw(&mut app, 80, 24);
    let (x, y) = locate(&buffer, "Review all");
    crate::tui::handle_mouse(
        &mut app,
        click(x, y),
        &ghost(),
        std::path::Path::new("/tmp/qrb-config.toml"),
    )
    .await;
    assert!(app.query_log.held.review.is_none());
    assert!(
        matches!(&app.operator_policy.as_ref().unwrap().origin, crate::tui::operator_policy::PolicyOrigin::QueryBatch { targets } if targets == &before)
    );
    assert_eq!(app.query_log.held.targets, before);
    assert!(app.query_log.held.receipt.is_none());
}

#[tokio::test]
async fn destructive_selection_survives_catalog_expansion_and_contraction_by_keyboard_and_mouse() {
    for pointer in [false, true] {
        for expand in [false, true] {
            let mut app = app();
            hold(
                &mut app,
                "first.example",
                RuleAction::Deny,
                vec!["list-0".into()],
            )
            .unwrap();
            hold(
                &mut app,
                "later.example",
                RuleAction::Allow,
                vec!["list-1".into()],
            )
            .unwrap();
            if !expand {
                let list = &mut app.operator_catalog.as_mut().unwrap().lists[0];
                list.display_name = "long metadata ".repeat(20);
                list.profiles = vec!["near-max-profile-".repeat(4); 8];
            }
            open_review(&mut app);
            if pointer {
                let buffer = draw(&mut app, 80, 24);
                let (x, y) = locate(&buffer, "ALLOW later.example");
                crate::tui::handle_mouse(
                    &mut app,
                    click(x, y),
                    &ghost(),
                    std::path::Path::new("/tmp/qrb-config.toml"),
                )
                .await;
            } else {
                handle_key(&mut app, key(KeyCode::End), &ghost()).await;
            }
            assert_eq!(app.query_log.held.selected_target, 1);
            let list = &mut app.operator_catalog.as_mut().unwrap().lists[0];
            list.display_name = if expand {
                "near-max-name-".repeat(20)
            } else {
                "short".into()
            };
            list.profiles = if expand {
                vec!["near-max-profile-".repeat(4); 8]
            } else {
                vec![]
            };
            let buffer = draw(&mut app, 80, 24);
            assert!(
                dump(&buffer).contains("ALLOW later.example"),
                "{}",
                dump(&buffer)
            );
            if pointer {
                let (x, y) = locate(&buffer, "Remove");
                crate::tui::handle_mouse(
                    &mut app,
                    click(x, y),
                    &ghost(),
                    std::path::Path::new("/tmp/qrb-config.toml"),
                )
                .await;
            } else {
                handle_key(&mut app, key(KeyCode::Delete), &ghost()).await;
            }
            assert_eq!(app.query_log.held.targets.len(), 1);
            assert_eq!(app.query_log.held.targets[0].domain, "first.example");
        }
    }
}

#[test]
fn near_max_local_conflict_shows_session_correction_route_without_cli_overflow_advice() {
    let mut app = app();
    let domain = format!(
        "{}.{}.{}.example",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    );
    let id = "l".repeat(64);
    app.operator_catalog.as_mut().unwrap().lists[0].id = id.clone();
    hold(&mut app, &domain, RuleAction::Deny, vec![id.clone()]).unwrap();
    let before = app.query_log.held.targets.clone();
    let error = hold(&mut app, &domain, RuleAction::Allow, vec![id.clone()]).unwrap_err();
    assert!(error.contains("(v, Delete)"), "{error}");
    app.query_log_rule_modal = Some(crate::tui::query_log_rule_modal::QueryLogRuleModal::open(
        crate::cli::commands::rules::Action::Allow,
        domain,
        "192.0.2.1".into(),
        vec![crate::tui::query_log_rule_modal::ListRow::new(
            id,
            "Long list".into(),
            vec![],
        )],
    ));
    app.query_log_rule_modal.as_mut().unwrap().error = Some(error);
    for (width, height) in [(80, 24), (120, 40), (200, 50)] {
        let text = dump(&draw(&mut app, width, height));
        assert!(text.contains("(v, Delete)"), "{text}");
        assert!(!text.contains("run in the CLI"), "{text}");
    }
    assert_eq!(app.query_log.held.targets, before);
}

#[tokio::test]
async fn production_background_completion_preserves_draft_and_open_quit_confirmation() {
    use crate::tui::{
        app::UiJob,
        jobs::{ReadReason, ReadRequest, ReadScheduler, ReadValue},
    };
    for while_quitting in [false, true] {
        let mut app = app();
        hold_two(&mut app);
        let captured = app.query_log.held.targets.clone();
        let poller = std::sync::Arc::new(ghost());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        app.job_tx = Some(tx.clone());
        let mut scheduler = ReadScheduler::new(poller.clone());
        scheduler.request(
            ReadRequest::QueryLog {
                query: Box::default(),
                page_index: 0,
            },
            ReadReason::Explicit,
        );
        let task = scheduler.take_ready().pop().unwrap();
        app.read_jobs = Some(scheduler);
        if while_quitting {
            assert!(
                !crate::tui::handle_key(
                    &mut app,
                    key(KeyCode::Char('q')),
                    &poller,
                    std::path::Path::new("/tmp/qrb-config.toml")
                )
                .await
            );
            assert_eq!(app.query_log.held.review, Some(Review::Quit));
        } else {
            crate::tui::handle_key(
                &mut app,
                key(KeyCode::Tab),
                &poller,
                std::path::Path::new("/tmp/qrb-config.toml"),
            )
            .await;
        }
        tx.send(UiJob::ReadFinished(task.complete_for_test(Ok(
            ReadValue::QueryLog(crate::tui::ipc_poller::QueryLogPollResult {
                entries: vec![],
                logging_enabled: true,
                file_state: crate::ipc::protocol::QueryLogFileState::Ok,
                next_cursor: None,
                cursor_stale: false,
            }),
        ))))
        .unwrap();
        crate::tui::apply_job_result(&mut app, rx.recv().await.unwrap());
        assert_eq!(app.query_log.held.targets, captured);
        assert!(app.operator_policy.is_none());
        if while_quitting {
            assert_eq!(app.query_log.held.review, Some(Review::Quit));
            assert!(
                !crate::tui::handle_key(
                    &mut app,
                    key(KeyCode::Char('n')),
                    &poller,
                    std::path::Path::new("/tmp/qrb-config.toml")
                )
                .await
            );
            assert_eq!(app.query_log.held.targets, captured);
        }
    }
}

#[test]
fn failed_apply_keeps_every_held_target_and_committed_clears_only_submitted() {
    let mut app = app();
    hold(&mut app, "ciao.it", RuleAction::Deny, vec!["list-0".into()]).unwrap();
    hold(
        &mut app,
        "saluto.com",
        RuleAction::Allow,
        vec!["list-1".into()],
    )
    .unwrap();
    let submitted = app.query_log.held.targets.clone();
    finish_failed(&mut app, "revision conflict");
    assert_eq!(app.query_log.held.targets, submitted);
    assert_eq!(
        app.query_log.held.error.as_deref(),
        Some("revision conflict")
    );
    // A rule held after submission survives the commit of the earlier batch.
    hold(
        &mut app,
        "later.example",
        RuleAction::Deny,
        vec!["list-2".into()],
    )
    .unwrap();
    finish_committed(&mut app, &submitted, "saved".into());
    assert_eq!(app.query_log.held.targets.len(), 1);
    assert_eq!(app.query_log.held.targets[0].domain, "later.example");
    assert!(app.query_log.held.error.is_none());
}

#[test]
fn query_batch_origin_round_trips_through_the_recovery_journal_encoding() {
    let origin = crate::tui::operator_policy::PolicyOrigin::QueryBatch {
        targets: vec![
            HeldTarget {
                domain: "ciao.it".into(),
                action: RuleAction::Deny,
                list_id: "abc".into(),
            },
            HeldTarget {
                domain: "saluto.com".into(),
                action: RuleAction::Allow,
                list_id: "fgh".into(),
            },
        ],
    };
    let json = serde_json::to_string(&origin).unwrap();
    assert!(json.contains("\"origin\":\"query_batch\""), "{json}");
    let back: crate::tui::operator_policy::PolicyOrigin = serde_json::from_str(&json).unwrap();
    assert_eq!(back, origin);
}

#[test]
fn legacy_query_rules_origin_from_0_42_0_still_decodes() {
    let json = r#"{"origin":"query_rules","ids":["local"],"already_present":[false]}"#;
    let origin: crate::tui::operator_policy::PolicyOrigin = serde_json::from_str(json).unwrap();
    assert_eq!(
        origin,
        crate::tui::operator_policy::PolicyOrigin::QueryRules {
            ids: vec!["local".into()],
            already_present: vec![false],
        }
    );
}

#[tokio::test]
async fn quit_with_held_rules_asks_first_and_confirmed_quit_discards() {
    let mut app = app();
    hold_two(&mut app);
    assert!(!request_quit(&mut app));
    assert_eq!(app.query_log.held.review, Some(Review::Quit));
    assert!(!handle_key(&mut app, key(KeyCode::Char('n')), &ghost()).await);
    assert_eq!(
        app.query_log.held.targets.len(),
        4,
        "Keep preserves the rules"
    );
    assert!(!request_quit(&mut app));
    assert!(handle_key(&mut app, key(KeyCode::Char('y')), &ghost()).await);
    assert!(app.query_log.held.targets.is_empty());
    assert!(request_quit(&mut app), "nothing held: quit at once");
}

#[test]
fn committed_batch_closes_an_open_quit_confirmation_instead_of_offering_zero() {
    let mut app = app();
    hold_two(&mut app);
    let submitted = app.query_log.held.targets.clone();
    assert!(!request_quit(&mut app));
    finish_committed(&mut app, &submitted, "saved".into());
    assert!(app.query_log.held.targets.is_empty());
    assert_eq!(app.query_log.held.review, None);
    assert!(request_quit(&mut app), "nothing held: quit at once");
}

#[test]
fn unloaded_catalog_reads_as_loading_and_is_requested_on_review() {
    let mut app = app();
    hold_two(&mut app);
    app.operator_catalog = None;
    app.read_jobs = Some(crate::tui::jobs::ReadScheduler::new(std::sync::Arc::new(
        ghost(),
    )));
    open_review(&mut app);
    assert!(app
        .read_jobs
        .as_ref()
        .unwrap()
        .is_loading(crate::tui::jobs::ReadResource::OperatorCatalog));
    let text = dump(&draw(&mut app, 120, 40));
    assert!(text.contains("not loaded yet"), "{text}");
    assert!(!text.contains("not found"), "{text}");
    // A failed read is not shown as still loading.
    app.operator_catalog_error = Some("read failed".into());
    let text = dump(&draw(&mut app, 120, 40));
    assert!(text.contains("unavailable: reopen to retry"), "{text}");
    assert!(!text.contains("not loaded yet"), "{text}");
}

#[test]
fn held_card_is_yellow_and_shares_one_gutter_with_the_query_log_card() {
    use crate::tui::theme::{CardRole, T};
    let mut app = app();
    hold_two(&mut app);
    for (width, height) in [(80, 24), (120, 40), (200, 50)] {
        let buffer = draw(&mut app, width, height);
        let (x, y) = locate(&buffer, "HELD RULES");
        let text = dump(&buffer);
        assert_eq!(
            buffer[(x, y)].bg,
            T.card_title_bg(CardRole::History),
            "{text}"
        );
        assert_eq!(
            buffer[(x, y + 1)].bg,
            T.card_subtitle_bg(CardRole::History),
            "{text}"
        );
        assert_eq!(
            buffer[(x, y + 3)].bg,
            T.bg_main,
            "one shared gutter:\n{text}"
        );
        assert_eq!(
            buffer[(x, y + 4)].bg,
            T.card_title_bg(CardRole::Analytics),
            "the Query Log title follows one blank row:\n{text}"
        );
    }
}

fn two_single_list_rules() -> App {
    let mut app = app();
    hold(
        &mut app,
        "first.example",
        RuleAction::Deny,
        vec!["list-0".into()],
    )
    .unwrap();
    hold(
        &mut app,
        "later.example",
        RuleAction::Allow,
        vec!["list-1".into()],
    )
    .unwrap();
    open_review(&mut app);
    app
}
fn target(domain: &str, action: RuleAction, list: &str) -> HeldTarget {
    HeldTarget {
        domain: domain.into(),
        action,
        list_id: list.into(),
    }
}
fn save() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
}
async fn press(app: &mut App, codes: &[KeyCode]) {
    for code in codes {
        handle_key(app, key(*code), &ghost()).await;
    }
}
async fn click_at(app: &mut App, x: u16, y: u16) {
    crate::tui::handle_mouse(
        app,
        click(x, y),
        &ghost(),
        std::path::Path::new("/tmp/qrb-config.toml"),
    )
    .await;
}

#[tokio::test]
async fn review_table_renders_one_row_per_rule_and_every_keys_row_fits() {
    let mut app = app();
    hold_two(&mut app);
    open_review(&mut app);
    let buffer = draw(&mut app, 80, 24);
    let text = dump(&buffer);
    let (_, y) = locate(&buffer, "ACTION DOMAIN");
    assert!(
        text.lines().nth(y.into()).unwrap().contains(" LIST "),
        "{text}"
    );
    for (action, domain, list) in [
        ("DENY", "first.example", "list-0"),
        ("DENY", "first.example", "list-1"),
        ("ALLOW", "second.example", "list-0"),
        ("ALLOW", "second.example", "list-1"),
    ] {
        let row = format!("{action:>6} {domain:<39} {list}");
        let rows = text.lines().filter(|line| line.contains(&row)).count();
        assert_eq!(rows, 1, "one row per rule, {row}:\n{text}");
    }
    for focus in 0..6 {
        assert_eq!(app.query_log.held.focus, focus);
        let text = dump(&draw(&mut app, 80, 24));
        let keys = if focus % 5 == 0 {
            "Enter review all · Esc keep"
        } else {
            "e edit · Esc keep"
        };
        assert!(text.contains(keys), "focus {focus}:\n{text}");
        handle_key(&mut app, key(KeyCode::Tab), &ghost()).await;
    }
    assert_eq!(app.query_log.held.focus, 0, "Tab wraps after Review all");
    handle_key(&mut app, key(KeyCode::End), &ghost()).await;
    let text = dump(&draw(&mut app, 80, 24));
    assert!(
        text.contains("List 1 · no profile uses it: filters nothing"),
        "{text}"
    );
    handle_key(&mut app, key(KeyCode::Home), &ghost()).await;
    let text = dump(&draw(&mut app, 80, 24));
    assert!(text.contains("List 0 · profiles: household"), "{text}");
}

#[test]
fn every_rule_table_has_a_header_and_a_receipt_only_review_has_none() {
    let mut app = app();
    hold_two(&mut app);
    for review in [Review::Discard, Review::Quit] {
        app.query_log.held.review = Some(review);
        let buffer = draw(&mut app, 80, 24);
        let (_, lead) = locate(&buffer, "Discarding drops held rules only");
        let (_, header) = locate(&buffer, "ACTION DOMAIN");
        let (x, first) = locate(&buffer, "DENY first.example");
        assert_eq!((header, first), (lead + 1, lead + 2), "{}", dump(&buffer));
        let highlight = crate::tui::theme::T.bg_highlight;
        assert_eq!(buffer[(x, first)].bg, highlight, "{}", dump(&buffer));
        assert_ne!(buffer[(x, first + 1)].bg, highlight, "{}", dump(&buffer));
    }
    let submitted = app.query_log.held.targets.clone();
    finish_committed(&mut app, &submitted, "saved".into());
    open_review(&mut app);
    let text = dump(&draw(&mut app, 80, 24));
    assert!(text.contains("Last Apply: saved"), "{text}");
    assert!(!text.contains("ACTION DOMAIN"), "{text}");
}

#[tokio::test]
async fn pointer_click_selects_row_and_cell() {
    let mut app = two_single_list_rules();
    handle_key(&mut app, key(KeyCode::Tab), &ghost()).await;
    let buffer = draw(&mut app, 80, 24);
    let (x, y) = locate(&buffer, "later.example");
    click_at(&mut app, x, y).await;
    let held = &app.query_log.held;
    assert_eq!((held.selected_target, held.column, held.focus), (1, 1, 0));
    assert!(
        held.editor.is_none(),
        "a click on another cell only selects"
    );
    let (x, y) = locate(&buffer, "list-1");
    click_at(&mut app, x, y).await;
    let held = &app.query_log.held;
    assert_eq!((held.selected_target, held.column, held.focus), (1, 2, 0));
    assert!(held.editor.is_none());
    click_at(&mut app, x, y).await;
    let editor = app
        .query_log
        .held
        .editor
        .as_ref()
        .expect("second click edits");
    assert_eq!(editor.column, 2);
    assert_eq!(editor.lists, vec!["list-1".to_string()]);
}

#[tokio::test]
async fn edit_list_cell_adds_the_domain_to_another_list_in_place() {
    let mut app = two_single_list_rules();
    press(
        &mut app,
        &[KeyCode::Right, KeyCode::Right, KeyCode::Char('e')],
    )
    .await;
    let editor = app.query_log.held.editor.as_ref().unwrap();
    assert_eq!(editor.lists, vec!["list-0".to_string()]);
    // Checked out of catalog order: list-2, then list-1.
    press(
        &mut app,
        &[
            KeyCode::Down,
            KeyCode::Down,
            KeyCode::Char(' '),
            KeyCode::Up,
            KeyCode::Char(' '),
        ],
    )
    .await;
    handle_key(&mut app, save(), &ghost()).await;
    let held = &app.query_log.held;
    assert_eq!(
        held.targets,
        vec![
            target("first.example", RuleAction::Deny, "list-0"),
            target("first.example", RuleAction::Deny, "list-1"),
            target("first.example", RuleAction::Deny, "list-2"),
            target("later.example", RuleAction::Allow, "list-1"),
        ]
    );
    assert!(held.editor.is_none() && held.error.is_none());
    assert_eq!(held.review, Some(Review::Rules));
}

#[tokio::test]
async fn edit_domain_and_action_replace_only_the_selected_rule() {
    let mut app = app();
    hold_two(&mut app);
    open_review(&mut app);
    let mut expected = app.query_log.held.targets.clone();
    press(&mut app, &[KeyCode::Right, KeyCode::Char('e')]).await;
    assert_eq!(
        app.query_log.held.editor.as_ref().unwrap().domain,
        "first.example"
    );
    press(&mut app, &[KeyCode::Backspace; 13]).await;
    let typed: Vec<KeyCode> = "Other.EXAMPLE".chars().map(KeyCode::Char).collect();
    press(&mut app, &typed).await;
    press(&mut app, &[KeyCode::Enter]).await;
    expected[0].domain = "other.example".into();
    assert_eq!(app.query_log.held.targets, expected);
    // Row 0 is DENY, so the Action editor starts on DENY; Up reaches ALLOW.
    press(
        &mut app,
        &[
            KeyCode::Left,
            KeyCode::Char('e'),
            KeyCode::Up,
            KeyCode::Enter,
        ],
    )
    .await;
    expected[0].action = RuleAction::Allow;
    assert_eq!(app.query_log.held.targets, expected);
    // Leaving an editor drops a changed draft: Esc, or Enter on Discard.
    let leave: [&[KeyCode]; 3] = [
        &[
            KeyCode::Right,
            KeyCode::Char('e'),
            KeyCode::Backspace,
            KeyCode::Char('z'),
            KeyCode::Esc,
        ],
        &[
            KeyCode::Right,
            KeyCode::Char('e'),
            KeyCode::Down,
            KeyCode::Char(' '),
            KeyCode::Esc,
        ],
        &[
            KeyCode::Left,
            KeyCode::Left,
            KeyCode::Char('e'),
            KeyCode::Down,
            KeyCode::Tab,
            KeyCode::Enter,
        ],
    ];
    for keys in leave {
        press(&mut app, keys).await;
        let held = &app.query_log.held;
        assert!(held.editor.is_none(), "{keys:?}");
        assert_eq!(held.review, Some(Review::Rules));
        assert_eq!(held.targets, expected, "{keys:?}");
    }
}

#[tokio::test]
async fn edit_passes_the_same_checks_as_a_new_hold() {
    let invalid = crate::config::custom_list::normalise_domain("x..example")
        .unwrap_err()
        .to_string();
    // (setup, domain, lists, expected refusal) for a DENY edit of row 0.
    type Case<'a> = (fn(&mut App), &'a str, &'a [&'a str], &'a str);
    let cases: [Case; 6] = [
        (|_| {}, "x..example", &["list-0"], invalid.as_str()),
        (
            |_| {},
            "later.example",
            &["list-1"],
            "Already held as ALLOW",
        ),
        (|_| {}, "first.example", &[], "Select at least one list"),
        (|_| {}, "first.example", &["deleted"], "no longer exists"),
        (
            |app| {
                let catalog = app.operator_catalog.as_mut().unwrap();
                catalog.capabilities.limits.max_operations = 2;
            },
            "first.example",
            &["list-0", "list-2"],
            "2 held",
        ),
        (
            |app| {
                let catalog = app.operator_catalog.as_mut().unwrap();
                catalog.capabilities.operations.clear();
            },
            "first.example",
            &["list-0"],
            "cannot add domain rules",
        ),
    ];
    for (setup, domain, lists, needle) in cases {
        let mut app = two_single_list_rules();
        let before = app.query_log.held.targets.clone();
        setup(&mut app);
        app.query_log.held.editor = Some(Editor {
            column: 1,
            action: RuleAction::Deny,
            domain: domain.into(),
            lists: lists.iter().map(|id| id.to_string()).collect(),
            cursor: 0,
            focus: FilterFocus::Value,
            error: None,
        });
        handle_key(&mut app, save(), &ghost()).await;
        let held = &app.query_log.held;
        assert_eq!(held.targets, before, "{needle}");
        let error = held.editor.as_ref().and_then(|e| e.error.as_deref());
        assert!(
            error.is_some_and(|e| e.contains(needle)),
            "{needle}: {error:?}"
        );
    }
}

#[tokio::test]
async fn editor_menus_use_the_filter_popup_and_are_mouse_reachable() {
    let mut app = two_single_list_rules();
    press(
        &mut app,
        &[KeyCode::Right, KeyCode::Right, KeyCode::Char('e')],
    )
    .await;
    let buffer = draw(&mut app, 80, 24);
    let text = dump(&buffer);
    for needle in [
        " LISTS ",
        "[x] List 0 · list-0",
        "[ ] List 2",
        " Discard ",
        " Apply ",
    ] {
        assert!(text.contains(needle), "{needle}:\n{text}");
    }
    let (x, y) = locate(&buffer, "List 2");
    click_at(&mut app, x, y).await;
    let editor = app.query_log.held.editor.as_ref().unwrap();
    assert!(editor.lists.contains(&"list-2".to_string()));
    let buffer = draw(&mut app, 80, 24);
    let (x, y) = locate(&buffer, "Discard    Apply");
    assert_eq!(
        mouse::action(&app, click(x, y)),
        Some(mouse::MouseAction::OverlayKey(key(KeyCode::Esc)))
    );
    click_at(&mut app, x + 11, y).await;
    let held = &app.query_log.held;
    assert!(held.editor.is_none());
    assert_eq!(
        held.targets,
        vec![
            target("first.example", RuleAction::Deny, "list-0"),
            target("first.example", RuleAction::Deny, "list-2"),
            target("later.example", RuleAction::Allow, "list-1"),
        ]
    );
}
