use std::sync::Arc;
use std::time::Instant;

use crate::api::operator_rule_jobs::{OperatorRuleJobConfig, OperatorRuleJobSupervisor};
use crate::auth::token::hash_token;
use crate::dns::cache::DnsCache;
use crate::filter::FilterEngine;
use crate::ipc::socket_server::{current_euid, spawn_ipc_server, DaemonState, ListManagerEndpoint};
use crate::operator_rules::{
    Operation, OperatorRulesService, PersistenceState, RuleAction, CONTRACT_VERSION,
};

use super::{
    read_catalog, read_rules, register_test_token, OperatorPolicyAdapter, OperatorPolicyWorkflow,
    WorkflowState,
};

fn daemon_state(
    token: &str,
    config_path: std::path::PathBuf,
    jobs: crate::api::operator_rule_jobs::OperatorRuleJobClient,
) -> DaemonState {
    DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&crate::config::settings::CacheConfig::default()),
        profiles: None,
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 1,
        upstream_servers: Vec::new(),
        upstream_runtime: None,
        list_count: 1,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(token)))),
        config_path: Some(config_path),
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(
            ListManagerEndpoint::EmptyStable,
        )),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        operator_rule_jobs: Some(jobs),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
        #[cfg(feature = "cluster")]
        node_controller: None,
    }
}

#[tokio::test]
async fn real_socket_adapter_applies_one_revision_bound_batch_and_reads_it_back() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.toml");
    let packs = temp.path().join("packs");
    let socket_path = temp.path().join("warden.sock");
    let sentinel_path = temp.path().join("unrelated.keep");
    std::fs::create_dir(&packs).unwrap();
    std::fs::write(
        &config_path,
        concat!(
            "schema_version = 5\n",
            "[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "[server]\ndefault_profile = \"household\"\n",
            "[profiles.household]\ndisplay_name = \"Whole household\"\nlists = {}\n",
            "[[custom_lists]]\nid = \"existing\"\ndisplay_name = \"Existing\"\n",
            "description = \"must remain untouched\"\n",
        ),
    )
    .unwrap();
    let existing_pack = packs.join("existing.txt");
    let existing_bytes = b"# preserved comment\n||existing.invalid^\n";
    std::fs::write(&existing_pack, existing_bytes).unwrap();
    std::fs::write(&sentinel_path, b"outside operator policy\n").unwrap();

    let service = Arc::new(OperatorRulesService::new(config_path.clone()));
    service
        .metadata()
        .unwrap_or_else(|error| panic!("schema-5 backend fixture must load before IPC: {error:?}"));
    let (supervisor, jobs) = OperatorRuleJobSupervisor::new(
        service,
        OperatorRuleJobConfig::default(),
        None,
        Arc::new(|_| {}),
    );
    jobs.recover().await.unwrap();
    let (supervisor_shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let supervisor_task = tokio::spawn(supervisor.run(shutdown_rx));

    let token = "test-tui-uor-e2e";
    let state = Arc::new(daemon_state(token, config_path.clone(), jobs));
    let server_task = spawn_ipc_server(socket_path.clone(), state).await.unwrap();
    register_test_token(&socket_path, token);

    let before = read_catalog(socket_path.clone()).await.unwrap();
    assert_eq!(before.metadata.schema_version, 5);
    assert_eq!(before.lists.len(), 1);
    assert_eq!(before.lists[0].id, "existing");
    let base_revision = before.metadata.config_revision.clone();

    let adapter = OperatorPolicyAdapter::connect(socket_path.clone())
        .await
        .unwrap();
    let operations = vec![
        Operation::CreateList {
            id: "tui-e2e".into(),
            display_name: "TUI end to end".into(),
            description: "created through the production socket".into(),
            into: None,
        },
        Operation::AddDomainRule {
            id: "tui-e2e".into(),
            domain: "ads.e2e.invalid".into(),
            action: RuleAction::Deny,
        },
        Operation::Mount {
            id: "tui-e2e".into(),
            profile_id: "household".into(),
        },
    ];
    let mut workflow = OperatorPolicyWorkflow::new(base_revision.clone(), operations).unwrap();
    let planning = workflow.begin_plan().unwrap();
    let request_id = planning.request.request_id.clone();
    assert_eq!(planning.request.contract_version, CONTRACT_VERSION);
    assert_eq!(planning.request.expected_config_revision, base_revision);

    let plan = adapter
        .create_plan(planning.request.clone(), planning.page)
        .await
        .unwrap();
    assert_eq!(plan.request_id, request_id);
    assert!(workflow.finish_plan(planning.ticket, Ok(plan)));

    let applying = workflow.begin_apply().unwrap();
    assert_eq!(applying.request.request_id, request_id);
    assert_eq!(applying.plan.request_id, request_id);
    let receipt = adapter.apply(&applying.plan).await.unwrap();
    assert_eq!(receipt.request_id, request_id);
    assert_eq!(receipt.persistence, PersistenceState::Committed);
    assert_eq!(receipt.activation.state, "unknown");
    assert_eq!(
        receipt.activation.reload_outcome.as_deref(),
        Some("not_configured")
    );
    assert!(workflow.finish_apply(applying.ticket, Ok(receipt.clone())));
    assert!(matches!(
        &workflow.state,
        WorkflowState::Outcome { receipt: saved, .. }
            if saved == &receipt && saved.persistence == PersistenceState::Committed
    ));

    let after = read_catalog(socket_path.clone()).await.unwrap();
    assert_ne!(after.metadata.config_revision, base_revision);
    assert_eq!(after.metadata.config_revision, receipt.config_revision);
    assert_eq!(
        after.metadata.desired_operator_policy_hash,
        receipt.operator_policy_hash.clone().unwrap()
    );
    assert!(!after.metadata.activation_in_sync);
    let created = after
        .lists
        .iter()
        .find(|list| list.id == "tui-e2e")
        .expect("created list must be in the daemon inventory");
    assert_eq!(created.config_revision, receipt.config_revision);
    assert_eq!(created.profiles, vec!["household".to_string()]);
    let rules = read_rules(
        socket_path.clone(),
        created.id.clone(),
        created.config_revision.clone(),
        created.pack_revision.clone(),
    )
    .await
    .unwrap();
    assert_eq!(rules.rows.len(), 1);
    assert_eq!(rules.rows[0].raw, "||ads.e2e.invalid^");
    assert_eq!(rules.rows[0].action, Some(RuleAction::Deny));

    let loaded =
        crate::config::loader::load_current_config(&config_path, time::OffsetDateTime::now_utc())
            .unwrap();
    let profile = &loaded.config.profiles["household"];
    assert_eq!(profile.display_name, "Whole household");
    assert!(profile
        .custom_lists
        .iter()
        .any(|id| id.as_str() == "tui-e2e"));
    assert_eq!(std::fs::read(&existing_pack).unwrap(), existing_bytes);
    assert_eq!(
        std::fs::read(&sentinel_path).unwrap(),
        b"outside operator policy\n"
    );

    server_task.abort();
    let _ = server_task.await;
    let _ = supervisor_shutdown.send(());
    supervisor_task.await.unwrap();
}
