use clap::{CommandFactory, Parser};
use purge_warden::cli::Cli;
use purge_warden::ipc::protocol::{IpcCommand, OPERATOR_RULES_MAX_BYTES};
use purge_warden::operator_rules::{
    BatchRequest, Operation, PageRequest, TransportLimits, CONTRACT_VERSION,
};

#[test]
fn canonical_custom_list_and_profile_mount_surfaces_parse() {
    for args in [
        vec!["warden", "custom-list", "list", "--json"],
        vec!["warden", "custom-list", "show", "local", "--json"],
        vec!["warden", "custom-list", "rules", "local", "--limit", "50"],
        vec!["warden", "custom-list", "create", "local", "--dry-run"],
        vec![
            "warden",
            "custom-list",
            "set",
            "local",
            "--description",
            "Local rules",
        ],
        vec![
            "warden",
            "custom-list",
            "add",
            "local",
            "ads.example",
            "--allow",
        ],
        vec![
            "warden",
            "custom-list",
            "add-rule",
            "local",
            "--rule",
            "||ads.example^",
        ],
        vec![
            "warden",
            "custom-list",
            "replace-rule",
            "local",
            "--row-ref",
            "opaque",
            "--rule",
            "||ads.example^",
        ],
        vec![
            "warden",
            "custom-list",
            "remove-rule",
            "local",
            "--row-ref",
            "opaque",
        ],
        vec!["warden", "custom-list", "export", "local"],
        vec![
            "warden",
            "custom-list",
            "delete",
            "local",
            "--cascade-unmount",
        ],
        vec![
            "warden",
            "custom-list",
            "plan",
            "--operations",
            "operations.json",
            "--json",
        ],
        vec![
            "warden",
            "custom-list",
            "apply",
            "--plan",
            "plan.json",
            "--expect-plan-hash",
            "digest",
            "--json",
        ],
        vec!["warden", "custom-list", "operation", "opaque", "--json"],
        vec!["warden", "custom-list", "--offline", "create", "local"],
        vec![
            "warden",
            "profile",
            "mount",
            "household",
            "--custom-list",
            "local",
            "--offline",
        ],
        vec![
            "warden",
            "profile",
            "unmount",
            "household",
            "--custom-list",
            "local",
        ],
    ] {
        Cli::try_parse_from(args.clone())
            .unwrap_or_else(|error| panic!("canonical command failed to parse: {args:?}: {error}"));
    }
}

#[test]
fn top_level_help_describes_the_current_migration_surface() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("Migrate configuration layouts and schema versions"));
    assert!(!help.contains("One-shot migration from the pre-v1"));
}

#[test]
fn custom_list_add_direction_is_exactly_one() {
    for args in [
        vec!["warden", "custom-list", "add", "local", "ads.example"],
        vec![
            "warden",
            "custom-list",
            "add",
            "local",
            "ads.example",
            "--allow",
            "--deny",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn protocol_constants_pin_ipc_batch_page_and_export_limits() {
    assert_eq!(OPERATOR_RULES_MAX_BYTES, 60 * 1024);
    assert_eq!(TransportLimits::IPC.max_operations, 32);
    assert_eq!(TransportLimits::IPC.default_page_size, 50);
    assert_eq!(TransportLimits::IPC.max_page_size, 100);
    assert_eq!(TransportLimits::IPC.max_export_bytes, 16 * 1024);
}

#[tokio::test]
async fn client_refuses_a_full_uor_envelope_over_60_kib() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("oversize.sock");
    let command = IpcCommand::OperatorRulesPlan {
        request: Some(BatchRequest {
            contract_version: CONTRACT_VERSION,
            request_id: "request".into(),
            expected_config_revision: "a".repeat(64),
            operations: vec![Operation::AddRawRule {
                id: "local".into(),
                rule: "x".repeat(OPERATOR_RULES_MAX_BYTES),
            }],
            expected_plan_hash: None,
        }),
        plan_ref: None,
        page: PageRequest::default(),
        token: Some("token".into()),
    };
    let error = purge_warden::ipc::socket_client::send_command(&socket, &command)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("60 KiB IPC limit"));
}

#[test]
fn offline_json_mutation_stdout_is_one_receipt_object() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Whole household"
lists = {}
"#,
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&config)
        .args([
            "custom-list",
            "--offline",
            "create",
            "local",
            "--display-name",
            "Local",
            "--json",
        ])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "stdout must contain exactly one JSON value: {error}; stdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(receipt["persistence"], "committed");
    assert_eq!(receipt["activation"]["state"], "pending");
    assert!(receipt["activation"]["reload_outcome"].is_string());
    assert!(
        output.stderr.is_empty(),
        "JSON mode emitted extra stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn offline_direct_mutation_retry_returns_the_durable_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Whole household"
lists = {}
"#,
    )
    .unwrap();
    let revision = purge_warden::operator_rules::OperatorRulesService::new(&config)
        .read(PageRequest::default(), TransportLimits::IPC)
        .unwrap()
        .config_revision;
    let run = |description: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&config)
            .args([
                "custom-list",
                "--offline",
                "create",
                "local",
                "--description",
                description,
                "--request-id",
                "durable-direct-retry",
                "--expect-revision",
                &revision,
                "--json",
            ])
            .current_dir(temp.path())
            .output()
            .unwrap()
    };

    let first = run("first");
    assert_eq!(first.status.code(), Some(5));
    let first_receipt: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let bytes_after_first = std::fs::read(&config).unwrap();
    let pack_after_first = std::fs::read(temp.path().join("packs/local.txt")).unwrap();

    let retry = run("first");
    assert_eq!(retry.status.code(), Some(5));
    let retry_receipt: serde_json::Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry_receipt["operation_id"], first_receipt["operation_id"]);
    assert_eq!(std::fs::read(&config).unwrap(), bytes_after_first);
    assert_eq!(
        std::fs::read(temp.path().join("packs/local.txt")).unwrap(),
        pack_after_first
    );

    let dry_run = std::process::Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&config)
        .args([
            "custom-list",
            "--offline",
            "create",
            "local",
            "--description",
            "first",
            "--request-id",
            "durable-direct-retry",
            "--expect-revision",
            &revision,
            "--dry-run",
            "--json",
        ])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert_eq!(dry_run.status.code(), Some(3));
    assert_eq!(std::fs::read(&config).unwrap(), bytes_after_first);
    assert_eq!(
        std::fs::read(temp.path().join("packs/local.txt")).unwrap(),
        pack_after_first
    );

    let conflict = run("different");
    assert_eq!(conflict.status.code(), Some(3));
    let error: serde_json::Value = serde_json::from_slice(&conflict.stderr).unwrap();
    assert_eq!(error["code"], "idempotency_conflict");
    assert_eq!(std::fs::read(&config).unwrap(), bytes_after_first);

    let add_revision = purge_warden::operator_rules::OperatorRulesService::new(&config)
        .read(PageRequest::default(), TransportLimits::IPC)
        .unwrap()
        .config_revision;
    let add = |domain: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&config)
            .args([
                "custom-list",
                "--offline",
                "add",
                "local",
                domain,
                "--deny",
                "--request-id",
                "durable-domain-retry",
                "--expect-revision",
                &add_revision,
                "--json",
            ])
            .current_dir(temp.path())
            .output()
            .unwrap()
    };
    let first_add = add("Ads.Example");
    assert_eq!(first_add.status.code(), Some(5));
    let first_add_receipt: serde_json::Value = serde_json::from_slice(&first_add.stdout).unwrap();
    let pack_after_add = std::fs::read(temp.path().join("packs/local.txt")).unwrap();
    let retry_add = add("Ads.Example");
    assert_eq!(retry_add.status.code(), Some(5));
    let retry_add_receipt: serde_json::Value = serde_json::from_slice(&retry_add.stdout).unwrap();
    assert_eq!(
        retry_add_receipt["operation_id"],
        first_add_receipt["operation_id"]
    );
    assert_eq!(
        std::fs::read(temp.path().join("packs/local.txt")).unwrap(),
        pack_after_add
    );
    let conflicting_add = add("Different.Example");
    assert_eq!(conflicting_add.status.code(), Some(3));
    let error: serde_json::Value = serde_json::from_slice(&conflicting_add.stderr).unwrap();
    assert_eq!(error["code"], "idempotency_conflict");
}
