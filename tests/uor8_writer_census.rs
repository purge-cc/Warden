//! Semantic census of every schema-5 policy ingress.
//!
//! This deliberately checks route boundaries rather than counting calls or
//! banning a spelling globally. External blocklists and generic configuration
//! have their own persistence contracts; their common obligation is to load a
//! schema-5 candidate and reject retired operator-rule fields. Operator point
//! policy, in contrast, has one service and one durable transaction path.

const CUSTOM_LIST_CLI: &str = include_str!("../src/cli/commands/custom_list.rs");
const IPC_SERVER: &str = include_str!("../src/ipc/socket_server.rs");
const REST_OPERATOR_RULES: &str = include_str!("../src/api/operator_rules.rs");
const OPERATOR_JOBS: &str = include_str!("../src/api/operator_rule_jobs.rs");
const OPERATOR_SERVICE: &str = include_str!("../src/operator_rules/service.rs");
const CONFIG_EDIT: &str = include_str!("../src/cli/commands/config/edit.rs");
const BLOCKLISTS: &str = include_str!("../src/cli/commands/blocklists.rs");
const RESTORE: &str = include_str!("../src/cli/commands/config/restore.rs");
const ARTIFACT_APPLY: &str = include_str!("../src/cluster/artifact_apply.rs");
const V4_TO_V5_MIGRATION: &str = include_str!("../src/config/migration/v4_to_v5.rs");

/// Legacy decoding is not a general writer exemption. These are the only
/// exact historical entry points the census permits to name schema 4.
const LEGACY_DECODER_EXCEPTIONS: &[(&str, &str)] = &[(
    "src/config/migration/v4_to_v5.rs",
    "offline v4-to-v5 plan, apply, rollback, and receipt recovery",
)];

fn production(source: &str) -> &str {
    // Several production functions contain tiny `#[cfg(test)]` fault hooks.
    // Only the terminal test module is outside the production route census.
    source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source)
}

fn require_in_order(surface: &str, source: &str, anchors: &[&str]) {
    let mut remaining = production(source);
    for anchor in anchors {
        let offset = remaining.find(anchor).unwrap_or_else(|| {
            panic!("{surface} no longer contains required route anchor `{anchor}`")
        });
        remaining = &remaining[offset + anchor.len()..];
    }
}

fn require_absent(surface: &str, source: &str, forbidden: &str) {
    assert!(
        !production(source).contains(forbidden),
        "{surface} gained direct writer marker `{forbidden}`; either route it through the \n         documented policy contract or add a narrowly justified census entry"
    );
}

#[test]
fn operator_point_policy_cli_ipc_and_rest_converge_on_one_service_transaction() {
    // Offline CLI is the one direct adapter; connected CLI sends the same
    // OperatorRulesApply envelope to the daemon rather than writing locally.
    require_in_order(
        "custom-list CLI",
        CUSTOM_LIST_CLI,
        &[
            "async fn mutate(",
            "if offline {",
            "OperatorRulesService::new(config_path)",
            "service.apply_with_prepared(",
            "IpcCommand::OperatorRulesApply",
        ],
    );
    require_absent(
        "custom-list CLI",
        CUSTOM_LIST_CLI,
        "write_value_validated_locked(",
    );

    require_in_order(
        "IPC operator-rules apply",
        IPC_SERVER,
        &[
            "IpcCommand::OperatorRulesApply {",
            "handle_operator_rules_apply(state, peer_uid, plan_ref, plan_hash, request_id).await",
            "async fn handle_operator_rules_apply(",
            "submit_operator_plan_and_wait(&jobs, actor, plan_ref, plan_hash, request_id).await",
            "jobs\n        .submit(actor.clone(), plan_ref, plan_hash, request_id)",
        ],
    );

    require_in_order(
        "REST operator-rules apply",
        REST_OPERATOR_RULES,
        &[
            "pub async fn apply(",
            "Idempotency-Key is required",
            ".submit_with_precondition(",
        ],
    );

    require_in_order(
        "operator job worker",
        OPERATOR_JOBS,
        &[
            "async fn run_job(",
            "tokio::task::spawn_blocking(move || {",
            "service.apply_with_prepared(&apply_actor, &request, limits",
        ],
    );
    require_in_order(
        "operator service transaction",
        OPERATOR_SERVICE,
        &[
            "pub fn apply_with_prepared(",
            "policy_transaction::prepare_with_hook(",
            "PrepareOutcome::Prepared(prepared) => match prepared.commit()",
        ],
    );
}

#[test]
fn generic_import_restore_and_replica_validate_schema_five_before_persisting() {
    require_in_order(
        "generic config edit",
        CONFIG_EDIT,
        &[
            "pub fn run_edit(",
            "write_lock::acquire_for_write(config_path)",
            "load_config_v5_executable_under_editor_guard(&guard, &canonical_master, now)",
        ],
    );

    // `import-local` deliberately remains an external-list writer. It must
    // nevertheless preflight and revalidate the exact schema-5 tree before
    // it can publish either the list body or its declaration.
    require_in_order(
        "external blocklist import",
        BLOCKLISTS,
        &[
            "pub async fn run_import_local(",
            "let preflight = load_current_config(config_path",
            "run_import_local_transaction(",
            "fn run_import_local_locked(",
            "load_config_for_schema_under_guard(guard, config_path, TARGET_SCHEMA_VERSION_V5",
            "prepare_value_validated_single_locked(guard, config_path, &target_path, &document)",
        ],
    );

    require_in_order(
        "config restore",
        RESTORE,
        &[
            "pub fn restore_archive(",
            "loader::load_config_v5_executable(&staged_master, now)",
            "fn restore_staged_locked(",
            "load_config_v5_executable_with_policy_overlays_under_migration_guard(",
            "policy_transaction::apply(",
        ],
    );

    require_in_order(
        "cluster replica receiver",
        ARTIFACT_APPLY,
        &[
            "fn apply_with_runtime(",
            "let loaded = load_current(&guard)?",
            "let validated = validate_candidate(&guard, &after, &toml, &packs, now)?",
            "let prepared = prepare_apply_verified(",
            "transaction.commit()?",
        ],
    );
}

#[test]
fn schema_five_rejects_retired_operator_rule_fields_before_external_import_can_write() {
    let temp = tempfile::tempdir().expect("temporary config directory");
    let config = temp.path().join("config.toml");
    std::fs::write(
        &config,
        "schema_version = 5\n\
         [server]\n\
         default_profile = \"household\"\n\
         [profiles.household]\n\
         display_name = \"Household\"\n\
         admin_rules = [\"retired-rule\"]\n\
         [upstream]\n\
         servers = [\"192.0.2.1:53\"]\n",
    )
    .expect("write test config");

    let errors = purge_warden::config::loader::load_current_config(
        &config,
        time::OffsetDateTime::UNIX_EPOCH,
    )
    .expect_err("schema-5 loader must reject retired profile admin_rules");
    assert!(
        errors
            .iter()
            .any(|error| error.to_string().contains("admin_rules")),
        "retired field must be named in the schema-5 diagnostic: {errors:?}"
    );
}

#[test]
fn legacy_decoder_exceptions_are_exact_and_stay_inside_migration_history() {
    assert_eq!(LEGACY_DECODER_EXCEPTIONS.len(), 1);
    let (path, purpose) = LEGACY_DECODER_EXCEPTIONS[0];
    assert_eq!(path, "src/config/migration/v4_to_v5.rs");
    assert_eq!(
        purpose,
        "offline v4-to-v5 plan, apply, rollback, and receipt recovery"
    );
    require_in_order(
        "v4 migration/history decoder",
        V4_TO_V5_MIGRATION,
        &[
            "const SOURCE_SCHEMA: u32 = 4;",
            "load_config_for_schema_under_migration_guard(",
            "SOURCE_SCHEMA,",
            "policy_transaction::prepare_with_hook_after_recovery(",
        ],
    );
}
