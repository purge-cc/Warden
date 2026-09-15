use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn run(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(config)
        .args(args)
        .current_dir(config.parent().unwrap())
        .output()
        .expect("run migration command")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn real_cli_bootstraps_rolls_back_reapplies_and_finalizes_v4_to_v5() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    let plan_path = root.path().join("migration-plan.json");
    let source = br#"schema_version = 4

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "household"

[profiles.household]
display_name = "Household"
lists = {}
"#;
    std::fs::write(&config, source).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
    let source_mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;

    let check = run(&config, &["migrate", "v4-to-v5", "--check", "--json"]);
    assert!(
        check.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check = json(&check);
    assert_eq!(check["source_schema"], 4);
    assert_eq!(check["target_schema"], 5);
    assert_eq!(check["blocked"], false);
    let plan_hash = check["plan_hash"].as_str().unwrap().to_string();

    let planned = run(
        &config,
        &["migrate", "v4-to-v5", "--plan", plan_path.to_str().unwrap()],
    );
    assert!(
        planned.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let plan: Value = serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(plan["plan_hash"], plan_hash);
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let wrong_hash = run(
        &config,
        &[
            "migrate",
            "v4-to-v5",
            "--apply-plan",
            plan_path.to_str().unwrap(),
            "--expect-plan-hash",
            &"0".repeat(64),
        ],
    );
    assert!(!wrong_hash.status.success());
    assert_eq!(std::fs::read(&config).unwrap(), source);

    let apply_args = [
        "migrate",
        "v4-to-v5",
        "--apply-plan",
        plan_path.to_str().unwrap(),
        "--expect-plan-hash",
        &plan_hash,
    ];
    let first = run(&config, &apply_args);
    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = json(&first);
    assert_eq!(first["persistence"], "committed");
    assert_eq!(first["plan_hash"], plan_hash);
    let first_receipt = first["receipt_id"].as_str().unwrap();
    let first_revision = first["candidate_config_revision"].as_str().unwrap();
    purge_warden::config::loader::load_config_v5_executable(
        &config,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();

    let wrong_rollback = run(
        &config,
        &[
            "migrate",
            "v4-to-v5",
            "--rollback",
            first_receipt,
            "--expect-revision",
            &"f".repeat(64),
        ],
    );
    assert!(!wrong_rollback.status.success());

    let rollback = run(
        &config,
        &[
            "migrate",
            "v4-to-v5",
            "--rollback",
            first_receipt,
            "--expect-revision",
            first_revision,
        ],
    );
    assert!(
        rollback.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    assert_eq!(
        json(&rollback)["restored"]["revision"],
        plan["source_config_revision"]
    );
    assert_eq!(std::fs::read(&config).unwrap(), source);
    assert_eq!(
        std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        source_mode
    );

    let second = run(&config, &apply_args);
    assert!(
        second.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second = json(&second);
    assert_eq!(second["persistence"], "committed");
    assert_ne!(second["receipt_id"], first["receipt_id"]);
    let replay = run(&config, &apply_args);
    assert!(replay.status.success());
    assert_eq!(json(&replay), second);

    let finalize = run(
        &config,
        &[
            "migrate",
            "v4-to-v5",
            "--finalize",
            second["receipt_id"].as_str().unwrap(),
        ],
    );
    assert!(
        finalize.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&finalize.stderr)
    );
    assert_eq!(
        json(&finalize)["finalized"]["receipt_id"],
        second["receipt_id"]
    );
    purge_warden::config::loader::load_config_v5_executable(
        &config,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
}
