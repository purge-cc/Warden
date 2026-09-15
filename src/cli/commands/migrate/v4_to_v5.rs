use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{ensure, Context};

use crate::config::migration::{self, MigrationChoicesV1, MigrationPlanV1};

const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub fn run(
    master: &Path,
    pid_file: &Path,
    check: bool,
    json: bool,
    plan_output: Option<&Path>,
    choices_path: Option<&Path>,
    replan_output: Option<&Path>,
    apply_plan_path: Option<&Path>,
    expected_plan_hash: Option<&str>,
    rollback_receipt: Option<&str>,
    expected_revision: Option<&str>,
    finalize_receipt: Option<&str>,
) -> anyhow::Result<i32> {
    let modes = usize::from(check)
        + usize::from(plan_output.is_some())
        + usize::from(replan_output.is_some())
        + usize::from(apply_plan_path.is_some())
        + usize::from(rollback_receipt.is_some())
        + usize::from(finalize_receipt.is_some());
    ensure!(modes == 1, "select exactly one v4-to-v5 operation");

    if check {
        let plan = migration::check(master)?;
        if json {
            print_json(&plan)?;
        } else {
            print_summary(&plan);
        }
        return Ok(i32::from(plan.blocked));
    }
    if let Some(output) = plan_output {
        let plan = migration::plan(master, None)?;
        write_new_json(output, &plan)?;
        println!(
            "wrote migration plan {} ({})",
            output.display(),
            plan.plan_hash
        );
        return Ok(i32::from(plan.blocked));
    }
    if let Some(output) = replan_output {
        let path = choices_path.context("--re-plan requires --choices")?;
        let choices: MigrationChoicesV1 = read_json(path)?;
        let plan = migration::plan(master, Some(choices))?;
        write_new_json(output, &plan)?;
        println!(
            "wrote revised migration plan {} ({})",
            output.display(),
            plan.plan_hash
        );
        return Ok(i32::from(plan.blocked));
    }
    if let Some(path) = apply_plan_path {
        let supplied: MigrationPlanV1 = read_json(path)?;
        let expected = expected_plan_hash.context("--apply-plan requires --expect-plan-hash")?;
        print_json(&migration::v4_to_v5::apply_with_pid_file(
            master, pid_file, &supplied, expected,
        )?)?;
        return Ok(0);
    }
    if let Some(receipt) = rollback_receipt {
        let expected = expected_revision.context("--rollback requires --expect-revision")?;
        print_json(&migration::v4_to_v5::rollback_with_pid_file(
            master, pid_file, receipt, expected,
        )?)?;
        return Ok(0);
    }
    let receipt = finalize_receipt.context("missing finalize receipt")?;
    print_json(&migration::v4_to_v5::finalize_with_pid_file(
        master, pid_file, receipt,
    )?)?;
    Ok(0)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(metadata.is_file(), "JSON input is not a regular file");
    ensure!(
        metadata.len() <= MAX_PLAN_BYTES,
        "JSON input exceeds the migration byte limit"
    );
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn write_new_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_PLAN_BYTES,
        "migration plan exceeds the output byte limit"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("refusing to replace migration output {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_summary(plan: &MigrationPlanV1) {
    println!("source revision: {}", plan.source_config_revision);
    println!("plan hash: {}", plan.plan_hash);
    println!("findings: {}", plan.findings.len());
    println!("apply blocked: {}", plan.blocked);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_uses_the_effective_cli_pid_file() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        std::fs::write(&master, "schema_version = 4\n[server]\ndefault_profile = 'base'\n[profiles.base]\n[upstream]\nservers = ['192.0.2.1:53']\n").unwrap();
        let plan = migration::plan(&master, None).unwrap();
        assert!(!plan.blocked);
        let plan_path = root.path().join("plan.json");
        std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        let custom_pid = root.path().join("explicit.pid");
        let _daemon = crate::cli::commands::pid::acquire_pid_lock(&custom_pid).unwrap();
        let before = std::fs::read(&master).unwrap();
        let error = run(
            &master,
            &custom_pid,
            false,
            false,
            None,
            None,
            None,
            Some(&plan_path),
            Some(&plan.plan_hash),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("NodeNotOffline"));
        assert_eq!(std::fs::read(&master).unwrap(), before);
    }
}
