//! `warden rewrite` CLI surface.
//!
//! Three verbs (`add` / `remove` / `list`) under `warden rewrite`, all
//! profile-scoped — no global rewrites. Mirrors [`super::local_dns`]'s
//! shape: validator pre-flight on the merged `[existing..., new]` slice
//! via [`crate::config::validator::validate_rewrite_rules`], TOML
//! mutation via [`super::target::write_value_validated`] (full v1 loader
//! run against the STAGED bytes before the rename, so a rejected tree
//! never lands), reload feedback, then single-seat audit emit.
//!
//! Idempotent silent no-op: `add` of a rule with the SAME `(from, to,
//! match_subdomains)` returns [`AddOutcome::NoOp`] — no write, no reload,
//! no audit.

use std::path::{Path, PathBuf};

use anyhow::bail;
use toml::Value;

use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::settings::RewriteRule;
use crate::config::validator::validate_rewrite_rules;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::local_dns::profile_scoped::{
    ensure_profile_exists, ensure_profile_exists_in, find_profile_entry_mut,
    find_profile_target_file, load_for_resolution,
};
use super::target::{
    count_devices_on_profile, read_or_empty, resolve_explicit_into_under, write_value_validated,
};

// ── Frozen strings ────────────────────────────────────────────────────

/// Profile referenced by `--profile <id>` does not exist.
pub const REWRITE_PROFILE_NOT_FOUND: &str =
    "rewrite_rules: profile '{id}' referenced by --profile does not exist. Known profiles: {list}.";

pub fn format_rewrite_profile_not_found(id: &str, known: &[&str]) -> String {
    let list = if known.is_empty() {
        "(none configured)".to_string()
    } else {
        known.join(", ")
    };
    REWRITE_PROFILE_NOT_FOUND
        .replace("{id}", id)
        .replace("{list}", &list)
}

/// Operator-facing success message for `add`.
pub const REWRITE_ADDED: &str =
    "Added rewrite '{from}' → '{to}' on profile '{profile}'. Affects {n} device(s) currently. \
     To remove: warden rewrite remove '{from}' --profile '{profile}'";

pub fn format_rewrite_added(from: &str, to: &str, profile: &str, n: usize) -> String {
    REWRITE_ADDED
        .replace("{from}", from)
        .replace("{to}", to)
        .replace("{profile}", profile)
        .replace("{n}", &n.to_string())
}

/// Operator-facing success message for `remove`.
pub const REWRITE_REMOVED: &str = "Removed rewrite '{from}' from profile '{profile}'.";

pub fn format_rewrite_removed(from: &str, profile: &str) -> String {
    REWRITE_REMOVED
        .replace("{from}", from)
        .replace("{profile}", profile)
}

/// `remove` of a rule that does not exist on the requested profile.
pub const REWRITE_REMOVE_NOT_FOUND: &str =
    "rewrite_rules: no rewrite '{from}' found on profile '{profile}' — nothing to remove.";

pub fn format_rewrite_remove_not_found(from: &str, profile: &str) -> String {
    REWRITE_REMOVE_NOT_FOUND
        .replace("{from}", from)
        .replace("{profile}", profile)
}

/// `list` empty-state when a single profile is targeted and has no rules.
pub const REWRITE_EMPTY_PROFILE: &str =
    "No rewrites on profile '{profile}'. Add with `warden rewrite add <from> <to> --profile '{profile}'`.";

pub fn format_rewrite_empty_profile(profile: &str) -> String {
    REWRITE_EMPTY_PROFILE.replace("{profile}", profile)
}

// ── Public types ──────────────────────────────────────────────────────

/// Operator-supplied rewrite spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteSpec {
    pub from: String,
    pub to: String,
    pub match_subdomains: bool,
}

impl RewriteSpec {
    fn to_schema(&self) -> RewriteRule {
        RewriteRule {
            from: self.from.clone(),
            to: self.to.clone(),
            match_subdomains: self.match_subdomains,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum AddOutcome {
    Applied {
        file: PathBuf,
        devices_affected: usize,
    },
    NoOp,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum RemoveOutcome {
    Removed { file: PathBuf, n_dropped: usize },
    NotFound,
}

// ── add_inner / remove_inner — single seat ────────────────────────────

pub(crate) fn add_inner(
    config_path: &Path,
    profile_id: &str,
    spec: &RewriteSpec,
    into: Option<&Path>,
) -> anyhow::Result<AddOutcome> {
    ensure_profile_exists(config_path, profile_id, format_rewrite_profile_not_found)?;

    // Snapshot existing rules + local_records (profile + global, for
    // shadow-warning context).
    let (existing, local_records, global_records) = load_profile_state(config_path, profile_id)?;

    // Idempotent silent no-op.
    let new_rule = spec.to_schema();
    if existing.iter().any(|r| rules_byte_equal(r, &new_rule)) {
        return Ok(AddOutcome::NoOp);
    }

    // Validator pre-flight on `[existing..., new_rule]`.
    let mut merged = existing;
    merged.push(new_rule.clone());
    let scope_label = format!("profiles.{profile_id}.rewrite_rules");
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    validate_rewrite_rules(
        &merged,
        &scope_label,
        &local_records,
        &global_records,
        &mut errors,
        &mut warnings,
    );
    if !errors.is_empty() {
        bail!(
            "cannot add rewrite rule — config would become invalid:\n  {}",
            errors.join("\n  ")
        );
    }
    for msg in warnings {
        tracing::warn!(target: "audit", "profiles.{profile_id}: {msg}");
    }

    let target_path = match into {
        Some(p) => resolve_explicit_into_under(config_path, p)?,
        None => find_profile_target_file(config_path, profile_id)?,
    };

    let (mut doc, _) = read_or_empty(&target_path)?;
    let inserted = append_profile_rule(&mut doc, profile_id, spec)?;
    if !inserted {
        return Ok(AddOutcome::NoOp);
    }
    write_value_validated(config_path, &target_path, &doc)?;

    tracing::debug!(
        target: "audit",
        scope = "profile",
        target_id = profile_id,
        from = %spec.from,
        to = %spec.to,
        match_subdomains = spec.match_subdomains,
        "rewrite.add detail"
    );

    let profile_id_for_audit = profile_id.to_string();
    let from_for_audit = spec.from.clone();
    let to_for_audit = spec.to.clone();
    let match_subdomains_for_audit = spec.match_subdomains;
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("rewrite.add")
            .with_scope("profile")
            .with_target_id(profile_id_for_audit)
            .with_rewrite_from(from_for_audit)
            .with_rewrite_to(to_for_audit)
            .with_match_subdomains(match_subdomains_for_audit)
    });

    let devices_affected = count_devices_on_profile(config_path, profile_id);
    Ok(AddOutcome::Applied {
        file: target_path,
        devices_affected,
    })
}

pub(crate) fn remove_inner(
    config_path: &Path,
    profile_id: &str,
    from: &str,
    into: Option<&Path>,
) -> anyhow::Result<RemoveOutcome> {
    ensure_profile_exists(config_path, profile_id, format_rewrite_profile_not_found)?;
    let canonical_from = from.to_ascii_lowercase();

    let target_path = match into {
        Some(p) => resolve_explicit_into_under(config_path, p)?,
        None => find_profile_target_file(config_path, profile_id)?,
    };

    // Snapshot matching rules pre-removal so audit can carry `to` field.
    let pre_removal: Vec<RewriteRule> = load_profile_state(config_path, profile_id)
        .map(|(rules, _, _)| rules)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.from.eq_ignore_ascii_case(&canonical_from))
        .collect();

    let (mut doc, _) = read_or_empty(&target_path)?;
    let n_dropped = drop_profile_rules(&mut doc, profile_id, &canonical_from)?;
    if n_dropped == 0 {
        return Ok(RemoveOutcome::NotFound);
    }
    write_value_validated(config_path, &target_path, &doc)?;

    let profile_id_for_audit = profile_id.to_string();
    let from_for_audit = canonical_from.clone();
    let single_pre = (pre_removal.len() == 1).then(|| pre_removal[0].clone());
    persist_cli_mutation_audit(config_path, move || {
        let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("rewrite.remove")
            .with_scope("profile")
            .with_target_id(profile_id_for_audit)
            .with_rewrite_from(from_for_audit);
        if let Some(prev) = single_pre {
            rec = rec
                .with_rewrite_to(prev.to)
                .with_match_subdomains(prev.match_subdomains);
        }
        rec
    });

    Ok(RemoveOutcome::Removed {
        file: target_path,
        n_dropped,
    })
}

// ── Public CLI handlers ───────────────────────────────────────────────

/// `warden rewrite add <from> <to> --profile <id> [--match-subdomains] [--into ...]`
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    from: &str,
    to: &str,
    profile: &str,
    match_subdomains: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let spec = RewriteSpec {
        from: from.to_ascii_lowercase(),
        to: to.to_ascii_lowercase(),
        match_subdomains,
    };
    let outcome = add_inner(config_path, profile, &spec, into)?;
    match outcome {
        AddOutcome::Applied {
            file: _,
            devices_affected,
        } => {
            println!(
                "{}",
                format_rewrite_added(&spec.from, &spec.to, profile, devices_affected)
            );
        }
        AddOutcome::NoOp => {
            println!(
                "rewrite '{}' → '{}' already present on profile '{}' — no-op",
                spec.from, spec.to, profile
            );
            return Ok(());
        }
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// `warden rewrite remove <from> --profile <id> [--into ...]`
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    from: &str,
    profile: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // `remove_inner` owns canonicalisation (it lowercases `from` itself),
    // so pass the raw input through and keep `canonical` only for the
    // operator-facing messages below — avoids lowercasing the same string
    // twice across the wrapper/inner boundary.
    let canonical = from.to_ascii_lowercase();
    let outcome = remove_inner(config_path, profile, from, into)?;
    match outcome {
        RemoveOutcome::Removed { .. } => {
            println!("{}", format_rewrite_removed(&canonical, profile));
        }
        RemoveOutcome::NotFound => {
            println!("{}", format_rewrite_remove_not_found(&canonical, profile));
            return Ok(());
        }
    }
    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// `warden rewrite list [--profile <id>]`
pub fn run_list(config_path: &Path, profile: Option<&str>) -> anyhow::Result<()> {
    let cfg = load_for_resolution(config_path)?;
    let want_profiles: Vec<String> = match profile {
        Some(id) => {
            ensure_profile_exists_in(&cfg, id, format_rewrite_profile_not_found)?;
            vec![id.to_string()]
        }
        None => cfg
            .profiles
            .keys()
            .map(|k| k.as_str().to_string())
            .collect(),
    };

    let mut printed_any = false;
    for pid in &want_profiles {
        let Some((_, profile_def)) = cfg.profiles.iter().find(|(k, _)| k.as_str() == pid) else {
            continue;
        };
        if profile_def.rewrite_rules.is_empty() {
            continue;
        }
        if printed_any {
            println!();
        }
        println!(
            "# profile '{pid}' rewrite rules ({} total)",
            profile_def.rewrite_rules.len()
        );
        print_rule_table(&profile_def.rewrite_rules);
        printed_any = true;
    }
    if !printed_any {
        if let Some(only) = (want_profiles.len() == 1).then(|| &want_profiles[0]) {
            println!("{}", format_rewrite_empty_profile(only));
        } else {
            println!("no rewrite rules configured on any profile");
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────

fn load_profile_state(
    config_path: &Path,
    profile_id: &str,
) -> anyhow::Result<(
    Vec<RewriteRule>,
    Vec<crate::config::settings::LocalDnsRecord>,
    Vec<crate::config::settings::LocalDnsRecord>,
)> {
    let cfg = load_for_resolution(config_path)?;
    let Some((_, p)) = cfg.profiles.iter().find(|(k, _)| k.as_str() == profile_id) else {
        let known: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
        bail!("{}", format_rewrite_profile_not_found(profile_id, &known));
    };
    Ok((
        p.rewrite_rules.clone(),
        p.local_records.clone(),
        cfg.local_dns.records.clone(),
    ))
}

fn append_profile_rule(
    doc: &mut Value,
    profile_id: &str,
    spec: &RewriteSpec,
) -> anyhow::Result<bool> {
    let entry = find_profile_entry_mut(doc, profile_id)?
        .ok_or_else(|| anyhow::anyhow!("profile '{profile_id}' not present in target document"))?;
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("profile entry is not a TOML table"))?;
    let arr_value = tbl
        .entry("rewrite_rules".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`rewrite_rules` must be an array of tables"))?;
    if rules_array_contains_byte_identical(arr, spec) {
        return Ok(false);
    }
    arr.push(spec_to_toml_value(spec));
    Ok(true)
}

fn drop_profile_rules(
    doc: &mut Value,
    profile_id: &str,
    canonical_from: &str,
) -> anyhow::Result<usize> {
    let Some(entry) = find_profile_entry_mut(doc, profile_id)? else {
        return Ok(0);
    };
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("profile entry is not a TOML table"))?;
    let Some(arr_value) = tbl.get_mut("rewrite_rules") else {
        return Ok(0);
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`rewrite_rules` must be an array"))?;
    let before = arr.len();
    arr.retain(|item| {
        let from_match = item
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
            == Some(canonical_from);
        !from_match
    });
    Ok(before.saturating_sub(arr.len()))
}

fn rules_byte_equal(a: &RewriteRule, b: &RewriteRule) -> bool {
    a.from.eq_ignore_ascii_case(&b.from)
        && a.to.eq_ignore_ascii_case(&b.to)
        && a.match_subdomains == b.match_subdomains
}

fn rules_array_contains_byte_identical(arr: &[Value], spec: &RewriteSpec) -> bool {
    arr.iter().any(|item| {
        let from_match = item
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case(&spec.from))
            .unwrap_or(false);
        let to_match = item
            .get("to")
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case(&spec.to))
            .unwrap_or(false);
        let subdomain_match = item
            .get("match_subdomains")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            == spec.match_subdomains;
        from_match && to_match && subdomain_match
    })
}

fn spec_to_toml_value(spec: &RewriteSpec) -> Value {
    let mut tbl = toml::map::Map::new();
    tbl.insert("from".into(), Value::String(spec.from.clone()));
    tbl.insert("to".into(), Value::String(spec.to.clone()));
    if spec.match_subdomains {
        tbl.insert("match_subdomains".into(), Value::Boolean(true));
    }
    Value::Table(tbl)
}

fn print_rule_table(rules: &[RewriteRule]) {
    println!("  {:<32}  {:<32}  SUBDOMAIN", "FROM", "TO");
    for r in rules {
        println!(
            "  {:<32}  {:<32}  {}",
            r.from,
            r.to,
            if r.match_subdomains { "true" } else { "false" }
        );
    }
}
