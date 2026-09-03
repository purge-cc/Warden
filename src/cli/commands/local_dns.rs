//! Local DNS Scoping CLI surface.
//!
//! Four verbs (`add` / `remove` / `list` / `show`) under `warden local-dns`,
//! each driving the `[[local_dns.records]]` global table OR a profile's
//! `Profile.local_records` array depending on `--profile <id>`. Single
//! seat: [`add_inner`] / [`remove_inner`] are the only paths that mutate
//! either slice — clap dispatches and the TUI tab modal both call them.
//!
//! Mutation flow:
//!   1. Validator pre-flight against the merged `[existing..., new]`
//!      slice via `validate_local_records_v2`.
//!   2. TOML mutation via [`super::target::write_value_validated`]: the
//!      full v1 loader runs against the STAGED bytes before the rename,
//!      so a tree the loader would reject never lands on disk.
//!   3. `super::ipc_reload::attempt_reload` fires the reload feedback.
//!   4. Audit emit via `AuditWriter::append_cli_mutation` inside the
//!      inner helpers, NOT the outer `run_*` — single-seat means single
//!      audit emission.
//!
//! Idempotent silent no-op: `add` of a record with the SAME
//! `(domain, type, value, match_subdomains, ttl_secs)` in the same scope
//! returns [`AddOutcome::NoOp`] — no write, no reload, no audit, mirroring
//! `apply_blocklists_change_inline`.

use std::path::{Path, PathBuf};

use anyhow::bail;
use toml::Value;

use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
use crate::config::validator::validate_local_records_v2;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::target::{
    count_devices_on_profile, read_or_empty, resolve_explicit_into_under, write_value_validated,
};

use self::profile_scoped::{
    ensure_profile_exists, ensure_profile_exists_in, find_profile_entry_mut,
    find_profile_target_file, load_for_resolution,
};

// ── Frozen strings ─────────────────────────────────────────────────────

/// Profile referenced by `--profile <id>` does not exist.
pub const LOCAL_RECORDS_PROFILE_NOT_FOUND: &str =
    "local_records: profile '{id}' referenced by --profile does not exist. Known profiles: {list}.";

pub fn format_local_records_profile_not_found(id: &str, known: &[&str]) -> String {
    let list = if known.is_empty() {
        "(none configured)".to_string()
    } else {
        known.join(", ")
    };
    LOCAL_RECORDS_PROFILE_NOT_FOUND
        .replace("{id}", id)
        .replace("{list}", &list)
}

/// Operator-facing success message for a global-scope `add`.
pub const LOCAL_RECORDS_ADDED_GLOBAL: &str =
    "Added global local DNS record '{domain}' {type} → {value}. To remove: warden local-dns remove '{domain}'";

pub fn format_local_records_added_global(domain: &str, ty: &str, value: &str) -> String {
    LOCAL_RECORDS_ADDED_GLOBAL
        .replace("{domain}", domain)
        .replace("{type}", ty)
        .replace("{value}", value)
}

/// Operator-facing success message for a profile-scope `add`.
pub const LOCAL_RECORDS_ADDED_PROFILE: &str =
    "Added local DNS record '{domain}' {type} → {value} on profile '{profile}'. Affects {n} device(s) currently. To remove: warden local-dns remove '{domain}' --profile '{profile}'";

pub fn format_local_records_added_profile(
    domain: &str,
    ty: &str,
    value: &str,
    profile: &str,
    n: usize,
) -> String {
    LOCAL_RECORDS_ADDED_PROFILE
        .replace("{domain}", domain)
        .replace("{type}", ty)
        .replace("{value}", value)
        .replace("{profile}", profile)
        .replace("{n}", &n.to_string())
}

/// Operator-facing success message for `remove`. `{scope}` is `"global"`
/// for the top-level table or `"profile '<id>'"` for a profile-scope.
pub const LOCAL_RECORDS_REMOVED: &str = "Removed local DNS record '{domain}' from {scope}.";

pub fn format_local_records_removed(domain: &str, scope: &str) -> String {
    LOCAL_RECORDS_REMOVED
        .replace("{domain}", domain)
        .replace("{scope}", scope)
}

/// `remove` of a record that does not exist in the requested scope.
pub const LOCAL_RECORDS_REMOVE_NOT_FOUND: &str =
    "local_records: no record '{domain}' found in {scope} — nothing to remove.";

pub fn format_local_records_remove_not_found(domain: &str, scope: &str) -> String {
    LOCAL_RECORDS_REMOVE_NOT_FOUND
        .replace("{domain}", domain)
        .replace("{scope}", scope)
}

/// TUI Local DNS tab — empty state on the Global panel.
pub const LOCAL_RECORDS_TAB_EMPTY_GLOBAL: &str =
    "No global local DNS records. Add with `warden local-dns add <domain> <type> <value>`.";

/// TUI Local DNS tab — empty state on a per-profile panel.
pub const LOCAL_RECORDS_TAB_EMPTY_PROFILE: &str =
    "No local DNS records on profile '{profile}'. Add with `warden local-dns add <domain> <type> <value> --profile '{profile}'`.";

pub fn format_local_records_tab_empty_profile(profile: &str) -> String {
    LOCAL_RECORDS_TAB_EMPTY_PROFILE.replace("{profile}", profile)
}

// ── Public types ──────────────────────────────────────────────────────

/// Scope of a local-DNS-records mutation: the global `[[local_dns.records]]`
/// table OR a single profile's `Profile.local_records` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalRecordScope {
    Global,
    Profile(String),
}

impl LocalRecordScope {
    /// Audit log + display tag.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Profile(_) => "profile",
        }
    }

    /// Operator-facing target id (`"global"` for the global scope, or the
    /// profile id otherwise).
    pub fn target_id(&self) -> &str {
        match self {
            Self::Global => "global",
            Self::Profile(id) => id.as_str(),
        }
    }

    /// Validator scope label (`"local_dns"` for global, `"profiles.<id>.local_records"` per-profile)
    /// matching [`validate_local_records_v2`] expectations.
    fn validator_label(&self) -> String {
        match self {
            Self::Global => "local_dns".to_string(),
            Self::Profile(id) => format!("profiles.{id}.local_records"),
        }
    }

    /// Human label for the success / not-found frozen strings
    /// (`"global"` or `"profile '<id>'"`).
    fn human_label(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Profile(id) => format!("profile '{id}'"),
        }
    }
}

/// Operator-supplied record being added. A separate type from
/// [`LocalDnsRecord`] so the CLI surface can stay distinct from the
/// schema struct (and so the TUI modal can pre-fill / inspect without
/// holding a borrowed schema reference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecordSpec {
    pub domain: String,
    pub record_type: LocalDnsRecordType,
    pub value: String,
    pub match_subdomains: bool,
    pub ttl_secs: Option<u32>,
}

impl LocalRecordSpec {
    fn record_type_str(&self) -> &'static str {
        record_type_to_str(self.record_type)
    }

    /// Convert into the schema struct so the validator pre-flight can
    /// reuse [`validate_local_records_v2`].
    fn to_schema(&self) -> LocalDnsRecord {
        LocalDnsRecord {
            domain: self.domain.clone(),
            record_type: self.record_type,
            value: self.value.clone(),
            match_subdomains: self.match_subdomains,
            ttl_secs: self.ttl_secs,
        }
    }
}

/// Outcome of an `add` mutation. `NoOp` covers the idempotent path
/// (record already present byte-identical); the caller skips the reload
/// + audit on a true no-op.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `file` is read only by tests; production callers
                    // (CLI dispatch, TUI submit handler) ignore it.
pub(crate) enum AddOutcome {
    Applied {
        file: PathBuf,
        devices_affected: usize,
    },
    NoOp,
}

/// Outcome of a `remove` mutation. `NotFound` distinguishes
/// "operator typed a non-existent record" from "removal succeeded".
#[derive(Debug, Clone)]
#[allow(dead_code)] // Same as `AddOutcome`: `file` + `n_dropped` are
                    // read only by tests.
pub(crate) enum RemoveOutcome {
    Removed { file: PathBuf, n_dropped: usize },
    NotFound,
}

// ── add_inner / remove_inner — single seat ─────────────────────────

/// Single-seat `add` mutation. Called by the CLI dispatch and by the
/// TUI Local DNS tab's submit handler. Sync — caller fires the reload +
/// the success message.
///
/// Validator pre-flight: builds the merged
/// `[existing_records..., new_spec]` slice and runs
/// [`validate_local_records_v2`] against it. Errors → bail without
/// touching disk. Catches every locked check:
///   - per-scope duplicate detection.
///   - PSL refusal on `match_subdomains: true` over public suffixes.
///   - root-subdomain refusal.
///   - reserved-IP target refusal (0.0.0.0, 127/8, 224/4, etc.).
///   - TTL out-of-range.
///   - CNAME loop detection.
///   - A+CNAME conflict per scope.
pub(crate) fn add_inner(
    config_path: &Path,
    scope: &LocalRecordScope,
    spec: &LocalRecordSpec,
    into: Option<&Path>,
) -> anyhow::Result<AddOutcome> {
    // 1. Validate scope target exists (profile-scope only — global
    //    always has a home, the master config).
    if let LocalRecordScope::Profile(id) = scope {
        ensure_profile_exists(config_path, id, format_local_records_profile_not_found)?;
    }

    // 2. Snapshot existing records in this scope (for idempotency probe
    //    + validator pre-flight context).
    let existing = load_scope_records(config_path, scope)?;

    // 3. Idempotent silent no-op: identical record already present.
    let new_record = spec.to_schema();
    if existing.iter().any(|r| records_byte_equal(r, &new_record)) {
        return Ok(AddOutcome::NoOp);
    }

    // 4. Validator pre-flight on `[existing..., new_record]`.
    let mut merged: Vec<LocalDnsRecord> = existing;
    merged.push(new_record.clone());
    let scope_label = scope.validator_label();
    let mut errors: Vec<String> = Vec::new();
    validate_local_records_v2(&merged, &scope_label, &mut errors);
    if !errors.is_empty() {
        bail!(
            "cannot add local DNS record — config would become invalid:\n  {}",
            errors.join("\n  ")
        );
    }

    // 5. Resolve target file. Global lives in master; profile may be in
    //    master or a `profiles.d/*.toml` slice.
    let target_path = match scope {
        LocalRecordScope::Global => config_path.to_path_buf(),
        LocalRecordScope::Profile(id) => match into {
            Some(p) => resolve_explicit_into_under(config_path, p)?,
            None => find_profile_target_file(config_path, id)?,
        },
    };

    // 6. TOML mutation.
    let (mut doc, _) = read_or_empty(&target_path)?;
    let inserted = match scope {
        LocalRecordScope::Global => append_global_record(&mut doc, spec)?,
        LocalRecordScope::Profile(id) => append_profile_record(&mut doc, id, spec)?,
    };
    if !inserted {
        // Race / drift: another writer added the same byte-identical
        // record between step 3 and now. Treat as no-op.
        return Ok(AddOutcome::NoOp);
    }
    write_value_validated(config_path, &target_path, &doc)?;

    // 7. Audit emit (single-seat). Best-effort — never bubbles. The
    //    record `value` / `match_subdomains` / `ttl_secs` are persisted
    //    natively on the audit record so the TUI side-card can render
    //    the full mutation state without cross-referencing the master
    //    TOML. The `tracing::debug!` line below mirrors the same fields
    //    onto the journald channel for operators who grep on
    //    `target: "audit"`.
    tracing::debug!(
        target: "audit",
        scope = scope.as_tag(),
        target_id = scope.target_id(),
        domain = %spec.domain,
        record_type = spec.record_type_str(),
        value = %spec.value,
        match_subdomains = spec.match_subdomains,
        ttl_secs = ?spec.ttl_secs,
        "local_records.add detail"
    );
    let scope_tag = scope.as_tag();
    let target_id_for_audit = scope.target_id().to_string();
    let domain_for_audit = spec.domain.clone();
    let type_for_audit = spec.record_type_str();
    let value_for_audit = spec.value.clone();
    let match_subdomains_for_audit = spec.match_subdomains;
    let ttl_secs_for_audit = spec.ttl_secs;
    persist_cli_mutation_audit(config_path, || {
        let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("local_records.add")
            .with_scope(scope_tag)
            .with_target_id(target_id_for_audit)
            .with_domain(domain_for_audit)
            .with_rule_action(type_for_audit)
            .with_record_value(value_for_audit)
            .with_match_subdomains(match_subdomains_for_audit);
        if let Some(ttl) = ttl_secs_for_audit {
            rec = rec.with_ttl_secs(ttl);
        }
        rec
    });

    let devices_affected = match scope {
        LocalRecordScope::Global => 0,
        LocalRecordScope::Profile(id) => count_devices_on_profile(config_path, id),
    };
    Ok(AddOutcome::Applied {
        file: target_path,
        devices_affected,
    })
}

/// Single-seat `remove` mutation. Drops every record matching `domain`
/// in the requested scope, optionally filtered by `record_type`. Sync —
/// caller fires the shared reload + the success message.
pub(crate) fn remove_inner(
    config_path: &Path,
    scope: &LocalRecordScope,
    domain: &str,
    record_type_filter: Option<LocalDnsRecordType>,
    into: Option<&Path>,
) -> anyhow::Result<RemoveOutcome> {
    if let LocalRecordScope::Profile(id) = scope {
        ensure_profile_exists(config_path, id, format_local_records_profile_not_found)?;
    }

    let canonical_domain = domain.to_ascii_lowercase();
    let target_path = match scope {
        LocalRecordScope::Global => config_path.to_path_buf(),
        LocalRecordScope::Profile(id) => match into {
            Some(p) => resolve_explicit_into_under(config_path, p)?,
            None => find_profile_target_file(config_path, id)?,
        },
    };

    // Snapshot the matching record(s) before mutation so the audit
    // entry can carry value / match_subdomains / ttl_secs. When exactly
    // one record matches we have enough signal to populate every field;
    // on a multi-match remove we leave them empty so the audit panel
    // doesn't claim a single value covered all dropped rows.
    let pre_removal: Vec<LocalDnsRecord> = load_scope_records(config_path, scope)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.domain.eq_ignore_ascii_case(&canonical_domain))
        .filter(|r| match record_type_filter {
            Some(rt) => r.record_type == rt,
            None => true,
        })
        .collect();

    let (mut doc, _) = read_or_empty(&target_path)?;
    let n_dropped = match scope {
        LocalRecordScope::Global => {
            drop_global_records(&mut doc, &canonical_domain, record_type_filter)?
        }
        LocalRecordScope::Profile(id) => {
            drop_profile_records(&mut doc, id, &canonical_domain, record_type_filter)?
        }
    };
    if n_dropped == 0 {
        return Ok(RemoveOutcome::NotFound);
    }
    write_value_validated(config_path, &target_path, &doc)?;

    let scope_tag = scope.as_tag();
    let target_id_for_audit = scope.target_id().to_string();
    let domain_for_audit = canonical_domain.clone();
    let rt_for_audit = record_type_filter.map(record_type_to_str);
    let single_pre_removal = (pre_removal.len() == 1).then(|| pre_removal[0].clone());
    persist_cli_mutation_audit(config_path, move || {
        let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("local_records.remove")
            .with_scope(scope_tag)
            .with_target_id(target_id_for_audit)
            .with_domain(domain_for_audit);
        if let Some(rt) = rt_for_audit {
            rec = rec.with_rule_action(rt);
        }
        if let Some(prev) = single_pre_removal {
            rec = rec
                .with_record_value(prev.value)
                .with_match_subdomains(prev.match_subdomains);
            if let Some(ttl) = prev.ttl_secs {
                rec = rec.with_ttl_secs(ttl);
            }
        }
        rec
    });

    Ok(RemoveOutcome::Removed {
        file: target_path,
        n_dropped,
    })
}

// ── Public CLI handlers ────────────────────────────────

/// `warden local-dns add <domain> <type> <value> [--profile ...] ...`
#[allow(clippy::too_many_arguments)]
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    domain: &str,
    record_type: &str,
    value: &str,
    profile: Option<&str>,
    match_subdomains: bool,
    ttl_secs: Option<u32>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let rt = parse_record_type(record_type)?;
    let spec = LocalRecordSpec {
        domain: domain.to_ascii_lowercase(),
        record_type: rt,
        value: value.to_string(),
        match_subdomains,
        ttl_secs,
    };
    let scope = match profile {
        Some(id) => LocalRecordScope::Profile(id.to_string()),
        None => LocalRecordScope::Global,
    };

    let outcome = add_inner(config_path, &scope, &spec, into)?;
    match outcome {
        AddOutcome::Applied {
            file: _,
            devices_affected,
        } => {
            let rt_str = spec.record_type_str();
            let msg = match &scope {
                LocalRecordScope::Global => {
                    format_local_records_added_global(&spec.domain, rt_str, &spec.value)
                }
                LocalRecordScope::Profile(id) => format_local_records_added_profile(
                    &spec.domain,
                    rt_str,
                    &spec.value,
                    id,
                    devices_affected,
                ),
            };
            println!("{msg}");
        }
        AddOutcome::NoOp => {
            println!(
                "local DNS record '{}' {} → {} already present in {} — no-op",
                spec.domain,
                spec.record_type_str(),
                spec.value,
                scope.human_label()
            );
            return Ok(());
        }
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// `warden local-dns remove <domain> [--profile ...] [--record-type ...]`
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    domain: &str,
    profile: Option<&str>,
    record_type: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let rt_filter = record_type.map(parse_record_type).transpose()?;
    let scope = match profile {
        Some(id) => LocalRecordScope::Profile(id.to_string()),
        None => LocalRecordScope::Global,
    };
    let canonical = domain.to_ascii_lowercase();

    let outcome = remove_inner(config_path, &scope, &canonical, rt_filter, into)?;
    let scope_label = scope.human_label();
    match outcome {
        RemoveOutcome::Removed { .. } => {
            println!("{}", format_local_records_removed(&canonical, &scope_label));
        }
        RemoveOutcome::NotFound => {
            println!(
                "{}",
                format_local_records_remove_not_found(&canonical, &scope_label)
            );
            return Ok(());
        }
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// `warden local-dns list [--profile ...] [--scope ...] [--record-type ...]`
///
/// `--profile` and `--scope` are mutually exclusive. clap refuses the pair
/// on the CLI path (`conflicts_with` on the arg), but this function is
/// `pub` and reachable from a non-clap seat, so the invariant is enforced
/// here too: previously `--profile` silently won and `--scope` was dropped,
/// including its value validation, so `--profile x --scope nonsense`
/// exited 0.
pub fn run_list(
    config_path: &Path,
    profile: Option<&str>,
    scope_filter: Option<&str>,
    record_type: Option<&str>,
) -> anyhow::Result<()> {
    let rt_filter = record_type.map(parse_record_type).transpose()?;
    let cfg = load_for_resolution(config_path)?;

    let want_global: bool;
    let want_profiles: Vec<String>;
    match (profile, scope_filter) {
        (Some(_), Some(s)) => {
            bail!(
                "--profile and --scope are mutually exclusive (got --scope '{s}'). \
                 Use --profile <id> for one profile, or --scope global|profile|all."
            );
        }
        (Some(id), None) => {
            ensure_profile_exists_in(&cfg, id, format_local_records_profile_not_found)?;
            want_global = false;
            want_profiles = vec![id.to_string()];
        }
        (None, Some("global")) => {
            want_global = true;
            want_profiles = Vec::new();
        }
        (None, Some("profile")) => {
            want_global = false;
            want_profiles = cfg
                .profiles
                .keys()
                .map(|id| id.as_str().to_string())
                .collect();
        }
        // Default: all
        (None, None) | (None, Some("all")) => {
            want_global = true;
            want_profiles = cfg
                .profiles
                .keys()
                .map(|id| id.as_str().to_string())
                .collect();
        }
        (None, Some(other)) => {
            bail!("unknown --scope value '{other}' (expected: global, profile, all)");
        }
    }

    let mut printed_any = false;
    if want_global {
        let recs = filter_records(&cfg.local_dns.records, rt_filter);
        if !recs.is_empty() {
            println!("# global local DNS records ({} total)", recs.len());
            print_record_table(&recs);
            printed_any = true;
        }
    }
    for pid in &want_profiles {
        let Some((_, profile_def)) = cfg.profiles.iter().find(|(k, _)| k.as_str() == pid) else {
            continue;
        };
        let recs = filter_records(&profile_def.local_records, rt_filter);
        if !recs.is_empty() {
            if printed_any {
                println!();
            }
            println!("# profile '{pid}' local DNS records ({} total)", recs.len());
            print_record_table(&recs);
            printed_any = true;
        }
    }
    if !printed_any {
        match (want_global, want_profiles.is_empty()) {
            (true, true) => println!("{LOCAL_RECORDS_TAB_EMPTY_GLOBAL}"),
            (false, false) => {
                if let Some(only) = want_profiles.first() {
                    println!("{}", format_local_records_tab_empty_profile(only));
                }
            }
            _ => println!("no local DNS records configured"),
        }
    }
    Ok(())
}

/// `warden local-dns show <domain> [--profile ...]` — print the
/// per-record detail (domain, type, value, match_subdomains, ttl, scope)
/// for every matching record across the requested scope.
pub fn run_show(config_path: &Path, domain: &str, profile: Option<&str>) -> anyhow::Result<()> {
    let canonical = domain.to_ascii_lowercase();
    let cfg = load_for_resolution(config_path)?;

    let mut found = false;
    let want_global = profile.is_none();
    if want_global {
        for r in &cfg.local_dns.records {
            if r.domain.to_ascii_lowercase() == canonical {
                print_record_detail(r, "global");
                found = true;
            }
        }
    }
    if let Some(id) = profile {
        // Single lookup that is also the existence gate — no separate
        // `ensure_*` + re-find + `unreachable!()` for a future edit to trip
        // on. Same not-found message as `ensure_profile_exists_in`.
        let Some((_, p)) = cfg.profiles.iter().find(|(k, _)| k.as_str() == id) else {
            let known: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
            bail!("{}", format_local_records_profile_not_found(id, &known));
        };
        for r in &p.local_records {
            if r.domain.to_ascii_lowercase() == canonical {
                print_record_detail(r, &format!("profile '{id}'"));
                found = true;
            }
        }
    } else {
        for (pid, p) in &cfg.profiles {
            for r in &p.local_records {
                if r.domain.to_ascii_lowercase() == canonical {
                    print_record_detail(r, &format!("profile '{}'", pid.as_str()));
                    found = true;
                }
            }
        }
    }
    if !found {
        let scope = match profile {
            Some(id) => format!("profile '{id}'"),
            None => "any scope".to_string(),
        };
        println!("no local DNS record matching '{canonical}' in {scope}");
    }
    Ok(())
}

// ── Helpers: parsing & probe ──────────────────────────────────────────

fn parse_record_type(s: &str) -> anyhow::Result<LocalDnsRecordType> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(LocalDnsRecordType::A),
        "AAAA" => Ok(LocalDnsRecordType::AAAA),
        "CNAME" => Ok(LocalDnsRecordType::CNAME),
        other => bail!("unknown local DNS record type '{other}' — expected A, AAAA, or CNAME"),
    }
}

fn record_type_to_str(rt: LocalDnsRecordType) -> &'static str {
    match rt {
        LocalDnsRecordType::A => "A",
        LocalDnsRecordType::AAAA => "AAAA",
        LocalDnsRecordType::CNAME => "CNAME",
    }
}

fn records_byte_equal(a: &LocalDnsRecord, b: &LocalDnsRecord) -> bool {
    a.domain.eq_ignore_ascii_case(&b.domain)
        && a.record_type == b.record_type
        && a.value == b.value
        && a.match_subdomains == b.match_subdomains
        && a.ttl_secs == b.ttl_secs
}

fn filter_records(
    records: &[LocalDnsRecord],
    rt_filter: Option<LocalDnsRecordType>,
) -> Vec<LocalDnsRecord> {
    match rt_filter {
        None => records.to_vec(),
        Some(rt) => records
            .iter()
            .filter(|r| r.record_type == rt)
            .cloned()
            .collect(),
    }
}

fn print_record_table(records: &[LocalDnsRecord]) {
    println!(
        "  {:<32}  {:<5}  {:<24}  {:<10}  TTL",
        "DOMAIN", "TYPE", "VALUE", "SUBDOMAIN"
    );
    for r in records {
        let ttl = match r.ttl_secs {
            Some(n) => n.to_string(),
            None => "(default)".to_string(),
        };
        println!(
            "  {:<32}  {:<5}  {:<24}  {:<10}  {}",
            r.domain,
            record_type_to_str(r.record_type),
            r.value,
            if r.match_subdomains { "true" } else { "false" },
            ttl,
        );
    }
}

fn print_record_detail(r: &LocalDnsRecord, scope: &str) {
    println!("record:");
    println!("  scope: {scope}");
    println!("  domain: {}", r.domain);
    println!("  type: {}", record_type_to_str(r.record_type));
    println!("  value: {}", r.value);
    println!("  match_subdomains: {}", r.match_subdomains);
    match r.ttl_secs {
        Some(n) => println!("  ttl_secs: {n}"),
        None => println!("  ttl_secs: (default — falls back to [local_dns].ttl_secs)"),
    }
}

// ── Helpers: scope probes ─────────────────────────────────────────────

/// Profile resolution shared by the profile-scoped record editors.
///
/// `local-dns` and `rewrite` both edit arrays hanging off `[profiles.<id>]`,
/// so they resolve the profile, locate its owning file and report a missing
/// one the same way. One seat keeps those from drifting apart.
///
/// Only the entity-agnostic half belongs here. Each editor keeps its own
/// `spec_to_toml_value` and `to_schema`: they read and write different
/// arrays, and merging them would need a parameter that switches behaviour
/// rather than one that carries data.
pub(crate) mod profile_scoped {
    use std::path::{Path, PathBuf};

    use anyhow::bail;
    use toml::Value;

    use crate::cli::commands::target::{self, EntityClass};
    use crate::config::loader::load_config;
    use crate::config::schema::ConfigV1;

    /// Renders the caller's own "profile not found" message.
    ///
    /// Each verb freezes its own operator-facing text for this one condition
    /// and each text is pinned separately, so the message travels with the
    /// verb that owns it while the lookup stays in one place. Data, not a
    /// behaviour switch: the control flow is identical either way.
    pub(crate) type ProfileNotFound = fn(&str, &[&str]) -> String;

    pub(crate) fn ensure_profile_exists(
        config_path: &Path,
        profile_id: &str,
        not_found: ProfileNotFound,
    ) -> anyhow::Result<()> {
        let cfg = load_for_resolution(config_path)?;
        ensure_profile_exists_in(&cfg, profile_id, not_found)
    }

    pub(crate) fn ensure_profile_exists_in(
        cfg: &ConfigV1,
        profile_id: &str,
        not_found: ProfileNotFound,
    ) -> anyhow::Result<()> {
        if cfg.profiles.iter().any(|(k, _)| k.as_str() == profile_id) {
            return Ok(());
        }
        let known: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
        bail!("{}", not_found(profile_id, &known));
    }

    /// Locate the file containing `[profiles.<profile_id>]`.
    ///
    /// Delegates to [`target::find_target_for_id`], which resolves owners from
    /// the loader's include graph. A profile living in an include the master
    /// reaches by glob is found here; a scan restricted to the master plus
    /// `profiles.d/*.toml` accepts the id and then fails the write.
    pub(crate) fn find_profile_target_file(
        config_path: &Path,
        profile_id: &str,
    ) -> anyhow::Result<PathBuf> {
        if let Some(owner) =
            target::find_target_for_id(config_path, EntityClass::Profiles, profile_id)?
        {
            return Ok(owner);
        }
        bail!(
            "profile '{profile_id}' not found in any of the {} config file(s) reachable from {}. \
             Run `warden profile list` to see configured profiles, or pass `--into <file>` \
             to target a specific include.",
            target::owner_candidate_files(config_path, &[EntityClass::Profiles]).len(),
            config_path.display()
        )
    }

    pub(crate) fn load_for_resolution(config_path: &Path) -> anyhow::Result<ConfigV1> {
        let now = time::OffsetDateTime::now_utc();
        load_config(config_path, now)
            .map(|loaded| loaded.config)
            .map_err(|errs| {
                let mut msg = format!("cannot load config ({} error(s)):", errs.len());
                for e in &errs {
                    msg.push_str("\n  - ");
                    msg.push_str(&e.to_string());
                }
                anyhow::anyhow!(msg)
            })
    }

    pub(crate) fn find_profile_entry_mut<'a>(
        doc: &'a mut Value,
        profile_id: &str,
    ) -> anyhow::Result<Option<&'a mut Value>> {
        let table = doc
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
        let Some(profiles_value) = table.get_mut("profiles") else {
            return Ok(None);
        };
        let profiles = profiles_value
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("`profiles` must be a TOML table"))?;
        Ok(profiles.get_mut(profile_id))
    }
}

fn load_scope_records(
    config_path: &Path,
    scope: &LocalRecordScope,
) -> anyhow::Result<Vec<LocalDnsRecord>> {
    let cfg = load_for_resolution(config_path)?;
    match scope {
        LocalRecordScope::Global => Ok(cfg.local_dns.records.clone()),
        LocalRecordScope::Profile(id) => {
            let Some((_, p)) = cfg.profiles.iter().find(|(k, _)| k.as_str() == id) else {
                let known: Vec<&str> = cfg.profiles.keys().map(|k| k.as_str()).collect();
                bail!("{}", format_local_records_profile_not_found(id, &known));
            };
            Ok(p.local_records.clone())
        }
    }
}

// ── Helpers: TOML mutations ───────────────────────────────────────────

/// Append a record to `[[local_dns.records]]` under the global table.
/// Returns `true` if a row was added.
fn append_global_record(doc: &mut Value, spec: &LocalRecordSpec) -> anyhow::Result<bool> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let local_dns_value = table
        .entry("local_dns".to_string())
        .or_insert_with(|| Value::Table(Default::default()));
    let local_dns = local_dns_value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_dns` must be a TOML table"))?;
    let arr_value = local_dns
        .entry("records".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_dns.records` must be an array of tables"))?;
    if records_array_contains_byte_identical(arr, spec) {
        return Ok(false);
    }
    arr.push(spec_to_toml_value(spec));
    Ok(true)
}

/// Append a record under `[[profiles.<id>.local_records]]`. Returns
/// `true` if a row was added.
fn append_profile_record(
    doc: &mut Value,
    profile_id: &str,
    spec: &LocalRecordSpec,
) -> anyhow::Result<bool> {
    let entry = find_profile_entry_mut(doc, profile_id)?
        .ok_or_else(|| anyhow::anyhow!("profile '{profile_id}' not present in target document"))?;
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("profile entry is not a TOML table"))?;
    let arr_value = tbl
        .entry("local_records".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_records` must be an array of tables"))?;
    if records_array_contains_byte_identical(arr, spec) {
        return Ok(false);
    }
    arr.push(spec_to_toml_value(spec));
    Ok(true)
}

fn drop_global_records(
    doc: &mut Value,
    canonical_domain: &str,
    rt_filter: Option<LocalDnsRecordType>,
) -> anyhow::Result<usize> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(local_dns_value) = table.get_mut("local_dns") else {
        return Ok(0);
    };
    let local_dns = local_dns_value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_dns` must be a TOML table"))?;
    let Some(arr_value) = local_dns.get_mut("records") else {
        return Ok(0);
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_dns.records` must be an array"))?;
    drop_matching_records(arr, canonical_domain, rt_filter)
}

fn drop_profile_records(
    doc: &mut Value,
    profile_id: &str,
    canonical_domain: &str,
    rt_filter: Option<LocalDnsRecordType>,
) -> anyhow::Result<usize> {
    let Some(entry) = find_profile_entry_mut(doc, profile_id)? else {
        return Ok(0);
    };
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("profile entry is not a TOML table"))?;
    let Some(arr_value) = tbl.get_mut("local_records") else {
        return Ok(0);
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`local_records` must be an array"))?;
    drop_matching_records(arr, canonical_domain, rt_filter)
}

fn drop_matching_records(
    arr: &mut Vec<Value>,
    canonical_domain: &str,
    rt_filter: Option<LocalDnsRecordType>,
) -> anyhow::Result<usize> {
    let before = arr.len();
    arr.retain(|item| {
        let row_domain = item
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.to_ascii_lowercase());
        let domain_match = row_domain.as_deref() == Some(canonical_domain);
        if !domain_match {
            return true;
        }
        let row_type = item.get("type").and_then(|v| v.as_str()).and_then(|s| {
            match s.to_ascii_uppercase().as_str() {
                "A" => Some(LocalDnsRecordType::A),
                "AAAA" => Some(LocalDnsRecordType::AAAA),
                "CNAME" => Some(LocalDnsRecordType::CNAME),
                _ => None,
            }
        });
        match (rt_filter, row_type) {
            (None, _) => false,                                // drop every type
            (Some(want), Some(have)) if want == have => false, // drop type-match
            _ => true,
        }
    });
    Ok(before.saturating_sub(arr.len()))
}

fn records_array_contains_byte_identical(arr: &[Value], spec: &LocalRecordSpec) -> bool {
    arr.iter().any(|item| {
        let domain_match = item
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case(&spec.domain))
            .unwrap_or(false);
        let type_match = item
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| s.eq_ignore_ascii_case(spec.record_type_str()))
            .unwrap_or(false);
        let value_match = item
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s == spec.value)
            .unwrap_or(false);
        let subdomain_match = item
            .get("match_subdomains")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            == spec.match_subdomains;
        let ttl_match = match (
            item.get("ttl_secs").and_then(|v| v.as_integer()),
            spec.ttl_secs,
        ) {
            (None, None) => true,
            (Some(a), Some(b)) => a == b as i64,
            _ => false,
        };
        domain_match && type_match && value_match && subdomain_match && ttl_match
    })
}

fn spec_to_toml_value(spec: &LocalRecordSpec) -> Value {
    let mut tbl = toml::map::Map::new();
    tbl.insert("domain".into(), Value::String(spec.domain.clone()));
    tbl.insert(
        "type".into(),
        Value::String(spec.record_type_str().to_string()),
    );
    tbl.insert("value".into(), Value::String(spec.value.clone()));
    if spec.match_subdomains {
        tbl.insert("match_subdomains".into(), Value::Boolean(true));
    }
    if let Some(ttl) = spec.ttl_secs {
        tbl.insert("ttl_secs".into(), Value::Integer(ttl as i64));
    }
    Value::Table(tbl)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rewrite` once carried its own byte-identical copy of this layer,
    /// operator-facing not-found text included, so improving one verb
    /// silently skipped the other. Keep the copy from growing back.
    #[test]
    fn rewrite_shares_the_profile_resolution_seat() {
        let src = include_str!("rewrite.rs");
        for name in [
            "fn ensure_profile_exists",
            "fn find_profile_target_file",
            "fn load_for_resolution",
            "fn find_profile_entry_mut",
        ] {
            assert!(
                !src.contains(name),
                "rewrite.rs defines `{name}` again; profile resolution has one seat"
            );
        }
        assert!(
            src.contains("profile_scoped::"),
            "rewrite.rs no longer reaches the shared profile-resolution seat"
        );
    }
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn temp_master(content: &str) -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/tmp/purge-warden-test-localdns-{}-{n}.toml",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    fn v1_master_with_default_profile() -> &'static str {
        r#"schema_version = 3

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy ads"
url = "https://example.com/ads.txt"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[upstream]
servers = ["192.0.2.1:53"]
"#
    }

    fn make_spec_a(domain: &str, value: &str) -> LocalRecordSpec {
        LocalRecordSpec {
            domain: domain.into(),
            record_type: LocalDnsRecordType::A,
            value: value.into(),
            match_subdomains: false,
            ttl_secs: None,
        }
    }

    // ── parse_record_type ─────────────────────────────────────────────

    #[test]
    fn t3_parse_record_type_accepts_each_variant_case_insensitive() {
        assert!(matches!(
            parse_record_type("A").unwrap(),
            LocalDnsRecordType::A
        ));
        assert!(matches!(
            parse_record_type("a").unwrap(),
            LocalDnsRecordType::A
        ));
        assert!(matches!(
            parse_record_type("AAAA").unwrap(),
            LocalDnsRecordType::AAAA
        ));
        assert!(matches!(
            parse_record_type("aaaa").unwrap(),
            LocalDnsRecordType::AAAA
        ));
        assert!(matches!(
            parse_record_type("CNAME").unwrap(),
            LocalDnsRecordType::CNAME
        ));
        assert!(matches!(
            parse_record_type("cname").unwrap(),
            LocalDnsRecordType::CNAME
        ));
    }

    #[test]
    fn t3_parse_record_type_rejects_unknown() {
        let err = parse_record_type("MX").unwrap_err();
        assert!(err.to_string().contains("MX"));
        assert!(err.to_string().contains("A, AAAA, or CNAME"));
    }

    // ── frozen string formatting ──────────────────────────────────────

    #[test]
    fn t3_frozen_strings_format_correctly() {
        let s = format_local_records_added_global("nas.home", "A", "192.168.1.50");
        assert!(s.contains("nas.home"));
        assert!(s.contains("A"));
        assert!(s.contains("192.168.1.50"));
        assert!(s.starts_with("Added global local DNS record"));

        let s = format_local_records_added_profile("example.test", "A", "10.10.1.50", "kids", 3);
        assert!(s.contains("example.test"));
        assert!(s.contains("kids"));
        assert!(s.contains("3 device"));

        let s = format_local_records_removed("media.home", "global");
        assert!(s.contains("media.home"));
        assert!(s.contains("global"));
        // The success string states only the durable fact; the reload
        // outcome is printed separately by report_reload_outcome.
        assert!(!s.contains("Reload triggered"));

        let s = format_local_records_remove_not_found("ghost.home", "profile 'kids'");
        assert!(s.contains("ghost.home"));
        assert!(s.contains("kids"));

        let s = format_local_records_profile_not_found("ghost", &["default", "kids"]);
        assert!(s.contains("ghost"));
        assert!(s.contains("default"));
        assert!(s.contains("kids"));

        let s = format_local_records_profile_not_found("ghost", &[]);
        assert!(s.contains("(none configured)"));
    }

    #[test]
    fn t3_frozen_string_constants_have_expected_prefixes() {
        assert!(LOCAL_RECORDS_ADDED_GLOBAL.starts_with("Added global"));
        assert!(LOCAL_RECORDS_ADDED_PROFILE.starts_with("Added local DNS"));
        assert!(LOCAL_RECORDS_REMOVED.starts_with("Removed local DNS"));
        assert!(LOCAL_RECORDS_REMOVE_NOT_FOUND.starts_with("local_records: no record"));
        assert!(LOCAL_RECORDS_PROFILE_NOT_FOUND.starts_with("local_records: profile"));
        assert!(LOCAL_RECORDS_TAB_EMPTY_GLOBAL.starts_with("No global"));
        assert!(LOCAL_RECORDS_TAB_EMPTY_PROFILE.starts_with("No local"));
    }

    // ── add_inner global-scope ────────────────────────────────────────

    #[test]
    fn t3_add_inner_global_appends_record() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = make_spec_a("nas.home", "192.168.1.50");
        let outcome = add_inner(&master, &scope, &spec, None).unwrap();
        assert!(matches!(outcome, AddOutcome::Applied { .. }));

        // Reload the master and assert the record landed.
        let cfg = load_for_resolution(&master).unwrap();
        assert!(cfg
            .local_dns
            .records
            .iter()
            .any(|r| r.domain == "nas.home" && r.value == "192.168.1.50"));
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_global_idempotent_no_op() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = make_spec_a("nas.home", "192.168.1.50");
        let _ = add_inner(&master, &scope, &spec, None).unwrap();
        // Second add of the byte-identical record → NoOp.
        let outcome = add_inner(&master, &scope, &spec, None).unwrap();
        assert!(matches!(outcome, AddOutcome::NoOp));
        let cfg = load_for_resolution(&master).unwrap();
        let n = cfg
            .local_dns
            .records
            .iter()
            .filter(|r| r.domain == "nas.home")
            .count();
        assert_eq!(n, 1, "no-op must not duplicate the record");
        std::fs::remove_file(&master).ok();
    }

    // ── add_inner profile-scope ───────────────────────────────────────

    #[test]
    fn t3_add_inner_profile_appends_record_in_master() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Profile("kids".into());
        let spec = make_spec_a("example.test", "10.10.1.50");
        let outcome = add_inner(&master, &scope, &spec, None).unwrap();
        assert!(matches!(outcome, AddOutcome::Applied { .. }));

        let cfg = load_for_resolution(&master).unwrap();
        let kids = cfg
            .profiles
            .iter()
            .find(|(k, _)| k.as_str() == "kids")
            .unwrap()
            .1;
        assert!(kids
            .local_records
            .iter()
            .any(|r| r.domain == "example.test" && r.value == "10.10.1.50"));
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_profile_not_found_errors() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Profile("ghost".into());
        let spec = make_spec_a("nas.home", "192.168.1.50");
        let err = add_inner(&master, &scope, &spec, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "names the missing profile: {msg}");
        assert!(msg.contains("default"), "lists known profile: {msg}");
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_validator_rejects_invalid_target() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = LocalRecordSpec {
            domain: "nas.home".into(),
            record_type: LocalDnsRecordType::A,
            value: "999.999.999.999".into(),
            match_subdomains: false,
            ttl_secs: None,
        };
        let err = add_inner(&master, &scope, &spec, None).unwrap_err();
        // Validator pre-flight catches the malformed IP → bail without writing.
        assert!(
            err.to_string().contains("999.999.999.999"),
            "validator surface: {err}"
        );
        // Confirm nothing landed on disk.
        let cfg = load_for_resolution(&master).unwrap();
        assert!(cfg.local_dns.records.is_empty());
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_validator_rejects_reserved_target() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = LocalRecordSpec {
            domain: "evil.home".into(),
            record_type: LocalDnsRecordType::A,
            value: "0.0.0.0".into(), // DR16 reserved-target refusal
            match_subdomains: false,
            ttl_secs: None,
        };
        let err = add_inner(&master, &scope, &spec, None).unwrap_err();
        assert!(
            err.to_string().contains("reserved")
                || err.to_string().contains("multicast")
                || err.to_string().contains("loopback"),
            "DR16 surface: {err}"
        );
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_validator_rejects_ttl_out_of_range() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = LocalRecordSpec {
            domain: "nas.home".into(),
            record_type: LocalDnsRecordType::A,
            value: "192.168.1.50".into(),
            match_subdomains: false,
            ttl_secs: Some(0), // DR5 — 0 is rejected
        };
        let err = add_inner(&master, &scope, &spec, None).unwrap_err();
        assert!(err.to_string().contains("ttl_secs"), "DR5 surface: {err}");
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_validator_rejects_subdomain_on_psl() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = LocalRecordSpec {
            domain: "com".into(), // public suffix
            record_type: LocalDnsRecordType::A,
            value: "10.0.0.1".into(),
            match_subdomains: true, // DR9 refusal
            ttl_secs: None,
        };
        let err = add_inner(&master, &scope, &spec, None).unwrap_err();
        assert!(
            err.to_string().contains("public suffix"),
            "DR9 surface: {err}"
        );
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_add_inner_match_subdomains_true_lands_when_valid() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Profile("kids".into());
        let spec = LocalRecordSpec {
            domain: "example.test".into(),
            record_type: LocalDnsRecordType::A,
            value: "10.10.1.50".into(),
            match_subdomains: true,
            ttl_secs: Some(7200),
        };
        let outcome = add_inner(&master, &scope, &spec, None).unwrap();
        assert!(matches!(outcome, AddOutcome::Applied { .. }));

        let cfg = load_for_resolution(&master).unwrap();
        let kids = cfg
            .profiles
            .iter()
            .find(|(k, _)| k.as_str() == "kids")
            .unwrap()
            .1;
        let r = kids
            .local_records
            .iter()
            .find(|r| r.domain == "example.test")
            .unwrap();
        assert!(r.match_subdomains);
        assert_eq!(r.ttl_secs, Some(7200));
        std::fs::remove_file(&master).ok();
    }

    // ── remove_inner ─────────────────────────────────────────────────

    #[test]
    fn t3_remove_inner_global_drops_record() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec = make_spec_a("nas.home", "192.168.1.50");
        let _ = add_inner(&master, &scope, &spec, None).unwrap();

        let outcome = remove_inner(&master, &scope, "nas.home", None, None).unwrap();
        match outcome {
            RemoveOutcome::Removed { n_dropped, .. } => assert_eq!(n_dropped, 1),
            other => panic!("expected Removed, got {other:?}"),
        }
        let cfg = load_for_resolution(&master).unwrap();
        assert!(cfg.local_dns.records.is_empty());
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_remove_inner_not_found_returns_notfound() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let outcome = remove_inner(&master, &scope, "ghost.home", None, None).unwrap();
        assert!(matches!(outcome, RemoveOutcome::NotFound));
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_remove_inner_with_type_filter_only_drops_matching_type() {
        let master = temp_master(v1_master_with_default_profile());
        let scope = LocalRecordScope::Global;
        let spec_a = make_spec_a("dual.home", "10.0.0.5");
        let spec_aaaa = LocalRecordSpec {
            domain: "dual.home".into(),
            record_type: LocalDnsRecordType::AAAA,
            value: "fd00::5".into(),
            match_subdomains: false,
            ttl_secs: None,
        };
        let _ = add_inner(&master, &scope, &spec_a, None).unwrap();
        let _ = add_inner(&master, &scope, &spec_aaaa, None).unwrap();

        let outcome = remove_inner(
            &master,
            &scope,
            "dual.home",
            Some(LocalDnsRecordType::A),
            None,
        )
        .unwrap();
        match outcome {
            RemoveOutcome::Removed { n_dropped, .. } => assert_eq!(n_dropped, 1),
            other => panic!("expected Removed, got {other:?}"),
        }
        let cfg = load_for_resolution(&master).unwrap();
        let remaining: Vec<_> = cfg
            .local_dns
            .records
            .iter()
            .filter(|r| r.domain == "dual.home")
            .collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].record_type, LocalDnsRecordType::AAAA);
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_remove_inner_profile_drops_only_in_target_profile() {
        let master = temp_master(v1_master_with_default_profile());
        let scope_kids = LocalRecordScope::Profile("kids".into());
        let scope_default = LocalRecordScope::Profile("default".into());
        let spec = make_spec_a("example.test", "10.10.1.50");
        let _ = add_inner(&master, &scope_kids, &spec, None).unwrap();
        let _ = add_inner(&master, &scope_default, &spec, None).unwrap();

        let outcome = remove_inner(&master, &scope_kids, "example.test", None, None).unwrap();
        assert!(matches!(outcome, RemoveOutcome::Removed { .. }));
        let cfg = load_for_resolution(&master).unwrap();
        let kids = cfg
            .profiles
            .iter()
            .find(|(k, _)| k.as_str() == "kids")
            .unwrap()
            .1;
        let default = cfg
            .profiles
            .iter()
            .find(|(k, _)| k.as_str() == "default")
            .unwrap()
            .1;
        assert!(kids.local_records.is_empty(), "kids removed");
        assert_eq!(default.local_records.len(), 1, "default untouched");
        std::fs::remove_file(&master).ok();
    }

    // ── records_byte_equal helper ─────────────────────────────────────

    #[test]
    fn t3_records_byte_equal_compares_all_fields() {
        let a = LocalDnsRecord {
            domain: "nas.home".into(),
            record_type: LocalDnsRecordType::A,
            value: "192.168.1.50".into(),
            match_subdomains: false,
            ttl_secs: None,
        };
        let mut b = a.clone();
        assert!(records_byte_equal(&a, &b));
        b.value = "192.168.1.51".into();
        assert!(!records_byte_equal(&a, &b));
        let mut c = a.clone();
        c.match_subdomains = true;
        assert!(!records_byte_equal(&a, &c));
        let mut d = a.clone();
        d.ttl_secs = Some(60);
        assert!(!records_byte_equal(&a, &d));
        // Domain match is case-insensitive (records are stored
        // lowercased everywhere; a hand-edited TOML with mixed case
        // must still compare equal to a lowercased operator input).
        let mut e = a.clone();
        e.domain = "NAS.HOME".into();
        assert!(records_byte_equal(&a, &e));
    }

    // ── spec_to_toml_value ────────────────────────────────────────────

    #[test]
    fn t3_spec_to_toml_value_omits_default_fields() {
        let spec = make_spec_a("nas.home", "192.168.1.50");
        let v = spec_to_toml_value(&spec);
        let tbl = v.as_table().unwrap();
        assert_eq!(tbl.get("domain").and_then(|v| v.as_str()), Some("nas.home"));
        assert_eq!(tbl.get("type").and_then(|v| v.as_str()), Some("A"));
        assert_eq!(
            tbl.get("value").and_then(|v| v.as_str()),
            Some("192.168.1.50")
        );
        assert!(
            !tbl.contains_key("match_subdomains"),
            "default false must not appear on disk"
        );
        assert!(!tbl.contains_key("ttl_secs"));
    }

    #[test]
    fn t3_spec_to_toml_value_emits_optional_fields_when_set() {
        let spec = LocalRecordSpec {
            domain: "example.test".into(),
            record_type: LocalDnsRecordType::A,
            value: "10.10.1.50".into(),
            match_subdomains: true,
            ttl_secs: Some(3600),
        };
        let v = spec_to_toml_value(&spec);
        let tbl = v.as_table().unwrap();
        assert_eq!(
            tbl.get("match_subdomains").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(tbl.get("ttl_secs").and_then(|v| v.as_integer()), Some(3600));
    }

    // ── scope helpers ─────────────────────────────────────────────────

    #[test]
    fn t3_scope_helpers_return_expected_tags() {
        let g = LocalRecordScope::Global;
        assert_eq!(g.as_tag(), "global");
        assert_eq!(g.target_id(), "global");
        assert_eq!(g.validator_label(), "local_dns");
        assert_eq!(g.human_label(), "global");

        let p = LocalRecordScope::Profile("kids".into());
        assert_eq!(p.as_tag(), "profile");
        assert_eq!(p.target_id(), "kids");
        assert_eq!(p.validator_label(), "profiles.kids.local_records");
        assert_eq!(p.human_label(), "profile 'kids'");
    }

    // ── public list / show happy-path (smoke) ─────────────────────────

    #[test]
    fn t3_run_list_smoke_no_records_does_not_panic() {
        let master = temp_master(v1_master_with_default_profile());
        // No records yet; just pin that the list path doesn't blow up.
        run_list(&master, None, None, None).unwrap();
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_run_show_no_match_prints_no_record_message() {
        let master = temp_master(v1_master_with_default_profile());
        run_show(&master, "ghost.home", None).unwrap();
        std::fs::remove_file(&master).ok();
    }

    #[test]
    fn t3_run_list_with_invalid_scope_filter_errors() {
        let master = temp_master(v1_master_with_default_profile());
        let err = run_list(&master, None, Some("bogus"), None).unwrap_err();
        assert!(err.to_string().contains("bogus"));
        std::fs::remove_file(&master).ok();
    }
}
