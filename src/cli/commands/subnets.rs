//! `warden subnet` — v1-native CRUD for `[[subnets]]` entries.
//!
//! Subnets are resolved via longest-prefix match; `priority` is
//! informational only. The operator can say "the 10.10.10.0/24 range uses
//! the marketing profile" with a single TOML entry.
//!
//! # Single-seat
//!
//! The public `run_*` helpers are thin async wrappers over sync
//! `*_inner` cores. Mirror of [`super::rules::add_inner`].
//! CLI dispatch (the binary's `main` via clap) and the TUI submit
//! path call the same `*_inner` so the validate-or-revert / TOCTOU
//! re-check / friendly error UX lives in one place. Only the wrappers
//! perform the post-write [`super::ipc_reload::attempt_reload`].

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::format_config_errors;
use super::ipc_reload;
use super::target::{
    read_or_empty, remove_id_keyed, resolve_existing_target_file, resolve_target_file,
    upsert_id_keyed, write_value_validated, EntityClass,
};
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::cidr::Cidr;
use crate::config::loader::load_config;
use crate::config::schema::{Id, Subnet};

// ── Reports & outcomes ─────────────────────────────────────────────────
//
// The inners return rich result types so callers (CLI now, TUI later)
// can render outcomes and feed audit cabling without re-deriving fields
// from the input args.

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields land in CLI println!; clippy only sees
                    // one direct caller here.
pub(crate) struct AddReport {
    pub id: String,
    pub target_path: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // See AddReport.
pub(crate) struct SetReport {
    pub id: String,
    pub field: String,
    pub value: String,
    pub target_path: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // See AddReport — `fields` is consumed by the TUI audit log.
pub(crate) struct SetFieldsReport {
    pub id: String,
    pub fields: Vec<String>,
    pub target_path: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // See AddReport.
pub(crate) struct RemoveReport {
    pub id: String,
    pub target_path: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // The NotFound variant carries the path the wrapper
                    // uses to print the friendly error; clippy only
                    // sees the Removed match arm consume target_path.
pub(crate) enum RemoveOutcome {
    Removed(RemoveReport),
    NotFound { target_path: PathBuf },
}

// ── Read-only commands ─────────────────────────────────────────────────

pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.subnets.is_empty() {
        println!("no subnets configured");
        println!("add one with: warden subnet add <id> --cidrs 10.0.0.0/8 --profile <profile>");
        return Ok(());
    }
    println!("configured subnets ({}):", loaded.config.subnets.len());
    for s in &loaded.config.subnets {
        println!(
            "  {id} \"{name}\" cidrs=[{cidrs}] profile={prof} priority={pri}",
            id = s.id.as_str(),
            name = s.display_name,
            cidrs = s.cidrs.join(","),
            prof = s.profile.as_str(),
            pri = s.priority,
        );
    }
    Ok(())
}

pub fn run_show(config_path: &Path, id: &str) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let s = loaded
        .config
        .subnets
        .iter()
        .find(|x| x.id.as_str() == id)
        .with_context(|| format!("subnet not found: {id}"))?;
    print!("{}", render_subnet_detail(s));
    Ok(())
}

/// The body of `warden subnet show` — one field per line. Pure so it is
/// unit-testable; `run_show` prints it verbatim.
fn render_subnet_detail(s: &Subnet) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "id:           {}", s.id.as_str());
    let _ = writeln!(out, "display_name: {}", s.display_name);
    let _ = writeln!(out, "cidrs:        {}", s.cidrs.join(", "));
    let _ = writeln!(out, "profile:      {}", s.profile.as_str());
    let _ = writeln!(out, "priority:     {}", s.priority);
    // A subnet's tags are shown because the config still stores them,
    // NOT because they select anything anymore. What a
    // client on this subnet filters comes from its profile:
    // `profiles.<id>.lists`, else each list's own `base`. Displayed
    // rather than hidden so a pre-cutover config's stored values stay
    // visible while being inert.
    //
    // A subnet's tags used to land in the effective tag set of every device that
    // falls inside its CIDRs but has no `[[devices]]` record — i.e. of
    // exactly the clients the operator never enumerated, and can least
    // afford to guess about.
    out
}

// ── Inner cores (sync; single-seat) ─────────────────────────────────

/// Add a `[[subnets]]` entry. **Sync** — caller owns the post-write
/// `ipc_reload::attempt_reload`. Friendly errors:
///
/// - `subnet "..." already exists` if the id collides (the pre-write
///   check; a concurrent-add race is caught by the merged pre-promote
///   validation in [`super::target::write_value_validated`]).
/// - `profile "..." is not defined` if the referenced profile is
///   missing.
/// - `at least one --cidr is required` / `invalid cidr "..."` / etc.
pub(crate) fn add_inner(
    config_path: &Path,
    id: &str,
    display_name: Option<&str>,
    cidrs: &[String],
    profile: &str,
    priority: Option<i32>,
    into: Option<&Path>,
) -> anyhow::Result<AddReport> {
    let _ = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;
    if cidrs.is_empty() {
        bail!("at least one --cidr is required");
    }
    let stored_cidrs = canonicalise_cidrs(cidrs)?;

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.subnets.iter().any(|s| s.id.as_str() == id) {
        bail!("subnet \"{id}\" already exists");
    }
    if !loaded.config.profiles.contains_key(profile) {
        bail!(
            "profile \"{profile}\" is not defined. Create it first with `warden profile add {profile} ...`."
        );
    }

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.unwrap_or(id).to_string()),
    );
    tbl.insert(
        "cidrs".into(),
        Value::Array(
            stored_cidrs
                .iter()
                .map(|c| Value::String(c.clone()))
                .collect(),
        ),
    );
    tbl.insert("profile".into(), Value::String(profile.to_string()));
    if let Some(p) = priority {
        tbl.insert("priority".into(), Value::Integer(p as i64));
    }

    let target_path = resolve_target_file(config_path, EntityClass::Subnets, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    // A create, and the returned flag is what says so — see the exhaustive
    // destructuring test in this module for the other half of the guard.
    anyhow::ensure!(
        upsert_id_keyed(
            &mut doc,
            EntityClass::Subnets.toml_key(),
            id,
            Value::Table(tbl),
        )?,
        "subnet \"{id}\" appeared in {} between the duplicate check and the write; \
         nothing was changed",
        target_path.display()
    );
    // write_value_validated runs the full merged validation (master + every
    // sibling include + this staged slice) BEFORE the rename, so a concurrent
    // `warden subnet add` that landed the same id in another file is caught
    // here as a cross-file duplicate and the write is refused — nothing is
    // promoted. The friendly pre-check above covers the common (non-race)
    // case; the rare race surfaces the validator's DuplicateId message
    // rather than a bespoke string.
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("subnet.add")
            .with_scope("subnet")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });

    Ok(AddReport {
        id: id.to_string(),
        target_path,
    })
}

/// Atomically update one or more fields of an existing subnet. Every
/// field mutation is applied to the in-memory TOML doc first, then the
/// file is written **once** and validated **once** — so either every
/// field lands or none do (a bad value bails before the write; a
/// whole-config validation failure reverts the single write). This is
/// the all-or-nothing path the TUI Edit submit needs; the single-field
/// `set_inner` delegates here. **Sync** — caller owns the post-write reload.
pub(crate) fn set_fields_inner(
    config_path: &Path,
    id: &str,
    fields: &[(&str, &str)],
    into: Option<&Path>,
) -> anyhow::Result<SetFieldsReport> {
    let target_path = resolve_existing_target_file(config_path, EntityClass::Subnets, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_id_entry_mut(&mut doc, EntityClass::Subnets.toml_key(), id)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "subnet \"{id}\" not found in {}. Use `--into <file>` to target a different include.",
                target_path.display()
            )
        })?;
    // In-memory only: a bad field value bails here, before any write, so
    // earlier fields in the same call never reach disk.
    for (field, value) in fields {
        apply_subnet_field(entry, field, value)?;
    }
    write_value_validated(config_path, &target_path, &doc)?;
    let id_for_audit = id.to_string();
    let fields_after = fields
        .iter()
        .map(|(f, v)| format!("{f}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("subnet.set")
            .with_scope("subnet")
            .with_target_id(id_for_audit)
            .with_fields_after(fields_after)
            .with_files([config_path, target_for_audit.as_path()])
    });
    Ok(SetFieldsReport {
        id: id.to_string(),
        fields: fields.iter().map(|(f, _)| (*f).to_string()).collect(),
        target_path,
    })
}

/// Update one field of an existing subnet. **Sync** — caller owns
/// the post-write reload. Thin wrapper over [`set_fields_inner`].
pub(crate) fn set_inner(
    config_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<SetReport> {
    let report = set_fields_inner(config_path, id, &[(field, value)], into)?;
    Ok(SetReport {
        id: report.id,
        field: field.to_string(),
        value: value.to_string(),
        target_path: report.target_path,
    })
}

/// Drop a `[[subnets]]` entry. Returns [`RemoveOutcome::NotFound`]
/// (carrying the resolved target path) when no entry matches; the
/// CLI wrapper turns that into a friendly bail. **Sync** — caller
/// owns the post-write reload.
pub(crate) fn remove_inner(
    config_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<RemoveOutcome> {
    let target_path = resolve_existing_target_file(config_path, EntityClass::Subnets, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let removed = remove_id_keyed(&mut doc, EntityClass::Subnets.toml_key(), id)?;
    if !removed {
        return Ok(RemoveOutcome::NotFound { target_path });
    }
    write_value_validated(config_path, &target_path, &doc)?;
    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("subnet.remove")
            .with_scope("subnet")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });
    Ok(RemoveOutcome::Removed(RemoveReport {
        id: id.to_string(),
        target_path,
    }))
}

// ── Public async wrappers (CLI dispatch surface) ───────────────────────
//
// Byte-identical operator-facing strings: any change here
// would surprise scripts grepping warden output.

#[allow(clippy::too_many_arguments)]
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    cidrs: &[String],
    profile: &str,
    priority: Option<i32>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let report = add_inner(
        config_path,
        id,
        display_name,
        cidrs,
        profile,
        priority,
        into,
    )?;
    println!(
        "added subnet {} → {}",
        report.id,
        report.target_path.display()
    );

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

pub async fn run_set(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let report = set_inner(config_path, id, field, value, into)?;
    println!("updated {}.{} = {}", report.id, report.field, report.value);

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    match remove_inner(config_path, id, into)? {
        RemoveOutcome::Removed(report) => {
            println!("removed subnet {}", report.id);
        }
        RemoveOutcome::NotFound { .. } => {
            // Idempotent — nothing changed, so no reload either.
            println!("subnet \"{id}\" not found — nothing to remove");
            return Ok(());
        }
    }

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

// ── Internal helpers ───────────────────────────────────────────────────

fn apply_subnet_field(entry: &mut Value, field: &str, value: &str) -> anyhow::Result<()> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("subnet entry is not a TOML table"))?;
    match field {
        "display_name" => {
            if value.is_empty() {
                bail!("display_name cannot be empty");
            }
            tbl.insert("display_name".into(), Value::String(value.to_string()));
        }
        "profile" => {
            tbl.insert("profile".into(), Value::String(value.to_string()));
        }
        "priority" => {
            let n: i32 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("priority must be integer, got \"{value}\""))?;
            tbl.insert("priority".into(), Value::Integer(n as i64));
        }
        "cidrs" => {
            let parts: Vec<String> = value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                bail!("cidrs cannot be empty — remove the subnet instead");
            }
            let stored = canonicalise_cidrs(&parts)?;
            tbl.insert(
                "cidrs".into(),
                Value::Array(stored.into_iter().map(Value::String).collect()),
            );
        }
        other => bail!("unknown field: {other}. Valid: display_name, profile, priority, cidrs"),
    }
    Ok(())
}

/// Validate + normalise each cidr input. Tries the strict
/// [`Cidr::parse`] first so already-canonical inputs land on disk
/// byte-identical to what the operator typed (preserves
/// scripts that grep the TOML). Falls through to
/// [`Cidr::parse_friendly`] for wildcards / ranges / etc; those land
/// on disk in canonical `network/prefix` form because the validator
/// would otherwise reject them at the next `load_config`.
fn canonicalise_cidrs(cidrs: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::with_capacity(cidrs.len());
    for c in cidrs {
        match Cidr::parse(c) {
            Ok(_) => out.push(c.clone()),
            Err(_) => {
                let parsed = Cidr::parse_friendly(c)
                    .map_err(|e| anyhow::anyhow!("invalid cidr \"{c}\": {e}"))?;
                out.push(parsed.to_string());
            }
        }
    }
    Ok(out)
}

fn find_id_entry_mut<'a>(
    doc: &'a mut Value,
    key: &str,
    find_value: &str,
) -> anyhow::Result<Option<&'a mut Value>> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(array) = table.get_mut(key) else {
        return Ok(None);
    };
    let arr = array
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{key}` must be an array of tables"))?;
    for item in arr.iter_mut() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id == find_value {
                return Ok(Some(item));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.guest]
display_name = "Guest"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        master
    }

    /// `add_inner` builds a WHOLE ROW and `upsert_id_keyed` replaces the
    /// matched row outright (`*item = entry`), so any field the builder omits
    /// is reset to its serde default — on save of *anything*, not of that
    /// field. That is the class that shipped once and cost a release.
    ///
    /// The defence is this destructuring, NOT a comment: prose does not fail
    /// a build. `let Subnet { .. }` is exhaustive on purpose — no `..` — so
    /// the day someone adds a sixth field to `Subnet`, **this stops
    /// compiling** and they have to decide whether `add_inner` should write
    /// it, instead of discovering months later that it silently vanishes.
    #[test]
    fn every_subnet_field_is_considered_by_the_row_builder() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);

        add_inner(
            &master,
            "lan",
            Some("LAN"),
            &["10.0.0.0/8".to_string()],
            "guest",
            Some(20),
            None,
        )
        .expect("add");

        let now = time::OffsetDateTime::now_utc();
        let loaded = load_config(&master, now).expect("reload");
        let s = loaded
            .config
            .subnets
            .iter()
            .find(|s| s.id.as_str() == "lan")
            .expect("subnet present after add");

        // Exhaustive. Adding a field to `Subnet` breaks THIS LINE first.
        let Subnet {
            id,
            display_name,
            cidrs,
            profile,
            priority,
        } = s;

        assert_eq!(id.as_str(), "lan");
        assert_eq!(display_name, "LAN");
        assert_eq!(cidrs.len(), 1, "got {cidrs:?}");
        assert_eq!(profile.as_str(), "guest");
        assert_eq!(*priority, 20);
    }

    fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("ghost.sock")
    }

    #[tokio::test]
    async fn add_subnet_writes_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "lan-guest",
            Some("Guest range"),
            &["10.10.1.200/29".into()],
            "guest",
            Some(10),
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.subnets.len(), 1);
        assert_eq!(loaded.config.subnets[0].id.as_str(), "lan-guest");
        assert_eq!(loaded.config.subnets[0].priority, 10);
    }

    #[tokio::test]
    async fn add_subnet_invalid_cidr_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "bad",
            None,
            &["not-a-cidr".into()],
            "default",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid cidr"));
    }

    #[tokio::test]
    async fn add_subnet_unknown_profile_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "s",
            None,
            &["10.0.0.0/8".into()],
            "missing",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[tokio::test]
    async fn set_subnet_cidrs_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "lan",
            None,
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .await
        .unwrap();
        run_set(
            &master,
            &sock,
            "lan",
            "cidrs",
            "10.0.0.0/16, 192.168.0.0/16",
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.subnets[0].cidrs.len(), 2);
    }

    #[tokio::test]
    async fn set_subnet_invalid_cidr_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "lan",
            None,
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .await
        .unwrap();
        let err = run_set(&master, &sock, "lan", "cidrs", "not-a-cidr", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid cidr"));
    }

    #[tokio::test]
    async fn remove_subnet_drops_entry() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "lan",
            None,
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .await
        .unwrap();
        run_remove(&master, &sock, "lan", None).await.unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.subnets.is_empty());
    }

    #[tokio::test]
    async fn remove_absent_subnet_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        // Remove of an absent subnet returns Ok (exit 0), not an error.
        assert!(run_remove(&master, &sock, "ghost", None).await.is_ok());
    }

    // ── inner-core lib tests ──────────────────────────────────

    #[test]
    fn subnet_add_inner_returns_applied_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let report = add_inner(
            &master,
            "lan",
            Some("LAN"),
            &["10.0.0.0/24".into()],
            "default",
            Some(5),
            None,
        )
        .unwrap();
        assert_eq!(report.id, "lan");
        assert_eq!(report.target_path, master);
        // Single-file layout: the entry landed in the master.
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.subnets.len(), 1);
        assert_eq!(loaded.config.subnets[0].priority, 5);
    }

    #[test]
    fn subnet_set_inner_unknown_field_returns_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        add_inner(
            &master,
            "lan",
            None,
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .unwrap();
        let err = set_inner(&master, "lan", "bogus_field", "x", None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("bogus_field"), "got: {msg}");
    }

    #[test]
    fn subnet_add_inner_accepts_wildcard_and_normalises_to_cidr() {
        // Wildcard input must be accepted by the CLI surface and
        // land on disk in canonical `network/prefix` form so the
        // validator at the next `load_config` round-trips. Plain
        // CIDR inputs should still pass through byte-identical
        // (covered indirectly by the existing `add_subnet_writes_*`
        // tests which use `10.0.0.0/8` and `10.10.1.200/29`).
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let report = add_inner(
            &master,
            "lan-99",
            None,
            &["10.99.0.*".into()],
            "default",
            None,
            None,
        )
        .unwrap();
        assert_eq!(report.id, "lan-99");

        let raw = std::fs::read_to_string(&master).unwrap();
        assert!(
            raw.contains("\"10.99.0.0/24\""),
            "wildcard '10.99.0.*' must normalise to canonical CIDR; raw TOML:\n{raw}"
        );
        assert!(
            !raw.contains("10.99.0.*"),
            "raw wildcard must not survive into the TOML; raw TOML:\n{raw}"
        );
    }

    #[test]
    fn subnet_set_inner_cidrs_accepts_wildcard_and_normalises() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        add_inner(
            &master,
            "lan",
            None,
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .unwrap();
        set_inner(&master, "lan", "cidrs", "10.99.0.*", None).unwrap();
        let raw = std::fs::read_to_string(&master).unwrap();
        assert!(raw.contains("\"10.99.0.0/24\""), "got: {raw}");
    }

    #[test]
    fn subnet_set_fields_inner_is_atomic_on_invalid_field() {
        // Editing display_name + an invalid cidr in ONE call must leave the
        // on-disk display_name unchanged: the earlier (valid) field is
        // applied in-memory but the call bails before any write, so nothing
        // persists. (The old per-field `set_inner` loop committed
        // display_name before the cidr field failed.)
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        add_inner(
            &master,
            "lan",
            Some("Original"),
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .unwrap();

        let err = set_fields_inner(
            &master,
            "lan",
            &[("display_name", "Renamed"), ("cidrs", "not-a-cidr")],
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cidr"),
            "expected a cidr validation error, got: {err}"
        );

        let raw = std::fs::read_to_string(&master).unwrap();
        assert!(
            raw.contains("\"Original\""),
            "display_name must NOT have persisted (atomic revert); raw TOML:\n{raw}"
        );
        assert!(
            !raw.contains("Renamed"),
            "the failed edit must leave no trace; raw TOML:\n{raw}"
        );
    }

    #[test]
    fn subnet_set_fields_inner_applies_all_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        add_inner(
            &master,
            "lan",
            Some("Original"),
            &["10.0.0.0/8".into()],
            "default",
            None,
            None,
        )
        .unwrap();

        let report = set_fields_inner(
            &master,
            "lan",
            &[("display_name", "Renamed"), ("priority", "7")],
            None,
        )
        .unwrap();
        assert_eq!(report.fields, vec!["display_name", "priority"]);

        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let s = &loaded.config.subnets[0];
        assert_eq!(s.display_name, "Renamed");
        assert_eq!(s.priority, 7);
    }

    #[test]
    fn subnet_remove_inner_returns_noop_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let outcome = remove_inner(&master, "ghost", None).unwrap();
        match outcome {
            RemoveOutcome::NotFound { target_path } => {
                assert_eq!(target_path, master);
            }
            RemoveOutcome::Removed(_) => panic!("expected NotFound for ghost id"),
        }
    }

    // ── hot-reload wiring ───────────────────────────────

    #[tokio::test]
    async fn subnets_add_triggers_reload_when_daemon_up() {
        use super::super::hr2_test_support::{
            assert_single_reload_with_resolved_token, env_home, seed_token_for_test, stub_reload_ok,
        };

        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = dir.path().join("stub.sock");
        let (server, recorded) = stub_reload_ok(sock.clone()).await;

        let _env = env_home(dir.path()).await;
        seed_token_for_test(dir.path());
        run_add(
            &master,
            &sock,
            "lan-guest",
            None,
            &["10.10.1.200/29".into()],
            "guest",
            None,
            None,
        )
        .await
        .unwrap();

        server.await.unwrap();
        assert_single_reload_with_resolved_token(&recorded);
    }
    // ── `subnet show` prints tags ─────────────────────────────
    //
    // A subnet's tags land in the effective tag set of every device inside
    // its CIDRs that has no `[[devices]]` record — the clients the
    // operator never enumerated.
}
