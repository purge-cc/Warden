//! `warden group` — v1-native CRUD for `[[groups]]` entries.
//!
//! Mirrors the device command surface: list / add / set / remove /
//! show, with `--into <file>` target selection and validate-or-revert
//! on every mutation. Groups are a profile anchor — a device inherits
//! its profile from the highest-priority group it belongs to (unless
//! it has a direct `profile` field).

use std::path::Path;

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
use crate::config::loader::load_config;
use crate::config::schema::ScheduleTargetType;
use crate::config::schema::{Group, Id};

pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.groups.is_empty() {
        println!("no groups configured");
        println!(
            "add one with: warden group add <id> --profile <profile> [--priority N] \
             [--devices id1,id2]"
        );
        return Ok(());
    }
    println!("configured groups ({}):", loaded.config.groups.len());
    for g in &loaded.config.groups {
        let devs = if g.devices.is_empty() {
            "[]".to_string()
        } else {
            let n: Vec<&str> = g.devices.iter().map(|i| i.as_str()).collect();
            format!("[{}]", n.join(","))
        };
        println!(
            "  {id} \"{name}\" profile={prof} priority={pri} devices={devs}",
            id = g.id.as_str(),
            name = g.display_name,
            prof = g.profile.as_str(),
            pri = g.priority,
        );
    }
    Ok(())
}

pub fn run_show(config_path: &Path, id: &str) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let g = loaded
        .config
        .groups
        .iter()
        .find(|x| x.id.as_str() == id)
        .with_context(|| format!("group not found: {id}"))?;
    print!("{}", render_group_detail(g));
    Ok(())
}

/// The body of `warden group show` — one field per line. Pure so it is
/// unit-testable; `run_show` prints it verbatim.
fn render_group_detail(g: &Group) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "id:           {}", g.id.as_str());
    let _ = writeln!(out, "display_name: {}", g.display_name);
    let _ = writeln!(out, "profile:      {}", g.profile.as_str());
    let _ = writeln!(out, "priority:     {}", g.priority);
    if g.devices.is_empty() {
        let _ = writeln!(out, "devices:      (none)");
    } else {
        let n: Vec<&str> = g.devices.iter().map(|i| i.as_str()).collect();
        let _ = writeln!(out, "devices:      {}", n.join(", "));
    }
    // A group's tags are shown because the config still stores them, NOT
    // because they do anything anymore. What a member device filters comes
    // from its profile: `profiles.<id>.lists` if that profile declares a
    // direction for the list, else the list's own `base`.
    //
    // The line stays in `show` on purpose. An operator whose config
    // predates the cutover still has these arrays on disk, and hiding
    // them would make a stored value invisible rather than inert.
    // Omitting them
    // means the operator cannot see, from any command, why a group's
    // devices are getting a list.
    out
}

// ── Sync inner writers ─────────────────────────────────────────────────
//
// The TUI cannot call `run_add` / `run_set` / `run_remove`: those are
// CLI-shaped and `println!` their outcome, which on a raw-mode alternate
// screen bypasses ratatui's diff buffer and staircases one column per line
// (the v0.29.1 defect). The pipeline is replicated here, not the entry
// points — so the pipeline lives here, and the `run_*` verbs are thin
// printing wrappers over it. One implementation, not two that drift.
//
// All three are **sync**: the caller owns the post-write reload, so a TUI
// Save that changes both scalars and tags costs exactly one reload instead
// of one per writer.

/// What `add_inner` actually wrote, for the caller's audit line and toast.
pub(crate) struct AddReport {
    pub id: String,
    pub target_path: std::path::PathBuf,
}

/// What `set_fields_inner` actually wrote.
pub(crate) struct SetFieldsReport {
    pub id: String,
    pub fields: Vec<String>,
    pub target_path: std::path::PathBuf,
}

/// What `remove_inner` actually removed.
pub(crate) struct RemoveReport {
    pub id: String,
    pub target_path: std::path::PathBuf,
}

/// Validate the cross-references a new group depends on. Shared by the CLI
/// verb and the TUI so both refuse the same inputs with the same words.
fn validate_group_refs(
    loaded: &crate::config::loader::LoadedConfig,
    id: &str,
    profile: &str,
    devices: &[String],
) -> anyhow::Result<()> {
    if loaded.config.groups.iter().any(|g| g.id.as_str() == id) {
        bail!(
            "group \"{id}\" already exists. Use `warden group set {id} <field> <value>` or \
             pick a different id."
        );
    }
    if !loaded.config.profiles.contains_key(profile) {
        bail!(
            "profile \"{profile}\" is not defined. Create it first with `warden profile add \
             {profile} ...`."
        );
    }
    for d in devices {
        if !loaded.config.devices.iter().any(|x| x.id.as_str() == d) {
            bail!(
                "device \"{d}\" is not defined. Add it first with `warden device add {d} \
                 --ip <ip>` (or drop it from --devices)."
            );
        }
    }
    Ok(())
}

/// Create a group. **Sync** — caller owns the post-write reload.
///
/// Builds a whole row and hands it to `upsert_id_keyed`, which replaces the
/// matched row outright. That is safe *here* because the row is new, but it
/// is exactly the reset-on-omit trap the test below guards against: any
/// field this builder forgets is absent from the created group. The
/// exhaustive-destructuring test in this module fails the build if
/// `Group` grows a field this function does not consider.
pub(crate) fn add_inner(
    config_path: &Path,
    id: &str,
    display_name: Option<&str>,
    profile: &str,
    priority: Option<i32>,
    devices: &[String],
    into: Option<&Path>,
) -> anyhow::Result<AddReport> {
    let _ = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    validate_group_refs(&loaded, id, profile, devices)?;

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.unwrap_or(id).to_string()),
    );
    tbl.insert("profile".into(), Value::String(profile.to_string()));
    if let Some(p) = priority {
        tbl.insert("priority".into(), Value::Integer(p as i64));
    }
    if !devices.is_empty() {
        tbl.insert(
            "devices".into(),
            Value::Array(devices.iter().map(|d| Value::String(d.clone())).collect()),
        );
    }
    // `tags` is deliberately NOT written here: it is a delta primitive owned
    // by `entity_tags::TagEntity::Group`, and `apply_group_field` refuses it
    // too. A new group starts with no tags; the caller adds them as a second
    // write.

    let target_path = resolve_target_file(config_path, EntityClass::Groups, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    // A create, and the returned flag is what says so. `upsert_id_keyed`
    // replaces a matched row outright, and this builder writes a whole row, so
    // the day this verb stops refusing an existing id the replace would reset
    // every field the builder omits. Refusing here means nothing reaches disk.
    anyhow::ensure!(
        upsert_id_keyed(
            &mut doc,
            EntityClass::Groups.toml_key(),
            id,
            Value::Table(tbl),
        )?,
        "group \"{id}\" appeared in {} between the duplicate check and the write; \
         nothing was changed",
        target_path.display()
    );
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("group.add")
            .with_scope("group")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });
    Ok(AddReport {
        id: id.to_string(),
        target_path,
    })
}

/// Atomically update one or more scalar fields. Every mutation is applied
/// to the in-memory doc first, then the file is written **once** and
/// validated **once** — either every field lands or none do. A bad value
/// bails before any write, so an earlier field in the same call never
/// reaches disk while a later one fails.
///
/// `tags` is **not** a valid field here — `apply_group_field` refuses it.
/// Group tags are a delta through `entity_tags`, a different primitive with
/// different semantics.
pub(crate) fn set_fields_inner(
    config_path: &Path,
    id: &str,
    fields: &[(&str, &str)],
    into: Option<&Path>,
) -> anyhow::Result<SetFieldsReport> {
    let target_path = resolve_existing_target_file(config_path, EntityClass::Groups, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry =
        find_id_entry_mut(&mut doc, EntityClass::Groups.toml_key(), id)?.ok_or_else(|| {
            anyhow::anyhow!(
                "group \"{id}\" not found in {}. Use `--into <file>` to target a different \
                 include.",
                target_path.display()
            )
        })?;
    for (field, value) in fields {
        apply_group_field(entry, field, value)?;
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
            .with_action("group.set")
            .with_scope("group")
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

/// Remove a group. **Sync** — caller owns the post-write reload.
///
/// Refuses while any device or schedule still references it, with the same
/// words the CLI verb uses. `Ok(None)` means the group was already absent —
/// removal is idempotent, and the caller decides how to say so.
pub(crate) fn remove_inner(
    config_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<Option<RemoveReport>> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let refs: Vec<&str> = loaded
        .config
        .devices
        .iter()
        .filter(|d| d.groups.iter().any(|g| g.as_str() == id))
        .map(|d| d.id.as_str())
        .collect();
    if !refs.is_empty() {
        bail!(
            "group \"{id}\" still appears in the groups field of device(s): {}. Remove the \
             reference first with `warden device set <device> groups <remaining-list>`.",
            refs.join(", ")
        );
    }
    let sched_refs: Vec<&str> = loaded
        .config
        .schedules
        .iter()
        .filter(|s| s.target_type == ScheduleTargetType::Group && s.target_id.as_str() == id)
        .map(|s| s.id.as_str())
        .collect();
    if !sched_refs.is_empty() {
        bail!(
            "group \"{id}\" is still the target of schedule(s): {}. Remove them first with \
             `warden schedule remove <schedule-id>`.",
            sched_refs.join(", ")
        );
    }

    let target_path = resolve_existing_target_file(config_path, EntityClass::Groups, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    if !remove_id_keyed(&mut doc, EntityClass::Groups.toml_key(), id)? {
        return Ok(None);
    }
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("group.remove")
            .with_scope("group")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });
    Ok(Some(RemoveReport {
        id: id.to_string(),
        target_path,
    }))
}

// Must sit HERE, on the function it guards: an inner-writer block
// between this attribute and `run_add` orphans it above a comment, and
// clippy then reports both an empty line after an outer attribute AND
// an unguarded 8-argument `run_add`.
#[allow(clippy::too_many_arguments)]
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    profile: &str,
    priority: Option<i32>,
    devices: &[String],
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let report = add_inner(
        config_path,
        id,
        display_name,
        profile,
        priority,
        devices,
        into,
    )?;
    println!("added group {id} → {}", report.target_path.display());

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
    let report = set_fields_inner(config_path, id, &[(field, value)], into)?;
    println!(
        "set {field} = {value} on group {id} → {}",
        report.target_path.display()
    );

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
        None => {
            // Remove of an absent entity is idempotent (exit 0).
            println!("group \"{id}\" not found — nothing to remove");
            return Ok(());
        }
        Some(_) => println!("removed group {id}"),
    }

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

fn apply_group_field(entry: &mut Value, field: &str, value: &str) -> anyhow::Result<()> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("group entry is not a TOML table"))?;
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
            let n: i32 = value.parse().map_err(|_| {
                anyhow::anyhow!("priority must be a signed integer, got \"{value}\"")
            })?;
            tbl.insert("priority".into(), Value::Integer(n as i64));
        }
        "devices" => {
            let parts: Vec<Value> = value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect();
            if parts.is_empty() {
                tbl.remove("devices");
            } else {
                tbl.insert("devices".into(), Value::Array(parts));
            }
        }
        other => bail!("unknown field: {other}. Valid: display_name, profile, priority, devices"),
    }
    Ok(())
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

[profiles.iot]
display_name = "IoT"

[[devices]]
id = "hue-1"
display_name = "Hue bulb 1"
mac = "AA:BB:CC:DD:EE:01"

[[devices]]
id = "hue-2"
display_name = "Hue bulb 2"
mac = "AA:BB:CC:DD:EE:02"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        master
    }

    /// Socket path that does not exist → `attempt_reload` lands on
    /// `DaemonUnreachable`, which is benign; the post-write reload
    /// wiring is transparent to the "change lands on disk" assertions.
    fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("ghost.sock")
    }

    /// `add_inner` builds a WHOLE ROW and `upsert_id_keyed`
    /// replaces the matched row outright (`*item = entry`), so any field the
    /// builder omits is reset to its serde default — on save of *anything*,
    /// not of that field. That is the `accept_unsigned_allow` bug class,
    /// which shipped once and cost a release.
    ///
    /// The defence is this destructuring, NOT a comment: prose does not fail
    /// a build. `let Group { .. }` is exhaustive on purpose — no `..` — so
    /// the day someone adds a seventh field to `Group`, **this stops
    /// compiling** and they have to decide whether `add_inner` should write
    /// it, instead of discovering months later that it silently vanishes.
    #[test]
    fn dg5_every_group_field_is_considered_by_the_row_builder() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);

        add_inner(
            &master,
            "iot",
            Some("IoT devices"),
            "iot",
            Some(10),
            &["hue-1".to_string(), "hue-2".to_string()],
            None,
        )
        .expect("add");

        let now = time::OffsetDateTime::now_utc();
        let loaded = load_config(&master, now).expect("reload");
        let g = loaded
            .config
            .groups
            .iter()
            .find(|g| g.id.as_str() == "iot")
            .expect("group present after add");

        // Exhaustive. Adding a field to `Group` breaks THIS LINE first.
        let Group {
            id,
            display_name,
            profile,
            priority,
            devices,
        } = g;

        assert_eq!(id.as_str(), "iot");
        assert_eq!(display_name, "IoT devices");
        assert_eq!(profile.as_str(), "iot");
        assert_eq!(*priority, 10);
        assert_eq!(
            devices.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
            vec!["hue-1", "hue-2"]
        );
    }

    /// A `set` must not disturb fields it was not asked about.
    /// `set_fields_inner` is field-surgical, so this is true by
    /// construction — pinned because "by construction" is exactly what
    /// stops being true when someone swaps in a row builder for
    /// convenience.
    #[test]
    fn dg4_a_field_surgical_set_leaves_every_other_field_alone() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        add_inner(
            &master,
            "iot",
            Some("IoT devices"),
            "iot",
            Some(10),
            &["hue-1".to_string()],
            None,
        )
        .expect("add");

        set_fields_inner(&master, "iot", &[("display_name", "Renamed")], None).expect("set");

        let now = time::OffsetDateTime::now_utc();
        let loaded = load_config(&master, now).expect("reload");
        let g = loaded
            .config
            .groups
            .iter()
            .find(|g| g.id.as_str() == "iot")
            .expect("group survives the rename");

        assert_eq!(g.display_name, "Renamed");
        assert_eq!(g.profile.as_str(), "iot", "profile must survive a rename");
        assert_eq!(g.priority, 10, "priority must survive a rename");
        assert_eq!(
            g.devices.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
            vec!["hue-1"],
            "membership must survive a rename"
        );
    }

    #[tokio::test]
    async fn add_group_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iot",
            Some("IoT devices"),
            "iot",
            Some(5),
            &["hue-1".into(), "hue-2".into()],
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.groups.len(), 1);
        assert_eq!(loaded.config.groups[0].id.as_str(), "iot");
        assert_eq!(loaded.config.groups[0].priority, 5);
        assert_eq!(loaded.config.groups[0].devices.len(), 2);
    }

    #[tokio::test]
    async fn add_group_rejects_unknown_device() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "iot",
            None,
            "iot",
            None,
            &["ghost".into()],
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn add_group_rejects_unknown_profile() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(&master, &sock, "iot", None, "nonexistent", None, &[], None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[tokio::test]
    async fn set_group_priority() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(&master, &sock, "iot", None, "iot", Some(5), &[], None)
            .await
            .unwrap();
        run_set(&master, &sock, "iot", "priority", "42", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.groups[0].priority, 42);
    }

    #[tokio::test]
    async fn remove_group_with_reference_fails() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iot",
            None,
            "iot",
            None,
            &["hue-1".into()],
            None,
        )
        .await
        .unwrap();
        // Add groups = ["iot"] reference on hue-1 via `warden device set`
        super::super::devices::run_set(&master, &sock, "hue-1", "groups", "iot", None)
            .await
            .unwrap();
        let err = run_remove(&master, &sock, "iot", None).await.unwrap_err();
        assert!(err.to_string().contains("hue-1"), "got: {err}");
    }

    #[tokio::test]
    async fn remove_absent_group_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        // Remove of an absent group returns Ok (exit 0), not an error.
        assert!(run_remove(&master, &sock, "ghost", None).await.is_ok());
    }

    #[tokio::test]
    async fn remove_group_with_schedule_ref_refuses() {
        // A group still targeted by a schedule is refused with a
        // friendly message naming the schedule.
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[groups]]
id = "iot"
display_name = "IoT"
profile = "kids"

[[schedules]]
id = "sched-iot-1"
display_name = "IoT schedule"
target_type = "group"
target_id = "iot"
profile = "kids"
days = ["all"]
hours = "09:00-17:00"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let sock = fake_socket(&dir);
        let err = run_remove(&master, &sock, "iot", None).await.unwrap_err();
        assert!(err.to_string().contains("schedule"), "got: {err}");
        assert!(err.to_string().contains("sched-iot-1"), "got: {err}");
    }

    #[tokio::test]
    async fn remove_group_clean() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(&master, &sock, "iot", None, "iot", None, &[], None)
            .await
            .unwrap();
        run_remove(&master, &sock, "iot", None).await.unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.groups.is_empty());
    }

    // ── Hot-reload wiring ────────────────────────────────────────────────

    #[tokio::test]
    async fn groups_add_triggers_reload_when_daemon_up() {
        use super::super::hr2_test_support::{
            assert_single_reload_with_resolved_token, env_home, seed_token_for_test, stub_reload_ok,
        };

        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = dir.path().join("stub.sock");
        let (server, recorded) = stub_reload_ok(sock.clone()).await;

        let _env = env_home(dir.path()).await;
        seed_token_for_test(dir.path());
        run_add(&master, &sock, "iot", None, "iot", None, &[], None)
            .await
            .unwrap();

        server.await.unwrap();
        assert_single_reload_with_resolved_token(&recorded);
    }
    // ── `group show` prints tags ──────────────────────────────
    //
    // A group's tags are unioned into every member device's effective tag
    // set. Before this, the word "tags" appeared nowhere in this
    // module: an operator could not learn, from any command, that a group
    // was contributing a tag to its members.
}
