//! `warden device` — v1-native CRUD for `[[devices]]` entries.
//!
//! Sprint 33 introduced the v1-native flow: every mutation locates the
//! right `devices.d/*.toml` file (or the master on a single-file layout)
//! via [`crate::cli::commands::target`] helpers, applies the edit through
//! a `toml::Value` surgery, runs `loader::load_config`, and reverts on
//! any validator error. Sprint 34 retired the legacy `warden client`
//! alias; this module is now the sole device-management surface.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::format_config_errors;
use super::ipc_reload;
use super::target::{
    read_or_empty, remove_id_keyed, resolve_existing_target_file, resolve_target_file,
    upsert_id_keyed, upsert_profile, write_value_validated, EntityClass,
};
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::loader::load_config;
use crate::config::schema::{Device, Id, ScheduleTargetType};

/// List configured devices against the on-disk config.
///
/// Prints one line per device with `id`, `display_name`, identity
/// summary (IP / MAC), direct profile (if any), and group memberships.
pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let devices = &loaded.config.devices;
    if devices.is_empty() {
        println!("no devices configured");
        println!("add one with: warden device add <id> --ip <ip> --profile <profile>");
        return Ok(());
    }
    println!("configured devices ({}):", devices.len());
    for d in devices {
        let ip = d.ip.map(|i| format!(" ip={}", i)).unwrap_or_default();
        let mac = d
            .mac
            .as_deref()
            .map(|m| format!(" mac={m}"))
            .unwrap_or_default();
        let profile = d
            .profile
            .as_ref()
            .map(|p| format!(" profile={}", p.as_str()))
            .unwrap_or_default();
        let groups = if d.groups.is_empty() {
            String::new()
        } else {
            let list: Vec<&str> = d.groups.iter().map(|g| g.as_str()).collect();
            format!(" groups=[{}]", list.join(","))
        };
        println!(
            "  {id} \"{name}\"{ip}{mac}{profile}{groups}",
            id = d.id.as_str(),
            name = d.display_name
        );
    }
    Ok(())
}

/// List live devices from a running daemon via IPC.
///
/// Calls the `GetAllDevices` verb (tier-1 `ReadOnly`, no token) and
/// renders BOTH mapped devices (`[[devices]]` joined with live stats)
/// and observed-but-unmapped devices, each with MAC + OUI vendor — the
/// shape the Devices tab and `GET /api/devices` already use. Replaces
/// the older flat `DeviceStats` path, which carried no MAC / vendor /
/// unmapped rows and (being `Admin`-tier) failed outright on any daemon
/// with a control-socket token set. Serves UC-2 unmapped-device triage.
pub async fn run_live_list(socket_path: &Path, json: bool) -> anyhow::Result<()> {
    use crate::ipc::protocol::{IpcCommand, IpcResponse};
    use crate::ipc::socket_client;

    let resp = socket_client::send_command(socket_path, &IpcCommand::GetAllDevices).await?;
    match resp {
        IpcResponse::DeviceView(view) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                print!("{}", render_device_view(&view));
            }
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

fn format_last_seen(unix_ts: u64) -> String {
    if unix_ts == 0 {
        return "never".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ago = now.saturating_sub(unix_ts);
    if ago < 60 {
        "now".into()
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

/// Blocked-percentage for display. Returns 0.0 when the device has
/// logged no queries yet (avoids a divide-by-zero) — `MappedDeviceDto`
/// carries raw counts, not a precomputed percentage.
fn blocked_pct(queries: u64, blocked: u64) -> f64 {
    if queries == 0 {
        0.0
    } else {
        blocked as f64 / queries as f64 * 100.0
    }
}

/// Truncate `s` to at most `max` characters, appending `…` when cut.
/// Keeps the live-list columns aligned for long vendor strings / names.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Render a [`DeviceViewDto`](crate::ipc::protocol::DeviceViewDto) as a
/// two-section text table — mapped (`[[devices]]` joined with live
/// stats) then observed-but-unmapped, each with MAC + OUI vendor. Pure
/// (no IPC) so it is unit-testable; `run_live_list` prints the returned
/// string verbatim. Missing MAC / vendor render as `-`.
fn render_device_view(view: &crate::ipc::protocol::DeviceViewDto) -> String {
    use std::fmt::Write as _;

    if view.mapped.is_empty() && view.unmapped.is_empty() {
        return "no active devices\n".to_string();
    }

    let mut out = String::new();

    if view.mapped.is_empty() {
        let _ = writeln!(out, "mapped devices: none");
    } else {
        let _ = writeln!(out, "mapped devices ({}):", view.mapped.len());
        let _ = writeln!(
            out,
            "  {:<14} {:<15} {:<17} {:<18} {:>8} {:>8} {:<10} {:>9}",
            "NAME", "IP", "MAC", "VENDOR", "QUERIES", "BLOCK%", "PROFILE", "LAST SEEN"
        );
        for d in &view.mapped {
            let _ = writeln!(
                out,
                "  {:<14} {:<15} {:<17} {:<18} {:>8} {:>7.1}% {:<10} {:>9}",
                truncate(&d.name, 14),
                truncate(&d.ip, 15),
                truncate(d.mac.as_deref().unwrap_or("-"), 17),
                truncate(d.vendor.as_deref().unwrap_or("-"), 18),
                d.queries,
                blocked_pct(d.queries, d.blocked),
                truncate(&d.profile, 10),
                format_last_seen(d.last_seen),
            );
        }
    }

    if !view.unmapped.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "unmapped (observed) devices ({}):",
            view.unmapped.len()
        );
        let _ = writeln!(
            out,
            "  {:<15} {:<17} {:<18} {:>8} {:>8} {:>9}",
            "IP", "MAC", "VENDOR", "QUERIES", "BLOCKED", "LAST SEEN"
        );
        for d in &view.unmapped {
            let _ = writeln!(
                out,
                "  {:<15} {:<17} {:<18} {:>8} {:>8} {:>9}",
                truncate(&d.ip, 15),
                truncate(d.mac.as_deref().unwrap_or("-"), 17),
                truncate(d.vendor.as_deref().unwrap_or("-"), 18),
                d.queries,
                d.blocked,
                format_last_seen(d.last_seen),
            );
        }
        let _ = writeln!(
            out,
            "  map one with: warden device add <id> --ip <ip> --profile <profile>"
        );
    }

    out
}

/// Render a single device in a detail view (one field per line).
pub fn run_show(config_path: &Path, id: &str) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let dev = loaded
        .config
        .devices
        .iter()
        .find(|d| d.id.as_str() == id)
        .with_context(|| format!("device not found: {id}"))?;
    print!("{}", render_device_detail(dev));
    Ok(())
}

/// The body of `warden device show` — one field per line.
///
/// Pure (no IPC, no config load) so it is unit-testable; `run_show`
/// prints the returned string verbatim. Same split as
/// [`render_device_view`] uses for the live list.
fn render_device_detail(dev: &Device) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "id:           {}", dev.id.as_str());
    let _ = writeln!(out, "display_name: {}", dev.display_name);
    match dev.ip {
        Some(ip) => {
            let _ = writeln!(out, "ip:           {ip}");
        }
        None => {
            let _ = writeln!(out, "ip:           <unset>");
        }
    }
    match dev.mac.as_deref() {
        Some(m) => {
            let _ = writeln!(out, "mac:          {m}");
        }
        None => {
            let _ = writeln!(out, "mac:          <unset>");
        }
    }
    if !dev.mac_aliases.is_empty() {
        let _ = writeln!(out, "mac_aliases:  {}", dev.mac_aliases.join(", "));
    }
    match dev.profile.as_ref() {
        Some(p) => {
            let _ = writeln!(out, "profile:      {}", p.as_str());
        }
        None => {
            let _ = writeln!(out, "profile:      <inherits from group/subnet>");
        }
    }
    if !dev.groups.is_empty() {
        let g: Vec<&str> = dev.groups.iter().map(|g| g.as_str()).collect();
        let _ = writeln!(out, "groups:       {}", g.join(", "));
    }
    if let Some(owner) = &dev.owner {
        let _ = writeln!(out, "owner:        {owner}");
    }
    if let Some(dn) = &dev.device_type {
        let _ = writeln!(out, "device_type:  {dn}");
    }
    if let Some(dept) = &dev.department {
        let _ = writeln!(out, "department:   {dept}");
    }
    if let Some(notes) = &dev.notes {
        let _ = writeln!(out, "notes:        {notes}");
    }

    // ── state that changes what the resolver does ─────────────────────
    //
    // Printed unconditionally, unlike the optional metadata above. These
    // four decide how the device's queries are filtered, and a field that
    // shows up only when set teaches the operator that absence means
    // `false` — which is indistinguishable from a build that cannot show
    // the field at all.
    let _ = writeln!(
        out,
        "allow_rules:  {}",
        join_rule_ids(&dev.allow_rules).as_str()
    );
    let _ = writeln!(
        out,
        "deny_rules:   {}",
        join_rule_ids(&dev.deny_rules).as_str()
    );
    if dev.override_profile_deny {
        let _ = writeln!(
            out,
            "override_profile_deny: true  (allow_rules beat profile-level denies)"
        );
    } else {
        let _ = writeln!(out, "override_profile_deny: false");
    }
    if dev.unfiltered {
        let _ = writeln!(out, "unfiltered:   true  (filtering skipped entirely)");
    } else {
        let _ = writeln!(out, "unfiltered:   false");
    }

    out
}

/// Render a rule-overlay id list, or `(none)` when empty. Empty is the
/// common case and it is an answer, not a reason to print nothing.
fn join_rule_ids(ids: &[Id]) -> String {
    if ids.is_empty() {
        return "(none)".to_string();
    }
    ids.iter()
        .map(|i| i.as_str())
        .collect::<Vec<&str>>()
        .join(", ")
}

/// Add or replace a device. See
/// [`DeviceAction::Add`](crate::cli::DeviceAction::Add) for the
/// per-field contract.
#[allow(clippy::too_many_arguments)]
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    ip: Option<IpAddr>,
    mac: Option<&str>,
    profile: Option<&str>,
    groups: &[String],
    owner: Option<&str>,
    device_field: Option<&str>,
    department: Option<&str>,
    notes: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // Validate the id at the CLI boundary so a bad id surfaces before
    // we touch any file. Per feedback_usability_first: name what failed.
    let _parsed_id = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;

    if ip.is_none() && mac.is_none() {
        bail!(
            "at least one of --ip or --mac is required — a device without \
             identity is unreachable by the resolver. Examples:\n  \
             warden device add {id} --ip 192.0.2.42\n  \
             warden device add {id} --mac AA:BB:CC:DD:EE:FF"
        );
    }

    // Pre-flight: reject duplicate id up front against the CURRENT merged
    // view. The validator will catch this too but we can give a better
    // message earlier.
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.devices.iter().any(|d| d.id.as_str() == id) {
        bail!(
            "device \"{id}\" already exists. Use `warden device set {id} <field> <value>` to edit, \
             or pick a different id."
        );
    }

    // Cross-reference any referenced profile / group as a friendliness
    // pre-check. A post-edit validator run would catch these too but the
    // operator gets a much clearer message when we fail at the CLI.
    if let Some(p) = profile {
        if !loaded.config.profiles.contains_key(p) {
            bail!(
                "profile \"{p}\" is not defined. Existing profiles: {}. \
                 Create it first with `warden profile add {p} ...` (or pick another).",
                profile_names(&loaded.config.profiles)
            );
        }
    }
    for g in groups {
        if !loaded.config.groups.iter().any(|x| x.id.as_str() == g) {
            bail!(
                "group \"{g}\" is not defined. Existing groups: {}. Create it first with \
                 `warden group add {g} --profile <profile>`.",
                group_names(&loaded.config.groups)
            );
        }
    }

    // Build the entry as a toml::Value so the in-memory transform and the
    // serialised output use the same shape that the schema would.
    let display = display_name.unwrap_or(id);
    let entry = build_device_value(
        id,
        display,
        ip,
        mac,
        profile,
        groups,
        owner,
        device_field,
        department,
        notes,
    )?;

    let target_path = resolve_target_file(config_path, EntityClass::Devices, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    // A create, and the returned flag is what says so — `build_device_value`
    // writes a partial row and `upsert_id_keyed` replaces a matched one
    // outright, so a replace here would reset every field it does not write.
    anyhow::ensure!(
        upsert_id_keyed(&mut doc, EntityClass::Devices.toml_key(), id, entry)?,
        "device \"{id}\" appeared in {} between the duplicate check and the write; \
         nothing was changed",
        target_path.display()
    );
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.add")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });

    println!("added device {id} → {path}", path = target_path.display());

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Set a single field on an existing device. Supported fields: `ip`,
/// `mac`, `profile`, `display_name`, `owner`, `device_type` (the legacy
/// `device` spelling is also accepted and rewritten to `device_type`),
/// `department`, `notes`. Lists (`tags`, `groups`) are comma-separated.
/// `mac_aliases` is config-file-only — there is no `set` arm for it; edit
/// the device's TOML entry directly to add aliases.
pub async fn run_set(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let target_path = apply_set_inline(config_path, id, field, value, into)?;
    let id_for_audit = id.to_string();
    let fields_after = format!("{field}={value}");
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.set")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_fields_after(fields_after)
            .with_files([config_path, target_path.as_path()])
    });
    println!("updated {id}.{field} = {value}");

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Apply a single field change without printing or reloading. Extracted
/// so [`run_block`] / [`run_unblock`] can share the mutation logic with
/// [`run_set`] while emitting a single reload after the compound write
/// (Sprint 36 HR2: "reload fires ONCE at the end of the compound
/// mutation, not twice"). Design doc §2 HR2 — atomicity invariant.
fn apply_set_inline(
    config_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    // Locate the file that actually defines the device. With `--into` the
    // operator's explicit choice wins; otherwise resolve the owning file
    // via the include graph so a `set` works even when the device lives in
    // a non-auto-selected slice (rev2606 target-02).
    let target_path = resolve_existing_target_file(config_path, EntityClass::Devices, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;

    let entry =
        find_id_entry_mut(&mut doc, EntityClass::Devices.toml_key(), id)?.ok_or_else(|| {
            anyhow::anyhow!(
                "device \"{id}\" not found in {}. Use `warden device list` to see all devices, \
                 or pass `--into <file>` to target a specific include.",
                target_path.display()
            )
        })?;

    apply_device_field(entry, field, value)?;

    write_value_validated(config_path, &target_path, &doc)?;
    Ok(target_path)
}

/// Remove a device by id. Fails if any group lists this device as a
/// member — the operator must remove it from the group first (clear
/// cross-ref before dropping the entity).
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let referenced_by: Vec<&str> = loaded
        .config
        .groups
        .iter()
        .filter(|g| g.devices.iter().any(|d| d.as_str() == id))
        .map(|g| g.id.as_str())
        .collect();
    if !referenced_by.is_empty() {
        bail!(
            "device \"{id}\" is still referenced by group(s): {}. Remove it from \
             each group first with `warden group set <group> remove-device {id}`.",
            referenced_by.join(", ")
        );
    }
    // verbs-05: also refuse if a schedule still targets this device (e.g. a
    // `warden device quiet` window). The post-write validator catches it,
    // but with a terser message.
    let sched_refs: Vec<&str> = loaded
        .config
        .schedules
        .iter()
        .filter(|s| s.target_type == ScheduleTargetType::Device && s.target_id.as_str() == id)
        .map(|s| s.id.as_str())
        .collect();
    if !sched_refs.is_empty() {
        bail!(
            "device \"{id}\" is still the target of schedule(s): {}. Remove them first with \
             `warden schedule remove <schedule-id>`.",
            sched_refs.join(", ")
        );
    }

    let target_path = resolve_existing_target_file(config_path, EntityClass::Devices, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let removed = remove_id_keyed(&mut doc, EntityClass::Devices.toml_key(), id)?;
    if !removed {
        // verbs-02: remove of an absent entity is idempotent (exit 0).
        println!("device \"{id}\" not found — nothing to remove");
        return Ok(());
    }
    write_value_validated(config_path, &target_path, &doc)?;
    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.remove")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });
    println!("removed device {id}");

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// `warden device block <id>` — force-route the device to the `blocked`
/// profile. Creates `[profiles.blocked]` with `block_all = true` if it
/// doesn't exist yet. Same semantics as the legacy `warden client block`.
///
/// Sprint 36 HR2: the compound mutation (profile auto-create THEN device
/// pointer set) emits exactly ONE reload at the end. The up-front
/// device-exists pre-flight (below) makes the common failure abort before
/// any write. Residual to be aware of: step 1 writes AND validates the
/// master before step 2 runs, so a (rare) step-2 failure rolls back only
/// step 2's target — the auto-created `[profiles.blocked]` is left on
/// disk. That is benign: `blocked` is idempotent (`block_all`) and is
/// reused on the next block via the `blocked_existed` guard, not duplicated.
pub async fn run_block(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // Pre-flight: confirm the device exists BEFORE touching the profile
    // file. Sprint 36 panel (Marco, 2026-04-23): without this check, a
    // `warden device block ghost` call on a master without a `blocked`
    // profile would auto-create `[profiles.blocked]`, then fail on the
    // missing device, and leave the half-committed profile on disk.
    // This check guarantees the compound mutation is all-or-nothing:
    // either both writes land, or neither does.
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if !loaded.config.devices.iter().any(|d| d.id.as_str() == id) {
        bail!(
            "device \"{id}\" not found. Run `warden device list` to see configured devices, \
             or `warden device add {id} --ip <ip>` to create it first."
        );
    }

    // Step 1: ensure the `blocked` profile exists. We write into the
    // MASTER file because profiles are rarely split; keeping them
    // centralised matches operator intuition. Operators who split
    // profiles can override via --into on a subsequent `warden profile`
    // mutation — out of scope for S33 MVP.
    //
    // cli-h4: this asked the MASTER's raw TOML whether `blocked` existed,
    // while `run_quiet` — the same auto-create, four hundred lines down —
    // asked the merged view. On a split layout with `[profiles.blocked]`
    // in `profiles.d/`, the raw probe said "absent", so `device block`
    // upserted a SECOND `blocked` into the master and the loader's
    // named-map duplicate-key detection refused the write. The verb was
    // unusable on exactly the layout `warden migrate` produces by default.
    // Existence questions go to the merged view; only the write target
    // stays the master.
    let (mut master_doc, _) = read_or_empty(config_path)?;
    let blocked_existed = loaded.config.profiles.contains_key("blocked");
    if !blocked_existed {
        let profile_entry: Value = toml::from_str(
            r#"display_name = "Blocked"
block_all = true
"#,
        )
        .context("building blocked profile")?;
        upsert_profile(&mut master_doc, "blocked", profile_entry)?;
        write_value_validated(config_path, config_path, &master_doc)?;
    }

    // Step 2: point the device at the blocked profile. Use the
    // reload-less inline helper so the compound mutation emits a SINGLE
    // reload at the end (not one per sub-step).
    let target_path = apply_set_inline(config_path, id, "profile", "blocked", into)?;
    let id_for_audit = id.to_string();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.block")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_path.as_path()])
    });
    if !blocked_existed {
        println!("auto-created profile \"blocked\" (block_all = true)");
    }
    println!("blocked device {id}");
    println!("to unblock: warden device unblock {id} --profile <original>");

    // Sprint 36 HR2: post-compound reload — one per `warden device
    // block`, regardless of whether the blocked profile was auto-created.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Restore a device's profile (the inverse of [`run_block`]).
pub async fn run_unblock(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    profile: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let target_path = apply_set_inline(config_path, id, "profile", profile, into)?;
    let id_for_audit = id.to_string();
    let profile_for_audit = profile.to_string();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.unblock")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_fields_after(profile_for_audit)
            .with_files([config_path, target_path.as_path()])
    });
    println!("updated {id}.profile = {profile}");

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Format a toml::Value entry for a device. Private helper so both
/// `run_add` and future test fixtures share the same shape.
#[allow(clippy::too_many_arguments)]
fn build_device_value(
    id: &str,
    display_name: &str,
    ip: Option<IpAddr>,
    mac: Option<&str>,
    profile: Option<&str>,
    groups: &[String],
    owner: Option<&str>,
    device_field: Option<&str>,
    department: Option<&str>,
    notes: Option<&str>,
) -> anyhow::Result<Value> {
    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.to_string()),
    );
    if let Some(ip) = ip {
        tbl.insert("ip".into(), Value::String(ip.to_string()));
    }
    if let Some(mac) = mac {
        tbl.insert("mac".into(), Value::String(mac.to_string()));
    }
    if let Some(profile) = profile {
        tbl.insert("profile".into(), Value::String(profile.to_string()));
    }
    if !groups.is_empty() {
        tbl.insert(
            "groups".into(),
            Value::Array(groups.iter().map(|g| Value::String(g.clone())).collect()),
        );
    }
    if let Some(v) = owner {
        tbl.insert("owner".into(), Value::String(v.to_string()));
    }
    if let Some(v) = device_field {
        // devices-04: write the canonical `device_type` key (the legacy
        // `device` name still loads via the serde alias on the struct).
        tbl.insert("device_type".into(), Value::String(v.to_string()));
    }
    if let Some(v) = department {
        tbl.insert("department".into(), Value::String(v.to_string()));
    }
    if let Some(v) = notes {
        tbl.insert("notes".into(), Value::String(v.to_string()));
    }
    Ok(Value::Table(tbl))
}

/// Mutate one field of a device entry, typed by field name.
fn apply_device_field(entry: &mut Value, field: &str, value: &str) -> anyhow::Result<()> {
    let table = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("device entry is not a TOML table"))?;
    match field {
        "ip" => {
            if value.is_empty() || value == "none" {
                table.remove("ip");
            } else {
                let parsed: IpAddr = value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid IP: {value}"))?;
                table.insert("ip".into(), Value::String(parsed.to_string()));
            }
        }
        "mac" => {
            if value.is_empty() || value == "none" {
                table.remove("mac");
            } else {
                table.insert("mac".into(), Value::String(value.to_string()));
            }
        }
        "profile" => {
            if value.is_empty() || value == "none" {
                table.remove("profile");
            } else {
                table.insert("profile".into(), Value::String(value.to_string()));
            }
        }
        "display_name" => {
            if value.is_empty() {
                bail!("display_name cannot be empty");
            }
            table.insert("display_name".into(), Value::String(value.to_string()));
        }
        "device" | "device_type" => {
            // devices-04: accept both the canonical `device_type` and the
            // legacy `device` spelling, but always write the canonical key
            // (and clear any legacy key) so on-disk vocabulary converges.
            table.remove("device");
            if value.is_empty() || value == "none" {
                table.remove("device_type");
            } else {
                table.insert("device_type".into(), Value::String(value.to_string()));
            }
        }
        "owner" | "department" | "notes" => {
            if value.is_empty() || value == "none" {
                table.remove(field);
            } else {
                table.insert(field.into(), Value::String(value.to_string()));
            }
        }
        // `plp-s5c`: the generic field-setter was the last CLI route that
        // still WROTE a device tag, and it wrote one silently.
        //
        // `warden device tag add` announced itself as a tag verb and was
        // refused by `refuse_tag_writes` at the plp-s3 cutover. This arm
        // reaches the same `tags` array through a field name, so that
        // refusal never covered it: `warden device set laptop tags work`
        // validated, persisted, reloaded and reported success, for a value
        // that has decided nothing since S3. Operator intent accepted and
        // dropped on the floor — the exact failure mode the tag model was
        // retired for.
        //
        // Refused by name rather than left to the `other` arm below,
        // because "unknown field: tags" would be false: the field exists,
        // still loads and is still shown by `warden device show`. What is
        // gone is its effect, and only a message that says so points the
        // operator anywhere useful.
        "tags" => bail!("{}", super::entity_tags::TAGS_RETIRED),
        "groups" => {
            let parts: Vec<Value> = value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect();
            if parts.is_empty() {
                table.remove("groups");
            } else {
                table.insert("groups".into(), Value::Array(parts));
            }
        }
        "network_name" => {
            if value.is_empty() || value == "none" {
                table.remove("network_name");
            } else {
                table.insert("network_name".into(), Value::String(value.to_string()));
            }
        }
        "network_name_wildcard" => {
            let parsed = match value.to_ascii_lowercase().as_str() {
                "true" | "on" | "yes" | "1" => true,
                "false" | "off" | "no" | "0" => false,
                other => bail!("invalid boolean for network_name_wildcard: {other}"),
            };
            table.insert("network_name_wildcard".into(), Value::Boolean(parsed));
        }
        other => bail!(
            "unknown field: {other}. Valid: ip, mac, profile, display_name, owner, device, \
             department, notes, groups, network_name, network_name_wildcard"
        ),
    }
    Ok(())
}

// ── Sprint C of `lists_categories_v2` (T7-Grp4): set-unfiltered verb
//    frozen strings + handler. Setting `unfiltered = true` also clears
//    the `tags` array (D14 mutual exclusion enforced at write time so
//    the operator can't tell-then-bail-on-validate).

pub const DEVICE_SET_UNFILTERED_OK: &str = "Device '{id}' unfiltered={value}.";

pub fn format_device_set_unfiltered_ok(id: &str, value: bool) -> String {
    DEVICE_SET_UNFILTERED_OK
        .replace("{id}", id)
        .replace("{value}", &value.to_string())
}

pub const DEVICE_SET_UNFILTERED_NOOP: &str = "Device '{id}' unfiltered already {value}. No change.";

pub fn format_device_set_unfiltered_noop(id: &str, value: bool) -> String {
    DEVICE_SET_UNFILTERED_NOOP
        .replace("{id}", id)
        .replace("{value}", &value.to_string())
}

/// Operator-facing warning emitted only when `set-unfiltered` flips a
/// device to `true`. Frozen by the inline pin below — wording chosen to
/// remind the operator that DNS resolution + query log + stats remain
/// active so the device is observable, just not filtered (D14).
pub const DEVICE_SET_UNFILTERED_WARN: &str = "device '{id}' not filtered. Monitoring stays active.";

pub fn format_device_set_unfiltered_warn(id: &str) -> String {
    DEVICE_SET_UNFILTERED_WARN.replace("{id}", id)
}

/// `warden devices set-unfiltered <id> <true|false>`. Idempotent. When
/// `value = true`, also clears the `tags` array in the same write to
/// preserve D14 mutual exclusion. Emits [`DEVICE_SET_UNFILTERED_WARN`]
/// in addition to the OK message when the new value is `true`.
pub async fn run_set_unfiltered(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    value: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let dev = loaded
        .config
        .devices
        .iter()
        .find(|d| d.id.as_str() == id)
        .with_context(|| format!("device '{id}' not found"))?;

    // The no-op test used to have a second half: `unfiltered = true` also
    // had to clear the device's `tags`, so an already-true device with tags
    // still had work to do. `plp-s5a` removed the field, so the flag is the
    // whole state this verb writes.
    if dev.unfiltered == value {
        println!("{}", format_device_set_unfiltered_noop(id, value));
        return Ok(());
    }

    let target_path = resolve_existing_target_file(config_path, EntityClass::Devices, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_id_entry_mut(&mut doc, EntityClass::Devices.toml_key(), id)?
        .ok_or_else(|| anyhow::anyhow!("device '{id}' not found in {}", target_path.display()))?;
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("device entry is not a TOML table"))?;
    tbl.insert("unfiltered".into(), Value::Boolean(value));
    if value {
        // D14: clear tags atomically so the post-write state is consistent.
        tbl.insert("tags".into(), Value::Array(toml::value::Array::new()));
    }
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let value_for_audit = value.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.set_unfiltered")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_fields_after(value_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });

    println!("{}", format_device_set_unfiltered_ok(id, value));
    if value {
        println!("{}", format_device_set_unfiltered_warn(id));
    }

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// Find a mutable reference to an id-keyed entry inside an array-of-tables.
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

fn profile_names(
    profiles: &std::collections::BTreeMap<String, crate::config::schema::Profile>,
) -> String {
    if profiles.is_empty() {
        return "(none)".into();
    }
    let mut keys: Vec<&str> = profiles.keys().map(|s| s.as_str()).collect();
    keys.sort();
    keys.join(", ")
}

fn group_names(groups: &[crate::config::schema::Group]) -> String {
    if groups.is_empty() {
        return "(none)".into();
    }
    let mut names: Vec<&str> = groups.iter().map(|g| g.id.as_str()).collect();
    names.sort();
    names.join(", ")
}

fn too_far_in_the_future(s: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "--for \"{s}\" is too far in the future; pick a shorter duration or use --until"
    )
}

/// Parse the helper for `warden device quiet --for 15m` / `--until <rfc3339>`.
/// Kept here (rather than in `clients.rs` where it originated) so the
/// full v1 device flow lives in one file; the semantics are unchanged.
pub fn parse_quiet_duration(
    for_str: Option<&str>,
    until_str: Option<&str>,
) -> anyhow::Result<time::OffsetDateTime> {
    match (for_str, until_str) {
        (Some(s), None) => {
            let d = humantime::parse_duration(s).map_err(|_| {
                anyhow::anyhow!(
                    "couldn't parse \"{s}\" as a duration. Try forms like `15m`, `2h`, \
                     `1h30m`, `45min`, `90s`."
                )
            })?;
            let secs = d.as_secs();
            if secs == 0 {
                bail!("--for must be at least 1 second; got 0");
            }
            // `humantime` accepts "100000years", and both the `as i64` narrowing
            // and `impl Add for OffsetDateTime` are lossy on it — the cast wraps
            // negative and the addition panics past year 9999. An operator-typed
            // value must fail as an error, like every other arm here.
            let secs = i64::try_from(secs).map_err(|_| too_far_in_the_future(s))?;
            time::OffsetDateTime::now_utc()
                .checked_add(time::Duration::seconds(secs))
                .ok_or_else(|| too_far_in_the_future(s))
        }
        (None, Some(s)) => {
            let exp =
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "couldn't parse \"{s}\" as RFC 3339. Try `2026-04-13T22:30:00Z`."
                        )
                    })?;
            if exp <= time::OffsetDateTime::now_utc() {
                bail!("--until must be in the future; \"{s}\" is already in the past");
            }
            Ok(exp)
        }
        (Some(_), Some(_)) => bail!("--for and --until are mutually exclusive"),
        (None, None) => bail!(
            "must specify one of --for <duration> or --until <rfc3339>. Example: \
             `warden device quiet tablet --for 15m`"
        ),
    }
}

/// Add a one-shot `[[schedules]]` entry that blocks the named device
/// until `now + duration` (or `--until <rfc3339>`). Mirrors the legacy
/// `warden client quiet` semantics on the v1 schedule shape.
///
/// Sprint 36 HR2: compound mutation (blocked profile + schedule append)
/// emits ONE reload at the end.
pub async fn run_quiet(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    for_str: Option<&str>,
    until_str: Option<&str>,
    into: Option<&PathBuf>,
) -> anyhow::Result<()> {
    let expires_at = parse_quiet_duration(for_str, until_str)?;

    // Device existence check up front.
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if !loaded.config.devices.iter().any(|d| d.id.as_str() == id) {
        bail!("no device named \"{id}\". Run `warden device list` to see configured devices.");
    }

    // Self-clean: drop already-expired schedules before appending the new
    // one, so repeated quiets never accumulate dead rows even when the
    // daemon (and its 60 s tick prune) isn't running. Best-effort —
    // expired rows are inert, so a prune failure must not block the quiet.
    match super::schedules::prune_expired_schedules(config_path, &loaded, now) {
        Ok(pruned) if !pruned.is_empty() => {
            println!(
                "pruned {} expired schedule(s): {}",
                pruned.len(),
                pruned.join(", ")
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("warning: could not prune expired schedules: {e:#}");
        }
    }

    // Formatted once and reused: the schedule row and the success line must
    // agree, and RFC 3339 has no five-digit year, so this is a failure the
    // operator gets told about rather than a panic.
    let expires_rfc3339 = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .context("formatting the quiet expiry as RFC 3339")?;

    // Ensure blocked profile exists.
    let blocked_existed = loaded.config.profiles.contains_key("blocked");
    if !blocked_existed {
        let (mut master_doc, _) = read_or_empty(config_path)?;
        let blocked_tbl: Value = toml::from_str(
            r#"display_name = "Blocked"
block_all = true
"#,
        )
        .context("building blocked profile")?;
        upsert_profile(&mut master_doc, "blocked", blocked_tbl)?;
        write_value_validated(config_path, config_path, &master_doc)?;
    }

    // Append the schedule. Schedule id must be unique + valid — we derive
    // one from device id + timestamp; callers hitting the 64-byte cap can
    // shorten manually via future iterations.
    let sched_id = format!(
        "quiet-{id}-{}",
        expires_at
            .unix_timestamp()
            .to_string()
            .chars()
            .rev()
            .take(6)
            .collect::<String>()
    );
    // `00:00-00:00` is the engine's canonical always-on form (midnight
    // wrap). NOT `00:00-23:59`: window matching is end-exclusive, which
    // left the quieted device unfiltered for the 23:59 minute every day
    // (rev-2606 devices-01).
    let sched_entry: Value = toml::from_str(&format!(
        r#"id = "{sched_id}"
display_name = "Quiet device {id}"
target_type = "device"
target_id = "{id}"
profile = "blocked"
days = ["all"]
hours = "00:00-00:00"
expires_at = "{ts}"
"#,
        ts = expires_rfc3339
    ))
    .context("building quiet schedule")?;

    let target_path = resolve_target_file(
        config_path,
        EntityClass::Schedules,
        into.map(|p| p.as_path()),
    )?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    // The one whole-row writer here that deliberately does NOT assert it
    // created a row: `sched_id` carries a six-digit slice of the expiry
    // timestamp, so re-quieting the same device inside the same second
    // resolves to the same id and must replace rather than stack a duplicate.
    // Safe because this builder writes every `Schedule` field — pinned by the
    // exhaustive destructuring test in this module, not by this sentence.
    upsert_id_keyed(&mut doc, "schedules", &sched_id, sched_entry)?;
    write_value_validated(config_path, &target_path, &doc)?;

    let id_for_audit = id.to_string();
    let sched_for_audit = sched_id.clone();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("device.quiet")
            .with_scope("device")
            .with_target_id(id_for_audit)
            .with_record_value(sched_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });

    if !blocked_existed {
        println!("auto-created profile \"blocked\"");
    }
    println!("quieted device {id} until {expires_rfc3339}");

    // Sprint 36 HR2: post-compound reload.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_minimal(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        master
    }

    /// Socket path that definitely does not exist → attempt_reload lands
    /// on `DaemonUnreachable`, the benign outcome. Sprint 36 HR2 wiring
    /// is agnostic to the reload outcome for the "change lands on disk"
    /// assertions below; the reload-triggers tests live further down in
    /// dedicated `hot_reload` modules.
    fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("ghost.sock")
    }

    /// cli-h4: `device block` asked the MASTER's raw TOML whether the
    /// `blocked` profile existed, while `device quiet` — same auto-create,
    /// same file — asked the merged view. With `[profiles.blocked]` in a
    /// `profiles.d/` slice the raw probe answered "absent", so block
    /// upserted a second `blocked` into the master and the loader's
    /// named-map duplicate-key detection refused the whole write.
    ///
    /// This is the layout `warden migrate v0-to-v1` produces by default,
    /// so the verb was broken on the normal case and working on the
    /// single-file one. The fixture puts `blocked` ONLY in the slice: a
    /// probe that reads the master cannot see it, and the pre-fix code
    /// fails on the duplicate rather than passing by luck.
    #[tokio::test]
    async fn block_finds_an_existing_blocked_profile_in_an_include_slice() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3
includes = ["profiles.d/*.toml"]

[server]
default_profile = "default"

[[devices]]
id = "laptop"
display_name = "Laptop"
ip = "10.0.0.5"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("profiles.d")).unwrap();
        std::fs::write(
            dir.path().join("profiles.d").join("p.toml"),
            "[profiles.default]\ndisplay_name = \"Default\"\n\n\
             [profiles.blocked]\ndisplay_name = \"Blocked\"\nblock_all = true\n",
        )
        .unwrap();

        run_block(&master, &fake_socket(&dir), "laptop", None)
            .await
            .expect("block must reuse the blocked profile the include already defines");

        // The device moved …
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let dev = loaded
            .config
            .devices
            .iter()
            .find(|d| d.id.as_str() == "laptop")
            .expect("device must survive");
        assert_eq!(dev.profile.as_ref().map(|p| p.as_str()), Some("blocked"));

        // … and no duplicate was written into the master. Asserting on the
        // master's own bytes, not the merged view: the merged view cannot
        // show a duplicate, because the loader refuses to produce one.
        let master_body = std::fs::read_to_string(&master).unwrap();
        assert!(
            !master_body.contains("[profiles.blocked]"),
            "block re-created `blocked` in the master despite the include \
             already defining it: {master_body}"
        );
    }

    #[test]
    fn live_list_renders_mapped_and_unmapped_with_mac_vendor() {
        use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto, UnmappedDeviceDto};

        let view = DeviceViewDto {
            mapped: vec![MappedDeviceDto {
                ip: "10.0.0.5".into(),
                name: "kitchen-pi".into(),
                mac: Some("AA:BB:CC:DD:EE:FF".into()),
                mac_aliases: vec![],
                profile: "default".into(),
                owner: None,
                device_type: None,
                department: None,
                queries: 200,
                queries_today: 0,
                blocked: 50,
                blocked_24h: 0,
                cache_hits: 0,
                last_seen: 0,
                online: true,
                vendor: Some("Raspberry Pi Foundation".into()),
                groups: vec![],
                notes: None,
                network_name: None,
                network_name_wildcard: false,
                id: Some("kitchen-pi".into()),
                hourly_queries: vec![],
                unfiltered: false,
            }],
            unmapped: vec![UnmappedDeviceDto {
                ip: "10.0.0.9".into(),
                mac: Some("11:22:33:44:55:66".into()),
                queries: 10,
                queries_today: 0,
                blocked: 1,
                blocked_24h: 0,
                last_seen: 0,
                online: true,
                vendor: Some("Acme Corp".into()),
                hourly_queries: vec![],
            }],
        };

        let out = render_device_view(&view);
        // Both sections render with their counts.
        assert!(out.contains("mapped devices (1):"), "out={out}");
        assert!(
            out.contains("unmapped (observed) devices (1):"),
            "out={out}"
        );
        // G5 enrichment: mapped row carries MAC + OUI vendor (flat list had neither).
        assert!(out.contains("AA:BB:CC:DD:EE:FF"), "out={out}");
        assert!(out.contains("Raspberry Pi"), "out={out}"); // vendor truncated to 18 cols
                                                            // blocked_pct = 50/200 = 25.0%.
        assert!(out.contains("25.0%"), "out={out}");
        // Unmapped row carries its own ARP MAC + vendor.
        assert!(out.contains("11:22:33:44:55:66"), "out={out}");
        assert!(out.contains("Acme Corp"), "out={out}");
        // New columns present in the header.
        assert!(out.contains("MAC"), "out={out}");
        assert!(out.contains("VENDOR"), "out={out}");
    }

    #[test]
    fn live_list_missing_mac_vendor_render_as_dash() {
        use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto};

        let view = DeviceViewDto {
            mapped: vec![MappedDeviceDto {
                ip: "10.0.0.5".into(),
                name: "nomac".into(),
                mac: None,
                mac_aliases: vec![],
                profile: "default".into(),
                owner: None,
                device_type: None,
                department: None,
                queries: 0,
                queries_today: 0,
                blocked: 0,
                blocked_24h: 0,
                cache_hits: 0,
                last_seen: 0,
                online: false,
                vendor: None,
                groups: vec![],
                notes: None,
                network_name: None,
                network_name_wildcard: false,
                id: Some("nomac".into()),
                hourly_queries: vec![],
                unfiltered: false,
            }],
            unmapped: vec![],
        };

        let out = render_device_view(&view);
        // Missing MAC + vendor → "-"; 0 queries → 0.0% (no divide-by-zero).
        assert!(out.contains(" - "), "out={out}");
        assert!(out.contains("0.0%"), "out={out}");
        // No unmapped section when the vector is empty.
        assert!(!out.contains("unmapped"), "out={out}");
    }

    #[test]
    fn live_list_empty_view_renders_placeholder() {
        use crate::ipc::protocol::DeviceViewDto;

        let view = DeviceViewDto {
            mapped: vec![],
            unmapped: vec![],
        };
        assert_eq!(render_device_view(&view), "no active devices\n");
    }

    #[tokio::test]
    async fn add_device_writes_to_master_when_no_dot_d() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            Some("iPhone"),
            Some("10.0.0.1".parse().unwrap()),
            None,
            Some("default"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.devices.len(), 1);
        assert_eq!(loaded.config.devices[0].id.as_str(), "iphone");
    }

    #[tokio::test]
    async fn add_device_rejects_missing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "iphone",
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--ip"), "got: {err}");
        assert!(err.to_string().contains("--mac"), "got: {err}");
    }

    #[tokio::test]
    async fn add_device_rejects_duplicate_id() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let err = run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.2".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn add_device_rejects_unknown_profile_with_hint() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            Some("nonexistent"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonexistent"), "got: {msg}");
        assert!(msg.contains("Existing profiles"), "got: {msg}");
    }

    #[tokio::test]
    async fn add_device_invalid_id_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "Bad Id",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid id"), "got: {err}");
    }

    #[tokio::test]
    async fn set_device_profile_updates_field() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        // Add a second profile first
        let mut doc: Value = std::fs::read_to_string(&master).unwrap().parse().unwrap();
        let profiles = doc
            .as_table_mut()
            .unwrap()
            .get_mut("profiles")
            .unwrap()
            .as_table_mut()
            .unwrap();
        let kids: Value = toml::from_str(
            r#"display_name = "Kids"
"#,
        )
        .unwrap();
        profiles.insert("kids".into(), kids);
        std::fs::write(&master, toml::to_string(&doc).unwrap()).unwrap();

        run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            Some("default"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        run_set(&master, &sock, "iphone", "profile", "kids", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(
            loaded.config.devices[0].profile.as_ref().unwrap().as_str(),
            "kids"
        );
    }

    #[tokio::test]
    async fn set_device_ip_rejects_bad_value() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let err = run_set(&master, &sock, "iphone", "ip", "not-an-ip", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid IP"), "got: {err}");
    }

    #[tokio::test]
    async fn remove_device_drops_entry() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        run_remove(&master, &sock, "iphone", None).await.unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.devices.is_empty());
    }

    #[tokio::test]
    async fn remove_absent_device_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        // verbs-02: remove of an absent device returns Ok (exit 0), not an error.
        assert!(run_remove(&master, &sock, "ghost", None).await.is_ok());
    }

    #[tokio::test]
    async fn remove_device_with_schedule_ref_refuses() {
        // verbs-05: a device still targeted by a schedule (e.g. a quiet
        // window) is refused with a friendly message naming the schedule.
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.blocked]
display_name = "Blocked"
block_all = true

[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "10.0.0.5"

[[schedules]]
id = "quiet-tablet-1"
display_name = "Quiet tablet"
target_type = "device"
target_id = "tablet"
profile = "blocked"
days = ["all"]
hours = "00:00-00:00"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let sock = fake_socket(&dir);
        let err = run_remove(&master, &sock, "tablet", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("schedule"), "got: {err}");
        assert!(err.to_string().contains("quiet-tablet-1"), "got: {err}");
    }

    #[test]
    fn apply_device_field_accepts_both_device_spellings_and_writes_canonical() {
        // devices-04: `set device_type` and the legacy `set device` both write
        // the canonical `device_type` key and clear any legacy `device` key.
        let mut entry = Value::Table(toml::map::Map::new());
        apply_device_field(&mut entry, "device_type", "iPad").unwrap();
        assert_eq!(
            entry.get("device_type").and_then(|v| v.as_str()),
            Some("iPad")
        );
        assert!(entry.get("device").is_none());

        let mut legacy = Value::Table(toml::map::Map::new());
        legacy
            .as_table_mut()
            .unwrap()
            .insert("device".into(), Value::String("old".into()));
        apply_device_field(&mut legacy, "device", "iPhone").unwrap();
        assert_eq!(
            legacy.get("device_type").and_then(|v| v.as_str()),
            Some("iPhone")
        );
        assert!(legacy.get("device").is_none());
    }

    #[test]
    fn apply_device_field_sets_network_name() {
        let mut entry = toml::Value::Table(toml::map::Map::new());
        apply_device_field(&mut entry, "network_name", "desktop-1").unwrap();
        assert_eq!(
            entry.get("network_name").and_then(|v| v.as_str()),
            Some("desktop-1")
        );
    }

    #[test]
    fn apply_device_field_clears_network_name_on_none() {
        let mut entry = toml::Value::Table(toml::map::Map::new());
        apply_device_field(&mut entry, "network_name", "desktop-1").unwrap();
        apply_device_field(&mut entry, "network_name", "none").unwrap();
        assert!(entry.get("network_name").is_none());
    }

    #[test]
    fn apply_device_field_sets_network_name_wildcard_bool() {
        let mut entry = toml::Value::Table(toml::map::Map::new());
        apply_device_field(&mut entry, "network_name_wildcard", "true").unwrap();
        assert_eq!(
            entry.get("network_name_wildcard").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    /// `plp-s5c`: `device set <id> tags …` must refuse, not write.
    ///
    /// The regression this pins is a **silent success**, so the assertion
    /// that carries the weight is the second one: an error alone would
    /// also be produced by the `other =>` arm, which would be a different
    /// (and wrong) refusal saying the field is unknown.
    #[test]
    fn apply_device_field_refuses_tags_and_names_the_replacement() {
        let mut entry = Value::Table(toml::map::Map::new());
        let err = apply_device_field(&mut entry, "tags", "work,privacy")
            .expect_err("writing a device tag must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("profiles.<id>.lists"),
            "the refusal must name what replaced tags; got: {msg}"
        );
        assert!(
            !msg.contains("unknown field"),
            "`tags` is a real field that still loads — refusing it as unknown \
             would be false; got: {msg}"
        );
    }

    /// The refusal must leave the entry untouched.
    ///
    /// Written because the value it guards is one the product *preserves*
    /// on failure: asserting "tags is absent" after a refusal would pass
    /// against a no-op too. So the entry is seeded with a tags array
    /// first, and the assertion is that the *pre-existing* value survives
    /// unchanged — a state a silent write would destroy and a no-op
    /// cannot fake.
    #[test]
    fn refused_tag_write_does_not_touch_the_existing_array() {
        let mut tbl = toml::map::Map::new();
        tbl.insert(
            "tags".into(),
            Value::Array(vec![Value::String("legacy".into())]),
        );
        let mut entry = Value::Table(tbl);
        apply_device_field(&mut entry, "tags", "work,privacy")
            .expect_err("writing a device tag must be refused");
        assert_eq!(
            entry.as_table().unwrap().get("tags"),
            Some(&Value::Array(vec![Value::String("legacy".into())])),
            "a refused write must not have edited the array on its way out"
        );
    }

    #[test]
    fn apply_device_field_rejects_bad_bool_for_wildcard() {
        let mut entry = toml::Value::Table(toml::map::Map::new());
        assert!(apply_device_field(&mut entry, "network_name_wildcard", "sideways").is_err());
    }

    #[tokio::test]
    async fn block_device_creates_blocked_profile_once() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "tablet",
            None,
            Some("10.0.0.5".parse().unwrap()),
            None,
            Some("default"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        run_block(&master, &sock, "tablet", None).await.unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(
            loaded.config.devices[0].profile.as_ref().unwrap().as_str(),
            "blocked"
        );
        assert!(loaded.config.profiles.contains_key("blocked"));
        assert!(loaded.config.profiles["blocked"].block_all);
    }

    #[test]
    fn list_empty_reports_friendly_message() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        // Just ensure it doesn't panic and the load works.
        run_list(&master).unwrap();
    }

    /// `build_device_value` builds a WHOLE ROW and `upsert_id_keyed` replaces
    /// the matched row outright (`*item = entry`), so any field the builder
    /// omits is reset to its serde default — on save of *anything*, not of
    /// that field. That is the class that shipped once and cost a release.
    ///
    /// The defence is this destructuring, NOT a comment: prose does not fail
    /// a build. `let Device { .. }` is exhaustive on purpose — no `..` — so
    /// the day someone adds an eighteenth field to `Device`, **this stops
    /// compiling** and they have to decide whether `add` should write it.
    /// The fields `add` deliberately leaves alone are asserted at their
    /// defaults below, with the reason each one is not an `add` concern.
    #[tokio::test]
    async fn every_device_field_is_considered_by_the_row_builder() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);

        run_add(
            &master,
            &sock,
            "iphone",
            Some("iPhone"),
            Some("10.0.0.5".parse().unwrap()),
            Some("AA:BB:CC:DD:EE:01"),
            Some("default"),
            &[],
            Some("Alex"),
            Some("phone"),
            Some("home"),
            Some("a note"),
            None,
        )
        .await
        .expect("add");

        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).expect("reload");
        let d = loaded
            .config
            .devices
            .iter()
            .find(|d| d.id.as_str() == "iphone")
            .expect("device present after add");

        // Exhaustive. Adding a field to `Device` breaks THIS LINE first.
        let Device {
            id,
            display_name,
            ip,
            mac,
            mac_aliases,
            profile,
            groups,
            owner,
            device_type,
            department,
            notes,
            allow_rules,
            deny_rules,
            override_profile_deny,
            unfiltered,
            network_name,
            network_name_wildcard,
        } = d;

        // Written by `add`.
        assert_eq!(id.as_str(), "iphone");
        assert_eq!(display_name, "iPhone");
        assert_eq!(ip.map(|a| a.to_string()).as_deref(), Some("10.0.0.5"));
        assert_eq!(mac.as_deref(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(profile.as_ref().map(|p| p.as_str()), Some("default"));
        assert!(groups.is_empty(), "none were passed");
        assert_eq!(owner.as_deref(), Some("Alex"));
        assert_eq!(device_type.as_deref(), Some("phone"));
        assert_eq!(department.as_deref(), Some("home"));
        assert_eq!(notes.as_deref(), Some("a note"));

        // Deliberately NOT written by `add`, and each for its own reason:
        // extra MACs and the per-device rule overlays are delta primitives
        // owned by their own verbs, and the two network-name fields plus the
        // filtering opt-out are opt-ins a fresh device must not carry.
        assert!(mac_aliases.is_empty());
        assert!(allow_rules.is_empty());
        assert!(deny_rules.is_empty());
        assert!(!*override_profile_deny);
        assert!(!*unfiltered);
        assert_eq!(network_name.as_deref(), None);
        assert!(!*network_name_wildcard);
    }

    /// `run_quiet` is the one whole-row writer here that does not assert it
    /// created a row — a same-second re-quiet resolves to the same derived id
    /// and must replace. That is safe only while the builder is TOTAL, so the
    /// totality is what this pins. `let Schedule { .. }` is exhaustive on
    /// purpose: a ninth field on `Schedule` stops this compiling.
    #[tokio::test]
    async fn quiet_writes_every_schedule_field() {
        use crate::config::schema::Schedule;

        let dir = tempfile::tempdir().unwrap();
        let master = mk_with_expired_quiet(&dir);
        let sock = fake_socket(&dir);

        run_quiet(&master, &sock, "tablet", Some("2h"), None, None)
            .await
            .expect("quiet");

        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).expect("reload");
        let s = loaded
            .config
            .schedules
            .iter()
            .find(|s| s.target_id.as_str() == "tablet")
            .expect("quiet schedule present");

        // Exhaustive. Adding a field to `Schedule` breaks THIS LINE first.
        let Schedule {
            id,
            display_name,
            target_type,
            target_id,
            profile,
            days,
            hours,
            expires_at,
        } = s;

        assert!(id.as_str().starts_with("quiet-tablet-"), "got {id:?}");
        assert_eq!(display_name, "Quiet device tablet");
        assert_eq!(*target_type, ScheduleTargetType::Device);
        assert_eq!(target_id.as_str(), "tablet");
        assert_eq!(profile.as_str(), "blocked");
        assert_eq!(days, &vec!["all".to_string()]);
        // Midnight wrap, not `00:00-23:59`: window matching is end-exclusive.
        assert_eq!(hours, "00:00-00:00");
        assert!(expires_at.is_some_and(|e| e > time::OffsetDateTime::now_utc()));
    }

    #[test]
    fn parse_quiet_for_rejects_bad_input() {
        let err = parse_quiet_duration(Some("nonsense"), None).unwrap_err();
        assert!(err.to_string().contains("nonsense"));
    }

    /// `humantime` accepts durations that `OffsetDateTime` cannot represent.
    /// Adding one used to panic (`impl Add` is documented to), and a value
    /// past `i64::MAX` seconds used to wrap negative through an `as i64`
    /// cast and land the expiry in the past. Both must be errors: this is an
    /// operator-typed value, and every other arm of this function is careful
    /// to say so politely.
    #[test]
    fn parse_quiet_for_rejects_a_duration_past_the_representable_range() {
        for input in ["100000years", "99999999999999999999s", "580000000000years"] {
            let err = parse_quiet_duration(Some(input), None)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("too far in the future") || err.contains("couldn't parse"),
                "{input} must error, got: {err}"
            );
        }
    }

    /// The boundary the fix must NOT move: an ordinary duration still
    /// resolves to a future instant.
    #[test]
    fn parse_quiet_for_still_accepts_an_ordinary_duration() {
        let exp = parse_quiet_duration(Some("15m"), None).unwrap();
        assert!(exp > time::OffsetDateTime::now_utc());
    }

    #[test]
    fn parse_quiet_neither_arg_errors_with_example() {
        let err = parse_quiet_duration(None, None).unwrap_err();
        assert!(err.to_string().contains("Example"));
    }

    /// Master with one device and one ALREADY-EXPIRED quiet schedule —
    /// the on-disk state every `warden device quiet` leaves behind once
    /// its window lapses.
    fn mk_with_expired_quiet(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[profiles.blocked]
display_name = "Blocked"
block_all = true

[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "10.0.0.7"
profile = "default"

[[schedules]]
id = "quiet-tablet-001122"
display_name = "Quiet device tablet"
target_type = "device"
target_id = "tablet"
profile = "blocked"
days = ["all"]
hours = "00:00-23:59"
expires_at = "2026-01-01T00:00:00Z"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        master
    }

    #[tokio::test]
    async fn cli_mutation_succeeds_with_expired_schedule_on_disk() {
        // rev-2606 schema-validator-01 regression: before the fix, every
        // entity verb ended in validate_or_revert → load_config → hard
        // error about the unrelated expired schedule, so `warden device
        // add` (and everything else) was bricked until a hand-edit.
        let dir = tempfile::tempdir().unwrap();
        let master = mk_with_expired_quiet(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            Some("iPhone"),
            Some("10.0.0.2".parse().unwrap()),
            None,
            Some("default"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("device add must succeed despite an expired schedule on disk");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.devices.len(), 2);
    }

    #[tokio::test]
    async fn quiet_self_cleans_expired_schedules() {
        // The quiet lifecycle must not accumulate dead rows: re-quieting a
        // device drops the previous (expired) quiet schedule before
        // appending the new one.
        let dir = tempfile::tempdir().unwrap();
        let master = mk_with_expired_quiet(&dir);
        let sock = fake_socket(&dir);
        run_quiet(&master, &sock, "tablet", Some("2h"), None, None)
            .await
            .expect("re-quiet must succeed");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let ids: Vec<&str> = loaded
            .config
            .schedules
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert!(
            !ids.contains(&"quiet-tablet-001122"),
            "expired quiet row must be pruned, got {ids:?}"
        );
        assert_eq!(
            loaded.config.schedules.len(),
            1,
            "exactly the fresh quiet row remains, got {ids:?}"
        );
        assert!(
            loaded.config.schedules[0]
                .expires_at
                .is_some_and(|exp| exp > time::OffsetDateTime::now_utc()),
            "fresh quiet row expires in the future"
        );
        // rev-2606 devices-01: the quiet window must be the canonical
        // always-on form — `00:00-23:59` is end-exclusive and left the
        // device unfiltered for one minute nightly.
        assert_eq!(
            loaded.config.schedules[0].hours, "00:00-00:00",
            "quiet writes the gap-free all-day window"
        );
    }

    // ── Sprint 36 HR2: hot-reload wiring ───────────────────────────────

    use super::super::hr2_test_support::{
        assert_single_reload_with_resolved_token, env_home, seed_token_for_test, stub_reload_ok,
    };

    #[tokio::test]
    async fn devices_add_triggers_reload_when_daemon_up() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = dir.path().join("stub.sock");
        let (server, recorded) = stub_reload_ok(sock.clone()).await;

        let _env = env_home(dir.path()).await;
        seed_token_for_test(dir.path());
        run_add(
            &master,
            &sock,
            "iphone",
            Some("iPhone"),
            Some("10.0.0.1".parse().unwrap()),
            None,
            Some("default"),
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        server.await.unwrap();
        assert_single_reload_with_resolved_token(&recorded);
    }

    #[tokio::test]
    async fn devices_add_works_gracefully_when_daemon_down() {
        // With no stub listening and no token file, the operation must
        // succeed on disk and the reload attempt must degrade to
        // DaemonUnreachable + NoToken (both benign). The CLI exit code
        // stays 0; the mutation is visible in the TOML file. This is
        // the Sprint 36 HR2 "post-write reload never fails the command"
        // invariant.
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "iphone",
            None,
            Some("10.0.0.1".parse().unwrap()),
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.devices.len(), 1, "mutation reached disk");
    }

    #[tokio::test]
    async fn block_device_reverts_when_device_not_found() {
        // Panel refinement (review 2026-04-23, Marco): compound mutation
        // atomicity. `run_block` first auto-creates the `blocked` profile
        // (if missing), then sets the device's profile pointer. If the
        // second step fails (e.g. device id unknown), the profile insert
        // must NOT survive on disk — the compound mutation is all-or-
        // nothing. This guards against a regression where auto-create
        // leaks a `[profiles.blocked]` entry into the master when the
        // pointer update aborts.
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        let original_bytes = std::fs::read_to_string(&master).unwrap();
        assert!(!original_bytes.contains("[profiles.blocked]"));

        // Device `ghost` does not exist → `apply_set_inline` fails →
        // `validate_or_revert` restores the pre-block master bytes.
        let err = run_block(&master, &sock, "ghost", None).await.unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "error must name the missing device: {err}"
        );

        let after_bytes = std::fs::read_to_string(&master).unwrap();
        assert!(
            !after_bytes.contains("[profiles.blocked]"),
            "compound mutation leaked a half-committed `blocked` profile:\n\n{after_bytes}"
        );
    }

    // ── Sprint C T7-Grp4: device set-unfiltered verb ───────────────────

    #[test]
    fn lc2_c_t7_grp4_device_set_unfiltered_ok_const_pinned() {
        assert_eq!(
            DEVICE_SET_UNFILTERED_OK,
            "Device '{id}' unfiltered={value}."
        );
    }

    #[test]
    fn lc2_c_t7_grp4_device_set_unfiltered_noop_const_pinned() {
        assert_eq!(
            DEVICE_SET_UNFILTERED_NOOP,
            "Device '{id}' unfiltered already {value}. No change."
        );
    }

    #[test]
    fn lc2_c_t7_grp4_device_set_unfiltered_warn_const_pinned() {
        assert_eq!(
            DEVICE_SET_UNFILTERED_WARN,
            "device '{id}' not filtered. Monitoring stays active."
        );
    }

    #[test]
    fn lc2_c_t7_grp4_format_set_unfiltered_warn_substitutes_id() {
        assert_eq!(
            format_device_set_unfiltered_warn("guest-laptop"),
            "device 'guest-laptop' not filtered. Monitoring stays active."
        );
    }

    #[tokio::test]
    async fn lc2_c_t7_grp4_set_unfiltered_unknown_device_errors() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_minimal(&dir);
        let sock = fake_socket(&dir);
        let err = run_set_unfiltered(&master, &sock, "ghost", true, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ghost"), "got: {err}");
    }

    // ── cli-h10: `device show` prints the state that changes filtering ──
    //
    // `unfiltered`, `allow_rules`, `deny_rules` and `override_profile_deny`
    // all change what the resolver does to a device's queries, and none of
    // them appeared in the detail view. So after
    // `warden device set-unfiltered iot-fridge true` — a verb this repo
    // ships — no command in the product would tell you the fridge had
    // stopped being filtered.
    //
    // The first three are printed UNCONDITIONALLY. A field that appears
    // only when true teaches the operator that absence means false, which
    // is indistinguishable from "this build does not show that field" —
    // exactly the class of defect this sprint exists to kill.

    fn device_from_toml(src: &str) -> Device {
        toml::from_str(src).expect("fixture device must deserialise")
    }

    #[test]
    fn h10_device_show_prints_unfiltered_when_true() {
        let dev =
            device_from_toml("id = \"iot-fridge\"\ndisplay_name = \"Fridge\"\nunfiltered = true\n");
        let out = render_device_detail(&dev);
        assert!(
            out.contains("unfiltered:   true"),
            "an unfiltered device must say so — the resolver skips filtering \
             entirely for it. got:\n{out}"
        );
    }

    #[test]
    fn h10_device_show_prints_unfiltered_when_false() {
        // The differential: the same field must be visible in both states,
        // or absence-means-false becomes the operator's only clue.
        let dev = device_from_toml("id = \"iphone\"\ndisplay_name = \"iPhone\"\n");
        let out = render_device_detail(&dev);
        assert!(
            out.contains("unfiltered:   false"),
            "a filtered device must say `unfiltered: false` explicitly. got:\n{out}"
        );
    }

    #[test]
    fn h10_device_show_prints_rule_overlays() {
        let dev = device_from_toml(
            "id = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             allow_rules = [\"allow-work\"]\ndeny_rules = [\"deny-social\"]\n",
        );
        let out = render_device_detail(&dev);
        assert!(
            out.contains("allow_rules:  allow-work"),
            "the per-device allow overlay is checked BEFORE the profile's \
             tables — it must be visible. got:\n{out}"
        );
        assert!(
            out.contains("deny_rules:   deny-social"),
            "the per-device deny overlay must be visible. got:\n{out}"
        );
    }

    #[test]
    fn h10_device_show_prints_empty_rule_overlays_as_none() {
        let dev = device_from_toml("id = \"laptop\"\ndisplay_name = \"Laptop\"\n");
        let out = render_device_detail(&dev);
        assert!(
            out.contains("allow_rules:  (none)") && out.contains("deny_rules:   (none)"),
            "\"this device has no overlays\" is an answer the operator needs \
             when asking why a domain resolved. got:\n{out}"
        );
    }

    #[test]
    fn h10_device_show_prints_override_profile_deny_both_ways() {
        let off = device_from_toml("id = \"laptop\"\ndisplay_name = \"Laptop\"\n");
        assert!(
            render_device_detail(&off).contains("override_profile_deny: false"),
            "got:\n{}",
            render_device_detail(&off)
        );

        let on = device_from_toml(
            "id = \"laptop\"\ndisplay_name = \"Laptop\"\n\
             allow_rules = [\"allow-work\"]\noverride_profile_deny = true\n",
        );
        let out = render_device_detail(&on);
        assert!(
            out.contains("override_profile_deny: true"),
            "this flag lets a device's allow beat a profile-level deny — it \
             has no CLI writer, so `show` is the ONLY way to discover a \
             hand-edited `true`. got:\n{out}"
        );
    }
}
