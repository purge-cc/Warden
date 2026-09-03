//! Admin-rule write helpers + scope-aware mutation seat.
//!
//! Every rule add / remove / undo / prune lands through one of the
//! helpers in this module. The CLI clap subcommands
//! (`warden {profile,device,group,subnet,default} {allow,deny}`,
//! `warden rule undo`, `warden device rules prune`) and the TUI scope
//! modal both call the same underlying functions — one mutation surface,
//! no new IPC verbs.
//!
//! The seats are sync — synchronous file IO inside an outer async CLI
//! handler — so the TUI can call them from a batch loop without
//! `.await`-per-row.
//!
//! # `add_inner` write order (atomicity)
//!
//! Every add touches **two** TOML slices: the master holding
//! `[[admin_rules]]`, and the entity file holding the reference
//! (`Profile.admin_rules` / `Device.allow_rules` / `Device.deny_rules`).
//! Both slices are staged in memory and handed to
//! [`super::target::write_values_validated`], which validates the merged
//! `{master + includes + both staged slices}` BEFORE promoting either.
//! Nothing cross-reference-invalid is ever renamed into place, so the
//! orphan-rule window (a master row with no entity reference) never
//! reaches disk. The slices promote master-row-first so every
//! inter-rename intermediate is itself valid (an unreferenced
//! `admin_rules` row is fine; a reference must never outlive its row).
//!
//! # `RULE_REFUSED_OVERRIDE` write-time gate
//!
//! For Device + Allow scope, [`add_inner`] inverts truth-table Row 6 from
//! [`crate::profiles::resolver::apply_overlay`]: if the device's
//! effective profile has an explicit deny on the same domain AND the
//! device's `override_profile_deny` flag is `false`, the write is
//! refused with the frozen [`RULE_REFUSED_OVERRIDE`] string. The daemon
//! enforces the same row defensively at runtime; the gate is a UX guard
//! catching the conflict before any TOML mutation lands.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ahash::RandomState;
use anyhow::{bail, Context};
use compact_str::CompactString;
use rand_core::{OsRng, RngCore};
#[cfg(test)]
use time::OffsetDateTime;
use toml::Value;

use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
#[cfg(test)]
use crate::config::loader::load_config;
use crate::config::schema::admin_rule::{format_rule_invalid_domain, validate_domain};
use crate::config::schema::id::Id;
#[cfg(test)]
use crate::config::schema::ConfigV1;
use crate::filter::engine::domain_matches_set;
use crate::filter::rules::{parse_rules, RuleAction as ParsedRuleAction};
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client::send_command;

#[cfg(test)]
use super::audit::audit_log_path_for;
use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::ipc_reload;
use super::local_dns::profile_scoped::{
    ensure_profile_exists, find_profile_entry_mut, find_profile_target_file, load_for_resolution,
};
use super::target::{
    self, count_devices_on_profile, effective_profile_for_device, read_or_empty,
    resolve_target_file, write_value_validated, write_values_validated, EntityClass, StagedWrite,
};

// ── public types ──────────────────────────────────────────────────────

/// Scope chosen by the operator. `Group` and `Subnet` resolve to a
/// profile target via `Group.profile` / `Subnet.profile`; `Default`
/// resolves via `[server].default_profile`. The scope is preserved in
/// the audit log so `warden audit tail` shows what the operator typed,
/// even when the underlying TOML mutation lands on a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope<'a> {
    Profile(&'a str),
    Device(&'a str),
    Group(&'a str),
    /// Operator-supplied subnet id OR CIDR string. Resolution walks
    /// `[[subnets]]` accepting either form.
    Subnet(&'a str),
    Default,
}

impl<'a> Scope<'a> {
    /// Short tag for audit logs and for routing the `RULE_APPLIED_*`
    /// frozen strings.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Scope::Profile(_) => "profile",
            Scope::Device(_) => "device",
            Scope::Group(_) => "group",
            Scope::Subnet(_) => "subnet",
            Scope::Default => "default",
        }
    }

    /// The operator-typed identifier, or "default" for [`Scope::Default`].
    pub fn target_id(&self) -> &str {
        match self {
            Scope::Profile(s) | Scope::Device(s) | Scope::Group(s) | Scope::Subnet(s) => s,
            Scope::Default => "default",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    pub fn slug(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        }
    }

    /// Synthesise the AdGuard rule string for a canonical domain.
    /// `@@||example.com^` for allow, `||example.com^` for deny.
    pub fn rule_string(self, canonical_domain: &str) -> String {
        match self {
            Action::Allow => format!("@@||{canonical_domain}^"),
            Action::Deny => format!("||{canonical_domain}^"),
        }
    }

    /// Past-tense verb used in [`RULE_APPLIED_DEVICE`] / `_PROFILE` /
    /// `_DEFAULT`. Frozen wording — other surfaces match on it exactly.
    pub fn past_tense(self) -> &'static str {
        match self {
            Action::Allow => "Allowed",
            Action::Deny => "Blocked",
        }
    }
}

/// What `add_inner` shipped on a successful Apply.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Several fields are only consumed by the audit
                    // log substitution + tests; clippy's dead-code
                    // analysis flags the ones the production CLI
                    // doesn't print directly. Keep them so the audit
                    // entry stays informative even when message
                    // formatting changes.
pub(crate) struct AddInnerReport {
    pub rule_id: String,
    pub rule_string: String,
    pub canonical_domain: String,
    pub master_file: PathBuf,
    pub entity_file: PathBuf,
    /// Profile id that effectively received the reference. `Some` for
    /// Profile / Group / Subnet / Default scopes; `None` for Device.
    pub effective_profile: Option<String>,
    /// `true` when the operator's existing `override_profile_deny=true`
    /// allowed an otherwise-conflicting Device-Allow to land. Audit
    /// surface only — the resolver still enforces row 7 at query time.
    pub override_used: bool,
    /// `true` when the master and entity_file are the same path (so the
    /// add stages a single slice rather than a master+entity pair).
    pub single_file_layout: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum ChangeOutcome {
    Applied(AddInnerReport),
    NoOp(NoOpReason),
}

#[derive(Debug, Clone)]
pub(crate) enum NoOpReason {
    AlreadyPresent { rule_id: String },
}

// ── frozen strings ──────────────────────────────────────────────

/// Emitted by [`add_inner`] when truth-table Row 6 would fire
/// (device.allow ∩ profile.deny ∧ ¬override).
pub const RULE_REFUSED_OVERRIDE: &str =
    "Cannot allow '{domain}' for device '{device}': profile '{profile}' explicitly denies it. To override, add `override_profile_deny = true` to the device entry and retry.";

pub fn format_rule_refused_override(domain: &str, device: &str, profile: &str) -> String {
    RULE_REFUSED_OVERRIDE
        .replace("{domain}", domain)
        .replace("{device}", device)
        .replace("{profile}", profile)
}

/// Operator-facing success message for device scope. `{verb}` is
/// `Allowed` or `Blocked` depending on the action.
pub const RULE_APPLIED_DEVICE: &str =
    "{verb} {domain} on {device}. Other devices unaffected. To undo: warden rule undo";

pub fn format_rule_applied_device(action: Action, domain: &str, device: &str) -> String {
    RULE_APPLIED_DEVICE
        .replace("{verb}", action.past_tense())
        .replace("{domain}", domain)
        .replace("{device}", device)
}

/// Operator-facing success message for profile-scope writes (also
/// covers Group and Subnet through their resolved profile).
pub const RULE_APPLIED_PROFILE: &str =
    "{verb} {domain} on profile '{profile}'. Affects {n} devices currently. To undo: warden rule undo";

pub fn format_rule_applied_profile(
    action: Action,
    domain: &str,
    profile: &str,
    n: usize,
) -> String {
    RULE_APPLIED_PROFILE
        .replace("{verb}", action.past_tense())
        .replace("{domain}", domain)
        .replace("{profile}", profile)
        .replace("{n}", &n.to_string())
}

/// Operator-facing success message for default scope.
pub const RULE_APPLIED_DEFAULT: &str =
    "{verb} {domain} for unknown devices. Existing devices on a profile are unaffected. To undo: warden rule undo";

pub fn format_rule_applied_default(action: Action, domain: &str) -> String {
    RULE_APPLIED_DEFAULT
        .replace("{verb}", action.past_tense())
        .replace("{domain}", domain)
}

/// TUI scope-modal typed-confirm prompt for profile / group /
/// subnet scopes. Operators type the scope id to confirm.
pub const RULES_BATCH_TYPE_CONFIRM: &str = "Type the scope id to confirm: ";

/// TUI scope-modal typed-confirm prompt for default scope, plus the CLI
/// prompt fired by `warden default {allow,deny}` when `--yes` is not
/// passed. The 5-second cooldown progress bar lives in the TUI only —
/// the CLI is gated by the blocking `read_line`.
pub const RULES_BATCH_DEFAULT_CONFIRM: &str =
    "This affects every unknown device on your network. Type DEFAULT to confirm: ";

/// Alias so `main.rs` can reach the const without naming the TUI-themed
/// suffix. Same byte content as [`RULES_BATCH_DEFAULT_CONFIRM`].
pub const RULES_BATCH_DEFAULT_CONFIRM_CLI: &str = RULES_BATCH_DEFAULT_CONFIRM;

/// Emitted by [`undo_inner`] on success.
pub const RULE_UNDO_OK: &str = "Removed last rule '{id}' ({rule_string}).";

pub fn format_rule_undo_ok(id: &str, rule_string: &str) -> String {
    RULE_UNDO_OK
        .replace("{id}", id)
        .replace("{rule_string}", rule_string)
}

/// Emitted by [`undo_inner`] when the admin_rules list is empty.
pub const RULE_UNDO_EMPTY: &str = "No rule to undo: admin_rules list is empty.";

/// Profile named by a `--profile` / group / subnet scope is absent from
/// the merged config.
pub const RULES_PROFILE_NOT_FOUND: &str =
    "profile \"{id}\" not found. Run `warden profile list` to see configured profiles.";

/// Rendered for the shared profile-resolution seat, which takes the text
/// as data so every verb keeps its own wording over one lookup. The known
/// ids stay unused here: this verb points the operator at `profile list`
/// rather than inlining the list.
pub fn format_rules_profile_not_found(id: &str, _known: &[&str]) -> String {
    RULES_PROFILE_NOT_FOUND.replace("{id}", id)
}

// ── add_inner core ────────────────────────────────────────────────────

/// Apply a single rule add against the resolved scope. **Sync** — the
/// caller (CLI handler async fn or TUI batch loop) is responsible for
/// the post-write `ipc_reload::attempt_reload` (one shared reload).
/// This is the single seat for rule add — clap subcommands and the TUI
/// scope modal call it.
///
/// Returns [`ChangeOutcome::NoOp`] when the entity already references
/// a rule equivalent to the one being added (idempotent — no write, no
/// audit, no reload).
pub(crate) fn add_inner(
    config_path: &Path,
    scope: Scope<'_>,
    action: Action,
    domain_input: &str,
    explicit_id: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<ChangeOutcome> {
    // 1. Validate domain → canonical lowercase form.
    let canonical = validate_domain(domain_input)
        .map_err(|reason| anyhow::anyhow!(format_rule_invalid_domain(domain_input, &reason)))?;
    let rule_string = action.rule_string(&canonical);

    // 2. Resolve scope → entity target (profile or device) + file.
    let resolution = resolve_scope_target(config_path, &scope, into)?;

    // 3. RULE_REFUSED_OVERRIDE write-time gate (Device + Allow only).
    let mut override_used = false;
    if let (EntityTarget::Device { device_id, .. }, Action::Allow) = (&resolution.target, action) {
        let outcome = check_override_required(config_path, device_id, &canonical)?;
        match outcome {
            OverrideCheck::Ok { override_used: u } => override_used = u,
            OverrideCheck::Refused {
                profile_id,
                device_id: dev,
            } => {
                bail!(
                    "{}",
                    format_rule_refused_override(&canonical, &dev, &profile_id)
                );
            }
        }
    }

    // 4. Idempotency: walk the entity's existing references; if any
    //    parses to the same canonical rule_string, return NoOp.
    // `None`: the add-time idempotency probe asks "does this entity already
    // have ANY rule for (action, domain)?", which must not be narrowed to
    // the id the operator proposed for the new rule.
    if let Some(existing_id) =
        find_existing_reference(config_path, &resolution, action, &canonical, None)?
    {
        return Ok(ChangeOutcome::NoOp(NoOpReason::AlreadyPresent {
            rule_id: existing_id,
        }));
    }

    // 5. Generate or accept the rule id.
    let rule_id = match explicit_id {
        Some(s) => {
            Id::new(s.to_string()).map_err(|e| anyhow::anyhow!("invalid --id \"{s}\": {e}"))?;
            // Reject collisions with existing ids.
            if rule_id_exists(config_path, s)? {
                bail!(
                    "rule id \"{s}\" already exists. Pick a different `--id` or omit \
                     it to auto-generate."
                );
            }
            s.to_string()
        }
        None => generate_unique_rule_id(config_path, action)?,
    };

    // 6. Stage the new master [[admin_rules]] row + the entity reference,
    //    then validate the merged tree BEFORE promoting either.
    //    Row-before-reference order keeps every inter-rename
    //    intermediate valid: an unreferenced admin_rules row is fine; a
    //    reference pointing at a missing row would dangle.
    let master = config_path.to_path_buf();
    let (mut master_doc, _) = read_or_empty(&master)?;
    append_admin_rule(&mut master_doc, &rule_id, &rule_string)?;

    let entity_path = resolution.file_path.clone();
    let same_file = entity_path == master;

    let writes: Vec<StagedWrite> = if same_file {
        // Single-file layout: the row and the reference land in one doc.
        let appended = append_entity_reference(&mut master_doc, &resolution, action, &rule_id)?;
        if !appended {
            // Race / drift: the reference already exists. Nothing has been
            // written yet, so simply report NoOp.
            return Ok(ChangeOutcome::NoOp(NoOpReason::AlreadyPresent { rule_id }));
        }
        vec![StagedWrite {
            final_path: master.clone(),
            content: toml::to_string_pretty(&master_doc)
                .with_context(|| format!("serialise {}", master.display()))?,
        }]
    } else {
        let (mut entity_doc, _) = read_or_empty(&entity_path)?;
        let appended = append_entity_reference(&mut entity_doc, &resolution, action, &rule_id)?;
        if !appended {
            return Ok(ChangeOutcome::NoOp(NoOpReason::AlreadyPresent { rule_id }));
        }
        // Master (row) first, entity slice (reference) second.
        vec![
            StagedWrite {
                final_path: master.clone(),
                content: toml::to_string_pretty(&master_doc)
                    .with_context(|| format!("serialise {}", master.display()))?,
            },
            StagedWrite {
                final_path: entity_path.clone(),
                content: toml::to_string_pretty(&entity_doc)
                    .with_context(|| format!("serialise {}", entity_path.display()))?,
            },
        ]
    };
    write_values_validated(&master, &writes)?;

    let report = AddInnerReport {
        rule_id,
        rule_string,
        canonical_domain: canonical,
        master_file: master,
        entity_file: entity_path,
        effective_profile: resolution.effective_profile.clone(),
        override_used,
        single_file_layout: same_file,
    };

    Ok(ChangeOutcome::Applied(report))
}

// ── remove_inner ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)] // See AddInnerReport above — audit surface.
pub(crate) struct RemoveReport {
    pub rule_id: String,
    pub rule_string: String,
    pub canonical_domain: String,
    pub master_file: PathBuf,
    pub entity_file: PathBuf,
    /// `true` when the cascade pass also dropped the `[[admin_rules]]`
    /// row (no other entity referenced the id after the entity unlink).
    pub admin_rule_dropped: bool,
    pub effective_profile: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum RemoveOutcome {
    Removed(RemoveReport),
    NotFound,
}

/// Drop a rule's reference from the resolved scope's entity, resolving
/// the rule by `(scope, action, domain)`.
///
/// Signature-stable wrapper over [`remove_inner_matching`] for the callers
/// that have no rule id to offer (the REST allow-list handler, the tests
/// that predate `--id`). Removing by id is the same engine with the filter
/// supplied — there is deliberately no second removal path.
pub(crate) fn remove_inner(
    config_path: &Path,
    scope: Scope<'_>,
    action: Action,
    domain_input: &str,
    into: Option<&Path>,
) -> anyhow::Result<RemoveOutcome> {
    remove_inner_matching(config_path, scope, action, domain_input, into, None)
}

/// Drop a rule's reference from the resolved scope's entity. When no
/// other entity still references the rule id after the unlink, also
/// drops the `[[admin_rules]]` row from the master.
///
/// `id_filter`: `Some(id)` restricts the match to that rule id, so
/// `--remove --id <id>` removes the rule the operator named rather than
/// the first one sharing its `(action, domain)`. A named id that this
/// entity does not reference — or that references a different domain — is
/// [`RemoveOutcome::NotFound`], never a fallback to some other rule.
///
/// Scope is preserved either way: this unlinks ONE entity and drops the
/// `[[admin_rules]]` row only when nothing else still points at it. That
/// is a different contract from [`remove_admin_rule_by_id`], which unlinks
/// every entity and drops the row unconditionally — correct for the TUI's
/// "delete this rule everywhere" affordance, wrong for a scoped verb.
pub(crate) fn remove_inner_matching(
    config_path: &Path,
    scope: Scope<'_>,
    action: Action,
    domain_input: &str,
    into: Option<&Path>,
    id_filter: Option<&str>,
) -> anyhow::Result<RemoveOutcome> {
    let canonical = validate_domain(domain_input)
        .map_err(|reason| anyhow::anyhow!(format_rule_invalid_domain(domain_input, &reason)))?;
    let rule_string = action.rule_string(&canonical);
    let resolution = resolve_scope_target(config_path, &scope, into)?;

    // Find the rule id this entity uses for (action, canonical_domain),
    // narrowed to `id_filter` when the operator named one.
    let Some(rule_id) =
        find_existing_reference(config_path, &resolution, action, &canonical, id_filter)?
    else {
        return Ok(RemoveOutcome::NotFound);
    };

    let master = config_path.to_path_buf();
    let entity_path = resolution.file_path.clone();
    let same_file = entity_path == master;

    // Determine if we should also drop the [[admin_rules]] row by counting
    // references across the whole loaded config.
    let other_refs = count_refs_excluding(config_path, &rule_id, &resolution)?;
    let drop_admin_rule = other_refs == 0;

    // Stage the reference removal (and the row drop when this was the last
    // reference), then validate the merged tree before promoting anything.
    if same_file {
        // Single-file layout: reference + row drop in one doc, one slice.
        let (mut doc, _) = read_or_empty(&master)?;
        let removed_ref = remove_entity_reference(&mut doc, &resolution, action, &rule_id)?;
        if !removed_ref {
            return Ok(RemoveOutcome::NotFound);
        }
        if drop_admin_rule {
            drop_admin_rule_row(&mut doc, &rule_id)?;
        }
        write_value_validated(&master, &master, &doc)?;
    } else {
        // Multi-file layout: reference-before-row order keeps every
        // inter-rename intermediate valid (the row may briefly stay with no
        // reference — valid; a reference must never outlive its row).
        let (mut entity_doc, _) = read_or_empty(&entity_path)?;
        let removed_ref = remove_entity_reference(&mut entity_doc, &resolution, action, &rule_id)?;
        if !removed_ref {
            return Ok(RemoveOutcome::NotFound);
        }
        let mut writes = vec![StagedWrite {
            final_path: entity_path.clone(),
            content: toml::to_string_pretty(&entity_doc)
                .with_context(|| format!("serialise {}", entity_path.display()))?,
        }];
        if drop_admin_rule {
            let (mut master_doc, _) = read_or_empty(&master)?;
            drop_admin_rule_row(&mut master_doc, &rule_id)?;
            writes.push(StagedWrite {
                final_path: master.clone(),
                content: toml::to_string_pretty(&master_doc)
                    .with_context(|| format!("serialise {}", master.display()))?,
            });
        }
        write_values_validated(&master, &writes)?;
    }

    Ok(RemoveOutcome::Removed(RemoveReport {
        rule_id,
        rule_string,
        canonical_domain: canonical,
        master_file: master,
        entity_file: entity_path,
        admin_rule_dropped: drop_admin_rule,
        effective_profile: resolution.effective_profile.clone(),
    }))
}

/// Count references to `rule_id` across every profile / device / group
/// in the loaded config, **excluding** the entity that the current
/// remove targets (so the caller can ask "would the rule still be
/// referenced after I unlink THIS entity?").
fn count_refs_excluding(
    config_path: &Path,
    rule_id: &str,
    resolution: &Resolution,
) -> anyhow::Result<usize> {
    let cfg = load_for_resolution(config_path)?;
    let mut count = 0usize;

    let exclude_profile_id: Option<&str> = match &resolution.target {
        EntityTarget::Profile { profile_id } => Some(profile_id.as_str()),
        EntityTarget::Device { .. } => None,
    };
    let exclude_device_id: Option<&str> = match &resolution.target {
        EntityTarget::Device { device_id } => Some(device_id.as_str()),
        EntityTarget::Profile { .. } => None,
    };

    for (pid, profile) in &cfg.profiles {
        if Some(pid.as_str()) == exclude_profile_id {
            continue;
        }
        count += profile
            .admin_rules
            .iter()
            .filter(|i| i.as_str() == rule_id)
            .count();
    }
    for device in &cfg.devices {
        if Some(device.id.as_str()) == exclude_device_id {
            continue;
        }
        count += device
            .allow_rules
            .iter()
            .filter(|i| i.as_str() == rule_id)
            .count();
        count += device
            .deny_rules
            .iter()
            .filter(|i| i.as_str() == rule_id)
            .count();
    }
    Ok(count)
}

fn remove_entity_reference(
    doc: &mut Value,
    resolution: &Resolution,
    action: Action,
    rule_id: &str,
) -> anyhow::Result<bool> {
    match &resolution.target {
        EntityTarget::Profile { profile_id } => {
            let entry = match find_profile_entry_mut(doc, profile_id)? {
                Some(e) => e,
                None => return Ok(false),
            };
            drop_id_from_array(entry, "admin_rules", rule_id)
        }
        EntityTarget::Device { device_id } => {
            let field = match action {
                Action::Allow => "allow_rules",
                Action::Deny => "deny_rules",
            };
            let entry = match find_device_entry_mut(doc, device_id)? {
                Some(e) => e,
                None => return Ok(false),
            };
            drop_id_from_array(entry, field, rule_id)
        }
    }
}

fn drop_id_from_array(entry: &mut Value, field: &str, rule_id: &str) -> anyhow::Result<bool> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("entry is not a TOML table"))?;
    let Some(arr_value) = tbl.get_mut(field) else {
        return Ok(false);
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{field}` must be an array of strings"))?;
    let before = arr.len();
    arr.retain(|v| v.as_str().map(|s| s != rule_id).unwrap_or(true));
    Ok(arr.len() < before)
}

fn drop_admin_rule_row(doc: &mut Value, rule_id: &str) -> anyhow::Result<bool> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(arr_value) = table.get_mut("admin_rules") else {
        return Ok(false);
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`admin_rules` must be an array of tables"))?;
    let before = arr.len();
    arr.retain(|item| {
        item.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id != rule_id)
            .unwrap_or(true)
    });
    Ok(arr.len() < before)
}

// ── scope resolution ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Resolution {
    target: EntityTarget,
    file_path: PathBuf,
    effective_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntityTarget {
    Profile { profile_id: String },
    Device { device_id: String },
}

fn resolve_scope_target(
    config_path: &Path,
    scope: &Scope<'_>,
    into: Option<&Path>,
) -> anyhow::Result<Resolution> {
    match scope {
        Scope::Profile(id) => {
            ensure_profile_exists(config_path, id, format_rules_profile_not_found)?;
            let file_path = locate_profile_file(config_path, id, into)?;
            Ok(Resolution {
                target: EntityTarget::Profile {
                    profile_id: (*id).to_string(),
                },
                file_path,
                effective_profile: Some((*id).to_string()),
            })
        }
        Scope::Device(id) => {
            ensure_device_exists(config_path, id)?;
            let file_path = locate_device_file(config_path, id, into)?;
            Ok(Resolution {
                target: EntityTarget::Device {
                    device_id: (*id).to_string(),
                },
                file_path,
                effective_profile: None,
            })
        }
        Scope::Group(id) => {
            let profile_id = resolve_group_profile(config_path, id)?;
            let file_path = locate_profile_file(config_path, &profile_id, into)?;
            Ok(Resolution {
                target: EntityTarget::Profile {
                    profile_id: profile_id.clone(),
                },
                file_path,
                effective_profile: Some(profile_id),
            })
        }
        Scope::Subnet(id_or_cidr) => {
            let profile_id = resolve_subnet_profile(config_path, id_or_cidr)?;
            let file_path = locate_profile_file(config_path, &profile_id, into)?;
            Ok(Resolution {
                target: EntityTarget::Profile {
                    profile_id: profile_id.clone(),
                },
                file_path,
                effective_profile: Some(profile_id),
            })
        }
        Scope::Default => {
            let profile_id = resolve_default_profile(config_path)?;
            let file_path = locate_profile_file(config_path, &profile_id, into)?;
            Ok(Resolution {
                target: EntityTarget::Profile {
                    profile_id: profile_id.clone(),
                },
                file_path,
                effective_profile: Some(profile_id),
            })
        }
    }
}

fn ensure_device_exists(config_path: &Path, device_id: &str) -> anyhow::Result<()> {
    let cfg = load_for_resolution(config_path)?;
    if !cfg.devices.iter().any(|d| d.id.as_str() == device_id) {
        bail!(
            "device \"{device_id}\" not found. Run `warden device list` to see configured devices."
        );
    }
    Ok(())
}

fn resolve_group_profile(config_path: &Path, group_id: &str) -> anyhow::Result<String> {
    let cfg = load_for_resolution(config_path)?;
    let group = cfg
        .groups
        .iter()
        .find(|g| g.id.as_str() == group_id)
        .with_context(|| {
            format!(
                "group \"{group_id}\" not found. Run `warden group list` to see configured groups."
            )
        })?;
    Ok(group.profile.as_str().to_string())
}

fn resolve_subnet_profile(config_path: &Path, id_or_cidr: &str) -> anyhow::Result<String> {
    let cfg = load_for_resolution(config_path)?;
    // Try id match first.
    if let Some(s) = cfg.subnets.iter().find(|s| s.id.as_str() == id_or_cidr) {
        return Ok(s.profile.as_str().to_string());
    }
    // Then CIDR match across every subnet's `cidrs` array. If multiple
    // subnets share the same CIDR string, error so the operator picks
    // one by id.
    let cidr_matches: Vec<&_> = cfg
        .subnets
        .iter()
        .filter(|s| s.cidrs.iter().any(|c| c == id_or_cidr))
        .collect();
    match cidr_matches.len() {
        0 => bail!(
            "subnet \"{id_or_cidr}\" not found (tried id and CIDR match). Run `warden subnet list` to see configured subnets."
        ),
        1 => Ok(cidr_matches[0].profile.as_str().to_string()),
        n => {
            let names: Vec<&str> = cidr_matches.iter().map(|s| s.id.as_str()).collect();
            bail!(
                "CIDR \"{id_or_cidr}\" matches {n} subnets ({}). Use the subnet id instead.",
                names.join(", ")
            )
        }
    }
}

fn resolve_default_profile(config_path: &Path) -> anyhow::Result<String> {
    let cfg = load_for_resolution(config_path)?;
    cfg.server
        .default_profile
        .as_ref()
        .map(|id| id.as_str().to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "[server].default_profile is not set. Configure it in {} before \
                 using `warden default {{allow,deny}}`.",
                config_path.display()
            )
        })
}

// ── file walkers ──────────────────────────────────────────────────────

/// Resolve the file that owns `[profiles.<profile_id>]`, or the file the
/// operator named with `--into`.
///
/// The owner walk is the shared profile-resolution seat, which also owns
/// the not-found wording every profile-scoped verb emits. A private walk
/// here would visit the same candidates and answer identically, so the
/// only thing it can do differently is word the failure differently.
fn locate_profile_file(
    config_path: &Path,
    profile_id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = into {
        return resolve_target_file(config_path, EntityClass::Profiles, Some(p));
    }
    find_profile_target_file(config_path, profile_id)
}

/// Locate the file owning the `[[devices]]` row for `device_id`.
///
/// Deliberately not the profile walker's twin: devices have no shared
/// resolution seat, so this walk and its wording live here. Harmonising
/// the two texts without a seat to hold the shared one just recreates
/// the copy that drifted.
fn locate_device_file(
    config_path: &Path,
    device_id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = into {
        return resolve_target_file(config_path, EntityClass::Devices, Some(p));
    }
    let candidates = candidate_files(config_path, EntityClass::Devices);

    for path in &candidates {
        if let Some(value) = read_toml(path) {
            let hit = value
                .get("devices")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|item| {
                        item.get("id")
                            .and_then(|v| v.as_str())
                            .map(|s| s == device_id)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if hit {
                return Ok(path.clone());
            }
            // Also check the legacy `[[clients]]` key — the loader still
            // accepts it as an alias, so the on-disk slice may still
            // carry it until the operator runs `warden migrate`.
            let legacy = value
                .get("clients")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|item| {
                        item.get("id")
                            .and_then(|v| v.as_str())
                            .map(|s| s == device_id)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if legacy {
                return Ok(path.clone());
            }
        }
    }

    bail!(
        "device \"{device_id}\" not found in any of the {} config file(s) \
         reachable from {}. Pass `--into <file>` to target a specific include.",
        candidates.len(),
        config_path.display()
    )
}

/// Every file that could own an entity of `class`, master first.
///
/// Delegates to [`target::owner_candidate_files`], which reads the
/// loader's own include graph rather than assuming a `<class>.d/*.toml`
/// naming convention: an operator whose `includes` names another
/// directory has a profile/device that the merged view sees, and a scan
/// hardcoded to the convention would report "not found … pass `--into`"
/// for an entity that plainly exists.
fn candidate_files(config_path: &Path, class: EntityClass) -> Vec<PathBuf> {
    target::owner_candidate_files(config_path, &[class])
}

fn read_toml(path: &Path) -> Option<Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.parse::<Value>().ok())
}

// ── existence + idempotency probes ────────────────────────────────────

fn rule_id_exists(config_path: &Path, rule_id: &str) -> anyhow::Result<bool> {
    let cfg = load_for_resolution(config_path)?;
    Ok(cfg.admin_rules.iter().any(|r| r.id.as_str() == rule_id))
}

/// Find the rule id this entity uses for `(action, canonical_domain)`.
///
/// `id_filter`: when `Some(id)`, only that id is considered — the caller
/// named a specific rule and must not be given a different one. Several
/// rules may carry the same `(action, domain)`: `add_inner` is idempotent
/// so the CLI cannot create that state, but a hand-authored master or two
/// `profiles.d` slices merged by the include graph can and do. Without the
/// filter this returns whichever id comes first in the entity's list, so
/// `--remove --id r2` removed `r1` and reported `r1` while `r2` survived.
fn find_existing_reference(
    config_path: &Path,
    resolution: &Resolution,
    action: Action,
    canonical_domain: &str,
    id_filter: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let cfg = load_for_resolution(config_path)?;
    let id_to_rule: HashMap<&str, &str> = cfg
        .admin_rules
        .iter()
        .map(|r| (r.id.as_str(), r.rule.as_str()))
        .collect();

    let referenced_ids: Vec<&str> = match &resolution.target {
        EntityTarget::Profile { profile_id } => cfg
            .profiles
            .get(profile_id)
            .map(|p| p.admin_rules.iter().map(|i| i.as_str()).collect())
            .unwrap_or_default(),
        EntityTarget::Device { device_id } => {
            let dev = cfg.devices.iter().find(|d| d.id.as_str() == device_id);
            match (dev, action) {
                (Some(d), Action::Allow) => d.allow_rules.iter().map(|i| i.as_str()).collect(),
                (Some(d), Action::Deny) => d.deny_rules.iter().map(|i| i.as_str()).collect(),
                (None, _) => vec![],
            }
        }
    };

    for rid in referenced_ids {
        if id_filter.is_some_and(|want| want != rid) {
            continue;
        }
        let Some(rule_str) = id_to_rule.get(rid) else {
            continue;
        };
        for parsed in parse_rules(rule_str) {
            let want_action = match action {
                Action::Allow => ParsedRuleAction::Allow,
                Action::Deny => ParsedRuleAction::Block,
            };
            if parsed.action != want_action || !parsed.is_simple_exact() {
                continue;
            }
            if let Some(d) = parsed.exact_domain() {
                if d.as_str() == canonical_domain {
                    return Ok(Some(rid.to_string()));
                }
            }
        }
    }
    Ok(None)
}

// ── id generation ─────────────────────────────────────────────────────

/// Generate `auto-{action}-{8hex}` via [`OsRng`] (CSPRNG, per CLAUDE.md
/// rule 9 — never `rand` for security-sensitive ids). Tries up to 4
/// times to dodge a collision with an existing id.
fn generate_unique_rule_id(config_path: &Path, action: Action) -> anyhow::Result<String> {
    for _ in 0..4 {
        let id = generate_rule_id_random(action);
        if !rule_id_exists(config_path, &id)? {
            return Ok(id);
        }
    }
    bail!(
        "could not generate a unique auto-id after 4 tries (32-bit collision space exhausted? \
         supply `--id <name>` to override)"
    )
}

fn generate_rule_id_random(action: Action) -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    format!("auto-{}-{}", action.slug(), hex::encode(bytes))
}

// ── document mutators ────────────────────────────────────────────────

fn append_admin_rule(doc: &mut Value, id: &str, rule_string: &str) -> anyhow::Result<()> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let arr_value = table
        .entry("admin_rules".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`admin_rules` must be an array of tables"))?;
    let mut entry = toml::map::Map::new();
    entry.insert("id".into(), Value::String(id.to_string()));
    entry.insert("rule".into(), Value::String(rule_string.to_string()));
    arr.push(Value::Table(entry));
    Ok(())
}

fn append_entity_reference(
    doc: &mut Value,
    resolution: &Resolution,
    action: Action,
    rule_id: &str,
) -> anyhow::Result<bool> {
    match &resolution.target {
        EntityTarget::Profile { profile_id } => {
            let entry = find_profile_entry_mut(doc, profile_id)?
                .ok_or_else(|| anyhow::anyhow!("profile \"{profile_id}\" not in document"))?;
            push_id_into_array(entry, "admin_rules", rule_id)
        }
        EntityTarget::Device { device_id } => {
            let field = match action {
                Action::Allow => "allow_rules",
                Action::Deny => "deny_rules",
            };
            let entry = find_device_entry_mut(doc, device_id)?
                .ok_or_else(|| anyhow::anyhow!("device \"{device_id}\" not in document"))?;
            push_id_into_array(entry, field, rule_id)
        }
    }
}

fn find_device_entry_mut<'a>(
    doc: &'a mut Value,
    device_id: &str,
) -> anyhow::Result<Option<&'a mut Value>> {
    // Resolve the array key first via an immutable look — the legacy
    // `[[clients]]` alias may still appear in older slices. Borrow the
    // chosen array mutably exactly once so the
    // borrow checker can reason about the lifetime extending into the
    // returned reference.
    let key: &'static str = {
        let table = doc
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
        if table.contains_key("devices") {
            "devices"
        } else if table.contains_key("clients") {
            "clients"
        } else {
            return Ok(None);
        }
    };

    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let arr_value = match table.get_mut(key) {
        Some(v) => v,
        None => return Ok(None),
    };
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{key}` must be an array of tables"))?;
    for item in arr.iter_mut() {
        let id_match = item
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s == device_id)
            .unwrap_or(false);
        if id_match {
            return Ok(Some(item));
        }
    }
    Ok(None)
}

fn push_id_into_array(entry: &mut Value, field: &str, rule_id: &str) -> anyhow::Result<bool> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("entry is not a TOML table"))?;
    let arr_value = tbl
        .entry(field.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{field}` must be an array of strings"))?;
    let already = arr
        .iter()
        .any(|v| v.as_str().map(|s| s == rule_id).unwrap_or(false));
    if already {
        return Ok(false);
    }
    arr.push(Value::String(rule_id.to_string()));
    Ok(true)
}

// ── TUI Rules-tab edit/delete helpers ─────────────────────────

/// Toggle the leading `@@` allow-prefix on an AdGuard rule string,
/// preserving wildcards, regex, and `$important` modifiers. Used by
/// the TUI Rules-tab edit modal when the operator flips an admin
/// rule's action: `Action::rule_string(&domain)` would lossy-rebuild
/// from a canonical domain only and lose modifiers / non-Exact
/// patterns; this function preserves the original syntax verbatim
/// minus the action prefix.
pub(crate) fn flip_at_at_prefix(rule_string: &str) -> String {
    if let Some(stripped) = rule_string.strip_prefix("@@") {
        stripped.to_string()
    } else {
        format!("@@{rule_string}")
    }
}

/// Outcome of [`move_admin_rule`].
#[derive(Debug)]
#[allow(dead_code)] // `reload_outcome` is currently inspected only via
                    // the Debug derive (e.g. for error logs); the TUI
                    // submit handler reads `master_rewritten` and
                    // discards the rest. Keep the field so future
                    // surfaces (CLI shim, audit log) have it ready.
pub(crate) enum MoveOutcome {
    /// `(old_scope, old_action) == (new_scope, new_action)` — no
    /// writes touched disk. Modal closes silently.
    NoOp,
    /// At least one of action/scope changed. `master_rewritten` is
    /// `true` when the `[[admin_rules]]` rule string was rewritten
    /// (action flipped). `reload_outcome` carries whether the daemon
    /// picked up the change.
    Applied {
        master_rewritten: bool,
        reload_outcome: ipc_reload::ReloadOutcome,
    },
}

/// Move an admin rule between scopes and/or flip its action. Used by
/// the TUI Rules-tab edit modal.
///
/// Diffs `(old_scope, old_action)` → `(new_scope, new_action)` and
/// applies the minimal write set:
///
/// - **action changed**: rewrite `[[admin_rules]].rule` via
///   [`flip_at_at_prefix`] (preserves Wildcard/Regex/`$important`).
/// - **scope changed** (different storage location — including same
///   device with allow→deny field swap): remove ref from old entity,
///   add ref to new entity.
/// - **neither changed**: returns [`MoveOutcome::NoOp`] without
///   touching disk.
///
/// The flip and the reference move are staged together and validated as
/// one merged tree before any rename, so a half-applied move (flipped
/// string with the reference still in the old field) can never be the
/// on-disk truth. A move never removes the `[[admin_rules]]` row, so no
/// intermediate can dangle.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn move_admin_rule(
    config_path: &Path,
    socket_path: &Path,
    rule_id: &str,
    old_scope: Scope<'_>,
    old_action: Action,
    new_scope: Scope<'_>,
    new_action: Action,
) -> anyhow::Result<MoveOutcome> {
    let action_changed = old_action != new_action;
    let old_resolution = resolve_scope_target(config_path, &old_scope, None)?;
    let new_resolution = resolve_scope_target(config_path, &new_scope, None)?;

    // Scope is "the same storage location" iff the resolved entity
    // matches AND the field within that entity matches. For Device
    // scopes the field depends on action (allow_rules vs deny_rules),
    // so an action flip on the same device IS a field move.
    let storage_changed = old_resolution.target != new_resolution.target
        || (matches!(&new_resolution.target, EntityTarget::Device { .. }) && action_changed);

    if !action_changed && !storage_changed {
        return Ok(MoveOutcome::NoOp);
    }

    // Stage every mutation this move makes — the master rule-string flip
    // (if the action changed) plus the reference move (remove from the old
    // entity, add to the new) — into per-file in-memory docs, then validate
    // the merged tree once and promote it before any rename is observable.
    // Folding the flip into the same batch means a half-applied flip can
    // never be the on-disk truth. A move never removes the [[admin_rules]]
    // row, so no intermediate can dangle; the promotion order is just the
    // deterministic discovery order (master flip, then old, then new),
    // coalescing same-file mutations into one slice. The schema does not
    // constrain reference polarity, so a transient allow/deny field
    // mismatch stays valid.
    use std::collections::BTreeMap;
    let master = config_path.to_path_buf();
    let mut docs: BTreeMap<PathBuf, Value> = BTreeMap::new();
    let mut order: Vec<PathBuf> = Vec::new();
    let mut master_rewritten = false;

    if action_changed {
        let doc = stage_doc(&mut docs, &mut order, &master)?;
        flip_master_rule_in_doc(doc, rule_id)?;
        master_rewritten = true;
    }
    if storage_changed {
        let old_doc = stage_doc(&mut docs, &mut order, &old_resolution.file_path)?;
        remove_entity_reference(old_doc, &old_resolution, old_action, rule_id)?;
        let new_doc = stage_doc(&mut docs, &mut order, &new_resolution.file_path)?;
        append_entity_reference(new_doc, &new_resolution, new_action, rule_id)?;
    }

    let writes: Vec<StagedWrite> = order
        .iter()
        .map(|p| {
            Ok(StagedWrite {
                final_path: p.clone(),
                content: toml::to_string_pretty(docs.get(p).expect("staged doc present"))
                    .with_context(|| format!("serialise {}", p.display()))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    write_values_validated(&master, &writes)?;

    let reload_outcome = ipc_reload::attempt_reload(socket_path).await;
    Ok(MoveOutcome::Applied {
        master_rewritten,
        reload_outcome,
    })
}

/// Locate the `[[admin_rules]]` entry with id `rule_id` in an already-read
/// master `doc` and flip its `rule` string via [`flip_at_at_prefix`], in
/// place. The write + validation is the caller's responsibility — folded
/// into [`move_admin_rule`]'s combined pre-promote batch so the flip and the
/// reference move are validated together and promoted atomically.
fn flip_master_rule_in_doc(doc: &mut Value, rule_id: &str) -> anyhow::Result<()> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("master config root is not a TOML table"))?;
    let arr_value = table
        .get_mut("admin_rules")
        .ok_or_else(|| anyhow::anyhow!("master has no [[admin_rules]] section"))?;
    let arr = arr_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`admin_rules` must be an array of tables"))?;
    let entry = arr
        .iter_mut()
        .find(|item| {
            item.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == rule_id)
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow::anyhow!("admin rule '{rule_id}' not found in master"))?;
    let entry_tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("admin rule entry is not a TOML table"))?;
    let current_rule = entry_tbl
        .get("rule")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("admin rule '{rule_id}' has no `rule` string"))?
        .to_string();
    let flipped = flip_at_at_prefix(&current_rule);
    entry_tbl.insert("rule".into(), Value::String(flipped));
    Ok(())
}

/// Read `path` into the per-file doc map on first touch (so multiple
/// mutations to the same file coalesce into one staged slice) and return a
/// mutable handle. Backs [`move_admin_rule`]'s combined staging.
fn stage_doc<'a>(
    docs: &'a mut std::collections::BTreeMap<PathBuf, Value>,
    order: &mut Vec<PathBuf>,
    path: &Path,
) -> anyhow::Result<&'a mut Value> {
    if !docs.contains_key(path) {
        let (doc, _) = read_or_empty(path)?;
        docs.insert(path.to_path_buf(), doc);
        order.push(path.to_path_buf());
    }
    Ok(docs.get_mut(path).expect("doc just inserted"))
}

/// Outcome of [`remove_admin_rule_by_id`].
#[derive(Debug)]
#[allow(dead_code)] // The TUI consumes the variants via `let _ = outcome`
                    // and lets the modal handler shape the footer text.
                    // Variants kept named for symmetry with [`MoveOutcome`].
pub(crate) enum RemoveByIdOutcome {
    /// No `[[admin_rules]]` entry with that id existed.
    NotFound,
    /// Removed `n_refs` references across entities + dropped the
    /// master row. `reload_outcome` carries the post-write reload.
    Removed {
        n_refs: usize,
        reload_outcome: ipc_reload::ReloadOutcome,
    },
}

/// Walk every device + every profile, drop every reference to
/// `rule_id`, then drop the master `[[admin_rules]]` row. Used by the
/// TUI Rules-tab delete-confirm flow — the existing
/// [`remove_inner`] requires `(scope, action, domain)` to FIND the
/// rule_id, but the TUI already has the id from the row. This helper
/// skips the find walk and operates directly by id.
///
/// Coalesces all single-file mutations into one validate; multi-file
/// layouts use the sequential per-file pattern from [`remove_inner`].
pub(crate) async fn remove_admin_rule_by_id(
    config_path: &Path,
    socket_path: &Path,
    rule_id: &str,
) -> anyhow::Result<RemoveByIdOutcome> {
    let cfg = load_for_resolution(config_path)?;
    let cfg = &cfg;

    // Confirm the master entry exists. NotFound is an Ok variant (the
    // operator deleted via CLI between modal-open and confirm — UX
    // surface decides how to phrase this).
    let exists_in_master = cfg.admin_rules.iter().any(|r| r.id.as_str() == rule_id);
    if !exists_in_master {
        return Ok(RemoveByIdOutcome::NotFound);
    }

    // Collect every entity ref. Stored as (file_path, resolution,
    // action) so the per-file write loop knows which field to drop.
    struct PendingRefDrop {
        file_path: PathBuf,
        resolution: Resolution,
        action: Action,
    }
    let mut drops: Vec<PendingRefDrop> = Vec::new();

    for device in &cfg.devices {
        if device.allow_rules.iter().any(|id| id.as_str() == rule_id) {
            let res = resolve_scope_target(config_path, &Scope::Device(device.id.as_str()), None)?;
            drops.push(PendingRefDrop {
                file_path: res.file_path.clone(),
                resolution: res,
                action: Action::Allow,
            });
        }
        if device.deny_rules.iter().any(|id| id.as_str() == rule_id) {
            let res = resolve_scope_target(config_path, &Scope::Device(device.id.as_str()), None)?;
            drops.push(PendingRefDrop {
                file_path: res.file_path.clone(),
                resolution: res,
                action: Action::Deny,
            });
        }
    }
    for (profile_id, profile) in &cfg.profiles {
        if profile.admin_rules.iter().any(|id| id.as_str() == rule_id) {
            let res =
                resolve_scope_target(config_path, &Scope::Profile(profile_id.as_str()), None)?;
            drops.push(PendingRefDrop {
                file_path: res.file_path.clone(),
                resolution: res,
                // Action is irrelevant for Profile (admin_rules is
                // single-field), but the helper signature wants it.
                action: Action::Allow,
            });
        }
    }
    let n_refs = drops.len();

    // Group drops by file so multi-ref-in-same-file is one write.
    use std::collections::BTreeMap;
    let mut by_file: BTreeMap<PathBuf, Vec<&PendingRefDrop>> = BTreeMap::new();
    for d in &drops {
        by_file.entry(d.file_path.clone()).or_default().push(d);
    }

    // Per-file: read → drop every relevant ref into the staged doc. The
    // master also loses the [[admin_rules]] row and must be promoted LAST
    // (references-before-row: no entity may still point at the row at the
    // instant it's removed). The whole batch is validated before any rename.
    let master = config_path.to_path_buf();
    let mut writes: Vec<StagedWrite> = Vec::new();
    let mut master_write: Option<StagedWrite> = None;
    for (file_path, file_drops) in &by_file {
        let (mut doc, _) = read_or_empty(file_path)?;
        for d in file_drops {
            remove_entity_reference(&mut doc, &d.resolution, d.action, rule_id)?;
        }
        if file_path == &master {
            // Master drops its own refs AND the row, in one slice, last.
            drop_admin_rule_row(&mut doc, rule_id)?;
            master_write = Some(StagedWrite {
                final_path: file_path.clone(),
                content: toml::to_string_pretty(&doc)
                    .with_context(|| format!("serialise {}", file_path.display()))?,
            });
        } else {
            writes.push(StagedWrite {
                final_path: file_path.clone(),
                content: toml::to_string_pretty(&doc)
                    .with_context(|| format!("serialise {}", file_path.display()))?,
            });
        }
    }
    // Drop the row last — either in the master slice that also dropped refs,
    // or (when no entity ref lived in the master) in its own slice.
    match master_write {
        Some(sw) => writes.push(sw),
        None => {
            let (mut doc, _) = read_or_empty(&master)?;
            drop_admin_rule_row(&mut doc, rule_id)?;
            writes.push(StagedWrite {
                final_path: master.clone(),
                content: toml::to_string_pretty(&doc)
                    .with_context(|| format!("serialise {}", master.display()))?,
            });
        }
    }
    write_values_validated(&master, &writes)?;

    let reload_outcome = ipc_reload::attempt_reload(socket_path).await;
    Ok(RemoveByIdOutcome::Removed {
        n_refs,
        reload_outcome,
    })
}

// ── override gate ────────────────────────────────────────────────────

#[derive(Debug)]
enum OverrideCheck {
    Ok {
        override_used: bool,
    },
    Refused {
        profile_id: String,
        device_id: String,
    },
}

fn check_override_required(
    config_path: &Path,
    device_id: &str,
    canonical_domain: &str,
) -> anyhow::Result<OverrideCheck> {
    let cfg = load_for_resolution(config_path)?;
    let device = cfg
        .devices
        .iter()
        .find(|d| d.id.as_str() == device_id)
        .with_context(|| format!("device \"{device_id}\" not found in loaded config"))?;

    // No effective profile → nothing to conflict with. (Default profile
    // unset, no group, no direct profile.) Allow the write.
    let Some(profile_id) = effective_profile_for_device(&cfg, device) else {
        return Ok(OverrideCheck::Ok {
            override_used: false,
        });
    };

    let Some(profile) = cfg.profiles.get(profile_id.as_str()) else {
        return Ok(OverrideCheck::Ok {
            override_used: false,
        });
    };

    // Build the profile's admin-rule deny set, mirroring
    // `DeviceOverlay::build_v1` on the deny side. Blocklists are NOT
    // included — the gate only catches conflicts with the operator's
    // explicit denies (the only ones they can reason about and revert).
    let id_to_rule: HashMap<&str, &str> = cfg
        .admin_rules
        .iter()
        .map(|r| (r.id.as_str(), r.rule.as_str()))
        .collect();
    let mut deny_set: HashSet<CompactString, RandomState> =
        HashSet::with_hasher(RandomState::new());
    for rid in &profile.admin_rules {
        let Some(rule_str) = id_to_rule.get(rid.as_str()) else {
            continue;
        };
        for parsed in parse_rules(rule_str) {
            if parsed.action == ParsedRuleAction::Block && parsed.is_simple_exact() {
                if let Some(d) = parsed.exact_domain() {
                    deny_set.insert(d.clone());
                }
            }
        }
    }

    let conflicts = domain_matches_set(canonical_domain, &deny_set);
    if !conflicts {
        return Ok(OverrideCheck::Ok {
            override_used: false,
        });
    }
    if device.override_profile_deny {
        Ok(OverrideCheck::Ok {
            override_used: true,
        })
    } else {
        Ok(OverrideCheck::Refused {
            profile_id: profile_id.as_str().to_string(),
            device_id: device_id.to_string(),
        })
    }
}

// ── public CLI handlers ────────────────────────────────

/// Shared dispatcher for every `warden {profile,device,group,subnet,
/// default} {allow,deny}` clap variant. Validates → calls
/// [`add_inner`] / [`remove_inner`] → emits the success / NoOp /
/// NotFound message → fires the shared reload via
/// [`super::ipc_reload::attempt_reload`].
///
/// Sync helpers `add_inner` / `remove_inner` keep the file IO inline;
/// only the post-write reload is async.
#[allow(clippy::too_many_arguments)]
pub async fn run_apply(
    config_path: &Path,
    socket_path: &Path,
    scope: Scope<'_>,
    action: Action,
    domain_input: &str,
    explicit_id: Option<&str>,
    remove: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let touched_domain: Option<String>;
    if remove {
        // `explicit_id` was reaching this function and being dropped: remove
        // resolved by (scope, action, domain) and took the first match, so
        // `--remove --id r2` could remove `r1`.
        let outcome = remove_inner_matching(
            config_path,
            scope.clone(),
            action,
            domain_input,
            into,
            explicit_id,
        )?;
        match outcome {
            RemoveOutcome::Removed(report) => {
                tracing::info!(
                    target: "audit",
                    action = "rule.remove",
                    scope = scope.as_tag(),
                    target_id = scope.target_id(),
                    rule_action = action.slug(),
                    domain = %report.canonical_domain,
                    rule_id = %report.rule_id,
                    cascade = report.admin_rule_dropped,
                    profile = %report.effective_profile.as_deref().unwrap_or(""),
                    "CLI mutation"
                );
                let canonical = report.canonical_domain.clone();
                let rule_id_for_audit = report.rule_id.clone();
                let target_id_for_audit = scope.target_id().to_string();
                let scope_tag = scope.as_tag();
                let action_slug = action.slug();
                persist_cli_mutation_audit(config_path, || {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                        .with_uid(current_uid())
                        .with_action("rule.remove")
                        .with_scope(scope_tag)
                        .with_target_id(target_id_for_audit)
                        .with_rule_id(rule_id_for_audit)
                        .with_rule_action(action_slug)
                        .with_domain(canonical)
                });
                if report.admin_rule_dropped {
                    println!(
                        "removed {action_slug} rule for \"{domain}\" ({id}) — admin_rules row dropped (no other references)",
                        action_slug = action.slug(),
                        domain = report.canonical_domain,
                        id = report.rule_id
                    );
                } else {
                    println!(
                        "removed {action_slug} rule for \"{domain}\" ({id}) — admin_rules row retained (still referenced elsewhere)",
                        action_slug = action.slug(),
                        domain = report.canonical_domain,
                        id = report.rule_id
                    );
                }
                touched_domain = Some(report.canonical_domain);
            }
            RemoveOutcome::NotFound => {
                // Name the id when one was given: "no allow rule for X"
                // reads as "the domain is not covered", which is wrong and
                // misleading when the domain IS covered by a different id.
                match explicit_id {
                    Some(id) => println!(
                        "no {action_slug} rule with id \"{id}\" for \"{domain}\" on {scope_tag} \"{target}\" — nothing to remove",
                        action_slug = action.slug(),
                        domain = domain_input,
                        scope_tag = scope.as_tag(),
                        target = scope.target_id()
                    ),
                    None => println!(
                        "no {action_slug} rule for \"{domain}\" on {scope_tag} \"{target}\" — nothing to remove",
                        action_slug = action.slug(),
                        domain = domain_input,
                        scope_tag = scope.as_tag(),
                        target = scope.target_id()
                    ),
                }
                return Ok(());
            }
        }
    } else {
        let outcome = add_inner(
            config_path,
            scope.clone(),
            action,
            domain_input,
            explicit_id,
            into,
        )?;
        match outcome {
            ChangeOutcome::Applied(report) => {
                tracing::info!(
                    target: "audit",
                    action = "rule.add",
                    scope = scope.as_tag(),
                    target_id = scope.target_id(),
                    rule_action = action.slug(),
                    domain = %report.canonical_domain,
                    rule_id = %report.rule_id,
                    profile = %report.effective_profile.as_deref().unwrap_or(""),
                    override_used = report.override_used,
                    "CLI mutation"
                );
                let canonical = report.canonical_domain.clone();
                let rule_id_for_audit = report.rule_id.clone();
                let target_id_for_audit = scope.target_id().to_string();
                let scope_tag = scope.as_tag();
                let action_slug = action.slug();
                let override_used = report.override_used;
                persist_cli_mutation_audit(config_path, || {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                        .with_uid(current_uid())
                        .with_action("rule.add")
                        .with_scope(scope_tag)
                        .with_target_id(target_id_for_audit)
                        .with_rule_id(rule_id_for_audit)
                        .with_rule_action(action_slug)
                        .with_domain(canonical)
                        .with_override_used(override_used)
                });
                let msg = applied_message(&scope, action, &report);
                println!("{msg}");
                touched_domain = Some(report.canonical_domain);
            }
            ChangeOutcome::NoOp(NoOpReason::AlreadyPresent { rule_id }) => {
                println!(
                    "{action_slug} rule for \"{domain}\" already on {scope_tag} \"{target}\" ({rule_id}) — no-op",
                    action_slug = action.slug(),
                    domain = domain_input,
                    scope_tag = scope.as_tag(),
                    target = scope.target_id()
                );
                return Ok(());
            }
        }
    }

    // Post-write reload via the shared helper.
    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);

    // Cache invalidation for the touched canonical domain. Best-effort —
    // never fails the command (the on-disk write already landed). Reuses
    // the existing `IpcCommand::CacheFlush` verb so rule writes do not
    // introduce a new IPC verb.
    //
    // **Known limitation:** `IpcCommand::CacheFlush { domain }` invalidates
    // the EXACT domain × (class, record-type) matrix on the daemon side;
    // it does not walk subdomains seen in the query log.
    if let Some(canonical) = touched_domain {
        invalidate_cache_for_domain(socket_path, &canonical).await;
    }
    Ok(())
}

/// Send a best-effort `IpcCommand::CacheFlush { domain }` to the daemon.
/// Never bubbles errors; the on-disk mutation has already landed and a
/// stale cache window for one rule is preferable to a CLI failure that
/// the operator might interpret as a write failure.
async fn invalidate_cache_for_domain(socket_path: &Path, canonical_domain: &str) {
    let cmd = IpcCommand::CacheFlush {
        domain: Some(canonical_domain.to_string()),
        token: None,
    };
    match send_command(socket_path, &cmd).await {
        Ok(IpcResponse::Ok { .. }) => {
            tracing::debug!(
                domain = %canonical_domain,
                "cache invalidated for rule write"
            );
        }
        Ok(other) => {
            tracing::warn!(
                response = ?other,
                domain = %canonical_domain,
                "cache invalidation: daemon returned non-Ok response (expected during reload race; will refresh on next query)"
            );
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                domain = %canonical_domain,
                "cache invalidation skipped (daemon unreachable or token unavailable; cache will refresh on TTL)"
            );
        }
    }
}

fn applied_message(scope: &Scope<'_>, action: Action, report: &AddInnerReport) -> String {
    match scope {
        Scope::Device(dev) => format_rule_applied_device(action, &report.canonical_domain, dev),
        Scope::Default => format_rule_applied_default(action, &report.canonical_domain),
        Scope::Profile(_) | Scope::Group(_) | Scope::Subnet(_) => {
            let profile_id = report
                .effective_profile
                .clone()
                .unwrap_or_else(|| scope.target_id().to_string());
            // n_devices: count devices whose effective profile matches
            // this id. Cheap — we just iterate the loaded config which
            // we already exercised through the loader; for the operator
            // message it's a "ballpark" number, not load-bearing.
            let n = count_devices_on_profile(&report.master_file, &profile_id);
            format_rule_applied_profile(action, &report.canonical_domain, &profile_id, n)
        }
    }
}

/// `warden rule undo` — pop the last `[[admin_rules]]` row + cascade
/// the reference drop across every profile / device referencing it.
pub async fn run_undo(config_path: &Path, socket_path: &Path) -> anyhow::Result<()> {
    let outcome = undo_inner(config_path)?;
    let touched_domain: Option<String> = match outcome {
        UndoOutcome::Removed(report) => {
            tracing::info!(
                target: "audit",
                action = "rule.undo",
                rule_id = %report.rule_id,
                rule_string = %report.rule_string,
                cascade_profiles = report.cascaded_profiles.len(),
                cascade_devices = report.cascaded_devices.len(),
                "CLI mutation"
            );
            let rule_id_for_audit = report.rule_id.clone();
            let rule_string_for_audit = report.rule_string.clone();
            let canonical_for_audit = extract_canonical_domain(&report.rule_string);
            persist_cli_mutation_audit(config_path, || {
                let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                    .with_uid(current_uid())
                    .with_action("rule.undo")
                    .with_rule_id(rule_id_for_audit);
                if let Some(d) = canonical_for_audit {
                    rec = rec.with_domain(d);
                }
                if rule_string_for_audit.starts_with("@@") {
                    rec = rec.with_rule_action("allow");
                } else if rule_string_for_audit.starts_with("||") {
                    rec = rec.with_rule_action("deny");
                }
                rec
            });
            println!(
                "{}",
                format_rule_undo_ok(&report.rule_id, &report.rule_string)
            );
            if !report.cascaded_profiles.is_empty() {
                println!(
                    "  cascade: dropped reference from {} profile(s): {}",
                    report.cascaded_profiles.len(),
                    report.cascaded_profiles.join(", ")
                );
            }
            if !report.cascaded_devices.is_empty() {
                println!(
                    "  cascade: dropped reference from {} device(s): {}",
                    report.cascaded_devices.len(),
                    report.cascaded_devices.join(", ")
                );
            }
            extract_canonical_domain(&report.rule_string)
        }
        UndoOutcome::Empty => {
            println!("{RULE_UNDO_EMPTY}");
            return Ok(());
        }
    };

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);

    if let Some(canonical) = touched_domain {
        invalidate_cache_for_domain(socket_path, &canonical).await;
    }
    Ok(())
}

/// Pull `example.com` out of `||example.com^` or `@@||example.com^` so
/// the undo path can wire cache invalidation. Returns `None` for any
/// rule shape that isn't a simple exact `||domain^` form (regex /
/// wildcard / etc. — those are admin-authored and out of scope for
/// the auto-generated rule pipeline).
fn extract_canonical_domain(rule_string: &str) -> Option<String> {
    let s = rule_string.strip_prefix("@@").unwrap_or(rule_string);
    let s = s.strip_prefix("||")?;
    let end = s.find('^')?;
    let domain = &s[..end];
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

/// `warden device rules prune <device>` — drop dangling rule ids from a
/// device's `allow_rules` + `deny_rules` arrays.
pub async fn run_prune(
    config_path: &Path,
    socket_path: &Path,
    device_id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let outcome = prune_inner(config_path, device_id, into)?;
    match outcome {
        PruneOutcome::Pruned(report) => {
            tracing::info!(
                target: "audit",
                action = "device.rules.prune",
                device = %device_id,
                before_n = report.before_n,
                after_n = report.after_n,
                dropped = report.dropped_ids.len(),
                "CLI mutation"
            );
            let target_id_for_audit = device_id.to_string();
            persist_cli_mutation_audit(config_path, || {
                AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                    .with_uid(current_uid())
                    .with_action("device.rules.prune")
                    .with_scope("device")
                    .with_target_id(target_id_for_audit)
            });
            println!(
                "pruned {} dangling rule id(s) from device \"{device_id}\" ({} → {} total refs)",
                report.dropped_ids.len(),
                report.before_n,
                report.after_n
            );
            for id in &report.dropped_ids {
                println!("  dropped: {id}");
            }
        }
        PruneOutcome::Clean => {
            println!("device \"{device_id}\" has no dangling rule ids — nothing to prune");
            return Ok(());
        }
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

// ── undo + prune internals (step 5 + step 6) ─────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct UndoReport {
    pub rule_id: String,
    pub rule_string: String,
    pub cascaded_profiles: Vec<String>,
    pub cascaded_devices: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum UndoOutcome {
    Removed(UndoReport),
    Empty,
}

/// The master file's OWN last top-level `[[admin_rules]]` row as
/// `(id, rule_string)`, or `None` when the master declares no such array
/// (or it is empty). [`undo_inner`] uses this so its victim matches
/// [`add_inner`]'s append target rather than the merged view's tail.
fn master_last_admin_rule(master_doc: &Value) -> Option<(String, String)> {
    let last = master_doc.get("admin_rules")?.as_array()?.last()?;
    let id = last.get("id")?.as_str()?.to_string();
    let rule = last.get("rule")?.as_str()?.to_string();
    Some((id, rule))
}

/// Pop the last `[[admin_rules]]` row from the master and drop every
/// reference to its id from every profile / device file. Multi-file
/// layouts are handled via a per-file walker, mirroring the cascade
/// used elsewhere in this module.
pub(crate) fn undo_inner(config_path: &Path) -> anyhow::Result<UndoOutcome> {
    // Pick the victim from the MASTER's own top-level
    // `[[admin_rules]]` tail. `add_inner` always appends the new row there,
    // so undo must pop from the same place add pushes. The merged view
    // (`load_for_resolution`) concatenates master rows first, then include
    // slices in glob order, so its `.last()` is a `rules.d/*.toml` row
    // whenever any slice exists — undoing an unrelated, often hand-written
    // rule instead of the one just added. Only when the master carries no
    // `[[admin_rules]]` of its own do we fall back to the merged tail (a
    // hand-authored slice-only layout — unreachable straight after a CLI
    // add, which writes the master).
    let (master_doc, _) = read_or_empty(config_path)?;
    let (rule_id, rule_string) = match master_last_admin_rule(&master_doc) {
        Some(pair) => pair,
        None => match load_for_resolution(config_path)?.admin_rules.last() {
            Some(r) => (r.id.as_str().to_string(), r.rule.clone()),
            None => return Ok(UndoOutcome::Empty),
        },
    };

    // Cascade: scan every profile / device file, drop the rule_id from
    // any allow_rules / deny_rules / admin_rules array we find.
    let mut cascaded_profiles: Vec<String> = Vec::new();
    let mut cascaded_devices: Vec<String> = Vec::new();

    // The scan must reach [[admin_rules]] rows split out into per-file
    // slices, so the orphan row is dropped and not just the cascading
    // profile/device refs — scanning only the master would leave a
    // slice's row behind, re-firing on the next `warden rule undo`.
    //
    // The candidate set is the loader's own include graph, not a
    // `<class>.d/*.toml` naming convention: a rule row (or a profile
    // referencing it) living under `includes = ["custom/*.toml"]` would
    // be invisible to a convention-based scan, so undo would remove the
    // master row and leave dangling references behind.
    let all_files = target::owner_candidate_files(
        config_path,
        &[
            EntityClass::Profiles,
            EntityClass::Devices,
            EntityClass::AdminRules,
        ],
    );

    // Stage the cascade: each touched file loses every reference to the rule
    // id (and `drop_rule_id_from_doc` also drops the [[admin_rules]] row from
    // whichever file carries it — the master in the CLI-add path, a rules.d
    // slice in a hand-authored layout). Partition so the row-bearing file
    // promotes LAST (references-before-row: no reference may outlive its
    // row). The whole batch is validated before any rename;
    // `write_values_validated` owns the rollback.
    let master = config_path.to_path_buf();
    let mut ref_writes: Vec<StagedWrite> = Vec::new();
    let mut row_writes: Vec<StagedWrite> = Vec::new();
    for path in &all_files {
        let (mut doc, _) = match read_or_empty(path) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let had_row = doc
            .get("admin_rules")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|it| it.get("id").and_then(|v| v.as_str()) == Some(rule_id.as_str()))
            })
            .unwrap_or(false);
        let drops = drop_rule_id_from_doc(
            &mut doc,
            &rule_id,
            &mut cascaded_profiles,
            &mut cascaded_devices,
        )?;
        if drops == 0 {
            continue;
        }
        let sw = StagedWrite {
            final_path: path.clone(),
            content: toml::to_string_pretty(&doc)
                .with_context(|| format!("serialise {}", path.display()))?,
        };
        if had_row {
            row_writes.push(sw);
        } else {
            ref_writes.push(sw);
        }
    }
    let mut writes = ref_writes;
    writes.extend(row_writes);
    if !writes.is_empty() {
        write_values_validated(&master, &writes)?;
    }

    cascaded_profiles.sort();
    cascaded_profiles.dedup();
    cascaded_devices.sort();
    cascaded_devices.dedup();

    Ok(UndoOutcome::Removed(UndoReport {
        rule_id,
        rule_string,
        cascaded_profiles,
        cascaded_devices,
    }))
}

fn drop_rule_id_from_doc(
    doc: &mut Value,
    rule_id: &str,
    cascaded_profiles: &mut Vec<String>,
    cascaded_devices: &mut Vec<String>,
) -> anyhow::Result<usize> {
    let mut drops = 0usize;

    {
        let table = match doc.as_table_mut() {
            Some(t) => t,
            None => return Ok(0),
        };

        // Profiles: named-map → walk each entry's admin_rules array.
        if let Some(profiles_value) = table.get_mut("profiles") {
            if let Some(profiles_table) = profiles_value.as_table_mut() {
                for (pid, entry) in profiles_table.iter_mut() {
                    if drop_id_from_array(entry, "admin_rules", rule_id)? {
                        drops += 1;
                        cascaded_profiles.push(pid.clone());
                    }
                }
            }
        }

        // Devices: array-of-tables → walk each entry's allow_rules + deny_rules.
        for key in ["devices", "clients"] {
            if let Some(arr_value) = table.get_mut(key) {
                if let Some(arr) = arr_value.as_array_mut() {
                    for item in arr.iter_mut() {
                        let dev_id = item
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let mut local = false;
                        if drop_id_from_array(item, "allow_rules", rule_id)? {
                            drops += 1;
                            local = true;
                        }
                        if drop_id_from_array(item, "deny_rules", rule_id)? {
                            drops += 1;
                            local = true;
                        }
                        if local {
                            if let Some(id) = dev_id {
                                cascaded_devices.push(id);
                            }
                        }
                    }
                }
            }
        }
    }

    // Also drop the `[[admin_rules]]` row whose id matches, in this file —
    // not just the master, since a rule's row may instead live in a
    // `rules.d/*.toml` slice. Walking it here makes the per-file pass
    // symmetric with `remove_inner`'s EntityClass::AdminRules cascade,
    // and keeps the post-loop master `drop_admin_rule_row` call
    // idempotent (`Ok(false)` when the row was already gone).
    if drop_admin_rule_row(doc, rule_id)? {
        drops += 1;
    }

    Ok(drops)
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // device_file consumed by tests only.
pub(crate) struct PruneReport {
    pub before_n: usize,
    pub after_n: usize,
    pub dropped_ids: Vec<String>,
    pub device_file: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) enum PruneOutcome {
    Pruned(PruneReport),
    Clean,
}

/// Walk a device's `allow_rules` + `deny_rules` arrays and drop ids
/// not declared in `[[admin_rules]]`. Recovery path for soft-cap
/// `LIST_PRUNE_WARN`.
pub(crate) fn prune_inner(
    config_path: &Path,
    device_id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PruneOutcome> {
    let cfg = load_for_resolution(config_path)?;
    let known_ids: HashSet<String> = cfg
        .admin_rules
        .iter()
        .map(|r| r.id.as_str().to_string())
        .collect();

    let device = cfg
        .devices
        .iter()
        .find(|d| d.id.as_str() == device_id)
        .with_context(|| format!("device \"{device_id}\" not found"))?;

    let before_n = device.allow_rules.len() + device.deny_rules.len();
    let dangling_allow: Vec<String> = device
        .allow_rules
        .iter()
        .filter(|i| !known_ids.contains(i.as_str()))
        .map(|i| i.as_str().to_string())
        .collect();
    let dangling_deny: Vec<String> = device
        .deny_rules
        .iter()
        .filter(|i| !known_ids.contains(i.as_str()))
        .map(|i| i.as_str().to_string())
        .collect();

    if dangling_allow.is_empty() && dangling_deny.is_empty() {
        return Ok(PruneOutcome::Clean);
    }

    let entity_path = locate_device_file(config_path, device_id, into)?;
    let (mut doc, _) = read_or_empty(&entity_path)?;
    let entry = find_device_entry_mut(&mut doc, device_id)?
        .ok_or_else(|| anyhow::anyhow!("device \"{device_id}\" not in document"))?;
    for id in &dangling_allow {
        let _ = drop_id_from_array(entry, "allow_rules", id)?;
    }
    for id in &dangling_deny {
        let _ = drop_id_from_array(entry, "deny_rules", id)?;
    }
    // Single-file prune: dropping dangling ids only makes the tree more
    // valid, but route through the pre-promote validator for one uniform
    // write path.
    write_value_validated(config_path, &entity_path, &doc)?;

    let after_n = before_n - dangling_allow.len() - dangling_deny.len();
    let mut dropped_ids = dangling_allow;
    dropped_ids.extend(dangling_deny);

    Ok(PruneOutcome::Pruned(PruneReport {
        before_n,
        after_n,
        dropped_ids,
        device_file: entity_path,
    }))
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
