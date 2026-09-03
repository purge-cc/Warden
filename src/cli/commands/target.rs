//! Target-file selection + TOML surgery for v1 entity mutations.
//!
//! The `warden device` / `group` / `subnet` / `blocklist` subcommands must
//! edit the right `*.d/*.toml` slice when the operator runs a multi-file
//! layout, and fall back to the master config when no `.d/` directory is
//! present. This module is the shared plumbing.
//!
//! # `--into <file>` semantics
//!
//! Each mutating command accepts `--into <path>`. Resolution order:
//! 1. If `--into` is set → canonicalise, ensure it lives inside the
//!    config directory, return it.
//! 2. Else, look at `<config-parent>/<class>.d/*.toml`:
//!    - One file → auto-select it.
//!    - Zero files (or directory missing) → fall through to the master.
//!    - Multiple files → ambiguity error listing the candidates.
//!
//! # Mutation shape
//!
//! Entities land in array-of-tables (`[[devices]]`, `[[groups]]`,
//! `[[subnets]]`, `[[blocklists]]`, `[[schedules]]`, `[[admin_rules]]`)
//! or named-maps (`[profiles.<id>]`). We mutate using `toml_edit` through
//! [`toml::Value`]: read file → parse as `Value` → upsert or remove the
//! row by its `id` (or the map key for profiles) → serialise back →
//! atomic-write.
//!
//! # Pre-promote validation
//!
//! Mutations route through [`write_value_validated`] (single file) or
//! [`write_values_validated`] (compound multi-file). Both run the full
//! [`crate::config::loader::load_config`] against the STAGED bytes — via a
//! [`crate::config::loader::LoaderOverlay`] that substitutes the would-be-
//! written content for each touched path — BEFORE the rename. A tree the
//! validator would reject is never promoted to disk, so the on-disk config is
//! cross-reference-valid at every instant and a CLI killed mid-write leaves
//! the previous valid tree intact. The operator sees every validator error
//! with `file:line` attribution and the live config is unchanged.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use crate::config::atomic_write::atomic_write_and_validate;
use crate::config::cidr::Cidr;
use crate::config::loader::{
    canonicalize_path, load_config, load_config_with_overlay, LoaderOverlay,
};
use crate::config::schema::device::Device;
use crate::config::schema::id::Id;
use crate::config::schema::subnet::Subnet;
use crate::config::schema::{
    ClusterConfig, ClusterRole, ConfigV1, REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER,
    REPLICATED_SECTIONS,
};

/// The entity collections the CLI can mutate. Maps to the v1 schema
/// top-level keys + the `<name>.d/` subdirectory convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityClass {
    Devices,
    Groups,
    Subnets,
    Blocklists,
    Profiles,
    Schedules,
    AdminRules,
    /// The `[[labels]]` vocabulary.
    ///
    /// Unlike every class above it, a `Label`'s identity is the pair
    /// `(kind, id)` rather than `id` alone, so the id-keyed helpers in
    /// this module ([`upsert_id_keyed`], [`find_target_for_id`]) are
    /// only safe for labels when the id happens to be unique across
    /// kinds. `cli::commands::labels` carries pair-keyed equivalents and
    /// uses this variant purely for path resolution.
    Labels,
}

impl EntityClass {
    /// Subdirectory name under the config root that holds split files
    /// for this entity class.
    pub fn dir_name(self) -> &'static str {
        match self {
            EntityClass::Devices => "devices.d",
            EntityClass::Groups => "groups.d",
            EntityClass::Subnets => "subnets.d",
            EntityClass::Blocklists => "blocklists.d",
            EntityClass::Profiles => "profiles.d",
            EntityClass::Schedules => "schedules.d",
            EntityClass::AdminRules => "rules.d",
            EntityClass::Labels => "labels.d",
        }
    }

    /// Top-level TOML key for the array-of-tables (or named-map).
    pub fn toml_key(self) -> &'static str {
        match self {
            EntityClass::Devices => "devices",
            EntityClass::Groups => "groups",
            EntityClass::Subnets => "subnets",
            EntityClass::Blocklists => "blocklists",
            EntityClass::Profiles => "profiles",
            EntityClass::Schedules => "schedules",
            EntityClass::AdminRules => "admin_rules",
            EntityClass::Labels => "labels",
        }
    }

    /// Human label for error messages.
    pub fn label(self) -> &'static str {
        match self {
            EntityClass::Devices => "device",
            EntityClass::Groups => "group",
            EntityClass::Subnets => "subnet",
            EntityClass::Blocklists => "blocklist",
            EntityClass::Profiles => "profile",
            EntityClass::Schedules => "schedule",
            EntityClass::AdminRules => "admin rule",
            EntityClass::Labels => "label",
        }
    }
}

/// Resolve the TOML file a mutation should edit.
///
/// See the module-level doc for the precedence rules. Returns the
/// absolute path of the target file (which may not exist yet — callers
/// treat missing-as-empty).
pub fn resolve_target_file(
    master: &Path,
    class: EntityClass,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let parent = master.parent().unwrap_or_else(|| Path::new("."));

    if let Some(explicit) = into {
        return resolve_explicit_into(parent, explicit);
    }

    let class_dir = parent.join(class.dir_name()); // include-dir-ok: creation default
    if !class_dir.is_dir() {
        // No subdirectory exists — fall through to the master file.
        // This is the layout where everything lives in a monolithic
        // `config.toml`.
        return Ok(master.to_path_buf());
    }

    let candidates = list_toml_files(&class_dir)?;
    match candidates.len() {
        0 => Ok(master.to_path_buf()),
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ => {
            let mut names: Vec<String> = candidates
                .iter()
                .map(|p| p.strip_prefix(parent).unwrap_or(p).display().to_string())
                .collect();
            names.sort();
            bail!(
                "ambiguous {label} target: {n} files in {dir}. Pick one with \
                 `--into <path>`: {list}",
                label = class.label(),
                n = names.len(),
                dir = class_dir.display(),
                list = names.join(", ")
            );
        }
    }
}

/// Resolve the file an **existing** entity lives in, for `set` / `remove`
/// verbs. With `--into` the operator's explicit choice wins (unchanged).
/// Otherwise locate the file that actually defines `id` via
/// [`find_target_for_id`] — the same owner resolution the IPC handlers use
/// — falling back to the default write target ([`resolve_target_file`])
/// when the id is absent, so a genuine not-found still surfaces the
/// existing error instead of mis-writing.
///
/// Previously these verbs used [`resolve_target_file`]'s directory
/// heuristic, which failed with "not found in <file>, use `--into`"
/// whenever the entity lived in a file other than the auto-selected one.
/// (Creation verbs keep [`resolve_target_file`]: the id must not exist
/// yet, so there is no owner to locate.)
pub fn resolve_existing_target_file(
    master: &Path,
    class: EntityClass,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if into.is_some() {
        return resolve_target_file(master, class, into);
    }
    match find_target_for_id(master, class, id)? {
        Some(owner) => Ok(owner),
        None => resolve_target_file(master, class, None),
    }
}

/// Apply `--into`-supplied path: accept as-is when relative-to-parent or
/// absolute-inside-parent, reject escapes outside the config tree.
fn resolve_explicit_into(parent: &Path, into: &Path) -> anyhow::Result<PathBuf> {
    let joined = if into.is_absolute() {
        into.to_path_buf()
    } else {
        parent.join(into)
    };

    // Normalise `..` by walking components; full canonicalisation would
    // require the file to exist. We just want to reject obvious escapes.
    let mut normalised = PathBuf::new();
    for comp in joined.components() {
        match comp {
            std::path::Component::ParentDir => {
                if !normalised.pop() {
                    bail!("--into path escapes config directory: {}", into.display());
                }
            }
            other => normalised.push(other.as_os_str()),
        }
    }

    // Run the containment guard against an absolute base so it applies
    // even when the supplied config path is relative (dev invocations) —
    // previously the check was skipped entirely for a relative parent,
    // which let an absolute `--into` escape the config tree. Symlinks are
    // deliberately not resolved here (canonicalisation needs the target to
    // exist); `normalised` is still returned as-is so legitimate relative
    // paths resolve to the same file.
    let abs = |p: &Path| -> anyhow::Result<PathBuf> {
        if p.is_absolute() {
            Ok(p.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .context("resolve current dir for --into containment check")?
                .join(p))
        }
    };
    if !abs(normalised.as_path())?.starts_with(abs(parent)?) {
        bail!(
            "--into path must live under {} (got {})",
            parent.display(),
            normalised.display()
        );
    }

    Ok(normalised)
}

/// Containment-check an explicit `--into` path for verbs that resolve their
/// own (non-[`EntityClass`]) target file — the profile-scoped `rewrite` /
/// `local-dns` inners. Mirrors [`resolve_target_file`]'s `--into` branch so
/// a caller forwarding operator input (e.g. the TUI) cannot write outside
/// the config tree.
pub(crate) fn resolve_explicit_into_under(master: &Path, into: &Path) -> anyhow::Result<PathBuf> {
    let parent = master.parent().unwrap_or_else(|| Path::new("."));
    resolve_explicit_into(parent, into)
}

/// Enumerate `*.toml` files in a directory (one level deep, no recursion).
/// Deterministic byte-wise sort for reproducible error messages.
fn list_toml_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("toml"))
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    Ok(out)
}

/// Convert a free-form display name (e.g. `"PC Dweller"`) into a valid
/// v1 [`Id`](crate::config::schema::Id) — lowercase ASCII, digits, and
/// `-` only, with leading / trailing dashes trimmed and runs of
/// non-id characters collapsed to a single dash.
///
/// Returns the slugged id on success, or a friendly error when the
/// input collapses to the empty string (e.g. pure emoji / whitespace).
/// Used by IPC mutation handlers that receive operator-typed names
/// from the TUI form and have to map them onto the v1 schema's strict
/// id contract (charset `[a-z0-9-]`, length 1..=64).
pub fn slug_id(name: &str) -> Result<String, String> {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = true; // suppress leading dashes
    for c in name.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            out.push(lc);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.len() > 64 {
        out.truncate(64);
        while out.ends_with('-') {
            out.pop();
        }
    }
    if out.is_empty() {
        return Err(format!(
            "the device name {name:?} collapsed to an empty id after slugging. \
             Use ASCII letters, digits, or `-` so a stable v1 id can be derived \
             (e.g. \"PC Dweller\" → \"pc-dweller\")."
        ));
    }
    Ok(out)
}

/// The complete set of files an **owner lookup** may search, master first.
///
/// The primary source is the include graph the loader actually merged
/// ([`crate::config::loader::LoadedConfig::files_loaded`]), *not* the
/// conventional `<class>.d/` directory names. The two differ the moment an
/// operator declares includes that point elsewhere: `includes =
/// ["custom/*.toml"]` is a legal v1 layout whose entities are visible to
/// every "does X exist?" probe (those read the merged view) and invisible
/// to a convention-derived directory scan. A verb that resolves its write
/// target by convention therefore passes its existence check and then
/// misses the file that owns the entity — the defect class this helper
/// closes.
///
/// The conventional `<class>.d/*.toml` for each of `convention_classes` is
/// searched **in addition**, never instead. Two layouts depend on it:
/// a config that does not currently load (a repair verb still has to find
/// its target, and the caller's own pre-promote validation —
/// [`write_value_validated`] — is the real gate on what lands), and a tree
/// whose `<class>.d/` predates the `includes` line that should declare it.
/// Dropping the convention would have turned this widening into a
/// regression for both. That union is the single sanctioned owner-lookup
/// use of the directory convention in the tree — see
/// `scripts/check_no_hardcoded_include_dirs.sh`.
///
/// The master is always first, so callers keep master-before-slice
/// precedence (`rule undo` depends on it). Convention
/// hits come next, in the caller's own path spelling and sorted for
/// determinism; include-graph files the convention did not already cover
/// are appended in the loader's canonical spelling. Duplicates are
/// suppressed on the canonical form, so a file reachable both ways is
/// visited exactly once.
pub fn owner_candidate_files(master: &Path, convention_classes: &[EntityClass]) -> Vec<PathBuf> {
    let key = |p: &Path| canonicalize_path(p).unwrap_or_else(|_| p.to_path_buf());

    let parent = master.parent().unwrap_or_else(|| Path::new("."));
    let mut convention: Vec<PathBuf> = convention_classes
        .iter()
        .flat_map(|class| {
            // Searched as a SUPERSET of the declared include graph below, so
            // a `<class>.d/` an operator never declared (or a config too
            // broken to load) still resolves. Never the only source.
            let class_dir = parent.join(class.dir_name()); // include-dir-ok: superset only
            list_toml_files(&class_dir).unwrap_or_default()
        })
        .collect();
    convention.sort();
    convention.dedup();

    let graph = match load_config(master, time::OffsetDateTime::now_utc()) {
        Ok(loaded) => loaded.files_loaded,
        Err(_) => Vec::new(),
    };

    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    seen.insert(key(master));
    let mut out = vec![master.to_path_buf()];
    for path in convention.into_iter().chain(graph) {
        if seen.insert(key(&path)) {
            out.push(path);
        }
    }
    out
}

/// Locate the TOML file that currently owns an entry of `class` keyed
/// by `id`. Searches the master first, then every other file in the
/// loaded include graph ([`owner_candidate_files`]). Returns
/// `Ok(Some(path))` for the first match, `Ok(None)` when no file contains
/// the id, and `Err` only on filesystem errors that prevent enumerating
/// the candidates.
///
/// IPC update / remove handlers use this to edit the SAME file the
/// entry lives in — without it we'd default to whatever
/// [`resolve_target_file`] picks for new entries (typically the first
/// `*.toml` in the class dir), which can silently move an existing
/// entity across files on every edit.
///
/// # Shape coverage
///
/// Each [`EntityClass`] is serialised in exactly one of two TOML shapes.
/// The lookup branches on the runtime type of `value.get(class.toml_key())`:
///
/// | Class       | Shape            | Lookup key                          |
/// |-------------|------------------|-------------------------------------|
/// | Devices     | array-of-tables  | `[[devices]]` items by `id` field    |
/// | Groups      | array-of-tables  | `[[groups]]` items by `id` field     |
/// | Subnets     | array-of-tables  | `[[subnets]]` items by `id` field    |
/// | Blocklists  | array-of-tables  | `[[blocklists]]` items by `id` field |
/// | Schedules   | array-of-tables  | `[[schedules]]` items by `id` field  |
/// | AdminRules  | array-of-tables  | `[[admin_rules]]` items by `id` field |
/// | Profiles    | named-map        | `[profiles.<id>]` sub-table keys     |
///
/// `Profiles` is the only v1 named-map today — if another class ever
/// flips shape, the writer ([`upsert_id_keyed`] vs [`upsert_profile`])
/// and the corresponding match arm here must move together.
///
/// Candidates come from [`owner_candidate_files`], i.e. the include
/// graph the loader merged — not a `[master] + <class>.d/*.toml`
/// convention, which would miss an entity living in an operator include
/// outside that directory (`includes = ["custom/*.toml"]`) and send
/// `set` / `remove` to the default creation target instead of the
/// owning file.
pub fn find_target_for_id(
    master: &Path,
    class: EntityClass,
    id: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let candidates = owner_candidate_files(master, &[class]);
    for path in &candidates {
        if !path.exists() {
            continue;
        }
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let value: Value = match raw.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        match value.get(class.toml_key()) {
            Some(Value::Array(arr)) => {
                // v0 / current array-of-tables shape: every entity class
                // except Profiles. Match on the explicit `id` field.
                for item in arr {
                    if let Some(item_id) = item.get("id").and_then(|v| v.as_str()) {
                        if item_id == id {
                            return Ok(Some(path.to_path_buf()));
                        }
                    }
                }
            }
            // v1 named-map shape: the id is the sub-table key
            // (`[profiles.<id>]`), not a field inside the row.
            Some(Value::Table(tbl)) if tbl.contains_key(id) => {
                return Ok(Some(path.to_path_buf()));
            }
            _ => {
                // Missing key, or unexpected scalar — try the next
                // candidate file. We deliberately don't error: a file
                // that doesn't mention this class at all is a normal
                // outcome when the operator splits entities across
                // multiple `*.d/` files.
            }
        }
    }
    Ok(None)
}

/// Convert a legacy v0 [`ClientConfig`](crate::config::settings::ClientConfig)
/// into the v1 device-entry [`Value`] shape consumed by
/// [`upsert_id_keyed`]. The v0 wire format keeps a flat `name` field;
/// v1 separates the stable `id` from the human `display_name`. The
/// caller is responsible for picking the id (typically via [`slug_id`]
/// applied to the v0 name).
///
/// Optional fields are emitted only when set / non-empty so the resulting
/// TOML stays minimal — the v1 schema treats absence as the documented
/// defaults rather than as `null`. `mac_aliases` is only emitted when
/// non-empty, mirroring the schema's `#[serde(default)]` behavior.
pub fn client_to_v1_value(client: &crate::config::settings::ClientConfig, id: &str) -> Value {
    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert("display_name".into(), Value::String(client.name.clone()));
    tbl.insert("ip".into(), Value::String(client.ip.to_string()));
    if let Some(mac) = &client.mac {
        if !mac.is_empty() {
            tbl.insert("mac".into(), Value::String(mac.clone()));
        }
    }
    if !client.mac_aliases.is_empty() {
        tbl.insert(
            "mac_aliases".into(),
            Value::Array(
                client
                    .mac_aliases
                    .iter()
                    .map(|m| Value::String(m.clone()))
                    .collect(),
            ),
        );
    }
    if !client.profile.is_empty() {
        tbl.insert("profile".into(), Value::String(client.profile.clone()));
    }
    // The TUI sends a single group; emit a one-element array because
    // the v1 schema's `Device.groups` is `Vec<Id>`. The CLI multi-group
    // path goes through `apply_set_inline` directly, so the single-emit
    // here doesn't constrain operators who still want multi-group.
    if let Some(g) = &client.group {
        if !g.is_empty() {
            tbl.insert(
                "groups".into(),
                Value::Array(vec![Value::String(g.clone())]),
            );
        }
    }
    if let Some(v) = &client.owner {
        if !v.is_empty() {
            tbl.insert("owner".into(), Value::String(v.clone()));
        }
    }
    if let Some(v) = &client.device_type {
        if !v.is_empty() {
            tbl.insert("device_type".into(), Value::String(v.clone()));
        }
    }
    if let Some(v) = &client.department {
        if !v.is_empty() {
            tbl.insert("department".into(), Value::String(v.clone()));
        }
    }
    if let Some(v) = &client.notes {
        if !v.is_empty() {
            tbl.insert("notes".into(), Value::String(v.clone()));
        }
    }
    Value::Table(tbl)
}

/// Read a target file as a `toml::Value`. Missing file → empty inline
/// table so the caller can upsert into it. Returns the pre-edit content
/// (or `None` if absent) so the `write_value` + `validate_or_revert`
/// two-step (module-private `revert`) can roll back.
/// # Rule 1 — never answer "does X exist?" from this function's result
///
/// This returns the raw TOML of **one file**. The config an operator
/// actually runs is the *merged* tree: master plus every include the
/// `includes` globs resolve to. Those are different objects, and the
/// default layout `warden migrate v0-to-v1` produces makes them
/// differ — entities live in `<class>.d/*.toml`, not in the master.
///
/// So a handler that asks this function whether an entity exists gets
/// the answer for one file and reports it as the answer for the config.
/// That has already shipped once: `device block` probed the master's raw
/// TOML for `[profiles.blocked]`, decided it was absent because the
/// master does not hold profiles on a split layout, and wrote a second
/// one — producing `duplicate [profiles.blocked] table` on exactly the
/// layout the product's own migrator generates.
///
/// **Existence questions go to `load_config`**, which merges. This
/// function is for reading a file you are about to write back.
///
/// ## When probing the raw value IS correct
///
/// Two shapes, and both are about the file rather than the config:
///
/// - **Idempotency within the file being written** — "is this exact row
///   already in the array I am about to append to?" (`rewrite`,
///   `local_dns`, `entity_tags`, `cluster`'s include glob). The question
///   is genuinely about this file's contents.
/// - **Repairing a config the loader refuses.** `blocklist set-kind` can
///   travel `allow → deny`, which is the fix for a tree the validator
///   rejects; a repair that begins by loading the thing it repairs
///   cannot run. That site says so in a comment, and any new one must.
///
/// ## Why this is prose and not a lint
///
/// `scripts/check_no_hardcoded_include_dirs.sh` fences the sibling rule
/// ("which file owns X?") lexically, because every violation of it names
/// a `.d` directory and a grep can find a string. Rule 1 has no such
/// marker: `contains_key` on a merged
/// config and `contains_key` on a raw one are the same three tokens. A
/// sweep of `src/cli` + `src/ipc` found no live violation and ~15 hits
/// that are all the legitimate shapes above — a detector that flags
/// those is a detector nobody keeps.
///
/// The honest defence is therefore a reviewer meeting the rule at the
/// call, which is here.
pub fn read_or_empty(path: &Path) -> anyhow::Result<(Value, Option<String>)> {
    if !path.exists() {
        return Ok((Value::Table(Default::default()), None));
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let value: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    Ok((value, Some(raw)))
}

/// Find or insert an id-keyed entry inside an array-of-tables. Returns
/// `true` if a new entry was created, `false` if an existing one was
/// replaced.
///
/// `find_value` is compared against the entry's `id` field.
pub fn upsert_id_keyed(
    doc: &mut Value,
    key: &str,
    find_value: &str,
    entry: Value,
) -> anyhow::Result<bool> {
    let table = match doc {
        Value::Table(t) => t,
        _ => bail!("config root is not a TOML table"),
    };

    let array = table
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = match array {
        Value::Array(a) => a,
        _ => bail!("`{key}` must be an array of tables"),
    };

    for item in arr.iter_mut() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id == find_value {
                *item = entry;
                return Ok(false);
            }
        }
    }

    arr.push(entry);
    Ok(true)
}

/// Remove an id-keyed entry from an array-of-tables. Returns whether an
/// entry was actually removed.
pub fn remove_id_keyed(doc: &mut Value, key: &str, find_value: &str) -> anyhow::Result<bool> {
    let table = match doc {
        Value::Table(t) => t,
        _ => bail!("config root is not a TOML table"),
    };

    let Some(array) = table.get_mut(key) else {
        return Ok(false);
    };
    let arr = match array {
        Value::Array(a) => a,
        _ => bail!("`{key}` must be an array of tables"),
    };

    let before = arr.len();
    arr.retain(|item| {
        item.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id != find_value)
            .unwrap_or(true)
    });
    Ok(arr.len() < before)
}

/// Set or replace a `[profiles.<id>]` entry in the named-map.
pub fn upsert_profile(doc: &mut Value, profile_id: &str, entry: Value) -> anyhow::Result<bool> {
    let table = match doc {
        Value::Table(t) => t,
        _ => bail!("config root is not a TOML table"),
    };
    let profiles_value = table
        .entry("profiles".to_string())
        .or_insert_with(|| Value::Table(Default::default()));
    let profiles = match profiles_value {
        Value::Table(t) => t,
        _ => bail!("`profiles` must be a table"),
    };
    let created = !profiles.contains_key(profile_id);
    profiles.insert(profile_id.to_string(), entry);
    Ok(created)
}

/// Remove a `[profiles.<id>]` entry. Returns whether anything was removed.
pub fn remove_profile(doc: &mut Value, profile_id: &str) -> anyhow::Result<bool> {
    let table = match doc {
        Value::Table(t) => t,
        _ => bail!("config root is not a TOML table"),
    };
    let Some(profiles_value) = table.get_mut("profiles") else {
        return Ok(false);
    };
    let profiles = match profiles_value {
        Value::Table(t) => t,
        _ => bail!("`profiles` must be a table"),
    };
    Ok(profiles.remove(profile_id).is_some())
}

/// Restore `path` to `original_content`, or remove it when the file did not
/// exist before our write. Used by [`write_values_validated`]'s compound
/// mid-sequence I/O-failure rollback (the cross-reference check already passed
/// for the whole batch, so a TOML round-trip on the restored bytes suffices).
fn revert(path: &Path, original_content: Option<&str>) -> anyhow::Result<()> {
    match original_content {
        // Restore previously-known-good bytes through the hardened
        // atomic-write helper. The bytes were valid before the
        // edit, so a lightweight `toml::Value` round-trip is sufficient
        // — a full v1 loader pass would re-resolve includes and could
        // spuriously fail mid-revert if a sibling slice changed.
        Some(content) => {
            atomic_write_and_validate(path, content, |staged: &Path| -> Result<(), String> {
                let raw = std::fs::read_to_string(staged).map_err(|e| e.to_string())?;
                raw.parse::<Value>().map(|_| ()).map_err(|e| e.to_string())
            })
            .map_err(|e| anyhow::anyhow!("{e}"))
        }
        None => {
            if path.exists() {
                std::fs::remove_file(path)
                    .with_context(|| format!("cannot remove {}", path.display()))?;
            }
            Ok(())
        }
    }
}

// ── pre-promote validating writers ──────────────
//
// `write_value` + `validate_or_revert` promote a slice and THEN run the full
// loader, leaving a window where a cross-reference-invalid tree is the on-disk
// truth (a CLI killed there bricks the next daemon start). The writers below
// run the full multi-file validation against the STAGED bytes, inside the
// atomic writer's pre-rename closure (via a [`LoaderOverlay`]), so a tree the
// loader would reject is never renamed into place — the on-disk state only
// ever transitions valid→valid.

/// One staged write in a (possibly compound) mutation: the destination and the
/// exact bytes to land there.
pub struct StagedWrite {
    pub final_path: PathBuf,
    pub content: String,
}

/// Serialise + validate-then-promote a single slice. Full cross-reference
/// validation against {master + every include + this staged slice} runs
/// BEFORE the rename; on failure nothing is written and the error names every
/// validator complaint. Drop-in replacement for the `write_value` +
/// `validate_or_revert` two-step at single-file mutation seats.
pub fn write_value_validated(
    master: &Path,
    final_path: &Path,
    value: &Value,
) -> anyhow::Result<()> {
    // Re-read the file we are about to replace so its comments and key
    // order can be carried across the mutation. `read_or_empty` already
    // hands the raw text back to most callers, but not through this
    // signature — and threading it here would mean touching ~40 call
    // sites to fix one serialiser. One extra read per CLI mutation is
    // not a cost anyone can measure; this is not the query path.
    let original = std::fs::read_to_string(final_path).unwrap_or_default();
    let content = super::toml_write::render_preserving(&original, value)
        .with_context(|| format!("serialise {}", final_path.display()))?;
    promote_validated(
        master,
        &[StagedWrite {
            final_path: final_path.to_path_buf(),
            content,
        }],
    )
}

/// Validate the COMBINED final state of a multi-file mutation ({master + every
/// include + ALL staged writes}) once, BEFORE promoting anything; only if that
/// full load succeeds are the files renamed into place, in the given order.
///
/// For compound seats that stage several files in one logical mutation
/// (`rule add` / `remove` / `move`, `tags rename`) so the merged validation
/// sees the complete intended state, never a half-applied one. The caller
/// orders `writes` so every inter-rename intermediate is itself a valid tree
/// (additions: container/row before reference; removals: reference before
/// row). If a later rename fails for I/O reasons, already-promoted files are
/// restored from their captured pre-edit bytes before bailing.
pub fn write_values_validated(master: &Path, writes: &[StagedWrite]) -> anyhow::Result<()> {
    promote_validated(master, writes)
}

/// Shared core for [`write_value_validated`] / [`write_values_validated`].
///
/// 1. Build a [`LoaderOverlay`] over every staged `(canonical_path → bytes)`,
///    keyed with the loader's own [`canonicalize_path`] so the keys match the
///    canonical paths the loader derives from globs — a raw-path key would
///    silently miss and let the loader read stale on-disk bytes (a false
///    pass). A `canonicalize_path` failure is a hard error, never a degraded
///    key. A path not yet on disk is staged as a `new_file` (extra include
///    member) so the merged view sees the post-rename file set.
/// 2. Run the overlay-aware load once. On failure: nothing is written.
/// 3. Promote each slice atomically (cross-ref already proven, so the staged
///    validator is a cheap TOML round-trip). On a later-rename I/O failure,
///    restore the slices already promoted in this batch.
///
/// All four steps run under the tree's exclusive write lock
/// ([`crate::config::write_lock`]), because step 3's rollback restores the
/// step-0 snapshot — so without it a concurrent writer's *committed* change to
/// a shared slice is silently reverted. That module's header carries the
/// interleaving table and explains why the lock cannot live on the config file
/// itself.
fn promote_validated(master: &Path, staged: &[StagedWrite]) -> anyhow::Result<()> {
    let lock = crate::config::write_lock::acquire(master)?;
    promote_validated_locked(&lock, master, staged)
}

/// [`promote_validated`]'s body, callable **only** with the tree's write lock
/// in hand.
///
/// # Why the guard is a parameter this function never reads
///
/// The first shape of this was `let _write_lock = acquire(master)?;` at the top
/// of one function, with a comment warning the next reader not to "simplify" it
/// to `let _ =` — which drops the guard immediately and leaves every step below
/// unprotected.
///
/// **That warning was measured, and it does not hold.** Mutating the binding to
/// `let _ =` left all 35 tests in this module green: the lock file is created
/// either way, and no fast test can separate "held" from "created, then
/// released" without contending against a real second writer. `#[must_use]`
/// does not fire on `let _ =` either. The defence was prose, and prose does not
/// fail a build.
///
/// Taking `&ConfigWriteLock` moves the requirement into the type system — this
/// function cannot be entered without a reference to a **live** guard, so there
/// is no binding left to get wrong. The parameter is deliberately unused:
/// possession is the entire contract.
fn promote_validated_locked(
    _lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    staged: &[StagedWrite],
) -> anyhow::Result<()> {
    // 0. Snapshot the pre-edit bytes of every staged path, ONCE.
    //
    // Two consumers: the cluster-secondary guard below (which needs to know
    // what this write CHANGES, not merely what the staged file contains)
    // and step 3's rollback capture. One read means both see the same
    // bytes — the tree as it stood
    // when the operator's command started — instead of two reads straddling a
    // full config load.
    let pre_edit: Vec<Option<String>> = staged
        .iter()
        .map(|w| {
            let path = w.final_path.as_path();
            if path.exists() {
                std::fs::read_to_string(path)
                    .map(Some)
                    .with_context(|| format!("snapshot {} before write", path.display()))
            } else {
                Ok(None)
            }
        })
        .collect::<anyhow::Result<_>>()?;

    // 0b. A cluster secondary is read-only for policy.
    refuse_policy_write_on_a_cluster_secondary(master, staged, &pre_edit)?;

    // 1. Build the overlay.
    let mut overlay = LoaderOverlay::default();
    for w in staged {
        let path = w.final_path.as_path();
        let new_file = !path.exists();
        if new_file {
            // Mirror the hardened writer's own mkdir so a brand-new slice in a
            // not-yet-existing dir both canonicalises and (later) writes.
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create parent dir for {}", path.display()))?;
            }
        }
        let canonical = canonicalize_path(path)
            .map_err(|e| anyhow::anyhow!("cannot resolve {}: {e}", path.display()))?;
        overlay.stage(canonical, w.content.clone(), new_file);
    }

    // 2. Validate the would-be-merged tree once, before promoting anything.
    let now = time::OffsetDateTime::now_utc();
    if let Err(errs) = load_config_with_overlay(master, now, Some(&overlay)) {
        // Errors first, boilerplate last. The TUI renders this string in a
        // fixed 2-row band (~105 usable cells after its own prefixes) and
        // ellipsises the rest, so any preamble is paid for in operator
        // diagnosis — a verbose lead-in can push the actual complaint
        // (e.g. `unknown variant "block"`) past the visible cutoff.
        let mut msg = if let [only] = errs.as_slice() {
            format!("{only} — nothing written")
        } else {
            format!("{} errors, nothing written:", errs.len())
        };
        if errs.len() > 1 {
            for e in &errs {
                msg.push_str("\n  - ");
                msg.push_str(&e.to_string());
            }
        }
        bail!(msg);
    }

    // 3. Promote each slice atomically, rolling back from the step-0 snapshot.
    let mut promoted: Vec<(&Path, Option<String>)> = Vec::with_capacity(staged.len());
    for (w, pre_edit) in staged.iter().zip(&pre_edit) {
        let path = w.final_path.as_path();
        let pre_edit = pre_edit.clone();
        match write_slice_syntax_checked(path, &w.content) {
            Ok(()) => promoted.push((path, pre_edit)),
            Err(e) => {
                let mut rollback_errs = Vec::new();
                for (done_path, original) in promoted.iter().rev() {
                    if let Err(re) = revert(done_path, original.as_deref()) {
                        rollback_errs.push(format!("{}: {re}", done_path.display()));
                    }
                }
                if rollback_errs.is_empty() {
                    return Err(e.context(format!(
                        "write {} failed; earlier slices in this change were rolled back",
                        path.display()
                    )));
                }
                return Err(e.context(format!(
                    "write {} failed AND rollback of {} earlier slice(s) failed: {}",
                    path.display(),
                    rollback_errs.len(),
                    rollback_errs.join("; ")
                )));
            }
        }
    }
    Ok(())
}

// ── A cluster secondary is read-only for policy ───────────────────────
//
// This guard is not redundant with the loader-level
// `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY` check, which fires only at
// LOAD time and filters `is_cluster_drop_in` — so policy written INTO
// the sync-owned drop-in is invisible to it:
//
// | write on a secondary        | outcome                                     |
// |-----------------------------|----------------------------------------------|
// | `devices.d/tablet.toml`     | refused, by the loader's check at LOAD time |
// | `cluster.d/01-local.toml`   | allowed — the write validates and lands     |
// | `server.listen` (master)    | allowed (correct — the node's own)          |
//
// The second row is the gap this guard closes. From there the operator
// gets one of two silent outcomes, and cannot tell which:
//
//   - until the next SUCCESSFUL apply, the stray slice merges with the
//     bundle on every load — a silent union reached through a different
//     door. On a secondary whose primary is unreachable that is every
//     boot, indefinitely;
//   - at the next successful apply, `apply::mirror_wipe_cluster_d` deletes
//     it — the edit the operator watched succeed vanishes with no diagnostic.
//
// Neither is a state the write path should be able to produce.
//
// This guard runs BEFORE the load rather than after: the loader's check
// fires at load, so a guard sitting after `load_config_with_overlay`
// would be shadowed on the commonest case and never speak. It also gives
// the operator the wrong instruction on a write: they ran
// `warden device add`, and "move these sections out of the master"
// describes a file they never opened.

/// This refusal. Frozen — pinned byte-for-byte by
/// `tests/cs8_secondary_policy_guard.rs`. `{peer}` / `{sections}` are
/// substituted at construction, the same template-const idiom as
/// `CLUSTER_ALLOW_PEER_INVALID_CIDR`.
///
/// **The word order is load-bearing.** This error reaches the TUI's fixed
/// 2-row band (~105 usable cells, ellipsised past that — see the note on the
/// `bail!` in `promote_validated` and the incident it records; plain backticks
/// because this const is `pub` and that fn is private, so an intra-doc link
/// here breaks the docs built without `--document-private-items`). The
/// actionable half — that the edit belongs on the primary, and the primary's
/// URL — lands inside those cells; the section list is what can afford to
/// fall off the end, because the operator already knows what they typed.
pub const CLUSTER_SECONDARY_POLICY_READ_ONLY: &str =
    "policy is read-only on a cluster secondary — edit it on the primary ({peer}); \
     it arrives at the next sync. Nothing written. Sections: {sections}";

/// Stands in for `{peer}` when `cluster.peer` is unset. The validator requires
/// it on a secondary, so this is defence against a hand-edited master, not an
/// expected state — but a guard that panics on one is worse than one that says
/// less.
pub const CLUSTER_PEER_UNSET: &str = "`cluster.peer` unset";

/// Refuse a write that changes a POLICY section on a node that is a cluster
/// secondary right now.
///
/// Runs before the overlay is built (which `mkdir`s for brand-new slices) and
/// before the validating load, so a refusal has no filesystem side effects at
/// all.
///
/// Three deliberate choices:
///
/// - **"Is this a policy section?" is answered from the data**, not from a
///   hand-rolled list: [`REPLICATED_SECTIONS`] minus
///   [`REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER`]. Those consts partition
///   every serialised `ConfigV1` key and are held by an exhaustive
///   destructuring test, so a section added to the schema later cannot escape
///   this guard without breaking the build.
/// - **The needle is what the write CHANGES**, not what the staged file
///   contains. When no `<class>.d/` directory exists, entity mutations fall
///   back to rewriting the whole master — which on any real node carries
///   `[cluster]`, `[api]`, and often policy besides. A key-presence test would
///   fire on every such write, including the node-local ones, and would refuse
///   `cluster leave` on a policy-carrying master: the exact verb an operator
///   reaches for to rescue a stuck node.
/// - **`schema_version` and `server` are carved out**, matching the
///   loader's `REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER` carve-out and
///   for the same reasons — every master carries `schema_version`, and the
///   master keeps node-local `server.listen` while the bundle supplies
///   `server`'s policy fields.
///   *Known residual:* the carve-out is section-granular, so a future verb
///   writing `server.<policy-field>` would pass this guard. Cover is partial
///   — the loader's sub-key `DuplicateId` fires only when the bundle sets the
///   same field. No verb writes `[server]` through this path today (the
///   only `get_mut("server")` in the CLI is `migrate.rs`), so the hole is
///   known and currently unreachable rather than unnoticed.
fn refuse_policy_write_on_a_cluster_secondary(
    master: &Path,
    staged: &[StagedWrite],
    pre_edit: &[Option<String>],
) -> anyhow::Result<()> {
    let Some(cluster) = cluster_section_in_effect(master, staged) else {
        return Ok(());
    };
    // Mirrors `validator::policy_arrives_from_a_primary`. `enabled` is the
    // load-bearing conjunct: `role` defaults to `primary` but an operator may
    // have set `role = "secondary"` on a node where clustering is off, and
    // such a node is a standalone warden that owns its policy.
    if !(cluster.enabled && cluster.role == ClusterRole::Secondary) {
        return Ok(());
    }

    let mut sections = BTreeSet::new();
    for (w, before) in staged.iter().zip(pre_edit) {
        sections.extend(
            changed_top_level_keys(before.as_deref(), &w.content)
                .into_iter()
                .filter(|k| is_replicated_policy_section(k)),
        );
    }
    if sections.is_empty() {
        return Ok(());
    }

    let peer = cluster
        .peer
        .as_deref()
        .filter(|p| !p.is_empty())
        .unwrap_or(CLUSTER_PEER_UNSET);
    bail!(CLUSTER_SECONDARY_POLICY_READ_ONLY
        .replace("{peer}", peer)
        .replace(
            "{sections}",
            &sections.into_iter().collect::<Vec<_>>().join(", ")
        ));
}

/// The `[cluster]` section this write would leave in force.
///
/// Read from the master's STAGED bytes when the master is itself one of the
/// staged writes (the `.d`-less fallback layout restages it wholesale), and
/// from disk otherwise. `None` when the master is unreadable, unparseable, or
/// declares no `[cluster]` — in the first two cases the load in
/// [`promote_validated`] reports the real syntax error a paragraph later, and
/// a refusal here would name the wrong cause.
///
/// *Known residual:* a `[cluster]` declared in an INCLUDE rather than the
/// master is invisible here. Every real path puts it in the master —
/// `cluster join` / `leave` write `config_path` — and the tree still fails
/// closed if one did not, because the loader's load-time check has the
/// merged config and refuses a policy-carrying secondary regardless.
/// Resolving it properly
/// would mean re-implementing the loader's include walk, and two
/// implementations of one rule drift.
fn cluster_section_in_effect(master: &Path, staged: &[StagedWrite]) -> Option<ClusterConfig> {
    let staged_master = staged
        .iter()
        .find(|w| same_file(&w.final_path, master))
        .map(|w| w.content.clone());
    let raw = match staged_master {
        Some(content) => content,
        None => std::fs::read_to_string(master).ok()?,
    };
    let table = raw.parse::<Value>().ok()?;
    let section = table.get("cluster")?;
    section.clone().try_into::<ClusterConfig>().ok()
}

/// Do these two paths denote the same file? Canonical comparison when both
/// resolve, raw comparison otherwise — a path that cannot be canonicalised is
/// not yet on disk, and a brand-new slice is never the master.
fn same_file(a: &Path, b: &Path) -> bool {
    match (canonicalize_path(a), canonicalize_path(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Top-level TOML keys whose value differs between the pre-edit bytes and the
/// staged ones — i.e. what this write actually changes.
///
/// Fails CLOSED on either side being unparseable: every key the staged
/// content names is reported as changed. A garbage pre-edit file is not
/// otherwise caught here — the overlay substitutes the staged bytes for that
/// path, so the loader never reads the old ones and this is their only reader.
fn changed_top_level_keys(before: Option<&str>, after: &str) -> BTreeSet<String> {
    let Some(after) = after.parse::<Value>().ok().and_then(|v| match v {
        Value::Table(t) => Some(t),
        _ => None,
    }) else {
        // Unparseable staged content: the write fails at the syntax check
        // anyway, but do not let "cannot tell" read as "nothing changed".
        return REPLICATED_SECTIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    };
    let before = before
        .and_then(|raw| raw.parse::<Value>().ok())
        .and_then(|v| match v {
            Value::Table(t) => Some(t),
            _ => None,
        });
    let Some(before) = before else {
        // New file, or a pre-edit file we cannot read as TOML: every section
        // it declares is new to the tree.
        return after.keys().cloned().collect();
    };
    before
        .keys()
        .chain(after.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect()
}

/// A section the primary replicates AND a secondary's master may not hold.
fn is_replicated_policy_section(key: &str) -> bool {
    REPLICATED_SECTIONS.contains(&key)
        && !REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER.contains(&key)
}

/// Promote one slice through the hardened atomic writer with a syntax-only
/// staged validator. The cross-reference check already passed for the whole
/// batch in [`promote_validated`], so this only guards against a serialise bug
/// producing non-round-trippable TOML. RAWFS-compliant (hardened atomic write).
fn write_slice_syntax_checked(path: &Path, content: &str) -> anyhow::Result<()> {
    atomic_write_and_validate(path, content, |staged: &Path| -> Result<(), String> {
        let raw = std::fs::read_to_string(staged).map_err(|e| e.to_string())?;
        raw.parse::<Value>().map(|_| ()).map_err(|e| e.to_string())
    })
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Longest-prefix length of a parsed CIDR, for subnet match tie-breaking.
fn cidr_prefix(c: &Cidr) -> u8 {
    match c {
        Cidr::V4 { prefix, .. } => *prefix,
        Cidr::V6 { prefix, .. } => *prefix,
    }
}

/// The profile a device resolves to by the **static** precedence
/// direct → group → subnet → global-default.
///
/// Mirrors [`crate::profiles::resolver::ProfileResolver`]'s levels minus
/// the time-varying schedule override — a static "affects N devices"
/// count (and the `device allow/deny` override pre-check) must not depend
/// on the wall clock. Subnet selection is longest-prefix, ties broken by
/// `priority` DESC, matching the resolver. Shared by `warden
/// rewrite` / `local-dns` / `rule` so the three former copies (which all
/// skipped the subnet level) can't drift again.
pub fn effective_profile_for_device(cfg: &ConfigV1, device: &Device) -> Option<Id> {
    // Level 1 — direct device profile.
    if let Some(p) = device.profile.clone() {
        return Some(p);
    }
    // Level 3 — highest-priority group containing the device.
    let mut groups: Vec<&_> = cfg
        .groups
        .iter()
        .filter(|g| g.devices.iter().any(|did| did == &device.id))
        .collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.priority));
    if let Some(g) = groups.first() {
        return Some(g.profile.clone());
    }
    // Level 4 — longest-prefix subnet match against the device's IP
    // (ties broken by subnet priority), the level the old copies skipped.
    if let Some(ip) = device.ip {
        let mut best: Option<((u8, i32), &Subnet)> = None;
        for s in &cfg.subnets {
            for c in &s.cidrs {
                let Ok(cidr) = Cidr::parse(c) else { continue };
                if cidr.contains(ip) {
                    let key = (cidr_prefix(&cidr), s.priority);
                    if best.is_none_or(|(bk, _)| key > bk) {
                        best = Some((key, s));
                    }
                }
            }
        }
        if let Some((_, s)) = best {
            return Some(s.profile.clone());
        }
    }
    // Level 5 — global default.
    cfg.server.default_profile.clone()
}

/// Count devices whose effective profile ([`effective_profile_for_device`])
/// is `profile_id`. Returns 0 if the config cannot be loaded (advisory
/// number — never blocks the mutation it annotates).
pub fn count_devices_on_profile(config_path: &Path, profile_id: &str) -> usize {
    let now = time::OffsetDateTime::now_utc();
    let Ok(loaded) = load_config(config_path, now) else {
        return 0;
    };
    let cfg = loaded.config;
    cfg.devices
        .iter()
        .filter(|d| effective_profile_for_device(&cfg, d).is_some_and(|p| p.as_str() == profile_id))
        .count()
}

#[cfg(test)]
mod tests;
