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
//! Mutations route through [`write_value_validated_locked`] (single file) or
//! [`write_values_validated_locked`] (compound multi-file). Both run the full
//! [`crate::config::loader::load_config`] against the STAGED bytes — via a
//! [`crate::config::loader::LoaderOverlay`] that substitutes the would-be-
//! written content for each touched path — BEFORE the rename. A tree the
//! validator would reject is never promoted to disk, so the on-disk config is
//! cross-reference-valid at every instant and a CLI killed mid-write leaves
//! the previous valid tree intact. The operator sees every validator error
//! with `file:line` attribution and the live config is unchanged.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use crate::config::atomic_write::{hardened_atomic_write_at, AtomicWriteAtOpts, AtomicWriteError};
use crate::config::cidr::Cidr;
use crate::config::loader::{
    canonicalize_path, load_config, load_config_for_schema_under_guard,
    load_config_with_overlay_for_schema_under_guard, LoaderOverlay, MAX_INCLUDE_FILES,
};
use crate::config::schema::device::Device;
use crate::config::schema::id::Id;
use crate::config::schema::subnet::Subnet;
use crate::config::schema::{
    ClusterConfig, ClusterRole, ConfigV1, REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER,
    REPLICATED_SECTIONS, SCHEMA_VERSION_V1,
};
use crate::config::tree_io::{
    for_each_dir_name, CappedRead, MemberKey, PinnedTarget, TargetPlan, TreeIo,
};
use crate::config::write_lock::ConfigWriteLock;

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

/// The pinned master member in a held config tree.
///
/// `display` is the canonical in-tree spelling; `key` is the descriptor-bound
/// member identity used to recognise alternate spellings of that same file.
pub(crate) struct GuardedMaster {
    display: PathBuf,
    key: MemberKey,
}

impl GuardedMaster {
    pub(crate) fn display(&self) -> &Path {
        &self.display
    }

    /// Whether `path` resolves to this guard's master member.
    pub(crate) fn matches_path(
        &self,
        guard: &ConfigWriteLock,
        path: &Path,
    ) -> anyhow::Result<bool> {
        Ok(guard.tree_io().plan_target(path)?.key() == &self.key)
    }
}

/// Return the canonical master display path and descriptor-bound identity for
/// a held config tree.
pub(crate) fn guarded_master_locked(
    guard: &ConfigWriteLock,
    master: &Path,
) -> anyhow::Result<GuardedMaster> {
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_master_target()?;
    Ok(GuardedMaster {
        display: plan.display().to_path_buf(),
        key: plan.key().clone(),
    })
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

/// Descriptor-pinned form of [`resolve_target_file`] for guarded mutations.
pub(crate) fn resolve_target_file_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    class: EntityClass,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    guard.verify_master(master)?;
    if let Some(explicit) = into {
        return resolve_explicit_into_under_locked(guard, master, explicit);
    }

    let candidates = conventional_candidates_locked(guard, class)?;
    match candidates.len() {
        0 => Ok(guard
            .tree_io()
            .plan_master_target()?
            .display()
            .to_path_buf()),
        1 => Ok(candidates.into_iter().next().expect("one candidate")),
        _ => {
            let class_dir = class.dir_name(); // include-dir-ok: ambiguity display only
            let parent = guard
                .tree_io()
                .plan_master_target()?
                .display()
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let names: Vec<_> = candidates
                .iter()
                .map(|path| {
                    path.strip_prefix(&parent)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                })
                .collect();
            bail!(
                "ambiguous {label} target: {n} files in {dir}. Pick one with \
                 `--into <path>`: {list}",
                label = class.label(),
                n = names.len(),
                dir = parent.join(class_dir).display(),
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

/// Descriptor-pinned form of [`resolve_existing_target_file`] for guarded
/// mutations.
pub(crate) fn resolve_existing_target_file_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    class: EntityClass,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    guard.verify_master(master)?;
    if let Some(explicit) = into {
        return resolve_explicit_into_under_locked(guard, master, explicit);
    }
    match find_target_for_id_locked(guard, master, class, id)? {
        Some(owner) => Ok(owner),
        None => resolve_target_file_locked(guard, master, class, None),
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

/// Preserve the CLI's `--into` spelling checks, then bind the result to the
/// guarded tree and return its canonical in-root display path.
pub(crate) fn resolve_explicit_into_under_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    into: &Path,
) -> anyhow::Result<PathBuf> {
    guard.verify_master(master)?;
    let parent = master.parent().unwrap_or_else(|| Path::new("."));
    let spelling = resolve_explicit_into(parent, into)?;
    Ok(guard
        .tree_io()
        .plan_target(&spelling)?
        .display()
        .to_path_buf())
}

fn conventional_candidates_locked(
    guard: &ConfigWriteLock,
    class: EntityClass,
) -> anyhow::Result<Vec<PathBuf>> {
    let tree = guard.tree_io();
    let dir_name = class.dir_name(); // include-dir-ok: bounded owner superset
    let Some(dir) = tree.directory_from(&tree.master_key(), Path::new(dir_name))? else {
        return Ok(Vec::new());
    };
    let mut candidates = BTreeSet::new();
    for_each_dir_name(&dir, |name| {
        if Path::new(name).extension() != Some(std::ffi::OsStr::new("toml")) {
            return Ok(());
        }
        if !dir.file_candidate(name)? {
            return Ok(());
        }
        let entry = tree.resolve_in_directory(&dir, name)?;
        let Some(metadata) = entry.metadata()? else {
            return Ok(());
        };
        anyhow::ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "managed config member must be a regular file with one link: {}",
            entry.display().display()
        );
        if candidates.insert(entry.display().to_path_buf()) {
            anyhow::ensure!(
                candidates.len() <= MAX_INCLUDE_FILES,
                "config candidate count exceeded hard cap {MAX_INCLUDE_FILES}"
            );
        }
        Ok(())
    })?;
    Ok(candidates.into_iter().collect())
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
/// `write_value_validated_locked` — is the real gate on what lands), and a tree
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

/// Descriptor-pinned owner search for guarded mutations.
///
/// A broken include graph intentionally contributes no graph members, matching
/// [`owner_candidate_files`]' repair-path behaviour. Descriptor or path-safety
/// failures are returned instead of being treated as an empty directory.
pub(crate) fn owner_candidate_files_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    convention_classes: &[EntityClass],
) -> anyhow::Result<Vec<PathBuf>> {
    guard.verify_master(master)?;
    let tree = guard.tree_io();
    let master_display = tree.plan_master_target()?.display().to_path_buf();

    let mut convention = BTreeSet::new();
    for class in convention_classes {
        for path in conventional_candidates_locked(guard, *class)? {
            convention.insert(path);
            anyhow::ensure!(
                convention.len() < MAX_INCLUDE_FILES,
                "config candidate count exceeded hard cap {MAX_INCLUDE_FILES}"
            );
        }
    }

    let graph = match load_config_for_schema_under_guard(
        guard,
        master,
        SCHEMA_VERSION_V1,
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(loaded) => loaded.files_loaded,
        Err(_) => Vec::new(),
    };

    let mut seen = BTreeSet::new();
    seen.insert(master_display.clone());
    let mut out = vec![master_display];
    for path in convention.into_iter().chain(graph) {
        // Bind every loader-reported path again before returning it. This
        // rejects a replaced or escaped member rather than handing a raw path
        // to a later locked read.
        let plan = tree.plan_target(&path)?;
        let display = plan.display().to_path_buf();
        if seen.insert(display.clone()) {
            anyhow::ensure!(
                out.len() < MAX_INCLUDE_FILES,
                "config candidate count exceeded hard cap {MAX_INCLUDE_FILES}"
            );
            out.push(display);
        }
    }
    Ok(out)
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

/// Descriptor-pinned form of [`find_target_for_id`] for guarded mutations.
pub(crate) fn find_target_for_id_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    class: EntityClass,
    id: &str,
) -> anyhow::Result<Option<PathBuf>> {
    guard.verify_master(master)?;
    for path in owner_candidate_files_locked(guard, master, &[class])? {
        // Existing owner lookup deliberately skips unreadable or malformed
        // members so a repair can still find another candidate. The final
        // guarded overlay validation remains the mutation gate.
        let Ok((value, _)) = read_or_empty_locked(guard, master, &path) else {
            continue;
        };
        match value.get(class.toml_key()) {
            Some(Value::Array(arr))
                if arr
                    .iter()
                    .any(|item| item.get("id").and_then(|value| value.as_str()) == Some(id)) =>
            {
                return Ok(Some(path));
            }
            Some(Value::Table(table)) if table.contains_key(id) => return Ok(Some(path)),
            _ => {}
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

/// Read a member through the held tree descriptor. Missing members retain the
/// legacy empty-table result; existing members must be pinned regular files.
pub(crate) fn read_or_empty_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    path: &Path,
) -> anyhow::Result<(Value, Option<String>)> {
    let (raw, display) = read_raw_or_empty_locked(guard, master, path)?;
    let Some(raw) = raw else {
        return Ok((Value::Table(Default::default()), None));
    };
    let value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", display.display()))?;
    Ok((value, Some(raw)))
}

/// Read a member through the held tree descriptor without parsing it.
///
/// This lets callers that scan optional repair candidates account for the
/// raw bytes before deciding whether to parse another member.
pub(crate) fn read_raw_or_empty_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    path: &Path,
) -> anyhow::Result<(Option<String>, PathBuf)> {
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_target(path)?;
    let display = plan.display().to_path_buf();
    Ok((plan.read_original()?, display))
}

/// Read at most `max_bytes + 1` bytes from a descriptor-pinned member.
pub(crate) fn read_raw_capped_locked(
    guard: &ConfigWriteLock,
    master: &Path,
    path: &Path,
    max_bytes: u64,
) -> anyhow::Result<(CappedRead, PathBuf)> {
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_target(path)?;
    let display = plan.display().to_path_buf();
    Ok((plan.read_original_capped(max_bytes)?, display))
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
/// exist before our write. Used by `write_values_validated_locked`'s compound
/// mid-sequence I/O-failure rollback (the cross-reference check already passed
/// for the whole batch, so a TOML round-trip on the restored bytes suffices).
fn revert(target: &PinnedTarget<'_>, original_content: Option<&str>) -> anyhow::Result<()> {
    let target = target.rollback_target()?;
    match original_content {
        Some(content) => write_slice_syntax_checked(&target, content).map_err(Into::into),
        None => Ok(target.unlink()?),
    }
}

/// Historical migration rollback restores the captured bytes verbatim.  The
/// replaced config may intentionally be malformed or from an older schema.
fn revert_raw(target: &PinnedTarget<'_>, original_content: Option<&str>) -> anyhow::Result<()> {
    let target = target.rollback_target()?;
    match original_content {
        Some(content) => write_slice_raw(&target, content).map_err(Into::into),
        None => Ok(target.unlink()?),
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
pub(crate) struct StagedWrite {
    pub(crate) final_path: PathBuf,
    pub(crate) content: String,
}

/// A staged write bound to the exact tree entry observed under the write
/// guard. Keeping the plan and before-image together prevents a later path
/// walk from accepting a replacement that appeared after preparation.
struct PreparedWrite<'g> {
    plan: TargetPlan<'g>,
    before_image: Option<String>,
    content: String,
}

/// A single config slice whose final bytes have passed the full overlay load.
///
/// This deliberately has no general "stage arbitrary members" surface: the
/// import-local transaction needs to validate one already-reachable document,
/// publish its body, then commit that exact prepared config write.
pub(crate) struct PreparedValidatedSingleWrite<'g> {
    target: PinnedTarget<'g>,
    before_image: Option<String>,
    content: String,
}

/// How far a failed prevalidated config commit got after its companion body
/// was published. Import-local reports this state while retaining the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigCommitDisposition {
    Untouched,
    RestoredDurably,
    Uncertain,
}

/// A config commit error with the recovery state kept machine-readable.
#[derive(Debug)]
pub(crate) struct ConfigCommitFailure {
    disposition: ConfigCommitDisposition,
    write_error: AtomicWriteError,
    rollback_error: Option<anyhow::Error>,
}

impl ConfigCommitFailure {
    /// Recovery disposition for the caller's already-published companion data.
    pub(crate) fn disposition(&self) -> ConfigCommitDisposition {
        self.disposition
    }
}

impl std::fmt::Display for ConfigCommitFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.disposition {
            ConfigCommitDisposition::Untouched => write!(
                f,
                "config commit failed before rename; config is untouched: {}",
                self.write_error
            ),
            ConfigCommitDisposition::RestoredDurably => write!(
                f,
                "config commit renamed its target but durable rollback restored the prior config: {}",
                self.write_error
            ),
            ConfigCommitDisposition::Uncertain => write!(
                f,
                "config state is uncertain; recovery required: {}{}",
                self.write_error,
                self.rollback_error
                    .as_ref()
                    .map(|error| format!("; rollback failed: {error:#}"))
                    .unwrap_or_default()
            ),
        }
    }
}

impl std::error::Error for ConfigCommitFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.write_error)
    }
}

/// Render, overlay-validate, and pin one existing config member without
/// promoting it. The caller must later use [`commit_prevalidated_single_write`]
/// while retaining the same write guard.
pub(crate) fn prepare_value_validated_single_locked<'g>(
    guard: &'g crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    final_path: &Path,
    value: &Value,
) -> anyhow::Result<PreparedValidatedSingleWrite<'g>> {
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_target(final_path)?;
    let resolved = plan.display().to_path_buf();
    let before_image = plan.read_original()?;
    let original = before_image.as_deref().unwrap_or_default();
    let content = super::toml_write::render_preserving(original, value)
        .with_context(|| format!("serialise {}", resolved.display()))?;
    prepare_prevalidated_single_locked(guard, master, plan, before_image, content)
}

/// Overlay-validate and pin one existing config member's exact final bytes
/// without promoting them.  This keeps editor saves byte-for-byte while
/// giving their later commit the same typed recovery disposition as rendered
/// config writes.
pub(crate) fn prepare_raw_validated_single_locked<'g>(
    guard: &'g crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    final_path: &Path,
    content: String,
) -> anyhow::Result<PreparedValidatedSingleWrite<'g>> {
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_target(final_path)?;
    let before_image = plan.read_original()?;
    prepare_prevalidated_single_locked(guard, master, plan, before_image, content)
}

fn prepare_prevalidated_single_locked<'g>(
    guard: &'g crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    plan: TargetPlan<'g>,
    before_image: Option<String>,
    content: String,
) -> anyhow::Result<PreparedValidatedSingleWrite<'g>> {
    let prepared = PreparedWrite {
        plan,
        before_image,
        content,
    };
    validate_prepared_locked(guard, master, std::slice::from_ref(&prepared))?;
    let PreparedWrite {
        plan,
        before_image,
        content,
    } = prepared;
    Ok(PreparedValidatedSingleWrite {
        target: plan.materialize()?,
        before_image,
        content,
    })
}

/// Commit one previously overlay-validated slice. A post-rename write failure
/// is rolled back through the retained promoted inode before its disposition is
/// returned to the enclosing body+config transaction.
pub(crate) fn commit_prevalidated_single_write(
    prepared: PreparedValidatedSingleWrite<'_>,
) -> Result<(), ConfigCommitFailure> {
    commit_prevalidated_single_write_with_ops(prepared, write_slice_syntax_checked, revert)
}

/// Operation-injected form used by import-local transaction tests. The fault
/// closures are scoped to this call rather than installed process-wide.
#[cfg(test)]
pub(crate) fn commit_prevalidated_single_write_with_ops<W, R>(
    prepared: PreparedValidatedSingleWrite<'_>,
    write: W,
    rollback: R,
) -> Result<(), ConfigCommitFailure>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    commit_prevalidated_single_write_inner(prepared, write, rollback)
}

#[cfg(not(test))]
fn commit_prevalidated_single_write_with_ops<W, R>(
    prepared: PreparedValidatedSingleWrite<'_>,
    write: W,
    rollback: R,
) -> Result<(), ConfigCommitFailure>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    commit_prevalidated_single_write_inner(prepared, write, rollback)
}

fn commit_prevalidated_single_write_inner<W, R>(
    prepared: PreparedValidatedSingleWrite<'_>,
    mut write: W,
    mut rollback: R,
) -> Result<(), ConfigCommitFailure>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    let PreparedValidatedSingleWrite {
        target,
        before_image,
        content,
    } = prepared;
    #[cfg(test)]
    crate::config::write_lock::test_event(crate::config::write_lock::TestEvent::BeforePromotion);
    match write(&target, &content) {
        Ok(()) => Ok(()),
        // A descriptor identity recheck is immediately before rename.  If it
        // fails, another writer may have changed the visible destination, so
        // claiming the transaction is untouched would authorize unsafe body
        // cleanup.
        Err(write_error @ AtomicWriteError::Stat { .. }) => Err(ConfigCommitFailure {
            disposition: ConfigCommitDisposition::Uncertain,
            write_error,
            rollback_error: None,
        }),
        Err(write_error) if !write_error.rename_landed() => Err(ConfigCommitFailure {
            disposition: ConfigCommitDisposition::Untouched,
            write_error,
            rollback_error: None,
        }),
        Err(write_error) => match rollback(&target, before_image.as_deref()) {
            Ok(()) => Err(ConfigCommitFailure {
                disposition: ConfigCommitDisposition::RestoredDurably,
                write_error,
                rollback_error: None,
            }),
            Err(rollback_error) => Err(ConfigCommitFailure {
                disposition: ConfigCommitDisposition::Uncertain,
                write_error,
                rollback_error: Some(rollback_error),
            }),
        },
    }
}

/// Serialise + validate-then-promote a single slice while retaining `guard`.
/// The destination is resolved and read through the pinned tree before its
/// staged bytes are validated and promoted.
pub(crate) fn write_value_validated_locked(
    guard: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    final_path: &Path,
    value: &Value,
) -> anyhow::Result<()> {
    write_value_validated_locked_inner(guard, master, final_path, value, || {})
}

#[cfg(test)]
fn write_value_validated_locked_after_prepare(
    guard: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    final_path: &Path,
    value: &Value,
    after_prepare: impl FnOnce(),
) -> anyhow::Result<()> {
    write_value_validated_locked_inner(guard, master, final_path, value, after_prepare)
}

fn write_value_validated_locked_inner(
    guard: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    final_path: &Path,
    value: &Value,
    after_prepare: impl FnOnce(),
) -> anyhow::Result<()> {
    // Re-read the file we are about to replace so its comments and key
    // order can be carried across the mutation. `read_or_empty` already
    // hands the raw text back to most callers, but not through this
    // signature — and threading it here would mean touching ~40 call sites
    // to fix one serialiser. Read through the pinned target so a path outside
    // this guard's tree is refused before touching the filesystem.
    guard.verify_master(master)?;
    let plan = guard.tree_io().plan_target(final_path)?;
    let resolved = plan.display().to_path_buf();
    let before_image = plan.read_original()?;
    let original = before_image.as_deref().unwrap_or_default();
    let content = super::toml_write::render_preserving(original, value)
        .with_context(|| format!("serialise {}", resolved.display()))?;
    let prepared = PreparedWrite {
        plan,
        before_image,
        content,
    };
    after_prepare();
    promote_prepared_locked(guard, master, vec![prepared])
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
pub(crate) fn write_values_validated_locked(
    guard: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    writes: &[StagedWrite],
) -> anyhow::Result<()> {
    promote_validated_locked(guard, master, writes)
}

/// Publish a historical migration batch under an already-held destination
/// guard.  Historical output has its own pinned schema contract and must not
/// inherit the normal CLI mutation policy gate.
pub(crate) fn write_historical_values_validated_locked(
    guard: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    writes: &[StagedWrite],
    historical_schema: u32,
) -> anyhow::Result<()> {
    let prepared = prepare_writes(guard, master, writes)?;
    promote_historical_prepared_locked(guard, master, prepared, historical_schema)
}

/// Shared core for [`write_value_validated_locked`] /
/// [`write_values_validated_locked`].
///
/// 1. Snapshot held destinations and bind their staged bytes into a
///    [`LoaderOverlay`]. Every staged document must participate at its planned
///    destination; new files enter as extra include members.
/// 2. Run the overlay-aware load once. On failure: nothing is written.
/// 3. Promote each slice atomically (cross-ref already proven, so the staged
///    validator is a cheap TOML round-trip). On a later-rename I/O failure,
///    restore the slices already promoted in this batch.
///
/// Passing the held guard prevents overlay validation from reacquiring a read lock.
fn promote_validated_locked(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    staged: &[StagedWrite],
) -> anyhow::Result<()> {
    let prepared = prepare_writes(lock, master, staged)?;
    promote_prepared_locked(lock, master, prepared)
}

/// The transaction core with operation parameters kept explicit so tests can
/// exercise a post-rename write failure and an independent rollback failure
/// without any process-global fault hook.
#[cfg(test)]
fn promote_validated_locked_with_ops<W, R>(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    staged: &[StagedWrite],
    write: W,
    rollback: R,
) -> anyhow::Result<()>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    let prepared = prepare_writes(lock, master, staged)?;
    promote_prepared_locked_with_ops(lock, master, prepared, write, rollback)
}

fn prepare_writes<'g>(
    lock: &'g crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    staged: &[StagedWrite],
) -> anyhow::Result<Vec<PreparedWrite<'g>>> {
    let master = guarded_master_locked(lock, master)?;
    let tree = lock.tree_io();
    let mut keys = BTreeSet::new();
    staged
        .iter()
        .map(|write| {
            let plan = if master.matches_path(lock, &write.final_path)? {
                tree.plan_master_target()?
            } else {
                tree.plan_target(&write.final_path)?
            };
            anyhow::ensure!(
                keys.insert(plan.key().clone()),
                "duplicate staged config member: {}",
                plan.display().display()
            );
            Ok(PreparedWrite {
                before_image: plan.read_original()?,
                plan,
                content: write.content.clone(),
            })
        })
        .collect()
}

fn promote_prepared_locked(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    prepared: Vec<PreparedWrite<'_>>,
) -> anyhow::Result<()> {
    promote_prepared_locked_with_ops(lock, master, prepared, write_slice_syntax_checked, revert)
}

fn promote_historical_prepared_locked(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    prepared: Vec<PreparedWrite<'_>>,
    historical_schema: u32,
) -> anyhow::Result<()> {
    validate_historical_prepared_locked(lock, master, &prepared, historical_schema)?;
    promote_prepared_after_validation_with_ops(lock, prepared, write_slice_raw, revert_raw)
}

#[cfg(test)]
fn promote_historical_prepared_locked_with_ops<W, R>(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    staged: &[StagedWrite],
    historical_schema: u32,
    write: W,
    rollback: R,
) -> anyhow::Result<()>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    let prepared = prepare_writes(lock, master, staged)?;
    validate_historical_prepared_locked(lock, master, &prepared, historical_schema)?;
    promote_prepared_after_validation_with_ops(lock, prepared, write, rollback)
}

fn promote_prepared_locked_with_ops<W, R>(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    prepared: Vec<PreparedWrite<'_>>,
    write: W,
    rollback: R,
) -> anyhow::Result<()>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    validate_prepared_locked(lock, master, &prepared)?;
    promote_prepared_after_validation_with_ops(lock, prepared, write, rollback)
}

/// Publish a batch whose final overlay has already been validated by the
/// caller's explicit contract.
fn promote_prepared_after_validation_with_ops<W, R>(
    _lock: &crate::config::write_lock::ConfigWriteLock,
    prepared: Vec<PreparedWrite<'_>>,
    mut write: W,
    mut rollback: R,
) -> anyhow::Result<()>
where
    W: FnMut(&PinnedTarget<'_>, &str) -> Result<(), AtomicWriteError>,
    R: FnMut(&PinnedTarget<'_>, Option<&str>) -> anyhow::Result<()>,
{
    // 3. Promote each slice atomically, rolling back from the step-0 snapshot.
    let prepared_targets = prepared
        .into_iter()
        .map(|write| {
            let PreparedWrite {
                plan,
                before_image,
                content,
            } = write;
            Ok((plan.materialize()?, before_image, content))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    #[cfg(test)]
    crate::config::write_lock::test_event(crate::config::write_lock::TestEvent::BeforePromotion);
    let mut promoted: Vec<(&PinnedTarget<'_>, Option<String>)> =
        Vec::with_capacity(prepared_targets.len());
    for (target, before_image, content) in &prepared_targets {
        let path = target.display();
        let before_image = before_image.clone();
        match write(target, content) {
            Ok(()) => promoted.push((target, before_image)),
            Err(write_err) => {
                let mut rollback_errs = Vec::new();
                let rename_landed = write_err.rename_landed();
                if rename_landed {
                    if let Err(re) = rollback(target, before_image.as_deref()) {
                        rollback_errs.push(format!("{}: {re}", path.display()));
                    }
                }
                for (done_path, original) in promoted.iter().rev() {
                    if let Err(re) = rollback(done_path, original.as_deref()) {
                        rollback_errs.push(format!("{}: {re}", done_path.display().display()));
                    }
                }
                if rollback_errs.is_empty() {
                    let recovered = if rename_landed {
                        format!(
                            "write {} renamed the target but parent-directory durability is unconfirmed; current and {} earlier slice(s) in this change were rolled back",
                            path.display(),
                            promoted.len()
                        )
                    } else {
                        format!(
                            "write {} failed before its rename; {} earlier slice(s) in this change were rolled back",
                            path.display(),
                            promoted.len()
                        )
                    };
                    return Err(anyhow::Error::new(write_err).context(recovered));
                }
                let disposition = if rename_landed {
                    "renamed the target but parent-directory durability is unconfirmed"
                } else {
                    "failed before its rename"
                };
                return Err(anyhow::Error::new(write_err).context(format!(
                    "write {} {}; rollback incomplete and recovery required ({} rollback failure(s)): {}",
                    path.display(),
                    disposition,
                    rollback_errs.len(),
                    rollback_errs.join("; ")
                )));
            }
        }
    }
    Ok(())
}

/// Validate staged config bytes while every destination remains unpromoted.
fn validate_prepared_locked(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    prepared: &[PreparedWrite<'_>],
) -> anyhow::Result<()> {
    lock.verify_master(master)?;
    let tree = lock.tree_io();
    refuse_policy_write_on_a_cluster_secondary(tree, prepared)?;
    #[cfg(test)]
    crate::config::write_lock::test_event(crate::config::write_lock::TestEvent::BeforeOverlay);
    let mut overlay = LoaderOverlay::default();
    for write in prepared {
        overlay.stage_plan(&write.plan, write.content.clone())?;
    }

    // 2. Validate the would-be-merged tree once, before promoting anything.
    let now = time::OffsetDateTime::now_utc();
    if let Err(errs) = load_config_with_overlay_for_schema_under_guard(
        lock,
        master,
        crate::config::schema::SCHEMA_VERSION_V1,
        now,
        Some(&overlay),
    ) {
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
    Ok(())
}

/// Validate a historical migration's exact final overlay.  New members are
/// admitted only when an include can reach them; unlike normal entity writes,
/// no cluster-secondary mutation policy is applied here.
fn validate_historical_prepared_locked(
    lock: &crate::config::write_lock::ConfigWriteLock,
    master: &Path,
    prepared: &[PreparedWrite<'_>],
    historical_schema: u32,
) -> anyhow::Result<()> {
    lock.verify_master(master)?;
    #[cfg(test)]
    crate::config::write_lock::test_event(crate::config::write_lock::TestEvent::BeforeOverlay);
    let mut overlay = LoaderOverlay::default();
    for write in prepared {
        overlay.stage_plan_reachable_only(&write.plan, write.content.clone())?;
    }
    let now = time::OffsetDateTime::now_utc();
    match load_config_with_overlay_for_schema_under_guard(
        lock,
        master,
        historical_schema,
        now,
        Some(&overlay),
    ) {
        Ok(_) => {}
        Err(errs) => {
            let mut msg =
                format!("historical schema {historical_schema} validation failed; nothing written");
            for error in &errs {
                msg.push_str("\n  - ");
                msg.push_str(&error.to_string());
            }
            bail!(msg);
        }
    };
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
/// `bail!` in `promote_validated_locked` and the incident it records; plain backticks
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
    tree: TreeIo<'_>,
    prepared: &[PreparedWrite<'_>],
) -> anyhow::Result<()> {
    let Some(cluster) = cluster_section_in_effect(tree, prepared) else {
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
    for write in prepared {
        sections.extend(
            changed_top_level_keys(write.before_image.as_deref(), &write.content)
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
/// [`promote_validated_locked`] reports the real syntax error a paragraph later, and
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
fn cluster_section_in_effect(
    tree: TreeIo<'_>,
    prepared: &[PreparedWrite<'_>],
) -> Option<ClusterConfig> {
    let staged_master = prepared
        .iter()
        .find(|write| write.plan.key() == &tree.master_key())
        .map(|write| write.content.clone());
    let raw = match staged_master {
        Some(content) => content,
        None => tree.plan_master_target().ok()?.read_original().ok()??,
    };
    let table = raw.parse::<Value>().ok()?;
    table
        .get("cluster")?
        .clone()
        .try_into::<ClusterConfig>()
        .ok()
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
/// batch in [`promote_validated_locked`], so this only guards against a serialise bug
/// producing non-round-trippable TOML. RAWFS-compliant (hardened atomic write).
fn write_slice_syntax_checked(
    path: &PinnedTarget<'_>,
    content: &str,
) -> Result<(), AtomicWriteError> {
    write_slice_syntax_checked_with_opts(path, content, AtomicWriteAtOpts::default())
}

/// Write already overlay-validated historical bytes without imposing a TOML
/// parser on either publication or compensating rollback.
fn write_slice_raw(path: &PinnedTarget<'_>, content: &str) -> Result<(), AtomicWriteError> {
    write_slice_raw_with_opts(path, content, AtomicWriteAtOpts::default())
}

fn write_slice_raw_with_opts(
    path: &PinnedTarget<'_>,
    content: &str,
    write_opts: AtomicWriteAtOpts<'_>,
) -> Result<(), AtomicWriteError> {
    hardened_atomic_write_at(
        path,
        content.as_bytes(),
        AtomicWriteAtOpts {
            validator: None,
            mode: write_opts.mode,
            owner: write_opts.owner,
            fsync_parent: write_opts.fsync_parent,
            #[cfg(test)]
            test_failure: write_opts.test_failure,
        },
    )
}

/// Syntax-only staged write with caller-supplied write options. Keeping this
/// typed helper beneath the transaction boundary lets it classify the sole
/// failure that occurs after rename before adding `anyhow` display context.
fn write_slice_syntax_checked_with_opts(
    path: &PinnedTarget<'_>,
    content: &str,
    write_opts: AtomicWriteAtOpts<'_>,
) -> Result<(), AtomicWriteError> {
    let syntax_check = |mut staged: &std::fs::File, _display: &Path| -> Result<(), String> {
        use std::io::Read;
        let mut raw = String::new();
        staged.read_to_string(&mut raw).map_err(|e| e.to_string())?;
        raw.parse::<Value>().map(|_| ()).map_err(|e| e.to_string())
    };
    hardened_atomic_write_at(
        path,
        content.as_bytes(),
        AtomicWriteAtOpts {
            validator: Some(&syntax_check),
            mode: write_opts.mode,
            owner: write_opts.owner,
            fsync_parent: write_opts.fsync_parent,
            #[cfg(test)]
            test_failure: write_opts.test_failure,
        },
    )
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
