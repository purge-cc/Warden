//! `warden migrate v0-to-v1` — one-shot translation from the pre-v1
//! single-file layout to the FHS-compliant `/etc/purge-warden/` multi-file
//! tree.
//!
//! # Input shape
//!
//! Any TOML file in the pre-v1 single-file layout — or one already in
//! the v1 [`ConfigV1`] shape — is accepted. Mixed files (scaffolds
//! that already carry `[[blocklists]]` / v1 `[profiles.*]` next to legacy
//! `[[clients]]`) are handled by extracting each section individually
//! rather than piping the whole thing through one deserialiser. This keeps
//! the tool useful for the Debian CT's current state (pure-v1 monolith) and
//! for synthetic Pi-hole-style imports (pure-v0 with `[[clients]]`).
//!
//! # Output shape (default, `single_file = false`)
//!
//! ```text
//! <target>/config.toml            ← master: schema_version + includes +
//!                                   [server] + every pass-through daemon
//!                                   section. No entity collections.
//! <target>/devices.d/auto-migrated.toml
//! <target>/groups.d/auto-migrated.toml
//! <target>/subnets.d/auto-migrated.toml
//! <target>/blocklists.d/auto-migrated.toml
//! <target>/schedules.d/auto-migrated.toml
//! <target>/rules.d/auto-migrated.toml
//! <target>/profiles.d/<id>.toml   ← one file per profile
//! ```
//!
//! Empty entity collections produce no file — the `.d/` directory itself
//! is created only when at least one entry exists. The master's
//! `includes` array is written unconditionally with the full set of glob
//! patterns so future `warden <entity> add` commands land in the correct
//! directory automatically.
//!
//! # Validation
//!
//! After the files are written, [`crate::config::loader::load_config`]
//! runs end-to-end against the new master. A validator failure aborts the
//! migration with the full error list (file:line per error). The legacy
//! file is NEVER deleted by this tool: the operator removes it manually
//! after confirming the new tree boots.
//!
//! # Backup
//!
//! A copy of the legacy config lands at
//! `<legacy-parent>/backups/pre-migration-<rfc3339>.toml`. The migration
//! cannot undo itself, but the backup gives the operator a trivial
//! rollback: point the systemd unit's `--config` back at the old file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use toml::Value;

use crate::cli::commands::config::restore::StagingDir;
use crate::config::atomic_write::atomic_write_and_validate;
use crate::config::schema::{
    AdminRule, Blocklist, BlocklistFormat, ConfigV1, Device, Id, Profile, Schedule,
    SCHEMA_VERSION_V1,
};
use crate::config::settings::{ClientConfig, ScheduleConfig};
use crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES;

/// Syntactic TOML round-trip validator for the migration writes. Full
/// v1 / v2 loader passes would fail on mid-migration intermediate
/// states (a slice file may already carry v2 shape while the master
/// still carries v1, etc.) — the `toml::Value` parse catches
/// serialiser corruption without coupling to schema-stage timing.
fn migration_toml_validator(staged: &Path) -> Result<(), String> {
    let raw = std::fs::read_to_string(staged).map_err(|e| e.to_string())?;
    raw.parse::<Value>().map(|_| ()).map_err(|e| e.to_string())
}

/// Adapter: pipe an [`atomic_write_and_validate`] call into the
/// migration's `anyhow::Result` surface with a fixed validator.
fn migration_atomic_write(path: &Path, content: &str) -> anyhow::Result<()> {
    atomic_write_and_validate(path, content, migration_toml_validator)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Create `path` (and any missing parents) at `mode` rather than the umask
/// default. Migrated `*.d/` slice dirs must not be world-listable — the
/// filenames leak device/profile ids even when the file contents stay `0o640`.
/// Mirrors `backup.rs` / `init.rs`; `recursive` makes it a no-op on an existing
/// dir (the mode applies only to dirs we actually create).
fn create_dir_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .with_context(|| format!("cannot create {} (mode {:o})", path.display(), mode))
}

/// Per-category entity counts reported by the migration, plus the notes
/// the operator should review before considering the migration complete.
#[derive(Debug, Default)]
pub struct MigrationSummary {
    pub devices: usize,
    pub groups: usize,
    pub subnets: usize,
    pub schedules: usize,
    pub blocklists: usize,
    pub admin_rules: usize,
    pub profiles: usize,
    pub target_master: PathBuf,
    pub backup_path: PathBuf,
    pub notes: Vec<String>,
    pub single_file: bool,
}

/// CLI entry point. Returns the exit code (0 on success; any failure is an
/// `anyhow::Error` that main.rs converts into a non-zero exit).
pub fn run(
    legacy_config: &Path,
    target: &Path,
    single_file: bool,
    force: bool,
) -> anyhow::Result<i32> {
    let summary = migrate(legacy_config, target, single_file, force)?;
    print_summary(&summary);
    Ok(0)
}

/// CLI entry point for `warden migrate v1-to-v2` — **deprecated alias for
/// `v1-to-v3`**.
///
/// The verb cannot do what its name says any more. `migrate_v1_to_v2`
/// writes [`SCHEMA_VERSION_V1`] into its output, which is now `3`, so it
/// would stamp a v3 version onto v2 *content* (`kind`, no `lists`) and its
/// own post-write validator would refuse it. Writing a literal `2` does not
/// rescue it either: `check_schema_version` demands equality with the
/// current constant, so the output would be a file no binary in the tree
/// can load. There is no reading of "v1 to v2" this build can satisfy.
///
/// So it forwards, loudly, rather than being deleted: an operator following
/// a two-year-old runbook gets their config migrated and told the new name,
/// instead of `error: unrecognized subcommand`. The underlying
/// [`migrate_v1_to_v2`] is kept and still tested — it is the shape-change
/// half that [`migrate_v1_to_v3`] calls.
pub fn run_v1_to_v2(from_config: &Path, target: &Path, force: bool) -> anyhow::Result<i32> {
    eprintln!(
        "warning: `migrate v1-to-v2` is a deprecated alias for `migrate v1-to-v3` and runs it \
         instead. schema_version 2 is no longer a version this binary can produce or load."
    );
    run_v1_to_v3(from_config, target, force)
}

/// Per-entity transformations applied during the v1→v2 migration.
#[derive(Debug, Default)]
pub struct V1ToV2Summary {
    pub blocklists_promoted_to_uncategorized: usize,
    pub blocklists_kept_empty_tags: usize,
    pub profiles_dropped_blocklists_field: usize,
    pub devices_tagged_uncategorized: usize,
    pub subnets_tagged_empty: usize,
    pub categories_blocks_dropped: usize,
    pub target_path: PathBuf,
    pub backup_path: PathBuf,
    pub notes: Vec<String>,
}

/// Translate a pre-`lists_categories_v2` config (schema_version = 2 wire)
/// into the tag-based v2 association model:
///
/// - Every `kind = "deny"` blocklist (including the implicit default)
///   gains `tags = ["uncategorized"]` so it stays applied to every
///   device that inherits the `uncategorized` sentinel post-migration.
/// - Every `kind = "allow"` blocklist keeps `tags = []` (auto-allow
///   for everyone is a security risk; the operator tags allow-lists
///   explicitly).
/// - `Profile.blocklists` and `Profile.categories` arrays are dropped;
///   profiles gain `tags = []` (operator customises post-migration).
/// - Devices gain `tags = ["uncategorized"]` + `unfiltered = false`.
/// - Subnets gain `tags = []`.
/// - Top-level `[[categories]]` blocks are dropped (entity removed).
/// - Legacy `Blocklist.category = "..."` fields are dropped (replaced
///   by `tags`).
///
/// Works on `toml::Value` rather than `ConfigV1` so it can read v1
/// configs that carry the now-removed fields without tripping
/// `#[serde(deny_unknown_fields)]`.
pub fn migrate_v1_to_v2(
    from_config: &Path,
    target: &Path,
    force: bool,
) -> anyhow::Result<V1ToV2Summary> {
    if !from_config.exists() {
        bail!("v1 config not found: {}", from_config.display());
    }

    // Refuse to clobber an existing target
    // unless --force. Previously the single-file output was overwritten
    // silently, costing operator post-edits on a re-run.
    if target.exists() && !force {
        bail!(
            "target {} already exists. Pass --force to overwrite (will replace the file). \
             Re-running on an already-migrated input is idempotent so the new \
             output should match the existing one byte-for-byte, but operator post-edits \
             would be lost.",
            target.display()
        );
    }

    let raw = std::fs::read_to_string(from_config)
        .with_context(|| format!("cannot read {}", from_config.display()))?;
    let mut root: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", from_config.display()))?;

    let mut summary = V1ToV2Summary::default();
    apply_v1_to_v2_transformations(&mut root, &mut summary)?;

    // Pin schema_version to the current value so a downgrade-input
    // (legacy schema_version = 1) lands on the current v2 wire.
    if let Value::Table(t) = &mut root {
        t.insert(
            "schema_version".into(),
            Value::Integer(SCHEMA_VERSION_V1 as i64),
        );
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }

    if force && target.exists() {
        eprintln!(
            "warning: --force overwrites existing target {}",
            target.display()
        );
    }

    let backup_path = backup_legacy(from_config)?;
    summary.backup_path = backup_path;

    let output = toml::to_string_pretty(&root).with_context(|| "failed to serialise v2 config")?;

    // Validate through the full v2 loader BEFORE the rename, not after.
    // `atomic_write_and_validate` writes a temp in target's directory, runs
    // the validator against that temp, and only renames it into place if it
    // passes — so a transformation bug surfaces here with `target` left
    // untouched, instead of after a corrupt-but-parseable config has already
    // clobbered the live master (the `--from-config X --target X --force`
    // in-place case the migrate-transactionality lens forbids). The v0→v1
    // multi-file path keeps the TOML-parse-only validator because its staged
    // slices can be mid-schema; this v1→v2 path produces a single complete
    // file, so the full loader can and must gate the rename.
    let now = OffsetDateTime::now_utc();
    atomic_write_and_validate(target, &output, |staged: &Path| {
        crate::config::loader::load_config(staged, now)
            .map(|_| ())
            .map_err(|errs| {
                let mut msg = format!("{} error(s):", errs.len());
                for e in &errs {
                    msg.push_str("\n  - ");
                    msg.push_str(&e.to_string());
                }
                msg
            })
    })
    .map_err(|e| {
        anyhow!(
            "v1→v2 migration produced an invalid v2 config ({e})\n\
             legacy backup preserved at {}; the input may carry an unhandled \
             field or a custom invariant the migrator does not know about — fix \
             the input or extend `apply_v1_to_v2_transformations`. {} was left \
             unchanged.",
            summary.backup_path.display(),
            target.display()
        )
    })?;
    summary.target_path = target.to_path_buf();

    if summary.blocklists_kept_empty_tags > 0 {
        summary.notes.push(format!(
            "{} allow-list(s) kept `tags = []`. The reload \
             validator will emit a WARN for each — tag the allow-list(s) \
             explicitly to silence the warning.",
            summary.blocklists_kept_empty_tags
        ));
    }
    if summary.profiles_dropped_blocklists_field > 0 {
        summary.notes.push(format!(
            "{} profile(s) had a `blocklists` array dropped. Their tags \
             are now empty — the bundled `[[blocklists]]` entries with \
             `tags = [\"uncategorized\"]` apply to every device because \
             every new device inherits the `uncategorized` sentinel. \
             Customise `[profiles.<id>].tags` to scope filtering.",
            summary.profiles_dropped_blocklists_field
        ));
    }

    Ok(summary)
}

fn apply_v1_to_v2_transformations(
    root: &mut Value,
    summary: &mut V1ToV2Summary,
) -> anyhow::Result<()> {
    let table = match root {
        Value::Table(t) => t,
        _ => bail!("v1 config root must be a TOML table"),
    };

    // Idempotency short-circuit: if the
    // input already carries v2 shape (every blocklist has `tags` and
    // no `[[categories]]` block survives), the transformation is a
    // no-op. Previously a re-run would clobber operator-set tags via
    // unconditional `t.insert("tags", …)`.
    if is_already_v2(table) {
        tracing::info!(
            target: "migrate.v1_to_v2",
            "input already carries v2 shape; transformation is a no-op"
        );
        return Ok(());
    }

    // 1) Drop top-level `[[categories]]` block (entity removed).
    if let Some(Value::Array(arr)) = table.remove("categories") {
        summary.categories_blocks_dropped = arr.len();
    }

    // 2) Walk `[[blocklists]]`: drop legacy `category`, set `tags`
    //    based on `kind`. Skip entries that already carry
    //    `tags` so an operator-customised value survives a re-run.
    if let Some(Value::Array(blocklists)) = table.get_mut("blocklists") {
        for entry in blocklists.iter_mut() {
            if let Value::Table(t) = entry {
                t.remove("category");
                if t.contains_key("tags") {
                    continue;
                }
                let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("deny");
                if kind == "allow" {
                    t.insert("tags".into(), Value::Array(vec![]));
                    summary.blocklists_kept_empty_tags += 1;
                } else {
                    t.insert(
                        "tags".into(),
                        Value::Array(vec![Value::String("uncategorized".into())]),
                    );
                    summary.blocklists_promoted_to_uncategorized += 1;
                }
            }
        }
    }

    // 3) Walk `[profiles.<id>]` table: drop `blocklists` + `categories`
    //    arrays, set `tags = []` ONLY when absent.
    if let Some(Value::Table(profiles)) = table.get_mut("profiles") {
        for (_, profile_val) in profiles.iter_mut() {
            if let Value::Table(t) = profile_val {
                let had_blocklists = t.remove("blocklists").is_some();
                t.remove("categories");
                if !t.contains_key("tags") {
                    t.insert("tags".into(), Value::Array(vec![]));
                }
                if had_blocklists {
                    summary.profiles_dropped_blocklists_field += 1;
                }
            }
        }
    }

    // 4) Walk `[[devices]]`: set `tags = ["uncategorized"]` +
    //    `unfiltered = false`. Gate both inserts on
    //    `contains_key` so an operator who has already moved a device
    //    to e.g. `tags = ["family"]` keeps that on re-run.
    if let Some(Value::Array(devices)) = table.get_mut("devices") {
        for entry in devices.iter_mut() {
            if let Value::Table(t) = entry {
                if !t.contains_key("tags") {
                    t.insert(
                        "tags".into(),
                        Value::Array(vec![Value::String("uncategorized".into())]),
                    );
                    summary.devices_tagged_uncategorized += 1;
                }
                if !t.contains_key("unfiltered") {
                    t.insert("unfiltered".into(), Value::Boolean(false));
                }
            }
        }
    }

    // 5) Walk `[[subnets]]`: set `tags = []` only when absent.
    if let Some(Value::Array(subnets)) = table.get_mut("subnets") {
        for entry in subnets.iter_mut() {
            if let Value::Table(t) = entry {
                if !t.contains_key("tags") {
                    t.insert("tags".into(), Value::Array(vec![]));
                    summary.subnets_tagged_empty += 1;
                }
            }
        }
    }

    Ok(())
}

/// Already-v2 detector for the idempotency short-circuit. The
/// loose signal is "no `[[categories]]` block AND every blocklist
/// carries a `tags` field" — a legacy v1 config has neither,
/// so the absence of categories alone is not enough.
fn is_already_v2(table: &toml::value::Table) -> bool {
    let no_categories = table.get("categories").is_none();
    let bls_all_tagged = match table.get("blocklists") {
        Some(Value::Array(arr)) if !arr.is_empty() => arr
            .iter()
            .all(|entry| matches!(entry, Value::Table(t) if t.contains_key("tags"))),
        _ => false,
    };
    no_categories && bls_all_tagged
}

/// Per-entity transformations applied during the v2→v3 migration.
#[derive(Debug, Default)]
pub struct V2ToV3Summary {
    /// Profiles that gained an explicit `lists` table.
    pub profiles_given_lists: usize,
    /// `(profile, list)` pairs written as `deny` or `allow` — the lists a
    /// profile's tags reached.
    pub pairs_kept: usize,
    /// `(profile, list)` pairs written as `ignore` — the lists a profile's
    /// tags did **not** reach. These are the ones that would otherwise
    /// change behaviour: in v3 a list with no override is inherited by every
    /// profile.
    pub pairs_ignored: usize,
    /// `[[blocklists]]` rows whose `kind` key was renamed to `base`.
    /// Counted separately from the policy work because it is the
    /// half that makes the output *loadable* at all: `Blocklist` carries
    /// `deny_unknown_fields`, so a surviving `kind` is a hard refusal.
    pub lists_renamed_kind_to_base: usize,
    /// Entities (`[[blocklists]]`, `[profiles.*]`, `[[devices]]`, …) that
    /// carried the retired `tags` key and had it removed. Without this the
    /// migrated config still loads — the loader strips it — but NOTES it
    /// once per entity at every single load, forever.
    pub entities_stripped_of_tags: usize,
    pub target_path: PathBuf,
    pub backup_path: PathBuf,
    pub notes: Vec<String>,
}

/// What the loader would have made of a `[[blocklists]]` row, read from the
/// RAW TOML.
///
/// **Raw, never `ConfigV1`, and that is the whole trick.**
/// `auto_promote_blocklists` (`config/schema/validator.rs`) gives an untagged
/// **deny**-list `tags = ["uncategorized"]` at load, so post-promotion every
/// deny-list looks tagged — a check written against a loaded config passes on
/// exactly the rows that must be treated as untagged. `run_set_kind_with_ack`
/// reads `tbl.get("tags")` for the same reason.
///
/// The promotion is still *applied* here, because the migration has to
/// reproduce what the daemon resolved yesterday — but it is applied **in the
/// computation and never written back**. A value the loader synthesises must
/// not round-trip into the file: doing so promotes a default to data, which
/// is a defect this repo has already had (the TUI's Lists modal seeded its
/// tag picker from the loaded config and wrote `uncategorized` back on the
/// next save).
/// The v2 sentinel the loader used to stamp on every untagged deny-list.
///
/// A local copy on purpose. A prior refactor deleted `config::schema::tag`, so the
/// shared const is gone — but this module reads **v2** files, where the tag
/// model was live, and it needs the same value the v2 loader would have
/// synthesised in order to derive the right `profiles.<id>.lists` table.
/// Re-exporting a v3 const for a v2-only fact is what would drift; this
/// value is frozen by the format it describes and cannot change again.
const V2_UNCATEGORIZED: &str = "uncategorized";

struct RawList {
    id: String,
    /// Tags **as resolved**, promotion included. Never serialised.
    effective_tags: Vec<String>,
    /// `deny` / `allow`, defaulting to `deny` exactly as serde does.
    kind: String,
}

fn raw_string_array(t: &toml::value::Table, key: &str) -> Option<Vec<String>> {
    match t.get(key) {
        Some(Value::Array(a)) => Some(
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    }
}

/// Entities that carry their own `tags` in the raw TOML.
///
/// Devices, groups and subnets are all refused for one reason: each of them
/// varies list applicability **below** the profile. `effective_tags` unioned
/// `device.tags`, its groups' tags and (for anonymous sources) its subnet's,
/// so two clients on one profile could see different lists. v3 has no such
/// axis — `profiles.<id>.lists` is the whole model — so flattening them would
/// be a silent verdict change for whichever client loses a list.
///
/// The design intent names devices; groups and
/// subnets are the same defect through a different door, and refusing all
/// three costs nothing on the two live hosts (measured: zero
/// tagged entities of any kind).
fn tagged_sub_profile_entities(table: &toml::value::Table) -> Vec<String> {
    let mut out = Vec::new();
    for kind in ["devices", "groups", "subnets"] {
        let Some(Value::Array(rows)) = table.get(kind) else {
            continue;
        };
        for row in rows {
            let Value::Table(t) = row else { continue };
            if raw_string_array(t, "tags").is_some_and(|v| !v.is_empty()) {
                let id = t.get("id").and_then(Value::as_str).unwrap_or("<no id>");
                out.push(format!("{}/{id}", kind.trim_end_matches('s')));
            }
        }
    }
    out
}

/// Snapshot the association v2 resolved, as explicit per-profile overrides.
///
/// The intent: a mechanical snapshot of today's resolution into explicit
/// overrides. Nothing is repaired.
/// If two profiles filtered identically because every list carried
/// `uncategorized`, the migrated config says so out loud — that
/// defect is the operator's to fix once they can see it, and a migration that
/// quietly improved it would be changing verdicts.
///
/// # Why every pair is written, including the ones that inherit
///
/// A missing entry means "inherit `base`", so writing only the `ignore`
/// entries would be enough for correctness. It is written in full anyway,
/// because the file is what the operator reads: the point of the workstream
/// is that the association stops being an emergent property of two tag arrays
/// and becomes a thing you can see. A half-written table restores the guessing.
///
/// # What is deliberately NOT written
///
/// The `uncategorized` the loader synthesises for untagged deny-lists never
/// lands on disk. A value the loader invents is not a value the file should
/// then claim.
///
/// **This paragraph used to say `tags` stay exactly as the file had them,
/// deferring their removal to later.** That has since landed:
/// the field is gone from the data model and the loader strips the
/// key at load, so leaving it here no longer defers the work —
/// it hands the operator a config that NOTES once per entity at every load,
/// forever, with no CLI able to clear it. The key is now removed here, which
/// is the only place the operator's forward path passes through.
/// Migrate a v2 config to v3, then — and only then — drop the retired
/// `tags` key.
///
/// **The order is the whole point, and getting it wrong is silent.**
/// [`apply_v2_to_v3_inner`] *reads* `tags` to do its job: the per-profile
/// `lists` table it writes is a snapshot of the tag intersection that decided
/// filtering under v2. Stripping the key before that runs leaves every
/// profile with no tags, every intersection empty, and therefore **`ignore`
/// written for every (profile, list) pair** — a config that loads, lints
/// clean, and filters nothing.
///
/// Not hypothetical: it shipped in this function briefly, and was
/// caught by migrating a real household config rather than by any
/// test — every one of its lists came out ignored by both profiles.
/// It lints clean because a `base = "deny"` list
/// that every profile overrides to `ignore` has no detector — see
/// `plp-all-profiles-ignore-is-silently-inert`.
///
/// The early strip also ran **before** `tagged_sub_profile_entities`, the
/// guard that must REFUSE a config carrying device/group/subnet tags rather
/// than flatten it silently. Stripping first made that guard unreachable, so
/// one misplaced line defeated the lossless-migration promise as well.
///
/// Structured as a wrapper rather than a strip at each `return` because the
/// inner function has three exits, and a rule that must hold on all of them
/// is one a future edit can break by adding a fourth.
///
/// The strip calls the same function the loader uses, never a second copy: a
/// strip that disagreed with the loader about what a retired key looks like
/// would be worse than no strip at all.
fn apply_v2_to_v3_transformations(
    root: &mut Value,
    summary: &mut V2ToV3Summary,
) -> anyhow::Result<()> {
    apply_v2_to_v3_inner(root, summary)?;

    // The loader strips this key at load and NOTES it once per entity on
    // every load and every reload, so a migrated config that still carried it
    // would warn forever, and the only way to silence it would be hand-editing
    // the file — in a product whose whole premise is that the CLI owns the
    // config. That noise is the same defect as silence: both teach the
    // operator to stop reading. Migration is the operator's forward path, so
    // it is where the key dies — after the migration has finished reading it.
    if let Value::Table(table) = root {
        for entity in crate::config::schema::retired_keys::strip_retired_tag_keys(table) {
            summary.notes.push(format!(
                "removed the retired key 'tags' from {entity} — it no longer decides anything"
            ));
            summary.entities_stripped_of_tags += 1;
        }
    }

    Ok(())
}

fn apply_v2_to_v3_inner(root: &mut Value, summary: &mut V2ToV3Summary) -> anyhow::Result<()> {
    let table = match root {
        Value::Table(t) => t,
        _ => bail!("v2 config root must be a TOML table"),
    };

    // `kind` → `base` on every `[[blocklists]]` row.
    //
    // ABOVE the `is_already_v3` short-circuit on purpose. That gate keys on
    // the *profiles* carrying `lists` tables, so a half-migrated file — one
    // whose profiles were hand-written but whose lists still say `kind` —
    // would short-circuit out and produce a config the post-write validator
    // then refuses. The rename is independently idempotent (no `kind` key is
    // a no-op), so running it first costs nothing and closes that hole.
    //
    // The value is carried across verbatim, never re-derived: `deny`,
    // `allow` and `ignore` mean under `base` exactly what they meant under
    // `kind`. This step is a rename, not a policy decision — the policy is
    // the `lists` tables below.
    if let Some(Value::Array(rows)) = table.get_mut("blocklists") {
        for row in rows.iter_mut() {
            let Value::Table(t) = row else { continue };
            let Some(kind) = t.remove("kind") else {
                continue;
            };
            // A row carrying BOTH is ambiguous and there is no safe pick:
            // `base` wins would discard what the daemon is running today,
            // `kind` wins would discard what somebody hand-wrote. Refuse
            // and name it.
            if t.contains_key("base") {
                let id = t.get("id").and_then(Value::as_str).unwrap_or("<no id>");
                bail!(
                    "blocklist `{id}` carries both `kind` (schema_version 2) and `base` \
                     (schema_version 3). Delete whichever is stale and re-run — the migrator \
                     will not guess which of the two directions you meant."
                );
            }
            t.insert("base".into(), kind);
            summary.lists_renamed_kind_to_base += 1;
        }
    }

    if is_already_v3(table) {
        tracing::info!(
            target: "migrate.v2_to_v3",
            "input already carries v3 shape; transformation is a no-op"
        );
        return Ok(());
    }

    let refused = tagged_sub_profile_entities(table);
    if !refused.is_empty() {
        let (subject, verb) = if refused.len() == 1 {
            ("entity carries", "it")
        } else {
            ("entities carry", "them")
        };
        bail!(
            "cannot migrate: {} {subject} its own `tags`, and v3 has no per-device, \
             per-group or per-subnet list policy to migrate {verb} into — flattening \
             {verb} onto the profile would silently change what those clients \
             filter.\n  {}\n\nMove the intent onto a profile first: give the affected \
             clients a profile of their own with the same list set, clear the `tags`, \
             and re-run.",
            refused.len(),
            refused.join("\n  "),
        );
    }

    // Read every list from the RAW table — see `RawList`.
    let lists: Vec<RawList> = match table.get("blocklists") {
        Some(Value::Array(rows)) => rows
            .iter()
            .filter_map(|row| {
                let Value::Table(t) = row else { return None };
                let id = t.get("id").and_then(Value::as_str)?.to_string();
                // `base`, not `kind`: the rename pass above has already
                // run over this same table, so by here every row speaks v3.
                let kind = t
                    .get("base")
                    .and_then(Value::as_str)
                    .unwrap_or("deny")
                    .to_string();
                let declared = raw_string_array(t, "tags");
                let effective_tags = match declared {
                    Some(tags) => tags,
                    // `auto_promote_blocklists`: untagged DENY lists become
                    // `uncategorized`; allow-lists deliberately do not
                    // (auto-allowing for every device is a security risk).
                    None if kind == "allow" => Vec::new(),
                    None => vec![V2_UNCATEGORIZED.to_string()],
                };
                Some(RawList {
                    id,
                    effective_tags,
                    kind,
                })
            })
            .collect(),
        _ => Vec::new(),
    };

    let Some(Value::Table(profiles)) = table.get_mut("profiles") else {
        return Ok(());
    };

    for (_, profile_val) in profiles.iter_mut() {
        let Value::Table(p) = profile_val else {
            continue;
        };
        // Per-profile idempotency, matching `apply_v1_to_v2_transformations`'s
        // per-entry `contains_key` gates: an operator who has already written
        // overrides by hand keeps them on a re-run.
        if p.contains_key("lists") {
            continue;
        }
        let profile_tags = raw_string_array(p, "tags").unwrap_or_default();

        let mut policy = toml::value::Table::new();
        for l in &lists {
            let applies = l
                .effective_tags
                .iter()
                .any(|t| profile_tags.iter().any(|pt| pt == t));
            let direction = if applies { l.kind.as_str() } else { "ignore" };
            if applies {
                summary.pairs_kept += 1;
            } else {
                summary.pairs_ignored += 1;
            }
            policy.insert(l.id.clone(), Value::String(direction.to_string()));
        }
        if policy.is_empty() {
            continue;
        }
        p.insert("lists".into(), Value::Table(policy));
        summary.profiles_given_lists += 1;
    }

    Ok(())
}

/// Already-v3 detector for the idempotency short-circuit.
///
/// The signal is "there is at least one profile and every one of them carries
/// a `lists` table". Deliberately not `schema_version`: the wire version and
/// the association model are bumped at different points, so keying on it
/// would make this a no-op on a config that has the new number and none of
/// the new content.
fn is_already_v3(table: &toml::value::Table) -> bool {
    match table.get("profiles") {
        Some(Value::Table(profiles)) if !profiles.is_empty() => profiles
            .values()
            .all(|v| matches!(v, Value::Table(t) if t.contains_key("lists"))),
        _ => false,
    }
}

/// Translate a tag-associated v2 config into the per-profile list policy of
/// v3.
///
/// Mirrors [`migrate_v1_to_v2`] exactly — same refusal-to-clobber rule, same
/// backup, same validate-before-rename write — because the properties that
/// matter are the same: idempotent, atomic, and a transformation bug must
/// surface with the target untouched rather than after it has been replaced.
pub fn migrate_v2_to_v3(
    from_config: &Path,
    target: &Path,
    force: bool,
) -> anyhow::Result<V2ToV3Summary> {
    if !from_config.exists() {
        bail!("v2 config not found: {}", from_config.display());
    }
    if target.exists() && !force && target != from_config {
        bail!(
            "target {} already exists. Pass --force to overwrite (will replace the file). \
             Re-running on an already-migrated input is idempotent, so the new output \
             should match the existing one byte-for-byte, but operator post-edits would \
             be lost.",
            target.display()
        );
    }

    let raw = std::fs::read_to_string(from_config)
        .with_context(|| format!("cannot read {}", from_config.display()))?;
    let mut root: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", from_config.display()))?;

    let mut summary = V2ToV3Summary::default();
    apply_v2_to_v3_transformations(&mut root, &mut summary)?;

    if let Value::Table(t) = &mut root {
        t.insert(
            "schema_version".into(),
            Value::Integer(SCHEMA_VERSION_V1 as i64),
        );
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    if force && target.exists() {
        eprintln!(
            "warning: --force overwrites existing target {}",
            target.display()
        );
    }

    summary.backup_path = backup_legacy(from_config)?;

    let output = toml::to_string_pretty(&root).with_context(|| "failed to serialise v3 config")?;

    let now = OffsetDateTime::now_utc();
    atomic_write_and_validate(target, &output, |staged: &Path| {
        crate::config::loader::load_config(staged, now)
            .map(|_| ())
            .map_err(|errs| {
                let mut msg = format!("{} error(s):", errs.len());
                for e in &errs {
                    msg.push_str("\n  - ");
                    msg.push_str(&e.to_string());
                }
                msg
            })
    })
    .map_err(|e| {
        anyhow!(
            "v2→v3 migration produced an invalid v3 config ({e})\n\
             legacy backup preserved at {}; {} was left unchanged.",
            summary.backup_path.display(),
            target.display()
        )
    })?;
    summary.target_path = target.to_path_buf();

    if summary.pairs_ignored > 0 {
        summary.notes.push(format!(
            "{} (profile, list) pair(s) were written as `ignore` — those lists \
             did not reach that profile under the tag model. Without the explicit \
             `ignore` they would start applying, because in v3 a list with no \
             override is inherited by every profile.",
            summary.pairs_ignored
        ));
    }

    Ok(summary)
}

/// Per-entity outcome of the v1→v3 migration.
#[derive(Debug, Default)]
pub struct V1ToV3Summary {
    /// Everything the v1→v2 shape change did (categories dropped, tags
    /// seeded, `unfiltered` defaulted). Reused verbatim rather than
    /// re-implemented — see [`migrate_v1_to_v3`].
    pub v2: V1ToV2Summary,
    /// Profiles that gained an explicit `lists` table.
    pub profiles_given_lists: usize,
    /// `(profile, list)` pairs the v1 config subscribed to.
    pub pairs_kept: usize,
    /// `(profile, list)` pairs written as `ignore` — lists the v1 profile
    /// did **not** subscribe to. Without the explicit entry they would
    /// start applying, because in v3 an un-overridden list is inherited.
    pub pairs_ignored: usize,
    /// `[[blocklists]]` rows whose `kind` key was renamed to `base`.
    pub lists_renamed_kind_to_base: usize,
    /// Entities (`[[blocklists]]`, `[profiles.*]`, `[[devices]]`, …) that
    /// carried the retired `tags` key and had it removed. Without this the
    /// migrated config still loads — the loader strips it — but NOTES it
    /// once per entity at every single load, forever.
    pub entities_stripped_of_tags: usize,
    pub target_path: PathBuf,
    pub backup_path: PathBuf,
    pub notes: Vec<String>,
}

/// The `(profile → subscribed list ids)` association a v1 config expressed.
///
/// v1 spelled it two ways and unioned them (`profiles/profile.rs`
/// `resolve_blocklist_ids` at the pre-v2 tree): the ids named directly in
/// `profiles.<id>.blocklists`, plus every `[[blocklists]]` row whose
/// `category` matched one of `profiles.<id>.categories`. Both arrays default
/// to empty, and an empty union meant the profile filtered on **no list at
/// all** — reproduced here rather than repaired, exactly as
/// `apply_v2_to_v3_transformations` reproduces the tag intersection.
///
/// Read from the RAW table, and read **before** the v1→v2 shape change runs:
/// that pass deletes all three fields.
fn v1_profile_association(
    table: &toml::value::Table,
) -> BTreeMap<String, std::collections::BTreeSet<String>> {
    use std::collections::BTreeSet;

    // `[[blocklists]]` id → its v1 `category`, for the category arm below.
    let mut category_of: BTreeMap<String, String> = BTreeMap::new();
    if let Some(Value::Array(rows)) = table.get("blocklists") {
        for row in rows {
            let Value::Table(t) = row else { continue };
            let (Some(id), Some(cat)) = (
                t.get("id").and_then(Value::as_str),
                t.get("category").and_then(Value::as_str),
            ) else {
                continue;
            };
            category_of.insert(id.to_string(), cat.to_string());
        }
    }

    let mut out = BTreeMap::new();
    let Some(Value::Table(profiles)) = table.get("profiles") else {
        return out;
    };
    for (pid, pval) in profiles {
        let Value::Table(p) = pval else { continue };
        let mut ids: BTreeSet<String> = raw_string_array(p, "blocklists")
            .unwrap_or_default()
            .into_iter()
            .collect();
        let cats: BTreeSet<String> = raw_string_array(p, "categories")
            .unwrap_or_default()
            .into_iter()
            .collect();
        for (list_id, cat) in &category_of {
            if cats.contains(cat) {
                ids.insert(list_id.clone());
            }
        }
        out.insert(pid.clone(), ids);
    }
    out
}

/// Translate a pre-`lists_categories_v2` config straight into v3, skipping
/// the tag model entirely.
///
/// # Why this is not `v1-to-v2` followed by `v2-to-v3`
///
/// That composition was the obvious design and it does not work. Traced
/// through the two functions it chains:
///
/// - [`apply_v1_to_v2_transformations`] step 3 does `t.remove("blocklists")`
///   on every profile. That array **is** the v3 model, one schema apart —
///   the composition begins by deleting the only thing worth carrying.
/// - Step 4 then stamps `tags = ["uncategorized"]` on every device, and
///   [`tagged_sub_profile_entities`] refuses a config whose devices carry
///   their own tags. So the chain **refuses every v1 config that has a
///   device**, on tags it wrote itself one step earlier.
/// - Suppress that refusal and it is worse, not better: step 3 also leaves
///   every profile at `tags = []`, so the tag intersection in
///   [`apply_v2_to_v3_transformations`] is empty for every pair and every
///   `(profile, list)` lands on `ignore`. The output loads, lints clean, and
///   filters **nothing** — that shape, frozen into explicit
///   config.
///
/// The direct route is also *lossless*, which the chain could never be: v1
/// had no policy axis below the profile at all (device / group / subnet tags
/// did not exist before `lists_categories_v2`), so there is nothing to
/// flatten and nothing to refuse. `v2-to-v3` refuses tagged sub-profile
/// entities because v2 really could scope a list per device; v1 could not.
///
/// # What it does
///
/// 1. Capture the v1 association ([`v1_profile_association`]) from the raw
///    table, before anything is deleted.
/// 2. Run [`apply_v1_to_v2_transformations`] unchanged — the shape change
///    (drop `[[categories]]`, drop `Blocklist.category`, seed `tags`,
///    default `unfiltered`) is the same work and is already covered by
///    `tests/migrate_v1_to_v2_golden.rs`. The tags it seeds decide nothing
///    under v3 and are removed later; reproducing that pass by hand to omit
///    them would fork a tested transformation to save a field.
/// 3. Rename `kind` → `base` on every `[[blocklists]]` row.
/// 4. Write `profiles.<id>.lists` from the captured association.
pub fn migrate_v1_to_v3(
    from_config: &Path,
    target: &Path,
    force: bool,
) -> anyhow::Result<V1ToV3Summary> {
    if !from_config.exists() {
        bail!("v1 config not found: {}", from_config.display());
    }
    if target.exists() && !force && target != from_config {
        bail!(
            "target {} already exists. Pass --force to overwrite (will replace the file). \
             Re-running on an already-migrated input is idempotent so the new \
             output should match the existing one byte-for-byte, but operator post-edits \
             would be lost.",
            target.display()
        );
    }

    let raw = std::fs::read_to_string(from_config)
        .with_context(|| format!("cannot read {}", from_config.display()))?;
    let mut root: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", from_config.display()))?;

    let mut summary = V1ToV3Summary::default();

    {
        let table = match &root {
            Value::Table(t) => t,
            _ => bail!("v1 config root must be a TOML table"),
        };
        // A v2 config reaching this verb is the dangerous input, not a
        // harmless one. `apply_v1_to_v2_transformations` would short-circuit
        // on it (`is_already_v2`), leaving `profiles.<id>.blocklists` absent
        // — so the association below would be empty for every profile and
        // every pair would be written `ignore`. That output loads and lints
        // clean while filtering nothing. Refuse by name instead.
        if is_already_v2(table) && !is_already_v3(table) {
            bail!(
                "this looks like a schema_version 2 config (no `[[categories]]`, and every \
                 `[[blocklists]]` row already carries `tags`), not a v1 one. Run \
                 `warden migrate v2-to-v3` — v1→v3 would read an empty per-profile \
                 association from it and write `ignore` for every (profile, list) pair, \
                 producing a config that loads cleanly and filters nothing."
            );
        }
    }

    // Captured BEFORE the v1→v2 pass, which deletes all three source
    // fields (`profiles.<id>.blocklists`, `profiles.<id>.categories`,
    // `[[blocklists]].category`).
    let assoc = match &root {
        Value::Table(t) => v1_profile_association(t),
        _ => unreachable!("root table checked above"),
    };

    apply_v1_to_v2_transformations(&mut root, &mut summary.v2)?;
    apply_v1_to_v3_policy(&mut root, &assoc, &mut summary)?;

    if let Value::Table(t) = &mut root {
        t.insert(
            "schema_version".into(),
            Value::Integer(SCHEMA_VERSION_V1 as i64),
        );
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    if force && target.exists() {
        eprintln!(
            "warning: --force overwrites existing target {}",
            target.display()
        );
    }

    summary.backup_path = backup_legacy(from_config)?;
    summary.v2.backup_path = summary.backup_path.clone();

    let output = toml::to_string_pretty(&root).with_context(|| "failed to serialise v3 config")?;

    let now = OffsetDateTime::now_utc();
    atomic_write_and_validate(target, &output, |staged: &Path| {
        crate::config::loader::load_config(staged, now)
            .map(|_| ())
            .map_err(|errs| {
                let mut msg = format!("{} error(s):", errs.len());
                for e in &errs {
                    msg.push_str("\n  - ");
                    msg.push_str(&e.to_string());
                }
                msg
            })
    })
    .map_err(|e| {
        anyhow!(
            "v1→v3 migration produced an invalid v3 config ({e})\n\
             legacy backup preserved at {}; {} was left unchanged.",
            summary.backup_path.display(),
            target.display()
        )
    })?;
    summary.target_path = target.to_path_buf();
    summary.v2.target_path = target.to_path_buf();

    if summary.pairs_ignored > 0 {
        summary.notes.push(format!(
            "{} (profile, list) pair(s) were written as `ignore` — the v1 profile did not \
             subscribe to those lists. Without the explicit `ignore` they would start \
             applying, because in v3 a list with no override is inherited by every profile.",
            summary.pairs_ignored
        ));
    }

    Ok(summary)
}

/// Rename `kind` → `base` and write `profiles.<id>.lists` from a captured
/// v1 association. Shares the `ignore`-by-default reasoning with
/// [`apply_v2_to_v3_transformations`]; only the `applies` predicate differs.
fn apply_v1_to_v3_policy(
    root: &mut Value,
    assoc: &BTreeMap<String, std::collections::BTreeSet<String>>,
    summary: &mut V1ToV3Summary,
) -> anyhow::Result<()> {
    let table = match root {
        Value::Table(t) => t,
        _ => bail!("v1 config root must be a TOML table"),
    };

    // A prior refactor retired the `tags` key from the data model. The loader
    // strips it at load and NOTES it, once per entity, on every load and
    // every reload — so a migrated config that still carries the key warns
    // forever, and the only way to silence it is hand-editing the file, in a
    // product whose whole premise is that the CLI owns the config.
    //
    // That noise is the same defect as silence: both teach the operator to
    // stop reading. Migration is the operator's forward path, so it is where
    // the key should die.
    //
    // The same function the loader uses, never a second copy — a strip that
    // disagreed with the loader's about what a retired key looks like would
    // be worse than no strip at all.
    for entity in crate::config::schema::retired_keys::strip_retired_tag_keys(table) {
        summary.notes.push(format!(
            "removed the retired key 'tags' from {entity} — it no longer decides anything"
        ));
        summary.entities_stripped_of_tags += 1;
    }

    // `(id, base)` in file order. `base` is read AFTER the rename below so
    // the direction written into the policy table is the same string the
    // `[[blocklists]]` row now carries — never a second derivation of it.
    let mut lists: Vec<(String, String)> = Vec::new();
    if let Some(Value::Array(rows)) = table.get_mut("blocklists") {
        for row in rows.iter_mut() {
            let Value::Table(t) = row else { continue };
            if let Some(kind) = t.remove("kind") {
                if t.contains_key("base") {
                    let id = t.get("id").and_then(Value::as_str).unwrap_or("<no id>");
                    bail!(
                        "blocklist `{id}` carries both `kind` and `base`. Delete whichever is \
                         stale and re-run — the migrator will not guess which direction you meant."
                    );
                }
                t.insert("base".into(), kind);
                summary.lists_renamed_kind_to_base += 1;
            }
            let Some(id) = t.get("id").and_then(Value::as_str) else {
                continue;
            };
            // Serde's own default for an absent `base`, spelled once.
            let base = t
                .get("base")
                .and_then(Value::as_str)
                .unwrap_or("deny")
                .to_string();
            lists.push((id.to_string(), base));
        }
    }

    let Some(Value::Table(profiles)) = table.get_mut("profiles") else {
        summary.profiles_given_lists = 0;
        return Ok(());
    };

    let mut given = 0usize;
    for (pid, pval) in profiles.iter_mut() {
        let Value::Table(p) = pval else { continue };
        // Same per-entry idempotency gate as every other arm in this file:
        // an operator who has already written overrides by hand keeps them.
        if p.contains_key("lists") {
            continue;
        }
        let subscribed = assoc.get(pid).cloned().unwrap_or_default();
        let mut policy = toml::value::Table::new();
        for (id, base) in &lists {
            // EVERY pair is written, including the ones that merely inherit
            // — same choice, and same reason, as
            // `apply_v2_to_v3_transformations`: the file is what the
            // operator reads, and the point of the workstream is that the
            // association stops being an emergent property of two arrays.
            // A half-written table restores the guessing.
            let direction = if subscribed.contains(id) {
                summary.pairs_kept += 1;
                base.as_str()
            } else {
                summary.pairs_ignored += 1;
                "ignore"
            };
            policy.insert(id.clone(), Value::String(direction.to_string()));
        }
        if policy.is_empty() {
            continue;
        }
        p.insert("lists".into(), Value::Table(policy));
        given += 1;
    }
    summary.profiles_given_lists = given;
    Ok(())
}

/// CLI entry point for `warden migrate v1-to-v3`.
pub fn run_v1_to_v3(from_config: &Path, target: &Path, force: bool) -> anyhow::Result<i32> {
    let summary = migrate_v1_to_v3(from_config, target, force)?;
    print_v1_to_v2_summary(&summary.v2);
    println!(
        "  {} profile(s) gained an explicit `lists` table: {} pair(s) kept, {} set to `ignore`",
        summary.profiles_given_lists, summary.pairs_kept, summary.pairs_ignored
    );
    println!(
        "  {} blocklist(s) had `kind` renamed to `base`",
        summary.lists_renamed_kind_to_base
    );
    for n in &summary.notes {
        println!("  - {n}");
    }
    Ok(0)
}

/// CLI entry point for `warden migrate v2-to-v3`.
pub fn run_v2_to_v3(from_config: &Path, target: &Path, force: bool) -> anyhow::Result<i32> {
    let summary = migrate_v2_to_v3(from_config, target, force)?;
    print_v2_to_v3_summary(&summary);
    Ok(0)
}

fn print_v2_to_v3_summary(s: &V2ToV3Summary) {
    println!("v2→v3 migration complete: {}", s.target_path.display());
    println!(
        "  {} profile(s) gained an explicit `lists` table: {} pair(s) kept, {} set to `ignore`",
        s.profiles_given_lists, s.pairs_kept, s.pairs_ignored
    );
    println!(
        "  {} blocklist(s) had `kind` renamed to `base`",
        s.lists_renamed_kind_to_base
    );
    println!("  legacy backup: {}", s.backup_path.display());
    if !s.notes.is_empty() {
        println!("notes for manual review:");
        for n in &s.notes {
            println!("  - {n}");
        }
    }
    println!(
        "next step: run `warden --config {} config lint` and reload the \
         daemon (`warden reload`) once the file is in place.",
        s.target_path.display()
    );
}

fn print_v1_to_v2_summary(s: &V1ToV2Summary) {
    println!("v1→v2 migration complete: {}", s.target_path.display());
    println!(
        "  {} blocklist(s) tagged `uncategorized`, {} allow-list(s) kept empty tags",
        s.blocklists_promoted_to_uncategorized, s.blocklists_kept_empty_tags
    );
    println!(
        "  {} device(s) tagged `uncategorized`, {} subnet(s) tagged empty",
        s.devices_tagged_uncategorized, s.subnets_tagged_empty
    );
    println!(
        "  {} profile(s) had `blocklists` arrays dropped, {} `[[categories]]` block(s) dropped",
        s.profiles_dropped_blocklists_field, s.categories_blocks_dropped
    );
    println!("  legacy backup: {}", s.backup_path.display());
    if !s.notes.is_empty() {
        println!("notes for manual review:");
        for n in &s.notes {
            println!("  - {n}");
        }
    }
    println!(
        "next step: run `warden --config {} config lint` and reload the \
         daemon (`warden reload`) once the file is in place.",
        s.target_path.display()
    );
}

/// Core migration routine, public for tests + programmatic callers.
///
/// The write sequence is
/// transactional via a `<target>/.staging/` directory:
///
/// 1. Pre-flight: refuse to clobber existing migration artifacts
///    unless `force` is set.
/// 2. `backup_legacy` runs BEFORE any write so a crash mid-stage
///    leaves the operator with a recoverable state (pre-fix the
///    backup landed AFTER `write_multi_file`).
/// 3. All writes land in `<target>/.staging/<class>.d/...` first;
///    the staged master is then validated end-to-end via
///    `load_config`.
/// 4. Only after validation succeeds is the staged tree promoted
///    into `<target>/` via per-file `rename(2)` (atomic within a
///    filesystem) — and the staging directory is removed.
/// 5. A staging/validation failure (step 3) wipes the staging directory
///    and leaves `<target>/` untouched. A failure *during* promote (step 4
///    — rare: post-validation intra-filesystem renames) also wipes staging
///    but may leave `<target>/` holding a partial subset of the renamed
///    files; the legacy config is never touched, so re-running with
///    `--force` completes it.
pub fn migrate(
    legacy_config: &Path,
    target: &Path,
    single_file: bool,
    force: bool,
) -> anyhow::Result<MigrationSummary> {
    if !legacy_config.exists() {
        bail!("legacy config not found: {}", legacy_config.display());
    }

    let raw = std::fs::read_to_string(legacy_config)
        .with_context(|| format!("cannot read {}", legacy_config.display()))?;
    let root: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", legacy_config.display()))?;

    let (mut config_v1, mut notes) = translate(&root)?;

    // Pre-flight: target shape + overwrite policy.
    if target.exists() {
        if !target.is_dir() {
            bail!("{} exists and is not a directory", target.display());
        }
        if target_has_existing_artifacts(target)? {
            if !force {
                bail!(
                    "{} already contains migration artifacts (config.toml or non-empty \
                     <entity>.d/). Pass --force to overwrite — the master + every \
                     auto-migrated.toml slice will be replaced; other files in \
                     <entity>.d/ stay untouched.",
                    target.display()
                );
            }
            eprintln!(
                "warning: --force overwrites the existing migration tree under {}",
                target.display()
            );
        }
    } else {
        create_dir_mode(target, 0o750)?;
    }

    // Backup BEFORE any writes hit disk so a partial
    // crash leaves the operator with a recoverable state.
    let backup_path = backup_legacy(legacy_config)?;

    // Stage into a CSPRNG-named 0o700 dir under the target
    // (same filesystem, so the promote rename(2) stays atomic) instead of a
    // predictable, EEXIST-tolerant `<target>/.staging` an attacker could
    // pre-create or symlink. The StagingDir guard wipes the staging tree on
    // every exit path (success, error, or panic), replacing the manual
    // remove_dir_all calls the previous code threaded through each arm.
    let staging = StagingDir::create_in(target)?;
    let staging_path = staging.path();

    // Stage every write; StagingDir::drop wipes the tree on any early return.
    let staged: anyhow::Result<(PathBuf, Counts)> = if single_file {
        write_monolithic(staging_path, &config_v1)
    } else {
        write_multi_file(staging_path, &mut config_v1)
    };
    let (staged_master, counts) = staged?;

    // Validate the staged tree end-to-end. load_config follows the
    // staged master's [includes] globs, which resolve relative to the
    // master's directory (staging/) — so the staged slices are picked
    // up correctly without any path rewriting.
    let now = OffsetDateTime::now_utc();
    if let Err(errs) = crate::config::loader::load_config(&staged_master, now) {
        let mut msg = format!(
            "migration produced an invalid v1 config at staged {} ({} error(s)):",
            staged_master.display(),
            errs.len()
        );
        for e in &errs {
            msg.push_str("\n  - ");
            msg.push_str(&e.to_string());
        }
        msg.push_str(&format!(
            "\nlegacy backup preserved at {}; <target>/ left untouched. \
             Fix the translator or the input config and re-run.",
            backup_path.display()
        ));
        bail!(msg);
    }

    // Promote staged tree → target. Per-file rename(2) is atomic on
    // the same filesystem; the validation step above ensures the
    // tree is internally consistent, so a partial-promote (e.g. a
    // crash between renames) leaves the target with a valid prefix
    // and the operator can re-run with --force to finish.
    // `<target>/` may hold a partial set of already-renamed files on
    // a promote failure; the legacy config is never deleted, so a `--force`
    // re-run completes the promote. StagingDir::drop wipes the staging
    // remainder on either outcome.
    let target_master = promote_staging_to_target(staging_path, target).map_err(|e| {
        e.context(format!(
            "promoting staged tree from {} to {} failed (target may hold a \
             partial tree; re-run with --force)",
            staging_path.display(),
            target.display()
        ))
    })?;

    // Surface a friendly reminder when the operator should pick a
    // `default_profile`. `translate` already pushed a note if the legacy
    // config had `block_unmapped_clients = true`; add a generic one when
    // default_profile is unset and the v1 default → REFUSED semantics might
    // surprise someone used to the v0 loose behaviour.
    if config_v1.server.default_profile.is_none() {
        notes.push(
            "server.default_profile is unset. Unmapped DNS queries will be \
             REFUSED. If that's surprising, set \
             `[server].default_profile = \"<id>\"` to a loose profile."
                .to_string(),
        );
    }

    Ok(MigrationSummary {
        devices: counts.devices,
        groups: counts.groups,
        subnets: counts.subnets,
        schedules: counts.schedules,
        blocklists: counts.blocklists,
        admin_rules: counts.admin_rules,
        profiles: counts.profiles,
        target_master,
        backup_path,
        notes,
        single_file,
    })
}

/// True when `target` already holds migration output: either
/// `<target>/config.toml` exists, or any of the known entity
/// subdirectories carry at least one file. Used by `migrate()` and
/// gated on `--force`.
fn target_has_existing_artifacts(target: &Path) -> anyhow::Result<bool> {
    if target.join("config.toml").exists() {
        return Ok(true);
    }
    for sub in [
        "devices.d",
        "profiles.d",
        "groups.d",
        "blocklists.d",
        "subnets.d",
        "schedules.d",
        "rules.d",
    ] {
        let dir = target.join(sub);
        if dir.is_dir() {
            let mut it = std::fs::read_dir(&dir)
                .with_context(|| format!("cannot read {}", dir.display()))?;
            if it.next().is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Recursively rename every file under `staging` into the matching
/// path under `target`. Directories are created as needed; existing
/// files at the destination are removed before the rename so the
/// per-file atomicity holds on overwrite. Returns the final path of
/// the master `config.toml` for use in `MigrationSummary`.
fn promote_staging_to_target(staging: &Path, target: &Path) -> anyhow::Result<PathBuf> {
    let mut master_landed: Option<PathBuf> = None;
    promote_recursive(staging, target, staging, &mut master_landed)?;
    master_landed
        .ok_or_else(|| anyhow!("internal: no config.toml landed during promote_staging_to_target"))
}

fn promote_recursive(
    cur: &Path,
    target_root: &Path,
    staging_root: &Path,
    master_landed: &mut Option<PathBuf>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(cur)
        .with_context(|| format!("cannot read staging dir {}", cur.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(staging_root)
            .expect("staging-root prefix invariant: scanned path is under staging_root");
        let dest = target_root.join(rel);

        if path.is_dir() {
            create_dir_mode(&dest, 0o750)?;
            promote_recursive(&path, target_root, staging_root, master_landed)?;
        } else {
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    create_dir_mode(parent, 0o750)?;
                }
            }
            // Overwrite-safe: rename(2) replaces the destination on
            // POSIX, but the explicit remove_file makes the --force
            // overwrite intent visible in the diff and decouples the
            // logic from kernel-specific rename atomicity edge cases.
            if dest.exists() {
                std::fs::remove_file(&dest)
                    .with_context(|| format!("cannot remove existing {}", dest.display()))?;
            }
            std::fs::rename(&path, &dest).with_context(|| {
                format!("cannot promote {} → {}", path.display(), dest.display())
            })?;
            // master_landed is the config.toml at the immediate root
            // of target (NOT the per-profile *.toml under profiles.d/).
            if dest.file_name().and_then(|n| n.to_str()) == Some("config.toml")
                && dest.parent() == Some(target_root)
            {
                *master_landed = Some(dest);
            }
        }
    }
    Ok(())
}

fn print_summary(s: &MigrationSummary) {
    println!("migration complete: {}", s.target_master.display());
    println!(
        "  {} device(s), {} group(s), {} subnet(s), {} schedule(s)",
        s.devices, s.groups, s.subnets, s.schedules
    );
    println!(
        "  {} profile(s), {} blocklist(s), {} admin rule(s)",
        s.profiles, s.blocklists, s.admin_rules
    );
    println!("  legacy backup: {}", s.backup_path.display());
    if !s.notes.is_empty() {
        println!("notes for manual review:");
        for n in &s.notes {
            println!("  - {n}");
        }
    }
    println!(
        "next step: run `warden --config {} config lint` and then point \
         the systemd unit at the new master.",
        s.target_master.display()
    );
}

// ── translation ───────────────────────────────────────────────────────

struct Counts {
    devices: usize,
    groups: usize,
    subnets: usize,
    schedules: usize,
    blocklists: usize,
    admin_rules: usize,
    profiles: usize,
}

/// Extract a [`ConfigV1`] from a raw TOML value plus a list of manual-review
/// notes. Accepts v0, v1, and mixed shapes.
pub fn translate(root_raw: &Value) -> anyhow::Result<(ConfigV1, Vec<String>)> {
    let mut notes = Vec::new();
    let mut filtered = root_raw.clone();
    let mut v0_clients: Vec<Value> = Vec::new();
    let mut v0_schedules: Vec<Value> = Vec::new();
    let mut v0_profile_extras: BTreeMap<String, V0ProfileExtras> = BTreeMap::new();
    let mut schedules_mixed: Vec<Value> = Vec::new();

    {
        let root_table = match &mut filtered {
            Value::Table(t) => t,
            _ => bail!("root must be a TOML table"),
        };

        if let Some(Value::Array(arr)) = root_table.remove("clients") {
            v0_clients = arr;
        }

        if let Some(Value::Array(arr)) = root_table.remove("schedules") {
            for item in arr {
                let has_target = matches!(&item, Value::Table(t) if t.contains_key("target_type"));
                if has_target {
                    schedules_mixed.push(item);
                } else {
                    v0_schedules.push(item);
                }
            }
        }

        if let Some(Value::Table(server)) = root_table.get_mut("server") {
            if let Some(v) = server.remove("blocked_ttl_secs") {
                // v0 blocked_ttl_secs is a per-server TTL; in v1 the
                // equivalent is server.default_blocked_ttl_secs (the
                // per-profile fallback). Forward only when the v1 field is
                // not already present, so a mixed config that already sets
                // `default_blocked_ttl_secs = 120` wins.
                server
                    .entry("default_blocked_ttl_secs")
                    .or_insert_with(|| v.clone());
            }
            if let Some(Value::Boolean(true)) = server.remove("block_unmapped_clients") {
                notes.push(
                    "server.block_unmapped_clients = true detected. This flag was removed — \
                     the equivalent v1 behaviour is leaving \
                     `server.default_profile` unset (→ REFUSED for unmapped \
                     sources). Review the produced config and, if appropriate, \
                     set `default_profile` explicitly."
                        .to_string(),
                );
                server.remove("default_profile");
            }
        }

        if let Some(Value::Table(profiles)) = root_table.get_mut("profiles") {
            for (name, p) in profiles.iter_mut() {
                if let Value::Table(prof) = p {
                    let extras = V0ProfileExtras {
                        lists: take_string_array(prof, "lists"),
                        deny: take_string_array(prof, "deny"),
                        allow: take_string_array(prof, "allow"),
                    };
                    if !extras.is_empty() {
                        v0_profile_extras.insert(name.clone(), extras);
                    }
                }
            }
        }

        // Ensure schema_version = 2 before the v1 deserialiser looks at it.
        root_table
            .entry("schema_version")
            .or_insert_with(|| Value::Integer(SCHEMA_VERSION_V1 as i64));
    }

    let mut config_v1: ConfigV1 = filtered.try_into().map_err(|e: toml::de::Error| {
        anyhow!(
            "legacy config does not parse as the v1 schema after v0-field \
             filtering: {e}. This usually means a v1-unknown top-level field \
             survived; check for stray sections."
        )
    })?;

    // Re-inject the v1-shape schedules (those that carried target_type).
    for (i, item) in schedules_mixed.into_iter().enumerate() {
        let sch: Schedule = item
            .try_into()
            .with_context(|| format!("could not parse v1-shape [[schedules]] entry #{i}"))?;
        config_v1.schedules.push(sch);
    }

    apply_v0_profile_extras(&mut config_v1, v0_profile_extras, &mut notes);

    let name_to_device_id = translate_v0_clients(&mut config_v1, v0_clients, &mut notes);
    translate_v0_schedules(&mut config_v1, v0_schedules, &name_to_device_id, &mut notes);

    // Derive legacy `[lists].sources` from `[[blocklists]]` when the v0
    // config had nothing — the downloader is still driven off `[lists]`
    // until the kebab→slash shim is retired. Leaves an explicit array in
    // the master so `warden start` picks up the right sources.
    if config_v1.lists.sources.is_empty() && !config_v1.blocklists.is_empty() {
        config_v1.lists.sources = config_v1
            .blocklists
            .iter()
            .filter(|b| b.enabled)
            .map(|b| kebab_to_slash(b.id.as_str()))
            .collect();
    }

    config_v1.schema_version = SCHEMA_VERSION_V1;
    Ok((config_v1, notes))
}

#[derive(Default)]
struct V0ProfileExtras {
    lists: Vec<String>,
    deny: Vec<String>,
    allow: Vec<String>,
}

impl V0ProfileExtras {
    fn is_empty(&self) -> bool {
        self.lists.is_empty() && self.deny.is_empty() && self.allow.is_empty()
    }
}

fn take_string_array(table: &mut toml::value::Table, key: &str) -> Vec<String> {
    match table.remove(key) {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn apply_v0_profile_extras(
    config: &mut ConfigV1,
    extras_map: BTreeMap<String, V0ProfileExtras>,
    notes: &mut Vec<String>,
) {
    for (name, extras) in extras_map {
        let profile_entry = config.profiles.entry(name.clone()).or_default();

        for slash_id in &extras.lists {
            let kebab_id = slash_to_kebab(slash_id);
            let id = match Id::new(kebab_id.clone()) {
                Ok(id) => id,
                Err(_) => {
                    notes.push(format!(
                        "profile '{name}' references legacy list '{slash_id}' \
                         (kebab-form '{kebab_id}' is not a valid v1 id) — skipped"
                    ));
                    continue;
                }
            };
            // `Profile.blocklists` was removed. The legacy v0 path no
            // longer attaches lists to profiles directly — tag
            // intersection takes over. The list itself is still
            // emitted into `[[blocklists]]` so the bitmask stays
            // populated; auto-promotion to `tags=["uncategorized"]`
            // happens at validator pass.
            let _ = profile_entry;
            if !config.blocklists.iter().any(|b| b.id == id) {
                config.blocklists.push(Blocklist {
                    id: id.clone(),
                    display_name: slash_id.clone(),
                    url: format!("https://lists.purge.cc/{slash_id}.txt"),
                    format: BlocklistFormat::Domains,
                    update_interval_hours: 12,
                    max_entries: DEFAULT_MAX_LIST_ENTRIES as u64,
                    enabled: true,
                    auth_token_ref: None,
                    base: Default::default(),
                    trust: Default::default(),
                    accept_unsigned_allow: false,
                    max_consecutive_failures: 5,
                });
            }
        }

        emit_rules(
            &mut config.admin_rules,
            &mut profile_entry.admin_rules,
            &name,
            "deny",
            &extras.deny,
            notes,
        );
        emit_rules(
            &mut config.admin_rules,
            &mut profile_entry.admin_rules,
            &name,
            "allow",
            &extras.allow,
            notes,
        );
    }
}

fn emit_rules(
    all_rules: &mut Vec<AdminRule>,
    profile_refs: &mut Vec<Id>,
    profile_name: &str,
    kind: &str,
    rules: &[String],
    notes: &mut Vec<String>,
) {
    for (j, rule_str) in rules.iter().enumerate() {
        let id_str = format!("migrated-{profile_name}-{kind}-{j}");
        let id = match Id::new(id_str.clone()) {
            Ok(id) => id,
            Err(_) => {
                notes.push(format!(
                    "could not build a valid v1 id for migrated {kind} rule #{j} \
                     in profile '{profile_name}' (tried '{id_str}')"
                ));
                continue;
            }
        };
        all_rules.push(AdminRule {
            id: id.clone(),
            rule: rule_str.clone(),
        });
        profile_refs.push(id);
    }
}

fn translate_v0_clients(
    config: &mut ConfigV1,
    v0_clients: Vec<Value>,
    notes: &mut Vec<String>,
) -> BTreeMap<String, Id> {
    let mut name_to_id: BTreeMap<String, Id> = BTreeMap::new();
    for item in v0_clients {
        let client: ClientConfig = match item.try_into() {
            Ok(c) => c,
            Err(e) => {
                notes.push(format!("failed to parse a [[clients]] entry: {e}"));
                continue;
            }
        };

        let sanitized = sanitize_id(&client.name);
        let (id, renamed_note) = match Id::new(sanitized.clone()) {
            Ok(id) => (id, None),
            Err(_) => {
                let hashed = format!("device-{}", short_hash(&client.name));
                let note = format!(
                    "client name '{}' is not a valid v1 id (derived '{sanitized}' \
                     rejected); assigned auto-generated id '{hashed}' — rename \
                     with `warden device set {hashed} ...` if you want something \
                     friendlier",
                    client.name
                );
                (
                    Id::new(hashed.clone()).expect("short_hash produces ascii"),
                    Some(note),
                )
            }
        };
        if let Some(note) = renamed_note {
            notes.push(note);
        }

        let profile = match Id::new(client.profile.clone()) {
            Ok(id) => Some(id),
            Err(_) => {
                notes.push(format!(
                    "client '{}' references profile '{}' which is not a valid v1 \
                     id — stripping the profile reference on device '{}'",
                    client.name, client.profile, id
                ));
                None
            }
        };

        let device = Device {
            id: id.clone(),
            display_name: client.name.clone(),
            ip: Some(client.ip),
            mac: client.mac.clone(),
            mac_aliases: client.mac_aliases.clone(),
            profile,
            groups: Vec::new(),
            // `device.tags` is now
            // Vec<TagSlug>. Legacy v0 free-form tags are dropped during
            // migration — auto-promote logic plus
            // `migrate v1→v2` will populate `["uncategorized"]` on the
            // device after this step.
            owner: client.owner.clone(),
            device_type: client.device_type.clone(),
            department: client.department.clone(),
            notes: client.notes.clone(),
            // Per-device overlay fields default-empty during the
            // legacy v0→v1 migration. Operators add them post-migration
            // via `warden device {allow,deny}`. Schema additive.
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        };

        name_to_id.insert(client.name.clone(), id);
        config.devices.push(device);
    }
    name_to_id
}

fn translate_v0_schedules(
    config: &mut ConfigV1,
    v0_schedules: Vec<Value>,
    name_to_device_id: &BTreeMap<String, Id>,
    notes: &mut Vec<String>,
) {
    for (i, item) in v0_schedules.into_iter().enumerate() {
        let sch: ScheduleConfig = match item.try_into() {
            Ok(s) => s,
            Err(e) => {
                notes.push(format!("failed to parse v0 [[schedules]] entry #{i}: {e}"));
                continue;
            }
        };

        let Some(device_id) = name_to_device_id.get(&sch.client) else {
            notes.push(format!(
                "v0 schedule #{i} targets client '{}' which has no corresponding \
                 [[devices]] entry — skipped",
                sch.client
            ));
            continue;
        };
        let Ok(profile_id) = Id::new(sch.profile.clone()) else {
            notes.push(format!(
                "v0 schedule #{i} profile '{}' is not a valid v1 id — skipped",
                sch.profile
            ));
            continue;
        };
        let schedule_id = match Id::new(format!("migrated-{}-{i}", sanitize_id(device_id.as_str())))
        {
            Ok(id) => id,
            Err(_) => {
                notes.push(format!(
                    "could not generate a valid schedule id for v0 schedule #{i} \
                     targeting device '{device_id}'"
                ));
                continue;
            }
        };

        config.schedules.push(Schedule {
            id: schedule_id,
            display_name: format!("Migrated schedule for {}", sch.client),
            target_type: crate::config::schema::ScheduleTargetType::Device,
            target_id: device_id.clone(),
            profile: profile_id,
            days: sch.days,
            hours: sch.hours,
            expires_at: sch.expires_at,
        });
    }
}

// ── output writers ────────────────────────────────────────────────────

fn write_multi_file(target_dir: &Path, config: &mut ConfigV1) -> anyhow::Result<(PathBuf, Counts)> {
    let counts = Counts {
        devices: config.devices.len(),
        groups: config.groups.len(),
        subnets: config.subnets.len(),
        schedules: config.schedules.len(),
        blocklists: config.blocklists.len(),
        admin_rules: config.admin_rules.len(),
        profiles: config.profiles.len(),
    };

    config.includes = vec![
        "devices.d/*.toml".to_string(),
        "profiles.d/*.toml".to_string(),
        "groups.d/*.toml".to_string(),
        "blocklists.d/*.toml".to_string(),
        "subnets.d/*.toml".to_string(),
        "schedules.d/*.toml".to_string(),
        "rules.d/*.toml".to_string(),
    ];

    write_array_file(target_dir, "devices.d", "devices", &config.devices)?;
    write_array_file(target_dir, "groups.d", "groups", &config.groups)?;
    write_array_file(target_dir, "subnets.d", "subnets", &config.subnets)?;
    write_array_file(target_dir, "blocklists.d", "blocklists", &config.blocklists)?;
    write_array_file(target_dir, "schedules.d", "schedules", &config.schedules)?;
    write_array_file(target_dir, "rules.d", "admin_rules", &config.admin_rules)?;
    write_profiles(target_dir, &config.profiles)?;

    // Clone the full config; the master keeps `retired` (a ledger, not
    // a `.d/`-splittable entity class) plus every pass-through daemon
    // section. Entity collections are cleared because they now live in
    // the `.d/` files.
    let mut master_cfg = config.clone();
    master_cfg.devices.clear();
    master_cfg.groups.clear();
    master_cfg.subnets.clear();
    master_cfg.schedules.clear();
    master_cfg.blocklists.clear();
    master_cfg.admin_rules.clear();
    master_cfg.profiles.clear();

    let master_path = target_dir.join("config.toml");
    let master_str =
        toml::to_string_pretty(&master_cfg).context("failed to serialise v1 master config")?;
    migration_atomic_write(&master_path, &master_str)?;

    Ok((master_path, counts))
}

fn write_monolithic(target_dir: &Path, config: &ConfigV1) -> anyhow::Result<(PathBuf, Counts)> {
    let counts = Counts {
        devices: config.devices.len(),
        groups: config.groups.len(),
        subnets: config.subnets.len(),
        schedules: config.schedules.len(),
        blocklists: config.blocklists.len(),
        admin_rules: config.admin_rules.len(),
        profiles: config.profiles.len(),
    };

    let master_path = target_dir.join("config.toml");
    let s = toml::to_string_pretty(config).context("failed to serialise v1 config")?;
    migration_atomic_write(&master_path, &s)?;

    Ok((master_path, counts))
}

fn write_array_file<T: Serialize>(
    target_dir: &Path,
    subdir: &str,
    key: &str,
    items: &[T],
) -> anyhow::Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let dir = target_dir.join(subdir);
    create_dir_mode(&dir, 0o750)?;

    let mut arr = Vec::with_capacity(items.len());
    for item in items {
        let v = Value::try_from(item).with_context(|| format!("serialise {key} entry"))?;
        arr.push(v);
    }
    let mut root = toml::value::Table::new();
    root.insert(key.to_string(), Value::Array(arr));
    let body = toml::to_string_pretty(&Value::Table(root))
        .with_context(|| format!("serialise {key} file"))?;

    migration_atomic_write(&dir.join("auto-migrated.toml"), &body)
}

fn write_profiles(target_dir: &Path, profiles: &BTreeMap<String, Profile>) -> anyhow::Result<()> {
    if profiles.is_empty() {
        return Ok(());
    }
    let dir = target_dir.join("profiles.d");
    create_dir_mode(&dir, 0o750)?;

    for (id_str, prof) in profiles {
        let safe_filename = sanitize_filename(id_str);
        let path = dir.join(format!("{safe_filename}.toml"));

        let mut root = toml::value::Table::new();
        let mut profiles_tbl = toml::value::Table::new();
        profiles_tbl.insert(
            id_str.clone(),
            Value::try_from(prof).with_context(|| format!("serialise profile '{id_str}'"))?,
        );
        root.insert("profiles".to_string(), Value::Table(profiles_tbl));

        let body = toml::to_string_pretty(&Value::Table(root))
            .with_context(|| format!("serialise profile file for '{id_str}'"))?;
        migration_atomic_write(&path, &body)?;
    }
    Ok(())
}

// ── backup ────────────────────────────────────────────────────────────

fn backup_legacy(legacy_config: &Path) -> anyhow::Result<PathBuf> {
    let parent = legacy_config
        .parent()
        .ok_or_else(|| anyhow!("legacy config path has no parent directory"))?;
    let backup_dir = parent.join("backups");
    std::fs::create_dir_all(&backup_dir)
        .with_context(|| format!("cannot create {}", backup_dir.display()))?;
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown-time".to_string())
        .replace(':', "-");
    // Bump the name on a same-second collision so a rapid re-run can't
    // silently overwrite the pre-migration rollback copy.
    let path =
        crate::cli::commands::make_unique_path(backup_dir.join(format!("pre-migration-{ts}.toml")));
    std::fs::copy(legacy_config, &path).with_context(|| {
        format!(
            "cannot copy {} to backup at {}",
            legacy_config.display(),
            path.display()
        )
    })?;
    Ok(path)
}

// ── id + filename helpers ─────────────────────────────────────────────

/// Convert a legacy v0 slash-form list id (`"privacy/ads"`) to a v1 kebab id
/// (`"privacy-ads"`). Only the first `/` is replaced so nested paths
/// (`"corp/internal/ads"`) round-trip sensibly to `"corp-internal/ads"`
/// which the validator will reject, producing a clear manual-review note.
fn slash_to_kebab(s: &str) -> String {
    s.replacen('/', "-", 1).to_lowercase()
}

/// Inverse of [`slash_to_kebab`] for the first dash only. Used to populate
/// the legacy `[lists].sources` array from `[[blocklists]]` when the v0
/// config had no explicit `[lists]` section. Round-trips the common
/// `"privacy-ads"` → `"privacy/ads"` case; leaves multi-dash ids without
/// forcing a path structure the operator may not want.
fn kebab_to_slash(s: &str) -> String {
    s.replacen('-', "/", 1)
}

/// Turn an arbitrary string into a candidate v1 [`Id`]. Lowercases, replaces
/// whitespace/underscores/dots with `-`, collapses runs of dashes, strips
/// any byte outside `[a-z0-9-]`. The result may still be empty or a lone
/// dash — the caller tries `Id::new` and falls back to a hashed id when
/// the candidate is unusable.
fn sanitize_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if matches!(c, ' ' | '_' | '.' | '/' | '\\' | '-') && !out.ends_with('-') {
            out.push('-');
        }
        // Silently drop everything else (accented chars, CJK, etc.).
    }
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Stable 8-hex-digit fingerprint used for fallback ids. Not collision-free;
/// the operator is expected to rename the auto-generated ids via
/// `warden device set` after reviewing them.
fn short_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:08x}", (h.finish() & 0xffff_ffff) as u32)
}

/// Sanitize a profile id for use as a filename. Same rules as [`sanitize_id`]
/// but more forgiving of pathological inputs: returns `"profile"` if the
/// cleaned form is empty.
fn sanitize_filename(id: &str) -> String {
    let cleaned = sanitize_id(id);
    if cleaned.is_empty() {
        "profile".to_string()
    } else {
        cleaned
    }
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// **Both migration paths strip the retired `tags` key, and the test
    /// covers BOTH on purpose.**
    ///
    /// `v1-to-v3` does not chain through `apply_v2_to_v3_transformations` —
    /// it carries its own copy of the `kind` → `base` rename — so the strip
    /// had to be added twice. This repo has already paid for the other
    /// outcome: a two-caller helper where only one caller was fixed is worse
    /// than one where neither was, because the green test on the fixed path
    /// reads as coverage of both.
    ///
    /// A migrated config that still carries `tags` LOADS — the loader strips
    /// it — so no existing test would have gone red. It would simply have
    /// NOTED once per entity at every load, forever. That is what this pins.
    #[test]
    fn both_migration_paths_strip_the_retired_tags_key() {
        const CARRIES_TAGS: &str = r#"
[[blocklists]]
id = "privacy-ads"
url = "https://lists.example.test/ads.txt"
kind = "deny"
tags = ["uncategorized"]

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]
"#;

        // --- v2 -> v3 ---
        let mut root: Value = toml::from_str(CARRIES_TAGS).expect("fixture parses");
        let mut s2 = V2ToV3Summary::default();
        apply_v2_to_v3_transformations(&mut root, &mut s2).expect("v2->v3 transforms");
        let out2 = toml::to_string(&root).expect("v2->v3 output serialises");
        assert!(
            !out2.contains("tags"),
            "v2->v3 left a retired `tags` key behind:\n{out2}"
        );
        assert_eq!(
            s2.entities_stripped_of_tags, 2,
            "one blocklist + one profile carried it; the count is what the \
             operator is shown, so a silent strip would be its own defect"
        );

        // --- v1 -> v3: a SEPARATE code path, not a chain ---
        let mut root: Value = toml::from_str(CARRIES_TAGS).expect("fixture parses");
        let mut s1 = V1ToV3Summary::default();
        let assoc = std::collections::BTreeMap::new();
        apply_v1_to_v3_policy(&mut root, &assoc, &mut s1).expect("v1->v3 transforms");
        let out1 = toml::to_string(&root).expect("v1->v3 output serialises");
        assert!(
            !out1.contains("tags"),
            "v1->v3 left a retired `tags` key behind — the second caller is \
             exactly the one a single-path test would miss:\n{out1}"
        );
        assert_eq!(s1.entities_stripped_of_tags, 2);
    }

    /// The strip must run AFTER the migration has read the tags, and this is
    /// the test that says so.
    ///
    /// `both_migration_paths_strip_the_retired_tags_key` above uses a fixture
    /// of exactly this shape and **passed while the migration was destroying
    /// every policy it wrote**, because it asserts only that `tags` is gone
    /// and that the count is 2 — and both of those are true of an output in
    /// which every pair was silently set to `ignore`. A test that cannot fail
    /// on the defect its own fixture reproduces is decoration.
    ///
    /// The fixture here is deliberately **asymmetric and two-by-two**: two
    /// profiles with different tag sets, two lists with different tags, so the
    /// expected matrix has both `deny` and `ignore` in it and in different
    /// places per profile. A single-profile or single-list fixture cannot
    /// discriminate "the intersection was computed" from "everything was
    /// kept" or "everything was dropped" — all three agree on a 1x1 matrix.
    #[test]
    fn v2_to_v3_snapshots_the_tag_intersection_before_stripping_tags() {
        const SRC: &str = r#"
[[blocklists]]
id = "ads"
url = "https://lists.example.test/ads.txt"
kind = "deny"
tags = ["general"]

[[blocklists]]
id = "adult"
url = "https://lists.example.test/adult.txt"
kind = "deny"
tags = ["kids-only"]

[profiles.default]
display_name = "Default"
tags = ["general"]

[profiles.kids]
display_name = "Kids"
tags = ["general", "kids-only"]
"#;

        let mut root: Value = toml::from_str(SRC).expect("fixture parses");
        let mut summary = V2ToV3Summary::default();
        apply_v2_to_v3_transformations(&mut root, &mut summary).expect("transforms");

        let policy = |profile: &str, list: &str| -> String {
            root.get("profiles")
                .and_then(|p| p.get(profile))
                .and_then(|p| p.get("lists"))
                .and_then(|l| l.get(list))
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>")
                .to_string()
        };

        // `default` carried only `general`, so it reached `ads` and not `adult`.
        assert_eq!(
            policy("default", "ads"),
            "deny",
            "default was tagged `general` and so was `ads` — the pair applied              under v2 and must survive as `deny`. `ignore` here means the tags              were stripped before the intersection ran, which turns a filtering              config into an inert one that still lints clean."
        );
        assert_eq!(
            policy("default", "adult"),
            "ignore",
            "default never carried `kids-only`, so this list did not reach it              under v2. Writing `deny` would make the migration START blocking              something the operator had not chosen."
        );

        // `kids` carried both tags, so it reached both lists.
        assert_eq!(policy("kids", "ads"), "deny");
        assert_eq!(
            policy("kids", "adult"),
            "deny",
            "kids carried `kids-only` and so did `adult` — the one pair that              distinguishes the two profiles. If this reads `ignore` while the              others are right, the profile side of the intersection is broken."
        );

        assert_eq!(summary.pairs_kept, 3, "3 of the 4 pairs applied under v2");
        assert_eq!(summary.pairs_ignored, 1, "only default x adult did not");

        // And the retired key is still gone from the output — the strip did
        // run, it just ran last.
        let out = toml::to_string(&root).expect("serialises");
        assert!(!out.contains("tags"), "retired key survived:\n{out}");
        assert_eq!(summary.entities_stripped_of_tags, 4);
    }

    #[test]
    fn slash_to_kebab_first_only() {
        assert_eq!(slash_to_kebab("privacy/ads"), "privacy-ads");
        assert_eq!(slash_to_kebab("security/malicious"), "security-malicious");
    }

    #[test]
    fn sanitize_id_drops_unsupported() {
        // The apostrophe is silently dropped (not in the
        // whitespace/punctuation → dash set), so "Alice's" → "alices".
        // The space between "Alice's" and "iPad" becomes a single dash.
        assert_eq!(sanitize_id("Alice's iPad"), "alices-ipad");
        assert_eq!(sanitize_id("tablet_01"), "tablet-01");
        assert_eq!(sanitize_id("__weird__"), "weird");
        // Accented chars are dropped entirely (charset is ASCII lowercase).
        assert_eq!(sanitize_id("caffè"), "caff");
        assert_eq!(sanitize_id("Operator iPhone"), "operator-iphone");
    }

    #[test]
    fn short_hash_is_stable_and_ascii() {
        let a = short_hash("hello");
        let b = short_hash("hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn translate_pure_v1_monolith_is_noop_passthrough() {
        let src = r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert_eq!(cfg.schema_version, 3);
        assert_eq!(cfg.blocklists.len(), 1);
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].id.as_str(), "iphone");
        // [lists].sources is derived from [[blocklists]] when absent.
        assert!(cfg.lists.sources.iter().any(|s| s == "privacy/ads"));
    }

    #[test]
    fn translate_v0_clients_become_devices() {
        let src = r#"
[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]

[profiles.default]
lists = ["privacy/ads"]

[[clients]]
name = "iphone"
ip = "10.10.1.107"
profile = "default"
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].id.as_str(), "iphone");
        assert_eq!(cfg.devices[0].ip, Some("10.10.1.107".parse().unwrap()));
        // v0 profile.lists -> blocklists + [[blocklists]] entry
        assert_eq!(cfg.blocklists.len(), 1);
        assert_eq!(cfg.blocklists[0].id.as_str(), "privacy-ads");
        // surface-5m: the v0->v1 migration path used to hardcode
        // `max_entries: 5_000_000` here — a stale copy of the daemon-wide
        // default. With the fail-closed corpus guard, a migrated list
        // over that stale cap would be refused whole on the next
        // refresh instead of truncated.
        assert_eq!(
            cfg.blocklists[0].max_entries,
            crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES as u64,
            "migrated blocklist must inherit the shared default max_entries"
        );
        let _default_prof = cfg.profiles.get("default").unwrap();
        // `Profile.blocklists` is
        // gone. The list is still emitted into `[[blocklists]]`
        // (asserted above); tag intersection takes over for
        // the per-profile applicability check.
    }

    #[test]
    fn translate_v0_profile_deny_allow_become_admin_rules() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"

[profiles.default]
deny = ["||tiktok.com^"]
allow = ["@@||github.com^"]
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert_eq!(cfg.admin_rules.len(), 2);
        let default_prof = cfg.profiles.get("default").unwrap();
        assert_eq!(default_prof.admin_rules.len(), 2);
        // rule strings preserved
        let rules: Vec<&str> = cfg.admin_rules.iter().map(|r| r.rule.as_str()).collect();
        assert!(rules.contains(&"||tiktok.com^"));
        assert!(rules.contains(&"@@||github.com^"));
    }

    #[test]
    fn translate_v0_schedule_maps_client_to_device() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"

[profiles.default]
lists = ["privacy/ads"]

[profiles.night]
block_all = true

[[clients]]
name = "tablet"
ip = "10.10.1.50"
profile = "default"

[[schedules]]
client = "tablet"
profile = "night"
days = ["weekdays"]
hours = "21:00-07:00"
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert_eq!(cfg.schedules.len(), 1);
        let sch = &cfg.schedules[0];
        assert_eq!(
            sch.target_type,
            crate::config::schema::ScheduleTargetType::Device
        );
        assert_eq!(sch.target_id.as_str(), "tablet");
        assert_eq!(sch.profile.as_str(), "night");
    }

    #[test]
    fn block_unmapped_clients_true_surfaces_note() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"
block_unmapped_clients = true
"#;
        let root: Value = src.parse().unwrap();
        let (_cfg, notes) = translate(&root).unwrap();
        assert!(notes.iter().any(|n| n.contains("block_unmapped_clients")));
    }

    #[test]
    fn end_to_end_migrate_writes_split_tree() {
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let target = tmp.path().join("etc-purge-warden");

        let summary = migrate(&legacy, &target, false, false).unwrap();
        assert_eq!(summary.devices, 1);
        assert_eq!(summary.profiles, 1);
        assert_eq!(summary.blocklists, 1);

        assert!(target.join("config.toml").exists());
        assert!(target.join("devices.d/auto-migrated.toml").exists());
        assert!(target.join("blocklists.d/auto-migrated.toml").exists());
        assert!(target.join("profiles.d/default.toml").exists());

        // backup exists
        let backups_dir = legacy.parent().unwrap().join("backups");
        let entries: Vec<_> = std::fs::read_dir(&backups_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);

        // The produced config lints cleanly via load_config
        let now = OffsetDateTime::now_utc();
        crate::config::loader::load_config(&summary.target_master, now)
            .expect("migrated config should lint clean");
    }

    /// Every migrated `*.d/` dir (and the fresh target
    /// root) lands `0o750`, not the umask-default `0o755` — the slice
    /// filenames leak device/profile ids and must not be world-listable.
    #[test]
    fn migrate_hardens_d_dir_modes_to_0750() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let target = tmp.path().join("etc-purge-warden");
        migrate(&legacy, &target, false, false).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&target), 0o750, "fresh target root must be 0o750");
        for d in ["devices.d", "profiles.d", "blocklists.d"] {
            let dir = target.join(d);
            assert_eq!(mode(&dir), 0o750, "{d} must be 0o750");
        }
    }

    #[test]
    fn end_to_end_migrate_single_file() {
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let target = tmp.path().join("etc-purge-warden");
        let summary = migrate(&legacy, &target, true, false).unwrap();
        assert!(summary.single_file);
        assert!(target.join("config.toml").exists());
        // No subdirs in single-file mode
        assert!(!target.join("devices.d").exists());
        assert!(!target.join("blocklists.d").exists());
    }

    // ── preserve explicit `query_log_enabled` ──────────
    // A past incident had the v0→v1 migrator silently overwrite
    // an operator's explicit `query_log_enabled = true` with the struct
    // default (which used to be `false`). These three tests pin
    // the invariants so any future refactor of `translate()` or the
    // `TrackingConfig` serde wiring that regresses them fails loudly.

    #[test]
    fn migrator_preserves_explicit_query_log_enabled_false() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"

[tracking]
query_log_enabled = false
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert!(
            !cfg.tracking.query_log_enabled,
            "explicit false on the v0 master must survive the migration"
        );
    }

    #[test]
    fn migrator_preserves_explicit_query_log_enabled_true() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"

[tracking]
query_log_enabled = true
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert!(
            cfg.tracking.query_log_enabled,
            "explicit true on the v0 master must survive the migration"
        );
    }

    #[test]
    fn migrator_uses_new_default_when_v0_has_no_tracking_section() {
        // The scenario: an old backup had no `[tracking]`
        // at all; the old migrator emitted `query_log_enabled = false`
        // via the struct default. The struct default is now
        // `true`, so an absent section now yields logging on.
        let src = r#"
[server]
listen = "127.0.0.1:5335"
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, _notes) = translate(&root).unwrap();
        assert!(
            cfg.tracking.query_log_enabled,
            "absent [tracking] section must pick up the new struct default"
        );
    }

    #[test]
    fn unparseable_client_name_falls_back_to_hashed_id() {
        let src = r#"
[server]
listen = "127.0.0.1:5335"

[profiles.default]
lists = ["privacy/ads"]

[[clients]]
name = "Alice's iPad"
ip = "10.10.1.108"
profile = "default"
"#;
        let root: Value = src.parse().unwrap();
        let (cfg, notes) = translate(&root).unwrap();
        assert_eq!(cfg.devices.len(), 1);
        let dev = &cfg.devices[0];
        // Display name keeps the human form
        assert_eq!(dev.display_name, "Alice's iPad");
        // Sanitisation lowercases, drops the apostrophe, converts space
        // to dash → "alices-ipad", which is a valid v1 Id. No hash
        // fallback needed.
        assert_eq!(dev.id.as_str(), "alices-ipad");
        // No rename note because sanitisation succeeded.
        assert!(!notes.iter().any(|n| n.contains("auto-generated")));
    }

    // ── idempotency + transactional + no-overwrite ─────────

    /// A second run of `apply_v1_to_v2_transformations` on an
    /// already-transformed document is a no-op. Operator-set tags
    /// survive byte-identical.
    #[test]
    fn migrate_v1_to_v2_is_idempotent_byte_identical() {
        let tmp = tmpdir();
        let from = tmp.path().join("v1.toml");
        std::fs::write(
            &from,
            r##"schema_version = 2

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"
format = "domains"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"##,
        )
        .unwrap();
        let target_a = tmp.path().join("v2-a.toml");
        let target_b = tmp.path().join("v2-b.toml");

        migrate_v1_to_v2(&from, &target_a, false).unwrap();
        let first = std::fs::read_to_string(&target_a).unwrap();

        // Feed the FIRST output back through the migrator. The result
        // must match byte-for-byte — operator-set tags / unfiltered /
        // dropped-blocklists fields are all already present.
        migrate_v1_to_v2(&target_a, &target_b, false).unwrap();
        let second = std::fs::read_to_string(&target_b).unwrap();
        assert_eq!(
            first, second,
            "second-run output must be byte-identical to the first"
        );
    }

    /// Operator-set tags on devices survive a re-run. Previously
    /// the unconditional `t.insert("tags", ["uncategorized"])` would
    /// clobber a `tags = ["family"]` the operator added by hand.
    #[test]
    fn migrate_v1_to_v2_preserves_operator_tags_on_rerun() {
        let tmp = tmpdir();
        let from = tmp.path().join("v1.toml");
        std::fs::write(
            &from,
            r##"schema_version = 2

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"
tags = ["family"]
format = "domains"

[profiles.default]
display_name = "Default"
tags = ["family"]

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"
tags = ["family"]
unfiltered = false

[upstream]
servers = ["192.0.2.1:53"]
"##,
        )
        .unwrap();
        let target = tmp.path().join("v2.toml");

        migrate_v1_to_v2(&from, &target, false).unwrap();
        let body = std::fs::read_to_string(&target).unwrap();
        let parsed: Value = body.parse().unwrap();
        let table = parsed.as_table().unwrap();
        let devices = table
            .get("devices")
            .and_then(|v| v.as_array())
            .expect("devices array");
        let dev = devices[0].as_table().unwrap();
        let tags = dev.get("tags").and_then(|v| v.as_array()).unwrap();
        let tag_strs: Vec<&str> = tags.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            tag_strs,
            vec!["family"],
            "operator-set device.tags must survive the migration"
        );
        // `unfiltered=false` is the v2 default; verify it survives a
        // re-run without being toggled. (The validator forbids
        // `unfiltered=true` with non-empty tags — that combination
        // belongs in a separate test.)
        assert_eq!(
            dev.get("unfiltered").and_then(|v| v.as_bool()),
            Some(false),
            "operator-set unfiltered=false must survive the migration"
        );
        let bls = table.get("blocklists").and_then(|v| v.as_array()).unwrap();
        let bl = bls[0].as_table().unwrap();
        let bl_tags: Vec<&str> = bl
            .get("tags")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            bl_tags,
            vec!["family"],
            "operator-set blocklist.tags must survive the migration"
        );
    }

    /// The `is_already_v2` short-circuit. A document where
    /// every blocklist already carries `tags` and there's no
    /// [[categories]] block is detected as already-migrated; the
    /// transformation logs and returns Ok without mutating summary.
    #[test]
    fn is_already_v2_short_circuits_on_tagged_blocklists() {
        let src = r##"
[[blocklists]]
id = "x"
url = "https://example.com/x.txt"
tags = ["uncategorized"]

[[devices]]
id = "d"
tags = ["family"]
"##;
        let mut root: Value = src.parse().unwrap();
        let mut summary = V1ToV2Summary::default();
        apply_v1_to_v2_transformations(&mut root, &mut summary).unwrap();
        // Every counter stays zero because the short-circuit fires.
        assert_eq!(summary.blocklists_promoted_to_uncategorized, 0);
        assert_eq!(summary.blocklists_kept_empty_tags, 0);
        assert_eq!(summary.devices_tagged_uncategorized, 0);
    }

    /// A re-run of `migrate()` against a populated target
    /// refuses without `--force`.
    #[test]
    fn migrate_v0_v1_refuses_populated_target_without_force() {
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let target = tmp.path().join("etc-purge-warden");
        migrate(&legacy, &target, false, false).unwrap();
        assert!(target.join("config.toml").exists());

        // Second run without --force: must bail.
        let err = migrate(&legacy, &target, false, false).expect_err("must refuse");
        assert!(
            err.to_string().contains("--force"),
            "error must mention --force; got: {err}"
        );
    }

    /// Happy-path: --force unlocks the overwrite. Pre-condition
    /// is the same as the refuse test — `migrate()` ran once and
    /// produced a tree. The second run with force succeeds and the
    /// master is replaced.
    #[test]
    fn migrate_v0_v1_force_unlocks_overwrite() {
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let target = tmp.path().join("etc-purge-warden");
        migrate(&legacy, &target, false, false).unwrap();
        // Second run with --force succeeds.
        let result = migrate(&legacy, &target, false, true);
        assert!(
            result.is_ok(),
            "--force must unlock overwrite, got: {:?}",
            result.err()
        );
    }

    /// Transactional invariant: when the staged tree fails
    /// validation, target/ remains untouched and the staging dir is
    /// cleaned up. Force a validation failure by handing the migrator
    /// a translatable-but-impossible config — a `default_profile`
    /// pointing at a profile that does not exist (the loader rejects
    /// this in `validate.rs`).
    #[test]
    fn migrate_v0_v1_transactional_cleanup_on_validator_failure() {
        let tmp = tmpdir();
        let legacy = tmp.path().join("legacy.toml");
        std::fs::write(
            &legacy,
            r#"
schema_version = 2

[server]
listen = "0.0.0.0:53"
allow_from = ["10.0.0.0/8"]
default_profile = "missing-profile"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let target = tmp.path().join("etc-purge-warden");
        let err = migrate(&legacy, &target, false, false).expect_err("must fail validation");
        assert!(
            err.to_string().contains("invalid v1 config"),
            "must surface the validation error; got: {err}"
        );

        // Target dir was created (it's our staging parent) but holds
        // NO migration artifacts — only the staging dir itself, which
        // must have been cleaned up.
        assert!(
            !target.join("config.toml").exists(),
            "target master must not exist after validation failure"
        );
        // The CSPRNG-named staging dir is wiped by the
        // StagingDir guard on the validation-failure return — no leftover
        // `purge-warden-stage-*` dir under target.
        let leftover = std::fs::read_dir(&target).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("purge-warden-stage-")
        });
        assert!(
            !leftover,
            "staging dir must be cleaned up after validation failure"
        );
    }

    /// `migrate_v1_to_v2()` refuses to overwrite an existing
    /// target without `--force`.
    #[test]
    fn migrate_v1_to_v2_refuses_populated_target_without_force() {
        let tmp = tmpdir();
        let from = tmp.path().join("v1.toml");
        std::fs::write(
            &from,
            r##"schema_version = 2

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"##,
        )
        .unwrap();
        let target = tmp.path().join("v2.toml");
        std::fs::write(&target, "pre-existing operator-edited content").unwrap();

        let err = migrate_v1_to_v2(&from, &target, false).expect_err("must refuse");
        assert!(
            err.to_string().contains("--force"),
            "error must mention --force; got: {err}"
        );
        // The pre-existing content must be untouched on failure.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "pre-existing operator-edited content"
        );
    }

    /// Happy-path: --force unlocks the v1→v2 overwrite.
    #[test]
    fn migrate_v1_to_v2_force_unlocks_overwrite() {
        let tmp = tmpdir();
        let from = tmp.path().join("v1.toml");
        std::fs::write(
            &from,
            r##"schema_version = 2

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"##,
        )
        .unwrap();
        let target = tmp.path().join("v2.toml");
        std::fs::write(&target, "pre-existing").unwrap();

        let result = migrate_v1_to_v2(&from, &target, true);
        assert!(
            result.is_ok(),
            "--force must unlock overwrite, got: {:?}",
            result.err()
        );
        assert_ne!(
            std::fs::read_to_string(&target).unwrap(),
            "pre-existing",
            "target must have been overwritten under --force"
        );
    }
}
