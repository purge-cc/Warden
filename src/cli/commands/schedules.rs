//! `warden schedule` — inspect and remove `[[schedules]]` entries, plus
//! the shared expired-schedule prune.
//!
//! Deliberately NOT full CRUD: schedules are authored via `warden device
//! quiet` (one-shot) or directly in TOML (recurring). This module is the
//! recovery/inspection path the rev-2606 schema-validator-01 escalation
//! called out — before it existed, a leftover quiet schedule could only
//! be removed by hand-editing the config.
//!
//! The prune intentionally avoids `write_config_v1`: re-serialising the
//! merged tree onto the master flattens (or is refused on) multi-file
//! layouts. Instead each file that actually contains an expired row gets
//! per-file `toml::Value` surgery through the same hardened seats every
//! entity verb uses.

use std::path::Path;

use anyhow::{bail, Context};
use toml::Value;

use super::format_config_errors;
use super::ipc_reload;
use super::target::{
    read_or_empty, remove_id_keyed, write_value_validated, write_values_validated, StagedWrite,
};
use crate::config::loader::{load_config, LoadedConfig};
use crate::profiles::schedule::{local_now, ParsedSchedule};

/// Remove every `[[schedules]]` row whose `expires_at` is in the past
/// from the file that defines it. Returns the pruned ids.
///
/// Callers treat failure as non-fatal: an expired row is inert at
/// resolver build (`ParsedSchedule::is_active` checks expiry first), so
/// the prune is hygiene, never correctness. Call sites: the daemon's
/// 60-second schedule tick and `warden device quiet`'s pre-clean.
///
/// Multi-file safe: only files from the loaded include graph that
/// actually contain an expired row are rewritten. If the post-prune
/// aggregate validation fails, every touched file is restored to its
/// pre-prune bytes.
pub fn prune_expired_schedules(
    config_path: &Path,
    loaded: &LoadedConfig,
    now: time::OffsetDateTime,
) -> anyhow::Result<Vec<String>> {
    let expired: Vec<String> = loaded
        .config
        .schedules
        .iter()
        .filter(|s| s.expires_at.is_some_and(|exp| exp <= now))
        .map(|s| s.id.as_str().to_string())
        .collect();
    if expired.is_empty() {
        return Ok(Vec::new());
    }

    let mut pruned: Vec<String> = Vec::new();
    let mut writes: Vec<StagedWrite> = Vec::new();
    for file in &loaded.files_loaded {
        let (mut doc, _) = read_or_empty(file)?;
        let mut changed = false;
        for id in &expired {
            if remove_id_keyed(&mut doc, "schedules", id)? {
                pruned.push(id.clone());
                changed = true;
            }
        }
        if changed {
            writes.push(StagedWrite {
                final_path: file.clone(),
                content: toml::to_string_pretty(&doc)?,
            });
        }
    }

    // Validate the merged tree against ALL prunes at once, BEFORE promoting
    // any file, then promote with rollback (write_values_validated owns both,
    // rev2606 target-01). Removing a schedule can't dangle a reference, so the
    // promotion order is immaterial; this replaces the former write-each-then-
    // aggregate-load-then-revert dance.
    if !writes.is_empty() {
        write_values_validated(config_path, &writes)?;
    }
    Ok(pruned)
}

/// Render a schedule's target type exactly as it is spelled in TOML.
///
/// `schedule list` used to print this with `{:?}`, which renders the Rust
/// variant name: `Device:tablet`. But `ScheduleTargetType` carries
/// `#[serde(rename_all = "lowercase")]`, so the value an operator must
/// actually write is `target_type = "device"`. The one surface that shows
/// you what is configured was spelling it differently from the file you
/// have to edit — and this module's whole reason to exist is being the
/// recovery path for a schedule you now have to remove by hand.
///
/// The match is exhaustive on purpose: a third variant fails to compile
/// here rather than silently reintroducing the mismatch.
/// The test `target_type_rendering_matches_the_serialised_form` pins it
/// against serde so the two cannot drift apart either.
///
/// Named in a plain code span rather than as an intra-doc link: it lives
/// in this file's `#[cfg(test)] mod tests`, which rustdoc does not
/// compile, so the link resolved to nothing and failed the doc gate —
/// while tests, clippy and fmt all stayed green on it.
fn target_type_toml_value(t: crate::config::schema::schedule::ScheduleTargetType) -> &'static str {
    use crate::config::schema::schedule::ScheduleTargetType as T;
    match t {
        T::Device => "device",
        T::Group => "group",
    }
}

/// `warden schedule list` — every `[[schedules]]` entry with its window
/// and current state. Works offline (reads config directly).
pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.schedules.is_empty() {
        println!("no schedules configured");
        println!(
            "one-shot schedules are created by `warden device quiet <id> --for <duration>`; \
             recurring ones live as [[schedules]] entries in the config"
        );
        return Ok(());
    }
    println!("configured schedules ({}):", loaded.config.schedules.len());
    let (weekday, hour, minute) = local_now();
    for s in &loaded.config.schedules {
        let expires = match s.expires_at {
            Some(exp) => exp
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| exp.to_string()),
            None => "-".to_string(),
        };
        let state = if s.expires_at.is_some_and(|exp| exp <= now) {
            "expired"
        } else {
            match ParsedSchedule::parse_v1(s) {
                Some(p) if p.is_active(weekday, hour, minute) => "active",
                Some(_) => "inactive",
                // Validation guarantees parseable days/hours; belt and
                // braces for hand-edited files loaded with --safe-mode.
                None => "invalid",
            }
        };
        println!(
            "  {id} \"{name}\" {ttype}:{target} profile={prof} days={days} hours={hours} \
             expires={expires} [{state}]",
            id = s.id.as_str(),
            name = s.display_name,
            ttype = target_type_toml_value(s.target_type),
            target = s.target_id.as_str(),
            prof = s.profile.as_str(),
            days = s.days.join(","),
            hours = s.hours,
        );
    }
    Ok(())
}

/// `warden schedule remove <id>` — drop one `[[schedules]]` row from the
/// file that defines it. Works on active entries too: removing a live
/// quiet schedule un-quiets the device early.
pub async fn run_remove(config_path: &Path, socket_path: &Path, id: &str) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if !loaded.config.schedules.iter().any(|s| s.id.as_str() == id) {
        bail!(
            "no schedule named \"{id}\". Run `warden schedule list` to see configured schedules."
        );
    }

    // Locate the owning file by scanning the loaded include graph — a
    // schedule may live in the master, schedules.d/, or any operator
    // include, and `files_loaded` is exactly that universe.
    let owner = loaded
        .files_loaded
        .iter()
        .find(|file| file_defines_schedule(file, id).unwrap_or(false))
        .cloned()
        .with_context(|| {
            format!("schedule \"{id}\" is in the merged config but no loaded file defines it")
        })?;

    let (mut doc, _) = read_or_empty(&owner)?;
    let removed = remove_id_keyed(&mut doc, "schedules", id)?;
    if !removed {
        bail!(
            "schedule \"{id}\" vanished from {} between locate and remove — retry",
            owner.display()
        );
    }
    write_value_validated(config_path, &owner, &doc)?;
    println!("removed schedule {id}");

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// True when `file`'s raw `[[schedules]]` array contains a row with this id.
fn file_defines_schedule(file: &Path, id: &str) -> anyhow::Result<bool> {
    let raw =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let value: Value = raw
        .parse()
        .with_context(|| format!("{} is not valid TOML", file.display()))?;
    Ok(value
        .get("schedules")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|row| row.get("id").and_then(|v| v.as_str()) == Some(id))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// What `schedule list` prints must equal what the operator has to
    /// type into the file.
    ///
    /// Derived from serde rather than compared against two hand-written
    /// literals: serde is what actually produces and consumes the TOML,
    /// so it is the authority. A second hardcoded list would only prove
    /// this file agrees with itself — which was true of `{:?}` too.
    #[test]
    fn target_type_rendering_matches_the_serialised_form() {
        use crate::config::schema::schedule::ScheduleTargetType as T;
        for t in [T::Device, T::Group] {
            let serialised = toml::Value::try_from(t)
                .expect("ScheduleTargetType must serialise")
                .as_str()
                .expect("…as a TOML string")
                .to_string();
            assert_eq!(
                target_type_toml_value(t),
                serialised,
                "`schedule list` renders `{:?}` as `{}` while the config \
                 file spells it `{serialised}` — an operator copying the \
                 listing into TOML gets a validation error",
                t,
                target_type_toml_value(t),
            );
        }
    }

    /// The control arm. Without it the test above passes against a
    /// renderer that returns the Rust name *and* a serde impl that also
    /// returns the Rust name — i.e. against the original bug, had
    /// `rename_all` never been applied.
    #[test]
    fn target_type_rendering_is_lowercase_not_the_rust_variant_name() {
        use crate::config::schema::schedule::ScheduleTargetType as T;
        assert_eq!(target_type_toml_value(T::Device), "device");
        assert_ne!(
            target_type_toml_value(T::Device),
            format!("{:?}", T::Device),
            "printing the Debug form is the defect being fixed"
        );
    }

    const MASTER_WITH_INCLUDES: &str = r#"schema_version = 3
includes = ["schedules.d/*.toml"]

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
id = "kids-night"
display_name = "Kids night"
target_type = "device"
target_id = "tablet"
profile = "blocked"
days = ["all"]
hours = "21:00-07:00"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    const EXPIRED_SLICE: &str = r#"[[schedules]]
id = "quiet-tablet-001122"
display_name = "Quiet device tablet"
target_type = "device"
target_id = "tablet"
profile = "blocked"
days = ["all"]
hours = "00:00-23:59"
expires_at = "2026-01-01T00:00:00Z"

[[schedules]]
id = "quiet-tablet-998877"
display_name = "Quiet device tablet"
target_type = "device"
target_id = "tablet"
profile = "blocked"
days = ["all"]
hours = "00:00-23:59"
expires_at = "2999-01-01T00:00:00Z"
"#;

    fn mk_multi_file(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(&master, MASTER_WITH_INCLUDES).unwrap();
        std::fs::create_dir_all(dir.path().join("schedules.d")).unwrap();
        std::fs::write(dir.path().join("schedules.d/quiet.toml"), EXPIRED_SLICE).unwrap();
        master
    }

    fn now() -> time::OffsetDateTime {
        time::macros::datetime!(2026-06-10 12:00:00 UTC)
    }

    #[test]
    fn prune_drops_expired_row_from_slice_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_multi_file(&dir);
        let loaded = load_config(&master, now()).expect("fixture loads");
        assert_eq!(loaded.config.schedules.len(), 3);

        let pruned = prune_expired_schedules(&master, &loaded, now()).unwrap();
        assert_eq!(pruned, vec!["quiet-tablet-001122".to_string()]);

        let reloaded = load_config(&master, now()).expect("post-prune reload");
        let ids: Vec<&str> = reloaded
            .config
            .schedules
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        // Recurring master row + future-expiry slice row survive.
        assert!(ids.contains(&"kids-night"), "ids: {ids:?}");
        assert!(ids.contains(&"quiet-tablet-998877"), "ids: {ids:?}");
        assert!(!ids.contains(&"quiet-tablet-001122"), "ids: {ids:?}");
        // The master file itself was not rewritten (its row survives in
        // the original byte-for-byte file).
        let master_raw = std::fs::read_to_string(&master).unwrap();
        assert_eq!(master_raw, MASTER_WITH_INCLUDES, "master untouched");
    }

    #[test]
    fn prune_is_a_noop_when_nothing_expired() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, MASTER_WITH_INCLUDES).unwrap();
        let loaded = load_config(&master, now()).unwrap();
        let pruned = prune_expired_schedules(&master, &loaded, now()).unwrap();
        assert!(pruned.is_empty());
        assert_eq!(
            std::fs::read_to_string(&master).unwrap(),
            MASTER_WITH_INCLUDES
        );
    }

    #[tokio::test]
    async fn remove_drops_row_from_owning_include() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_multi_file(&dir);
        let sock = dir.path().join("ghost.sock");
        run_remove(&master, &sock, "quiet-tablet-998877")
            .await
            .expect("remove must succeed");
        let reloaded = load_config(&master, now()).unwrap();
        assert!(!reloaded
            .config
            .schedules
            .iter()
            .any(|s| s.id.as_str() == "quiet-tablet-998877"));
        // Sibling row in the same slice survives the surgery.
        assert!(reloaded
            .config
            .schedules
            .iter()
            .any(|s| s.id.as_str() == "quiet-tablet-001122"));
    }

    #[tokio::test]
    async fn remove_unknown_id_points_at_list() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_multi_file(&dir);
        let sock = dir.path().join("ghost.sock");
        let err = run_remove(&master, &sock, "nope").await.unwrap_err();
        assert!(
            err.to_string().contains("warden schedule list"),
            "got: {err}"
        );
    }

    #[test]
    fn list_renders_states() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_multi_file(&dir);
        // Smoke: must not panic and must classify the expired row.
        run_list(&master).unwrap();
    }
}
