//! Atomic v1 config file writer.
//!
//! The daemon and every CLI verb operate exclusively on [`ConfigV1`]; the
//! single writer here is [`write_config_v1_locked`], retained for guarded
//! in-crate whole-file writer coverage.
//! Per-section mutations (the schedule-tick prune, the IPC
//! tracking-config handler, every entity editor) do NOT go through here
//! — they use per-file `toml::Value` surgery via
//! `cli::commands::target::write_value_validated_locked` so multi-file include
//! layouts aren't flattened onto the master.

use std::path::Path;

use super::atomic_write::{hardened_atomic_write_at, AtomicWriteAtOpts};
use super::loader::{load_config_with_overlay_for_schema_under_guard, LoaderOverlay};
use super::schema::ConfigV1;
use super::write_lock::ConfigWriteLock;

/// Serialize a v1 [`ConfigV1`] back to TOML and write atomically.
///
/// Uses `toml::to_string_pretty`, so the output round-trips semantically
/// but **does not preserve comment layout or field ordering** of a
/// hand-edited source. Sufficient for:
///
/// - `warden init` scaffolding (writing a fresh file).
/// - `warden config restore` (staged replacement, operator already accepted
///   the backup being canonical).
///
/// Not suitable for round-tripping a hand-edited file without churn.
pub(crate) fn write_config_v1_locked(
    guard: &ConfigWriteLock,
    path: &Path,
    config: &ConfigV1,
) -> anyhow::Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|e| anyhow::anyhow!("failed to serialize v1 config: {}", e))?;
    guard.verify_master(path)?;
    let plan = guard.tree_io().plan_master_target()?;
    let mut overlay = LoaderOverlay::default();
    overlay.stage_plan(&plan, content.clone())?;

    // Validate staged master bytes under the same guard before materializing
    // a missing parent or promoting the pinned target.
    let now = time::OffsetDateTime::now_utc();
    if let Err(errs) = load_config_with_overlay_for_schema_under_guard(
        guard,
        path,
        super::schema::SCHEMA_VERSION_V1,
        now,
        Some(&overlay),
    ) {
        let message = errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow::anyhow!("validation failed: {message}"));
    }

    let target = plan.materialize()?;
    hardened_atomic_write_at(&target, content.as_bytes(), AtomicWriteAtOpts::default())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

// No raw config writer is exposed: whole-config writes use the pinned target
// and guarded overlay above; per-section mutations use the target module's
// guarded transaction. Manpage output is not live configuration and keeps its
// own hardened writer.

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use time::OffsetDateTime;

    use crate::config::loader::load_config;
    use crate::config::schema::load::load_from_str;
    use crate::config::schema::Id;

    const MINIMAL_V1: &str = r#"schema_version = 4

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn guarded_writer_roundtrips_semantically() {
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).expect("fixture parses");
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();
        write_config_v1_locked(&guard, &path, &original).unwrap();
        drop(guard);
        let reloaded = load_config(&path, now).expect("written config reloads");
        // Semantic equality via TOML serialisation — ConfigV1 does not
        // implement PartialEq (pass-through types do not).
        let a = toml::to_string(&original).unwrap();
        let b = toml::to_string(&reloaded.config).unwrap();
        assert_eq!(a, b, "config written and reloaded should match");
    }

    #[test]
    fn guarded_writer_is_atomic() {
        // The `.tmp` sibling must not survive a successful write.
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();
        write_config_v1_locked(&guard, &path, &original).unwrap();
        let tmp_sibling = path.with_extension("toml.tmp");
        assert!(
            !tmp_sibling.exists(),
            ".tmp sibling must be renamed away on success"
        );
        assert!(path.exists(), "target config file must exist");
    }

    #[test]
    fn guarded_writer_creates_file_when_absent() {
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fresh.toml");
        assert!(!path.exists());
        let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();
        write_config_v1_locked(&guard, &path, &original).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn locked_writer_completes_under_a_live_guard() {
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();

        write_config_v1_locked(&guard, &path, &original).unwrap();

        assert!(path.exists());
        drop(guard);
        let reloaded = load_config(&path, now).expect("written config reloads");
        let actual = toml::to_string(&reloaded.config).unwrap();
        assert_eq!(actual, toml::to_string(&original).unwrap());
    }

    #[test]
    fn locked_writer_rejects_a_guard_from_another_tree_before_change() {
        let now = OffsetDateTime::now_utc();
        let config = load_from_str(MINIMAL_V1, None, now).unwrap();
        for present in [false, true] {
            let target_dir = tempfile::tempdir().unwrap();
            let path = target_dir.path().join("config.toml");
            let before = "existing sentinel\n";
            if present {
                std::fs::write(&path, before).unwrap();
            }
            let other_dir = tempfile::tempdir().unwrap();
            let other_master = other_dir.path().join("config.toml");
            let guard = crate::config::write_lock::acquire_for_write(&other_master).unwrap();

            let error = write_config_v1_locked(&guard, &path, &config).unwrap_err();

            assert!(error.to_string().contains("config guard belongs to"));
            if present {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
            } else {
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn locked_writer_updates_existing_and_absent_masters_twice() {
        let now = OffsetDateTime::now_utc();
        let first = load_from_str(
            &MINIMAL_V1.replace("127.0.0.1:15353", "127.0.0.1:15354"),
            None,
            now,
        )
        .unwrap();
        let second = load_from_str(
            &MINIMAL_V1.replace("127.0.0.1:15353", "127.0.0.1:15355"),
            None,
            now,
        )
        .unwrap();
        for present in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("config.toml");
            if present {
                std::fs::write(&path, MINIMAL_V1).unwrap();
            }
            let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();

            write_config_v1_locked(&guard, &path, &first).unwrap();
            write_config_v1_locked(&guard, &path, &second).unwrap();

            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                toml::to_string_pretty(&second).unwrap()
            );
        }
    }

    #[test]
    fn locked_writer_validation_failure_preserves_existing_or_absent_master() {
        let now = OffsetDateTime::now_utc();
        let valid = load_from_str(MINIMAL_V1, None, now).unwrap();
        let mut invalid = valid.clone();
        invalid.server.default_profile = Some(Id::new("ghost").unwrap());
        for present in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("config.toml");
            if present {
                std::fs::write(&path, MINIMAL_V1).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let before = present.then(|| {
                let metadata = std::fs::metadata(&path).unwrap();
                (std::fs::read(&path).unwrap(), metadata.mode() & 0o7777)
            });
            let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();

            let error = write_config_v1_locked(&guard, &path, &invalid).unwrap_err();

            assert!(error.to_string().contains("ghost"), "{error:#}");
            if let Some((bytes, mode)) = before {
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            } else {
                assert!(!path.exists());
            }
        }
    }

    /// The deprecation must be **clearable**: a loader-synthesised value
    /// must never round-trip back into the operator's file. `enforce_device_mac`
    /// is the canonical serde name; `enforce_client_mac` survives as a
    /// read-only alias. Without this pin, nothing stops a rewrite from
    /// re-serialising the deprecated spelling, so an operator who renamed
    /// the key by hand would get it reverted on the next rewrite and the
    /// WARN would never clear.
    ///
    /// **`false` is load-bearing.** `default_enforce_device_mac()` returns
    /// `true`, so the same test written with `true` passes even if the alias is
    /// gone and serde quietly fills the default in — it would assert on a value
    /// the config never supplied. With `false`, a lost alias cannot be
    /// mistaken for a working one.
    ///
    /// Deliberately routed through `load_from_str`, which is the single-file
    /// fast path and therefore the shipped layout. That path does **not** run
    /// the loader's `normalise_deprecated_keys`, so the serde alias is the only
    /// thing carrying the legacy key here — exactly the mechanism under test.
    #[test]
    fn legacy_enforce_client_mac_loads_and_rewrites_to_the_canonical_key() {
        let now = OffsetDateTime::now_utc();
        let legacy = MINIMAL_V1.replace(
            "default_profile = \"default\"",
            "default_profile = \"default\"\nenforce_client_mac = false",
        );

        let original = load_from_str(&legacy, None, now).expect(
            "the legacy spelling must still load — removing the alias is a schema_version 2 change",
        );
        assert!(
            !original.server.enforce_device_mac,
            "the legacy key's VALUE must survive the alias, not be replaced by \
             default_enforce_device_mac() = true"
        );

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();
        write_config_v1_locked(&guard, &path, &original).unwrap();
        drop(guard);
        let written = std::fs::read_to_string(&path).unwrap();

        assert!(
            written.contains("enforce_device_mac = false"),
            "a rewrite must emit the CANONICAL key, carrying the operator's \
             value: {written}"
        );
        assert!(
            !written.contains("enforce_client_mac"),
            "a rewrite must not re-introduce the deprecated key — that is the \
             revert loop that made the warning impossible to clear: {written}"
        );

        // The healed file must be a fixpoint: load it back and confirm the
        // value survived the round trip. Without this, "emits the new key"
        // could still be emitting it with the wrong value.
        let reloaded = load_config(&path, now).expect("the healed config must reload");
        assert!(
            !reloaded.config.server.enforce_device_mac,
            "self-healed config must preserve the operator's value"
        );
    }
}
