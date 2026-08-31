//! Atomic v1 config file writer.
//!
//! §4.41 retired the legacy v0 `write_config` path (and its
//! `WriteConfigError` / `guard_against_v1_master` / `write_err_from_atomic`
//! helpers) along with the v0 `Settings` struct. The daemon and every
//! CLI verb now operate exclusively on [`ConfigV1`]; the single writer
//! left is [`write_config_v1`], used by `warden init` and `config
//! restore` — both whole-file replacements where flattening is not a
//! concern (a fresh scaffold / an operator-accepted backup). Per-section
//! mutations (the schedule-tick prune, the IPC tracking-config handler,
//! every entity editor) do NOT go through here — they use per-file
//! `toml::Value` surgery via `cli::commands::target::write_value_validated`
//! so multi-file include layouts aren't flattened onto the master
//! (rev-2606 writer-01).

use std::path::Path;

use super::atomic_write::atomic_write_and_validate;
use super::schema::ConfigV1;

/// Serialize a v1 [`ConfigV1`] back to TOML and write atomically.
///
/// Sprint 31 minimum-viable writer (option A per `_docs/features/config_architecture.md`
/// §16.3 follow-up #1): uses `toml::to_string_pretty` so the output round-trips
/// semantically but **does not preserve comment layout or field ordering** of
/// a hand-edited source. Sufficient for:
///
/// - `warden init` scaffolding (writing a fresh file).
/// - `warden config restore` (staged replacement, operator already accepted
///   the backup being canonical).
///
/// Not suitable for round-tripping a hand-edited file without churn. A future
/// sprint can upgrade this to a `toml_edit::Document` path that keeps
/// comments and ordering intact; the signature stays the same.
pub fn write_config_v1(path: &Path, config: &ConfigV1) -> anyhow::Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|e| anyhow::anyhow!("failed to serialize v1 config: {}", e))?;
    // CS2 atomic write: the validator is the full v1 loader so we
    // surface include-graph / cross-reference errors before the rename
    // lands. If the staged bytes would not boot the daemon, the
    // original file on disk stays untouched. Matching loader = same
    // code path a cold-start would take.
    let now = time::OffsetDateTime::now_utc();
    atomic_write_and_validate(path, &content, |staged: &Path| {
        super::loader::load_config(staged, now).map(|_| ()).map_err(
            |errs: Vec<super::error::ConfigError>| {
                // Collapse the error list into a single human-readable
                // string — the atomic helper only needs Display, and
                // the original struct list is carried in the daemon's
                // audit trail already.
                let mut s = String::new();
                for (i, e) in errs.iter().enumerate() {
                    if i > 0 {
                        s.push_str("; ");
                    }
                    s.push_str(&e.to_string());
                }
                s
            },
        )
    })
    .map_err(|e| anyhow::anyhow!("{e}"))
}

// §4.31: the legacy `pub(crate) atomic_write(&str)` was removed.
// All config-mutation call-sites were rewired to
// [`atomic_write_and_validate`] so the v1 master + every `.d/*.toml`
// slice gets the CS2 round-trip validator AND §4.31 fsync + mode/owner
// preservation. The remaining manpage-output caller (man pages are
// not config) carries its own private helper inside
// `cli/commands/manpages.rs`; it still routes through
// [`hardened_atomic_write`] so even non-config writes get fsync.

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    use crate::config::loader::load_config;
    use crate::config::schema::load::load_from_str;

    const MINIMAL_V1: &str = r#"schema_version = 3

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
    fn write_config_v1_roundtrips_semantically() {
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).expect("fixture parses");
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        write_config_v1(&path, &original).unwrap();
        let reloaded = load_config(&path, now).expect("written config reloads");
        // Semantic equality via TOML serialisation — ConfigV1 does not
        // implement PartialEq (pass-through types do not).
        let a = toml::to_string(&original).unwrap();
        let b = toml::to_string(&reloaded.config).unwrap();
        assert_eq!(a, b, "config written and reloaded should match");
    }

    #[test]
    fn write_config_v1_is_atomic() {
        // The `.tmp` sibling must not survive a successful write.
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        write_config_v1(&path, &original).unwrap();
        let tmp_sibling = path.with_extension("toml.tmp");
        assert!(
            !tmp_sibling.exists(),
            ".tmp sibling must be renamed away on success"
        );
        assert!(path.exists(), "target config file must exist");
    }

    #[test]
    fn write_config_v1_creates_file_when_absent() {
        let now = OffsetDateTime::now_utc();
        let original = load_from_str(MINIMAL_V1, None, now).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fresh.toml");
        assert!(!path.exists());
        write_config_v1(&path, &original).unwrap();
        assert!(path.exists());
    }

    /// `config-enforce-device-mac-canonical-serde` — the deprecation must be
    /// **clearable**.
    ///
    /// The reported defect was a loader-synthesised value round-tripping back
    /// into the operator's file: the daemon re-serialised the deprecated
    /// spelling, so an operator who renamed the key by hand got it reverted on
    /// the next rewrite and the WARN never went away. The code fix landed in
    /// S42 T5 (`enforce_device_mac` is the canonical serde name,
    /// `enforce_client_mac` survives as a read-only alias); what was missing is
    /// this pin, so nothing stopped a later edit from making the legacy
    /// spelling canonical again.
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
        write_config_v1(&path, &original).unwrap();
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
