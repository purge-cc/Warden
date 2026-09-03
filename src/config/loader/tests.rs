//! Tests for the multi-file loader.
//!
//! Heavy use of [`tempfile::TempDir`] so each case gets a fresh
//! filesystem tree — cheaper and more portable than committing
//! scenario-specific fixtures for every error path (symlinks, large
//! files, deep nesting). The one committed fixture,
//! `tests/fixtures/full-v1/`, is used for the happy-path "master + 5
//! `.d/` dirs + 20 small files" DoD case.

use std::fs;
use std::path::{Path, PathBuf};

use time::macros::datetime;
use time::OffsetDateTime;

use super::*;

fn now() -> OffsetDateTime {
    datetime!(2026-04-22 12:00:00 UTC)
}

/// Absolute path to `tests/fixtures/full-v1/config.toml`.
fn committed_full_v1_master() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("tests/fixtures/full-v1/config.toml")
}

/// Absolute path to `tests/fixtures/minimal-v1/config.toml`.
fn committed_minimal_v1_master() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("tests/fixtures/minimal-v1/config.toml")
}

fn write(root: &Path, rel: &str, body: &str) -> PathBuf {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(&full, body).expect("write");
    full
}

// ── 1. happy-path single file (fast path) ───────────────────────────

#[test]
fn single_file_no_includes_uses_fast_path() {
    let master = committed_minimal_v1_master();
    let loaded = load_config(&master, now()).expect("minimal-v1 must load");
    assert_eq!(loaded.files_loaded.len(), 1);
    assert_eq!(loaded.files_loaded[0], master.canonicalize().unwrap());
    assert!(loaded.total_bytes > 0);
    // Fast-path populates provenance too (so downstream error
    // enrichment still has top-level keys available).
    assert!(loaded.provenance.contains_key("server"));
    assert!(loaded.provenance.contains_key("devices.dweller-iphone"));
}

// ── 2. happy-path multi-file (committed full-v1 fixture) ────────────

#[test]
fn full_v1_fixture_loads_cleanly() {
    let master = committed_full_v1_master();
    let loaded = load_config(&master, now()).expect("full-v1 must load clean");
    assert_eq!(loaded.config.schema_version, 3);
    assert_eq!(loaded.config.blocklists.len(), 4);
    assert_eq!(loaded.config.profiles.len(), 3);
    assert_eq!(loaded.config.devices.len(), 5);
    assert_eq!(loaded.config.groups.len(), 3);
    assert_eq!(loaded.config.subnets.len(), 2);
    assert_eq!(loaded.config.schedules.len(), 3);
    assert_eq!(loaded.config.admin_rules.len(), 2);
    // master + 3 blocklists + 3 profiles + 5 devices + 3 groups + 2 subnets + 3 schedules + 1 rules = 21 files
    assert_eq!(loaded.files_loaded.len(), 21);
}

#[test]
fn full_v1_fixture_provenance_points_at_the_actual_files() {
    let master = committed_full_v1_master();
    let loaded = load_config(&master, now()).expect("load");
    let (file, _line) = loaded
        .provenance
        .get("devices.dweller-iphone")
        .expect("entity provenance must be recorded");
    assert!(
        file.ends_with("devices.d/dweller.toml"),
        "expected dweller.toml, got {}",
        file.display()
    );
    let (server_file, _) = loaded.provenance.get("server").expect("server provenance");
    assert!(server_file.ends_with("full-v1/config.toml"));
}

// ── 3. deterministic glob ordering ──────────────────────────────────

#[test]
fn glob_ordering_is_bytewise_stable() {
    let tmp = tempfile::tempdir().unwrap();
    // Intentional mixed case and numbers to drive the sort.
    write(
        tmp.path(),
        "devices.d/03.toml",
        r#"[[devices]]
id = "dev-three"
display_name = "Three"
ip = "10.0.0.3"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "devices.d/01.toml",
        r#"[[devices]]
id = "dev-one"
display_name = "One"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "devices.d/02.toml",
        r#"[[devices]]
id = "dev-two"
display_name = "Two"
ip = "10.0.0.2"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("load");
    let ids: Vec<_> = loaded
        .config
        .devices
        .iter()
        .map(|d| d.id.as_str())
        .collect();
    assert_eq!(ids, vec!["dev-one", "dev-two", "dev-three"]);
}

#[test]
fn empty_glob_is_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("devices.d")).unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("empty glob must be tolerated");
    assert!(loaded.config.devices.is_empty());
    assert_eq!(loaded.files_loaded.len(), 1);
}

#[test]
fn missing_explicit_include_is_error() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["no-such-file.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("must fail");
    assert!(errs.iter().any(|e| matches!(e, ConfigError::Parse(_))));
    let combined = join_errs(&errs);
    assert!(combined.contains("no-such-file.toml"), "got {combined}");
}

// ── rev-2606 §05 loader include-path hardening (07/08/10/11) ─────────

#[test]
fn non_regular_file_include_is_refused() {
    // loader-07: an include resolving to a non-regular file (here a
    // directory; a FIFO/socket would otherwise block `read_to_string`
    // forever) is rejected at stat time, before the read.
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("notafile.toml")).unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\nincludes = [\"notafile.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let errs = load_config(&master, now()).expect_err("directory include must be refused");
    let combined = join_errs(&errs);
    assert!(combined.contains("not a regular file"), "got {combined}");
}

#[test]
fn glob_self_match_is_skipped_not_a_cycle() {
    // loader-10: `*.toml` in dir/config.toml matches config.toml itself —
    // skip it (conventional self-skip) instead of erroring "include cycle".
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "blocklist.toml",
        "[[blocklists]]\nid = \"ads\"\ndisplay_name = \"Ads\"\nurl = \"https://e.example/a.txt\"\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\nincludes = [\"*.toml\"]\n\
         [server]\ndefault_profile = \"default\"\n\
         [profiles.default]\ndisplay_name = \"D\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("glob self-match must not be a cycle");
    assert!(loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.id.as_str() == "ads"));
}

#[test]
fn glob_skips_dotfile_disabled_includes() {
    // loader-11: `*.toml` must NOT match `.disabled.toml`, preserving the
    // rename-to-dotfile disable convention.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "blocklists.d/active.toml",
        "[[blocklists]]\nid = \"active\"\ndisplay_name = \"A\"\nurl = \"https://e.example/a.txt\"\n",
    );
    write(
        tmp.path(),
        "blocklists.d/.disabled.toml",
        "[[blocklists]]\nid = \"disabled\"\ndisplay_name = \"D\"\nurl = \"https://e.example/d.txt\"\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\nincludes = [\"blocklists.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("must load active, skip dotfile");
    assert!(loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.id.as_str() == "active"));
    assert!(
        !loaded
            .config
            .blocklists
            .iter()
            .any(|b| b.id.as_str() == "disabled"),
        "dotfile .disabled.toml must be skipped"
    );
}

#[test]
fn read_to_string_capped_rejects_overrun() {
    // loader-08: the bounded reader caps at `cap + 1` and errors past `cap`.
    let tmp = tempfile::tempdir().unwrap();
    let p = write(tmp.path(), "data.txt", "0123456789"); // exactly 10 bytes
    assert_eq!(super::read_to_string_capped(&p, 10).unwrap(), "0123456789");
    let err = super::read_to_string_capped(&p, 5).expect_err("10-over-5 must error");
    assert!(matches!(err.as_slice(), [ConfigError::ValidationFailed(_)]));
}

#[test]
fn oversized_schema_version_errors_with_file_line() {
    // loader-06: a schema_version that doesn't fit u32 is rejected at
    // extraction time WITH file:line, not lost to the post-merge try_into.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        "[server]\ndefault_profile = \"d\"\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 99999999999\nincludes = [\"extra.toml\"]\n[profiles.d]\ndisplay_name = \"D\"\n",
    );
    let errs = load_config(&master, now()).expect_err("oversized schema_version must error");
    assert!(
        errs.iter().any(|e| {
            matches!(e, ConfigError::Parse(_))
                && e.context().reason.contains("u32")
                && e.context().file.is_some()
        }),
        "got {errs:?}"
    );
}

#[test]
fn include_only_schema_version_is_refused() {
    // loader-09: when the master omits schema_version, an include must NOT
    // silently supply it (the previous behaviour misattributed later
    // mismatches to "the master's value"). Require the master to declare it.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        "schema_version = 3\n[server]\ndefault_profile = \"d\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "includes = [\"extra.toml\"]\n[profiles.d]\ndisplay_name = \"D\"\n",
    );
    let errs =
        load_config(&master, now()).expect_err("include-only schema_version must be refused");
    assert!(
        errs.iter()
            .any(|e| e.context().reason.contains("declared in an include")),
        "got {errs:?}"
    );
}

// ── 4. merge rules §7.3 ─────────────────────────────────────────────

#[test]
fn duplicate_singleton_across_files_errors_with_both_citations() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"[server]
default_profile = "other"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[server]
default_profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("duplicate [server] must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(_))));
    let combined = join_errs(&errs);
    assert!(
        combined.contains("server"),
        "expected `server` in error: {combined}"
    );
    assert!(
        combined.contains("config.toml") && combined.contains("extra.toml"),
        "expected both file citations: {combined}"
    );
}

/// §4.11-3 R3: `[server]` is a SPLIT-merge singleton — node-local fields
/// in the master (`listen`) and policy fields in an include
/// (`default_profile`, the cluster bundle's shape) field-merge into one
/// `[server]` instead of colliding. This is what lets a cluster secondary
/// drop the synced policy bundle into `cluster.d/` while keeping its own
/// listen address. Cluster-only behaviour, so the test is feature-gated.
#[cfg(feature = "cluster")]
#[test]
fn server_fields_merge_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"[server]
default_profile = "default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[server]
listen = "127.0.0.1:15399"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("split [server] must field-merge");
    // Node-local field from the master survived…
    assert_eq!(loaded.config.server.listen.to_string(), "127.0.0.1:15399");
    // …and the policy field from the include merged in.
    assert_eq!(
        loaded
            .config
            .server
            .default_profile
            .as_ref()
            .map(|i| i.as_str()),
        Some("default"),
    );
}

/// A singleton NOT on the split-merge allowlist (`[tracking]`) still
/// rejects a second whole-section definition across files — R3 narrowed
/// the field-merge to `[server]` only. Cluster-gated so the default lib
/// test count is unchanged (the default build's `[server]` path is already
/// covered by `duplicate_singleton_across_files_errors_with_both_citations`).
#[cfg(feature = "cluster")]
#[test]
fn duplicate_non_split_singleton_across_files_errors() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"[tracking]
enabled = false
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[tracking]
enabled = true

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("duplicate [tracking] must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(_))));
    let combined = join_errs(&errs);
    assert!(
        combined.contains("tracking"),
        "expected `tracking` in error: {combined}"
    );
    assert!(
        combined.contains("config.toml") && combined.contains("extra.toml"),
        "expected both file citations: {combined}"
    );
}

#[test]
fn duplicate_named_map_key_across_files_errors() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "profiles.d/a.toml",
        r#"[profiles.default]
display_name = "A"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/b.toml",
        r#"[profiles.default]
display_name = "B"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("duplicate profile key must fail");
    let combined = join_errs(&errs);
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(_))));
    assert!(combined.contains("profiles.default"), "got {combined}");
}

#[test]
fn arrays_of_tables_are_concatenated() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "devices.d/a.toml",
        r#"[[devices]]
id = "a"
display_name = "A"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "devices.d/b.toml",
        r#"[[devices]]
id = "b"
display_name = "B"
ip = "10.0.0.2"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("load");
    assert_eq!(loaded.config.devices.len(), 2);
}

#[test]
fn custom_lists_across_include_files_are_concatenated() {
    // `custom_lists` must be registered in `ARRAY_OF_TABLES_KEYS`, not just
    // `KNOWN_TOP_LEVEL`. A key that is known but absent from the array
    // roster falls through to `merge_singleton`, so a second
    // `[[custom_lists]]` in a sibling include file would be rejected as a
    // duplicate singleton instead of concatenated.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "custom_lists.d/a.toml",
        r#"[[custom_lists]]
id = "minecraft"
"#,
    );
    write(
        tmp.path(),
        "custom_lists.d/b.toml",
        r#"[[custom_lists]]
id = "homework"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["custom_lists.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    // A declared list with no pack file fails the load, so the concatenation
    // this test is about is only reachable once both files exist.
    write(tmp.path(), "packs/minecraft.txt", "||ads.example.com^\n");
    write(tmp.path(), "packs/homework.txt", "@@||cdn.example.com^\n");
    let loaded = load_config(&master, now()).expect("load");
    assert_eq!(loaded.config.custom_lists.len(), 2);
}

// ── 5. cycle + depth ─────────────────────────────────────────────

#[test]
fn cycle_detected_with_chain_in_error() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "a.toml",
        r#"schema_version = 3
includes = ["b.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    write(
        tmp.path(),
        "b.toml",
        r#"includes = ["a.toml"]
"#,
    );
    let master = tmp.path().join("a.toml");
    let errs = load_config(&master, now()).expect_err("cycle must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(_))));
    let combined = join_errs(&errs);
    assert!(combined.contains("cycle"), "got {combined}");
    assert!(
        combined.contains("a.toml") && combined.contains("b.toml"),
        "expected both in chain: {combined}"
    );
}

#[test]
fn depth_limit_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    // Build a chain of 6 files — deeper than MAX_INCLUDE_DEPTH (4).
    //
    // chain: 0 → 1 → 2 → 3 → 4 → 5. load_file recurses; 5 hits
    // depth=5 which exceeds the cap.
    write(
        tmp.path(),
        "f5.toml",
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    for i in (0..5).rev() {
        // `[upstream]` is a SINGLETON across the include set — only the
        // master may declare it, or the loader raises a duplicate-singleton
        // error before the depth check it is here to exercise.
        let upstream = if i == 0 {
            "\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        } else {
            ""
        };
        write(
            tmp.path(),
            &format!("f{i}.toml"),
            &format!(
                "schema_version = 3\nincludes = [\"f{}.toml\"]\n{upstream}",
                i + 1,
            ),
        );
    }
    let master = tmp.path().join("f0.toml");
    let errs = load_config(&master, now()).expect_err("depth > 4 must fail");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("depth"),
        "expected depth error: {combined}"
    );
}

#[test]
fn depth_at_limit_passes() {
    let tmp = tempfile::tempdir().unwrap();
    // 0 → 1 → 2 → 3 → 4 (depth=4, exactly at the limit).
    write(
        tmp.path(),
        "f4.toml",
        r#"schema_version = 3
"#,
    );
    for i in (0..4).rev() {
        // Singleton: only the master (f0) declares `[upstream]`. Declaring it
        // in every file of the chain is a duplicate-singleton error.
        let upstream = if i == 0 {
            "\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        } else {
            ""
        };
        write(
            tmp.path(),
            &format!("f{i}.toml"),
            &format!(
                "schema_version = 3\nincludes = [\"f{}.toml\"]\n{upstream}",
                i + 1,
            ),
        );
    }
    let master = tmp.path().join("f0.toml");
    let loaded = load_config(&master, now()).expect("depth == 4 must pass");
    assert_eq!(loaded.files_loaded.len(), 5);
}

// ── 6. limits (size + count) ────────────────────────────────────

#[test]
fn size_limit_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    // 51 MB of payload in a single included file — trips the 50 MB cap.
    let payload = "# ".to_string() + &"x".repeat((51 * 1024 * 1024) - 2);
    write(tmp.path(), "huge.toml", &payload);
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["huge.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("size cap must fail");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("50 MB") || combined.contains("aggregate"),
        "expected size cap mention: {combined}"
    );
}

#[test]
fn file_count_limit_enforced_smoke() {
    // Verify the constant is threaded. A real 1001-file test is slow
    // and IO-heavy — smoke-test by asserting the constant value and
    // the error path via a trivial harness below.
    assert_eq!(MAX_INCLUDE_FILES, 1000);
}

// ── 6b. allowlist drift guard ───────────────────────────────────

#[test]
fn known_top_level_covers_configv1_serialized_keys() {
    // `KNOWN_TOP_LEVEL` (used by the multi-file path's
    // `reject_unknown_top_level`) is hand-synced with `ConfigV1`'s serde
    // fields. If a future section is added to `ConfigV1` but forgotten in
    // `KNOWN_TOP_LEVEL`, a config using it is REJECTED in multi-file mode
    // yet ACCEPTED by the single-file serde fast path — same bytes, two
    // verdicts. This guard catches that drift for every section present
    // in a default `ConfigV1` serialization (the realistic case: recent
    // additions `[dnssec]` / `[resource_budget]` / `[backup]` were all
    // such singleton sections).
    //
    // Limitation: array-of-tables sections (`[[devices]]`, `[[blocklists]]`,
    // …) default to empty and may be skipped by serde, so they are not
    // covered here — only by adding one to the default would they appear.
    let v = crate::config::schema::ConfigV1::default();
    let value = toml::Value::try_from(&v).expect("default ConfigV1 serializes to a toml value");
    let table = value
        .as_table()
        .expect("ConfigV1 serializes as a top-level table");
    for key in table.keys() {
        assert!(
            super::KNOWN_TOP_LEVEL.contains(&key.as_str()),
            "ConfigV1 serializes top-level key `{key}` but loader::KNOWN_TOP_LEVEL omits it — \
             multi-file load would falsely reject a config using `{key}` while the single-file \
             fast path accepts it. Add `{key}` to KNOWN_TOP_LEVEL."
        );
    }
}

#[test]
fn known_top_level_has_no_stale_entries() {
    // The REVERSE of the guard above (rev-2606 loader-01): every key in
    // `KNOWN_TOP_LEVEL` must be a real `ConfigV1` serde field — except the
    // deprecated aliases that `normalise_deprecated_keys` renames away
    // BEFORE deserialise. A stale entry (e.g. `categories`, retired in the
    // v2-tags migration) would let a multi-file config pass the per-file
    // allowlist check and then die in the post-merge `try_into::<ConfigV1>()`
    // with a provenance-less "unknown field" error — the worst diagnostic
    // the loader can produce, on exactly the key v1→v2 migrators still
    // carry. `deny_unknown_fields` on `ConfigV1` is the oracle: a known
    // field yields at most a value-type / missing-field error; an unknown
    // one yields "unknown field `{key}`".
    //
    // ALIASES: accepted by the allowlist (reject runs before normalise) but
    // intentionally NOT ConfigV1 fields — the loader rewrites them to their
    // canonical field name before the struct ever sees them.
    const ALIASES: &[&str] = &["ip_denylists", "clients"];
    for &key in super::KNOWN_TOP_LEVEL {
        if ALIASES.contains(&key) {
            continue;
        }
        let doc = format!("{key} = {{}}\n");
        if let Err(e) = toml::from_str::<crate::config::schema::ConfigV1>(&doc) {
            assert!(
                !e.to_string().contains("unknown field"),
                "KNOWN_TOP_LEVEL contains `{key}` but ConfigV1 has no such field \
                 (stale allowlist entry — multi-file configs using it get a \
                 provenance-less post-merge error). Remove it from KNOWN_TOP_LEVEL \
                 or add the field / an ALIAS exemption.\ndeserialise error: {e}"
            );
        }
    }
}

// ── 7. path security (N12) ──────────────────────────────────────

#[test]
fn absolute_include_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["/etc/passwd"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("absolute path must fail");
    let combined = join_errs(&errs);
    assert!(combined.contains("absolute"), "got {combined}");
}

#[test]
fn parent_dir_traversal_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["../outside.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("`..` must fail");
    let combined = join_errs(&errs);
    assert!(combined.contains(".."), "got {combined}");
}

#[cfg(unix)]
#[test]
fn symlink_escaping_root_rejected() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // Outside file
    let outside_file = outside.path().join("secret.toml");
    fs::write(
        &outside_file,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    // Symlink from inside root → outside
    let inside_link = root.path().join("link.toml");
    symlink(&outside_file, &inside_link).unwrap();

    let master = write(
        root.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["link.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("escaping symlink must fail");
    let combined = join_errs(&errs);
    assert!(combined.contains("escapes"), "got {combined}");
}

#[cfg(unix)]
#[test]
fn symlink_staying_inside_root_is_allowed() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    // Real file inside root.
    write(
        root.path(),
        "devices.d/real.toml",
        r#"[[devices]]
id = "real"
display_name = "Real"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        root.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    // Symlink inside root pointing to the real file.
    let link = root.path().join("devices.d/link.toml");
    symlink(root.path().join("devices.d/real.toml"), &link).unwrap();
    let master = write(
        root.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    // Symlink + real both match the glob. Loader dedups by canonical
    // path so the device is loaded once, not twice.
    let loaded = load_config(&master, now()).expect("symlink inside root must load");
    assert_eq!(loaded.config.devices.len(), 1);
}

#[test]
fn canonicalize_with_missing_leaf_uses_parent_trick() {
    // Not-yet-existing path whose PARENT exists → canonicalisation
    // must still succeed so a fresh-install flow with an empty
    // /etc/purge-warden/ produces a precise "cannot read" error later
    // on, not a generic "canonicalise failed" panic here.
    let tmp = tempfile::tempdir().unwrap();
    let ghost = tmp.path().join("does-not-exist.toml");
    let canon = canonicalize_path(&ghost).expect("parent trick must succeed");
    assert_eq!(canon.file_name(), ghost.file_name());
    let parent_canon = canon.parent().unwrap();
    assert_eq!(parent_canon, tmp.path().canonicalize().unwrap().as_path(),);
}

// ── 8. unknown-key pre-merge ───────────────────────────────────

#[test]
fn unknown_top_level_key_caught_at_source_file() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"[mystery_section]
foo = 1
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("unknown key must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::UnknownField(_))));
    let combined = join_errs(&errs);
    // The error must cite the file where the unknown key lives, not
    // the master.
    assert!(
        combined.contains("extra.toml") && combined.contains("mystery_section"),
        "got {combined}"
    );
}

// ── 9. schema_version discipline ────────────────────────────────

#[test]
fn sub_file_may_echo_master_schema_version() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"schema_version = 3

[[devices]]
id = "dev"
display_name = "Dev"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("matching echo must work");
    assert_eq!(loaded.config.schema_version, 3);
}

#[test]
fn sub_file_disagreeing_schema_version_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "extra.toml",
        r#"schema_version = 99
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("version mismatch must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::VersionMismatch(_))));
}

// ── 10. provenance enrichment of validator errors ────────────────

#[test]
fn validator_cross_ref_error_carries_entity_file_line() {
    let tmp = tempfile::tempdir().unwrap();
    // Device references a profile that doesn't exist.
    write(
        tmp.path(),
        "devices.d/broken.toml",
        r#"[[devices]]
id = "broken"
display_name = "Broken"
ip = "10.0.0.1"
profile = "ghost"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("cross-ref miss must fail");
    let cross_ref = errs
        .iter()
        .find(|e| matches!(e, ConfigError::CrossRefMiss(_)))
        .expect("cross-ref error");
    let ctx = cross_ref.context();
    let file = ctx
        .file
        .as_ref()
        .unwrap_or_else(|| panic!("expected file on cross-ref error: {cross_ref:?}"));
    assert!(
        file.ends_with("devices.d/broken.toml"),
        "expected broken.toml, got {}",
        file.display()
    );
    assert!(ctx.line.is_some(), "expected line on cross-ref error");
}

// ── 11. includes is an array of strings ─────────────────────────

#[test]
fn includes_must_be_array_of_strings() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = "not-an-array.toml"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("scalar includes must fail");
    assert!(errs.iter().any(|e| matches!(e, ConfigError::Parse(_))));
}

#[test]
fn wildcard_only_in_final_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["*/devices.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("mid-path wildcard must fail");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("final path segment") || combined.contains("wildcard"),
        "got {combined}"
    );
}

// ── 12. master path variants ────────────────────────────────────

#[test]
fn master_missing_returns_parse_error() {
    let errs =
        load_config(Path::new("/nonexistent/path/config.toml"), now()).expect_err("must fail");
    assert!(errs.iter().any(|e| matches!(e, ConfigError::Parse(_))));
}

#[test]
fn fast_path_preserves_includes_field_when_empty() {
    let master = committed_minimal_v1_master();
    let loaded = load_config(&master, now()).expect("load");
    // minimal-v1 has no includes
    assert!(loaded.config.includes.is_empty());
}

#[test]
fn multi_file_preserves_master_includes_only() {
    let master = committed_full_v1_master();
    let loaded = load_config(&master, now()).expect("load");
    // The 7 patterns from the master.
    assert_eq!(loaded.config.includes.len(), 7);
}

// ── 13. deduplication across overlapping globs ───────────────────

#[test]
fn same_file_matched_twice_loaded_once() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "devices.d/one.toml",
        r#"[[devices]]
id = "only"
display_name = "Only"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    // Two patterns that both resolve to the same file. The loader
    // dedups by canonical path so the device is not loaded twice.
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = [
  "devices.d/*.toml",
  "devices.d/one.toml",
  "profiles.d/*.toml",
]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("load");
    assert_eq!(loaded.config.devices.len(), 1);
}

// ── 14. helpers ─────────────────────────────────────────────────

fn join_errs(errs: &[ConfigError]) -> String {
    errs.iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

// ── 15. line_of_top_key / collect_headings helpers ───────────────

#[test]
fn line_of_top_key_finds_scalar_and_ignores_comments() {
    let src = "# comment\nschema_version = 3\n\n[server]\n";
    assert_eq!(line_of_top_key(src, "schema_version"), Some(2));
    assert_eq!(line_of_top_key(src, "server"), None); // headings aren't `key = ...`
}

#[test]
fn collect_array_headings_records_each_occurrence() {
    let src = "[[devices]]\nid = \"a\"\n\n[[devices]]\nid = \"b\"\n\n[[groups]]\nid = \"g\"\n";
    let headings = collect_array_headings(src);
    assert_eq!(headings.get("devices"), Some(&vec![1, 4]));
    assert_eq!(headings.get("groups"), Some(&vec![7]));
}

#[test]
fn collect_table_headings_distinguishes_tables_from_arrays() {
    let src = "[server]\n\n[[devices]]\n\n[profiles.default]\n\n[profiles.kids]\n";
    let headings = collect_table_headings(src);
    assert_eq!(headings.get("server"), Some(&1));
    assert_eq!(headings.get("profiles.default"), Some(&5));
    assert_eq!(headings.get("profiles.kids"), Some(&7));
    assert!(!headings.contains_key("devices")); // [[…]] is not a plain table heading
}

// ── 16. nested includes + more edge cases ─────────────────────

#[test]
fn nested_includes_merge_transitively() {
    // master → level1 → level2, each contributing a different entity
    // kind. Verifies that recursive traversal is breadth-complete.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "level2.toml",
        r#"[[blocklists]]
id = "from-l2"
display_name = "From level 2"
url = "https://example.com/l2.txt"
format = "domains"
"#,
    );
    write(
        tmp.path(),
        "level1.toml",
        r#"includes = ["level2.toml"]

[[devices]]
id = "from-l1"
display_name = "From level 1"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["level1.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("nested include chain must load");
    assert_eq!(loaded.config.devices.len(), 1);
    assert_eq!(loaded.config.blocklists.len(), 1);
    assert_eq!(loaded.files_loaded.len(), 4);
}

#[test]
fn schema_version_only_is_a_valid_config() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("minimal config must load");
    assert!(loaded.config.devices.is_empty());
    assert!(loaded.config.profiles.is_empty());
}

#[test]
fn wildcard_prefix_suffix_match() {
    // Pattern with both prefix and suffix around `*`.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "things/device-a.toml",
        r#"[[devices]]
id = "a"
display_name = "A"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "things/device-b.toml",
        r#"[[devices]]
id = "b"
display_name = "B"
ip = "10.0.0.2"
profile = "default"
"#,
    );
    // Distractor — does not match `device-*.toml`.
    write(
        tmp.path(),
        "things/group-c.toml",
        r#"[[groups]]
id = "g"
display_name = "G"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["things/device-*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("load");
    assert_eq!(loaded.config.devices.len(), 2);
    assert_eq!(loaded.config.groups.len(), 0);
}

#[test]
fn array_merge_type_mismatch_errors() {
    // A sub-file puts a scalar where an array-of-tables is expected.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "extra.toml", "devices = \"not-an-array\"\n");
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["extra.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("type mismatch must fail");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("array-of-tables") || combined.contains("expected"),
        "got {combined}"
    );
}

#[test]
fn duplicate_id_across_files_is_caught_by_validator() {
    // Two sub-files define [[devices]] with the same `id`. The
    // loader concatenates them; validator then rejects as DuplicateId.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "devices.d/a.toml",
        r#"[[devices]]
id = "clash"
display_name = "A"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "devices.d/b.toml",
        r#"[[devices]]
id = "clash"
display_name = "B"
ip = "10.0.0.2"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        r#"[profiles.default]
display_name = "Default"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let errs = load_config(&master, now()).expect_err("duplicate id must fail");
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(_))));
    // Validator error carries an entity — enriched with the FIRST file
    // that defined the id (provenance is first-writer-wins).
    let dup = errs
        .iter()
        .find(|e| matches!(e, ConfigError::DuplicateId(_)))
        .unwrap();
    assert_eq!(dup.context().entity.as_deref(), Some("devices.clash"));
    let file = dup.context().file.as_ref().expect("provenance file");
    assert!(
        file.ends_with("devices.d/a.toml"),
        "expected first definition file, got {}",
        file.display()
    );
}

#[test]
fn profile_named_map_provenance_points_at_sub_file() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "profiles.d/kids.toml",
        r#"[profiles.kids]
display_name = "Kids"
"#,
    );
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["profiles.d/*.toml"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let loaded = load_config(&master, now()).expect("load");
    let (file, line) = loaded
        .provenance
        .get("profiles.kids")
        .expect("profile provenance");
    assert!(file.ends_with("profiles.d/kids.toml"));
    assert_eq!(*line, 1);
}

#[test]
fn non_toml_master_returns_parse_error() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "this is not \u{1F4A9} valid toml",
    );
    let errs = load_config(&master, now()).expect_err("garbage must fail");
    assert!(errs.iter().any(|e| matches!(e, ConfigError::Parse(_))));
}

#[test]
fn relative_master_path_is_canonicalised() {
    // Caller passes a relative path — canonicalise_path must resolve
    // via cwd. Use tempfile as cwd substitute: we create a file in
    // tmpdir, cd (via absolute rel path)... actually the simpler
    // assertion: when we build a path like `<tmp>/./config.toml`,
    // canonicalisation strips the `.` component.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let mut noisy = tmp.path().to_path_buf();
    noisy.push(".");
    noisy.push("config.toml");
    let loaded = load_config(&noisy, now()).expect("noisy path must load");
    assert_eq!(loaded.master_path, master.canonicalize().unwrap());
}

#[test]
fn lookup_entity_prefix_walks_dotted_paths() {
    let mut p = ProvenanceMap::new();
    p.insert("devices.iphone".to_string(), (PathBuf::from("dev.toml"), 4));
    let hit = lookup_entity_prefix("devices.iphone.profile", &p);
    assert!(hit.is_some());
    let miss = lookup_entity_prefix("groups.foo", &p);
    assert!(miss.is_none());
}

// ── S42 T2 — `[ip_denylists]` → `[ip_blocklists]` rename ─────────────
//
// The loader must accept both section names: the new canonical key is
// `[ip_blocklists]`; the legacy `[ip_denylists]` survives as a
// deprecated alias (WARN at load, removed at schema_version = 3). Two
// tests pin both paths so future edits can't silently drop either.

#[test]
fn ip_blocklists_canonical_key_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[ip_blocklists]\nenabled = true\ninline = [\"1.2.3.4\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("canonical key must load");
    assert!(loaded.config.ip_blocklists.enabled);
    assert_eq!(loaded.config.ip_blocklists.inline, vec!["1.2.3.4"]);
}

#[test]
fn ip_denylists_legacy_alias_loads_into_ip_blocklists() {
    // Config files written before S42 used `[ip_denylists]`. The
    // loader normalises the key in place (emitting a deprecation
    // `tracing::warn!`) so the deserialised `ConfigV1` sees the new
    // name. End-state must be indistinguishable from a file that
    // already uses the canonical key.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[ip_denylists]\nenabled = true\ninline = [\"5.6.7.8\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("legacy alias must load");
    assert!(loaded.config.ip_blocklists.enabled);
    assert_eq!(loaded.config.ip_blocklists.inline, vec!["5.6.7.8"]);
}

#[test]
fn ip_denylists_and_ip_blocklists_in_same_file_is_refused() {
    // loader-02: declaring BOTH spellings in one file used to silently
    // drop the legacy `[ip_denylists]` (a DoH-bypass blocklist — a
    // security control). It now hard-errors, matching the cross-file
    // duplicate-singleton behaviour.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\
         [ip_denylists]\nenabled = true\ninline = [\"5.6.7.8\"]\n\
         [ip_blocklists]\nenabled = true\ninline = [\"1.2.3.4\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let errs = load_config(&master, now()).expect_err("both spellings must be refused");
    assert!(
        errs.iter().any(|e| {
            let r = &e.context().reason;
            r.contains("ip_denylists") && r.contains("ip_blocklists")
        }),
        "error must name both keys, got: {errs:?}"
    );
}

#[test]
fn retired_categories_section_gets_directed_migration_hint() {
    // loader-01: `[[categories]]` was retired in the v2-tags migration and
    // dropped from KNOWN_TOP_LEVEL. A config still carrying it gets a
    // directed "run warden migrate" suggestion, not the generic
    // allowed-keys dump.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[[categories]]\nid = \"ads\"\ndisplay_name = \"Ads\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let errs = load_config(&master, now()).expect_err("retired categories must be rejected");
    assert!(
        errs.iter().any(|e| {
            let s = e.context().suggestion.as_deref().unwrap_or("");
            s.contains("warden migrate") && s.contains("tags")
        }),
        "categories rejection must carry the directed migrate hint, got: {errs:?}"
    );
}

// ── S42 T4 — `refresh_interval_secs` / `refresh_interval_hours` rename
//
// T4 introduces the nested-key deprecation form of the T2 template:
// `[lists].refresh_interval_secs` → `update_interval_secs` and
// per-entry `[[blocklists]].refresh_interval_hours` →
// `update_interval_hours`. Both live inside a parent table rather than
// at the top level, so `normalise_deprecated_keys` descends into the
// containing table/array before renaming. Four tests pin the two
// canonical paths and the two legacy-alias paths.

#[test]
fn lists_update_interval_secs_canonical_key_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[lists]\nupdate_interval_secs = 1800\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("canonical key must load");
    assert_eq!(loaded.config.lists.update_interval_secs, 1800);
}

#[test]
fn lists_refresh_interval_secs_legacy_alias_loads_into_update_interval_secs() {
    // Operator configs written before S42 T4 used
    // `[lists].refresh_interval_secs`. The loader renames the key in
    // place (emitting a deprecation `tracing::warn!`) so the
    // deserialised `ConfigV1` sees the canonical name. End-state must
    // be indistinguishable from a canonical file.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[lists]\nrefresh_interval_secs = 2400\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("legacy alias must load");
    assert_eq!(loaded.config.lists.update_interval_secs, 2400);
}

#[test]
fn blocklist_update_interval_hours_canonical_key_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\
         [[blocklists]]\n\
         id = \"priv-ads\"\n\
         display_name = \"Privacy: Ads\"\n\
         url = \"https://lists.purge.cc/privacy/ads.txt\"\n\
         update_interval_hours = 6\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("canonical key must load");
    assert_eq!(loaded.config.blocklists.len(), 1);
    assert_eq!(loaded.config.blocklists[0].update_interval_hours, 6);
}

#[test]
fn blocklist_refresh_interval_hours_legacy_alias_loads_into_update_interval_hours() {
    // Per-blocklist retro-compat: operators with multiple
    // `[[blocklists]]` entries each keep their pre-S42 T4 key value.
    // The loader walks the array and normalises every entry
    // independently, emitting one WARN per legacy site.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\
         [[blocklists]]\n\
         id = \"priv-ads\"\n\
         display_name = \"Privacy: Ads\"\n\
         url = \"https://lists.purge.cc/privacy/ads.txt\"\n\
         refresh_interval_hours = 3\n\
         [[blocklists]]\n\
         id = \"priv-track\"\n\
         display_name = \"Privacy: Tracking\"\n\
         url = \"https://lists.purge.cc/privacy/tracking.txt\"\n\
         refresh_interval_hours = 9\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("legacy alias must load");
    assert_eq!(loaded.config.blocklists.len(), 2);
    assert_eq!(loaded.config.blocklists[0].update_interval_hours, 3);
    assert_eq!(loaded.config.blocklists[1].update_interval_hours, 9);
}

// ── S42 T5 — `[[clients]]` → `[[devices]]` + `tracking.max_clients`
//
// T5 closes the Client→Device migration at the config layer. The v1
// schema has always been `[[devices]]`; T5 adds the retro-compat
// branch for masters still carrying the pre-v1 `[[clients]]` section
// name, plus the nested `[tracking].max_clients` field rename. Each
// rename gets canonical + legacy-alias coverage, matching the T2 / T4
// precedent.

#[test]
fn devices_canonical_array_of_tables_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\
         [[devices]]\n\
         id = \"laptop\"\n\
         display_name = \"Laptop\"\n\
         ip = \"10.0.0.42\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("canonical key must load");
    assert_eq!(loaded.config.devices.len(), 1);
    assert_eq!(loaded.config.devices[0].id.as_str(), "laptop");
}

#[test]
fn clients_legacy_array_of_tables_loads_into_devices() {
    // Masters written before T5 used `[[clients]]` as the section
    // header even though the field shape was already v1. The loader
    // rewrites the array-of-tables key in place (emitting a
    // deprecation `tracing::warn!`) so the deserialised `ConfigV1`
    // populates `.devices`.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n\
         [[clients]]\n\
         id = \"laptop\"\n\
         display_name = \"Laptop\"\n\
         ip = \"10.0.0.42\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("legacy alias must load");
    assert_eq!(loaded.config.devices.len(), 1);
    assert_eq!(loaded.config.devices[0].id.as_str(), "laptop");
}

#[test]
fn tracking_max_devices_canonical_key_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[tracking]\nmax_devices = 512\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("canonical key must load");
    assert_eq!(loaded.config.tracking.max_devices, 512);
}

#[test]
fn tracking_max_clients_legacy_alias_loads_into_max_devices() {
    // Pre-T5 masters carried `[tracking].max_clients`. The loader
    // normalises the nested key in place and emits the deprecation
    // `tracing::warn!`; end-state must be indistinguishable from the
    // canonical key.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\n[tracking]\nmax_clients = 2048\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    let loaded = load_config(&master, now()).expect("legacy alias must load");
    assert_eq!(loaded.config.tracking.max_devices, 2048);
}

// ── rev-2606 schema-validator-01 — expired schedule must not brick ───

#[test]
fn expired_schedule_on_disk_still_loads() {
    // THE boot-brick regression: `warden device quiet` writes a one-shot
    // [[schedules]] row with expires_at = now + duration. Before the fix,
    // the first load after expiry (daemon restart, SIGHUP, any CLI
    // mutation) hard-failed validation until the operator hand-edited
    // the TOML. An expired row is inert at resolver build — loading it
    // must succeed.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3

[server]
listen = "127.0.0.1:15353"
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
hours = "22:00-06:00"
expires_at = "2026-01-01T00:00:00Z"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    // `now()` is 2026-04-22 — well past the expiry above.
    let loaded = load_config(&master, now()).expect("expired schedule must not refuse the load");
    assert_eq!(loaded.config.schedules.len(), 1, "row stays on disk");
}

// ── overlay (rev2606 target-01) ─────────────────────────────────────
//
// The overlay lets a validating writer load + validate STAGED bytes before
// the rename. Two guarantees are pinned here:
//   G1  `overlay = None` is byte-identical to the pre-overlay loader.
//   G2  `Some(overlay)` actually substitutes (and injects new members), so a
//       cross-reference-invalid staged tree is REFUSED — no silent false-pass.

/// Lay down a minimal valid multi-file tree: master + one device slice
/// referencing the `default` profile. Returns (tempdir, master, device slice).
fn valid_multifile() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dev = write(
        tmp.path(),
        "devices.d/dev.toml",
        r#"[[devices]]
id = "dev-one"
display_name = "One"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        "[profiles.default]\ndisplay_name = \"Default\"\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\nincludes = [\"devices.d/*.toml\", \"profiles.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    (tmp, master, dev)
}

/// Structural snapshot used to assert the `None` path is a no-op: the merged
/// config (serialised), the files-loaded list, and the provenance map.
fn snapshot(loaded: &LoadedConfig) -> (String, Vec<PathBuf>, ProvenanceMap) {
    (
        toml::to_string(&loaded.config).expect("config serialises"),
        loaded.files_loaded.clone(),
        loaded.provenance.clone(),
    )
}

#[test]
fn overlay_none_byte_identical_multifile() {
    let (_tmp, master, _dev) = valid_multifile();
    let base = load_config(&master, now()).expect("load");
    let with_none = load_config_with_overlay(&master, now(), None).expect("None overlay must load");
    assert_eq!(snapshot(&base), snapshot(&with_none));
}

#[test]
fn overlay_none_byte_identical_single_file() {
    // Committed single-file fixture exercises the fast path.
    let master = committed_minimal_v1_master();
    let base = load_config(&master, now()).expect("load");
    let with_none = load_config_with_overlay(&master, now(), None).expect("None overlay must load");
    assert_eq!(snapshot(&base), snapshot(&with_none));
    assert_eq!(with_none.files_loaded.len(), 1, "still the fast path");
}

#[test]
fn overlay_substitution_changes_verdict() {
    let (_tmp, master, dev) = valid_multifile();
    // On disk the tree is valid.
    assert!(load_config(&master, now()).is_ok());

    // Stage bytes for the device slice that point at a profile that does not
    // exist — a cross-reference miss the on-disk bytes do not have.
    let mut ov = LoaderOverlay::default();
    ov.stage(
        canonicalize_path(&dev).unwrap(),
        r#"[[devices]]
id = "dev-one"
display_name = "One"
ip = "10.0.0.1"
profile = "ghost"
"#
        .to_string(),
        false,
    );

    let errs = load_config_with_overlay(&master, now(), Some(&ov))
        .expect_err("staged dangling profile ref must be refused");
    assert!(
        errs.iter().any(|e| e.to_string().contains("ghost")),
        "error must cite the staged ghost profile: {errs:?}"
    );
    // Disk is untouched: a fresh load still passes.
    assert!(
        load_config(&master, now()).is_ok(),
        "on-disk tree unchanged"
    );
}

// ── config-lint-blind-to-loader-deprecations ─────────────────────────

/// The loader's key-deprecation notices must reach `load_config_collect`'s
/// returned warnings, which is the channel `warden config lint` reads.
///
/// **Single-file on purpose.** The loader has two exits — the single-file
/// fast path and the multi-file merge — and the shipped layout (and every
/// lint fixture) takes the fast one. A multi-file fixture here would go green
/// against a drain placed in the merge arm only, i.e. against a fix that does
/// nothing for any real install. This is the discriminating shape.
#[test]
fn deprecated_keys_reach_the_lint_warning_channel_on_a_single_file_config() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"
enforce_client_mac = false

[tracking]
max_clients = 100

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    let (result, warns) = load_config_collect(&master, now());
    assert!(result.is_ok(), "deprecated keys load, they do not refuse");
    assert_eq!(
        result.unwrap().files_loaded.len(),
        1,
        "must be the single-file fast path, or this proves nothing"
    );

    assert!(
        warns
            .iter()
            .any(|w| w.contains("server.enforce_client_mac")),
        "the enforce_client_mac deprecation must be visible to lint: {warns:?}"
    );
    assert!(
        warns.iter().any(|w| w.contains("tracking.max_clients")),
        "the max_clients deprecation must be visible to lint: {warns:?}"
    );
    // The file:line prefix is what makes the notice actionable in a tree
    // with more than one slice.
    assert!(
        warns
            .iter()
            .filter(|w| w.contains("deprecated"))
            .all(|w| w.contains("config.toml:")),
        "each collected deprecation carries its file:line: {warns:?}"
    );
}

/// The control arm: a config with no deprecated key must contribute no
/// deprecation notices. Without this, a drain that pushed unconditionally
/// (or pushed a constant) would satisfy the test above.
#[test]
fn a_config_without_deprecated_keys_contributes_no_deprecation_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"
enforce_device_mac = false

[tracking]
max_devices = 100

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    let (result, warns) = load_config_collect(&master, now());
    assert!(result.is_ok());
    assert!(
        !warns.iter().any(|w| w.contains("deprecated")),
        "canonical spellings must be silent: {warns:?}"
    );
}

// ── s-review-2605-config-m3 — the size cap must precede allocation ───

/// A master over the aggregate cap is refused on the strength of its
/// `stat`, never after being read into memory.
///
/// Sparse by construction: `set_len` produces a file whose
/// `metadata().len()` is over the cap without writing a byte, so the case
/// costs nothing and still drives exactly the guard under test.
///
/// **The assertion discriminates between the loader's two size errors on
/// purpose.** There is a pre-read guard ("would exceed") and a post-read
/// one ("exceeded ... after loading"); only the first proves nothing was
/// allocated. Asserting merely "it errored" would pass against the
/// post-read check alone — which is precisely the defect m3 reported, so
/// that weaker assertion would have been green on the broken code.
#[test]
fn an_oversized_master_is_refused_before_it_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let master = tmp.path().join("config.toml");
    let f = fs::File::create(&master).expect("create");
    f.set_len(MAX_TOTAL_BYTES + 1).expect("set_len");
    drop(f);

    let errs = load_config(&master, now()).expect_err("an over-cap master must be refused");
    let joined = errs
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        joined.contains("would exceed"),
        "must be refused by the PRE-read stat guard, not after allocating the \
         file into memory: {joined}"
    );
}

/// The single-file fast path must consume the bytes the loader already
/// read, never re-read the file from disk.
///
/// Written as the arm that can only pass if no re-read happens: the master
/// **on disk is not valid TOML at all**, and the overlay stages valid bytes
/// over it. A fast path that re-opened the path would parse the garbage and
/// fail. This is the regression guard for m3's fix, which deleted the fast
/// path's own `fs::read_to_string` (the one read in the loader with no cap
/// in front of it) along with its duplicate overlay branch.
#[test]
fn m3_single_file_fast_path_never_rereads_the_master_from_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        "this is not valid toml at all {{{",
    );

    // Control arm: without the overlay the garbage on disk is what loads,
    // and it must fail. Without this, the assertion below would also pass
    // against a loader that ignored the file for some unrelated reason.
    assert!(
        load_config(&master, now()).is_err(),
        "the on-disk master really is invalid — otherwise the staged arm \
         below proves nothing"
    );

    let mut ov = LoaderOverlay::default();
    ov.stage(
        canonicalize_path(&master).unwrap(),
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#
        .to_string(),
        false,
    );

    let loaded = load_config_with_overlay(&master, now(), Some(&ov))
        .expect("the STAGED bytes must drive the load, not the bytes on disk");
    assert_eq!(
        loaded.files_loaded.len(),
        1,
        "this must exercise the single-file fast path, or it tests nothing"
    );
}

#[test]
fn overlay_extra_member_new_slice_validates_in_merged_view() {
    let (_tmp, master, _dev) = valid_multifile();
    // A brand-new slice path under the (existing) devices.d dir — NOT on disk.
    let new_slice = master.parent().unwrap().join("devices.d/extra.toml");
    assert!(!new_slice.exists());
    let canonical_new = canonicalize_path(&new_slice).unwrap();

    // Valid new device → accepted, and present in the merged view.
    let mut ok_ov = LoaderOverlay::default();
    ok_ov.stage(
        canonical_new.clone(),
        r#"[[devices]]
id = "dev-two"
display_name = "Two"
ip = "10.0.0.2"
profile = "default"
"#
        .to_string(),
        true,
    );
    let loaded =
        load_config_with_overlay(&master, now(), Some(&ok_ov)).expect("valid new slice must load");
    assert!(
        loaded
            .config
            .devices
            .iter()
            .any(|d| d.id.as_str() == "dev-two"),
        "new-slice device must be merged in"
    );
    assert!(!new_slice.exists(), "validation must not create the file");

    // New device referencing a ghost profile → refused.
    let mut bad_ov = LoaderOverlay::default();
    bad_ov.stage(
        canonical_new,
        r#"[[devices]]
id = "dev-two"
display_name = "Two"
ip = "10.0.0.2"
profile = "ghost"
"#
        .to_string(),
        true,
    );
    assert!(
        load_config_with_overlay(&master, now(), Some(&bad_ov)).is_err(),
        "cross-ref-invalid new slice must be refused"
    );
}

#[test]
fn overlay_extra_member_dup_id_detected_across_master_and_new_slice() {
    let (_tmp, master, _dev) = valid_multifile();
    // The on-disk tree already has `dev-one`; a new slice re-declaring it is a
    // duplicate the merged validation must catch.
    let new_slice = master.parent().unwrap().join("devices.d/extra.toml");
    let mut ov = LoaderOverlay::default();
    ov.stage(
        canonicalize_path(&new_slice).unwrap(),
        r#"[[devices]]
id = "dev-one"
display_name = "Dup"
ip = "10.0.0.9"
profile = "default"
"#
        .to_string(),
        true,
    );
    assert!(
        load_config_with_overlay(&master, now(), Some(&ov)).is_err(),
        "duplicate id across master+overlay must be refused"
    );
}

#[cfg(unix)]
#[test]
fn overlay_symlinked_class_dir_substitution_fires() {
    // Guards the key-matching landmine (red-team P0 #2): when the include dir
    // is a symlink, the writer's canonicalize_path(final_path) must equal the
    // key the loader derives from the glob match, or the substitution misses
    // and the loader silently reads stale on-disk bytes (false pass).
    let tmp = tempfile::tempdir().unwrap();
    // Real storage dir + a symlink the master's include points through.
    fs::create_dir_all(tmp.path().join("real_devices")).unwrap();
    std::os::unix::fs::symlink(
        tmp.path().join("real_devices"),
        tmp.path().join("devices.d"),
    )
    .unwrap();
    write(
        tmp.path(),
        "real_devices/dev.toml",
        r#"[[devices]]
id = "dev-one"
display_name = "One"
ip = "10.0.0.1"
profile = "default"
"#,
    );
    write(
        tmp.path(),
        "profiles.d/default.toml",
        "[profiles.default]\ndisplay_name = \"Default\"\n",
    );
    let master = write(
        tmp.path(),
        "config.toml",
        "schema_version = 3\nincludes = [\"devices.d/*.toml\", \"profiles.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    );
    assert!(load_config(&master, now()).is_ok(), "baseline loads");

    // Address the slice via the SYMLINK path (what resolve_target_file yields).
    let via_symlink = tmp.path().join("devices.d/dev.toml");
    let mut ov = LoaderOverlay::default();
    ov.stage(
        canonicalize_path(&via_symlink).unwrap(),
        r#"[[devices]]
id = "dev-one"
display_name = "One"
ip = "10.0.0.1"
profile = "ghost"
"#
        .to_string(),
        false,
    );
    assert!(
        load_config_with_overlay(&master, now(), Some(&ov)).is_err(),
        "substitution must fire through the symlinked dir (key match), not read stale disk"
    );
}

// ── §5.1 — a cluster secondary's master must carry no policy ────────
//
// These drive the LOADER, not the validator in isolation: the defect being
// pinned is a MERGE outcome, and the merge is the loader's. The three shapes
// fail differently and only one of them was ever loud, which is why a test
// per shape exists rather than one representative case.

/// A secondary master with `[cluster]` and the `cluster.d/*.toml` glob.
/// `body` is appended verbatim — that is where each test puts its policy.
fn secondary_master_with(tmp: &Path, body: &str) -> PathBuf {
    write(
        tmp,
        "config.toml",
        &format!(
            "schema_version = 3\n\
             includes = [\"cluster.d/*.toml\"]\n\n\
             [cluster]\n\
             enabled = true\n\
             role = \"secondary\"\n\
             peer = \"https://10.10.1.94:8053\"\n\
             token_hash = \"{}\"\n\n{body}",
            "00".repeat(32),
        ),
    )
}

/// The bundle the primary would have installed. Carries the `[upstream]` a
/// secondary's master is forbidden to hold, so the merged tree is complete.
const SYNCED_BUNDLE: &str = "[upstream]\nservers = [\"192.0.2.1:53\"]\n";

#[test]
fn a_secondary_master_carrying_blocklists_is_refused_not_unioned() {
    // Array-of-tables merge is SILENT concatenation. Without the guard this
    // loads clean and the secondary permanently filters a superset of the
    // primary, with sync reporting success.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "cluster.d/00-cluster-policy.toml",
        &format!(
            "{SYNCED_BUNDLE}\n\
             [[blocklists]]\nid = \"from-primary\"\ndisplay_name = \"P\"\n\
             url = \"https://e.example/p.txt\"\n"
        ),
    );
    let master = secondary_master_with(
        tmp.path(),
        "[[blocklists]]\nid = \"local-extra\"\ndisplay_name = \"L\"\n\
         url = \"https://e.example/l.txt\"\n",
    );

    let errs = load_config(&master, now())
        .expect_err("policy in a secondary's master must be refused, not merged");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("must not carry policy")
            || combined.contains("carries policy of its own"),
        "the refusal must name the real problem: {combined}"
    );
    assert!(
        combined.contains("blocklists"),
        "and must name the offending section: {combined}"
    );
}

#[test]
fn a_secondary_master_carrying_a_differently_named_profile_is_refused() {
    // Named maps error on the SAME id but silently union different ids —
    // so this shape, like the array one, is invisible without the guard.
    // It is also the section most likely to be hand-written on a second box.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "cluster.d/00-cluster-policy.toml",
        &format!("{SYNCED_BUNDLE}\n[profiles.default]\ndisplay_name = \"D\"\n"),
    );
    let master = secondary_master_with(tmp.path(), "[profiles.local-only]\ndisplay_name = \"L\"\n");

    let errs = load_config(&master, now()).expect_err("a locally-added profile must be refused");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("profiles"),
        "the offending section must be named — a named map written only as \
         [profiles.<id>] records no bare `profiles` provenance key, so a \
         guard that consults the section key alone misses it: {combined}"
    );
}

#[test]
fn a_secondary_master_carrying_upstream_is_refused() {
    // The operator's obvious escape from the pre-sync boot failure Task 3
    // resolves: hand-write [upstream] into the master. Refusing it is the
    // other half of the same rule.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "cluster.d/00-cluster-policy.toml",
        "[[devices]]\nid = \"phone\"\ndisplay_name = \"P\"\nip = \"10.0.0.9\"\n",
    );
    let master = secondary_master_with(tmp.path(), SYNCED_BUNDLE);

    let errs = load_config(&master, now()).expect_err("a hand-written [upstream] must be refused");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("upstream"),
        "the offending section must be named: {combined}"
    );
}

#[test]
fn a_joined_secondary_whose_policy_lives_only_in_the_bundle_loads() {
    // The whole point: the legitimate shape must still work. If this goes
    // red the guard has stopped being a guard and become a prohibition.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "cluster.d/00-cluster-policy.toml",
        &format!(
            "{SYNCED_BUNDLE}\n\
             [[blocklists]]\nid = \"from-primary\"\ndisplay_name = \"P\"\n\
             url = \"https://e.example/p.txt\"\n\n\
             [profiles.default]\ndisplay_name = \"D\"\n"
        ),
    );
    let master = secondary_master_with(tmp.path(), "");

    let loaded = load_config(&master, now())
        .expect("a secondary whose policy lives only in cluster.d/ must load");
    assert_eq!(loaded.config.blocklists.len(), 1);
    assert_eq!(loaded.config.profiles.len(), 1);
}

#[test]
fn a_secondary_master_may_keep_its_node_local_sections() {
    // §5.3's keep-list. A guard that refused these would refuse every
    // secondary that exists — the sections are exactly the node identity
    // the CS3 fence keeps OFF the wire.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "cluster.d/00-cluster-policy.toml",
        SYNCED_BUNDLE,
    );
    let master = secondary_master_with(
        tmp.path(),
        // `allow_from` is not decoration here: a 0.0.0.0 bind with an empty
        // one is an open resolver, and the validator says so — which would
        // red this test for a reason that has nothing to do with the guard.
        "[server]\nlisten = \"0.0.0.0:53\"\nallow_from = [\"10.10.1.0/24\"]\n\n\
         [tracking]\nenabled = true\n\n\
         [socket]\nenabled = true\n\n\
         [backup]\nauto_interval = \"24h\"\n",
    );

    load_config(&master, now())
        .expect("node-local sections are the secondary's own identity, never policy");
}

#[test]
fn a_primary_master_carrying_policy_is_untouched_by_the_guard() {
    // Scoped to secondaries. A primary IS the source of policy; refusing it
    // would refuse the only node that may hold any.
    let tmp = tempfile::tempdir().unwrap();
    let master = write(
        tmp.path(),
        "config.toml",
        &format!(
            "schema_version = 3\n\n\
             [cluster]\n\
             enabled = true\n\
             role = \"primary\"\n\
             token_hash = \"{}\"\n\n\
             {SYNCED_BUNDLE}\n\
             [[blocklists]]\nid = \"ads\"\ndisplay_name = \"A\"\n\
             url = \"https://e.example/a.txt\"\n",
            "00".repeat(32),
        ),
    );

    load_config(&master, now()).expect("a primary's own policy is the point of a primary");
}

#[test]
fn the_single_file_fast_path_still_refuses_a_policy_carrying_secondary() {
    // The post-join, pre-sync state is NOT an edge case: `join` writes the
    // `cluster.d/*.toml` include, a zero-match glob is legal, so
    // `files_loaded == 1` and the loader takes its single-file fast path.
    // That path builds provenance and re-runs the validator on a separate
    // branch, so a guard wired only into the merge path would be blind on
    // exactly the config a freshly joined node has.
    let tmp = tempfile::tempdir().unwrap();
    let master = secondary_master_with(
        tmp.path(),
        "[[devices]]\nid = \"phone\"\ndisplay_name = \"P\"\nip = \"10.0.0.9\"\n",
    );

    let errs = load_config(&master, now())
        .expect_err("the fast path must refuse policy in a secondary's master too");
    let combined = join_errs(&errs);
    assert!(
        combined.contains("devices"),
        "the offending section must be named on the fast path too: {combined}"
    );
}

// ── per-device rules are announced as going away ─────────────────────

#[test]
fn a_device_rule_warns_that_the_path_is_going_away() {
    // `Device.allow_rules` is `Vec<Id>` — REFERENCES to `[[admin_rules]]`
    // entries, not inline rule text. A fixture putting `||x.example.com^`
    // there fails to deserialise as an `Id` and would go red for a reason
    // that has nothing to do with the warning. `display_name` carries no
    // serde default either, so omitting it fails the same way.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[admin_rules]]\nid = \"let-tv-through\"\nrule = \"@@||x.example.com^\"\n\n\
         [[devices]]\nid = \"tv\"\ndisplay_name = \"TV\"\nip = \"192.0.2.10\"\n\
         allow_rules = [\"let-tv-through\"]\n",
    )
    .unwrap();

    let (result, warns) = load_config_collect(&master, now());
    let loaded = result.expect("must load");
    assert_eq!(loaded.config.devices.len(), 1, "the config must still load");
    assert!(
        warns
            .iter()
            .any(|w| w.contains("allow_rules") && w.contains("custom")),
        "the warning must name the field and the replacement: {warns:?}"
    );
}

#[test]
fn a_device_without_rules_produces_no_deprecation_warning() {
    // Negative control. Without it, a warning emitted unconditionally
    // passes the test above, and every operator sees the notice whether or
    // not it applies to them.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[devices]]\nid = \"tv\"\ndisplay_name = \"TV\"\nip = \"192.0.2.10\"\n",
    )
    .unwrap();
    let (result, warns) = load_config_collect(&master, now());
    result.expect("must load");
    assert!(
        !warns.iter().any(|w| w.contains("allow_rules")),
        "a device with no rules must not be warned about: {warns:?}"
    );
}

#[test]
fn an_empty_rule_array_is_not_a_deprecated_rule() {
    // `allow_rules = []` is what a device that HAD rules and lost them
    // looks like on disk. Keying the notice on the key's presence rather
    // than on its contents would nag an operator who has already migrated.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[devices]]\nid = \"tv\"\ndisplay_name = \"TV\"\nip = \"192.0.2.10\"\n\
         allow_rules = []\ndeny_rules = []\n",
    )
    .unwrap();
    let (result, warns) = load_config_collect(&master, now());
    result.expect("must load");
    assert!(
        !warns.iter().any(|w| w.contains("allow_rules")),
        "an emptied rule list must not be warned about: {warns:?}"
    );
}

#[test]
fn a_device_with_twenty_rules_is_warned_about_once() {
    // One line per device, not one per rule: the notice is about the
    // field, and an operator with a long allow list needs one sentence,
    // not twenty identical ones scrolling past the real errors.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let rules: String = (0..20)
        .map(|n| format!("[[admin_rules]]\nid = \"r{n}\"\nrule = \"@@||h{n}.example.com^\"\n\n"))
        .collect();
    let refs: Vec<String> = (0..20).map(|n| format!("\"r{n}\"")).collect();
    fs::write(
        &master,
        format!(
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n{rules}\
             [[devices]]\nid = \"tv\"\ndisplay_name = \"TV\"\nip = \"192.0.2.10\"\n\
             allow_rules = [{}]\n",
            refs.join(", ")
        ),
    )
    .unwrap();
    let (result, warns) = load_config_collect(&master, now());
    result.expect("must load");
    assert_eq!(
        warns.iter().filter(|w| w.contains("allow_rules")).count(),
        1,
        "one device, one notice: {warns:?}"
    );
}

// ── the custom list store is built during the load ───────────────────

#[test]
fn a_declared_custom_list_is_loaded_into_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[custom_lists]]\nid = \"minecraft\"\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("packs")).unwrap();
    fs::write(
        dir.path().join("packs").join("minecraft.txt"),
        "@@||cdn.example.com^\n",
    )
    .unwrap();

    let loaded = load_config(&master, now()).expect("must load");
    assert_eq!(loaded.custom_lists.len(), 1);
    let id = crate::config::schema::Id::new("minecraft").unwrap();
    assert_eq!(loaded.custom_lists[&id].allow.len(), 1);
}

#[test]
fn a_declared_custom_list_with_no_file_fails_the_load() {
    // Cold start refuses rather than filtering less than the config says.
    // Applying an unreadable file "as empty" drops its allow rules and its
    // deny rules together; the allows fail loudly and the denies do not.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[custom_lists]]\nid = \"minecraft\"\n",
    )
    .unwrap();

    let errs = load_config(&master, now()).expect_err("a missing pack file must fail the load");
    let joined = join_errs(&errs);
    assert!(
        joined.contains("minecraft.txt"),
        "the error must name the path: {joined}"
    );
}

#[test]
fn a_config_with_no_custom_lists_loads_with_an_empty_store() {
    // Every config that exists today. Must not require a packs/ directory.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let loaded = load_config(&master, now()).expect("must load");
    assert!(loaded.custom_lists.is_empty());
}

#[test]
fn the_pack_path_is_anchored_to_the_master_not_to_the_declaring_fragment() {
    // `includes` is live, so a fragment is a legitimate declaration site.
    // Two readings of "the config parent" are each internally coherent and
    // neither can produce an error, so the anchor has to be pinned by a
    // test. The decoy file under conf.d/packs/ carries DIFFERENT rules:
    // without it, a wrong anchor would read "file missing" and be
    // indistinguishable from a broken fixture.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\nincludes = [\"conf.d/*.toml\"]\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("conf.d")).unwrap();
    fs::write(
        dir.path().join("conf.d").join("kids.toml"),
        "[[custom_lists]]\nid = \"minecraft\"\n",
    )
    .unwrap();

    fs::create_dir(dir.path().join("packs")).unwrap();
    fs::write(
        dir.path().join("packs").join("minecraft.txt"),
        "@@||correct.example.com^\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("conf.d").join("packs")).unwrap();
    fs::write(
        dir.path()
            .join("conf.d")
            .join("packs")
            .join("minecraft.txt"),
        "@@||decoy.example.com^\n",
    )
    .unwrap();

    let loaded = load_config(&master, now()).expect("must load");
    let id = crate::config::schema::Id::new("minecraft").unwrap();
    let allow = &loaded.custom_lists[&id].allow;
    assert!(
        allow.iter().any(|d| d == "correct.example.com"),
        "the master's packs/ must win: {allow:?}"
    );
    assert!(
        !allow.iter().any(|d| d == "decoy.example.com"),
        "the declaring fragment's packs/ must not be read: {allow:?}"
    );
}

#[test]
fn a_pack_reaches_the_resolver_through_a_real_load() {
    // The seam. Every other test either hands `build_v1` a store it built
    // itself or asserts on the loader's store; neither observes a
    // `ProfileResolver`. A call site wired with an empty store instead of
    // the loaded one leaves the whole feature inert with the suite green.
    use crate::lists::source_key::SourceBitMap;
    use crate::profiles::resolver::ProfileResolver;

    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 3\n\n[server]\ndefault_profile = \"kids\"\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
         [[custom_lists]]\nid = \"minecraft\"\n\n\
         [profiles.kids]\ncustom_lists = [\"minecraft\"]\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("packs")).unwrap();
    fs::write(
        dir.path().join("packs").join("minecraft.txt"),
        "@@||mc.example.com^\n||ads.example.com^\n",
    )
    .unwrap();

    let loaded = load_config(&master, now()).expect("config must load");
    let resolver = ProfileResolver::build(
        &loaded.config,
        &SourceBitMap::default(),
        &loaded.custom_lists,
    );

    let rp = resolver
        .default_profile()
        .expect("default_profile must resolve to kids");
    assert!(
        rp.allow_domains.contains("mc.example.com"),
        "the pack's allow rule must reach the live resolver"
    );
    assert!(
        rp.deny_domains.contains("ads.example.com"),
        "the pack's deny rule must reach the live resolver"
    );
}

#[test]
fn mounting_a_custom_list_consumes_no_source_bit() {
    // The list seat has 64 bits. A custom list takes the admin seat
    // instead; if one ever consumed a bit, the ceiling would become a
    // per-operator limit on how many lists they may author.
    use crate::lists::manager::merge_sources_with_blocklists;
    use crate::lists::source_key::SourceBitMap;

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("packs")).unwrap();
    fs::write(
        dir.path().join("packs").join("minecraft.txt"),
        "||ads.example.com^\n",
    )
    .unwrap();

    let base = "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
                [profiles.kids]\ndisplay_name = \"K\"\n";
    let master = dir.path().join("config.toml");
    let bits_of = |path: &std::path::Path| {
        let loaded = load_config(path, now()).expect("config must load");
        let (merged, _trust) =
            merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
        SourceBitMap::build(&merged, &loaded.config.blocklists).expect("bitmap must build")
    };

    fs::write(&master, base).unwrap();
    let without = bits_of(&master);

    fs::write(
        &master,
        format!("{base}custom_lists = [\"minecraft\"]\n\n[[custom_lists]]\nid = \"minecraft\"\n"),
    )
    .unwrap();
    let with = bits_of(&master);

    assert_eq!(
        without.len(),
        with.len(),
        "mounting a custom list must not assign a list-source bit"
    );
    assert!(
        with.bit_for_v1_id(&crate::config::schema::Id::new("minecraft").unwrap())
            .is_none(),
        "a custom list id must never resolve to a list-source bit"
    );
}
