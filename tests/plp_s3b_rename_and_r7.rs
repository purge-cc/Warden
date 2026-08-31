//! plp-s3b — the wire rename (`kind` → `base`, `BlocklistBase::Ignore`,
//! `SCHEMA_VERSION_V1 = 3`) and R7, the ordering that keeps the bump from
//! being an outage.
//!
//! `_docs/features/profile_list_policy.md` §2.1 P6 and §6.1.
//!
//! **What R7 is about.** `check_schema_version` demands equality, not `>=`.
//! A config saying `2` under a binary saying `3` is refused, so the daemon
//! does not start — and every config on disk said `2`, on hosts serving a
//! household's DNS. The remedy is that migrate + lint happen BEFORE any
//! restart, so a failure aborts while the old daemon is still answering.
//!
//! The shell half of that (the ordering inside `make upgrade` and
//! `install.sh`) is fenced by `scripts/check_upgrade_config_gate.sh`. This
//! file proves the half the shell cannot: that the refusal is real, that the
//! migration removes it, and that an in-place migration leaves a file the
//! daemon user can still read.

use std::fs;

use purge_warden::cli::commands::migrate::{migrate_v1_to_v3, migrate_v2_to_v3};
use purge_warden::config::loader::load_config;
use purge_warden::config::schema::validator::{
    format_base_ignore_list_is_inert, BASE_IGNORE_LIST_IS_INERT,
};
use purge_warden::config::schema::validator::{validate_collect, AuditWarnings};
use purge_warden::config::schema::{
    effective_direction, ConfigV1, Id, ListPolicy, SCHEMA_VERSION_V1,
};

/// A minimal, real v2 config: the wire this binary no longer speaks.
const V2_ON_DISK: &str = r##"schema_version = 2

[server]
default_profile = "default"

[upstream]
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://lists.invalid/ads.txt"
kind = "deny"
tags = ["household"]

[[blocklists]]
id = "work"
display_name = "Work"
url = "https://lists.invalid/work.txt"
kind = "deny"
tags = ["office"]

[profiles.default]
display_name = "Default"
tags = ["household"]

[[devices]]
id = "laptop"
display_name = "Laptop"
ip = "192.0.2.10"
profile = "default"
"##;

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

// ── The bump itself ───────────────────────────────────────────────────

#[test]
fn the_schema_version_this_binary_speaks_is_three() {
    // Spelled as a literal on purpose. Asserting `SCHEMA_VERSION_V1 ==
    // SCHEMA_VERSION_V1` is the shape of test that survives every bump and
    // notices none of them, and the number is the thing R7 is about: it is
    // what every config on disk has to be dragged up to before a restart.
    assert_eq!(SCHEMA_VERSION_V1, 3);
}

// ── R7, proved by running it ──────────────────────────────────────────

/// The whole of R7 in one measurement: **refuse, migrate, accept.**
///
/// The middle step is the one that matters. Without it a `make upgrade`
/// installs the binary, restarts, and the daemon refuses its own config —
/// so the fence is not "does lint fail" (it does, trivially) but "does the
/// migration turn a refusal into an acceptance, at the same path".
#[test]
fn a_v2_config_is_refused_then_migrated_then_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    fs::write(&cfg, V2_ON_DISK).unwrap();

    // 1. Refused. This is the state a naive upgrade restarts into.
    let errs = load_config(&cfg, now()).expect_err("a v2 config must not load under a v3 binary");
    let joined = errs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("renamed to `base`"),
        "the refusal must name the rename, not just report an unknown field:\n{joined}"
    );
    assert!(
        joined.contains("migrate v2-to-v3"),
        "the refusal must carry the command that fixes it:\n{joined}"
    );

    // 2. Migrate, in place, exactly as `scripts/upgrade_config_gate.sh` does.
    let summary = migrate_v2_to_v3(&cfg, &cfg, true).expect("migration must succeed");
    assert_eq!(summary.lists_renamed_kind_to_base, 2);

    // 3. Accepted.
    let loaded = load_config(&cfg, now()).expect("the migrated config must load");
    assert_eq!(loaded.config.schema_version, SCHEMA_VERSION_V1);

    // And it filters what it filtered yesterday: the `household` tag reached
    // `ads` and not `work`, so `work` must come out explicitly ignored. If
    // this said `Deny`, the migration would have quietly widened what the
    // household blocks.
    let default = loaded.config.profiles.get("default").expect("profile");
    let by = |id: &str| {
        loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} must survive"))
    };
    assert_eq!(effective_direction(default, by("ads")), ListPolicy::Deny);
    assert_eq!(effective_direction(default, by("work")), ListPolicy::Ignore);
}

/// A failed migration must leave the file **byte-identical**, because the
/// upgrade path's whole safety argument is "abort and the old daemon keeps
/// serving the config it already parsed". A half-written master would still
/// be there on the next restart.
#[test]
fn a_migration_that_cannot_produce_a_loadable_config_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    // A profile naming a list that does not exist: the transformation runs,
    // the post-write validator refuses, and the rename must never land.
    let broken = V2_ON_DISK.replace(
        "[profiles.default]\ndisplay_name = \"Default\"\ntags = [\"household\"]",
        "[profiles.default]\ndisplay_name = \"Default\"\ntags = [\"household\"]\n\n[profiles.default.lists]\nghost = \"deny\"",
    );
    fs::write(&cfg, &broken).unwrap();
    let before = fs::read_to_string(&cfg).unwrap();

    let err = migrate_v2_to_v3(&cfg, &cfg, true).expect_err("a config that cannot load must fail");
    assert!(
        err.to_string().contains("left unchanged"),
        "the failure must say the target was left alone: {err}"
    );
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        before,
        "the master was modified by a migration that failed"
    );
}

/// The upgrade gate runs as **root**; the daemon runs as `purge-warden`.
/// An in-place migration that reset the file's mode would produce a config
/// that lints green (as root) and that the daemon then cannot read — the
/// outage R7 exists to prevent, arriving through R7's own remedy.
///
/// Owner preservation needs `CAP_CHOWN` and is not assertable unprivileged;
/// mode is, and it is the half that changes under a plain rename.
#[test]
fn an_in_place_migration_preserves_the_files_mode() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    fs::write(&cfg, V2_ON_DISK).unwrap();
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o640)).unwrap();

    migrate_v2_to_v3(&cfg, &cfg, true).expect("migration must succeed");

    let mode = fs::metadata(&cfg).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o640,
        "in-place migration changed the config's mode to {mode:o}"
    );
}

/// Idempotency is what makes a repeated `make upgrade` safe: the gate lints
/// first and skips, but a caller that migrates unconditionally must still
/// not damage anything.
#[test]
fn migrating_an_already_migrated_config_is_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    fs::write(&cfg, V2_ON_DISK).unwrap();

    migrate_v2_to_v3(&cfg, &cfg, true).expect("first pass");
    let first = fs::read_to_string(&cfg).unwrap();
    migrate_v2_to_v3(&cfg, &cfg, true).expect("second pass");
    assert_eq!(first, fs::read_to_string(&cfg).unwrap());
}

// ── P6 — `base = "ignore"` is legitimate, never silent ────────────────

/// A v3 config carrying one list at `base`, built through the **wire** —
/// not a struct literal. The point of the sprint is a wire rename, so a
/// fixture that bypasses deserialisation would pass even if `base` were
/// spelled wrong in TOML.
fn config_with_base(base: &str) -> ConfigV1 {
    let src = format!(
        r##"schema_version = 3

[server]
default_profile = "default"

[upstream]
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "inert-list"
display_name = "Inert"
url = "https://lists.invalid/inert.txt"
base = "{base}"

[profiles.default]
display_name = "Default"
"##
    );
    toml::from_str(&src).unwrap_or_else(|e| panic!("fixture must parse (base = {base:?}): {e}"))
}

fn warnings_of(cfg: &ConfigV1) -> Vec<String> {
    let mut warns = AuditWarnings::silent();
    validate_collect(cfg, now(), &mut warns, None, None)
        .unwrap_or_else(|errs| panic!("fixture must validate: {errs:?}"));
    warns.into_messages()
}

/// The text, not merely "something was emitted".
///
/// A test that only counts warnings passes when the WARN says the wrong
/// thing, and an operator reading journald gets a line that does not name
/// the list. Naming the list is the entire property: the 2026-05-07
/// incident was eight lists filtering nothing, and "some list is inert" is
/// not actionable at eight.
#[test]
fn a_base_ignore_list_warns_and_the_warning_names_the_list() {
    let cfg = config_with_base("ignore");
    let warns = warnings_of(&cfg);

    let hit = warns
        .iter()
        .find(|w| w.contains("inert-list"))
        .unwrap_or_else(|| panic!("no WARN named the inert list. Got: {warns:?}"));
    assert_eq!(
        hit,
        &format_base_ignore_list_is_inert("inert-list"),
        "the WARN drifted from its frozen string"
    );
    assert!(
        BASE_IGNORE_LIST_IS_INERT.contains("filters nothing"),
        "the frozen string must say what is wrong, not just that something is"
    );
}

/// The symmetric half of P6, and the one that is easy to get wrong by being
/// helpful: a **per-profile** `ignore` is the narrow, reviewed form — it is
/// the point of the workstream — and warning on it would fire once per
/// (profile, list) pair on every migrated config, training operators to skim
/// past the WARN above.
#[test]
fn a_per_profile_ignore_override_is_silent() {
    let mut cfg = config_with_base("deny");
    cfg.profiles
        .get_mut("default")
        .unwrap()
        .lists
        .insert(Id::new("inert-list").unwrap(), ListPolicy::Ignore);

    let warns = warnings_of(&cfg);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains(&format_base_ignore_list_is_inert("inert-list"))),
        "a per-profile ignore must not raise the list-level WARN: {warns:?}"
    );
    // The control arm: the same fixture with the list itself at `ignore`
    // DOES warn. Without it this test passes on a validator that emits
    // nothing at all, which is the failure mode it exists to catch.
    let warns_global = warnings_of(&config_with_base("ignore"));
    assert!(
        warns_global
            .iter()
            .any(|w| w == &format_base_ignore_list_is_inert("inert-list")),
        "control arm: a list-level ignore must warn, else the test above is vacuous"
    );
}

/// `Ignore` has to reach the engine as "contributes nothing", not as one of
/// the other two. The inheritance mapping lives in exactly one place
/// (`BlocklistBase::as_policy`) so that this cannot be answered differently
/// at the two call sites; this asks it through the public rule.
#[test]
fn base_ignore_is_inherited_as_ignore() {
    let cfg = config_with_base("ignore");
    let profile = cfg.profiles.get("default").unwrap();
    assert_eq!(
        effective_direction(profile, &cfg.blocklists[0]),
        ListPolicy::Ignore
    );
    // Discriminating: the same shape at `deny` must NOT come out `Ignore`,
    // so a mapping that collapsed every variant onto one answer fails here.
    let deny = config_with_base("deny");
    assert_eq!(
        effective_direction(deny.profiles.get("default").unwrap(), &deny.blocklists[0]),
        ListPolicy::Deny
    );
}

// ── Part C — v1→v3 is direct, and refuses the input that would lie ────

/// The trap the direct route has to defend against.
///
/// A v2 config fed to `v1-to-v3` would short-circuit the v1 shape change
/// (`is_already_v2`), so `profiles.<id>.blocklists` is absent, so the
/// association is empty for every profile, so **every** pair is written
/// `ignore`. That output loads, lints clean, and filters nothing — the
/// 2026-05-07 shape, produced by a migration. It must refuse by name.
#[test]
fn v1_to_v3_refuses_a_v2_config_instead_of_writing_ignore_everywhere() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("actually-v2.toml");
    let target = tmp.path().join("out.toml");
    fs::write(&from, V2_ON_DISK).unwrap();

    let err = migrate_v1_to_v3(&from, &target, false)
        .expect_err("a v2 config must not be silently flattened to all-ignore");
    let msg = err.to_string();
    assert!(
        msg.contains("v2-to-v3"),
        "the refusal must point at the right verb: {msg}"
    );
    assert!(
        msg.contains("filters nothing"),
        "the refusal must say what the wrong route would have produced: {msg}"
    );
    assert!(
        !target.exists(),
        "nothing may be written on the refusal path"
    );
}

// ── The migration must leave the household still filtering ────────────

const ZIMA: &str = include_str!("fixtures/plp_v2_site_a.toml");
const PROXMOX: &str = include_str!("fixtures/plp_v2_site_b.toml");

/// **The check the rest of this workstream does not make.**
///
/// Every other migration test proves *fidelity* (v3 states what v2
/// resolved) or *loadability*. Both pass identically whether v2 resolved
/// "everything applies" or "nothing applies" — they compare v3 to v2, so
/// they cannot tell those apart. And `scripts/upgrade_config_gate.sh`
/// succeeds on `config lint` **without** `--strict`, where
/// `PROFILE_FILTERS_NO_LISTS` and `BASE_IGNORE_LIST_IS_INERT` are WARNs
/// that exit 0.
///
/// So a bug that wrote `ignore` for every pair would: migrate cleanly, lint
/// cleanly, let the gate say "safe to restart", and hand two households a
/// resolver that answers every query and blocks nothing. That is the
/// 2026-05-07 shape, delivered by the remedy meant to prevent an outage.
/// It matters more than it did before plp-s3b, because `make upgrade` and
/// `install.sh` now run that migration **unattended** on both live hosts.
///
/// This asks the only question that separates the two: after migrating the
/// two real shapes, does every profile still enforce at least one list?
#[test]
fn the_live_shapes_still_filter_after_migrating() {
    for (name, body) in [("zima", ZIMA), ("proxmox", PROXMOX)] {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config.toml");
        fs::write(&cfg, body).unwrap();
        migrate_v2_to_v3(&cfg, &cfg, true)
            .unwrap_or_else(|e| panic!("{name}: migration must succeed: {e}"));
        let loaded = load_config(&cfg, now())
            .unwrap_or_else(|e| panic!("{name}: migrated config must load: {e:?}"));

        assert!(
            !loaded.config.profiles.is_empty(),
            "{name}: fixture has no profiles — this test would be vacuous"
        );
        for (pid, profile) in &loaded.config.profiles {
            // Through `effective_direction`, not by reading the `lists`
            // table: what matters is the verdict the engine will act on,
            // and that is the function the projection calls.
            let enforced = loaded
                .config
                .blocklists
                .iter()
                .filter(|b| b.enabled)
                .filter(|b| effective_direction(profile, b) != ListPolicy::Ignore)
                .count();
            assert!(
                enforced > 0,
                "{name}: profile `{pid}` enforces ZERO lists after migration — \
                 it would answer every query and block nothing, and `config lint` \
                 would still exit 0"
            );
        }
    }
}

/// The control arm for the test above, and it is not optional: without it,
/// `enforced > 0` would also pass on a migrator that ignored the tag model
/// entirely and wrote `deny` for every pair. That failure is the *opposite*
/// verdict change — lists applying to profiles that never had them — and it
/// is equally silent.
///
/// A profile whose tags reach nothing must come out with every pair
/// `ignore`, and that config lints clean while filtering nothing. Which is
/// exactly why `PROFILE_FILTERS_NO_LISTS` exists and why the gate's
/// non-strict lint is not a filtering check.
#[test]
fn a_profile_whose_tags_reached_nothing_is_migrated_to_all_ignore() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    // `V2_ON_DISK`'s default profile carries `household`; `work` is tagged
    // `office`, which no profile carries.
    fs::write(&cfg, V2_ON_DISK).unwrap();
    migrate_v2_to_v3(&cfg, &cfg, true).expect("migration must succeed");
    let loaded = load_config(&cfg, now()).expect("must load");
    let default = loaded.config.profiles.get("default").expect("profile");

    let by = |id: &str| {
        loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} must survive"))
    };
    assert_eq!(effective_direction(default, by("work")), ListPolicy::Ignore);
    assert_eq!(effective_direction(default, by("ads")), ListPolicy::Deny);

    // And that all-ignore state really does lint clean — the property that
    // makes the check above necessary rather than paranoid.
    let mut warns = AuditWarnings::silent();
    validate_collect(&loaded.config, now(), &mut warns, None, None)
        .expect("a config that filters nothing is still a VALID config");
}
