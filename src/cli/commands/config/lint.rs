//! `warden config lint` — validate the v1 config without touching the daemon.
//!
//! Loads the config tree from `config_path` via
//! [`crate::config::loader::load_config`], which runs the full include
//! resolution + cross-ref validator. On success, prints a one-line
//! summary with the entity counts. On failure, prints every error on a
//! separate line with file + line + entity + suggestion attached.
//!
//! Design doc §11.2.
//!
//! # Exit codes
//!
//! - [`SUCCESS`] — the configuration is valid. Warnings may have been
//!   printed; they do not change the code unless `--strict` was passed.
//! - [`CONFIG`] — the configuration has at least one validation error, or
//!   could not be loaded at all (missing / unreadable file); or it is
//!   valid-with-warnings and `--strict` was passed.
//!
//! Lint never returns [`FAILURE`](crate::cli::exit_codes::FAILURE): the
//! operation — judging a config — always completes. What varies is the
//! verdict, and an invalid config is exactly what code 2 means.
//!
//! ## Why warnings-only is `0` (changed here; was `2`)
//!
//! Under the contract `2` means "could not be loaded, or is invalid". A
//! warnings-only config is neither: the daemon boots on it and serves.
//! Conflating the two costs an operator the one distinction they need —
//! "this will not start" vs "this has a cosmetic nit".
//!
//! The deciding evidence is in-repo. `scripts/install.sh` Phase 3.5 gates
//! the upgrade path on `if "$BINARY" --config "$CONFIG" config lint; then`
//! and aborts with exit 6 otherwise, *before* the running service is
//! stopped. Any non-zero is a hard abort there. With warnings-only at `2`,
//! a config carrying nothing worse than a duplicate-URL or inert-list WARN
//! — both deliberately WARN-not-fatal, and both present on real installs —
//! blocks its own upgrade forever. The same shape appears in the
//! documented operator idiom `warden config lint && systemctl reload`.
//!
//! The warnings themselves are unaffected: they are still collected and
//! still printed to stderr. What changed is only whether their presence
//! alone is grounds to fail a script.
//!
//! ## `--strict` — the opt-in that gets the distinction back
//!
//! Moving warnings-only to `0` is right for the default and it cost
//! something real: the errors-vs-warnings distinction left the exit code
//! entirely and now lives only in stderr, where a script would have to
//! grep for it. `--strict` restores it for the caller who wants it, on
//! their explicit request rather than by surprise:
//!
//! | config state | default | `--strict` |
//! |---|---|---|
//! | valid, no warnings | [`SUCCESS`] | [`SUCCESS`] |
//! | valid, warnings only | [`SUCCESS`] | [`CONFIG`] |
//! | has errors | [`CONFIG`] | [`CONFIG`] |
//!
//! The installer keeps passing on a warnings-only config precisely
//! because it does *not* pass `--strict` — which is the whole point of
//! making it a flag rather than reversing the default back.
//!
//! ## Why errors moved `1` → `2`
//!
//! `resolve` already exits `2` for a config-load failure, so
//! 2-means-bad-config is the codebase's existing precedent, not a new
//! invention. Leaving the one verb whose entire job is judging config
//! validity on `1` would have made the rendered contract self-defeating.
//!
//! **Read-only.** Lint never writes — it loads a path (or a copy) and reports.
//!
//! **Warnings (rev-2606 `rev2606-lint-warn-channel`).** The validator emits
//! its operator WARNs (zero-intersection tags, §5.4 rows, expired schedules)
//! via `tracing::warn!(target = "audit", …)`. The daemon's global subscriber
//! routes those to journald at hot-reload, but the lint CLI installs no
//! global subscriber, so they would vanish here — defeating lint's
//! pre-flight-before-upgrade purpose. The validator therefore *also* returns
//! them as data: [`crate::config::loader::load_config_collect`] hands back
//! `(result, warnings)` and we print what it collected. The daemon
//! boot/reload paths are untouched, so their journald output and exit
//! behaviour are byte-for-byte unchanged.
//!
//! **De-raced (`s-rev2606-lint-warn-fixture-flaky-parallel`).** This used to
//! capture the WARNs by installing a thread-scoped `tracing` subscriber
//! around the load and reading the events back out — using the
//! process-global tracing dispatcher as a data channel. Under `cargo test`
//! that global is shared with every other test thread, which made
//! `lint_returns_success_for_warnings_only_fixture` (then named
//! `…_returns_two_…`) flaky and, worse, trained everyone to re-run a red
//! tri-gate until it went green. Lint no longer touches `tracing` at all;
//! there is no shared state left to race on.

use std::io::Write;
use std::path::Path;

use crate::cli::exit_codes::{CONFIG, SUCCESS};
use crate::config::error::ConfigError;
use crate::config::loader::{self, LoadedConfig};

/// Run the lint. Returns the intended process exit code.
pub fn run_lint(config_path: &Path, strict: bool) -> anyhow::Result<i32> {
    let (result, warnings) = lint_collect(config_path);
    Ok(report(
        &mut std::io::stderr(),
        config_path,
        result,
        &warnings,
        strict,
    ))
}

/// Render a load outcome and pick the exit code.
///
/// `diagnostics` is the error/warning sink — stderr in production, a
/// buffer in tests, which is the only way to assert that a warning was
/// shown rather than merely collected. The clean summary keeps going to
/// stdout; it is the command's answer, not a diagnostic.
///
/// **Warnings are rendered on both arms.** A config carrying an error AND
/// a deprecation used to show only the error, so the operator fixed one
/// thing, re-ran, and discovered four more — on exactly the messages that
/// name `schema_version = 3` as their removal point.
fn report(
    diagnostics: &mut dyn Write,
    config_path: &Path,
    result: Result<LoadedConfig, Vec<ConfigError>>,
    warnings: &[String],
    strict: bool,
) -> i32 {
    match result {
        Ok(loaded) => {
            print_clean_summary(config_path, &loaded);
            // See the module docs for why a warnings-only config stays `0`
            // by default, and why `--strict` is the opt-in that makes them
            // fatal.
            if !warnings.is_empty() {
                write_warnings(diagnostics, config_path, warnings);
                if strict {
                    let _ = writeln!(diagnostics, "{STRICT_WARNINGS_ARE_FATAL}");
                    return CONFIG;
                }
            }
            SUCCESS
        }
        Err(errs) => {
            // Warnings first: they are advisory, the errors are the
            // verdict, and the verdict reads better last.
            if !warnings.is_empty() {
                write_warnings(diagnostics, config_path, warnings);
            }
            write_errors(diagnostics, config_path, &errs);
            CONFIG
        }
    }
}

/// Printed only under `--strict`, and only when warnings were the sole
/// reason for the non-zero exit.
///
/// It exists so the two ways to reach [`CONFIG`] never look alike on
/// stderr. Without it a `--strict` failure is indistinguishable from a
/// genuinely invalid config, and the operator's next move — "which is
/// it: did my config break, or did I ask for a stricter check?" — has no
/// answer in the output.
pub const STRICT_WARNINGS_ARE_FATAL: &str =
    "--strict: the configuration is valid but has warnings, which --strict treats as failure.";

/// Load + validate `config_path`, capturing the validator's
/// `target = "audit"` WARN lines emitted during the load. Pure of stdout —
/// the printing/exit-code policy lives in [`run_lint`]; tests drive this
/// directly to assert both the outcome and the captured warning text.
fn lint_collect(config_path: &Path) -> (Result<LoadedConfig, Vec<ConfigError>>, Vec<String>) {
    let now = time::OffsetDateTime::now_utc();
    // No subscriber, no thread-local, no shared state of any kind: the
    // validator hands its audit WARNs back in the return value.
    loader::load_config_collect(config_path, now)
}

fn print_clean_summary(config_path: &Path, loaded: &LoadedConfig) {
    println!("config is valid: {}", config_path.display());
    println!(
        "  {} file(s) loaded, {} byte(s) total",
        loaded.files_loaded.len(),
        loaded.total_bytes,
    );
    let c = &loaded.config;
    println!(
        "  {} device(s), {} group(s), {} subnet(s), {} schedule(s)",
        c.devices.len(),
        c.groups.len(),
        c.subnets.len(),
        c.schedules.len(),
    );
    println!(
        "  {} profile(s), {} blocklist(s), {} admin rule(s)",
        c.profiles.len(),
        c.blocklists.len(),
        c.admin_rules.len(),
    );
    match &c.server.default_profile {
        Some(p) => println!("  default_profile: {}", p.as_str()),
        None => println!("  default_profile: <none — level 5 falls through to REFUSED>"),
    }
}

fn write_errors(w: &mut dyn Write, config_path: &Path, errs: &[ConfigError]) {
    let _ = writeln!(
        w,
        "config has {} error(s) in {}:",
        errs.len(),
        config_path.display()
    );
    for err in errs {
        let _ = writeln!(w, "  - {err}");
    }
}

fn write_warnings(w: &mut dyn Write, config_path: &Path, warnings: &[String]) {
    let _ = writeln!(
        w,
        "config has {} warning(s) in {}:",
        warnings.len(),
        config_path.display()
    );
    for warning in warnings {
        let _ = writeln!(w, "  - {warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_returns_zero_for_minimal_valid_fixture() {
        // tests/fixtures/minimal-v1/config.toml is the canonical
        // one-of-every-entity reference — S28 pinned it as the
        // happy-path integration shape. Its tag wiring is clean (every
        // device/profile tag set intersects an enabled list); since N1
        // it does raise one warning — it omits `[anti_bypass]`, whose
        // defaults claim a protection that builds no checker. That is a
        // warning, so the code stays SUCCESS. See
        // `lint_captures_exactly_the_expected_warnings_for_the_reference_fixture`.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal-v1/config.toml");
        let rc = run_lint(&path, false).unwrap();
        assert_eq!(rc, SUCCESS, "minimal-v1 fixture must lint clean");
    }

    #[test]
    fn lint_returns_config_for_broken_fixture() {
        // tests/fixtures/broken-v1/cross_ref_miss.toml references a
        // non-existent profile — the validator catches it. An invalid
        // config is exactly what CONFIG means; it used to be 1, which
        // the contract reserves for "the operation failed".
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/broken-v1/cross_ref_miss.toml");
        let rc = run_lint(&path, false).unwrap();
        assert_eq!(rc, CONFIG, "broken-v1 fixture must lint with exit 2");
    }

    #[test]
    fn lint_returns_config_when_config_file_missing() {
        // "Could not be loaded" is the other half of what CONFIG covers.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-config.toml");
        let rc = run_lint(&missing, false).unwrap();
        assert_eq!(rc, CONFIG, "missing config must lint with exit 2");
    }

    /// The reversal: a warnings-only config is valid, so it exits 0.
    ///
    /// It used to exit 2, which made `scripts/install.sh` Phase 3.5 abort
    /// the upgrade (exit 6) on any config carrying a merely-cosmetic WARN
    /// — duplicate URLs and inert lists are deliberately WARN-not-fatal
    /// and appear on real installs. See the module docs.
    #[test]
    fn lint_returns_success_for_warnings_only_fixture() {
        // tests/fixtures/warns-v1/config.toml = minimal-v1 plus one
        // `base = "ignore"` blocklist — the P6 inert WARN, no errors.
        // (rev-2606 rev2606-lint-warn-channel; the row was a tag orphan
        // until the plp cutover retired that diagnostic.)
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warns-v1/config.toml");
        let rc = run_lint(&path, false).unwrap();
        assert_eq!(rc, SUCCESS, "a warnings-only config is valid — it boots");
    }

    /// `--strict` on the SAME config that exits 0 without it.
    ///
    /// Both polarities in one test, on one fixture, deliberately. A test
    /// that only asserted `--strict` exits 2 would pass against a lint
    /// that failed warnings-only configs unconditionally — i.e. against
    /// the very regression `--strict` exists to avoid re-introducing. It
    /// is the *difference* between the two runs that proves the flag is
    /// wired to anything.
    #[test]
    fn strict_makes_warnings_fatal_and_only_strict_does() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warns-v1/config.toml");

        let lenient = run_lint(&path, false).unwrap();
        let strict = run_lint(&path, true).unwrap();

        assert_eq!(
            lenient, SUCCESS,
            "without --strict a warnings-only config must still exit 0 — \
             scripts/install.sh Phase 3.5 aborts the upgrade on any \
             non-zero, and warnings appear on real installs"
        );
        assert_eq!(
            strict, CONFIG,
            "with --strict the same config must exit 2 — otherwise the flag \
             parses and does nothing, which is the defect class cli-h5 \
             deleted four other flags for"
        );
        assert_ne!(
            lenient, strict,
            "one config, two verdicts: if these ever agree the flag is inert"
        );
    }

    /// `--strict` must not invent a failure where there is nothing to
    /// warn about. Without this, "strict always exits 2" would satisfy
    /// the test above.
    ///
    /// The config is minimal-v1 **plus an explicit `[anti_bypass]`
    /// opt-out**, derived into a tempdir rather than checked in. It used
    /// to point straight at the fixture, and since N1 that fixture raises
    /// one warning by design — see
    /// `lint_captures_exactly_the_expected_warnings_for_the_reference_fixture`.
    /// The two requirements are genuinely incompatible in one file:
    /// minimal-v1 earns its keep by looking like a real install (no
    /// `[anti_bypass]` section, exactly as `warden init` writes it),
    /// while this control arm needs a config with *zero* warnings.
    /// Editing the opt-out into the fixture was tried and reverted — it
    /// turned this test green and the exact-set pin red, the same
    /// collision seen from the other side. Deriving it here keeps one
    /// checked-in shape instead of a near-duplicate fixture free to
    /// drift from it.
    #[test]
    fn strict_leaves_a_clean_config_alone() {
        const MINIMAL_V1: &str = include_str!("../../../../tests/fixtures/minimal-v1/config.toml");
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            format!("{MINIMAL_V1}\n[anti_bypass]\nenabled = false\n"),
        )
        .unwrap();

        let (_, warnings) = lint_collect(&path);
        assert!(
            warnings.is_empty(),
            "the control arm must be warning-free; it now emits \
             {warnings:?}, so the assertion below proves nothing"
        );
        assert_eq!(
            run_lint(&path, true).unwrap(),
            SUCCESS,
            "--strict escalates warnings, it does not manufacture them"
        );
    }

    /// Guard on the reversal above: warnings must still be *collected and
    /// printed*. Downgrading the exit code is only defensible because the
    /// operator still sees them; if a later change quietly dropped the
    /// capture, warnings would vanish with no signal at all.
    #[test]
    fn warnings_are_still_collected_even_though_they_no_longer_fail() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warns-v1/config.toml");
        let (result, warnings) = lint_collect(&path);
        assert!(result.is_ok());
        assert!(
            !warnings.is_empty(),
            "exit 0 with no warnings surfaced would make the WARN channel silent"
        );
    }

    #[test]
    fn lint_surfaces_the_audit_warning_text() {
        // The exit code alone is not enough — assert the operator actually
        // sees the validator WARN line. BASE_IGNORE_LIST_IS_INERT is the
        // warning the warns-v1 fixture provokes.
        //
        // It was BLOCKLIST_TAGS_MATCH_NOTHING until the plp cutover. That
        // WARN was computed from `tags`, which stopped deciding which lists
        // reach which profile at S3; the fixture row moved to
        // `base = "ignore"`, which is the shape P6 keeps from being silent.
        // Asserted through the on-disk fixture rather than an inline config
        // deliberately: this is the path an operator's file actually takes.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/warns-v1/config.toml");
        let (result, warnings) = lint_collect(&path);
        assert!(result.is_ok(), "warns-v1 must load without errors");
        let expected =
            crate::config::schema::validator::format_base_ignore_list_is_inert("inert-list");
        assert!(
            warnings.iter().any(|w| w.contains(&expected)),
            "expected BASE_IGNORE_LIST_IS_INERT verbatim, got: {warnings:?}"
        );
    }

    /// The reference fixture's warning set, pinned **exactly**.
    ///
    /// This asserted `warnings.is_empty()` until N1. It went red because
    /// `minimal-v1` omits `[anti_bypass]`, and the section's serde
    /// defaults are `enabled = true, extra_domains = []` — the state that
    /// builds no checker at all. The fixture was not edited to silence
    /// it: omitting the section is precisely what `warden init` writes
    /// and what both live CTs carry, so the fixture's whole value is that
    /// it looks like a real install. A diagnostic that fires there is the
    /// finding, not fixture noise.
    ///
    /// Pinned as an exact set rather than relaxed to "contains" — the
    /// guard this test exists to provide is that a *new, unexpected*
    /// warning on the reference config fails the suite, and `any()` would
    /// have thrown that away along with the red.
    #[test]
    fn lint_captures_exactly_the_expected_warnings_for_the_reference_fixture() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal-v1/config.toml");
        let (result, warnings) = lint_collect(&path);
        assert!(result.is_ok());
        assert_eq!(
            warnings.len(),
            1,
            "minimal-v1 raises exactly one warning; a new one here needs a \
             deliberate decision, not an amended assertion: {warnings:?}"
        );
        assert!(
            warnings[0].contains("has no domains to block"),
            "the one expected warning is ANTI_BYPASS_ENABLED_NO_DOMAINS, got: {warnings:?}"
        );
    }

    // ── tag_model_consolidation §3.3 ─────────────────────────────────
    //
    // Lint is NOT rewritten here. §3.3 says its job for the inert-list
    // work is to *verify* the existing channel already covers both
    // cases and pin that — so these tests only assert, and would catch
    // a future change that silently drops one of the two WARNs out of
    // the capture layer (which is how a signal goes quiet without
    // anyone noticing).

    fn write_config(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    /// **Case 1, inverted by `plp-s3`.** It used to read "inert case 1 — an
    /// allow-list with no tags […] installed, visible, and filters nothing.
    /// This is how `mycompany` got onto the live box."
    ///
    /// That list is no longer inert: tags stopped gating, so an
    /// allow-direction list is inherited by every profile that does not
    /// override it. `lint` must therefore stop saying "has no effect" — the
    /// string would have survived the cutover intact and described the
    /// opposite of what the daemon does — and must instead surface the
    /// standing exposure (§2.5), which is what a permanent, silent allow for
    /// everybody actually is.
    ///
    /// Still WARN, still exit 0: an operator who wants a global allow-list is
    /// entitled to one. What is forbidden is the silence.
    #[test]
    fn lint_reports_an_allow_direction_list_as_a_standing_exposure() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "mycompany"
display_name = "My Company"
url = "https://example.com/allow.txt"
base = "allow"
trust = "local"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (result, warnings) = lint_collect(&path);
        assert!(
            result.is_ok(),
            "a declared allow-list must never be a load error"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("is allow-direction") && w.contains("mycompany")),
            "expected ALLOW_DIRECTION_LIST_STANDING_EXPOSURE naming the list, \
             got: {warnings:?}"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("has no effect")),
            "the retired `has no effect` WARN must not fire: it is false now, \
             and a diagnostic that lies is worse than a missing one. \
             Got: {warnings:?}"
        );
        assert_eq!(
            run_lint(&path, false).unwrap(),
            SUCCESS,
            "warnings-only exits 0"
        );
    }

    /// Inert case 2 — a `base = "ignore"` list, which contributes nothing
    /// to any profile that does not override it. Asserted here alongside
    /// case 1 so "lint covers BOTH" is one visible claim.
    ///
    /// **This asked about tags until the plp cutover** (`tags =
    /// ["nobody-has-this"]` → `BLOCKLIST_TAGS_MATCH_NOTHING`). Tags stopped
    /// deciding which lists reach which profile at S3, so that WARN and its
    /// predicate left; `base = "ignore"` is the shape that means the same
    /// thing now, and P6 exists precisely so it cannot be silent — it is,
    /// byte for byte, the 2026-05-07 incident shape.
    ///
    /// `tests/plp_s3b_rename_and_r7.rs` already pins the WARN at the
    /// validator; what this adds is that it reaches the operator through
    /// `config lint`, which that test cannot see.
    #[test]
    fn tmc_lint_reports_a_base_ignore_list_as_inert() {
        let config = |base: &str| {
            format!(
                r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "parked"
display_name = "Parked"
url = "https://example.com/deny.txt"
base = "{base}"

[upstream]
servers = ["192.0.2.1:53"]
"#
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(&dir, &config("ignore"));
        let expected = crate::config::schema::validator::format_base_ignore_list_is_inert("parked");
        let (result, warnings) = lint_collect(&path);
        assert!(result.is_ok());
        assert!(
            warnings.iter().any(|w| w.contains(&expected)),
            "expected BASE_IGNORE_LIST_IS_INERT, got: {warnings:?}"
        );
        assert_eq!(run_lint(&path, false).unwrap(), SUCCESS);

        // Control arm. The same config one word apart must be silent —
        // without it this passes against a lint that warned about every
        // list, which is how a WARN stops being read.
        let dir2 = tempfile::tempdir().unwrap();
        let path2 = write_config(&dir2, &config("deny"));
        let (result2, warnings2) = lint_collect(&path2);
        assert!(result2.is_ok());
        assert!(
            !warnings2.iter().any(|w| w.contains(&expected)),
            "a `base = deny` list is not inert: {warnings2:?}"
        );
    }

    // ── N1 — the anti-bypass drop is loud ────────────────────────────
    //
    // `[anti_bypass] enabled = true` with an empty `extra_domains` builds
    // no checker at all (`SecurityLayer::from_config` drops it to `None`
    // so the hot path pays nothing for a set that cannot match). That
    // drop is correct; the silence was not. Both live CTs carry exactly
    // the config below.

    /// The config an operator reads as "protection on" must produce a
    /// row here — this is the pre-flight they run before a deploy.
    #[test]
    fn n1_lint_reports_enabled_anti_bypass_with_no_domains() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[anti_bypass]
enabled = true
extra_domains = []

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (result, warnings) = lint_collect(&path);
        assert!(
            result.is_ok(),
            "a toothless anti-bypass is not a load error"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("has no domains to block")),
            "expected ANTI_BYPASS_ENABLED_NO_DOMAINS, got: {warnings:?}"
        );
    }

    /// Non-fatal, pinned. `scripts/install.sh` Phase 3.5 aborts the
    /// upgrade on any non-zero from lint, and the daemon load path aborts
    /// on any `ConfigError` — so promoting this diagnostic to an error
    /// would both block upgrades and refuse to start on the two boxes
    /// that serve household DNS.
    #[test]
    fn n1_lint_still_exits_zero_on_a_toothless_anti_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[anti_bypass]
enabled = true

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        assert_eq!(
            run_lint(&path, false).unwrap(),
            SUCCESS,
            "this config boots and serves — it must not fail a deploy gate"
        );
    }

    /// §3.2 — the duplicate-URL rule reaches the operator through the
    /// same channel, and (§2.1) never as an error: the live config
    /// already contains a duplicate pair, and exit 1 there would mean a
    /// daemon that refuses to start.
    #[test]
    fn tmc_lint_reports_duplicate_urls_as_a_warning_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy ads"
url = "https://lists.purge.cc/ads.txt"

[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt/"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (result, warnings) = lint_collect(&path);
        assert!(
            result.is_ok(),
            "duplicate URLs must never fail the load — the live config has a pair"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("resolve to the same source URL")),
            "expected BLOCKLIST_DUPLICATE_URL, got: {warnings:?}"
        );
        assert_eq!(run_lint(&path, false).unwrap(), SUCCESS);
    }
    // ── warnings survive an error ────────────────────────────────────

    fn one_error() -> Vec<ConfigError> {
        vec![ConfigError::DuplicateId(
            crate::config::error::ErrorContext::new("ip_denylists and ip_blocklists both declared"),
        )]
    }

    /// A config carrying an error AND a deprecation showed only the
    /// error, so the operator fixed one thing, re-ran, and discovered
    /// four more — on exactly the messages naming `schema_version = 3`
    /// as their removal point. On a config being prepared for that
    /// version, that is backwards.
    #[test]
    fn an_invalid_config_still_reports_its_deprecations() {
        let mut out: Vec<u8> = Vec::new();
        let rc = report(
            &mut out,
            Path::new("/etc/purge-warden/config.toml"),
            Err(one_error()),
            &["[ip_denylists] is deprecated; use [ip_blocklists]".to_string()],
            false,
        );

        assert_eq!(rc, CONFIG, "an invalid config is still invalid");
        let seen = String::from_utf8(out).unwrap();
        assert!(
            seen.contains("deprecated"),
            "the deprecation must not be dropped on the error path: {seen}"
        );
        assert!(
            seen.contains("ip_denylists and ip_blocklists both declared"),
            "the error is still the verdict: {seen}"
        );
        assert!(
            seen.find("warning(s)").unwrap() < seen.find("error(s)").unwrap(),
            "advisory first, verdict last: {seen}"
        );
    }

    /// Negative control: with no warnings to report, the error path says
    /// nothing about warnings. Without this, a renderer that always
    /// printed a warnings header would satisfy the test above.
    #[test]
    fn an_invalid_config_with_no_warnings_reports_only_the_error() {
        let mut out: Vec<u8> = Vec::new();
        let rc = report(
            &mut out,
            Path::new("/etc/purge-warden/config.toml"),
            Err(one_error()),
            &[],
            false,
        );

        assert_eq!(rc, CONFIG);
        let seen = String::from_utf8(out).unwrap();
        assert!(
            !seen.contains("warning(s)"),
            "no warnings to report: {seen}"
        );
        assert!(seen.contains("error(s)"));
    }
}
