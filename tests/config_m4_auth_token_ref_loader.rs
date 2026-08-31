//! s4 config-m4 — end-to-end cover for the `auth_token_ref` cross-check
//! **plumbing**, not the check itself.
//!
//! The unit tests in `config::schema::validator` call `validate_collect`
//! directly with a table already in hand. That leaves the wiring untested,
//! and the wiring is the part most likely to be wrong: the loader has to
//! resolve `secrets.toml` from the master's directory, pass it down, and —
//! on the single-file fast path — actually *surface* the error rather than
//! discarding the `Result` the way it did before this change. A check that
//! is correct but never reached is the failure mode this file exists for.
//!
//! Both layouts are covered. Single-file matters most — it is what the CTs
//! ship (`/etc/purge-warden/config.toml`) and it is the path where the
//! validator re-run's result was previously thrown away — but the multi-file
//! case pins that `secrets.toml` is resolved beside the MASTER, so an
//! include-based tree does not silently degrade to "no secrets loaded".

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use purge_warden::config::error::ConfigError;
use purge_warden::config::loader::load_config;
use time::macros::datetime;

const BASE: &str = "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n\
                    [profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";

fn config_with_ref(token_ref: &str) -> String {
    format!(
        "{BASE}\n[[blocklists]]\nid = \"corp-list\"\ndisplay_name = \"Corp list\"\n\
         url = \"https://lists.example.com/corp.txt\"\nformat = \"domains\"\n\
         update_interval_hours = 12\nmax_entries = 1000\n\
         auth_token_ref = \"{token_ref}\"\ntags = [\"uncategorized\"]\n"
    )
}

/// Writes `config.toml` and, when `secrets` is `Some`, a sibling 0600
/// `secrets.toml` — the exact path shape `secrets_path_for(master)` derives
/// (`master.parent().join("secrets.toml")`).
fn load_with(token_ref: &str, secrets: Option<&[&str]>) -> Result<(), Vec<ConfigError>> {
    let tmp = tempfile::tempdir().unwrap();
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, config_with_ref(token_ref)).unwrap();

    if let Some(names) = secrets {
        let sp = tmp.path().join("secrets.toml");
        {
            let mut f = std::fs::File::create(&sp).unwrap();
            for n in names {
                writeln!(f, "{n} = \"token-value\"").unwrap();
            }
        }
        // `load_secrets` refuses anything looser than 0600.
        let mut perm = std::fs::metadata(&sp).unwrap().permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(&sp, perm).unwrap();
    }

    load_config(Path::new(&master), datetime!(2026-04-22 12:00:00 UTC)).map(|_| ())
}

#[test]
fn m4_dangling_ref_is_refused_through_the_real_loader() {
    let errs = load_with("ghost-ref", Some(&["corp-list-token", "vendor-token"]))
        .expect_err("a dangling auth_token_ref must fail the load");

    let miss = errs
        .iter()
        .find(|e| matches!(e, ConfigError::CrossRefMiss(_)))
        .unwrap_or_else(|| panic!("expected a CrossRefMiss, got {errs:?}"));

    let ctx = miss.context();
    assert!(ctx.reason.contains("ghost-ref"), "{ctx:?}");
    // The operator is told which names actually exist — the part that makes
    // this actionable rather than merely reported.
    let sugg = ctx.suggestion.as_deref().unwrap_or_default();
    assert!(sugg.contains("corp-list-token"), "{sugg}");
    assert!(sugg.contains("vendor-token"), "{sugg}");
    // File attribution survives the fast path's error mapping.
    assert!(ctx.file.is_some(), "error should carry the master path");
}

#[test]
fn m4_resolvable_ref_loads_clean_through_the_real_loader() {
    load_with("corp-list-token", Some(&["corp-list-token"]))
        .expect("a resolvable auth_token_ref must load");
}

/// The loader derives the secrets path from the MASTER
/// (`secrets_path_for` = `master.parent().join("secrets.toml")`), so an
/// include-based tree must resolve the same sibling file — secrets are one
/// file next to the master, never per-include. Asserted rather than assumed:
/// if this were wrong the check would silently see `loaded == false` on every
/// multi-file install and fire on nobody, the exact mirror of the discarded-
/// `Result` bug on the single-file path.
#[test]
fn m4_multi_file_tree_resolves_secrets_beside_the_master() {
    let tmp = tempfile::tempdir().unwrap();
    let master = tmp.path().join("config.toml");
    // `includes` is a top-level key: it must precede every table, or TOML
    // scopes it into whichever section came last.
    std::fs::write(
        &master,
        "schema_version = 3\nincludes = [\"conf.d/*.toml\"]\n\n\
         [server]\ndefault_profile = \"default\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();

    let confd = tmp.path().join("conf.d");
    std::fs::create_dir_all(&confd).unwrap();
    std::fs::write(
        confd.join("lists.toml"),
        "[[blocklists]]\nid = \"corp-list\"\ndisplay_name = \"Corp list\"\n\
         url = \"https://lists.example.com/corp.txt\"\nformat = \"domains\"\n\
         update_interval_hours = 12\nmax_entries = 1000\n\
         auth_token_ref = \"ghost-ref\"\ntags = [\"uncategorized\"]\n",
    )
    .unwrap();

    let sp = tmp.path().join("secrets.toml");
    std::fs::write(&sp, "corp-list-token = \"token-value\"\n").unwrap();
    let mut perm = std::fs::metadata(&sp).unwrap().permissions();
    perm.set_mode(0o600);
    std::fs::set_permissions(&sp, perm).unwrap();

    let errs = load_config(Path::new(&master), datetime!(2026-04-22 12:00:00 UTC))
        .expect_err("a dangling ref in an INCLUDE must fail the multi-file path too");
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(_))
                && e.context().reason.contains("ghost-ref")),
        "got {errs:?}"
    );
}

#[test]
fn m4_absent_secrets_file_still_boots() {
    // Regression guard in the opposite direction: an operator who has not
    // set up secrets at all must not be locked out by this check. A missing
    // file yields `loaded == false`, which skips it. If this ever fails, the
    // gate has been dropped and every such install stops booting.
    load_with("ghost-ref", None)
        .expect("a missing secrets.toml must skip the check, not fail the load");
}
