//! `--into` on `local-dns` / `rewrite`: the flag two error messages have
//! recommended all along.
//!
//! # Why this test exists
//!
//! `local_dns::find_profile_target_file` and its `rewrite` twin both end
//! their "profile not found" bail with *"or pass `--into <file>` to target
//! a specific include"* — but neither verb declared the flag, so an
//! operator who followed the advice got `unexpected argument '--into'`.
//! The inner cores (`add_inner` / `remove_inner`) already took
//! `into: Option<&Path>` and routed it through the shared, path-checked
//! [`resolve_explicit_into_under`]; only the clap surface and the `run_*`
//! parameter were missing.
//!
//! # The failure mode the message described — closed in cli-h4
//!
//! Both `find_profile_target_file` implementations used to scan the
//! master plus `profiles.d/*.toml` and nothing else. A profile declared
//! in an include outside that directory (`includes = ["custom/*.toml"]`)
//! is visible to the *merged* config, so `ensure_profile_exists` passed,
//! but invisible to the target scan, so the write had nowhere to go, and
//! `--into` was the only recovery.
//!
//! That was a defect, not a limitation, and cli-h4 fixed it: both
//! implementations now delegate to `target::find_target_for_id`, which
//! resolves owners from the loader's include graph. The bail still exists
//! and still recommends `--into`, but it now fires only when the profile
//! exists in no loaded file at all.
//!
//! `--into` keeps its own reason to exist — an operator choosing WHICH
//! include a record goes into — and that is what the rest of this file
//! pins. [`the_advice_the_error_message_gives_actually_works`] now
//! asserts both halves: the no-flag path reaches the owning include, and
//! the flag still routes to a named one.
//!
//! Nothing here binds a socket or touches a real config path: every case
//! runs inside a `tempfile::TempDir` against a socket path that does not
//! exist, so the post-write reload degrades to "daemon not running".

use std::path::{Path, PathBuf};

use clap::Parser;
use purge_warden::cli::commands::{local_dns, rewrite};
use purge_warden::cli::Cli;

/// Master declaring an include glob that is deliberately **not**
/// `profiles.d/` — the layout the convention-derived target scan could
/// not see, and which owner resolution must now reach.
const MASTER: &str = r#"schema_version = 3

includes = ["custom/*.toml"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

const SLICE: &str = r#"[profiles.kids]
display_name = "Kids"
"#;

struct Fixture {
    _tmp: tempfile::TempDir,
    master: PathBuf,
    slice: PathBuf,
    /// A socket path that deliberately does not exist, so a successful
    /// write degrades to "daemon not running" rather than reaching one.
    ghost_socket: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, MASTER).expect("seed master");
    let custom = tmp.path().join("custom");
    std::fs::create_dir_all(&custom).expect("mkdir custom");
    let slice = custom.join("kids.toml");
    std::fs::write(&slice, SLICE).expect("seed slice");
    let ghost_socket = tmp.path().join("no-such.sock");
    Fixture {
        _tmp: tmp,
        master,
        slice,
        ghost_socket,
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).expect("read")
}

// ── The clap surface ──────────────────────────────────────────────────

#[test]
fn all_four_mutating_verbs_declare_into() {
    for argv in [
        vec![
            "warden",
            "local-dns",
            "add",
            "nas.home",
            "A",
            "10.0.0.5",
            "--profile",
            "kids",
            "--into",
            "custom/kids.toml",
        ],
        vec![
            "warden",
            "local-dns",
            "remove",
            "nas.home",
            "--profile",
            "kids",
            "--into",
            "custom/kids.toml",
        ],
        vec![
            "warden",
            "rewrite",
            "add",
            "a.old.com",
            "a.new.com",
            "--profile",
            "kids",
            "--into",
            "custom/kids.toml",
        ],
        vec![
            "warden",
            "rewrite",
            "remove",
            "a.old.com",
            "--profile",
            "kids",
            "--into",
            "custom/kids.toml",
        ],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_ok(),
            "clap rejected an argv the error messages recommend: {argv:?}"
        );
    }
}

/// `local-dns`'s global table only ever lives in the master, so `--into`
/// without `--profile` names a target that cannot be honoured. Rejecting
/// at parse time beats accepting and silently ignoring it — the latter
/// would be the same class of defect this flag was added to close.
#[test]
fn local_dns_into_without_profile_is_refused_not_ignored() {
    for verb in ["add", "remove"] {
        let mut argv = vec!["warden", "local-dns", verb, "nas.home"];
        if verb == "add" {
            argv.extend(["A", "10.0.0.5"]);
        }
        argv.extend(["--into", "custom/kids.toml"]);

        // `Cli` is not `Debug`, so `expect_err` is unavailable — match
        // the Ok arm explicitly instead of forcing a derive on the CLI
        // type just to satisfy a test.
        let err = match Cli::try_parse_from(&argv) {
            Ok(_) => panic!("`--into` without `--profile` must not parse: {argv:?}"),
            Err(e) => e.to_string(),
        };

        // Discriminating: any parse error at all would satisfy
        // `expect_err` — a typo in the argv above would pass a bare
        // `is_err()`. Pin it to the missing-requirement clap reports.
        assert!(
            err.contains("--profile"),
            "expected the failure to name --profile, got: {err}"
        );
    }
}

// ── The behaviour ─────────────────────────────────────────────────────

/// `--into` remains honoured, and — since cli-h4 — is no longer *needed*
/// to reach a profile in a non-conventional include.
///
/// # What changed under this test
///
/// It used to open by asserting that a write with no `--into` FAILS,
/// because `find_profile_target_file` scanned `profiles.d/` and nothing
/// else. That assertion pinned the defect as intended behaviour: the
/// profile is in the merged config, the operator can see it in
/// `warden profile list`, and the verb refused to write to it. cli-h4
/// routes both `find_profile_target_file`s through
/// `target::find_target_for_id`, which resolves owners from the loader's
/// include graph, so the no-flag path now finds `custom/kids.toml`.
///
/// Step 1 therefore asserts the opposite of what it used to — a strictly
/// stronger claim, since the old code could not satisfy it. Steps 2-3 are
/// unchanged: `--into` still routes to the named slice and still does not
/// leak into the master.
#[tokio::test]
async fn the_advice_the_error_message_gives_actually_works() {
    let f = fixture();

    // 1. WITHOUT `--into`: the profile lives in a declared include that is
    //    not `profiles.d/`, and the write must find it anyway. Asserting
    //    the landing site, not just the Ok — resolving to the master would
    //    also return Ok while silently writing to the wrong file.
    local_dns::run_add(
        &f.master,
        &f.ghost_socket,
        "router.home",
        "A",
        "10.0.0.1",
        Some("kids"),
        false,
        None,
        None,
    )
    .await
    .expect("cli-h4: a profile in a declared include must be writable without --into");
    assert!(
        read(&f.slice).contains("router.home"),
        "record did not land in the include that owns the profile: {}",
        read(&f.slice)
    );
    assert!(
        !read(&f.master).contains("router.home"),
        "record fell back to the master instead of the owning include: {}",
        read(&f.master)
    );

    // 2. `--into` still works, and is still what the bail recommends for
    //    the case that remains reachable (a profile that exists nowhere).
    local_dns::run_add(
        &f.master,
        &f.ghost_socket,
        "nas.home",
        "A",
        "10.0.0.5",
        Some("kids"),
        false,
        None,
        Some(Path::new("custom/kids.toml")),
    )
    .await
    .expect("the flag the message recommends must work");

    // 3. The record landed in the slice the operator named, and the
    //    master was left alone. Asserting both sides is what makes this
    //    discriminating: a `--into` that was parsed and then dropped on
    //    the floor would still satisfy the first assertion alone.
    assert!(read(&f.slice).contains("nas.home"), "{}", read(&f.slice));
    assert!(
        !read(&f.master).contains("nas.home"),
        "record leaked into the master: {}",
        read(&f.master)
    );
}

/// cli-h4, the `rewrite` half. `local_dns` and `rewrite` carried
/// byte-identical copies of `find_profile_target_file`, so they also
/// carried the same defect — and a fix applied to one would leave the
/// other silently broken. Both now delegate to the same seat; this pins
/// the second one independently rather than trusting the shared call.
#[tokio::test]
async fn rewrite_reaches_a_non_conventional_include_without_into() {
    let f = fixture();

    rewrite::run_add(
        &f.master,
        &f.ghost_socket,
        "ads.old.com",
        "ads.new.com",
        "kids",
        false,
        None,
    )
    .await
    .expect("cli-h4: rewrite must reach a profile in a declared include without --into");

    assert!(
        read(&f.slice).contains("ads.old.com"),
        "rule did not land in the include that owns the profile: {}",
        read(&f.slice)
    );
    assert!(
        !read(&f.master).contains("ads.old.com"),
        "rule fell back to the master instead of the owning include: {}",
        read(&f.master)
    );
}

#[tokio::test]
async fn rewrite_into_round_trips_through_the_named_slice() {
    let f = fixture();

    rewrite::run_add(
        &f.master,
        &f.ghost_socket,
        "a.old.com",
        "a.new.com",
        "kids",
        false,
        Some(Path::new("custom/kids.toml")),
    )
    .await
    .expect("add --into");
    assert!(read(&f.slice).contains("a.old.com"), "{}", read(&f.slice));
    assert!(
        !read(&f.master).contains("a.old.com"),
        "rule leaked into the master: {}",
        read(&f.master)
    );

    rewrite::run_remove(
        &f.master,
        &f.ghost_socket,
        "a.old.com",
        "kids",
        Some(Path::new("custom/kids.toml")),
    )
    .await
    .expect("remove --into");
    assert!(
        !read(&f.slice).contains("a.old.com"),
        "remove --into left the rule behind: {}",
        read(&f.slice)
    );
}

/// `--into` reaches the shared path-checked resolver rather than writing
/// wherever it is pointed. Without this the new flag would be a
/// write-anywhere primitive on a root-run binary.
#[tokio::test]
async fn into_cannot_escape_the_config_tree() {
    let f = fixture();

    for escape in ["/etc/passwd", "../evil.toml"] {
        let err = local_dns::run_add(
            &f.master,
            &f.ghost_socket,
            "nas.home",
            "A",
            "10.0.0.5",
            Some("kids"),
            false,
            None,
            Some(Path::new(escape)),
        )
        .await
        .unwrap_err();

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("must live under"),
            "expected the path guard to refuse {escape}, got: {rendered}"
        );
    }
}
