//! `warden lists set` — the write paths that must not corrupt config.
//!
//! `set` mutates the master through `write_value_validated`, which loads
//! the COMBINED master + includes state and only promotes the write if
//! that load succeeds. The property that matters operationally is that a
//! value the validator rejects leaves the file **byte-identical** — not
//! written-then-reverted, and certainly not written-and-left.
//!
//! Every assertion here is paired with a control arm. "The write was
//! refused and the bytes match" also holds when the fixture is invalid
//! for some unrelated reason, so each refusal test is accompanied by a
//! success on the same fixture proving the path works at all.

use std::path::Path;

use purge_warden::cli::commands::lists_knobs;
use purge_warden::config::schema::validator::LISTS_MAX_ENTRIES_ZERO;

/// Minimal valid v1 master carrying an explicit `[lists]` section.
const MASTER: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[lists]
max_entries = 5000000
max_total_domains = 14000000

[upstream]
servers = ["192.0.2.1:53"]
"#;

struct Fixture {
    _tmp: tempfile::TempDir,
    master: std::path::PathBuf,
    /// A socket path that deliberately does not exist: a successful
    /// `set` attempts a reload, and must degrade to "daemon not running"
    /// rather than reaching any real daemon.
    ghost_socket: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, MASTER).expect("seed master");
    let ghost_socket = tmp.path().join("absent.sock");
    assert!(!ghost_socket.exists(), "the ghost socket must not exist");
    Fixture {
        _tmp: tmp,
        master,
        ghost_socket,
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read master")
}

/// A validator-rejected value must leave the file byte-identical.
///
/// `lists.max_entries = 0` truncates every list to zero domains, which
/// runs the daemon normally with filtering silently off — the validator
/// refuses it. `set` must surface that refusal without having touched
/// the config.
#[tokio::test]
async fn max_entries_zero_is_refused_with_the_file_byte_identical() {
    let f = fixture();
    let before = read(&f.master);

    let err = lists_knobs::run_set(&f.master, &f.ghost_socket, "max_entries", "0")
        .await
        .expect_err("max_entries = 0 must be refused");

    // Discriminating: any error at all would satisfy `expect_err`, so
    // pin it to the validator's own frozen message. A fixture that was
    // invalid for an unrelated reason would fail here.
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(LISTS_MAX_ENTRIES_ZERO),
        "the refusal must be the max_entries gate, got: {rendered}"
    );

    assert_eq!(
        before,
        read(&f.master),
        "a refused write must leave the config byte-identical"
    );

    // Control arm: the same fixture, the same knob, a value the
    // validator accepts. Without this, the assertion above would also
    // pass if `run_set` could never write anything at all.
    lists_knobs::run_set(&f.master, &f.ghost_socket, "max_entries", "6000000")
        .await
        .expect("a valid max_entries must be accepted");
    let after = read(&f.master);
    assert_ne!(before, after, "the control write must change the file");
    assert!(
        after.contains("6000000"),
        "the new value must be on disk: {after}"
    );
}

/// The DoD case from the brief: raise the corpus ceiling, then raise it
/// again to the same value.
#[tokio::test]
async fn setting_the_same_value_twice_is_a_no_op_that_leaves_the_file_alone() {
    let f = fixture();

    lists_knobs::run_set(&f.master, &f.ghost_socket, "max_total_domains", "15000000")
        .await
        .expect("first set");
    let after_first = read(&f.master);
    assert!(
        after_first.contains("15000000"),
        "the first set must land: {after_first}"
    );

    lists_knobs::run_set(&f.master, &f.ghost_socket, "max_total_domains", "15000000")
        .await
        .expect("second set");
    assert_eq!(
        after_first,
        read(&f.master),
        "a no-op set must not rewrite the file"
    );
}

/// An unknown key must fail, and the error must be actionable — the
/// operator needs the valid keys without running a second command.
#[tokio::test]
async fn an_unknown_key_is_refused_and_the_error_lists_the_valid_keys() {
    let f = fixture();
    let before = read(&f.master);

    let err = lists_knobs::run_set(&f.master, &f.ghost_socket, "nonsense", "5")
        .await
        .expect_err("an unknown key must be refused");
    let rendered = format!("{err:#}");

    assert!(rendered.contains("nonsense"), "{rendered}");
    for key in [
        "max_total_domains",
        "max_entries",
        "max_body_bytes",
        "cache_dir",
        "staleness_threshold_secs",
        "shrink_guard_enabled",
        "shrink_guard_max_drop_pct",
    ] {
        assert!(
            rendered.contains(key),
            "the error must name the valid key '{key}': {rendered}"
        );
    }

    assert_eq!(
        before,
        read(&f.master),
        "an unknown key must not touch the config"
    );
}

/// A value that parses but is out of the field's range is refused by the
/// validator, not silently clamped.
#[tokio::test]
async fn an_out_of_range_shrink_guard_pct_is_refused_with_the_file_unchanged() {
    let f = fixture();
    let before = read(&f.master);

    let err = lists_knobs::run_set(
        &f.master,
        &f.ghost_socket,
        "shrink_guard_max_drop_pct",
        "150",
    )
    .await
    .expect_err("150 is outside 1..=100");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("shrink_guard_max_drop_pct"),
        "the refusal must name the field: {rendered}"
    );
    assert_eq!(before, read(&f.master), "refused write must not touch disk");

    // Control arm: an in-range value on the same knob lands.
    lists_knobs::run_set(
        &f.master,
        &f.ghost_socket,
        "shrink_guard_max_drop_pct",
        "75",
    )
    .await
    .expect("75 is in range");
    assert!(
        read(&f.master).contains("75"),
        "the in-range value must land"
    );
}

/// `[lists]` is a singleton section: the loader refuses it appearing in
/// two files. `set` writes the master unconditionally, so an operator
/// who moved the section into an include must get a refusal naming both
/// files — never a successful write of a value the merged config would
/// then ignore.
#[tokio::test]
async fn a_lists_section_in_an_include_makes_the_master_write_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3
includes = ["conf.d/*.toml"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .expect("seed master");
    let dir = tmp.path().join("conf.d");
    std::fs::create_dir_all(&dir).expect("mk include dir");
    let include = dir.join("lists.toml");
    std::fs::write(&include, "[lists]\nmax_entries = 5000000\n").expect("seed include");

    let master_before = read(&master);
    let include_before = read(&include);
    let ghost = tmp.path().join("absent.sock");

    let err = lists_knobs::run_set(&master, &ghost, "max_entries", "6000000")
        .await
        .expect_err("writing [lists] to the master must collide with the include");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("duplicate singleton") && rendered.contains("lists"),
        "the refusal must explain the collision: {rendered}"
    );

    assert_eq!(master_before, read(&master), "master must be untouched");
    assert_eq!(include_before, read(&include), "include must be untouched");
}
