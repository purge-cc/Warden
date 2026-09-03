use super::*;
use std::sync::Mutex;

/// Serialises the EDITOR-mutating test below. `std::env::set_var` is
/// process-global — without this lock it races any other test in this
/// binary that touches `EDITOR` under `cargo test`'s default thread
/// parallelism. Mirrors the `ENV_LOCK` pattern in
/// `cli/commands/config/edit.rs` / `hr2_test_support.rs`. Poison is
/// recovered — a panicking test must not wedge the rest.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    master
}

fn poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

/// `tui-mod-01`: the `[e]` `$EDITOR` hand-off used to refresh only the
/// document *viewer* (`app.file.sections` / `config_text`) and never
/// `app.loaded_config` — the field Subnets, Profiles, Rules, Local DNS,
/// Labels, Groups and Custom Lists all read. This drives the real `[e]`
/// arm with `EDITOR` pointed at a stand-in that rewrites the config out
/// from under the TUI, exactly as a real editor save would, and asserts
/// the structured config caught up — not just the raw text.
///
/// The raw-mode / alternate-screen toggles in this arm run against
/// whatever `cargo test`'s process considers its terminal; under this
/// harness that is not a live tty (`terminal_guard_tests.rs` notes the
/// same thing — "cargo test, no tty at all cannot reproduce" a live
/// ioctl failure, because there is no tty to fail on), so those calls
/// error and land in `step_error`. That is fine for this assertion:
/// `app.loaded_config` and `refresh_auto_backup_view` run
/// unconditionally, before the `step_error` early-return that skips only
/// the daemon reload — so the assertion below holds regardless of
/// whether this test process happens to have a controlling terminal.
#[cfg(unix)]
#[tokio::test]
async fn editor_save_refreshes_loaded_config_not_just_the_viewer() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    // Stands in for the operator's editor: it overwrites whatever path it
    // is given (the config, appended by `handle_file_key` itself) with a
    // config that differs from the fixture above in a way
    // `app.loaded_config` can observe. `cp` needs no exec bit and no
    // shell quoting — `split_editor_invocation` is a dumb whitespace
    // split, so a script with embedded spaces could not be passed as one
    // EDITOR token anyway.
    let edited = dir.path().join("edited.toml");
    std::fs::write(
        &edited,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Edited By Operator"
"#,
    )
    .unwrap();

    let mut app = App::new();
    app.loaded_config = load_v1_config(&master);
    assert_eq!(
        app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
        "Default",
        "fixture sanity check before the edit"
    );

    // Scoped rather than held for the whole test: `handle_file_key` is
    // `async` now (that is the fix under test), and clippy's
    // `await_holding_lock` refuses a std `MutexGuard` alive across an
    // `.await`. The guard only needs to serialise the two env mutations
    // against other EDITOR-touching tests, not the call in between.
    {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", format!("cp {}", edited.display()));
    }

    let poller = poller(dir.path());
    handle_file_key(
        &mut app,
        KeyEvent::from(KeyCode::Char('e')),
        &poller,
        &master,
    )
    .await;

    {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("EDITOR");
    }

    assert_eq!(
        app.loaded_config
            .as_ref()
            .expect("the edit produced valid TOML — loaded_config must stay Some")
            .config
            .profiles["default"]
            .display_name,
        "Edited By Operator",
        "app.loaded_config must observe the on-disk change $EDITOR made — \
         before this fix only app.file.config_text (the raw viewer) did"
    );
}
