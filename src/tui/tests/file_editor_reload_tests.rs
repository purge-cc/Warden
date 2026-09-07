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
        r#"schema_version = 4

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

/// The File editor promotes exact staged bytes and refreshes both caches.
#[cfg(unix)]
#[test]
fn editor_save_refreshes_loaded_config_not_just_the_viewer() {
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
        r#"schema_version = 4

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

    let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prior_editor = std::env::var_os("EDITOR");
    let editor = format!("cp {}", edited.display());
    std::env::set_var("EDITOR", &editor);
    let outcome = run_file_editor_guarded(&mut app, &master, &editor);
    match prior_editor {
        Some(value) => std::env::set_var("EDITOR", value),
        None => std::env::remove_var("EDITOR"),
    }
    assert!(outcome.edit_error.is_none(), "{:?}", outcome.step_error);

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
    assert_eq!(
        app.file.config_text,
        std::fs::read_to_string(&edited).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn editor_rejects_a_migration_fence_without_launching_or_touching_the_tty() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let marker = dir.path().join("editor-ran");
    let migration = crate::config::write_lock::acquire_for_migration(&master).unwrap();
    crate::config::migration_journal::create_fence(&migration).unwrap();
    drop(migration);

    let mut app = App::new();
    let outcome =
        run_file_editor_guarded(&mut app, &master, &format!("touch {}", marker.display()));

    assert!(
        outcome
            .step_error
            .as_deref()
            .is_some_and(|message| message.contains("migration")),
        "unexpected outcome: {:?}",
        outcome.step_error
    );
    assert!(!marker.exists(), "the editor must not be launched");
    assert!(
        !app.reader_suspended
            .load(std::sync::atomic::Ordering::Acquire),
        "preflight refusal must not suspend the reader"
    );
}

#[cfg(unix)]
#[test]
fn invalid_staged_edit_leaves_the_live_bytes_and_cache_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let invalid = dir.path().join("invalid.toml");
    std::fs::write(&invalid, "schema_version = [\n").unwrap();
    let mut app = App::new();
    app.loaded_config = load_v1_config(&master);

    let outcome = run_file_editor_guarded(&mut app, &master, &format!("cp {}", invalid.display()));

    assert!(
        outcome
            .edit_error
            .as_deref()
            .is_some_and(|message| message.contains("edit not applied:")
                && message.contains("config is unchanged")),
        "unexpected outcome: {:?}",
        outcome.edit_error
    );
    assert_eq!(std::fs::read_to_string(&master).unwrap(), before);
    assert_eq!(
        app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
        "Default"
    );
    assert!(
        !outcome.should_attempt_reload(),
        "an invalid pre-commit edit must not request daemon reload"
    );
}

#[cfg(unix)]
#[test]
fn editor_uses_the_canonical_master_when_started_through_an_alias() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let alias_dir = tempfile::tempdir().unwrap();
    let alias = alias_dir.path().join("dashboard.toml");
    std::os::unix::fs::symlink(&master, &alias).unwrap();
    let edited = alias_dir.path().join("edited.toml");
    std::fs::write(
        &edited,
        r#"schema_version = 4

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Edited through alias"
"#,
    )
    .unwrap();

    let mut app = App::new();
    let outcome = run_file_editor_guarded(&mut app, &alias, &format!("cp {}", edited.display()));

    assert!(outcome.edit_error.is_none(), "{:?}", outcome.edit_error);
    assert!(std::fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        std::fs::read_to_string(&edited).unwrap()
    );
    assert!(
        !alias_dir.path().join(".warden-config.lock").exists()
            && !alias_dir.path().join("packs").exists()
            && std::fs::read_dir(alias_dir.path())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp")),
        "managed files must stay under the canonical tree"
    );
}

#[cfg(unix)]
#[test]
fn atomic_save_editor_can_replace_the_staged_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let editor = dir.path().join("atomic-save-editor");
    let observed = dir.path().join("staging-observed");
    std::fs::write(
        &editor,
        r#"#!/bin/sh
marker="$1"
stage="$2"
parent="$(dirname "$stage")"
printf '%s %s %s\n' "$(stat -c '%a' "$parent")" "$(stat -c '%a' "$stage")" "$parent" > "$marker"
printf 'editor backup\n' > "$stage~"
cat > "$stage.next" <<'TOML'
schema_version = 4

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Atomic save"
TOML
mv "$stage.next" "$stage"
"#,
    )
    .unwrap();
    let mut mode = std::fs::metadata(&editor).unwrap().permissions();
    mode.set_mode(0o700);
    std::fs::set_permissions(&editor, mode).unwrap();

    let mut app = App::new();
    let outcome = run_file_editor_guarded(
        &mut app,
        &master,
        &format!("{} {}", editor.display(), observed.display()),
    );

    assert!(outcome.edit_error.is_none(), "{:?}", outcome.edit_error);
    assert_eq!(
        app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
        "Atomic save"
    );
    let observed = std::fs::read_to_string(&observed).unwrap();
    let mut fields = observed.split_whitespace();
    assert_eq!(fields.next(), Some("700"), "staging directory: {observed}");
    assert_eq!(fields.next(), Some("600"), "staged file: {observed}");
    let staging_dir = std::path::PathBuf::from(fields.next().unwrap());
    assert!(
        !staging_dir.exists(),
        "the private directory must clean editor replacements and backups"
    );
}

#[test]
fn saved_refresh_failure_keeps_caches_and_still_requests_reload() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = App::new();
    app.loaded_config = load_v1_config(&master);
    app.file.config_text = "old text".to_string();
    app.file.sections = vec!["old".to_string()];
    assert!(
        install_file_editor_caches(&mut app, Err("injected cache read failure".into())).is_err()
    );
    let outcome = FileEditorOutcome::refresh_failed(
        None,
        FileEditorSaveState::Saved,
        "injected cache read failure".to_string(),
    );

    assert!(
        outcome
            .edit_error
            .as_deref()
            .is_some_and(|message| message.contains("edit saved, but TUI refresh failed")),
        "unexpected outcome: {:?}",
        outcome.edit_error
    );
    assert!(outcome.should_attempt_reload());
    assert_eq!(
        app.loaded_config.as_ref().unwrap().config.profiles["default"].display_name,
        "Default"
    );
    assert_eq!(app.file.config_text, "old text");
    assert_eq!(app.file.sections, ["old"]);
}

#[cfg(unix)]
#[test]
fn editor_failures_resume_the_reader() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    for editor in ["false", "warden-editor-does-not-exist"] {
        let mut app = App::new();
        let outcome = run_file_editor_guarded(&mut app, &master, editor);

        assert!(
            outcome.step_error.is_some(),
            "a failed editor must be surfaced"
        );
        assert!(
            !app.reader_suspended
                .load(std::sync::atomic::Ordering::Acquire),
            "the reader must resume after a failed editor"
        );
    }
}
