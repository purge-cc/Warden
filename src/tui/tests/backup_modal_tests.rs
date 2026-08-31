use super::*;
use crate::tui::app::{App, Leaf};
use crate::tui::backup_restore_modal::BackupModal;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn dummy_poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

/// Minimal v2 master that `load_v1_config` will accept. Mirrors the
/// helper used by the s53 list-modal tests but copied here so this
/// module is independent.
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

/// Count `*.tar.gz` archives in the resolved backup dir. `0` when
/// the dir doesn't exist yet — that's the "no archive written"
/// state we assert in the cancel-path tests.
fn archive_count(backup_dir: &Path) -> usize {
    if !backup_dir.exists() {
        return 0;
    }
    std::fs::read_dir(backup_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
        .count()
}

#[tokio::test]
async fn pressing_b_opens_backup_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;

    handle_settings_key(&mut app, key(KeyCode::Char('b')), &poller, &master).await;

    assert!(
        matches!(app.settings.backup_modal, Some(BackupModal::Confirm { .. })),
        "b opens the confirm modal, got {:?}",
        app.settings.backup_modal
    );
    let backup_dir = master.parent().unwrap().join("backups");
    assert_eq!(
        archive_count(&backup_dir),
        0,
        "no archive may be written on press-b — confirm is required"
    );
}

#[tokio::test]
async fn confirm_y_runs_backup_and_transitions_to_submitted() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;

    handle_settings_key(&mut app, key(KeyCode::Char('b')), &poller, &master).await;
    handle_backup_modal_key(&mut app, key(KeyCode::Char('y')), &master).await;

    match &app.settings.backup_modal {
        Some(BackupModal::Submitted { msg, ok }) => {
            assert!(*ok, "backup must succeed, msg = {msg}");
            assert!(
                msg.starts_with("backup saved:"),
                "success message template, got: {msg}"
            );
        }
        other => panic!("expected Submitted{{ok:true,..}}, got {other:?}"),
    }
    let backup_dir = master.parent().unwrap().join("backups");
    assert_eq!(
        archive_count(&backup_dir),
        1,
        "exactly one *.tar.gz must land in the resolved backup dir"
    );
}

#[tokio::test]
async fn confirm_n_cancels_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;

    handle_settings_key(&mut app, key(KeyCode::Char('b')), &poller, &master).await;
    handle_backup_modal_key(&mut app, key(KeyCode::Char('n')), &master).await;

    assert!(app.settings.backup_modal.is_none(), "n drops the modal");
    let backup_dir = master.parent().unwrap().join("backups");
    assert_eq!(archive_count(&backup_dir), 0, "n must NOT write an archive");
}

#[tokio::test]
async fn confirm_esc_cancels_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;

    handle_settings_key(&mut app, key(KeyCode::Char('b')), &poller, &master).await;
    handle_backup_modal_key(&mut app, key(KeyCode::Esc), &master).await;

    assert!(app.settings.backup_modal.is_none(), "Esc drops the modal");
    let backup_dir = master.parent().unwrap().join("backups");
    assert_eq!(
        archive_count(&backup_dir),
        0,
        "Esc must NOT write an archive"
    );
}
