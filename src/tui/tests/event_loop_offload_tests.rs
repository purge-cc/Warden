use super::*;
use backup_restore_modal::{RestoreModal, RestorePoint, RestoreStage, SubmitOutcome};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;
use std::time::Duration;

fn key_char(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn dummy_poller() -> IpcPoller {
    // Ghost socket: the post-restore reload fails, which must NOT demote a
    // successful swap to `Failed` — asserted below.
    IpcPoller::new(Path::new(
        "/tmp/purge-warden-tui-02-nonexistent-socket.sock",
    ))
}

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

/// A real tar.gz of a real, valid config tree — so the restore genuinely
/// untars, validates and swaps. That work is what moved to the blocking
/// pool; a mocked archive would not exercise it.
fn mk_master_and_archive(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let master = mk_master(dir);
    let backup_dir = dir.path().join("backups");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let report = crate::cli::commands::config::create_backup(&master, Some(&backup_dir)).unwrap();
    (master, report.archive)
}

fn point_for(archive: &Path) -> RestorePoint {
    RestorePoint {
        path: archive.to_path_buf(),
        date: "2026-07-12 12:00".to_string(),
        age: "just now".to_string(),
        size: "1.0 KiB".to_string(),
    }
}

fn app_with_restore_modal(
    stage: RestoreStage,
) -> (App, tokio::sync::mpsc::UnboundedReceiver<app::UiJob>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<app::UiJob>();
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;
    app.job_tx = Some(tx);
    app.settings.restore_modal = Some(RestoreModal { stage });
    (app, rx)
}

/// tui-02, the headline regression. `y` on the confirm card must RETURN with
/// the restore still in flight. Before the fix the untar ran inline on the
/// event-loop thread and the handler could only ever come back with
/// `Submitted` — `Restoring` was a state the old code could not produce, so
/// this assertion fails against it. The outcome then comes home through the
/// same `job_rx` channel the loop drains for the catalog fetch.
#[tokio::test]
async fn restore_confirm_hands_off_to_a_background_job() {
    let dir = tempfile::tempdir().unwrap();
    let (master, archive) = mk_master_and_archive(&dir);
    let (mut app, mut rx) = app_with_restore_modal(RestoreStage::Confirming {
        point: point_for(&archive),
    });

    handle_key(&mut app, key_char('y'), &dummy_poller(), &master).await;

    let modal = app
        .settings
        .restore_modal
        .as_ref()
        .expect("the card stays open while the restore runs");
    assert!(
        matches!(modal.stage, RestoreStage::Restoring { .. }),
        "`y` must hand off and leave the card in Restoring — an inline \
             extraction would have come back Submitted"
    );

    let job = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("the restore job must report back through job_rx")
        .expect("job channel open");
    let app::UiJob::RestoreFinished(outcome) = job else {
        panic!("expected UiJob::RestoreFinished");
    };
    // The archive is a real backup of a valid tree, so the swap lands. Only
    // the daemon reload fails (ghost socket) — and a reload failure must not
    // demote the restore, the config is already swapped on disk.
    assert!(
        matches!(outcome, SubmitOutcome::Ok(_)),
        "real archive + valid tree must restore: {outcome:?}"
    );

    apply_job_result(&mut app, app::UiJob::RestoreFinished(outcome));
    assert!(
        matches!(
            app.settings.restore_modal.as_ref().unwrap().stage,
            RestoreStage::Submitted(_)
        ),
        "applying the job result must land the outcome on the open card"
    );
}

/// The `Restoring` card owns the keyboard. A second `y` must not start a
/// second extraction — two `restore_archive` calls interleaving on the same
/// live tree (each renaming the master aside and swapping the `*.d/` dirs)
/// is a config-corrupting race. Esc must not close the card either: the
/// outcome of a live-config swap is still coming.
#[tokio::test]
async fn restoring_card_swallows_keys_and_starts_no_second_extraction() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    // A nonexistent archive: were the guard missing, `start_restore` would
    // spawn a job that fails fast ("archive not found") and reports within
    // microseconds — so the empty channel below is a real negative, not a
    // race we happened to win.
    let ghost = dir.path().join("no-such-archive.tar.gz");
    let (mut app, mut rx) = app_with_restore_modal(RestoreStage::Restoring {
        point: point_for(&ghost),
    });

    handle_key(&mut app, key_char('y'), &dummy_poller(), &master).await;
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &dummy_poller(),
        &master,
    )
    .await;

    let modal = app
        .settings
        .restore_modal
        .as_ref()
        .expect("Esc must not close a card whose restore is still in flight");
    assert!(
        matches!(modal.stage, RestoreStage::Restoring { .. }),
        "keys must not move the stage while the restore runs"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .is_err(),
        "no second restore job may be spawned while one is in flight"
    );
}

/// The outcome of a live-config swap is never dropped on the floor. If the
/// card is gone by the time the job lands, it falls back to the footer.
#[test]
fn restore_outcome_falls_back_to_the_footer_when_the_card_is_gone() {
    let mut app = App::new();
    apply_job_result(
        &mut app,
        app::UiJob::RestoreFinished(SubmitOutcome::Failed("restore failed: boom".into())),
    );
    let status = app.last_status.expect("the outcome must surface somewhere");
    assert!(status.text.contains("boom"), "got: {}", status.text);
    assert!(matches!(
        status.severity,
        crate::tui::app::StatusSeverity::Error
    ));
}

/// tui-11. The dismissal write now runs on the blocking pool, so the
/// keypress returns immediately — but the line must still reach disk.
/// Fire-and-forget is exactly the shape that can silently never run, so pin
/// the effect, not just the intent.
#[tokio::test]
async fn welcome_banner_dismiss_still_persists_when_run_off_thread() {
    let dir = tempfile::tempdir().unwrap();
    let seen = dir.path().join("seen_versions");
    let mut app = App::new();
    app.welcome_banner = Some(welcome_banner::WelcomeBanner::with_path(
        welcome_banner::WELCOME_SEEN_KEY,
        "copy",
        seen.clone(),
    ));

    handle_key(
        &mut app,
        key_char('x'),
        &dummy_poller(),
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.welcome_banner.is_none(),
        "any key dismisses the banner and is consumed by it"
    );

    let mut persisted = false;
    for _ in 0..100 {
        if welcome_banner::version_already_seen(&seen, welcome_banner::WELCOME_SEEN_KEY) {
            persisted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        persisted,
        "the off-thread dismissal must still record the seen key, or the \
             banner re-shows on every launch"
    );
}

// ── tui-14: the backup half of the same defect ──

fn app_with_backup_modal(
    modal: backup_restore_modal::BackupModal,
) -> (App, tokio::sync::mpsc::UnboundedReceiver<app::UiJob>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<app::UiJob>();
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;
    app.job_tx = Some(tx);
    app.settings.backup_modal = Some(modal);
    (app, rx)
}

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

/// tui-14, the headline regression and the exact mirror of
/// `restore_confirm_hands_off_to_a_background_job`. `y` on the confirm card
/// must RETURN with the backup still in flight. Before the fix the tar+gzip
/// ran inline on the event-loop thread and the handler could only ever come
/// back with `Submitted` — `Running` was a state the old code could not
/// produce, so this assertion fails against it. The outcome then comes home
/// through the same `job_rx` channel the loop drains for the catalog fetch.
#[tokio::test]
async fn backup_confirm_hands_off_to_a_background_job() {
    use backup_restore_modal::BackupModal;

    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let backup_dir = crate::cli::commands::config::resolved_backup_dir(&master);
    let (mut app, mut rx) = app_with_backup_modal(BackupModal::Confirm {
        dir: backup_dir.clone(),
    });

    handle_key(&mut app, key_char('y'), &dummy_poller(), &master).await;

    assert!(
        matches!(app.settings.backup_modal, Some(BackupModal::Running { .. })),
        "`y` must hand off and leave the card in Running — an inline \
             tar+gzip would have come back Submitted; got {:?}",
        app.settings.backup_modal
    );

    let job = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("the backup job must report back through job_rx")
        .expect("job channel open");
    let app::UiJob::BackupFinished {
        outcome,
        auto_backup,
    } = job
    else {
        panic!("expected UiJob::BackupFinished");
    };
    assert!(
        matches!(outcome, SubmitOutcome::Ok(_)),
        "a real, valid config tree must back up: {outcome:?}"
    );

    apply_job_result(
        &mut app,
        app::UiJob::BackupFinished {
            outcome,
            auto_backup,
        },
    );
    match &app.settings.backup_modal {
        Some(BackupModal::Submitted { msg, ok }) => {
            assert!(*ok, "backup must succeed, msg = {msg}");
            assert!(
                msg.starts_with("backup saved:"),
                "success message template, got: {msg}"
            );
        }
        other => {
            panic!("applying the job result must land the outcome on the open card, got {other:?}")
        }
    }

    // The work actually happened off-thread, not just the state transition.
    assert_eq!(
        archive_count(&backup_dir),
        1,
        "exactly one *.tar.gz must land in the resolved backup dir"
    );
    // And the post-backup snapshot — itself a readdir + JSON read, taken on
    // the blocking thread — came home in the payload and saw the new archive.
    assert!(
        app.settings.auto_backup.last_archive.is_some(),
        "the refreshed auto-backup view must observe the archive just written"
    );
}

/// The `Running` card owns the keyboard. A second `y` must not start a
/// second `create_backup`: the TUI path takes no lock (unlike the
/// `run_backup_managed` CLI path), so two archives could collide on the same
/// second-granularity filename. Esc must not close the card either — the
/// outcome is still coming, and `apply_job_result` would have nowhere to
/// land it.
#[tokio::test]
async fn running_card_swallows_keys_and_starts_no_second_backup() {
    use backup_restore_modal::BackupModal;

    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let backup_dir = crate::cli::commands::config::resolved_backup_dir(&master);
    let (mut app, mut rx) = app_with_backup_modal(BackupModal::Running {
        dir: backup_dir.clone(),
    });

    handle_key(&mut app, key_char('y'), &dummy_poller(), &master).await;
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &dummy_poller(),
        &master,
    )
    .await;

    assert!(
        matches!(app.settings.backup_modal, Some(BackupModal::Running { .. })),
        "keys must not move the stage while the backup runs, and Esc must \
             not close a card whose outcome is still in flight"
    );
    // Were the guard missing, `start_backup` would spawn a job against this
    // valid tree that succeeds and reports within milliseconds — so an empty
    // channel here is a real negative, not a race we happened to win.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .is_err(),
        "no second backup job may be spawned while one is in flight"
    );
    assert_eq!(
        archive_count(&backup_dir),
        0,
        "a swallowed key must not write an archive"
    );
}
