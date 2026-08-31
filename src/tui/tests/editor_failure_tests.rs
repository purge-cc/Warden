use super::format_editor_failure;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

#[test]
fn success_exit_returns_none() {
    let status = Ok(ExitStatus::from_raw(0));
    assert!(format_editor_failure("nano", status).is_none());
}

#[test]
fn non_zero_exit_names_editor_and_offers_retry() {
    // Wait-status encoding: low byte is signal, high byte is exit code.
    let status = Ok(ExitStatus::from_raw(1 << 8));
    let msg = format_editor_failure("vim", status).expect("non-zero must surface");
    assert!(msg.contains("vim"), "must name the editor: {msg}");
    assert!(
        msg.contains("Press 'e' to retry"),
        "must give next command: {msg}"
    );
    assert!(
        msg.contains("config reloaded"),
        "must explain reload-from-disk: {msg}"
    );
}

#[test]
fn spawn_failure_names_editor_and_points_to_fix() {
    let err = io::Error::new(io::ErrorKind::NotFound, "no such file");
    let msg =
        format_editor_failure("nonsense-editor", Err(err)).expect("spawn failure must surface");
    assert!(
        msg.contains("nonsense-editor"),
        "must name the editor: {msg}"
    );
    assert!(msg.contains("Set $EDITOR"), "must point to fix: {msg}");
    assert!(
        msg.contains("Press 'e' to retry"),
        "must give next command: {msg}"
    );
}
