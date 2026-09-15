use super::*;

fn fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let before = b"sentinel: legacy writers must not parse or replace this\n".to_vec();
    std::fs::write(&path, &before).unwrap();
    (dir, path, before)
}

fn assert_retired<T>(result: anyhow::Result<T>) {
    let error = result.err().expect("legacy rule writer must fail");
    assert_eq!(error.to_string(), LEGACY_RULES_RETIRED);
}

fn assert_unchanged(path: &Path, before: &[u8]) {
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn retirement_message_directs_operators_to_schema_five_policy() {
    assert_eq!(
        LEGACY_RULES_RETIRED,
        "Legacy allow/deny rules and device overlays are retired. Create a Custom List and mount it on the target profile instead."
    );
}

#[test]
fn add_remove_and_filtered_remove_reject_before_read_or_write() {
    let (_dir, path, before) = fixture();

    assert_retired(add_inner(
        &path,
        Scope::Profile("default"),
        Action::Allow,
        "example.com",
        None,
        None,
    ));
    assert_retired(remove_inner(
        &path,
        Scope::Profile("default"),
        Action::Deny,
        "example.com",
        None,
    ));
    assert_retired(remove_inner_matching(
        &path,
        Scope::Device("device"),
        Action::Allow,
        "example.com",
        None,
        Some("legacy-id"),
    ));

    assert_unchanged(&path, &before);
}

#[test]
fn move_remove_by_id_undo_and_prune_reject_before_read_or_write() {
    let (_dir, path, before) = fixture();

    assert_retired(move_admin_rule_without_reload(
        &path,
        "legacy-id",
        Scope::Profile("default"),
        Action::Allow,
        Scope::Profile("default"),
        Action::Deny,
    ));
    assert_retired(remove_admin_rule_by_id_without_reload(&path, "legacy-id"));
    assert_retired(undo_inner(&path));
    assert_retired(prune_inner(&path, "device", None));

    assert_unchanged(&path, &before);
}

#[test]
fn guarded_entry_points_also_reject_without_mutating() {
    let (_dir, path, before) = fixture();
    let guard = acquire_for_write(&path).unwrap();

    assert_retired(add_inner_locked(
        &guard,
        &path,
        Scope::Default,
        Action::Allow,
        "example.com",
        None,
        None,
    ));
    assert_retired(remove_inner_locked(
        &guard,
        &path,
        Scope::Default,
        Action::Deny,
        "example.com",
        None,
    ));
    assert_retired(remove_inner_matching_locked(
        &guard,
        &path,
        Scope::Default,
        Action::Deny,
        "example.com",
        None,
        Some("legacy-id"),
    ));
    assert_retired(undo_inner_locked(&guard, &path));
    assert_retired(prune_inner_locked(&guard, &path, "device", None));

    assert_unchanged(&path, &before);
}

#[tokio::test]
async fn public_async_rule_commands_reject_without_reload_or_write() {
    let (_dir, path, before) = fixture();
    let socket = path.with_extension("sock");

    assert_retired(
        run_apply(
            &path,
            &socket,
            Scope::Default,
            Action::Allow,
            "example.com",
            None,
            false,
            None,
        )
        .await,
    );
    assert_retired(run_undo(&path, &socket).await);
    assert_retired(run_prune(&path, &socket, "device", None).await);

    assert_unchanged(&path, &before);
    assert!(
        !socket.exists(),
        "rejected commands must not contact a daemon"
    );
}
