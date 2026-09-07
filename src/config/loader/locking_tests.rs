use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::sync::mpsc;
use std::time::Duration;

fn now() -> OffsetDateTime {
    time::macros::datetime!(2026-04-22 12:00:00 UTC)
}

#[test]
fn acquired_master_leaf_cannot_redirect_to_a_fenced_separately_locked_subtree() {
    for present in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        if present {
            tree(dir.path());
        }
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let nested_master = tree(&nested);
        let other = write_lock::acquire_for_migration(&nested_master).unwrap();
        migration_journal::create_fence(&other).unwrap();
        let guard = write_lock::acquire_for_migration(&master).unwrap();
        if present {
            fs::rename(&master, dir.path().join("old-master")).unwrap();
        }
        std::os::unix::fs::symlink("nested/config.toml", &master).unwrap();
        for errors in [
            probe_declared_schema_version_under_migration_guard(&guard, &master).unwrap_err(),
            load_config_for_schema_under_migration_guard(&guard, &master, 3, now()).unwrap_err(),
        ] {
            assert!(errors[0]
                .context()
                .reason
                .contains("canonical master changed"));
        }
        assert!(guard.tree_io().plan_master_target().is_err());
        assert!(guard.tree_io().plan_target(&master).is_err());
        assert_eq!(
            fs::read_to_string(&nested_master).unwrap(),
            "schema_version = 4\nincludes = [\"slice.toml\"]\n"
        );
        assert!(other.identity().txn_dir.exists());
    }
}

#[test]
fn public_load_and_probe_refuse_post_acquisition_master_swaps() {
    for probe in [false, true] {
        for symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let master = tree(dir.path());
            let nested = dir.path().join("nested");
            fs::create_dir(&nested).unwrap();
            let nested_master = tree(&nested);
            let other = write_lock::acquire_for_migration(&nested_master).unwrap();
            migration_journal::create_fence(&other).unwrap();
            let leaf = master.clone();
            let replacement = dir.path().join("replacement");
            fs::write(&replacement, "schema_version = 4\n").unwrap();
            write_lock::with_test_hook(
                move |event| {
                    if event == write_lock::TestEvent::RootLocked {
                        if symlink {
                            fs::remove_file(&leaf).unwrap();
                            std::os::unix::fs::symlink("nested/config.toml", &leaf).unwrap();
                        } else {
                            fs::rename(&replacement, &leaf).unwrap();
                        }
                    }
                },
                || {
                    let errors = if probe {
                        probe_declared_schema_version(&master).unwrap_err()
                    } else {
                        load_config(&master, now()).unwrap_err()
                    };
                    assert!(errors[0]
                        .context()
                        .reason
                        .contains("canonical master changed"));
                },
            );
        }
    }
}

#[test]
fn migration_capability_promotes_master_and_then_validates_under_the_fence() {
    use crate::config::atomic_write::{hardened_atomic_write_at, AtomicWriteAtOpts};
    for present in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        if present {
            fs::write(
                &master,
                "schema_version = 3\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            )
            .unwrap();
        }
        let guard = write_lock::acquire_for_migration(&master).unwrap();
        migration_journal::create_fence(&guard).unwrap();
        let plan = guard.tree_io().plan_master_target().unwrap();
        let after = "schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let mut overlay = LoaderOverlay::default();
        overlay.stage_plan(&plan, after.into()).unwrap();
        load_config_with_overlay_for_schema_under_migration_guard(
            &guard,
            &master,
            4,
            now(),
            Some(&overlay),
        )
        .unwrap();
        let target = plan.materialize().unwrap();
        hardened_atomic_write_at(&target, after.as_bytes(), AtomicWriteAtOpts::default()).unwrap();
        assert_eq!(
            probe_declared_schema_version_under_migration_guard(&guard, &master).unwrap(),
            4
        );
        load_config_for_schema_under_migration_guard(&guard, &master, 4, now()).unwrap();
        drop(guard);
        assert!(load_config_for_schema(&master, 4, now()).unwrap_err()[0]
            .context()
            .reason
            .contains("unfinished v3-to-v4"));
    }
}

#[test]
fn matching_symlink_to_directory_is_not_silently_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"*.toml\"]\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("directory")).unwrap();
    std::os::unix::fs::symlink("directory", dir.path().join("link.toml")).unwrap();
    let errors = load_config(&master, now()).unwrap_err();
    assert!(errors[0].context().reason.contains("not a regular file"));
}

#[test]
fn root_glob_ignores_the_reserved_write_lock_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"*\"]\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();

    let guard = write_lock::acquire_for_write(&master).unwrap();
    assert!(dir.path().join(".warden-config.lock").exists());
    load_config_for_schema_under_guard(&guard, &master, 4, now()).unwrap();
}

#[test]
fn glob_file_limit_and_descriptor_budget_in_an_isolated_process() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config::loader::locking_tests::glob_budget_child",
            "--nocapture",
        ])
        .env("WARDEN_GLOB_BUDGET_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn glob_budget_child() {
    if std::env::var_os("WARDEN_GLOB_BUDGET_CHILD").is_none() {
        return;
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_cur = limit.rlim_max.min(1024);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let slices = dir.path().join("slices");
    fs::create_dir(&slices).unwrap();
    fs::write(&master, "schema_version = 4\nincludes = [\"slices/*.toml\", \"slices/0*.toml\"]\n[upstream]\nservers = [\"192.0.2.1:53\"]\n").unwrap();
    let mut expected = vec![master.clone()];
    for index in 0..999 {
        let path = slices.join(format!("{index:04}.toml"));
        fs::write(
            &path,
            format!("[profiles.p{index:04}]\ndisplay_name = \"Profile {index}\"\n"),
        )
        .unwrap();
        expected.push(path);
    }
    for index in 0..4000 {
        fs::write(slices.join(format!("nonmatching-{index}")), "").unwrap();
    }
    // Many aliases consume neither additional file slots nor retained descriptors.
    for index in 0..1001 {
        std::os::unix::fs::symlink("0000.toml", slices.join(format!("alias-{index}.toml")))
            .unwrap();
    }
    let loaded = load_config(&master, now()).unwrap();
    assert_eq!(loaded.files_loaded, expected);
    assert_eq!(loaded.config.profiles.len(), 999);
    assert!(loaded.total_bytes > 40_000);
    fs::write(
        slices.join("1000.toml"),
        "[profiles.extra]\ndisplay_name = \"Extra\"\n",
    )
    .unwrap();
    let errors = load_config(&master, now()).unwrap_err();
    assert!(
        errors[0]
            .context()
            .reason
            .contains("include file count exceeded 1001 (hard cap 1000)"),
        "{errors:?}"
    );
}

fn tree(root: &Path) -> PathBuf {
    tree_for_schema(root, 4)
}

fn tree_for_schema(root: &Path, schema_version: u32) -> PathBuf {
    let master = root.join("config.toml");
    fs::write(
        &master,
        format!("schema_version = {schema_version}\nincludes = [\"slice.toml\"]\n"),
    )
    .unwrap();
    fs::write(
        root.join("slice.toml"),
        "[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    master
}

#[test]
fn every_normal_loader_and_probe_refuses_empty_and_malformed_fences() {
    for malformed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let master = tree(dir.path());
        let guard = write_lock::acquire_for_migration(&master).unwrap();
        migration_journal::create_fence(&guard).unwrap();
        let journal = guard
            .identity()
            .txn_dir
            .join(migration_journal::JOURNAL_NAME);
        if malformed {
            fs::write(&journal, "{").unwrap();
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        }
        drop(guard);
        let (collected, warnings) = load_config_collect(&master, now());
        assert!(warnings.is_empty());
        for errors in [
            load_config(&master, now()).unwrap_err(),
            load_config_for_schema(&master, 3, now()).unwrap_err(),
            load_config_for_schema(&master, 4, now()).unwrap_err(),
            load_config_with_overlay(&master, now(), None).unwrap_err(),
            load_config_with_overlay_for_schema(&master, 3, now(), None).unwrap_err(),
            collected.unwrap_err(),
            probe_declared_schema_version(&master).unwrap_err(),
        ] {
            assert_eq!(errors.len(), 1);
            assert!(matches!(errors[0], ConfigError::ValidationFailed(_)));
            assert_eq!(errors[0].context().file.as_deref(), Some(journal.as_path()));
            assert!(errors[0]
                .context()
                .reason
                .contains("warden migrate v3-to-v4 --from-config"));
        }
        assert!(journal.parent().unwrap().exists());
    }
}

#[test]
fn typed_loaders_complete_without_reacquiring_and_check_tree_and_schema() {
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let master = tree(dir.path());
        let wrong_master = tree(other.path());
        let baseline = load_config(&master, now()).unwrap();
        let guard = write_lock::acquire_for_write(&master).unwrap();
        let alias = dir.path().join("master-link");
        std::os::unix::fs::symlink("config.toml", &alias).unwrap();
        let loaded = load_config_for_schema_under_guard(&guard, &alias, 4, now()).unwrap();
        assert_eq!(loaded.files_loaded, baseline.files_loaded);
        assert_eq!(loaded.provenance, baseline.provenance);
        assert_eq!(loaded.total_bytes, baseline.total_bytes);
        assert!(load_config_for_schema_under_guard(&guard, &master, 3, now()).is_err());
        let wrong =
            load_config_for_schema_under_guard(&guard, &wrong_master, 4, now()).unwrap_err();
        assert!(wrong[0].context().reason.contains("guard belongs to"));
        let mut overlay = LoaderOverlay::default();
        overlay.stage(
            master.clone(),
            "schema_version = 4\nincludes = [\"slice.toml\"]\n".into(),
            false,
        );
        assert_eq!(
            load_config_with_overlay_for_schema_under_guard(
                &guard,
                &master,
                4,
                now(),
                Some(&overlay)
            )
            .unwrap()
            .config
            .schema_version,
            4
        );
        // A normal guard cannot acquire a migration bypass by outliving fence creation.
        fs::create_dir(guard.identity().txn_dir.clone()).unwrap();
        assert!(load_config_for_schema_under_guard(&guard, &master, 4, now()).is_err());
        drop(guard);
        let guard = write_lock::acquire_for_migration(&master).unwrap();
        assert_eq!(
            probe_declared_schema_version_under_migration_guard(&guard, &alias).unwrap(),
            4
        );
        assert!(load_config_for_schema_under_migration_guard(&guard, &master, 4, now()).is_ok());
        assert!(
            load_config_for_schema_under_migration_guard(&guard, &wrong_master, 4, now()).is_err()
        );
        assert!(load_config_with_overlay_for_schema_under_migration_guard(
            &guard,
            &wrong_master,
            4,
            now(),
            Some(&overlay)
        )
        .is_err());
        assert_eq!(
            load_config_with_overlay_for_schema_under_migration_guard(
                &guard,
                &alias,
                4,
                now(),
                Some(&overlay)
            )
            .unwrap()
            .config
            .schema_version,
            4
        );
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("under-guard loading reacquired a lock or failed");
    worker.join().unwrap();
}

#[test]
fn read_guard_loader_checks_binding_and_the_fence_without_reacquiring() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    let other = tempfile::tempdir().unwrap();
    let master = tree(&root);
    let wrong_master = tree(other.path());
    let alias = root.join("master-link");
    std::os::unix::fs::symlink("config.toml", &alias).unwrap();
    let baseline = load_config_for_schema(&master, 4, now()).unwrap();
    let guard = write_lock::acquire_for_read(&alias).unwrap();

    assert_eq!(guard.canonical_master(), master);
    let loaded = write_lock::with_test_hook(
        |event| assert_ne!(event, write_lock::TestEvent::RootLocked),
        || load_config_for_schema_under_read_guard(&guard, &alias, 4, now()).unwrap(),
    );
    assert_eq!(
        toml::to_string(&loaded.config).unwrap(),
        toml::to_string(&baseline.config).unwrap()
    );
    assert_eq!(loaded.master_path, baseline.master_path);
    assert_eq!(loaded.files_loaded, baseline.files_loaded);
    assert_eq!(loaded.provenance, baseline.provenance);
    assert_eq!(loaded.total_bytes, baseline.total_bytes);
    assert!(load_config_for_schema_under_read_guard(&guard, &alias, 3, now()).is_err());
    let wrong =
        load_config_for_schema_under_read_guard(&guard, &wrong_master, 4, now()).unwrap_err();
    assert!(wrong[0].context().reason.contains("guard belongs to"));

    fs::create_dir(guard.identity().txn_dir.clone()).unwrap();
    assert!(load_config_for_schema_under_read_guard(&guard, &master, 4, now()).is_err());
    fs::remove_dir(guard.identity().txn_dir.clone()).unwrap();

    let old = dir.path().join("old-root");
    fs::rename(&root, &old).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("config.toml"), "schema_version = 4\n").unwrap();
    let held = write_lock::with_test_hook(
        |event| assert_ne!(event, write_lock::TestEvent::RootLocked),
        || load_config_for_schema_under_read_guard(&guard, &master, 4, now()).unwrap(),
    );
    assert_eq!(
        toml::to_string(&held.config).unwrap(),
        toml::to_string(&baseline.config).unwrap()
    );
    assert_eq!(held.files_loaded, baseline.files_loaded);
    let held_original = load_config_for_schema_under_read_guard(&guard, &alias, 4, now()).unwrap();
    assert_eq!(
        toml::to_string(&held_original.config).unwrap(),
        toml::to_string(&baseline.config).unwrap()
    );
}

#[test]
fn a_reader_waiting_for_migration_loads_the_completed_tree() {
    let dir = tempfile::tempdir().unwrap();
    let master = tree_for_schema(dir.path(), 3);
    let guard = write_lock::acquire_for_migration(&master).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let reader_master = master.clone();
    let reader = std::thread::spawn(move || {
        let mut started_tx = Some(started_tx);
        write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::Contended {
                    if let Some(tx) = started_tx.take() {
                        tx.send(()).unwrap();
                    }
                }
            },
            || {
                done_tx
                    .send(load_config_for_schema(&reader_master, 4, now()))
                    .unwrap()
            },
        );
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    fs::write(
        dir.path().join("slice.toml"),
        "schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    fs::write(&master, "schema_version = 4\nincludes = [\"slice.toml\"]\n").unwrap();
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(guard);
    let loaded = done_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.config.schema_version, 4);
    assert_eq!(loaded.files_loaded.len(), 2);
    reader.join().unwrap();
}

#[test]
fn readable_non_writable_tree_loads_without_metadata_creation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    fs::create_dir(&root).unwrap();
    let master = tree(&root);
    for path in [&master, &root.join("slice.toml")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o111)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
    let before = fs::metadata(&root).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "config::loader::locking_tests::read_only_load_child",
            "--nocapture",
        ])
        .env("WARDEN_READ_ONLY_LOAD_TEST_MASTER", &master);
    if unsafe { libc::geteuid() } == 0 {
        command.uid(65534).gid(65534);
    }
    let output = command.output().unwrap();
    let after = fs::metadata(&root).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join(".warden-config.lock").exists());
    assert!(!root.join(migration_journal::TXN_DIR_NAME).exists());
    assert_eq!(
        (before.ctime(), before.ctime_nsec()),
        (after.ctime(), after.ctime_nsec())
    );
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
}

#[test]
fn read_only_load_child() {
    let Some(master) = std::env::var_os("WARDEN_READ_ONLY_LOAD_TEST_MASTER") else {
        return;
    };
    let master = PathBuf::from(master);
    assert!(fs::File::create(master.parent().unwrap().join("cannot-create")).is_err());
    assert_eq!(load_config(&master, now()).unwrap().files_loaded.len(), 2);
    assert!(load_config_collect(&master, now()).0.is_ok());
    assert_eq!(probe_declared_schema_version(&master).unwrap(), 4);
}

#[test]
fn held_reader_and_probe_use_original_root_after_swap() {
    for probe in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let master = tree(&root);
        let old = dir.path().join("old");
        let replacement = root.clone();
        write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    fs::rename(&replacement, &old).unwrap();
                    fs::create_dir(&replacement).unwrap();
                    fs::write(replacement.join("config.toml"), "schema_version = 4\n").unwrap();
                    fs::create_dir(replacement.join(migration_journal::TXN_DIR_NAME)).unwrap();
                }
            },
            || {
                if probe {
                    assert_eq!(probe_declared_schema_version(&master).unwrap(), 4);
                } else {
                    let loaded = load_config(&master, now()).unwrap();
                    assert_eq!(loaded.config.schema_version, 4);
                    assert_eq!(
                        loaded.files_loaded,
                        vec![master.clone(), root.join("slice.toml")]
                    );
                }
            },
        );
        assert_eq!(fs::read_to_string(&master).unwrap(), "schema_version = 4\n");
        assert!(load_config(&master, now()).is_err());
    }
}

#[test]
fn included_leaf_swap_cannot_read_external_toml() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let master = tree(dir.path());
    let external = outside.path().join("external.toml");
    fs::write(&external, "[server]\ndefault_blocked_ttl_secs = 919\n").unwrap();
    let leaf = dir.path().join("slice.toml");
    let linked = external.clone();
    write_lock::with_test_hook(
        move |event| {
            if event == write_lock::TestEvent::RootLocked {
                fs::remove_file(&leaf).unwrap();
                std::os::unix::fs::symlink(&linked, &leaf).unwrap();
            }
        },
        || {
            let errors = load_config(&master, now()).unwrap_err();
            assert!(errors[0].context().reason.contains("escapes config root"));
        },
    );
    assert_eq!(
        fs::read_to_string(external).unwrap(),
        "[server]\ndefault_blocked_ttl_secs = 919\n"
    );
}

#[test]
fn glob_enumerates_the_pinned_directory_after_alias_swap() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("inside")).unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"alias/*.toml\"]\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("inside/original.toml"),
        "[server]\ndefault_blocked_ttl_secs = 123\n",
    )
    .unwrap();
    fs::write(
        outside.path().join("external.toml"),
        "[server]\ndefault_blocked_ttl_secs = 919\n",
    )
    .unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink("inside", &alias).unwrap();
    let external = outside.path().to_path_buf();
    let mut swapped = false;
    let loaded = write_lock::with_test_hook(
        move |event| {
            if event == write_lock::TestEvent::IncludeDirectoryPinned && !swapped {
                swapped = true;
                fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&external, &alias).unwrap();
            }
        },
        || load_config(&master, now()).unwrap(),
    );
    assert_eq!(loaded.config.server.default_blocked_ttl_secs, 123);
    assert_eq!(
        loaded.files_loaded,
        vec![master, dir.path().join("inside/original.toml")]
    );
    assert!(fs::read_to_string(outside.path().join("external.toml"))
        .unwrap()
        .contains("919"));
}

#[test]
fn secrets_and_custom_packs_use_the_held_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("packs")).unwrap();
    let master = root.join("config.toml");
    let config = "schema_version = 4\n[[custom_lists]]\nid = \"mine\"\n[[blocklists]]\nid = \"remote\"\ndisplay_name = \"Remote\"\nurl = \"https://example.test/list.txt\"\nauth_token_ref = \"original\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
    fs::write(&master, config).unwrap();
    fs::write(root.join("packs/mine.txt"), "||original.example.test^\n").unwrap();
    fs::write(root.join("secrets.toml"), "original = \"test-fixture\"\n").unwrap();
    fs::set_permissions(root.join("secrets.toml"), fs::Permissions::from_mode(0o600)).unwrap();
    let guard = write_lock::acquire_for_read(&master).unwrap();
    fs::rename(&root, dir.path().join("old")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("packs")).unwrap();
    fs::write(&master, config).unwrap();
    fs::write(root.join("packs/mine.txt"), "||replacement.example.test^\n").unwrap();
    fs::write(
        root.join("secrets.toml"),
        "replacement = \"test-fixture\"\n",
    )
    .unwrap();
    fs::set_permissions(root.join("secrets.toml"), fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = load_config_inner(
        guard.tree_io(),
        4,
        now(),
        None,
        &mut AuditWarnings::emitting(),
    )
    .unwrap();
    let id = super::super::schema::Id::new("mine").unwrap();
    assert_eq!(loaded.custom_lists[&id].deny[0], "original.example.test");
    assert_eq!(
        super::super::secrets::load_secrets_under_tree(guard.tree_io())
            .unwrap()
            .names(),
        vec!["original"]
    );
    drop(guard);
    assert!(load_config(&master, now()).is_err());
}

#[test]
fn custom_pack_parent_cannot_escape_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\n[[custom_lists]]\nid = \"mine\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    fs::write(
        outside.path().join("mine.txt"),
        "||external.example.test^\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("packs")).unwrap();
    let errors = load_config(&master, now()).unwrap_err();
    assert!(errors[0].context().reason.contains("escapes config root"));
    assert_eq!(
        fs::read_to_string(outside.path().join("mine.txt")).unwrap(),
        "||external.example.test^\n"
    );
}

#[test]
fn conflicting_overlay_aliases_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let master = tree(dir.path());
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink("slice.toml", &alias).unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay.stage(
        alias,
        "[server]\ndefault_blocked_ttl_secs = 123\n".into(),
        false,
    );
    overlay.stage(
        dir.path().join("slice.toml"),
        "[server]\ndefault_blocked_ttl_secs = 456\n".into(),
        false,
    );
    assert!(
        load_config_with_overlay(&master, now(), Some(&overlay)).unwrap_err()[0]
            .context()
            .reason
            .contains("conflicting overlay aliases")
    );
}

#[test]
fn descriptor_bound_omissions_model_the_final_globbed_tree() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"cluster.d/*.toml\"]\n",
    )
    .unwrap();
    let cluster_d = dir.path().join("cluster.d");
    fs::create_dir(&cluster_d).unwrap();
    let bundle = cluster_d.join("00-cluster-policy.toml");
    let next_bundle = "[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
    fs::write(&bundle, next_bundle).unwrap();
    let stray = cluster_d.join("old.toml");
    fs::write(&stray, "[profiles.stale]\ndisplay_name = \"Stale\"\n").unwrap();

    let guard = write_lock::acquire_for_write(&master).unwrap();
    let bundle_plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
        .unwrap();
    let stray_plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/old.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan(&bundle_plan, next_bundle.into())
        .unwrap();
    overlay.omit_plan(&stray_plan).unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .config
        .profiles
        .keys()
        .all(|profile| profile.as_str() != "stale"));
    assert!(!loaded.files_loaded.iter().any(|path| path == &stray));
    assert_eq!(
        fs::read_to_string(&stray).unwrap(),
        "[profiles.stale]\ndisplay_name = \"Stale\"\n"
    );

    let mut collision = LoaderOverlay::default();
    collision
        .stage_plan(&bundle_plan, next_bundle.into())
        .unwrap();
    assert!(collision.omit_plan(&bundle_plan).is_err());
}

#[test]
fn descriptor_bound_omission_makes_an_exact_include_missing() {
    let dir = tempfile::tempdir().unwrap();
    let master = tree(dir.path());
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_target(&dir.path().join("slice.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay.omit_plan(&plan).unwrap();

    let errors =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap_err();
    assert!(errors[0]
        .context()
        .reason
        .contains("include file not found"));
}

#[test]
fn descriptor_bound_omission_rejects_a_replaced_member() {
    let dir = tempfile::tempdir().unwrap();
    let master = tree(dir.path());
    let slice = dir.path().join("slice.toml");
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard.tree_io().plan_target(&slice).unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay.omit_plan(&plan).unwrap();

    let replacement = dir.path().join("replacement.toml");
    fs::write(
        &replacement,
        "[profiles.replacement]\ndisplay_name = \"Replacement\"\n",
    )
    .unwrap();
    fs::rename(&replacement, &slice).unwrap();

    let errors =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap_err();
    assert!(errors.iter().any(|error| error
        .context()
        .reason
        .contains("omitted overlay destination changed since its snapshot")));
    assert!(fs::read_to_string(&slice)
        .unwrap()
        .contains("profiles.replacement"));
}

#[test]
fn stage_plan_keeps_forcing_an_unreferenced_new_member() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
    )
    .unwrap();
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan(&plan, "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into())
        .unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .files_loaded
        .iter()
        .any(|path| { path.ends_with(Path::new("cluster.d/00-cluster-policy.toml")) }));
    assert!(!plan.display().exists());
}

#[test]
fn exact_include_accepts_a_descriptor_staged_new_member() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"cluster.d/00-cluster-policy.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
    )
    .unwrap();
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan_reachable_only(&plan, "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into())
        .unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .files_loaded
        .iter()
        .any(|path| { path.ends_with(Path::new("cluster.d/00-cluster-policy.toml")) }));
    assert!(!plan.display().exists());
}

#[test]
fn glob_include_accepts_a_reachable_descriptor_staged_new_member_in_a_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"cluster.d/*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
    )
    .unwrap();
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan_reachable_only(&plan, "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into())
        .unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .files_loaded
        .iter()
        .any(|path| { path.ends_with(Path::new("cluster.d/00-cluster-policy.toml")) }));
    assert!(!dir.path().join("cluster.d").exists());
}

#[test]
fn explicit_root_glob_accepts_a_reachable_descriptor_staged_new_member() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"./*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
    )
    .unwrap();
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("staged.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan_reachable_only(&plan, "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into())
        .unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .files_loaded
        .iter()
        .any(|path| path.ends_with("staged.toml")));
    assert!(!plan.display().exists());
}

#[test]
#[cfg(unix)]
fn directory_alias_to_root_uses_one_pinned_glob_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"alias/*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(".", dir.path().join("alias")).unwrap();
    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("staged.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay
        .stage_plan_reachable_only(&plan, "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into())
        .unwrap();

    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert!(loaded
        .files_loaded
        .iter()
        .any(|path| path.ends_with("staged.toml")));
    assert!(!plan.display().exists());
}

#[test]
fn unreachable_or_nonmatching_descriptor_staged_new_members_are_rejected() {
    for includes in ["", "includes = [\"other.d/*.toml\"]\n"] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(
            &master,
            format!(
                "schema_version = 4\n{includes}\n[server]\nlisten = \"127.0.0.1:15354\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
            ),
        )
        .unwrap();
        let guard = write_lock::acquire_for_write(&master).unwrap();
        let plan = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
            .unwrap();
        let mut overlay = LoaderOverlay::default();
        overlay
            .stage_plan_reachable_only(
                &plan,
                "[profiles.staged]\ndisplay_name = \"Staged\"\n".into(),
            )
            .unwrap();

        let errors = load_config_with_overlay_for_schema_under_guard(
            &guard,
            &master,
            3,
            now(),
            Some(&overlay),
        )
        .unwrap_err();
        assert!(errors.iter().any(|error| error
            .context()
            .reason
            .contains("staged config document was not reached")));
        assert!(!plan.display().exists());
        assert!(!dir.path().join("cluster.d").exists());
    }
}

#[test]
fn glob_omission_rejects_a_surviving_alias_to_the_removed_member() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(
        &master,
        "schema_version = 4\nincludes = [\"cluster.d/*.toml\", \"aliases.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let cluster_d = dir.path().join("cluster.d");
    let aliases_d = dir.path().join("aliases.d");
    fs::create_dir(&cluster_d).unwrap();
    fs::create_dir(&aliases_d).unwrap();
    let old = cluster_d.join("old.toml");
    fs::write(&old, "[profiles.old]\ndisplay_name = \"Old\"\n").unwrap();
    std::os::unix::fs::symlink("../cluster.d/old.toml", aliases_d.join("link.toml")).unwrap();

    let guard = write_lock::acquire_for_write(&master).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("cluster.d/old.toml"))
        .unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay.omit_plan(&plan).unwrap();
    let errors =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap_err();
    assert!(errors.iter().any(|error| error
        .context()
        .reason
        .contains("resolves to an omitted member")));
    assert!(old.exists());
    assert!(aliases_d.join("link.toml").exists());
}

#[test]
fn overlay_binds_the_admitted_parent_alias_without_reopening_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("real");
    fs::create_dir(&root).unwrap();
    tree(&root);
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink("real", &alias).unwrap();
    let master = alias.join("config.toml");
    let guard = write_lock::acquire_for_write(&master).unwrap();
    fs::remove_file(&alias).unwrap();
    fs::create_dir(&alias).unwrap();
    fs::write(alias.join("slice.toml"), "replacement sentinel").unwrap();
    let mut overlay = LoaderOverlay::default();
    overlay.stage(
        alias.join("slice.toml"),
        "[upstream]\nservers = [\"192.0.2.1:53\"]\n[server]\ndefault_blocked_ttl_secs = 123\n"
            .into(),
        false,
    );
    let loaded =
        load_config_with_overlay_for_schema_under_guard(&guard, &master, 4, now(), Some(&overlay))
            .unwrap();
    assert_eq!(loaded.config.server.default_blocked_ttl_secs, 123);
    assert_eq!(
        fs::read_to_string(alias.join("slice.toml")).unwrap(),
        "replacement sentinel"
    );
}
