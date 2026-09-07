use super::*;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;

#[test]
fn reserved_names_are_rejected_for_masters_and_members_after_alias_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    for (index, name) in [
        ".warden-config.lock",
        ".warden-migration",
        ".warden-migration.cleanup-",
        ".warden-migration.cleanup-deadbeef",
        ".warden-write-",
        ".warden-write-stale",
    ]
    .iter()
    .enumerate()
    {
        let reserved = dir.path().join(name);
        assert!(ConfigTreeIdentity::resolve(&reserved).is_err());
        assert!(guard.resolve_member(&reserved).is_err());
        assert!(ConfigTreeIdentity::resolve(&reserved.join("config.toml")).is_err());
        assert!(guard.resolve_member(&reserved.join("member.toml")).is_err());
        let alias = dir.path().join(format!("alias-{index}"));
        symlink(&reserved, &alias).unwrap();
        assert!(ConfigTreeIdentity::resolve(&alias).is_err());
        assert!(guard.resolve_member(&alias).is_err());
    }
    for name in [
        ".warden-migration.old",
        ".warden-migration-cleanup",
        "migration.toml",
    ] {
        assert!(ConfigTreeIdentity::resolve(&dir.path().join(name)).is_ok());
        assert!(guard.resolve_member(&dir.path().join(name)).is_ok());
    }
}

#[test]
fn an_unsafe_lock_is_rejected_before_data_open_and_names_offline_remediation() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    symlink("/dev/null", dir.path().join(WRITE_LOCK_FILE)).unwrap();
    let err = with_test_hook(
        |event| {
            assert!(
                event != TestEvent::BeforeDataOpen,
                "unsafe inode reached data open"
            );
        },
        || acquire_for_write(&master).unwrap_err(),
    );
    let message = format!("{err:#}");
    assert!(message.contains("Stop all warden daemons and commands"));
    assert!(message.contains(WRITE_LOCK_FILE));
    assert!(message.contains("Do not remove or replace a lock"));
}

#[test]
fn a_device_inspection_descriptor_cannot_be_reopened_for_data_access() {
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open("/dev/null")
        .unwrap();
    with_test_hook(
        |event| assert!(event != TestEvent::BeforeDataOpen),
        || {
            assert!(reopen_inspected(&device, libc::O_RDWR).is_err());
        },
    );
}

#[test]
fn a_competing_directory_creator_is_opened_and_locked_normally() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("new-root");
    let master = root.join("config.toml");
    let winner = root.clone();
    let guard = with_test_hook(
        move |event| {
            if event == TestEvent::BeforeMkdir {
                std::fs::create_dir(&winner).unwrap();
            }
        },
        || acquire_for_write(&master).unwrap(),
    );
    assert_eq!(guard.canonical_master(), master);
    assert!(acquire_write_with_deadline(&master, Duration::ZERO).is_err());
}

#[test]
fn symlink_then_parent_matches_kernel_path_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let real = dir.path().join("elsewhere");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir_all(real.join("nested")).unwrap();
    std::fs::write(root.join("config.toml"), "wrong tree").unwrap();
    std::fs::write(real.join("config.toml"), "intended tree").unwrap();
    symlink("../elsewhere/nested", root.join("link")).unwrap();
    let requested = root.join("link/../config.toml");
    let expected = requested.canonicalize().unwrap();
    assert_eq!(
        ConfigTreeIdentity::resolve(&requested)
            .unwrap()
            .canonical_master,
        expected
    );
    assert_eq!(
        std::fs::read_to_string(&requested).unwrap(),
        "intended tree"
    );
    assert_eq!(
        ConfigTreeIdentity::resolve(&root.join("link/../missing/deep/config.toml"))
            .unwrap()
            .canonical_master,
        real.join("missing/deep/config.toml")
    );
    symlink("../elsewhere", root.join("existing-link")).unwrap();
    assert_eq!(
        resolve_path(&root.join("missing/../existing-link/config.toml")).unwrap(),
        real.join("config.toml")
    );
    assert!(acquire_for_read(&root.join("missing/../existing-link/config.toml")).is_err());
}

fn aliases(base: &Path, present: bool) -> Vec<PathBuf> {
    let root = base.join("real");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    let master = root.join("config.toml");
    if present {
        std::fs::write(&master, "").unwrap();
    }
    symlink("real", base.join("parent-alias")).unwrap();
    symlink("real/config.toml", base.join("master-alias")).unwrap();
    symlink(&master, base.join("absolute-master-alias")).unwrap();
    let cwd = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(master.strip_prefix("/").unwrap());
    vec![
        master,
        relative,
        root.join("nested/.././config.toml"),
        base.join("parent-alias/config.toml"),
        base.join("master-alias"),
        base.join("absolute-master-alias"),
    ]
}

#[test]
fn existing_and_missing_master_aliases_converge_and_contend() {
    for present in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let paths = aliases(dir.path(), present);
        let held = acquire_for_migration(&paths[0]).unwrap();
        let lock_inode = inode(&held.0._side_file.metadata().unwrap());
        for path in &paths {
            assert_eq!(ConfigTreeIdentity::resolve(path).unwrap(), *held.identity());
            assert!(
                acquire_write_with_deadline(path, Duration::ZERO).is_err(),
                "{}",
                path.display()
            );
            assert!(
                acquire_read_with_deadline(path, Duration::ZERO).is_err(),
                "{}",
                path.display()
            );
        }
        let probe = OpenOptions::new()
            .read(true)
            .open(&held.identity().lock_path)
            .unwrap();
        assert!(flock_until(&probe, true, Duration::ZERO).is_err());
        drop(held);
        flock_until(&probe, true, Duration::ZERO).unwrap();
        drop(probe);
        for path in paths {
            let guard = acquire_for_write(&path).unwrap();
            assert_eq!(inode(&guard._side_file.metadata().unwrap()), lock_inode);
        }
    }
}

#[test]
fn missing_suffix_and_dangling_target_follow_existing_parent_aliases() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    symlink("real", dir.path().join("alias")).unwrap();
    symlink("alias/new/deep/config.toml", dir.path().join("master-link")).unwrap();
    let expected =
        ConfigTreeIdentity::resolve(&dir.path().join("real/new/deep/config.toml")).unwrap();
    assert_eq!(
        ConfigTreeIdentity::resolve(&dir.path().join("master-link")).unwrap(),
        expected
    );
    let guard = acquire_for_write(&dir.path().join("master-link")).unwrap();
    assert_eq!(guard.canonical_master(), expected.canonical_master);
    for rel in ["real/new", "real/new/deep"] {
        assert_eq!(
            std::fs::metadata(dir.path().join(rel)).unwrap().mode() & 0o7777,
            0o750
        );
    }
    assert!(std::fs::symlink_metadata(dir.path().join("master-link"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn editor_recapture_admits_one_regular_rename_then_keeps_swap_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(&master, "before").unwrap();
    let guard = acquire_for_write(&master).unwrap();

    let replacement = dir.path().join("editor-save");
    fs::write(&replacement, "after").unwrap();
    fs::rename(&replacement, &master).unwrap();
    guard.recapture_canonical_master_after_editor().unwrap();
    let admitted = guard.tree_io().plan_master_target().unwrap();
    assert!(matches!(
        admitted.read_original_capped(64).unwrap(),
        crate::config::tree_io::CappedRead::Contents(bytes) if bytes == b"after"
    ));

    fs::write(&replacement, "second replacement").unwrap();
    fs::rename(&replacement, &master).unwrap();
    assert!(guard.tree_io().plan_master_target().is_err());
}

#[test]
fn editor_recapture_normalizes_owner_to_the_admitted_side_lock() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    fs::write(&master, "before").unwrap();
    let original = File::open(&master).unwrap();
    assert_eq!(
        unsafe { libc::fchown(original.as_raw_fd(), 65534, 65534) },
        0
    );
    drop(original);
    let guard = acquire_for_write(&master).unwrap();

    for owner in [(0, 65534), (65534, 0)] {
        let replacement = dir.path().join("editor-save");
        fs::write(&replacement, "after").unwrap();
        let file = File::open(&replacement).unwrap();
        assert_eq!(
            unsafe { libc::fchown(file.as_raw_fd(), owner.0, owner.1) },
            0
        );
        drop(file);
        fs::rename(&replacement, &master).unwrap();
        guard.recapture_canonical_master_after_editor().unwrap();
        let meta = fs::metadata(&master).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (65534, 65534));
    }

    let file = File::open(&master).unwrap();
    assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 0) }, 0);
    drop(file);
    guard.recapture_canonical_master_after_editor().unwrap();
    let meta = fs::metadata(&master).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (65534, 65534));
    drop(guard);
    drop(acquire_for_write(&master).unwrap());
}

#[test]
fn editor_recapture_rejects_unsafe_canonical_leaves() {
    for kind in [
        "absent",
        "symlink",
        "hardlink",
        "directory",
        "fifo",
        "socket",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(&master, "original").unwrap();
        let guard = acquire_for_write(&master).unwrap();
        fs::remove_file(&master).unwrap();
        let mut socket = None;
        match kind {
            "absent" => {}
            "symlink" => {
                fs::write(dir.path().join("target"), "target").unwrap();
                symlink("target", &master).unwrap();
            }
            "hardlink" => {
                let target = dir.path().join("target");
                fs::write(&target, "target").unwrap();
                fs::hard_link(target, &master).unwrap();
            }
            "directory" => fs::create_dir(&master).unwrap(),
            "fifo" => {
                let name = CString::new(master.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "socket" => socket = Some(UnixListener::bind(&master).unwrap()),
            _ => unreachable!(),
        }
        with_test_hook(
            |event| assert_ne!(event, TestEvent::BeforeDataOpen),
            || {
                assert!(
                    guard.recapture_canonical_master_after_editor().is_err(),
                    "{kind} canonical leaf was admitted"
                );
            },
        );
        drop(socket);
    }
}

#[test]
fn shared_readers_block_writes_and_writers_block_reads_until_drop() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let first = acquire_for_read(&master).unwrap();
    let second = acquire_for_read(&master).unwrap();
    assert!(!first.identity().lock_path.exists());
    assert!(acquire_write_with_deadline(&master, Duration::ZERO).is_err());
    drop(first);
    assert!(acquire_write_with_deadline(&master, Duration::ZERO).is_err());
    drop(second);
    let writer = acquire_for_write(&master).unwrap();
    assert!(acquire_read_with_deadline(&master, Duration::ZERO).is_err());
    drop(writer);
    drop(acquire_for_read(&master).unwrap());
}

#[test]
fn contended_acquisition_waits_for_its_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let _held = acquire_for_write(&master).unwrap();
    let wait = Duration::from_millis(25);
    let start = Instant::now();
    let err = acquire_read_with_deadline(&master, wait).unwrap_err();
    assert!(start.elapsed() >= wait);
    assert!(format!("{err:#}").contains("another warden process"));
}

#[test]
fn fence_is_checked_after_locking_and_both_normal_guards_refuse() {
    for malformed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let held = acquire_for_migration(&master).unwrap();
        migration_journal::create_fence(&held).unwrap();
        if malformed {
            let journal = held
                .identity()
                .txn_dir
                .join(migration_journal::JOURNAL_NAME);
            std::fs::write(&journal, "{").unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let waiting = acquire_read_with_deadline(&master, Duration::ZERO).unwrap_err();
        assert!(!format!("{waiting:#}").contains("unfinished v3-to-v4"));
        assert!(format!("{waiting:#}").contains("holds the config tree lock"));
        drop(held);
        for err in [
            acquire_for_read(&master).unwrap_err(),
            acquire_for_write(&master).unwrap_err(),
        ] {
            let message = format!("{err:#}");
            assert!(message.contains("unfinished v3-to-v4 migration"));
            assert!(message.contains(".warden-migration/journal.json"));
            assert!(message.contains("warden migrate v3-to-v4 --from-config"));
        }
        drop(acquire_for_migration(&master).unwrap());
    }
}

#[test]
fn unsafe_side_lock_types_links_and_modes_are_refused_without_repair() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let path = ConfigTreeIdentity::resolve(&master).unwrap().lock_path;
    let target = dir.path().join("target");
    std::fs::write(&target, "untouched").unwrap();
    symlink(&target, &path).unwrap();
    assert!(acquire_for_write(&master).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&target, &path).unwrap();
    assert!(acquire_for_write(&master).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(acquire_for_write(&master).is_err());
    std::fs::remove_dir(&path).unwrap();
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(acquire_for_write(&master).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "").unwrap();
    for mode in [
        0o000, 0o400, 0o200, 0o700, 0o640, 0o666, 0o1600, 0o2600, 0o4600,
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(acquire_for_write(&master).is_err(), "mode {mode:o}");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, mode);
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let guard = acquire_for_write(&master).unwrap();
    for file in [&guard._side_file, &guard._root] {
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}

#[test]
fn member_resolution_rejects_escapes_hard_links_and_non_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    std::fs::create_dir(&root).unwrap();
    let guard = acquire_for_write(&root.join("config.toml")).unwrap();
    let member = root.join("slice.toml");
    std::fs::write(&member, "").unwrap();
    symlink("slice.toml", root.join("alias")).unwrap();
    assert_eq!(guard.resolve_member(&root.join("alias")).unwrap(), member);
    assert!(guard
        .resolve_member(&root.join("missing/deep/slice.toml"))
        .is_ok());
    assert!(guard.resolve_member(&root).is_err());
    assert!(guard.resolve_member(&guard.identity().lock_path).is_err());
    assert!(guard
        .resolve_member(&guard.identity().txn_dir.join("journal.json"))
        .is_err());
    assert!(guard
        .resolve_member(&dir.path().join("outside.toml"))
        .is_err());
    symlink(dir.path(), root.join("escape")).unwrap();
    assert!(guard
        .resolve_member(&root.join("escape/missing.toml"))
        .is_err());
    std::fs::hard_link(&member, root.join("hard-link")).unwrap();
    assert!(guard.resolve_member(&member).is_err());
}

#[test]
fn invalid_master_spellings_cycles_and_substituted_roots_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for path in [
        Path::new(""),
        Path::new("/"),
        Path::new("/../../config.toml"),
        dir.path(),
    ] {
        assert!(
            ConfigTreeIdentity::resolve(path).is_err(),
            "{}",
            path.display()
        );
    }
    assert!(ConfigTreeIdentity::resolve(&dir.path().join("missing/.")).is_err());
    symlink("b", dir.path().join("a")).unwrap();
    symlink("a", dir.path().join("b")).unwrap();
    assert!(ConfigTreeIdentity::resolve(&dir.path().join("a")).is_err());
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let identity = ConfigTreeIdentity::resolve(&root.join("config.toml")).unwrap();
    std::fs::rename(&root, dir.path().join("old-root")).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(identity.open_root(false).is_err());
    std::fs::remove_dir(&root).unwrap();
    symlink("old-root", &root).unwrap();
    assert!(identity.open_root(false).is_err());
}

#[test]
fn root_created_lock_inherits_master_owner_and_rejects_existing_wrong_owner() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    let file = File::create(&master).unwrap();
    assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 65534, 65534) }, 0);
    let guard = acquire_for_write(&master).unwrap();
    let meta = guard._side_file.metadata().unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (65534, 65534, 0o600)
    );
    assert_eq!(
        unsafe { libc::fchown(guard._side_file.as_raw_fd(), 0, 0) },
        0
    );
    drop(guard);
    assert!(acquire_for_write(&master).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_thread_runtime_can_acquire() {
    let dir = tempfile::tempdir().unwrap();
    drop(acquire_for_write(&dir.path().join("config.toml")).unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn current_thread_runtime_can_acquire() {
    let dir = tempfile::tempdir().unwrap();
    drop(acquire_for_read(&dir.path().join("config.toml")).unwrap());
}

#[test]
fn reserved_alias_spellings_cannot_bypass_the_namespace_policy() {
    for name in [
        ".warden-config.lock",
        ".warden-migration",
        ".warden-migration.cleanup-obsolete",
        ".warden-write-obsolete",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, "schema_version = 3\n").unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        let reserved = dir.path().join(name);
        if name == ".warden-config.lock" {
            drop(guard);
            std::fs::remove_file(&reserved).unwrap();
            symlink("config.toml", &reserved).unwrap();
            assert!(ConfigTreeIdentity::resolve(&reserved).is_err());
        } else {
            symlink("config.toml", &reserved).unwrap();
            assert!(ConfigTreeIdentity::resolve(&reserved).is_err());
            assert!(guard.tree_io().plan_target(&reserved).is_err());
        }
    }
}

#[test]
fn master_capture_rejects_regular_replacement_and_unexpected_creation() {
    for present in [false, true] {
        for write in [false, true] {
            // Writers verify again after acquiring the compatibility side lock.
            for capture_number in 1..=if write { 2 } else { 1 } {
                let dir = tempfile::tempdir().unwrap();
                let master = dir.path().join("config.toml");
                if present {
                    std::fs::write(&master, "original").unwrap();
                }
                let leaf = master.clone();
                let replacement = dir.path().join("replacement");
                std::fs::write(&replacement, "replacement sentinel").unwrap();
                let mut captures = 0;
                let error = with_test_hook(
                    move |event| {
                        if event == TestEvent::BeforeMasterCapture {
                            captures += 1;
                            if captures == capture_number {
                                std::fs::rename(&replacement, &leaf).unwrap();
                            }
                        }
                    },
                    || {
                        if write {
                            acquire_for_write(&master).unwrap_err()
                        } else {
                            acquire_for_read(&master).unwrap_err()
                        }
                    },
                );
                assert!(
                    format!("{error:#}").contains("between identity verification and capture"),
                    "{error:#}"
                );
                assert_eq!(
                    std::fs::read_to_string(&master).unwrap(),
                    "replacement sentinel"
                );
            }
        }
    }
}
