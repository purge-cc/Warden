use super::*;
use crate::config::write_lock::acquire_for_write;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn spool(bytes: &[u8]) -> std::fs::File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn foreign_gid_we_may_set() -> Option<u32> {
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if euid == 0 {
        return Some(if egid == 0 { 1 } else { 0 });
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return None;
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let read = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if read < 0 {
        return None;
    }
    groups.truncate(read as usize);
    groups.into_iter().find(|gid| *gid != egid)
}

#[test]
fn descriptor_writer_preserves_metadata_and_classifies_all_fsync_faults() {
    for fault in [
        None,
        Some(AtomicWriteTestFailure::TempFsync),
        Some(AtomicWriteTestFailure::ParentOpen),
        Some(AtomicWriteTestFailure::ParentFsync),
    ] {
        for present in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("slice.toml");
            if present {
                std::fs::write(&path, "before").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
            let target = guard
                .tree_io()
                .plan_target(&path)
                .unwrap()
                .materialize()
                .unwrap();
            let owner = std::fs::metadata(dir.path()).unwrap();
            let result = hardened_atomic_write_at(
                &target,
                b"after",
                AtomicWriteAtOpts {
                    test_failure: fault,
                    ..Default::default()
                },
            );
            match fault {
                None => assert!(result.is_ok()),
                Some(AtomicWriteTestFailure::TempFsync) => {
                    let err = result.unwrap_err();
                    assert!(matches!(err, AtomicWriteError::Fsync { .. }));
                    assert!(!err.rename_landed());
                }
                Some(_) => {
                    assert!(result.unwrap_err().rename_landed());
                }
            }
            if fault == Some(AtomicWriteTestFailure::TempFsync) {
                if present {
                    assert_eq!(std::fs::read_to_string(&path).unwrap(), "before");
                } else {
                    assert!(!path.exists());
                }
            } else {
                assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
                let meta = std::fs::metadata(&path).unwrap();
                assert_eq!(meta.mode() & 0o7777, if present { 0o600 } else { 0o640 });
                assert_eq!((meta.uid(), meta.gid()), (owner.uid(), owner.gid()));
            }
            assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(crate::config::write_lock::WRITE_STAGE_PREFIX)));
        }
    }
}

#[test]
fn descriptor_writer_sets_requested_owner_for_an_absent_target() {
    let Some(gid) = foreign_gid_we_may_set() else {
        eprintln!("SKIPPED explicit-owner test: no second group is available");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slice.toml");
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&path)
        .unwrap()
        .materialize()
        .unwrap();
    let owner = (unsafe { libc::geteuid() }, gid);

    hardened_atomic_write_at(
        &target,
        b"after",
        AtomicWriteAtOpts {
            owner: Some(owner),
            ..Default::default()
        },
    )
    .unwrap();

    let metadata = std::fs::metadata(path).unwrap();
    assert_eq!((metadata.uid(), metadata.gid()), owner);
}

#[test]
fn descriptor_validator_reads_staged_fd_and_rejection_cleans_temp() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slice.toml");
    std::fs::write(&path, "before").unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&path)
        .unwrap()
        .materialize()
        .unwrap();
    let validator = |mut file: &File, _display: &Path| {
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "after");
        Err("injected rejection".into())
    };
    let err = hardened_atomic_write_at(
        &target,
        b"after",
        AtomicWriteAtOpts {
            validator: Some(&validator),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, AtomicWriteError::Validation { .. }));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "before");
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(crate::config::write_lock::WRITE_STAGE_PREFIX)));
}

#[test]
fn replacing_the_visible_source_name_during_validation_cannot_change_promoted_bytes() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slice.toml");
    std::fs::write(&path, "before").unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&path)
        .unwrap()
        .materialize()
        .unwrap();
    let moved = dir.path().join("moved-staging");
    let planted = std::cell::RefCell::new(None);
    let validator = |mut file: &File, tmp: &Path| {
        let stage = tmp.parent().unwrap();
        let meta = std::fs::metadata(stage).unwrap();
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        assert_eq!(meta.mode() & 0o7777, 0o700);
        std::fs::rename(stage, &moved).unwrap();
        std::fs::create_dir(stage).unwrap();
        std::fs::write(tmp, "unvalidated replacement").unwrap();
        *planted.borrow_mut() = Some(tmp.to_path_buf());
        let mut bytes = String::new();
        file.read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "validated after");
        Ok(())
    };
    hardened_atomic_write_at(
        &target,
        b"validated after",
        AtomicWriteAtOpts {
            validator: Some(&validator),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "validated after");
    assert_eq!(
        std::fs::read_to_string(planted.borrow().as_ref().unwrap()).unwrap(),
        "unvalidated replacement"
    );
    assert_eq!(std::fs::read_dir(moved).unwrap().count(), 0);
}

#[test]
fn replacement_during_validation_is_refused_before_target_rename() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slice.toml");
    std::fs::write(&path, "before").unwrap();
    let replacement = dir.path().join("replacement");
    std::fs::write(&replacement, "unexpected regular replacement").unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&path)
        .unwrap()
        .materialize()
        .unwrap();
    let validator = |_: &File, _: &Path| {
        std::fs::rename(&replacement, &path).unwrap();
        Ok(())
    };
    let error = hardened_atomic_write_at(
        &target,
        b"after",
        AtomicWriteAtOpts {
            validator: Some(&validator),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(error, AtomicWriteError::Stat { .. }));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "unexpected regular replacement"
    );
}

#[test]
fn create_only_writer_streams_exact_bytes_with_parent_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("generated");
    std::fs::create_dir(&parent).unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("generated/body.bin"))
        .unwrap()
        .materialize()
        .unwrap();
    let expected = (0..(192 * 1024 + 37))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut source = spool(&expected);

    hardened_atomic_create_only_at(
        &target,
        &mut source,
        expected.len() as u64,
        AtomicCreateOnlyAtOpts::default(),
    )
    .unwrap();

    let path = parent.join("body.bin");
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    let target_meta = std::fs::metadata(&path).unwrap();
    let parent_meta = std::fs::metadata(&parent).unwrap();
    assert_eq!(target_meta.mode() & 0o7777, 0o640);
    assert_eq!(
        (target_meta.uid(), target_meta.gid()),
        (parent_meta.uid(), parent_meta.gid())
    );
}

#[test]
fn create_only_writer_honors_explicit_mode_and_current_owner() {
    let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
    let Some(parent_gid) = foreign_gid_we_may_set() else {
        eprintln!("SKIPPED explicit-owner test: no second group is available");
        return;
    };
    for mode in [0o600, 0o644] {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
        std::os::unix::fs::lchown(dir.path(), None, Some(parent_gid)).unwrap();
        assert_ne!(std::fs::metadata(dir.path()).unwrap().gid(), owner.1);
        let path = dir.path().join(format!("mode-{mode:o}.bin"));
        let target = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new(path.file_name().unwrap()))
            .unwrap()
            .materialize()
            .unwrap();
        let mut source = spool(b"explicit metadata");

        hardened_atomic_create_only_at(
            &target,
            &mut source,
            17,
            AtomicCreateOnlyAtOpts {
                mode: Some(mode),
                owner: Some(owner),
                ..Default::default()
            },
        )
        .unwrap();

        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, mode);
        assert_eq!((metadata.uid(), metadata.gid()), owner);
    }
}

#[test]
fn create_only_writer_enforces_the_spool_size_and_eof_contract() {
    for (bytes, expected_size) in [(b"short".as_slice(), 6), (b"long".as_slice(), 3)] {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
        let target = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("generated.bin"))
            .unwrap()
            .materialize()
            .unwrap();
        let mut source = spool(bytes);

        let error = hardened_atomic_create_only_at(
            &target,
            &mut source,
            expected_size,
            AtomicCreateOnlyAtOpts::default(),
        )
        .unwrap_err();
        assert!(matches!(error, AtomicWriteError::SourceSize { .. }));
        assert!(!dir.path().join("generated.bin").exists());
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(crate::config::write_lock::WRITE_STAGE_PREFIX)));
    }
}

#[test]
fn create_only_writer_requires_an_absent_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sentinel.bin");
    std::fs::write(&path, "sentinel").unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&path)
        .unwrap()
        .materialize()
        .unwrap();
    let mut source = spool(b"replacement");

    let error =
        hardened_atomic_create_only_at(&target, &mut source, 11, AtomicCreateOnlyAtOpts::default())
            .unwrap_err();
    assert!(matches!(error, AtomicWriteError::TargetMustBeAbsent { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), b"sentinel");
}

#[test]
fn create_only_writer_reports_an_observed_racing_destination_as_target_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("racing.bin");
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("racing.bin"))
        .unwrap()
        .materialize()
        .unwrap();
    std::fs::write(&path, "other writer").unwrap();
    let mut source = spool(b"ours");

    let error =
        hardened_atomic_create_only_at(&target, &mut source, 4, AtomicCreateOnlyAtOpts::default())
            .unwrap_err();
    assert!(matches!(error, AtomicWriteError::TargetExists { .. }));
    assert_eq!(std::fs::read_to_string(path).unwrap(), "other writer");
}

#[test]
fn create_only_writer_handles_a_setgid_parent_without_widening_staging() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("setgid");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2700)).unwrap();
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("setgid/body.bin"))
        .unwrap()
        .materialize()
        .unwrap();
    let mut source = spool(b"setgid bytes");

    hardened_atomic_create_only_at(&target, &mut source, 12, AtomicCreateOnlyAtOpts::default())
        .unwrap();

    let meta = std::fs::metadata(parent.join("body.bin")).unwrap();
    let parent_meta = std::fs::metadata(&parent).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o640);
    assert_eq!(
        (meta.uid(), meta.gid()),
        (parent_meta.uid(), parent_meta.gid())
    );
    assert!(std::fs::read_dir(&parent).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(crate::config::write_lock::WRITE_STAGE_PREFIX)));
}

#[test]
fn staging_directory_clears_a_setgid_parent_bit_and_stays_private() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("setgid");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2700)).unwrap();
    let parent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(&parent)
        .unwrap();

    let staging = super::staging::StagingDirectory::create(&parent_file).unwrap();
    let meta = staging.file.metadata().unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o700);
    assert_eq!(meta.mode() & libc::S_ISGID, 0);
}

#[test]
fn staging_drop_never_unlinks_a_payload_it_did_not_create() {
    let dir = tempfile::tempdir().unwrap();
    let parent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir.path())
        .unwrap();
    let staging = super::staging::StagingDirectory::create(&parent_file).unwrap();
    let payload = dir
        .path()
        .join(&staging.name)
        .join(super::staging::payload());
    std::fs::write(&payload, "foreign payload").unwrap();
    drop(staging);
    assert_eq!(std::fs::read_to_string(payload).unwrap(), "foreign payload");
}

#[test]
fn create_only_owner_decision_changes_only_the_needed_field() {
    assert_eq!(super::needed_owner_ids(10, 20, 10, 20), None);
    assert_eq!(
        super::needed_owner_ids(10, 20, 10, 30),
        Some((libc::uid_t::MAX, 30))
    );
    assert_eq!(
        super::needed_owner_ids(10, 20, 11, 20),
        Some((11, libc::gid_t::MAX))
    );
    assert_eq!(super::needed_owner_ids(10, 20, 11, 30), Some((11, 30)));
}

#[test]
fn create_only_writer_keeps_a_promoted_receipt_after_parent_fsync_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.bin");
    let guard = acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("new.bin"))
        .unwrap()
        .materialize()
        .unwrap();
    let mut source = spool(b"new bytes");

    let error = hardened_atomic_create_only_at(
        &target,
        &mut source,
        9,
        AtomicCreateOnlyAtOpts {
            test_failure: Some(AtomicWriteTestFailure::ParentFsync),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(error.rename_landed());
    assert_eq!(std::fs::read(&path).unwrap(), b"new bytes");
    target.rollback_target().unwrap().unlink().unwrap();
    assert!(!path.exists());
}

#[test]
fn no_replace_unsupported_errors_are_classified_without_a_replace_fallback() {
    let target = Path::new("/tmp/target.bin");
    let error = super::classify_noreplace_error(
        target,
        std::path::PathBuf::from("/tmp/staged.bin"),
        std::io::Error::new(std::io::ErrorKind::Unsupported, "injected"),
    );
    assert!(matches!(
        error,
        AtomicWriteError::NoReplaceUnsupported { .. }
    ));
}
