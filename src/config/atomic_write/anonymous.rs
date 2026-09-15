//! Anonymous `O_TMPFILE` staging for durable multi-file transactions.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

use rand_core::RngCore;

#[cfg(test)]
use super::AtomicWriteTestFailure;
use super::{
    check_create_only_target_absent, classify_noreplace_error, copy_spool_exact, needed_owner_ids,
    AnonymousAfterLinkCallback, AnonymousStageOpts, AnonymousStagedPayload,
    AnonymousStagingCallback, AtomicCreateOnlyAtOpts, AtomicWriteAtOpts, AtomicWriteBoundary,
    AtomicWriteBoundaryCallback, AtomicWriteError, DEFAULT_TARGET_MODE,
};
use crate::config::tree_io::{
    inspect_at, rename_at, rename_noreplace_at, same_inode, PinnedTarget,
};
use crate::config::write_lock::WRITE_STAGE_PREFIX;

pub(super) fn write(
    target: &PinnedTarget<'_>,
    content: &[u8],
    opts: &AtomicWriteAtOpts<'_>,
    callback: AnonymousStagingCallback<'_>,
    after_link: Option<AnonymousAfterLinkCallback<'_>>,
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
    mode: u32,
) -> Result<(), AtomicWriteError> {
    let path = target.display();
    let stage_path = allocate_stage_path(target, path)?;
    let mut file = open_anonymous(
        &target.parent,
        path,
        #[cfg(test)]
        opts.test_failure,
    )?;

    file.write_all(content)
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.clone(),
            source,
        })?;
    let requested_owner = target
        .metadata
        .as_ref()
        .map(|meta| (meta.uid(), meta.gid()))
        .or(opts.owner);
    set_metadata(
        &file,
        requested_owner,
        mode,
        &stage_path,
        target.metadata.is_some(),
    )?;
    sync_and_validate(
        &mut file,
        opts.validator,
        path,
        &stage_path,
        #[cfg(test)]
        opts.test_failure,
        #[cfg(not(test))]
        (),
        boundaries,
    )?;
    journal_and_publish_replace(
        target,
        &file,
        callback,
        after_link,
        &stage_path,
        #[cfg(test)]
        opts.test_failure,
        #[cfg(not(test))]
        (),
        boundaries,
    )
}

/// Persist a named recovery payload without changing the target name. The
/// post-link receipt is emitted only after the parent fsync: a receipt
/// claiming this name exists therefore remains safe after SIGKILL.
pub(super) fn stage_only(
    target: &PinnedTarget<'_>,
    content: &[u8],
    opts: AnonymousStageOpts<'_>,
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
) -> Result<AnonymousStagedPayload, AtomicWriteError> {
    let path = target.display();
    let stage_path = allocate_stage_path(target, path)?;
    let mut payload = open_anonymous(
        &target.parent,
        path,
        #[cfg(test)]
        test_failure,
    )?;
    payload
        .write_all(content)
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.clone(),
            source,
        })?;
    set_metadata(&payload, Some(opts.owner), opts.mode, &stage_path, false)?;
    sync_and_validate_stage_only(&mut payload, opts.validator, path, &stage_path, boundaries)?;

    let basename = stage_basename(&stage_path);
    (opts.before_link)(&target.parent, &payload, basename).map_err(|reason| {
        AtomicWriteError::JournalCallback {
            target: path.to_path_buf(),
            reason,
        }
    })?;
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeStagingLink,
        path,
        false,
    )?;
    link_anonymous(
        &payload,
        &target.parent,
        basename,
        path,
        #[cfg(test)]
        test_failure,
    )?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterStagingLink,
        path,
        false,
    )?;
    verify_link(target, &payload, basename, &stage_path)?;
    verify_payload_bytes(&payload, content, &stage_path)?;
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeStagingLinkParentFsync,
        path,
        false,
    )?;
    target
        .parent
        .sync_all()
        .map_err(|source| AtomicWriteError::Fsync {
            path: path.parent().expect("target parent").to_path_buf(),
            source,
        })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterStagingLinkParentFsync,
        path,
        false,
    )?;
    if let Some(after_link) = opts.after_link {
        after_link(&target.parent, &payload, basename).map_err(|reason| {
            AtomicWriteError::JournalReceiptCallback {
                target: path.to_path_buf(),
                reason,
            }
        })?;
    }
    Ok(AnonymousStagedPayload {
        basename: basename.to_os_string(),
        payload,
    })
}

pub(super) fn create_only(
    target: &PinnedTarget<'_>,
    source: &mut File,
    expected_size: u64,
    opts: &AtomicCreateOnlyAtOpts<'_>,
    callback: AnonymousStagingCallback<'_>,
    after_link: Option<AnonymousAfterLinkCallback<'_>>,
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
) -> Result<(), AtomicWriteError> {
    let path = target.display();
    let stage_path = allocate_stage_path(target, path)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|source| AtomicWriteError::ReadSource {
            target: path.to_path_buf(),
            source,
        })?;
    let mut file = open_anonymous(
        &target.parent,
        path,
        #[cfg(test)]
        opts.test_failure,
    )?;
    copy_spool_exact(source, &mut file, expected_size, path, &stage_path)?;
    let owner = match opts.owner {
        Some(owner) => owner,
        None => {
            let parent = target
                .parent
                .metadata()
                .map_err(|source| AtomicWriteError::Metadata {
                    tmp: stage_path.clone(),
                    source,
                })?;
            (parent.uid(), parent.gid())
        }
    };
    set_metadata(
        &file,
        Some(owner),
        opts.mode.unwrap_or(DEFAULT_TARGET_MODE),
        &stage_path,
        false,
    )?;
    sync_and_validate(
        &mut file,
        opts.validator,
        path,
        &stage_path,
        #[cfg(test)]
        opts.test_failure,
        #[cfg(not(test))]
        (),
        boundaries,
    )?;
    journal_and_publish_create(
        target,
        &file,
        callback,
        after_link,
        &stage_path,
        #[cfg(test)]
        opts.test_failure,
        #[cfg(not(test))]
        (),
        boundaries,
    )
}

fn allocate_stage_path(
    target: &PinnedTarget<'_>,
    target_path: &Path,
) -> Result<PathBuf, AtomicWriteError> {
    for _ in 0..32 {
        let basename = random_stage_basename().map_err(|source| AtomicWriteError::WriteTemp {
            tmp: target_path.to_path_buf(),
            source,
        })?;
        match inspect_at(&target.parent, &basename).map_err(|source| AtomicWriteError::Stat {
            path: target_path.to_path_buf(),
            source,
        })? {
            None => return Ok(target_path.parent().expect("target parent").join(basename)),
            Some(_) => continue,
        }
    }
    Err(AtomicWriteError::WriteTemp {
        tmp: target_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate an unused anonymous staging basename",
        ),
    })
}

fn random_stage_basename() -> io::Result<OsString> {
    let mut random = [0_u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(OsString::from(format!(
        "{WRITE_STAGE_PREFIX}{:032x}",
        u128::from_ne_bytes(random)
    )))
}

fn open_anonymous(
    parent: &File,
    target: &Path,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
) -> Result<File, AtomicWriteError> {
    #[cfg(target_os = "linux")]
    {
        #[cfg(test)]
        match test_failure {
            Some(AtomicWriteTestFailure::AnonymousOpenUnsupported) => {
                return Err(anonymous_unsupported(
                    target,
                    "O_TMPFILE unavailable: injected unsupported error",
                ));
            }
            Some(AtomicWriteTestFailure::AnonymousOpenError) => {
                return Err(AtomicWriteError::WriteTemp {
                    tmp: target.to_path_buf(),
                    source: io::Error::other("injected O_TMPFILE error"),
                });
            }
            _ => {}
        }
        let dot = c".";
        // SAFETY: `parent` is a pinned directory descriptor, `dot` is a
        // NUL-terminated constant, and `O_TMPFILE` creates an unlinked inode
        // beneath that descriptor without resolving an attacker-controlled path.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                dot.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: successful `openat` returns a uniquely-owned file
            // descriptor, transferred directly into `File`.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
        ) {
            return Err(anonymous_unsupported(
                target,
                format!("O_TMPFILE unavailable: {source}"),
            ));
        }
        Err(AtomicWriteError::WriteTemp {
            tmp: target.to_path_buf(),
            source,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(AtomicWriteError::AnonymousStagingUnsupported {
            target: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "O_TMPFILE anonymous staging requires Linux",
            ),
        })
    }
}

fn set_metadata(
    file: &File,
    owner: Option<(u32, u32)>,
    mode: u32,
    stage_path: &Path,
    preserve_snapshot_owner: bool,
) -> Result<(), AtomicWriteError> {
    if let Some((uid, gid)) = owner {
        let current = file
            .metadata()
            .map_err(|source| AtomicWriteError::Metadata {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        if let Some((uid, gid)) = needed_owner_ids(current.uid(), current.gid(), uid, gid) {
            // SAFETY: `file` owns a valid anonymous inode descriptor and the
            // requested ids were derived from trusted target metadata or opts.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(AtomicWriteError::Metadata {
                    tmp: stage_path.to_path_buf(),
                    source: io::Error::last_os_error(),
                });
            }
        }
        let staged = file
            .metadata()
            .map_err(|source| AtomicWriteError::Metadata {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        if (staged.uid(), staged.gid()) != (uid, gid) {
            return Err(AtomicWriteError::Metadata {
                tmp: stage_path.to_path_buf(),
                source: io::Error::other(if preserve_snapshot_owner {
                    "cannot preserve snapshot ownership"
                } else {
                    "cannot set requested new file ownership"
                }),
            });
        }
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|source| AtomicWriteError::Metadata {
            tmp: stage_path.to_path_buf(),
            source,
        })
}

fn sync_and_validate(
    file: &mut File,
    validator: Option<super::AtomicWriteFdValidator<'_>>,
    target: &Path,
    stage_path: &Path,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
    #[cfg(not(test))] _test_failure: (),
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
) -> Result<(), AtomicWriteError> {
    #[cfg(test)]
    if test_failure == Some(AtomicWriteTestFailure::TempFsync) {
        return Err(AtomicWriteError::Fsync {
            path: stage_path.to_path_buf(),
            source: io::Error::other("injected anonymous staged-temp fsync failure"),
        });
    }
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeAnonymousInodeFsync,
        target,
        false,
    )?;
    file.sync_all().map_err(|source| AtomicWriteError::Fsync {
        path: stage_path.to_path_buf(),
        source,
    })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterAnonymousInodeFsync,
        target,
        false,
    )?;
    if let Some(validator) = validator {
        let mut validated = file
            .try_clone()
            .map_err(|source| AtomicWriteError::WriteTemp {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        validated
            .rewind()
            .map_err(|source| AtomicWriteError::WriteTemp {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        validator(&validated, stage_path).map_err(|reason| AtomicWriteError::Validation {
            target: target.to_path_buf(),
            reason,
        })?;
    }
    Ok(())
}

fn sync_and_validate_stage_only(
    file: &mut File,
    validator: Option<super::AtomicWriteFdValidator<'_>>,
    target: &Path,
    stage_path: &Path,
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
) -> Result<(), AtomicWriteError> {
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeAnonymousInodeFsync,
        target,
        false,
    )?;
    file.sync_all().map_err(|source| AtomicWriteError::Fsync {
        path: stage_path.to_path_buf(),
        source,
    })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterAnonymousInodeFsync,
        target,
        false,
    )?;
    if let Some(validator) = validator {
        let mut validated = file
            .try_clone()
            .map_err(|source| AtomicWriteError::WriteTemp {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        validated
            .rewind()
            .map_err(|source| AtomicWriteError::WriteTemp {
                tmp: stage_path.to_path_buf(),
                source,
            })?;
        validator(&validated, stage_path).map_err(|reason| AtomicWriteError::Validation {
            target: target.to_path_buf(),
            reason,
        })?;
    }
    Ok(())
}

fn journal_and_publish_replace(
    target: &PinnedTarget<'_>,
    file: &File,
    callback: AnonymousStagingCallback<'_>,
    after_link: Option<AnonymousAfterLinkCallback<'_>>,
    stage_path: &Path,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
    #[cfg(not(test))] _test_failure: (),
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
) -> Result<(), AtomicWriteError> {
    journal_and_link(
        target,
        file,
        callback,
        after_link,
        stage_path,
        boundaries,
        #[cfg(test)]
        test_failure,
    )?;
    #[cfg(test)]
    if test_failure == Some(AtomicWriteTestFailure::AnonymousAfterLink) {
        return Err(AtomicWriteError::Fsync {
            path: stage_path.to_path_buf(),
            source: io::Error::other("injected anonymous post-link failure"),
        });
    }
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeStagingLinkParentFsync,
        target.display(),
        false,
    )?;
    target
        .parent
        .sync_all()
        .map_err(|source| AtomicWriteError::Fsync {
            path: target
                .display()
                .parent()
                .expect("target parent")
                .to_path_buf(),
            source,
        })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterStagingLinkParentFsync,
        target.display(),
        false,
    )?;
    target
        .check_original()
        .map_err(|source| AtomicWriteError::Stat {
            path: target.display().to_path_buf(),
            source,
        })?;
    let promoted = file
        .try_clone()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let master = target
        .master
        .map(|_| file.try_clone())
        .transpose()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let basename = stage_basename(stage_path);
    observe(
        boundaries,
        AtomicWriteBoundary::BeforePromotionRename,
        target.display(),
        false,
    )?;
    rename_at(&target.parent, basename, &target.parent, &target.name).map_err(|source| {
        AtomicWriteError::Rename {
            tmp: stage_path.to_path_buf(),
            target: target.display().to_path_buf(),
            source,
        }
    })?;
    target.record_promotion(promoted, master);
    observe(
        boundaries,
        AtomicWriteBoundary::AfterPromotionRename,
        target.display(),
        true,
    )?;
    observe(
        boundaries,
        AtomicWriteBoundary::BeforePostRenameParentFsync,
        target.display(),
        true,
    )?;
    target
        .parent
        .sync_all()
        .map_err(|source| AtomicWriteError::PostRenameFsync {
            path: target
                .display()
                .parent()
                .expect("target parent")
                .to_path_buf(),
            source,
        })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterPostRenameParentFsync,
        target.display(),
        true,
    )?;
    Ok(())
}

fn journal_and_publish_create(
    target: &PinnedTarget<'_>,
    file: &File,
    callback: AnonymousStagingCallback<'_>,
    after_link: Option<AnonymousAfterLinkCallback<'_>>,
    stage_path: &Path,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
    #[cfg(not(test))] _test_failure: (),
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
) -> Result<(), AtomicWriteError> {
    journal_and_link(
        target,
        file,
        callback,
        after_link,
        stage_path,
        boundaries,
        #[cfg(test)]
        test_failure,
    )?;
    #[cfg(test)]
    if test_failure == Some(AtomicWriteTestFailure::AnonymousAfterLink) {
        return Err(AtomicWriteError::Fsync {
            path: stage_path.to_path_buf(),
            source: io::Error::other("injected anonymous post-link failure"),
        });
    }
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeStagingLinkParentFsync,
        target.display(),
        false,
    )?;
    target
        .parent
        .sync_all()
        .map_err(|source| AtomicWriteError::Fsync {
            path: target
                .display()
                .parent()
                .expect("target parent")
                .to_path_buf(),
            source,
        })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterStagingLinkParentFsync,
        target.display(),
        false,
    )?;
    check_create_only_target_absent(target, target.display())?;
    let promoted = file
        .try_clone()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let master = target
        .master
        .map(|_| file.try_clone())
        .transpose()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let basename = stage_basename(stage_path);
    observe(
        boundaries,
        AtomicWriteBoundary::BeforePromotionRename,
        target.display(),
        false,
    )?;
    rename_noreplace_at(&target.parent, basename, &target.parent, &target.name).map_err(
        |source| classify_noreplace_error(target.display(), stage_path.to_path_buf(), source),
    )?;
    target.record_promotion(promoted, master);
    observe(
        boundaries,
        AtomicWriteBoundary::AfterPromotionRename,
        target.display(),
        true,
    )?;
    observe(
        boundaries,
        AtomicWriteBoundary::BeforePostRenameParentFsync,
        target.display(),
        true,
    )?;
    target
        .parent
        .sync_all()
        .map_err(|source| AtomicWriteError::PostRenameFsync {
            path: target
                .display()
                .parent()
                .expect("target parent")
                .to_path_buf(),
            source,
        })?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterPostRenameParentFsync,
        target.display(),
        true,
    )?;
    Ok(())
}

fn journal_and_link(
    target: &PinnedTarget<'_>,
    file: &File,
    callback: AnonymousStagingCallback<'_>,
    after_link: Option<AnonymousAfterLinkCallback<'_>>,
    stage_path: &Path,
    boundaries: Option<AtomicWriteBoundaryCallback<'_>>,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
) -> Result<(), AtomicWriteError> {
    let basename = stage_basename(stage_path);
    callback(&target.parent, file, basename).map_err(|reason| {
        AtomicWriteError::JournalCallback {
            target: target.display().to_path_buf(),
            reason,
        }
    })?;
    observe(
        boundaries,
        AtomicWriteBoundary::BeforeStagingLink,
        target.display(),
        false,
    )?;
    link_anonymous(
        file,
        &target.parent,
        basename,
        target.display(),
        #[cfg(test)]
        test_failure,
    )?;
    observe(
        boundaries,
        AtomicWriteBoundary::AfterStagingLink,
        target.display(),
        false,
    )?;
    verify_link(target, file, basename, stage_path)?;
    if let Some(after_link) = after_link {
        after_link().map_err(|reason| AtomicWriteError::JournalCallback {
            target: target.display().to_path_buf(),
            reason,
        })?;
    }
    Ok(())
}

fn link_anonymous(
    file: &File,
    parent: &File,
    basename: &OsStr,
    target: &Path,
    #[cfg(test)] test_failure: Option<AtomicWriteTestFailure>,
) -> Result<(), AtomicWriteError> {
    #[cfg(target_os = "linux")]
    {
        #[cfg(test)]
        match test_failure {
            Some(AtomicWriteTestFailure::AnonymousLinkUnsupported) => {
                return Err(anonymous_unsupported(
                    target,
                    "linkat anonymous inode unavailable: injected unsupported error",
                ));
            }
            Some(AtomicWriteTestFailure::AnonymousLinkError) => {
                return Err(AtomicWriteError::WriteTemp {
                    tmp: target.to_path_buf(),
                    source: io::Error::other("injected linkat anonymous inode error"),
                });
            }
            _ => {}
        }
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).expect("fd path");
        let destination =
            CString::new(basename.as_bytes()).map_err(|source| AtomicWriteError::WriteTemp {
                tmp: target.to_path_buf(),
                source: source.into(),
            })?;
        // SAFETY: `source` and `destination` are NUL-terminated, `file` and
        // `parent` are held descriptors, and AT_SYMLINK_FOLLOW is required to
        // link the anonymous inode referred to by `/proc/self/fd/<fd>`.
        let rc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL | libc::ENOENT)
        ) {
            return Err(anonymous_unsupported(
                target,
                format!("linkat anonymous inode unavailable: {source}"),
            ));
        }
        Err(AtomicWriteError::WriteTemp {
            tmp: target.to_path_buf(),
            source,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(AtomicWriteError::AnonymousStagingUnsupported {
            target: target.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "linkat anonymous staging requires Linux",
            ),
        })
    }
}

fn anonymous_unsupported(target: &Path, message: impl Into<String>) -> AtomicWriteError {
    AtomicWriteError::AnonymousStagingUnsupported {
        target: target.to_path_buf(),
        source: io::Error::new(io::ErrorKind::Unsupported, message.into()),
    }
}

fn observe(
    callback: Option<AtomicWriteBoundaryCallback<'_>>,
    boundary: AtomicWriteBoundary,
    target: &Path,
    rename_landed: bool,
) -> Result<(), AtomicWriteError> {
    let Some(callback) = callback else {
        return Ok(());
    };
    callback(boundary).map_err(|reason| AtomicWriteError::TransactionBoundaryCallback {
        target: target.to_path_buf(),
        boundary,
        rename_landed,
        reason,
    })
}

fn verify_link(
    target: &PinnedTarget<'_>,
    file: &File,
    basename: &OsStr,
    stage_path: &Path,
) -> Result<(), AtomicWriteError> {
    let held = file
        .metadata()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let named = inspect_at(&target.parent, basename)
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source: io::Error::other("anonymous staging link disappeared"),
        })?;
    let named = named
        .metadata()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    if !held.is_file()
        || held.nlink() != 1
        || !named.is_file()
        || named.nlink() != 1
        || !same_inode(&held, &named)
        || held.len() != named.len()
        || held.mode() != named.mode()
        || held.uid() != named.uid()
        || held.gid() != named.gid()
    {
        return Err(AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source: io::Error::other("anonymous staging link identity or metadata changed"),
        });
    }
    Ok(())
}

fn verify_payload_bytes(
    payload: &File,
    expected: &[u8],
    stage_path: &Path,
) -> Result<(), AtomicWriteError> {
    let mut reader = payload
        .try_clone()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    reader
        .rewind()
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let mut actual = vec![0_u8; expected.len()];
    reader
        .read_exact(&mut actual)
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    let mut extra = [0_u8; 1];
    let extra = reader
        .read(&mut extra)
        .map_err(|source| AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source,
        })?;
    if actual != expected || extra != 0 {
        return Err(AtomicWriteError::WriteTemp {
            tmp: stage_path.to_path_buf(),
            source: io::Error::other("anonymous staging payload content changed"),
        });
    }
    Ok(())
}

fn stage_basename(path: &Path) -> &OsStr {
    path.file_name().expect("anonymous staging basename")
}
