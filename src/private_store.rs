//! Private, descriptor-relative storage for node-local control-plane state.

#[cfg(any(test, feature = "cluster"))]
use std::ffi::CStr;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
#[cfg(any(test, feature = "cluster"))]
use std::os::unix::io::FromRawFd;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};

use crate::config::tree_io::{
    check_basename, inspect_at, rename_at, rename_noreplace_at, same_inode, unlink_at,
};
use crate::config::write_lock::{open_at, preserve_owner, reopen_inspected, MigrationWriteLock};

const LOCK: &str = ".lock";
const STAGE: &str = ".write.next";

/// The tree guard precedes the store flock and outlives every store operation.
pub(crate) struct PrivateStore<'g> {
    guard: &'g MigrationWriteLock,
    parent: File,
    base_name: String,
    base: File,
    namespace: String,
    directory: File,
    owner: Metadata,
    lock: File,
}

impl<'g> PrivateStore<'g> {
    pub(crate) fn open(guard: &'g MigrationWriteLock, base_name: &str) -> anyhow::Result<Self> {
        guard.verify_root_linked()?;
        check_basename(OsStr::new(base_name))?;
        ensure!(
            base_name.starts_with(".warden-"),
            "invalid cluster store namespace"
        );
        let parent = crate::config::state_dir::open_for_migration(guard)?;
        let owner = parent.metadata()?;
        ensure!(owner.is_dir(), "cluster state parent is not a directory");
        let base = private_directory(&parent, base_name, &owner)?;
        let namespace = hex::encode(Sha256::digest(
            guard.canonical_master().as_os_str().as_bytes(),
        ));
        let directory = private_directory(&base, &namespace, &owner)?;
        let lock = match checked_file(&directory, LOCK, &owner)? {
            Some(file) => reopen_inspected(&file, libc::O_RDWR)?,
            None => match new_file(&directory, LOCK, &owner) {
                Ok(file) => {
                    file.sync_all()?;
                    directory.sync_all()?;
                    file
                }
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
                {
                    reopen_inspected(
                        &checked_file(&directory, LOCK, &owner)?
                            .context("cluster lock disappeared")?,
                        libc::O_RDWR,
                    )?
                }
                Err(error) => return Err(error),
            },
        };
        let started = Instant::now();
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            ensure!(
                matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EINTR)),
                "cannot lock cluster store: {error}"
            );
            ensure!(
                started.elapsed() < Duration::from_secs(30),
                "cluster store lock timeout"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let store = Self {
            guard,
            parent,
            base_name: base_name.to_owned(),
            base,
            namespace,
            directory,
            owner,
            lock,
        };
        store.check()?;
        // A staging inode is never authoritative, even after its file fsync.
        if checked_file(&store.directory, STAGE, &store.owner)?.is_some() {
            unlink_at(&store.directory, OsStr::new(STAGE))?;
            store.directory.sync_all()?;
        }
        Ok(store)
    }

    pub(crate) fn check(&self) -> anyhow::Result<()> {
        self.guard.verify_root_linked()?;
        let linked_parent = crate::config::state_dir::open_for_migration(self.guard)?;
        ensure!(
            same_inode(&self.parent.metadata()?, &linked_parent.metadata()?),
            "cluster state parent was replaced"
        );
        let parent_meta = linked_parent.metadata()?;
        ensure!(
            parent_meta.uid() == self.owner.uid() && parent_meta.gid() == self.owner.gid(),
            "cluster state parent ownership changed"
        );
        for (parent, name, directory) in [
            (&self.parent, self.base_name.as_str(), &self.base),
            (&self.base, self.namespace.as_str(), &self.directory),
        ] {
            let linked =
                inspect_at(parent, OsStr::new(name))?.context("cluster store disappeared")?;
            let meta = directory.metadata()?;
            ensure!(
                same_inode(&meta, &linked.metadata()?),
                "cluster store directory was replaced"
            );
            check_directory(&meta, &self.owner)?;
        }
        let linked = checked_file(&self.directory, LOCK, &self.owner)?
            .context("cluster lock disappeared")?;
        ensure!(
            same_inode(&self.lock.metadata()?, &linked.metadata()?),
            "cluster lock was replaced"
        );
        Ok(())
    }

    pub(crate) fn read(&self, name: &str, max_bytes: u64) -> anyhow::Result<Option<Vec<u8>>> {
        self.check()?;
        payload_name(name)?;
        let Some(inspected) = checked_file(&self.directory, name, &self.owner)? else {
            return Ok(None);
        };
        let before = inspected.metadata()?;
        ensure!(
            before.len() <= max_bytes,
            "cluster store file exceeds byte limit"
        );
        let mut bytes = Vec::new();
        reopen_inspected(&inspected, libc::O_RDONLY)?
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max_bytes,
            "cluster store file exceeds byte limit"
        );
        check_linked(&self.directory, name, &inspected, &self.owner)?;
        ensure!(
            inspected.metadata()?.len() == bytes.len() as u64,
            "cluster store file changed while reading"
        );
        self.check()?;
        Ok(Some(bytes))
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_inner(name, bytes, false)
    }

    #[cfg(any(test, feature = "cluster"))]
    pub(crate) fn create(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_inner(name, bytes, true)
    }

    fn write_inner(&self, name: &str, bytes: &[u8], create_only: bool) -> anyhow::Result<()> {
        self.check()?;
        payload_name(name)?;
        let original = checked_file(&self.directory, name, &self.owner)?;
        ensure!(
            !create_only || original.is_none(),
            "immutable cluster store entry already exists"
        );
        if checked_file(&self.directory, STAGE, &self.owner)?.is_some() {
            unlink_at(&self.directory, OsStr::new(STAGE))?;
            self.directory.sync_all()?;
        }
        let mut staged = new_file(&self.directory, STAGE, &self.owner)?;
        staged.write_all(bytes)?;
        fault(WriteBoundary::Written)?;
        staged.sync_all()?;
        fault(WriteBoundary::FileSynced)?;
        self.check()?;
        check_linked(&self.directory, STAGE, &staged, &self.owner)?;
        match original {
            Some(file) => check_linked(&self.directory, name, &file, &self.owner)?,
            None => ensure!(
                inspect_at(&self.directory, OsStr::new(name))?.is_none(),
                "cluster store destination appeared"
            ),
        }
        if create_only {
            rename_noreplace_at(
                &self.directory,
                OsStr::new(STAGE),
                &self.directory,
                OsStr::new(name),
            )?;
        } else {
            rename_at(
                &self.directory,
                OsStr::new(STAGE),
                &self.directory,
                OsStr::new(name),
            )?;
        }
        fault(WriteBoundary::Renamed)?;
        self.directory.sync_all()?;
        fault(WriteBoundary::DirectorySynced)?;
        check_linked(&self.directory, name, &staged, &self.owner)?;
        self.check()
    }

    #[cfg(feature = "cluster")]
    pub(crate) fn remove(&self, name: &str) -> anyhow::Result<()> {
        self.check()?;
        payload_name(name)?;
        if let Some(file) = checked_file(&self.directory, name, &self.owner)? {
            check_linked(&self.directory, name, &file, &self.owner)?;
            unlink_at(&self.directory, OsStr::new(name))?;
            self.directory.sync_all()?;
        }
        self.check()
    }

    #[cfg(any(test, feature = "cluster"))]
    pub(crate) fn names(&self, max_entries: usize) -> anyhow::Result<Vec<String>> {
        self.check()?;
        let file = reopen_inspected(&self.directory, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let raw = unsafe { libc::fdopendir(fd) };
        if raw.is_null() {
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(io::Error::last_os_error().into());
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let stream = Stream(raw);
        let mut names = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                ensure!(
                    io::Error::last_os_error().raw_os_error() == Some(0),
                    "cannot enumerate cluster store"
                );
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_str()?;
            if matches!(name, "." | ".." | LOCK | STAGE) {
                continue;
            }
            payload_name(name)?;
            ensure!(
                names.len() < max_entries,
                "cluster store entry limit exceeded"
            );
            checked_file(&self.directory, name, &self.owner)?
                .context("cluster store entry disappeared")?;
            names.push(name.to_owned());
        }
        self.check()?;
        Ok(names)
    }
}

fn payload_name(name: &str) -> anyhow::Result<()> {
    check_basename(OsStr::new(name))?;
    ensure!(
        name.len() <= 128 && !name.starts_with('.'),
        "invalid private store payload name"
    );
    Ok(())
}

fn check_directory(meta: &Metadata, owner: &Metadata) -> anyhow::Result<()> {
    ensure!(
        meta.is_dir()
            && meta.mode() & 0o7777 == 0o700
            && meta.uid() == owner.uid()
            && meta.gid() == owner.gid(),
        "cluster store directory owner or mode changed"
    );
    Ok(())
}

fn private_directory(parent: &File, name: &str, owner: &Metadata) -> anyhow::Result<File> {
    let name_c = CString::new(name)?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0;
    if !created {
        let error = io::Error::last_os_error();
        ensure!(
            error.kind() == io::ErrorKind::AlreadyExists,
            "cannot create cluster store: {error}"
        );
    }
    let file = open_at(
        parent,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    if created {
        preserve_owner(&file, owner)?;
        file.set_permissions(Permissions::from_mode(0o700))?;
        file.sync_all()?;
        parent.sync_all()?;
    }
    check_directory(&file.metadata()?, owner)?;
    let linked =
        inspect_at(parent, OsStr::new(name))?.context("cluster store directory disappeared")?;
    ensure!(
        same_inode(&file.metadata()?, &linked.metadata()?),
        "cluster store directory was replaced"
    );
    Ok(file)
}

fn checked_file(parent: &File, name: &str, owner: &Metadata) -> anyhow::Result<Option<File>> {
    let Some(file) = inspect_at(parent, OsStr::new(name))? else {
        return Ok(None);
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o600
            && meta.uid() == owner.uid()
            && meta.gid() == owner.gid(),
        "cluster store entry must be a private, single-link regular file"
    );
    Ok(Some(file))
}

fn check_linked(parent: &File, name: &str, file: &File, owner: &Metadata) -> anyhow::Result<()> {
    let linked = checked_file(parent, name, owner)?.context("cluster store entry disappeared")?;
    ensure!(
        same_inode(&file.metadata()?, &linked.metadata()?),
        "cluster store entry was replaced"
    );
    Ok(())
}

fn new_file(parent: &File, name: &str, owner: &Metadata) -> anyhow::Result<File> {
    let file = open_at(
        parent,
        OsStr::new(name),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    preserve_owner(&file, owner)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    check_linked(parent, name, &file, owner)?;
    Ok(file)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteBoundary {
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

fn fault(boundary: WriteBoundary) -> anyhow::Result<()> {
    #[cfg(test)]
    if FAILURE.with(|point| point.get() == Some(boundary)) {
        FAILURE.with(|point| point.set(None));
        anyhow::bail!("injected private store failure at {boundary:?}");
    }
    let _ = boundary;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::Cell<Option<WriteBoundary>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_lock::acquire_for_migration;

    const BASE: &str = ".warden-cluster-test";

    #[test]
    fn namespaces_isolate_masters_and_preserve_private_modes() {
        let root = tempfile::tempdir().unwrap();
        let first = acquire_for_migration(&root.path().join("first.toml")).unwrap();
        let store = PrivateStore::open(&first, BASE).unwrap();
        store.write("ledger.json", b"first").unwrap();
        assert_eq!(store.directory.metadata().unwrap().mode() & 0o7777, 0o700);
        assert_eq!(
            checked_file(&store.directory, "ledger.json", &store.owner)
                .unwrap()
                .unwrap()
                .metadata()
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        drop(store);
        drop(first);
        let second = acquire_for_migration(&root.path().join("second.toml")).unwrap();
        let store = PrivateStore::open(&second, BASE).unwrap();
        assert_eq!(store.read("ledger.json", 100).unwrap(), None);
    }

    #[test]
    fn atomic_failure_boundaries_never_expose_partial_payloads() {
        for boundary in [
            WriteBoundary::Written,
            WriteBoundary::FileSynced,
            WriteBoundary::Renamed,
            WriteBoundary::DirectorySynced,
        ] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let store = PrivateStore::open(&guard, BASE).unwrap();
            store.write("state.json", b"old").unwrap();
            FAILURE.with(|point| point.set(Some(boundary)));
            assert!(store.write("state.json", b"complete-new-state").is_err());
            drop(store);
            let recovered = PrivateStore::open(&guard, BASE).unwrap();
            let expected: &[u8] = match boundary {
                WriteBoundary::Written | WriteBoundary::FileSynced => b"old",
                WriteBoundary::Renamed | WriteBoundary::DirectorySynced => b"complete-new-state",
            };
            assert_eq!(
                recovered.read("state.json", 100).unwrap().unwrap(),
                expected
            );
            assert_eq!(recovered.names(10).unwrap(), vec!["state.json"]);
        }
    }

    #[test]
    fn symlinks_hardlinks_and_fifo_are_refused_before_data_open() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let store = PrivateStore::open(&guard, BASE).unwrap();
        store.write("safe", b"retained").unwrap();
        let directory = root.path().join(BASE).join(&store.namespace);
        symlink(directory.join("safe"), directory.join("alias")).unwrap();
        assert!(store.read("alias", 100).is_err());
        assert!(store.write("alias", b"replacement").is_err());
        std::fs::hard_link(directory.join("safe"), directory.join("linked")).unwrap();
        assert!(store.read("linked", 100).is_err());
        let fifo = CString::new(directory.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(store.read("fifo", 100).is_err());
    }

    #[test]
    fn changed_directory_lock_and_file_modes_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let store = PrivateStore::open(&guard, BASE).unwrap();
        store.write("payload", b"data").unwrap();
        store
            .directory
            .set_permissions(Permissions::from_mode(0o750))
            .unwrap();
        assert!(store.read("payload", 100).is_err());
        store
            .directory
            .set_permissions(Permissions::from_mode(0o700))
            .unwrap();
        store
            .lock
            .set_permissions(Permissions::from_mode(0o640))
            .unwrap();
        assert!(store.check().is_err());
        store
            .lock
            .set_permissions(Permissions::from_mode(0o600))
            .unwrap();
        let file = checked_file(&store.directory, "payload", &store.owner)
            .unwrap()
            .unwrap();
        reopen_inspected(&file, libc::O_RDWR)
            .unwrap()
            .set_permissions(Permissions::from_mode(0o640))
            .unwrap();
        assert!(store.read("payload", 100).is_err());
    }

    #[test]
    fn replaced_store_directory_and_tree_are_refused() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let guard = acquire_for_migration(&root.join("config.toml")).unwrap();
        let store = PrivateStore::open(&guard, BASE).unwrap();
        let namespace = root.join(BASE).join(&store.namespace);
        std::fs::rename(&namespace, namespace.with_extension("detached")).unwrap();
        std::fs::create_dir(&namespace).unwrap();
        assert!(store.write("payload", b"data").is_err());
        std::fs::rename(&root, base.path().join("detached-root")).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(store.check().is_err());
    }

    #[test]
    fn immutable_create_and_bounded_reads_are_enforced() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let store = PrivateStore::open(&guard, BASE).unwrap();
        store.create("payload", b"immutable").unwrap();
        assert!(store.create("payload", b"new").is_err());
        assert!(store.read("payload", 8).is_err());
        assert_eq!(store.read("payload", 9).unwrap().unwrap(), b"immutable");
        assert!(store.write("../escape", b"bad").is_err());
        assert!(store.write(LOCK, b"bad").is_err());
        assert!(store.names(0).is_err());
    }

    #[test]
    fn publication_flock_serializes_independent_file_descriptions() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let store = PrivateStore::open(&guard, BASE).unwrap();
        let contender = open_at(&store.directory, OsStr::new(LOCK), libc::O_RDWR, 0).unwrap();
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        drop(store);
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }
}
