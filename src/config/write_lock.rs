//! Directory flock lets readers synchronize without creating filesystem metadata.
//! Writers also keep a stable side lock across config-file renames.
//! Every participant must lock the directory first; older side-only lockers cannot
//! synchronize these readers. Unsupported directory flock fails closed.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context};

use super::migration_journal;

const WRITE_LOCK_FILE: &str = ".warden-config.lock";
pub(crate) const WRITE_STAGE_PREFIX: &str = ".warden-write-";
const LOCK_DEADLINE: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(10);

pub(crate) fn reserved_component(name: &OsStr) -> bool {
    name == WRITE_LOCK_FILE
        || name.as_bytes().starts_with(WRITE_STAGE_PREFIX.as_bytes())
        || name == migration_journal::TXN_DIR_NAME
        || name
            .as_bytes()
            .starts_with(migration_journal::CLEANUP_DIR_PREFIX.as_bytes())
        || name
            .as_bytes()
            .starts_with(migration_journal::FINALIZED_DIR_PREFIX.as_bytes())
}

#[derive(Debug, thiserror::Error)]
#[error("config path is not a regular file: {0}")]
pub(crate) struct NonRegularMaster(pub(crate) PathBuf);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigTreeIdentity {
    pub(crate) canonical_master: PathBuf,
    pub(crate) root: PathBuf,
    pub(crate) lock_path: PathBuf,
    pub(crate) txn_dir: PathBuf,
    // The existing ancestor pins identity even before a new root is created.
    anchor: PathBuf,
    anchor_inode: (u64, u64),
}

impl ConfigTreeIdentity {
    #[allow(dead_code, reason = "standalone identity inspection API")]
    pub(crate) fn resolve(requested_master: &Path) -> anyhow::Result<Self> {
        Self::resolve_from(requested_master, &std::env::current_dir()?)
    }

    fn resolve_from(requested_master: &Path, cwd: &Path) -> anyhow::Result<Self> {
        Ok(Self::resolve_with_master_from(requested_master, cwd)?.0)
    }

    fn resolve_with_master_from(
        requested_master: &Path,
        cwd: &Path,
    ) -> anyhow::Result<(Self, Option<File>)> {
        ensure!(
            !requested_master.as_os_str().is_empty() && requested_master.file_name().is_some(),
            "master config path must name a file: {}",
            requested_master.display()
        );
        let (canonical_master, master) =
            super::tree_io::resolve_global_entry_from(requested_master, cwd)?;
        ensure!(
            !matches!(
                requested_master
                    .as_os_str()
                    .as_bytes()
                    .rsplit(|b| *b == b'/')
                    .next(),
                Some(b"" | b"." | b"..")
            ),
            "master config path must name a file: {}",
            requested_master.display()
        );
        ensure!(
            !canonical_master
                .components()
                .any(|part| reserved_component(part.as_os_str())),
            "reserved config namespace cannot contain a master: {}",
            canonical_master.display()
        );
        if let Some(file) = &master {
            ensure!(
                file.metadata()?.is_file(),
                NonRegularMaster(canonical_master.clone())
            );
        }
        let root = canonical_master
            .parent()
            .context("master config path has no parent")?
            .to_path_buf();
        let mut anchor = root.clone();
        let meta = loop {
            match std::fs::symlink_metadata(&anchor) {
                Ok(meta) => break meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    ensure!(anchor.pop(), "config root has no existing ancestor");
                }
                Err(e) => return Err(e.into()),
            }
        };
        ensure!(
            meta.is_dir(),
            "config root ancestor is not a directory: {}",
            anchor.display()
        );
        Ok((
            Self {
                lock_path: root.join(WRITE_LOCK_FILE),
                txn_dir: root.join(migration_journal::TXN_DIR_NAME),
                canonical_master,
                root,
                anchor,
                anchor_inode: inode(&meta),
            },
            master,
        ))
    }

    fn verify_master_from(&self, master: &Path, cwd: &Path) -> anyhow::Result<Option<File>> {
        self.open_root(false)?;
        let (requested, file) = Self::resolve_with_master_from(master, cwd)?;
        ensure!(
            &requested == self,
            "config guard belongs to {}, not {}",
            self.canonical_master.display(),
            master.display()
        );
        Ok(file)
    }

    pub(crate) fn open_root(&self, create: bool) -> anyhow::Result<File> {
        // O_PATH preserves traversal through searchable but unreadable ancestors.
        let access = if self.root == Path::new("/") {
            libc::O_RDONLY
        } else {
            libc::O_PATH
        };
        let mut dir = OpenOptions::new()
            .read(true)
            .custom_flags(access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let mut path = PathBuf::from("/");
        self.check_anchor(&path, &dir)?;
        for component in self.root.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            path.push(name);
            let access = if path == self.root {
                libc::O_RDONLY
            } else {
                libc::O_PATH
            };
            let next = match open_at(&dir, name, access | libc::O_DIRECTORY, 0) {
                Ok(next) => next,
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    let parent =
                        open_at(&dir, OsStr::new("."), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    let name_c = CString::new(name.as_bytes())?;
                    #[cfg(test)]
                    test_event(TestEvent::BeforeMkdir);
                    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o750) };
                    let created = rc == 0;
                    if !created && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error()).with_context(|| {
                            format!("create config directory {}", path.display())
                        });
                    }
                    let next = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    if created {
                        preserve_owner(&next, &dir.metadata()?)?;
                        next.set_permissions(std::fs::Permissions::from_mode(0o750))?;
                        next.sync_all()?;
                        parent.sync_all()?;
                    }
                    next
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "open config directory {} without following symlinks",
                            path.display()
                        )
                    })
                }
            };
            self.check_anchor(&path, &next)?;
            dir = next;
        }
        Ok(dir)
    }

    fn check_anchor(&self, path: &Path, file: &File) -> anyhow::Result<()> {
        if path == self.anchor {
            ensure!(
                inode(&file.metadata()?) == self.anchor_inode,
                "config root changed while acquiring its lock: {}",
                path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn owner_metadata(&self, root: &File) -> anyhow::Result<Metadata> {
        match open_at(
            root,
            self.canonical_master
                .file_name()
                .context("master filename")?,
            libc::O_PATH,
            0,
        ) {
            Ok(master) => {
                let meta = master.metadata()?;
                ensure!(meta.is_file(), "master config must be a regular file");
                Ok(meta)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(root.metadata()?),
            Err(e) => Err(e).context("inspect canonical master ownership"),
        }
    }
}

pub(crate) fn resolve_path(requested: &Path) -> anyhow::Result<PathBuf> {
    super::tree_io::resolve_global_from(requested, &std::env::current_dir()?)
}

pub(crate) fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(crate) fn preserve_owner(file: &File, owner: &Metadata) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        let rc = unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) };
        if rc != 0 {
            return Err(io::Error::last_os_error()).context("preserve config ownership");
        }
    }
    Ok(())
}

fn inode(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

#[must_use = "dropping the guard releases the config tree lock"]
#[derive(Debug)]
pub struct ConfigWriteLock {
    _side_file: File,
    side_lock_owner: (u32, u32),
    _root: File,
    identity: ConfigTreeIdentity,
    cwd: PathBuf,
    requested: PathBuf,
    root_alias: Option<PathBuf>,
    master: RefCell<Option<File>>,
}

#[must_use = "dropping the guard releases the config tree lock"]
#[derive(Debug)]
pub(crate) struct ConfigReadLock {
    _root: File,
    identity: ConfigTreeIdentity,
    cwd: PathBuf,
    requested: PathBuf,
    root_alias: Option<PathBuf>,
    master: RefCell<Option<File>>,
}

#[must_use = "dropping the guard releases the config tree lock"]
#[derive(Debug)]
pub(crate) struct MigrationWriteLock(ConfigWriteLock);

macro_rules! identity_accessors {
    () => {
        pub(crate) fn tree_io(&self) -> super::tree_io::TreeIo<'_> {
            super::tree_io::TreeIo {
                identity: &self.identity,
                root: &self._root,
                cwd: &self.cwd,
                requested: &self.requested,
                root_alias: self.root_alias.as_deref(),
                master: &self.master,
            }
        }
        pub(crate) fn verify_master(&self, master: &Path) -> anyhow::Result<()> {
            if self.cwd.join(master).as_os_str() == self.requested.as_os_str()
                || master.as_os_str() == self.canonical_master().as_os_str()
            {
                return Ok(());
            }
            let resolved = ConfigTreeIdentity::resolve_from(master, &self.cwd)?;
            ensure!(
                resolved == self.identity,
                "config guard belongs to {}, not {}",
                self.canonical_master().display(),
                master.display()
            );
            Ok(())
        }
        pub(crate) fn identity(&self) -> &ConfigTreeIdentity {
            &self.identity
        }
        pub(crate) fn canonical_master(&self) -> &Path {
            &self.identity.canonical_master
        }
        #[allow(dead_code, reason = "guarded mutation API")]
        pub(crate) fn resolve_member(&self, path: &Path) -> anyhow::Result<PathBuf> {
            Ok(self.tree_io().plan_target(path)?.display().to_path_buf())
        }
    };
}

impl ConfigWriteLock {
    identity_accessors!();

    pub(crate) fn admitted_side_lock_owner(&self) -> anyhow::Result<(u32, u32)> {
        let meta = self._side_file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.mode() & 0o7777 == 0o600
                && (meta.uid(), meta.gid()) == self.side_lock_owner,
            "config side lock changed after admission: {}",
            self.identity.lock_path.display()
        );
        Ok(self.side_lock_owner)
    }

    /// Admit the canonical master's replacement made by the direct CLI editor.
    ///
    /// This is deliberately not a general identity refresh: it examines only
    /// the canonical leaf beneath the already locked root, without following
    /// it, and accepts only a regular single-link replacement.
    pub(crate) fn recapture_canonical_master_after_editor(&self) -> anyhow::Result<()> {
        let owner = self.admitted_side_lock_owner()?;
        let name = self
            .identity
            .canonical_master
            .file_name()
            .context("master filename")?;
        let file = super::tree_io::inspect_at(&self._root, name)?
            .context("editor removed the canonical master")?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.nlink() == 1,
            "editor replacement must be a regular single-link canonical master: {}",
            self.identity.canonical_master.display()
        );
        let ownership = reopen_inspected(&file, libc::O_RDONLY)
            .context("reopen editor replacement before ownership normalization")?;
        if (meta.uid(), meta.gid()) != owner && unsafe { libc::geteuid() } == 0 {
            let rc = unsafe { libc::fchown(ownership.as_raw_fd(), owner.0, owner.1) };
            if rc != 0 {
                return Err(io::Error::last_os_error())
                    .context("preserve editor replacement ownership");
            }
            #[cfg(test)]
            if take_recaptured_owner_sync_failure() {
                return Err(io::Error::other(
                    "injected editor replacement ownership sync failure",
                ))
                .context("sync editor replacement ownership");
            }
            ownership
                .sync_all()
                .context("sync editor replacement ownership")?;
        }
        let meta = ownership.metadata()?;
        ensure!(
            (meta.uid(), meta.gid()) == owner,
            "editor replacement owner does not match admitted config lock owner {}:{}: {}",
            owner.0,
            owner.1,
            self.identity.canonical_master.display()
        );
        *self.master.borrow_mut() = Some(file);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.identity.lock_path
    }
}

impl ConfigReadLock {
    pub(crate) fn tree_io(&self) -> super::tree_io::TreeIo<'_> {
        super::tree_io::TreeIo {
            identity: &self.identity,
            root: &self._root,
            cwd: &self.cwd,
            requested: &self.requested,
            root_alias: self.root_alias.as_deref(),
            master: &self.master,
        }
    }

    #[allow(dead_code, reason = "guarded backup seam")]
    pub(crate) fn verify_master(&self, master: &Path) -> anyhow::Result<()> {
        if self.cwd.join(master).as_os_str() == self.requested.as_os_str()
            || master.as_os_str() == self.canonical_master().as_os_str()
        {
            return Ok(());
        }
        let resolved = ConfigTreeIdentity::resolve_from(master, &self.cwd)?;
        ensure!(
            resolved == self.identity,
            "config guard belongs to {}, not {}",
            self.canonical_master().display(),
            master.display()
        );
        Ok(())
    }

    #[allow(dead_code, reason = "guarded backup seam")]
    pub(crate) fn canonical_master(&self) -> &Path {
        &self.identity.canonical_master
    }

    #[cfg(test)]
    pub(crate) fn identity(&self) -> &ConfigTreeIdentity {
        &self.identity
    }
}

impl MigrationWriteLock {
    pub(crate) fn tree_io(&self) -> super::tree_io::TreeIo<'_> {
        self.0.tree_io()
    }
    pub(crate) fn verify_master(&self, master: &Path) -> anyhow::Result<()> {
        self.0.verify_master(master)
    }
    pub(crate) fn identity(&self) -> &ConfigTreeIdentity {
        self.0.identity()
    }
    pub(crate) fn canonical_master(&self) -> &Path {
        self.0.canonical_master()
    }
}

pub fn acquire_for_write(master: &Path) -> anyhow::Result<ConfigWriteLock> {
    let guard = acquire_write_with_deadline(master, LOCK_DEADLINE)?;
    migration_journal::refuse_normal_write(guard.tree_io())?;
    #[cfg(test)]
    test_event(TestEvent::WriteRootLocked);
    Ok(guard)
}

pub(crate) fn acquire_for_read(master: &Path) -> anyhow::Result<ConfigReadLock> {
    acquire_read_with_deadline(master, LOCK_DEADLINE)
}

#[cfg(test)]
pub(crate) fn acquire_for_read_with_timeout(
    master: &Path,
    wait: Duration,
) -> anyhow::Result<ConfigReadLock> {
    acquire_read_with_deadline(master, wait)
}

#[cfg(test)]
pub(crate) fn acquire_for_write_with_timeout(
    master: &Path,
    wait: Duration,
) -> anyhow::Result<ConfigWriteLock> {
    acquire_write_with_deadline(master, wait)
}

fn acquire_read_with_deadline(master: &Path, wait: Duration) -> anyhow::Result<ConfigReadLock> {
    let cwd = std::env::current_dir()?;
    let (identity, root, captured) = lock_root(master, &cwd, false, wait)?;
    let guard = ConfigReadLock {
        master: RefCell::new(captured),
        _root: root,
        root_alias: admitted_parent_alias(master, &cwd, &identity)?,
        identity,
        requested: cwd.join(master),
        cwd,
    };
    migration_journal::refuse_normal_access(guard.tree_io())?;
    #[cfg(test)]
    test_event(TestEvent::RootLocked);
    Ok(guard)
}

#[allow(dead_code, reason = "migration-only API")]
pub(crate) fn acquire_for_migration(master: &Path) -> anyhow::Result<MigrationWriteLock> {
    Ok(MigrationWriteLock(acquire_write_with_deadline(
        master,
        LOCK_DEADLINE,
    )?))
}

fn admitted_parent_alias(
    master: &Path,
    cwd: &Path,
    identity: &ConfigTreeIdentity,
) -> anyhow::Result<Option<PathBuf>> {
    let absolute = cwd.join(master);
    let parent = absolute.parent().context("master parent")?;
    Ok(
        (super::tree_io::resolve_global_from(parent, cwd)? == identity.root)
            .then(|| parent.to_path_buf()),
    )
}

fn lock_root(
    master: &Path,
    cwd: &Path,
    exclusive: bool,
    wait: Duration,
) -> anyhow::Result<(ConfigTreeIdentity, File, Option<File>)> {
    let initial = ConfigTreeIdentity::resolve_from(master, cwd)?;
    if std::fs::metadata(&initial.canonical_master).is_ok() {
        std::fs::metadata(cwd.join(master))
            .context("requested master spelling cannot be traversed")?;
    }
    let root = initial.open_root(exclusive)?;
    let identity = ConfigTreeIdentity::resolve_from(master, cwd)?;
    ensure!(
        initial.root == identity.root && initial.canonical_master == identity.canonical_master,
        "config identity changed while creating its root"
    );
    ensure!(
        inode(&root.metadata()?) == identity.anchor_inode && identity.anchor == identity.root,
        "config root changed while opening its lock"
    );
    wait_for_flock(&root, exclusive, wait).with_context(|| {
        format!(
            "lock config directory {}; Nothing was written",
            identity.root.display()
        )
    })?;
    let verified = identity.verify_master_from(master, cwd)?;
    let captured = capture_master(&identity, &root, verified.as_ref())?;
    Ok((identity, root, captured))
}

fn acquire_write_with_deadline(master: &Path, wait: Duration) -> anyhow::Result<ConfigWriteLock> {
    let started = Instant::now();
    // Directory-first ordering lets readers synchronize without side-file access.
    let cwd = std::env::current_dir()?;
    let (identity, root, captured) = lock_root(master, &cwd, true, wait)?;
    let owner = captured
        .as_ref()
        .map(File::metadata)
        .transpose()?
        .unwrap_or(root.metadata()?);
    let name = OsStr::new(WRITE_LOCK_FILE);
    let flags = libc::O_RDWR | libc::O_NONBLOCK;
    let (file, created) = match open_at(&root, name, flags | libc::O_CREAT | libc::O_EXCL, 0o600) {
        Ok(file) => (file, true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (
            open_at(&root, name, libc::O_PATH, 0).with_context(|| {
                format!("open safe config lock {}", identity.lock_path.display())
            })?,
            false,
        ),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("create config lock {}", identity.lock_path.display()))
        }
    };
    if created {
        preserve_owner(&file, &owner)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    validate_lock(&file.metadata()?, &owner, &identity.lock_path)?;
    let file = if created {
        file
    } else {
        reopen_inspected(&file, flags)?
    };
    if created {
        file.sync_all()?;
        root.sync_all()?;
    }
    wait_for_flock(&file, true, wait.saturating_sub(started.elapsed())).with_context(|| {
        format!(
            "lock config tree via {}; Nothing was written",
            identity.lock_path.display()
        )
    })?;
    let verified = identity.verify_master_from(master, &cwd)?;
    ensure!(
        super::tree_io::same_optional_inode(captured.as_ref(), verified.as_ref())?,
        "canonical master changed while acquiring the side lock"
    );
    let current = open_at(&root, name, libc::O_PATH, 0)?;
    validate_lock(&current.metadata()?, &owner, &identity.lock_path)?;
    ensure!(
        inode(&file.metadata()?) == inode(&current.metadata()?),
        "config lock inode changed during acquisition"
    );
    Ok(ConfigWriteLock {
        master: RefCell::new(capture_master(&identity, &root, verified.as_ref())?),
        _side_file: file,
        side_lock_owner: (owner.uid(), owner.gid()),
        _root: root,
        root_alias: admitted_parent_alias(master, &cwd, &identity)?,
        identity,
        requested: cwd.join(master),
        cwd,
    })
}

fn capture_master(
    identity: &ConfigTreeIdentity,
    root: &File,
    verified: Option<&File>,
) -> anyhow::Result<Option<File>> {
    #[cfg(test)]
    test_event(TestEvent::BeforeMasterCapture);
    let file = super::tree_io::inspect_at(
        root,
        identity
            .canonical_master
            .file_name()
            .context("master filename")?,
    )?;
    ensure!(
        super::tree_io::same_optional_inode(verified, file.as_ref())?,
        "canonical master changed between identity verification and capture"
    );
    Ok(file)
}

fn validate_lock(meta: &Metadata, owner: &Metadata, path: &Path) -> anyhow::Result<()> {
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o600
            && meta.uid() == owner.uid()
            && meta.gid() == owner.gid(),
        "unsafe config lock (expected regular, single-link, mode 0600, owner {}:{}): {}. Stop all warden daemons and commands before maintenance; inspect this exact entry without following symlinks. After confirming it is an obsolete lock, move it aside and let warden recreate it. Do not remove or replace a lock while any old or new process may hold it",
        owner.uid(),
        owner.gid(),
        path.display()
    );
    Ok(())
}

fn flock_until(file: &File, exclusive: bool, wait: Duration) -> io::Result<()> {
    let deadline = Instant::now() + wait;
    let kind = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(err);
        }
        #[cfg(test)]
        test_event(TestEvent::Contended);
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("another warden process holds the config tree lock (waited {wait:?})"),
            ));
        };
        std::thread::sleep(LOCK_POLL.min(remaining));
    }
}

pub(crate) fn reopen_inspected(file: &File, flags: i32) -> io::Result<File> {
    let meta = file.metadata()?;
    if !meta.is_file() && !meta.is_dir() {
        return Err(io::Error::other(
            "refusing data access to a non-regular, non-directory inode",
        ));
    }
    #[cfg(test)]
    test_event(TestEvent::BeforeDataOpen);
    // procfs names the inspected inode, so replacement devices are never opened.
    let reopened = OpenOptions::new()
        .read(true)
        .write(flags & libc::O_RDWR != 0)
        .custom_flags(flags | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    if inode(&meta) != inode(&reopened.metadata()?) {
        return Err(io::Error::other("inspected inode changed during reopen"));
    }
    Ok(reopened)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestEvent {
    Contended,
    BeforeMkdir,
    BeforeDataOpen,
    BeforeExternalSourceParentPin,
    RootLocked,
    WriteRootLocked,
    BeforePromotion,
    IncludeDirectoryPinned,
    BeforeOverlay,
    OverlayResolved,
    BeforeMasterCapture,
    BeforeGuardedValidation,
    AfterGuardedValidation,
    AfterEditorRecapture,
}

#[cfg(test)]
type TestHook = Box<dyn FnMut(TestEvent)>;
#[cfg(test)]
thread_local! { static TEST_HOOK: std::cell::RefCell<Option<TestHook>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
thread_local! { static FAIL_RECAPTURED_OWNER_SYNC: Cell<bool> = const { Cell::new(false) }; }

#[cfg(test)]
pub(crate) fn test_event(event: TestEvent) {
    TEST_HOOK.with(|slot| {
        let Some(mut hook) = slot.borrow_mut().take() else {
            return;
        };
        hook(event);
        *slot.borrow_mut() = Some(hook);
    });
}

#[cfg(test)]
pub(crate) fn with_test_hook<T>(
    hook: impl FnMut(TestEvent) + 'static,
    body: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<TestHook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(TEST_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    body()
}

#[cfg(test)]
pub(crate) fn with_recaptured_owner_sync_failure<T>(body: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_RECAPTURED_OWNER_SYNC.with(|slot| slot.set(self.0));
        }
    }
    let reset = FAIL_RECAPTURED_OWNER_SYNC.with(|slot| Reset(slot.replace(true)));
    let result = body();
    drop(reset);
    result
}

#[cfg(test)]
fn take_recaptured_owner_sync_failure() -> bool {
    FAIL_RECAPTURED_OWNER_SYNC.with(|slot| slot.replace(false))
}

fn wait_for_flock(file: &File, exclusive: bool, wait: Duration) -> io::Result<()> {
    use tokio::runtime::{Handle, RuntimeFlavor};
    // Contention must not park a daemon worker; current-thread runtimes cannot use block_in_place.
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| flock_until(file, exclusive, wait))
        }
        _ => flock_until(file, exclusive, wait),
    }
}

#[cfg(test)]
#[path = "write_lock/tests.rs"]
mod tests;
