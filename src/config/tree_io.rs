//! Descriptor capabilities keep reads and writes in the tree whose root was locked.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::marker::PhantomData;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};

use super::write_lock::{open_at, preserve_owner, reopen_inspected, reserved_component};
use anyhow::{ensure, Context};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MemberKey(PathBuf);

impl MemberKey {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        ensure!(
            !path.as_os_str().is_empty()
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "non-canonical member key: {}",
            path.display()
        );
        ensure!(
            !path.components().any(|c| reserved_component(c.as_os_str())),
            "reserved config namespace: {}",
            path.display()
        );
        Ok(Self(path))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TreeIo<'g> {
    pub(crate) identity: &'g super::write_lock::ConfigTreeIdentity,
    pub(crate) root: &'g File,
    pub(crate) cwd: &'g Path,
    pub(crate) requested: &'g Path,
    pub(crate) root_alias: Option<&'g Path>,
    pub(crate) master: &'g RefCell<Option<File>>,
}

struct Walk<'g> {
    relative: PathBuf,
    file: Option<File>,
    dirs: Vec<File>,
    missing_parents: Vec<OsString>,
    _guard: PhantomData<&'g File>,
}

pub(crate) struct ResolvedEntry<'g> {
    key: MemberKey,
    display: PathBuf,
    walk: Walk<'g>,
}

/// Descriptor-retained plan for an arbitrary output directory.
///
/// Resolution follows existing aliases once. Missing components are then
/// created beneath the retained nearest ancestor, so a later pathname swap
/// cannot redirect directory creation.
pub(crate) struct ExternalDirectoryPlan {
    resolved: PathBuf,
    file: Option<File>,
    dirs: Vec<File>,
    missing: Vec<OsString>,
}

impl ExternalDirectoryPlan {
    pub(crate) fn resolved(&self) -> &Path {
        &self.resolved
    }

    /// Return this destination relative to `ancestor` when its retained
    /// descriptor chain passes through that directory.
    pub(crate) fn relative_to(&self, ancestor: &File) -> io::Result<Option<PathBuf>> {
        let expected = ancestor.metadata()?;
        if self.file.as_ref().is_some_and(|file| {
            file.metadata()
                .is_ok_and(|meta| same_inode(&meta, &expected))
        }) {
            return Ok(Some(PathBuf::new()));
        }
        for (depth, directory) in self.dirs.iter().enumerate() {
            if same_inode(&directory.metadata()?, &expected) {
                // `dirs[0]` is `/`, which is also the first component of an
                // absolute `resolved` path.
                return Ok(Some(self.resolved.components().skip(depth + 1).collect()));
            }
        }
        Ok(None)
    }

    pub(crate) fn open_existing(self) -> anyhow::Result<File> {
        let file = self.file.context("external directory does not exist")?;
        let metadata = file.metadata()?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.is_dir(),
            "external output is not a directory: {}",
            self.resolved.display()
        );
        Ok(reopen_inspected(&file, libc::O_RDONLY | libc::O_DIRECTORY)?)
    }

    pub(crate) fn open_or_create(self) -> anyhow::Result<File> {
        if self.file.is_some() {
            return self.open_existing();
        }
        let mut parent = reopen_inspected(
            self.dirs.last().context("external directory ancestor")?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        for name in self.missing {
            check_basename(&name)?;
            #[cfg(test)]
            super::write_lock::test_event(super::write_lock::TestEvent::BeforeMkdir);
            let c_name = CString::new(name.as_bytes())?;
            let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o750) };
            let created = rc == 0;
            if !created {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
            let file = inspect_at(&parent, &name)?.context("external directory disappeared")?;
            let metadata = file.metadata()?;
            ensure!(
                !metadata.file_type().is_symlink() && metadata.is_dir(),
                "external output component is not a directory: {:?}",
                name
            );
            let next = reopen_inspected(&file, libc::O_RDONLY | libc::O_DIRECTORY)?;
            if created {
                next.sync_all()?;
                parent.sync_all()?;
            }
            parent = next;
        }
        Ok(parent)
    }
}

impl ResolvedEntry<'_> {
    pub(crate) fn key(&self) -> &MemberKey {
        &self.key
    }
    pub(crate) fn display(&self) -> &Path {
        &self.display
    }
    pub(crate) fn metadata(&self) -> io::Result<Option<Metadata>> {
        self.walk.file.as_ref().map(File::metadata).transpose()
    }

    pub(crate) fn destination(&self) -> io::Result<DestinationIdentity> {
        Ok(DestinationIdentity {
            ancestors: self
                .walk
                .dirs
                .iter()
                .map(|file| file.metadata().map(|m| (m.dev(), m.ino())))
                .collect::<io::Result<_>>()?,
            missing_parents: self.walk.missing_parents.clone(),
            leaf: self.metadata()?.map(|metadata| LeafIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
                mtime: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                len: metadata.len(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                nlink: metadata.nlink(),
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafIdentity {
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DestinationIdentity {
    ancestors: Vec<(u64, u64)>,
    missing_parents: Vec<OsString>,
    leaf: Option<LeafIdentity>,
}

#[derive(Debug, thiserror::Error)]
#[error("canonical master changed since acquisition or guarded promotion")]
pub(crate) struct MasterIdentityChanged;

pub(crate) struct PinnedDirectory<'g> {
    relative: PathBuf,
    dirs: Vec<File>,
    _guard: PhantomData<&'g File>,
}

impl PinnedDirectory<'_> {
    /// Root-relative location retained by this descriptor chain.
    pub(crate) fn backup_relative(&self) -> &Path {
        &self.relative
    }

    /// Root-relative key of this directory entry before following its leaf.
    /// Overlay removals use it to distinguish an unlinked name from a
    /// surviving symlink that resolves to the same target.
    pub(crate) fn entry_key(&self, name: &OsStr) -> anyhow::Result<MemberKey> {
        check_basename(name)?;
        MemberKey::new(self.relative.join(name))
    }

    pub(crate) fn file_candidate(&self, name: &OsStr) -> io::Result<bool> {
        let Some(file) = inspect_at(self.dirs.last().expect("pinned directory"), name)? else {
            return Ok(false);
        };
        let meta = file.metadata()?;
        Ok(meta.is_file() || meta.file_type().is_symlink())
    }
}

impl<'g> TreeIo<'g> {
    /// Persist names created directly beneath the held config root.
    pub(crate) fn sync_root(self) -> io::Result<()> {
        self.root.sync_all()
    }

    fn walk(self, dirs: Vec<File>, names: PathBuf, relative: &Path) -> anyhow::Result<Walk<'g>> {
        walk(
            dirs,
            &self.identity.root,
            names,
            relative,
            Some((
                self.identity
                    .canonical_master
                    .file_name()
                    .expect("master filename"),
                self.master,
            )),
            true,
        )
    }
    pub(crate) fn master_key(self) -> MemberKey {
        MemberKey::new(PathBuf::from(
            self.identity
                .canonical_master
                .file_name()
                .expect("validated master filename"),
        ))
        .expect("validated master namespace")
    }

    pub(crate) fn display(self, key: &MemberKey) -> PathBuf {
        self.identity.root.join(&key.0)
    }

    pub(crate) fn directory_display(self, directory: &PinnedDirectory<'_>) -> PathBuf {
        self.identity.root.join(&directory.relative)
    }

    fn entry(self, walk: Walk<'g>) -> anyhow::Result<ResolvedEntry<'g>> {
        ensure!(
            !walk.relative.as_os_str().is_empty(),
            "config path is not a regular file: {}",
            self.identity.root.display()
        );
        Ok(ResolvedEntry {
            key: MemberKey::new(walk.relative.clone())?,
            display: self.identity.root.join(&walk.relative),
            walk,
        })
    }

    fn root_dirs(self) -> io::Result<Vec<File>> {
        Ok(vec![open_at(
            self.root,
            OsStr::new("."),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?])
    }

    /// Retain the locked root for a descriptor-relative read-only walk.
    pub(crate) fn backup_root_directory(self) -> io::Result<PinnedDirectory<'g>> {
        Ok(PinnedDirectory {
            relative: PathBuf::new(),
            dirs: self.root_dirs()?,
            _guard: PhantomData,
        })
    }

    /// Inspect one child without following it.  Backup uses this to reject
    /// aliases and non-regular leaves before handing names to tar.
    pub(crate) fn backup_inspect_child(
        self,
        parent: &PinnedDirectory<'g>,
        name: &OsStr,
    ) -> anyhow::Result<(File, Metadata)> {
        let file = inspect_at(parent.dirs.last().context("pinned backup directory")?, name)?
            .context("backup member disappeared during inventory")?;
        let metadata = file.metadata()?;
        Ok((file, metadata))
    }

    /// Descend only through a real directory held beneath the locked root.
    pub(crate) fn backup_child_directory(
        self,
        parent: &PinnedDirectory<'g>,
        name: &OsStr,
    ) -> anyhow::Result<PinnedDirectory<'g>> {
        check_basename(name)?;
        let (file, metadata) = self.backup_inspect_child(parent, name)?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.is_dir(),
            "backup member is not a directory: {}",
            self.identity
                .root
                .join(&parent.relative)
                .join(name)
                .display()
        );
        // Backup traversal needs only its current directory descriptor; the
        // caller's recursion retains its ancestors.  Avoid O(depth²) FDs.
        let dirs = vec![file];
        Ok(PinnedDirectory {
            relative: parent.relative.join(name),
            dirs,
            _guard: PhantomData,
        })
    }

    /// A readable descriptor for tar's child-only working directory.
    pub(crate) fn backup_root_fd(self) -> io::Result<File> {
        reopen_inspected(self.root, libc::O_RDONLY | libc::O_DIRECTORY)
    }

    /// Alternate master leaf admitted inside the held root, if any.
    pub(crate) fn backup_master_alias(self) -> Option<&'g OsStr> {
        let requested = self.requested.file_name()?;
        let canonical = self.identity.canonical_master.file_name()?;
        (self.root_alias.is_some() && requested != canonical).then_some(requested)
    }

    pub(crate) fn resolve_key(self, key: &MemberKey) -> anyhow::Result<ResolvedEntry<'g>> {
        self.entry(self.walk(self.root_dirs()?, PathBuf::new(), &key.0)?)
    }

    pub(crate) fn resolve_member(self, path: &Path) -> anyhow::Result<ResolvedEntry<'g>> {
        let absolute = self.cwd.join(path);
        if absolute.as_os_str() == self.requested.as_os_str() {
            return self.resolve_key(&self.master_key());
        }
        let relative = strip_prefix_preserving_directory(&absolute, &self.identity.root)
            .or_else(|e| {
                self.root_alias
                    .and_then(|alias| strip_prefix_preserving_directory(&absolute, alias).ok())
                    .ok_or(e)
            })
            .with_context(|| {
                format!(
                    "include target {} escapes config root {}",
                    path.display(),
                    self.identity.root.display()
                )
            })?;
        self.entry(self.walk(self.root_dirs()?, PathBuf::new(), &relative)?)
    }

    pub(crate) fn resolve_from(
        self,
        base: &MemberKey,
        path: &Path,
    ) -> anyhow::Result<ResolvedEntry<'g>> {
        ensure!(!path.is_absolute(), "include must be relative");
        let relative = base.0.parent().unwrap_or(Path::new("")).join(path);
        self.entry(self.walk(self.root_dirs()?, PathBuf::new(), &relative)?)
    }

    pub(crate) fn directory_from(
        self,
        base: &MemberKey,
        path: &Path,
    ) -> anyhow::Result<Option<PinnedDirectory<'g>>> {
        ensure!(!path.is_absolute(), "include directory must be relative");
        let relative = base.0.parent().unwrap_or(Path::new("")).join(path);
        let mut resolved = self.walk(self.root_dirs()?, PathBuf::new(), &relative)?;
        ensure!(
            !resolved
                .relative
                .components()
                .any(|c| reserved_component(c.as_os_str())),
            "reserved config namespace"
        );
        let Some(file) = resolved.file else {
            return Ok(None);
        };
        ensure!(
            file.metadata()?.is_dir(),
            "include parent is not a directory"
        );
        resolved.dirs.push(file);
        Ok(Some(PinnedDirectory {
            relative: resolved.relative,
            dirs: resolved.dirs,
            _guard: PhantomData,
        }))
    }

    pub(crate) fn resolve_in_directory(
        self,
        dir: &PinnedDirectory<'g>,
        name: &OsStr,
    ) -> anyhow::Result<ResolvedEntry<'g>> {
        check_basename(name)?;
        let dirs = dir
            .dirs
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        self.entry(self.walk(dirs, dir.relative.clone(), Path::new(name))?)
    }

    pub(crate) fn open_regular(
        self,
        entry: &ResolvedEntry<'g>,
    ) -> anyhow::Result<(File, Metadata)> {
        let file = entry.walk.file.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("include file not found: {}", entry.display.display()),
            )
        })?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file(),
            "config path is not a regular file: {}",
            entry.display.display()
        );
        Ok((reopen_inspected(file, libc::O_RDONLY)?, meta))
    }

    pub(crate) fn open_no_follow(self, path: &Path) -> anyhow::Result<Option<File>> {
        ensure!(!path.is_absolute(), "expected root-relative file");
        let parent_path = path.parent().unwrap_or(Path::new(""));
        let Some(parent) = self.directory_from(&self.master_key(), parent_path)? else {
            return Ok(None);
        };
        let file = inspect_at(
            parent.dirs.last().context("pinned parent")?,
            path.file_name().context("filename")?,
        )?;
        file.map(|file| {
            if file.metadata()?.file_type().is_symlink() {
                return Err(io::Error::from_raw_os_error(libc::ELOOP).into());
            }
            Ok(reopen_inspected(&file, libc::O_RDONLY)?)
        })
        .transpose()
    }

    pub(crate) fn plan_master_target(self) -> anyhow::Result<TargetPlan<'g>> {
        self.plan_entry(self.resolve_key(&self.master_key())?)
    }

    pub(crate) fn plan_target(self, path: &Path) -> anyhow::Result<TargetPlan<'g>> {
        self.plan_entry(self.resolve_member(path)?)
    }

    /// Plan one exact root-relative file without following symlinks.  The
    /// leaf may be absent or an existing regular, single-link file; callers
    /// use the latter as a descriptor-pinned retry receipt.
    pub(crate) fn plan_root_file_no_follow(self, path: &Path) -> anyhow::Result<TargetPlan<'g>> {
        let key = canonical_root_relative_key(path)?;
        let components: Vec<_> = key
            .0
            .components()
            .map(|component| match component {
                Component::Normal(name) => name.to_os_string(),
                _ => unreachable!("canonical member key contains only normal components"),
            })
            .collect();
        let (leaf, parents) = components
            .split_last()
            .expect("canonical member key is not empty");
        let mut dirs = self.root_dirs()?;
        let mut missing_parents = Vec::new();
        for (index, name) in parents.iter().enumerate() {
            let parent = dirs.last().context("path parent descriptor")?;
            let Some(file) = inspect_at(parent, name)? else {
                missing_parents.extend(parents[index..].iter().cloned());
                break;
            };
            let meta = file.metadata()?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::from_raw_os_error(libc::ELOOP)).with_context(|| {
                    format!(
                        "managed root-relative parent is a symlink: {}",
                        self.identity.root.join(&key.0).display()
                    )
                });
            }
            ensure!(
                meta.is_dir(),
                "managed root-relative parent is not a directory: {}",
                self.identity.root.join(&key.0).display()
            );
            dirs.push(file);
        }
        let file = if missing_parents.is_empty() {
            let parent = dirs.last().context("path parent descriptor")?;
            let file = inspect_at(parent, leaf)?;
            if let Some(file) = &file {
                let meta = file.metadata()?;
                if meta.file_type().is_symlink() {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP)).with_context(|| {
                        format!(
                            "managed root-relative file is a symlink: {}",
                            self.identity.root.join(&key.0).display()
                        )
                    });
                }
                ensure!(
                    meta.is_file() && meta.nlink() == 1,
                    "managed root-relative file must be a regular file with one link: {}",
                    self.identity.root.join(&key.0).display()
                );
            }
            file
        } else {
            None
        };
        let entry = self.entry(Walk {
            relative: key.0,
            file,
            dirs,
            missing_parents,
            _guard: PhantomData,
        })?;
        let metadata = entry.metadata()?;
        let master = (entry.key() == &self.master_key()).then_some(self.master);
        Ok(TargetPlan {
            entry,
            metadata,
            master,
        })
    }

    fn plan_entry(self, entry: ResolvedEntry<'g>) -> anyhow::Result<TargetPlan<'g>> {
        if let Some(file) = &entry.walk.file {
            let meta = file.metadata()?;
            ensure!(
                meta.is_file() && meta.nlink() == 1,
                "managed config member must be a regular file with one link: {}",
                entry.display.display()
            );
        }
        let metadata = entry.metadata()?;
        let master = (entry.key() == &self.master_key()).then_some(self.master);
        Ok(TargetPlan {
            entry,
            metadata,
            master,
        })
    }
}

pub(crate) struct TargetPlan<'g> {
    entry: ResolvedEntry<'g>,
    metadata: Option<Metadata>,
    master: Option<&'g RefCell<Option<File>>>,
}

impl<'g> TargetPlan<'g> {
    pub(crate) fn key(&self) -> &MemberKey {
        self.entry.key()
    }
    pub(crate) fn display(&self) -> &Path {
        self.entry.display()
    }
    pub(crate) fn is_new(&self) -> bool {
        self.entry.walk.file.is_none()
    }
    /// The fstat length captured with this plan's original inode.
    pub(crate) fn original_len(&self) -> Option<u64> {
        self.metadata.as_ref().map(Metadata::len)
    }
    /// Metadata captured from the descriptor-pinned original inode.
    pub(crate) fn original_metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }
    pub(crate) fn read_original(&self) -> anyhow::Result<Option<String>> {
        read_original(self.entry.walk.file.as_ref())
    }

    pub(crate) fn read_original_capped(&self, max_bytes: u64) -> anyhow::Result<CappedRead> {
        read_original_capped(self.entry.walk.file.as_ref(), max_bytes)
    }

    /// Hash the descriptor-pinned original with constant working memory.
    #[cfg(feature = "cluster")]
    pub(crate) fn original_sha256(&self) -> anyhow::Result<Option<[u8; 32]>> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let Some(file) = self.entry.walk.file.as_ref() else {
            return Ok(None);
        };
        let expected_len = self.metadata.as_ref().context("original metadata")?.len();
        let mut reader =
            reopen_inspected(file, libc::O_RDONLY)?.take(expected_len.saturating_add(1));
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut observed = 0_u64;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            observed = observed.saturating_add(read as u64);
            digest.update(&buffer[..read]);
        }
        ensure!(
            observed == expected_len,
            "config target changed size while fingerprinting"
        );
        Ok(Some(digest.finalize().into()))
    }

    pub(crate) fn destination(&self) -> io::Result<DestinationIdentity> {
        self.entry.destination()
    }

    pub(crate) fn materialize(self) -> anyhow::Result<PinnedTarget<'g>> {
        materialize_target(self.entry, self.metadata, self.master)
    }
}

fn materialize_target<'g>(
    mut entry: ResolvedEntry<'g>,
    metadata: Option<Metadata>,
    master: Option<&'g RefCell<Option<File>>>,
) -> anyhow::Result<PinnedTarget<'g>> {
    let ancestor = entry.walk.dirs.pop().context("pinned target ancestor")?;
    let mut parent = reopen_inspected(&ancestor, libc::O_RDONLY | libc::O_DIRECTORY)?;
    for name in &entry.walk.missing_parents {
        parent = mkdir_open(&parent, name)?;
    }
    let name = entry
        .key
        .0
        .file_name()
        .context("target filename")?
        .to_os_string();
    let target = PinnedTarget {
        key: entry.key,
        display: entry.display,
        parent,
        name,
        original: entry.walk.file,
        metadata,
        promoted: RefCell::new(None),
        master,
        _guard: PhantomData,
    };
    target.check_original()?;
    Ok(target)
}

pub(crate) struct PinnedTarget<'g> {
    key: MemberKey,
    display: PathBuf,
    pub(crate) parent: File,
    pub(crate) name: OsString,
    pub(crate) original: Option<File>,
    pub(crate) metadata: Option<Metadata>,
    promoted: RefCell<Option<File>>,
    pub(crate) master: Option<&'g RefCell<Option<File>>>,
    _guard: PhantomData<&'g File>,
}

impl<'g> PinnedTarget<'g> {
    pub(crate) fn display(&self) -> &Path {
        &self.display
    }
    pub(crate) fn check_original(&self) -> io::Result<()> {
        let current = inspect_at(&self.parent, &self.name)?;
        if !same_optional_inode(self.original.as_ref(), current.as_ref())? {
            return Err(io::Error::other("config target changed since its snapshot"));
        }
        Ok(())
    }

    /// Sync the held original or promoted inode, then its pinned parent, and
    /// prove the directory entry still names that exact inode.
    pub(crate) fn sync_held_file_and_parent(&self) -> io::Result<()> {
        let held = self
            .promoted
            .borrow()
            .as_ref()
            .or(self.original.as_ref())
            .ok_or_else(|| io::Error::other("pinned target has no held inode"))?
            .try_clone()?;
        let file = reopen_inspected(&held, libc::O_RDONLY)?;
        file.sync_all()?;
        self.parent.sync_all()?;
        let current = inspect_at(&self.parent, &self.name)?;
        if current.is_some_and(|current| {
            current
                .metadata()
                .and_then(|current| held.metadata().map(|held| same_inode(&held, &current)))
                .unwrap_or(false)
        }) {
            Ok(())
        } else {
            Err(io::Error::other("config target changed since its snapshot"))
        }
    }

    pub(crate) fn record_promotion(&self, file: File, master: Option<File>) {
        *self.promoted.borrow_mut() = Some(file);
        if let Some(slot) = self.master {
            // Only an intentional promotion may advance the guarded master identity.
            *slot.borrow_mut() = master;
        }
    }

    pub(crate) fn rollback_target(&self) -> anyhow::Result<PinnedTarget<'g>> {
        let promoted = self.promoted.borrow();
        let file = promoted
            .as_ref()
            .context("rollback has no retained promoted inode")?;
        let target = Self {
            key: self.key.clone(),
            display: self.display.clone(),
            parent: self.parent.try_clone()?,
            name: self.name.clone(),
            original: Some(file.try_clone()?),
            metadata: self.metadata.clone(),
            promoted: RefCell::new(None),
            master: self.master,
            _guard: PhantomData,
        };
        target
            .check_original()
            .context("rollback target was replaced")?;
        Ok(target)
    }

    pub(crate) fn unlink(&self) -> io::Result<()> {
        self.check_original()?;
        match unlink_at(&self.parent, &self.name) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        if let Some(master) = self.master {
            *master.borrow_mut() = None;
        }
        self.parent.sync_all()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CappedRead {
    Missing,
    Contents(Vec<u8>),
    LimitExceeded { bytes_read: u64 },
}

fn read_original(file: Option<&File>) -> anyhow::Result<Option<String>> {
    use std::io::Read;
    file.map(|file| {
        let mut text = String::new();
        reopen_inspected(file, libc::O_RDONLY)?
            .take(super::loader::MAX_TOTAL_BYTES + 1)
            .read_to_string(&mut text)?;
        ensure!(
            text.len() as u64 <= super::loader::MAX_TOTAL_BYTES,
            "config snapshot exceeds size limit"
        );
        Ok(text)
    })
    .transpose()
}

fn read_original_capped(file: Option<&File>, max_bytes: u64) -> anyhow::Result<CappedRead> {
    use std::io::Read;
    file.map(|file| {
        let mut bytes = Vec::new();
        reopen_inspected(file, libc::O_RDONLY)?
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_bytes {
            Ok(CappedRead::LimitExceeded {
                bytes_read: bytes.len() as u64,
            })
        } else {
            Ok(CappedRead::Contents(bytes))
        }
    })
    .transpose()
    .map(|result| result.unwrap_or(CappedRead::Missing))
}

pub(crate) fn inspect_at(parent: &File, name: &OsStr) -> io::Result<Option<File>> {
    check_basename(name)?;
    match open_at(parent, name, libc::O_PATH, 0) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

pub(crate) fn same_optional_inode(a: Option<&File>, b: Option<&File>) -> io::Result<bool> {
    match (a, b) {
        (Some(a), Some(b)) => Ok(same_inode(&a.metadata()?, &b.metadata()?)),
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

fn parts(path: &Path) -> VecDeque<OsString> {
    let mut parts: VecDeque<_> = path
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| OsString::from_vec(p.to_vec()))
        .collect();
    // A final slash requires the preceding inode to be a directory, even in a link target.
    if path.as_os_str().as_bytes().ends_with(b"/") {
        parts.push_back(OsString::from("."));
    }
    parts
}

fn strip_prefix_preserving_directory(
    path: &Path,
    prefix: &Path,
) -> Result<PathBuf, std::path::StripPrefixError> {
    let mut relative = path.strip_prefix(prefix)?.to_path_buf();
    let bytes = path.as_os_str().as_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
        relative.push(".");
    }
    Ok(relative)
}

fn canonical_root_relative_key(path: &Path) -> anyhow::Result<MemberKey> {
    ensure!(
        !path.is_absolute(),
        "managed target must be root-relative: {}",
        path.display()
    );
    ensure!(
        !path.as_os_str().as_bytes().ends_with(b"/")
            && !path.as_os_str().as_bytes().ends_with(b"/."),
        "managed target must name a file: {}",
        path.display()
    );
    let mut canonical = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => canonical.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("managed target must not contain `..`: {}", path.display());
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("managed target must be root-relative: {}", path.display());
            }
        }
    }
    MemberKey::new(canonical)
}

fn walk<'g>(
    mut dirs: Vec<File>,
    root_path: &Path,
    mut names: PathBuf,
    relative: &Path,
    master: Option<(&OsStr, &RefCell<Option<File>>)>,
    reject_reserved: bool,
) -> anyhow::Result<Walk<'g>> {
    ensure!(!relative.is_absolute(), "expected root-relative path");
    let mut pending = parts(relative);
    let mut missing: Vec<OsString> = Vec::new();
    let mut links = 0;
    let mut steps = 0;
    while let Some(name) = pending.pop_front() {
        steps += 1;
        ensure!(steps <= 8192, "config path exceeds resolution work limit");
        if name == "." {
            if pending.is_empty() && !missing.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT).into());
            }
            continue;
        }
        if name == ".." {
            if !missing.is_empty() {
                missing.pop();
                continue;
            }
            ensure!(
                dirs.len() > 1,
                "path escapes config root {}",
                root_path.display()
            );
            dirs.pop();
            names.pop();
            continue;
        }
        if reject_reserved {
            ensure!(
                !reserved_component(&name),
                "reserved config namespace: {}",
                name.to_string_lossy()
            );
        }
        if !missing.is_empty() {
            missing.push(name);
            continue;
        }
        let parent = dirs.last().context("path parent descriptor")?;
        let inspected = inspect_at(parent, &name)?;
        if let Some((master_name, expected)) = master {
            if names.as_os_str().is_empty()
                && name == master_name
                && !same_optional_inode(expected.borrow().as_ref(), inspected.as_ref())?
            {
                return Err(MasterIdentityChanged.into());
            }
        }
        let Some(file) = inspected else {
            missing.push(name);
            continue;
        };
        let meta = file.metadata()?;
        if meta.file_type().is_symlink() {
            links += 1;
            ensure!(
                links <= 40,
                "config path contains a symlink cycle or exceeds 40 links"
            );
            let target = read_link(&file)?;
            let target = if target.is_absolute() {
                let relative_target = strip_prefix_preserving_directory(&target, root_path)
                    .with_context(|| {
                        format!(
                            "symlink target {} escapes config root {}",
                            target.display(),
                            root_path.display()
                        )
                    })?;
                dirs.truncate(1);
                names.clear();
                relative_target
            } else {
                target
            };
            let mut next = parts(&target);
            next.append(&mut pending);
            pending = next;
            continue;
        }
        names.push(&name);
        if pending.is_empty() {
            return Ok(Walk {
                relative: names,
                file: Some(file),
                dirs,
                missing_parents: Vec::new(),
                _guard: PhantomData,
            });
        }
        if !meta.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR)).with_context(|| {
                format!(
                    "config path component is not a directory: {}",
                    root_path.join(&names).display()
                )
            });
        }
        dirs.push(file);
    }
    if missing.is_empty() {
        let file = dirs.pop().context("resolved directory")?;
        Ok(Walk {
            relative: names,
            file: Some(file),
            dirs,
            missing_parents: Vec::new(),
            _guard: PhantomData,
        })
    } else {
        names.extend(&missing);
        missing.pop();
        Ok(Walk {
            relative: names,
            file: None,
            dirs,
            missing_parents: missing,
            _guard: PhantomData,
        })
    }
}

pub(crate) fn resolve_global_from(requested: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
    Ok(resolve_global_entry_from(requested, cwd)?.0)
}

pub(crate) fn resolve_global_entry_from(
    requested: &Path,
    cwd: &Path,
) -> anyhow::Result<(PathBuf, Option<File>)> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let absolute = cwd.join(requested);
    let resolved = walk(
        vec![root],
        Path::new("/"),
        PathBuf::new(),
        &strip_prefix_preserving_directory(&absolute, Path::new("/"))?,
        None,
        true,
    )?;
    Ok((Path::new("/").join(resolved.relative), resolved.file))
}

/// Resolve an external input through held descriptors without applying the
/// config tree's reserved-component namespace policy.
pub(crate) fn resolve_external_entry_from(
    requested: &Path,
    cwd: &Path,
) -> anyhow::Result<(PathBuf, Option<File>)> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let absolute = cwd.join(requested);
    let resolved = walk(
        vec![root],
        Path::new("/"),
        PathBuf::new(),
        &strip_prefix_preserving_directory(&absolute, Path::new("/"))?,
        None,
        false,
    )?;
    Ok((Path::new("/").join(resolved.relative), resolved.file))
}

/// Resolve an arbitrary directory and retain the descriptors needed to open
/// it or create its missing tail without returning to the original pathname.
pub(crate) fn plan_external_directory_from(
    requested: &Path,
    cwd: &Path,
) -> anyhow::Result<ExternalDirectoryPlan> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let absolute = cwd.join(requested);
    // Unlike general resolution, this API always plans a directory.  The
    // terminal marker is useful when resolving files, but must not turn a
    // missing `output/` into a missing `output/.` component.
    let absolute = strip_terminal_directory_marker(&absolute);
    let resolved = walk(
        vec![root],
        Path::new("/"),
        PathBuf::new(),
        &strip_prefix_preserving_directory(&absolute, Path::new("/"))?,
        None,
        false,
    )?;
    let mut missing = resolved.missing_parents;
    if resolved.file.is_none() {
        missing.push(
            resolved
                .relative
                .file_name()
                .context("external directory has no final component")?
                .to_os_string(),
        );
    }
    Ok(ExternalDirectoryPlan {
        resolved: Path::new("/").join(resolved.relative),
        file: resolved.file,
        dirs: resolved.dirs,
        missing,
    })
}

fn strip_terminal_directory_marker(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let mut end = bytes.len();
    loop {
        if (end > 1 && bytes[..end].ends_with(b"/")) || (end > 2 && bytes[..end].ends_with(b"/.")) {
            end -= 1;
        } else {
            break;
        }
    }
    if end == bytes.len() {
        path.to_path_buf()
    } else {
        PathBuf::from(OsString::from_vec(bytes[..end].to_vec()))
    }
}

fn read_link(file: &File) -> anyhow::Result<PathBuf> {
    let mut bytes = vec![0; 256];
    loop {
        let count = unsafe {
            libc::readlinkat(
                file.as_raw_fd(),
                c"".as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if (count as usize) < bytes.len() {
            bytes.truncate(count as usize);
            return Ok(PathBuf::from(OsString::from_vec(bytes)));
        }
        ensure!(
            bytes.len() < 1024 * 1024,
            "symlink target exceeds path limit"
        );
        bytes.resize(bytes.len() * 2, 0);
    }
}

pub(crate) fn for_each_dir_name(
    dir: &PinnedDirectory<'_>,
    mut visit: impl FnMut(&OsStr) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let file = reopen_inspected(
        dir.dirs.last().context("pinned directory")?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
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
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(raw);
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(io::Error::last_os_error().into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            visit(OsStr::from_bytes(name))?;
        }
    }
    Ok(())
}

pub(crate) fn mkdir_open(parent: &File, name: &OsStr) -> anyhow::Result<File> {
    check_basename(name)?;
    #[cfg(test)]
    super::write_lock::test_event(super::write_lock::TestEvent::BeforeMkdir);
    let name_c = CString::new(name.as_bytes())?;
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o750) };
    let created = rc == 0;
    if !created {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err.into());
        }
    }
    let next = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    if created {
        preserve_owner(&next, &parent.metadata()?)?;
        next.set_permissions(std::fs::Permissions::from_mode(0o750))?;
        next.sync_all()?;
        parent.sync_all()?;
    }
    Ok(next)
}

pub(crate) fn check_basename(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.contains(&b'/')
        || bytes.contains(&0)
        || name == "."
        || name == ".."
    {
        return Err(io::Error::other("expected one ordinary basename"));
    }
    Ok(())
}

pub(crate) fn unlink_at(parent: &File, name: &OsStr) -> io::Result<()> {
    check_basename(name)?;
    let name = CString::new(name.as_bytes())?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn rename_at(
    source_parent: &File,
    from: &OsStr,
    parent: &File,
    to: &OsStr,
) -> io::Result<()> {
    check_basename(from)?;
    check_basename(to)?;
    let from = CString::new(from.as_bytes())?;
    let to = CString::new(to.as_bytes())?;
    if unsafe {
        libc::renameat(
            source_parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Atomically promote a name only when its destination is absent.
///
/// Linux' `renameat2(RENAME_NOREPLACE)` is required.  Unsupported kernels or
/// filesystems return an `Unsupported` error; callers must not retry with
/// replacement semantics.
pub(crate) fn rename_noreplace_at(
    source_parent: &File,
    from: &OsStr,
    parent: &File,
    to: &OsStr,
) -> io::Result<()> {
    check_basename(from)?;
    check_basename(to)?;
    let from = CString::new(from.as_bytes())?;
    let to = CString::new(to.as_bytes())?;
    #[cfg(target_os = "linux")]
    {
        const RENAME_NOREPLACE: u32 = 1;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("renameat2(RENAME_NOREPLACE) unavailable: {error}"),
            ));
        }
        Err(error)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source_parent, from, parent, to);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "renameat2(RENAME_NOREPLACE) requires Linux",
        ))
    }
}

#[cfg(test)]
mod tests;
