use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;

use rand_core::RngCore;

use crate::config::tree_io::{inspect_at, same_inode, unlink_at};
use crate::config::write_lock::{open_at, WRITE_STAGE_PREFIX};

pub(super) fn payload() -> &'static OsStr {
    OsStr::new("payload")
}

pub(super) struct StagingDirectory<'a> {
    pub file: File,
    pub name: OsString,
    parent: &'a File,
    /// Only enabled after this invocation created `payload` and retained its
    /// inode.  A name in a staging directory is not authority to unlink it.
    payload: Option<(u64, u64)>,
}

impl<'a> StagingDirectory<'a> {
    pub fn create(parent: &'a File) -> io::Result<Self> {
        for _ in 0..32 {
            let mut random = [0; 16];
            rand_core::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let name = OsString::from(format!(
                "{WRITE_STAGE_PREFIX}{:032x}",
                u128::from_ne_bytes(random)
            ));
            let c_name = CString::new(name.as_bytes())?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
            // Without a held descriptor there is no safe receipt for a
            // cleanup.  Another writer may have replaced the name after
            // mkdirat, so an open failure leaves it for an operator.
            let file = open_at(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let initial = file.metadata()?;
            // mkdirat may inherit setgid and a group from its parent. That is
            // legitimate across Linux and BSD; verify only properties that
            // establish this newly held directory is private before chmod.
            let mode = initial.mode() & 0o7777;
            if !initial.is_dir()
                || initial.uid() != unsafe { libc::geteuid() }
                || (mode != 0o700 && mode != 0o2700)
            {
                return Err(io::Error::other(
                    "unsafe initial config staging directory ownership, type, or mode",
                ));
            }
            let staging = Self {
                file,
                name,
                parent,
                payload: None,
            };
            // A setgid parent can add S_ISGID despite mkdirat's 0700 mode.
            // Clear it explicitly so the staging directory stays private.
            staging
                .file
                .set_permissions(std::fs::Permissions::from_mode(0o700))?;
            let metadata = staging.file.metadata()?;
            // Parent writers may rename this directory, but cannot redirect its held contents.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
                return Err(io::Error::other(
                    "unsafe config staging directory ownership or mode",
                ));
            }
            return Ok(staging);
        }
        Err(io::Error::other(
            "cannot allocate a unique config staging directory",
        ))
    }

    pub(super) fn record_payload(&mut self, payload: &File) -> io::Result<()> {
        let metadata = payload.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::other(
                "unsafe staging payload type or link count",
            ));
        }
        self.payload = Some((metadata.dev(), metadata.ino()));
        Ok(())
    }
}

impl Drop for StagingDirectory<'_> {
    fn drop(&mut self) {
        if let Some((dev, ino)) = self.payload {
            let _ = inspect_at(&self.file, payload()).and_then(|current| {
                if current.is_some_and(|file| {
                    file.metadata()
                        .map(|meta| (meta.dev(), meta.ino()) == (dev, ino))
                        .unwrap_or(false)
                }) {
                    unlink_at(&self.file, payload())
                } else {
                    Ok(())
                }
            });
        }
        let same = || -> io::Result<bool> {
            Ok(inspect_at(self.parent, &self.name)?.is_some_and(|file| {
                file.metadata()
                    .and_then(|current| {
                        self.file.metadata().map(|held| same_inode(&held, &current))
                    })
                    .unwrap_or(false)
            }))
        };
        if same().unwrap_or(false) {
            if let Ok(name) = CString::new(self.name.as_bytes()) {
                // Never recursively sweep a name that an external writer can replace.
                unsafe {
                    libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                }
            }
        }
    }
}
