//! Receipt of a `config relocate` run: its format, its file check and the
//! fence that keeps every normal access away while a run is incomplete.
//!
//! The fence decides on the name of the active receipt alone. It never opens
//! or parses the file, so no owner, mode or content change can lower it and
//! no parser runs in the daemon.

use std::ffi::OsStr;
use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};

use super::tree_io::{inspect_at, rename_at, rename_noreplace_at, unlink_at};
use super::write_lock::{open_at, reopen_inspected};

/// The active receipt. Its presence in the state directory is the fence.
pub(crate) const ACTIVE: &str = ".warden-relocate.json";
/// The receipt of the last complete run.
pub(crate) const DONE: &str = ".warden-relocate.done.json";
pub(crate) const FORMAT: u32 = 1;
pub(crate) const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunState {
    Planned,
    InProgress,
    Complete,
}

/// Identity of a root or a renamed object. Equality compares the inode alone,
/// as for policy transaction records: `st_dev` is not stable across boots.
/// `device` stays in the receipt format; the same-filesystem check before a
/// run reads it live. Accepted ceiling: another filesystem of the same type
/// mounted in place with the same inodes matches, and so does a btrfs
/// snapshot of the config subvolume swapped in place.
#[derive(Debug, Clone, Copy, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inode {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl PartialEq for Inode {
    fn eq(&self, other: &Self) -> bool {
        self.inode == other.inode
    }
}

impl Inode {
    pub(crate) fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }

    pub(crate) fn pair(self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Scheme {
    Plain,
    Domain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreRename {
    pub(crate) base: String,
    pub(crate) scheme: Scheme,
    pub(crate) old: String,
    pub(crate) new: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    CreateRoot,
    LockTarget,
    Rename {
        from_dir: PathBuf,
        from: String,
        to_dir: PathBuf,
        to: String,
        object: Inode,
    },
    CreateLists,
    Rebind,
    DeleteCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    pub(crate) number: u8,
    pub(crate) action: Action,
    pub(crate) done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) format: u32,
    pub(crate) direction: Direction,
    pub(crate) state: RunState,
    pub(crate) binary_version: String,
    pub(crate) source: PathBuf,
    pub(crate) source_inode: Inode,
    pub(crate) target: PathBuf,
    /// Known from plan time when the target root existed, otherwise from step 1.
    pub(crate) target_inode: Option<Inode>,
    pub(crate) master: String,
    pub(crate) target_root_existed: bool,
    pub(crate) target_lists_existed: bool,
    pub(crate) target_lock_existed: bool,
    /// Reverse runs: whether the forward run created the `/etc` root and its `lists`.
    pub(crate) forward_created_root: bool,
    pub(crate) forward_created_lists: bool,
    pub(crate) stores: Vec<StoreRename>,
    pub(crate) steps: Vec<Step>,
}

/// A receipt file as relocate found it.
pub(crate) enum Loaded {
    Absent,
    Valid(Box<Receipt>),
    /// The file exists but fails the file check. `parsed` holds its content
    /// when it still parses, so the operator can match it against the tree.
    Invalid {
        parsed: Option<Box<Receipt>>,
        problem: String,
    },
}

/// Refuse while an active relocate receipt exists in `state`, the
/// node-local state directory of the config root being accessed.
pub(crate) fn refuse_if_active(state: &Path) -> anyhow::Result<()> {
    let path = state.join(ACTIVE);
    let refusal = || {
        format!(
            "RelocateInProgress: {} exists, so a `config relocate` run is incomplete and this node stays fenced; run `{} config relocate --dry-run` as root to see the rollback command",
            path.display(),
            binary()
        )
    };
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!(refusal()),
        Err(error) => Err(anyhow::Error::new(error).context(refusal())),
    }
}

/// The binary the operator runs relocate with, for printed commands.
pub(crate) fn binary() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "warden".into())
}

/// Read and check one receipt file in the state directory. `owner` is the
/// required uid and gid: root in production.
pub(crate) fn read(state: &File, name: &str, owner: (u32, u32)) -> anyhow::Result<Loaded> {
    let Some(inspected) = inspect_at(state, OsStr::new(name))? else {
        return Ok(Loaded::Absent);
    };
    let meta = inspected.metadata()?;
    if !meta.is_file() {
        return Ok(Loaded::Invalid {
            parsed: None,
            problem: format!("{name} is not a regular file"),
        });
    }
    let mut problems = Vec::new();
    if meta.nlink() != 1 {
        problems.push(format!("{} links instead of 1", meta.nlink()));
    }
    if (meta.uid(), meta.gid()) != owner {
        problems.push(format!(
            "owner {}:{} instead of {}:{}",
            meta.uid(),
            meta.gid(),
            owner.0,
            owner.1
        ));
    }
    if meta.mode() & 0o7777 != 0o600 {
        problems.push(format!("mode {:o} instead of 600", meta.mode() & 0o7777));
    }
    if meta.len() > MAX_BYTES {
        return Ok(Loaded::Invalid {
            parsed: None,
            problem: format!("{name} exceeds {MAX_BYTES} bytes"),
        });
    }
    let mut bytes = Vec::new();
    reopen_inspected(&inspected, libc::O_RDONLY)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let parsed = serde_json::from_slice::<Receipt>(&bytes)
        .ok()
        .filter(|receipt| receipt.format == FORMAT)
        .map(Box::new);
    if parsed.is_none() {
        problems.push("content does not parse as a relocate receipt".into());
    }
    match (parsed, problems.is_empty()) {
        (Some(receipt), true) => Ok(Loaded::Valid(receipt)),
        (parsed, _) => Ok(Loaded::Invalid {
            parsed,
            problem: format!("{name}: {}", problems.join(", ")),
        }),
    }
}

/// Write a receipt through `<name>.next`: exclusive create, fsync, rename,
/// directory fsync. A torn write never appears under `name`. `replace` is
/// false only for the first write of the active receipt.
pub(crate) fn write(
    state: &File,
    name: &str,
    receipt: &Receipt,
    owner: (u32, u32),
    replace: bool,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(receipt)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "relocate receipt exceeds {MAX_BYTES} bytes"
    );
    let stage = format!("{name}.next");
    remove_stage(state, &stage)?;
    let mut file = open_at(
        state,
        OsStr::new(&stage),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .with_context(|| format!("create {stage}"))?;
    // A setgid state directory would otherwise give the stage its group.
    // SAFETY: geteuid has no preconditions; the descriptor is open.
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(file.as_raw_fd(), owner.0, owner.1) } != 0
    {
        return Err(io::Error::last_os_error()).context("own the relocate receipt stage");
    }
    file.set_permissions(Permissions::from_mode(0o600))?;
    let meta = file.metadata()?;
    ensure!(
        (meta.uid(), meta.gid()) == owner,
        "relocate receipt stage is owned by {}:{}, not {}:{}",
        meta.uid(),
        meta.gid(),
        owner.0,
        owner.1
    );
    file.write_all(&bytes)?;
    file.sync_all()?;
    if replace {
        rename_at(state, OsStr::new(&stage), state, OsStr::new(name))?;
    } else if let Err(error) =
        rename_noreplace_at(state, OsStr::new(&stage), state, OsStr::new(name))
    {
        remove_stage(state, &stage)?;
        return Err(anyhow::Error::new(error).context(format!("publish {name}")));
    }
    state.sync_all()?;
    Ok(())
}

/// Remove a stale `.next` stage left by an interrupted write.
pub(crate) fn remove_stage(state: &File, stage: &str) -> anyhow::Result<()> {
    match unlink_at(state, OsStr::new(stage)) {
        Ok(()) => {
            state.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove stale {stage}")),
    }
}

/// Commit a complete run: the active receipt becomes the done record.
pub(crate) fn retire(state: &File) -> anyhow::Result<()> {
    rename_at(state, OsStr::new(ACTIVE), state, OsStr::new(DONE))
        .with_context(|| format!("rename {ACTIVE} to {DONE}"))?;
    state.sync_all()?;
    Ok(())
}

/// End a rollback: drop the fence and keep the done record as it is.
pub(crate) fn remove_active(state: &File) -> anyhow::Result<()> {
    match unlink_at(state, OsStr::new(ACTIVE)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove {ACTIVE}")),
    }
    state.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn receipt() -> Receipt {
        Receipt {
            format: FORMAT,
            direction: Direction::Forward,
            state: RunState::Planned,
            binary_version: "test".into(),
            source: "/var/lib/purge-warden".into(),
            source_inode: Inode {
                device: 1,
                inode: 2,
            },
            target: "/etc/purge-warden".into(),
            target_inode: None,
            master: "config.toml".into(),
            target_root_existed: false,
            target_lists_existed: false,
            target_lock_existed: false,
            forward_created_root: false,
            forward_created_lists: false,
            stores: Vec::new(),
            steps: vec![Step {
                number: 8,
                action: Action::DeleteCapability,
                done: false,
            }],
        }
    }

    fn owner() -> (u32, u32) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    #[test]
    fn inode_identity_ignores_the_device_and_keeps_it_in_the_format() {
        let inode = |device, inode| Inode { device, inode };
        assert_eq!(inode(1, 5), inode(2, 5));
        assert_ne!(inode(1, 5), inode(1, 6));
        assert_eq!(inode(1, 5).pair(), (1, 5));
        assert_eq!(
            serde_json::to_value(inode(1, 5)).unwrap(),
            serde_json::json!({"device": 1, "inode": 5})
        );
    }

    #[test]
    fn fence_refuses_any_entry_and_passes_only_when_absent() {
        let state = tempfile::tempdir().unwrap();
        refuse_if_active(state.path()).unwrap();
        refuse_if_active(&state.path().join("missing")).unwrap();
        let active = state.path().join(ACTIVE);
        for make in [
            (|path: &Path| std::fs::write(path, b"")) as fn(&Path) -> io::Result<()>,
            |path| std::fs::write(path, b"not json"),
            |path| std::fs::create_dir(path),
            |path| symlink("/nonexistent", path),
        ] {
            make(&active).unwrap();
            let error = refuse_if_active(state.path()).unwrap_err().to_string();
            assert!(error.contains("RelocateInProgress"), "{error}");
            assert!(error.contains("config relocate --dry-run"), "{error}");
            if active.is_dir() && !active.is_symlink() {
                std::fs::remove_dir(&active).unwrap();
            } else {
                std::fs::remove_file(&active).unwrap();
            }
        }
        std::fs::write(&active, b"{}").unwrap();
        std::fs::set_permissions(&active, Permissions::from_mode(0o000)).unwrap();
        assert!(refuse_if_active(state.path()).is_err());
        std::fs::remove_file(&active).unwrap();
        // The done record and stale stages never raise the fence.
        for name in [DONE, ".warden-relocate.json.next"] {
            std::fs::write(state.path().join(name), b"{}").unwrap();
        }
        refuse_if_active(state.path()).unwrap();
    }

    #[test]
    fn receipts_round_trip_and_fail_the_file_check_on_drift() {
        let dir = tempfile::tempdir().unwrap();
        let state = File::open(dir.path()).unwrap();
        assert!(matches!(
            read(&state, ACTIVE, owner()).unwrap(),
            Loaded::Absent
        ));
        write(&state, ACTIVE, &receipt(), owner(), false).unwrap();
        assert!(write(&state, ACTIVE, &receipt(), owner(), false).is_err());
        let Loaded::Valid(loaded) = read(&state, ACTIVE, owner()).unwrap() else {
            panic!("valid receipt expected");
        };
        assert_eq!(*loaded, receipt());
        assert!(!dir.path().join(".warden-relocate.json.next").exists());

        std::fs::set_permissions(dir.path().join(ACTIVE), Permissions::from_mode(0o644)).unwrap();
        let Loaded::Invalid { parsed, problem } = read(&state, ACTIVE, owner()).unwrap() else {
            panic!("mode drift must fail the file check");
        };
        assert!(
            parsed.is_some() && problem.contains("mode 644"),
            "{problem}"
        );
        let Loaded::Invalid { problem, .. } =
            read(&state, ACTIVE, (owner().0 + 1, owner().1)).unwrap()
        else {
            panic!("owner drift must fail the file check");
        };
        assert!(problem.contains("owner"), "{problem}");

        std::fs::write(dir.path().join(DONE), b"{").unwrap();
        std::fs::set_permissions(dir.path().join(DONE), Permissions::from_mode(0o600)).unwrap();
        let Loaded::Invalid { parsed, .. } = read(&state, DONE, owner()).unwrap() else {
            panic!("unparsable receipt must fail the file check");
        };
        assert!(parsed.is_none());

        std::fs::set_permissions(dir.path().join(ACTIVE), Permissions::from_mode(0o600)).unwrap();
        retire(&state).unwrap();
        assert!(!dir.path().join(ACTIVE).exists());
        assert!(matches!(
            read(&state, DONE, owner()).unwrap(),
            Loaded::Valid(_)
        ));
        remove_active(&state).unwrap();
    }
}
