use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;

use super::write_lock::{open_at, MigrationWriteLock};

/// Resolve the node-local mutable-state directory for a config root.
///
/// System configurations beneath `/etc/<package>` keep mutable state beneath
/// `/var/lib/<package>`. Development and self-contained installations keep it
/// beside the configuration.
pub(crate) fn for_config_parent(config_parent: &Path) -> PathBuf {
    if let Ok(stripped) = config_parent.strip_prefix("/etc") {
        if let Some(first) = stripped.components().next() {
            return Path::new("/var/lib").join(first.as_os_str());
        }
    }
    config_parent.to_path_buf()
}

/// Retain the locked root for self-contained state, or open the separate system
/// state directory without following symlinks in any path component.
pub(crate) fn open_for_migration(guard: &MigrationWriteLock) -> anyhow::Result<File> {
    let config_parent = &guard.identity().root;
    let path = for_config_parent(config_parent);
    if path == *config_parent {
        return guard
            .tree_io()
            .root
            .try_clone()
            .context("cannot retain locked node-local state directory");
    }
    open_directory(&path)
        .with_context(|| format!("cannot open node-local state directory {}", path.display()))
}

fn open_directory(path: &Path) -> anyhow::Result<File> {
    anyhow::ensure!(path.is_absolute(), "state directory path must be absolute");
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let access = if components.peek().is_none() {
                    libc::O_RDONLY
                } else {
                    libc::O_PATH
                };
                directory = open_at(&directory, name, access | libc::O_DIRECTORY, 0)?;
            }
            _ => anyhow::bail!("state directory path must be canonical"),
        }
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_roots_remain_self_contained() {
        assert_eq!(
            for_config_parent(Path::new("/tmp/warden")),
            Path::new("/tmp/warden")
        );
        assert_eq!(
            for_config_parent(Path::new("/var/lib/purge-warden")),
            Path::new("/var/lib/purge-warden")
        );
    }

    #[test]
    fn etc_roots_use_the_matching_var_lib_directory() {
        assert_eq!(
            for_config_parent(Path::new("/etc/purge-warden")),
            Path::new("/var/lib/purge-warden")
        );
        assert_eq!(
            for_config_parent(Path::new("/etc/purge-warden/staging")),
            Path::new("/var/lib/purge-warden")
        );
    }

    #[test]
    fn opens_a_self_contained_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let directory = open_for_migration(&guard).unwrap();
        assert!(directory.metadata().unwrap().is_dir());
        assert!(super::super::tree_io::same_inode(
            &directory.metadata().unwrap(),
            &guard.tree_io().root.metadata().unwrap()
        ));
    }

    #[test]
    fn self_contained_state_keeps_the_locked_inode_after_path_replacement() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let guard =
            super::super::write_lock::acquire_for_migration(&root.join("config.toml")).unwrap();
        std::fs::rename(&root, base.path().join("detached")).unwrap();
        std::fs::create_dir(&root).unwrap();

        let directory = open_for_migration(&guard).unwrap();
        assert!(super::super::tree_io::same_inode(
            &directory.metadata().unwrap(),
            &guard.tree_io().root.metadata().unwrap()
        ));
        assert!(!super::super::tree_io::same_inode(
            &directory.metadata().unwrap(),
            &std::fs::metadata(root).unwrap()
        ));
    }

    #[test]
    fn refuses_a_symlink_as_the_effective_state_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let alias = root.path().join("state");
        symlink(target.path(), &alias).unwrap();

        assert!(open_directory(&alias).is_err());
        std::fs::create_dir(target.path().join("nested")).unwrap();
        assert!(open_directory(&alias.join("nested")).is_err());
    }
}
