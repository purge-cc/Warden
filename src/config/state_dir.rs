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
    #[cfg(test)]
    if let Some(state) = test_mapping(config_parent) {
        return state;
    }
    if let Ok(stripped) = config_parent.strip_prefix("/etc") {
        if let Some(first) = stripped.components().next() {
            return Path::new("/var/lib").join(first.as_os_str());
        }
    }
    config_parent.to_path_buf()
}

/// Retain the locked root for self-contained state, or open the separate system
/// state directory.
pub(crate) fn open_for_migration(guard: &MigrationWriteLock) -> anyhow::Result<File> {
    open_for_root(&guard.identity().root, guard.tree_io().root)
}

/// [`open_for_migration`] for any guard: `config_parent` is the locked
/// canonical root and `root` its held descriptor.
///
/// The system state directory's own entry and its ancestors live in root-owned
/// directories such as `/var/lib`, so root-made symlinks there are resolved
/// first, as `warden init` does (`InitLayout::anchored`). This assumes root
/// points them only into root-controlled trees. The resolved path is then
/// opened without following any symlink, so a swap fails closed, and callers
/// reach entries below it only through no-follow `open_at`.
pub(crate) fn open_for_root(config_parent: &Path, root: &File) -> anyhow::Result<File> {
    let path = for_config_parent(config_parent);
    if path == *config_parent {
        return root
            .try_clone()
            .context("cannot retain locked node-local state directory");
    }
    super::write_lock::resolve_path(&path)
        .and_then(|resolved| open_directory(&resolved))
        .with_context(|| format!("cannot open node-local state directory {}", path.display()))
}

/// Open an existing absolute directory without following symlinks in any
/// component. Nothing is created.
pub(crate) fn open_directory(path: &Path) -> anyhow::Result<File> {
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
static TEST_MAPPINGS: std::sync::Mutex<Vec<(PathBuf, PathBuf)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn test_mapping(config_parent: &Path) -> Option<PathBuf> {
    TEST_MAPPINGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(root, _)| config_parent.starts_with(root))
        .map(|(_, state)| state.clone())
}

/// Map a temporary `/etc`-style config root to a temporary state directory,
/// so tests get the production shape where state lives apart from the root.
#[cfg(test)]
pub(crate) struct TestMapping(PathBuf);

#[cfg(test)]
pub(crate) fn map_for_test(config_root: &Path, state: &Path) -> TestMapping {
    TEST_MAPPINGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((config_root.to_path_buf(), state.to_path_buf()));
    TestMapping(config_root.to_path_buf())
}

#[cfg(test)]
impl Drop for TestMapping {
    fn drop(&mut self) {
        TEST_MAPPINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(root, _)| root != &self.0);
    }
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
    fn test_mapping_moves_state_out_of_a_temporary_root() {
        let base = tempfile::tempdir().unwrap();
        let etc = base.path().join("etc");
        let state = base.path().join("var");
        let _mapping = map_for_test(&etc, &state);
        assert_eq!(for_config_parent(&etc), state);
        assert_eq!(for_config_parent(&etc.join("nested")), state);
        assert_eq!(for_config_parent(&state), state);
    }

    /// A root-made symlink at the state directory entry or an ancestor is
    /// resolved; the opened directory is the target.
    #[test]
    fn opens_a_system_state_directory_through_root_owned_symlinks() {
        use std::os::unix::fs::symlink;

        for linked in ["var/lib", "var/lib/purge-warden"] {
            let base = tempfile::tempdir().unwrap();
            let etc = base.path().join("etc/purge-warden");
            std::fs::create_dir_all(&etc).unwrap();
            let state = base.path().join("var/lib/purge-warden");
            let link = base.path().join(linked);
            let real = base.path().join("mnt/data");
            std::fs::create_dir_all(&real).unwrap();
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            symlink(&real, &link).unwrap();
            let real_state = real.join(state.strip_prefix(&link).unwrap());
            std::fs::create_dir_all(&real_state).unwrap();
            let _mapping = map_for_test(&etc, &state);

            let guard =
                super::super::write_lock::acquire_for_migration(&etc.join("config.toml")).unwrap();
            let directory = open_for_migration(&guard).unwrap();
            assert!(
                super::super::tree_io::same_inode(
                    &directory.metadata().unwrap(),
                    &std::fs::metadata(&real_state).unwrap()
                ),
                "{linked}"
            );
        }
    }

    #[test]
    fn open_directory_refuses_a_symlink_in_any_component() {
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
