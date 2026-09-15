//! Operator-authored rule files: grammar, on-disk form, and the store the
//! profile compiler reads.

pub mod grammar;
pub mod io;

pub use grammar::{compose_line, normalise_domain, parse_pack_line, GrammarError, PackLine};
pub use io::{
    add_rule, create_pack, read_pack, read_pack_lines, remove_rule, replace_rule_at_line,
    write_pack, AddOutcome, CompiledCustomList, PackLineView, PackReadError, PackWriteError,
};

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io as std_io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::schema::{CustomList, Id};

/// Every declared custom list, parsed, keyed by id.
///
/// Built once per config load and handed to the profile compiler as a
/// parameter, so profile compilation performs no file I/O — the 60-second
/// schedule tick rebuilds every profile and must not read N files a minute.
pub type CustomListStore = BTreeMap<Id, CompiledCustomList>;
pub(crate) type PackBodies = BTreeMap<Id, Arc<str>>;
pub(crate) type PackReadFailures = Vec<(Id, PackReadError)>;

/// Candidate pack bodies supplied separately from the TOML include overlay.
/// `None` represents a planned deletion.
#[derive(Debug, Clone, Default)]
pub struct PackOverlay {
    bodies: BTreeMap<Id, Option<Vec<u8>>>,
    ignored_stages: BTreeSet<PathBuf>,
}

impl PackOverlay {
    pub fn stage(&mut self, id: Id, bytes: Vec<u8>) -> Option<Option<Vec<u8>>> {
        self.bodies.insert(id, Some(bytes))
    }

    pub fn omit(&mut self, id: Id) -> Option<Option<Vec<u8>>> {
        self.bodies.insert(id, None)
    }

    /// Ignore one already-verified transaction stage during flat inventory.
    /// Ordinary loads never carry this exact, bounded exclusion set.
    pub(crate) fn ignore_verified_stage(&mut self, relative: PathBuf) -> anyhow::Result<()> {
        let mut components = relative.components();
        anyhow::ensure!(
            !relative.is_absolute()
                && components
                    .next()
                    .is_some_and(|part| part.as_os_str() == "packs")
                && components.next().is_some()
                && components.next().is_none(),
            "pack stage path must be exactly packs/<basename>"
        );
        let name = relative
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow::anyhow!("pack stage name is not UTF-8"))?;
        anyhow::ensure!(is_write_stage_name(name), "invalid pack write-stage name");
        anyhow::ensure!(
            self.ignored_stages.contains(&relative) || self.ignored_stages.len() < MAX_PACK_MEMBERS,
            "pack write-stage exclusion budget exceeded"
        );
        self.ignored_stages.insert(relative);
        Ok(())
    }

    fn get(&self, id: &Id) -> Option<Option<&[u8]>> {
        self.bodies
            .get(id)
            .map(|body| body.as_ref().map(Vec::as_slice))
    }

    pub(crate) fn ignored_stages(&self) -> &BTreeSet<PathBuf> {
        &self.ignored_stages
    }
}

const MAX_UNSUPPORTED_PACK_PATHS: usize = 16;
pub(crate) const MAX_PACK_MEMBERS: usize = 4096;
pub(crate) const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;

/// A `packs/` entry that cannot participate in the flat, descriptor-safe
/// Custom List store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedPackTree {
    paths: Vec<PathBuf>,
    omitted: usize,
    member_limit_exceeded: Option<usize>,
}

impl UnsupportedPackTree {
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    pub fn omitted(&self) -> usize {
        self.omitted
    }

    /// The configured member cap when the otherwise-flat tree exceeded it.
    pub(crate) fn member_limit_exceeded(&self) -> Option<usize> {
        self.member_limit_exceeded
    }
}

impl std::fmt::Display for UnsupportedPackTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported flat Custom List pack tree")?;
        if !self.paths.is_empty() {
            write!(
                f,
                ": {}",
                self.paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        if self.omitted != 0 {
            write!(f, " (and {} more)", self.omitted)?;
        }
        if let Some(limit) = self.member_limit_exceeded {
            write!(f, "; pack inventory exceeds the {limit}-member cap")?;
        }
        write!(
            f,
            "; packs/ accepts only single-link regular <id>.txt files"
        )
    }
}

impl std::error::Error for UnsupportedPackTree {}

/// Validate a trusted staging tree before it is offered to restore.
///
/// The path may be absent. If present, `packs/` itself must be a real
/// directory and every immediate member must be a single-link regular file
/// named from a valid Custom List id. Nested trees and special files are not
/// interpreted or recursively cleaned up.
pub fn validate_flat_pack_tree(config_root: &Path) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    validate_flat_pack_tree_with_cap(config_root, MAX_PACK_MEMBERS)
}

fn validate_flat_pack_tree_with_cap(
    config_root: &Path,
    max_members: usize,
) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    let dir = pack_dir(config_root);
    let metadata = match std::fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std_io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(unsupported([PathBuf::from("packs")], 0)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsupported([PathBuf::from("packs")], 0));
    }

    let entries = std::fs::read_dir(&dir).map_err(|_| unsupported([PathBuf::from("packs")], 0))?;
    let mut files = Vec::new();
    let mut rejected = Vec::new();
    let mut omitted = 0;
    let mut limit_exceeded = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                push_unsupported(
                    &mut rejected,
                    &mut omitted,
                    PathBuf::from("packs/<unreadable>"),
                );
                continue;
            }
        };
        let relative = PathBuf::from("packs").join(entry.file_name());
        let accepted = entry.file_type().ok().is_some_and(|kind| kind.is_file())
            && entry
                .metadata()
                .ok()
                .is_some_and(|metadata| metadata.nlink() == 1)
            && valid_pack_name(&entry.file_name());
        if accepted {
            if files.len() < max_members {
                files.push(relative);
            } else {
                limit_exceeded = true;
            }
        } else {
            push_unsupported(&mut rejected, &mut omitted, relative);
        }
    }
    finish_pack_inventory(files, rejected, omitted, limit_exceeded, max_members)
}

/// Descriptor-relative form used while a config tree guard is held.
pub(crate) fn validate_flat_pack_tree_under_tree(
    tree: super::tree_io::TreeIo<'_>,
) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    validate_flat_pack_tree_under_tree_with_cap(tree, MAX_PACK_MEMBERS, None)
}

pub(crate) fn validate_flat_pack_tree_under_tree_with_overlay(
    tree: super::tree_io::TreeIo<'_>,
    overlay: Option<&PackOverlay>,
) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    validate_flat_pack_tree_under_tree_with_cap(
        tree,
        MAX_PACK_MEMBERS,
        overlay.map(PackOverlay::ignored_stages),
    )
}

fn validate_flat_pack_tree_under_tree_with_cap(
    tree: super::tree_io::TreeIo<'_>,
    max_members: usize,
    ignored_stages: Option<&BTreeSet<PathBuf>>,
) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    let root = tree
        .backup_root_directory()
        .map_err(|_| unsupported([PathBuf::from("packs")], 0))?;
    let (_, metadata) = match tree.backup_inspect_optional_child(&root, OsStr::new("packs")) {
        Ok(Some(entry)) => entry,
        Ok(None) if ignored_stages.is_none_or(BTreeSet::is_empty) => return Ok(Vec::new()),
        Ok(None) => {
            return Err(unsupported(
                ignored_stages.into_iter().flatten().cloned(),
                0,
            ));
        }
        Err(_) => return Err(unsupported([PathBuf::from("packs")], 0)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsupported([PathBuf::from("packs")], 0));
    }
    let dir = tree
        .backup_child_directory(&root, OsStr::new("packs"))
        .map_err(|_| unsupported([PathBuf::from("packs")], 0))?;
    let mut names = Vec::new();
    let mut rejected = Vec::new();
    let mut omitted = 0;
    let mut valid_names = 0;
    let mut seen_stages = BTreeSet::new();
    super::tree_io::for_each_dir_name(&dir, |name| {
        let relative = PathBuf::from("packs").join(name);
        if ignored_stages.is_some_and(|ignored| ignored.contains(&relative)) {
            let accepted = tree
                .backup_inspect_child(&dir, name)
                .ok()
                .is_some_and(|(_, metadata)| metadata.is_file() && metadata.nlink() == 1);
            if accepted {
                seen_stages.insert(relative);
            } else {
                push_unsupported(&mut rejected, &mut omitted, relative);
            }
        } else if valid_pack_name(name) {
            if valid_names < max_members {
                names.push(name.to_os_string());
            }
            valid_names += 1;
        } else {
            push_unsupported(&mut rejected, &mut omitted, relative);
        }
        Ok(())
    })
    .map_err(|_| unsupported([PathBuf::from("packs")], 0))?;
    if let Some(ignored) = ignored_stages {
        for missing in ignored.difference(&seen_stages) {
            push_unsupported(&mut rejected, &mut omitted, missing.clone());
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let mut files = Vec::new();
    let limit_exceeded = valid_names > max_members;
    for name in names {
        let relative = PathBuf::from("packs").join(&name);
        let accepted = tree
            .backup_inspect_child(&dir, &name)
            .ok()
            .is_some_and(|(_, metadata)| metadata.is_file() && metadata.nlink() == 1)
            && valid_pack_name(&name);
        if accepted {
            files.push(relative);
        } else {
            push_unsupported(&mut rejected, &mut omitted, relative);
        }
    }
    finish_pack_inventory(files, rejected, omitted, limit_exceeded, max_members)
}

fn is_write_stage_name(name: &str) -> bool {
    name.strip_prefix(super::write_lock::WRITE_STAGE_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_pack_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(id) = name.strip_suffix(".txt") else {
        return false;
    };
    !id.is_empty() && Id::new(id).is_ok()
}

fn push_unsupported(paths: &mut Vec<PathBuf>, omitted: &mut usize, path: PathBuf) {
    if paths.len() < MAX_UNSUPPORTED_PACK_PATHS {
        paths.push(path);
    } else {
        *omitted += 1;
    }
}

fn unsupported(paths: impl IntoIterator<Item = PathBuf>, omitted: usize) -> UnsupportedPackTree {
    UnsupportedPackTree {
        paths: paths.into_iter().collect(),
        omitted,
        member_limit_exceeded: None,
    }
}

fn finish_pack_inventory(
    mut files: Vec<PathBuf>,
    mut rejected: Vec<PathBuf>,
    omitted: usize,
    limit_exceeded: bool,
    member_limit: usize,
) -> Result<Vec<PathBuf>, UnsupportedPackTree> {
    files.sort();
    rejected.sort();
    if rejected.is_empty() && !limit_exceeded {
        Ok(files)
    } else {
        Err(UnsupportedPackTree {
            paths: rejected,
            omitted,
            member_limit_exceeded: limit_exceeded.then_some(member_limit),
        })
    }
}

/// The directory holding every pack file, at the root of the config fence.
pub fn pack_dir(config_root: &Path) -> PathBuf {
    config_root.join("packs")
}

/// The file backing one custom list.
///
/// Derived from the id and never configured, so a path traversal, an
/// absolute path and two entries sharing one file are unrepresentable
/// rather than refused. A symlink is the case derivation cannot reach —
/// it constrains the path, not the inode at it — so the reader opens with
/// `O_NOFOLLOW` and refuses one instead of following it out of the fence.
///
/// `config_root` is the parent of the **master** config, not of whichever
/// included fragment declares the entity — the loader keeps one fence for
/// the whole include graph, and this sits at its root.
pub fn pack_path(config_root: &Path, id: &Id) -> PathBuf {
    pack_dir(config_root).join(format!("{}.txt", id.as_str()))
}

/// Read every declared pack file.
///
/// All-or-nothing: one unreadable file fails the whole store. A partial
/// store would install the lists that read and drop the one that did not,
/// and a dropped deny rule has no symptom.
///
/// Returns every failure, not the first — an operator repairing a restored
/// tree should not have to learn the names one restart at a time.
pub fn build_store(
    config_root: &Path,
    lists: &[CustomList],
    max_bytes: u64,
) -> Result<CustomListStore, Vec<(Id, PackReadError)>> {
    build_store_with_budget(config_root, lists, max_bytes, PackBudget::production())
}

#[derive(Clone, Copy)]
struct PackBudget {
    max_members: usize,
    max_bytes: u64,
}

impl PackBudget {
    const fn production() -> Self {
        Self {
            max_members: MAX_PACK_MEMBERS,
            max_bytes: MAX_PACK_BYTES,
        }
    }
}

fn build_store_with_budget(
    config_root: &Path,
    lists: &[CustomList],
    max_bytes: u64,
    budget: PackBudget,
) -> Result<CustomListStore, Vec<(Id, PackReadError)>> {
    if lists.len() > budget.max_members {
        let rejected = &lists[budget.max_members];
        return Err(vec![(
            rejected.id.clone(),
            PackReadError::TooManyMembers {
                path: pack_path(config_root, &rejected.id),
                count: lists.len(),
                cap: budget.max_members,
            },
        )]);
    }
    let mut store = CustomListStore::new();
    let mut errs = Vec::new();
    let mut total_bytes = 0;
    for entry in lists {
        let path = pack_path(config_root, &entry.id);
        match io::read_pack_with_budget(&path, max_bytes, total_bytes, budget.max_bytes) {
            Ok((compiled, bytes)) => {
                total_bytes = total_bytes.saturating_add(bytes);
                store.insert(entry.id.clone(), compiled);
            }
            Err(e) => errs.push((entry.id.clone(), e)),
        }
    }
    if errs.is_empty() {
        Ok(store)
    } else {
        Err(errs)
    }
}

pub(crate) fn build_store_under_tree(
    tree: super::tree_io::TreeIo<'_>,
    lists: &[CustomList],
    max_bytes: u64,
    overlay: Option<&PackOverlay>,
) -> Result<CustomListStore, Vec<(Id, PackReadError)>> {
    build_store_under_tree_with_budget(tree, lists, max_bytes, overlay, PackBudget::production())
}

fn build_store_under_tree_with_budget(
    tree: super::tree_io::TreeIo<'_>,
    lists: &[CustomList],
    max_bytes: u64,
    overlay: Option<&PackOverlay>,
    budget: PackBudget,
) -> Result<CustomListStore, Vec<(Id, PackReadError)>> {
    if lists.len() > budget.max_members {
        let rejected = &lists[budget.max_members];
        let relative = pack_path(Path::new(""), &rejected.id);
        return Err(vec![(
            rejected.id.clone(),
            PackReadError::TooManyMembers {
                path: tree.identity.root.join(relative),
                count: lists.len(),
                cap: budget.max_members,
            },
        )]);
    }
    let mut store = CustomListStore::new();
    let mut errors = Vec::new();
    let mut total_bytes = 0;
    for entry in lists {
        let relative = pack_path(Path::new(""), &entry.id);
        let display = tree.identity.root.join(&relative);
        let result = match overlay.and_then(|overlay| overlay.get(&entry.id)) {
            Some(Some(bytes)) => io::read_pack_from_bytes_with_budget(
                bytes,
                &display,
                max_bytes,
                total_bytes,
                budget.max_bytes,
            ),
            Some(None) => Err(PackReadError::Missing {
                path: display.clone(),
            }),
            None => tree
                .open_no_follow(&relative)
                .map_err(|e| {
                    io::classify(
                        &display,
                        e.downcast::<std::io::Error>()
                            .unwrap_or_else(|e| std::io::Error::other(format!("{e:#}"))),
                    )
                })
                .and_then(|file| {
                    file.ok_or_else(|| PackReadError::Missing {
                        path: display.clone(),
                    })
                })
                .and_then(|file| {
                    io::read_pack_from_file_with_budget(
                        file,
                        &display,
                        max_bytes,
                        total_bytes,
                        budget.max_bytes,
                    )
                }),
        };
        match result {
            Ok((compiled, bytes)) => {
                total_bytes = total_bytes.saturating_add(bytes);
                store.insert(entry.id.clone(), compiled);
            }
            Err(e) => errors.push((entry.id.clone(), e)),
        }
    }
    if errors.is_empty() {
        Ok(store)
    } else {
        Err(errors)
    }
}

/// Read raw bodies for an offline policy candidate under the same hard pack
/// admission used by the runtime store. The caller owns parsing and compiler
/// policy; this function owns only descriptor-safe body acquisition.
pub(crate) fn read_pack_bodies_under_tree(
    tree: super::tree_io::TreeIo<'_>,
    lists: &[CustomList],
    max_bytes: u64,
    max_members: usize,
    max_total_bytes: u64,
    overlay: Option<&PackOverlay>,
) -> Result<PackBodies, PackReadFailures> {
    let budget = PackBudget {
        max_members,
        max_bytes: max_total_bytes,
    };
    if lists.len() > budget.max_members {
        let rejected = &lists[budget.max_members];
        let relative = pack_path(Path::new(""), &rejected.id);
        return Err(vec![(
            rejected.id.clone(),
            PackReadError::TooManyMembers {
                path: tree.identity.root.join(relative),
                count: lists.len(),
                cap: budget.max_members,
            },
        )]);
    }

    let mut bodies = BTreeMap::new();
    let mut errors = Vec::new();
    let mut total_bytes = 0;
    for entry in lists {
        let relative = pack_path(Path::new(""), &entry.id);
        let display = tree.identity.root.join(&relative);
        let result = match overlay.and_then(|overlay| overlay.get(&entry.id)) {
            Some(Some(bytes)) => io::read_pack_text_from_bytes_with_budget(
                bytes,
                &display,
                max_bytes,
                total_bytes,
                budget.max_bytes,
            )
            .map(|(text, bytes)| (Arc::<str>::from(text), bytes)),
            Some(None) => Err(PackReadError::Missing {
                path: display.clone(),
            }),
            None => tree
                .open_no_follow(&relative)
                .map_err(|e| {
                    io::classify(
                        &display,
                        e.downcast::<std::io::Error>()
                            .unwrap_or_else(|e| std::io::Error::other(format!("{e:#}"))),
                    )
                })
                .and_then(|file| {
                    file.ok_or_else(|| PackReadError::Missing {
                        path: display.clone(),
                    })
                })
                .and_then(|file| {
                    io::read_pack_text_from_file_with_budget(
                        file,
                        &display,
                        max_bytes,
                        total_bytes,
                        budget.max_bytes,
                    )
                })
                .map(|(text, bytes)| (Arc::<str>::from(text), bytes)),
        };
        match result {
            Ok((body, bytes)) => {
                total_bytes = total_bytes.saturating_add(bytes);
                bodies.insert(entry.id.clone(), body);
            }
            Err(error) => errors.push((entry.id.clone(), error)),
        }
    }
    if errors.is_empty() {
        Ok(bodies)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    fn entity(s: &str) -> CustomList {
        CustomList {
            id: id(s),
            display_name: String::new(),
            description: String::new(),
        }
    }

    #[test]
    fn the_path_is_the_id_under_packs() {
        let root = std::path::Path::new("/var/lib/purge-warden");
        assert_eq!(
            pack_path(root, &id("minecraft")),
            std::path::Path::new("/var/lib/purge-warden/packs/minecraft.txt")
        );
    }

    #[test]
    fn the_store_is_keyed_by_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        std::fs::write(
            dir.path().join("packs").join("a.txt"),
            "||ads.example.com^\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("packs").join("b.txt"),
            "@@||cdn.example.com^\n",
        )
        .unwrap();

        let store = build_store(dir.path(), &[entity("a"), entity("b")], 1024 * 1024).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store[&id("a")].deny.len(), 1);
        assert_eq!(store[&id("b")].allow.len(), 1);
    }

    #[test]
    fn one_unreadable_file_fails_the_whole_store() {
        // Fail-closed. A partial store would install the lists that read and
        // silently drop the one that did not — the deny rules vanish without
        // a symptom.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        std::fs::write(
            dir.path().join("packs").join("a.txt"),
            "||ads.example.com^\n",
        )
        .unwrap();
        // "b" is declared but has no file.
        let errs = build_store(dir.path(), &[entity("a"), entity("b")], 1024 * 1024)
            .expect_err("a declared list with no file must fail the store");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].0, id("b"));
    }

    #[test]
    fn every_unreadable_file_is_reported_not_only_the_first() {
        // The operator repairing a restored tree wants the whole list, not
        // one name per restart.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        let errs = build_store(
            dir.path(),
            &[entity("a"), entity("b"), entity("c")],
            1024 * 1024,
        )
        .expect_err("three missing files must fail");
        assert_eq!(errs.len(), 3, "all three must be reported");
    }

    #[test]
    fn aggregate_body_budget_accepts_the_exact_cap_and_rejects_one_byte_over() {
        let dir = tempfile::tempdir().unwrap();
        let packs = dir.path().join("packs");
        std::fs::create_dir(&packs).unwrap();
        std::fs::write(packs.join("a.txt"), b"x").unwrap();
        std::fs::write(packs.join("b.txt"), b"y").unwrap();
        let budget = PackBudget {
            max_members: 2,
            max_bytes: 2,
        };

        let store = build_store_with_budget(dir.path(), &[entity("a"), entity("b")], 16, budget)
            .expect("the exact aggregate cap must load");
        assert_eq!(store.len(), 2);

        std::fs::write(packs.join("b.txt"), b"yz").unwrap();
        let errors = build_store_with_budget(dir.path(), &[entity("a"), entity("b")], 16, budget)
            .expect_err("one byte over the aggregate cap must reject the store");
        assert!(matches!(
            errors.as_slice(),
            [(actual, PackReadError::AggregateTooLarge { size: 3, cap: 2, .. })] if *actual == id("b")
        ));
    }

    #[test]
    fn member_budget_accepts_the_exact_cap_and_rejects_one_declaration_over() {
        let dir = tempfile::tempdir().unwrap();
        let packs = dir.path().join("packs");
        std::fs::create_dir(&packs).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(packs.join(name), b"").unwrap();
        }
        let budget = PackBudget {
            max_members: 2,
            max_bytes: 16,
        };

        assert!(
            build_store_with_budget(dir.path(), &[entity("a"), entity("b")], 16, budget,).is_ok()
        );
        let errors = build_store_with_budget(
            dir.path(),
            &[entity("a"), entity("b"), entity("c")],
            16,
            budget,
        )
        .expect_err("one declaration over the member cap must reject the store");
        assert!(matches!(
            errors.as_slice(),
            [(actual, PackReadError::TooManyMembers { count: 3, cap: 2, .. })] if *actual == id("c")
        ));
    }

    #[test]
    fn overlay_bodies_share_the_aggregate_admission_budget() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        std::fs::write(&master, "schema_version = 4\n").unwrap();
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let mut overlay = PackOverlay::default();
        overlay.stage(id("a"), b"x".to_vec());
        overlay.stage(id("b"), b"yz".to_vec());

        let errors = build_store_under_tree_with_budget(
            guard.tree_io(),
            &[entity("a"), entity("b")],
            16,
            Some(&overlay),
            PackBudget {
                max_members: 2,
                max_bytes: 2,
            },
        )
        .expect_err("overlay bodies must not bypass aggregate admission");
        assert!(matches!(
            errors.as_slice(),
            [(actual, PackReadError::AggregateTooLarge { size: 3, cap: 2, .. })] if *actual == id("b")
        ));
    }

    #[test]
    fn an_empty_declaration_list_needs_no_packs_directory() {
        // A config with no [[custom_lists]] must not require the directory
        // to exist — that is every config that exists today.
        let dir = tempfile::tempdir().unwrap();
        let store = build_store(dir.path(), &[], 1024 * 1024).unwrap();
        assert!(store.is_empty());
        assert!(
            !dir.path().join("packs").exists(),
            "must not create the dir"
        );
    }

    #[test]
    fn flat_pack_inventory_is_sorted_and_accepts_orphans() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        std::fs::write(dir.path().join("packs/zeta.txt"), b"").unwrap();
        std::fs::write(dir.path().join("packs/alpha.txt"), b"").unwrap();
        assert_eq!(
            validate_flat_pack_tree(dir.path()).unwrap(),
            [
                PathBuf::from("packs/alpha.txt"),
                PathBuf::from("packs/zeta.txt")
            ]
        );
    }

    #[test]
    fn flat_pack_inventory_rejects_the_first_member_over_a_test_cap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(dir.path().join("packs").join(name), b"").unwrap();
        }

        let error = validate_flat_pack_tree_with_cap(dir.path(), 2)
            .expect_err("the member cap must reject the additional valid name");
        assert!(error.to_string().contains("2-member cap"));
        assert!(error.paths().is_empty());
    }

    #[test]
    fn flat_pack_inventory_rejects_nested_links_and_special_files() {
        fn rejected(populate: impl FnOnce(&Path)) {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("packs")).unwrap();
            populate(dir.path());
            validate_flat_pack_tree(dir.path()).expect_err("unsafe pack tree must fail");
        }

        rejected(|root| {
            std::fs::create_dir(root.join("packs/sub")).unwrap();
        });
        rejected(|root| {
            std::os::unix::fs::symlink("target.txt", root.join("packs/link.txt")).unwrap();
        });
        rejected(|root| {
            let source = root.join("source");
            std::fs::write(&source, b"body").unwrap();
            std::fs::hard_link(source, root.join("packs/hard.txt")).unwrap();
        });
        rejected(|root| {
            let path = root.join("packs/pipe.txt");
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: the test owns this temporary path and passes a valid mode.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        });
    }

    #[test]
    fn transaction_overlay_ignores_only_its_exact_safe_pack_stage() {
        const STAGE: &str = ".warden-write-0123456789abcdef0123456789abcdef";

        fn guarded_root() -> (
            tempfile::TempDir,
            super::super::write_lock::MigrationWriteLock,
        ) {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("config.toml"), "schema_version = 4\n").unwrap();
            std::fs::create_dir(root.path().join("packs")).unwrap();
            let guard =
                super::super::write_lock::acquire_for_migration(&root.path().join("config.toml"))
                    .unwrap();
            (root, guard)
        }

        let (root, guard) = guarded_root();
        std::fs::write(root.path().join("packs").join(STAGE), b"before").unwrap();
        assert!(validate_flat_pack_tree_under_tree(guard.tree_io()).is_err());
        let mut overlay = PackOverlay::default();
        overlay
            .ignore_verified_stage(PathBuf::from("packs").join(STAGE))
            .unwrap();
        assert_eq!(
            validate_flat_pack_tree_under_tree_with_overlay(guard.tree_io(), Some(&overlay))
                .unwrap(),
            Vec::<PathBuf>::new()
        );

        let (root, guard) = guarded_root();
        let source = root.path().join("source");
        std::fs::write(&source, b"before").unwrap();
        std::fs::hard_link(&source, root.path().join("packs").join(STAGE)).unwrap();
        let mut overlay = PackOverlay::default();
        overlay
            .ignore_verified_stage(PathBuf::from("packs").join(STAGE))
            .unwrap();
        assert!(
            validate_flat_pack_tree_under_tree_with_overlay(guard.tree_io(), Some(&overlay))
                .is_err()
        );

        assert!(PackOverlay::default()
            .ignore_verified_stage(PathBuf::from(
                "packs/.warden-write-0123456789ABCDEF0123456789ABCDEF"
            ))
            .is_err());
        assert!(PackOverlay::default()
            .ignore_verified_stage(PathBuf::from(format!("packs/nested/{STAGE}")))
            .is_err());
    }

    #[test]
    fn pack_tree_limit_is_exposed_separately_from_unsafe_paths() {
        let limit = finish_pack_inventory(Vec::new(), Vec::new(), 0, true, 7).unwrap_err();
        assert_eq!(limit.member_limit_exceeded(), Some(7));
        assert!(limit.paths().is_empty());

        let unsafe_path =
            finish_pack_inventory(Vec::new(), vec![PathBuf::from("packs/nested")], 0, false, 7)
                .unwrap_err();
        assert_eq!(unsafe_path.member_limit_exceeded(), None);
    }
}
