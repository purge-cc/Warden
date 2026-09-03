//! Operator-authored rule files: grammar, on-disk form, and the store the
//! profile compiler reads.

pub mod grammar;
pub mod io;

pub use grammar::{compose_line, normalise_domain, parse_pack_line, GrammarError, PackLine};
pub use io::{
    add_rule, create_pack, read_pack, read_pack_lines, remove_rule, replace_rule_at_line,
    write_pack, AddOutcome, CompiledCustomList, PackLineView, PackReadError, PackWriteError,
};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::schema::{CustomList, Id};

/// Every declared custom list, parsed, keyed by id.
///
/// Built once per config load and handed to the profile compiler as a
/// parameter, so profile compilation performs no file I/O — the 60-second
/// schedule tick rebuilds every profile and must not read N files a minute.
pub type CustomListStore = BTreeMap<Id, CompiledCustomList>;

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
    let mut store = CustomListStore::new();
    let mut errs = Vec::new();
    for entry in lists {
        match read_pack(&pack_path(config_root, &entry.id), max_bytes) {
            Ok(compiled) => {
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
}
