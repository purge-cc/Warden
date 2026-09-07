//! Format-preserving retirement of schema-3 blocklist row controls.

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::Metadata;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use time::OffsetDateTime;
use toml_edit::{ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::cli::commands::{config::lint::preflight_source_plan_collect, format_config_errors};
use crate::config::{
    loader::{
        self, load_config_for_schema_under_migration_guard,
        load_config_for_schema_under_read_guard,
        load_config_with_overlay_for_schema_under_migration_guard,
        load_config_with_overlay_for_schema_under_read_guard, LoadedConfig, LoaderOverlay,
    },
    migration_journal::{self, MemberRole, MigrationMember},
    tree_io::TreeIo,
    write_lock::{self, ConfigReadLock, MigrationWriteLock},
};

const RETIRED_ROW_KEYS: [&str; 3] = [
    "max_entries",
    "update_interval_hours",
    "refresh_interval_hours",
];

/// The outcome retained by the later CLI layer; this module does not print.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TreeMigrationStatus {
    AlreadyV4,
    Migrated {
        members: usize,
        cleanup_path: PathBuf,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeMigrationSummary {
    pub(crate) status: TreeMigrationStatus,
    pub(crate) source_plan_warnings: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TreeCheckStatus {
    AlreadyV4,
    Ready { members: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeCheckSummary {
    pub(crate) status: TreeCheckStatus,
    pub(crate) source_plan_warnings: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TreeRollbackStatus {
    Restored,
    AlreadyValidNoSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeRollbackSummary {
    pub(crate) status: TreeRollbackStatus,
    pub(crate) source_plan_warnings: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TreeFinalizeStatus {
    Finalized,
    AlreadyValidNoSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeFinalizeSummary {
    pub(crate) status: TreeFinalizeStatus,
    pub(crate) source_plan_warnings: Vec<String>,
}

struct PreparedMember {
    path: PathBuf,
    role: MemberRole,
    before: Vec<u8>,
    after: Vec<u8>,
    metadata: Metadata,
}

/// Migrate every loaded member under one held migration lock.
pub(crate) fn migrate_tree(master: &Path) -> Result<TreeMigrationSummary> {
    let guard = write_lock::acquire_for_migration(master)?;
    migrate_tree_locked(&guard, master)
}

/// Validate the complete migration candidate without changing the tree.
pub(crate) fn check_tree(master: &Path) -> Result<TreeCheckSummary> {
    let guard = write_lock::acquire_for_read(master)?;
    check_tree_locked(&guard, master)
}

fn check_tree_locked(guard: &ConfigReadLock, master: &Path) -> Result<TreeCheckSummary> {
    let now = OffsetDateTime::now_utc();
    match loader::probe_declared_schema_version_under_read_guard(guard, master)
        .map_err(format_config_errors)?
    {
        4 => {
            let (_, warnings) = load_and_validate_v4_read(guard, master, now, None)?;
            Ok(TreeCheckSummary {
                status: TreeCheckStatus::AlreadyV4,
                source_plan_warnings: deduplicate_warnings(warnings),
            })
        }
        3 => {
            let loaded = load_v3_read(guard, master, now)?;
            let expected_members = normalized_member_inventory(guard.tree_io(), &loaded)?;
            let mut warnings = preflight(master, &loaded)?;
            let mut overlay = LoaderOverlay::default();
            prepare_members(
                guard.tree_io(),
                guard.canonical_master(),
                &expected_members,
                &mut overlay,
            )?;
            #[cfg(test)]
            run_test_hook(TestHookPoint::BeforeCandidateValidation);
            let (candidate, candidate_warnings) =
                load_and_validate_v4_read(guard, master, now, Some(&overlay))?;
            ensure_same_member_inventory(
                guard.tree_io(),
                &expected_members,
                &candidate,
                "candidate overlay",
            )?;
            warnings.extend(candidate_warnings);
            Ok(TreeCheckSummary {
                status: TreeCheckStatus::Ready {
                    members: expected_members.len(),
                },
                source_plan_warnings: deduplicate_warnings(warnings),
            })
        }
        version => bail!(
            "cannot check schema_version = {version}; this command only supports schema 3 or 4"
        ),
    }
}

/// Restore the retained schema-3 undo snapshot, if one exists.
pub(crate) fn rollback_tree(master: &Path) -> Result<TreeRollbackSummary> {
    let guard = write_lock::acquire_for_migration(master)?;
    let now = OffsetDateTime::now_utc();
    let mut warnings = Vec::new();
    let outcome = migration_journal::rollback(&guard, |members| {
        let callback_warnings = validate_v3_inventory(&guard, master, now, members)?;
        warnings.extend(callback_warnings);
        Ok(())
    })?;
    let status = match outcome {
        migration_journal::RollbackOutcome::Restored => TreeRollbackStatus::Restored,
        migration_journal::RollbackOutcome::NoArtifact
        | migration_journal::RollbackOutcome::SetupRemoved => {
            warnings.extend(validate_v3(&guard, master, now)?);
            TreeRollbackStatus::AlreadyValidNoSnapshot
        }
    };
    Ok(TreeRollbackSummary {
        status,
        source_plan_warnings: deduplicate_warnings(warnings),
    })
}

/// Validate schema 4 and discard the retained undo snapshot, if one exists.
pub(crate) fn finalize_tree(master: &Path) -> Result<TreeFinalizeSummary> {
    let guard = write_lock::acquire_for_migration(master)?;
    let now = OffsetDateTime::now_utc();
    migration_journal::refuse_normal_access(guard.tree_io())?;
    let (_, initial_warnings) = load_and_validate_v4(&guard, master, now, None)?;
    let mut warnings = initial_warnings;
    let outcome = migration_journal::finalize(&guard, |members| {
        let (loaded, callback_warnings) = load_and_validate_v4(&guard, master, now, None)?;
        ensure_same_member_inventory(guard.tree_io(), members, &loaded, "installed v4")?;
        warnings.extend(callback_warnings);
        Ok(())
    })?;
    let status = match outcome {
        migration_journal::FinalizeOutcome::Finalized => TreeFinalizeStatus::Finalized,
        migration_journal::FinalizeOutcome::NoArtifact => {
            TreeFinalizeStatus::AlreadyValidNoSnapshot
        }
    };
    Ok(TreeFinalizeSummary {
        status,
        source_plan_warnings: deduplicate_warnings(warnings),
    })
}

fn migrate_tree_locked(guard: &MigrationWriteLock, master: &Path) -> Result<TreeMigrationSummary> {
    let now = OffsetDateTime::now_utc();
    migration_journal::recover_fixed(guard, || validate_v3(guard, master, now).map(|_| ()))?;

    match loader::probe_declared_schema_version_under_migration_guard(guard, master)
        .map_err(format_config_errors)?
    {
        4 => {
            let (_, warnings) = load_and_validate_v4(guard, master, now, None)?;
            return Ok(TreeMigrationSummary {
                status: TreeMigrationStatus::AlreadyV4,
                source_plan_warnings: deduplicate_warnings(warnings),
            });
        }
        3 => {}
        version => bail!(
            "cannot migrate schema_version = {version}; this command only migrates schema 3 to 4"
        ),
    }

    let loaded = load_v3(guard, master, now)?;
    let expected_members = normalized_member_inventory(guard.tree_io(), &loaded)?;
    let mut warnings = preflight(master, &loaded)?;
    let mut overlay = LoaderOverlay::default();
    let prepared = prepare_members(
        guard.tree_io(),
        guard.canonical_master(),
        &expected_members,
        &mut overlay,
    )?;

    #[cfg(test)]
    run_test_hook(TestHookPoint::BeforeCandidateValidation);
    let (candidate, candidate_warnings) = load_and_validate_v4(guard, master, now, Some(&overlay))?;
    ensure_same_member_inventory(
        guard.tree_io(),
        &expected_members,
        &candidate,
        "candidate overlay",
    )?;
    warnings.extend(candidate_warnings);

    let members = prepared
        .into_iter()
        .map(|member| {
            MigrationMember::new(
                member.path,
                member.role,
                member.before,
                member.after,
                member.metadata,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let member_count = members.len();
    let mut transaction = match migration_journal::publish(guard, members) {
        Ok(transaction) => transaction,
        Err(error) => return recover_after_failure(guard, master, now, &expected_members, error),
    };

    if let Err(error) = transaction.promote_all() {
        drop(transaction);
        return recover_after_failure(guard, master, now, &expected_members, error);
    }
    #[cfg(test)]
    if take_installed_validation_failure() {
        drop(transaction);
        return recover_after_failure(
            guard,
            master,
            now,
            &expected_members,
            anyhow!("injected installed-v4 validation failure"),
        );
    }
    match load_and_validate_v4(guard, master, now, None) {
        Ok((installed, installed_warnings)) => {
            if let Err(error) = ensure_same_member_inventory(
                guard.tree_io(),
                &expected_members,
                &installed,
                "installed v4",
            ) {
                drop(transaction);
                return recover_after_failure(guard, master, now, &expected_members, error);
            }
            warnings.extend(installed_warnings);
        }
        Err(error) => {
            drop(transaction);
            return recover_after_failure(guard, master, now, &expected_members, error);
        }
    }

    match transaction.commit() {
        Ok(cleanup_path) => Ok(TreeMigrationSummary {
            status: TreeMigrationStatus::Migrated {
                members: member_count,
                cleanup_path,
            },
            source_plan_warnings: deduplicate_warnings(warnings),
        }),
        Err(error) if error.rename_landed() => Err(anyhow!(
            "migration commit reached its rename point; v4 is live but durability is uncertain ({error:#}). Do not roll back; inspect the retained cleanup path."
        )),
        Err(error) => {
            recover_after_failure(guard, master, now, &expected_members, anyhow!(error))
        }
    }
}

fn load_v3(guard: &MigrationWriteLock, master: &Path, now: OffsetDateTime) -> Result<LoadedConfig> {
    load_config_for_schema_under_migration_guard(guard, master, 3, now)
        .map_err(format_config_errors)
}

fn load_v3_read(
    guard: &ConfigReadLock,
    master: &Path,
    now: OffsetDateTime,
) -> Result<LoadedConfig> {
    load_config_for_schema_under_read_guard(guard, master, 3, now).map_err(format_config_errors)
}

fn validate_v3(
    guard: &MigrationWriteLock,
    master: &Path,
    now: OffsetDateTime,
) -> Result<Vec<String>> {
    let loaded = load_v3(guard, master, now)?;
    preflight(master, &loaded)
}

fn validate_v3_inventory(
    guard: &MigrationWriteLock,
    master: &Path,
    now: OffsetDateTime,
    expected_members: &[PathBuf],
) -> Result<Vec<String>> {
    let loaded = load_v3(guard, master, now)?;
    ensure_same_member_inventory(guard.tree_io(), expected_members, &loaded, "restored v3")?;
    preflight(master, &loaded)
}

fn load_and_validate_v4(
    guard: &MigrationWriteLock,
    master: &Path,
    now: OffsetDateTime,
    overlay: Option<&LoaderOverlay>,
) -> Result<(LoadedConfig, Vec<String>)> {
    let loaded =
        load_config_with_overlay_for_schema_under_migration_guard(guard, master, 4, now, overlay)
            .map_err(format_config_errors)?;
    let warnings = preflight(master, &loaded)?;
    Ok((loaded, warnings))
}

fn load_and_validate_v4_read(
    guard: &ConfigReadLock,
    master: &Path,
    now: OffsetDateTime,
    overlay: Option<&LoaderOverlay>,
) -> Result<(LoadedConfig, Vec<String>)> {
    let loaded =
        load_config_with_overlay_for_schema_under_read_guard(guard, master, 4, now, overlay)
            .map_err(format_config_errors)?;
    let warnings = preflight(master, &loaded)?;
    Ok((loaded, warnings))
}

fn preflight(master: &Path, loaded: &LoadedConfig) -> Result<Vec<String>> {
    let (result, warnings) = preflight_source_plan_collect(master, &loaded.config);
    result.map_err(format_config_errors)?;
    Ok(warnings)
}

fn prepare_members(
    tree: TreeIo<'_>,
    canonical_master: &Path,
    members: &[PathBuf],
    overlay: &mut LoaderOverlay,
) -> Result<Vec<PreparedMember>> {
    let master = canonical_master
        .strip_prefix(&tree.identity.root)
        .context("canonical master is outside the config root")?
        .to_path_buf();
    ensure!(
        members.contains(&master),
        "loaded config did not contain the canonical master: {}",
        master.display()
    );

    let master_for_filter = master.clone();
    let paths = members
        .iter()
        .filter(|path| **path != master_for_filter)
        .cloned()
        .map(|path| (path, MemberRole::Include))
        .chain(std::iter::once((master, MemberRole::Master)));
    let mut prepared = Vec::with_capacity(members.len());
    for (path, role) in paths {
        let plan = tree.plan_root_file_no_follow(&path)?;
        let metadata = plan
            .original_metadata()
            .cloned()
            .with_context(|| format!("loaded config member disappeared: {}", path.display()))?;
        let source = plan
            .read_original()?
            .with_context(|| format!("loaded config member disappeared: {}", path.display()))?;
        let mut doc = source
            .parse::<DocumentMut>()
            .with_context(|| format!("parse loaded config member as TOML: {}", path.display()))?;
        apply(&mut doc).with_context(|| format!("migrate config member: {}", path.display()))?;
        let after = doc.to_string();
        overlay.stage_plan(&plan, after.clone())?;
        prepared.push(PreparedMember {
            path,
            role,
            before: source.into_bytes(),
            after: after.into_bytes(),
            metadata,
        });
    }
    Ok(prepared)
}

fn normalized_member_inventory(tree: TreeIo<'_>, loaded: &LoadedConfig) -> Result<Vec<PathBuf>> {
    let root = &tree.identity.root;
    let mut seen = BTreeSet::new();
    let mut members = Vec::with_capacity(loaded.files_loaded.len());
    for canonical in &loaded.files_loaded {
        let member = canonical
            .strip_prefix(root)
            .with_context(|| {
                format!(
                    "loaded file is outside the config root: {}",
                    canonical.display()
                )
            })?
            .to_path_buf();
        ensure!(
            seen.insert(member.clone()),
            "loaded config member appears more than once: {}",
            member.display()
        );
        members.push(member);
    }
    members.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    Ok(members)
}

fn ensure_same_member_inventory(
    tree: TreeIo<'_>,
    expected: &[PathBuf],
    actual: &LoadedConfig,
    stage: &str,
) -> Result<()> {
    let actual = normalized_member_inventory(tree, actual)?;
    let mut expected = expected.to_vec();
    expected.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    ensure!(
        actual == expected,
        "{stage} changed loaded config membership during migration"
    );
    Ok(())
}

fn deduplicate_warnings(warnings: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    warnings
        .into_iter()
        .filter(|warning| seen.insert(warning.clone()))
        .collect()
}

fn recover_after_failure<T>(
    guard: &MigrationWriteLock,
    master: &Path,
    now: OffsetDateTime,
    expected_members: &[PathBuf],
    primary: anyhow::Error,
) -> Result<T> {
    let validate = || validate_v3_inventory(guard, master, now, expected_members).map(|_| ());
    match migration_journal::recover_fixed(guard, validate) {
        Ok(_) => match validate_v3_inventory(guard, master, now, expected_members) {
            Ok(_) => Err(primary.context("migration failed before commit; restored schema 3")),
            Err(validation) => Err(anyhow!(
                "migration failed before commit: {primary:#}; recovery completed but schema-3 validation failed: {validation:#}"
            )),
        },
        Err(recovery) => Err(anyhow!(
            "migration failed before commit: {primary:#}; recovery also failed: {recovery:#}"
        )),
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestHookPoint {
    BeforeCandidateValidation,
}

#[cfg(test)]
type TestHook = Option<(TestHookPoint, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    static TEST_HOOK: RefCell<TestHook> = const { RefCell::new(None) };
    static FAIL_INSTALLED_VALIDATION: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
fn run_test_hook(point: TestHookPoint) {
    TEST_HOOK.with(|slot| {
        if slot
            .borrow()
            .as_ref()
            .is_some_and(|(expected, _)| *expected == point)
        {
            let (_, hook) = slot.borrow_mut().take().expect("matching test hook");
            hook();
        }
    });
}

#[cfg(test)]
fn with_test_hook<R>(
    point: TestHookPoint,
    hook: impl FnOnce() + 'static,
    operation: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<(TestHookPoint, Box<dyn FnOnce()>)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(TEST_HOOK.with(|slot| slot.replace(Some((point, Box::new(hook))))));
    operation()
}

#[cfg(test)]
fn with_installed_validation_failure<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_INSTALLED_VALIDATION.with(|slot| slot.set(self.0));
        }
    }
    let _reset = FAIL_INSTALLED_VALIDATION.with(|slot| Reset(slot.replace(true)));
    operation()
}

#[cfg(test)]
fn take_installed_validation_failure() -> bool {
    FAIL_INSTALLED_VALIDATION.with(|slot| slot.replace(false))
}

/// Apply the schema-3 to schema-4 document-only change.
///
/// Versionless documents are include fragments, so they receive the row
/// cleanup but do not gain a version declaration. A v4 document is left
/// byte-for-byte alone: its row values are deliberate v4 overrides.
pub fn apply(doc: &mut DocumentMut) -> Result<()> {
    match declared_version(doc)? {
        Some(4) => return Ok(()),
        Some(3) | None => {}
        Some(version) => bail!(
            "cannot apply the v3-to-v4 migration to schema_version = {version}; expected 3, 4, or a versionless include document"
        ),
    }

    retire_blocklist_row_controls(doc);

    if declared_version(doc)? == Some(3) {
        // `Value::from` makes a fresh scalar, so carry the old trailing
        // comment and spacing across instead of discarding them.
        let version = doc
            .get_mut("schema_version")
            .and_then(Item::as_value_mut)
            .expect("declared_version accepted only scalar values");
        let decor = version.decor().clone();
        *version = Value::from(4);
        *version.decor_mut() = decor;
    }

    Ok(())
}

fn declared_version(doc: &DocumentMut) -> Result<Option<i64>> {
    let Some(item) = doc.get("schema_version") else {
        return Ok(None);
    };
    item.as_integer().map(Some).ok_or_else(|| {
        anyhow::anyhow!("cannot apply the v3-to-v4 migration: `schema_version` must be an integer")
    })
}

fn retire_blocklist_row_controls(doc: &mut DocumentMut) {
    let Some(blocklists) = doc.get_mut("blocklists") else {
        return;
    };

    match blocklists {
        Item::ArrayOfTables(rows) => retire_array_of_tables(rows),
        Item::Value(Value::Array(rows)) => {
            for value in rows.iter_mut() {
                if let Some(row) = value.as_inline_table_mut() {
                    retire_inline_table_controls(row);
                }
            }
        }
        _ => {}
    }
}

fn retire_array_of_tables(rows: &mut ArrayOfTables) {
    for row in rows.iter_mut() {
        retire_table_controls(row);
    }
}

/// The reattachment rule is intentionally local and mechanical: comments on
/// removed assignments move to the next retained assignment in the same row;
/// if none follows, they move to the previous retained assignment. This keeps
/// a comment in its row without guessing what another row or global it means.
fn retire_table_controls(row: &mut Table) {
    let keys: Vec<String> = row.iter().map(|(key, _)| key.to_owned()).collect();
    let mut pending_comments = String::new();
    let mut previous_retained: Option<String> = None;

    for key in keys {
        if RETIRED_ROW_KEYS.contains(&key.as_str()) {
            pending_comments.push_str(&comments_on_assignment(row, &key));
            row.remove(&key);
            continue;
        }

        if !pending_comments.is_empty() {
            prepend_key_comments(row, &key, &pending_comments);
            pending_comments.clear();
        }
        previous_retained = Some(key);
    }

    if !pending_comments.is_empty() {
        if let Some(key) = previous_retained {
            append_value_comments(row, &key, &pending_comments);
        }
    }
}

fn retire_inline_table_controls(row: &mut InlineTable) {
    for key in RETIRED_ROW_KEYS {
        row.remove(key);
    }
}

fn comments_on_assignment(row: &Table, key: &str) -> String {
    let mut comments = String::new();

    if let Some(prefix) = row
        .key(key)
        .and_then(|key| key.leaf_decor().prefix())
        .and_then(toml_edit::RawString::as_str)
        .filter(|decor| decor.contains('#'))
    {
        comments.push_str(prefix);
    }
    if let Some(suffix) = row
        .get(key)
        .and_then(Item::as_value)
        .and_then(|value| value.decor().suffix())
        .and_then(toml_edit::RawString::as_str)
        .and_then(comment_suffix)
    {
        comments.push_str(&suffix);
    }

    comments
}

fn comment_suffix(suffix: &str) -> Option<String> {
    suffix.find('#').map(|start| {
        let mut comment = suffix[start..].to_owned();
        if !comment.ends_with('\n') {
            comment.push('\n');
        }
        comment
    })
}

fn prepend_key_comments(row: &mut Table, key: &str, comments: &str) {
    let existing = row
        .key(key)
        .and_then(|key| key.leaf_decor().prefix())
        .and_then(toml_edit::RawString::as_str)
        .unwrap_or_default();
    let mut combined = String::with_capacity(comments.len() + existing.len());
    combined.push_str(comments);
    combined.push_str(existing);
    if let Some(mut key) = row.key_mut(key) {
        key.leaf_decor_mut().set_prefix(combined);
    }
}

fn append_value_comments(row: &mut Table, key: &str, comments: &str) {
    let Some(value) = row.get_mut(key).and_then(Item::as_value_mut) else {
        return;
    };
    let existing = value
        .decor()
        .suffix()
        .and_then(toml_edit::RawString::as_str)
        .unwrap_or_default();
    let mut combined = String::with_capacity(existing.len() + comments.len());
    combined.push_str(existing);
    combined.push_str(comments);
    value.decor_mut().set_suffix(combined);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[derive(Debug, PartialEq, Eq)]
    struct SnapshotEntry {
        bytes: Option<Vec<u8>>,
        mode: u32,
        uid: u32,
        gid: u32,
        inode: u64,
        links: u64,
        len: u64,
        modified: (i64, i64),
    }

    fn recursive_snapshot(root: &Path) -> BTreeMap<PathBuf, SnapshotEntry> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, SnapshotEntry>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            let relative = path.strip_prefix(root).unwrap();
            entries.insert(
                relative.to_path_buf(),
                SnapshotEntry {
                    bytes: metadata.is_file().then(|| fs::read(path).unwrap()),
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    inode: metadata.ino(),
                    links: metadata.nlink(),
                    len: metadata.len(),
                    modified: (metadata.mtime(), metadata.mtime_nsec()),
                },
            );
            if metadata.is_dir() {
                let mut children = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                children.sort();
                for child in children {
                    visit(root, &child, entries);
                }
            }
        }

        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    fn master_body(includes: &str) -> String {
        format!(
            "schema_version = 3\nincludes = {includes}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        )
    }

    fn blocklist(id: &str) -> String {
        format!(
            "[[blocklists]]\nid = \"{id}\"\ndisplay_name = \"{id}\"\nurl = \"https://lists.example.test/{id}.txt\"\nmax_entries = 7\nrefresh_interval_hours = 12\n"
        )
    }

    fn v4_blocklist(id: &str) -> String {
        format!(
            "[[blocklists]]\nid = \"{id}\"\ndisplay_name = \"{id}\"\nurl = \"https://lists.example.test/{id}.txt\"\n"
        )
    }

    fn no_fixed_fence(root: &Path) {
        assert!(!root
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .exists());
    }

    fn assert_v3_bytes_and_modes(paths: &[(&Path, Vec<u8>, u32)]) {
        for (path, bytes, mode) in paths {
            assert_eq!(fs::read(path).unwrap(), *bytes);
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, *mode);
        }
    }

    fn migrate(input: &str) -> Result<String> {
        let mut doc = input.parse::<DocumentMut>()?;
        apply(&mut doc)?;
        Ok(doc.to_string())
    }

    #[test]
    fn retires_each_row_control_byte_for_byte() {
        let input = concat!(
            "schema_version = 3\n\n",
            "[[blocklists]]\n",
            "id = \"ads\"\n",
            "max_entries = 100\n",
            "update_interval_hours = 12\n",
            "refresh_interval_hours = 24\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );
        let expected = concat!(
            "schema_version = 4\n\n",
            "[[blocklists]]\n",
            "id = \"ads\"\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );

        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[test]
    fn retires_both_interval_spellings_from_a_disabled_row() {
        let input = concat!(
            "schema_version = 3\n\n",
            "[[blocklists]]\n",
            "id = \"paused\"\n",
            "enabled = false\n",
            "update_interval_hours = 12\n",
            "refresh_interval_hours = 24\n",
            "max_entries = 100\n",
        );
        let expected = concat!(
            "schema_version = 4\n\n",
            "[[blocklists]]\n",
            "id = \"paused\"\n",
            "enabled = false\n",
        );

        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[test]
    fn preserves_comments_by_reattaching_them_within_the_row() {
        let input = concat!(
            "# keep the version note\n",
            "schema_version = 3 # schema note\n\n",
            "[[blocklists]]\n",
            "id = \"ads\"\n",
            "# old ceiling\n",
            "max_entries = 100 # temporary exception\n",
            "# old cadence\n",
            "update_interval_hours = 12\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );
        let expected = concat!(
            "# keep the version note\n",
            "schema_version = 4 # schema note\n\n",
            "[[blocklists]]\n",
            "id = \"ads\"\n",
            "# old ceiling\n",
            "# temporary exception\n",
            "# old cadence\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );

        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[test]
    fn handles_inline_table_rows() {
        let input = concat!(
            "schema_version = 3\n",
            "blocklists = [{ id = \"ads\", max_entries = 100, update_interval_hours = 12, refresh_interval_hours = 24, enabled = false }]\n",
        );
        let expected = concat!(
            "schema_version = 4\n",
            "blocklists = [{ id = \"ads\", enabled = false }]\n",
        );

        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[test]
    fn leaves_versionless_includes_globals_and_unrelated_keys_alone() {
        let input = concat!(
            "max_entries = 999\n",
            "[lists]\n",
            "max_entries = 500\n",
            "update_interval_hours = 6\n",
            "refresh_interval_hours = 7\n\n",
            "[unrelated]\n",
            "max_entries = 7\n\n",
            "[[blocklists]]\n",
            "\"id\" = \"ads\"\n",
            "\"max_entries\" = 100\n",
            "\"update_interval_hours\" = 12\n",
            "\"refresh_interval_hours\" = 24\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );
        let expected = concat!(
            "max_entries = 999\n",
            "[lists]\n",
            "max_entries = 500\n",
            "update_interval_hours = 6\n",
            "refresh_interval_hours = 7\n\n",
            "[unrelated]\n",
            "max_entries = 7\n\n",
            "[[blocklists]]\n",
            "\"id\" = \"ads\"\n",
            "url = \"https://lists.example.test/ads.txt\"\n",
        );

        assert_eq!(migrate(input).unwrap(), expected);
    }

    #[test]
    fn v4_is_a_byte_preserving_no_op() {
        let input = concat!(
            "schema_version = 4 # deliberate\n\n",
            "[[blocklists]]\n",
            "id = \"ads\"\n",
            "max_entries = 100\n",
            "update_interval_hours = 12\n",
            "refresh_interval_hours = 24\n",
        );

        assert_eq!(migrate(input).unwrap(), input);
    }

    #[test]
    fn unsupported_or_malformed_versions_are_refused_without_mutation() {
        for input in [
            "schema_version = 2\n[[blocklists]]\nmax_entries = 100\n",
            "schema_version = 5\n[[blocklists]]\nmax_entries = 100\n",
            "schema_version = \"3\"\n[[blocklists]]\nmax_entries = 100\n",
        ] {
            let mut doc = input.parse::<DocumentMut>().unwrap();
            let error = apply(&mut doc).unwrap_err();
            assert!(error.to_string().contains("schema_version"));
            assert_eq!(doc.to_string(), input);
        }
    }

    #[test]
    fn schema_four_is_a_byte_and_metadata_preserving_no_write_success() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let input = "schema_version = 4 # deliberate\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        fs::write(&master, input).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&master).unwrap();

        let summary = migrate_tree(&master).unwrap();

        assert_eq!(summary.status, TreeMigrationStatus::AlreadyV4);
        assert_eq!(fs::read_to_string(&master).unwrap(), input);
        let after = fs::metadata(&master).unwrap();
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.mode(), before.mode());
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        assert_eq!(after.len(), before.len());
        no_fixed_fence(dir.path());
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(crate::config::migration_journal::CLEANUP_DIR_PREFIX)));
    }

    #[test]
    fn check_validates_a_split_candidate_without_creating_side_files() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let include = dir.path().join("include.toml");
        fs::write(&master, master_body("[\"include.toml\"]")).unwrap();
        fs::write(&include, blocklist("ads")).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&include, fs::Permissions::from_mode(0o600)).unwrap();
        let tree_before = recursive_snapshot(dir.path());
        let before = [
            (
                &master,
                fs::read(&master).unwrap(),
                fs::metadata(&master).unwrap(),
            ),
            (
                &include,
                fs::read(&include).unwrap(),
                fs::metadata(&include).unwrap(),
            ),
        ];

        let summary = check_tree(&master).unwrap();

        assert_eq!(
            summary.status,
            TreeCheckStatus::Ready { members: 2 },
            "the master and its selected include must both be staged"
        );
        for (path, bytes, metadata) in before {
            let after = fs::metadata(path).unwrap();
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(after.ino(), metadata.ino());
            assert_eq!(after.mode(), metadata.mode());
            assert_eq!(after.uid(), metadata.uid());
            assert_eq!(after.gid(), metadata.gid());
        }
        assert!(!dir.path().join(".warden-config.lock").exists());
        no_fixed_fence(dir.path());
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(crate::config::migration_journal::CLEANUP_DIR_PREFIX)));
        assert_eq!(recursive_snapshot(dir.path()), tree_before);
    }

    #[test]
    fn check_accepts_v4_and_refuses_unsupported_masters_without_writes() {
        for (input, expected) in [
            (
                "schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                Some(TreeCheckStatus::AlreadyV4),
            ),
            (
                "schema_version = 2\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                None,
            ),
            (
                "schema_version = 5\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                None,
            ),
            ("[upstream]\nservers = [\"192.0.2.1:53\"]\n", None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            fs::write(&master, input).unwrap();
            let before = recursive_snapshot(dir.path());

            let result = check_tree(&master);
            match expected {
                Some(status) => assert_eq!(result.unwrap().status, status),
                None => assert!(result.is_err()),
            }
            assert_eq!(recursive_snapshot(dir.path()), before);
        }
    }

    #[test]
    fn check_rejects_a_cross_file_candidate_change_without_rewriting_members() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments).unwrap();
        let master = dir.path().join("config.toml");
        let first = fragments.join("first.toml");
        let late = fragments.join("late.toml");
        fs::write(&master, master_body("[\"fragments/*.toml\"]")).unwrap();
        fs::write(&first, blocklist("first")).unwrap();
        let master_before = fs::read(&master).unwrap();
        let first_before = fs::read(&first).unwrap();
        let late_for_hook = late.clone();

        let result = with_test_hook(
            TestHookPoint::BeforeCandidateValidation,
            move || fs::write(late_for_hook, v4_blocklist("late")).unwrap(),
            || check_tree(&master),
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&master).unwrap(), master_before);
        assert_eq!(fs::read(&first).unwrap(), first_before);
        assert!(late.exists());
        assert!(!dir.path().join(".warden-config.lock").exists());
        no_fixed_fence(dir.path());
    }

    #[test]
    fn rollback_and_finalize_require_their_respective_valid_installed_schema() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(
            &master,
            format!("{}\n{}", master_body("[]"), blocklist("ads")),
        )
        .unwrap();

        migrate_tree(&master).unwrap();
        assert_eq!(
            rollback_tree(&master).unwrap().status,
            TreeRollbackStatus::Restored
        );
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 3"));
        assert_eq!(
            rollback_tree(&master).unwrap().status,
            TreeRollbackStatus::AlreadyValidNoSnapshot
        );
        assert!(finalize_tree(&master).is_err(), "a v3 tree cannot finalize");

        migrate_tree(&master).unwrap();
        assert_eq!(
            finalize_tree(&master).unwrap().status,
            TreeFinalizeStatus::Finalized
        );
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 4"));
        assert_eq!(
            finalize_tree(&master).unwrap().status,
            TreeFinalizeStatus::AlreadyValidNoSnapshot
        );
        assert!(
            rollback_tree(&master).is_err(),
            "a v4 tree cannot roll back without undo"
        );
    }

    #[test]
    fn split_tree_rollback_validates_the_exact_journal_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments).unwrap();
        let master = dir.path().join("config.toml");
        let first = fragments.join("first.toml");
        fs::write(&master, master_body("[\"fragments/*.toml\"]")).unwrap();
        fs::write(&first, blocklist("first")).unwrap();
        let master_before = fs::read(&master).unwrap();
        let first_before = fs::read(&first).unwrap();

        migrate_tree(&master).unwrap();
        assert_eq!(
            rollback_tree(&master).unwrap().status,
            TreeRollbackStatus::Restored
        );
        assert_eq!(fs::read(&master).unwrap(), master_before);
        assert_eq!(fs::read(&first).unwrap(), first_before);
    }

    #[test]
    fn rollback_refuses_inventory_drift_and_live_third_states() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments).unwrap();
        let master = dir.path().join("config.toml");
        let first = fragments.join("first.toml");
        fs::write(&master, master_body("[\"fragments/*.toml\"]")).unwrap();
        fs::write(&first, blocklist("first")).unwrap();
        migrate_tree(&master).unwrap();
        fs::write(fragments.join("late.toml"), blocklist("late")).unwrap();

        assert!(rollback_tree(&master).is_err());
        assert!(dir
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .exists());

        let other = tempfile::tempdir().unwrap();
        let other_master = other.path().join("config.toml");
        fs::write(
            &other_master,
            format!("{}\n{}", master_body("[]"), blocklist("ads")),
        )
        .unwrap();
        let summary = migrate_tree(&other_master).unwrap();
        let cleanup = match summary.status {
            TreeMigrationStatus::Migrated { cleanup_path, .. } => cleanup_path,
            TreeMigrationStatus::AlreadyV4 => unreachable!(),
        };
        fs::write(&other_master, b"untrusted replacement").unwrap();

        assert!(rollback_tree(&other_master).is_err());
        assert_eq!(fs::read(&other_master).unwrap(), b"untrusted replacement");
        assert!(cleanup.exists());
    }

    #[test]
    fn finalize_resumes_an_empty_terminal_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(
            &master,
            format!("{}\n{}", master_body("[]"), blocklist("ads")),
        )
        .unwrap();
        let summary = migrate_tree(&master).unwrap();
        let cleanup = match summary.status {
            TreeMigrationStatus::Migrated { cleanup_path, .. } => cleanup_path,
            TreeMigrationStatus::AlreadyV4 => unreachable!(),
        };
        let cleanup_name = cleanup.file_name().unwrap().to_string_lossy();
        let terminal_name = cleanup_name.replacen(
            crate::config::migration_journal::CLEANUP_DIR_PREFIX,
            crate::config::migration_journal::FINALIZED_DIR_PREFIX,
            1,
        );
        let terminal = dir.path().join(terminal_name);
        fs::rename(&cleanup, &terminal).unwrap();
        fs::remove_dir_all(terminal.join("originals")).unwrap();
        fs::remove_file(terminal.join("journal.json")).unwrap();

        assert_eq!(
            finalize_tree(&master).unwrap().status,
            TreeFinalizeStatus::Finalized
        );
        assert!(!terminal.exists());
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 4"));
    }

    #[test]
    fn migration_preserves_schema_three_inherited_source_settings() {
        fn effective_source_settings(
            config: &crate::config::schema::ConfigV1,
        ) -> Vec<(usize, u64)> {
            crate::lists::source_key::ResolvedSourcePlan::build_for_schema(
                &crate::lists::catalog::Catalog::fallback(),
                &config.lists.sources,
                &config.blocklists,
                &config.profiles,
                crate::lists::source_key::RowControlDefaults {
                    max_entries: config.lists.max_entries,
                    update_interval_secs: config.lists.update_interval_secs,
                },
                config.schema_version,
            )
            .unwrap()
            .sources()
            .map(|source| {
                (
                    source.effective_max_entries(),
                    source.effective_update_interval_secs(),
                )
            })
            .collect()
        }

        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(
            &master,
            concat!(
                "schema_version = 3\n\n",
                "[lists]\nmax_entries = 25\nupdate_interval_secs = 7200\n\n",
                "[[blocklists]]\nid = \"ads\"\ndisplay_name = \"ads\"\n",
                "url = \"https://lists.example.test/ads.txt\"\n",
                "max_entries = 1\nupdate_interval_hours = 1\n\n",
                "[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            ),
        )
        .unwrap();
        let v3 = loader::load_config_for_schema(&master, 3, OffsetDateTime::now_utc()).unwrap();
        let inherited = effective_source_settings(&v3.config);

        migrate_tree(&master).unwrap();

        let v4 = loader::load_config_for_schema(&master, 4, OffsetDateTime::now_utc()).unwrap();
        assert_eq!(effective_source_settings(&v4.config), inherited);
        let migrated = fs::read_to_string(&master).unwrap();
        assert!(!migrated.contains("max_entries = 1"));
        assert!(!migrated.contains("update_interval_hours = 1"));
    }

    #[test]
    fn migrates_a_monolithic_schema_three_master() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let input = format!(
            "schema_version = 3\n\n{}\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            blocklist("ads")
        );
        fs::write(&master, input).unwrap();

        let summary = migrate_tree(&master).unwrap();

        assert!(matches!(
            summary.status,
            TreeMigrationStatus::Migrated { members: 1, .. }
        ));
        let output = fs::read_to_string(&master).unwrap();
        assert!(output.contains("schema_version = 4"));
        assert!(!output.contains("max_entries"));
        assert!(!output.contains("refresh_interval_hours"));
        no_fixed_fence(dir.path());
    }

    #[test]
    fn migrates_nested_split_members_once_and_preserves_modes() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        let deeper = nested.join("deeper");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&deeper).unwrap();
        let master = dir.path().join("config.toml");
        let first = nested.join("a.toml");
        let leaf = nested.join("leaf.toml");
        let index = nested.join("index.toml");
        let deep = deeper.join("deep.toml");
        fs::write(
            &master,
            master_body("[\"nested/*.toml\", \"nested/leaf.toml\"]"),
        )
        .unwrap();
        fs::write(&first, blocklist("first")).unwrap();
        fs::write(&leaf, blocklist("leaf")).unwrap();
        fs::write(
            &index,
            "includes = [\"deeper/*.toml\", \"deeper/deep.toml\"]\n",
        )
        .unwrap();
        fs::write(&deep, blocklist("deep")).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&index, fs::Permissions::from_mode(0o620)).unwrap();
        fs::set_permissions(&deep, fs::Permissions::from_mode(0o640)).unwrap();
        let members = [&master, &first, &leaf, &index, &deep];
        let modes = members.map(|path| fs::metadata(path).unwrap().mode() & 0o7777);

        let summary = migrate_tree(&master).unwrap();

        match &summary.status {
            TreeMigrationStatus::Migrated { members, .. } => assert_eq!(*members, 5),
            TreeMigrationStatus::AlreadyV4 => panic!("schema-3 tree was not migrated"),
        }
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 4"));
        for path in [&first, &leaf, &deep] {
            let output = fs::read_to_string(path).unwrap();
            assert!(!output.contains("max_entries"));
            assert!(!output.contains("refresh_interval_hours"));
        }
        assert_eq!(
            members.map(|path| fs::metadata(path).unwrap().mode() & 0o7777),
            modes
        );
        no_fixed_fence(dir.path());
    }

    #[test]
    fn malformed_unsupported_and_invalid_v3_trees_leave_members_untouched() {
        for (master_text, include_text) in [
            ("schema_version = \"three\"\n", None),
            ("schema_version = 2\n", None),
            (
                "schema_version = 3\nincludes = [\"broken.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                Some("[[blocklists]\n"),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            let include = dir.path().join("broken.toml");
            fs::write(&master, master_text).unwrap();
            if let Some(include_text) = include_text {
                fs::write(&include, include_text).unwrap();
            }
            let before_master = fs::read(&master).unwrap();
            let before_include = include_text.map(|_| fs::read(&include).unwrap());

            assert!(migrate_tree(&master).is_err());

            assert_eq!(fs::read(&master).unwrap(), before_master);
            assert_eq!(
                include_text.map(|_| fs::read(&include).unwrap()),
                before_include
            );
            no_fixed_fence(dir.path());
        }
    }

    #[test]
    fn publication_failure_after_fence_creation_cleans_setup_and_restores_v3() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let input = format!("{}\n{}", master_body("[]"), blocklist("ads"));
        fs::write(&master, &input).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::read(&master).unwrap();
        let mode = fs::metadata(&master).unwrap().mode() & 0o7777;
        let blob = dir
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .join("originals/0000.toml");

        let result = crate::config::migration_journal::with_test_hook(
            crate::config::migration_journal::TestHookPoint::OriginalsReady,
            move || fs::write(blob, b"corrupt").unwrap(),
            || migrate_tree(&master),
        );

        assert!(result.is_err());
        assert_v3_bytes_and_modes(&[(&master, before, mode)]);
        no_fixed_fence(dir.path());
    }

    #[test]
    fn promotion_failure_after_an_include_recovers_the_complete_v3_tree() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let include = dir.path().join("include.toml");
        fs::write(&master, master_body("[\"include.toml\"]")).unwrap();
        fs::write(&include, blocklist("ads")).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&include, fs::Permissions::from_mode(0o600)).unwrap();
        let before_master = fs::read(&master).unwrap();
        let before_include = fs::read(&include).unwrap();
        let master_mode = fs::metadata(&master).unwrap().mode() & 0o7777;
        let include_mode = fs::metadata(&include).unwrap().mode() & 0o7777;

        let result = crate::config::migration_journal::with_promotion_failure_after(1, || {
            migrate_tree(&master)
        });

        assert!(result.is_err());
        assert_v3_bytes_and_modes(&[
            (&master, before_master, master_mode),
            (&include, before_include, include_mode),
        ]);
        no_fixed_fence(dir.path());
    }

    #[test]
    fn installed_validation_failure_after_promotion_recovers_v3() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let input = format!("{}\n{}", master_body("[]"), blocklist("ads"));
        fs::write(&master, &input).unwrap();
        let before = fs::read(&master).unwrap();
        let mode = fs::metadata(&master).unwrap().mode() & 0o7777;

        let result = with_installed_validation_failure(|| migrate_tree(&master));

        assert!(result.is_err());
        assert_v3_bytes_and_modes(&[(&master, before, mode)]);
        no_fixed_fence(dir.path());
    }

    #[test]
    fn pre_rename_commit_failure_recovers_v3() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let input = format!("{}\n{}", master_body("[]"), blocklist("ads"));
        fs::write(&master, &input).unwrap();
        let before = fs::read(&master).unwrap();
        let mode = fs::metadata(&master).unwrap().mode() & 0o7777;

        let result = crate::config::migration_journal::with_commit_failure_before_rename(|| {
            migrate_tree(&master)
        });

        assert!(result.is_err());
        assert_v3_bytes_and_modes(&[(&master, before, mode)]);
        no_fixed_fence(dir.path());
    }

    #[test]
    fn post_rename_durability_uncertainty_keeps_v4_and_undo_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        fs::write(
            &master,
            format!("{}\n{}", master_body("[]"), blocklist("ads")),
        )
        .unwrap();

        let result = crate::config::migration_journal::with_commit_root_fsync_uncertain(|| {
            migrate_tree(&master)
        });

        assert!(result.is_err());
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 4"));
        assert!(!fs::read_to_string(&master).unwrap().contains("max_entries"));
        no_fixed_fence(dir.path());
        assert!(fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(crate::config::migration_journal::CLEANUP_DIR_PREFIX)
        }));
    }

    #[test]
    fn source_plan_refusal_before_publication_preserves_bytes_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let sources = (0..65)
            .map(|index| format!("\"https://lists.example.test/{index}.txt\""))
            .collect::<Vec<_>>()
            .join(", ");
        let input = format!(
            "schema_version = 3\n\n[lists]\nsources = [{sources}]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        );
        fs::write(&master, &input).unwrap();
        fs::set_permissions(&master, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::read(&master).unwrap();
        let metadata = fs::metadata(&master).unwrap();

        assert!(migrate_tree(&master).is_err());

        assert_eq!(fs::read(&master).unwrap(), before);
        let after = fs::metadata(&master).unwrap();
        assert_eq!(after.ino(), metadata.ino());
        assert_eq!(after.mode(), metadata.mode());
        no_fixed_fence(dir.path());
    }

    #[test]
    fn version_five_and_versionless_masters_refuse_without_writes() {
        for input in [
            "schema_version = 5\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            fs::write(&master, input).unwrap();
            let before = fs::read(&master).unwrap();
            let metadata = fs::metadata(&master).unwrap();

            assert!(migrate_tree(&master).is_err());

            assert_eq!(fs::read(&master).unwrap(), before);
            assert_eq!(fs::metadata(&master).unwrap().ino(), metadata.ino());
            no_fixed_fence(dir.path());
        }
    }

    #[test]
    fn candidate_membership_change_from_a_new_glob_match_refuses_without_writes() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments).unwrap();
        let master = dir.path().join("config.toml");
        let first = fragments.join("first.toml");
        let late = fragments.join("late.toml");
        fs::write(&master, master_body("[\"fragments/*.toml\"]")).unwrap();
        fs::write(&first, blocklist("first")).unwrap();
        let before_master = fs::read(&master).unwrap();
        let before_first = fs::read(&first).unwrap();
        let late_for_hook = late.clone();

        let result = with_test_hook(
            TestHookPoint::BeforeCandidateValidation,
            move || fs::write(late_for_hook, v4_blocklist("late")).unwrap(),
            || migrate_tree(&master),
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&master).unwrap(), before_master);
        assert_eq!(fs::read(&first).unwrap(), before_first);
        assert!(late.exists());
        no_fixed_fence(dir.path());
    }

    #[test]
    fn warnings_are_stably_deduplicated() {
        assert_eq!(
            deduplicate_warnings(vec!["first".into(), "second".into(), "first".into()]),
            vec!["first", "second"]
        );
    }
}
