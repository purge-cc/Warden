//! Byte-level revisioning for one declared policy tree.
//!
//! A policy revision is an optimistic-concurrency token, not a semantic
//! policy hash. It includes every byte in the effective TOML graph and every
//! declared custom-list pack, including comments and whitespace.

use std::collections::BTreeSet;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::custom_list::{pack_path, PackOverlay, MAX_PACK_BYTES, MAX_PACK_MEMBERS};
use super::loader::{self, LoadedConfig, LoadedConfigV5, LoaderOverlay, MAX_TOTAL_BYTES};
use super::schema::Id;
use super::tree_io::{for_each_dir_name, CappedRead, TreeIo};
#[cfg(test)]
use super::write_lock::ConfigWriteLock;
use super::write_lock::MigrationWriteLock;

const REVISION_DOMAIN: &[u8] = b"purge-warden.policy-revision\0";
const REVISION_FORMAT: u8 = 1;

trait LoadedPolicy {
    fn master_path(&self) -> &Path;
    fn files_loaded(&self) -> &[PathBuf];
    fn declared_pack_ids(&self) -> Vec<&Id>;
    fn max_pack_file_bytes(&self) -> u64;
    fn max_pack_members(&self) -> usize;
    fn max_pack_bytes(&self) -> u64;
}

impl LoadedPolicy for LoadedConfig {
    fn master_path(&self) -> &Path {
        &self.master_path
    }

    fn files_loaded(&self) -> &[PathBuf] {
        &self.files_loaded
    }

    fn declared_pack_ids(&self) -> Vec<&Id> {
        self.config
            .custom_lists
            .iter()
            .map(|list| &list.id)
            .collect()
    }

    fn max_pack_file_bytes(&self) -> u64 {
        self.config.custom_list_limits.max_file_bytes
    }

    fn max_pack_members(&self) -> usize {
        MAX_PACK_MEMBERS
    }

    fn max_pack_bytes(&self) -> u64 {
        MAX_PACK_BYTES
    }
}

impl LoadedPolicy for LoadedConfigV5 {
    fn master_path(&self) -> &Path {
        &self.master_path
    }

    fn files_loaded(&self) -> &[PathBuf] {
        &self.files_loaded
    }

    fn declared_pack_ids(&self) -> Vec<&Id> {
        self.config
            .custom_lists
            .iter()
            .map(|list| &list.id)
            .collect()
    }

    fn max_pack_file_bytes(&self) -> u64 {
        self.config.custom_list_limits.max_file_bytes as u64
    }

    fn max_pack_members(&self) -> usize {
        self.config.custom_list_limits.max_lists
    }

    fn max_pack_bytes(&self) -> u64 {
        self.config.custom_list_limits.max_total_bytes as u64
    }
}

/// The role a file has in the closed policy inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PolicyMemberKind {
    Master,
    Include,
    Pack,
}

impl PolicyMemberKind {
    fn tag(self) -> u8 {
        match self {
            Self::Master => 1,
            Self::Include => 2,
            Self::Pack => 3,
        }
    }
}

/// The state of a member in a transaction candidate.
///
/// Captured live trees contain only present members: a declared pack that is
/// missing is an error. `Absent` exists for a candidate that explicitly
/// deletes a declared member, so it cannot hash like an empty file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicyMemberState {
    Present(Vec<u8>),
    Absent,
}

/// One canonical member of the closed revision inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRevisionMember {
    kind: PolicyMemberKind,
    path: PathBuf,
    state: PolicyMemberState,
}

impl PolicyRevisionMember {
    pub(crate) fn present(
        kind: PolicyMemberKind,
        path: PathBuf,
        bytes: Vec<u8>,
    ) -> Result<Self, PolicyRevisionError> {
        validate_relative_path(&path)?;
        Ok(Self {
            kind,
            path,
            state: PolicyMemberState::Present(bytes),
        })
    }

    #[cfg(test)]
    pub(crate) fn absent(
        kind: PolicyMemberKind,
        path: PathBuf,
    ) -> Result<Self, PolicyRevisionError> {
        validate_relative_path(&path)?;
        Ok(Self {
            kind,
            path,
            state: PolicyMemberState::Absent,
        })
    }

    pub(crate) fn kind(&self) -> PolicyMemberKind {
        self.kind
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn state(&self) -> &PolicyMemberState {
        &self.state
    }
}

/// A validated, closed inventory suitable for a transaction snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRevisionInventory {
    members: Vec<PolicyRevisionMember>,
}

impl PolicyRevisionInventory {
    /// Validate and canonically order a closed member inventory.
    ///
    /// A physical path has one policy role. Keeping duplicate path spellings
    /// as separate entries would make a transaction's preconditions ambiguous,
    /// even though the hash format itself tags every member kind.
    pub(crate) fn new(mut members: Vec<PolicyRevisionMember>) -> Result<Self, PolicyRevisionError> {
        let mut paths = BTreeSet::new();
        let mut masters = 0;
        for member in &members {
            match member.kind {
                PolicyMemberKind::Master | PolicyMemberKind::Include => {
                    validate_relative_path(&member.path)?;
                }
                PolicyMemberKind::Pack => validate_flat_pack_path(&member.path)?,
            }
            if !paths.insert(member.path.clone()) {
                return Err(PolicyRevisionError::DuplicatePath {
                    path: member.path.clone(),
                });
            }
            if member.kind == PolicyMemberKind::Master {
                masters += 1;
                if member.state == PolicyMemberState::Absent {
                    return Err(PolicyRevisionError::InvalidInventory {
                        detail: "the master config member cannot be absent".to_string(),
                    });
                }
            }
        }
        if masters != 1 {
            return Err(PolicyRevisionError::InvalidInventory {
                detail: format!(
                    "policy inventory needs exactly one master member, found {masters}"
                ),
            });
        }
        members.sort_by(|left, right| {
            left.kind.cmp(&right.kind).then_with(|| {
                left.path
                    .as_os_str()
                    .as_bytes()
                    .cmp(right.path.as_os_str().as_bytes())
            })
        });
        Ok(Self { members })
    }

    pub(crate) fn members(&self) -> &[PolicyRevisionMember] {
        &self.members
    }

    pub(crate) fn revision(&self) -> PolicyRevision {
        let mut digest = Sha256::new();
        digest.update(REVISION_DOMAIN);
        digest.update([REVISION_FORMAT]);
        update_len(&mut digest, self.members.len() as u64);
        for member in &self.members {
            digest.update([member.kind.tag()]);
            update_bytes(&mut digest, member.path.as_os_str().as_bytes());
            match &member.state {
                PolicyMemberState::Present(bytes) => {
                    digest.update([1]);
                    update_bytes(&mut digest, bytes);
                }
                PolicyMemberState::Absent => digest.update([0]),
            }
        }
        PolicyRevision(digest.finalize().into())
    }
}

/// SHA-256 revision of a [`PolicyRevisionInventory`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PolicyRevision([u8; 32]);

impl PolicyRevision {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PolicyRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PolicyRevision")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for PolicyRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A byte-consistent snapshot of the declared policy and its extraneous packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRevisionSnapshot {
    inventory: PolicyRevisionInventory,
    revision: PolicyRevision,
    orphan_packs: Vec<PathBuf>,
}

impl PolicyRevisionSnapshot {
    pub(crate) fn inventory(&self) -> &PolicyRevisionInventory {
        &self.inventory
    }

    pub(crate) fn revision(&self) -> PolicyRevision {
        self.revision
    }

    /// Flat, regular packs not declared by the current config.
    ///
    /// They are observed so a caller can surface them, but stay outside the
    /// declared-policy revision until an explicit transaction adopts them.
    pub(crate) fn orphan_packs(&self) -> &[PathBuf] {
        &self.orphan_packs
    }
}

/// Capture the master, every effective include, and every declared pack while
/// holding the tree's write lock.
///
/// The current loader is deliberately schema-4-only. This helper consumes its
/// already-resolved file graph without changing that runtime boundary; a
/// schema-5 transaction can feed its candidate through `PolicyRevisionInventory`.
#[cfg(test)]
pub(crate) fn capture_loaded_policy_revision(
    guard: &ConfigWriteLock,
    loaded: &LoadedConfig,
) -> Result<PolicyRevisionSnapshot, PolicyRevisionError> {
    guard
        .verify_master(&loaded.master_path)
        .map_err(|source| PolicyRevisionError::Tree {
            path: loaded.master_path.clone(),
            detail: format!("{source:#}"),
        })?;
    capture_loaded_policy_revision_from_tree(guard.tree_io(), loaded)
}

/// Capture a loaded policy through the lock that admits journal recovery and
/// multi-file publication.
pub(crate) fn capture_loaded_policy_revision_under_migration_guard(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfig,
) -> Result<PolicyRevisionSnapshot, PolicyRevisionError> {
    guard
        .verify_master(&loaded.master_path)
        .map_err(|source| PolicyRevisionError::Tree {
            path: loaded.master_path.clone(),
            detail: format!("{source:#}"),
        })?;
    capture_loaded_policy_revision_from_tree(guard.tree_io(), loaded)
}

/// Capture and re-parse the exact bytes that form a revision.
///
/// The advisory config lock cannot stop a non-cooperating editor. Re-validating
/// through closed overlays makes the returned inventory self-consistent even
/// when on-disk bytes changed after the caller's initial load.
#[cfg(test)]
pub(crate) fn capture_coherent_policy_revision_under_migration_guard(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfig,
    expected_schema: u32,
    now: time::OffsetDateTime,
) -> Result<PolicyRevisionSnapshot, PolicyRevisionError> {
    capture_coherent_loaded_under_migration_guard(guard, loaded, expected_schema, now)
        .map(|(snapshot, _)| snapshot)
}

pub(crate) fn capture_coherent_loaded_under_migration_guard(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfig,
    expected_schema: u32,
    now: time::OffsetDateTime,
) -> Result<(PolicyRevisionSnapshot, LoadedConfig), PolicyRevisionError> {
    let snapshot = capture_loaded_policy_revision_under_migration_guard(guard, loaded)?;
    capture_coherent_with(guard.tree_io(), snapshot, |toml, packs| {
        loader::load_config_with_policy_overlays_under_migration_guard(
            guard,
            guard.canonical_master(),
            expected_schema,
            now,
            Some(toml),
            Some(packs),
        )
        .map_err(config_errors_detail)
    })
}

pub(crate) fn capture_coherent_loaded_under_read_guard(
    guard: &super::write_lock::ConfigReadLock,
    loaded: &LoadedConfig,
    expected_schema: u32,
    now: time::OffsetDateTime,
) -> Result<(PolicyRevisionSnapshot, LoadedConfig), PolicyRevisionError> {
    let snapshot = capture_loaded_policy_revision_from_tree(guard.tree_io(), loaded)?;
    capture_coherent_with(guard.tree_io(), snapshot, |toml, packs| {
        loader::load_config_with_policy_overlays_under_read_guard(
            guard,
            &loaded.master_path,
            expected_schema,
            now,
            Some(toml),
            Some(packs),
        )
        .map_err(config_errors_detail)
    })
}

pub(crate) fn capture_coherent_loaded_v5_under_migration_guard(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfigV5,
    now: time::OffsetDateTime,
) -> Result<(PolicyRevisionSnapshot, LoadedConfigV5), PolicyRevisionError> {
    guard
        .verify_master(&loaded.master_path)
        .map_err(|source| PolicyRevisionError::Tree {
            path: loaded.master_path.clone(),
            detail: format!("{source:#}"),
        })?;
    let snapshot = capture_loaded_policy_revision_from_tree(guard.tree_io(), loaded)?;
    capture_coherent_with(guard.tree_io(), snapshot, |toml, packs| {
        loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
            guard,
            guard.canonical_master(),
            now,
            Some(toml),
            Some(packs),
        )
        .map_err(guarded_load_detail)
    })
}

pub(crate) fn capture_coherent_loaded_v5_under_read_guard(
    guard: &super::write_lock::ConfigReadLock,
    loaded: &LoadedConfigV5,
    now: time::OffsetDateTime,
) -> Result<(PolicyRevisionSnapshot, LoadedConfigV5), PolicyRevisionError> {
    guard
        .verify_master(&loaded.master_path)
        .map_err(|source| PolicyRevisionError::Tree {
            path: loaded.master_path.clone(),
            detail: format!("{source:#}"),
        })?;
    let snapshot = capture_loaded_policy_revision_from_tree(guard.tree_io(), loaded)?;
    capture_coherent_with(guard.tree_io(), snapshot, |toml, packs| {
        loader::load_config_v5_with_policy_overlays_under_service_read_guard(
            guard,
            &loaded.master_path,
            now,
            Some(toml),
            Some(packs),
        )
        .map_err(guarded_load_detail)
    })
}

fn capture_coherent_with<T: LoadedPolicy>(
    tree: TreeIo<'_>,
    snapshot: PolicyRevisionSnapshot,
    reparse: impl FnOnce(&LoaderOverlay, &PackOverlay) -> Result<T, String>,
) -> Result<(PolicyRevisionSnapshot, T), PolicyRevisionError> {
    let mut toml_overlay = LoaderOverlay::default();
    let mut pack_overlay = PackOverlay::default();
    let mut expected_toml = BTreeSet::new();
    let mut expected_packs = BTreeSet::new();

    for member in snapshot.inventory.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            return Err(PolicyRevisionError::InvalidInventory {
                detail: "a captured live policy member is absent".to_string(),
            });
        };
        match member.kind() {
            PolicyMemberKind::Master | PolicyMemberKind::Include => {
                let path = tree.identity.root.join(member.path());
                let plan = tree
                    .plan_target(&path)
                    .map_err(|source| PolicyRevisionError::Tree {
                        path: member.path().to_path_buf(),
                        detail: format!("{source:#}"),
                    })?;
                let text = String::from_utf8(bytes.clone()).map_err(|_| {
                    PolicyRevisionError::InvalidInventory {
                        detail: format!(
                            "captured TOML member is not UTF-8: {}",
                            member.path().display()
                        ),
                    }
                })?;
                toml_overlay
                    .stage_plan_reachable_only(&plan, text)
                    .map_err(|source| PolicyRevisionError::Tree {
                        path: member.path().to_path_buf(),
                        detail: format!("{source:#}"),
                    })?;
                expected_toml.insert(path);
            }
            PolicyMemberKind::Pack => {
                let id = pack_id_from_path(member.path())?;
                pack_overlay.stage(id.clone(), bytes.clone());
                expected_packs.insert(id);
            }
        }
    }

    let reparsed = reparse(&toml_overlay, &pack_overlay)
        .map_err(|detail| PolicyRevisionError::IncoherentSnapshot { detail })?;
    let actual_toml: BTreeSet<_> = reparsed.files_loaded().iter().cloned().collect();
    let actual_packs: BTreeSet<_> = reparsed.declared_pack_ids().into_iter().cloned().collect();
    if actual_toml != expected_toml || actual_packs != expected_packs {
        return Err(PolicyRevisionError::IncoherentSnapshot {
            detail: "captured bytes resolve a different TOML or pack inventory".to_string(),
        });
    }
    Ok((snapshot, reparsed))
}

fn config_errors_detail(errors: Vec<super::error::ConfigError>) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn guarded_load_detail(failure: loader::GuardedLoadFailure) -> String {
    match failure {
        loader::GuardedLoadFailure::Diagnostics(errors) => config_errors_detail(errors),
        loader::GuardedLoadFailure::UnsafePath(error)
        | loader::GuardedLoadFailure::BudgetExceeded(error)
        | loader::GuardedLoadFailure::TreeChanged(error)
        | loader::GuardedLoadFailure::RecoveryRequired(error)
        | loader::GuardedLoadFailure::Storage(error) => format!("{error:#}"),
    }
}

fn capture_loaded_policy_revision_from_tree<T: LoadedPolicy>(
    tree: TreeIo<'_>,
    loaded: &T,
) -> Result<PolicyRevisionSnapshot, PolicyRevisionError> {
    let (mut members, declared_pack_paths) = capture_toml_members(tree, loaded)?;
    let (packs, orphan_packs) = capture_pack_members(tree, loaded, &declared_pack_paths)?;
    members.extend(packs);
    let inventory = PolicyRevisionInventory::new(members)?;
    let revision = inventory.revision();
    Ok(PolicyRevisionSnapshot {
        inventory,
        revision,
        orphan_packs,
    })
}

fn capture_toml_members<T: LoadedPolicy>(
    tree: TreeIo<'_>,
    loaded: &T,
) -> Result<(Vec<PolicyRevisionMember>, BTreeSet<PathBuf>), PolicyRevisionError> {
    let (master, includes) = loaded.files_loaded().split_first().ok_or_else(|| {
        PolicyRevisionError::InvalidInventory {
            detail: "loaded configuration has no master member".to_string(),
        }
    })?;
    if master != loaded.master_path() {
        return Err(PolicyRevisionError::InvalidInventory {
            detail: "loaded master is not the first effective TOML member".to_string(),
        });
    }

    let mut total = 0_u64;
    let mut members = Vec::with_capacity(loaded.files_loaded().len());
    let mut paths = BTreeSet::new();
    for (index, file) in loaded.files_loaded().iter().enumerate() {
        let path = root_relative(tree, file)?;
        if !paths.insert(path.clone()) {
            return Err(PolicyRevisionError::DuplicatePath { path });
        }
        let bytes = read_toml_member(tree, file, MAX_TOTAL_BYTES.saturating_sub(total))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_TOTAL_BYTES {
            return Err(PolicyRevisionError::TomlLimitExceeded {
                bytes: total,
                cap: MAX_TOTAL_BYTES,
            });
        }
        members.push(PolicyRevisionMember::present(
            if index == 0 {
                PolicyMemberKind::Master
            } else {
                PolicyMemberKind::Include
            },
            path,
            bytes,
        )?);
    }
    debug_assert_eq!(master, loaded.master_path());
    debug_assert_eq!(includes.len() + 1, loaded.files_loaded().len());
    Ok((members, paths))
}

fn read_toml_member(
    tree: TreeIo<'_>,
    path: &Path,
    remaining: u64,
) -> Result<Vec<u8>, PolicyRevisionError> {
    let plan = tree
        .plan_target(path)
        .map_err(|source| PolicyRevisionError::Tree {
            path: path.to_path_buf(),
            detail: format!("{source:#}"),
        })?;
    match plan
        .read_original_capped(remaining)
        .map_err(|source| PolicyRevisionError::Tree {
            path: path.to_path_buf(),
            detail: format!("{source:#}"),
        })? {
        CappedRead::Contents(bytes) => Ok(bytes),
        CappedRead::Missing => Err(PolicyRevisionError::Tree {
            path: path.to_path_buf(),
            detail: "effective TOML member disappeared during snapshot".to_string(),
        }),
        CappedRead::LimitExceeded { bytes_read } => Err(PolicyRevisionError::TomlLimitExceeded {
            bytes: bytes_read,
            cap: remaining,
        }),
    }
}

fn capture_pack_members<T: LoadedPolicy>(
    tree: TreeIo<'_>,
    loaded: &T,
    toml_paths: &BTreeSet<PathBuf>,
) -> Result<(Vec<PolicyRevisionMember>, Vec<PathBuf>), PolicyRevisionError> {
    capture_pack_members_with_limits(
        tree,
        loaded,
        toml_paths,
        loaded.max_pack_members(),
        loaded.max_pack_bytes(),
    )
}

fn capture_pack_members_with_limits<T: LoadedPolicy>(
    tree: TreeIo<'_>,
    loaded: &T,
    toml_paths: &BTreeSet<PathBuf>,
    max_members: usize,
    max_bytes: u64,
) -> Result<(Vec<PolicyRevisionMember>, Vec<PathBuf>), PolicyRevisionError> {
    let mut declared = BTreeSet::new();
    for id in loaded.declared_pack_ids() {
        let path = pack_path(Path::new(""), id);
        validate_flat_pack_path(&path)?;
        if toml_paths.contains(&path) || !declared.insert(path.clone()) {
            return Err(PolicyRevisionError::DuplicatePath { path });
        }
        if declared.len() > max_members {
            return Err(PolicyRevisionError::PackMembersLimitExceeded {
                count: declared.len() as u64,
                cap: max_members,
            });
        }
    }

    validate_packs_parent(tree)?;
    let mut members = Vec::with_capacity(declared.len());
    let mut total_bytes = 0_u64;
    for path in &declared {
        let plan =
            tree.plan_root_file_no_follow(path)
                .map_err(|source| PolicyRevisionError::Tree {
                    path: path.clone(),
                    detail: format!("{source:#}"),
                })?;
        let id = pack_id_from_path(path)?;
        let file_cap = loaded
            .max_pack_file_bytes()
            .min(max_bytes.saturating_sub(total_bytes));
        let bytes = match plan.read_original_capped(file_cap).map_err(|source| {
            PolicyRevisionError::Tree {
                path: path.clone(),
                detail: format!("{source:#}"),
            }
        })? {
            CappedRead::Contents(bytes) => bytes,
            CappedRead::Missing => {
                return Err(PolicyRevisionError::MissingDeclaredPack {
                    id,
                    path: path.clone(),
                })
            }
            CappedRead::LimitExceeded { bytes_read } => {
                if total_bytes.saturating_add(bytes_read) > max_bytes {
                    return Err(PolicyRevisionError::PackBytesLimitExceeded {
                        bytes: total_bytes.saturating_add(bytes_read),
                        cap: max_bytes,
                    });
                }
                return Err(PolicyRevisionError::PackLimitExceeded {
                    path: path.clone(),
                    bytes: bytes_read,
                    cap: loaded.max_pack_file_bytes(),
                });
            }
        };
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        members.push(PolicyRevisionMember::present(
            PolicyMemberKind::Pack,
            path.clone(),
            bytes,
        )?);
    }

    let orphan_packs = inspect_pack_directory(tree, &declared)?;
    Ok((members, orphan_packs))
}

fn validate_packs_parent(tree: TreeIo<'_>) -> Result<(), PolicyRevisionError> {
    // This no-follow plan has no write effect. It validates an existing packs
    // directory as a direct child, rejecting a directory symlink before any
    // declared or orphan member is considered.
    tree.plan_root_file_no_follow(Path::new("packs/.policy-revision-probe"))
        .map(|_| ())
        .map_err(|source| PolicyRevisionError::Tree {
            path: PathBuf::from("packs"),
            detail: format!("{source:#}"),
        })
}

fn inspect_pack_directory(
    tree: TreeIo<'_>,
    declared: &BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, PolicyRevisionError> {
    let Some(directory) = tree
        .directory_from(&tree.master_key(), Path::new("packs"))
        .map_err(|source| PolicyRevisionError::Tree {
            path: PathBuf::from("packs"),
            detail: format!("{source:#}"),
        })?
    else {
        return Ok(Vec::new());
    };

    let mut orphans = Vec::new();
    for_each_dir_name(&directory, |name| {
        let path = PathBuf::from("packs").join(name);
        validate_flat_pack_path(&path)?;
        let plan = tree.plan_root_file_no_follow(&path)?;
        if plan.is_new() {
            return Err(anyhow::anyhow!("pack entry disappeared during snapshot"));
        }
        if !declared.contains(&path) {
            orphans.push(path);
        }
        Ok(())
    })
    .map_err(|source| PolicyRevisionError::Tree {
        path: PathBuf::from("packs"),
        detail: format!("{source:#}"),
    })?;
    orphans.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    Ok(orphans)
}

fn root_relative(tree: TreeIo<'_>, path: &Path) -> Result<PathBuf, PolicyRevisionError> {
    let relative =
        path.strip_prefix(&tree.identity.root)
            .map_err(|_| PolicyRevisionError::UnsafePath {
                path: path.to_path_buf(),
                detail: "effective TOML path escapes the locked config root".to_string(),
            })?;
    let relative = relative.to_path_buf();
    validate_relative_path(&relative)?;
    Ok(relative)
}

fn validate_relative_path(path: &Path) -> Result<(), PolicyRevisionError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(PolicyRevisionError::UnsafePath {
            path: path.to_path_buf(),
            detail: "path must be non-empty and root-relative".to_string(),
        });
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(PolicyRevisionError::UnsafePath {
            path: path.to_path_buf(),
            detail: "path must contain only ordinary components".to_string(),
        });
    }
    Ok(())
}

fn validate_flat_pack_path(path: &Path) -> Result<(), PolicyRevisionError> {
    validate_relative_path(path)?;
    let components: Vec<_> = path.components().collect();
    let valid = matches!(components.as_slice(), [Component::Normal(dir), Component::Normal(_)] if *dir == std::ffi::OsStr::new("packs"))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".txt"))
            .and_then(|id| Id::new(id).ok())
            .is_some();
    if !valid {
        return Err(PolicyRevisionError::UnsafePackPath {
            path: path.to_path_buf(),
            detail: "packs accepts only regular packs/<id>.txt members".to_string(),
        });
    }
    Ok(())
}

fn pack_id_from_path(path: &Path) -> Result<Id, PolicyRevisionError> {
    validate_flat_pack_path(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".txt"))
        .expect("flat pack path was validated");
    Id::new(name).map_err(|error| PolicyRevisionError::UnsafePackPath {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

fn update_len(digest: &mut Sha256, len: u64) {
    digest.update(len.to_be_bytes());
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) {
    update_len(digest, bytes.len() as u64);
    digest.update(bytes);
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PolicyRevisionError {
    #[error("unsafe policy path {path}: {detail}")]
    UnsafePath { path: PathBuf, detail: String },
    #[error("unsafe flat-pack path {path}: {detail}")]
    UnsafePackPath { path: PathBuf, detail: String },
    #[error("policy inventory names {path} more than once")]
    DuplicatePath { path: PathBuf },
    #[error("declared custom-list pack {id} is missing at {path}")]
    MissingDeclaredPack { id: Id, path: PathBuf },
    #[error("effective TOML bytes {bytes} exceed the {cap}-byte snapshot cap")]
    TomlLimitExceeded { bytes: u64, cap: u64 },
    #[error("pack {path} is {bytes} bytes, over the {cap}-byte snapshot cap")]
    PackLimitExceeded { path: PathBuf, bytes: u64, cap: u64 },
    #[error("declared pack inventory has {count} members, over the {cap}-member snapshot cap")]
    PackMembersLimitExceeded { count: u64, cap: usize },
    #[error("declared pack bodies are {bytes} bytes, over the {cap}-byte snapshot cap")]
    PackBytesLimitExceeded { bytes: u64, cap: u64 },
    #[error("invalid policy inventory: {detail}")]
    InvalidInventory { detail: String },
    #[error("incoherent policy snapshot: {detail}")]
    IncoherentSnapshot { detail: String },
    #[error("secure tree operation for {path} failed: {detail}")]
    Tree { path: PathBuf, detail: String },
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::config::loader::ProvenanceMap;
    use crate::config::schema::{ConfigV1, CustomList, SCHEMA_VERSION_V1};
    use crate::config::write_lock::{acquire_for_migration, acquire_for_write};

    fn member(kind: PolicyMemberKind, path: &str, bytes: &[u8]) -> PolicyRevisionMember {
        PolicyRevisionMember::present(kind, PathBuf::from(path), bytes.to_vec()).unwrap()
    }

    fn inventory(members: Vec<PolicyRevisionMember>) -> PolicyRevision {
        PolicyRevisionInventory::new(members).unwrap().revision()
    }

    #[test]
    fn member_order_does_not_change_the_revision() {
        let left = inventory(vec![
            member(PolicyMemberKind::Pack, "packs/night.txt", b"allow"),
            member(
                PolicyMemberKind::Master,
                "config.toml",
                b"schema_version = 4\n",
            ),
            member(
                PolicyMemberKind::Include,
                "profiles.d/default.toml",
                b"[profiles.default]\n",
            ),
        ]);
        let right = inventory(vec![
            member(
                PolicyMemberKind::Include,
                "profiles.d/default.toml",
                b"[profiles.default]\n",
            ),
            member(
                PolicyMemberKind::Master,
                "config.toml",
                b"schema_version = 4\n",
            ),
            member(PolicyMemberKind::Pack, "packs/night.txt", b"allow"),
        ]);
        assert_eq!(left, right);
    }

    #[test]
    fn every_toml_byte_changes_the_revision() {
        let clean = inventory(vec![member(
            PolicyMemberKind::Master,
            "config.toml",
            b"schema_version = 4\n",
        )]);
        let commented = inventory(vec![member(
            PolicyMemberKind::Master,
            "config.toml",
            b"# operator note\nschema_version = 4\n",
        )]);
        assert_ne!(clean, commented);
    }

    #[test]
    fn pack_only_change_changes_the_revision() {
        let before = inventory(vec![
            member(
                PolicyMemberKind::Master,
                "config.toml",
                b"schema_version = 4\n",
            ),
            member(
                PolicyMemberKind::Pack,
                "packs/night.txt",
                b"||ads.example.test^\n",
            ),
        ]);
        let after = inventory(vec![
            member(
                PolicyMemberKind::Master,
                "config.toml",
                b"schema_version = 4\n",
            ),
            member(
                PolicyMemberKind::Pack,
                "packs/night.txt",
                b"@@||ads.example.test^\n",
            ),
        ]);
        assert_ne!(before, after);
    }

    #[test]
    fn absence_is_not_an_empty_file() {
        let master = member(
            PolicyMemberKind::Master,
            "config.toml",
            b"schema_version = 4\n",
        );
        let empty = inventory(vec![
            master.clone(),
            member(PolicyMemberKind::Pack, "packs/night.txt", b""),
        ]);
        let absent = PolicyRevisionInventory::new(vec![PolicyRevisionMember::absent(
            PolicyMemberKind::Master,
            PathBuf::from("config.toml"),
        )
        .unwrap()])
        .unwrap_err();
        assert!(matches!(
            absent,
            PolicyRevisionError::InvalidInventory { .. }
        ));
        let absent = PolicyRevisionInventory::new(vec![
            master,
            PolicyRevisionMember::absent(PolicyMemberKind::Pack, PathBuf::from("packs/night.txt"))
                .unwrap(),
        ])
        .unwrap()
        .revision();
        assert_ne!(empty, absent);
    }

    #[test]
    fn ambiguous_or_unsafe_paths_are_rejected() {
        let duplicate = PolicyRevisionInventory::new(vec![
            member(PolicyMemberKind::Master, "config.toml", b"a"),
            member(PolicyMemberKind::Include, "config.toml", b"b"),
        ]);
        assert!(matches!(
            duplicate,
            Err(PolicyRevisionError::DuplicatePath { .. })
        ));
        assert!(matches!(
            PolicyRevisionMember::present(
                PolicyMemberKind::Pack,
                PathBuf::from("packs/../night.txt"),
                Vec::new()
            ),
            Err(PolicyRevisionError::UnsafePath { .. })
        ));
        assert!(matches!(
            validate_flat_pack_path(Path::new("packs/sub/night.txt")),
            Err(PolicyRevisionError::UnsafePackPath { .. })
        ));
    }

    #[test]
    fn missing_declared_pack_is_an_error() {
        let fixture = fixture(&["night"]);
        let guard = acquire_for_write(&fixture.master).unwrap();
        let error = capture_loaded_policy_revision(&guard, &fixture.loaded).unwrap_err();
        assert!(matches!(
            error,
            PolicyRevisionError::MissingDeclaredPack { .. }
        ));
    }

    #[test]
    fn orphan_pack_is_observed_but_does_not_change_declared_revision() {
        let fixture = fixture(&["night"]);
        fs::create_dir(fixture.root.path().join("packs")).unwrap();
        fs::write(
            fixture.root.path().join("packs/night.txt"),
            b"||ads.example.test^\n",
        )
        .unwrap();
        let guard = acquire_for_write(&fixture.master).unwrap();
        let before = capture_loaded_policy_revision(&guard, &fixture.loaded).unwrap();
        fs::write(
            fixture.root.path().join("packs/orphan.txt"),
            b"@@||cdn.example.test^\n",
        )
        .unwrap();
        let after = capture_loaded_policy_revision(&guard, &fixture.loaded).unwrap();
        assert_eq!(before.revision(), after.revision());
        assert_eq!(after.orphan_packs(), &[PathBuf::from("packs/orphan.txt")]);
    }

    #[test]
    fn coherent_capture_rejects_a_master_that_changes_its_include_graph_after_load() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        fs::write(
            &master,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config_for_schema_under_migration_guard(
            &guard,
            &master,
            SCHEMA_VERSION_V1,
            now,
        )
        .unwrap();
        fs::write(
            &master,
            "schema_version = 4\nincludes = [\"other.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        fs::write(root.path().join("other.toml"), "# newly referenced\n").unwrap();

        let error = capture_coherent_policy_revision_under_migration_guard(
            &guard,
            &loaded,
            SCHEMA_VERSION_V1,
            now,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyRevisionError::IncoherentSnapshot { .. }
        ));
    }

    #[test]
    fn coherent_capture_rejects_a_master_that_changes_pack_declarations_after_load() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        fs::write(
            &master,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config_for_schema_under_migration_guard(
            &guard,
            &master,
            SCHEMA_VERSION_V1,
            now,
        )
        .unwrap();
        fs::create_dir(root.path().join("packs")).unwrap();
        fs::write(root.path().join("packs/night.txt"), "||ads.example.test^\n").unwrap();
        fs::write(
            &master,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[[custom_lists]]\nid = \"night\"\n",
        )
        .unwrap();

        let error = capture_coherent_policy_revision_under_migration_guard(
            &guard,
            &loaded,
            SCHEMA_VERSION_V1,
            now,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyRevisionError::IncoherentSnapshot { .. }
        ));
    }

    #[test]
    fn pack_capture_rejects_the_first_declared_member_over_a_test_cap() {
        let fixture = fixture(&["a", "b", "c"]);
        fs::create_dir(fixture.root.path().join("packs")).unwrap();
        for id in ["a", "b", "c"] {
            fs::write(
                fixture.root.path().join("packs").join(format!("{id}.txt")),
                b"",
            )
            .unwrap();
        }
        let guard = acquire_for_write(&fixture.master).unwrap();
        let error = capture_pack_members_with_limits(
            guard.tree_io(),
            &fixture.loaded,
            &BTreeSet::new(),
            2,
            MAX_PACK_BYTES,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyRevisionError::PackMembersLimitExceeded { count: 3, cap: 2 }
        ));
    }

    #[test]
    fn pack_capture_rejects_aggregate_bytes_before_retaining_extra_body() {
        let fixture = fixture(&["a", "b"]);
        fs::create_dir(fixture.root.path().join("packs")).unwrap();
        fs::write(fixture.root.path().join("packs/a.txt"), b"1234").unwrap();
        fs::write(fixture.root.path().join("packs/b.txt"), b"5678").unwrap();
        let guard = acquire_for_write(&fixture.master).unwrap();
        let error = capture_pack_members_with_limits(
            guard.tree_io(),
            &fixture.loaded,
            &BTreeSet::new(),
            MAX_PACK_MEMBERS,
            6,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyRevisionError::PackBytesLimitExceeded { bytes: 7, cap: 6 }
        ));
    }

    struct Fixture {
        root: tempfile::TempDir,
        master: PathBuf,
        loaded: LoadedConfig,
    }

    fn fixture(declared: &[&str]) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        fs::write(&master, b"schema_version = 4\n").unwrap();
        let config = ConfigV1 {
            custom_lists: declared
                .iter()
                .map(|id| CustomList {
                    id: Id::new(*id).unwrap(),
                    display_name: String::new(),
                    description: String::new(),
                })
                .collect(),
            ..Default::default()
        };
        Fixture {
            root,
            master: master.clone(),
            loaded: LoadedConfig {
                config,
                master_path: master.clone(),
                files_loaded: vec![master],
                total_bytes: 17,
                provenance: ProvenanceMap::new(),
                custom_lists: Default::default(),
            },
        }
    }
}
