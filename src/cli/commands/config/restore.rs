//! Restore a validated archive through a recoverable TOML and pack transaction.
//!
//! Only declared policy files enter the transaction inventory. Unreferenced
//! files remain untouched, and the exclusive guard ends before reload is requested.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Seek};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
use rand_core::RngCore;

use crate::config::custom_list::{self, PackOverlay};
use crate::config::loader::{self, GuardedLoadFailure, LoaderOverlay};
use crate::config::policy_revision::{
    capture_coherent_loaded_v5_under_migration_guard, PolicyMemberKind, PolicyMemberState,
    PolicyRevisionInventory, PolicyRevisionMember,
};
use crate::config::policy_transaction::{
    self, Persistence, ReceiptStore, RecoveryOutcome, RepairDestinationSet, RepairRequest,
    TransactionRequest,
};
use crate::config::schema::{
    ClusterConfig, ClusterRole, Id, NodeConfig, TARGET_SCHEMA_VERSION_V5 as SCHEMA_VERSION,
};
use crate::config::tree_io::CappedRead;
use crate::config::write_lock::{self, MigrationWriteLock};

/// Persistence result returned without requesting daemon activation.
/// Archive, I/O, recovery and uncertain-durability errors are returned as `Err`.
#[derive(Debug)]
pub enum RestoreOutcome {
    /// The policy transaction committed durably. Its recovery copy is retained
    /// by the transaction backend; no standalone master backup is created.
    Restored {
        pre_restore: Option<PathBuf>,
        changed: bool,
        /// Invalid or absent live configuration was repaired; unnamed paths remain.
        repair: bool,
    },
    /// Candidate validation failed before any live policy file changed.
    ValidationFailed(Vec<String>),
}

/// Largest archive copied into staging.
#[cfg(not(test))]
const MAX_ARCHIVE_BYTES: u64 = 1 << 30;
#[cfg(test)]
const MAX_ARCHIVE_BYTES: u64 = 1 << 20;
/// Largest sum of member sizes the archive listing may announce.
#[cfg(not(test))]
const MAX_EXTRACTED_BYTES: u64 = 1 << 30;
#[cfg(test)]
const MAX_EXTRACTED_BYTES: u64 = 1 << 20;
/// Most members one archive may list.
#[cfg(not(test))]
const MAX_ARCHIVE_MEMBERS: usize = 10_000;
#[cfg(test)]
const MAX_ARCHIVE_MEMBERS: usize = 64;
/// Most bytes read from one tar listing.
#[cfg(not(test))]
const MAX_LISTING_BYTES: u64 = 8 << 20;
#[cfg(test)]
const MAX_LISTING_BYTES: u64 = 8 << 10;
/// Most bytes of tar's stderr quoted in an error.
const MAX_TAR_STDERR_BYTES: u64 = 4096;

/// Restore declared policy files without printing or signalling the daemon.
/// The CLI wrapper [`run_restore`] requests reload after this function returns.
pub fn restore_archive(live_config: &Path, archive: &Path) -> anyhow::Result<RestoreOutcome> {
    let staging = StagingDir::create()?;
    // The archive's directory may be writable by the daemon user. Every tar
    // run reads a private copy, so the bytes checked are the bytes extracted.
    let pinned = pin_archive(archive, staging.path())?;
    #[cfg(test)]
    write_lock::test_event(write_lock::TestEvent::AfterArchivePinned);
    let tree = staging.path().join("tree");
    std::fs::DirBuilder::new().mode(0o700).create(&tree)?;
    extract_archive(&pinned, &tree, staging.path())?;
    let staged_master = locate_staged_master(&tree, live_config)?;
    let staged_root = staged_master
        .parent()
        .context("staged master has no parent")?;
    custom_list::validate_flat_pack_tree(staged_root)
        .context("refusing restore with an unsupported staged packs/ tree")?;
    let now = time::OffsetDateTime::now_utc();
    let staged = match loader::load_config_v5_executable(&staged_master, now) {
        Ok(loaded) => loaded,
        Err(errors) => {
            // The loader's hint assumes a live older install; an archive
            // needs another route. Key words first: the TUI shows one band.
            if let Some(version) = older_archived_schema(&staged_master) {
                anyhow::bail!(
                    "schema-{version} archive (Warden 0.41 or earlier); live config untouched. \
                     This Warden restores schema-{SCHEMA_VERSION} archives only. To reuse its \
                     settings, extract it into a new empty directory with `tar --no-same-owner \
                     --no-same-permissions -xzf {} -C DIR` and copy them into the current \
                     config with `warden config edit`.",
                    archive.display()
                );
            }
            return Ok(RestoreOutcome::ValidationFailed(
                errors.iter().map(ToString::to_string).collect(),
            ));
        }
    };
    let staged_inventory = staged_inventory(&staged)?;
    let archived = membership(&staged.config.cluster, &staged.config.node);

    let guard = write_lock::acquire_for_migration(live_config)?;
    restore_staged_locked(&guard, live_config, &staged_inventory, archived, now)
}

/// What ties a node to its cluster; `None` is standalone. A disabled
/// `[cluster]` is standalone whatever its role, as in `warden cluster
/// status`. The identity must keep matching the node credential and the
/// primary's roster, which live outside the archive.
#[derive(PartialEq)]
struct Membership {
    role: ClusterRole,
    identity: [(&'static str, Option<String>); 6],
}

fn membership(cluster: &ClusterConfig, node: &NodeConfig) -> Option<Membership> {
    // A primary ignores `peer`.
    let peer = cluster
        .peer
        .clone()
        .filter(|_| cluster.role == ClusterRole::Secondary);
    cluster.enabled.then(|| Membership {
        role: cluster.role,
        identity: [
            (
                "cluster.membership_version",
                cluster
                    .membership_version
                    .map(|version| version.to_string()),
            ),
            ("cluster.cluster_id", cluster.cluster_id.clone()),
            ("cluster.primary_node_id", cluster.primary_node_id.clone()),
            (
                "cluster.primary_cert_fingerprint",
                cluster.primary_cert_fingerprint.clone(),
            ),
            ("cluster.peer", peer),
            ("node.id", node.id.clone()),
        ],
    })
}

/// The membership the live master declares, for a repair whose live config
/// does not load. Only the master's own `[cluster]` and `[node]` are read
/// (`warden cluster` writes them there). `None` (unknown) when the master is
/// absent, it or one of these sections does not parse, or a section is
/// absent while the master has `includes` (the loader may take it from an
/// include).
fn raw_live_membership(guard: &MigrationWriteLock) -> anyhow::Result<Option<Option<Membership>>> {
    fn section<T: serde::de::DeserializeOwned + Default>(
        table: &mut toml::Table,
        key: &str,
    ) -> Option<T> {
        match table.remove(key) {
            Some(value) => value.try_into().ok(),
            None => (!table.contains_key("includes")).then(T::default),
        }
    }
    let CappedRead::Contents(bytes) = guard
        .tree_io()
        .plan_master_target()?
        .read_original_capped(loader::MAX_TOTAL_BYTES)?
    else {
        return Ok(None);
    };
    let Some(mut table) = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
    else {
        return Ok(None);
    };
    Ok(section::<ClusterConfig>(&mut table, "cluster")
        .zip(section::<NodeConfig>(&mut table, "node"))
        .map(|(cluster, node)| membership(&cluster, &node)))
}

/// Restore never changes cluster membership: the node credential, the
/// ownership ledger and the primary's roster live outside the archive, and a
/// node whose `[cluster]` no longer matches them cannot start or is cut off.
/// An unknown live membership (`None`) admits only a standalone archive, and
/// no archive when node-local state shows the node is a member.
fn refuse_membership_change(
    guard: &MigrationWriteLock,
    live: Option<Option<Membership>>,
    archived: Option<Membership>,
) -> anyhow::Result<()> {
    let role = |membership: &Option<Membership>| match membership.as_ref().map(|m| m.role) {
        None => "standalone",
        Some(ClusterRole::Primary) => "primary",
        Some(ClusterRole::Secondary) => "secondary",
    };
    let Some(live) = live else {
        anyhow::ensure!(
            !member_evidence(guard)?,
            "refusing restore: this node's cluster membership is unknown (the live config does \
             not load) and node-local cluster state shows it is a member; live config unchanged. \
             Run `warden config lint` to see the error, fix it by hand, then restore again."
        );
        anyhow::ensure!(
            archived.is_none(),
            "refusing restore: this node's cluster membership is unknown and the archive's is \
             {}; live config unchanged. The live master is missing or does not parse, or it \
             leaves `[cluster]` or `[node]` to an include: fix the master and restore again, or \
             restore an archive taken while the node was standalone.",
            role(&archived)
        );
        return Ok(());
    };
    let change = match (&live, &archived) {
        _ if live == archived => return Ok(()),
        (Some(now), Some(then)) if now.role == then.role => format!(
            "{} membership: the archive's {} differs",
            role(&live),
            now.identity
                .iter()
                .zip(&then.identity)
                .find(|(now, then)| now != then)
                .map_or("identity", |((field, _), _)| *field)
        ),
        _ => format!(
            "cluster membership from {} to {}",
            role(&live),
            role(&archived)
        ),
    };
    anyhow::bail!(
        "refusing restore: it would change this node's {change}; live config unchanged. \
         Membership changes go through `warden cluster` (leave, join or create); restore an \
         archive taken with the current membership instead."
    )
}

/// Whether node-local state shows this node is a cluster member: the
/// secondary credential `warden cluster join` saves or the roster
/// `warden cluster create` starts. `warden cluster leave` removes both.
fn member_evidence(guard: &MigrationWriteLock) -> anyhow::Result<bool> {
    #[cfg(feature = "cluster")]
    if let Some(files) =
        crate::private_store::PrivateStore::open_existing(guard, crate::cluster::membership::STORE)?
    {
        return Ok(files.read("secondary.json", 8192)?.is_some()
            || files.read("roster.json", 256 * 1024)?.is_some());
    }
    #[cfg(not(feature = "cluster"))]
    let _ = guard;
    Ok(false)
}

/// The `schema_version` a staged master declares when it is older than this
/// Warden's. An unreadable or unparsable master gives `None`, so the
/// loader's diagnostics stand.
fn older_archived_schema(staged_master: &Path) -> Option<i64> {
    let bytes = read_staged_file(staged_master, loader::MAX_TOTAL_BYTES).ok()?;
    let table: toml::Table = std::str::from_utf8(&bytes).ok()?.parse().ok()?;
    table
        .get("schema_version")?
        .as_integer()
        .filter(|version| *version < i64::from(SCHEMA_VERSION))
}

fn staged_inventory(loaded: &loader::LoadedConfigV5) -> anyhow::Result<PolicyRevisionInventory> {
    staged_inventory_with_budget(loaded, policy_transaction::MAX_POLICY_BYTES)
}

fn staged_inventory_with_budget(
    loaded: &loader::LoadedConfigV5,
    transaction_budget: u64,
) -> anyhow::Result<PolicyRevisionInventory> {
    let root = loaded
        .master_path
        .parent()
        .context("staged master has no parent")?;
    let mut members = Vec::new();
    let mut toml_bytes = 0_u64;
    let mut retained_bytes = 0_u64;
    for path in &loaded.files_loaded {
        let relative = path
            .strip_prefix(root)
            .context("staged TOML escaped its root")?;
        let remaining = transaction_budget
            .checked_sub(retained_bytes)
            .context("restore candidate exceeds transaction byte budget")?;
        let bytes = read_staged_file(
            path,
            loader::MAX_TOTAL_BYTES
                .saturating_sub(toml_bytes)
                .min(remaining),
        )?;
        let length = bytes.len() as u64;
        toml_bytes = toml_bytes
            .checked_add(length)
            .context("restore TOML byte budget overflow")?;
        retained_bytes = retained_bytes
            .checked_add(length)
            .context("restore transaction byte budget overflow")?;
        members.push(PolicyRevisionMember::present(
            if path == &loaded.master_path {
                PolicyMemberKind::Master
            } else {
                PolicyMemberKind::Include
            },
            relative.to_path_buf(),
            bytes,
        )?);
    }
    for list in &loaded.config.custom_lists {
        let relative = custom_list::pack_path(Path::new(""), &list.id);
        let remaining = transaction_budget
            .checked_sub(retained_bytes)
            .context("restore candidate exceeds transaction byte budget")?;
        let bytes = read_staged_file(
            &root.join(&relative),
            u64::try_from(loaded.config.custom_list_limits.max_file_bytes)
                .context("schema-5 pack limit does not fit the restore byte budget")?
                .min(remaining),
        )?;
        retained_bytes = retained_bytes
            .checked_add(bytes.len() as u64)
            .context("restore transaction byte budget overflow")?;
        members.push(PolicyRevisionMember::present(
            PolicyMemberKind::Pack,
            relative,
            bytes,
        )?);
    }
    Ok(PolicyRevisionInventory::new(members)?)
}

/// Open a regular file with one link and at most `cap` bytes, without
/// following a final symlink. `what` names the file in the refusal.
fn open_capped(
    path: &Path,
    cap: u64,
    what: &str,
) -> anyhow::Result<(std::fs::File, std::fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= cap,
        "unsafe or oversized {what}: {} (it must be a regular file with one link and at most {cap} bytes)",
        path.display()
    );
    Ok((file, metadata))
}

/// True when exactly `read` bytes came from `file` and its size and times
/// still match `before`.
fn same_capture(
    file: &std::fs::File,
    before: &std::fs::Metadata,
    read: u64,
) -> anyhow::Result<bool> {
    let after = file.metadata()?;
    Ok(read == before.len()
        && after.len() == before.len()
        && after.mtime() == before.mtime()
        && after.mtime_nsec() == before.mtime_nsec()
        && after.ctime() == before.ctime()
        && after.ctime_nsec() == before.ctime_nsec())
}

fn read_staged_file(path: &Path, cap: u64) -> anyhow::Result<Vec<u8>> {
    let (file, before) = open_capped(path, cap, "staged file")?;
    let mut bytes = Vec::new();
    (&file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        same_capture(&file, &before, bytes.len() as u64)?,
        "staged file changed during capture: {}",
        path.display()
    );
    Ok(bytes)
}

/// Copy `archive` into `staging` and return the copy's path. The copy is
/// created new with mode 0600, and the source must not change while it is
/// read.
fn pin_archive(archive: &Path, staging: &Path) -> anyhow::Result<PathBuf> {
    let (file, before) = open_capped(archive, MAX_ARCHIVE_BYTES, "archive").map_err(|error| {
        let errno = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error);
        match errno {
            Some(libc::ENOENT) => anyhow::anyhow!("archive not found: {}", archive.display()),
            Some(libc::ELOOP) => anyhow::anyhow!(
                "refusing archive {}: it is a symbolic link",
                archive.display()
            ),
            Some(_) => anyhow::anyhow!("cannot open archive {}: {error}", archive.display()),
            None => error,
        }
    })?;
    let pinned = staging.join("archive.tar.gz");
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pinned)?;
    let copied = std::io::copy(&mut (&file).take(MAX_ARCHIVE_BYTES + 1), &mut copy)?;
    anyhow::ensure!(
        same_capture(&file, &before, copied)?,
        "archive changed while it was copied: {}",
        archive.display()
    );
    Ok(pinned)
}

fn restore_staged_locked(
    guard: &MigrationWriteLock,
    requested_master: &Path,
    staged: &PolicyRevisionInventory,
    archived: Option<Membership>,
    now: time::OffsetDateTime,
) -> anyhow::Result<RestoreOutcome> {
    guard.verify_master(requested_master)?;
    let active_transaction = crate::config::tree_io::inspect_at(
        guard.tree_io().root,
        OsStr::new(crate::config::migration_journal::TXN_DIR_NAME),
    )?
    .is_some();
    let receipts = if active_transaction {
        let data = crate::config::state_dir::open_for_migration(guard)?;
        let receipts = ReceiptStore::open(&data, guard)?;
        if matches!(
            policy_transaction::recover_active(guard, &receipts)?,
            RecoveryOutcome::LegacyActive
        ) {
            anyhow::bail!(
                "unfinished v3-to-v4 migration: use its recovery workflow before restoring"
            );
        }
        Some(receipts)
    } else {
        None
    };
    policy_transaction::preflight_restore_pack_tree(guard)
        .context("refusing restore with an unsupported live packs/ tree")?;
    let receipts = match receipts {
        Some(receipts) => receipts,
        None => {
            let data = crate::config::state_dir::open_for_migration(guard)?;
            ReceiptStore::open(&data, guard)?
        }
    };
    let (before, live_membership) = match loader::load_config_v5_for_repair_under_migration_guard(
        guard,
        guard.canonical_master(),
        now,
    ) {
        Ok(live) => (
            Some(capture_coherent_loaded_v5_under_migration_guard(
                guard, &live, now,
            )?),
            Some(membership(&live.config.cluster, &live.config.node)),
        ),
        Err(loader::EditorGuardedLoadFailure::Diagnostics(_)) => {
            (None, raw_live_membership(guard)?)
        }
        Err(loader::EditorGuardedLoadFailure::Operational(error)) => return Err(error),
    };
    let repair = before.is_none();
    let master_name = guard
        .canonical_master()
        .file_name()
        .context("master has no name")?;
    let after = PolicyRevisionInventory::new(
        staged
            .members()
            .iter()
            .map(|member| {
                let path = if member.kind() == PolicyMemberKind::Master {
                    PathBuf::from(master_name)
                } else {
                    member.path().to_path_buf()
                };
                let PolicyMemberState::Present(bytes) = member.state() else {
                    anyhow::bail!("staged archive contains an absent member");
                };
                Ok(PolicyRevisionMember::present(
                    member.kind(),
                    path,
                    bytes.clone(),
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    )?;
    refuse_membership_change(guard, live_membership, archived)?;
    // On a secondary the replicated files belong to the ownership ledger;
    // replacing them would fail every later artifact apply.
    #[cfg(feature = "cluster")]
    crate::cluster::ledger::refuse_owned_changes(guard, &after, !repair)?;
    let destinations = if repair {
        Some(RepairDestinationSet::capture(guard, &after)?)
    } else {
        None
    };
    let after_paths: BTreeSet<_> = after.members().iter().map(|member| member.path()).collect();
    let mut toml_overlay = LoaderOverlay::default();
    let mut pack_overlay = PackOverlay::default();
    for member in after.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            anyhow::bail!("restore candidate contains an absent member");
        };
        if member.kind() == PolicyMemberKind::Pack {
            pack_overlay.stage(pack_id(member.path())?, bytes.clone());
        } else {
            let plan = guard.tree_io().plan_root_file_no_follow(member.path())?;
            toml_overlay.stage_plan_reachable_only(
                &plan,
                String::from_utf8(bytes.clone()).context("staged TOML is not UTF-8")?,
            )?;
        }
    }
    for member in before
        .iter()
        .flat_map(|(snapshot, _)| snapshot.inventory().members())
    {
        if !after_paths.contains(member.path()) {
            if member.kind() == PolicyMemberKind::Pack {
                pack_overlay.omit(pack_id(member.path())?);
            } else {
                let plan = guard.tree_io().plan_root_file_no_follow(member.path())?;
                toml_overlay.omit_plan(&plan)?;
            }
        }
    }

    let mut random = [0_u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow::anyhow!("restore request identity entropy: {error}"))?;
    let request_id = format!(
        "restore-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    // SAFETY: geteuid has no preconditions and cannot fail.
    let actor = format!("uid:{}", unsafe { libc::geteuid() });
    let (lookup_actor, lookup_request) = (actor.clone(), request_id.clone());
    let mut candidate_errors = None;
    let validate = || {
        custom_list::validate_flat_pack_tree_under_tree(guard.tree_io())?;
        let candidate =
            loader::load_config_v5_executable_with_policy_overlays_under_migration_guard(
                guard,
                guard.canonical_master(),
                now,
                Some(&toml_overlay),
                Some(&pack_overlay),
            )
            .map_err(|failure| match failure {
                GuardedLoadFailure::Diagnostics(errors) => {
                    candidate_errors = Some(errors.iter().map(ToString::to_string).collect());
                    anyhow::anyhow!("restored candidate failed validation")
                }
                GuardedLoadFailure::UnsafePath(error)
                | GuardedLoadFailure::BudgetExceeded(error)
                | GuardedLoadFailure::TreeChanged(error)
                | GuardedLoadFailure::RecoveryRequired(error)
                | GuardedLoadFailure::Storage(error) => error,
            })?;
        let root = guard
            .canonical_master()
            .parent()
            .context("master has no parent")?;
        let expected: BTreeSet<_> = after
            .members()
            .iter()
            .filter(|member| member.kind() != PolicyMemberKind::Pack)
            .map(|member| root.join(member.path()))
            .collect();
        let actual: BTreeSet<_> = candidate.files_loaded.into_iter().collect();
        if actual != expected {
            candidate_errors = Some(vec![
                    "restored include graph would adopt an unowned live TOML file or omit an archived member; resolve the include collision before restoring".to_owned(),
                ]);
            anyhow::bail!("restored include graph differs from its closed inventory");
        }
        let expected_packs: BTreeSet<_> = after
            .members()
            .iter()
            .filter(|member| member.kind() == PolicyMemberKind::Pack)
            .map(|member| member.path().to_path_buf())
            .collect();
        let actual_packs: BTreeSet<_> = candidate
            .config
            .custom_lists
            .iter()
            .map(|list| custom_list::pack_path(Path::new(""), &list.id))
            .collect();
        if actual_packs != expected_packs {
            candidate_errors = Some(vec![
                "restored pack declarations differ from the archived inventory".to_owned(),
            ]);
            anyhow::bail!("restored pack graph differs from its closed inventory");
        }
        Ok(())
    };
    let result = if let Some(before) = &before {
        let request = TransactionRequest {
            request_id,
            actor,
            origin: "cli".to_owned(),
            operation: "config.restore".to_owned(),
            payload: after.revision().as_bytes().to_vec(),
            expected_revision: before.0.revision(),
            source_schema: u64::from(SCHEMA_VERSION),
            target_schema: u64::from(SCHEMA_VERSION),
        };
        policy_transaction::apply(
            guard,
            &receipts,
            &request,
            before.0.inventory(),
            &after,
            validate,
        )
    } else {
        let destinations = destinations.context("repair destinations were not captured")?;
        let request = RepairRequest {
            request_id,
            actor,
            origin: "cli".to_owned(),
            operation: "config.restore.repair".to_owned(),
            payload: Vec::new(),
            expected_destinations: destinations.revision(),
            source_schema: u64::from(SCHEMA_VERSION),
            target_schema: u64::from(SCHEMA_VERSION),
        };
        policy_transaction::apply_repair(&receipts, &request, destinations, validate)
    };
    if let Some(errors) = candidate_errors {
        return Ok(RestoreOutcome::ValidationFailed(errors));
    }
    let restored = |receipt: &policy_transaction::BaseReceipt| RestoreOutcome::Restored {
        pre_restore: None,
        changed: receipt.changed_members != 0,
        repair,
    };
    // `commit` never errs, so an Err comes from prepare, which leaves live
    // members alone.
    let (stage, transaction, failure) = match result {
        Ok(receipt) if receipt.persistence == Persistence::Committed => {
            return Ok(restored(&receipt))
        }
        Ok(receipt) => (
            "commit",
            receipt.transaction_id,
            receipt
                .failure
                .unwrap_or_else(|| format!("persistence {:?}", receipt.persistence)),
        ),
        Err(error) => ("prepare", String::new(), format!("{error:#}")),
    };
    // Settle the failure while this guard still holds the tree: recovery
    // rolls the transaction back or finishes it, and the terminal receipt
    // says which. Only `Aborted` or a prepare failure proves "unchanged".
    match policy_transaction::lookup_receipt(guard, &receipts, &lookup_actor, &lookup_request) {
        Ok(Some(receipt)) if receipt.persistence == Persistence::Committed => {
            Ok(restored(&receipt))
        }
        Ok(Some(receipt)) if receipt.persistence == Persistence::Aborted => anyhow::bail!(
            "restore rolled back after a {stage} failure (transaction {}): live config \
             unchanged; daemon activation was not requested: {failure}",
            receipt.transaction_id
        ),
        Ok(None) if stage == "prepare" => {
            anyhow::bail!("{failure}; live config unchanged")
        }
        Ok(_) => Err(uncertain_restore(&transaction, &lookup_request, &failure)),
        Err(error) => Err(uncertain_restore(
            &transaction,
            &lookup_request,
            &format!("{failure}; recovery: {error:#}"),
        )),
    }
}

/// A failed commit that recovery could not settle. It never says
/// "unchanged": only boot recovery can tell.
fn uncertain_restore(transaction: &str, request: &str, detail: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "restore state is uncertain (transaction {transaction}, request {request}): run \
         `systemctl restart purge-warden` so boot recovery settles it before another write; \
         daemon activation was not requested. See \"{}\" in docs/UPGRADE_RECOVERY.md \
         ({detail})",
        crate::config::migration_journal::POLICY_RECOVERY_SECTION
    )
}

fn pack_id(path: &Path) -> anyhow::Result<Id> {
    Id::new(
        path.file_stem()
            .and_then(OsStr::to_str)
            .context("pack has no valid ID")?,
    )
    .map_err(anyhow::Error::from)
}

/// CLI entry point. Returns the intended process exit code (0 success,
/// 1 staged-config validation failure); hard I/O / archive errors
/// propagate as `Err`. Prints the human summary and, given a `pid_file`,
/// sends `SIGHUP` so a running daemon reloads.
pub fn run_restore(
    live_config: &Path,
    archive: &Path,
    pid_file: Option<&Path>,
) -> anyhow::Result<i32> {
    match restore_archive(live_config, archive)? {
        RestoreOutcome::ValidationFailed(errs) => {
            eprintln!(
                "staged config failed validation ({} error(s)) — live config untouched:",
                errs.len()
            );
            for e in &errs {
                eprintln!("  - {e}");
            }
            Ok(1)
        }
        RestoreOutcome::Restored {
            pre_restore,
            changed,
            repair,
        } => {
            if !changed {
                println!("config already matches the archive; no reload requested");
                return Ok(0);
            }
            if let Some(prev) = &pre_restore {
                println!("saved previous config as {}", prev.display());
            }
            if repair {
                println!(
                    "repaired invalid config at {}; unnamed paths retained",
                    live_config.display()
                );
            } else {
                println!("restored config to {}", live_config.display());
            }
            if let Some(pid) = pid_file {
                if let Err(e) = send_sighup_from_pid(pid) {
                    eprintln!(
                        "note: SIGHUP reload failed: {e} — run `systemctl reload purge-warden` manually"
                    );
                } else {
                    println!("sent SIGHUP — daemon activation is pending");
                }
            }
            Ok(0)
        }
    }
}

/// Self-cleaning, CSPRNG-named `0o700` staging directory. Only restore uses
/// it: it holds the pinned archive copy and the extracted tree.
pub(crate) struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    /// Create a CSPRNG-named `0o700` staging dir under the system temp dir.
    /// Used by `restore`, which only *copies* out of staging (cross-filesystem
    /// is fine).
    pub(crate) fn create() -> anyhow::Result<Self> {
        Self::create_in(&std::env::temp_dir())
    }

    /// Create a CSPRNG-named `0o700` staging dir under `parent`.
    ///
    /// Exclusive + unpredictable. A fixed/predictable name with `create_dir_all`
    /// succeeds on EEXIST — so a local attacker could pre-create the dir or
    /// plant a symlink there and interpose on the validate↔install window (a
    /// classic TOCTOU; these flows may run privileged and write into system
    /// config dirs). `OsRng` (CSPRNG, per CLAUDE.md) names it and
    /// `DirBuilder::create` (NOT create_dir_all) fails on EEXIST, so we either
    /// own a freshly-made `0o700` directory or we abort.
    ///
    /// `parent` lets a caller pin staging onto a specific filesystem —
    /// `migrate` promotes staging→target with `rename(2)`, which `EXDEV`-fails
    /// across filesystems, so it must stage under the target dir, not `/tmp`.
    pub(crate) fn create_in(parent: &Path) -> anyhow::Result<Self> {
        use rand_core::{OsRng, RngCore};
        use std::os::unix::fs::DirBuilderExt;
        let mut rng = OsRng;
        for _ in 0..8 {
            let path = parent.join(format!(
                "purge-warden-stage-{}-{:016x}",
                std::process::id(),
                rng.next_u64()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "cannot create staging directory {}: {}",
                        path.display(),
                        e
                    ))
                }
            }
        }
        anyhow::bail!(
            "cannot create a unique staging directory under {} after 8 attempts",
            parent.display()
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        // Best-effort cleanup — leaving a few KB of staged config on a
        // panic path is preferable to erroring out during unwinding.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn extract_archive(archive: &Path, dest: &Path, scratch: &Path) -> anyhow::Result<()> {
    // Defend against a hostile backup archive. Before extracting,
    // list the members and reject any that could write outside `dest`:
    // absolute paths, `..` traversal, or symlink/hardlink members (a crafted
    // archive can use a symlink member to redirect a later write outside the
    // staging root). `restore` may run privileged and writes into system
    // config dirs, so an escape is an arbitrary-file-write primitive. Modern
    // GNU tar strips leading `/` and refuses `..` by default, but BSD/busybox
    // tar are weaker — so we enforce it ourselves rather than trust the
    // extractor.
    reject_hostile_members(archive, scratch)?;

    // `reject_hostile_members` above is the portable path enforcement, and
    // GNU tar additionally strips leading `/` and refuses `..` by default.
    let status = tar_command(archive, TarRun::Extract(dest))
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run tar: {}", e))?;
    if !status.success() {
        anyhow::bail!("tar -xzf {} exited with {status}", archive.display());
    }
    Ok(())
}

/// Reject a backup archive whose members could escape the staging root on
/// extraction: absolute paths, `..` traversal, or symlink/hardlink members.
/// Two passes so neither check is fooled by member names containing spaces:
/// `-tzf` yields one exact member path per line (path-safety check), `-tvzf`
/// adds the leading type column (`l` symlink, `h` hardlink) and the size.
/// The passes also cap the member count and the announced extracted bytes.
fn reject_hostile_members(archive: &Path, scratch: &Path) -> anyhow::Result<()> {
    let mut members = 0_usize;
    run_tar_list(
        tar_command(archive, TarRun::Names),
        archive,
        scratch,
        |name| {
            members += 1;
            anyhow::ensure!(
                members <= MAX_ARCHIVE_MEMBERS,
                "refusing archive: more than {MAX_ARCHIVE_MEMBERS} members"
            );
            let name = name.trim_end_matches('/'); // dir entries list with a trailing '/'
            if !name.is_empty() && is_unsafe_member_path(name) {
                anyhow::bail!(
                    "refusing archive: member '{name}' is absolute or contains '..' \
                 (path traversal) — a backup must not write outside the staging dir"
                );
            }
            Ok(())
        },
    )?;
    // Second pass: the leading type column of `-tvzf` classifies each member.
    // Whitelist regular files (`-`) and directories (`d`); reject everything
    // else — symlink (`l`), hardlink (`h`), char/block device (`c`/`b`), FIFO
    // (`p`), socket (`s`). A blacklist that only catches `l`/`h` lets a
    // device/fifo/socket member through. A legit backup
    // (`tar -czf` of the config dir) holds only files and dirs, so this is a
    // fail-fast on obviously-hostile archives; the descriptor-rooted copy
    // re-checks extracted entries before they enter the live tree.
    let mut total = 0_u64;
    run_tar_list(
        tar_command(archive, TarRun::Long),
        archive,
        scratch,
        |line| {
            match line.as_bytes().first() {
                None => return Ok(()),        // blank line
                Some(b'-') | Some(b'd') => {} // regular file or directory — allowed
                Some(_) => anyhow::bail!(
                    "refusing archive: member is not a regular file or directory \
                 — symlink/hardlink/device/fifo/socket members can escape the \
                 staging directory ({})",
                    line.trim()
                ),
            }
            let size = listed_member_size(line).with_context(|| {
                format!(
                    "refusing archive: unexpected listing line ({})",
                    line.trim()
                )
            })?;
            total = total.saturating_add(size);
            anyhow::ensure!(
                total <= MAX_EXTRACTED_BYTES,
                "refusing archive: its members hold more than {MAX_EXTRACTED_BYTES} bytes"
            );
            Ok(())
        },
    )
}

/// The size column of a `tar --numeric-owner -tv` line for a regular file or
/// a directory, or `None` unless the mode, `UID/GID` and size columns have
/// exactly that shape. Numeric owners keep a group name with a space and a
/// digit from shifting the size column.
fn listed_member_size(line: &str) -> Option<u64> {
    let mut fields = line.split_whitespace();
    let (mode, owner, size) = (fields.next()?, fields.next()?, fields.next()?);
    let digits = |field: &str| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit());
    let mode_ok = mode.len() == 10
        && mode.starts_with(['-', 'd'])
        && mode.bytes().skip(1).all(|b| b"rwxsStT-".contains(&b));
    let owner_ok = owner
        .split_once('/')
        .is_some_and(|(uid, gid)| digits(uid) && digits(gid));
    if mode_ok && owner_ok && digits(size) {
        size.parse().ok()
    } else {
        None
    }
}

/// What one tar run does.
enum TarRun<'a> {
    /// `-t`: one member path per line.
    Names,
    /// `-tv` with numeric owners.
    Long,
    /// `-x` into the given directory, without the archive's owners or
    /// set-id bits (GNU tar restores both by default when run as root).
    Extract(&'a Path),
}

/// One tar run on `archive`. `TAR_OPTIONS` from the caller's environment
/// could add flags, so it is removed.
fn tar_command(archive: &Path, run: TarRun<'_>) -> std::process::Command {
    let mut command = std::process::Command::new("tar");
    command.env_remove("TAR_OPTIONS");
    match run {
        TarRun::Names => command.arg("-tzf"),
        TarRun::Long => command.args(["--numeric-owner", "-tvzf"]),
        // `-C <dest>` must precede `-f <archive>` so it names the destination.
        TarRun::Extract(dest) => command
            .args(["--no-same-owner", "--no-same-permissions", "-C"])
            .arg(dest)
            .arg("-xzf"),
    };
    command.arg(archive);
    command
}

/// Run a tar listing and pass each stdout line to `each_line`. At most
/// [`MAX_LISTING_BYTES`] are read; past that, or when `each_line` refuses,
/// tar is killed and reaped. Stderr goes to an unnamed file in `scratch`, so
/// no pipe can block tar, and at most its first 4 KiB are quoted.
fn run_tar_list(
    mut command: std::process::Command,
    archive: &Path,
    scratch: &Path,
    mut each_line: impl FnMut(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut stderr = tempfile::tempfile_in(scratch)?;
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(stderr.try_clone()?)
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to list archive {}: {}", archive.display(), e))?;
    let stdout = child.stdout.take().context("tar listing has no stdout")?;
    let scanned = scan_listing(stdout, &mut each_line);
    if scanned.is_err() {
        // Stop tar at once rather than reap it after a full listing.
        let _ = child.kill();
    }
    let status = child.wait()?;
    scanned?;
    if !status.success() {
        let mut quoted = Vec::new();
        stderr.rewind()?;
        (&stderr)
            .take(MAX_TAR_STDERR_BYTES)
            .read_to_end(&mut quoted)?;
        anyhow::bail!(
            "cannot list archive {} ({}): {}",
            archive.display(),
            status,
            String::from_utf8_lossy(&quoted).trim()
        );
    }
    Ok(())
}

fn scan_listing(
    stdout: std::process::ChildStdout,
    each_line: &mut impl FnMut(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut reader = std::io::BufReader::new(stdout.take(MAX_LISTING_BYTES + 1));
    let mut seen = 0_u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        seen += read as u64;
        anyhow::ensure!(
            seen <= MAX_LISTING_BYTES,
            "refusing archive: its listing is longer than {MAX_LISTING_BYTES} bytes"
        );
        each_line(String::from_utf8_lossy(&line).trim_end_matches('\n'))?;
    }
}

/// True if `name` is an absolute path or contains a `..` / root component —
/// either lets an archive member escape the extraction root.
fn is_unsafe_member_path(name: &str) -> bool {
    let p = Path::new(name);
    p.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    })
}

/// Select one safe root-level staged master. Hints preserve old archives;
/// ambiguity is never resolved by filesystem enumeration order.
fn locate_staged_master(staging: &Path, live_config: &Path) -> anyhow::Result<PathBuf> {
    let requested_name = live_config
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("live config has no file name"))?
        .to_os_string();
    let canonical_name = write_lock::ConfigTreeIdentity::resolve(live_config)
        .ok()
        .and_then(|identity| {
            identity
                .canonical_master
                .file_name()
                .map(OsStr::to_os_string)
        });

    let entries: Vec<PathBuf> = std::fs::read_dir(staging)?
        .map(|entry| entry.map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        // `file_type` is lstat-based, so a staged symlink never becomes a
        // master hint merely because its destination is a regular file.
        .filter(|entry| entry.file_type().map(|ty| ty.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()) != Some(crate::config::secrets::SECRETS_FILENAME)
        })
        .collect();
    if let Some(path) = entries
        .iter()
        .find(|path| path.file_name() == Some(requested_name.as_os_str()))
    {
        return Ok(path.clone());
    }
    if let Some(canonical_name) = canonical_name {
        if let Some(path) = entries
            .iter()
            .find(|path| path.file_name() == Some(canonical_name.as_os_str()))
        {
            return Ok(path.clone());
        }
    }
    let mut candidates: Vec<PathBuf> = entries
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    candidates.sort();
    if candidates.len() == 1 {
        return Ok(candidates.remove(0));
    }
    if candidates.is_empty() {
        anyhow::bail!(
            "no master *.toml found in staged archive at {}",
            staging.display()
        );
    }
    anyhow::bail!(
        "ambiguous staged archive at {}: multiple non-secrets root TOML files ({})",
        staging.display(),
        candidates
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn send_sighup_from_pid(pid_file: &Path) -> anyhow::Result<()> {
    // The shared sender signals only the process that holds the PID-file lock
    // and runs as the file's owner; each refusal names the PID file.
    crate::cli::commands::pid::send_signal(pid_file, "HUP").map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::config::backup::run_backup;
    use crate::config::migration_journal;
    use std::os::unix::fs::PermissionsExt;

    const BASE: &str = r#"schema_version = 5

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn restore_roundtrip_reinstates_identical_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, BASE).unwrap();
        let archive = run_backup(&config, None).unwrap();
        std::fs::write(&config, format!("{BASE}\n# edited\n")).unwrap();

        assert_eq!(run_restore(&config, &archive, None).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), BASE);
        assert!(!dir.path().join(migration_journal::TXN_DIR_NAME).exists());
        assert!(dir.path().join(policy_transaction::STORE_DIR_NAME).is_dir());
    }

    #[test]
    fn staged_inventory_admits_the_exact_transaction_budget_and_rejects_plus_one() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!("{BASE}\n[[custom_lists]]\nid = \"streaming\"\n"),
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        let pack = b"||media.example.test^\n";
        std::fs::write(dir.path().join("packs/streaming.txt"), pack).unwrap();
        let loaded = loader::load_config_v5(&config, time::OffsetDateTime::UNIX_EPOCH).unwrap();
        let exact = std::fs::metadata(&config).unwrap().len() + pack.len() as u64;

        assert!(staged_inventory_with_budget(&loaded, exact).is_ok());
        let error = staged_inventory_with_budget(&loaded, exact - 1)
            .expect_err("one byte over the transaction budget must reject before retention");
        assert!(
            error
                .to_string()
                .contains("unsafe or oversized staged file"),
            "{error:#}"
        );
    }

    #[test]
    fn restore_uses_one_write_guard_and_releases_it_before_return() {
        use std::cell::Cell;
        use std::rc::Rc;
        use std::time::Duration;

        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, format!("{BASE}\n# edited\n")).unwrap();
        let acquisitions = Rc::new(Cell::new(0));
        let seen = Rc::clone(&acquisitions);
        let outcome = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    seen.set(seen.get() + 1);
                }
            },
            || restore_archive(&live_config, &archive),
        )
        .unwrap();
        assert!(matches!(outcome, RestoreOutcome::Restored { .. }));
        assert_eq!(acquisitions.get(), 1);

        let probe =
            write_lock::acquire_for_write_with_timeout(&live_config, Duration::from_millis(50))
                .expect("restore must release its guard before returning");
        drop(probe);
    }

    #[test]
    fn restore_refuses_a_migration_fence_before_live_effects() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();
        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        let fence = live.path().join(migration_journal::TXN_DIR_NAME);
        std::fs::create_dir(&fence).unwrap();
        std::fs::set_permissions(&fence, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = fence.join("journal.json");
        let legacy = b"{\"format_version\":1}\n";
        std::fs::write(&journal, legacy).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = restore_archive(&live_config, &archive).unwrap_err();
        assert!(
            error.to_string().contains("unfinished v3-to-v4 migration"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_to_string(&live_config).unwrap(), BASE);
        assert_eq!(std::fs::read(&journal).unwrap(), legacy);
        assert!(!live
            .path()
            .join(policy_transaction::STORE_DIR_NAME)
            .exists());
        assert_eq!(std::fs::read_dir(&fence).unwrap().count(), 1);
    }

    #[test]
    fn restore_through_an_alias_updates_only_the_canonical_master() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();
        let live = tempfile::tempdir().unwrap();
        let real = live.path().join("real");
        let front = live.path().join("front");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&front).unwrap();
        let canonical = real.join("config.toml");
        std::fs::write(&canonical, format!("{BASE}\n# edited\n")).unwrap();
        let alias = front.join("active.toml");
        symlink("../real/config.toml", &alias).unwrap();

        assert!(matches!(
            restore_archive(&alias, &archive).unwrap(),
            RestoreOutcome::Restored {
                changed: true,
                pre_restore: None,
                repair: false,
            }
        ));
        assert!(std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&canonical).unwrap(), BASE);
        assert_eq!(std::fs::read_to_string(&alias).unwrap(), BASE);
        assert!(real.join(policy_transaction::STORE_DIR_NAME).is_dir());
        assert!(real.join(policy_transaction::RECEIPT_DIR).is_dir());
        assert!(!front.join(policy_transaction::RECEIPT_DIR).exists());
    }

    /// An include that does NOT live in a `<class>.d/` directory must
    /// survive backup and come back on restore.
    ///
    /// Pre-fix, `KNOWN_INCLUDE_DIRS` listed seven names, `custom` was not
    /// one of them, and the archive silently omitted the file. Restore
    /// then reinstalled the master alone — so the operator got back a
    /// config referencing a profile whose defining file was gone, and
    /// found out at the worst possible moment.
    ///
    /// The fixture makes `custom/` the ONLY home of the `kids` profile and
    /// `server.default_profile` points at it, so a restore that drops the
    /// directory produces a config that does not load — an assertion the
    /// old behaviour cannot satisfy by accident.
    #[test]
    fn roundtrip_preserves_a_non_conventional_include_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 5\nincludes = [\"custom/*.toml\"]\n\n\
             [server]\ndefault_profile = \"kids\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("custom")).unwrap();
        let slice = dir.path().join("custom").join("policy.toml");
        std::fs::write(&slice, "[profiles.kids]\ndisplay_name = \"Kids\"\n").unwrap();

        let archive = run_backup(&config, None).unwrap();

        // It must be IN the archive — assert on the tar listing, not just
        // on the end state, so a restore that quietly reused the surviving
        // live directory could not make this pass.
        let listing = String::from_utf8_lossy(
            &std::process::Command::new("tar")
                .arg("-tzf")
                .arg(&archive)
                .output()
                .expect("tar listing must run")
                .stdout,
        )
        .into_owned();
        assert!(
            listing.contains("custom/policy.toml"),
            "backup omitted the declared non-conventional include: {listing}"
        );

        // Replace the old declared graph with another valid policy.
        std::fs::remove_dir_all(dir.path().join("custom")).unwrap();
        std::fs::write(&config, BASE).unwrap();

        assert_eq!(run_restore(&config, &archive, None).unwrap(), 0);
        assert_eq!(
            std::fs::read_to_string(&slice).unwrap(),
            "[profiles.kids]\ndisplay_name = \"Kids\"\n",
            "custom/policy.toml was not reinstalled"
        );
        // The restored tree must actually load — the operator-visible half.
        let loaded = loader::load_config_v5(&config, time::OffsetDateTime::now_utc())
            .expect("restored config must load; a dropped include breaks default_profile");
        assert!(loaded.config.profiles.contains_key("kids"));
    }

    /// `includes = ["extra.toml"]` puts an include at the TOP
    /// level of the config directory rather than inside a directory.
    /// Backup can capture such a file, so restore has to be able to
    /// reinstall it — a captured-but-unrestorable include is the same
    /// silent omission one layer down.
    #[test]
    fn roundtrip_preserves_a_top_level_include_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 5\nincludes = [\"extra.toml\"]\n\n\
             [server]\ndefault_profile = \"kids\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let extra = dir.path().join("extra.toml");
        std::fs::write(&extra, "[profiles.kids]\ndisplay_name = \"Kids\"\n").unwrap();

        let archive = run_backup(&config, None).unwrap();
        std::fs::remove_file(&extra).unwrap();
        std::fs::write(&config, BASE).unwrap();

        assert_eq!(run_restore(&config, &archive, None).unwrap(), 0);
        assert!(
            extra.exists(),
            "a top-level include FILE was captured but not reinstalled"
        );
        let loaded = loader::load_config_v5(&config, time::OffsetDateTime::now_utc())
            .expect("restored config must load");
        assert!(loaded.config.profiles.contains_key("kids"));
    }

    /// The install set is bounded by what the staged master DECLARES, not
    /// by what the archive happens to contain. An operator-supplied
    /// archive carrying an extra directory must not get it written into
    /// the live config tree just by being in the tarball.
    #[test]
    fn restore_does_not_promote_an_undeclared_archive_member() {
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(&src_config, BASE).unwrap();
        std::fs::create_dir(src.path().join("stowaway")).unwrap();
        std::fs::write(src.path().join("stowaway").join("x.toml"), "payload").unwrap();
        // The sweep captures it (backup is deliberately inclusive) …
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        // … but restore promotes only what the staged master declares,
        // and BASE declares no includes.
        assert!(
            !live.path().join("stowaway").exists(),
            "an archive member no include references was written into the live config dir"
        );
    }

    #[test]
    fn restore_reinstates_the_pack_file_of_a_declared_custom_list() {
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(
            &src_config,
            format!("{BASE}\n[[custom_lists]]\nid = \"minecraft\"\n"),
        )
        .unwrap();
        std::fs::create_dir(src.path().join("packs")).unwrap();
        std::fs::write(
            src.path().join("packs").join("minecraft.txt"),
            "@@||cdn.example.com^\n",
        )
        .unwrap();
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        let restored = live.path().join("packs").join("minecraft.txt");
        assert!(
            restored.exists(),
            "restore reinstated a master declaring a custom list without its file — \
             the daemon will refuse to start"
        );
        assert!(std::fs::read_to_string(&restored)
            .unwrap()
            .contains("cdn.example.com"));
    }

    #[test]
    fn restore_still_refuses_a_pack_file_no_entry_declares() {
        // The discipline is unchanged: only what the staged master declares
        // is promoted. Only the declaration source is new.
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(&src_config, BASE).unwrap();
        std::fs::create_dir(src.path().join("packs")).unwrap();
        std::fs::write(
            src.path().join("packs").join("stowaway.txt"),
            "@@||evil.example.com^\n",
        )
        .unwrap();
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        assert!(
            !live.path().join("packs").join("stowaway.txt").exists(),
            "an undeclared pack file was promoted into the live config dir"
        );
    }

    #[test]
    fn restore_rejects_a_nested_pack_tree_before_touching_live_state() {
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(
            &src_config,
            format!("{BASE}\n[[custom_lists]]\nid = \"mine\"\n"),
        )
        .unwrap();
        std::fs::create_dir_all(src.path().join("packs/sub")).unwrap();
        std::fs::write(src.path().join("packs/mine.txt"), b"||ads.example.test^\n").unwrap();
        std::fs::write(src.path().join("packs/sub/x.txt"), b"nested\n").unwrap();
        let (_output, archive) = raw_archive(src.path());

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        let before = format!("{BASE}\n# live sentinel\n");
        std::fs::write(&live_config, &before).unwrap();

        let error = restore_archive(&live_config, &archive)
            .expect_err("a nested pack tree must be refused");
        assert!(error.to_string().contains("unsupported staged packs/ tree"));
        assert_eq!(std::fs::read_to_string(&live_config).unwrap(), before);
        assert_no_restore_artifacts(live.path());
        assert!(
            std::fs::read_dir(live.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("pre-restore")),
            "preflight must run before any live recovery artifact is created"
        );
    }

    #[test]
    fn restoring_an_old_master_deletes_only_previously_declared_packs() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();
        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(
            &live_config,
            format!("{BASE}\n[[custom_lists]]\nid = \"retired\"\n"),
        )
        .unwrap();
        std::fs::create_dir(live.path().join("packs")).unwrap();
        let retired = live.path().join("packs/retired.txt");
        let orphan = live.path().join("packs/orphan.txt");
        std::fs::write(&retired, "||old.example.test^\n").unwrap();
        std::fs::write(&orphan, "||orphan.example.test^\n").unwrap();
        let orphan_inode = std::fs::metadata(&orphan).unwrap().ino();

        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);
        loader::load_config_v5(&live_config, time::OffsetDateTime::now_utc()).unwrap();
        assert!(!retired.exists());
        assert_eq!(
            std::fs::read_to_string(&orphan).unwrap(),
            "||orphan.example.test^\n"
        );
        assert_eq!(std::fs::metadata(&orphan).unwrap().ino(), orphan_inode);
    }

    #[test]
    fn restore_rejects_archive_with_invalid_staged_config() {
        // Build an archive whose master config fails validation
        // (cross-ref miss); the live file must remain untouched.
        let good_dir = tempfile::tempdir().unwrap();
        let live = good_dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();

        let bad_dir = tempfile::tempdir().unwrap();
        let bad_config = bad_dir.path().join("config.toml");
        std::fs::write(
            &bad_config,
            r#"schema_version = 5

[server]
default_profile = "missing-profile"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let (_output, archive) = raw_archive(bad_dir.path());

        let rc = run_restore(&live, &archive, None).unwrap();
        assert_eq!(rc, 1, "invalid archive must not overwrite live config");
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    #[test]
    fn restore_rejects_uncompilable_pack_before_touching_live_state() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();

        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("config.toml"),
            r#"schema_version = 5

[server]
default_profile = "default"

[[custom_lists]]
id = "policy"

[profiles.default]
custom_lists = ["policy"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        std::fs::create_dir(source.path().join("packs")).unwrap();
        std::fs::write(source.path().join("packs/policy.txt"), "bad..example\n").unwrap();
        let (_output, archive) = raw_archive(source.path());

        assert!(matches!(
            restore_archive(&live, &archive).unwrap(),
            RestoreOutcome::ValidationFailed(errors)
                if errors.iter().any(|error| error.contains("row 1"))
        ));
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
        assert_no_restore_artifacts(live_dir.path());
    }

    fn raw_archive(root: &Path) -> (tempfile::TempDir, PathBuf) {
        let output = tempfile::tempdir().unwrap();
        let archive = output.path().join("archive.tar.gz");
        assert!(std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(root)
            .arg(".")
            .status()
            .unwrap()
            .success());
        (output, archive)
    }

    fn assert_no_restore_artifacts(root: &Path) {
        for name in [
            migration_journal::TXN_DIR_NAME,
            policy_transaction::STORE_DIR_NAME,
            policy_transaction::RECEIPT_DIR,
        ] {
            assert!(
                !root.join(name).exists(),
                "unexpected restore artifact: {name}"
            );
        }
        assert!(std::fs::read_dir(root).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            !name.contains("pre-restore") && !name.contains(".incoming-")
        }));
    }

    #[test]
    fn restore_repairs_invalid_or_absent_master_and_missing_or_invalid_include() {
        for kind in [
            "syntax",
            "schema",
            "absent",
            "missing-include",
            "invalid-include",
        ] {
            let source = tempfile::tempdir().unwrap();
            let archived = BASE.replacen(
                "schema_version = 5",
                "schema_version = 5\nincludes = [\"restored.toml\"]",
                1,
            );
            std::fs::write(source.path().join("config.toml"), &archived).unwrap();
            std::fs::write(source.path().join("restored.toml"), "[profiles.restored]\n").unwrap();
            let (_output, archive) = raw_archive(source.path());
            let live = tempfile::tempdir().unwrap();
            let master = live.path().join("config.toml");
            match kind {
                "syntax" => std::fs::write(&master, "[broken").unwrap(),
                "schema" => std::fs::write(&master, "damaged = true\n").unwrap(),
                "absent" => {}
                "missing-include" | "invalid-include" => {
                    std::fs::write(
                        &master,
                        BASE.replacen(
                            "schema_version = 5",
                            "schema_version = 5\nincludes = [\"stale.toml\"]",
                            1,
                        ),
                    )
                    .unwrap();
                    if kind == "invalid-include" {
                        std::fs::write(live.path().join("stale.toml"), "[broken").unwrap();
                    }
                }
                _ => unreachable!(),
            }
            let previous = std::fs::metadata(&master).ok();
            if previous.is_some() {
                std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            std::fs::write(live.path().join("unnamed.toml"), "# preserve\n").unwrap();
            let unnamed_inode = std::fs::metadata(live.path().join("unnamed.toml"))
                .unwrap()
                .ino();
            assert!(
                matches!(
                    restore_archive(&master, &archive).unwrap(),
                    RestoreOutcome::Restored {
                        changed: true,
                        repair: true,
                        ..
                    }
                ),
                "{kind}"
            );
            assert_eq!(std::fs::read_to_string(&master).unwrap(), archived);
            assert_eq!(
                std::fs::metadata(&master).unwrap().mode() & 0o777,
                if previous.is_some() { 0o600 } else { 0o640 }
            );
            assert_eq!(
                std::fs::metadata(live.path().join("unnamed.toml"))
                    .unwrap()
                    .ino(),
                unnamed_inode
            );
            if kind == "invalid-include" {
                assert_eq!(
                    std::fs::read(live.path().join("stale.toml")).unwrap(),
                    b"[broken"
                );
            }
            loader::load_config_v5(&master, time::OffsetDateTime::now_utc()).unwrap();
            let inode = std::fs::metadata(&master).unwrap().ino();
            assert!(matches!(
                restore_archive(&master, &archive).unwrap(),
                RestoreOutcome::Restored {
                    changed: false,
                    repair: false,
                    ..
                }
            ));
            assert_eq!(std::fs::metadata(&master).unwrap().ino(), inode);
            assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn repair_restores_named_packs_and_includes_without_deleting_stale_or_orphan_paths() {
        let source = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();
        for root in [source.path(), live.path()] {
            std::fs::create_dir(root.join("policy")).unwrap();
            std::fs::create_dir(root.join("packs")).unwrap();
        }
        let archived = BASE.replacen(
            "schema_version = 5",
            "schema_version = 5\nincludes = [\"policy/kept.toml\", \"policy/new.toml\"]",
            1,
        ) + "\n[[custom_lists]]\nid = \"kept\"\n[[custom_lists]]\nid = \"new\"\n";
        std::fs::write(source.path().join("config.toml"), &archived).unwrap();
        for (path, bytes) in [
            ("policy/kept.toml", "[profiles.kept]\n"),
            ("policy/new.toml", "[profiles.new]\n"),
            ("packs/kept.txt", "||kept.example.test^\n"),
            ("packs/new.txt", "||new.example.test^\n"),
        ] {
            std::fs::write(source.path().join(path), bytes).unwrap();
        }
        let master = live.path().join("config.toml");
        std::fs::write(&master, "[broken").unwrap();
        for path in [
            "policy/kept.toml",
            "policy/stale.toml",
            "packs/kept.txt",
            "packs/orphan.txt",
        ] {
            std::fs::write(live.path().join(path), "# old\n").unwrap();
            std::fs::set_permissions(
                live.path().join(path),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let unnamed: Vec<_> = ["policy/stale.toml", "packs/orphan.txt"]
            .into_iter()
            .map(|path| (path, std::fs::metadata(live.path().join(path)).unwrap()))
            .collect();
        let (_output, archive) = raw_archive(source.path());
        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored {
                repair: true,
                changed: true,
                ..
            }
        ));
        for path in [
            "policy/kept.toml",
            "policy/new.toml",
            "packs/kept.txt",
            "packs/new.txt",
        ] {
            assert_eq!(
                std::fs::read(live.path().join(path)).unwrap(),
                std::fs::read(source.path().join(path)).unwrap()
            );
            assert_eq!(
                std::fs::metadata(live.path().join(path)).unwrap().mode() & 0o777,
                if path.contains("kept") { 0o600 } else { 0o640 }
            );
        }
        for (path, metadata) in unnamed {
            assert_eq!(
                std::fs::metadata(live.path().join(path)).unwrap().ino(),
                metadata.ino()
            );
            assert_eq!(std::fs::read(live.path().join(path)).unwrap(), b"# old\n");
        }
        loader::load_config_v5(&master, time::OffsetDateTime::now_utc()).unwrap();
    }

    #[test]
    fn repair_rejects_archive_glob_adoption_before_intent() {
        let source = tempfile::tempdir().unwrap();
        let archived = BASE.replacen(
            "schema_version = 5",
            "schema_version = 5\nincludes = [\"policy/*.toml\"]",
            1,
        );
        std::fs::write(source.path().join("config.toml"), archived).unwrap();
        let (_output, archive) = raw_archive(source.path());
        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        std::fs::write(&master, "[broken").unwrap();
        std::fs::create_dir(live.path().join("policy")).unwrap();
        let orphan = live.path().join("policy/orphan.toml");
        std::fs::write(&orphan, "[profiles.orphan]\n").unwrap();
        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::ValidationFailed(_)
        ));
        assert_eq!(std::fs::read(&master).unwrap(), b"[broken");
        assert_eq!(std::fs::read(&orphan).unwrap(), b"[profiles.orphan]\n");
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    #[test]
    fn repair_rejects_unsafe_named_include_destinations() {
        for kind in ["symlink", "hardlink", "fifo", "socket", "directory"] {
            let source = tempfile::tempdir().unwrap();
            let archived = BASE.replacen(
                "schema_version = 5",
                "schema_version = 5\nincludes = [\"include.toml\"]",
                1,
            );
            std::fs::write(source.path().join("config.toml"), archived).unwrap();
            std::fs::write(source.path().join("include.toml"), "[profiles.included]\n").unwrap();
            let (_output, archive) = raw_archive(source.path());
            let live = tempfile::tempdir().unwrap();
            let master = live.path().join("config.toml");
            std::fs::write(&master, "[broken").unwrap();
            let bad = live.path().join("include.toml");
            let other = live.path().join("foreign.toml");
            std::fs::write(&other, "# preserve\n").unwrap();
            match kind {
                "symlink" => std::os::unix::fs::symlink(&other, &bad).unwrap(),
                "hardlink" => std::fs::hard_link(&other, &bad).unwrap(),
                "fifo" => {
                    let name = std::ffi::CString::new(bad.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: name is a valid NUL-terminated path and mode is valid.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "socket" => {
                    let _listener = std::os::unix::net::UnixListener::bind(&bad).unwrap();
                }
                "directory" => std::fs::create_dir(&bad).unwrap(),
                _ => unreachable!(),
            }
            let inode = std::fs::symlink_metadata(&bad).unwrap().ino();
            assert!(restore_archive(&master, &archive).is_err(), "{kind}");
            assert_eq!(std::fs::symlink_metadata(&bad).unwrap().ino(), inode);
            assert_eq!(std::fs::read(&master).unwrap(), b"[broken");
            assert_eq!(std::fs::read(&other).unwrap(), b"# preserve\n");
            assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn restore_rejects_unsafe_live_packs_before_creating_artifacts() {
        for kind in ["nested", "symlink", "hardlink", "fifo", "socket"] {
            let source = tempfile::tempdir().unwrap();
            std::fs::write(source.path().join("config.toml"), BASE).unwrap();
            let (_output, archive) = raw_archive(source.path());
            let live = tempfile::tempdir().unwrap();
            let master = live.path().join("config.toml");
            std::fs::write(&master, BASE).unwrap();
            std::fs::create_dir(live.path().join("packs")).unwrap();
            let bad = live.path().join("packs/unsafe.txt");
            match kind {
                "nested" => {
                    std::fs::create_dir(&bad).unwrap();
                    std::fs::write(bad.join("nested.txt"), "preserve\n").unwrap();
                }
                "symlink" => std::os::unix::fs::symlink(&master, &bad).unwrap(),
                "hardlink" => {
                    std::fs::hard_link(source.path().join("config.toml"), &bad).unwrap();
                }
                "fifo" => {
                    let name = std::ffi::CString::new(bad.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: name is a valid NUL-terminated path and mode is valid.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "socket" => {
                    let _listener = std::os::unix::net::UnixListener::bind(&bad).unwrap();
                }
                _ => unreachable!(),
            }
            let inode = std::fs::symlink_metadata(&bad).unwrap().ino();

            let error = restore_archive(&master, &archive).unwrap_err();
            assert!(
                error.to_string().contains("unsupported live packs/ tree"),
                "{kind}: {error:#}"
            );
            assert_eq!(std::fs::read_to_string(&master).unwrap(), BASE);
            assert_eq!(std::fs::symlink_metadata(&bad).unwrap().ino(), inode);
            assert_no_restore_artifacts(live.path());
        }
    }

    #[test]
    fn restore_mixes_named_creates_replacements_and_deletions_preserving_orphans() {
        let source = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();
        for root in [source.path(), live.path()] {
            std::fs::create_dir(root.join("policy")).unwrap();
            std::fs::create_dir(root.join("packs")).unwrap();
        }
        let archived = BASE.replacen(
            "schema_version = 5",
            "schema_version = 5\nincludes = [\"policy/shared.toml\", \"policy/created.toml\"]",
            1,
        )
            + "\n[[custom_lists]]\nid = \"shared\"\n[[custom_lists]]\nid = \"created\"\n";
        let current = BASE.replacen(
            "schema_version = 5",
            "schema_version = 5\nincludes = [\"policy/shared.toml\", \"policy/deleted.toml\"]",
            1,
        )
            + "\n[[custom_lists]]\nid = \"shared\"\n[[custom_lists]]\nid = \"deleted\"\n";
        let master = live.path().join("config.toml");
        std::fs::write(source.path().join("config.toml"), &archived).unwrap();
        std::fs::write(&master, current).unwrap();
        for (path, bytes) in [
            (
                "policy/shared.toml",
                "[profiles.shared]\ndisplay_name = \"New\"\n",
            ),
            ("policy/created.toml", "[profiles.created]\n"),
            ("packs/shared.txt", "@@||new.example.test^\n"),
            ("packs/created.txt", "||created.example.test^\n"),
        ] {
            std::fs::write(source.path().join(path), bytes).unwrap();
        }
        for (path, bytes) in [
            (
                "policy/shared.toml",
                "[profiles.shared]\ndisplay_name = \"Old\"\n",
            ),
            ("policy/deleted.toml", "[profiles.deleted]\n"),
            ("packs/shared.txt", "||old.example.test^\n"),
            ("packs/deleted.txt", "||deleted.example.test^\n"),
            ("policy/orphan.toml", "# operator-owned orphan\n"),
            ("packs/orphan.txt", "||orphan.example.test^\n"),
        ] {
            std::fs::write(live.path().join(path), bytes).unwrap();
        }
        let shared = live.path().join("packs/shared.txt");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o600)).unwrap();
        let root_inodes: Vec<_> = ["policy", "packs", "policy/orphan.toml", "packs/orphan.txt"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    std::fs::metadata(live.path().join(name)).unwrap().ino(),
                )
            })
            .collect();
        let (_output, archive) = raw_archive(source.path());

        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        assert_eq!(std::fs::read_to_string(&master).unwrap(), archived);
        for path in [
            "policy/shared.toml",
            "policy/created.toml",
            "packs/shared.txt",
            "packs/created.txt",
        ] {
            assert_eq!(
                std::fs::read(live.path().join(path)).unwrap(),
                std::fs::read(source.path().join(path)).unwrap(),
                "{path}"
            );
        }
        for path in ["policy/deleted.toml", "packs/deleted.txt"] {
            assert!(!live.path().join(path).exists(), "{path}");
        }
        for (path, inode) in root_inodes {
            assert_eq!(
                std::fs::metadata(live.path().join(path)).unwrap().ino(),
                inode,
                "{path}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(live.path().join("packs/orphan.txt")).unwrap(),
            "||orphan.example.test^\n"
        );
        assert_eq!(
            std::fs::read_to_string(live.path().join("policy/orphan.toml")).unwrap(),
            "# operator-owned orphan\n"
        );
        assert_eq!(std::fs::metadata(&shared).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(live.path().join("packs/created.txt"))
                .unwrap()
                .mode()
                & 0o777,
            0o640
        );
        loader::load_config_v5(&master, time::OffsetDateTime::now_utc()).unwrap();
    }

    #[test]
    fn restore_refuses_a_collision_with_an_undeclared_live_pack() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("config.toml"),
            format!("{BASE}\n[[custom_lists]]\nid = \"shared\"\n"),
        )
        .unwrap();
        std::fs::create_dir(source.path().join("packs")).unwrap();
        std::fs::write(
            source.path().join("packs/shared.txt"),
            "||new.example.test^\n",
        )
        .unwrap();
        let (_output, archive) = raw_archive(source.path());
        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        std::fs::write(&master, BASE).unwrap();
        std::fs::create_dir(live.path().join("packs")).unwrap();
        let orphan = live.path().join("packs/shared.txt");
        std::fs::write(&orphan, "||owned.example.test^\n").unwrap();
        let inode = std::fs::metadata(&orphan).unwrap().ino();

        let error = restore_archive(&master, &archive).unwrap_err();
        assert!(error.to_string().contains("RevisionConflict"), "{error:#}");
        assert_eq!(std::fs::read_to_string(&master).unwrap(), BASE);
        assert_eq!(
            std::fs::read_to_string(&orphan).unwrap(),
            "||owned.example.test^\n"
        );
        assert_eq!(std::fs::metadata(&orphan).unwrap().ino(), inode);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    #[test]
    fn restore_revalidates_the_complete_live_candidate_before_intent() {
        for orphan_bytes in ["[profiles.default]\n", "[profiles.orphan]\n"] {
            let source = tempfile::tempdir().unwrap();
            let candidate = BASE.replacen(
                "schema_version = 5",
                "schema_version = 5\nincludes = [\"extra/*.toml\"]",
                1,
            ) + "\n[[custom_lists]]\nid = \"created\"\n";
            std::fs::write(source.path().join("config.toml"), candidate).unwrap();
            std::fs::create_dir(source.path().join("packs")).unwrap();
            std::fs::write(
                source.path().join("packs/created.txt"),
                "||created.example.test^\n",
            )
            .unwrap();
            let (_output, archive) = raw_archive(source.path());
            let live = tempfile::tempdir().unwrap();
            let master = live.path().join("config.toml");
            std::fs::write(&master, BASE).unwrap();
            std::fs::create_dir(live.path().join("extra")).unwrap();
            let orphan = live.path().join("extra/orphan.toml");
            std::fs::write(&orphan, orphan_bytes).unwrap();

            assert!(matches!(
                restore_archive(&master, &archive).unwrap(),
                RestoreOutcome::ValidationFailed(_)
            ));
            assert_eq!(std::fs::read_to_string(&master).unwrap(), BASE);
            assert_eq!(std::fs::read_to_string(&orphan).unwrap(), orphan_bytes);
            assert!(!live.path().join("packs").exists());
            assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn restore_propagates_a_pack_tree_race_as_an_operational_failure() {
        use std::cell::Cell;
        use std::rc::Rc;

        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("config.toml"),
            format!("{BASE}\n# restored\n"),
        )
        .unwrap();
        let (_output, archive) = raw_archive(source.path());
        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        let current = format!("{BASE}\n# current\n");
        std::fs::write(&master, &current).unwrap();
        let events = Rc::new(Cell::new(0_usize));
        let seen = Rc::clone(&events);
        let packs = live.path().join("packs");

        let result = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::OverlayResolved {
                    let count = seen.get() + 1;
                    seen.set(count);
                    if count == 3 {
                        std::fs::create_dir_all(&packs).unwrap();
                        std::fs::create_dir(packs.join("late-subtree")).unwrap();
                    }
                }
            },
            || restore_archive(&master, &archive),
        );

        let error = result.expect_err("pack-tree drift must stay operational");
        assert!(
            error.to_string().contains("pack tree") || error.to_string().contains("custom list"),
            "{error:#}"
        );
        assert_eq!(events.get(), 3);
        assert_eq!(std::fs::read_to_string(&master).unwrap(), current);
        assert!(live.path().join("packs/late-subtree").is_dir());
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    #[test]
    fn restore_recovers_a_prepared_transaction_before_capturing_live_revision() {
        let source = tempfile::tempdir().unwrap();
        let desired = format!("{BASE}\n# restored\n");
        std::fs::write(source.path().join("config.toml"), &desired).unwrap();
        let (_output, archive) = raw_archive(source.path());
        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        std::fs::write(&master, BASE).unwrap();
        {
            let guard = write_lock::acquire_for_migration(&master).unwrap();
            let data = crate::config::state_dir::open_for_migration(&guard).unwrap();
            let receipts = ReceiptStore::open(&data, &guard).unwrap();
            let before = PolicyRevisionInventory::new(vec![PolicyRevisionMember::present(
                PolicyMemberKind::Master,
                PathBuf::from("config.toml"),
                BASE.as_bytes().to_vec(),
            )
            .unwrap()])
            .unwrap();
            let after = PolicyRevisionInventory::new(vec![PolicyRevisionMember::present(
                PolicyMemberKind::Master,
                PathBuf::from("config.toml"),
                format!("{BASE}\n# interrupted\n").into_bytes(),
            )
            .unwrap()])
            .unwrap();
            let request = TransactionRequest {
                request_id: "interrupted-restore".to_owned(),
                actor: "restore-test".to_owned(),
                origin: "cli".to_owned(),
                operation: "config.restore".to_owned(),
                payload: b"interrupted".to_vec(),
                expected_revision: before.revision(),
                source_schema: u64::from(SCHEMA_VERSION),
                target_schema: u64::from(SCHEMA_VERSION),
            };
            let prepared = policy_transaction::prepare(
                &guard,
                &receipts,
                &request,
                &before,
                &after,
                || Ok(()),
            )
            .unwrap();
            assert!(matches!(
                prepared,
                policy_transaction::PrepareOutcome::Prepared(_)
            ));
            drop(prepared);
        }
        assert!(live.path().join(migration_journal::TXN_DIR_NAME).exists());

        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        assert_eq!(std::fs::read_to_string(&master).unwrap(), desired);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
        loader::load_config_v5(&master, time::OffsetDateTime::now_utc()).unwrap();
    }

    #[test]
    fn restore_recovers_a_linked_pack_rollback_stage_before_live_pack_preflight() {
        let source = tempfile::tempdir().unwrap();
        let desired = format!("{BASE}\n[[custom_lists]]\nid = \"payload\"\n# restored\n");
        std::fs::write(source.path().join("config.toml"), &desired).unwrap();
        std::fs::create_dir(source.path().join("packs")).unwrap();
        std::fs::write(
            source.path().join("packs/payload.txt"),
            "||restored.example.test^\n",
        )
        .unwrap();
        let (_output, archive) = raw_archive(source.path());

        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        let current = format!("{BASE}\n[[custom_lists]]\nid = \"payload\"\n# current\n");
        let before_pack = b"||before.example.test^\n";
        std::fs::write(&master, &current).unwrap();
        std::fs::create_dir(live.path().join("packs")).unwrap();
        let pack = live.path().join("packs/payload.txt");
        std::fs::write(&pack, before_pack).unwrap();

        let stage_name = ".warden-write-0123456789abcdef0123456789abcdef";
        {
            let guard = write_lock::acquire_for_migration(&master).unwrap();
            let data = crate::config::state_dir::open_for_migration(&guard).unwrap();
            let receipts = ReceiptStore::open(&data, &guard).unwrap();
            let before = PolicyRevisionInventory::new(vec![
                PolicyRevisionMember::present(
                    PolicyMemberKind::Master,
                    PathBuf::from("config.toml"),
                    current.as_bytes().to_vec(),
                )
                .unwrap(),
                PolicyRevisionMember::present(
                    PolicyMemberKind::Pack,
                    PathBuf::from("packs/payload.txt"),
                    before_pack.to_vec(),
                )
                .unwrap(),
            ])
            .unwrap();
            let after = PolicyRevisionInventory::new(vec![
                PolicyRevisionMember::present(
                    PolicyMemberKind::Master,
                    PathBuf::from("config.toml"),
                    format!("{current}\n# interrupted\n").into_bytes(),
                )
                .unwrap(),
                PolicyRevisionMember::present(
                    PolicyMemberKind::Pack,
                    PathBuf::from("packs/payload.txt"),
                    b"||interrupted.example.test^\n".to_vec(),
                )
                .unwrap(),
            ])
            .unwrap();
            let request = TransactionRequest {
                request_id: "interrupted-pack-restore".to_owned(),
                actor: "restore-test".to_owned(),
                origin: "cli".to_owned(),
                operation: "config.restore".to_owned(),
                payload: b"interrupted-pack".to_vec(),
                expected_revision: before.revision(),
                source_schema: u64::from(SCHEMA_VERSION),
                target_schema: u64::from(SCHEMA_VERSION),
            };
            let prepared = match policy_transaction::prepare(
                &guard,
                &receipts,
                &request,
                &before,
                &after,
                || Ok(()),
            )
            .unwrap()
            {
                policy_transaction::PrepareOutcome::Prepared(transaction) => transaction,
                policy_transaction::PrepareOutcome::Replay(_) => panic!("unexpected replay"),
            };

            let stage = live.path().join("packs").join(stage_name);
            std::fs::write(&stage, before_pack).unwrap();
            std::fs::set_permissions(&stage, std::fs::metadata(&pack).unwrap().permissions())
                .unwrap();
            let stage_metadata = std::fs::metadata(&stage).unwrap();
            let pack_directory = std::fs::metadata(live.path().join("packs")).unwrap();
            let journal_path = live
                .path()
                .join(migration_journal::TXN_DIR_NAME)
                .join(migration_journal::JOURNAL_NAME);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
            let pack_member = journal["members"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|member| member["path"] == "packs/payload.txt")
                .unwrap();
            let before_state = pack_member["before"].clone();
            pack_member["rollback_staging"] = serde_json::json!({
                "parent": {"device": pack_directory.dev(), "inode": pack_directory.ino()},
                "name": stage_name,
                "payload": {"device": stage_metadata.dev(), "inode": stage_metadata.ino()},
                "payload_uid": stage_metadata.uid(),
                "payload_gid": stage_metadata.gid(),
                "payload_mode": stage_metadata.mode() & 0o7777,
                "payload_length": stage_metadata.len(),
                "payload_digest": before_state["digest"].clone(),
                "linked": true,
            });
            std::fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
            drop(prepared);
        }

        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        assert_eq!(std::fs::read_to_string(&master).unwrap(), desired);
        assert_eq!(
            std::fs::read_to_string(live.path().join("packs/payload.txt")).unwrap(),
            "||restored.example.test^\n"
        );
        assert!(!live.path().join("packs").join(stage_name).exists());
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    #[test]
    fn repeated_restore_is_a_noop_and_does_not_rewrite_policy_files() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("config.toml"), BASE).unwrap();
        let (_output, archive) = raw_archive(source.path());
        let live = tempfile::tempdir().unwrap();
        let master = live.path().join("config.toml");
        std::fs::write(&master, format!("{BASE}\n# before\n")).unwrap();

        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        let inode = std::fs::metadata(&master).unwrap().ino();
        assert!(matches!(
            restore_archive(&master, &archive).unwrap(),
            RestoreOutcome::Restored { changed: false, .. }
        ));
        assert_eq!(std::fs::metadata(&master).unwrap().ino(), inode);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    #[test]
    fn restore_errors_when_archive_missing() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("config.toml");
        let missing = dir.path().join("no-such-archive.tar.gz");
        let err = run_restore(&live, &missing, None);
        assert!(err.is_err());
    }

    /// The member-path safety predicate flags absolute paths and
    /// `..` traversal while leaving normal config-tree members alone.
    #[test]
    fn is_unsafe_member_path_flags_traversal_and_absolute() {
        assert!(is_unsafe_member_path("/etc/passwd"));
        assert!(is_unsafe_member_path("../escape.toml"));
        assert!(is_unsafe_member_path("a/../../b"));
        assert!(!is_unsafe_member_path("config.toml"));
        assert!(!is_unsafe_member_path("devices.d/laptop.toml"));
        assert!(!is_unsafe_member_path("./config.toml"));
    }

    /// A hostile archive carrying a symlink member must be rejected
    /// before extraction — a symlink can redirect a later write outside the
    /// staging root. (GNU tar stores symlinks as symlink members by default,
    /// so this reproduces the vector portably.)
    #[test]
    fn restore_rejects_archive_with_symlink_member() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("config.toml"), BASE).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", payload.join("evil")).unwrap();
        let archive = dir.path().join("evil.tar.gz");
        let built = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(built, "test archive must build");

        let live = dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        // Avoid `unwrap_err` so we don't require `RestoreOutcome: Debug`.
        let err = match restore_archive(&live, &archive) {
            Ok(_) => panic!("symlink member must be rejected, but restore succeeded"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("symlink"),
            "symlink member must be rejected: {err}"
        );
        // The live config must be untouched (rejected before any swap).
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    // ── archive member type + restored perms ─────────────

    #[test]
    fn restore_rejects_archive_with_fifo_member() {
        // A FIFO (`p`) member must be rejected by the pre-extraction scan —
        // a blacklist that only catches symlink/hardlink lets special
        // files through.
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("config.toml"), BASE).unwrap();
        let fifo = payload.join("evil.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: cpath is a valid NUL-terminated path and mode is valid.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo must succeed for the test");

        let archive = dir.path().join("fifo.tar.gz");
        let built = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(built, "test archive must build");

        let live = dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        let err = match restore_archive(&live, &archive) {
            Ok(_) => panic!("fifo member must be rejected, but restore succeeded"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not a regular file or directory"),
            "fifo member must be rejected: {err}"
        );
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    #[test]
    fn staging_dir_create_in_is_0700_and_under_parent() {
        use std::os::unix::fs::PermissionsExt;
        // `migrate.rs` reuses this to stage on the target filesystem: a
        // CSPRNG-named 0o700 dir under the given parent, never a fixed name.
        let parent = tempfile::tempdir().unwrap();
        let s = StagingDir::create_in(parent.path()).unwrap();
        assert!(
            s.path().starts_with(parent.path()),
            "staging must be under the given parent"
        );
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "staging dir must be 0o700");
        let name = s.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("purge-warden-stage-"), "name: {name}");
        assert_ne!(name, ".staging", "must not use the old predictable name");
    }

    // ── pinned archive, tar flags and caps ─────────────────

    /// A live tree at `BASE` and a source tree whose valid master differs
    /// from it, so a restore that wrongly succeeds changes the live bytes.
    fn live_and_source() -> (tempfile::TempDir, PathBuf, tempfile::TempDir) {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("config.toml"),
            format!("{BASE}\n# archived\n"),
        )
        .unwrap();
        (live_dir, live, source)
    }

    /// The refusal text of a restore that must fail before live effects.
    fn refused(live: &Path, archive: &Path) -> String {
        let error = match restore_archive(live, archive) {
            Ok(_) => panic!("restore must refuse {}", archive.display()),
            Err(error) => error.to_string(),
        };
        assert_eq!(std::fs::read_to_string(live).unwrap(), BASE);
        assert_no_restore_artifacts(live.parent().unwrap());
        error
    }

    #[test]
    fn restore_refuses_a_symlinked_archive() {
        let (_live_dir, live, source) = live_and_source();
        let (output, archive) = raw_archive(source.path());
        let link = output.path().join("link.tar.gz");
        std::os::unix::fs::symlink(&archive, &link).unwrap();
        let error = refused(&live, &link);
        assert!(error.contains("symbolic link"), "{error}");
    }

    #[test]
    fn restore_refuses_an_archive_with_two_links() {
        let (_live_dir, live, source) = live_and_source();
        let (output, archive) = raw_archive(source.path());
        std::fs::hard_link(&archive, output.path().join("second.tar.gz")).unwrap();
        let error = refused(&live, &archive);
        assert!(error.contains("unsafe or oversized archive"), "{error}");
    }

    #[test]
    fn restore_uses_the_pinned_archive_bytes() {
        let (_live_dir, live, source) = live_and_source();
        let (_output, archive) = raw_archive(source.path());
        let other = tempfile::tempdir().unwrap();
        std::fs::write(
            other.path().join("config.toml"),
            format!("{BASE}\n# swapped\n"),
        )
        .unwrap();
        let (_other_output, swapped) = raw_archive(other.path());
        let swapped_bytes = std::fs::read(&swapped).unwrap();
        let fired = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = std::rc::Rc::clone(&fired);
        let target = archive.clone();
        let outcome = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::AfterArchivePinned {
                    seen.set(seen.get() + 1);
                    std::fs::rename(&swapped, &target).unwrap();
                }
            },
            || restore_archive(&live, &archive),
        );
        assert!(matches!(
            outcome.unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        assert_eq!(fired.get(), 1);
        assert_eq!(std::fs::read(&archive).unwrap(), swapped_bytes);
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            format!("{BASE}\n# archived\n")
        );
    }

    #[test]
    fn restore_refuses_an_oversized_archive() {
        let (_live_dir, live, source) = live_and_source();
        // Xorshift bytes do not compress, so the archive outgrows the cap.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let noise: Vec<u8> = (0..MAX_ARCHIVE_BYTES + 4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        std::fs::write(source.path().join("noise.bin"), noise).unwrap();
        let (_output, archive) = raw_archive(source.path());
        let error = refused(&live, &archive);
        assert!(error.contains("unsafe or oversized archive"), "{error}");
    }

    #[test]
    fn restore_refuses_members_larger_than_the_extraction_cap() {
        let (_live_dir, live, source) = live_and_source();
        let zeros = vec![0_u8; usize::try_from(MAX_EXTRACTED_BYTES).unwrap() + 1];
        std::fs::write(source.path().join("zeros.bin"), zeros).unwrap();
        let (_output, archive) = raw_archive(source.path());
        let error = refused(&live, &archive);
        assert!(
            error.contains(&format!("more than {MAX_EXTRACTED_BYTES} bytes")),
            "{error}"
        );
    }

    #[test]
    fn restore_refuses_too_many_members() {
        let (_live_dir, live, source) = live_and_source();
        for index in 0..MAX_ARCHIVE_MEMBERS {
            std::fs::write(source.path().join(format!("extra-{index}.txt")), "").unwrap();
        }
        let (_output, archive) = raw_archive(source.path());
        let error = refused(&live, &archive);
        assert!(
            error.contains(&format!("more than {MAX_ARCHIVE_MEMBERS} members")),
            "{error}"
        );
    }

    #[test]
    fn restore_refuses_an_oversized_listing() {
        let (_live_dir, live, source) = live_and_source();
        // Few members with long names: under the member cap, over the
        // listing cap.
        let name = "n".repeat(200);
        let count = usize::try_from(MAX_LISTING_BYTES).unwrap() / name.len() + 1;
        assert!(count + 2 <= MAX_ARCHIVE_MEMBERS);
        for index in 0..count {
            std::fs::write(source.path().join(format!("{index}-{name}")), "").unwrap();
        }
        let (_output, archive) = raw_archive(source.path());
        let error = refused(&live, &archive);
        assert!(error.contains("listing is longer than"), "{error}");
    }

    #[test]
    fn listing_parser_accepts_only_numeric_file_and_directory_lines() {
        let date = "2026-10-13 06:00";
        assert_eq!(
            listed_member_size(&format!("-rw-r--r-- 0/0 12 {date} ./config.toml")),
            Some(12)
        );
        assert_eq!(
            listed_member_size(&format!("drwx------ 990/990 0 {date} ./packs/")),
            Some(0)
        );
        assert_eq!(
            listed_member_size(&format!("-rwsr-xr-T 65534/65534 7 {date} ./tool")),
            Some(7)
        );
        for line in [
            // A group name with a space and a digit would shift the size.
            format!("-rw-r--r-- a/b 7 {date} ./spoof"),
            format!("-rw-r--r-- user/group 7 {date} ./named"),
            format!("-rw-r--r-- 0 7 {date} ./no-group"),
            format!("-rw-r--r-- 0/0 7x {date} ./size"),
            format!("-rw-r--r-- 0/0 1,3 {date} ./device-size"),
            format!("-rw-r--r--- 0/0 7 {date} ./long-mode"),
            format!("-rw-r--r-? 0/0 7 {date} ./odd-mode"),
            format!("lrwxrwxrwx 0/0 0 {date} ./link -> target"),
            "-rw-r--r-- 0/0".to_owned(),
            String::new(),
        ] {
            assert_eq!(listed_member_size(&line), None, "{line}");
        }
    }

    #[test]
    fn tar_commands_use_safe_flags_and_drop_tar_options() {
        let archive = Path::new("/staging/archive.tar.gz");
        let tree = Path::new("/staging/tree");
        for (run, expected) in [
            (TarRun::Names, vec!["-tzf"]),
            (TarRun::Long, vec!["--numeric-owner", "-tvzf"]),
            (
                TarRun::Extract(tree),
                vec![
                    "--no-same-owner",
                    "--no-same-permissions",
                    "-C",
                    "/staging/tree",
                    "-xzf",
                ],
            ),
        ] {
            let command = tar_command(archive, run);
            let mut expected = expected;
            expected.push("/staging/archive.tar.gz");
            assert_eq!(
                command
                    .get_args()
                    .map(|arg| arg.to_str().unwrap())
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(command
                .get_envs()
                .any(|(key, value)| key == "TAR_OPTIONS" && value.is_none()));
        }
    }

    /// Root only: GNU tar run by any other user already drops archive owners
    /// and set-id bits.
    #[test]
    fn restore_strips_setuid_and_archive_owners() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let source = tempfile::tempdir().unwrap();
        let tool = source.path().join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::os::unix::fs::chown(&tool, Some(65534), Some(65534)).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let (_output, archive) = raw_archive(source.path());

        let staging = tempfile::tempdir().unwrap();
        let tree = staging.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        extract_archive(&archive, &tree, staging.path()).unwrap();
        let meta = std::fs::metadata(tree.join("tool")).unwrap();
        assert_eq!(meta.mode() & 0o7000, 0, "set-id bits must be dropped");
        assert_ne!(meta.uid(), 65534, "the archive owner must not be kept");
    }

    // ── older schema archives ───────────────────────────────

    #[test]
    fn restore_refuses_a_schema_four_archive_with_a_next_step() {
        let live_dir = tempfile::tempdir().unwrap();
        let live = live_dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        let snapshot = |root: &Path| {
            std::fs::read_dir(root)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap_or_default();
                    (path, bytes)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = snapshot(live_dir.path());
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("config.toml"),
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let (_output, archive) = raw_archive(source.path());

        let error = match restore_archive(&live, &archive) {
            Ok(_) => panic!("a schema-4 archive must be refused"),
            Err(error) => error.to_string(),
        };
        for needle in [
            "schema-4 archive",
            "live config untouched",
            "warden config edit",
            &archive.display().to_string(),
        ] {
            assert!(error.contains(needle), "{needle}: {error}");
        }
        // The TUI prefixes "restore failed: " and shows about 105 characters.
        let shown = &format!("restore failed: {error}")[..105];
        assert!(shown.contains("live config untouched"), "{shown}");
        assert_no_restore_artifacts(live_dir.path());
        assert_eq!(snapshot(live_dir.path()), before);
    }

    // ── failed commits settle before return ─────────────────

    /// An archive of `BASE` and a live master that differs from it.
    fn edited_live_and_archive() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, PathBuf) {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();
        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, format!("{BASE}\n# edited\n")).unwrap();
        (source, live, live_config, archive)
    }

    #[test]
    fn restore_rolls_back_at_once_when_promotion_fails() {
        let (_source, live, live_config, archive) = edited_live_and_archive();
        let before = std::fs::read(&live_config).unwrap();

        policy_transaction::fail_at_promotion_for_test();
        let error = restore_archive(&live_config, &archive)
            .expect_err("a failed promotion must not report success")
            .to_string();
        assert!(error.contains("rolled back"), "{error}");
        assert!(error.contains("live config unchanged"), "{error}");
        assert_eq!(std::fs::read(&live_config).unwrap(), before);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());

        assert!(matches!(
            restore_archive(&live_config, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
        assert_eq!(std::fs::read_to_string(&live_config).unwrap(), BASE);
    }

    #[test]
    fn restore_reports_applied_when_the_final_fsync_fails() {
        let (_source, live, live_config, archive) = edited_live_and_archive();

        policy_transaction::fail_at_root_fsync_for_test();
        assert!(matches!(
            restore_archive(&live_config, &archive).unwrap(),
            RestoreOutcome::Restored {
                changed: true,
                repair: false,
                ..
            }
        ));
        assert_eq!(std::fs::read_to_string(&live_config).unwrap(), BASE);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());
    }

    /// Restore is an operator write, so the undo cap applies: prepare
    /// refuses before any member changes.
    #[test]
    fn restore_refuses_a_full_undo_store_and_says_unchanged() {
        let (_source, live, live_config, archive) = edited_live_and_archive();
        let before = std::fs::read(&live_config).unwrap();

        policy_transaction::set_undo_cap_for_test(Some(1));
        let error = restore_archive(&live_config, &archive)
            .expect_err("a full undo store must refuse the restore")
            .to_string();
        policy_transaction::set_undo_cap_for_test(None);
        assert!(error.starts_with("UndoStoreFull:"), "{error}");
        assert!(error.ends_with("; live config unchanged"), "{error}");
        assert_eq!(std::fs::read(&live_config).unwrap(), before);
        assert!(!live.path().join(migration_journal::TXN_DIR_NAME).exists());

        assert!(matches!(
            restore_archive(&live_config, &archive).unwrap(),
            RestoreOutcome::Restored { changed: true, .. }
        ));
    }

    #[test]
    fn uncertain_restore_names_the_recovery_section_and_never_unchanged() {
        let message = uncertain_restore("txn-1", "req-1", "ENOSPC").to_string();
        assert!(
            message.contains("systemctl restart purge-warden"),
            "{message}"
        );
        assert!(
            message.contains(&format!(
                "See \"{}\" in docs/UPGRADE_RECOVERY.md",
                migration_journal::POLICY_RECOVERY_SECTION
            )),
            "{message}"
        );
        assert!(message.ends_with("(ENOSPC)"), "{message}");
        assert!(!message.contains("unchanged"), "{message}");
    }

    // ── PID validation before SIGHUP ────────────────────────
    //
    // A corrupt/hostile PID file must never reach `libc::kill` with a value
    // that could broadcast (`-1`, `0`, a negative, or a value that wraps
    // negative through `as i32`). These drive the private helper directly with
    // a temp PID file and assert it errors *without* signalling. The
    // happy-path delivery (valid + flock-held → real SIGHUP) is covered by the
    // `pid::verified_daemon_pid` unit tests and by CT-smoke against a live
    // daemon — signalling self in-process would terminate the test runner.

    fn write_pidfile(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.pid");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn send_sighup_refuses_negative_pid() {
        let (_d, p) = write_pidfile("-1");
        // `-1` is rejected at the u32 parse, long before any kill.
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_zero_pid() {
        let (_d, p) = write_pidfile("0");
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "0 must be refused as out of range: {err}"
        );
    }

    #[test]
    fn send_sighup_refuses_out_of_range_pid() {
        // Parses as u32 but exceeds i32::MAX → would wrap negative through
        // `as i32` → must be refused.
        let (_d, p) = write_pidfile("3000000000");
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "value > i32::MAX must be refused: {err}"
        );
    }

    #[test]
    fn send_sighup_refuses_garbage_pid() {
        let (_d, p) = write_pidfile("not-a-number");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_empty_pid() {
        let (_d, p) = write_pidfile("");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_trailing_junk_pid() {
        let (_d, p) = write_pidfile("1234 evil");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_skips_unlocked_pid_file() {
        // A syntactically valid, in-range PID whose file is NOT flock-held is
        // stale: the liveness gate must skip the signal rather than risk
        // hitting a reused PID. Use our own PID (definitely alive, but the
        // plain file carries no lock) so the value guard passes and only the
        // flock gate trips.
        let (_d, p) = write_pidfile(&std::process::id().to_string());
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("not held by a running daemon"),
            "unlocked PID file must be skipped: {err}"
        );
    }

    /// The lock holder is not the PID in the file: the daemon user rewrote
    /// it. Root must not signal the named process.
    #[test]
    fn send_sighup_refuses_a_pid_that_does_not_hold_the_lock() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.pid");
        let _lock = crate::cli::commands::pid::acquire_pid_lock(&path).unwrap();
        std::fs::write(&path, child.id().to_string()).unwrap();

        let outcome = send_sighup_from_pid(&path);
        // Give a delivered SIGHUP time to end the child before checking.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();

        let err = outcome.expect_err("a PID that does not hold the lock must not be signalled");
        assert!(
            err.to_string()
                .contains(&format!("held by PID {}", std::process::id())),
            "the refusal must name the lock holder: {err}"
        );
        assert!(alive, "the named process must not be signalled");
    }

    // ── staged-master selection ─────────────────────────────────────

    /// `backup.rs`'s sweep captures every non-dot top-level entry, so a
    /// real archive carries `secrets.toml` beside the master. When the
    /// live master has a different name — the precise case this fallback
    /// exists for — `secrets.toml` was an equally valid pick, and
    /// `read_dir` order decided. It sorts before `config.toml`, so the old
    /// unordered scan could hand a recovery tool the secrets file and
    /// report validator errors about it mid-incident.
    #[test]
    fn the_staged_master_fallback_never_picks_secrets_toml() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("config.toml"), "schema_version = 5\n").unwrap();
        std::fs::write(staging.path().join("secrets.toml"), "token = \"x\"\n").unwrap();
        // Live master named something else, so the direct hit misses and
        // the fallback runs.
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(
            picked.file_name().unwrap(),
            "config.toml",
            "the secrets file is never a master"
        );
    }

    /// Multiple unhinted root TOMLs are ambiguous; sorting only stabilizes
    /// the diagnostic and never chooses what gets installed.
    #[test]
    fn the_staged_master_fallback_refuses_ambiguity() {
        let staging = tempfile::tempdir().unwrap();
        for name in ["zulu.toml", "alpha.toml", "mike.toml"] {
            std::fs::write(staging.path().join(name), "schema_version = 5\n").unwrap();
        }
        let live = staging.path().join("warden.toml");

        let error = locate_staged_master(staging.path(), &live).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ambiguous staged archive"), "{message}");
        assert!(message.contains("alpha.toml"), "{message}");
    }

    /// The direct name match still wins — the fallback must not have
    /// become the only path.
    #[test]
    fn the_staged_master_prefers_the_live_masters_own_name() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("alpha.toml"), "schema_version = 5\n").unwrap();
        std::fs::write(staging.path().join("warden.toml"), "schema_version = 5\n").unwrap();
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "warden.toml");
    }

    #[test]
    fn the_staged_master_accepts_a_safe_exact_non_toml_name() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("warden.conf"), "schema_version = 5\n").unwrap();
        std::fs::write(staging.path().join("other.toml"), "schema_version = 5\n").unwrap();
        let live = staging.path().join("warden.conf");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "warden.conf");
    }

    /// An archive taken while the node was a member, restored after
    /// `cluster leave`, wrote `[cluster]` back and the node crash-looped.
    #[test]
    fn restore_never_changes_cluster_membership() {
        let secondary = "schema_version = 5\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\n\
                         [cluster]\nenabled = true\nrole = \"secondary\"\n\
                         peer = \"https://192.0.2.1\"\ntoken_hash = \"fixture-token-hash\"\n";
        let primary =
            format!("{BASE}\n[cluster]\nenabled = true\ntoken_hash = \"fixture-token-hash\"\n");
        // The same node after `cluster create --migrate-legacy`.
        let node = "00000000-0000-4000-8000-000000000001";
        let v1 = format!(
            "{BASE}\n[node]\nid = \"{node}\"\n\n[cluster]\nenabled = true\n\
             membership_version = 1\ncluster_id = \"00000000-0000-4000-8000-000000000002\"\n\
             primary_node_id = \"{node}\"\nprimary_cert_fingerprint = \"{}\"\n",
            "ab".repeat(32)
        );
        let archive = |master: &str| {
            let source = tempfile::tempdir().unwrap();
            std::fs::write(source.path().join("config.toml"), master).unwrap();
            raw_archive(source.path())
        };
        let restore = |live: &str, archive: &Path| {
            let root = tempfile::tempdir().unwrap();
            let master = root.path().join("config.toml");
            std::fs::write(&master, live).unwrap();
            let result = restore_archive(&master, archive);
            assert!(!root.path().join(migration_journal::TXN_DIR_NAME).exists());
            (result, std::fs::read_to_string(&master).unwrap())
        };
        let (_member_dir, member) = archive(secondary);
        let (_standalone_dir, standalone) = archive(BASE);
        let (_own_dir, own) = archive(&primary);
        let (_v1_dir, v1_own) = archive(&v1);

        for (live, archive, expected) in [
            (BASE, &member, "from standalone to secondary"),
            (primary.as_str(), &standalone, "from primary to standalone"),
            (
                v1.as_str(),
                &own,
                "primary membership: the archive's cluster.membership_version differs",
            ),
            (
                "[broken",
                &member,
                "membership is unknown and the archive's is secondary",
            ),
        ] {
            let (result, after) = restore(live, archive);
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(expected) && error.contains("live config unchanged"),
                "{error}"
            );
            assert_eq!(after, live);
        }

        let edited = |master: &str| format!("{master}# edited\n");
        for (live, archive, master) in [
            (edited(BASE), &standalone, BASE),
            (edited(&primary), &own, primary.as_str()),
            (edited(&v1), &v1_own, v1.as_str()),
            ("[broken".to_owned(), &standalone, BASE),
            (
                secondary.replace("[server]", "damaged = true\n[server]"),
                &member,
                secondary,
            ),
        ] {
            let (result, after) = restore(&live, archive);
            assert!(
                matches!(
                    result.unwrap(),
                    RestoreOutcome::Restored { changed: true, .. }
                ),
                "{live}"
            );
            assert_eq!(after, master);
        }
    }

    /// A member whose live config does not load: even a standalone archive
    /// would make it standalone, so node-local membership state refuses every
    /// archive. A `[cluster]` the master leaves to an include is unknown too,
    /// not standalone. Without that state the standalone archive restores.
    #[cfg(feature = "cluster")]
    #[test]
    fn unknown_membership_of_a_member_refuses_every_archive() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("config.toml"), BASE).unwrap();
        let (_archive_dir, standalone) = raw_archive(source.path());
        let included = format!("damaged = true\nincludes = [\"conf.d/*.toml\"]\n{BASE}");
        for (live, evidence) in [
            ("[broken", "secondary.json"),
            ("[broken", "roster.json"),
            (included.as_str(), "secondary.json"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let master = root.path().join("config.toml");
            std::fs::write(&master, live).unwrap();
            let include = root.path().join("conf.d/cluster.toml");
            let member = "[cluster]\nenabled = true\nrole = \"secondary\"\n";
            std::fs::create_dir(root.path().join("conf.d")).unwrap();
            std::fs::write(&include, member).unwrap();
            let store = |write: bool| {
                let guard = write_lock::acquire_for_migration(&master).unwrap();
                let files = crate::private_store::PrivateStore::open(
                    &guard,
                    crate::cluster::membership::STORE,
                )
                .unwrap();
                if write {
                    files.create(evidence, b"{}").unwrap();
                } else {
                    files.remove(evidence).unwrap();
                }
            };
            store(true);
            let error = restore_archive(&master, &standalone)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("node-local cluster state shows it is a member")
                    && error.contains("live config unchanged"),
                "{error}"
            );
            assert_eq!(std::fs::read_to_string(&master).unwrap(), live);
            assert_eq!(std::fs::read_to_string(&include).unwrap(), member);
            assert!(!root.path().join(migration_journal::TXN_DIR_NAME).exists());

            store(false);
            assert!(matches!(
                restore_archive(&master, &standalone).unwrap(),
                RestoreOutcome::Restored { changed: true, .. }
            ));
            assert_eq!(std::fs::read_to_string(&master).unwrap(), BASE);
        }
    }
}
