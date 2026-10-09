//! `warden config relocate`: move the config set of a host installed before
//! the /etc split from `/var/lib/purge-warden` to `/etc/purge-warden`, or back
//! with `--reverse`.
//!
//! Every entry moves by rename on one filesystem, so device, inode, owner and
//! mode of each member stay. The run is offline: it holds the runtime lease,
//! the PID lease and both config write locks. From the first receipt write
//! until the run commits or its rollback ends, the active receipt in the state
//! directory fences every normal access.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context};

use crate::cli::exit_codes;
use crate::config::loader::{self, EditorGuardedLoadFailure};
use crate::config::policy_revision::{self, PolicyMemberKind, PolicyMemberState};
use crate::config::relocate_receipt::{
    self as receipt_file, Action, Direction, Inode, Loaded, Receipt, RunState, Scheme, Step,
    StoreRename, ACTIVE, DONE,
};
use crate::config::write_lock::{self, MigrationWriteLock, RelocateProbe, WRITE_LOCK_FILE};
use crate::config::{migration_journal, policy_transaction, runtime_lease, state_dir, tree_io};
use crate::private_store::plain_namespace;

const MASTER: &str = "config.toml";
const LISTS: &str = "lists";
const IMPORTED_LOCAL_HOST: &str = "imported.local";
/// Private stores in the state directory, named by the plain master hash.
const PLAIN_STORES: [&str; 7] = [
    ".warden-cluster-peers",
    ".warden-cluster-publications",
    ".warden-cluster-ownership",
    ".warden-node-membership",
    ".warden-node-lifecycle",
    ".warden-node-control",
    ".warden-tui-uor",
];
/// The stores above that only a binary with cluster support can inspect.
#[cfg(not(feature = "cluster"))]
const CLUSTER_STORES: [&str; 6] = [
    ".warden-cluster-peers",
    ".warden-cluster-publications",
    ".warden-cluster-ownership",
    ".warden-node-membership",
    ".warden-node-lifecycle",
    ".warden-node-control",
];
/// Top-level names that hold node state and never move with the config set.
const STATE_NAMES: [&str; 4] = ["logs", "audit", "data", "backups"];

/// Where relocate acts. Production uses the fixed system paths.
pub(crate) struct Layout {
    /// The legacy root, which is also the state directory of both layouts.
    pub(crate) legacy: PathBuf,
    pub(crate) etc: PathBuf,
    pub(crate) pid_file: PathBuf,
    /// Required owner of the receipt files.
    pub(crate) receipt_owner: (u32, u32),
    /// Free space the state directory needs for the receipt and its stage.
    pub(crate) min_free_bytes: u64,
    /// Directories searched for `restorecon`.
    pub(crate) search_path: OsString,
}

impl Layout {
    fn system() -> Self {
        let etc = PathBuf::from("/etc/purge-warden");
        Self {
            legacy: PathBuf::from("/var/lib/purge-warden"),
            pid_file: crate::cli::config_discovery::resolve_pid_file(None, &etc.join(MASTER)),
            etc,
            receipt_owner: (0, 0),
            min_free_bytes: 2 * receipt_file::MAX_BYTES,
            search_path: std::env::var_os("PATH").unwrap_or_default(),
        }
    }

    fn roots(&self, direction: Direction) -> (&Path, &Path) {
        match direction {
            Direction::Forward => (&self.legacy, &self.etc),
            Direction::Reverse => (&self.etc, &self.legacy),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    pub(crate) dry_run: bool,
    pub(crate) reverse: bool,
}

/// What a run prints and how it exits.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) out: Vec<String>,
    pub(crate) err: Vec<String>,
    pub(crate) code: i32,
    /// The root `restorecon` relabels once the run committed.
    relabel: Option<PathBuf>,
}

impl Outcome {
    fn refused(refusals: &[Refusal], rollback: Option<Direction>) -> Self {
        let mut err: Vec<String> = refusals.iter().map(Refusal::line).collect();
        match rollback {
            Some(direction) => err.push(format!(
                "An incomplete run keeps this node fenced. Roll it back first: {}",
                rollback_command(direction)
            )),
            None => err.push("Nothing was changed.".into()),
        }
        Self {
            err,
            code: exit_codes::FAILURE,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
struct Refusal {
    slug: &'static str,
    message: String,
}

impl Refusal {
    fn new(slug: &'static str, message: impl Into<String>) -> Self {
        Self {
            slug,
            message: message.into(),
        }
    }

    fn line(&self) -> String {
        format!("refused ({}): {}", self.slug, self.message)
    }
}

/// Test hook: the point where an injected stop interrupts a run.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// After the action of step `n` (an index into the receipt steps),
    /// before its done flag is written.
    AfterAction(usize),
    /// After the done flag of step `n` is written.
    AfterReceipt(usize),
    /// After the state `complete` is written, before the receipt retires.
    BeforeRetire,
    /// The rename of step `n` fails with EXDEV.
    Exdev(usize),
    /// The cleanup of `/etc` after a reverse commit fails.
    Cleanup,
    /// The rollback fails at the undo of step `n`.
    Undo(usize),
}

#[cfg(test)]
thread_local! {
    static STOP: std::cell::Cell<Option<Stop>> = const { std::cell::Cell::new(None) };
    /// A directory that `filesystem_of` reports on another mount.
    static OTHER_MOUNT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn injected(point: Stop) -> anyhow::Result<()> {
    if STOP.get() == Some(point) {
        anyhow::bail!("injected stop at {point:?}");
    }
    Ok(())
}

/// `warden config relocate [--dry-run] [--reverse]`.
pub fn run_relocate(explicit_config: bool, dry_run: bool, reverse: bool) -> anyhow::Result<i32> {
    // SAFETY: geteuid has no preconditions.
    if let Some(refusal) = invoker_refusal(explicit_config, unsafe { libc::geteuid() }) {
        eprintln!("{}", refusal.line());
        return Ok(exit_codes::FAILURE);
    }
    let outcome = relocate(&Layout::system(), Options { dry_run, reverse })?;
    for line in &outcome.out {
        println!("{line}");
    }
    for line in &outcome.err {
        eprintln!("{line}");
    }
    Ok(outcome.code)
}

fn invoker_refusal(explicit_config: bool, euid: u32) -> Option<Refusal> {
    if explicit_config {
        return Some(Refusal::new(
            "explicit-config",
            "config relocate acts on the fixed paths /var/lib/purge-warden and /etc/purge-warden only; drop --config",
        ));
    }
    if euid != 0 {
        return Some(Refusal::new(
            "not-root",
            "config relocate must run as root; call the real binary, not the warden wrapper",
        ));
    }
    None
}

/// Run relocate on `layout`, then relabel the new root when the run committed.
pub(crate) fn relocate(layout: &Layout, options: Options) -> anyhow::Result<Outcome> {
    let mut outcome = relocate_locked(layout, options)?;
    if let Some(root) = outcome.relabel.take() {
        relabel(&root, &layout.search_path, &mut outcome);
    }
    Ok(outcome)
}

fn relocate_locked(layout: &Layout, options: Options) -> anyhow::Result<Outcome> {
    let direction = if options.reverse {
        Direction::Reverse
    } else {
        Direction::Forward
    };
    ensure!(
        state_dir::for_config_parent(&layout.etc) == layout.legacy,
        "the state directory of {} is not {}",
        layout.etc.display(),
        layout.legacy.display()
    );
    let (source, target) = layout.roots(direction);
    for root in [source, target] {
        let master = root.join(MASTER);
        let identity = match write_lock::ConfigTreeIdentity::resolve(&master) {
            Ok(identity) => identity,
            Err(error)
                if root == target
                    || error
                        .downcast_ref::<write_lock::NonRegularMaster>()
                        .is_some() =>
            {
                let slug = if root == target {
                    "target-occupied"
                } else {
                    "master-not-regular"
                };
                return Ok(Outcome::refused(
                    &[Refusal::new(slug, format!("{error:#}"))],
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        if identity.canonical_master != master {
            return Ok(Outcome::refused(
                &[Refusal::new(
                    "not-fixed-path",
                    format!(
                        "{} resolves to {}; relocate acts only on the literal path, without symlinked components",
                        master.display(),
                        identity.canonical_master.display()
                    ),
                )],
                None,
            ));
        }
    }
    // The leases and the write lock compare their own files with the owners of
    // the directory and the master. The lock-free owner checks run first, so a
    // changed owner is not reported as a busy daemon or tree; the run repeats
    // them under its locks. An active receipt leads to its rollback or finish,
    // which needs no owner check.
    if std::fs::symlink_metadata(layout.legacy.join(ACTIVE)).is_err() {
        let refusals = owner_refusals(direction, source, target)?;
        if !refusals.is_empty() {
            return Ok(Outcome::refused(&refusals, None));
        }
    }
    let state = state_dir::open_directory(&layout.legacy)
        .with_context(|| format!("open the state directory {}", layout.legacy.display()))?;
    let state_meta = state.metadata()?;
    let _lease = match runtime_lease::hold_for_relocate(&state, !options.dry_run) {
        Ok(lease) => lease,
        Err(error) => return Ok(Outcome::refused(&[lease_refusal(&error)], None)),
    };
    let pid_present = std::fs::symlink_metadata(&layout.pid_file).is_ok();
    let _pid = if !options.dry_run || pid_present {
        match crate::cli::commands::pid::acquire_offline_pid_lease(
            &layout.pid_file,
            Some(&state_meta),
        ) {
            Ok(lease) => Some(lease),
            Err(error) => return Ok(Outcome::refused(&[lease_refusal(&error)], None)),
        }
    } else {
        None
    };
    if !options.dry_run {
        receipt_file::remove_stage(&state, &format!("{ACTIVE}.next"))?;
        receipt_file::remove_stage(&state, &format!("{DONE}.next"))?;
    }
    match receipt_file::read(&state, ACTIVE, layout.receipt_owner)? {
        Loaded::Absent => run(layout, options, direction, &state),
        Loaded::Invalid { parsed, problem } => Ok(manual_recovery(layout, parsed, &problem)),
        Loaded::Valid(receipt) => {
            if let Some(refusal) = foreign_receipt(layout, &receipt) {
                return Ok(Outcome::refused(&[refusal], None));
            }
            if receipt.state == RunState::Complete {
                finish(options, &state, *receipt)
            } else if receipt.direction == direction {
                Ok(Outcome::refused(
                    &[Refusal::new(
                        "receipt",
                        format!(
                            "{} records an incomplete {} run; only its rollback may run",
                            layout.legacy.join(ACTIVE).display(),
                            direction_name(direction)
                        ),
                    )],
                    Some(direction),
                ))
            } else {
                rollback(options, &state, *receipt)
            }
        }
    }
}

/// A receipt whose roots are not the two fixed roots is not ours to act on.
fn foreign_receipt(layout: &Layout, receipt: &Receipt) -> Option<Refusal> {
    let (source, target) = layout.roots(receipt.direction);
    (receipt.source != source || receipt.target != target || receipt.master != MASTER).then(|| {
        Refusal::new(
            "receipt",
            format!(
                "{} names {} and {}, not this layout; recover it by hand",
                layout.legacy.join(ACTIVE).display(),
                receipt.source.display(),
                receipt.target.display()
            ),
        )
    })
}

/// A lease held by another process means a daemon or a warden command runs.
/// Any other lease failure keeps its own message.
fn lease_refusal(error: &anyhow::Error) -> Refusal {
    let message = format!("{error:#}");
    let slug = if error.root_cause().to_string().starts_with("NodeNotOffline") {
        "daemon-running"
    } else {
        "lease"
    };
    Refusal::new(slug, message)
}

/// The owner and mode refusals that need no lock: the master owner and the
/// owner and mode of the target root.
fn owner_refusals(
    direction: Direction,
    source: &Path,
    target: &Path,
) -> anyhow::Result<Vec<Refusal>> {
    let Ok(root) = std::fs::symlink_metadata(source) else {
        return Ok(Vec::new());
    };
    let master = source.join(MASTER);
    let mut refusals: Vec<Refusal> = std::fs::symlink_metadata(&master)
        .ok()
        .and_then(|meta| master_owner(&master, &meta, &root))
        .into_iter()
        .collect();
    let mut target_refusals = Vec::new();
    inspect_target(direction, target, &root, &mut target_refusals)?;
    refusals.extend(
        target_refusals
            .into_iter()
            .filter(|refusal| matches!(refusal.slug, "target-owner" | "target-root")),
    );
    Ok(refusals)
}

/// The master and its root must have one owner.
fn master_owner(master: &Path, meta: &Metadata, root: &Metadata) -> Option<Refusal> {
    ((meta.uid(), meta.gid()) != (root.uid(), root.gid())).then(|| {
        Refusal::new(
            "master-owner",
            format!(
                "{} is owned by {}:{}, its root by {}:{}",
                master.display(),
                meta.uid(),
                meta.gid(),
                root.uid(),
                root.gid()
            ),
        )
    })
}

fn manual_recovery(layout: &Layout, parsed: Option<Box<Receipt>>, problem: &str) -> Outcome {
    let active = layout.legacy.join(ACTIVE);
    let mut err = vec![Refusal::new("receipt", format!("{problem}; the fence stays up")).line()];
    match parsed {
        Some(receipt) => err.push(format!(
            "Check with stat that the source, target and step dev/ino in {} match the tree, then run chown root:root and chmod 0600 on it, remove any extra link, and run: {}",
            active.display(),
            rollback_command(receipt.direction)
        )),
        None => err.push(format!(
            "Nothing records what moved. Compare both roots with the archive of `warden config backup`, move entries back with mv on the same filesystem (a copy breaks the member identities), then remove {}",
            active.display()
        )),
    }
    Outcome {
        err,
        code: exit_codes::FAILURE,
        ..Outcome::default()
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Forward => "forward",
        Direction::Reverse => "reverse",
    }
}

/// The command that rolls back an incomplete run in `direction`.
fn rollback_command(direction: Direction) -> String {
    match direction {
        Direction::Forward => format!("{} config relocate --reverse", receipt_file::binary()),
        Direction::Reverse => format!("{} config relocate", receipt_file::binary()),
    }
}

/// The target as the run found it, before it creates anything there.
struct TargetFound {
    root_existed: bool,
    lists_existed: bool,
    lock_existed: bool,
    inode: Option<Inode>,
}

/// The move set and the ordered steps of a run.
struct Plan {
    stores: Vec<StoreRename>,
    steps: Vec<Step>,
    stays: Vec<String>,
    /// The run moves every entry of the source lists directory.
    lists_emptied: bool,
}

fn run(
    layout: &Layout,
    options: Options,
    direction: Direction,
    state: &File,
) -> anyhow::Result<Outcome> {
    let (source, target) = layout.roots(direction);
    let (source_master, target_master) = (source.join(MASTER), target.join(MASTER));
    let (forward_created_root, forward_created_lists) = match direction {
        Direction::Forward => (false, false),
        Direction::Reverse => match receipt_file::read(state, DONE, layout.receipt_owner)? {
            Loaded::Valid(done)
                if done.direction == Direction::Forward && done.state == RunState::Complete =>
            {
                (
                    !done.target_root_existed,
                    !done.target_lists_existed
                        && done
                            .steps
                            .iter()
                            .any(|step| step.action == Action::CreateLists),
                )
            }
            Loaded::Valid(_) => {
                return Ok(Outcome::refused(
                    &[Refusal::new(
                        "receipt",
                        format!(
                            "{} does not record a complete forward run, so there is nothing to reverse",
                            layout.legacy.join(DONE).display()
                        ),
                    )],
                    None,
                ))
            }
            Loaded::Absent => {
                return Ok(Outcome::refused(
                    &[Refusal::new(
                        "receipt",
                        format!(
                            "{} is absent: no complete forward run to reverse",
                            layout.legacy.join(DONE).display()
                        ),
                    )],
                    None,
                ))
            }
            Loaded::Invalid { problem, .. } => {
                return Ok(Outcome::refused(
                    &[Refusal::new(
                        "receipt",
                        format!(
                            "{problem}; make the done record root:root with mode 0600 and a single link, then rerun"
                        ),
                    )],
                    None,
                ))
            }
        },
    };
    match std::fs::symlink_metadata(&source_master) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let moved = direction == Direction::Forward
                && std::fs::symlink_metadata(&target_master).is_ok()
                && matches!(
                    receipt_file::read(state, DONE, layout.receipt_owner)?,
                    Loaded::Valid(done)
                        if done.direction == Direction::Forward && done.state == RunState::Complete
                );
            let refusal = if moved {
                Refusal::new(
                    "already-moved",
                    format!(
                        "{} does not exist, {} does, and the done record shows a complete forward run: the config set is already in {}. On an SELinux host, if that run stopped before it relabelled, run restorecon -RF {} before the daemon starts",
                        source_master.display(),
                        target_master.display(),
                        target.display(),
                        target.display()
                    ),
                )
            } else {
                Refusal::new(
                    "master-missing",
                    format!("{} does not exist", source_master.display()),
                )
            };
            return Ok(Outcome::refused(&[refusal], None));
        }
        Err(error) => return Err(error).context("inspect the source master"),
        Ok(meta) if !meta.file_type().is_file() => {
            return Ok(Outcome::refused(
                &[Refusal::new(
                    "master-not-regular",
                    format!("{} is not a regular file", source_master.display()),
                )],
                None,
            ))
        }
        Ok(_) => {}
    }
    let source_guard = match write_lock::acquire_for_relocate(&source_master) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Outcome::refused(
                &[Refusal::new("tree-busy", format!("{error:#}"))],
                None,
            ))
        }
    };
    let probe = match write_lock::probe_for_relocate(&target_master) {
        Ok(probe) => probe,
        Err(error) => {
            return Ok(Outcome::refused(
                &[Refusal::new("tree-busy", format!("{error:#}"))],
                None,
            ))
        }
    };
    let mut refusals = Vec::new();
    let source_root_meta = source_guard.tree_io().root.metadata()?;
    let master_meta = std::fs::symlink_metadata(&source_master)?;
    refusals.extend(master_owner(
        &source_master,
        &master_meta,
        &source_root_meta,
    ));
    let found = inspect_target(direction, target, &source_root_meta, &mut refusals)?;
    let names = directory_names(source)?;
    for name in &names {
        if migration_name(name) {
            refusals.push(Refusal::new(
                "migration-active",
                format!(
                    "{} holds a schema migration ({}); finish or roll back the migration first",
                    source.display(),
                    name.to_string_lossy()
                ),
            ));
        } else if !known_name(direction, name) {
            refusals.push(Refusal::new(
                "unknown-entry",
                format!(
                    "{} is not a known warden entry; move it away or remove it first",
                    source.join(name).display()
                ),
            ));
        }
    }
    let now = time::OffsetDateTime::now_utc();
    let loaded = match loader::load_config_v5_for_repair_under_migration_guard(
        &source_guard,
        &source_master,
        now,
    ) {
        Ok(loaded) => loaded,
        Err(EditorGuardedLoadFailure::Diagnostics(errors)) => {
            let detail = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Ok(load_failed(refusals, &source_master, &detail));
        }
        Err(EditorGuardedLoadFailure::Operational(error)) => {
            return Ok(load_failed(refusals, &source_master, &format!("{error:#}")))
        }
    };
    let (snapshot, loaded) = match policy_revision::capture_coherent_loaded_v5_under_migration_guard(
        &source_guard,
        &loaded,
        now,
    ) {
        Ok(captured) => captured,
        Err(error) => return Ok(load_failed(refusals, &source_master, &error.to_string())),
    };
    if !loaded
        .config
        .backup
        .dir
        .as_deref()
        .is_some_and(Path::is_absolute)
    {
        refusals.push(Refusal::new(
            "backup-dir",
            "[backup] dir is unset or relative; set an absolute directory such as /var/lib/purge-warden/backups with `warden config edit` first",
        ));
    }
    let plan = plan(
        layout,
        direction,
        &snapshot,
        &loaded.config,
        &names,
        &found,
        &mut refusals,
    )?;
    inspect_stores(&source_guard, state, &mut refusals);
    let free = free_bytes(state)?;
    if free < layout.min_free_bytes {
        refusals.push(Refusal::new(
            "low-space",
            format!(
                "{} has {free} bytes free; the receipt needs {}",
                layout.legacy.display(),
                layout.min_free_bytes
            ),
        ));
    }
    let receipt = Receipt {
        format: receipt_file::FORMAT,
        direction,
        state: RunState::Planned,
        binary_version: env!("CARGO_PKG_VERSION").into(),
        source: source.to_path_buf(),
        source_inode: Inode::of(&source_root_meta),
        target: target.to_path_buf(),
        target_inode: found.inode,
        master: MASTER.into(),
        target_root_existed: found.root_existed,
        target_lists_existed: found.lists_existed,
        target_lock_existed: found.lock_existed,
        forward_created_root,
        forward_created_lists,
        stores: plan.stores,
        steps: plan.steps,
    };
    if options.dry_run {
        let mut outcome = Outcome {
            out: describe(&receipt, &plan.stays, plan.lists_emptied),
            ..Outcome::default()
        };
        if refusals.is_empty() {
            outcome
                .out
                .push("dry run: every check passed and nothing was moved".into());
        } else {
            outcome.err = refusals.iter().map(Refusal::line).collect();
            outcome
                .err
                .push("dry run: a real run would refuse; nothing was moved".into());
            outcome.code = exit_codes::FAILURE;
        }
        return Ok(outcome);
    }
    if !refusals.is_empty() {
        return Ok(Outcome::refused(&refusals, None));
    }
    commit(
        layout,
        state,
        receipt,
        source_guard,
        probe,
        &source_root_meta,
    )
}

fn load_failed(refusals: Vec<Refusal>, master: &Path, detail: &str) -> Outcome {
    let mut outcome = Outcome::refused(
        &refusals
            .into_iter()
            .chain([Refusal::new(
                "load-failed",
                format!("{} does not load as schema 5: {detail}", master.display()),
            )])
            .collect::<Vec<_>>(),
        None,
    );
    outcome.code = exit_codes::CONFIG;
    outcome
}

fn inspect_target(
    direction: Direction,
    target: &Path,
    source_root: &Metadata,
    refusals: &mut Vec<Refusal>,
) -> anyhow::Result<TargetFound> {
    let mut found = TargetFound {
        root_existed: false,
        lists_existed: false,
        lock_existed: false,
        inode: None,
    };
    let meta = match std::fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if direction == Direction::Reverse {
                refusals.push(Refusal::new(
                    "target-occupied",
                    format!("{} does not exist", target.display()),
                ));
            }
            return Ok(found);
        }
        Err(error) => return Err(error).with_context(|| format!("inspect {}", target.display())),
        Ok(meta) => meta,
    };
    if !meta.file_type().is_dir() {
        refusals.push(Refusal::new(
            "target-occupied",
            format!("{} is a symlink or not a directory", target.display()),
        ));
        return Ok(found);
    }
    found.root_existed = true;
    found.inode = Some(Inode::of(&meta));
    found.lists_existed = std::fs::symlink_metadata(target.join(LISTS)).is_ok_and(|m| m.is_dir());
    found.lock_existed = std::fs::symlink_metadata(target.join(WRITE_LOCK_FILE)).is_ok();
    if std::fs::symlink_metadata(target.join(MASTER)).is_ok() {
        refusals.push(Refusal::new(
            "target-occupied",
            format!("{} already exists", target.join(MASTER).display()),
        ));
    }
    let owner_differs = (meta.uid(), meta.gid()) != (source_root.uid(), source_root.gid());
    if direction == Direction::Reverse {
        if owner_differs {
            refusals.push(Refusal::new(
                "target-owner",
                format!(
                    "{} is owned by {}:{}, not {}:{} like the source root",
                    target.display(),
                    meta.uid(),
                    meta.gid(),
                    source_root.uid(),
                    source_root.gid()
                ),
            ));
        }
        return Ok(found);
    }
    let others: Vec<String> = directory_names(target)?
        .iter()
        .filter(|name| *name != MASTER && *name != WRITE_LOCK_FILE)
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    if !others.is_empty() {
        refusals.push(Refusal::new(
            "target-occupied",
            format!("{} already holds {}", target.display(), others.join(", ")),
        ));
    } else if owner_differs || meta.mode() & 0o7777 != 0o750 {
        refusals.push(Refusal::new(
            "target-root",
            format!(
                "{} has owner {}:{} and mode {:o}, not {}:{} and 750; remove {} when present, then rmdir {}",
                target.display(),
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o7777,
                source_root.uid(),
                source_root.gid(),
                target.join(WRITE_LOCK_FILE).display(),
                target.display()
            ),
        ));
    }
    Ok(found)
}

fn migration_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    name == migration_journal::TXN_DIR_NAME
        || bytes.starts_with(migration_journal::CLEANUP_DIR_PREFIX.as_bytes())
        || bytes.starts_with(migration_journal::FINALIZED_DIR_PREFIX.as_bytes())
}

/// Whether a top-level source entry is outside the `.warden-*` namespace or
/// one relocate knows.
fn known_name(direction: Direction, name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    if !bytes.starts_with(b".warden-") {
        return true;
    }
    match direction {
        Direction::Forward => write_lock::reserved_component(name) || name == ".warden-tui-uor",
        Direction::Reverse => {
            name == WRITE_LOCK_FILE
                || name == policy_transaction::STORE_DIR_NAME
                || bytes.starts_with(write_lock::WRITE_STAGE_PREFIX.as_bytes())
        }
    }
}

fn directory_names(path: &Path) -> anyhow::Result<Vec<OsString>> {
    let mut names = std::fs::read_dir(path)
        .with_context(|| format!("list {}", path.display()))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()
        .with_context(|| format!("list {}", path.display()))?;
    names.sort();
    Ok(names)
}

fn inode_at(path: &Path) -> anyhow::Result<Option<Inode>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(Inode::of(&meta))),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn utf8(name: &OsStr) -> anyhow::Result<String> {
    name.to_str()
        .map(str::to_owned)
        .with_context(|| format!("entry name is not UTF-8: {}", name.to_string_lossy()))
}

fn rename_step(
    number: u8,
    from_dir: &Path,
    from: &str,
    to_dir: &Path,
    to: &str,
) -> anyhow::Result<Step> {
    let object = inode_at(&from_dir.join(from))?
        .with_context(|| format!("{} disappeared", from_dir.join(from).display()))?;
    Ok(Step {
        number,
        action: Action::Rename {
            from_dir: from_dir.to_path_buf(),
            from: from.to_owned(),
            to_dir: to_dir.to_path_buf(),
            to: to.to_owned(),
            object,
        },
        done: false,
    })
}

fn plain_step(number: u8, action: Action) -> Step {
    Step {
        number,
        action,
        done: false,
    }
}

/// The file name of an `imported.local` blocklist body under `<root>/lists`.
fn imported_local_name(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.host_str() != Some(IMPORTED_LOCAL_HOST) {
        return None;
    }
    let name = parsed.path().trim_start_matches('/');
    (!name.is_empty() && !name.contains('/') && name != ".." && name != ".")
        .then(|| name.to_owned())
}

/// The first normal component of a root-relative path.
fn first_component(path: &Path) -> Option<&OsStr> {
    path.components().find_map(|component| match component {
        Component::Normal(name) => Some(name),
        _ => None,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan(
    layout: &Layout,
    direction: Direction,
    snapshot: &policy_revision::PolicyRevisionSnapshot,
    config: &crate::config::schema::target_v5::ConfigV5,
    names: &[OsString],
    found: &TargetFound,
    refusals: &mut Vec<Refusal>,
) -> anyhow::Result<Plan> {
    let (source, target) = layout.roots(direction);
    let (source_master, target_master) = (source.join(MASTER), target.join(MASTER));
    let exists = |name: &OsStr| std::fs::symlink_metadata(source.join(name)).is_ok();
    let mut top = BTreeSet::<OsString>::new();
    for member in snapshot.inventory().members() {
        let relative = member.path();
        if !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            refusals.push(Refusal::new(
                "member-not-plain",
                format!("member {} lies outside the root", relative.display()),
            ));
            continue;
        }
        if let PolicyMemberState::Present(bytes) = member.state() {
            check_member(source, relative, refusals);
            if matches!(
                member.kind(),
                PolicyMemberKind::Master | PolicyMemberKind::Include
            ) {
                for pattern in declared_includes(bytes) {
                    let joined = relative.parent().unwrap_or(Path::new("")).join(&pattern);
                    if let Some(first) = first_component(&joined) {
                        let wildcard = first.as_bytes().iter().any(|b| b"*?[".contains(b));
                        if !wildcard && exists(first) {
                            top.insert(first.to_os_string());
                        }
                    }
                }
            }
        }
        if member.kind() != PolicyMemberKind::Master {
            if let Some(first) = first_component(relative) {
                top.insert(first.to_os_string());
            }
        }
    }
    for extra in [loader::CLUSTER_DROP_IN_DIR, "packs", "secrets.toml"] {
        if exists(OsStr::new(extra)) {
            top.insert(extra.into());
        }
    }
    top.remove(OsStr::new(MASTER));
    for name in &top {
        let meta = std::fs::symlink_metadata(source.join(name))?;
        if !meta.is_dir() && !meta.is_file() {
            refusals.push(Refusal::new(
                "member-not-plain",
                format!(
                    "{} is a symlink or special file",
                    source.join(name).display()
                ),
            ));
        }
    }
    let mut state_names: Vec<OsString> = STATE_NAMES.iter().map(OsString::from).collect();
    let cache = &config.lists.cache_dir;
    let cache_relative = if cache.is_absolute() {
        cache.strip_prefix(&layout.legacy).ok()
    } else {
        Some(cache.as_path())
    };
    if let Some(first) = cache_relative.and_then(first_component) {
        state_names.push(first.to_os_string());
    }
    for name in &top {
        if state_names.contains(name) {
            refusals.push(Refusal::new(
                "state-name",
                format!(
                    "{} holds members but has the name of a state path; rename the include first",
                    source.join(name).display()
                ),
            ));
        }
    }
    let mut bodies = BTreeSet::new();
    for list in &config.blocklists {
        let Some(name) = imported_local_name(&list.url) else {
            continue;
        };
        match std::fs::symlink_metadata(source.join(LISTS).join(&name)) {
            Ok(meta) if meta.is_file() => {
                bodies.insert(name);
            }
            Ok(_) => refusals.push(Refusal::new(
                "member-not-plain",
                format!(
                    "{} is not a regular file",
                    source.join(LISTS).join(&name).display()
                ),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect an imported list body"),
        }
    }

    let mut stores = Vec::new();
    let mut steps = vec![
        plain_step(1, Action::CreateRoot),
        plain_step(2, Action::LockTarget),
    ];
    let mut store_bases: Vec<(&str, Scheme)> = PLAIN_STORES
        .iter()
        .map(|base| (*base, Scheme::Plain))
        .collect();
    store_bases.push((policy_transaction::RECEIPT_DIR, Scheme::Domain));
    for (base, scheme) in store_bases {
        let (old, new) = namespaces(scheme, &source_master, &target_master);
        let base_dir = layout.legacy.join(base);
        if inode_at(&base_dir.join(&old))?.is_none() {
            continue;
        }
        #[cfg(not(feature = "cluster"))]
        if CLUSTER_STORES.contains(&base) {
            refusals.push(Refusal::new(
                "cluster-store",
                format!(
                    "{} needs a binary built with cluster support",
                    base_dir.join(&old).display()
                ),
            ));
        }
        steps.push(rename_step(3, &base_dir, &old, &base_dir, &new)?);
        stores.push(StoreRename {
            base: base.into(),
            scheme,
            old,
            new,
        });
    }
    let transactions = policy_transaction::STORE_DIR_NAME;
    if inode_at(&source.join(transactions))?.is_some() {
        let (old, new) = namespaces(Scheme::Domain, &source_master, &target_master);
        let store_dir = source.join(transactions);
        if inode_at(&store_dir.join(&old))?.is_some() {
            steps.push(rename_step(4, &store_dir, &old, &store_dir, &new)?);
            stores.push(StoreRename {
                base: transactions.into(),
                scheme: Scheme::Domain,
                old,
                new,
            });
        }
        steps.push(rename_step(4, source, transactions, target, transactions)?);
    }
    if !bodies.is_empty() && !top.contains(OsStr::new(LISTS)) {
        steps.push(plain_step(5, Action::CreateLists));
        for name in &bodies {
            steps.push(rename_step(
                5,
                &source.join(LISTS),
                name,
                &target.join(LISTS),
                name,
            )?);
        }
    }
    for name in &top {
        let name = utf8(name)?;
        steps.push(rename_step(6, source, &name, target, &name)?);
    }
    steps.push(plain_step(7, Action::Rebind));
    steps.push(plain_step(8, Action::DeleteCapability));
    steps.push(rename_step(9, source, MASTER, target, MASTER)?);

    let home = filesystem_of(source)?;
    let mut directories = BTreeSet::new();
    for step in &steps {
        if let Action::Rename {
            from_dir,
            to_dir,
            to,
            ..
        } = &step.action
        {
            directories.insert(from_dir.clone());
            directories.insert(to_dir.clone());
            if inode_at(&to_dir.join(to))?.is_some() {
                refusals.push(Refusal::new(
                    "name-taken",
                    format!("{} already exists", to_dir.join(to).display()),
                ));
            }
        }
    }
    if !found.root_existed {
        directories.insert(
            target
                .parent()
                .context("target root has no parent")?
                .to_path_buf(),
        );
    }
    for directory in directories {
        if filesystem_of(&directory)?.is_some_and(|here| Some(here) != home) {
            refusals.push(Refusal::new(
                "other-filesystem",
                format!(
                    "{} is on another filesystem or mount than {}; a rename cannot move across it",
                    directory.display(),
                    source.display()
                ),
            ));
        }
    }

    let moved: BTreeSet<&OsStr> = top
        .iter()
        .map(OsString::as_os_str)
        .chain([OsStr::new(MASTER), OsStr::new(transactions)])
        .collect();
    let stays = names
        .iter()
        .filter(|name| {
            !moved.contains(name.as_os_str())
                && (!name.as_bytes().starts_with(b".warden-")
                    || name
                        .as_bytes()
                        .starts_with(write_lock::WRITE_STAGE_PREFIX.as_bytes()))
        })
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    let lists_emptied = !top.contains(OsStr::new(LISTS))
        && directory_names(&source.join(LISTS)).is_ok_and(|names| {
            names
                .iter()
                .all(|name| name.to_str().is_some_and(|name| bodies.contains(name)))
        });
    Ok(Plan {
        stores,
        steps,
        stays,
        lists_emptied,
    })
}

/// No symlink on the way to a member, and the member is a regular file
/// with one link.
fn check_member(root: &Path, relative: &Path, refusals: &mut Vec<Refusal>) {
    let mut path = root.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        let last = index + 1 == parts.len();
        let problem = match std::fs::symlink_metadata(&path) {
            Err(error) => Some(format!("cannot be inspected: {error}")),
            Ok(meta) if meta.file_type().is_symlink() => Some("is a symlink".into()),
            Ok(meta) if !last && !meta.is_dir() => Some("is not a directory".into()),
            Ok(meta) if last && !meta.is_file() => Some("is not a regular file".into()),
            Ok(meta) if last && meta.nlink() != 1 => {
                Some(format!("has {} links instead of 1", meta.nlink()))
            }
            Ok(_) => None,
        };
        if let Some(problem) = problem {
            refusals.push(Refusal::new(
                "member-not-plain",
                format!("{} {problem}", path.display()),
            ));
            return;
        }
    }
}

/// The relative include patterns a master or include file declares.
fn declared_includes(bytes: &[u8]) -> Vec<String> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| table.get("includes").cloned())
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn namespaces(scheme: Scheme, source_master: &Path, target_master: &Path) -> (String, String) {
    match scheme {
        Scheme::Plain => (
            plain_namespace(source_master),
            plain_namespace(target_master),
        ),
        Scheme::Domain => (
            policy_transaction::master_namespace(source_master),
            policy_transaction::master_namespace(target_master),
        ),
    }
}

/// The device and mount id of an existing directory. The mount id comes from
/// procfs; on a kernel that does not report it the device decides alone.
fn filesystem_of(path: &Path) -> anyhow::Result<Option<(u64, Option<u64>)>> {
    let Some(inode) = inode_at(path)? else {
        return Ok(None);
    };
    let directory = state_dir::open_directory(path)?;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", directory.as_raw_fd()))
        .context("read the mount id from procfs")?;
    let mount = info
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|value| value.trim().parse().ok());
    #[cfg(test)]
    let mount = if OTHER_MOUNT.with_borrow(|other| other.as_deref() == Some(path)) {
        Some(mount.map_or(0, |id: u64| id.wrapping_add(1)))
    } else {
        mount
    };
    Ok(Some((inode.device, mount)))
}

fn free_bytes(directory: &File) -> anyhow::Result<u64> {
    // SAFETY: statvfs is plain data and the descriptor is open.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and `stat` is a valid out pointer.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error()).context("statvfs the state directory");
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// The remedy for a store that one normal daemon start recovers.
const RESTART_REMEDY: &str = "start the daemon normally once and stop it, then rerun";

fn inspect_stores(guard: &MigrationWriteLock, state: &File, refusals: &mut Vec<Refusal>) {
    let mut check = |store: &str, remedy: &str, result: anyhow::Result<()>| {
        if let Err(error) = result {
            refusals.push(Refusal::new(
                "recovery-required",
                format!("{store}: {error:#}; {remedy}"),
            ));
        }
    };
    check(
        policy_transaction::STORE_DIR_NAME,
        RESTART_REMEDY,
        policy_transaction::relocate_transactions_settled(guard),
    );
    check(
        policy_transaction::RECEIPT_DIR,
        RESTART_REMEDY,
        policy_transaction::relocate_receipts_settled(guard, state),
    );
    // The TUI resumes its journal when it opens, not the daemon.
    check(
        ".warden-tui-uor",
        "start the daemon, open `warden tui` so it resumes or discards the pending policy change, quit it and stop the daemon, then rerun",
        crate::tui::relocate_recovery_settled(guard),
    );
    #[cfg(feature = "cluster")]
    {
        // An open preview stays until it is applied or cancelled.
        check(
            ".warden-node-lifecycle",
            "once no preview is open, start the daemon normally once and stop it, then rerun",
            crate::cluster::lifecycle::relocate_settled(guard),
        );
        // Node operations advance only through the running daemon.
        check(
            ".warden-node-control",
            "start the daemon, resume or cancel the operation in the Configuration / Nodes screen of `warden tui` until `warden node status` shows it complete or cancelled, stop the daemon, then rerun",
            crate::cluster::node_control::relocate_settled(guard),
        );
        check(
            ".warden-cluster-ownership",
            RESTART_REMEDY,
            crate::cluster::ledger::relocate_settled(guard),
        );
        check(
            ".warden-cluster-publications",
            RESTART_REMEDY,
            crate::cluster::publication::relocate_settled(guard),
        );
    }
}

fn describe(receipt: &Receipt, stays: &[String], lists_emptied: bool) -> Vec<String> {
    let (source, target) = (&receipt.source, &receipt.target);
    let mut lines = vec![format!(
        "config relocate {}: {} -> {} (dry run)",
        direction_name(receipt.direction),
        source.display(),
        target.display()
    )];
    for step in &receipt.steps {
        let text = match &step.action {
            Action::CreateRoot if receipt.target_root_existed => {
                format!("keep the existing {}", target.display())
            }
            Action::CreateRoot => format!(
                "create {} with mode 0750 and the owner of {}",
                target.display(),
                source.display()
            ),
            Action::LockTarget => format!("lock {}", target.join(WRITE_LOCK_FILE).display()),
            Action::Rename {
                from_dir,
                from,
                to_dir,
                to,
                ..
            } => format!(
                "rename {} -> {}",
                from_dir.join(from).display(),
                to_dir.join(to).display()
            ),
            Action::CreateLists if receipt.target_lists_existed => {
                format!("keep the existing {}", target.join(LISTS).display())
            }
            Action::CreateLists => format!("create {}", target.join(LISTS).display()),
            Action::Rebind => format!(
                "rebind the root pin of stored receipts, retained transactions and the ownership ledger from {}:{} to the root {}",
                receipt.source_inode.device,
                receipt.source_inode.inode,
                target.display()
            ),
            Action::DeleteCapability => {
                "delete the runtime capability; the next normal start attests again".into()
            }
        };
        lines.push(format!("step {}: {text}", step.number));
    }
    for store in &receipt.stores {
        lines.push(format!(
            "namespace {}: {} -> {}",
            store.base, store.old, store.new
        ));
    }
    // The cleanup after a reverse commit removes the lists directory the
    // forward run created, when the move empties it.
    let stays: Vec<&str> = stays
        .iter()
        .map(String::as_str)
        .filter(|name| !(receipt.forward_created_lists && lists_emptied && *name == LISTS))
        .collect();
    if !stays.is_empty() {
        lines.push(format!(
            "stays in {}: {}",
            source.display(),
            stays.join(", ")
        ));
    }
    if receipt.forward_created_lists {
        lines.push(format!(
            "after the move: remove {} if it is empty",
            source.join(LISTS).display()
        ));
    }
    if receipt.forward_created_root {
        lines.push(format!(
            "after the move: remove {} if nothing else is left in it",
            source.display()
        ));
    }
    lines
}

/// Steps 0-10 of a run. Any error after step 0 leaves the fence up and names
/// the rollback command.
fn commit(
    layout: &Layout,
    state: &File,
    mut receipt: Receipt,
    source_guard: MigrationWriteLock,
    mut probe: Option<RelocateProbe>,
    source_root: &Metadata,
) -> anyhow::Result<Outcome> {
    let owner = layout.receipt_owner;
    receipt_file::write(state, ACTIVE, &receipt, owner, false)?;
    let mut target_guard = None;
    let steps = (|| -> anyhow::Result<()> {
        for index in 0..receipt.steps.len() {
            let action = receipt.steps[index].action.clone();
            perform(
                &receipt,
                index,
                &action,
                state,
                source_root,
                &mut probe,
                &mut target_guard,
            )?;
            #[cfg(test)]
            injected(Stop::AfterAction(index))?;
            if action == Action::CreateRoot && receipt.target_inode.is_none() {
                receipt.target_inode = inode_at(&receipt.target)?;
            }
            receipt.steps[index].done = true;
            receipt.state = RunState::InProgress;
            receipt_file::write(state, ACTIVE, &receipt, owner, true)?;
            #[cfg(test)]
            injected(Stop::AfterReceipt(index))?;
        }
        receipt.state = RunState::Complete;
        receipt_file::write(state, ACTIVE, &receipt, owner, true)?;
        #[cfg(test)]
        injected(Stop::BeforeRetire)?;
        receipt_file::retire(state)
    })();
    if let Err(error) = steps {
        return Ok(Outcome {
            err: vec![
                format!("error: {error:#}"),
                format!(
                    "The run stopped and the relocate fence stays up. Roll back before anything else: {}",
                    rollback_command(receipt.direction)
                ),
            ],
            code: exit_codes::FAILURE,
            ..Outcome::default()
        });
    }
    drop(target_guard);
    let mut outcome = Outcome {
        out: vec![format!(
            "relocated the config set: {} -> {}",
            receipt.source.display(),
            receipt.target.display()
        )],
        ..Outcome::default()
    };
    if receipt.direction == Direction::Reverse {
        clean_etc(&receipt, source_guard, true, &mut outcome);
    }
    finished(&receipt, &mut outcome);
    Ok(outcome)
}

/// After a reverse commit: unlink the `/etc` write lock, release `held` (the
/// lock and root descriptors), then remove the directories the forward run
/// created. The move is committed, so a failure here is reported with the
/// manual steps and the run still relabels.
fn clean_etc<T>(receipt: &Receipt, held: T, unlink: bool, outcome: &mut Outcome) {
    let unlinked = if unlink {
        unlink_lock(&receipt.source)
    } else {
        Ok(())
    };
    drop(held);
    let Err(error) = unlinked.and_then(|()| remove_created(receipt, outcome)) else {
        return;
    };
    let mut steps = vec![format!(
        "rm -f {}",
        receipt.source.join(WRITE_LOCK_FILE).display()
    )];
    if receipt.forward_created_lists {
        steps.push(format!("rmdir {}", receipt.source.join(LISTS).display()));
    }
    if receipt.forward_created_root {
        steps.push(format!("rmdir {}", receipt.source.display()));
    }
    outcome.err.push(format!("error: {error:#}"));
    outcome.err.push(format!(
        "The move is committed and the relocate fence is down. Finish the cleanup by hand (an rmdir of a directory that is not empty fails; keep that directory): {}",
        steps.join("; ")
    ));
    outcome.code = exit_codes::FAILURE;
}

fn finished(receipt: &Receipt, outcome: &mut Outcome) {
    outcome.out.push(
        "The first normal daemon start attests the runtime capability again; start it before a v4-to-v5 migration rollback.".into(),
    );
    outcome.relabel = Some(receipt.target.clone());
}

#[allow(clippy::too_many_arguments)]
fn perform(
    receipt: &Receipt,
    #[cfg_attr(not(test), allow(unused_variables))] index: usize,
    action: &Action,
    state: &File,
    source_root: &Metadata,
    probe: &mut Option<RelocateProbe>,
    target_guard: &mut Option<MigrationWriteLock>,
) -> anyhow::Result<()> {
    match action {
        Action::CreateRoot => {
            if !receipt.target_root_existed {
                create_root(&receipt.target, source_root)?;
            }
        }
        Action::LockTarget => {
            drop(probe.take());
            *target_guard = Some(write_lock::acquire_for_relocate(
                &receipt.target.join(&receipt.master),
            )?);
        }
        Action::Rename {
            from_dir,
            from,
            to_dir,
            to,
            object,
        } => {
            let source = state_dir::open_directory(from_dir)?;
            let target = state_dir::open_directory(to_dir)?;
            let found = tree_io::inspect_at(&source, OsStr::new(from))?
                .map(|file| file.metadata().map(|meta| Inode::of(&meta)))
                .transpose()?;
            ensure!(
                found == Some(*object),
                "{} changed since the plan",
                from_dir.join(from).display()
            );
            #[cfg(test)]
            if STOP.get() == Some(Stop::Exdev(index)) {
                return Err(io::Error::from_raw_os_error(libc::EXDEV))
                    .with_context(|| format!("rename {}", from_dir.join(from).display()));
            }
            tree_io::rename_noreplace_at(&source, OsStr::new(from), &target, OsStr::new(to))
                .with_context(|| {
                    format!(
                        "rename {} to {}",
                        from_dir.join(from).display(),
                        to_dir.join(to).display()
                    )
                })?;
            target.sync_all()?;
            source.sync_all()?;
        }
        Action::CreateLists => {
            if !receipt.target_lists_existed {
                let root = state_dir::open_directory(&receipt.target)?;
                tree_io::mkdir_open(&root, OsStr::new(LISTS))?;
            }
        }
        Action::Rebind => {
            let guard = target_guard
                .as_ref()
                .context("the target write lock is not held")?;
            let to = receipt
                .target_inode
                .context("the target root inode is unknown")?;
            rebind(guard, state, receipt.source_inode, to)?;
        }
        Action::DeleteCapability => {
            runtime_lease::delete_capability(state)?;
        }
    }
    Ok(())
}

fn rebind(guard: &MigrationWriteLock, state: &File, from: Inode, to: Inode) -> anyhow::Result<()> {
    policy_transaction::rebind_root(guard, state, from.pair(), to.pair())?;
    #[cfg(feature = "cluster")]
    crate::cluster::ledger::rebind_root(guard, from.pair(), to.pair())?;
    Ok(())
}

fn create_root(target: &Path, owner: &Metadata) -> anyhow::Result<()> {
    let parent = state_dir::open_directory(target.parent().context("target root has no parent")?)?;
    let name = target.file_name().context("target root has no name")?;
    let name_c = CString::new(name.as_bytes())?;
    // SAFETY: the parent descriptor is open and the name is NUL-terminated.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o750) } != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("create {}", target.display()));
    }
    let created = write_lock::open_at(&parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    write_lock::preserve_owner(&created, owner)?;
    created.set_permissions(Permissions::from_mode(0o750))?;
    created.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

enum Removed {
    Yes,
    Absent,
    NotEmpty,
}

fn remove_dir(path: &Path) -> anyhow::Result<Removed> {
    let parent = state_dir::open_directory(path.parent().context("directory has no parent")?)?;
    let name = CString::new(
        path.file_name()
            .context("directory has no name")?
            .as_bytes(),
    )?;
    // SAFETY: the parent descriptor is open and the name is NUL-terminated.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
        parent.sync_all()?;
        return Ok(Removed::Yes);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOENT) => Ok(Removed::Absent),
        Some(libc::ENOTEMPTY | libc::EEXIST) => Ok(Removed::NotEmpty),
        _ => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn unlink_lock(root: &Path) -> anyhow::Result<()> {
    let directory = state_dir::open_directory(root)?;
    match tree_io::unlink_at(&directory, OsStr::new(WRITE_LOCK_FILE)) {
        Ok(()) => Ok(directory.sync_all()?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove {}", root.join(WRITE_LOCK_FILE).display()))
        }
    }
}

/// After a reverse run: remove the /etc directories the forward run created,
/// when they are empty, and list what keeps them.
fn remove_created(receipt: &Receipt, outcome: &mut Outcome) -> anyhow::Result<()> {
    #[cfg(test)]
    injected(Stop::Cleanup)?;
    let etc = &receipt.source;
    if inode_at(etc)?.is_none() {
        return Ok(());
    }
    if receipt.forward_created_lists && inode_at(&etc.join(LISTS))?.is_some() {
        if let Removed::NotEmpty = remove_dir(&etc.join(LISTS))? {
            outcome.out.push(format!(
                "kept {}: it is not empty",
                etc.join(LISTS).display()
            ));
        }
    }
    let left: Vec<String> = directory_names(etc)?
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    if receipt.forward_created_root && left.is_empty() {
        remove_dir(etc)?;
        outcome.out.push(format!("removed {}", etc.display()));
    } else if !left.is_empty() {
        outcome.out.push(format!(
            "left in {} (not part of the config set): {}",
            etc.display(),
            left.join(", ")
        ));
    }
    Ok(())
}

/// An active receipt in state `complete`: the run stopped inside step 10.
fn finish(options: Options, state: &File, receipt: Receipt) -> anyhow::Result<Outcome> {
    if options.dry_run {
        return Ok(Outcome {
            out: vec![format!(
                "The {} run moved everything and stopped while it committed. The next real run in either direction only finishes the commit.",
                direction_name(receipt.direction)
            )],
            ..Outcome::default()
        });
    }
    let mut outcome = Outcome {
        out: vec![format!(
            "finished the commit of the {} run: {} -> {}",
            direction_name(receipt.direction),
            receipt.source.display(),
            receipt.target.display()
        )],
        ..Outcome::default()
    };
    if receipt.direction == Direction::Reverse {
        let probe = write_lock::probe_for_relocate(&receipt.source.join(&receipt.master))?;
        receipt_file::retire(state)?;
        let unlink = probe.is_some();
        clean_etc(&receipt, probe, unlink, &mut outcome);
    } else {
        receipt_file::retire(state)?;
    }
    finished(&receipt, &mut outcome);
    Ok(outcome)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    Source,
    Target,
    Elsewhere,
}

/// Where the object of a rename step is now, and the two directories it is
/// looked for in.
struct Located {
    place: Place,
    from_dir: PathBuf,
    to_dir: PathBuf,
}

fn locate(action: &Action, steps: &[Step]) -> anyhow::Result<Option<Located>> {
    let Action::Rename {
        from_dir,
        from,
        to_dir,
        to,
        object,
    } = action
    else {
        return Ok(None);
    };
    let (from_dir, to_dir) = (moved_along(from_dir, steps)?, moved_along(to_dir, steps)?);
    let place = if inode_at(&from_dir.join(from))? == Some(*object) {
        Place::Source
    } else if inode_at(&to_dir.join(to))? == Some(*object) {
        Place::Target
    } else {
        Place::Elsewhere
    };
    Ok(Some(Located {
        place,
        from_dir,
        to_dir,
    }))
}

/// `dir` as it is now: below an entry that another rename step already
/// moved, it moved along with that entry.
fn moved_along(dir: &Path, steps: &[Step]) -> anyhow::Result<PathBuf> {
    for step in steps {
        let Action::Rename {
            from_dir,
            from,
            to_dir,
            to,
            object,
        } = &step.action
        else {
            continue;
        };
        if let Ok(rest) = dir.strip_prefix(from_dir.join(from)) {
            let moved = to_dir.join(to);
            if inode_at(&moved)? == Some(*object) {
                return Ok(if rest.as_os_str().is_empty() {
                    moved
                } else {
                    moved.join(rest)
                });
            }
        }
    }
    Ok(dir.to_path_buf())
}

/// Undo an incomplete run. Locates every rename object first and changes
/// nothing unless the receipt matches the tree.
fn rollback(options: Options, state: &File, receipt: Receipt) -> anyhow::Result<Outcome> {
    let direction = receipt.direction;
    let source_guard = match write_lock::acquire_for_relocate(&receipt.source.join(&receipt.master))
    {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Outcome::refused(
                &[Refusal::new("tree-busy", format!("{error:#}"))],
                Some(direction),
            ))
        }
    };
    let target_master = receipt.target.join(&receipt.master);
    let held = if inode_at(&receipt.target.join(WRITE_LOCK_FILE))?.is_some() {
        write_lock::acquire_for_relocate(&target_master).map(|guard| (Some(guard), None))
    } else {
        write_lock::probe_for_relocate(&target_master).map(|probe| (None, probe))
    };
    let (mut target_guard, mut probe) = match held {
        Ok(held) => held,
        Err(error) => {
            return Ok(Outcome::refused(
                &[Refusal::new("tree-busy", format!("{error:#}"))],
                Some(direction),
            ))
        }
    };
    let steps = &receipt.steps;
    let frontier = steps
        .iter()
        .position(|step| !step.done)
        .unwrap_or(steps.len());
    let last = frontier.min(steps.len().saturating_sub(1));
    for (index, step) in steps.iter().enumerate() {
        let Some(Located {
            place, from_dir, ..
        }) = locate(&step.action, steps)?
        else {
            continue;
        };
        let Action::Rename { from, .. } = &step.action else {
            unreachable!("only renames are located");
        };
        let source = from_dir.join(from);
        let (problem, remedy) = match place {
            Place::Source => continue,
            Place::Target if index > last => (
                "is already at its target although the receipt says it never moved",
                "recover by hand",
            ),
            Place::Target if inode_at(&source)?.is_none() => continue,
            Place::Target => (
                "exists, so the object at its target cannot move back",
                "move that entry away, then rerun",
            ),
            Place::Elsewhere => (
                "is neither at its source nor at its target",
                "recover by hand",
            ),
        };
        let message = format!(
            "the receipt does not match the tree: {} {problem}; nothing was changed, {remedy}",
            source.display()
        );
        return Ok(Outcome::refused(
            &[Refusal::new("receipt", message)],
            Some(direction),
        ));
    }
    let mut lines = vec![format!(
        "{} the incomplete {} run: {} -> {}",
        if options.dry_run {
            "dry run: the rollback would undo"
        } else {
            "rolled back"
        },
        direction_name(direction),
        receipt.source.display(),
        receipt.target.display()
    )];
    let undone = (|| -> anyhow::Result<()> {
        for index in (0..=last).rev() {
            let step = &steps[index];
            #[cfg(test)]
            injected(Stop::Undo(index))?;
            let line = undo(
                &receipt,
                step,
                state,
                options.dry_run,
                &mut target_guard,
                &mut probe,
            )?;
            if let Some(line) = line {
                lines.push(format!("step {}: {line}", step.number));
            }
        }
        if !options.dry_run {
            drop((target_guard.take(), probe.take()));
            receipt_file::remove_active(state)?;
        }
        Ok(())
    })();
    if let Err(error) = undone {
        // Every undo locates its object first, so a rerun skips what is back.
        return Ok(Outcome {
            out: lines.split_off(1),
            err: vec![
                format!("error: {error:#}"),
                format!(
                    "The rollback stopped and the relocate fence stays up. Fix the cause and rerun: {}",
                    rollback_command(direction)
                ),
            ],
            code: exit_codes::FAILURE,
            ..Outcome::default()
        });
    }
    if options.dry_run {
        lines.push(format!("run it with: {}", rollback_command(direction)));
        return Ok(Outcome {
            out: lines,
            ..Outcome::default()
        });
    }
    drop(source_guard);
    lines.push(
        "The relocate fence is down. The runtime capability stays deleted; the next normal start attests again.".into(),
    );
    Ok(Outcome {
        out: lines,
        ..Outcome::default()
    })
}

fn undo(
    receipt: &Receipt,
    step: &Step,
    state: &File,
    dry_run: bool,
    target_guard: &mut Option<MigrationWriteLock>,
    probe: &mut Option<RelocateProbe>,
) -> anyhow::Result<Option<String>> {
    let target = &receipt.target;
    let root_present = inode_at(target)?.is_some();
    Ok(match &step.action {
        Action::Rename { from, to, .. } => {
            let Some(Located {
                place: Place::Target,
                from_dir,
                to_dir,
            }) = locate(&step.action, &receipt.steps)?
            else {
                return Ok(None);
            };
            if !dry_run {
                let source = state_dir::open_directory(&from_dir)?;
                let destination = state_dir::open_directory(&to_dir)?;
                tree_io::rename_noreplace_at(
                    &destination,
                    OsStr::new(to),
                    &source,
                    OsStr::new(from),
                )
                .with_context(|| {
                    format!(
                        "rename {} back to {}",
                        to_dir.join(to).display(),
                        from_dir.join(from).display()
                    )
                })?;
                source.sync_all()?;
                destination.sync_all()?;
            }
            Some(format!(
                "rename {} back to {}",
                to_dir.join(to).display(),
                from_dir.join(from).display()
            ))
        }
        Action::CreateLists => {
            let lists = target.join(LISTS);
            if receipt.target_lists_existed || inode_at(&lists)?.is_none() {
                return Ok(None);
            }
            if dry_run {
                Some(format!("remove {}", lists.display()))
            } else {
                match remove_dir(&lists)? {
                    Removed::NotEmpty => Some(format!("kept {}: it is not empty", lists.display())),
                    _ => Some(format!("removed {}", lists.display())),
                }
            }
        }
        Action::Rebind => {
            let Some(target_inode) = receipt.target_inode.filter(|_| root_present) else {
                return Ok(None);
            };
            if !dry_run {
                // Without its lock file the rollback holds only the probe.
                // Take the write lock now, which creates the file; the undo
                // of step 2 removes it again unless it existed at plan time.
                let guard = match target_guard {
                    Some(guard) => guard,
                    None => {
                        drop(probe.take());
                        target_guard.insert(write_lock::acquire_for_relocate(
                            &target.join(&receipt.master),
                        )?)
                    }
                };
                rebind(guard, state, target_inode, receipt.source_inode)?;
            }
            Some("rebind the root pins back to the source root".into())
        }
        Action::DeleteCapability => None,
        Action::LockTarget => {
            if !root_present {
                return Ok(None);
            }
            let lock = target.join(WRITE_LOCK_FILE);
            let remove = !receipt.target_lock_existed && inode_at(&lock)?.is_some();
            if dry_run {
                return Ok(remove.then(|| format!("remove {}", lock.display())));
            }
            if remove {
                unlink_lock(target)?;
            }
            drop(target_guard.take());
            drop(probe.take());
            remove.then(|| format!("removed {}", lock.display()))
        }
        Action::CreateRoot => {
            if receipt.target_root_existed || !root_present {
                return Ok(None);
            }
            if dry_run {
                return Ok(Some(format!("remove {}", target.display())));
            }
            drop(target_guard.take());
            drop(probe.take());
            match remove_dir(target)? {
                Removed::NotEmpty => Some(format!("kept {}: it is not empty", target.display())),
                _ => Some(format!("removed {}", target.display())),
            }
        }
    })
}

/// Run `restorecon -RF root` when restorecon is installed. A failure keeps
/// the committed move and prints the exact command to rerun.
fn relabel(root: &Path, search_path: &OsStr, outcome: &mut Outcome) {
    let program = std::env::split_paths(search_path)
        .map(|directory| directory.join("restorecon"))
        .find(|path| {
            std::fs::metadata(path)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        });
    let Some(program) = program else {
        outcome
            .out
            .push("restorecon is not installed; no SELinux relabel".into());
        return;
    };
    let command = format!("{} -RF {}", program.display(), root.display());
    let failure = match std::process::Command::new(&program)
        .arg("-RF")
        .arg(root)
        .status()
    {
        Ok(status) if status.success() => {
            outcome.out.push(format!("relabelled: {command}"));
            return;
        }
        Ok(status) => format!("{command} failed: {status}"),
        Err(error) => format!("{command} could not run: {error}"),
    };
    outcome.err.push(format!("error: {failure}"));
    outcome.err.push(format!(
        "The move is committed. Fix the cause and rerun before the daemon starts: {command}"
    ));
    outcome.code = exit_codes::FAILURE;
}

#[cfg(test)]
pub(crate) mod tests;
