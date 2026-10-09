//! `config relocate` on temporary trees: the legacy root is
//! `<base>/var/lib/purge-warden`, the new root `<base>/etc/purge-warden`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::*;
use crate::config::loader::LoadedConfigV5;
use crate::config::policy_revision::{PolicyRevisionInventory, PolicyRevisionMember};
use crate::config::policy_transaction::{
    BaseReceipt, Persistence, ReceiptStore, TransactionRequest,
};

const FORWARD: Options = Options {
    dry_run: false,
    reverse: false,
};
const REVERSE: Options = Options {
    dry_run: false,
    reverse: true,
};
const DRY_FORWARD: Options = Options {
    dry_run: true,
    reverse: false,
};
const DRY_REVERSE: Options = Options {
    dry_run: true,
    reverse: true,
};
const LEASE: &str = ".purge-warden-runtime.lock";
const CAPABILITY: &str = ".purge-warden-runtime-capability.json";
/// Stores whose records the rebind rewrites in place, so their files get new
/// inodes while their bytes return to the original after a round trip.
const REBOUND: [&str; 3] = [
    ".warden-policy-receipts",
    ".warden-policy-transactions",
    ".warden-cluster-ownership",
];

/// Run `body` with an injected stop.
fn with_stop<T>(stop: Stop, body: impl FnOnce() -> T) -> T {
    STOP.set(Some(stop));
    let result = body();
    STOP.set(None);
    result
}

/// A layout below `base` shaped like the system one. The mapping makes
/// `<base>/var/lib/purge-warden` the state directory of `<base>/etc/purge-warden`.
pub(crate) fn layout_for_test(base: &Path) -> (Layout, state_dir::TestMapping) {
    let legacy = base.join("var/lib/purge-warden");
    let etc = base.join("etc/purge-warden");
    fs::create_dir_all(&legacy).unwrap();
    fs::set_permissions(&legacy, Permissions::from_mode(0o750)).unwrap();
    for directory in ["etc", "run", "bin"] {
        fs::create_dir_all(base.join(directory)).unwrap();
    }
    let mapping = state_dir::map_for_test(&etc, &legacy);
    // SAFETY: geteuid and getegid have no preconditions.
    let owner = unsafe { (libc::geteuid(), libc::getegid()) };
    let layout = Layout {
        legacy,
        etc,
        pid_file: base.join("run/purge-warden/purge-warden.pid"),
        receipt_owner: owner,
        min_free_bytes: 0,
        search_path: base.join("bin").into_os_string(),
    };
    (layout, mapping)
}

fn master_text(includes: &[&str], backup: Option<&str>) -> String {
    let includes = includes
        .iter()
        .map(|include| format!("{include:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let backup = match backup {
        Some(dir) => format!("[backup]\ndir = {dir:?}\n\n"),
        None => String::new(),
    };
    format!(
        "schema_version = 5\nincludes = [{includes}]\n\n{backup}[upstream]\nservers = [\"192.0.2.53:53\"]\n\n[[blocklists]]\nid = \"local-allow\"\ndisplay_name = \"Local allow\"\nurl = \"https://imported.local/local-allow.txt\"\nbase = \"allow\"\ntrust = \"local\"\n\n[[custom_lists]]\nid = \"streaming\"\ndisplay_name = \"Streaming\"\n\n[profiles.home]\ndisplay_name = \"Home\"\ncustom_lists = [\"streaming\"]\n"
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    base: PathBuf,
    layout: Layout,
    _mapping: state_dir::TestMapping,
}

impl Fixture {
    /// The legacy root exists and is empty; `/etc/purge-warden` is absent.
    fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let (layout, mapping) = layout_for_test(&base);
        Self {
            _dir: dir,
            base,
            layout,
            _mapping: mapping,
        }
    }

    /// A node installed before the split, with an attested runtime
    /// capability, a committed policy receipt and its retained transaction.
    fn new() -> Self {
        Self::with_master(|legacy| {
            master_text(
                &["conf.d/*.toml", "empty.d/*.toml"],
                Some(&legacy.join("backups").display().to_string()),
            )
        })
    }

    fn with_master(master: impl FnOnce(&Path) -> String) -> Self {
        let fixture = Self::empty();
        let legacy = &fixture.layout.legacy;
        let write = |relative: &str, bytes: &str, mode: u32| {
            let path = legacy.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        };
        write(MASTER, &master(legacy), 0o640);
        write("packs/streaming.txt", "||ads.example^\n", 0o640);
        write(
            "conf.d/kids.toml",
            "[profiles.kids]\ndisplay_name = \"Kids\"\n",
            0o640,
        );
        write("lists/local-allow.txt", "allowed.example\n", 0o640);
        write("lists/cache-entry.bin", "cached list\n", 0o640);
        write("secrets.toml", "# no secrets\n", 0o600);
        write("logs/warden.log", "started\n", 0o640);
        fs::create_dir(legacy.join("empty.d")).unwrap();
        fs::create_dir(legacy.join("cluster.d")).unwrap();
        let master = fixture.legacy_master();
        let lease = runtime_lease::acquire_for_daemon(&master).unwrap();
        lease.attest_schema5_runtime(5).unwrap();
        drop(lease);
        apply_policy(&master, "request-1");
        #[cfg(feature = "cluster")]
        {
            let guard = write_lock::acquire_for_migration(&master).unwrap();
            let root = guard.tree_io().root.metadata().unwrap();
            crate::private_store::PrivateStore::open(&guard, crate::cluster::ledger::STORE_DIR)
                .unwrap()
                .write(
                    "state.json",
                    format!(
                        "{{\"format\":1,\"root_device\":{},\"root_inode\":{},\"ledger\":null,\"pending\":null}}",
                        root.dev(),
                        root.ino()
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        fixture
    }

    fn legacy_master(&self) -> PathBuf {
        self.layout.legacy.join(MASTER)
    }

    fn etc_master(&self) -> PathBuf {
        self.layout.etc.join(MASTER)
    }

    fn run(&self, options: Options) -> Outcome {
        relocate(&self.layout, options).unwrap()
    }

    /// Every entry below the base except the PID directory and the lease
    /// file, whose content a daemon start rewrites.
    fn tree(&self) -> BTreeMap<PathBuf, Entry> {
        let mut tree = manifest(&self.base, false);
        tree.retain(|path, _| {
            !path.starts_with("run") && path.file_name() != Some(OsStr::new(LEASE))
        });
        tree
    }

    /// The step lines of a dry run, in receipt order.
    fn steps(&self, options: Options) -> Vec<String> {
        let dry = self.run(Options {
            dry_run: true,
            ..options
        });
        assert_eq!(dry.code, 0, "{dry:?}");
        dry.out
            .into_iter()
            .filter(|line| line.starts_with("step "))
            .collect()
    }

    fn write_restorecon(&self, body: &str) {
        let path = self.base.join("bin/restorecon");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    digest: Option<String>,
    mtime: Option<(i64, i64)>,
}

fn manifest(root: &Path, mtimes: bool) -> BTreeMap<PathBuf, Entry> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
        }
        let digest = meta
            .is_file()
            .then(|| hex::encode(Sha256::digest(fs::read(&path).unwrap())));
        entries.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            Entry {
                device: meta.dev(),
                inode: meta.ino(),
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode(),
                digest,
                mtime: mtimes.then(|| (meta.mtime(), meta.mtime_nsec())),
            },
        );
    }
    entries
}

/// Forget the inodes of rebound store records and of their directories.
fn without_rebound(mut tree: BTreeMap<PathBuf, Entry>) -> BTreeMap<PathBuf, Entry> {
    for (path, entry) in &mut tree {
        if path
            .components()
            .any(|part| REBOUND.iter().any(|store| part.as_os_str() == *store))
            && entry.digest.is_some()
        {
            entry.inode = 0;
        }
    }
    tree
}

fn identity(path: &Path) -> (u64, u64) {
    let meta =
        fs::symlink_metadata(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    (meta.dev(), meta.ino())
}

fn refused(outcome: &Outcome, slug: &str) -> bool {
    let prefix = format!("refused ({slug})");
    outcome.err.iter().any(|line| line.starts_with(&prefix))
}

fn load(guard: &MigrationWriteLock, master: &Path) -> LoadedConfigV5 {
    match loader::load_config_v5_for_repair_under_migration_guard(
        guard,
        master,
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(loaded) => loaded,
        Err(EditorGuardedLoadFailure::Diagnostics(errors)) => panic!(
            "{}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Err(EditorGuardedLoadFailure::Operational(error)) => panic!("{error:#}"),
    }
}

/// Commit one policy transaction that appends a comment to the master.
fn apply_policy(master: &Path, request_id: &str) -> BaseReceipt {
    let guard = write_lock::acquire_for_migration(master).unwrap();
    let loaded = load(&guard, master);
    let (snapshot, _) = policy_revision::capture_coherent_loaded_v5_under_migration_guard(
        &guard,
        &loaded,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let before = snapshot.inventory().clone();
    let after = PolicyRevisionInventory::new(
        before
            .members()
            .iter()
            .map(|member| match member.state() {
                PolicyMemberState::Present(bytes) if member.kind() == PolicyMemberKind::Master => {
                    let mut bytes = bytes.clone();
                    bytes.extend_from_slice(format!("# {request_id}\n").as_bytes());
                    PolicyRevisionMember::present(
                        PolicyMemberKind::Master,
                        member.path().to_path_buf(),
                        bytes,
                    )
                    .unwrap()
                }
                _ => member.clone(),
            })
            .collect(),
    )
    .unwrap();
    let receipts =
        ReceiptStore::open(&state_dir::open_for_migration(&guard).unwrap(), &guard).unwrap();
    let request = TransactionRequest {
        request_id: request_id.into(),
        actor: "operator-1".into(),
        origin: "cli".into(),
        operation: "import".into(),
        payload: request_id.as_bytes().to_vec(),
        expected_revision: before.revision(),
        source_schema: 5,
        target_schema: 5,
    };
    let receipt =
        policy_transaction::apply(&guard, &receipts, &request, &before, &after, || Ok(())).unwrap();
    assert_eq!(receipt.persistence, Persistence::Committed);
    receipt
}

fn committed(master: &Path, request_id: &str) -> bool {
    let guard = write_lock::acquire_for_migration(master).unwrap();
    let receipts =
        ReceiptStore::open(&state_dir::open_for_migration(&guard).unwrap(), &guard).unwrap();
    policy_transaction::lookup_receipt(&guard, &receipts, "operator-1", request_id)
        .unwrap()
        .is_some_and(|receipt| receipt.persistence == Persistence::Committed)
}

/// Normal access after a run: stored receipts resolve, a new transaction
/// commits, the daemon lease is granted and the ownership ledger opens.
fn assert_usable(master: &Path, request_id: &str) {
    assert!(committed(master, "request-1"));
    apply_policy(master, request_id);
    assert!(committed(master, request_id));
    drop(runtime_lease::acquire_for_daemon(master).unwrap());
    #[cfg(feature = "cluster")]
    {
        let guard = write_lock::acquire_for_migration(master).unwrap();
        crate::cluster::ledger::OwnershipStore::open(&guard).unwrap();
    }
}

#[test]
fn invoker_must_be_root_without_explicit_config() {
    assert_eq!(invoker_refusal(true, 0).unwrap().slug, "explicit-config");
    assert_eq!(invoker_refusal(false, 1000).unwrap().slug, "not-root");
    assert!(invoker_refusal(false, 0).is_none());
}

#[test]
fn forward_and_reverse_keep_bytes_inodes_and_owners() {
    let fixture = Fixture::new();
    let (legacy, etc) = (&fixture.layout.legacy, &fixture.layout.etc);
    let mut before = fixture.tree();
    before.remove(&legacy.strip_prefix(&fixture.base).unwrap().join(CAPABILITY));
    let moved = [
        MASTER,
        "packs",
        "packs/streaming.txt",
        "conf.d",
        "conf.d/kids.toml",
        "empty.d",
        "cluster.d",
        "secrets.toml",
        policy_transaction::STORE_DIR_NAME,
    ];
    let identities: Vec<_> = moved
        .iter()
        .map(|name| identity(&legacy.join(name)))
        .collect();
    let body = identity(&legacy.join("lists/local-allow.txt"));
    let receipts = identity(&legacy.join(policy_transaction::RECEIPT_DIR).join(
        policy_transaction::master_namespace(&fixture.legacy_master()),
    ));

    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
    for (name, moved_identity) in moved.iter().zip(&identities) {
        assert_eq!(identity(&etc.join(name)), *moved_identity, "{name}");
        assert!(fs::symlink_metadata(legacy.join(name)).is_err(), "{name}");
    }
    assert_eq!(identity(&etc.join("lists/local-allow.txt")), body);
    assert!(legacy.join("lists/cache-entry.bin").is_file());
    assert!(legacy.join("logs/warden.log").is_file());
    assert_eq!(
        identity(
            &legacy
                .join(policy_transaction::RECEIPT_DIR)
                .join(policy_transaction::master_namespace(&fixture.etc_master()))
        ),
        receipts
    );
    let etc_meta = fs::metadata(etc).unwrap();
    let legacy_meta = fs::metadata(legacy).unwrap();
    assert_eq!(etc_meta.mode() & 0o7777, 0o750);
    assert_eq!(
        (etc_meta.uid(), etc_meta.gid()),
        (legacy_meta.uid(), legacy_meta.gid())
    );
    assert!(!legacy.join(ACTIVE).exists());
    assert!(legacy.join(DONE).is_file());
    assert!(!legacy.join(CAPABILITY).exists());
    assert!(forward
        .out
        .iter()
        .any(|line| line.contains("restorecon is not installed")));

    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    assert!(!etc.exists(), "{reverse:?}");
    let mut after = fixture.tree();
    after.remove(&legacy.strip_prefix(&fixture.base).unwrap().join(DONE));
    assert_eq!(without_rebound(after), without_rebound(before));
}

#[test]
fn moved_tree_stays_usable_in_both_directions() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    assert_attests_after_one_start(&fixture, &fixture.etc_master());
    assert_usable(&fixture.etc_master(), "request-2");

    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    assert_attests_after_one_start(&fixture, &fixture.legacy_master());
    assert_usable(&fixture.legacy_master(), "request-3");
}

/// A run deletes the runtime capability, so a migration lock is in bootstrap
/// mode until the first normal start attests the moved master again.
fn assert_attests_after_one_start(fixture: &Fixture, master: &Path) {
    let capability = fixture.layout.legacy.join(CAPABILITY);
    assert!(!capability.exists());
    let pid_file = &fixture.layout.pid_file;
    let migration = runtime_lease::acquire_for_migration(master, pid_file).unwrap();
    assert!(migration.requires_migration_bootstrap());
    drop(migration);
    let lease = runtime_lease::acquire_for_daemon(master).unwrap();
    lease.attest_schema5_runtime(5).unwrap();
    drop(lease);
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&capability).unwrap()).unwrap();
    assert_eq!(recorded["canonical_master"], master.display().to_string());
    let migration = runtime_lease::acquire_for_migration(master, pid_file).unwrap();
    assert!(!migration.requires_migration_bootstrap());
}

#[test]
fn dry_run_writes_nothing() {
    let fixture = Fixture::new();
    let before = manifest(&fixture.base, true);
    let dry = fixture.run(DRY_FORWARD);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert_eq!(
        dry.out.last().unwrap(),
        "dry run: every check passed and nothing was moved"
    );
    assert_eq!(manifest(&fixture.base, true), before);

    assert_eq!(fixture.run(FORWARD).code, 0);
    let before = manifest(&fixture.base, true);
    let dry = fixture.run(DRY_REVERSE);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert_eq!(manifest(&fixture.base, true), before);
}

#[test]
fn dry_run_creates_at_most_the_source_write_lock() {
    let fixture = Fixture::new();
    let lock = fixture.layout.legacy.join(WRITE_LOCK_FILE);
    fs::remove_file(&lock).unwrap();
    let before = manifest(&fixture.base, true);
    assert_eq!(fixture.run(DRY_FORWARD).code, 0);
    let after = manifest(&fixture.base, true);
    let legacy = fixture.layout.legacy.strip_prefix(&fixture.base).unwrap();
    let changed: Vec<_> = after
        .iter()
        .filter(|(path, entry)| before.get(*path) != Some(entry))
        .map(|(path, _)| path.clone())
        .collect();
    assert!(before.keys().all(|path| after.contains_key(path)));
    assert!(
        changed
            .iter()
            .all(|path| path == legacy || *path == legacy.join(WRITE_LOCK_FILE)),
        "{changed:?}"
    );
}

#[test]
fn dry_run_reports_every_refusal() {
    let fixture = Fixture::new();
    fs::write(fixture.layout.legacy.join(".warden-unknown"), "x").unwrap();
    let mut layout = layout_clone(&fixture.layout);
    layout.min_free_bytes = u64::MAX;
    let before = fixture.tree();
    let dry = relocate(&layout, DRY_FORWARD).unwrap();
    assert_eq!(dry.code, exit_codes::FAILURE, "{dry:?}");
    assert!(refused(&dry, "unknown-entry") && refused(&dry, "low-space"));
    assert_eq!(
        dry.err.last().unwrap(),
        "dry run: a real run would refuse; nothing was moved"
    );
    let real = relocate(&layout, FORWARD).unwrap();
    assert!(refused(&real, "unknown-entry") && refused(&real, "low-space"));
    assert_eq!(fixture.tree(), before);
}

fn layout_clone(layout: &Layout) -> Layout {
    Layout {
        legacy: layout.legacy.clone(),
        etc: layout.etc.clone(),
        pid_file: layout.pid_file.clone(),
        receipt_owner: layout.receipt_owner,
        min_free_bytes: layout.min_free_bytes,
        search_path: layout.search_path.clone(),
    }
}

/// Run `options` on a fixture, expect the refusal `slug` and an unchanged tree.
fn assert_refused(fixture: &Fixture, options: Options, slug: &str) -> Outcome {
    let before = fixture.tree();
    let outcome = fixture.run(options);
    assert_ne!(outcome.code, 0, "{outcome:?}");
    assert!(refused(&outcome, slug), "{slug}: {outcome:?}");
    assert_eq!(fixture.tree(), before, "{slug}");
    assert!(!fixture.layout.legacy.join(ACTIVE).exists());
    outcome
}

#[test]
fn refuses_a_symlinked_root() {
    let fixture = Fixture::empty();
    let real = fixture.base.join("real");
    fs::rename(&fixture.layout.legacy, &real).unwrap();
    fs::write(real.join(MASTER), "schema_version = 5\n").unwrap();
    std::os::unix::fs::symlink(&real, &fixture.layout.legacy).unwrap();
    assert_refused(&fixture, FORWARD, "not-fixed-path");
}

#[test]
fn refuses_while_the_daemon_holds_a_lease() {
    let fixture = Fixture::new();
    let lease = runtime_lease::acquire_for_daemon(&fixture.legacy_master()).unwrap();
    assert_refused(&fixture, FORWARD, "daemon-running");
    assert_refused(&fixture, DRY_FORWARD, "daemon-running");
    drop(lease);
    let pid = crate::cli::commands::pid::acquire_offline_pid_lease(&fixture.layout.pid_file, None)
        .unwrap();
    assert_refused(&fixture, FORWARD, "daemon-running");
    drop(pid);
    // A lease file that fails its own checks is not a running daemon.
    fs::set_permissions(
        fixture.layout.legacy.join(LEASE),
        Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_refused(&fixture, DRY_FORWARD, "lease");
}

/// A group other than the effective one that this process may give to a
/// file it owns.
fn other_gid() -> Option<u32> {
    // SAFETY: these calls have no preconditions; the buffer holds `count` groups.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if euid == 0 {
        return Some(if egid == 0 { 1 } else { 0 });
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; usize::try_from(count).ok()?];
    let read = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    groups.truncate(usize::try_from(read).ok()?);
    groups.into_iter().find(|gid| *gid != egid)
}

#[test]
fn owner_refusals_come_before_the_lease_and_lock_checks() {
    let Some(gid) = other_gid() else {
        eprintln!("SKIPPED owner refusal order: no second group is available");
        return;
    };
    let fixture = Fixture::new();
    // The write lock keeps the owner of the root.
    std::os::unix::fs::lchown(fixture.legacy_master(), None, Some(gid)).unwrap();
    assert_refused(&fixture, DRY_FORWARD, "master-owner");
    assert_refused(&fixture, FORWARD, "master-owner");
    let own_gid = fixture.layout.receipt_owner.1;
    std::os::unix::fs::lchown(fixture.legacy_master(), None, Some(own_gid)).unwrap();
    assert_eq!(fixture.run(FORWARD).code, 0);
    // The runtime lease keeps the owner of its state directory.
    std::os::unix::fs::lchown(&fixture.layout.legacy, None, Some(gid)).unwrap();
    assert_refused(&fixture, DRY_REVERSE, "target-owner");
    assert_refused(&fixture, REVERSE, "target-owner");
}

#[test]
fn refuses_a_busy_target_tree() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.layout.etc).unwrap();
    fs::set_permissions(&fixture.layout.etc, Permissions::from_mode(0o750)).unwrap();
    let probe = write_lock::probe_for_relocate(&fixture.etc_master())
        .unwrap()
        .unwrap();
    assert_refused(&fixture, FORWARD, "tree-busy");
    drop(probe);
}

#[test]
fn refuses_a_missing_or_irregular_master() {
    let fixture = Fixture::empty();
    assert_refused(&fixture, FORWARD, "master-missing");
    fs::create_dir(fixture.legacy_master()).unwrap();
    assert_refused(&fixture, FORWARD, "master-not-regular");
}

#[test]
fn refuses_an_occupied_target() {
    let fixture = Fixture::new();
    let etc = &fixture.layout.etc;
    fs::create_dir(etc).unwrap();
    fs::set_permissions(etc, Permissions::from_mode(0o750)).unwrap();
    fs::write(etc.join("stray"), "x").unwrap();
    assert_refused(&fixture, FORWARD, "target-occupied");
    fs::remove_file(etc.join("stray")).unwrap();
    fs::write(etc.join(MASTER), "x").unwrap();
    assert_refused(&fixture, FORWARD, "target-occupied");
    fs::remove_file(etc.join(MASTER)).unwrap();
    fs::remove_dir(etc).unwrap();
    fs::write(etc, "x").unwrap();
    assert_refused(&fixture, FORWARD, "target-occupied");
    fs::remove_file(etc).unwrap();
    std::os::unix::fs::symlink(fixture.base.join("bin"), etc).unwrap();
    assert_refused(&fixture, FORWARD, "not-fixed-path");
}

#[test]
fn refuses_a_target_root_with_another_mode() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.layout.etc).unwrap();
    fs::set_permissions(&fixture.layout.etc, Permissions::from_mode(0o755)).unwrap();
    let outcome = assert_refused(&fixture, FORWARD, "target-root");
    assert!(outcome.err[0].contains("then rmdir"), "{outcome:?}");
}

#[test]
fn reverse_refuses_without_a_forward_run_or_with_a_legacy_master() {
    let fixture = Fixture::new();
    assert_refused(&fixture, REVERSE, "receipt");
    assert_eq!(fixture.run(FORWARD).code, 0);
    fs::write(fixture.legacy_master(), "x").unwrap();
    assert_refused(&fixture, REVERSE, "target-occupied");
}

#[test]
fn refuses_an_active_schema_migration() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.layout.legacy.join(migration_journal::TXN_DIR_NAME)).unwrap();
    assert_refused(&fixture, FORWARD, "migration-active");
}

#[test]
fn refuses_an_unknown_warden_entry() {
    let fixture = Fixture::new();
    fs::write(fixture.layout.legacy.join(".warden-unknown"), "x").unwrap();
    assert_refused(&fixture, FORWARD, "unknown-entry");
}

#[test]
fn refuses_a_master_that_does_not_load() {
    let fixture = Fixture::empty();
    fs::write(
        fixture.legacy_master(),
        "schema_version = 5\n[upstream]\nservers = 5\n",
    )
    .unwrap();
    drop(write_lock::acquire_for_relocate(&fixture.legacy_master()).unwrap());
    let outcome = assert_refused(&fixture, FORWARD, "load-failed");
    assert_eq!(outcome.code, exit_codes::CONFIG);
}

#[test]
fn a_reverse_dry_run_of_a_master_that_does_not_load_has_the_config_code() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    fs::write(fixture.etc_master(), "schema_version = 4\n").unwrap();
    let outcome = assert_refused(&fixture, DRY_REVERSE, "load-failed");
    assert_eq!(outcome.code, exit_codes::CONFIG);
}

#[test]
fn a_forward_run_after_a_complete_one_says_the_set_already_moved() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    assert_refused(&fixture, DRY_FORWARD, "already-moved");
    assert_refused(&fixture, FORWARD, "already-moved");
}

#[test]
fn refuses_a_backup_dir_that_is_not_absolute() {
    let fixture = Fixture::with_master(|_| master_text(&[], None));
    assert_refused(&fixture, FORWARD, "backup-dir");
    let fixture = Fixture::with_master(|_| master_text(&[], Some("backups")));
    assert_refused(&fixture, FORWARD, "backup-dir");
}

#[test]
fn refuses_entries_that_are_not_plain() {
    // The loader already refuses members with links or of another type.
    let fixture = Fixture::new();
    let legacy = &fixture.layout.legacy;
    fs::rename(
        legacy.join("secrets.toml"),
        legacy.join("logs/secrets.toml"),
    )
    .unwrap();
    std::os::unix::fs::symlink("logs/secrets.toml", legacy.join("secrets.toml")).unwrap();
    assert_refused(&fixture, FORWARD, "member-not-plain");

    let fixture = Fixture::new();
    let body = fixture.layout.legacy.join("lists/local-allow.txt");
    fs::remove_file(&body).unwrap();
    fs::create_dir(&body).unwrap();
    assert_refused(&fixture, FORWARD, "member-not-plain");
}

#[test]
fn refuses_members_under_a_state_name() {
    let fixture = Fixture::with_master(|legacy| {
        master_text(
            &["data/*.toml"],
            Some(&legacy.join("backups").display().to_string()),
        )
    });
    let data = fixture.layout.legacy.join("data");
    fs::create_dir(&data).unwrap();
    fs::write(
        data.join("extra.toml"),
        "[profiles.extra]\ndisplay_name = \"Extra\"\n",
    )
    .unwrap();
    assert_refused(&fixture, FORWARD, "state-name");
}

#[test]
fn refuses_a_taken_store_namespace() {
    let fixture = Fixture::new();
    fs::create_dir(
        fixture
            .layout
            .legacy
            .join(policy_transaction::RECEIPT_DIR)
            .join(policy_transaction::master_namespace(&fixture.etc_master())),
    )
    .unwrap();
    assert_refused(&fixture, FORWARD, "name-taken");
}

#[cfg(not(feature = "cluster"))]
#[test]
fn refuses_cluster_stores_without_cluster_support() {
    let fixture = Fixture::new();
    fs::create_dir_all(
        fixture
            .layout
            .legacy
            .join(".warden-cluster-peers")
            .join(plain_namespace(&fixture.legacy_master())),
    )
    .unwrap();
    assert_refused(&fixture, FORWARD, "cluster-store");
}

#[test]
fn refuses_an_unsettled_policy_receipt() {
    let fixture = Fixture::new();
    let directory = fixture
        .layout
        .legacy
        .join(policy_transaction::RECEIPT_DIR)
        .join(policy_transaction::master_namespace(
            &fixture.legacy_master(),
        ));
    let record = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("json")))
        .unwrap();
    let original = fs::read(&record).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&original).unwrap();
    json["receipt"]["persistence"] = "prepared".into();
    fs::write(&record, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_refused(&fixture, FORWARD, "recovery-required");
    fs::write(&record, original).unwrap();
    assert_eq!(fixture.run(FORWARD).code, 0);
}

#[cfg(feature = "cluster")]
#[test]
fn a_pending_publication_intent_refuses_until_it_is_aborted() {
    use crate::cluster::publication::{PublicationCandidate, PublicationStore};
    let fixture = Fixture::new();
    let sha = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let reservation = {
        let guard = write_lock::acquire_for_migration(&fixture.legacy_master()).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        store
            .reserve_bound(|lineage, epoch| {
                let value = b"published policy";
                let manifest = serde_json::to_vec(&(lineage, epoch, sha(value))).unwrap();
                let candidate = PublicationCandidate {
                    artifact_hash: sha(&manifest),
                    config_revision: sha(value),
                    manifest,
                    objects: BTreeMap::from([(sha(value), std::sync::Arc::from(&value[..]))]),
                };
                let envelope = serde_json::json!({
                    "actor": "operator-1",
                    "request_id": "publish-1",
                    "primary_lineage": lineage,
                    "policy_epoch": epoch,
                    "artifact_hash": candidate.artifact_hash,
                    "expected_after_revision": candidate.config_revision,
                });
                Ok((
                    candidate,
                    envelope,
                    serde_json::json!({"before": "captured"}),
                ))
            })
            .unwrap()
    };
    let outcome = assert_refused(&fixture, FORWARD, "recovery-required");
    assert!(
        outcome
            .err
            .iter()
            .any(|line| line.contains(".warden-cluster-publications")),
        "{outcome:?}"
    );
    // Uncommitted records that still carry a preparation proof, read raw.
    let proofs = |master: &Path| {
        let guard = write_lock::acquire_for_migration(master).unwrap();
        let files = crate::private_store::PrivateStore::open_existing(
            &guard,
            crate::cluster::publication::STORE_DIR,
        )
        .unwrap()
        .unwrap();
        let state: serde_json::Value =
            serde_json::from_slice(&files.read("state.json", 16 << 20).unwrap().unwrap()).unwrap();
        state["records"]
            .as_object()
            .unwrap()
            .values()
            .filter(|record| {
                record["committed"].is_null() && !record["preparation_proof"].is_null()
            })
            .count()
    };
    assert_eq!(proofs(&fixture.legacy_master()), 1);
    {
        let guard = write_lock::acquire_for_migration(&fixture.legacy_master()).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store.preparation_proof(&reservation).unwrap().is_some());
        store.abort(&reservation).unwrap();
    }
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
    {
        let guard = write_lock::acquire_for_migration(&fixture.etc_master()).unwrap();
        let receipts =
            ReceiptStore::open(&state_dir::open_for_migration(&guard).unwrap(), &guard).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        crate::cluster::publisher::recover(&guard, &receipts, &mut store).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        assert!(store.preparation_proof(&reservation).is_err());
    }
    assert_eq!(proofs(&fixture.etc_master()), 0);
}

#[cfg(feature = "cluster")]
#[test]
fn an_open_lifecycle_preview_refuses_with_its_apply_and_cancel_commands() {
    let fixture = Fixture::new();
    let id = "0b6f1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4";
    let lifecycle = |body: &dyn Fn(&crate::private_store::PrivateStore<'_>)| {
        let guard = write_lock::acquire_for_migration(&fixture.legacy_master()).unwrap();
        body(&crate::private_store::PrivateStore::open(&guard, ".warden-node-lifecycle").unwrap());
    };
    lifecycle(&|files| {
        let marker = format!("{{\"preview_id\":\"{id}\",\"expires_at\":1}}");
        files.write("pending.lockdata", marker.as_bytes()).unwrap();
    });
    let outcome = assert_refused(&fixture, FORWARD, "recovery-required");
    assert!(
        outcome.err[0].contains("lifecycle marker pending.lockdata exists"),
        "{outcome:?}"
    );
    lifecycle(&|files| files.write(&format!("{id}.json"), b"{}").unwrap());
    let outcome = assert_refused(&fixture, FORWARD, "recovery-required");
    assert!(
        outcome.err[0].contains(&format!("`warden cluster cancel --preview-id {id}`")),
        "{outcome:?}"
    );
    lifecycle(&|files| {
        files.remove(&format!("{id}.json")).unwrap();
        files.remove("pending.lockdata").unwrap();
    });
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
}

#[test]
fn an_unsettled_tui_journal_refuses_until_it_is_empty() {
    let fixture = Fixture::new();
    let journal = |state: &str| {
        let guard = write_lock::acquire_for_migration(&fixture.legacy_master()).unwrap();
        crate::private_store::PrivateStore::open(&guard, ".warden-tui-uor")
            .unwrap()
            .write(
                "recovery.json",
                format!("{{\"format\":1,\"state\":{state}}}").as_bytes(),
            )
            .unwrap();
    };
    journal(
        r#"{"phase":"property_pending","origin":{"origin":"recovery"},"operations":[],"prefix":{"profile_id":"home","patch":{}}}"#,
    );
    let outcome = assert_refused(&fixture, FORWARD, "recovery-required");
    assert!(
        outcome.err[0].contains("journal is not empty") && outcome.err[0].contains("`warden tui`"),
        "{outcome:?}"
    );
    journal(r#"{"phase":"empty"}"#);
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
}

#[test]
fn refuses_a_rename_directory_on_another_mount() {
    let fixture = Fixture::new();
    OTHER_MOUNT.set(Some(fixture.base.join("etc")));
    let outcome = assert_refused(&fixture, FORWARD, "other-filesystem");
    OTHER_MOUNT.set(None);
    assert!(
        outcome.err[0].contains("/etc is on another filesystem"),
        "{outcome:?}"
    );
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
}

#[test]
fn a_stop_after_any_forward_step_rolls_back_to_the_original_tree() {
    let steps = Fixture::new().steps(FORWARD);
    assert!(steps.len() > 10, "{steps:?}");
    for (index, step) in steps.iter().enumerate() {
        for stop in [Stop::AfterAction(index), Stop::AfterReceipt(index)] {
            let fixture = Fixture::new();
            let capability = fixture
                .layout
                .legacy
                .strip_prefix(&fixture.base)
                .unwrap()
                .join(CAPABILITY);
            let mut before = without_rebound(fixture.tree());
            before.remove(&capability);
            let stopped = with_stop(stop, || fixture.run(FORWARD));
            assert_eq!(stopped.code, exit_codes::FAILURE, "{stop:?} {stopped:?}");
            assert!(
                stopped.err[1].ends_with("config relocate --reverse"),
                "{stopped:?}"
            );
            let fenced = runtime_lease::acquire_for_daemon(&fixture.legacy_master()).unwrap_err();
            assert!(format!("{fenced:#}").contains("RelocateInProgress"));

            let undo = fixture.run(REVERSE);
            assert_eq!(undo.code, 0, "{stop:?} {step} {undo:?}");
            let mut after = without_rebound(fixture.tree());
            after.remove(&capability);
            assert_eq!(after, before, "{stop:?} {step}");
            assert_refused(&fixture, REVERSE, "receipt");
        }
    }
}

#[test]
fn a_stop_after_any_reverse_step_rolls_back_to_the_moved_tree() {
    let probe = Fixture::new();
    assert_eq!(probe.run(FORWARD).code, 0);
    let steps = probe.steps(REVERSE);
    for (index, step) in steps.iter().enumerate() {
        for stop in [Stop::AfterAction(index), Stop::AfterReceipt(index)] {
            let fixture = Fixture::new();
            assert_eq!(fixture.run(FORWARD).code, 0);
            let before = without_rebound(fixture.tree());
            let stopped = with_stop(stop, || fixture.run(REVERSE));
            assert_eq!(stopped.code, exit_codes::FAILURE, "{stop:?} {stopped:?}");
            assert!(stopped.err[1].ends_with("config relocate"), "{stopped:?}");
            let undo = fixture.run(FORWARD);
            assert_eq!(undo.code, 0, "{stop:?} {step} {undo:?}");
            assert_eq!(without_rebound(fixture.tree()), before, "{stop:?} {step}");
        }
    }
}

#[test]
fn a_cross_device_rename_stops_and_rolls_back() {
    let steps = Fixture::new().steps(FORWARD);
    let transactions = steps
        .iter()
        .position(|line| {
            line.starts_with("step 4: rename")
                && line.ends_with(&format!(
                    "/etc/purge-warden/{}",
                    policy_transaction::STORE_DIR_NAME
                ))
        })
        .unwrap();
    let top = steps
        .iter()
        .position(|line| line.starts_with("step 6: rename"))
        .unwrap();
    for index in [transactions, top] {
        let fixture = Fixture::new();
        let before = without_rebound(fixture.tree());
        let stopped = with_stop(Stop::Exdev(index), || fixture.run(FORWARD));
        assert_eq!(stopped.code, exit_codes::FAILURE);
        assert!(stopped.err[0].contains("cross-device"), "{stopped:?}");
        let undo = fixture.run(REVERSE);
        assert_eq!(undo.code, 0, "{undo:?}");
        assert_eq!(without_rebound(fixture.tree()), before);
    }
}

#[test]
fn a_stop_before_retire_is_finished_by_the_next_run() {
    let fixture = Fixture::new();
    let stopped = with_stop(Stop::BeforeRetire, || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE, "{stopped:?}");
    let before = fixture.tree();
    let dry = fixture.run(DRY_REVERSE);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(dry.out[0].contains("stopped while it committed"), "{dry:?}");
    assert_eq!(fixture.tree(), before);
    let finished = fixture.run(REVERSE);
    assert_eq!(finished.code, 0, "{finished:?}");
    assert!(finished.out[0].starts_with("finished the commit of the forward run"));
    assert!(!fixture.layout.legacy.join(ACTIVE).exists());
    assert!(fixture.layout.legacy.join(DONE).is_file());
    assert!(fixture.etc_master().is_file());
    assert_usable(&fixture.etc_master(), "request-2");
}

#[test]
fn an_incomplete_run_refuses_a_rerun_in_its_own_direction() {
    let fixture = Fixture::new();
    let stopped = with_stop(Stop::AfterReceipt(4), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    let before = fixture.tree();
    let again = fixture.run(FORWARD);
    assert!(refused(&again, "receipt"), "{again:?}");
    assert!(again
        .err
        .last()
        .unwrap()
        .ends_with("config relocate --reverse"));
    assert_eq!(fixture.tree(), before);
    let dry = fixture.run(DRY_REVERSE);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(dry.out[0].starts_with("dry run: the rollback would undo"));
    assert_eq!(fixture.tree(), before);
}

#[test]
fn a_rollback_refuses_a_tree_that_does_not_match_the_receipt() {
    let steps = Fixture::new().steps(FORWARD);
    let packs = steps
        .iter()
        .position(|line| line.starts_with("step 6: rename") && line.ends_with("/packs"))
        .unwrap();
    let fixture = Fixture::new();
    let stopped = with_stop(Stop::AfterReceipt(packs), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    let moved = fixture.base.join("moved-packs");
    fs::rename(fixture.layout.etc.join("packs"), &moved).unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(outcome.err[0].contains("neither at its source nor at its target"));
    fs::rename(&moved, fixture.layout.etc.join("packs")).unwrap();

    fs::rename(fixture.legacy_master(), fixture.etc_master()).unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(
        outcome.err[0].contains("already at its target"),
        "{outcome:?}"
    );
}

/// A refused rollback keeps the fence and the tree.
fn assert_refused_fenced(fixture: &Fixture, options: Options) -> Outcome {
    let before = fixture.tree();
    let outcome = fixture.run(options);
    assert!(refused(&outcome, "receipt"), "{outcome:?}");
    assert!(fixture.layout.legacy.join(ACTIVE).exists());
    assert_eq!(fixture.tree(), before);
    outcome
}

#[test]
fn an_unchecked_or_foreign_receipt_needs_manual_recovery() {
    let fixture = Fixture::new();
    assert_eq!(
        with_stop(Stop::AfterReceipt(3), || fixture.run(FORWARD)).code,
        exit_codes::FAILURE
    );
    let active = fixture.layout.legacy.join(ACTIVE);
    fs::set_permissions(&active, Permissions::from_mode(0o644)).unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(
        outcome.err[0].contains("mode 644 instead of 600"),
        "{outcome:?}"
    );
    assert!(outcome.err[1].contains("chmod 0600"), "{outcome:?}");
    fs::set_permissions(&active, Permissions::from_mode(0o600)).unwrap();

    let original = fs::read(&active).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&original).unwrap();
    json["source"] = "/srv/elsewhere".into();
    fs::write(&active, serde_json::to_vec(&json).unwrap()).unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(outcome.err[0].contains("not this layout"), "{outcome:?}");

    fs::write(&active, "not a receipt").unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(
        outcome.err[1].starts_with("Nothing records what moved"),
        "{outcome:?}"
    );

    fs::write(&active, original).unwrap();
    assert_eq!(fixture.run(REVERSE).code, 0);
}

#[test]
fn an_existing_empty_target_root_and_lock_are_kept() {
    let fixture = Fixture::new();
    let etc = &fixture.layout.etc;
    fs::create_dir(etc).unwrap();
    fs::set_permissions(etc, Permissions::from_mode(0o750)).unwrap();
    drop(write_lock::acquire_for_relocate(&fixture.etc_master()).unwrap());
    let root = identity(etc);
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
    assert_eq!(identity(etc), root);
    assert_usable(&fixture.etc_master(), "request-2");
    let dry = fixture.run(DRY_REVERSE);
    assert!(
        dry.out.contains(&format!(
            "after the move: remove {} if it is empty",
            etc.join(LISTS).display()
        )),
        "{dry:?}"
    );
    assert!(
        !dry.out
            .iter()
            .any(|line| line.starts_with(&format!("after the move: remove {} if", etc.display()))),
        "{dry:?}"
    );
    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    assert_eq!(identity(etc), root);
    assert_eq!(fs::read_dir(etc).unwrap().count(), 0);
}

#[test]
fn restorecon_relabels_the_new_root_and_a_failure_keeps_the_move() {
    let fixture = Fixture::new();
    let arguments = fixture.base.join("restorecon.args");
    fixture.write_restorecon(&format!("printf '%s\\n' \"$@\" > {arguments:?}"));
    assert_eq!(fixture.run(DRY_FORWARD).code, 0);
    assert!(!arguments.exists());
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
    assert_eq!(
        fs::read_to_string(&arguments).unwrap(),
        format!("-RF\n{}\n", fixture.layout.etc.display())
    );
    assert!(forward.out.last().unwrap().starts_with("relabelled: "));

    fixture.write_restorecon("exit 3");
    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, exit_codes::FAILURE, "{reverse:?}");
    let command = format!(
        "{} -RF {}",
        fixture.base.join("bin/restorecon").display(),
        fixture.layout.legacy.display()
    );
    assert!(reverse.err[0].starts_with(&format!("error: {command} failed")));
    assert!(reverse.err[1].ends_with(&command), "{reverse:?}");
    assert!(fixture.legacy_master().is_file());
    assert!(!fixture.layout.legacy.join(ACTIVE).exists());
    assert!(fixture.layout.legacy.join(DONE).is_file());
}

#[test]
fn a_rollback_does_not_relabel() {
    let fixture = Fixture::new();
    let arguments = fixture.base.join("restorecon.args");
    fixture.write_restorecon(&format!("printf '%s\\n' \"$@\" > {arguments:?}"));
    assert_eq!(
        with_stop(Stop::AfterReceipt(5), || fixture.run(FORWARD)).code,
        exit_codes::FAILURE
    );
    assert_eq!(fixture.run(REVERSE).code, 0);
    assert!(!arguments.exists());
}

/// The receipt index of the dry-run step line with `prefix` and `suffix`.
fn step_index(steps: &[String], prefix: &str, suffix: &str) -> usize {
    steps
        .iter()
        .position(|line| line.starts_with(prefix) && line.ends_with(suffix))
        .unwrap_or_else(|| panic!("{prefix} ... {suffix}: {steps:?}"))
}

/// The tree without the runtime capability, which a forward run deletes.
fn tree_without_capability(fixture: &Fixture) -> BTreeMap<PathBuf, Entry> {
    let mut tree = without_rebound(fixture.tree());
    tree.remove(
        &fixture
            .layout
            .legacy
            .strip_prefix(&fixture.base)
            .unwrap()
            .join(CAPABILITY),
    );
    tree
}

#[test]
fn a_reverse_dry_run_names_what_the_cleanup_removes() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let etc = &fixture.layout.etc;
    let dry = fixture.run(DRY_REVERSE);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(
        !dry.out
            .iter()
            .any(|line| line.starts_with("stays in") && line.contains(LISTS)),
        "{dry:?}"
    );
    for line in [
        format!(
            "after the move: remove {} if it is empty",
            etc.join(LISTS).display()
        ),
        format!(
            "after the move: remove {} if nothing else is left in it",
            etc.display()
        ),
    ] {
        assert!(dry.out.contains(&line), "{line} in {dry:?}");
    }
    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    assert!(
        reverse.out.contains(&format!("removed {}", etc.display())),
        "{reverse:?}"
    );
}

#[test]
fn a_reverse_dry_run_keeps_a_lists_directory_the_move_leaves_entries_in() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let etc = &fixture.layout.etc;
    fs::write(etc.join(LISTS).join("stray.txt"), "x").unwrap();
    let dry = fixture.run(DRY_REVERSE);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(
        dry.out
            .contains(&format!("stays in {}: {LISTS}", etc.display())),
        "{dry:?}"
    );
    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    assert!(
        reverse.out.contains(&format!(
            "kept {}: it is not empty",
            etc.join(LISTS).display()
        )),
        "{reverse:?}"
    );
}

#[test]
fn a_cleanup_failure_after_a_reverse_commit_keeps_the_move_and_relabels() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let arguments = fixture.base.join("restorecon.args");
    fixture.write_restorecon(&format!("printf '%s\\n' \"$@\" > {arguments:?}"));
    let reverse = with_stop(Stop::Cleanup, || fixture.run(REVERSE));
    assert_eq!(reverse.code, exit_codes::FAILURE, "{reverse:?}");
    assert!(reverse.out[0].starts_with("relocated the config set"));
    assert!(
        reverse.err[0].contains("injected stop at Cleanup"),
        "{reverse:?}"
    );
    let etc = &fixture.layout.etc;
    assert!(reverse.err[1].starts_with("The move is committed"));
    assert!(
        reverse.err[1].ends_with(&format!("rmdir {}", etc.display())),
        "{reverse:?}"
    );
    assert_eq!(
        fs::read_to_string(&arguments).unwrap(),
        format!("-RF\n{}\n", fixture.layout.legacy.display())
    );
    assert!(!fixture.layout.legacy.join(ACTIVE).exists());
    assert!(fixture.layout.legacy.join(DONE).is_file());
    assert!(!etc.join(WRITE_LOCK_FILE).exists());
    assert_usable(&fixture.legacy_master(), "request-2");
}

#[test]
fn a_failed_rollback_keeps_the_fence_and_a_rerun_finishes_it() {
    let steps = Fixture::new().steps(FORWARD);
    let packs = step_index(&steps, "step 6: rename", "/packs");
    let transactions = step_index(
        &steps,
        "step 4: rename",
        &format!("/etc/purge-warden/{}", policy_transaction::STORE_DIR_NAME),
    );
    let fixture = Fixture::new();
    let before = tree_without_capability(&fixture);
    let stopped = with_stop(Stop::AfterReceipt(packs), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    let failed = with_stop(Stop::Undo(transactions), || fixture.run(REVERSE));
    assert_eq!(failed.code, exit_codes::FAILURE, "{failed:?}");
    assert!(
        failed.err[0].contains("injected stop at Undo"),
        "{failed:?}"
    );
    assert!(failed.err[1].starts_with("The rollback stopped and the relocate fence stays up"));
    assert!(failed.err[1].ends_with("config relocate --reverse"));
    assert!(fixture.layout.legacy.join("packs").is_dir());
    assert!(fixture.layout.legacy.join(ACTIVE).exists());
    let fenced = runtime_lease::acquire_for_daemon(&fixture.legacy_master()).unwrap_err();
    assert!(format!("{fenced:#}").contains("RelocateInProgress"));

    let undo = fixture.run(REVERSE);
    assert_eq!(undo.code, 0, "{undo:?}");
    assert_eq!(tree_without_capability(&fixture), before);
}

#[test]
fn a_rollback_refuses_a_taken_source_name_and_changes_nothing() {
    let steps = Fixture::new().steps(FORWARD);
    let master = step_index(&steps, "step 9: rename", MASTER);
    let fixture = Fixture::new();
    let before = tree_without_capability(&fixture);
    let stopped = with_stop(Stop::AfterReceipt(master), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    let stray = fixture.layout.legacy.join("packs");
    fs::write(&stray, "stray").unwrap();
    let outcome = assert_refused_fenced(&fixture, REVERSE);
    assert!(
        outcome.err[0].contains("exists, so the object at its target cannot move back"),
        "{outcome:?}"
    );
    assert!(outcome.err[1].ends_with("config relocate --reverse"));
    fs::remove_file(&stray).unwrap();
    let undo = fixture.run(REVERSE);
    assert_eq!(undo.code, 0, "{undo:?}");
    assert_eq!(tree_without_capability(&fixture), before);
}

#[test]
fn a_rollback_takes_a_missing_target_lock_and_removes_it_again() {
    let steps = Fixture::new().steps(FORWARD);
    let rebind = step_index(&steps, "step 7: rebind", "");
    let fixture = Fixture::new();
    let before = tree_without_capability(&fixture);
    let stopped = with_stop(Stop::AfterReceipt(rebind), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    fs::remove_file(fixture.layout.etc.join(WRITE_LOCK_FILE)).unwrap();
    let undo = fixture.run(REVERSE);
    assert_eq!(undo.code, 0, "{undo:?}");
    assert_eq!(tree_without_capability(&fixture), before);
    assert_usable(&fixture.legacy_master(), "request-2");
}

#[test]
fn reverse_moves_back_an_include_and_a_body_added_after_the_forward_run() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let (legacy, etc) = (&fixture.layout.legacy, &fixture.layout.etc);
    let backup = legacy.join("backups").display().to_string();
    let master = master_text(
        &["conf.d/*.toml", "empty.d/*.toml", "extra.d/*.toml"],
        Some(&backup),
    );
    fs::write(
        fixture.etc_master(),
        format!("{master}\n[[blocklists]]\nid = \"new-allow\"\ndisplay_name = \"New allow\"\nurl = \"https://imported.local/new.txt\"\nbase = \"allow\"\ntrust = \"local\"\n"),
    )
    .unwrap();
    fs::create_dir(etc.join("extra.d")).unwrap();
    for (relative, bytes) in [
        (
            "extra.d/x.toml",
            "[profiles.extra]\ndisplay_name = \"Extra\"\n",
        ),
        ("lists/new.txt", "new.example\n"),
    ] {
        fs::write(etc.join(relative), bytes).unwrap();
        fs::set_permissions(etc.join(relative), Permissions::from_mode(0o640)).unwrap();
    }
    apply_policy(&fixture.etc_master(), "request-2");
    let added = ["extra.d", "extra.d/x.toml", "lists/new.txt"];
    let identities: Vec<_> = added.iter().map(|name| identity(&etc.join(name))).collect();

    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
    for (name, moved) in added.iter().zip(&identities) {
        assert_eq!(identity(&legacy.join(name)), *moved, "{name}");
    }
    assert!(!etc.exists(), "{reverse:?}");
    assert_usable(&fixture.legacy_master(), "request-3");
}

#[test]
fn a_reverse_stop_before_retire_is_finished_by_the_next_run() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let stopped = with_stop(Stop::BeforeRetire, || fixture.run(REVERSE));
    assert_eq!(stopped.code, exit_codes::FAILURE, "{stopped:?}");
    let etc = &fixture.layout.etc;
    assert!(etc.join(WRITE_LOCK_FILE).is_file());
    let finished = fixture.run(FORWARD);
    assert_eq!(finished.code, 0, "{finished:?}");
    assert!(finished.out[0].starts_with("finished the commit of the reverse run"));
    assert!(!fixture.layout.legacy.join(ACTIVE).exists());
    assert!(fixture.layout.legacy.join(DONE).is_file());
    assert!(!etc.exists(), "{finished:?}");
    assert_usable(&fixture.legacy_master(), "request-2");
}

#[test]
fn a_rollback_after_the_lock_step_keeps_an_existing_root_without_a_lock() {
    let fixture = Fixture::new();
    let etc = &fixture.layout.etc;
    fs::create_dir(etc).unwrap();
    fs::set_permissions(etc, Permissions::from_mode(0o750)).unwrap();
    let root = identity(etc);
    let lock = step_index(&fixture.steps(FORWARD), "step 2:", "");
    let stopped = with_stop(Stop::AfterReceipt(lock), || fixture.run(FORWARD));
    assert_eq!(stopped.code, exit_codes::FAILURE);
    assert!(etc.join(WRITE_LOCK_FILE).is_file());
    let undo = fixture.run(REVERSE);
    assert_eq!(undo.code, 0, "{undo:?}");
    assert_eq!(identity(etc), root);
    assert_eq!(fs::read_dir(etc).unwrap().count(), 0);
    let forward = fixture.run(FORWARD);
    assert_eq!(forward.code, 0, "{forward:?}");
    assert_eq!(identity(etc), root);
}

#[test]
fn a_drifted_done_record_does_not_fence_but_refuses_a_reverse_run() {
    let fixture = Fixture::new();
    assert_eq!(fixture.run(FORWARD).code, 0);
    let done = fixture.layout.legacy.join(DONE);
    let master = fixture.etc_master();
    // A non-root reader cannot open a 0000 record, so that mode is checked
    // at the choke points only.
    for mode in [0o644, 0o000] {
        fs::set_permissions(&done, Permissions::from_mode(mode)).unwrap();
        drop(runtime_lease::acquire_for_daemon(&master).unwrap());
        drop(write_lock::acquire_for_read(&master).unwrap());
        drop(write_lock::acquire_for_write(&master).unwrap());
        drop(write_lock::acquire_for_migration(&master).unwrap());
        #[cfg(feature = "cluster")]
        drop(crate::cluster::corpus::CorpusStore::open(&master).unwrap());
    }
    fs::set_permissions(&done, Permissions::from_mode(0o644)).unwrap();
    let outcome = assert_refused(&fixture, REVERSE, "receipt");
    assert!(
        outcome.err[0].contains("mode 644 instead of 600"),
        "{outcome:?}"
    );
    fs::set_permissions(&done, Permissions::from_mode(0o600)).unwrap();
    let mut foreign = layout_clone(&fixture.layout);
    foreign.receipt_owner.0 += 1;
    let outcome = relocate(&foreign, REVERSE).unwrap();
    assert!(refused(&outcome, "receipt"), "{outcome:?}");
    let reverse = fixture.run(REVERSE);
    assert_eq!(reverse.code, 0, "{reverse:?}");
}
