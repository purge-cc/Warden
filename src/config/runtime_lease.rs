use std::cell::Cell;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, ensure, Context};

const LEASE_NAME: &str = ".purge-warden-runtime.lock";
const CAPABILITY_NAME: &str = ".purge-warden-runtime-capability.json";
// This is deliberately independent of the config schema number.  Bumping it
// makes a capability issued by an older binary fail closed instead of being
// silently reinterpreted as evidence that this binary can run schema 5.
const CAPABILITY_VERSION: u32 = 2;
const RUNTIME_SCHEMA_VERSION: u32 = 5;
const MAX_CAPABILITY_BYTES: u64 = 4096;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCapability {
    capability_version: u32,
    attestation: String,
    canonical_master: String,
    root_device: u64,
    root_inode: u64,
}

#[derive(Debug)]
pub struct RuntimeLease {
    _file: File,
    directory: File,
    capability: RuntimeCapability,
    attested: Cell<bool>,
    bootstrap: bool,
    _pid_lease: Option<crate::cli::commands::pid::OfflinePidLease>,
    #[cfg(test)]
    path: std::path::PathBuf,
}

impl RuntimeLease {
    pub(crate) fn requires_migration_bootstrap(&self) -> bool {
        self.bootstrap
    }

    pub(crate) fn verify_migration_tree(
        &self,
        guard: &super::write_lock::MigrationWriteLock,
    ) -> anyhow::Result<()> {
        guard.verify_root_linked()?;
        let expected = capability(guard.identity(), guard.tree_io().root)?;
        ensure!(
            self.capability.canonical_master == expected.canonical_master
                && self.capability.root_device == expected.root_device
                && self.capability.root_inode == expected.root_inode,
            "LeaseCapabilityMismatch: runtime lease belongs to another config tree"
        );
        Ok(())
    }

    /// Record that this locked tree completed an authoritative schema-5 runtime load.
    ///
    /// This is intentionally the only capability issuance API.  In particular,
    /// a schema-4 bridge must never turn a v1 capability into authorization for
    /// an offline v4-to-v5 apply.
    pub fn attest_schema5_runtime(&self, schema_version: u32) -> anyhow::Result<()> {
        ensure!(
            schema_version == RUNTIME_SCHEMA_VERSION,
            "runtime lease capability requires a successful authoritative schema-5 runtime load"
        );
        ensure!(
            !self.attested.get(),
            "runtime lease capability was already attested"
        );
        let owner = self.directory.metadata()?;
        write_capability(&self.directory, &owner, &self.capability)?;
        self.directory.sync_all()?;
        self.attested.set(true);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub fn acquire_for_daemon(master: &Path) -> anyhow::Result<RuntimeLease> {
    acquire(master, "daemon startup", false, false, None)
}

#[cfg(test)]
pub(crate) fn acquire_for_offline_operation(master: &Path) -> anyhow::Result<RuntimeLease> {
    let pid_file = master.with_extension("test.pid");
    acquire(master, "offline migration", true, false, Some(&pid_file))
}

/// Reserve an offline tree for migration. An absent capability requires separate
/// authorization from the validated candidate or its retained migration receipt.
pub(crate) fn acquire_for_migration(
    master: &Path,
    pid_file: &Path,
) -> anyhow::Result<RuntimeLease> {
    acquire(master, "offline migration", true, true, Some(pid_file))
}

fn acquire(
    master: &Path,
    operation: &str,
    require_capability: bool,
    allow_bootstrap: bool,
    pid_file: Option<&Path>,
) -> anyhow::Result<RuntimeLease> {
    let identity = super::write_lock::ConfigTreeIdentity::resolve(master).with_context(|| {
        format!(
            "cannot resolve authoritative config tree for {}",
            master.display()
        )
    })?;
    let state = super::state_dir::for_config_parent(&identity.root);
    ensure!(
        state.is_absolute(),
        "authoritative config state directory is not absolute"
    );
    #[cfg(test)]
    let path = state.join(LEASE_NAME);
    let directory = if state == identity.root {
        identity.open_root(true)?
    } else {
        super::tree_io::plan_external_directory_from(&state, Path::new("/"))?.open_or_create()?
    };
    let owner = directory.metadata()?;
    let name = std::ffi::OsStr::new(LEASE_NAME);
    let flags = libc::O_RDWR | libc::O_NONBLOCK;
    let (file, created) = match super::write_lock::open_at(
        &directory,
        name,
        flags | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            super::write_lock::open_at(&directory, name, libc::O_PATH, 0)?,
            false,
        ),
        Err(error) => return Err(error.into()),
    };
    if created {
        super::write_lock::preserve_owner(&file, &owner)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "runtime lease is not a regular file"
    );
    ensure!(
        metadata.nlink() == 1,
        "runtime lease has multiple hard links"
    );
    ensure!(
        metadata.uid() == owner.uid() && metadata.gid() == owner.gid(),
        "runtime lease owner differs from its state directory"
    );
    ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "runtime lease mode is not 0600"
    );
    let mut file = if created {
        file
    } else {
        super::write_lock::reopen_inspected(&file, flags)?
    };
    // SAFETY: `file` owns a live descriptor for the validated regular lease file.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "NodeNotOffline: {operation} cannot acquire the runtime lease for {}",
                identity.canonical_master.display()
            );
        }
        return Err(error).context("cannot lock the tree-bound runtime lease");
    }
    file.set_len(0)?;
    file.rewind()?;
    write!(file, "{}", std::process::id())?;
    file.sync_data()?;
    let root = identity.open_root(true)?;
    let capability = capability(&identity, &root)?;
    let bootstrap = if require_capability {
        let present = verify_capability(&directory, &owner, &identity, &root, allow_bootstrap)?;
        !present
    } else {
        false
    };
    let pid_lease = pid_file
        .map(|path| crate::cli::commands::pid::acquire_offline_pid_lease(path, Some(&owner)))
        .transpose()?;
    directory.sync_all()?;
    Ok(RuntimeLease {
        _file: file,
        directory,
        capability,
        attested: Cell::new(false),
        bootstrap,
        _pid_lease: pid_lease,
        #[cfg(test)]
        path,
    })
}

fn capability(
    identity: &super::write_lock::ConfigTreeIdentity,
    root: &File,
) -> anyhow::Result<RuntimeCapability> {
    let metadata = root.metadata()?;
    Ok(RuntimeCapability {
        capability_version: CAPABILITY_VERSION,
        attestation: "schema5_runtime".into(),
        canonical_master: identity.canonical_master.to_string_lossy().into_owned(),
        root_device: metadata.dev(),
        root_inode: metadata.ino(),
    })
}

fn write_capability(
    directory: &File,
    owner: &std::fs::Metadata,
    capability: &RuntimeCapability,
) -> anyhow::Result<()> {
    let name = std::ffi::OsStr::new(CAPABILITY_NAME);
    let flags = libc::O_RDWR | libc::O_NONBLOCK;
    let (mut file, created) = match super::write_lock::open_at(
        directory,
        name,
        flags | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let inspected = super::write_lock::open_at(directory, name, libc::O_PATH, 0)?;
            validate_private_member(&inspected, owner, CAPABILITY_NAME)?;
            (
                super::write_lock::reopen_inspected(&inspected, flags)?,
                false,
            )
        }
        Err(error) => return Err(error.into()),
    };
    if created {
        super::write_lock::preserve_owner(&file, owner)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let bytes = serde_json::to_vec(capability)?;
    ensure!(
        bytes.len() as u64 <= MAX_CAPABILITY_BYTES,
        "runtime capability is too large"
    );
    file.set_len(0)?;
    file.rewind()?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn verify_capability(
    directory: &File,
    owner: &std::fs::Metadata,
    identity: &super::write_lock::ConfigTreeIdentity,
    root: &File,
    allow_missing: bool,
) -> anyhow::Result<bool> {
    let inspected = match super::write_lock::open_at(
        directory,
        std::ffi::OsStr::new(CAPABILITY_NAME),
        libc::O_PATH,
        0,
    ) {
        Ok(file) => file,
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => {
            return Err(error)
                .context("LeaseCapabilityMissing: no authoritative schema-5 runtime capability")
        }
    };
    validate_private_member(&inspected, owner, CAPABILITY_NAME)?;
    let file = super::write_lock::reopen_inspected(&inspected, libc::O_RDONLY)?;
    let mut bytes = Vec::new();
    file.take(MAX_CAPABILITY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CAPABILITY_BYTES,
        "runtime capability exceeds its byte limit"
    );
    let recorded: RuntimeCapability = serde_json::from_slice(&bytes)
        .context("LeaseCapabilityInvalid: runtime capability is not valid JSON")?;
    let expected = capability(identity, root)?;
    ensure!(
        recorded.capability_version == expected.capability_version
            && recorded.attestation == expected.attestation,
        "LeaseCapabilityStale: start this authoritative schema-5 tree once with the current runtime before offline migration"
    );
    ensure!(
        recorded.canonical_master == expected.canonical_master
            && recorded.root_device == expected.root_device
            && recorded.root_inode == expected.root_inode,
        "LeaseCapabilityMismatch: runtime capability belongs to another config tree"
    );
    Ok(true)
}

fn validate_private_member(
    file: &File,
    owner: &std::fs::Metadata,
    name: &str,
) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "{name} is not a regular file");
    ensure!(metadata.nlink() == 1, "{name} has multiple hard links");
    ensure!(
        metadata.uid() == owner.uid() && metadata.gid() == owner.gid(),
        "{name} owner differs from its state directory"
    );
    ensure!(metadata.mode() & 0o777 == 0o600, "{name} mode is not 0600");
    ensure!(
        metadata.len() <= MAX_CAPABILITY_BYTES,
        "{name} exceeds its byte limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquire_for_migration(master: &Path) -> anyhow::Result<RuntimeLease> {
        super::acquire_for_migration(master, &master.with_extension("test.pid"))
    }

    fn master(root: &tempfile::TempDir) -> std::path::PathBuf {
        let master = root.path().join("config.toml");
        std::fs::write(&master, "schema_version = 5\n").unwrap();
        master
    }

    fn verify_capability_read_only(master: &Path) -> anyhow::Result<()> {
        let identity = super::super::write_lock::ConfigTreeIdentity::resolve(master)?;
        let directory = identity.open_root(true)?;
        let owner = directory.metadata()?;
        let root = identity.open_root(true)?;
        verify_capability(&directory, &owner, &identity, &root, false).map(|_| ())
    }

    fn write_capability_file(path: &Path, capability: &RuntimeCapability) {
        std::fs::write(path, serde_json::to_vec(capability).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn one_tree_has_one_runtime_lease_independent_of_pid_paths() {
        let root = tempfile::tempdir().unwrap();
        let master = master(&root);
        let daemon = acquire_for_daemon(&master).unwrap();
        let error = acquire_for_offline_operation(&master).unwrap_err();
        assert!(error.to_string().contains("NodeNotOffline"));
        daemon.attest_schema5_runtime(5).unwrap();
        drop(daemon);
        let offline = acquire_for_offline_operation(&master).unwrap();
        assert_eq!(offline.path(), root.path().join(LEASE_NAME));
        assert!(acquire_for_daemon(&master).is_err());
    }

    #[test]
    fn missing_master_uses_the_tree_identity_without_canonicalizing_the_file() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("missing.toml");
        let lease = acquire_for_daemon(&master).unwrap();
        assert_eq!(lease.path(), root.path().join(LEASE_NAME));
        assert!(!master.exists());
        assert!(lease.attest_schema5_runtime(4).is_err());
        assert!(!root.path().join(CAPABILITY_NAME).exists());
    }

    #[test]
    fn safe_mode_can_establish_a_lease_for_an_absent_config_tree() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("not-created-yet");
        let master = tree.join("config.toml");
        let lease = acquire_for_daemon(&master).unwrap();
        assert_eq!(lease.path(), tree.join(LEASE_NAME));
        assert!(tree.is_dir());
        assert!(!master.exists());
        assert!(!tree.join(CAPABILITY_NAME).exists());
    }

    #[test]
    fn offline_operation_refuses_a_tree_missing_a_schema5_runtime_capability() {
        let root = tempfile::tempdir().unwrap();
        let master = master(&root);
        let error = verify_capability_read_only(&master).unwrap_err();
        assert!(error.to_string().contains("LeaseCapabilityMissing"));
        assert!(!root.path().join(CAPABILITY_NAME).exists());
    }

    #[test]
    fn stale_schema4_capability_cannot_authorize_offline_migration() {
        let root = tempfile::tempdir().unwrap();
        let master = master(&root);
        let identity = super::super::write_lock::ConfigTreeIdentity::resolve(&master).unwrap();
        let root_file = identity.open_root(true).unwrap();
        let mut stale = capability(&identity, &root_file).unwrap();
        stale.capability_version = 1;
        stale.attestation = "schema4_dns_ready".into();
        let capability_path = root.path().join(CAPABILITY_NAME);
        write_capability_file(&capability_path, &stale);
        let before = std::fs::read(&capability_path).unwrap();

        let error = verify_capability_read_only(&master).unwrap_err();

        assert!(error.to_string().contains("LeaseCapabilityStale"));
        assert_eq!(std::fs::read(capability_path).unwrap(), before);
    }

    #[test]
    fn schema5_capability_is_bound_to_its_original_tree() {
        let source = tempfile::tempdir().unwrap();
        let source_master = master(&source);
        let source_lease = acquire_for_daemon(&source_master).unwrap();
        source_lease.attest_schema5_runtime(5).unwrap();
        drop(source_lease);

        let target = tempfile::tempdir().unwrap();
        let target_master = master(&target);
        let copied = std::fs::read(source.path().join(CAPABILITY_NAME)).unwrap();
        let target_capability = target.path().join(CAPABILITY_NAME);
        std::fs::write(&target_capability, copied).unwrap();
        std::fs::set_permissions(&target_capability, std::fs::Permissions::from_mode(0o600))
            .unwrap();

        let error = verify_capability_read_only(&target_master).unwrap_err();

        assert!(error.to_string().contains("LeaseCapabilityMismatch"));
        assert!(acquire_for_migration(&target_master)
            .unwrap_err()
            .to_string()
            .contains("LeaseCapabilityMismatch"));
    }

    #[test]
    fn bootstrap_accepts_only_absent_capability_and_keeps_tree_identity() {
        let root = tempfile::tempdir().unwrap();
        let master = master(&root);
        let lease = acquire_for_migration(&master).unwrap();
        assert!(lease.requires_migration_bootstrap());
        let other = tempfile::tempdir().unwrap();
        let other_master = self::master(&other);
        let guard = super::super::write_lock::acquire_for_migration(&other_master).unwrap();
        assert!(lease.verify_migration_tree(&guard).is_err());
        drop(lease);
        let identity = super::super::write_lock::ConfigTreeIdentity::resolve(&master).unwrap();
        let mut stale = capability(&identity, &identity.open_root(true).unwrap()).unwrap();
        stale.capability_version = 1;
        let path = root.path().join(CAPABILITY_NAME);
        write_capability_file(&path, &stale);
        let error = acquire_for_migration(&master).unwrap_err();
        assert!(
            error.to_string().contains("LeaseCapabilityStale"),
            "{error:#}"
        );
        std::fs::write(&path, b"broken json").unwrap();
        let error = acquire_for_migration(&master).unwrap_err();
        assert!(
            error.to_string().contains("LeaseCapabilityInvalid"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(path).unwrap(), b"broken json");
    }

    #[test]
    fn symlink_runtime_lease_is_refused() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let master = master(&root);
        std::fs::write(&target, "foreign").unwrap();
        symlink(&target, root.path().join(LEASE_NAME)).unwrap();
        assert!(acquire_for_daemon(&master).is_err());
    }
}
