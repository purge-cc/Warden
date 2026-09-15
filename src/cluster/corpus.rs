//! Verified, immutable parser inputs shared by primary and secondary nodes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::dto::ArtifactIdentity;
use super::manifest::{digest, is_hash, ObjectRef};
use crate::lists::catalog::{Catalog, CatalogEntry};
use crate::lists::source_key::ResolvedSourcePlan;

pub(crate) const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_CORPUS_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_STAGING_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MANIFESTS: usize = 4096;
const PRIVATE_PINS: &str = "private-pins";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceIdentity {
    pub representative: String,
    pub fetch_url: String,
    pub canonical_url: String,
    pub aliases: Vec<String>,
    pub ids: Vec<String>,
    pub max_entries: u64,
    pub update_interval_secs: u64,
    pub format: String,
    pub trust: String,
}

pub(crate) fn source_inventory(plan: &ResolvedSourcePlan) -> Vec<SourceIdentity> {
    plan.sources()
        .map(|source| {
            let mut aliases: Vec<_> = plan
                .source_aliases()
                .iter()
                .filter(|(_, representative)| representative.as_str() == source.representative())
                .map(|(alias, _)| alias.clone())
                .collect();
            aliases.sort();
            let mut ids: Vec<_> = source
                .id_aliases()
                .iter()
                .map(ToString::to_string)
                .collect();
            ids.sort();
            SourceIdentity {
                representative: source.representative().to_owned(),
                fetch_url: source.fetch_url().to_owned(),
                canonical_url: source.canonical_url().to_owned(),
                aliases,
                ids,
                max_entries: source.effective_max_entries() as u64,
                update_interval_secs: source.effective_update_interval_secs(),
                format: source
                    .owner_blocklist()
                    .map(|row| format!("{:?}", row.format))
                    .unwrap_or_else(|| "Domains".into()),
                trust: source
                    .owner_blocklist()
                    .map(|row| format!("{:?}", row.trust))
                    .unwrap_or_else(|| "RemoteUnsigned".into()),
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusSource {
    pub source: SourceIdentity,
    pub body: ObjectRef,
    /// Original successful primary acquisition or revalidation time.
    pub fetched_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusAuxSource {
    pub url: String,
    pub body: ObjectRef,
    pub fetched_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusManifest {
    pub version: u32,
    pub artifact: ArtifactIdentity,
    pub source_plan_hash: String,
    pub sources: Vec<CorpusSource>,
    pub auxiliary: Vec<CorpusAuxSource>,
    /// Content identity includes freshness and policy binding, not a local counter.
    pub generation: String,
}

impl CorpusManifest {
    pub(crate) fn new(
        artifact: ArtifactIdentity,
        sources: Vec<CorpusSource>,
        auxiliary: Vec<CorpusAuxSource>,
    ) -> anyhow::Result<Self> {
        let inventory: Vec<_> = sources.iter().map(|s| &s.source).collect();
        let mut manifest = Self {
            version: 1,
            artifact,
            source_plan_hash: digest(&serde_json::to_vec(&inventory)?),
            sources,
            auxiliary,
            generation: String::new(),
        };
        manifest.generation = manifest.compute_generation()?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn compute_generation(&self) -> anyhow::Result<String> {
        let mut copy = self.clone();
        copy.generation.clear();
        Ok(digest(&serde_json::to_vec(&copy)?))
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.artifact.validate()?;
        ensure!(
            self.version == 1 && self.sources.len() <= crate::lists::manager::MAX_LIST_SOURCES,
            "CorpusInvalidManifest: version or source count"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_MANIFEST_BYTES,
            "CorpusManifestTooLarge"
        );
        let mut representatives = BTreeSet::new();
        let mut urls = BTreeSet::new();
        let mut total = 0u64;
        for item in &self.sources {
            ensure!(
                is_hash(&item.body.sha256)
                    && item.body.bytes <= MAX_OBJECT_BYTES
                    && item.fetched_at > 0,
                "CorpusInvalidObject"
            );
            ensure!(
                !item.source.representative.is_empty()
                    && !item.source.fetch_url.is_empty()
                    && !item.source.canonical_url.is_empty(),
                "CorpusInvalidSource"
            );
            ensure!(
                representatives.insert(&item.source.representative)
                    && urls.insert(&item.source.canonical_url),
                "CorpusDuplicateSource"
            );
            total = total
                .checked_add(item.body.bytes)
                .context("CorpusSizeOverflow")?;
        }
        ensure!(self.auxiliary.len() <= 64, "CorpusAuxiliaryCountExceeded");
        let mut auxiliary_urls = BTreeSet::new();
        for item in &self.auxiliary {
            ensure!(
                !item.url.is_empty() && auxiliary_urls.insert(&item.url),
                "CorpusInvalidAuxiliarySource"
            );
            ensure!(
                is_hash(&item.body.sha256)
                    && item.body.bytes <= MAX_OBJECT_BYTES
                    && item.fetched_at > 0,
                "CorpusInvalidAuxiliaryObject"
            );
            total = total
                .checked_add(item.body.bytes)
                .context("CorpusSizeOverflow")?;
        }
        ensure!(total <= MAX_CORPUS_BYTES, "CorpusQuotaExceeded");
        let inventory: Vec<_> = self.sources.iter().map(|s| &s.source).collect();
        ensure!(
            self.source_plan_hash == digest(&serde_json::to_vec(&inventory)?)
                && self.generation == self.compute_generation()?,
            "CorpusManifestHashMismatch"
        );
        Ok(())
    }

    pub(crate) fn objects(&self) -> impl Iterator<Item = &ObjectRef> {
        self.sources
            .iter()
            .map(|s| &s.body)
            .chain(self.auxiliary.iter().map(|s| &s.body))
    }

    pub(crate) fn verify_auxiliary(&self, urls: &[String]) -> anyhow::Result<()> {
        ensure!(
            self.auxiliary
                .iter()
                .map(|source| &source.url)
                .eq(urls.iter()),
            "CorpusAuxiliaryInventoryMismatch"
        );
        Ok(())
    }

    pub(crate) fn verify_plan(&self, plan: &ResolvedSourcePlan) -> anyhow::Result<()> {
        self.validate()?;
        let inventory: Vec<_> = self.sources.iter().map(|s| s.source.clone()).collect();
        ensure!(
            inventory == source_inventory(plan),
            "CorpusSourcePlanMismatch: complete configured inventory required"
        );
        Ok(())
    }

    /// Rebuild only the catalog identities already resolved by the primary.
    pub(crate) fn catalog(&self) -> Catalog {
        let mut entries = BTreeMap::new();
        for item in &self.sources {
            for alias in item
                .source
                .aliases
                .iter()
                .chain(std::iter::once(&item.source.representative))
            {
                if crate::lists::source_key::is_url_source(alias) || item.source.ids.contains(alias)
                {
                    continue;
                }
                let (scope, topic) = alias
                    .split_once('/')
                    .map_or((alias.as_str(), None), |(scope, topic)| {
                        (scope, Some(topic.to_owned()))
                    });
                entries.insert(
                    alias.clone(),
                    CatalogEntry {
                        scope: scope.to_owned(),
                        topic,
                        name: alias.clone(),
                        url: item.source.fetch_url.clone(),
                        entries: 0,
                        updated_at: String::new(),
                        format: Default::default(),
                    },
                );
            }
        }
        Catalog::from_verified_entries(entries.into_values().collect())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairState {
    pub desired: Option<String>,
    pub persisted: Option<String>,
    pub active: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateManifestPin {
    generation: String,
    expires_at: u64,
}

/// Disk work is serialized off the query path. Manifests retain every referenced
/// object; collection refuses uncertainty instead of guessing ownership.
pub(crate) struct CorpusStore {
    root: PathBuf,
    directory: File,
    pins: Mutex<BTreeMap<String, File>>,
}

impl CorpusStore {
    pub(crate) fn open(config_path: &Path) -> anyhow::Result<Self> {
        let root = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".warden-node-corpus");
        for dir in [
            &root,
            &root.join("objects"),
            &root.join("manifests"),
            &root.join("candidates"),
            &root.join(PRIVATE_PINS),
        ] {
            ensure_directory_durable(dir)?;
        }
        let directory = open_directory(&root)?;
        let store = Self {
            root,
            directory,
            pins: Mutex::new(BTreeMap::new()),
        };
        {
            let _guard = store.write_lock()?;
            store.collect_retired_caches()?;
        }
        Ok(store)
    }

    pub(crate) fn open_existing(config_path: &Path) -> anyhow::Result<Option<Self>> {
        let root = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".warden-node-corpus");
        if !root.try_exists()? {
            return Ok(None);
        }
        for dir in [
            &root,
            &root.join("objects"),
            &root.join("manifests"),
            &root.join("candidates"),
        ] {
            verify_directory(dir)?;
        }
        let private_pins = root.join(PRIVATE_PINS);
        ensure_directory_durable(&private_pins)?;
        let directory = open_directory(&root)?;
        Ok(Some(Self {
            root,
            directory,
            pins: Mutex::new(BTreeMap::new()),
        }))
    }

    fn write_lock(&self) -> anyhow::Result<DirectoryLock> {
        verify_directory(&self.root)?;
        let file = open_directory(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let expected = self.directory.metadata()?;
            let actual = file.metadata()?;
            ensure!(
                expected.ino() == actual.ino() && expected.dev() == actual.dev(),
                "CorpusDirectoryReplaced"
            );
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0,
                "CorpusLockFailed"
            );
        }
        Ok(DirectoryLock(file))
    }

    pub(crate) fn primary_cache_dir(&self) -> anyhow::Result<Option<PathBuf>> {
        let path = self.root.join("primary-cache.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        let name: String = read_json(&path)?;
        ensure!(
            name.starts_with("parser-") && !name.contains('/') && !name.contains('\\'),
            "CorpusUnsafeCachePath"
        );
        let directory = self.root.join(name);
        let metadata = std::fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "CorpusUnsafeCacheDirectory"
        );
        Ok(Some(directory))
    }

    pub(crate) fn set_primary_cache_dir(&self, directory: &Path) -> anyhow::Result<()> {
        let _guard = self.write_lock()?;
        self.record_owned_cache(directory)?;
        if let Some(previous) = self.primary_cache_dir()? {
            self.record_owned_cache(&previous)?;
        }
        let name = directory
            .file_name()
            .context("CorpusInvalidCacheDirectory")?;
        self.write_json(&self.root.join("primary-cache.json"), &name.to_str())?;
        if let Err(error) = self.collect_retired_caches() {
            tracing::warn!(%error, "cannot retire unused primary parser caches");
        }
        Ok(())
    }

    pub(crate) fn lease_primary_cache(&self) -> anyhow::Result<Option<(PathBuf, File)>> {
        let _guard = self.write_lock()?;
        let Some(path) = self.primary_cache_dir()? else {
            return Ok(None);
        };
        let lease = self.lease_cache_directory(&path)?;
        self.record_owned_cache(&path)?;
        if let Err(error) = self.collect_retired_caches() {
            tracing::warn!(%error, "cannot retire unused primary parser caches");
        }
        Ok(Some((path, lease)))
    }

    pub(crate) fn lease_cache_directory(&self, directory: &Path) -> anyhow::Result<File> {
        ensure!(
            directory.parent() == Some(self.root.as_path()),
            "CorpusUnownedCacheDirectory"
        );
        verify_directory(directory)?;
        let lease = open_directory(directory)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            ensure!(
                unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_SH) } == 0,
                "CorpusCacheLeaseFailed"
            );
        }
        Ok(lease)
    }

    fn record_owned_cache(&self, directory: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            directory.parent() == Some(self.root.as_path()),
            "CorpusUnownedCacheDirectory"
        );
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .context("CorpusInvalidCacheDirectory")?;
        ensure!(name.starts_with("parser-"), "CorpusUnownedCacheDirectory");
        verify_directory(directory)?;
        let metadata = open_directory(directory)?.metadata()?;
        let receipt = self.root.join(format!("cache-owner-{name}"));
        let identity = (metadata.dev(), metadata.ino());
        if receipt.try_exists()? {
            let previous: (u64, u64) = read_json(&receipt)?;
            ensure!(previous == identity, "CorpusCacheOwnershipChanged");
            return Ok(());
        }
        self.write_json(&receipt, &identity)
    }

    fn collect_retired_caches(&self) -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let selected = self.primary_cache_dir()?;
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(cache) = name.strip_prefix("cache-owner-") else {
                continue;
            };
            ensure!(cache.starts_with("parser-"), "CorpusUnknownCacheOwner");
            let expected: (u64, u64) = read_json(&entry.path())?;
            let path = self.root.join(cache);
            if selected.as_ref() == Some(&path) {
                continue;
            }
            let lease = match open_directory(&path) {
                Ok(lease) => lease,
                Err(error) if is_not_found(&error) => {
                    std::fs::remove_file(entry.path())?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let metadata = lease.metadata()?;
            ensure!(
                (metadata.dev(), metadata.ino()) == expected,
                "CorpusCacheOwnershipChanged"
            );
            verify_directory(&path)?;
            if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(error.into());
            }
            std::fs::remove_dir_all(&path)?;
            std::fs::remove_file(entry.path())?;
        }
        self.directory.sync_all()?;
        Ok(())
    }

    pub(crate) fn parser_workspace(&self) -> anyhow::Result<(tempfile::TempDir, File)> {
        use std::os::unix::fs::PermissionsExt;
        let _guard = self.write_lock()?;
        let workspace = tempfile::Builder::new()
            .prefix("parser-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&self.root)?;
        let lease = self.lease_cache_directory(workspace.path())?;
        self.record_owned_cache(workspace.path())?;
        self.collect_retired_caches()?;
        Ok((workspace, lease))
    }

    pub(crate) fn object_path(&self, hash: &str) -> anyhow::Result<PathBuf> {
        ensure!(is_hash(hash), "CorpusInvalidObjectHash");
        Ok(self.root.join("objects").join(hash))
    }

    pub(crate) fn open_object(&self, hash: &str) -> anyhow::Result<File> {
        open_regular(&self.object_path(hash)?)
    }

    pub(crate) fn authorized_object(&self, hash: &str) -> anyhow::Result<File> {
        ensure!(is_hash(hash), "CorpusInvalidObjectHash");
        for entry in std::fs::read_dir(self.root.join("manifests"))? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CorpusUnknownManifest"))?;
            let manifest = self.manifest(&name)?;
            let object = manifest.objects().find(|object| object.sha256 == hash);
            if let Some(object) = object {
                return self.verified_object(object);
            }
        }
        anyhow::bail!("CorpusObjectNotOwned")
    }

    pub(crate) fn verified_object(&self, object: &ObjectRef) -> anyhow::Result<File> {
        let mut file = self.open_object(&object.sha256)?;
        verify_file(&mut file, object)?;
        Ok(file)
    }

    pub(crate) fn has_object(&self, object: &ObjectRef) -> bool {
        self.verified_object(object).is_ok()
    }

    pub(crate) fn manifest(&self, generation: &str) -> anyhow::Result<CorpusManifest> {
        ensure!(is_hash(generation), "CorpusInvalidGeneration");
        let manifest: CorpusManifest = read_json(&self.root.join("manifests").join(generation))?;
        manifest.validate()?;
        ensure!(
            manifest.generation == generation,
            "CorpusGenerationMismatch"
        );
        Ok(manifest)
    }

    /// Read desired identity metadata without asserting body admission or activation.
    pub(crate) fn manifest_metadata(&self, generation: &str) -> anyhow::Result<CorpusManifest> {
        match self.manifest(generation) {
            Ok(manifest) => return Ok(manifest),
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(error),
        }
        let candidate: CorpusManifest =
            match read_json(&self.root.join("candidates").join(generation)) {
                Ok(candidate) => candidate,
                // Publication may move ownership after the first lookup.
                Err(error) if is_not_found(&error) => return self.manifest(generation),
                Err(error) => return Err(error),
            };
        candidate.validate()?;
        ensure!(
            candidate.generation == generation,
            "CorpusGenerationMismatch"
        );
        Ok(candidate)
    }

    pub(crate) fn manifest_for_artifact(&self, artifact: &str) -> anyhow::Result<CorpusManifest> {
        ensure!(is_hash(artifact), "CorpusInvalidArtifactHash");
        let generation: String = read_json(&self.root.join(format!("policy-{artifact}")))?;
        let manifest = self.manifest(&generation)?;
        ensure!(
            manifest.artifact.artifact_hash == artifact,
            "CorpusArtifactMismatch"
        );
        Ok(manifest)
    }

    pub(crate) fn pair_state(&self) -> anyhow::Result<PairState> {
        let path = self.root.join("pair.json");
        if !path.try_exists()? {
            return Ok(PairState::default());
        }
        read_json(&path)
    }

    pub(crate) fn record_desired(&self, manifest: &CorpusManifest) -> anyhow::Result<File> {
        manifest.validate()?;
        let _guard = self.write_lock()?;
        self.prune_abandoned_candidates()?;
        let candidate = self.root.join("candidates").join(&manifest.generation);
        if !candidate.try_exists()? {
            ensure!(
                std::fs::read_dir(self.root.join("candidates"))?.count() < MAX_MANIFESTS,
                "CorpusCandidateQuotaExceeded"
            );
            self.write_json(&candidate, manifest)?;
        }
        let mut state = self.pair_state()?;
        state.desired = Some(manifest.generation.clone());
        self.write_json(&self.root.join("pair.json"), &state)?;
        let lease = open_regular(&candidate)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            ensure!(
                unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_SH) } == 0,
                "CorpusCandidateLeaseFailed"
            );
        }
        self.prune_abandoned_candidates()?;
        Ok(lease)
    }

    /// Publish selection only after every immutable parser input is durable.
    pub(crate) fn install_manifest(&self, manifest: &CorpusManifest) -> anyhow::Result<()> {
        self.publish_manifest(manifest, true)?;
        self.collect_unreferenced()?;
        Ok(())
    }

    pub(crate) fn prepare_manifest(&self, manifest: &CorpusManifest) -> anyhow::Result<()> {
        self.publish_manifest(manifest, false)
    }

    /// Retain a complete enrollment candidate without selecting it as desired policy.
    #[cfg(test)]
    pub(crate) fn prepare_manifest_private(&self, manifest: &CorpusManifest) -> anyhow::Result<()> {
        manifest.validate()?;
        let _guard = self.write_lock()?;
        for object in manifest.objects() {
            self.verified_object(object)?;
        }
        let candidate = self.root.join("candidates").join(&manifest.generation);
        if !candidate.try_exists()? {
            ensure!(
                std::fs::read_dir(self.root.join("candidates"))?.count() < MAX_MANIFESTS,
                "CorpusCandidateQuotaExceeded"
            );
            self.write_json(&candidate, manifest)?;
        }
        Ok(())
    }

    /// Retain an enrollment candidate across process restarts without selecting it.
    pub(crate) fn prepare_manifest_private_pinned(
        &self,
        manifest: &CorpusManifest,
        owner_id: &str,
        expires_at: u64,
    ) -> anyhow::Result<()> {
        ensure!(
            super::membership::valid_id(owner_id),
            "CorpusInvalidPrivatePinOwner"
        );
        ensure!(
            expires_at > super::membership::now()?,
            "CorpusPrivatePinExpired"
        );
        manifest.validate()?;
        let _guard = self.write_lock()?;
        for object in manifest.objects() {
            self.verified_object(object)?;
        }
        let candidate = self.root.join("candidates").join(&manifest.generation);
        if !candidate.try_exists()? {
            ensure!(
                std::fs::read_dir(self.root.join("candidates"))?.count() < MAX_MANIFESTS,
                "CorpusCandidateQuotaExceeded"
            );
            self.write_json(&candidate, manifest)?;
        } else {
            let existing: CorpusManifest = read_json(&candidate)?;
            ensure!(&existing == manifest, "CorpusCandidateConflict");
        }
        self.prune_expired_private_pins(super::membership::now()?)?;
        let path = self.private_pin_path(owner_id)?;
        if path.try_exists()? {
            let existing: PrivateManifestPin = read_json(&path)?;
            ensure!(
                existing.generation == manifest.generation,
                "CorpusPrivatePinConflict"
            );
        } else {
            ensure!(
                std::fs::read_dir(self.root.join(PRIVATE_PINS))?.count() < MAX_MANIFESTS,
                "CorpusPrivatePinQuotaExceeded"
            );
        }
        self.write_json(
            &path,
            &PrivateManifestPin {
                generation: manifest.generation.clone(),
                expires_at,
            },
        )?;
        Ok(())
    }

    /// Release one private enrollment candidate and collect its unowned objects.
    pub(crate) fn release_private_manifest_pin(&self, owner_id: &str) -> anyhow::Result<()> {
        let path = self.private_pin_path(owner_id)?;
        let _guard = self.write_lock()?;
        match open_regular(&path) {
            Ok(_) => {
                std::fs::remove_file(&path)?;
                File::open(self.root.join(PRIVATE_PINS))?.sync_all()?;
            }
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(error),
        }
        self.prune_retired_manifests()?;
        self.collect_unreferenced_locked()?;
        Ok(())
    }

    fn publish_manifest(&self, manifest: &CorpusManifest, persisted: bool) -> anyhow::Result<()> {
        manifest.validate()?;
        let _guard = self.write_lock()?;
        for object in manifest.objects() {
            self.verified_object(object)?;
        }
        let path = self.root.join("manifests").join(&manifest.generation);
        if !path.try_exists()? {
            ensure!(
                std::fs::read_dir(self.root.join("manifests"))?.count() < MAX_MANIFESTS,
                "CorpusManifestQuotaExceeded"
            );
            self.write_json(&path, manifest)?;
        }
        self.write_json(
            &self
                .root
                .join(format!("policy-{}", manifest.artifact.artifact_hash)),
            &manifest.generation,
        )?;
        let mut state = self.pair_state()?;
        state.desired = Some(manifest.generation.clone());
        if persisted {
            state.persisted = Some(manifest.generation.clone());
        }
        self.write_json(&self.root.join("pair.json"), &state)?;
        let candidate = self.root.join("candidates").join(&manifest.generation);
        if candidate.try_exists()? {
            std::fs::remove_file(candidate)?;
            File::open(self.root.join("candidates"))?.sync_all()?;
        }
        self.prune_retired_manifests()?;
        let mut pins = self
            .pins
            .lock()
            .map_err(|_| anyhow::anyhow!("CorpusPinsPoisoned"))?;
        for object in manifest.objects() {
            pins.remove(&object.sha256);
        }
        Ok(())
    }

    /// Called only after the matching policy and parsed corpus are installed.
    pub(crate) fn mark_active(
        &self,
        generation: &str,
        artifact: &ArtifactIdentity,
    ) -> anyhow::Result<()> {
        let _guard = self.write_lock()?;
        let manifest = self.manifest(generation)?;
        ensure!(&manifest.artifact == artifact, "CorpusActivePolicyMismatch");
        let mut state = self.pair_state()?;
        ensure!(
            state.persisted.as_deref() == Some(generation),
            "CorpusActiveNotPersisted"
        );
        state.active = Some(generation.to_owned());
        self.write_json(&self.root.join("pair.json"), &state)?;
        self.prune_retired_manifests()?;
        Ok(())
    }

    /// Recover the corpus selected by committed policy evidence, never an
    /// unadmitted list-only candidate that happens to share its policy hash.
    pub(crate) fn recover_committed_pair(
        &self,
        artifact: &ArtifactIdentity,
    ) -> anyhow::Result<CorpusManifest> {
        let _guard = self.write_lock()?;
        let mut state = self.pair_state()?;
        let prior = state
            .persisted
            .as_deref()
            .map(|generation| self.manifest(generation))
            .transpose()?;
        let manifest = match prior.filter(|manifest| &manifest.artifact == artifact) {
            Some(manifest) => manifest,
            None => self.manifest_for_artifact(&artifact.artifact_hash)?,
        };
        ensure!(
            &manifest.artifact == artifact,
            "CorpusCommittedPolicyMismatch"
        );
        self.verify_manifest_objects(&manifest)?;
        self.write_json(
            &self.root.join(format!("policy-{}", artifact.artifact_hash)),
            &manifest.generation,
        )?;
        state.persisted = Some(manifest.generation.clone());
        self.write_json(&self.root.join("pair.json"), &state)?;
        Ok(manifest)
    }

    pub(crate) fn verify_manifest_objects(&self, manifest: &CorpusManifest) -> anyhow::Result<()> {
        manifest.validate()?;
        for object in manifest.objects() {
            self.verified_object(object)?;
        }
        Ok(())
    }

    /// The sole producer releases unadvertised acquisitions after aborting a cycle.
    pub(crate) fn release_unpublished_pins(&self) -> anyhow::Result<()> {
        self.pins
            .lock()
            .map_err(|_| anyhow::anyhow!("CorpusPinsPoisoned"))?
            .clear();
        self.collect_unreferenced()?;
        Ok(())
    }

    fn pin_object(&self, object: &ObjectRef) -> anyhow::Result<()> {
        let file = self.open_object(&object.sha256)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } == 0,
                "CorpusObjectPinFailed"
            );
        }
        self.pins
            .lock()
            .map_err(|_| anyhow::anyhow!("CorpusPinsPoisoned"))?
            .insert(object.sha256.clone(), file);
        Ok(())
    }

    pub(crate) fn import_file(&self, object: &ObjectRef, input: &mut File) -> anyhow::Result<()> {
        if self.has_object(object) {
            let _guard = self.write_lock()?;
            self.pin_object(object)?;
            return Ok(());
        }
        let mut stage = self.stage(object)?;
        input.seek(SeekFrom::Start(0))?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            stage.write_chunk(&buffer[..count])?;
        }
        stage.finish_with_pin(self, true)
    }

    pub(crate) fn stage(&self, object: &ObjectRef) -> anyhow::Result<ObjectStage> {
        match self.stage_reserved(object) {
            Err(error) if error.to_string() == "CorpusDiskQuotaExceeded" => {
                self.collect_unreferenced()?;
                self.stage_reserved(object)
            }
            result => result,
        }
    }

    fn stage_reserved(&self, object: &ObjectRef) -> anyhow::Result<ObjectStage> {
        ensure!(
            is_hash(&object.sha256) && object.bytes <= MAX_OBJECT_BYTES,
            "CorpusObjectQuotaExceeded"
        );
        let _guard = self.write_lock()?;
        let mut total = 0u64;
        let mut staging = 0u64;
        for entry in std::fs::read_dir(self.root.join("objects"))? {
            let entry = entry?;
            let meta = entry.metadata()?;
            ensure!(meta.is_file(), "CorpusUnexpectedObjectEntry");
            total = total
                .checked_add(meta.len())
                .context("CorpusSizeOverflow")?;
            if entry.file_name().to_string_lossy().starts_with(".stage-") {
                staging = staging
                    .checked_add(meta.len())
                    .context("CorpusSizeOverflow")?;
            }
        }
        ensure!(
            staging
                .checked_add(object.bytes)
                .is_some_and(|bytes| bytes <= MAX_STAGING_BYTES),
            "CorpusStagingQuotaExceeded"
        );
        ensure!(
            total
                .checked_add(object.bytes)
                .is_some_and(|n| n <= MAX_CORPUS_BYTES + MAX_STAGING_BYTES),
            "CorpusDiskQuotaExceeded"
        );
        let mut random = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|e| anyhow::anyhow!("CorpusEntropy: {e}"))?;
        let path = self
            .root
            .join("objects")
            .join(format!(".stage-{}", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        let stage = ObjectStage {
            path,
            file,
            expected: object.clone(),
            hash: Sha256::new(),
            written: 0,
        };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if object.bytes > 0 {
                let result = unsafe {
                    libc::posix_fallocate(stage.file.as_raw_fd(), 0, object.bytes as libc::off_t)
                };
                ensure!(
                    result == 0,
                    "CorpusDiskReservationFailed: {}",
                    std::io::Error::from_raw_os_error(result)
                );
            }
        }
        Ok(stage)
    }

    fn write_json(&self, path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "CorpusMetadataQuotaExceeded"
        );
        crate::config::atomic_write::hardened_atomic_write(path, &bytes, Default::default())?;
        Ok(())
    }

    /// Retire only indexes released by authoritative policy ownership. Runtime
    /// selections and in-flight candidates remain independent retention roots.
    pub(crate) fn retain_policy_artifacts(
        &self,
        retained: &BTreeSet<String>,
    ) -> anyhow::Result<()> {
        ensure!(
            retained.iter().all(|hash| is_hash(hash)),
            "CorpusInvalidOwnershipProof"
        );
        {
            let _guard = self.write_lock()?;
            self.prune_abandoned_candidates()?;
            let mut keep = retained.clone();
            let state = self.pair_state()?;
            for generation in [state.active, state.persisted, state.desired]
                .into_iter()
                .flatten()
            {
                let manifest = self.manifest(&generation).or_else(|_| {
                    read_json::<CorpusManifest>(&self.root.join("candidates").join(&generation))
                })?;
                manifest.validate()?;
                keep.insert(manifest.artifact.artifact_hash);
            }
            for entry in std::fs::read_dir(self.root.join("candidates"))? {
                let candidate: CorpusManifest = read_json(&entry?.path())?;
                candidate.validate()?;
                keep.insert(candidate.artifact.artifact_hash);
            }
            for entry in std::fs::read_dir(&self.root)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(hash) = name.strip_prefix("policy-") {
                    ensure!(is_hash(hash), "CorpusUnknownPolicyIndex");
                    let generation: String = read_json(&entry.path())?;
                    let manifest = self.manifest(&generation)?;
                    ensure!(
                        manifest.artifact.artifact_hash == hash,
                        "CorpusPolicyIndexMismatch"
                    );
                    if !keep.contains(hash) {
                        std::fs::remove_file(entry.path())?;
                    }
                }
            }
            self.directory.sync_all()?;
            self.prune_retired_manifests()?;
        }
        self.collect_unreferenced()?;
        Ok(())
    }

    fn prune_retired_manifests(&self) -> anyhow::Result<()> {
        let state = self.pair_state()?;
        let mut keep: BTreeSet<String> = [state.active, state.persisted, state.desired]
            .into_iter()
            .flatten()
            .collect();
        keep.extend(self.prune_expired_private_pins(super::membership::now()?)?);
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(hash) = name.strip_prefix("policy-") {
                ensure!(is_hash(hash), "CorpusUnknownPolicyPointer");
                let generation: String = read_json(&entry.path())?;
                ensure!(is_hash(&generation), "CorpusInvalidGenerationPointer");
                keep.insert(generation);
            }
        }
        for entry in std::fs::read_dir(self.root.join("manifests"))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CorpusUnknownManifest"))?;
            self.manifest(&name)?;
            if !keep.contains(&name) {
                std::fs::remove_file(entry.path())?;
            }
        }
        File::open(self.root.join("manifests"))?.sync_all()?;
        Ok(())
    }

    fn prune_abandoned_candidates(&self) -> anyhow::Result<()> {
        self.prune_abandoned_candidates_at(super::membership::now()?)
    }

    fn prune_abandoned_candidates_at(&self, now: u64) -> anyhow::Result<()> {
        let state = self.pair_state()?;
        let mut keep: BTreeSet<String> = [state.active, state.persisted, state.desired]
            .into_iter()
            .flatten()
            .collect();
        keep.extend(self.prune_expired_private_pins(now)?);
        for entry in std::fs::read_dir(self.root.join("candidates"))? {
            let entry = entry?;
            let candidate: CorpusManifest = read_json(&entry.path())?;
            candidate.validate()?;
            ensure!(
                entry.file_name().to_str() == Some(&candidate.generation),
                "CorpusUnknownCandidate"
            );
            if keep.contains(&candidate.generation) {
                continue;
            }
            let lease = open_regular(&entry.path())?;
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(error.into());
                }
            }
            std::fs::remove_file(entry.path())?;
        }
        File::open(self.root.join("candidates"))?.sync_all()?;
        Ok(())
    }

    fn private_pin_path(&self, owner_id: &str) -> anyhow::Result<PathBuf> {
        ensure!(
            super::membership::valid_id(owner_id),
            "CorpusInvalidPrivatePinOwner"
        );
        Ok(self.root.join(PRIVATE_PINS).join(owner_id))
    }

    fn prune_expired_private_pins(&self, now: u64) -> anyhow::Result<BTreeSet<String>> {
        let directory = self.root.join(PRIVATE_PINS);
        let mut live = BTreeSet::new();
        let mut removed = false;
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let owner_id = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CorpusUnknownPrivatePin"))?;
            ensure!(
                super::membership::valid_id(&owner_id),
                "CorpusUnknownPrivatePin"
            );
            let pin: PrivateManifestPin = read_json(&entry.path())?;
            ensure!(
                is_hash(&pin.generation) && pin.expires_at > 0,
                "CorpusInvalidPrivatePin"
            );
            if pin.expires_at <= now {
                std::fs::remove_file(entry.path())?;
                removed = true;
            } else {
                ensure!(
                    self.root
                        .join("candidates")
                        .join(&pin.generation)
                        .try_exists()?
                        || self
                            .root
                            .join("manifests")
                            .join(&pin.generation)
                            .try_exists()?,
                    "CorpusPrivatePinTargetMissing"
                );
                live.insert(pin.generation);
            }
        }
        if removed {
            File::open(directory)?.sync_all()?;
        }
        Ok(live)
    }

    /// Only hash-named regular objects absent from every owned manifest are
    /// removable. Unknown files and failed stages require explicit recovery.
    pub(crate) fn collect_unreferenced(&self) -> anyhow::Result<usize> {
        let _guard = self.write_lock()?;
        self.collect_unreferenced_locked()
    }

    fn collect_unreferenced_locked(&self) -> anyhow::Result<usize> {
        self.prune_abandoned_candidates()?;
        let mut referenced = BTreeSet::new();
        for entry in std::fs::read_dir(self.root.join("manifests"))? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CorpusUnknownManifest"))?;
            for object in self.manifest(&name)?.objects() {
                referenced.insert(object.sha256.clone());
            }
        }
        for entry in std::fs::read_dir(self.root.join("candidates"))? {
            let entry = entry?;
            let candidate: CorpusManifest = read_json(&entry.path())?;
            candidate.validate()?;
            ensure!(
                entry.file_name().to_str() == Some(&candidate.generation),
                "CorpusUnknownCandidate"
            );
            for object in candidate.objects() {
                referenced.insert(object.sha256.clone());
            }
        }
        let mut removed = 0;
        for entry in std::fs::read_dir(self.root.join("objects"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_hash(&name) && !referenced.contains(&name) {
                let metadata = std::fs::symlink_metadata(entry.path())?;
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "CorpusUnsafeObject"
                );
                let file = self.open_object(&name)?;
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
                    {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                        return Err(error.into());
                    }
                }
                std::fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        File::open(self.root.join("objects"))?.sync_all()?;
        Ok(removed)
    }
}

pub(crate) struct PreparedAuxiliary {
    pub sources: Vec<CorpusAuxSource>,
    pub activate: Box<dyn FnOnce() + Send>,
}

pub(crate) type AuxiliaryRefresh = std::sync::Arc<
    dyn Fn(
            std::sync::Arc<CorpusStore>,
            reqwest::Client,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<PreparedAuxiliary>> + Send>,
        > + Send
        + Sync,
>;

/// Stream an origin IP-list response into the same reserved immutable object
/// store used by domain lists. Only primary acquisition calls this boundary.
pub(crate) async fn acquire_auxiliary(
    store: std::sync::Arc<CorpusStore>,
    client: &reqwest::Client,
    url: &str,
    max_body_bytes: usize,
) -> anyhow::Result<CorpusAuxSource> {
    crate::lists::http_client::validate_list_url(url)?;
    let limit = (max_body_bytes as u64).min(MAX_OBJECT_BYTES);
    let reserve_store = std::sync::Arc::clone(&store);
    let mut stage = tokio::task::spawn_blocking(move || {
        reserve_store.stage(&ObjectRef {
            sha256: "0".repeat(64),
            bytes: limit,
        })
    })
    .await??;
    let mut response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "CorpusAuxiliaryOriginFailed: HTTP {}",
        response.status()
    );
    if let Some(bytes) = response.content_length() {
        ensure!(bytes <= limit, "CorpusAuxiliaryBodyQuotaExceeded");
    }
    while let Some(chunk) = response.chunk().await? {
        stage = tokio::task::spawn_blocking(move || {
            stage.write_chunk(&chunk)?;
            Ok::<_, anyhow::Error>(stage)
        })
        .await??;
    }
    let body = tokio::task::spawn_blocking(move || {
        stage.expected.bytes = stage.written;
        stage.expected.sha256 = hex::encode(stage.hash.clone().finalize());
        stage.file.set_len(stage.written)?;
        let object = stage.expected.clone();
        stage.finish_with_pin(&store, true)?;
        Ok::<_, anyhow::Error>(object)
    })
    .await??;
    Ok(CorpusAuxSource {
        url: url.to_owned(),
        body,
        fetched_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    })
}

pub(crate) struct ObjectStage {
    path: PathBuf,
    file: File,
    expected: ObjectRef,
    hash: Sha256,
    written: u64,
}

impl ObjectStage {
    pub(crate) fn write_chunk(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        ensure!(
            bytes.len() as u64 <= self.expected.bytes.saturating_sub(self.written),
            "CorpusObjectOversize"
        );
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    pub(crate) fn finish(self, store: &CorpusStore) -> anyhow::Result<()> {
        self.finish_with_pin(store, false)
    }

    fn finish_with_pin(mut self, store: &CorpusStore, pin: bool) -> anyhow::Result<()> {
        ensure!(
            self.written == self.expected.bytes
                && hex::encode(self.hash.clone().finalize()) == self.expected.sha256,
            "CorpusObjectMismatch: digest or truncated body"
        );
        self.file.sync_all()?;
        verify_file(&mut self.file, &self.expected)?;
        let _guard = store.write_lock()?;
        let destination = store.object_path(&self.expected.sha256)?;
        if destination.try_exists()? {
            if store.verified_object(&self.expected).is_err() {
                let metadata = std::fs::symlink_metadata(&destination)?;
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "CorpusUnsafeObjectReplacement"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    ensure!(
                        metadata.uid() == unsafe { libc::geteuid() },
                        "CorpusUnownedObjectReplacement"
                    );
                }
                std::fs::rename(&self.path, &destination)?;
            }
        } else {
            std::fs::hard_link(&self.path, &destination)?;
        }
        File::open(store.root.join("objects"))?.sync_all()?;
        if pin {
            store.pin_object(&self.expected)?;
        }
        Ok(())
    }
}

impl Drop for ObjectStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct DirectoryLock(File);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn ensure_directory_durable(path: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    verify_directory(path)?;
    if created {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        open_directory(parent)?.sync_all()?;
    }
    Ok(())
}

fn verify_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "CorpusUnsafeDirectory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "CorpusUnprotectedDirectory"
        );
    }
    Ok(())
}

fn open_directory(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    Ok(options.open(path)?)
}

fn open_regular(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.is_file(), "CorpusNotRegularFile");
    Ok(file)
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let mut file = open_regular(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_MANIFEST_BYTES as u64,
        "CorpusMetadataQuotaExceeded"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "CorpusMetadataQuotaExceeded"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn verify_file(file: &mut File, expected: &ObjectRef) -> anyhow::Result<()> {
    ensure!(
        expected.bytes <= MAX_OBJECT_BYTES && file.metadata()?.len() == expected.bytes,
        "CorpusObjectSizeMismatch"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = expected.bytes;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let limit = (remaining as usize).min(buffer.len());
        let count = file.read(&mut buffer[..limit])?;
        ensure!(count > 0, "CorpusObjectTruncated");
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    ensure!(
        file.read(&mut buffer[..1])? == 0 && hex::encode(hash.finalize()) == expected.sha256,
        "CorpusObjectDigestMismatch"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;

#[cfg(test)]
mod durable_private_pin_tests {
    use super::*;

    fn identity(marker: char) -> ArtifactIdentity {
        let hash = marker.to_string().repeat(64);
        ArtifactIdentity {
            primary_lineage: hash.clone(),
            policy_epoch: 1,
            artifact_hash: hash.clone(),
            config_revision: hash.clone(),
            operator_policy_hash: hash,
        }
    }

    fn source(bytes: &[u8]) -> CorpusSource {
        CorpusSource {
            source: SourceIdentity {
                representative: "https://lists.example.test/private".into(),
                fetch_url: "https://lists.example.test/private".into(),
                canonical_url: "https://lists.example.test/private".into(),
                aliases: Vec::new(),
                ids: Vec::new(),
                max_entries: 100,
                update_interval_secs: 60,
                format: "Domains".into(),
                trust: "RemoteUnsigned".into(),
            },
            body: ObjectRef::of(bytes),
            fetched_at: 1_800_000_000,
        }
    }

    fn put(store: &CorpusStore, bytes: &[u8]) {
        let object = ObjectRef::of(bytes);
        let mut stage = store.stage(&object).unwrap();
        stage.write_chunk(bytes).unwrap();
        stage.finish(store).unwrap();
    }

    #[test]
    fn private_pin_survives_reopen_and_gc_until_release() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let private_body = b"private.example\n";
        let private_object = ObjectRef::of(private_body);
        let private =
            CorpusManifest::new(identity('a'), vec![source(private_body)], Vec::new()).unwrap();
        let owner = "11111111-1111-4111-8111-111111111111";

        let store = CorpusStore::open(&master).unwrap();
        put(&store, private_body);
        store
            .prepare_manifest_private_pinned(
                &private,
                owner,
                super::super::membership::now().unwrap() + 3_600,
            )
            .unwrap();
        let pair = store.pair_state().unwrap();
        assert_eq!(
            (pair.desired, pair.persisted, pair.active),
            (None, None, None)
        );
        drop(store);

        let store = CorpusStore::open(&master).unwrap();
        let installed_body = b"installed.example\n";
        put(&store, installed_body);
        let installed =
            CorpusManifest::new(identity('b'), vec![source(installed_body)], Vec::new()).unwrap();
        store.install_manifest(&installed).unwrap();
        assert_eq!(
            store
                .manifest_metadata(&private.generation)
                .unwrap()
                .generation,
            private.generation
        );
        assert!(store.has_object(&private_object));
        assert_ne!(
            store.pair_state().unwrap().desired.as_deref(),
            Some(private.generation.as_str())
        );
        drop(store);

        let store = CorpusStore::open(&master).unwrap();
        store.release_private_manifest_pin(owner).unwrap();
        store.release_private_manifest_pin(owner).unwrap();
        assert!(store.manifest_metadata(&private.generation).is_err());
        assert!(!store.has_object(&private_object));
        assert_eq!(store.collect_unreferenced().unwrap(), 0);
        assert_eq!(
            store.manifest(&installed.generation).unwrap().generation,
            installed.generation
        );
    }

    #[test]
    fn published_review_survives_policy_retirement_until_readiness_releases_its_pin() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let reviewed_body = b"reviewed.example\n";
        let reviewed_object = ObjectRef::of(reviewed_body);
        let reviewed =
            CorpusManifest::new(identity('a'), vec![source(reviewed_body)], Vec::new()).unwrap();
        let owner = "33333333-3333-4333-8333-333333333333";
        let store = CorpusStore::open(&master).unwrap();
        put(&store, reviewed_body);
        store
            .prepare_manifest_private_pinned(
                &reviewed,
                owner,
                super::super::membership::now().unwrap() + 3_600,
            )
            .unwrap();
        store.install_manifest(&reviewed).unwrap();
        store
            .mark_active(&reviewed.generation, &reviewed.artifact)
            .unwrap();
        assert!(!store
            .root
            .join("candidates")
            .join(&reviewed.generation)
            .exists());

        let current_body = b"current.example\n";
        put(&store, current_body);
        let current =
            CorpusManifest::new(identity('b'), vec![source(current_body)], Vec::new()).unwrap();
        store.install_manifest(&current).unwrap();
        store
            .mark_active(&current.generation, &current.artifact)
            .unwrap();
        store
            .retain_policy_artifacts(&BTreeSet::from([current.artifact.artifact_hash.clone()]))
            .unwrap();
        drop(store);

        let store = CorpusStore::open(&master).unwrap();
        assert_eq!(store.manifest(&reviewed.generation).unwrap(), reviewed);
        assert!(store.has_object(&reviewed_object));
        assert_eq!(
            store.pair_state().unwrap().active,
            Some(current.generation.clone())
        );
        store.release_private_manifest_pin(owner).unwrap();
        store.release_private_manifest_pin(owner).unwrap();
        assert!(store.manifest_metadata(&reviewed.generation).is_err());
        assert!(!store.has_object(&reviewed_object));
        assert_eq!(store.manifest(&current.generation).unwrap(), current);
    }

    #[test]
    fn expired_private_pin_releases_candidate_and_object_without_sleeping() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let body = b"expires.example\n";
        let object = ObjectRef::of(body);
        let manifest = CorpusManifest::new(identity('c'), vec![source(body)], Vec::new()).unwrap();
        let owner = "22222222-2222-4222-8222-222222222222";
        let expires_at = super::super::membership::now().unwrap() + 3_600;
        let store = CorpusStore::open(&master).unwrap();
        put(&store, body);
        store
            .prepare_manifest_private_pinned(&manifest, owner, expires_at)
            .unwrap();

        {
            let _guard = store.write_lock().unwrap();
            store.prune_abandoned_candidates_at(expires_at).unwrap();
            store.collect_unreferenced_locked().unwrap();
        }

        assert!(!store.private_pin_path(owner).unwrap().try_exists().unwrap());
        assert!(store.manifest_metadata(&manifest.generation).is_err());
        assert!(!store.has_object(&object));
    }
}
