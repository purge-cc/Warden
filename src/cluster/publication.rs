//! Durable publication identity, immutable objects, and availability promises.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::store::PrivateStore;
use crate::config::write_lock::MigrationWriteLock;

pub(crate) const STORE_DIR: &str = ".warden-cluster-publications";
pub(crate) const AVAILABILITY_SECONDS: u64 = 24 * 60 * 60;
const STATE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PREPARATION_PROOF_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 80 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const MAX_OBJECTS_PER_ARTIFACT: usize = 1001;
const MAX_STORE_ENTRIES: usize = 65536;

/// Complete candidate bytes captured before any mutable policy is promoted.
pub(crate) struct PublicationCandidate {
    pub artifact_hash: String,
    pub config_revision: String,
    pub manifest: Vec<u8>,
    pub objects: BTreeMap<String, Arc<[u8]>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub primary_lineage: String,
    pub policy_epoch: u64,
    pub artifact_hash: String,
    pub config_revision: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PublishedArtifact {
    pub reservation: Reservation,
    pub manifest: Vec<u8>,
    pub receipt_id: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ManifestDelivery {
    pub artifact: PublishedArtifact,
    pub available_until: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    primary_lineage: String,
    high_water: u64,
    clock_watermark: u64,
    records: BTreeMap<u64, Record>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    reservation: Reservation,
    manifest_digest: String,
    manifest_bytes: u64,
    objects: BTreeMap<String, u64>,
    #[serde(default)]
    operation_manifest: Option<serde_json::Value>,
    #[serde(default)]
    preparation_proof: Option<serde_json::Value>,
    committed: Option<Commit>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    receipt_id: String,
    committed_at: u64,
    available_until: u64,
}

pub(crate) struct PublicationStore<'g> {
    files: PrivateStore<'g>,
    state: State,
    // An uncertain rename/fsync result requires reopening authoritative state.
    poisoned: bool,
    byte_limit: u64,
}

impl<'g> PublicationStore<'g> {
    pub(crate) fn retained_artifact_hashes(&self) -> std::collections::BTreeSet<String> {
        self.state
            .records
            .values()
            .map(|record| record.reservation.artifact_hash.clone())
            .collect()
    }

    pub(crate) fn open(guard: &'g MigrationWriteLock) -> anyhow::Result<Self> {
        let files = PrivateStore::open(guard, STORE_DIR)?;
        let state = match files.read(STATE, MAX_STATE_BYTES)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).context("invalid cluster publication state")?
            }
            None => {
                ensure!(
                    files.names(MAX_STORE_ENTRIES)?.is_empty(),
                    "publication state missing from nonempty store"
                );
                let mut lineage = [0_u8; 32];
                rand_core::OsRng
                    .try_fill_bytes(&mut lineage)
                    .map_err(|error| anyhow::anyhow!("cannot generate primary lineage: {error}"))?;
                let state = State {
                    format: 1,
                    primary_lineage: hex::encode(lineage),
                    high_water: 0,
                    clock_watermark: 0,
                    records: BTreeMap::new(),
                };
                files.create(STATE, &serde_json::to_vec(&state)?)?;
                state
            }
        };
        validate_state(&state)?;
        let store = Self {
            files,
            state,
            poisoned: false,
            byte_limit: MAX_STORE_BYTES,
        };
        store.collect_orphans()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn reserve(
        &mut self,
        build: impl FnOnce(&str, u64) -> anyhow::Result<PublicationCandidate>,
    ) -> anyhow::Result<Reservation> {
        self.reserve_record(
            |lineage, epoch| Ok((build(lineage, epoch)?, None, None)),
            None,
        )
    }

    pub(crate) fn reserve_bound(
        &mut self,
        build: impl FnOnce(
            &str,
            u64,
        ) -> anyhow::Result<(
            PublicationCandidate,
            serde_json::Value,
            serde_json::Value,
        )>,
    ) -> anyhow::Result<Reservation> {
        self.reserve_record(
            |lineage, epoch| {
                let (candidate, envelope, proof) = build(lineage, epoch)?;
                Ok((candidate, Some(envelope), Some(proof)))
            },
            None,
        )
    }

    pub(crate) fn publish_capture(
        &mut self,
        build: impl FnOnce(&str, u64) -> anyhow::Result<PublicationCandidate>,
        receipt_id: &str,
    ) -> anyhow::Result<Reservation> {
        validate_receipt_id(receipt_id)?;
        let now = unix_seconds()?.max(self.state.clock_watermark);
        self.reserve_record(
            |lineage, epoch| Ok((build(lineage, epoch)?, None, None)),
            Some(Commit {
                receipt_id: receipt_id.to_owned(),
                committed_at: now,
                available_until: now.saturating_add(AVAILABILITY_SECONDS),
            }),
        )
    }

    fn reserve_record(
        &mut self,
        build: impl FnOnce(
            &str,
            u64,
        ) -> anyhow::Result<(
            PublicationCandidate,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
        )>,
        committed: Option<Commit>,
    ) -> anyhow::Result<Reservation> {
        self.check()?;
        self.collect_orphans()?;
        ensure!(
            self.state.records.len() < MAX_RECORDS,
            "publication reservation capacity exhausted"
        );
        let epoch = self
            .state
            .high_water
            .checked_add(1)
            .context("publication epoch exhausted")?;
        let (candidate, operation_manifest, preparation_proof) =
            build(&self.state.primary_lineage, epoch)?;
        validate_candidate(&candidate)?;
        ensure!(
            self.state
                .records
                .values()
                .all(|record| record.reservation.artifact_hash != candidate.artifact_hash),
            "artifact identity already reserved"
        );
        let reservation = Reservation {
            primary_lineage: self.state.primary_lineage.clone(),
            policy_epoch: epoch,
            artifact_hash: candidate.artifact_hash.clone(),
            config_revision: candidate.config_revision,
        };
        if let Some(envelope) = &operation_manifest {
            validate_operation_manifest(&reservation, envelope)?;
        }
        if let Some(proof) = &preparation_proof {
            validate_preparation_proof(proof)?;
        }
        let record = Record {
            reservation: reservation.clone(),
            manifest_digest: digest(&candidate.manifest),
            manifest_bytes: candidate.manifest.len() as u64,
            objects: candidate
                .objects
                .iter()
                .map(|(hash, bytes)| (hash.clone(), bytes.len() as u64))
                .collect(),
            operation_manifest,
            preparation_proof,
            committed,
        };
        let mut next = self.state.clone();
        next.high_water = epoch;
        if let Some(commit) = &record.committed {
            next.clock_watermark = next.clock_watermark.max(commit.committed_at);
        }
        next.records.insert(epoch, record.clone());
        self.admit(&next)?;

        let mut allocated = self.state.clone();
        allocated.high_water = epoch;
        self.persist(allocated)?;
        fault(PublicationBoundary::EpochReserved)?;
        for (hash, bytes) in &candidate.objects {
            self.create_immutable(&object_name(hash), bytes, MAX_OBJECT_BYTES)?;
        }
        self.create_immutable(
            &manifest_name(&candidate.artifact_hash),
            &candidate.manifest,
            MAX_MANIFEST_BYTES,
        )?;
        fault(PublicationBoundary::CandidatePersisted)?;
        self.persist(next)?;
        fault(PublicationBoundary::ReservationPersisted)?;
        Ok(reservation)
    }

    #[cfg(test)]
    pub(crate) fn bind_intent(
        &mut self,
        reservation: &Reservation,
        operation_manifest: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.bind(reservation, operation_manifest, None)
    }

    #[cfg(test)]
    fn bind(
        &mut self,
        reservation: &Reservation,
        operation_manifest: serde_json::Value,
        preparation_proof: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        self.check()?;
        let record = self.record(reservation)?;
        validate_operation_manifest(reservation, &operation_manifest)?;
        if let Some(existing) = &record.operation_manifest {
            ensure!(
                existing == &operation_manifest && record.preparation_proof == preparation_proof,
                "publication operation manifest association mismatch"
            );
            return Ok(());
        }
        ensure!(
            record.committed.is_none(),
            "cannot attach an intent to a committed publication"
        );
        let mut next = self.state.clone();
        let record = next
            .records
            .get_mut(&reservation.policy_epoch)
            .context("reservation disappeared")?;
        record.operation_manifest = Some(operation_manifest);
        record.preparation_proof = preparation_proof;
        self.admit(&next)?;
        self.persist(next)?;
        fault(PublicationBoundary::IntentPersisted)?;
        Ok(())
    }

    /// Return recovery candidates without treating their envelopes as commit proof.
    pub(crate) fn pending_intents(&self) -> anyhow::Result<Vec<(Reservation, serde_json::Value)>> {
        self.check()?;
        Ok(self
            .state
            .records
            .values()
            .filter(|record| record.committed.is_none())
            .filter_map(|record| {
                record
                    .operation_manifest
                    .as_ref()
                    .map(|manifest| (record.reservation.clone(), manifest.clone()))
            })
            .collect())
    }

    /// Retain the original binding when a committed publication is finalized again.
    #[allow(dead_code, reason = "publication finalization coordinator interface")]
    pub(crate) fn bound_intent(
        &self,
        reservation: &Reservation,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        self.check()?;
        Ok(self.record(reservation)?.operation_manifest.clone())
    }

    pub(crate) fn preparation_proof(
        &self,
        reservation: &Reservation,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        self.check()?;
        Ok(self.record(reservation)?.preparation_proof.clone())
    }

    /// Commit only a reservation whose policy receipt was independently verified.
    pub(crate) fn commit(
        &mut self,
        reservation: &Reservation,
        receipt_id: &str,
    ) -> anyhow::Result<()> {
        self.commit_at(reservation, receipt_id, unix_seconds()?)
    }

    fn commit_at(
        &mut self,
        reservation: &Reservation,
        receipt_id: &str,
        now: u64,
    ) -> anyhow::Result<()> {
        self.check()?;
        validate_receipt_id(receipt_id)?;
        let record = self.record(reservation)?;
        if let Some(commit) = &record.committed {
            ensure!(
                commit.receipt_id == receipt_id,
                "publication receipt association mismatch"
            );
            self.verify_artifact(record)?;
            return Ok(());
        }
        self.verify_artifact(record)?;
        fault(PublicationBoundary::BeforeCommit)?;
        let now = now.max(self.state.clock_watermark);
        let mut next = self.state.clone();
        next.clock_watermark = now;
        next.records
            .get_mut(&reservation.policy_epoch)
            .context("reservation disappeared")?
            .committed = Some(Commit {
            receipt_id: receipt_id.to_owned(),
            committed_at: now,
            available_until: now.saturating_add(AVAILABILITY_SECONDS),
        });
        self.admit(&next)?;
        self.persist(next)?;
        fault(PublicationBoundary::Committed)?;
        Ok(())
    }

    pub(crate) fn abort(&mut self, reservation: &Reservation) -> anyhow::Result<()> {
        self.check()?;
        let record = self.record(reservation)?;
        ensure!(
            record.committed.is_none(),
            "cannot abort a committed publication"
        );
        let mut next = self.state.clone();
        next.records.remove(&reservation.policy_epoch);
        self.persist(next)?;
        self.collect_orphans()
    }

    pub(crate) fn current(&self) -> anyhow::Result<Option<PublishedArtifact>> {
        self.check()?;
        self.state
            .records
            .values()
            .rev()
            .find(|record| record.committed.is_some())
            .map(|record| self.published(record))
            .transpose()
    }

    #[allow(dead_code, reason = "retained publication revision lookup API")]
    pub(crate) fn find_committed_revision(
        &self,
        revision: &str,
    ) -> anyhow::Result<Option<PublishedArtifact>> {
        self.check()?;
        self.state
            .records
            .values()
            .rev()
            .find(|record| {
                record.committed.is_some() && record.reservation.config_revision == revision
            })
            .map(|record| self.published(record))
            .transpose()
    }

    pub(crate) fn deliver_manifest(
        &mut self,
        hash: &str,
        now: u64,
    ) -> anyhow::Result<ManifestDelivery> {
        self.check()?;
        let record = self.committed_hash(hash)?;
        let artifact = self.published(record)?;
        let now = now.max(self.state.clock_watermark);
        let available_until = record
            .committed
            .as_ref()
            .context("publication not committed")?
            .available_until
            .max(now.saturating_add(AVAILABILITY_SECONDS));
        let mut next = self.state.clone();
        next.clock_watermark = now;
        next.records
            .get_mut(&artifact.reservation.policy_epoch)
            .and_then(|record| record.committed.as_mut())
            .context("publication disappeared")?
            .available_until = available_until;
        self.admit(&next)?;
        self.persist(next)?;
        fault(PublicationBoundary::PromisePersisted)?;
        Ok(ManifestDelivery {
            artifact,
            available_until,
        })
    }

    /// Owned bytes remain pinned through a response even after its store closes.
    pub(crate) fn object(
        &self,
        artifact_hash: &str,
        object_digest: &str,
    ) -> anyhow::Result<Arc<[u8]>> {
        self.check()?;
        ensure!(is_hash(object_digest), "invalid object digest");
        let record = self.committed_hash(artifact_hash)?;
        let expected = record
            .objects
            .get(object_digest)
            .context("object is not referenced by artifact")?;
        let bytes = self.read_object(object_digest, *expected)?;
        Ok(Arc::from(bytes))
    }

    pub(crate) fn gc(&mut self, now: u64) -> anyhow::Result<()> {
        self.check()?;
        let now = now.max(self.state.clock_watermark);
        let last_two: BTreeSet<_> = self
            .state
            .records
            .iter()
            .rev()
            .filter(|(_, record)| record.committed.is_some())
            .take(2)
            .map(|(epoch, _)| *epoch)
            .collect();
        let mut next = self.state.clone();
        next.clock_watermark = now;
        next.records
            .retain(|epoch, record| match &record.committed {
                Some(commit) => commit.available_until > now || last_two.contains(epoch),
                // A policy transaction requires a durable operation binding first.
                // An unbound record owns only private, unadvertised artifact objects.
                None => record.operation_manifest.is_some(),
            });
        self.persist(next)?;
        fault(PublicationBoundary::GcPersisted)?;
        self.collect_orphans()
    }

    fn check(&self) -> anyhow::Result<()> {
        ensure!(
            !self.poisoned,
            "publication store requires recovery after an uncertain write"
        );
        self.files.check()
    }

    fn persist(&mut self, next: State) -> anyhow::Result<()> {
        self.check()?;
        validate_state(&next)?;
        let bytes = encode_state(&next)?;
        self.poisoned = true;
        self.files.write(STATE, &bytes)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    fn record(&self, reservation: &Reservation) -> anyhow::Result<&Record> {
        let record = self
            .state
            .records
            .get(&reservation.policy_epoch)
            .context("unknown publication reservation")?;
        ensure!(
            &record.reservation == reservation,
            "publication reservation association mismatch"
        );
        Ok(record)
    }

    fn committed_hash(&self, hash: &str) -> anyhow::Result<&Record> {
        ensure!(is_hash(hash), "invalid artifact hash");
        self.state
            .records
            .values()
            .find(|record| record.reservation.artifact_hash == hash && record.committed.is_some())
            .context("artifact is not available")
    }

    fn published(&self, record: &Record) -> anyhow::Result<PublishedArtifact> {
        let commit = record
            .committed
            .as_ref()
            .context("publication not committed")?;
        let manifest = self.verify_artifact(record)?;
        Ok(PublishedArtifact {
            reservation: record.reservation.clone(),
            manifest,
            receipt_id: commit.receipt_id.clone(),
        })
    }

    fn verify_artifact(&self, record: &Record) -> anyhow::Result<Vec<u8>> {
        let manifest = self
            .files
            .read(
                &manifest_name(&record.reservation.artifact_hash),
                MAX_MANIFEST_BYTES,
            )?
            .context("publication manifest missing")?;
        ensure!(
            manifest.len() as u64 == record.manifest_bytes
                && digest(&manifest) == record.manifest_digest,
            "publication manifest digest or size mismatch"
        );
        for (hash, size) in &record.objects {
            self.read_object(hash, *size)?;
        }
        Ok(manifest)
    }

    fn read_object(&self, hash: &str, expected: u64) -> anyhow::Result<Vec<u8>> {
        let bytes = self
            .files
            .read(&object_name(hash), MAX_OBJECT_BYTES)?
            .context("publication object missing")?;
        ensure!(
            bytes.len() as u64 == expected && digest(&bytes) == hash,
            "publication object digest or size mismatch"
        );
        Ok(bytes)
    }

    fn create_immutable(&self, name: &str, bytes: &[u8], limit: u64) -> anyhow::Result<()> {
        match self.files.read(name, limit)? {
            Some(existing) => ensure!(existing == bytes, "immutable publication object changed"),
            None => self.files.create(name, bytes)?,
        }
        Ok(())
    }

    fn admit(&self, state: &State) -> anyhow::Result<()> {
        let mut objects = BTreeMap::new();
        let mut bytes = encode_state(state)?.len() as u64;
        let mut manifests = 0_usize;
        for record in state.records.values() {
            bytes = bytes
                .checked_add(record.manifest_bytes)
                .context("publication size overflow")?;
            manifests += 1;
            for (hash, size) in &record.objects {
                if let Some(previous) = objects.insert(hash, size) {
                    ensure!(previous == size, "shared object size disagreement");
                }
            }
        }
        for size in objects.values() {
            bytes = bytes
                .checked_add(**size)
                .context("publication size overflow")?;
        }
        ensure!(
            objects.len() + manifests < MAX_STORE_ENTRIES,
            "publication object count capacity exhausted"
        );
        ensure!(
            bytes <= self.byte_limit,
            "publication retention capacity exhausted"
        );
        Ok(())
    }

    fn collect_orphans(&self) -> anyhow::Result<()> {
        self.check()?;
        let mut referenced = BTreeSet::from([STATE.to_owned()]);
        for record in self.state.records.values() {
            referenced.insert(manifest_name(&record.reservation.artifact_hash));
            referenced.extend(record.objects.keys().map(|hash| object_name(hash)));
        }
        let names = self.files.names(MAX_STORE_ENTRIES)?;
        let present: BTreeSet<_> = names.iter().cloned().collect();
        ensure!(
            referenced.is_subset(&present),
            "publication store is missing referenced files"
        );
        for name in names {
            if referenced.contains(&name) {
                continue;
            }
            let hash = name
                .strip_prefix("object-")
                .or_else(|| name.strip_prefix("manifest-"))
                .context("unexpected publication store entry")?;
            ensure!(is_hash(hash), "invalid publication store entry");
            self.files.remove(&name)?;
        }
        Ok(())
    }
}

fn validate_candidate(candidate: &PublicationCandidate) -> anyhow::Result<()> {
    ensure!(
        is_hash(&candidate.artifact_hash) && is_hash(&candidate.config_revision),
        "invalid candidate identity"
    );
    ensure!(
        !candidate.manifest.is_empty() && candidate.manifest.len() as u64 <= MAX_MANIFEST_BYTES,
        "manifest size limit exceeded"
    );
    ensure!(
        !candidate.objects.is_empty() && candidate.objects.len() <= MAX_OBJECTS_PER_ARTIFACT,
        "artifact object count limit exceeded"
    );
    let mut total = 0_u64;
    for (hash, bytes) in &candidate.objects {
        ensure!(
            is_hash(hash) && digest(bytes) == *hash,
            "candidate object digest mismatch"
        );
        ensure!(
            bytes.len() as u64 <= MAX_OBJECT_BYTES,
            "artifact object byte limit exceeded"
        );
        total = total
            .checked_add(bytes.len() as u64)
            .context("artifact size overflow")?;
    }
    ensure!(total <= MAX_ARTIFACT_BYTES, "artifact byte limit exceeded");
    Ok(())
}

fn validate_state(state: &State) -> anyhow::Result<()> {
    ensure!(
        state.format == 1 && is_hash(&state.primary_lineage),
        "invalid publication state identity"
    );
    ensure!(
        state.records.len() <= MAX_RECORDS,
        "publication record limit exceeded"
    );
    let mut hashes = BTreeSet::new();
    for (epoch, record) in &state.records {
        let reservation = &record.reservation;
        ensure!(
            *epoch > 0
                && *epoch <= state.high_water
                && *epoch == reservation.policy_epoch
                && reservation.primary_lineage == state.primary_lineage
                && is_hash(&reservation.artifact_hash)
                && is_hash(&reservation.config_revision)
                && hashes.insert(&reservation.artifact_hash),
            "invalid publication reservation association"
        );
        ensure!(
            is_hash(&record.manifest_digest)
                && (1..=MAX_MANIFEST_BYTES).contains(&record.manifest_bytes),
            "invalid stored manifest descriptor"
        );
        ensure!(
            !record.objects.is_empty() && record.objects.len() <= MAX_OBJECTS_PER_ARTIFACT,
            "invalid stored object roster"
        );
        let mut total = 0_u64;
        for (hash, size) in &record.objects {
            ensure!(
                is_hash(hash) && *size <= MAX_OBJECT_BYTES,
                "invalid stored object descriptor"
            );
            total = total.checked_add(*size).context("artifact size overflow")?;
        }
        ensure!(
            total <= MAX_ARTIFACT_BYTES,
            "stored artifact exceeds byte limit"
        );
        if let Some(operation_manifest) = &record.operation_manifest {
            validate_operation_manifest(reservation, operation_manifest)?;
        }
        if let Some(proof) = &record.preparation_proof {
            ensure!(
                record.operation_manifest.is_some(),
                "publication proof has no operation binding"
            );
            validate_preparation_proof(proof)?;
        }
        if let Some(commit) = &record.committed {
            validate_receipt_id(&commit.receipt_id)?;
            ensure!(
                commit.committed_at <= state.clock_watermark
                    && commit.available_until
                        >= commit.committed_at.saturating_add(AVAILABILITY_SECONDS),
                "invalid stored availability promise"
            );
        }
    }
    Ok(())
}

fn validate_preparation_proof(proof: &serde_json::Value) -> anyhow::Result<()> {
    ensure!(
        proof.is_object(),
        "publication preparation proof must be an object"
    );
    struct Limited(u64);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len() as u64);
            if self.0 > MAX_PREPARATION_PROOF_BYTES {
                return Err(std::io::Error::other(
                    "publication preparation proof exceeds byte limit",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Limited(0), proof)?;
    Ok(())
}

fn validate_operation_manifest(
    reservation: &Reservation,
    manifest: &serde_json::Value,
) -> anyhow::Result<()> {
    let fields = manifest
        .as_object()
        .context("publication operation manifest must be an object")?;
    for name in ["actor", "request_id"] {
        validate_receipt_id(
            fields
                .get(name)
                .and_then(serde_json::Value::as_str)
                .context("publication operation request identity missing")?,
        )?;
    }
    for (name, expected) in [
        ("primary_lineage", reservation.primary_lineage.as_str()),
        ("artifact_hash", reservation.artifact_hash.as_str()),
        (
            "expected_after_revision",
            reservation.config_revision.as_str(),
        ),
    ] {
        ensure!(
            fields.get(name).and_then(serde_json::Value::as_str) == Some(expected),
            "publication operation manifest reservation mismatch: {name}"
        );
    }
    ensure!(
        fields
            .get("policy_epoch")
            .and_then(serde_json::Value::as_u64)
            == Some(reservation.policy_epoch),
        "publication operation manifest reservation mismatch: policy_epoch"
    );
    for name in ["config_revision", "source_config_revision"] {
        if let Some(value) = fields.get(name) {
            ensure!(
                value.as_str() == Some(reservation.config_revision.as_str()),
                "publication operation manifest reservation mismatch: {name}"
            );
        }
    }
    struct Limited(u64);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len() as u64);
            if self.0 > MAX_MANIFEST_BYTES {
                return Err(std::io::Error::other(
                    "publication operation manifest exceeds byte limit",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Limited(0), manifest)?;
    Ok(())
}

fn encode_state(state: &State) -> anyhow::Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_STATE_BYTES as usize {
                return Err(std::io::Error::other(
                    "publication state byte limit exceeded",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, state)?;
    Ok(output.0)
}

fn validate_receipt_id(value: &str) -> anyhow::Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid publication receipt identity"
    );
    Ok(())
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn object_name(hash: &str) -> String {
    format!("object-{hash}")
}
fn manifest_name(hash: &str) -> String {
    format!("manifest-{hash}")
}
fn unix_seconds() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationBoundary {
    EpochReserved,
    CandidatePersisted,
    ReservationPersisted,
    #[allow(dead_code, reason = "precommit publication fault boundary")]
    IntentPersisted,
    BeforeCommit,
    Committed,
    PromisePersisted,
    GcPersisted,
}

fn fault(boundary: PublicationBoundary) -> anyhow::Result<()> {
    #[cfg(test)]
    if FAILURE.with(|point| point.get() == Some(boundary)) {
        FAILURE.with(|point| point.set(None));
        if EXIT_ON_FAILURE.with(|exit| exit.get()) {
            unsafe { libc::_exit(77) };
        }
        anyhow::bail!("injected publication failure at {boundary:?}");
    }
    let _ = boundary;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::Cell<Option<PublicationBoundary>> = const { std::cell::Cell::new(None) };
    static EXIT_ON_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn kill_at_reservation_boundary(boundary: &str) {
    let boundary = match boundary {
        "epoch" => PublicationBoundary::EpochReserved,
        "candidate" => PublicationBoundary::CandidatePersisted,
        "reservation" => PublicationBoundary::ReservationPersisted,
        _ => panic!("unknown reservation boundary"),
    };
    EXIT_ON_FAILURE.with(|exit| exit.set(true));
    FAILURE.with(|point| point.set(Some(boundary)));
}

#[cfg(test)]
pub(super) fn fail_next_publication_for_test() {
    FAILURE.with(|point| point.set(Some(PublicationBoundary::CandidatePersisted)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_lock::acquire_for_migration;

    fn candidate(lineage: &str, epoch: u64, value: &[u8]) -> PublicationCandidate {
        let manifest = serde_json::to_vec(&(lineage, epoch, digest(value))).unwrap();
        PublicationCandidate {
            artifact_hash: digest(&manifest),
            config_revision: digest(value),
            manifest,
            objects: BTreeMap::from([(digest(value), Arc::from(value))]),
        }
    }

    fn reserve(store: &mut PublicationStore<'_>, value: &[u8]) -> Reservation {
        store
            .reserve(|lineage, epoch| Ok(candidate(lineage, epoch, value)))
            .unwrap()
    }

    fn publish(store: &mut PublicationStore<'_>, value: &[u8], now: u64) -> Reservation {
        let reservation = reserve(store, value);
        store
            .commit_at(
                &reservation,
                &format!("receipt-{}", reservation.policy_epoch),
                now,
            )
            .unwrap();
        reservation
    }

    fn operation_manifest(reservation: &Reservation) -> serde_json::Value {
        serde_json::json!({
            "format": 1,
            "operation": "cluster.artifact.publish",
            "actor": "cluster-publisher",
            "request_id": "publication-request",
            "primary_lineage": reservation.primary_lineage,
            "policy_epoch": reservation.policy_epoch,
            "artifact_hash": reservation.artifact_hash,
            "source_config_revision": reservation.config_revision,
            "expected_after_revision": reservation.config_revision,
        })
    }

    #[test]
    fn bound_intent_survives_restart_without_advertising_the_reservation() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"bound policy");
        let envelope = operation_manifest(&reservation);
        store.bind_intent(&reservation, envelope.clone()).unwrap();
        store.bind_intent(&reservation, envelope.clone()).unwrap();
        let orphan = reserve(&mut store, b"unbound policy");
        assert!(store.current().unwrap().is_none());
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        assert_eq!(
            store.pending_intents().unwrap(),
            vec![(reservation.clone(), envelope.clone())]
        );
        assert!(store.current().unwrap().is_none());
        store
            .commit_at(&reservation, "verified-bound-receipt", 100)
            .unwrap();
        store.bind_intent(&reservation, envelope.clone()).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        assert_eq!(store.current().unwrap().unwrap().reservation, reservation);
        store.abort(&orphan).unwrap();
        assert_eq!(reserve(&mut store, b"next policy").policy_epoch, 3);
        let committed = publish(&mut store, b"already committed", 101);
        assert!(store
            .bind_intent(&committed, operation_manifest(&committed))
            .is_err());
    }

    #[test]
    fn intent_binding_rejects_reservation_and_request_reassociation() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"policy");
        let envelope = operation_manifest(&reservation);
        let mut different = reservation.clone();
        different.config_revision = digest(b"different");
        assert!(store.bind_intent(&different, envelope.clone()).is_err());
        for name in [
            "primary_lineage",
            "artifact_hash",
            "config_revision",
            "source_config_revision",
            "expected_after_revision",
        ] {
            let mut changed = envelope.clone();
            changed[name] = digest(b"different").into();
            assert!(store.bind_intent(&reservation, changed).is_err());
        }
        let mut changed = envelope.clone();
        changed["policy_epoch"] = (reservation.policy_epoch + 1).into();
        assert!(store.bind_intent(&reservation, changed).is_err());
        let mut changed = envelope.clone();
        changed["actor"] = "".into();
        assert!(store.bind_intent(&reservation, changed).is_err());
        assert!(store
            .bind_intent(&reservation, serde_json::Value::Null)
            .is_err());
        assert!(store.pending_intents().unwrap().is_empty());
        store.bind_intent(&reservation, envelope.clone()).unwrap();
        for name in ["actor", "request_id"] {
            let mut changed = envelope.clone();
            changed[name] = "another-request".into();
            assert!(store.bind_intent(&reservation, changed).is_err());
        }
        assert_eq!(
            store.pending_intents().unwrap(),
            vec![(reservation, envelope)]
        );
    }

    #[test]
    fn intent_byte_and_store_caps_refuse_before_binding() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"policy");
        let mut oversized = operation_manifest(&reservation);
        oversized["padding"] = "x".repeat(MAX_MANIFEST_BYTES as usize).into();
        assert!(store.bind_intent(&reservation, oversized).is_err());
        store.byte_limit = 1;
        assert!(store
            .bind_intent(&reservation, operation_manifest(&reservation))
            .is_err());
        assert!(store.pending_intents().unwrap().is_empty());
        drop(store);
        let store = PublicationStore::open(&guard).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        assert_eq!(store.state.high_water, reservation.policy_epoch);
    }

    #[test]
    fn intent_persist_failure_recovers_the_same_private_envelope() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"policy");
        let envelope = operation_manifest(&reservation);
        FAILURE.with(|point| point.set(Some(PublicationBoundary::IntentPersisted)));
        assert!(store.bind_intent(&reservation, envelope.clone()).is_err());
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store.current().unwrap().is_none());
        assert_eq!(
            store.pending_intents().unwrap(),
            vec![(reservation.clone(), envelope.clone())]
        );
        store.bind_intent(&reservation, envelope).unwrap();
        assert_eq!(store.state.high_water, reservation.policy_epoch);
    }

    #[test]
    fn recovery_defaults_missing_intents_and_refuses_mismatched_envelopes() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"policy");
        let mut legacy = serde_json::to_value(&store.state).unwrap();
        legacy["records"]["1"]
            .as_object_mut()
            .unwrap()
            .remove("operation_manifest");
        store
            .files
            .write(STATE, &serde_json::to_vec(&legacy).unwrap())
            .unwrap();
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        store
            .bind_intent(&reservation, operation_manifest(&reservation))
            .unwrap();
        let mut corrupted = serde_json::to_value(&store.state).unwrap();
        corrupted["records"]["1"]["operation_manifest"]["artifact_hash"] =
            digest(b"different").into();
        store
            .files
            .write(STATE, &serde_json::to_vec(&corrupted).unwrap())
            .unwrap();
        drop(store);
        assert!(PublicationStore::open(&guard).is_err());
    }

    #[test]
    fn reservation_restarts_privately_and_commit_recovers_without_source_bytes() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let reservation = reserve(&mut store, b"captured policy");
        assert!(store.current().unwrap().is_none());
        assert!(store
            .object(&reservation.artifact_hash, &digest(b"captured policy"))
            .is_err());
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store.current().unwrap().is_none());
        store
            .commit_at(&reservation, "verified-receipt", 100)
            .unwrap();
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        let published = store.current().unwrap().unwrap();
        assert_eq!(published.reservation, reservation);
        assert_eq!(published.receipt_id, "verified-receipt");
        assert!(!published.manifest.is_empty());
        assert_eq!(
            store
                .find_committed_revision(&digest(b"captured policy"))
                .unwrap()
                .unwrap()
                .reservation,
            reservation
        );
        store
            .commit_at(&reservation, "verified-receipt", 200)
            .unwrap();
        assert!(store
            .commit_at(&reservation, "another-receipt", 200)
            .is_err());
    }

    #[test]
    fn failed_and_aborted_reservations_never_reuse_an_epoch() {
        for boundary in [
            PublicationBoundary::EpochReserved,
            PublicationBoundary::CandidatePersisted,
            PublicationBoundary::ReservationPersisted,
        ] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let mut store = PublicationStore::open(&guard).unwrap();
            FAILURE.with(|point| point.set(Some(boundary)));
            assert!(store
                .reserve(|lineage, epoch| Ok(candidate(lineage, epoch, b"failed")))
                .is_err());
            let lineage = store.state.primary_lineage.clone();
            drop(store);
            let mut store = PublicationStore::open(&guard).unwrap();
            assert!(store.current().unwrap().is_none());
            let next = reserve(&mut store, b"different");
            assert_eq!(next.policy_epoch, 2);
            assert_eq!(next.primary_lineage, lineage);
            store.abort(&next).unwrap();
            drop(store);
            let mut store = PublicationStore::open(&guard).unwrap();
            assert_eq!(reserve(&mut store, b"third").policy_epoch, 3);
        }
    }

    #[test]
    fn commit_boundary_has_one_receipt_association_after_restart() {
        for boundary in [
            PublicationBoundary::BeforeCommit,
            PublicationBoundary::Committed,
        ] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let mut store = PublicationStore::open(&guard).unwrap();
            let reservation = reserve(&mut store, b"policy");
            FAILURE.with(|point| point.set(Some(boundary)));
            assert!(store.commit_at(&reservation, "receipt", 100).is_err());
            drop(store);
            let mut store = PublicationStore::open(&guard).unwrap();
            assert_eq!(
                store.current().unwrap().is_some(),
                boundary == PublicationBoundary::Committed
            );
            store.commit_at(&reservation, "receipt", 100).unwrap();
            assert_eq!(store.current().unwrap().unwrap().reservation, reservation);
            let mut changed = reservation.clone();
            changed.artifact_hash = digest(b"different");
            assert!(store.commit_at(&changed, "receipt", 100).is_err());
        }
    }

    #[test]
    fn retention_promises_survive_restart_and_keep_last_two_and_response_pins() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let first = publish(&mut store, b"first", 100);
        let second = publish(&mut store, b"second", 101);
        let third = publish(&mut store, b"third", 102);
        let pin = store
            .object(&first.artifact_hash, &digest(b"first"))
            .unwrap();
        let (ready, started) = std::sync::mpsc::sync_channel(0);
        let (release, continue_reading) = std::sync::mpsc::sync_channel(0);
        let response = std::thread::spawn(move || {
            ready.send(()).unwrap();
            continue_reading.recv().unwrap();
            assert_eq!(&*pin, b"first");
        });
        started.recv().unwrap();
        let delivery = store.deliver_manifest(&first.artifact_hash, 1000).unwrap();
        assert_eq!(delivery.artifact.reservation, first);
        assert_eq!(delivery.available_until, 1000 + AVAILABILITY_SECONDS);
        let earlier = store.deliver_manifest(&first.artifact_hash, 1).unwrap();
        assert_eq!(earlier.available_until, delivery.available_until);
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        store.gc(999 + AVAILABILITY_SECONDS).unwrap();
        assert!(store
            .object(&first.artifact_hash, &digest(b"first"))
            .is_ok());
        store.gc(1000 + AVAILABILITY_SECONDS).unwrap();
        assert!(store
            .object(&first.artifact_hash, &digest(b"first"))
            .is_err());
        release.send(()).unwrap();
        response.join().unwrap();
        assert!(store
            .object(&second.artifact_hash, &digest(b"second"))
            .is_ok());
        assert!(store
            .object(&third.artifact_hash, &digest(b"third"))
            .is_ok());
        assert_eq!(store.current().unwrap().unwrap().reservation, third);
    }

    #[test]
    fn shared_objects_live_until_the_final_reference_expires() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let first = publish(&mut store, b"shared", 100);
        let shared = publish(&mut store, b"shared", 101);
        publish(&mut store, b"third", 102);
        store.gc(200 + AVAILABILITY_SECONDS).unwrap();
        assert!(store
            .object(&first.artifact_hash, &digest(b"shared"))
            .is_err());
        assert_eq!(
            &*store
                .object(&shared.artifact_hash, &digest(b"shared"))
                .unwrap(),
            b"shared"
        );
        publish(&mut store, b"fourth", 201 + AVAILABILITY_SECONDS);
        store.gc(202 + AVAILABILITY_SECONDS).unwrap();
        assert!(store
            .files
            .read(&object_name(&digest(b"shared")), 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn failed_promise_and_gc_boundaries_remain_safe_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let first = publish(&mut store, b"first", 100);
        publish(&mut store, b"second", 101);
        publish(&mut store, b"third", 102);
        FAILURE.with(|point| point.set(Some(PublicationBoundary::PromisePersisted)));
        assert!(store.deliver_manifest(&first.artifact_hash, 1000).is_err());
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        store.gc(999 + AVAILABILITY_SECONDS).unwrap();
        assert!(store
            .object(&first.artifact_hash, &digest(b"first"))
            .is_ok());
        FAILURE.with(|point| point.set(Some(PublicationBoundary::GcPersisted)));
        assert!(store.gc(1000 + AVAILABILITY_SECONDS).is_err());
        drop(store);
        let store = PublicationStore::open(&guard).unwrap();
        assert!(store
            .object(&first.artifact_hash, &digest(b"first"))
            .is_err());
        assert!(store
            .files
            .read(&object_name(&digest(b"first")), 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn capacity_refusal_precedes_reservation_and_promise() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        store.byte_limit = 1;
        assert!(store
            .reserve(|lineage, epoch| Ok(candidate(lineage, epoch, b"refused")))
            .is_err());
        assert_eq!(store.state.high_water, 0);
        store.byte_limit = MAX_STORE_BYTES;
        let first = publish(&mut store, b"first", 100);
        let before = store.state.records[&1]
            .committed
            .as_ref()
            .unwrap()
            .available_until;
        store.byte_limit = 1;
        assert!(store.deliver_manifest(&first.artifact_hash, 1000).is_err());
        assert_eq!(
            store.state.records[&1]
                .committed
                .as_ref()
                .unwrap()
                .available_until,
            before
        );
        assert_eq!(
            &*store
                .object(&first.artifact_hash, &digest(b"first"))
                .unwrap(),
            b"first"
        );
    }

    #[test]
    fn corruption_and_cross_artifact_reads_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let first = publish(&mut store, b"first", 100);
        publish(&mut store, b"second", 101);
        assert!(store
            .object(&first.artifact_hash, &digest(b"second"))
            .is_err());
        assert!(store.object(&first.artifact_hash, "../escape").is_err());
        store
            .files
            .write(&object_name(&digest(b"first")), b"wrong")
            .unwrap();
        assert!(store.deliver_manifest(&first.artifact_hash, 102).is_err());
        assert!(store
            .object(&first.artifact_hash, &digest(b"first"))
            .is_err());
    }

    #[test]
    fn invalid_candidate_never_allocates_an_identity() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store
            .reserve(|lineage, epoch| {
                let mut invalid = candidate(lineage, epoch, b"data");
                invalid
                    .objects
                    .insert(digest(b"other"), Arc::from(b"data".as_slice()));
                Ok(invalid)
            })
            .is_err());
        assert_eq!(reserve(&mut store, b"valid").policy_epoch, 1);
    }

    #[test]
    fn gc_retires_legacy_unbound_records_without_reusing_their_epoch() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        let unbound = reserve(&mut store, b"never bound");
        let bound = reserve(&mut store, b"bound intent");
        store
            .bind_intent(&bound, operation_manifest(&bound))
            .unwrap();
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        store.gc(100).unwrap();
        assert!(store.record(&unbound).is_err());
        assert_eq!(store.pending_intents().unwrap()[0].0, bound);
        assert!(store.current().unwrap().is_none());
        drop(store);
        let mut store = PublicationStore::open(&guard).unwrap();
        assert!(store.record(&unbound).is_err());
        assert_eq!(reserve(&mut store, b"never bound").policy_epoch, 3);
    }

    #[test]
    fn capture_record_is_committed_at_its_first_durable_boundary() {
        for boundary in [
            PublicationBoundary::EpochReserved,
            PublicationBoundary::CandidatePersisted,
            PublicationBoundary::ReservationPersisted,
        ] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let mut store = PublicationStore::open(&guard).unwrap();
            FAILURE.with(|point| point.set(Some(boundary)));
            assert!(store
                .publish_capture(
                    |lineage, epoch| Ok(candidate(lineage, epoch, b"capture")),
                    "capture-receipt"
                )
                .is_err());
            drop(store);
            let store = PublicationStore::open(&guard).unwrap();
            assert!(store.pending_intents().unwrap().is_empty());
            assert_eq!(
                store.current().unwrap().is_some(),
                boundary == PublicationBoundary::ReservationPersisted
            );
            assert!(store
                .state
                .records
                .values()
                .all(|record| record.committed.is_some()));
        }
    }

    #[test]
    fn publication_crash_child() {
        let Some(path) = std::env::var_os("WARDEN_PUBLICATION_CRASH_MASTER") else {
            return;
        };
        let boundary = match std::env::var("WARDEN_PUBLICATION_CRASH_BOUNDARY")
            .unwrap()
            .as_str()
        {
            "epoch" => PublicationBoundary::EpochReserved,
            "candidate" => PublicationBoundary::CandidatePersisted,
            "reservation" => PublicationBoundary::ReservationPersisted,
            "intent" => PublicationBoundary::IntentPersisted,
            "before_commit" => PublicationBoundary::BeforeCommit,
            "committed" => PublicationBoundary::Committed,
            other => panic!("unknown boundary {other}"),
        };
        let guard = acquire_for_migration(std::path::Path::new(&path)).unwrap();
        let mut store = PublicationStore::open(&guard).unwrap();
        EXIT_ON_FAILURE.with(|exit| exit.set(true));
        FAILURE.with(|point| point.set(Some(boundary)));
        let reservation = reserve(&mut store, b"child-policy");
        store
            .bind_intent(&reservation, operation_manifest(&reservation))
            .unwrap();
        store.commit_at(&reservation, "child-receipt", 100).unwrap();
        panic!("crash boundary was not reached");
    }

    #[test]
    fn process_death_preserves_epoch_and_never_promotes_a_reservation() {
        for boundary in [
            "epoch",
            "candidate",
            "reservation",
            "intent",
            "before_commit",
            "committed",
        ] {
            let root = tempfile::tempdir().unwrap();
            let master = root.path().join("config.toml");
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cluster::publication::tests::publication_crash_child",
                    "--nocapture",
                ])
                .env("WARDEN_PUBLICATION_CRASH_MASTER", &master)
                .env("WARDEN_PUBLICATION_CRASH_BOUNDARY", boundary)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(77),
                "{boundary}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let guard = acquire_for_migration(&master).unwrap();
            let mut store = PublicationStore::open(&guard).unwrap();
            assert_eq!(store.current().unwrap().is_some(), boundary == "committed");
            assert_eq!(
                store.pending_intents().unwrap().len(),
                usize::from(matches!(boundary, "intent" | "before_commit"))
            );
            let next = reserve(&mut store, b"parent-policy");
            assert_eq!(next.policy_epoch, 2);
        }
    }
}
