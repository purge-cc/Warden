//! Canonical, closed descriptions of immutable cluster policy objects.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::schema::Id;
use crate::filter::operator_rules::CompiledCostV1;

pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TOML_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_PACK_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_TOTAL_PACK_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_APPLY_BYTES: usize = 50 * 1024 * 1024;
pub(crate) const MAX_APPLY_FILES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectRef {
    pub sha256: String,
    pub bytes: u64,
}

impl ObjectRef {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            sha256: digest(bytes),
            bytes: bytes.len() as u64,
        }
    }

    pub fn verify(&self, bytes: &[u8], maximum: usize) -> anyhow::Result<()> {
        ensure!(bytes.len() <= maximum, "ArtifactLimitExceeded: object size");
        ensure!(
            self.bytes == bytes.len() as u64 && self.sha256 == digest(bytes),
            "ArtifactObjectMismatch: size or digest"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleRequirements {
    pub source_rules: u64,
    pub indexed: u64,
    pub advanced: u64,
    pub regex: u64,
    pub regex_source_bytes: u64,
    pub max_regex_source_bytes: u64,
    pub max_rule_bytes: u64,
    pub skipped_rows: u64,
}

impl RuleRequirements {
    pub fn add(&mut self, other: &Self) -> anyhow::Result<()> {
        macro_rules! sum { ($($field:ident),+) => { $(self.$field = self.$field.checked_add(other.$field).context("ArtifactLimitExceeded: counter overflow")?;)+ }; }
        sum!(
            source_rules,
            indexed,
            advanced,
            regex,
            regex_source_bytes,
            skipped_rows
        );
        self.max_regex_source_bytes = self
            .max_regex_source_bytes
            .max(other.max_regex_source_bytes);
        self.max_rule_bytes = self.max_rule_bytes.max(other.max_rule_bytes);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirements {
    pub version: u32,
    pub compiler_version: u32,
    pub pack_bytes: u64,
    pub store: RuleRequirements,
    pub profiles: BTreeMap<String, RuleRequirements>,
    pub packs: BTreeMap<String, RuleRequirements>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackRef {
    pub id: Id,
    pub sha256: String,
    pub bytes: u64,
}

impl PackRef {
    pub fn object(&self) -> ObjectRef {
        ObjectRef {
            sha256: self.sha256.clone(),
            bytes: self.bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub artifact_format: u32,
    pub schema_version: u32,
    pub operator_rule_grammar: String,
    pub compiled_cost_version: u32,
    pub primary_lineage: String,
    pub policy_epoch: u64,
    pub config_revision: String,
    pub operator_policy_hash: String,
    pub policy_toml: ObjectRef,
    pub packs: Vec<PackRef>,
    pub mounts: BTreeMap<String, Vec<Id>>,
    pub requirements: Requirements,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub artifact_hash: String,
}

impl Manifest {
    /// The wire structs fix field order; maps and ID arrays have canonical order.
    /// The hash field is absent from its own length-prefixed hash input.
    pub fn canonical_hash(&self) -> anyhow::Result<String> {
        let mut unsigned = self.clone();
        unsigned.artifact_hash.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "ArtifactLimitExceeded: manifest"
        );
        let mut hash = Sha256::new();
        hash.update(b"warden/uor/cluster-artifact/v2\0");
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(hex::encode(hash.finalize()))
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "ArtifactLimitExceeded: manifest"
        );
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "ArtifactLimitExceeded: manifest"
        );
        let result: Self = serde_json::from_slice(bytes)?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.artifact_format == 2
                && self.schema_version == crate::config::schema::TARGET_SCHEMA_VERSION_V5
                && self.operator_rule_grammar == "1"
                && self.compiled_cost_version == CompiledCostV1::VERSION
                && self.requirements.version == 1
                && self.requirements.compiler_version == 1,
            "ArtifactCapabilityMismatch: format, schema, grammar or cost version"
        );
        ensure!(
            is_hash(&self.artifact_hash)
                && is_hash(&self.config_revision)
                && is_hash(&self.operator_policy_hash)
                && is_hash(&self.policy_toml.sha256)
                && is_hash(&self.primary_lineage)
                && self.policy_epoch > 0,
            "ArtifactInvalidIdentity"
        );
        ensure!(
            self.policy_toml.bytes <= MAX_TOML_BYTES as u64 && self.packs.len() < MAX_APPLY_FILES,
            "ArtifactLimitExceeded: TOML or member count"
        );
        let mut previous = None;
        let mut total = 0_u64;
        let mut ids = BTreeSet::new();
        for pack in &self.packs {
            ensure!(
                previous.is_none_or(|id: &Id| id < &pack.id),
                "ArtifactInventoryMismatch: unordered or duplicate ID"
            );
            ensure!(
                is_hash(&pack.sha256) && pack.bytes <= MAX_PACK_BYTES as u64,
                "ArtifactLimitExceeded: pack"
            );
            total = total
                .checked_add(pack.bytes)
                .context("ArtifactLimitExceeded: pack bytes overflow")?;
            previous = Some(&pack.id);
            ids.insert(pack.id.as_str());
        }
        ensure!(
            total == self.requirements.pack_bytes
                && total <= MAX_TOTAL_PACK_BYTES as u64
                && total + self.policy_toml.bytes <= MAX_APPLY_BYTES as u64,
            "ArtifactLimitExceeded: aggregate apply bytes"
        );
        ensure!(
            ids == self.requirements.packs.keys().map(String::as_str).collect(),
            "ArtifactInventoryMismatch: pack requirements"
        );
        ensure!(
            self.mounts.keys().eq(self.requirements.profiles.keys()),
            "ArtifactInventoryMismatch: profile requirements"
        );
        for (profile, mounted) in &self.mounts {
            Id::new(profile).context("ArtifactInventoryMismatch: profile ID")?;
            ensure!(
                mounted.windows(2).all(|p| p[0] < p[1])
                    && mounted.iter().all(|id| ids.contains(id.as_str())),
                "ArtifactInventoryMismatch: missing or duplicate mount"
            );
        }
        ensure!(
            self.artifact_hash == self.canonical_hash()?,
            "ArtifactHashMismatch"
        );
        Ok(())
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
