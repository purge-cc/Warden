use std::collections::BTreeSet;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHOICES_VERSION: u32 = 1;
pub const PLANNER_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationChoicesV1 {
    pub choices_version: u32,
    pub planner_version: u32,
    pub source_config_revision: String,
    #[serde(default)]
    pub list_mappings: Vec<MappingChoiceV1>,
    #[serde(default)]
    pub profile_mappings: Vec<MappingChoiceV1>,
    #[serde(default)]
    pub destination_mappings: Vec<MappingChoiceV1>,
    #[serde(default)]
    pub collision_resolutions: Vec<CollisionResolutionV1>,
    #[serde(default)]
    pub finding_decisions: Vec<FindingDecisionV1>,
}

impl MigrationChoicesV1 {
    pub fn empty(source_config_revision: impl Into<String>) -> Self {
        Self {
            choices_version: CHOICES_VERSION,
            planner_version: PLANNER_VERSION,
            source_config_revision: source_config_revision.into(),
            list_mappings: Vec::new(),
            profile_mappings: Vec::new(),
            destination_mappings: Vec::new(),
            collision_resolutions: Vec::new(),
            finding_decisions: Vec::new(),
        }
    }

    pub(crate) fn validate(&self, source_revision: &str) -> anyhow::Result<()> {
        ensure!(
            self.choices_version == CHOICES_VERSION,
            "unsupported choices_version"
        );
        ensure!(
            self.planner_version == PLANNER_VERSION,
            "choices require another planner"
        );
        ensure!(
            self.source_config_revision == source_revision,
            "StaleChoices: source_config_revision does not match the current source tree"
        );
        validate_unique(&self.list_mappings, "list mapping")?;
        validate_unique(&self.profile_mappings, "profile mapping")?;
        validate_unique(&self.destination_mappings, "destination mapping")?;
        let mut collisions = BTreeSet::new();
        for choice in &self.collision_resolutions {
            crate::config::schema::Id::new(choice.target_id.clone())
                .with_context(|| format!("invalid collision target for {}", choice.source_id))?;
            ensure!(
                collisions.insert((choice.kind, choice.source_id.as_str())),
                "duplicate collision resolution for {}",
                choice.source_id
            );
        }
        let mut findings = BTreeSet::new();
        for decision in &self.finding_decisions {
            ensure!(
                !decision.finding_id.is_empty() && findings.insert(decision.finding_id.as_str()),
                "duplicate or empty finding decision"
            );
            match &decision.decision {
                MigrationDecisionV1::ReplaceMapping { target_id, .. } => {
                    crate::config::schema::Id::new(target_id.clone())
                        .context("invalid replacement mapping target")?;
                }
                MigrationDecisionV1::RepairInactiveRows { repairs } => {
                    ensure!(
                        !repairs.is_empty(),
                        "repair_inactive_rows requires exact rows"
                    );
                    let mut rows = BTreeSet::new();
                    for repair in repairs {
                        ensure!(repair.line != 0, "row_ref lines are one-based");
                        ensure!(is_hash(&repair.row_digest), "invalid row digest");
                        ensure!(
                            rows.insert((repair.list_id.as_str(), repair.line)),
                            "duplicate repaired row"
                        );
                    }
                }
                MigrationDecisionV1::AcceptV5Semantics | MigrationDecisionV1::Defer => {}
            }
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> anyhow::Result<String> {
        let mut canonical = self.clone();
        canonical.list_mappings.sort();
        canonical.profile_mappings.sort();
        canonical.destination_mappings.sort();
        canonical.collision_resolutions.sort();
        canonical
            .finding_decisions
            .sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        let bytes = serde_json::to_vec(&canonical)?;
        let mut hash = Sha256::new();
        hash.update(b"warden/uor/migration-choices/v1\0");
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(hex(&hash.finalize()))
    }
}

fn validate_unique(values: &[MappingChoiceV1], label: &str) -> anyhow::Result<()> {
    let mut sources = BTreeSet::new();
    for value in values {
        crate::config::schema::Id::new(value.target_id.clone())
            .with_context(|| format!("invalid {label} target for {}", value.source_id))?;
        ensure!(
            !value.source_id.is_empty() && sources.insert(value.source_id.as_str()),
            "duplicate or empty {label} source"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingChoiceV1 {
    pub source_id: String,
    pub target_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationMappingKindV1 {
    ProfileList,
    DeviceList,
    DeviceClone,
    UnmountedArchive,
}

impl MigrationMappingKindV1 {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::ProfileList => "p",
            Self::DeviceList => "d",
            Self::DeviceClone => "c",
            Self::UnmountedArchive => "u",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollisionResolutionV1 {
    pub kind: MigrationMappingKindV1,
    pub source_id: String,
    pub target_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingDecisionV1 {
    pub finding_id: String,
    #[serde(flatten)]
    pub decision: MigrationDecisionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrationDecisionV1 {
    AcceptV5Semantics,
    ReplaceMapping {
        kind: MigrationMappingKindV1,
        source_id: String,
        target_id: String,
    },
    RepairInactiveRows {
        repairs: Vec<InactiveRowRepairV1>,
    },
    Defer,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InactiveRowRepairV1 {
    pub list_id: String,
    pub line: usize,
    pub row_digest: String,
    #[serde(default)]
    pub replacement: Option<String>,
}

pub(crate) fn row_digest(row: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"warden/uor/migration-row/v1\0");
    hash.update((row.len() as u64).to_be_bytes());
    hash.update(row.as_bytes());
    hex(&hash.finalize())
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_independent_but_choice_sensitive() {
        let mut first = MigrationChoicesV1::empty("a".repeat(64));
        first.list_mappings = vec![
            MappingChoiceV1 {
                source_id: "b".into(),
                target_id: "two".into(),
            },
            MappingChoiceV1 {
                source_id: "a".into(),
                target_id: "one".into(),
            },
        ];
        let mut reordered = first.clone();
        reordered.list_mappings.reverse();
        assert_eq!(first.digest().unwrap(), reordered.digest().unwrap());
        reordered.list_mappings[0].target_id = "three".into();
        assert_ne!(first.digest().unwrap(), reordered.digest().unwrap());
    }
}
