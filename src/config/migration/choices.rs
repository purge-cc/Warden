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
#[serde(try_from = "FindingDecisionWire")]
pub struct FindingDecisionV1 {
    pub finding_id: String,
    #[serde(flatten)]
    pub decision: MigrationDecisionV1,
}

/// Read side of [`FindingDecisionV1`]. serde refuses every flattened key of
/// an internally tagged enum under `deny_unknown_fields`, so the flat wire
/// form is read here and each decision takes only its own fields. Serialize
/// stays on the derive: the choices digest and the plan hash depend on it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingDecisionWire {
    finding_id: String,
    decision: WireDecision,
    kind: Option<MigrationMappingKindV1>,
    source_id: Option<String>,
    target_id: Option<String>,
    repairs: Option<Vec<InactiveRowRepairV1>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireDecision {
    AcceptV5Semantics,
    ReplaceMapping,
    RepairInactiveRows,
    Defer,
}

impl TryFrom<FindingDecisionWire> for FindingDecisionV1 {
    type Error = String;

    fn try_from(wire: FindingDecisionWire) -> Result<Self, Self::Error> {
        use WireDecision as W;
        let FindingDecisionWire {
            finding_id,
            decision,
            kind,
            source_id,
            target_id,
            repairs,
        } = wire;
        let decision = match (decision, kind, source_id, target_id, repairs) {
            (W::AcceptV5Semantics, None, None, None, None) => {
                MigrationDecisionV1::AcceptV5Semantics
            }
            (W::ReplaceMapping, Some(kind), Some(source_id), Some(target_id), None) => {
                MigrationDecisionV1::ReplaceMapping {
                    kind,
                    source_id,
                    target_id,
                }
            }
            (W::RepairInactiveRows, None, None, None, Some(repairs)) => {
                MigrationDecisionV1::RepairInactiveRows { repairs }
            }
            (W::Defer, None, None, None, None) => MigrationDecisionV1::Defer,
            _ => {
                return Err(format!(
                    "finding decision for {finding_id} lacks a field its decision needs or has a field of another decision"
                ))
            }
        };
        Ok(Self {
            finding_id,
            decision,
        })
    }
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

    #[test]
    fn finding_decision_round_trips_every_variant() {
        // Golden values from the derive before the read side changed: the
        // choices digest and the plan hash serialize these types.
        let cases = [
            (
                FindingDecisionV1 {
                    finding_id: "f-accept".into(),
                    decision: MigrationDecisionV1::AcceptV5Semantics,
                },
                r#"{"finding_id":"f-accept","decision":"accept_v5_semantics"}"#.to_string(),
            ),
            (
                FindingDecisionV1 {
                    finding_id: "f-replace".into(),
                    decision: MigrationDecisionV1::ReplaceMapping {
                        kind: MigrationMappingKindV1::ProfileList,
                        source_id: "src".into(),
                        target_id: "dst".into(),
                    },
                },
                r#"{"finding_id":"f-replace","decision":"replace_mapping","kind":"profile_list","source_id":"src","target_id":"dst"}"#.to_string(),
            ),
            (
                FindingDecisionV1 {
                    finding_id: "f-repair".into(),
                    decision: MigrationDecisionV1::RepairInactiveRows {
                        repairs: vec![InactiveRowRepairV1 {
                            list_id: "list".into(),
                            line: 3,
                            row_digest: "a".repeat(64),
                            replacement: Some("example.com".into()),
                        }],
                    },
                },
                format!(
                    r#"{{"finding_id":"f-repair","decision":"repair_inactive_rows","repairs":[{{"list_id":"list","line":3,"row_digest":"{}","replacement":"example.com"}}]}}"#,
                    "a".repeat(64)
                ),
            ),
            (
                FindingDecisionV1 {
                    finding_id: "f-defer".into(),
                    decision: MigrationDecisionV1::Defer,
                },
                r#"{"finding_id":"f-defer","decision":"defer"}"#.to_string(),
            ),
        ];
        for (decision, golden) in &cases {
            assert_eq!(&serde_json::to_string(decision).unwrap(), golden);
            let parsed: FindingDecisionV1 = serde_json::from_str(golden).unwrap();
            assert_eq!(&parsed, decision);
        }
        let mut choices = MigrationChoicesV1::empty("b".repeat(64));
        choices.finding_decisions = cases.into_iter().map(|(decision, _)| decision).collect();
        assert_eq!(
            choices.digest().unwrap(),
            "4b3d3aaef7946e7b5c8015791690ec2e20d11127ec427e2deedaab546874c042"
        );
        let json = serde_json::to_string(&choices).unwrap();
        assert_eq!(
            serde_json::from_str::<MigrationChoicesV1>(&json).unwrap(),
            choices
        );
    }

    #[test]
    fn finding_decision_refuses_unknown_and_foreign_keys() {
        for json in [
            r#"{"finding_id":"f","decision":"defer","extra":1}"#,
            r#"{"finding_id":"f","decision":"accept_v5_semantics","kind":"profile_list"}"#,
            r#"{"finding_id":"f","decision":"defer","repairs":[]}"#,
            r#"{"finding_id":"f","decision":"replace_mapping","kind":"profile_list","target_id":"dst"}"#,
            r#"{"finding_id":"f","decision":"unknown"}"#,
        ] {
            assert!(
                serde_json::from_str::<FindingDecisionV1>(json).is_err(),
                "accepted {json}"
            );
        }
    }
}
