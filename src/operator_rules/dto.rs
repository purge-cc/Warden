use serde::{Deserialize, Serialize};

pub const CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportLimits {
    pub max_operations: usize,
    pub default_page_size: usize,
    pub max_page_size: usize,
    pub max_response_bytes: usize,
    pub max_export_bytes: usize,
}
impl TransportLimits {
    pub const IPC: Self = Self {
        max_operations: 32,
        default_page_size: 50,
        max_page_size: 100,
        max_response_bytes: 60 * 1024,
        max_export_bytes: 16 * 1024,
    };
    pub const REST: Self = Self {
        max_operations: 256,
        default_page_size: 200,
        max_page_size: 500,
        max_response_bytes: 1024 * 1024,
        max_export_bytes: 1024 * 1024,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub identity: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub contract_version: u32,
    pub request_id: String,
    pub expected_config_revision: String,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub expected_plan_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    CreateList {
        id: String,
        #[serde(default)]
        display_name: String,
        #[serde(default)]
        description: String,
        #[serde(default)]
        into: Option<String>,
    },
    SetMetadata {
        id: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        description: Option<String>,
    },
    AddDomainRule {
        id: String,
        domain: String,
        action: RuleAction,
    },
    AddRawRule {
        id: String,
        rule: String,
    },
    ReplaceRule {
        id: String,
        row_ref: String,
        rule: String,
    },
    RemoveRule {
        id: String,
        row_ref: String,
    },
    Mount {
        id: String,
        profile_id: String,
    },
    Unmount {
        id: String,
        profile_id: String,
    },
    DeleteList {
        id: String,
        #[serde(default)]
        cascade_unmount: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub id: String,
    #[serde(default)]
    pub offset: usize,
    pub max_bytes: usize,
    #[serde(default)]
    pub expected_pack_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub contract_version: u32,
    pub schema_version: u32,
    pub operator_rule_grammar: u32,
    pub operations: Vec<String>,
    pub semantic_hash: bool,
    pub activation_ack: bool,
    pub cluster_artifact: bool,
    pub limits: TransportLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub contract_version: u32,
    pub schema_version: u32,
    pub config_revision: String,
    pub desired_operator_policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_policy: Option<super::activation::ActivePolicyIdentity>,
    pub activation_in_sync: bool,
    pub lists: usize,
    pub mounted_lists: usize,
    pub orphan_packs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListDetail {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub config_revision: String,
    pub pack_revision: String,
    pub bytes: usize,
    pub rule_count: usize,
    pub invalid_rows: usize,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListPage {
    pub contract_version: u32,
    pub config_revision: String,
    pub lists: Vec<ListDetail>,
    pub next_cursor: Option<String>,
    pub orphan_packs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleRow {
    pub line: usize,
    pub raw: String,
    pub row_ref: String,
    pub rule_key: Option<String>,
    pub action: Option<RuleAction>,
    pub valid: bool,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePage {
    pub contract_version: u32,
    pub id: String,
    pub config_revision: String,
    pub pack_revision: String,
    pub rows: Vec<RuleRow>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportChunk {
    pub contract_version: u32,
    pub id: String,
    pub pack_revision: String,
    pub offset: usize,
    pub total_bytes: usize,
    pub data_base64: String,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedExport {
    pub pack_revision: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub contract_version: u32,
    pub planner_version: u32,
    pub request: BatchRequest,
    pub base_config_revision: String,
    pub candidate_config_revision: String,
    pub base_operator_policy_hash: String,
    pub candidate_operator_policy_hash: String,
    pub semantic_diff: SemanticDiffSummary,
    pub plan_hash: String,
    pub changed: bool,
    pub touched_members: Vec<String>,
    pub impacted_profiles: Vec<String>,
    pub impacted_recipients: Vec<String>,
    pub pack_bytes_after: usize,
    pub rules_after: usize,
    pub warnings: Vec<String>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiffSummary {
    pub semantic_changed: bool,
    pub cosmetic_changed: bool,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub exact_changes: usize,
    pub wildcard_changes: usize,
    pub regex_changes: usize,
    pub changed_scopes: Vec<String>,
    pub omitted_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanSummary {
    pub contract_version: u32,
    pub plan_hash: String,
    pub base_config_revision: String,
    pub candidate_config_revision: String,
    pub base_operator_policy_hash: String,
    pub candidate_operator_policy_hash: String,
    pub semantic_changed: bool,
    pub cosmetic_changed: bool,
    pub changed: bool,
    pub operation_count: usize,
    pub touched_member_count: usize,
    pub impacted_profile_count: usize,
    pub impacted_recipient_count: usize,
    pub warning_count: usize,
    pub pack_bytes_after: usize,
    pub rules_after: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanImpactRow {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanImpactPage {
    pub contract_version: u32,
    pub plan_hash: String,
    pub rows: Vec<PlanImpactRow>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceState {
    Prepared,
    Committed,
    Aborted,
    DurabilityUncertain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub state: String,
    pub correlation_id: Option<String>,
    pub reload_outcome: Option<String>,
    pub active_config_revision: Option<String>,
    pub active_policy_hash: Option<String>,
    pub daemon_instance_id: Option<String>,
    pub superseded_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub contract_version: u32,
    pub operation_id: String,
    pub request_id: String,
    pub changed: bool,
    pub persistence: PersistenceState,
    pub config_revision: String,
    pub operator_policy_hash: Option<String>,
    pub activation: Activation,
    pub replication: String,
    pub audit: String,
    pub diagnostics: Vec<String>,
}
