//! Schema-5 data model for the current operator-policy runtime.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::blocklist::ListPolicy;
use super::custom_list::CustomList;
use super::{
    BackupConfig, BlockResponseV1, Blocklist, ClusterConfig, Group, Id, Label, NodeConfig,
    ProfileEcsConfig, ResourceBudgetConfig, RetiredEntry, Schedule, ServerGlobals, Subnet,
};
use crate::config::settings::{
    AntiBypassConfig, ApiConfig, CacheConfig, DnssecConfig, ForwardingZoneConfig,
    IpBlocklistConfig, ListsConfig, LocalDnsConfig, LocalDnsRecord, RewriteRule, SecurityConfig,
    SocketConfig, TrackingConfig, UpstreamConfig,
};

pub const TARGET_SCHEMA_VERSION_V5: u32 = 5;

/// Provenance for a profile snapshot created while removing a device overlay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOriginV1 {
    pub source_profile: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_group: Option<Id>,
    pub device_id: Id,
    pub source_policy_hash: String,
    /// Byte identities captured for every source-profile pack. A mismatch is
    /// evidence that semantic classification is required; it is not itself a
    /// policy-change verdict.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_pack_digests: BTreeMap<Id, String>,
    pub resolver_source_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_custom_lists: Vec<Id>,
}

macro_rules! target_limits {
    ($($name:ident: $default:expr),+ $(,)?) => {
        /// Node-local limits for declared packs and their compiled snapshots.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct CustomListLimitsV5 {
            $(pub $name: usize,)+
        }

        impl Default for CustomListLimitsV5 {
            fn default() -> Self {
                Self { $($name: $default,)+ }
            }
        }
    };
}

target_limits! {
    max_lists: 256,
    max_file_bytes: 1 << 20,
    max_total_bytes: 32 << 20,
    max_rules_per_list: 25_000,
    max_indexed_rules_per_profile: 100_000,
    max_indexed_rules_total: 500_000,
    max_advanced_rules_per_profile: 256,
    max_advanced_rules_total: 2_048,
    max_regex_rules_per_profile: 32,
    max_regex_rules_total: 128,
    max_store_indexed_rules: 500_000,
    max_store_advanced_rules: 2_048,
    max_store_regex_rules: 128,
    max_rule_bytes: 4_096,
    max_regex_program_bytes: 1 << 20,
    max_store_compiled_bytes: 32 << 20,
    max_compiled_bytes_per_profile: 8 << 20,
    max_compiled_bytes_total: 32 << 20,
}

/// A profile whose operator rules come only from mounted custom lists.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileV5 {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub block_response: Option<BlockResponseV1>,
    #[serde(default)]
    pub blocked_ttl_secs: Option<u32>,
    #[serde(default)]
    pub block_all: bool,
    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
    #[serde(default)]
    pub ecs: Option<ProfileEcsConfig>,
    #[serde(default)]
    pub rewrite_rules: Vec<RewriteRule>,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_lists: Vec<Id>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lists: BTreeMap<Id, ListPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_origin: Option<MigrationOriginV1>,
}

/// A device with identity, assignment and metadata but no rule overlay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceV5 {
    pub id: Id,
    pub display_name: String,
    #[serde(default)]
    pub ip: Option<IpAddr>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub mac_aliases: Vec<String>,
    #[serde(default)]
    pub profile: Option<Id>,
    #[serde(default)]
    pub groups: Vec<Id>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub unfiltered: bool,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub network_name_wildcard: bool,
}

/// Complete schema-5 configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV5 {
    pub schema_version: u32,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub server: ServerGlobals,
    #[serde(default)]
    pub retired: Vec<RetiredEntry>,
    #[serde(default)]
    pub blocklists: Vec<Blocklist>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileV5>,
    #[serde(default)]
    pub devices: Vec<DeviceV5>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub subnets: Vec<Subnet>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
    #[serde(default)]
    pub custom_lists: Vec<CustomList>,
    #[serde(default)]
    pub custom_list_limits: CustomListLimitsV5,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub tracking: TrackingConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub anti_bypass: AntiBypassConfig,
    #[serde(default)]
    pub socket: SocketConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub forwarding: Vec<ForwardingZoneConfig>,
    #[serde(default)]
    pub local_dns: LocalDnsConfig,
    #[serde(default)]
    pub ip_blocklists: IpBlocklistConfig,
    #[serde(default)]
    pub lists: ListsConfig,
    #[serde(default)]
    pub resource_budget: ResourceBudgetConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub node: NodeConfig,
}

impl Default for ConfigV5 {
    fn default() -> Self {
        Self {
            schema_version: TARGET_SCHEMA_VERSION_V5,
            includes: Vec::new(),
            server: ServerGlobals::default(),
            retired: Vec::new(),
            blocklists: Vec::new(),
            profiles: BTreeMap::new(),
            devices: Vec::new(),
            groups: Vec::new(),
            subnets: Vec::new(),
            schedules: Vec::new(),
            custom_lists: Vec::new(),
            custom_list_limits: CustomListLimitsV5::default(),
            labels: Vec::new(),
            upstream: UpstreamConfig::default(),
            dnssec: DnssecConfig::default(),
            cache: CacheConfig::default(),
            tracking: TrackingConfig::default(),
            security: SecurityConfig::default(),
            anti_bypass: AntiBypassConfig::default(),
            socket: SocketConfig::default(),
            api: ApiConfig::default(),
            forwarding: Vec::new(),
            local_dns: LocalDnsConfig::default(),
            ip_blocklists: IpBlocklistConfig::default(),
            lists: ListsConfig::default(),
            resource_budget: ResourceBudgetConfig::default(),
            backup: BackupConfig::default(),
            cluster: ClusterConfig::default(),
            node: NodeConfig::default(),
        }
    }
}

/// Top-level policy sections carried by a schema-5 replication artifact.
pub const TARGET_V5_REPLICATED_SECTIONS: &[&str] = &[
    "schema_version",
    "server",
    "retired",
    "blocklists",
    "profiles",
    "devices",
    "groups",
    "subnets",
    "schedules",
    "custom_lists",
    "labels",
    "upstream",
    "dnssec",
    "cache",
    "security",
    "anti_bypass",
    "forwarding",
    "local_dns",
    "ip_blocklists",
    "lists",
];

/// Sections whose values belong to the receiving node.
pub const TARGET_V5_NODE_LOCAL_SECTIONS: &[&str] = &[
    "custom_list_limits",
    "tracking",
    "socket",
    "api",
    "resource_budget",
    "backup",
    "cluster",
    "node",
];

/// Filesystem include expressions are resolved only by their local tree.
pub const TARGET_V5_SECTIONS_EXCLUDED_FROM_REPLICATION: &[&str] = &["includes"];
