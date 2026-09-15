//! In-memory validation and compilation adapter for schema-5 candidates.

use std::collections::BTreeMap;
use std::sync::Arc;

use time::OffsetDateTime;

use super::error::ConfigError;
use super::schema::validator::AuditWarnings;
use super::schema::{
    validate_collect_for_schema, ConfigV1, ConfigV5, CustomListLimits, CustomListLimitsV5, Device,
    DeviceV5, Id, Profile, ProfileV5, TARGET_SCHEMA_VERSION_V5,
};
use super::secrets::Secrets;
use crate::filter::operator_rules::{
    BudgetExceeded, CompileAdmission, CompileError, CompiledOperatorRules, PackSource,
    ProfileMounts, RuleCompileLimits,
};

/// Owned bodies captured by a coherent reader before validation or compilation.
#[derive(Debug, Clone, Default)]
pub struct PackBodiesV5 {
    bodies: BTreeMap<Id, Arc<str>>,
}

impl PackBodiesV5 {
    pub fn new(bodies: BTreeMap<Id, Arc<str>>) -> Self {
        Self { bodies }
    }

    pub fn insert(&mut self, id: Id, body: Arc<str>) -> Option<Arc<str>> {
        self.bodies.insert(id, body)
    }

    pub fn get(&self, id: &Id) -> Option<&Arc<str>> {
        self.bodies.get(id)
    }

    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Id, &Arc<str>)> {
        self.bodies.iter()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TargetV5Error {
    #[error("schema-5 validation failed with {count} error(s)", count = .0.len())]
    Validation(Vec<ConfigError>),
    #[error("target limit {field} cannot represent value {value}")]
    LimitConversion { field: &'static str, value: u128 },
    #[error(transparent)]
    Limits(#[from] BudgetExceeded),
    #[error("missing bodies for declared custom lists: {0:?}")]
    MissingBodies(Vec<Id>),
    #[error(transparent)]
    Compiler(#[from] CompileError),
}

impl TargetV5Error {
    pub fn validation_errors(&self) -> Option<&[ConfigError]> {
        match self {
            Self::Validation(errors) => Some(errors),
            _ => None,
        }
    }

    pub fn missing_bodies(&self) -> Option<&[Id]> {
        match self {
            Self::MissingBodies(ids) => Some(ids),
            _ => None,
        }
    }
}

impl TryFrom<&CustomListLimitsV5> for RuleCompileLimits {
    type Error = TargetV5Error;

    fn try_from(value: &CustomListLimitsV5) -> Result<Self, Self::Error> {
        let CustomListLimitsV5 {
            max_lists,
            max_file_bytes,
            max_total_bytes,
            max_rules_per_list,
            max_indexed_rules_per_profile,
            max_indexed_rules_total,
            max_advanced_rules_per_profile,
            max_advanced_rules_total,
            max_regex_rules_per_profile,
            max_regex_rules_total,
            max_store_indexed_rules,
            max_store_advanced_rules,
            max_store_regex_rules,
            max_rule_bytes,
            max_regex_program_bytes,
            max_store_compiled_bytes,
            max_compiled_bytes_per_profile,
            max_compiled_bytes_total,
        } = *value;
        let limits = Self {
            max_lists,
            max_file_bytes,
            max_total_bytes,
            max_rules_per_list,
            max_indexed_rules_per_profile,
            max_indexed_rules_total,
            max_advanced_rules_per_profile,
            max_advanced_rules_total,
            max_regex_rules_per_profile,
            max_regex_rules_total,
            max_store_indexed_rules,
            max_store_advanced_rules,
            max_store_regex_rules,
            max_rule_bytes,
            max_regex_program_bytes,
            max_store_compiled_bytes,
            max_compiled_bytes_per_profile,
            max_compiled_bytes_total,
        };
        limits.validate()?;
        Ok(limits)
    }
}

impl ProfileV5 {
    fn validation_projection(&self) -> Profile {
        let Self {
            display_name,
            block_response,
            blocked_ttl_secs,
            block_all,
            local_records,
            ecs,
            rewrite_rules,
            safe_search,
            custom_lists,
            lists,
            migration_origin: _,
        } = self;
        Profile {
            display_name: display_name.clone(),
            block_response: *block_response,
            blocked_ttl_secs: *blocked_ttl_secs,
            admin_rules: Vec::new(),
            block_all: *block_all,
            local_records: local_records.clone(),
            ecs: ecs.clone(),
            rewrite_rules: rewrite_rules.clone(),
            safe_search: *safe_search,
            custom_lists: custom_lists.clone(),
            lists: lists.clone(),
        }
    }
}

impl DeviceV5 {
    fn validation_projection(&self) -> Device {
        let Self {
            id,
            display_name,
            ip,
            mac,
            mac_aliases,
            profile,
            groups,
            owner,
            device_type,
            department,
            notes,
            unfiltered,
            network_name,
            network_name_wildcard,
        } = self;
        Device {
            id: id.clone(),
            display_name: display_name.clone(),
            ip: *ip,
            mac: mac.clone(),
            mac_aliases: mac_aliases.clone(),
            profile: profile.clone(),
            groups: groups.clone(),
            owner: owner.clone(),
            device_type: device_type.clone(),
            department: department.clone(),
            notes: notes.clone(),
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            override_profile_deny: false,
            unfiltered: *unfiltered,
            network_name: network_name.clone(),
            network_name_wildcard: *network_name_wildcard,
        }
    }
}

impl ConfigV5 {
    /// Project the target shape onto the current semantic validator without
    /// making any removed rule seat representable in schema 5.
    pub fn validation_projection(&self) -> Result<ConfigV1, TargetV5Error> {
        let Self {
            schema_version,
            includes,
            server,
            retired,
            blocklists,
            profiles,
            devices,
            groups,
            subnets,
            schedules,
            custom_lists,
            custom_list_limits,
            labels,
            upstream,
            dnssec,
            cache,
            tracking,
            security,
            anti_bypass,
            socket,
            api,
            forwarding,
            local_dns,
            ip_blocklists,
            lists,
            resource_budget,
            backup,
            cluster,
            node,
        } = self;
        let max_file_bytes = u64::try_from(custom_list_limits.max_file_bytes).map_err(|_| {
            TargetV5Error::LimitConversion {
                field: "max_file_bytes",
                value: custom_list_limits.max_file_bytes as u128,
            }
        })?;
        Ok(ConfigV1 {
            schema_version: *schema_version,
            includes: includes.clone(),
            server: server.clone(),
            retired: retired.clone(),
            blocklists: blocklists.clone(),
            profiles: profiles
                .iter()
                .map(|(id, profile)| (id.clone(), profile.validation_projection()))
                .collect(),
            devices: devices
                .iter()
                .map(DeviceV5::validation_projection)
                .collect(),
            groups: groups.clone(),
            subnets: subnets.clone(),
            schedules: schedules.clone(),
            admin_rules: Vec::new(),
            custom_lists: custom_lists.clone(),
            custom_list_limits: CustomListLimits { max_file_bytes },
            labels: labels.clone(),
            upstream: upstream.clone(),
            dnssec: dnssec.clone(),
            cache: cache.clone(),
            tracking: tracking.clone(),
            security: security.clone(),
            anti_bypass: anti_bypass.clone(),
            socket: socket.clone(),
            api: api.clone(),
            forwarding: forwarding.clone(),
            local_dns: local_dns.clone(),
            ip_blocklists: ip_blocklists.clone(),
            lists: lists.clone(),
            resource_budget: resource_budget.clone(),
            backup: backup.clone(),
            cluster: cluster.clone(),
            node: node.clone(),
        })
    }
}

/// Reuse the complete current semantic validator against a schema-5 projection.
pub fn validate_v5_collect(
    config: &ConfigV5,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
) -> Result<(), TargetV5Error> {
    validate_v5_collect_inner(config, now, warns, secrets, None)
}

/// Validate a schema-5 candidate with a coherent set of pack bodies. Byte
/// changes are reported as requiring semantic classification, never as policy
/// drift. Callers with only TOML receive an explicit
/// `migration_pack_policy_unverified` warning for body-backed origins.
pub fn validate_v5_collect_with_bodies(
    config: &ConfigV5,
    bodies: &PackBodiesV5,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
) -> Result<(), TargetV5Error> {
    validate_v5_collect_inner(config, now, warns, secrets, Some(bodies))
}

fn validate_v5_collect_inner(
    config: &ConfigV5,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
    bodies: Option<&PackBodiesV5>,
) -> Result<(), TargetV5Error> {
    let projection = config.validation_projection()?;
    let limits = RuleCompileLimits::try_from(&config.custom_list_limits)?;
    limits.validate()?;
    validate_collect_for_schema(
        &projection,
        TARGET_SCHEMA_VERSION_V5,
        now,
        warns,
        secrets,
        None,
    )
    .map_err(TargetV5Error::Validation)?;
    let origin_findings = match bodies {
        Some(bodies) => {
            crate::config::migration::lint_migration_origins_with_bodies(config, bodies)
        }
        None => crate::config::migration::lint_migration_origins(config),
    };
    for finding in origin_findings {
        let message = format!(
            "profile {}: {}: {}",
            finding.profile_id, finding.code, finding.detail
        );
        if warns.emit() {
            tracing::warn!(
                target: "audit",
                profile = %finding.profile_id,
                code = %finding.code,
                "{}",
                finding.detail
            );
        }
        warns.push(message);
    }
    Ok(())
}

struct PackBacking {
    list_id: String,
    body: Arc<str>,
}

struct ProfileBacking {
    profile_id: String,
    custom_lists: Vec<String>,
    block_all: bool,
}

/// Compile one complete in-memory candidate without file access or publication.
pub fn compile_v5_operator_rules(
    config: &ConfigV5,
    bodies: &PackBodiesV5,
    admission: &CompileAdmission,
) -> Result<CompiledOperatorRules, TargetV5Error> {
    let limits = RuleCompileLimits::try_from(&config.custom_list_limits)?;
    let mut missing: Vec<Id> = config
        .custom_lists
        .iter()
        .filter(|list| bodies.get(&list.id).is_none())
        .map(|list| list.id.clone())
        .collect();
    missing.sort_unstable();
    missing.dedup();
    if !missing.is_empty() {
        return Err(TargetV5Error::MissingBodies(missing));
    }

    let pack_backing: Vec<PackBacking> = config
        .custom_lists
        .iter()
        .map(|list| PackBacking {
            list_id: list.id.as_str().to_owned(),
            body: Arc::clone(
                bodies
                    .get(&list.id)
                    .expect("all declared bodies were checked above"),
            ),
        })
        .collect();
    let pack_sources: Vec<PackSource<'_>> = pack_backing
        .iter()
        .map(|pack| PackSource {
            list_id: pack.list_id.as_str(),
            content: pack.body.as_ref(),
        })
        .collect();

    let profile_backing: Vec<ProfileBacking> = config
        .profiles
        .iter()
        .map(|(profile_id, profile)| ProfileBacking {
            profile_id: profile_id.clone(),
            custom_lists: profile
                .custom_lists
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            block_all: profile.block_all,
        })
        .collect();
    let mount_backing: Vec<Vec<&str>> = profile_backing
        .iter()
        .map(|profile| profile.custom_lists.iter().map(String::as_str).collect())
        .collect();
    let profile_mounts: Vec<ProfileMounts<'_>> = profile_backing
        .iter()
        .zip(&mount_backing)
        .map(|(profile, mounts)| ProfileMounts {
            profile_id: profile.profile_id.as_str(),
            custom_lists: mounts.as_slice(),
            block_all: profile.block_all,
        })
        .collect();

    CompiledOperatorRules::compile(&pack_sources, &profile_mounts, limits, admission)
        .map_err(TargetV5Error::Compiler)
}

/// Validate and compile one complete schema-5 candidate before publication.
pub fn validate_and_compile_v5(
    config: &ConfigV5,
    bodies: &PackBodiesV5,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
    admission: &CompileAdmission,
) -> Result<CompiledOperatorRules, TargetV5Error> {
    validate_v5_collect_with_bodies(config, bodies, now, warns, secrets)?;
    compile_v5_operator_rules(config, bodies, admission)
}

/// Validate and compile an offline candidate under a bounded one-build admission.
pub fn validate_and_compile_v5_one_shot(
    config: &ConfigV5,
    bodies: &PackBodiesV5,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
) -> Result<CompiledOperatorRules, TargetV5Error> {
    let limits = RuleCompileLimits::try_from(&config.custom_list_limits)?;
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1)?;
    validate_and_compile_v5(config, bodies, now, warns, secrets, &admission)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(body: &'static str) -> (ConfigV5, PackBodiesV5) {
        let list_id = Id::new("policy").unwrap();
        let config: ConfigV5 = toml::from_str(
            r#"schema_version = 5

[server]
default_profile = "default"

[[custom_lists]]
id = "policy"

[profiles.default]
custom_lists = ["policy"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let bodies = PackBodiesV5::new(BTreeMap::from([(list_id, Arc::<str>::from(body))]));
        (config, bodies)
    }

    fn validate(config: &ConfigV5, bodies: &PackBodiesV5) -> Result<(), TargetV5Error> {
        validate_and_compile_v5_one_shot(
            config,
            bodies,
            OffsetDateTime::UNIX_EPOCH,
            &mut AuditWarnings::silent(),
            None,
        )
        .map(drop)
    }

    #[test]
    fn executable_boundary_rejects_invalid_rule_rows() {
        let (config, bodies) = candidate("bad..example\n");

        assert!(matches!(
            validate(&config, &bodies),
            Err(TargetV5Error::Compiler(CompileError::InvalidRule {
                row: 1,
                ..
            }))
        ));
    }

    #[test]
    fn executable_boundary_rejects_invalid_regex() {
        let (config, bodies) = candidate("/(invalid/\n");

        assert!(matches!(
            validate(&config, &bodies),
            Err(TargetV5Error::Compiler(CompileError::InvalidRegex {
                row: 1,
                ..
            }))
        ));
    }

    #[test]
    fn executable_boundary_enforces_compiled_limits() {
        let (mut config, bodies) = candidate("one.example\ntwo.example\n");
        config.custom_list_limits.max_store_indexed_rules = 1;

        assert!(matches!(
            validate(&config, &bodies),
            Err(TargetV5Error::Compiler(CompileError::BudgetExceeded(
                BudgetExceeded {
                    limit: "max_store_indexed_rules",
                    ..
                }
            )))
        ));
    }
}
