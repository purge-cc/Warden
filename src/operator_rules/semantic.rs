//! Semantic identity and bounded change summaries for operator policy.
//!
//! This deliberately does not reuse the byte-level policy revision. A revision
//! protects the precise tree an editor read; this module identifies the policy
//! that tree expresses after rule normalization.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::config::custom_list::grammar::{parse_pack_line, PackLine};
use crate::config::policy_revision::{
    PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionSnapshot,
};
use crate::config::schema::{ConfigV1, ConfigV5, ProfileV5, TARGET_SCHEMA_VERSION_V5};
use crate::filter::operator_rules::{parse_rule_ast, OperatorPattern, RuleKey};

const HASH_DOMAIN: &[u8] = b"warden/uor/operator-policy/v1\0";
const HASH_VERSION: u8 = 1;
/// The public diff is intentionally a summary rather than an export channel.
pub const MAX_DIFF_ENTRIES: usize = 128;

/// SHA-256 identity of a normalized operator-policy model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperatorPolicyHash([u8; 32]);

impl OperatorPolicyHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OperatorPolicyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackGrammar {
    Schema4Migration,
    TargetV5,
}

/// One declared pack body from a coherent policy snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SemanticPack<'a> {
    pub id: &'a str,
    pub body: &'a str,
}

/// The rule family is exposed in diffs without exposing its source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleClass {
    Exact,
    Wildcard,
    Regex,
}

/// Refusal while constructing a semantic model.
#[derive(Debug, thiserror::Error)]
pub enum SemanticError {
    #[error("operator policy hash requires schema_version = {expected}, got {actual}")]
    UnsupportedSchema { expected: u32, actual: u32 },
    #[error("custom list {id} is declared more than once")]
    DuplicatePack { id: String },
    #[error("custom list {id} has no declared pack body")]
    MissingPack { id: String },
    #[error("pack {id} is not UTF-8")]
    NonUtf8Pack { id: String },
    #[error("pack {id}, row {row}: {detail}")]
    InvalidPackRule {
        id: String,
        row: usize,
        detail: String,
    },
    #[error("historical schema-4 admin rule {id}: {detail}")]
    InvalidAdminRule { id: String, detail: String },
}

/// A rule-level semantic change. `key` is deliberately opaque: callers that
/// need rule text must use the separately authorized export surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDelta {
    pub pack_id: String,
    pub kind: RuleDeltaKind,
    pub key: RuleKey,
    pub class: RuleClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDeltaKind {
    Added,
    Removed,
}

/// A non-rule semantic change. Names identify config concepts, never pack rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiffEntry {
    pub scope: String,
}

/// A bounded policy comparison suitable for receipts, audit summaries, and
/// status APIs. It contains no raw rule lines or descriptive metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiff {
    pub before: OperatorPolicyHash,
    pub after: OperatorPolicyHash,
    pub semantic_changed: bool,
    pub cosmetic_changed: bool,
    pub rule_deltas: Vec<RuleDelta>,
    pub semantic_entries: Vec<SemanticDiffEntry>,
    pub omitted_entries: usize,
}

#[derive(Debug, Clone)]
struct SemanticPolicy {
    hash: OperatorPolicyHash,
    typed_canonical: Vec<u8>,
    packs: BTreeMap<String, BTreeMap<RuleKey, RuleClass>>,
}

/// Hash a historical schema-4 policy for migration and recovery comparison.
pub(crate) fn hash_schema4_migration_snapshot(
    snapshot: &PolicyRevisionSnapshot,
    config: &ConfigV1,
) -> Result<OperatorPolicyHash, SemanticError> {
    hash_schema4_migration_inventory(snapshot.inventory(), config)
}

/// Hash a validated schema-5 candidate and its declared pack bodies.
pub fn hash_policy_candidate(
    config: &ConfigV5,
    packs: &[SemanticPack<'_>],
) -> Result<OperatorPolicyHash, SemanticError> {
    if config.schema_version != TARGET_SCHEMA_VERSION_V5 {
        return Err(SemanticError::UnsupportedSchema {
            expected: TARGET_SCHEMA_VERSION_V5,
            actual: config.schema_version,
        });
    }
    semantic_policy_v5(config, packs).map(|policy| policy.hash)
}

/// Hash the effective policy of one profile and the packs it mounts.
///
/// This deliberately shares pack normalization with whole-policy hashing but
/// omits unrelated profiles and packs. It is intended for provenance checks
/// whose verdict must not be affected by another profile's policy.
pub fn hash_profile_policy_candidate(
    profile: &ProfileV5,
    packs: &[SemanticPack<'_>],
) -> Result<OperatorPolicyHash, SemanticError> {
    let mut supplied = BTreeMap::new();
    for pack in packs {
        if supplied.insert(pack.id, pack.body).is_some() {
            return Err(SemanticError::DuplicatePack { id: pack.id.into() });
        }
    }

    let mut normalized_packs = BTreeMap::new();
    for id in &profile.custom_lists {
        let id = id.as_str();
        let body = supplied
            .remove(id)
            .ok_or_else(|| SemanticError::MissingPack { id: id.into() })?;
        normalized_packs.insert(id.into(), normalize_pack(id, body, PackGrammar::TargetV5)?);
    }

    let mut canonical = Canonical::default();
    canonical.bytes(HASH_DOMAIN);
    canonical.u8(HASH_VERSION);
    canonical.tag("profile_policy");
    canonical.value(
        &toml::Value::try_from(profile).expect("profile serializes"),
        &["display_name", "migration_origin"],
    );
    write_packs(&mut canonical, &normalized_packs);
    Ok(OperatorPolicyHash(Sha256::digest(&canonical.0).into()))
}

fn hash_schema4_migration_inventory(
    inventory: &PolicyRevisionInventory,
    config: &ConfigV1,
) -> Result<OperatorPolicyHash, SemanticError> {
    if config.schema_version != 4 {
        return Err(SemanticError::UnsupportedSchema {
            expected: 4,
            actual: config.schema_version,
        });
    }
    let mut packs = Vec::with_capacity(config.custom_lists.len());
    for list in &config.custom_lists {
        let expected = format!("packs/{}.txt", list.id);
        let body = inventory
            .members()
            .iter()
            .find(|member| {
                member.kind() == PolicyMemberKind::Pack
                    && member.path() == std::path::Path::new(&expected)
            })
            .ok_or_else(|| SemanticError::MissingPack {
                id: list.id.to_string(),
            })?;
        let PolicyMemberState::Present(bytes) = body.state() else {
            return Err(SemanticError::MissingPack {
                id: list.id.to_string(),
            });
        };
        let text = std::str::from_utf8(bytes).map_err(|_| SemanticError::NonUtf8Pack {
            id: list.id.to_string(),
        })?;
        packs.push(SemanticPack {
            id: list.id.as_str(),
            body: text,
        });
    }
    semantic_policy_v4_migration(config, &packs).map(|policy| policy.hash)
}

fn semantic_policy_v4_migration(
    config: &ConfigV1,
    packs: &[SemanticPack<'_>],
) -> Result<SemanticPolicy, SemanticError> {
    if config.schema_version != 4 {
        return Err(SemanticError::UnsupportedSchema {
            expected: 4,
            actual: config.schema_version,
        });
    }
    let mut supplied = BTreeMap::new();
    for pack in packs {
        if supplied.insert(pack.id, pack.body).is_some() {
            return Err(SemanticError::DuplicatePack { id: pack.id.into() });
        }
    }
    let mut normalized_packs = BTreeMap::new();
    for declaration in &config.custom_lists {
        let id = declaration.id.as_str();
        let body = supplied
            .remove(id)
            .ok_or_else(|| SemanticError::MissingPack { id: id.into() })?;
        normalized_packs.insert(
            id.into(),
            normalize_pack(id, body, PackGrammar::Schema4Migration)?,
        );
    }
    // A supplied body which is not declared belongs to an orphan and cannot
    // alter policy identity.

    let mut typed = Canonical::default();
    typed.bytes(HASH_DOMAIN);
    typed.u8(HASH_VERSION);
    typed.u32(config.schema_version);
    write_external_lists_schema4_migration(&mut typed, config);
    write_admin_rules_schema4_migration(&mut typed, config)?;
    write_profiles_schema4_migration(&mut typed, config);
    write_resolver_assignments_schema4_migration(&mut typed, config);
    let typed_canonical = typed.0.clone();
    let mut canonical = typed;
    write_packs(&mut canonical, &normalized_packs);
    let hash = OperatorPolicyHash(Sha256::digest(&canonical.0).into());
    Ok(SemanticPolicy {
        hash,
        typed_canonical,
        packs: normalized_packs,
    })
}

#[cfg(test)]
fn semantic_policy(
    config: &ConfigV1,
    packs: &[SemanticPack<'_>],
    grammar: PackGrammar,
) -> Result<SemanticPolicy, SemanticError> {
    let mut supplied = BTreeMap::new();
    for pack in packs {
        if supplied.insert(pack.id, pack.body).is_some() {
            return Err(SemanticError::DuplicatePack { id: pack.id.into() });
        }
    }
    let mut normalized_packs = BTreeMap::new();
    for declaration in &config.custom_lists {
        let id = declaration.id.as_str();
        let body = supplied
            .remove(id)
            .ok_or_else(|| SemanticError::MissingPack { id: id.into() })?;
        normalized_packs.insert(id.into(), normalize_pack(id, body, grammar)?);
    }
    let mut typed = Canonical::default();
    typed.bytes(HASH_DOMAIN);
    typed.u8(HASH_VERSION);
    typed.u32(config.schema_version);
    write_external_lists_schema4_migration(&mut typed, config);
    write_admin_rules_schema4_migration(&mut typed, config)?;
    write_profiles_schema4_migration(&mut typed, config);
    write_resolver_assignments_schema4_migration(&mut typed, config);
    let typed_canonical = typed.0.clone();
    let mut canonical = typed;
    write_packs(&mut canonical, &normalized_packs);
    Ok(SemanticPolicy {
        hash: OperatorPolicyHash(Sha256::digest(&canonical.0).into()),
        typed_canonical,
        packs: normalized_packs,
    })
}

fn semantic_policy_v5(
    config: &ConfigV5,
    packs: &[SemanticPack<'_>],
) -> Result<SemanticPolicy, SemanticError> {
    let mut supplied = BTreeMap::new();
    for pack in packs {
        if supplied.insert(pack.id, pack.body).is_some() {
            return Err(SemanticError::DuplicatePack { id: pack.id.into() });
        }
    }
    let mut normalized_packs = BTreeMap::new();
    for declaration in &config.custom_lists {
        let id = declaration.id.as_str();
        let body = supplied
            .remove(id)
            .ok_or_else(|| SemanticError::MissingPack { id: id.into() })?;
        normalized_packs.insert(id.into(), normalize_pack(id, body, PackGrammar::TargetV5)?);
    }

    let mut typed = Canonical::default();
    typed.bytes(HASH_DOMAIN);
    typed.u8(HASH_VERSION);
    typed.u32(config.schema_version);
    write_external_lists_v5(&mut typed, config);
    write_profiles_v5(&mut typed, config);
    write_resolver_assignments_v5(&mut typed, config);
    let typed_canonical = typed.0.clone();
    let mut canonical = typed;
    write_packs(&mut canonical, &normalized_packs);
    let hash = OperatorPolicyHash(Sha256::digest(&canonical.0).into());
    Ok(SemanticPolicy {
        hash,
        typed_canonical,
        packs: normalized_packs,
    })
}

#[allow(dead_code, reason = "migration/recovery semantic oracle")]
pub(crate) fn diff_schema4_migration_inventories(
    before_inventory: &PolicyRevisionInventory,
    before: &ConfigV1,
    after_inventory: &PolicyRevisionInventory,
    after: &ConfigV1,
) -> Result<SemanticDiff, SemanticError> {
    let before = semantic_v4_migration_from_inventory(before_inventory, before)?;
    let after = semantic_v4_migration_from_inventory(after_inventory, after)?;
    Ok(diff_policies(
        &before,
        &after,
        before_inventory.revision() != after_inventory.revision(),
    ))
}

fn semantic_v4_migration_from_inventory(
    inventory: &PolicyRevisionInventory,
    config: &ConfigV1,
) -> Result<SemanticPolicy, SemanticError> {
    if config.schema_version != 4 {
        return Err(SemanticError::UnsupportedSchema {
            expected: 4,
            actual: config.schema_version,
        });
    }
    let mut packs = Vec::with_capacity(config.custom_lists.len());
    for list in &config.custom_lists {
        let path = format!("packs/{}.txt", list.id);
        let member = inventory
            .members()
            .iter()
            .find(|member| {
                member.kind() == PolicyMemberKind::Pack
                    && member.path() == std::path::Path::new(&path)
            })
            .ok_or_else(|| SemanticError::MissingPack {
                id: list.id.to_string(),
            })?;
        let PolicyMemberState::Present(bytes) = member.state() else {
            return Err(SemanticError::MissingPack {
                id: list.id.to_string(),
            });
        };
        packs.push(SemanticPack {
            id: list.id.as_str(),
            body: std::str::from_utf8(bytes).map_err(|_| SemanticError::NonUtf8Pack {
                id: list.id.to_string(),
            })?,
        });
    }
    semantic_policy_v4_migration(config, &packs)
}

pub(crate) fn diff_policy_inventories(
    before_inventory: &PolicyRevisionInventory,
    before: &ConfigV5,
    after_inventory: &PolicyRevisionInventory,
    after: &ConfigV5,
) -> Result<SemanticDiff, SemanticError> {
    let before = semantic_v5_from_inventory(before_inventory, before)?;
    let after = semantic_v5_from_inventory(after_inventory, after)?;
    Ok(diff_policies(
        &before,
        &after,
        before_inventory.revision() != after_inventory.revision(),
    ))
}

pub(crate) fn hash_policy_inventory(
    inventory: &PolicyRevisionInventory,
    config: &ConfigV5,
) -> Result<OperatorPolicyHash, SemanticError> {
    semantic_v5_from_inventory(inventory, config).map(|policy| policy.hash)
}

fn semantic_v5_from_inventory(
    inventory: &PolicyRevisionInventory,
    config: &ConfigV5,
) -> Result<SemanticPolicy, SemanticError> {
    let mut packs = Vec::with_capacity(config.custom_lists.len());
    for list in &config.custom_lists {
        let path = format!("packs/{}.txt", list.id);
        let member = inventory
            .members()
            .iter()
            .find(|member| {
                member.kind() == PolicyMemberKind::Pack
                    && member.path() == std::path::Path::new(&path)
            })
            .ok_or_else(|| SemanticError::MissingPack {
                id: list.id.to_string(),
            })?;
        let PolicyMemberState::Present(bytes) = member.state() else {
            return Err(SemanticError::MissingPack {
                id: list.id.to_string(),
            });
        };
        packs.push(SemanticPack {
            id: list.id.as_str(),
            body: std::str::from_utf8(bytes).map_err(|_| SemanticError::NonUtf8Pack {
                id: list.id.to_string(),
            })?,
        });
    }
    semantic_policy_v5(config, &packs)
}

fn normalize_pack(
    id: &str,
    body: &str,
    grammar: PackGrammar,
) -> Result<BTreeMap<RuleKey, RuleClass>, SemanticError> {
    let mut rules = BTreeMap::new();
    for (index, raw) in body.lines().enumerate() {
        let row = index + 1;
        let normalized = match grammar {
            PackGrammar::Schema4Migration => match parse_pack_line(raw) {
                Ok(PackLine::Blank) | Err(_) => continue,
                Ok(PackLine::Allow(domain)) => format!("@@||{domain}^"),
                Ok(PackLine::Deny(domain)) => format!("||{domain}^"),
            },
            PackGrammar::TargetV5 if raw.trim().is_empty() || raw.trim_start().starts_with('#') => {
                continue
            }
            PackGrammar::TargetV5 => raw.to_string(),
        };
        let ast = parse_rule_ast(&normalized).map_err(|error| SemanticError::InvalidPackRule {
            id: id.into(),
            row,
            detail: error.to_string(),
        })?;
        rules.insert(ast.rule_key(), rule_class(ast.pattern()));
    }
    Ok(rules)
}

fn rule_class(pattern: &OperatorPattern) -> RuleClass {
    match pattern {
        OperatorPattern::Exact(_) => RuleClass::Exact,
        OperatorPattern::Wildcard(_) => RuleClass::Wildcard,
        OperatorPattern::Regex { .. } => RuleClass::Regex,
    }
}

fn write_external_lists_schema4_migration(out: &mut Canonical, config: &ConfigV1) {
    out.tag("external_lists");
    let mut lists: Vec<_> = config.blocklists.iter().collect();
    lists.sort_by_key(|list| list.id.as_str());
    out.len(lists.len());
    for list in lists {
        out.str(list.id.as_str());
        out.str(&list.url);
        out.value(
            &toml::Value::try_from(list).expect("blocklist serializes"),
            &["display_name"],
        );
    }
}

fn write_external_lists_v5(out: &mut Canonical, config: &ConfigV5) {
    out.tag("external_lists");
    let mut lists: Vec<_> = config.blocklists.iter().collect();
    lists.sort_by_key(|list| list.id.as_str());
    out.len(lists.len());
    for list in lists {
        out.str(list.id.as_str());
        out.str(&list.url);
        out.value(
            &toml::Value::try_from(list).expect("blocklist serializes"),
            &["display_name"],
        );
    }
}

fn write_admin_rules_schema4_migration(
    out: &mut Canonical,
    config: &ConfigV1,
) -> Result<(), SemanticError> {
    out.tag("admin_rules");
    let mut rules: Vec<_> = config.admin_rules.iter().collect();
    rules.sort_by_key(|rule| rule.id.as_str());
    out.len(rules.len());
    for rule in rules {
        // Historical schema-4 accepted surrounding whitespace. Preserve that
        // migration-oracle identity without relaxing schema-5 pack parsing.
        let text = rule.rule.trim();
        let ast = parse_rule_ast(text).map_err(|error| SemanticError::InvalidAdminRule {
            id: rule.id.to_string(),
            detail: error.to_string(),
        })?;
        out.str(rule.id.as_str());
        out.bytes(&ast.rule_key().0);
    }
    Ok(())
}

fn write_profiles_schema4_migration(out: &mut Canonical, config: &ConfigV1) {
    out.tag("profiles");
    out.len(config.profiles.len());
    for (id, profile) in &config.profiles {
        out.str(id);
        out.value(
            &toml::Value::try_from(profile).expect("profile serializes"),
            &["display_name"],
        );
    }
}

fn write_profiles_v5(out: &mut Canonical, config: &ConfigV5) {
    out.tag("profiles");
    out.len(config.profiles.len());
    for (id, profile) in &config.profiles {
        out.str(id);
        out.value(
            &toml::Value::try_from(profile).expect("profile serializes"),
            &["display_name", "migration_origin"],
        );
    }
}

fn write_resolver_assignments_schema4_migration(out: &mut Canonical, config: &ConfigV1) {
    out.tag("resolver");
    out.option_id(config.server.default_profile.as_ref().map(|id| id.as_str()));
    out.u8(u8::from(config.server.enforce_device_mac));
    out.value(
        &toml::Value::try_from(config.server.default_block_response)
            .expect("block response serializes"),
        &[],
    );
    out.u32(config.server.default_blocked_ttl_secs);
    out.u32(config.local_dns.ttl_secs);
    out.value(
        &toml::Value::try_from(&config.upstream.ecs).expect("ECS policy serializes"),
        &[],
    );
    write_entity_collection(
        out,
        "devices",
        &config.devices,
        &[
            "display_name",
            "owner",
            "device_type",
            "department",
            "notes",
        ],
    );
    write_entity_collection(out, "groups", &config.groups, &["display_name"]);
    write_entity_collection(out, "subnets", &config.subnets, &["display_name"]);
    write_entity_collection(out, "schedules", &config.schedules, &["display_name"]);
}

fn write_resolver_assignments_v5(out: &mut Canonical, config: &ConfigV5) {
    out.tag("resolver");
    out.option_id(config.server.default_profile.as_ref().map(|id| id.as_str()));
    out.u8(u8::from(config.server.enforce_device_mac));
    out.value(
        &toml::Value::try_from(config.server.default_block_response)
            .expect("block response serializes"),
        &[],
    );
    out.u32(config.server.default_blocked_ttl_secs);
    out.u32(config.local_dns.ttl_secs);
    out.value(
        &toml::Value::try_from(&config.upstream.ecs).expect("ECS policy serializes"),
        &[],
    );
    write_entity_collection(
        out,
        "devices",
        &config.devices,
        &[
            "display_name",
            "owner",
            "device_type",
            "department",
            "notes",
        ],
    );
    write_entity_collection(out, "groups", &config.groups, &["display_name"]);
    write_entity_collection(out, "subnets", &config.subnets, &["display_name"]);
    write_entity_collection(out, "schedules", &config.schedules, &["display_name"]);
}

fn write_entity_collection<T: serde::Serialize>(
    out: &mut Canonical,
    name: &str,
    values: &[T],
    ignored: &[&str],
) {
    let mut encoded: Vec<Vec<u8>> = values
        .iter()
        .map(|value| {
            let mut item = Canonical::default();
            item.value(
                &toml::Value::try_from(value).expect("schema entity serializes"),
                ignored,
            );
            item.0
        })
        .collect();
    encoded.sort();
    out.tag(name);
    out.len(encoded.len());
    for item in encoded {
        out.bytes(&item);
    }
}

fn write_packs(out: &mut Canonical, packs: &BTreeMap<String, BTreeMap<RuleKey, RuleClass>>) {
    out.tag("custom_packs");
    out.len(packs.len());
    for (id, rules) in packs {
        out.str(id);
        out.len(rules.len());
        for (key, class) in rules {
            out.bytes(&key.0);
            out.u8(match class {
                RuleClass::Exact => 0,
                RuleClass::Wildcard => 1,
                RuleClass::Regex => 2,
            });
        }
    }
}

fn diff_policies(
    before: &SemanticPolicy,
    after: &SemanticPolicy,
    revision_changed: bool,
) -> SemanticDiff {
    let mut rule_deltas = Vec::new();
    let mut semantic_entries = Vec::new();
    let mut omitted_entries = 0;
    for id in before
        .packs
        .keys()
        .chain(after.packs.keys())
        .collect::<BTreeSet<_>>()
    {
        let old = before.packs.get(id);
        let new = after.packs.get(id);
        for (kind, source, other) in [
            (RuleDeltaKind::Removed, old, new),
            (RuleDeltaKind::Added, new, old),
        ] {
            for (key, class) in source.into_iter().flat_map(|rules| rules.iter()) {
                if other.is_some_and(|rules| rules.contains_key(key)) {
                    continue;
                }
                push_bounded(
                    &mut rule_deltas,
                    RuleDelta {
                        pack_id: (*id).clone(),
                        kind,
                        key: *key,
                        class: *class,
                    },
                    &mut omitted_entries,
                );
            }
        }
    }
    if before.typed_canonical != after.typed_canonical {
        push_bounded(
            &mut semantic_entries,
            SemanticDiffEntry {
                scope: "typed_policy_or_assignment".into(),
            },
            &mut omitted_entries,
        );
    }
    SemanticDiff {
        before: before.hash,
        after: after.hash,
        semantic_changed: before.hash != after.hash,
        cosmetic_changed: revision_changed && before.hash == after.hash,
        rule_deltas,
        semantic_entries,
        omitted_entries,
    }
}

fn push_bounded<T>(items: &mut Vec<T>, value: T, omitted: &mut usize) {
    if items.len() < MAX_DIFF_ENTRIES {
        items.push(value);
    } else {
        *omitted += 1;
    }
}

#[derive(Default)]
struct Canonical(Vec<u8>);

impl Canonical {
    fn tag(&mut self, value: &str) {
        self.u8(1);
        self.str(value);
    }
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn len(&mut self, value: usize) {
        self.0.extend_from_slice(&(value as u64).to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.len(value.len());
        self.0.extend_from_slice(value);
    }
    fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn option_id(&mut self, value: Option<&str>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.str(value);
        }
    }
    fn value(&mut self, value: &toml::Value, ignored: &[&str]) {
        match value {
            toml::Value::String(value) => {
                self.u8(2);
                self.str(value);
            }
            toml::Value::Integer(value) => {
                self.u8(3);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
            toml::Value::Float(value) => {
                self.u8(4);
                self.0.extend_from_slice(&value.to_bits().to_be_bytes());
            }
            toml::Value::Boolean(value) => {
                self.u8(5);
                self.u8(u8::from(*value));
            }
            toml::Value::Datetime(value) => {
                self.u8(6);
                self.str(&value.to_string());
            }
            toml::Value::Array(values) => {
                self.u8(7);
                let mut encoded: Vec<_> = values
                    .iter()
                    .map(|value| {
                        let mut item = Self::default();
                        item.value(value, ignored);
                        item.0
                    })
                    .collect();
                encoded.sort();
                self.len(encoded.len());
                for item in encoded {
                    self.bytes(&item);
                }
            }
            toml::Value::Table(values) => {
                self.u8(8);
                let included: Vec<_> = values
                    .iter()
                    .filter(|(key, _)| !ignored.contains(&key.as_str()))
                    .collect();
                self.len(included.len());
                for (key, value) in included {
                    self.str(key);
                    self.value(value, ignored);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_v5(extra: &str) -> ConfigV5 {
        toml::from_str(&format!(
            "schema_version = 5\n\n[[custom_lists]]\nid = \"rules\"\n\n[profiles.default]\ncustom_lists = [\"rules\"]\n{extra}"
        ))
        .unwrap()
    }

    fn v5_hash(config: &ConfigV5, body: &str) -> OperatorPolicyHash {
        hash_policy_candidate(config, &[SemanticPack { id: "rules", body }]).unwrap()
    }

    fn config(extra: &str) -> ConfigV1 {
        toml::from_str(&format!(
            "schema_version = 4\n\n[[custom_lists]]\nid = \"rules\"\n\n[profiles.default]\ncustom_lists = [\"rules\"]\n{extra}"
        ))
        .unwrap()
    }

    fn hash(config: &ConfigV1, body: &str, grammar: PackGrammar) -> OperatorPolicyHash {
        semantic_policy(config, &[SemanticPack { id: "rules", body }], grammar)
            .unwrap()
            .hash
    }

    #[test]
    fn pack_only_semantic_change_changes_policy_hash() {
        let config = config("");
        let before = hash(&config, "||one.example^\n", PackGrammar::Schema4Migration);
        let after = hash(&config, "||two.example^\n", PackGrammar::Schema4Migration);
        assert_ne!(before, after);
    }

    #[test]
    fn schema5_public_hash_accepts_every_target_rule_family() {
        let config = config_v5("");
        let combined = v5_hash(
            &config,
            "||one.example^$important\n@@||*.two.example^$noapex\n/^three[.]example$/\n",
        );
        let reordered = v5_hash(
            &config,
            "/^three[.]example$/\n@@||*.TWO.example^$noapex\n||ONE.example^$important\n",
        );
        assert_eq!(combined, reordered);
    }

    #[test]
    fn schema5_public_hash_rejects_record_separators() {
        let config = config_v5("");
        for separator in ['\0', '\u{85}', '\u{2028}', '\u{2029}'] {
            let body = format!("||one.example^{separator}||two.example^");
            assert!(matches!(
                hash_policy_candidate(
                    &config,
                    &[SemanticPack {
                        id: "rules",
                        body: &body,
                    }],
                ),
                Err(SemanticError::InvalidPackRule { .. })
            ));
        }
    }

    #[test]
    fn schema5_diff_classifies_advanced_rules_from_config_v5() {
        let config = config_v5("");
        let before = semantic_policy_v5(
            &config,
            &[SemanticPack {
                id: "rules",
                body: "||*.before.example^$important\n",
            }],
        )
        .unwrap();
        let after = semantic_policy_v5(
            &config,
            &[SemanticPack {
                id: "rules",
                body: "/^after[.]example$/\n",
            }],
        )
        .unwrap();
        let diff = diff_policies(&before, &after, true);
        assert_eq!(diff.rule_deltas.len(), 2);
        assert!(diff
            .rule_deltas
            .iter()
            .any(|delta| delta.class == RuleClass::Wildcard));
        assert!(diff
            .rule_deltas
            .iter()
            .any(|delta| delta.class == RuleClass::Regex));
    }

    #[test]
    fn migration_provenance_is_not_part_of_schema5_policy_identity() {
        let before = config_v5("");
        let mut after = before.clone();
        after.profiles.get_mut("default").unwrap().migration_origin =
            Some(crate::config::schema::MigrationOriginV1 {
                source_profile: crate::config::schema::Id::new("source").unwrap(),
                source_group: None,
                device_id: crate::config::schema::Id::new("device").unwrap(),
                source_policy_hash: "a".repeat(64),
                source_pack_digests: BTreeMap::new(),
                resolver_source_hash: "b".repeat(64),
                added_custom_lists: Vec::new(),
            });
        assert_eq!(
            v5_hash(&before, "||policy.example^\n"),
            v5_hash(&after, "||policy.example^\n")
        );
    }

    #[test]
    fn comments_order_case_pipe_and_anchor_are_cosmetic() {
        let config = config("");
        let before = hash(
            &config,
            "# preserved prose\n||Example.One^\n@@||two.example^\n",
            PackGrammar::TargetV5,
        );
        let after = hash(
            &config,
            "@@two.example\n# another comment\nexample.one\n",
            PackGrammar::TargetV5,
        );
        assert_eq!(before, after);
    }

    #[test]
    fn unordered_profile_membership_does_not_change_policy_hash() {
        let parse = |mounts: &str| {
            toml::from_str::<ConfigV1>(&format!(
                "schema_version = 4\n\n[[custom_lists]]\nid = \"rules\"\n\n[profiles.default]\ncustom_lists = {mounts}\n"
            ))
            .unwrap()
        };
        let left = parse("[\"rules\", \"other\"]");
        let right = parse("[\"other\", \"rules\"]");
        assert_eq!(
            hash(&left, "||example.test^\n", PackGrammar::Schema4Migration),
            hash(&right, "||example.test^\n", PackGrammar::Schema4Migration),
        );
    }

    #[test]
    fn exact_noapex_is_inert_but_wildcard_noapex_is_not() {
        let config = config("");
        assert_eq!(
            hash(&config, "||example.test^$noapex\n", PackGrammar::TargetV5),
            hash(&config, "||example.test^\n", PackGrammar::TargetV5),
        );
        assert_ne!(
            hash(&config, "||*.example.test^$noapex\n", PackGrammar::TargetV5),
            hash(&config, "||*.example.test^\n", PackGrammar::TargetV5),
        );
    }

    #[test]
    fn schedule_definition_changes_hash_without_a_current_minute() {
        let before = config("");
        let after = config(
            "\n[[schedules]]\nid = \"night\"\ndisplay_name = \"Night\"\ntarget_type = \"group\"\ntarget_id = \"family\"\nprofile = \"default\"\ndays = [\"all\"]\nhours = \"21:00-07:00\"\n",
        );
        assert_ne!(
            hash(&before, "||example.test^\n", PackGrammar::Schema4Migration),
            hash(&after, "||example.test^\n", PackGrammar::Schema4Migration),
        );
    }

    #[test]
    fn resolver_defaults_that_change_dns_behaviour_change_hash() {
        let before = config("");
        let mut enforce_mac = before.clone();
        enforce_mac.server.enforce_device_mac = !before.server.enforce_device_mac;
        let mut response = before.clone();
        response.server.default_block_response =
            crate::config::schema::profile::BlockResponseV1::Nxdomain;
        let mut ttl = before.clone();
        ttl.server.default_blocked_ttl_secs += 1;
        let mut local_ttl = before.clone();
        local_ttl.local_dns.ttl_secs += 1;
        let mut ecs = before.clone();
        ecs.upstream.ecs.enabled = true;
        let before_hash = hash(&before, "||example.test^\n", PackGrammar::Schema4Migration);
        for candidate in [&enforce_mac, &response, &ttl, &local_ttl, &ecs] {
            assert_ne!(
                before_hash,
                hash(
                    candidate,
                    "||example.test^\n",
                    PackGrammar::Schema4Migration
                )
            );
        }
    }

    #[test]
    fn inactive_schema4_rows_are_cosmetic_not_a_reload_refusal() {
        let config = config("");
        assert_eq!(
            hash(
                &config,
                "||example.test^\nunsupported historical row\n",
                PackGrammar::Schema4Migration,
            ),
            hash(
                &config,
                "||example.test^\nanother ignored row\n",
                PackGrammar::Schema4Migration,
            ),
        );
    }

    #[test]
    fn schema4_admin_rule_surrounding_whitespace_is_cosmetic() {
        let canonical = config("\n[[admin_rules]]\nid = \"admin\"\nrule = \"@@||example.test^\"\n");
        let escaped_newline = config(
            r#"
[[admin_rules]]
id = "admin"
rule = "\n\t@@||Example.Test^ \r\n"
"#,
        );
        let multiline = config(
            r#"
[[admin_rules]]
id = "admin"
rule = """
    @@||Example.Test^
"""
"#,
        );

        let expected = hash(
            &canonical,
            "||pack.example^\n",
            PackGrammar::Schema4Migration,
        );
        assert_eq!(
            hash(
                &escaped_newline,
                "||pack.example^\n",
                PackGrammar::Schema4Migration
            ),
            expected
        );
        assert_eq!(
            hash(
                &multiline,
                "||pack.example^\n",
                PackGrammar::Schema4Migration
            ),
            expected
        );
    }

    #[test]
    fn schema5_type_rejects_loose_admin_rule_seats() {
        let decoded = toml::from_str::<ConfigV5>(
            r#"schema_version = 5
[[admin_rules]]
id = "admin"
rule = "@@||example.test^"
"#,
        );
        assert!(decoded.is_err());
    }

    #[test]
    fn external_downloaded_corpus_is_not_an_input_to_policy_identity() {
        let config = config(
            "\n[[blocklists]]\nid = \"external\"\ndisplay_name = \"External\"\nurl = \"https://lists.example/policy.txt\"\n",
        );
        let first_download = "one.example\ntwo.example\n";
        let later_download = "different.example\n";
        assert_ne!(first_download, later_download);
        assert_eq!(
            hash(&config, "||local.example^\n", PackGrammar::Schema4Migration),
            hash(&config, "||local.example^\n", PackGrammar::Schema4Migration),
            "the semantic API intentionally accepts declarations and declared packs only",
        );
    }

    #[test]
    fn diff_reports_bounded_rule_identity_without_source_rows() {
        let config = config("");
        let before = semantic_policy(
            &config,
            &[SemanticPack {
                id: "rules",
                body: "||removed.example^\n",
            }],
            PackGrammar::Schema4Migration,
        )
        .unwrap();
        let after = semantic_policy(
            &config,
            &[SemanticPack {
                id: "rules",
                body: "@@||added.example^\n",
            }],
            PackGrammar::Schema4Migration,
        )
        .unwrap();
        let diff = diff_policies(&before, &after, true);

        assert!(diff.semantic_changed);
        assert!(!diff.cosmetic_changed);
        assert_eq!(diff.rule_deltas.len(), 2);
        assert!(diff
            .rule_deltas
            .iter()
            .any(|delta| delta.kind == RuleDeltaKind::Added && delta.class == RuleClass::Exact));
        assert!(diff
            .rule_deltas
            .iter()
            .any(|delta| delta.kind == RuleDeltaKind::Removed && delta.class == RuleClass::Exact));
        assert!(diff.semantic_entries.is_empty());
    }

    #[test]
    fn diff_retains_typed_scope_when_rules_also_change() {
        let before_config = config("");
        let mut after_config = config("");
        after_config
            .profiles
            .get_mut("default")
            .unwrap()
            .custom_lists
            .clear();
        let before = semantic_policy(
            &before_config,
            &[SemanticPack {
                id: "rules",
                body: "||before.example^\n",
            }],
            PackGrammar::Schema4Migration,
        )
        .unwrap();
        let after = semantic_policy(
            &after_config,
            &[SemanticPack {
                id: "rules",
                body: "||after.example^\n",
            }],
            PackGrammar::Schema4Migration,
        )
        .unwrap();
        let diff = diff_policies(&before, &after, true);
        assert_eq!(diff.rule_deltas.len(), 2);
        assert_eq!(diff.semantic_entries.len(), 1);
    }
}
