//! Immutable schema-5 policy captures used by cluster publication and admission.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{ensure, Context};

#[cfg(test)]
use crate::config::schema::CustomList;
use crate::config::schema::{ConfigV5, Id, TARGET_SCHEMA_VERSION_V5};
use crate::config::target_v5::PackBodiesV5;
#[cfg(test)]
use crate::filter::operator_rules::CompileAdmission;
use crate::filter::operator_rules::{parse_rule_ast, CompiledCostV1, OperatorPattern};
use crate::operator_rules::{hash_policy_candidate, SemanticPack, VerifiedPolicyCandidate};

use super::manifest::{
    Manifest, ObjectRef, PackRef, Requirements, RuleRequirements, MAX_PACK_BYTES, MAX_TOML_BYTES,
    MAX_TOTAL_PACK_BYTES,
};
use super::publication::PublicationCandidate;

/// Server fields whose values identify one receiving node rather than policy.
pub(crate) const ARTIFACT_NODE_LOCAL_SERVER_FIELDS: &[&str] =
    &["listen", "log_level", "tcp_timeout_secs"];

#[derive(Debug, Clone)]
pub(crate) struct CapturedPack {
    pub bytes: Arc<[u8]>,
    pub object: ObjectRef,
}

/// A coherent schema-5 capture. It deliberately excludes includes and all
/// node-local settings, particularly `custom_list_limits`.
#[derive(Debug, Clone)]
pub(crate) struct PolicySnapshot {
    toml: Arc<[u8]>,
    #[cfg(test)]
    declarations: BTreeMap<Id, CustomList>,
    mounts: BTreeMap<String, Vec<Id>>,
    packs: BTreeMap<Id, CapturedPack>,
    config_revision: String,
    operator_policy_hash: String,
    requirements: Requirements,
}

impl PolicySnapshot {
    /// Capture an artifact from the exact candidate already admitted by the
    /// policy runtime.
    pub(crate) fn from_verified_candidate(
        candidate: &VerifiedPolicyCandidate,
    ) -> anyhow::Result<Self> {
        Self::from_parts(
            candidate.config(),
            candidate.pack_bodies(),
            candidate.revision().to_owned(),
            candidate.policy_hash(),
        )
    }

    /// Materialize an artifact from a complete schema-5 policy candidate.
    ///
    /// Every declared pack is compiled before publication, including packs
    /// that no profile mounts. An unmounted malformed pack must not become a
    /// deferred invalid artifact.
    #[cfg(test)]
    pub(crate) fn from_target_v5(
        config: &ConfigV5,
        bodies: &PackBodiesV5,
        config_revision: String,
    ) -> anyhow::Result<Self> {
        Self::check_roster(config, bodies)?;
        let admission =
            CompileAdmission::new(config.custom_list_limits.max_compiled_bytes_total, 1)?;
        crate::config::target_v5::compile_v5_operator_rules(config, bodies, &admission)?;
        let bytes = Self::captured_bytes(config, bodies)?;
        let semantic: Vec<_> = bytes
            .iter()
            .map(|(id, body)| {
                Ok(SemanticPack {
                    id: id.as_str(),
                    body: std::str::from_utf8(body)?,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        let operator_policy_hash = hash_policy_candidate(config, &semantic)?.to_string();
        Self::from_parts(config, bodies, config_revision, &operator_policy_hash)
    }

    fn from_parts(
        config: &ConfigV5,
        bodies: &PackBodiesV5,
        config_revision: String,
        operator_policy_hash: &str,
    ) -> anyhow::Result<Self> {
        ensure!(
            config.schema_version == TARGET_SCHEMA_VERSION_V5,
            "ArtifactCapabilityMismatch: target schema"
        );
        Self::check_roster(config, bodies)?;
        let bytes = Self::captured_bytes(config, bodies)?;
        let declared: BTreeSet<_> = config
            .custom_lists
            .iter()
            .map(|list| list.id.clone())
            .collect();

        let mut mounts = BTreeMap::new();
        for (id, profile) in &config.profiles {
            let mut lists = profile.custom_lists.clone();
            lists.sort();
            ensure!(
                lists.windows(2).all(|pair| pair[0] < pair[1])
                    && lists.iter().all(|list| declared.contains(list)),
                "ArtifactInventoryMismatch: mounts"
            );
            mounts.insert(id.clone(), lists);
        }
        let policy = replicated_policy_toml(config)?;
        let requirements = requirements(&bytes, &mounts)?;
        let packs = bytes
            .into_iter()
            .map(|(id, bytes)| {
                let object = ObjectRef::of(&bytes);
                (id, CapturedPack { bytes, object })
            })
            .collect();
        Ok(Self {
            toml: Arc::from(policy),
            #[cfg(test)]
            declarations: config
                .custom_lists
                .iter()
                .map(|list| (list.id.clone(), list.clone()))
                .collect(),
            mounts,
            packs,
            config_revision,
            operator_policy_hash: operator_policy_hash.to_owned(),
            requirements,
        })
    }

    fn check_roster(config: &ConfigV5, bodies: &PackBodiesV5) -> anyhow::Result<()> {
        let declared: BTreeSet<_> = config
            .custom_lists
            .iter()
            .map(|list| list.id.clone())
            .collect();
        ensure!(
            declared.len() == config.custom_lists.len(),
            "ArtifactInventoryMismatch: duplicate declaration"
        );
        ensure!(
            declared.len() == bodies.len(),
            "ArtifactInventoryMismatch: declaration roster"
        );
        ensure!(
            bodies.iter().all(|(id, _)| declared.contains(id)),
            "ArtifactInventoryMismatch: extra pack"
        );
        Ok(())
    }

    fn captured_bytes(
        config: &ConfigV5,
        bodies: &PackBodiesV5,
    ) -> anyhow::Result<BTreeMap<Id, Arc<[u8]>>> {
        config
            .custom_lists
            .iter()
            .map(|list| {
                bodies
                    .get(&list.id)
                    .map(|body| (list.id.clone(), Arc::from(body.as_bytes())))
                    .context("ArtifactInventoryMismatch: missing declared pack")
            })
            .collect()
    }

    pub(crate) fn toml(&self) -> &Arc<[u8]> {
        &self.toml
    }
    #[cfg(test)]
    pub(crate) fn packs(&self) -> &BTreeMap<Id, CapturedPack> {
        &self.packs
    }
    pub(crate) fn config_revision(&self) -> &str {
        &self.config_revision
    }
    pub(crate) fn operator_policy_hash(&self) -> &str {
        &self.operator_policy_hash
    }
    #[cfg(test)]
    pub(crate) fn declarations(&self) -> &BTreeMap<Id, CustomList> {
        &self.declarations
    }

    pub(crate) fn publication(
        &self,
        lineage: &str,
        epoch: u64,
    ) -> anyhow::Result<PublicationCandidate> {
        let mut manifest = Manifest {
            artifact_format: 2,
            schema_version: TARGET_SCHEMA_VERSION_V5,
            operator_rule_grammar: "1".into(),
            compiled_cost_version: CompiledCostV1::VERSION,
            primary_lineage: lineage.into(),
            policy_epoch: epoch,
            config_revision: self.config_revision.clone(),
            operator_policy_hash: self.operator_policy_hash.clone(),
            policy_toml: ObjectRef::of(&self.toml),
            packs: self
                .packs
                .iter()
                .map(|(id, pack)| PackRef {
                    id: id.clone(),
                    sha256: pack.object.sha256.clone(),
                    bytes: pack.object.bytes,
                })
                .collect(),
            mounts: self.mounts.clone(),
            requirements: self.requirements.clone(),
            artifact_hash: String::new(),
        };
        manifest.artifact_hash = manifest.canonical_hash()?;
        let mut objects = BTreeMap::new();
        objects.insert(manifest.policy_toml.sha256.clone(), Arc::clone(&self.toml));
        for pack in self.packs.values() {
            objects.insert(pack.object.sha256.clone(), Arc::clone(&pack.bytes));
        }
        Ok(PublicationCandidate {
            artifact_hash: manifest.artifact_hash.clone(),
            config_revision: self.config_revision.clone(),
            manifest: manifest.encode()?,
            objects,
        })
    }
}

/// Verify a complete current artifact. Schema 4 is rejected here; its decoder
/// belongs solely to the migration/recovery oracle.
pub(crate) fn verify_objects(
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
) -> anyhow::Result<ConfigV5> {
    manifest.validate()?;
    ensure!(
        manifest.schema_version == TARGET_SCHEMA_VERSION_V5
            && manifest.operator_rule_grammar == "1",
        "ArtifactCapabilityMismatch: runtime schema"
    );
    let toml = objects
        .get(&manifest.policy_toml.sha256)
        .context("ArtifactInventoryMismatch: missing TOML")?;
    manifest.policy_toml.verify(toml, MAX_TOML_BYTES)?;
    let value: toml::Value = toml::from_str(std::str::from_utf8(toml)?)?;
    let table = value
        .as_table()
        .context("ArtifactInventoryMismatch: policy TOML is not a table")?;
    for field in crate::config::schema::TARGET_V5_NODE_LOCAL_SECTIONS
        .iter()
        .chain(["includes"].iter())
    {
        ensure!(
            !table.contains_key(*field),
            "ArtifactNodeLocalLeak: {field}"
        );
    }
    if let Some(server) = table.get("server") {
        let server = server
            .as_table()
            .context("ArtifactNodeLocalLeak: server is not a table")?;
        for field in ARTIFACT_NODE_LOCAL_SERVER_FIELDS {
            ensure!(
                !server.contains_key(*field),
                "ArtifactNodeLocalLeak: server.{field}"
            );
        }
    }
    let config: ConfigV5 = value.try_into()?;
    ensure!(
        config.schema_version == TARGET_SCHEMA_VERSION_V5,
        "ArtifactCapabilityMismatch: TOML schema"
    );
    let mut expected = BTreeSet::from([manifest.policy_toml.sha256.as_str()]);
    let mut bodies: BTreeMap<Id, Arc<str>> = BTreeMap::new();
    for pack in &manifest.packs {
        let body = objects
            .get(&pack.sha256)
            .context("ArtifactInventoryMismatch: missing pack")?;
        pack.object().verify(body, MAX_PACK_BYTES)?;
        ensure!(
            bodies
                .insert(pack.id.clone(), Arc::from(std::str::from_utf8(body)?))
                .is_none(),
            "ArtifactInventoryMismatch: duplicate pack"
        );
        expected.insert(pack.sha256.as_str());
    }
    ensure!(
        expected == objects.keys().map(String::as_str).collect(),
        "ArtifactInventoryMismatch: extra object"
    );
    let declared: BTreeSet<_> = config
        .custom_lists
        .iter()
        .map(|list| list.id.clone())
        .collect();
    ensure!(
        declared.len() == config.custom_lists.len() && declared == bodies.keys().cloned().collect(),
        "ArtifactInventoryMismatch: declarations"
    );
    let mut mounts = BTreeMap::new();
    for (id, profile) in &config.profiles {
        let mut lists = profile.custom_lists.clone();
        lists.sort();
        ensure!(
            lists.windows(2).all(|pair| pair[0] < pair[1]),
            "ArtifactInventoryMismatch: duplicate mounts"
        );
        mounts.insert(id.clone(), lists);
    }
    ensure!(
        mounts == manifest.mounts,
        "ArtifactInventoryMismatch: mounts"
    );
    let bytes = bodies
        .iter()
        .map(|(id, body)| (id.clone(), Arc::from(body.as_bytes())))
        .collect();
    ensure!(
        requirements(&bytes, &mounts)? == manifest.requirements,
        "ArtifactRequirementsMismatch"
    );
    let semantic: Vec<_> = bodies
        .iter()
        .map(|(id, body)| SemanticPack {
            id: id.as_str(),
            body,
        })
        .collect();
    ensure!(
        hash_policy_candidate(&config, &semantic)?.to_string() == manifest.operator_policy_hash,
        "ArtifactPolicyHashMismatch"
    );
    Ok(config)
}

fn replicated_policy_toml(config: &ConfigV5) -> anyhow::Result<Vec<u8>> {
    let mut value = toml::Value::try_from(config)?;
    let table = value
        .as_table_mut()
        .context("artifact policy is not a table")?;
    table.remove("includes");
    for section in crate::config::schema::TARGET_V5_NODE_LOCAL_SECTIONS {
        table.remove(*section);
    }
    if let Some(server) = table.get_mut("server") {
        let server = server
            .as_table_mut()
            .context("artifact policy server is not a table")?;
        for field in ARTIFACT_NODE_LOCAL_SERVER_FIELDS {
            server.remove(*field);
        }
    }
    let bytes = toml::to_string(&value)?.into_bytes();
    ensure!(
        bytes.len() <= MAX_TOML_BYTES,
        "ArtifactLimitExceeded: policy TOML"
    );
    Ok(bytes)
}

pub(crate) fn replicated_policy_object(config: &ConfigV5) -> anyhow::Result<ObjectRef> {
    Ok(ObjectRef::of(&replicated_policy_toml(config)?))
}

fn requirements(
    packs: &BTreeMap<Id, Arc<[u8]>>,
    mounts: &BTreeMap<String, Vec<Id>>,
) -> anyhow::Result<Requirements> {
    let mut result = Requirements {
        version: 1,
        compiler_version: 1,
        pack_bytes: 0,
        store: RuleRequirements::default(),
        profiles: BTreeMap::new(),
        packs: BTreeMap::new(),
    };
    for (id, bytes) in packs {
        ensure!(bytes.len() <= MAX_PACK_BYTES, "ArtifactLimitExceeded: pack");
        result.pack_bytes = result
            .pack_bytes
            .checked_add(bytes.len() as u64)
            .context("ArtifactLimitExceeded: pack byte overflow")?;
        ensure!(
            result.pack_bytes <= MAX_TOTAL_PACK_BYTES as u64,
            "ArtifactLimitExceeded: total pack bytes"
        );
        let mut counts = RuleRequirements::default();
        let mut keys = BTreeSet::new();
        for raw in std::str::from_utf8(bytes)?.lines() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
                continue;
            }
            counts.source_rules += 1;
            counts.max_rule_bytes = counts.max_rule_bytes.max(raw.len() as u64);
            let ast = parse_rule_ast(raw)?;
            if !keys.insert(ast.rule_key()) {
                continue;
            }
            match ast.pattern() {
                OperatorPattern::Exact(_) => counts.indexed += 1,
                OperatorPattern::Wildcard(_) => {
                    counts.advanced += 1;
                    if !ast.noapex() {
                        counts.indexed += 1;
                    }
                }
                OperatorPattern::Regex { source, .. } => {
                    counts.advanced += 1;
                    counts.regex += 1;
                    counts.regex_source_bytes += source.len() as u64;
                    counts.max_regex_source_bytes =
                        counts.max_regex_source_bytes.max(source.len() as u64);
                }
            }
        }
        result.store.add(&counts)?;
        result.packs.insert(id.to_string(), counts);
    }
    for (profile, ids) in mounts {
        let mut counts = RuleRequirements::default();
        for id in ids {
            counts.add(
                result
                    .packs
                    .get(id.as_str())
                    .context("ArtifactInventoryMismatch: unknown mount")?,
            )?;
        }
        result.profiles.insert(profile.clone(), counts);
    }
    Ok(result)
}

#[cfg(test)]
mod exact_projection_tests {
    use super::*;

    #[test]
    fn exact_projection_distinguishes_replicated_settings_omitted_by_the_semantic_hash() {
        let mut before = ConfigV5::default();
        before.upstream.servers = vec!["192.0.2.1:53".into()];
        let mut after = before.clone();
        after.upstream.servers = vec!["192.0.2.2:53".into()];
        after.security.enabled = !before.security.enabled;

        assert_eq!(
            hash_policy_candidate(&before, &[]).unwrap(),
            hash_policy_candidate(&after, &[]).unwrap()
        );
        assert_ne!(
            replicated_policy_object(&before).unwrap(),
            replicated_policy_object(&after).unwrap()
        );
    }
}
