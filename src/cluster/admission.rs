//! Receiver-owned limits gate a complete schema-5 artifact before persistence.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;

use crate::config::schema::CustomListLimitsV5;
use crate::config::target_v5::{validate_v5_collect, PackBodiesV5};
use crate::filter::operator_rules::{BudgetExceeded, ProjectionCounts, RuleCompileLimits};
#[cfg(test)]
use crate::{
    config::target_v5::compile_v5_operator_rules,
    filter::operator_rules::{CompileAdmission, CompiledOperatorRules},
};

use super::artifact::verify_objects;
use super::manifest::{Manifest, RuleRequirements};

#[cfg(test)]
pub(crate) fn admit(
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    limits: &RuleCompileLimits,
    admission: &CompileAdmission,
) -> anyhow::Result<CompiledOperatorRules> {
    let (config, bodies) = validate_candidate(manifest, objects, limits)?;
    Ok(compile_v5_operator_rules(&config, &bodies, admission)?)
}

pub(crate) fn verify_for_receiver(
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    limits: &RuleCompileLimits,
) -> anyhow::Result<()> {
    validate_candidate(manifest, objects, limits).map(drop)
}

fn validate_candidate(
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    limits: &RuleCompileLimits,
) -> anyhow::Result<(crate::config::schema::ConfigV5, PackBodiesV5)> {
    limits.validate()?;
    manifest.validate()?;
    preflight(manifest, limits)?;
    let mut config = verify_objects(manifest, objects)?;
    let mut bodies = BTreeMap::new();
    for pack in &manifest.packs {
        let body = std::str::from_utf8(
            objects
                .get(&pack.sha256)
                .context("ArtifactInventoryMismatch: missing pack")?,
        )?;
        for raw in body.lines() {
            if !raw.trim().is_empty() && !raw.trim_start().starts_with('#') {
                check("max_rule_bytes", raw.len() as u64, limits.max_rule_bytes)?;
            }
        }
        bodies.insert(pack.id.clone(), Arc::from(body));
    }
    // Artifact requirements prove what the primary saw; they never elevate
    // this receiver's node-local limits.
    config.custom_list_limits = target_limits(limits);
    validate_v5_collect(
        &config,
        time::OffsetDateTime::now_utc(),
        &mut crate::config::schema::validator::AuditWarnings::silent(),
        None,
    )?;
    Ok((config, PackBodiesV5::new(bodies)))
}

fn preflight(manifest: &Manifest, limits: &RuleCompileLimits) -> anyhow::Result<()> {
    check("max_lists", manifest.packs.len() as u64, limits.max_lists)?;
    check(
        "max_total_bytes",
        manifest.requirements.pack_bytes,
        limits.max_total_bytes,
    )?;
    for pack in &manifest.packs {
        check("max_file_bytes", pack.bytes, limits.max_file_bytes)?;
        let counts = manifest
            .requirements
            .packs
            .get(pack.id.as_str())
            .context("ArtifactInventoryMismatch: missing pack requirements")?;
        check(
            "max_rules_per_list",
            counts.source_rules,
            limits.max_rules_per_list,
        )?;
        check(
            "max_rule_bytes",
            counts.max_rule_bytes,
            limits.max_rule_bytes,
        )?;
    }
    limits.check_store_counts(projections(&manifest.requirements.store)?)?;
    let mut total = ProjectionCounts::default();
    for counts in manifest.requirements.profiles.values() {
        let counts = projections(counts)?;
        limits.check_profile_counts(counts)?;
        total = total.checked_add(counts)?;
    }
    limits.check_total_counts(total)?;
    Ok(())
}

fn check(limit: &'static str, actual: u64, maximum: usize) -> Result<(), BudgetExceeded> {
    let actual = usize::try_from(actual).ok();
    if actual.is_none_or(|actual| actual > maximum) {
        return Err(BudgetExceeded {
            limit,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn projections(counts: &RuleRequirements) -> Result<ProjectionCounts, BudgetExceeded> {
    let count = |value| {
        usize::try_from(value).map_err(|_| BudgetExceeded {
            limit: "arithmetic",
            actual: None,
            maximum: usize::MAX,
        })
    };
    Ok(ProjectionCounts {
        indexed: count(counts.indexed)?,
        advanced: count(counts.advanced)?,
        regex: count(counts.regex)?,
    })
}

fn target_limits(limits: &RuleCompileLimits) -> CustomListLimitsV5 {
    let RuleCompileLimits {
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
    } = *limits;
    CustomListLimitsV5 {
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
    }
}
