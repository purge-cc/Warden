use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context};

use crate::config::loader::LoadedConfig;
use crate::config::schema::{AdminRule, ConfigV1, Device, Group, Id, Profile, ScheduleTargetType};

/// Frozen migration view of the last schema-4 runtime model.
#[derive(Debug, Clone)]
pub(crate) struct HistoricalConfigV4 {
    pub(crate) config: ConfigV1,
    rules: BTreeMap<Id, AdminRule>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolverSourceV4 {
    pub(crate) profile_id: Id,
    pub(crate) group_id: Option<Id>,
}

impl HistoricalConfigV4 {
    pub(crate) fn decode(loaded: &LoadedConfig) -> anyhow::Result<Self> {
        ensure!(
            loaded.config.schema_version == 4,
            "historical decoder requires schema 4"
        );
        let mut rules = BTreeMap::new();
        for rule in &loaded.config.admin_rules {
            ensure!(
                rules.insert(rule.id.clone(), rule.clone()).is_none(),
                "duplicate historical admin rule {}",
                rule.id
            );
        }
        Ok(Self {
            config: loaded.config.clone(),
            rules,
        })
    }

    pub(crate) fn rule(&self, id: &Id) -> anyhow::Result<&AdminRule> {
        self.rules
            .get(id)
            .with_context(|| format!("historical admin rule {id} does not exist"))
    }

    pub(crate) fn profile(&self, id: &Id) -> anyhow::Result<&Profile> {
        self.config
            .profiles
            .get(id.as_str())
            .with_context(|| format!("historical profile {id} does not exist"))
    }

    pub(crate) fn resolver_source(&self, device: &Device) -> Option<ResolverSourceV4> {
        if let Some(profile) = device.profile.as_ref() {
            return Some(ResolverSourceV4 {
                profile_id: profile.clone(),
                group_id: None,
            });
        }
        let memberships = self.memberships(device);
        self.config
            .groups
            .iter()
            .filter(|group| memberships.contains(&group.id))
            .max_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then_with(|| right.id.cmp(&left.id))
            })
            .map(|group| ResolverSourceV4 {
                profile_id: group.profile.clone(),
                group_id: Some(group.id.clone()),
            })
    }

    pub(crate) fn memberships(&self, device: &Device) -> BTreeSet<Id> {
        let mut memberships: BTreeSet<_> = device.groups.iter().cloned().collect();
        memberships.extend(
            self.config
                .groups
                .iter()
                .filter(|group| group.devices.iter().any(|id| id == &device.id))
                .map(|group| group.id.clone()),
        );
        memberships
    }

    pub(crate) fn applicable_schedule_exists(&self, device: &Device) -> bool {
        let memberships = self.memberships(device);
        self.config
            .schedules
            .iter()
            .any(|schedule| match schedule.target_type {
                ScheduleTargetType::Device => schedule.target_id == device.id,
                ScheduleTargetType::Group => memberships.contains(&schedule.target_id),
            })
    }

    pub(crate) fn groups(&self) -> &[Group] {
        &self.config.groups
    }
}
