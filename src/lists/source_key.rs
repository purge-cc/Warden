//! Typed source-key facades for the list manager / profile resolver
//! contract.
//!
//! [`SourceBitMap`] replaces a raw `HashMap<String, u8>` that keyed every
//! entry by `String` and relied on a kebab→slash compatibility shim to
//! bridge URL-keyed producer to id-keyed consumer. That contract was too
//! easy to break: a config cleanup that emptied `[lists].sources = []`
//! left every profile's `list_bitmask` zeroed because no slash-form keys
//! remained for the shim to translate.
//!
//! The typed facades expose lookup methods, one per source kind, so call
//! sites declare their intent at the lookup line:
//!
//! - [`SourceBitMap::bit_for_url`] / [`SourceBitMap::bit_for_v1_id`] /
//!   [`SourceBitMap::bit_for_legacy_catalog_id`] — the bit map.
//! - [`SourceTrustMap::trust_for_url`] / [`SourceTrustMap::trust_for_v1_id`]
//!   — per-source `BlocklistTrust`, fed to the `imported.local` loader
//!   bridge.
//! - [`SourceTokenMap::token_for_url`] / [`SourceTokenMap::token_for_v1_id`]
//!   — per-source bearer token resolved from `secrets.toml`.
//!
//! Each facade owns its own seeding rules but shares the same
//! [`is_url_source`] heuristic for distinguishing URL-form vs legacy
//! slash-form catalog ids — the validator at
//! `src/config/schema/validator.rs` only accepts the two shapes.
//!

use std::collections::{BTreeMap, HashMap};

use ahash::RandomState;
use compact_str::CompactString;
use sha2::{Digest, Sha256};

use crate::config::schema::id::Id;
use crate::config::schema::{effective_direction, Blocklist, BlocklistTrust, ListPolicy, Profile};
use crate::filter::engine::{PolicyMasks, ProfileMasks};

use super::catalog::Catalog;
use super::manager::{BitMapBuildError, MAX_LIST_SOURCES};

/// Frozen error for aliases that would make one fetched source mean two
/// different policies.
pub const LIST_SOURCE_ALIAS_CONFLICT: &str =
    "list source aliases \"{first}\" and \"{second}\" resolve to \"{url}\" but disagree on {field}; make their effective source settings identical or disable one";

/// Controls whether row-level settings are part of a source's meaning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RowControlMode {
    /// Historical schemas retain global-only row-control semantics.
    #[default]
    InheritAll,
    /// New schemas honor row controls.
    HonorOverrides,
}

impl RowControlMode {
    pub fn for_schema_version(schema_version: u32) -> Self {
        if schema_version >= 4 {
            Self::HonorOverrides
        } else {
            Self::InheritAll
        }
    }
}

/// Global values used when a row control is inherited or schema-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowControlDefaults {
    pub max_entries: usize,
    pub update_interval_secs: u64,
}

impl Default for RowControlDefaults {
    fn default() -> Self {
        let lists = crate::config::settings::ListsConfig::default();
        Self {
            max_entries: lists.max_entries,
            update_interval_secs: lists.update_interval_secs,
        }
    }
}

pub(crate) type ManagerSourceMaps = (
    HashMap<String, (Id, u32)>,
    HashMap<String, crate::lists::detector::ListFormat>,
    HashMap<String, usize>,
);

/// Substitute every alias-conflict placeholder.
pub fn format_list_source_alias_conflict(
    first: &str,
    second: &str,
    canonical_url: &str,
    field: &str,
) -> String {
    LIST_SOURCE_ALIAS_CONFLICT
        .replace("{first}", first)
        .replace("{second}", second)
        .replace("{url}", canonical_url)
        .replace("{field}", field)
}

/// The configured fields that must agree before aliases can share a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceAliasConflict {
    field: String,
}

impl SourceAliasConflict {
    pub(crate) fn field(&self) -> &str {
        &self.field
    }
}

/// Compare semantics after profile inheritance has been applied.
pub(crate) fn blocklist_alias_conflict(
    first: &Blocklist,
    second: &Blocklist,
    profiles: &BTreeMap<String, Profile>,
    defaults: RowControlDefaults,
    row_control_mode: RowControlMode,
) -> Option<SourceAliasConflict> {
    if first.base != second.base {
        return Some(SourceAliasConflict {
            field: "base direction".to_string(),
        });
    }
    for (profile_id, profile) in profiles {
        if effective_direction(profile, first) != effective_direction(profile, second) {
            return Some(SourceAliasConflict {
                field: format!("effective direction for profile \"{profile_id}\""),
            });
        }
    }
    if first.format != second.format {
        return Some(SourceAliasConflict {
            field: "parser format".to_string(),
        });
    }
    if first.trust != second.trust {
        return Some(SourceAliasConflict {
            field: "trust mode".to_string(),
        });
    }
    if first.auth_token_ref != second.auth_token_ref {
        return Some(SourceAliasConflict {
            field: "auth-token reference".to_string(),
        });
    }
    if effective_max_entries(first.max_entries, defaults.max_entries, row_control_mode)
        != effective_max_entries(second.max_entries, defaults.max_entries, row_control_mode)
    {
        return Some(SourceAliasConflict {
            field: "effective max-entries cap".to_string(),
        });
    }
    if effective_update_interval_secs(
        first.update_interval_hours,
        defaults.update_interval_secs,
        row_control_mode,
    ) != effective_update_interval_secs(
        second.update_interval_hours,
        defaults.update_interval_secs,
        row_control_mode,
    ) {
        return Some(SourceAliasConflict {
            field: "effective update interval".to_string(),
        });
    }
    if first.max_consecutive_failures != second.max_consecutive_failures {
        return Some(SourceAliasConflict {
            field: "max-consecutive-failures retry ownership".to_string(),
        });
    }
    None
}

/// A row can only narrow the global safety ceiling. Values wider than this
/// platform's `usize` are necessarily wider than that ceiling too.
pub(crate) fn effective_max_entries(
    row_max_entries: Option<u64>,
    global_max_entries: usize,
    row_control_mode: RowControlMode,
) -> usize {
    if matches!(row_control_mode, RowControlMode::InheritAll) {
        return global_max_entries;
    }
    row_max_entries
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(global_max_entries)
        .min(global_max_entries)
}

/// Resolve the source's cadence after schema compatibility and inheritance.
pub(crate) fn effective_update_interval_secs(
    row_update_interval_hours: Option<u32>,
    global_update_interval_secs: u64,
    row_control_mode: RowControlMode,
) -> u64 {
    let configured = if matches!(row_control_mode, RowControlMode::HonorOverrides) {
        row_update_interval_hours
            .map(|hours| u64::from(hours) * 3600)
            .unwrap_or(global_update_interval_secs)
    } else {
        global_update_interval_secs
    };
    configured.max(60)
}

/// One enabled, catalog-resolved source and every configured alias for it.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    representative: String,
    fetch_url: String,
    canonical_url: String,
    schedule_key: CanonicalSourceScheduleKey,
    source_aliases: Vec<String>,
    id_aliases: Vec<Id>,
    owner: Option<PlannedBlocklist>,
    effective_max_entries: usize,
    effective_update_interval_secs: u64,
}

impl ResolvedSource {
    /// The first configured spelling. It is the sole cache and status key
    /// for this canonical URL.
    pub fn representative(&self) -> &str {
        &self.representative
    }

    /// Exact URL selected for this generation's HTTP fetch.
    pub fn fetch_url(&self) -> &str {
        &self.fetch_url
    }

    /// Canonical URL identity after catalog resolution.
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    /// Opaque durable scheduling identity computed from the raw fetch URL.
    pub fn schedule_key(&self) -> &CanonicalSourceScheduleKey {
        &self.schedule_key
    }

    fn owner(&self) -> Option<&PlannedBlocklist> {
        self.owner.as_ref()
    }

    pub(crate) fn owner_blocklist(&self) -> Option<&Blocklist> {
        self.owner().map(|owner| &owner.row)
    }

    /// The cap this canonical source is parsed and digested under.
    pub fn effective_max_entries(&self) -> usize {
        self.effective_max_entries
    }

    /// The cadence modeled for this canonical source.
    pub fn effective_update_interval_secs(&self) -> u64 {
        self.effective_update_interval_secs
    }

    /// All configuration ids sharing this canonical fetch identity.
    pub(crate) fn id_aliases(&self) -> &[Id] {
        &self.id_aliases
    }
}

/// The first configured row owns source behavior.
#[derive(Debug, Clone)]
struct PlannedBlocklist {
    row: Blocklist,
}

/// Error raised when aliases would make one downloaded body ambiguous.
#[derive(Debug, thiserror::Error)]
pub enum ResolvedSourcePlanError {
    #[error("{message}")]
    Conflict { message: String },
}

/// The single resolved identity plan for one list generation.
///
/// A canonical URL owns one representative, bit, cache stem, status slot,
/// and retry owner. All configured spellings resolve back to that seat.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSourcePlan {
    sources: Vec<ResolvedSource>,
    source_to_representative: HashMap<String, String>,
    canonical_url_to_representative: HashMap<String, String>,
    id_to_representative: HashMap<Id, String>,
    primary_id_by_representative: HashMap<String, Id>,
    row_control_mode: RowControlMode,
}

impl ResolvedSourcePlan {
    /// Resolve configured sources through the exact catalog selected for this
    /// generation, keeping the first configured spelling as representative.
    pub fn build(
        catalog: &Catalog,
        legacy: &[String],
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
    ) -> Result<Self, ResolvedSourcePlanError> {
        Self::build_for_schema(
            catalog,
            legacy,
            blocklists,
            profiles,
            RowControlDefaults::default(),
            3,
        )
    }

    /// Resolve sources with explicitly selected row-control semantics.
    pub fn build_with_row_control_defaults(
        catalog: &Catalog,
        legacy: &[String],
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
        defaults: RowControlDefaults,
        row_control_mode: RowControlMode,
    ) -> Result<Self, ResolvedSourcePlanError> {
        Self::build_with_control_mode(
            catalog,
            legacy,
            blocklists,
            profiles,
            defaults,
            row_control_mode,
        )
    }

    /// Resolve sources under the compatibility mode selected by config.
    pub fn build_for_schema(
        catalog: &Catalog,
        legacy: &[String],
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
        defaults: RowControlDefaults,
        schema_version: u32,
    ) -> Result<Self, ResolvedSourcePlanError> {
        Self::build_with_control_mode(
            catalog,
            legacy,
            blocklists,
            profiles,
            defaults,
            RowControlMode::for_schema_version(schema_version),
        )
    }

    fn build_with_control_mode(
        catalog: &Catalog,
        legacy: &[String],
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
        defaults: RowControlDefaults,
        row_control_mode: RowControlMode,
    ) -> Result<Self, ResolvedSourcePlanError> {
        let mut plan = Self {
            row_control_mode,
            ..Self::default()
        };
        let mut by_canonical_url: HashMap<String, usize> = HashMap::new();
        let enabled_by_id: HashMap<Id, &Blocklist> = blocklists
            .iter()
            .filter(|row| row.enabled)
            .map(|row| (row.id.clone(), row))
            .collect();
        let mut catalog_legacy_ids: HashMap<Id, (String, String)> = HashMap::new();

        for source in legacy {
            let catalog_url = catalog.resolve(source);
            let legacy_id = (!is_url_source(source))
                .then(|| Id::new(source.replace('/', "-")))
                .transpose()
                .ok()
                .flatten();
            let fetch_url = match (&catalog_url, legacy_id.as_ref()) {
                (Some(url), _) => url.clone(),
                (None, Some(id)) => match enabled_by_id.get(id) {
                    Some(row) => row.url.clone(),
                    None => continue,
                },
                (None, None) => continue,
            };
            let canonical_url = canonical_url_key(&fetch_url);
            let index = plan.push_or_get(
                &mut by_canonical_url,
                source,
                fetch_url,
                canonical_url,
                defaults,
            );
            plan.sources[index].source_aliases.push(source.clone());
            if let Some(id) = legacy_id {
                plan.sources[index].id_aliases.push(id.clone());
                if catalog_url.is_some() {
                    let resolved_url = plan.sources[index].canonical_url.clone();
                    if let Some((first_source, first_url)) = catalog_legacy_ids.get(&id) {
                        if first_url != &resolved_url {
                            return Err(ResolvedSourcePlanError::Conflict {
                                message: format_list_source_alias_conflict(
                                    first_source,
                                    source,
                                    first_url,
                                    "resolved URL",
                                ),
                            });
                        }
                    } else {
                        catalog_legacy_ids.insert(id, (source.clone(), resolved_url));
                    }
                }
            }
        }

        for blocklist in blocklists.iter().filter(|b| b.enabled) {
            let canonical_url = canonical_url_key(&blocklist.url);
            if let Some((legacy_source, legacy_url)) = catalog_legacy_ids.get(&blocklist.id) {
                if legacy_url != &canonical_url {
                    return Err(ResolvedSourcePlanError::Conflict {
                        message: format_list_source_alias_conflict(
                            legacy_source,
                            blocklist.id.as_str(),
                            legacy_url,
                            "resolved URL",
                        ),
                    });
                }
            }

            let index = plan.push_or_get(
                &mut by_canonical_url,
                blocklist.url.as_str(),
                blocklist.url.clone(),
                canonical_url.clone(),
                defaults,
            );
            let source = &mut plan.sources[index];
            source.source_aliases.push(blocklist.url.clone());
            source.source_aliases.push(blocklist.id.to_string());
            if let Some(slug) = legacy_slug_for_id(&blocklist.id) {
                source.source_aliases.push(slug);
            }
            source.id_aliases.push(blocklist.id.clone());
            if let Some(owner) = source.owner.as_ref() {
                if let Some(conflict) = blocklist_alias_conflict(
                    &owner.row,
                    blocklist,
                    profiles,
                    defaults,
                    row_control_mode,
                ) {
                    return Err(ResolvedSourcePlanError::Conflict {
                        message: format_list_source_alias_conflict(
                            owner.row.id.as_str(),
                            blocklist.id.as_str(),
                            &canonical_url,
                            conflict.field(),
                        ),
                    });
                }
            } else {
                source.owner = Some(PlannedBlocklist {
                    row: blocklist.clone(),
                });
                source.effective_max_entries = effective_max_entries(
                    blocklist.max_entries,
                    defaults.max_entries,
                    row_control_mode,
                );
                source.effective_update_interval_secs = effective_update_interval_secs(
                    blocklist.update_interval_hours,
                    defaults.update_interval_secs,
                    row_control_mode,
                );
            }
        }

        for source in &plan.sources {
            for alias in &source.source_aliases {
                insert_alias(
                    &mut plan.source_to_representative,
                    alias,
                    source,
                    "resolved URL",
                )?;
            }
            insert_alias(
                &mut plan.canonical_url_to_representative,
                &source.canonical_url,
                source,
                "resolved URL",
            )?;
            for id in &source.id_aliases {
                if let Some(existing) = plan.id_to_representative.get(id) {
                    if existing != &source.representative {
                        return Err(ResolvedSourcePlanError::Conflict {
                            message: format_list_source_alias_conflict(
                                existing,
                                id.as_str(),
                                &source.canonical_url,
                                "resolved URL",
                            ),
                        });
                    }
                } else {
                    plan.id_to_representative
                        .insert(id.clone(), source.representative.clone());
                }
            }
            let primary = source
                .owner()
                .map(|owner| owner.row.id.clone())
                .or_else(|| source.id_aliases.first().cloned());
            if let Some(id) = primary {
                plan.primary_id_by_representative
                    .insert(source.representative.clone(), id);
            }
        }
        Ok(plan)
    }

    fn push_or_get(
        &mut self,
        by_canonical_url: &mut HashMap<String, usize>,
        representative: &str,
        fetch_url: String,
        canonical_url: String,
        defaults: RowControlDefaults,
    ) -> usize {
        if let Some(index) = by_canonical_url.get(&canonical_url) {
            *index
        } else {
            let index = self.sources.len();
            by_canonical_url.insert(canonical_url.clone(), index);
            self.sources.push(ResolvedSource {
                representative: representative.to_string(),
                schedule_key: schedule_key_from_raw_fetch_url(&fetch_url),
                fetch_url,
                canonical_url,
                source_aliases: Vec::new(),
                id_aliases: Vec::new(),
                owner: None,
                effective_max_entries: defaults.max_entries,
                effective_update_interval_secs: effective_update_interval_secs(
                    None,
                    defaults.update_interval_secs,
                    self.row_control_mode,
                ),
            });
            index
        }
    }

    /// Representatives in deterministic declaration order.
    pub fn representatives(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(|source| source.representative.clone())
            .collect()
    }

    /// Number of canonical source identities.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// `true` when no enabled source has a representative.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub fn row_control_mode(&self) -> RowControlMode {
        self.row_control_mode
    }

    /// Resolve a configured source spelling or canonical-equivalent URL.
    pub fn representative_for_source(&self, source: &str) -> Option<&str> {
        self.source_to_representative
            .get(source)
            .or_else(|| {
                self.canonical_url_to_representative
                    .get(&canonical_url_key(source))
            })
            .or_else(|| {
                Id::new(source)
                    .ok()
                    .and_then(|id| self.id_to_representative.get(&id))
            })
            .map(String::as_str)
    }

    /// Resolve any configured list id to its representative.
    pub fn representative_for_id(&self, id: &Id) -> Option<&str> {
        self.id_to_representative.get(id).map(String::as_str)
    }

    /// Resolve an alias to the exact URL this generation fetches.
    pub fn fetch_url_for_source(&self, source: &str) -> Option<&str> {
        let representative = self.representative_for_source(source)?;
        self.sources
            .iter()
            .find(|planned| planned.representative == representative)
            .map(ResolvedSource::fetch_url)
    }

    /// Deterministic list id displayed for a representative source.
    pub fn primary_id_for_source(&self, source: &str) -> Option<&Id> {
        let representative = self.representative_for_source(source)?;
        self.primary_id_by_representative.get(representative)
    }

    /// Iterate canonical sources in declaration order.
    pub fn sources(&self) -> impl Iterator<Item = &ResolvedSource> {
        self.sources.iter()
    }

    pub(crate) fn source_aliases(&self) -> &HashMap<String, String> {
        &self.source_to_representative
    }

    pub(crate) fn canonical_url_aliases(&self) -> &HashMap<String, String> {
        &self.canonical_url_to_representative
    }

    pub(crate) fn id_aliases(&self) -> &HashMap<Id, String> {
        &self.id_to_representative
    }

    pub(crate) fn primary_ids(&self) -> &HashMap<String, Id> {
        &self.primary_id_by_representative
    }

    pub(crate) fn fetch_urls(&self) -> HashMap<String, String> {
        self.sources
            .iter()
            .map(|source| (source.representative.clone(), source.fetch_url.clone()))
            .collect()
    }

    /// Manager lookups for the representatives that can reach its fetch loop.
    pub(crate) fn manager_source_maps(&self) -> ManagerSourceMaps {
        let mut source_to_blocklist = HashMap::new();
        let mut source_to_format = HashMap::new();
        let mut source_to_max_entries = HashMap::new();
        for source in &self.sources {
            for alias in &source.source_aliases {
                source_to_max_entries.insert(alias.clone(), source.effective_max_entries);
            }
            let Some(owner) = source.owner() else {
                continue;
            };
            let format = match owner.row.format {
                crate::config::schema::BlocklistFormat::Domains => None,
                crate::config::schema::BlocklistFormat::Hosts => {
                    Some(crate::lists::detector::ListFormat::Hosts)
                }
                crate::config::schema::BlocklistFormat::Adguard => {
                    Some(crate::lists::detector::ListFormat::AdGuard)
                }
            };
            for alias in &source.source_aliases {
                source_to_blocklist.insert(
                    alias.clone(),
                    (owner.row.id.clone(), owner.row.max_consecutive_failures),
                );
                if let Some(format) = format {
                    source_to_format.insert(alias.clone(), format);
                }
            }
        }
        (source_to_blocklist, source_to_format, source_to_max_entries)
    }
}

fn insert_alias(
    aliases: &mut HashMap<String, String>,
    alias: &str,
    source: &ResolvedSource,
    field: &str,
) -> Result<(), ResolvedSourcePlanError> {
    if let Some(existing) = aliases.get(alias) {
        if existing != &source.representative {
            return Err(ResolvedSourcePlanError::Conflict {
                message: format_list_source_alias_conflict(
                    existing,
                    alias,
                    &source.canonical_url,
                    field,
                ),
            });
        }
    } else {
        aliases.insert(alias.to_string(), source.representative.clone());
    }
    Ok(())
}

fn legacy_slug_for_id(id: &Id) -> Option<String> {
    let id = id.as_str();
    let split = id.find('-')?;
    Some(format!("{}/{}", &id[..split], &id[split + 1..]))
}

/// Typed facade over the URL ↔ v1-id ↔ legacy-catalog-id source bit map.
///
/// Internally three submaps share a single bit-index space (0..64). Every
/// bit that is reachable by URL is also reachable by v1 id (when a
/// matching `[[blocklists]]` row exists) and by legacy catalog id (when
/// the entry came from `[lists].sources` in slash form). The asymmetry
/// only goes one way: the URL channel is always populated; the id
/// channels are populated when the data is available.
#[derive(Debug, Clone, Default)]
pub struct SourceBitMap {
    by_url: HashMap<String, u8>,
    by_canonical_url: HashMap<String, u8>,
    by_v1_id: HashMap<Id, u8>,
    by_legacy_catalog_id: HashMap<String, u8>,
    representatives: Vec<String>,
}

impl SourceBitMap {
    /// Build the typed bit map from a merged `sources` vector
    /// (`merge_sources_with_blocklists` output) and the v1
    /// `[[blocklists]]` catalogue.
    ///
    /// **Bit assignment.** Sequential, one bit per canonical URL identity.
    /// Returns [`BitMapBuildError::TooManySources`] when
    /// the number of distinct canonical identities exceeds
    /// `MAX_LIST_SOURCES`. The error message is
    /// preserved verbatim from the legacy `build_source_bit_map` so
    /// frozen-strings tests stay green.
    ///
    /// **Seeding.** For each source, always populate `by_url` (the
    /// manager's fetch loop keys exactly on this string). When the
    /// source is a slash-form catalog id (heuristic: scheme is not
    /// `http://` / `https://`), also populate `by_legacy_catalog_id`
    /// and try to seed `by_v1_id` with `Id::new(source.replace('/','-'))`
    /// — invalid translations are silently skipped (the lookup simply
    /// returns `None` and the consumer treats it as "this list is not
    /// in the profile's bitmask").
    ///
    /// For each enabled blocklist whose URL has a bit, alias
    /// `by_v1_id[blocklist.id] → bit`. Disabled blocklists are skipped
    /// (their URL is not in `sources` per
    /// `merge_sources_with_blocklists`, so the alias would dangle).
    ///
    /// **Why both paths seed `by_v1_id`.** A pure-v1 config (empty
    /// `[lists].sources`, populated `[[blocklists]]`) would zero the
    /// profile resolver's bitmask if only the URL-keyed map were
    /// consulted, because it has no id to match. A mixed/legacy config
    /// (`[lists].sources = ["privacy/ads"]`) only worked through the
    /// kebab→slash shim. With both channels seeding `by_v1_id`, the
    /// consumer collapses to a single `bit_for_v1_id(bid)` call
    /// regardless of source kind — closing the contract gap at the type
    /// level.
    pub fn build(sources: &[String], blocklists: &[Blocklist]) -> Result<Self, BitMapBuildError> {
        let mut representatives = Vec::with_capacity(sources.len());
        let mut representative_by_canonical = HashMap::with_capacity(sources.len());
        for source in sources {
            let canonical = canonical_url_key(source);
            if let std::collections::hash_map::Entry::Vacant(entry) =
                representative_by_canonical.entry(canonical)
            {
                entry.insert(representatives.len());
                representatives.push(source.clone());
            }
        }
        if representatives.len() > MAX_LIST_SOURCES {
            return Err(BitMapBuildError::TooManySources {
                got: representatives.len(),
                max: MAX_LIST_SOURCES,
            });
        }

        // Tighter capacity hints: every source contributes at most one
        // entry to each submap (`by_v1_id` is bounded by `sources +
        // blocklists`, the slash-form translation can never exceed
        // `sources`). Avoids one rehash on the typical 64-bit-cap path.
        let mut by_url: HashMap<String, u8> = HashMap::with_capacity(sources.len());
        let mut by_canonical_url: HashMap<String, u8> =
            HashMap::with_capacity(representatives.len());
        let mut by_v1_id: HashMap<Id, u8> =
            HashMap::with_capacity(sources.len() + blocklists.len());
        let mut by_legacy_catalog_id: HashMap<String, u8> = HashMap::with_capacity(sources.len());

        for source in sources {
            let bit = *representative_by_canonical
                .get(&canonical_url_key(source))
                .expect("each source canonical key has a representative")
                as u8;
            by_url.entry(source.clone()).or_insert(bit);
            by_canonical_url
                .entry(canonical_url_key(source))
                .or_insert(bit);

            if !is_url_source(source) {
                by_legacy_catalog_id.insert(source.clone(), bit);
                if let Ok(id) = Id::new(source.replace('/', "-")) {
                    by_v1_id.entry(id).or_insert(bit);
                }
            }
        }

        for b in blocklists {
            if !b.enabled {
                continue;
            }
            if let Some(&bit) = by_canonical_url.get(&canonical_url_key(&b.url)) {
                by_v1_id.insert(b.id.clone(), bit);
                by_canonical_url
                    .entry(canonical_url_key(&b.url))
                    .or_insert(bit);
            }
        }

        Ok(Self {
            by_url,
            by_canonical_url,
            by_v1_id,
            by_legacy_catalog_id,
            representatives,
        })
    }

    /// Build every alias lookup from the one resolved source plan.
    pub fn from_plan(plan: &ResolvedSourcePlan) -> Result<Self, BitMapBuildError> {
        if plan.len() > MAX_LIST_SOURCES {
            return Err(BitMapBuildError::TooManySources {
                got: plan.len(),
                max: MAX_LIST_SOURCES,
            });
        }

        let representatives = plan.representatives();
        let mut by_url = HashMap::new();
        let mut by_canonical_url = HashMap::new();
        let mut by_v1_id = HashMap::new();
        let mut by_legacy_catalog_id = HashMap::new();
        for (bit, source) in plan.sources().enumerate() {
            let bit = bit as u8;
            for alias in &source.source_aliases {
                by_url.entry(alias.clone()).or_insert(bit);
            }
            by_canonical_url
                .entry(source.canonical_url.clone())
                .or_insert(bit);
            for id in &source.id_aliases {
                by_v1_id.entry(id.clone()).or_insert(bit);
            }
            for alias in &source.source_aliases {
                if !is_url_source(alias) {
                    by_legacy_catalog_id.entry(alias.clone()).or_insert(bit);
                }
            }
        }
        Ok(Self {
            by_url,
            by_canonical_url,
            by_v1_id,
            by_legacy_catalog_id,
            representatives,
        })
    }

    /// Project the operator's list policy onto **this** generation's bits.
    ///
    /// The one place a stable list id becomes a bit position: the config
    /// expresses policy per **list id**, which is stable, and only this
    /// function turns it into a `u64`, which is **positional** — `bit = i`
    /// over the merged sources vector, so removing one list slides every
    /// later list down one bit. A mask that crossed the config→engine
    /// boundary on its own could therefore meet a corpus that had
    /// re-assigned the bits it names, and under allow-beats-block the
    /// superset error is silent and fails open.
    ///
    /// The returned [`PolicyMasks`] goes straight into
    /// [`crate::filter::engine::ListPolicy::publish`] and travels in the same
    /// `Arc` as the entries it interprets. **Do not stash it anywhere else.**
    ///
    /// Direction per pair is [`effective_direction`] — one function, every
    /// caller; this is not the place to re-derive the inheritance rule.
    ///
    /// **Disabled rows contribute nothing**, and not by an explicit test:
    /// `merge_sources_with_blocklists` never puts their URL in the merged
    /// sources vector, so `by_url` has no bit for them. Claiming one would be
    /// meaningless at best and, if a disabled row shadowed an enabled row's
    /// URL, actively wrong.
    ///
    /// **A list with no bit is skipped silently, and that is correct here.**
    /// It carries no domains in this generation, so no mask bit could ever
    /// meet it. The operator-facing complaint about a policy naming a list
    /// that does not exist belongs to the validator, which sees the config
    /// and can name the id.
    pub fn project_policy(
        &self,
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
    ) -> PolicyMasks {
        // The masks a profile carrying no override of its own gets. Same
        // rule as the per-profile loop below, reached through the same
        // mapping (`BlocklistBase::as_policy`) rather than re-spelled here
        // — the reason `Ignore` could not be forgotten at one of the two
        // sites.
        let mut inherited = ProfileMasks::INERT;
        for b in blocklists {
            let Some(bit) = self.bit_for_list(b) else {
                continue;
            };
            match b.base.as_policy() {
                ListPolicy::Deny => inherited.block |= 1u64 << bit,
                ListPolicy::Allow => inherited.allow |= 1u64 << bit,
                ListPolicy::Ignore => {}
            }
        }

        let mut per_profile: HashMap<CompactString, ProfileMasks, RandomState> =
            HashMap::with_capacity_and_hasher(profiles.len(), RandomState::new());
        for (pid, profile) in profiles {
            let mut masks = ProfileMasks::INERT;
            for b in blocklists {
                let Some(bit) = self.bit_for_list(b) else {
                    continue;
                };
                match effective_direction(profile, b) {
                    ListPolicy::Deny => masks.block |= 1u64 << bit,
                    ListPolicy::Allow => masks.allow |= 1u64 << bit,
                    ListPolicy::Ignore => {}
                }
            }
            debug_assert_eq!(
                masks.allow & masks.block,
                0,
                "profile `{pid}` has a list bit in both directions — \
                 `effective_direction` returned two answers for one pair",
            );
            per_profile.insert(CompactString::new(pid), masks);
        }

        PolicyMasks {
            base: inherited,
            per_profile,
        }
    }

    /// The bit this generation gave `b`, or `None` if it holds none.
    /// Id aliases preserve one policy bit across URL and legacy spellings.
    fn bit_for_list(&self, b: &Blocklist) -> Option<u8> {
        if !b.enabled {
            return None;
        }
        self.bit_for_v1_id(&b.id)
    }

    /// Look up the bit for a fetch URL. Used by the list manager's
    /// download loop.
    pub fn bit_for_url(&self, url: &str) -> Option<u8> {
        self.by_url
            .get(url)
            .or_else(|| self.by_canonical_url.get(&canonical_url_key(url)))
            .copied()
    }

    /// Look up the bit for a v1 entity [`Id`]. Called by the profile
    /// resolver once per applicable list when it turns the tag
    /// intersection into a subscription mask — `ResolvedProfile::build_v1`
    /// and `specialise_with_effective_tags`, both in
    /// `src/profiles/profile.rs`. The ids come from
    /// `blocklist.tags ∩ effective_tags`.
    pub fn bit_for_v1_id(&self, id: &Id) -> Option<u8> {
        self.by_v1_id.get(id).copied()
    }

    /// Look up the bit for a legacy slash-form catalog id (e.g.
    /// `"security/malicious"`). Used by tooling and migration paths
    /// that still speak the pre-v1 `[lists].sources` format.
    pub fn bit_for_legacy_catalog_id(&self, slash_id: &str) -> Option<u8> {
        self.by_legacy_catalog_id.get(slash_id).copied()
    }

    /// Iterate representatives in bit order. Used by the list manager's
    /// fetch loop and debug tooling.
    pub fn iter_urls(&self) -> impl Iterator<Item = (&str, u8)> {
        self.representatives
            .iter()
            .enumerate()
            .map(|(bit, source)| (source.as_str(), bit as u8))
    }

    /// Total number of URL keys (one per assigned bit).
    pub fn len(&self) -> usize {
        self.representatives.len()
    }

    /// `true` when no source has been seeded.
    pub fn is_empty(&self) -> bool {
        self.representatives.is_empty()
    }
}

/// Heuristic: an entry is a URL when it carries the `http://` or
/// `https://` scheme. Everything else is treated as a legacy slash-form
/// catalog id (the validator at `src/config/schema/validator.rs` only
/// accepts these two shapes for `[lists].sources`).
///
/// **The one seat for this classification, crate-wide** — the source-key
/// facades here, the `lists`/`blocklist` CLI verbs, and the catalog
/// resolver all route through it. The predicate decides where warden
/// fetches a blocklist from, so a second copy is a second scheme policy:
/// whichever copy a change misses keeps accepting or rejecting on the
/// old rule, silently and without a failing build.
///
/// Case-sensitive by contract: `HTTP://host/l.txt` is **not** a URL
/// here, it is a (nonsensical) legacy catalog id. Widening that is a
/// scheme-policy change and belongs in this function, not at a call
/// site.
pub(crate) fn is_url_source(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Canonical key for comparing blocklist identity.
///
/// **NOT used for fetching**: the original URL is still what gets
/// downloaded, and the on-disk cache stem is still derived from it
/// (`lists::manager::source_to_cache_stem`). This is purely an
/// equivalence key, so two entries that differ only in ways HTTP
/// considers meaningless compare equal.
///
/// The single point of truth for "are these two blocklists the same
/// source?". Three callers share it:
/// the `warden blocklist add` gate, the `warden blocklist set <id> url`
/// gate, and the validator's duplicate check
/// ([`crate::config::schema::validator::BLOCKLIST_DUPLICATE_URL`]).
/// A byte-exact comparison let `.../ads.txt` and `.../ads.txt/` coexist,
/// and twins share one cache file and one ETag: a `304` for one silently
/// satisfies the other, and the last writer wins the body.
///
/// Normalisation, in order:
///
/// 1. scheme lowercased;
/// 2. host lowercased (userinfo, if any, left alone — it is a
///    credential, and two different credentials are not one source);
/// 3. default port dropped (`:80` on http, `:443` on https) — any other
///    port is kept;
/// 4. one trailing `/` dropped from the path;
/// 5. path left otherwise untouched, **case-sensitive** (RFC 3986 says
///    only scheme and host are case-insensitive; `/Ads.txt` and
///    `/ads.txt` are genuinely different resources on most servers);
/// 6. query and fragment left untouched, including their order.
///
/// Deliberately dependency-free (hand-rolled scan, no `url` crate) so
/// the key can be computed from the config layer, which must not pull
/// in an HTTP stack. Input that does not parse as `scheme://…` is
/// returned unchanged: a malformed URL is refused elsewhere with a
/// better message, and silently rewriting it here would only obscure it.
pub fn canonical_url_key(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let scheme = url[..scheme_end].to_ascii_lowercase();
    let rest = &url[scheme_end + 3..];

    // The authority runs to the first `/`, `?` or `#`.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];

    // `[userinfo@]host[:port]` — split on the LAST `@`, since userinfo
    // may itself contain one.
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };

    // An IPv6 literal is bracketed and its colons are not port
    // separators — only a colon AFTER the closing bracket is.
    let port_sep = if host_port.starts_with('[') {
        host_port
            .find(']')
            .and_then(|close| host_port[close + 1..].starts_with(':').then_some(close + 1))
    } else {
        // A bare host has at most one colon; more than one means a
        // malformed authority, so leave it alone rather than guess.
        (host_port.matches(':').count() == 1).then(|| host_port.find(':').unwrap_or(0))
    };
    let (host, port) = match port_sep {
        Some(i) => (&host_port[..i], Some(&host_port[i + 1..])),
        None => (host_port, None),
    };

    let keep_port = match (scheme.as_str(), port) {
        (_, None) => None,
        ("http", Some("80")) | ("https", Some("443")) => None,
        (_, Some(p)) => Some(p),
    };

    // Split the tail into path vs query/fragment so the trailing-slash
    // rule applies to the path and never eats a `/` inside a query.
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = tail[..path_end]
        .strip_suffix('/')
        .unwrap_or(&tail[..path_end]);
    let suffix = &tail[path_end..];

    let mut out = String::with_capacity(url.len());
    out.push_str(&scheme);
    out.push_str("://");
    if let Some(ui) = userinfo {
        out.push_str(ui);
        out.push('@');
    }
    out.push_str(&host.to_ascii_lowercase());
    if let Some(p) = keep_port {
        out.push(':');
        out.push_str(p);
    }
    out.push_str(path);
    out.push_str(suffix);
    out
}

const CANONICAL_SOURCE_SCHEDULE_KEY_PREFIX: &str = "canonical-url-v1-sha256-";
const CANONICAL_SOURCE_SCHEDULE_KEY_HEX_LEN: usize = 64;
const CANONICAL_SOURCE_SCHEDULE_KEY_DOMAIN: &[u8] = b"warden:list-schedule-key\0v1\0";

/// Validated opaque key for one canonical source's scheduling ledger row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalSourceScheduleKey(String);

impl CanonicalSourceScheduleKey {
    /// Stable text used as the sidecar's TOML map key.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_digest(digest: [u8; 32]) -> Self {
        Self(format!(
            "{CANONICAL_SOURCE_SCHEDULE_KEY_PREFIX}{}",
            hex::encode(digest)
        ))
    }

    fn validate(value: &str) -> Result<(), &'static str> {
        let Some(hex) = value.strip_prefix(CANONICAL_SOURCE_SCHEDULE_KEY_PREFIX) else {
            return Err("schedule key must use the canonical-url-v1-sha256 prefix");
        };
        if hex.len() != CANONICAL_SOURCE_SCHEDULE_KEY_HEX_LEN
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("schedule key must end in 64 lowercase hexadecimal characters");
        }
        Ok(())
    }
}

impl std::str::FromStr for CanonicalSourceScheduleKey {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::validate(value)?;
        Ok(Self(value.to_string()))
    }
}

impl serde::Serialize for CanonicalSourceScheduleKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for CanonicalSourceScheduleKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::validate(&value).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

/// Frozen v1 source identity for durable scheduling.
///
/// Unlike [`canonical_url_key`], this intentionally excludes userinfo:
/// authentication is not source identity, and Force handles credential rotation.
fn canonical_schedule_identity_v1(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let scheme = url[..scheme_end].to_ascii_lowercase();
    let rest = &url[scheme_end + 3..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let tail = &rest[auth_end..];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let port_sep = if host_port.starts_with('[') {
        host_port
            .find(']')
            .and_then(|close| host_port[close + 1..].starts_with(':').then_some(close + 1))
    } else {
        (host_port.matches(':').count() == 1).then(|| host_port.find(':').unwrap_or(0))
    };
    let (host, port) = match port_sep {
        Some(index) => (&host_port[..index], Some(&host_port[index + 1..])),
        None => (host_port, None),
    };
    let keep_port = match (scheme.as_str(), port) {
        (_, None) => None,
        ("http", Some("80")) | ("https", Some("443")) => None,
        (_, Some(port)) => Some(port),
    };
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = tail[..path_end]
        .strip_suffix('/')
        .unwrap_or(&tail[..path_end]);
    let suffix = &tail[path_end..];

    let mut out = String::with_capacity(url.len());
    out.push_str(&scheme);
    out.push_str("://");
    out.push_str(&host.to_ascii_lowercase());
    if let Some(port) = keep_port {
        out.push(':');
        out.push_str(port);
    }
    out.push_str(path);
    out.push_str(suffix);
    out
}

/// Opaque durable-scheduling key for one canonical source identity.
///
/// WHY: aliases share a cadence while a versioned hash avoids persisting
/// credential-bearing URLs in mutable state. The hash is an identifier, not
/// a secrecy boundary.
fn schedule_key_from_raw_fetch_url(url: &str) -> CanonicalSourceScheduleKey {
    let identity = canonical_schedule_identity_v1(url);
    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_SOURCE_SCHEDULE_KEY_DOMAIN);
    hasher.update(
        u64::try_from(identity.len())
            .expect("source identity length fits u64")
            .to_be_bytes(),
    );
    hasher.update(identity.as_bytes());
    CanonicalSourceScheduleKey::from_digest(hasher.finalize().into())
}

/// Typed facade over the URL ↔ v1-id source → [`BlocklistTrust`] map.
///
/// Replaces a raw `HashMap<String, BlocklistTrust>` that
/// [`merge_sources_with_blocklists`](crate::lists::manager::merge_sources_with_blocklists)
/// historically returned. The trust is associated with each
/// `[[blocklists]]` row at the schema level; both `[lists].sources`
/// entries (legacy slash form, no schema-level trust) and absent rows
/// resolve to [`BlocklistTrust::RemoteUnsigned`] at the consumer via the
/// usual `unwrap_or` default.
///
/// Two internal submaps share the same trust values:
///
/// - `by_url` — the manager's fetch loop keys exactly on the source
///   string. Every enabled or disabled `[[blocklists]]` row contributes
///   (the manager checks trust unconditionally on the fetch path; the
///   disabled rows simply never reach that path because the merged
///   sources vector omits them).
/// - `by_v1_id` — lets consumers (TUI, IPC, audit) resolve trust by
///   canonical [`Id`] without monkey-patching a reverse lookup through
///   the URL.
///
/// Build is infallible — the trust map has no per-list cap (the
/// 64-source cap is enforced exactly once, by [`SourceBitMap::build`],
/// which is the canonical entry point on the daemon hot path).
#[derive(Debug, Clone, Default)]
pub struct SourceTrustMap {
    by_url: HashMap<String, BlocklistTrust>,
    by_v1_id: HashMap<Id, BlocklistTrust>,
}

impl SourceTrustMap {
    /// Build trust aliases from the resolved source plan.
    pub fn from_plan(plan: &ResolvedSourcePlan) -> Self {
        let mut by_url = HashMap::new();
        let mut by_v1_id = HashMap::new();
        for source in plan.sources() {
            let Some(owner) = source.owner() else {
                continue;
            };
            for alias in &source.source_aliases {
                by_url.insert(alias.clone(), owner.row.trust);
            }
            by_url.insert(source.canonical_url.clone(), owner.row.trust);
            for id in &source.id_aliases {
                by_v1_id.insert(id.clone(), owner.row.trust);
            }
        }
        Self { by_url, by_v1_id }
    }

    /// Build the typed trust map from the v1 `[[blocklists]]`
    /// catalogue.
    ///
    /// Every blocklist row contributes both lookups regardless of
    /// `enabled`. The manager's fetch loop only sees enabled rows in
    /// the merged sources vector, but the trust map carries every row
    /// so that out-of-band consumers (a hypothetical `warden blocklist
    /// inspect <id>` verb, for instance) can still resolve trust for
    /// rows the operator has temporarily disabled.
    pub fn build(blocklists: &[Blocklist]) -> Self {
        let mut by_url: HashMap<String, BlocklistTrust> = HashMap::with_capacity(blocklists.len());
        let mut by_v1_id: HashMap<Id, BlocklistTrust> = HashMap::with_capacity(blocklists.len());
        for b in blocklists {
            by_url.entry(b.url.clone()).or_insert(b.trust);
            by_v1_id.entry(b.id.clone()).or_insert(b.trust);
        }
        Self { by_url, by_v1_id }
    }

    /// Look up trust by fetch URL. Used by the list manager's
    /// `imported.local` bridge guard at fetch time.
    pub fn trust_for_url(&self, url: &str) -> Option<BlocklistTrust> {
        self.by_url
            .get(url)
            .or_else(|| self.by_url.get(&canonical_url_key(url)))
            .copied()
    }

    /// Look up trust by canonical v1 entity [`Id`]. Added for symmetry
    /// with [`SourceBitMap::bit_for_v1_id`]; future id-keyed consumers
    /// (TUI lists tab inspection, audit attribution) can read trust
    /// without resolving the URL first.
    pub fn trust_for_v1_id(&self, id: &Id) -> Option<BlocklistTrust> {
        self.by_v1_id.get(id).copied()
    }

    /// Borrow the URL submap as a raw `HashMap<String, BlocklistTrust>`
    /// for transition consumers that pre-date this typed facade. New
    /// consumers should reach for [`trust_for_url`](Self::trust_for_url)
    /// or [`trust_for_v1_id`](Self::trust_for_v1_id) instead.
    pub fn url_trusts(&self) -> &HashMap<String, BlocklistTrust> {
        &self.by_url
    }

    /// Total number of distinct URL keys.
    pub fn len(&self) -> usize {
        self.by_url.len()
    }

    /// `true` when no blocklist row has been seeded.
    pub fn is_empty(&self) -> bool {
        self.by_url.is_empty()
    }
}

/// Typed facade over bearer tokens for list fetches.
///
/// The resolved source plan assigns one token owner to each representative
/// and exposes the same token through its configured aliases.
#[derive(Clone, Default)]
pub struct SourceTokenMap {
    by_url: HashMap<String, String>,
    by_v1_id: HashMap<Id, String>,
}

/// Hand-written `Debug` that redacts the resolved bearer tokens.
/// The derived `Debug` would print every secret
/// in cleartext on any accidental `{:?}` — a future `debug!(?token_map)`,
/// a `#[derive(Debug)]` on a containing struct that then gets logged, or
/// a test dump. Print only the counts; never the values.
impl std::fmt::Debug for SourceTokenMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceTokenMap")
            .field("by_url", &format_args!("<{} tokens>", self.by_url.len()))
            .field(
                "by_v1_id",
                &format_args!("<{} tokens>", self.by_v1_id.len()),
            )
            .finish()
    }
}

impl SourceTokenMap {
    /// Resolve one token per planned source owner.
    pub fn from_plan(plan: &ResolvedSourcePlan, secrets: &crate::config::secrets::Secrets) -> Self {
        let mut by_url = HashMap::new();
        let mut by_v1_id = HashMap::new();
        for source in plan.sources() {
            let Some(owner) = source.owner() else {
                continue;
            };
            let Some(ref_name) = owner.row.auth_token_ref.as_deref() else {
                continue;
            };
            let Some(value) = secrets.get(ref_name) else {
                tracing::warn!(
                    blocklist = %owner.row.id,
                    auth_token_ref = ref_name,
                    "blocklist auth_token_ref points at a missing secret; download will \
                     proceed without an Authorization header"
                );
                continue;
            };
            for alias in &source.source_aliases {
                by_url.insert(alias.clone(), value.to_string());
            }
            for id in &source.id_aliases {
                by_v1_id.insert(id.clone(), value.to_string());
            }
        }
        Self { by_url, by_v1_id }
    }

    /// Build compatibility aliases from blocklist rows.
    pub fn build(
        config: &crate::config::schema::ConfigV1,
        secrets: &crate::config::secrets::Secrets,
    ) -> Self {
        let mut by_url: HashMap<String, String> = HashMap::new();
        let mut by_v1_id: HashMap<Id, String> = HashMap::new();
        for b in &config.blocklists {
            let Some(ref_name) = b.auth_token_ref.as_deref() else {
                continue;
            };
            let Some(value) = secrets.get(ref_name) else {
                tracing::warn!(
                    blocklist = %b.id,
                    auth_token_ref = ref_name,
                    "blocklist auth_token_ref points at a missing secret; download will \
                     proceed without an Authorization header"
                );
                continue;
            };
            // Kebab→slash translation matches the legacy
            // `build_source_tokens` key shape so the manager's
            // existing `source_tokens.get(source)` lookup at
            // `download_list` continues to hit byte-identically.
            let source_key = b.id.as_str().replacen('-', "/", 1);
            by_url
                .entry(source_key)
                .or_insert_with(|| value.to_string());
            by_v1_id
                .entry(b.id.clone())
                .or_insert_with(|| value.to_string());
        }
        Self { by_url, by_v1_id }
    }

    /// Look up a bearer token by source alias.
    pub fn token_for_url(&self, source: &str) -> Option<&str> {
        self.by_url.get(source).map(String::as_str)
    }

    /// Look up a bearer token by canonical list id.
    pub fn token_for_v1_id(&self, id: &Id) -> Option<&str> {
        self.by_v1_id.get(id).map(String::as_str)
    }

    /// Borrow the URL submap as a raw `HashMap<String, String>` for
    /// transition consumers that pre-date this typed facade. New
    /// consumers should reach for [`token_for_url`](Self::token_for_url)
    /// or [`token_for_v1_id`](Self::token_for_v1_id) instead.
    pub fn url_tokens(&self) -> &HashMap<String, String> {
        &self.by_url
    }

    /// Total number of resolved token entries (one per
    /// `auth_token_ref` that found a matching secret).
    pub fn len(&self) -> usize {
        self.by_url.len()
    }

    /// `true` when no blocklist resolved a token.
    pub fn is_empty(&self) -> bool {
        self.by_url.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};

    fn mk_blocklist(id: &str, url: &str, enabled: bool) -> Blocklist {
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            update_interval_hours: None,
            max_entries: None,
            enabled,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    fn source_plan(
        legacy: &[String],
        blocklists: &[Blocklist],
        profiles: &BTreeMap<String, Profile>,
    ) -> Result<ResolvedSourcePlan, ResolvedSourcePlanError> {
        ResolvedSourcePlan::build(&Catalog::fallback(), legacy, blocklists, profiles)
    }

    #[test]
    fn resolved_plan_keeps_distinct_urls_on_distinct_bits() {
        let blocklists = vec![
            mk_blocklist("ads", "https://example.test/ads.txt", true),
            mk_blocklist("tracking", "https://example.test/tracking.txt", true),
        ];
        let plan = source_plan(&[], &blocklists, &BTreeMap::new()).unwrap();
        let bits = SourceBitMap::from_plan(&plan).unwrap();
        assert_eq!(plan.representatives().len(), 2);
        assert_ne!(
            bits.bit_for_v1_id(&Id::new("ads").unwrap()),
            bits.bit_for_v1_id(&Id::new("tracking").unwrap())
        );
    }

    #[test]
    fn resolved_plan_allows_identical_aliases_and_explicit_inheritance_equivalence() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let second = mk_blocklist("ads-b", "https://EXAMPLE.test:443/ads.txt/", true);
        let mut profiles = BTreeMap::new();
        let mut profile = Profile::default();
        profile
            .lists
            .insert(Id::new("ads-b").unwrap(), ListPolicy::Deny);
        profiles.insert("kids".to_string(), profile);

        let plan = source_plan(&[], &[first, second], &profiles).unwrap();
        let bits = SourceBitMap::from_plan(&plan).unwrap();
        assert_eq!(plan.representatives(), vec!["https://example.test/ads.txt"]);
        assert_eq!(
            bits.bit_for_url("https://EXAMPLE.test:443/ads.txt/"),
            bits.bit_for_v1_id(&Id::new("ads-b").unwrap())
        );
        let source = plan.sources().next().unwrap();
        assert_eq!(
            source.schedule_key(),
            &schedule_key_from_raw_fetch_url("https://example.test/ads.txt")
        );
    }

    #[test]
    fn resolved_plan_keeps_schedule_keys_bound_to_raw_fetch_identities() {
        let first = mk_blocklist("one", "https://example.test/list/", true);
        let second = mk_blocklist("two", "https://example.test/list//", true);
        let plan = source_plan(&[], &[first, second], &BTreeMap::new()).unwrap();
        let sources = plan.sources().collect::<Vec<_>>();

        assert_eq!(sources.len(), 2);
        assert_ne!(sources[0].schedule_key(), sources[1].schedule_key());
        assert_eq!(
            sources[0].schedule_key(),
            &schedule_key_from_raw_fetch_url("https://example.test/list/")
        );
        assert_eq!(
            sources[1].schedule_key(),
            &schedule_key_from_raw_fetch_url("https://example.test/list//")
        );
    }

    #[test]
    fn resolved_plan_ignores_presentation_and_ineffective_row_settings() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let mut second = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        second.display_name = "Different label".to_string();
        second.update_interval_hours = Some(1);
        second.max_entries = Some(1);
        second.accept_unsigned_allow = true;

        assert!(source_plan(&[], &[first, second], &BTreeMap::new()).is_ok());
    }

    #[test]
    fn effective_caps_inherit_narrow_and_never_exceed_global() {
        let inherited = mk_blocklist("inherited", "https://example.test/inherited.txt", true);
        let mut narrow = mk_blocklist("narrow", "https://example.test/narrow.txt", true);
        narrow.max_entries = Some(5);
        let mut wide = mk_blocklist("wide", "https://example.test/wide.txt", true);
        wide.max_entries = Some(u64::MAX);

        let plan = ResolvedSourcePlan::build_with_row_control_defaults(
            &Catalog::fallback(),
            &[],
            &[inherited, narrow, wide],
            &BTreeMap::new(),
            RowControlDefaults {
                max_entries: 10,
                update_interval_secs: 3600,
            },
            RowControlMode::HonorOverrides,
        )
        .unwrap();
        assert_eq!(
            plan.sources()
                .map(ResolvedSource::effective_max_entries)
                .collect::<Vec<_>>(),
            vec![10, 5, 10]
        );
    }

    #[test]
    fn cap_aliases_only_conflict_when_overrides_are_honored() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let mut inherited_equivalent = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        inherited_equivalent.max_entries = Some(10);
        assert!(ResolvedSourcePlan::build_with_row_control_defaults(
            &Catalog::fallback(),
            &[],
            &[first.clone(), inherited_equivalent],
            &BTreeMap::new(),
            RowControlDefaults {
                max_entries: 10,
                update_interval_secs: 3600,
            },
            RowControlMode::HonorOverrides,
        )
        .is_ok());

        let mut divergent = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        divergent.max_entries = Some(5);
        let err = ResolvedSourcePlan::build_with_row_control_defaults(
            &Catalog::fallback(),
            &[],
            &[first.clone(), divergent.clone()],
            &BTreeMap::new(),
            RowControlDefaults {
                max_entries: 10,
                update_interval_secs: 3600,
            },
            RowControlMode::HonorOverrides,
        )
        .unwrap_err();
        assert!(err.to_string().contains("effective max-entries cap"));

        let v3 = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first, divergent],
            &BTreeMap::new(),
            RowControlDefaults {
                max_entries: 10,
                update_interval_secs: 3600,
            },
            3,
        )
        .unwrap();
        assert_eq!(v3.row_control_mode(), RowControlMode::InheritAll);
        assert_eq!(v3.sources().next().unwrap().effective_max_entries(), 10);
    }

    #[test]
    fn cadence_resolution_is_schema_aware_and_preserves_representative_order() {
        let mut first = mk_blocklist("first", "https://example.test/first.txt", true);
        first.update_interval_hours = Some(1);
        let second = mk_blocklist("second", "https://example.test/second.txt", true);
        let defaults = RowControlDefaults {
            max_entries: 10,
            update_interval_secs: 7200,
        };

        let v3 = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first.clone(), second.clone()],
            &BTreeMap::new(),
            defaults,
            3,
        )
        .unwrap();
        assert_eq!(
            v3.sources()
                .map(ResolvedSource::effective_update_interval_secs)
                .collect::<Vec<_>>(),
            vec![7200, 7200],
            "schema 3 leaves row cadence inert"
        );

        let v4 = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first, second],
            &BTreeMap::new(),
            defaults,
            4,
        )
        .unwrap();
        assert_eq!(
            v4.sources()
                .map(ResolvedSource::effective_update_interval_secs)
                .collect::<Vec<_>>(),
            vec![3600, 7200],
            "the omitted setting inherits the global interval"
        );
    }

    #[test]
    fn cadence_aliases_compare_effective_values_only_when_honored() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let mut equal_raw_different = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        equal_raw_different.update_interval_hours = Some(1);
        let defaults = RowControlDefaults {
            max_entries: 10,
            update_interval_secs: 3600,
        };

        assert!(ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first.clone(), equal_raw_different.clone()],
            &BTreeMap::new(),
            defaults,
            4,
        )
        .is_ok());

        let mut different = equal_raw_different.clone();
        different.update_interval_hours = Some(2);
        let err = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first.clone(), different.clone()],
            &BTreeMap::new(),
            defaults,
            4,
        )
        .unwrap_err();
        assert!(err.to_string().contains("effective update interval"));

        let v3 = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[first, different],
            &BTreeMap::new(),
            defaults,
            3,
        )
        .unwrap();
        assert_eq!(
            v3.sources()
                .next()
                .unwrap()
                .effective_update_interval_secs(),
            3600
        );
    }

    #[test]
    fn cadence_resolution_applies_the_sixty_second_floor() {
        let inherited = mk_blocklist("inherited", "https://example.test/inherited.txt", true);
        let plan = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[inherited],
            &BTreeMap::new(),
            RowControlDefaults {
                max_entries: 10,
                update_interval_secs: 1,
            },
            4,
        )
        .unwrap();
        assert_eq!(
            plan.sources()
                .map(ResolvedSource::effective_update_interval_secs)
                .collect::<Vec<_>>(),
            vec![60]
        );
    }

    #[test]
    fn resolved_plan_rejects_base_and_profile_policy_conflicts() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let mut base_conflict = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        base_conflict.base = BlocklistBase::Allow;
        base_conflict.trust = BlocklistTrust::Local;
        assert!(
            source_plan(&[], &[first.clone(), base_conflict], &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("base direction")
        );

        let second = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
        let mut profiles = BTreeMap::new();
        let mut profile = Profile::default();
        profile
            .lists
            .insert(Id::new("ads-b").unwrap(), ListPolicy::Allow);
        profiles.insert("children".to_string(), profile);
        let err = source_plan(&[], &[first, second], &profiles).unwrap_err();
        assert!(err.to_string().contains("profile \"children\""), "{err}");
    }

    #[test]
    fn resolved_plan_rejects_every_shared_runtime_semantic_conflict() {
        type BlocklistMutation = fn(&mut Blocklist);

        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let cases: [(&str, BlocklistMutation); 4] = [
            ("parser format", |b| b.format = BlocklistFormat::Hosts),
            ("trust mode", |b| b.trust = BlocklistTrust::Local),
            ("auth-token reference", |b| {
                b.auth_token_ref = Some("other".to_string())
            }),
            ("max-consecutive-failures retry ownership", |b| {
                b.max_consecutive_failures = 9
            }),
        ];
        for (field, mutate) in cases {
            let mut second = mk_blocklist("ads-b", "https://example.test/ads.txt", true);
            mutate(&mut second);
            let err = source_plan(&[], &[first.clone(), second], &BTreeMap::new()).unwrap_err();
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn resolved_plan_ignores_disabled_conflicts_until_the_row_is_enabled() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let mut second = mk_blocklist("ads-b", "https://example.test/ads.txt", false);
        second.format = BlocklistFormat::Hosts;
        assert!(source_plan(&[], &[first.clone(), second.clone()], &BTreeMap::new()).is_ok());
        second.enabled = true;
        assert!(source_plan(&[], &[first, second], &BTreeMap::new()).is_err());
    }

    #[test]
    fn resolved_plan_unifies_matching_legacy_slug_and_v1_row() {
        let legacy = vec!["privacy/ads".to_string()];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let plan = source_plan(&legacy, &blocklists, &BTreeMap::new()).unwrap();
        let bits = SourceBitMap::from_plan(&plan).unwrap();
        assert_eq!(plan.representatives(), legacy);
        assert_eq!(
            bits.bit_for_legacy_catalog_id("privacy/ads"),
            bits.bit_for_url("https://lists.purge.cc/ads.txt")
        );
        assert_eq!(
            bits.bit_for_v1_id(&Id::new("privacy-ads").unwrap()),
            bits.bit_for_legacy_catalog_id("privacy/ads")
        );
    }

    #[test]
    fn resolved_plan_unifies_unknown_legacy_id_aliases_with_the_enabled_row_fetch_url() {
        let legacy = vec!["team-ads".to_string(), "team/ads".to_string()];
        let rows = vec![mk_blocklist(
            "team-ads",
            "https://example.test/team-ads.txt",
            true,
        )];
        let plan = source_plan(&legacy, &rows, &BTreeMap::new()).unwrap();
        let bits = SourceBitMap::from_plan(&plan).unwrap();

        assert_eq!(plan.representatives(), vec!["team-ads"]);
        assert_eq!(
            plan.fetch_url_for_source("team/ads"),
            Some("https://example.test/team-ads.txt")
        );
        assert_eq!(
            plan.representative_for_source("https://EXAMPLE.test:443/team-ads.txt/"),
            Some("team-ads")
        );
        assert_eq!(bits.len(), 1);
        assert_eq!(
            bits.bit_for_legacy_catalog_id("team/ads"),
            bits.bit_for_v1_id(&Id::new("team-ads").unwrap())
        );
    }

    #[test]
    fn resolved_plan_keeps_catalog_url_conflict_for_matching_legacy_id() {
        let catalog = Catalog::from_entries(vec![super::super::catalog::CatalogEntry {
            scope: "team".to_string(),
            topic: Some("ads".to_string()),
            name: "Ads".to_string(),
            url: "https://catalog.example.test/team-ads.txt".to_string(),
            entries: 0,
            updated_at: String::new(),
            format: BlocklistFormat::Domains,
        }]);
        let rows = vec![mk_blocklist(
            "team-ads",
            "https://row.example.test/team-ads.txt",
            true,
        )];
        let err =
            ResolvedSourcePlan::build(&catalog, &["team/ads".to_string()], &rows, &BTreeMap::new())
                .unwrap_err();
        assert!(err.to_string().contains("resolved URL"), "{err}");
    }

    #[test]
    fn compatibility_build_deduplicates_cosmetic_url_aliases_before_assigning_bits() {
        let sources = vec![
            "https://Example.test:443/ads.txt/".to_string(),
            "https://example.test/ads.txt".to_string(),
        ];
        let map = SourceBitMap::build(&sources, &[]).unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(
            map.bit_for_url("https://Example.test:443/ads.txt/"),
            Some(0)
        );
        assert_eq!(map.bit_for_url("https://example.test/ads.txt"), Some(0));
        assert_eq!(
            map.bit_for_url("https://EXAMPLE.test:443/ads.txt/"),
            Some(0)
        );
        assert_eq!(
            map.iter_urls().collect::<Vec<_>>(),
            vec![("https://Example.test:443/ads.txt/", 0)]
        );
    }

    #[test]
    fn resolved_plan_rejects_matching_legacy_id_with_a_different_url() {
        let legacy = vec!["privacy/ads".to_string()];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://example.test/other.txt",
            true,
        )];
        let err = source_plan(&legacy, &blocklists, &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("resolved URL"), "{err}");
    }

    #[test]
    fn resolved_plan_keeps_allow_aliases_allow_only() {
        let mut first = mk_blocklist("allow-a", "https://example.test/allow.txt", true);
        first.base = BlocklistBase::Allow;
        first.trust = BlocklistTrust::Local;
        let mut second = mk_blocklist("allow-b", "https://example.test/allow.txt", true);
        second.base = BlocklistBase::Allow;
        second.trust = BlocklistTrust::Local;
        let plan = source_plan(&[], &[first.clone(), second.clone()], &BTreeMap::new()).unwrap();
        let bits = SourceBitMap::from_plan(&plan).unwrap();
        let masks = bits.project_policy(&[first, second], &BTreeMap::new());
        assert_eq!(masks.base.allow, 1);
        assert_eq!(masks.base.block, 0);
    }

    #[test]
    fn resolved_plan_keeps_first_representative_under_reversed_declarations() {
        let first = mk_blocklist("ads-a", "https://example.test/ads.txt", true);
        let second = mk_blocklist("ads-b", "https://EXAMPLE.test:443/ads.txt/", true);
        let forward = source_plan(&[], &[first.clone(), second.clone()], &BTreeMap::new()).unwrap();
        let reversed = source_plan(&[], &[second, first.clone()], &BTreeMap::new()).unwrap();
        assert_eq!(forward.len(), 1);
        assert_eq!(reversed.len(), 1);
        assert_eq!(
            forward.representatives(),
            vec!["https://example.test/ads.txt"]
        );
        assert_eq!(
            reversed.representatives(),
            vec!["https://EXAMPLE.test:443/ads.txt/"]
        );

        let mut conflicting = mk_blocklist("ads-c", "https://example.test/ads.txt", true);
        conflicting.base = BlocklistBase::Allow;
        conflicting.trust = BlocklistTrust::Local;
        assert!(source_plan(&[], &[first.clone(), conflicting.clone()], &BTreeMap::new()).is_err());
        assert!(source_plan(&[], &[conflicting, first], &BTreeMap::new()).is_err());
    }

    #[test]
    fn resolved_plan_preserves_the_64_source_limit() {
        let rows: Vec<Blocklist> = (0..65)
            .map(|n| {
                mk_blocklist(
                    &format!("source-{n}"),
                    &format!("https://example.test/{n}"),
                    true,
                )
            })
            .collect();
        let plan = source_plan(&[], &rows, &BTreeMap::new()).unwrap();
        assert!(SourceBitMap::from_plan(&plan).is_err());
    }

    #[test]
    fn build_seeds_url_bit_for_each_source() {
        let sources = vec![
            "https://lists.purge.cc/ads.txt".to_string(),
            "https://lists.purge.cc/malicious.txt".to_string(),
        ];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_url("https://lists.purge.cc/ads.txt"), Some(0));
        assert_eq!(
            map.bit_for_url("https://lists.purge.cc/malicious.txt"),
            Some(1),
        );
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn build_pure_v1_config_seeds_v1_id_alias_from_blocklist() {
        // The pure-v1 case: empty `[lists].sources`, populated
        // `[[blocklists]]`. After `merge_sources_with_blocklists`, the
        // sources vector carries the URL — the v1 id alias must point
        // at the same bit so the profile resolver's `bit_for_v1_id`
        // lookup hits.
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let map = SourceBitMap::build(&sources, &blocklists).unwrap();
        assert_eq!(
            map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(0),
            "pure-v1 config must produce a non-zero bit for the v1 id, \
             not silently fall to None",
        );
        assert_eq!(map.bit_for_url("https://lists.purge.cc/ads.txt"), Some(0));
    }

    /// The shard builder needs to know which source bits are
    /// allow-direction. Direction is a per-source property, so it
    /// collapses to a single `u64` over the same bit space the corpus
    /// already uses.
    #[test]
    fn allow_bits_sets_only_allow_direction_sources() {
        let sources = vec![
            "https://lists.purge.cc/ads.txt".to_string(),
            "https://lists.purge.cc/compat.txt".to_string(),
        ];
        let deny = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", true);
        let mut allow = mk_blocklist("compat", "https://lists.purge.cc/compat.txt", true);
        allow.base = BlocklistBase::Allow;
        allow.trust = BlocklistTrust::Local;

        let map = SourceBitMap::build(&sources, &[deny.clone(), allow.clone()]).unwrap();

        assert_eq!(
            map.project_policy(&[deny, allow], &BTreeMap::new())
                .base
                .allow,
            0b10,
            "only the kind=allow source's bit may be set"
        );
    }

    /// A config with no allow-direction list must yield an empty mask.
    #[test]
    fn allow_bits_is_zero_when_every_list_is_deny() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let deny = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", true);
        let map = SourceBitMap::build(&sources, std::slice::from_ref(&deny)).unwrap();
        assert_eq!(map.project_policy(&[deny], &BTreeMap::new()).base.allow, 0);
    }

    /// A disabled allow list never reaches the corpus, so it must not
    /// claim a bit in the mask either.
    #[test]
    fn allow_bits_ignores_disabled_allow_lists() {
        let sources = vec!["https://lists.purge.cc/compat.txt".to_string()];
        let mut allow = mk_blocklist("compat", "https://lists.purge.cc/compat.txt", false);
        allow.base = BlocklistBase::Allow;
        allow.trust = BlocklistTrust::Local;
        let map = SourceBitMap::build(&sources, std::slice::from_ref(&allow)).unwrap();
        assert_eq!(map.project_policy(&[allow], &BTreeMap::new()).base.allow, 0);
    }

    #[test]
    fn build_legacy_slash_form_seeds_v1_id_alias_via_translation() {
        // Pre-v1 configs carried slash-form catalog ids in
        // `[lists].sources`. The translation `"privacy/ads" →
        // Id("privacy-ads")` must be done at build time so the
        // consumer's `bit_for_v1_id(bid)` lookup hits without a
        // fallback.
        let sources = vec!["privacy/ads".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_legacy_catalog_id("privacy/ads"), Some(0));
        assert_eq!(
            map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(0),
            "legacy slash-form id must auto-alias to v1 id",
        );
    }

    #[test]
    fn build_skips_disabled_blocklists() {
        // Disabled entries don't appear in
        // `merge_sources_with_blocklists` output, so their URL has no
        // bit. The id alias would dangle — skip it.
        let sources: Vec<String> = vec![];
        let blocklists = vec![mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            false,
        )];
        let map = SourceBitMap::build(&sources, &blocklists).unwrap();
        assert!(map.is_empty());
        assert_eq!(map.bit_for_v1_id(&Id::new("privacy-ads").unwrap()), None);
    }

    #[test]
    fn bit_for_v1_id_returns_none_for_unknown_id() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_v1_id(&Id::new("not-configured").unwrap()), None,);
    }

    #[test]
    fn bit_for_url_returns_none_for_unknown_url() {
        let sources = vec!["https://lists.purge.cc/ads.txt".to_string()];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        assert_eq!(map.bit_for_url("https://other.example/ads.txt"), None);
    }

    #[test]
    fn build_errors_one_over_cap_with_legacy_message() {
        let sources: Vec<String> = (0..65).map(|i| format!("list/{i}")).collect();
        let err = SourceBitMap::build(&sources, &[]).expect_err("65 sources exceeds cap");
        let msg = err.to_string();
        assert!(msg.contains("65"), "report actual count: {msg}");
        assert!(msg.contains("64"), "report cap: {msg}");
        assert!(msg.contains("config.toml"), "preserve operator hint: {msg}");
    }

    #[test]
    fn resolved_plan_never_repoints_a_slug_alias_to_another_bit() {
        let sources = vec!["security/malicious".to_string()];
        let blocklists = vec![mk_blocklist(
            "security-malicious",
            "https://lists.purge.cc/malicious.txt",
            true,
        )];
        let plan = source_plan(&sources, &blocklists, &BTreeMap::new()).unwrap();
        let map = SourceBitMap::from_plan(&plan).unwrap();
        assert_eq!(
            map.bit_for_v1_id(&Id::new("security-malicious").unwrap()),
            map.bit_for_legacy_catalog_id("security/malicious"),
            "one logical source owns one bit",
        );
    }

    #[test]
    fn iter_urls_yields_only_url_keys() {
        let sources = vec![
            "privacy/ads".to_string(),
            "https://lists.purge.cc/malicious.txt".to_string(),
        ];
        let map = SourceBitMap::build(&sources, &[]).unwrap();
        let urls: Vec<_> = map.iter_urls().collect();
        assert_eq!(urls.len(), 2, "iter_urls covers every assigned bit");
        // Both source kinds populate `by_url` — manager keys verbatim
        // on whatever string the operator put in `[lists].sources`.
        let keys: Vec<&str> = urls.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"privacy/ads"));
        assert!(keys.contains(&"https://lists.purge.cc/malicious.txt"));
    }

    fn mk_trusted_blocklist(id: &str, url: &str, trust: BlocklistTrust) -> Blocklist {
        let mut b = mk_blocklist(id, url, true);
        b.trust = trust;
        b
    }

    #[test]
    fn trust_map_build_pure_v1_seeds_url_and_v1_id_both_lookups() {
        let blocklists = vec![
            mk_trusted_blocklist(
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
                BlocklistTrust::RemoteUnsigned,
            ),
            mk_trusted_blocklist(
                "security-malicious",
                "https://lists.purge.cc/malicious.txt",
                BlocklistTrust::Signed,
            ),
        ];
        let map = SourceTrustMap::build(&blocklists);

        assert_eq!(
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
            Some(BlocklistTrust::RemoteUnsigned),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(BlocklistTrust::RemoteUnsigned),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("security-malicious").unwrap()),
            Some(BlocklistTrust::Signed),
        );
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn trust_map_build_seeds_disabled_blocklists_too() {
        // `merge_sources_with_blocklists` inserts trust
        // unconditionally. A disabled blocklist's URL still gets a
        // trust lookup because the manager's mutate helpers
        // (`list_state` transitions, hypothetical `inspect` verb) may
        // legitimately ask about a list the operator has toggled off.
        // Disabled rows don't reach the fetch path
        // (`merge_sources_with_blocklists` skips them when building
        // `sources`), so the disabled entry's URL is unreachable from
        // the manager's download loop regardless.
        let blocklists = vec![{
            let mut b = mk_blocklist("privacy-ads", "https://lists.purge.cc/ads.txt", false);
            b.trust = BlocklistTrust::Local;
            b
        }];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
            Some(BlocklistTrust::Local),
        );
        assert_eq!(
            map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()),
            Some(BlocklistTrust::Local),
        );
    }

    #[test]
    fn trust_for_url_returns_none_when_passed_a_v1_id_string() {
        // Symmetric to `bit_for_url_returns_none_for_unknown_url` —
        // proves the typed contract at the lookup line: passing a
        // kebab-form `Id::as_str()` into `trust_for_url` does not
        // accidentally hit a legacy slash-translation fallback.
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::Signed,
        )];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(map.trust_for_url("privacy-ads"), None);
        assert_eq!(map.trust_for_url("privacy/ads"), None);
    }

    #[test]
    fn trust_for_v1_id_returns_none_when_id_not_in_blocklists() {
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::Signed,
        )];
        let map = SourceTrustMap::build(&blocklists);
        assert_eq!(
            map.trust_for_v1_id(&Id::new("security-malicious").unwrap()),
            None,
        );
    }

    #[test]
    fn trust_map_url_trusts_accessor_matches_typed_lookup_byte_for_byte() {
        // `url_trusts()` is the legacy accessor for transition
        // consumers that still hold a `&HashMap<String, BlocklistTrust>`.
        // Kept `pub` until no caller remains.
        let blocklists = vec![mk_trusted_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::RemoteUnsigned,
        )];
        let map = SourceTrustMap::build(&blocklists);
        let raw = map.url_trusts();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw.get("https://lists.purge.cc/ads.txt").copied(),
            map.trust_for_url("https://lists.purge.cc/ads.txt"),
        );
    }

    #[test]
    fn trust_map_empty_for_no_blocklists() {
        let map = SourceTrustMap::build(&[]);
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.trust_for_v1_id(&Id::new("privacy-ads").unwrap()), None,);
        assert_eq!(map.trust_for_url("https://lists.purge.cc/ads.txt"), None);
    }

    fn make_secrets_with(name: &str, value: &str) -> crate::config::secrets::Secrets {
        // Build a real `Secrets` via the public `load_secrets` path to
        // avoid leaning on private fields. Mirrors the pattern at
        // `cli::commands::start::tests::build_source_tokens_*`. Each
        // call gets a unique tempdir via a process-wide atomic counter
        // so concurrent test workers don't race on the same path
        // (`line!()` inside this helper is fixed, not per-caller).
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-stkn-{pid}-{n}"));
        fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("secrets.toml");
        {
            let mut f = fs::File::create(&sp).unwrap();
            writeln!(f, "{name} = \"{value}\"").unwrap();
        }
        let mut perm = fs::metadata(&sp).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&sp, perm).unwrap();
        let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
        let _ = fs::remove_dir_all(&dir);
        secrets
    }

    fn mk_blocklist_with_token_ref(id: &str, url: &str, token_ref: &str) -> Blocklist {
        let mut b = mk_blocklist(id, url, true);
        b.auth_token_ref = Some(token_ref.to_string());
        b
    }

    #[test]
    fn token_map_build_seeds_both_legacy_source_key_and_v1_id() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");

        let map = SourceTokenMap::build(&config, &secrets);
        // Legacy slash-form lookup — manager.rs:1032 byte-identical hit.
        assert_eq!(map.token_for_url("security/malicious"), Some("bearer-xyz"));
        // New typed v1-id lookup — symmetry with SourceBitMap /
        // SourceTrustMap.
        assert_eq!(
            map.token_for_v1_id(&Id::new("security-malicious").unwrap()),
            Some("bearer-xyz"),
        );
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
    }

    #[test]
    fn token_map_skips_blocklists_without_auth_token_ref() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        ));
        let secrets = make_secrets_with("ignored", "ignored");
        let map = SourceTokenMap::build(&config, &secrets);
        assert!(map.is_empty());
        assert_eq!(map.token_for_url("privacy/ads"), None);
        assert_eq!(map.token_for_v1_id(&Id::new("privacy-ads").unwrap()), None,);
    }

    #[test]
    fn token_map_skips_blocklists_with_missing_secret() {
        // An `auth_token_ref` pointing at a non-existent secret emits
        // `tracing::warn!` and the row is skipped (downloads
        // anonymously).
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "missing-secret",
        ));
        let secrets = make_secrets_with("present-but-different", "ignored");
        let map = SourceTokenMap::build(&config, &secrets);
        assert!(map.is_empty());
        assert_eq!(
            map.token_for_v1_id(&Id::new("security-malicious").unwrap()),
            None,
        );
    }

    #[test]
    fn token_for_v1_id_returns_none_for_unknown_id() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");
        let map = SourceTokenMap::build(&config, &secrets);
        assert_eq!(
            map.token_for_v1_id(&Id::new("not-configured").unwrap()),
            None,
        );
    }

    #[test]
    fn token_map_url_tokens_accessor_matches_typed_lookup_byte_for_byte() {
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "bearer-xyz");
        let map = SourceTokenMap::build(&config, &secrets);
        let raw = map.url_tokens();
        assert_eq!(raw.len(), 1);
        assert_eq!(
            raw.get("security/malicious").map(String::as_str),
            map.token_for_url("security/malicious"),
        );
    }

    #[test]
    fn debug_redacts_bearer_tokens() {
        // The hand-written Debug must print counts, never the secret
        // values.
        use crate::config::schema::ConfigV1;
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(mk_blocklist_with_token_ref(
            "security-malicious",
            "https://corp.example.com/m.txt",
            "sec-token",
        ));
        let secrets = make_secrets_with("sec-token", "SUPER-SECRET-BEARER");
        let map = SourceTokenMap::build(&config, &secrets);
        // The token must actually be resolved, so the redaction is real.
        assert!(map
            .token_for_v1_id(&Id::new("security-malicious").unwrap())
            .is_some());
        let dbg = format!("{map:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-BEARER"),
            "Debug leaked a bearer token: {dbg}"
        );
        assert!(
            dbg.contains("tokens"),
            "Debug should summarise counts: {dbg}"
        );
    }

    // ── canonical_url_key ─────────────────────────────────────────

    #[test]
    fn tmc_canonical_key_lowercases_scheme_and_host_only() {
        assert_eq!(
            canonical_url_key("HTTPS://Lists.Purge.CC/Ads.txt"),
            "https://lists.purge.cc/Ads.txt",
            "path case is meaningful to the server and must survive",
        );
    }

    #[test]
    fn tmc_canonical_key_drops_default_ports_keeps_others() {
        assert_eq!(
            canonical_url_key("http://example.com:80/a.txt"),
            "http://example.com/a.txt",
        );
        assert_eq!(
            canonical_url_key("https://example.com:443/a.txt"),
            "https://example.com/a.txt",
        );
        // Wrong-scheme default port is NOT a default — keep it.
        assert_eq!(
            canonical_url_key("https://example.com:80/a.txt"),
            "https://example.com:80/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://example.com:8080/a.txt"),
            "http://example.com:8080/a.txt",
        );
    }

    #[test]
    fn tmc_canonical_key_drops_exactly_one_trailing_slash() {
        assert_eq!(
            canonical_url_key("https://example.com/list/"),
            canonical_url_key("https://example.com/list"),
        );
        // Bare host with and without the root slash are one source.
        assert_eq!(
            canonical_url_key("https://example.com/"),
            canonical_url_key("https://example.com"),
        );
        // Only ONE — a doubled slash is a different path.
        assert_eq!(
            canonical_url_key("https://example.com/list//"),
            "https://example.com/list/",
        );
    }

    #[test]
    fn tmc_canonical_key_leaves_query_and_fragment_alone() {
        // Trailing slash belongs to the path, not the query: stripping
        // must not reach past the `?`.
        assert_eq!(
            canonical_url_key("https://example.com/l/?v=2&a=1"),
            "https://example.com/l?v=2&a=1",
        );
        // Query order is meaningful to the server — do not sort.
        assert_ne!(
            canonical_url_key("https://example.com/l?a=1&v=2"),
            canonical_url_key("https://example.com/l?v=2&a=1"),
        );
        assert_eq!(
            canonical_url_key("https://example.com/l/#frag"),
            "https://example.com/l#frag",
        );
        // A `/` inside the query survives untouched.
        assert_eq!(
            canonical_url_key("https://example.com/l?path=a/"),
            "https://example.com/l?path=a/",
        );
    }

    #[test]
    fn tmc_canonical_key_handles_ipv6_literal_and_userinfo() {
        // Colons inside the brackets are not a port separator.
        assert_eq!(
            canonical_url_key("http://[2001:DB8::1]/a.txt"),
            "http://[2001:db8::1]/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://[2001:db8::1]:80/a.txt"),
            "http://[2001:db8::1]/a.txt",
        );
        assert_eq!(
            canonical_url_key("http://[2001:db8::1]:8080/a.txt"),
            "http://[2001:db8::1]:8080/a.txt",
        );
        // Userinfo is a credential: host lowercases, the credential
        // does not, and two different credentials stay two keys.
        assert_eq!(
            canonical_url_key("https://User:Pw@Example.com/a.txt"),
            "https://User:Pw@example.com/a.txt",
        );
    }

    #[test]
    fn tmc_canonical_key_passes_through_unparseable_input() {
        // No `://` — refused elsewhere with a better message; rewriting
        // it here would only obscure the operator's typo.
        assert_eq!(canonical_url_key("not-a-url"), "not-a-url");
        assert_eq!(canonical_url_key(""), "");
    }

    #[test]
    fn tmc_canonical_key_is_idempotent() {
        for raw in [
            "HTTPS://Lists.Purge.CC:443/Ads.txt/",
            "http://example.com:80/",
            "https://a.example.com/l?x=1#f",
            "not-a-url",
        ] {
            let once = canonical_url_key(raw);
            assert_eq!(
                canonical_url_key(&once),
                once,
                "key must be a fixed point: {raw}",
            );
        }
    }

    #[test]
    fn canonical_schedule_key_v1_known_answers_and_aliases_are_frozen() {
        let ads = schedule_key_from_raw_fetch_url("https://lists.purge.cc/ads.txt");
        let ads_alias = schedule_key_from_raw_fetch_url("https://lists.purge.cc:443/ads.txt/");
        let path = schedule_key_from_raw_fetch_url("https://example.com/path?x=1");

        assert_eq!(
            ads.as_str(),
            "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1"
        );
        assert_eq!(ads, ads_alias);
        assert_eq!(
            path.as_str(),
            "canonical-url-v1-sha256-4e597e623d4112f2872d16b23fdc91d5f7f38102bf6fcf204c8b41911e5da6f8"
        );
    }

    #[test]
    fn canonical_schedule_key_v1_excludes_auth_context() {
        let unauthenticated = schedule_key_from_raw_fetch_url("https://example.com/a.txt");
        let authenticated =
            schedule_key_from_raw_fetch_url("https://user:secret@example.com/a.txt");

        // Defense-in-depth: production validation rejects embedded userinfo.
        assert_eq!(unauthenticated, authenticated);
        assert!(!authenticated.as_str().contains("secret"));
    }

    /// The scheme contract, pinned at the seat rather than at N call
    /// sites. Widening it is a policy change; this test is what a
    /// widening has to argue with.
    #[test]
    fn is_url_source_accepts_only_the_two_lowercase_http_schemes() {
        for accepted in [
            "http://lists.purge.cc/ads.txt",
            "https://lists.purge.cc/ads.txt",
            "https://",
        ] {
            assert!(is_url_source(accepted), "must classify as URL: {accepted}");
        }
        for rejected in [
            // The legacy slash-form catalog ids the `else` branch exists for.
            "privacy/ads",
            "services/resolvers",
            // Case matters: uppercase is not a URL here.
            "HTTP://lists.purge.cc/ads.txt",
            "Https://lists.purge.cc/ads.txt",
            // Other schemes, including the one a local-import shortcut
            // would reach for.
            "ftp://lists.purge.cc/ads.txt",
            "file:///var/lib/purge-warden/lists/ads.txt",
            // Scheme-like text that does not start the string.
            " https://lists.purge.cc/ads.txt",
            "redirect?to=https://lists.purge.cc/ads.txt",
            "",
        ] {
            assert!(
                !is_url_source(rejected),
                "must NOT classify as URL: {rejected}"
            );
        }
    }

    /// Trip-wire: the CLI verbs that classify an operator-typed source
    /// must ask this function, not re-derive the scheme test inline.
    ///
    /// The predicate decides where warden fetches a blocklist from, so a
    /// copy that a scheme-policy change misses keeps enforcing the old
    /// rule with nothing going red. A hand-rolled copy compiles and
    /// passes every behavioural test on the day it is written — the only
    /// thing that can catch it is a reader, or this.
    ///
    /// The needle is assembled at run time so this test does not match
    /// itself.
    #[test]
    fn cli_source_classification_has_no_hand_rolled_copy() {
        let needle = format!("starts_with({:?})", "http://");
        for (path, src) in [
            (
                "src/cli/commands/lists.rs",
                include_str!("../cli/commands/lists.rs"),
            ),
            (
                "src/cli/commands/blocklists.rs",
                include_str!("../cli/commands/blocklists.rs"),
            ),
        ] {
            assert!(
                !src.contains(&needle),
                "{path} re-derives the URL-scheme test inline; call \
                 lists::source_key::is_url_source instead"
            );
        }
    }

    #[test]
    fn tmc_canonical_key_matches_the_live_ct_duplicate_pair() {
        // Two differently-named entries can point at the same URL with
        // only a trailing slash difference; a byte-exact gate would let
        // them both in as if they were distinct sources.
        assert_eq!(
            canonical_url_key("https://lists.purge.cc/ads.txt"),
            canonical_url_key("https://lists.purge.cc/ads.txt/"),
        );
    }
}
