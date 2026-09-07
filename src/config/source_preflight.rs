//! Semantic preflight for a catalog-resolved list-source plan.

use std::path::Path;

use crate::config::error::{ConfigError, ErrorContext};
use crate::config::schema::ConfigV1;
use crate::lists::catalog::Catalog;
use crate::lists::source_key::{ResolvedSourcePlan, RowControlDefaults, SourceBitMap};

/// Resolve and validate the source identities the selected catalog produces.
///
/// Keeping this beside the schema lets migrations validate the prospective
/// configuration without depending on CLI catalog-selection policy.
pub(crate) fn preflight_resolved_source_plan(
    config_path: &Path,
    config: &ConfigV1,
    catalog: &Catalog,
) -> Result<ResolvedSourcePlan, Vec<ConfigError>> {
    let plan = ResolvedSourcePlan::build_for_schema(
        catalog,
        &config.lists.sources,
        &config.blocklists,
        &config.profiles,
        RowControlDefaults {
            max_entries: config.lists.max_entries,
            update_interval_secs: config.lists.update_interval_secs,
        },
        config.schema_version,
    )
    .map_err(|error| source_plan_error(config_path, error))?;
    SourceBitMap::from_plan(&plan).map_err(|error| source_plan_error(config_path, error))?;
    if (!config.lists.sources.is_empty() || config.blocklists.iter().any(|row| row.enabled))
        && plan.is_empty()
    {
        return Err(vec![ConfigError::ValidationFailed(
            ErrorContext::new("configured list sources resolved to no usable catalog entries")
                .with_file(config_path)
                .with_entity("lists.sources"),
        )]);
    }
    Ok(plan)
}

fn source_plan_error(config_path: &Path, error: impl std::fmt::Display) -> Vec<ConfigError> {
    vec![ConfigError::ValidationFailed(
        ErrorContext::new(format!("source plan preflight failed: {error}"))
            .with_file(config_path)
            .with_entity("lists.sources"),
    )]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::schema::id::Id;
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};
    use crate::lists::catalog::CatalogEntry;

    const CONFIG_PATH: &str = "/tmp/source-preflight.toml";
    const CATALOG_URL: &str = "https://catalog.example.test/from-catalog.txt";

    fn config() -> ConfigV1 {
        ConfigV1::test_scaffold()
    }

    fn blocklist(id: &str, url: &str) -> Blocklist {
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    fn catalog_first() -> Catalog {
        Catalog::from_entries(vec![CatalogEntry {
            scope: "catalog".to_string(),
            topic: Some("first".to_string()),
            name: "First".to_string(),
            url: CATALOG_URL.to_string(),
            entries: 1,
            updated_at: String::new(),
            format: BlocklistFormat::Domains,
        }])
    }

    fn assert_preflight_error(error: &ConfigError, reason: &str) {
        assert!(matches!(error, ConfigError::ValidationFailed(_)));
        assert_eq!(
            error.context().file.as_deref(),
            Some(Path::new(CONFIG_PATH))
        );
        assert_eq!(error.context().entity.as_deref(), Some("lists.sources"));
        assert_eq!(error.context().reason, reason);
    }

    #[test]
    fn succeeds_and_returns_the_catalog_resolved_plan() {
        let mut config = config();
        config.lists.sources = vec!["catalog/first".to_string()];

        let plan =
            preflight_resolved_source_plan(Path::new(CONFIG_PATH), &config, &catalog_first())
                .expect("the catalog source resolves");

        assert_eq!(plan.representatives(), vec!["catalog/first"]);
    }

    #[test]
    fn preserves_alias_conflict_classification_and_attribution() {
        let mut config = config();
        config.lists.sources = vec!["catalog/first".to_string()];
        config.blocklists = vec![blocklist(
            "catalog-first",
            "https://row.example.test/different.txt",
        )];
        let reason = format!(
            "source plan preflight failed: {}",
            crate::lists::source_key::format_list_source_alias_conflict(
                "catalog/first",
                "catalog-first",
                CATALOG_URL,
                "resolved URL",
            )
        );

        let errors =
            preflight_resolved_source_plan(Path::new(CONFIG_PATH), &config, &catalog_first())
                .expect_err("conflicting aliases must fail");

        assert_eq!(errors.len(), 1);
        assert_preflight_error(&errors[0], &reason);
    }

    #[test]
    fn preserves_bitmap_limit_classification_and_attribution() {
        let mut config = config();
        config.lists.sources = (0..65)
            .map(|index| format!("https://example.test/{index}.txt"))
            .collect();
        let reason = "source plan preflight failed: too many list sources: 65 configured, max 64 supported (each source consumes one bit of a u64 bitmask). Edit `config.toml` to reduce the `[lists].sources` list to 64 entries or fewer, then retry.";

        let errors =
            preflight_resolved_source_plan(Path::new(CONFIG_PATH), &config, &Catalog::fallback())
                .expect_err("65 source identities exceed the bitmap");

        assert_eq!(errors.len(), 1);
        assert_preflight_error(&errors[0], reason);
    }

    #[test]
    fn rejects_configured_sources_that_resolve_to_an_empty_plan() {
        let mut config = config();
        config.lists.sources = vec!["missing/source".to_string()];
        let reason = "configured list sources resolved to no usable catalog entries";

        let errors =
            preflight_resolved_source_plan(Path::new(CONFIG_PATH), &config, &Catalog::fallback())
                .expect_err("configured unresolved sources must fail");

        assert_eq!(errors.len(), 1);
        assert_preflight_error(&errors[0], reason);
    }
}
