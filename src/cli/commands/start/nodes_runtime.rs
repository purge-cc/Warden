use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context};

use crate::cluster::corpus::{CorpusAuxSource, CorpusManifest, CorpusStore};
use crate::cluster::dto::ArtifactIdentity;
use crate::cluster::node_control::{ActivePairProvider, ActivePolicyCorpus};
use crate::config::schema::{ClusterRole, ConfigV1};
use crate::filter::ip_filter::{parse_ip_blocklist, IpFilter};
use crate::filter::FilterEngine;
use crate::lists::manager::{ListManager, RefreshMode};
use crate::lists::source_key::{ResolvedSourcePlan, SourceBitMap, SourceTokenMap};

pub(super) struct NodeCorpusRuntime {
    pub store: Arc<CorpusStore>,
    pub secondary: Option<CorpusManifest>,
}

impl NodeCorpusRuntime {
    pub fn load(
        master: &Path,
        config: &ConfigV1,
        authoritative: bool,
    ) -> anyhow::Result<Option<Self>> {
        if !authoritative {
            return Ok(None);
        }
        let store = Arc::new(CorpusStore::open(master)?);
        let secondary = if config.cluster.enabled
            && config.cluster.membership_version == Some(1)
            && config.cluster.role == ClusterRole::Secondary
        {
            let ledger = crate::cluster::apply::load_persisted(master)?
                .context("paired node has no verified policy")?;
            Some(store.manifest_for_artifact(&ledger.manifest.artifact_hash)?)
        } else {
            None
        };
        Ok(Some(Self { store, secondary }))
    }

    pub fn active_pair_provider(&self, enrolled: bool) -> Arc<RuntimeActivePairProvider> {
        Arc::new(RuntimeActivePairProvider {
            store: Some(Arc::clone(&self.store)),
            enrolled,
        })
    }

    pub fn configure_secondary(&self, manager: &mut ListManager) -> anyhow::Result<()> {
        if let Some(manifest) = &self.secondary {
            manager.set_node_corpus_secondary(Arc::clone(&self.store), manifest.clone())?;
        }
        Ok(())
    }

    pub fn mark_secondary_active(&self) -> anyhow::Result<()> {
        if let Some(manifest) = &self.secondary {
            self.store
                .mark_active(&manifest.generation, &manifest.artifact)?;
        }
        Ok(())
    }

    pub fn publish_primary(
        &self,
        manager: Option<&mut ListManager>,
        artifact: &ArtifactIdentity,
        auxiliary: Vec<CorpusAuxSource>,
    ) -> anyhow::Result<()> {
        if self.secondary.is_some() {
            return Ok(());
        }
        match manager {
            Some(manager) => manager.set_node_corpus_primary(
                Arc::clone(&self.store),
                artifact.clone(),
                auxiliary,
            ),
            None => {
                let manifest = CorpusManifest::new(artifact.clone(), Vec::new(), auxiliary)?;
                self.store.install_manifest(&manifest)?;
                self.store.mark_active(&manifest.generation, artifact)
            }
        }
    }

    pub fn record_active(
        &self,
        observe: Option<&Arc<crate::cluster::ClusterObserve>>,
        primary: Option<&Arc<crate::cluster::ClusterState>>,
    ) -> anyhow::Result<()> {
        let manifest = match &self.secondary {
            Some(manifest) => manifest.clone(),
            None => {
                let pair = self.store.pair_state()?;
                let Some(active) = pair.active.as_deref() else {
                    ensure!(
                        observe.is_none() && primary.is_none(),
                        "installed primary corpus missing"
                    );
                    return Ok(());
                };
                self.store.manifest(active)?
            }
        };
        if let Some(primary) = primary {
            primary.set_primary_active_pair(manifest.artifact.clone(), manifest.generation.clone());
        }
        if let Some(observe) = observe {
            observe.record_active_pair(manifest.artifact, manifest.generation);
        }
        Ok(())
    }

    pub fn finish_activation(
        &self,
        manager: Option<&mut ListManager>,
        observe: Option<&Arc<crate::cluster::ClusterObserve>>,
        primary: Option<&Arc<crate::cluster::ClusterState>>,
        artifact: Option<&ArtifactIdentity>,
        auxiliary: Vec<CorpusAuxSource>,
    ) -> anyhow::Result<()> {
        self.mark_secondary_active()?;
        if self.secondary.is_none() {
            self.publish_primary(
                manager,
                artifact.context("enrollment artifact unavailable")?,
                auxiliary,
            )?;
        }
        self.record_active(observe, primary)
    }
}

pub(super) struct RuntimeActivePairProvider {
    store: Option<Arc<CorpusStore>>,
    enrolled: bool,
}

impl RuntimeActivePairProvider {
    pub fn unavailable() -> Arc<Self> {
        Arc::new(Self {
            store: None,
            enrolled: false,
        })
    }

    fn read_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        let store = self
            .store
            .as_ref()
            .context("enrollment corpus is unavailable")?;
        let state = store.pair_state()?;
        let generation = state
            .active
            .context("no verified policy/corpus pair is active")?;
        let manifest = store.manifest(&generation)?;
        store.verify_manifest_objects(&manifest)?;
        ensure!(
            manifest.generation == generation,
            "active corpus generation changed during inspection"
        );
        Ok(ActivePolicyCorpus {
            policy: manifest.artifact,
            corpus_generation: generation,
        })
    }
}

#[async_trait::async_trait]
impl ActivePairProvider for RuntimeActivePairProvider {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        if !self.enrolled {
            return None;
        }
        match self.read_pair() {
            Ok(pair) => Some(pair),
            Err(error) => {
                tracing::error!(%error, "active Nodes policy/corpus proof is unavailable");
                None
            }
        }
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            RuntimeActivePairProvider {
                store,
                enrolled: false,
            }
            .read_pair()
        })
        .await?
    }
}

pub(super) fn clear_active(
    observe: Option<&Arc<crate::cluster::ClusterObserve>>,
    primary: Option<&Arc<crate::cluster::ClusterState>>,
) {
    if let Some(observe) = observe {
        observe.clear_active_pair();
    }
    if let Some(state) = primary {
        state.clear_primary_active_pair();
    }
}

pub(super) fn wire_live_manager(
    manager: &mut ListManager,
    config: &ConfigV1,
    ip_filter: Option<&Arc<IpFilter>>,
    observe: Option<&Arc<crate::cluster::ClusterObserve>>,
    primary: Option<&Arc<crate::cluster::ClusterState>>,
) {
    let observe = observe.cloned();
    let primary_state = primary.cloned();
    let unconfirmed_observe = observe.clone();
    let unconfirmed_primary = primary_state.clone();
    manager.set_node_pair_unconfirmed_hook(Arc::new(move || {
        if let Some(state) = &unconfirmed_primary {
            state.clear_primary_active_pair();
        }
        if let Some(observe) = &unconfirmed_observe {
            observe.clear_active_pair();
        }
    }));
    manager.set_node_active_pair_hook(Arc::new(move |policy, corpus| {
        if let Some(state) = &primary_state {
            state.set_primary_active_pair(policy.clone(), corpus.clone());
        }
        if let Some(observe) = &observe {
            observe.record_active_pair(policy, corpus);
        }
    }));
    if primary.is_some() && config.ip_blocklists.enabled {
        if let Some(live) = ip_filter.cloned() {
            let config = config.clone();
            manager.set_node_auxiliary_refresh(Arc::new(move |store, client| {
                let config = config.clone();
                let live = Arc::clone(&live);
                Box::pin(async move {
                    let context = NodeCorpusRuntime {
                        store,
                        secondary: None,
                    };
                    let (prepared, sources) = prepare_ip_filter(&config, &client, &context).await?;
                    let prepared = prepared.context("prepared IP filter missing")?;
                    Ok(crate::cluster::corpus::PreparedAuxiliary {
                        sources,
                        activate: Box::new(move || live.install_prepared(&prepared)),
                    })
                })
            }));
        }
    }
}

/// Run on a blocking worker before the received policy can replace local files.
pub(crate) fn preflight_received(
    master: &Path,
    config: &ConfigV1,
    artifact: &ArtifactIdentity,
) -> anyhow::Result<()> {
    let store = CorpusStore::open(master)?;
    let manifest = store.manifest_for_artifact(&artifact.artifact_hash)?;
    ensure!(
        &manifest.artifact == artifact,
        "received corpus policy mismatch"
    );
    preflight_received_manifest(master, config, &manifest)
}

/// Validate an exact staged corpus without requiring it to be promoted first.
pub(crate) fn preflight_received_manifest(
    master: &Path,
    config: &ConfigV1,
    manifest: &CorpusManifest,
) -> anyhow::Result<()> {
    let store = Arc::new(CorpusStore::open(master)?);
    store.verify_manifest_objects(manifest)?;
    let urls = if config.ip_blocklists.enabled {
        config.ip_blocklists.sources.as_slice()
    } else {
        &[]
    };
    manifest.verify_auxiliary(urls)?;
    parse_auxiliary(config, &store, &manifest.auxiliary)?;
    let catalog = manifest.catalog();
    let plan = ResolvedSourcePlan::build_for_schema(
        &catalog,
        &config.lists.sources,
        &config.blocklists,
        &config.profiles,
        crate::lists::source_key::RowControlDefaults {
            max_entries: config.lists.max_entries,
            update_interval_secs: config.lists.update_interval_secs,
        },
        config.schema_version,
    )?;
    manifest.verify_plan(&plan)?;
    if plan.representatives().is_empty() {
        ensure!(
            !super::rejects_declared_empty_plan(config, &plan),
            "declared sources are unresolved"
        );
        return Ok(());
    }
    let bits = SourceBitMap::from_plan(&plan)?;
    let masks = bits.project_policy(&config.blocklists, &config.profiles);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut manager = ListManager::with_plan_and_tokens(
            crate::lists::http_client::build_list_client(Duration::from_secs(30))?,
            Arc::new(FilterEngine::new()),
            plan.clone(),
            Duration::from_secs(config.lists.update_interval_secs),
            bits,
            SourceTokenMap::default(),
            config.lists.max_body_bytes,
            config.lists.max_entries,
            None,
        );
        super::ManagerWiring::from_config(
            config,
            master,
            &plan,
            master.parent().unwrap_or(Path::new(".")).to_owned(),
            masks,
            super::ListStateWriteback::ReadOnly,
        )
        .apply(&mut manager);
        manager.set_node_corpus_secondary(store, manifest.clone())?;
        manager.refresh_with_mode(RefreshMode::CacheOnly).await;
        manager.verify_node_corpus()?;
        ensure!(
            manager.node_corpus_generation().is_some(),
            "received corpus has no installed generation"
        );
        Ok(())
    })
}

pub(super) async fn prepare_ip_filter(
    config: &ConfigV1,
    client: &reqwest::Client,
    context: &NodeCorpusRuntime,
) -> anyhow::Result<(Option<Arc<IpFilter>>, Vec<CorpusAuxSource>)> {
    if !config.ip_blocklists.enabled {
        if let Some(manifest) = &context.secondary {
            manifest.verify_auxiliary(&[])?;
        }
        return Ok((Some(Arc::new(IpFilter::new())), Vec::new()));
    }
    let mut auxiliary = Vec::new();
    if let Some(manifest) = &context.secondary {
        manifest.verify_auxiliary(&config.ip_blocklists.sources)?;
        auxiliary = manifest.auxiliary.clone();
    } else {
        let pair = context.store.pair_state()?;
        let prior = pair
            .active
            .as_deref()
            .or(pair.persisted.as_deref())
            .map(|generation| context.store.manifest(generation))
            .transpose()?;
        for url in &config.ip_blocklists.sources {
            let source = match crate::cluster::corpus::acquire_auxiliary(
                Arc::clone(&context.store),
                client,
                url,
                config.lists.max_body_bytes,
            )
            .await
            {
                Ok(source) => source,
                Err(error) => {
                    let source = prior
                        .as_ref()
                        .and_then(|manifest| {
                            manifest.auxiliary.iter().find(|source| &source.url == url)
                        })
                        .with_context(|| {
                            format!("IP list acquisition failed without a retained body: {error}")
                        })?;
                    tracing::warn!(%url, %error, "IP list unavailable; retaining verified previous body");
                    source.clone()
                }
            };
            auxiliary.push(source);
        }
    }
    let ips = parse_auxiliary(config, &context.store, &auxiliary)?;
    Ok((Some(Arc::new(IpFilter::with_ips(ips))), auxiliary))
}

fn parse_auxiliary(
    config: &ConfigV1,
    store: &CorpusStore,
    auxiliary: &[CorpusAuxSource],
) -> anyhow::Result<std::collections::HashSet<std::net::IpAddr, ahash::RandomState>> {
    let mut ips = std::collections::HashSet::default();
    for value in &config.ip_blocklists.inline {
        if let Ok(ip) = value.parse() {
            ips.insert(ip);
        }
    }
    for source in auxiliary {
        ensure!(
            source.body.bytes <= config.lists.max_body_bytes as u64,
            "received IP list exceeds the configured body cap"
        );
        let mut reader = BufReader::new(store.verified_object(&source.body)?);
        let mut line = Vec::new();
        loop {
            line.clear();
            let count = reader.by_ref().take(65_538).read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            let payload = line.strip_suffix(b"\n").unwrap_or(&line);
            let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
            ensure!(payload.len() <= 65_536, "IP list line exceeds 64 KiB");
            ips.extend(parse_ip_blocklist(std::str::from_utf8(&line)?));
        }
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(store: &CorpusStore, bytes: &[u8]) -> CorpusAuxSource {
        let body = crate::cluster::manifest::ObjectRef::of(bytes);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        store.import_file(&body, &mut file).unwrap();
        CorpusAuxSource {
            url: "https://list.example.test/ips".into(),
            body,
            fetched_at: 1,
        }
    }

    #[test]
    fn auxiliary_stream_preserves_ip_parser_and_rejects_body_and_line_overflow() {
        let root = tempfile::tempdir().unwrap();
        let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
        let mut config = ConfigV1::test_scaffold();
        let source = fixture(
            &store,
            b"# list\n192.0.2.1 # comment\n2001:db8::1\ninvalid\n",
        );
        let ips = parse_auxiliary(&config, &store, std::slice::from_ref(&source)).unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.0.2.1".parse().unwrap()));
        config.lists.max_body_bytes = source.body.bytes as usize - 1;
        assert!(parse_auxiliary(&config, &store, &[source])
            .unwrap_err()
            .to_string()
            .contains("body cap"));
        config.lists.max_body_bytes = 100_000;
        let oversized = fixture(&store, &vec![b'#'; 65_537]);
        assert!(parse_auxiliary(&config, &store, &[oversized])
            .unwrap_err()
            .to_string()
            .contains("64 KiB"));
    }

    #[tokio::test]
    async fn standalone_without_api_or_domain_sources_keeps_inline_ip_policy() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let mut config = ConfigV1::test_scaffold();
        config.api.enabled = false;
        config.ip_blocklists.enabled = true;
        config.ip_blocklists.inline = vec!["192.0.2.42".into()];
        let context = NodeCorpusRuntime::load(&master, &config, true)
            .unwrap()
            .unwrap();
        let client = crate::lists::http_client::build_list_client(Duration::from_secs(1)).unwrap();
        let (filter, auxiliary) = prepare_ip_filter(&config, &client, &context).await.unwrap();
        assert!(auxiliary.is_empty());
        assert!(!filter.unwrap().is_empty());
    }

    #[tokio::test]
    async fn standalone_exposes_enrollment_pair_without_claiming_active_membership() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
        let artifact = ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        let manifest = CorpusManifest::new(artifact.clone(), Vec::new(), Vec::new()).unwrap();
        store.install_manifest(&manifest).unwrap();
        store.mark_active(&manifest.generation, &artifact).unwrap();
        let standalone = RuntimeActivePairProvider {
            store: Some(store.clone()),
            enrolled: false,
        };
        assert_eq!(standalone.active_pair(), None);
        assert_eq!(
            standalone.enrollment_pair().await.unwrap(),
            ActivePolicyCorpus {
                policy: artifact.clone(),
                corpus_generation: manifest.generation.clone(),
            }
        );
        let enrolled = RuntimeActivePairProvider {
            store: Some(store),
            enrolled: true,
        };
        assert_eq!(
            enrolled.active_pair(),
            Some(ActivePolicyCorpus {
                policy: artifact,
                corpus_generation: manifest.generation,
            })
        );
    }

    #[tokio::test]
    async fn standalone_legacy_cache_can_serve_before_exact_enrollment_pair_exists() {
        let root = tempfile::tempdir().unwrap();
        let context = NodeCorpusRuntime {
            store: Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap()),
            secondary: None,
        };
        let provider = context.active_pair_provider(false);

        context.record_active(None, None).unwrap();
        assert!(provider.active_pair().is_none());
        assert!(provider.enrollment_pair().await.is_err());
    }

    #[test]
    fn private_candidate_preflight_does_not_require_promotion() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let store = CorpusStore::open(&master).unwrap();
        let artifact = ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        let manifest = CorpusManifest::new(artifact.clone(), Vec::new(), Vec::new()).unwrap();
        store.prepare_manifest_private(&manifest).unwrap();
        assert!(store
            .manifest_for_artifact(&artifact.artifact_hash)
            .is_err());

        preflight_received_manifest(&master, &ConfigV1::test_scaffold(), &manifest).unwrap();
    }
}
