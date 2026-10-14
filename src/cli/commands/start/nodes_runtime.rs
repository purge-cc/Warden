use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context};

use crate::cluster::corpus::{is_not_found, CorpusAuxSource, CorpusManifest, CorpusStore};
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
            proof_available: Arc::new(AtomicBool::new(true)),
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
                let manifest = self.store.manifest(active)?;
                // Without a membership corpus nothing else retires past
                // policy pointers; the store still keeps active, pinned and
                // in-flight generations.
                if primary.and_then(|state| state.corpus_store()).is_none() {
                    if let Err(error) = self.store.retain_policy_artifacts(&BTreeSet::new()) {
                        tracing::warn!(
                            error = %format_args!("{error:#}"),
                            "past node policy corpora not retired"
                        );
                    }
                }
                manifest
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
        mut manager: Option<&mut ListManager>,
        observe: Option<&Arc<crate::cluster::ClusterObserve>>,
        primary: Option<&Arc<crate::cluster::ClusterState>>,
        artifact: Option<&ArtifactIdentity>,
        auxiliary: Vec<CorpusAuxSource>,
    ) -> anyhow::Result<()> {
        self.mark_secondary_active()?;
        if self.secondary.is_none() {
            self.publish_primary(
                manager.as_deref_mut(),
                artifact.context("enrollment artifact unavailable")?,
                auxiliary,
            )?;
            // A Partial corpus publishes nothing and the store still names
            // the previous pair; the active-pair hook claims the pair on the
            // first complete publication.
            if manager.is_some_and(|manager| manager.node_corpus_generation().is_none()) {
                return Ok(());
            }
        }
        self.record_active(observe, primary)
    }
}

/// Reads of the active pair a concurrent publish may interrupt. Each pass
/// hashes the whole corpus, and a publish lands at most once per refresh.
const READ_PAIR_PASSES: usize = 3;

pub(super) struct RuntimeActivePairProvider {
    store: Option<Arc<CorpusStore>>,
    enrolled: bool,
    proof_available: Arc<AtomicBool>,
}

impl RuntimeActivePairProvider {
    pub fn unavailable() -> Arc<Self> {
        Arc::new(Self {
            store: None,
            enrolled: false,
            proof_available: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn set_proof_available(&self, available: bool) {
        self.proof_available.store(available, Ordering::Release);
    }

    /// Prove the active pair from the store, `None` when no verified pair
    /// is active. A list refresh publishes and prunes without waiting for
    /// readers, so a pass that loses a file or sees the active generation
    /// move starts over, up to [`READ_PAIR_PASSES`] passes in all.
    fn read_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        self.read_pair_checked(true)
    }

    /// [`Self::read_pair`]; `verify_objects = false` trusts the manifest
    /// and skips hashing every corpus object.
    fn read_pair_checked(
        &self,
        verify_objects: bool,
    ) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        let mut pass = 1;
        loop {
            let error = match self.read_pair_pass(verify_objects) {
                Ok(None) => return Ok(None),
                Ok(Some((pair, true))) => return Ok(Some(pair)),
                Ok(Some((pair, false))) => anyhow::anyhow!(
                    "active corpus generation {} changed during inspection",
                    pair.corpus_generation
                ),
                Err(error) if is_not_found(&error) => error,
                Err(error) => return Err(error),
            };
            if pass == READ_PAIR_PASSES {
                return Err(error.context(format!(
                    "active pair unreadable after {READ_PAIR_PASSES} reads"
                )));
            }
            pass += 1;
        }
    }

    /// One unlocked read, and whether its generation was still active at
    /// the end of it.
    fn read_pair_pass(
        &self,
        verify_objects: bool,
    ) -> anyhow::Result<Option<(ActivePolicyCorpus, bool)>> {
        ensure!(
            self.proof_available.load(Ordering::Acquire),
            "active pair is transitioning"
        );
        let store = self
            .store
            .as_ref()
            .context("enrollment corpus is unavailable")?;
        let Some(generation) = store.pair_state()?.active else {
            return Ok(None);
        };
        #[cfg(test)]
        read_pair_hook("pair");
        let manifest = store
            .manifest(&generation)
            .with_context(|| format!("corpus generation {generation}"))?;
        #[cfg(test)]
        read_pair_hook("manifest");
        if verify_objects {
            store
                .verify_manifest_objects(&manifest)
                .with_context(|| format!("corpus generation {generation}"))?;
        }
        let still_active = store.pair_state()?.active.as_deref() == Some(generation.as_str());
        ensure!(
            self.proof_available.load(Ordering::Acquire),
            "active pair is transitioning"
        );
        Ok(Some((
            ActivePolicyCorpus {
                policy: manifest.artifact,
                corpus_generation: generation,
            },
            still_active,
        )))
    }

    /// [`Self::read_pair`] off the async runtime.
    async fn read_pair_blocking(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        let store = self.store.clone();
        let proof_available = Arc::clone(&self.proof_available);
        tokio::task::spawn_blocking(move || {
            RuntimeActivePairProvider {
                store,
                enrolled: false,
                proof_available,
            }
            .read_pair()
        })
        .await?
    }
}

fn log_unavailable_proof(error: &anyhow::Error) {
    tracing::error!(
        error = %format_args!("{error:#}"),
        "active Nodes policy/corpus proof is unavailable"
    );
}

#[cfg(test)]
type ReadPairHook = Box<dyn FnMut(&'static str)>;

#[cfg(test)]
thread_local! {
    static READ_PAIR_HOOK: std::cell::RefCell<Option<ReadPairHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn read_pair_hook(stage: &'static str) {
    READ_PAIR_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(stage);
        }
    });
}

#[async_trait::async_trait]
impl ActivePairProvider for RuntimeActivePairProvider {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        if !self.enrolled {
            return None;
        }
        self.read_pair()
            .inspect_err(log_unavailable_proof)
            .ok()
            .flatten()
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        self.read_pair_blocking()
            .await?
            .context("no verified policy/corpus pair is active")
    }

    async fn verified_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        if !self.enrolled {
            return Ok(None);
        }
        self.read_pair_blocking()
            .await
            .inspect_err(log_unavailable_proof)
    }

    fn active_identity(&self) -> Option<ActivePolicyCorpus> {
        if !self.enrolled {
            return None;
        }
        self.read_pair_checked(false)
            .inspect_err(|error| {
                tracing::debug!(
                    error = %format_args!("{error:#}"),
                    "active Nodes pair identity is unavailable"
                );
            })
            .ok()
            .flatten()
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
    pair_provider: Option<&Arc<RuntimeActivePairProvider>>,
) {
    let observe = observe.cloned();
    let primary_state = primary.cloned();
    let pair_provider = pair_provider.cloned();
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
        // A complete publication ends a Partial reload's hidden proof.
        if let Some(provider) = &pair_provider {
            provider.set_proof_available(true);
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
                    let (prepared, sources) =
                        prepare_ip_filter(&config, &client, &context, true).await?;
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

/// Build the IP filter and the IP list bodies a primary publishes.
///
/// `allow_missing` (boot and the primary refresh) skips, with a warning, a
/// source that has no usable body, so one dead IP list never keeps DNS down.
/// A reload and a secondary still require every body.
pub(super) async fn prepare_ip_filter(
    config: &ConfigV1,
    client: &reqwest::Client,
    context: &NodeCorpusRuntime,
    allow_missing: bool,
) -> anyhow::Result<(Option<Arc<IpFilter>>, Vec<CorpusAuxSource>)> {
    if !config.ip_blocklists.enabled {
        if let Some(manifest) = &context.secondary {
            manifest.verify_auxiliary(&[])?;
        }
        return Ok((Some(Arc::new(IpFilter::new())), Vec::new()));
    }
    let lenient = allow_missing && context.secondary.is_none();
    let mut auxiliary = Vec::new();
    let prior = if let Some(manifest) = &context.secondary {
        manifest.verify_auxiliary(&config.ip_blocklists.sources)?;
        auxiliary = manifest.auxiliary.clone();
        None
    } else {
        let prior = context.store.pair_state().and_then(|pair| {
            pair.active
                .or(pair.persisted)
                .map(|generation| context.store.manifest(&generation))
                .transpose()
        });
        let prior = match prior {
            Ok(prior) => prior,
            Err(error) if lenient => {
                tracing::warn!(
                    error = %format_args!("{error:#}"),
                    "previous IP list bodies unreadable; fetching without them"
                );
                None
            }
            Err(error) => return Err(error),
        };
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
                    let retained = prior.as_ref().and_then(|manifest| {
                        manifest.auxiliary.iter().find(|source| &source.url == url)
                    });
                    match retained {
                        Some(source) => {
                            tracing::warn!(%url, %error, "IP list unavailable; retaining verified previous body");
                            source.clone()
                        }
                        None if lenient => {
                            tracing::warn!(
                                %url,
                                %error,
                                "IP list unavailable; continuing without it until it can be fetched"
                            );
                            continue;
                        }
                        None => anyhow::bail!(
                            "IP list acquisition failed without a retained body: {error}"
                        ),
                    }
                }
            };
            auxiliary.push(source);
        }
        prior
    };
    let ips = if lenient {
        // A body that does not parse falls back to the previous body, else
        // the source is dropped: no manifest may list a body that was never
        // parsed.
        let mut ips = inline_ips(config);
        auxiliary.retain_mut(|source| {
            let error = match parse_auxiliary_source(config, &context.store, source) {
                Ok(parsed) => {
                    ips.extend(parsed);
                    return true;
                }
                Err(error) => error,
            };
            let previous = prior.as_ref().and_then(|manifest| {
                let previous = manifest
                    .auxiliary
                    .iter()
                    .find(|previous| previous.url == source.url && previous.body != source.body)?;
                let parsed = parse_auxiliary_source(config, &context.store, previous).ok()?;
                Some((previous, parsed))
            });
            let Some((previous, parsed)) = previous else {
                tracing::warn!(
                    url = %source.url,
                    error = %format_args!("{error:#}"),
                    "IP list unusable; continuing without it until it can be fetched"
                );
                return false;
            };
            tracing::warn!(
                url = %source.url,
                error = %format_args!("{error:#}"),
                "IP list unusable; retaining verified previous body"
            );
            *source = previous.clone();
            ips.extend(parsed);
            true
        });
        ips
    } else {
        parse_auxiliary(config, &context.store, &auxiliary)?
    };
    Ok((Some(Arc::new(IpFilter::with_ips(ips))), auxiliary))
}

type IpSet = std::collections::HashSet<std::net::IpAddr, ahash::RandomState>;

fn inline_ips(config: &ConfigV1) -> IpSet {
    config
        .ip_blocklists
        .inline
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn parse_auxiliary(
    config: &ConfigV1,
    store: &CorpusStore,
    auxiliary: &[CorpusAuxSource],
) -> anyhow::Result<IpSet> {
    let mut ips = inline_ips(config);
    for source in auxiliary {
        ips.extend(parse_auxiliary_source(config, store, source)?);
    }
    Ok(ips)
}

fn parse_auxiliary_source(
    config: &ConfigV1,
    store: &CorpusStore,
    source: &CorpusAuxSource,
) -> anyhow::Result<IpSet> {
    ensure!(
        source.body.bytes <= config.lists.max_body_bytes as u64,
        "received IP list exceeds the configured body cap"
    );
    let mut ips = IpSet::default();
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
    Ok(ips)
}

/// Prepare each stored Nodes listener. A listener that cannot be restored
/// is logged and reported; the others still start.
// ponytail: no retry before the next start; a retry needs a check against
// the current Nodes state, because a later operation may have retired it.
pub(super) async fn restore_listeners(
    listeners: &dyn crate::cluster::node_control::NodeListenerControl,
    specs: Vec<crate::cluster::node_control::NodeListenerSpec>,
) -> (Vec<std::net::SocketAddr>, Vec<String>) {
    let mut ready = Vec::with_capacity(specs.len());
    let mut problems = Vec::new();
    for spec in specs {
        let endpoint = spec.endpoint;
        match listeners.prepare(spec).await {
            Ok(()) => ready.push(endpoint),
            Err(error) => {
                tracing::error!(
                    %endpoint,
                    error = %format_args!("{error:#}"),
                    "Nodes listener not restored; peers cannot reach this node at this endpoint"
                );
                problems.push(format!("Nodes listener {endpoint} not restored: {error:#}"));
            }
        }
    }
    (ready, problems)
}

/// Owns the Nodes bring-up after DNS is up: runtime start, listener restore,
/// the runtime-start acknowledgement and readiness, in that order. A stage
/// that fails is reported in the Nodes status and retried on the next tick
/// instead of stopping a daemon that already serves DNS, except a listener
/// that could not be restored: it stays reported until the next start (see
/// `restore_listeners`).
pub(super) struct NodeRuntimeSupervisor {
    controller: Arc<crate::cluster::node_control::NodeController>,
    listeners: Arc<dyn crate::cluster::node_control::NodeListenerControl>,
    master: std::path::PathBuf,
    /// The boot config: the acknowledgement covers only this membership.
    active: ConfigV1,
    started: bool,
    acknowledged: bool,
    pending_ready: Vec<std::net::SocketAddr>,
    unrestored: Vec<String>,
    /// Last logged failure per stage, so a repeat logs at debug only.
    last_error: std::collections::HashMap<&'static str, String>,
}

impl NodeRuntimeSupervisor {
    pub fn new(
        controller: Arc<crate::cluster::node_control::NodeController>,
        listeners: Arc<dyn crate::cluster::node_control::NodeListenerControl>,
        master: std::path::PathBuf,
        active: ConfigV1,
    ) -> Self {
        Self {
            controller,
            listeners,
            master,
            active,
            started: false,
            acknowledged: false,
            pending_ready: Vec::new(),
            unrestored: Vec::new(),
            last_error: std::collections::HashMap::new(),
        }
    }

    /// One pass over the stages still pending. Publishes the problems to the
    /// Nodes status and returns them.
    pub async fn step(&mut self) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.started {
            match self.controller.runtime_start().await {
                Ok(plan) => {
                    self.started = true;
                    self.record("start", None);
                    (self.pending_ready, self.unrestored) =
                        restore_listeners(self.listeners.as_ref(), plan.listeners).await;
                }
                Err(error) => {
                    problems.push(format!("Nodes runtime start pending: {error:#}"));
                    self.record("start", problems.last());
                }
            }
        }
        if !self.acknowledged {
            let master = self.master.clone();
            let active = self.active.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                crate::cluster::lifecycle::acknowledge_runtime_start(&master, &active)
            })
            .await
            .context("node readiness worker failed")
            .and_then(|outcome| outcome);
            match outcome {
                Ok(()) => {
                    self.acknowledged = true;
                    self.record("acknowledge", None);
                }
                // The acknowledgement and readiness errors can quote
                // config.toml, and the Nodes status is readable without a
                // token: the status gets a summary, the daemon log the cause.
                Err(error) => {
                    let summary =
                        "runtime start acknowledgement pending (policy edits stay blocked)";
                    self.record("acknowledge", Some(&format!("{summary}: {error:#}")));
                    problems.push(format!("{summary}; see the daemon log"));
                }
            }
        }
        // Readiness acknowledges restart steps, so it waits for the
        // acknowledgement: until then the membership still reports a
        // pending restart.
        if self.started && self.acknowledged {
            let mut failures = Vec::new();
            let mut pending = Vec::new();
            for endpoint in std::mem::take(&mut self.pending_ready) {
                if let Err(error) = self.controller.runtime_ready(endpoint).await {
                    failures.push(format!("readiness pending for {endpoint}: {error:#}"));
                    problems.push(format!(
                        "readiness pending for {endpoint}; see the daemon log"
                    ));
                    pending.push(endpoint);
                }
            }
            self.pending_ready = pending;
            self.record(
                "ready",
                (!failures.is_empty()).then(|| failures.join("; ")).as_ref(),
            );
        } else if self.started && !self.pending_ready.is_empty() {
            problems.push("readiness waiting for acknowledgement".into());
        }
        problems.extend(self.unrestored.iter().cloned());
        self.controller.set_runtime_problems(problems.clone());
        problems
    }

    /// Log a stage outcome: error on a new failure, debug on a repeat, info
    /// once on recovery.
    fn record(&mut self, stage: &'static str, problem: Option<&String>) {
        match problem {
            Some(problem) if self.last_error.get(stage) == Some(problem) => {
                tracing::debug!(stage, %problem, "Nodes bring-up still pending");
            }
            Some(problem) => {
                tracing::error!(stage, %problem, "Nodes bring-up step failed; retrying");
                self.last_error.insert(stage, problem.clone());
            }
            None => {
                if self.last_error.remove(stage).is_some() {
                    tracing::info!(stage, "Nodes bring-up step recovered");
                }
            }
        }
    }

    /// Retry the pending stages; once all are done, drive the durable Nodes
    /// reconciliation. Never runs the reconciliation before readiness.
    // ponytail: fixed 2 s tick; each attempt can also wait 30 s on the config
    // lock, which is the effective backoff. Add a setting if hosts need one.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.step().await;
            if self.started && self.acknowledged && self.pending_ready.is_empty() {
                match self.controller.runtime_tick().await {
                    Ok(advanced) if advanced > 0 => {
                        tracing::info!(advanced, "durable Nodes operation reconciled");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, "durable Nodes reconciliation failed");
                    }
                }
            }
        }
    }
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
        let (filter, auxiliary) = prepare_ip_filter(&config, &client, &context, false)
            .await
            .unwrap();
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
            proof_available: Arc::new(AtomicBool::new(true)),
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
            proof_available: Arc::new(AtomicBool::new(true)),
        };
        assert_eq!(standalone.verified_pair().await.unwrap(), None);
        enrolled.set_proof_available(false);
        assert!(enrolled.active_pair().is_none());
        assert!(enrolled.enrollment_pair().await.is_err());
        assert!(
            enrolled.verified_pair().await.is_err(),
            "a hidden proof read as no active pair"
        );
        enrolled.set_proof_available(true);
        let active = Some(ActivePolicyCorpus {
            policy: artifact,
            corpus_generation: manifest.generation,
        });
        assert_eq!(enrolled.active_pair(), active);
        assert_eq!(enrolled.verified_pair().await.unwrap(), active);
    }

    /// Run `publish` once, the first time a read reaches `stage`.
    fn publish_mid_read(stage: &'static str, publish: impl FnOnce() + 'static) {
        let mut publish = Some(publish);
        READ_PAIR_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |at| {
                if at == stage {
                    if let Some(publish) = publish.take() {
                        publish();
                    }
                }
            }));
        });
    }

    #[test]
    fn active_pair_survives_a_same_artifact_publish_mid_read() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
        let artifact = ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        let old_body = fixture(&store, b"192.0.2.1\n");
        let publish = {
            let (store, artifact) = (store.clone(), artifact.clone());
            move |auxiliary: CorpusAuxSource| {
                let manifest =
                    CorpusManifest::new(artifact.clone(), Vec::new(), vec![auxiliary]).unwrap();
                store.install_manifest(&manifest).unwrap();
                store.mark_active(&manifest.generation, &artifact).unwrap();
                store.release_unpublished_pins().unwrap();
                manifest.generation
            }
        };
        publish(old_body.clone());
        let provider = RuntimeActivePairProvider {
            store: Some(store.clone()),
            enrolled: true,
            proof_available: Arc::new(AtomicBool::new(true)),
        };

        // A revalidation changes only `fetched_at`: a new generation of the
        // same bodies, whose activation prunes the manifest being read.
        let revalidated = CorpusAuxSource {
            fetched_at: 2,
            ..old_body.clone()
        };
        let generation = Arc::new(std::sync::Mutex::new(String::new()));
        let (sink, next) = (generation.clone(), publish.clone());
        publish_mid_read("pair", move || {
            *sink.lock().unwrap() = next(revalidated);
        });
        let pair = provider
            .active_pair()
            .expect("a pruned manifest ended the read");
        assert_eq!(pair.corpus_generation, *generation.lock().unwrap());

        // The same revalidation after the manifest is read leaves every file
        // readable, but the generation proven is no longer the active one.
        let revalidated = CorpusAuxSource {
            fetched_at: 3,
            ..old_body.clone()
        };
        let (sink, next) = (generation.clone(), publish.clone());
        publish_mid_read("manifest", move || {
            *sink.lock().unwrap() = next(revalidated);
        });
        let pair = provider.active_pair().expect("a superseded read ended");
        assert_eq!(pair.corpus_generation, *generation.lock().unwrap());

        // New content: the old body is collected while the read still has to
        // hash it.
        let changed = fixture(&store, b"192.0.2.2\n");
        let (sink, next) = (generation.clone(), publish);
        publish_mid_read("manifest", move || {
            *sink.lock().unwrap() = next(changed);
        });
        let pair = provider
            .active_pair()
            .expect("a collected object ended the read");
        assert_eq!(pair.corpus_generation, *generation.lock().unwrap());
        assert!(store.open_object(&old_body.body.sha256).is_err());

        // A body that stays missing still fails, naming what was read.
        READ_PAIR_HOOK.with(|hook| hook.borrow_mut().take());
        let active = generation.lock().unwrap().clone();
        let manifest = store.manifest(&active).unwrap();
        let object = manifest.objects().next().unwrap();
        std::fs::remove_file(store.object_path(&object.sha256).unwrap()).unwrap();
        let error = format!("{:#}", provider.read_pair().unwrap_err());
        assert!(
            error.contains("unreadable after 3 reads") && error.contains(&active),
            "{error}"
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
        let enrolled = context.active_pair_provider(true);
        assert_eq!(enrolled.verified_pair().await.unwrap(), None);
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

    struct RefuseSome(Vec<std::net::SocketAddr>);

    #[async_trait::async_trait]
    impl crate::cluster::node_control::NodeListenerControl for RefuseSome {
        async fn prepare(
            &self,
            spec: crate::cluster::node_control::NodeListenerSpec,
        ) -> anyhow::Result<()> {
            ensure!(!self.0.contains(&spec.endpoint), "address in use");
            Ok(())
        }

        async fn retire(&self, _endpoint: std::net::SocketAddr) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn listener_spec(endpoint: &str) -> crate::cluster::node_control::NodeListenerSpec {
        crate::cluster::node_control::NodeListenerSpec {
            endpoint: endpoint.parse().unwrap(),
            certificate_pem: "certificate".into(),
            private_key_pem: crate::cluster::membership::SecretString("key".into()),
            scope: crate::cluster::node_control::ListenerScope::Management,
        }
    }

    #[tokio::test]
    async fn restore_listeners_skips_unrestorable_endpoints_and_keeps_the_rest() {
        let (a, b, c) = ("192.0.2.1:8053", "192.0.2.2:8053", "192.0.2.3:8053");
        let listeners = RefuseSome(vec![a.parse().unwrap(), b.parse().unwrap()]);
        let (ready, problems) = restore_listeners(
            &listeners,
            vec![listener_spec(a), listener_spec(b), listener_spec(c)],
        )
        .await;
        assert_eq!(ready, vec![c.parse::<std::net::SocketAddr>().unwrap()]);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains(a) && problems[0].contains("address in use"));
        assert!(problems[1].contains(b));
    }

    #[derive(Default)]
    struct CountPrepares(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl crate::cluster::node_control::NodeListenerControl for CountPrepares {
        async fn prepare(
            &self,
            _spec: crate::cluster::node_control::NodeListenerSpec,
        ) -> anyhow::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn retire(&self, _endpoint: std::net::SocketAddr) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct NoPair;

    #[async_trait::async_trait]
    impl ActivePairProvider for NoPair {
        fn active_pair(&self) -> Option<ActivePolicyCorpus> {
            None
        }

        async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
            anyhow::bail!("this fixture has no published pair")
        }

        async fn verified_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
            Ok(None)
        }
    }

    fn supervised_node() -> (
        tempfile::TempDir,
        Arc<crate::cluster::node_control::NodeController>,
        Arc<CountPrepares>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("config.toml");
        let node_id = crate::cluster::membership::random_id();
        let text = format!(
            "schema_version = 5\n[node]\nid = {node_id:?}\nname = \"Desk\"\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        );
        crate::config::atomic_write::hardened_atomic_write(
            &master,
            text.as_bytes(),
            Default::default(),
        )
        .unwrap();
        let listeners = Arc::new(CountPrepares::default());
        let (restart, _receiver) = crate::cluster::managed_restart::channel(1);
        let controller = crate::cluster::node_control::NodeController::new(
            master,
            listeners.clone(),
            restart,
            Arc::new(NoPair),
        );
        (directory, controller, listeners)
    }

    fn supervisor(
        directory: &tempfile::TempDir,
        controller: &Arc<crate::cluster::node_control::NodeController>,
        listeners: &Arc<CountPrepares>,
    ) -> NodeRuntimeSupervisor {
        NodeRuntimeSupervisor::new(
            controller.clone(),
            listeners.clone(),
            directory.path().join("config.toml"),
            ConfigV1::test_scaffold(),
        )
    }

    #[tokio::test]
    async fn supervisor_retries_runtime_start_after_a_store_error() {
        let (directory, controller, listeners) = supervised_node();
        // Let the store create itself, then corrupt its state in place.
        controller.runtime_start().await.unwrap();
        let state = std::fs::read_dir(directory.path().join(".warden-node-control"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap()
            .join("state.json");
        std::fs::write(&state, b"{").unwrap();
        let mut supervisor = supervisor(&directory, &controller, &listeners);

        let problems = supervisor.step().await;
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("runtime start pending")),
            "{problems:?}"
        );
        assert_eq!(listeners.0.load(Ordering::SeqCst), 0);
        assert!(!supervisor.started);

        std::fs::remove_file(&state).unwrap();
        let problems = supervisor.step().await;
        assert!(problems.is_empty(), "{problems:?}");
        assert!(supervisor.started);
    }

    #[tokio::test]
    async fn supervisor_waits_for_acknowledgement_before_readiness() {
        let (directory, controller, listeners) = supervised_node();
        controller
            .handle(
                crate::cluster::node_control::NodeControlCommand::TokenPrepare {
                    listen: Some("127.0.0.1:19300".parse().unwrap()),
                },
            )
            .await
            .unwrap();
        let prepared = listeners.0.load(Ordering::SeqCst);
        let mut supervisor = supervisor(&directory, &controller, &listeners);
        let master = directory.path().join("config.toml");
        let saved = std::fs::read(&master).unwrap();
        crate::config::atomic_write::hardened_atomic_write(
            &master,
            b"not = [valid toml",
            Default::default(),
        )
        .unwrap();

        // Runtime start does not parse the master, so the listener comes
        // back; the acknowledgement does, so readiness has to wait.
        let problems = supervisor.step().await;
        assert_eq!(listeners.0.load(Ordering::SeqCst), prepared + 1);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("acknowledgement pending")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("readiness waiting for acknowledgement")),
            "{problems:?}"
        );
        // Status is readable without a token: no config.toml text in it.
        assert!(
            !problems
                .iter()
                .any(|problem| problem.contains("valid toml")),
            "{problems:?}"
        );
        assert_eq!(supervisor.pending_ready.len(), 1);
        // Readiness reads the master through the same loader.
        supervisor.acknowledged = true;
        let problems = supervisor.step().await;
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("readiness pending for 127.0.0.1:19300")),
            "{problems:?}"
        );
        assert!(
            !problems
                .iter()
                .any(|problem| problem.contains("valid toml")),
            "{problems:?}"
        );
        supervisor.acknowledged = false;

        crate::config::atomic_write::hardened_atomic_write(&master, &saved, Default::default())
            .unwrap();
        let problems = supervisor.step().await;
        assert!(problems.is_empty(), "{problems:?}");
        assert!(supervisor.pending_ready.is_empty());
    }

    fn artifact() -> ArtifactIdentity {
        ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        }
    }

    /// An IP list config whose one source is refused before any connection
    /// (a literal private address), so a fetch fails at once.
    fn refused_ip_source_config() -> ConfigV1 {
        let mut config = ConfigV1::test_scaffold();
        config.ip_blocklists.enabled = true;
        config.ip_blocklists.inline = vec!["192.0.2.42".into()];
        config.ip_blocklists.sources = vec!["https://192.168.0.1/ips".into()];
        config
    }

    #[tokio::test]
    async fn boot_skips_ip_source_without_retained_body() {
        let root = tempfile::tempdir().unwrap();
        let config = refused_ip_source_config();
        let context = NodeCorpusRuntime::load(&root.path().join("config.toml"), &config, true)
            .unwrap()
            .unwrap();
        let client = reqwest::Client::new();
        let (filter, auxiliary) = prepare_ip_filter(&config, &client, &context, true)
            .await
            .unwrap();
        assert!(auxiliary.is_empty());
        assert_eq!(filter.unwrap().len(), 1, "the inline IP is lost");
        let Err(error) = prepare_ip_filter(&config, &client, &context, false).await else {
            panic!("a reload accepted an IP list without a body");
        };
        assert!(
            error.to_string().contains("without a retained body"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn boot_skips_retained_ip_body_over_cap() {
        let root = tempfile::tempdir().unwrap();
        let mut config = refused_ip_source_config();
        let context = NodeCorpusRuntime::load(&root.path().join("config.toml"), &config, true)
            .unwrap()
            .unwrap();
        let retained = CorpusAuxSource {
            url: config.ip_blocklists.sources[0].clone(),
            ..fixture(&context.store, b"192.0.2.1\n192.0.2.2\n")
        };
        let manifest = CorpusManifest::new(artifact(), Vec::new(), vec![retained.clone()]).unwrap();
        context.store.install_manifest(&manifest).unwrap();
        context
            .store
            .mark_active(&manifest.generation, &manifest.artifact)
            .unwrap();
        config.lists.max_body_bytes = retained.body.bytes as usize - 1;
        let client = reqwest::Client::new();
        let (filter, auxiliary) = prepare_ip_filter(&config, &client, &context, true)
            .await
            .unwrap();
        assert!(
            auxiliary.is_empty(),
            "a body that never parsed is published"
        );
        assert_eq!(filter.unwrap().len(), 1);
        let Err(error) = prepare_ip_filter(&config, &client, &context, false).await else {
            panic!("a reload accepted an IP list over the body cap");
        };
        assert!(error.to_string().contains("body cap"), "{error:#}");
    }

    /// A client for a one-shot HTTPS origin at `ips.example.test` that
    /// answers `body`.
    async fn ip_origin(body: &'static [u8]) -> reqwest::Client {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["ips.example.test".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let _ = tls.read(&mut [0; 4096]).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(head.as_bytes()).await.unwrap();
            tls.write_all(body).await.unwrap();
            let _ = tls.shutdown().await;
        });
        reqwest::Client::builder()
            .resolve("ips.example.test", addr)
            .add_root_certificate(
                reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap(),
            )
            .build()
            .unwrap()
    }

    /// The primary refresh must not swap a good retained body for a fresh
    /// one that does not parse.
    #[tokio::test]
    async fn refresh_keeps_retained_ip_body_when_the_fetched_one_does_not_parse() {
        let root = tempfile::tempdir().unwrap();
        let mut config = ConfigV1::test_scaffold();
        config.ip_blocklists.enabled = true;
        config.ip_blocklists.sources = vec!["https://ips.example.test/ips".into()];
        let context = NodeCorpusRuntime::load(&root.path().join("config.toml"), &config, true)
            .unwrap()
            .unwrap();
        let retained = CorpusAuxSource {
            url: config.ip_blocklists.sources[0].clone(),
            ..fixture(&context.store, b"192.0.2.1\n")
        };
        let manifest = CorpusManifest::new(artifact(), Vec::new(), vec![retained.clone()]).unwrap();
        context.store.install_manifest(&manifest).unwrap();
        context
            .store
            .mark_active(&manifest.generation, &manifest.artifact)
            .unwrap();
        let client = ip_origin(b"192.0.2.2\n\xff\n").await;
        let (filter, auxiliary) = prepare_ip_filter(&config, &client, &context, true)
            .await
            .unwrap();
        assert_eq!(auxiliary, vec![retained]);
        assert_eq!(filter.unwrap().len(), 1);
    }

    #[test]
    fn standalone_activation_retires_past_policy_pointers() {
        let root = tempfile::tempdir().unwrap();
        let context = NodeCorpusRuntime {
            store: Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap()),
            secondary: None,
        };
        for epoch in 1..=5 {
            let artifact = ArtifactIdentity {
                policy_epoch: epoch,
                artifact_hash: format!("{epoch:064x}"),
                ..artifact()
            };
            context
                .publish_primary(None, &artifact, Vec::new())
                .unwrap();
            context.record_active(None, None).unwrap();
        }
        let count = |dir: &Path, prefix: &str| {
            std::fs::read_dir(dir)
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(prefix)
                })
                .count()
        };
        let corpus = root.path().join(".warden-node-corpus");
        assert_eq!(count(&corpus, "policy-"), 1);
        assert!(count(&corpus.join("manifests"), "") <= 1);
    }

    #[test]
    fn active_identity_reads_the_pair_without_hashing_corpus_objects() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
        let artifact = ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        let body = fixture(&store, b"192.0.2.1\n");
        let manifest =
            CorpusManifest::new(artifact.clone(), Vec::new(), vec![body.clone()]).unwrap();
        store.install_manifest(&manifest).unwrap();
        store.mark_active(&manifest.generation, &artifact).unwrap();
        std::fs::remove_file(store.object_path(&body.body.sha256).unwrap()).unwrap();
        let provider = RuntimeActivePairProvider {
            store: Some(store),
            enrolled: true,
            proof_available: Arc::new(AtomicBool::new(true)),
        };

        assert_eq!(provider.active_pair(), None, "a missing body still proves");
        assert_eq!(
            provider.active_identity(),
            Some(ActivePolicyCorpus {
                policy: artifact,
                corpus_generation: manifest.generation,
            })
        );
        provider.set_proof_available(false);
        assert_eq!(provider.active_identity(), None);
    }
}
