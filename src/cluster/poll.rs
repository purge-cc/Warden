//! Authenticated artifact polling preserves persisted and active identities separately.
//!
//! A successful cycle requires the current resolver to match the owned artifact
//! and the primary to acknowledge that identity in its fresh heartbeat response.
//! Failed polling retains the last-good policy while invalidating convergence.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::sync::mpsc;

use crate::tracking::StatsEngine;

use super::dto::ClusterStats;
use super::observe::{ClusterObserve, SyncStatus};

/// Per-request timeout for the poll HTTP client — bounded so a hung primary
/// never stalls the loop past a tick or two.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGEMENT_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(3);
const MANAGEMENT_UPGRADE_RETRY: Duration = Duration::from_secs(300);

/// Run the secondary poll loop forever. Captures clones of the daemon's
/// shared handles; returns only if the reload channel closes (daemon
/// shutdown). All identity (`peer`, `token`, `interval`) is fixed at boot.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    config_path: PathBuf,
    reload_tx: mpsc::Sender<Option<u32>>,
    peer: String,
    token: String,
    interval: Duration,
    stats: Option<Arc<StatsEngine>>,
    observe: Arc<ClusterObserve>,
    node_name: Option<String>,
    profiles: Option<Arc<crate::profiles::ProfileResolver>>,
    candidate_runtime: Arc<crate::operator_rules::PolicyCandidateRuntime>,
    node_controller: Arc<super::node_control::NodeController>,
) {
    let modern = modern_membership(&config_path).await;
    let transport = if modern {
        let master = config_path.clone();
        match tokio::task::spawn_blocking(move || {
            super::pairing::load_secondary_credential(&master)
        })
        .await
        {
            Ok(Ok(credential)) => match super::pairing::secondary_client(&credential) {
                Ok(client) => Some((
                    client,
                    credential.primary.trim_end_matches('/').to_owned(),
                    credential.credential.0.clone(),
                    Some(credential),
                )),
                Err(error) => {
                    tracing::error!(%error, "node replication TLS setup failed");
                    None
                }
            },
            result => {
                tracing::error!(?result, "node replication credential unavailable");
                None
            }
        }
    } else {
        let peer = peer.trim_end_matches('/').to_owned();
        let peer_cert = peer_cert_from_config(&config_path);
        match super::pinned::build_pinned_client(&peer, peer_cert.as_deref(), REQUEST_TIMEOUT) {
            Ok(client) => Some((client, peer, token, None)),
            Err(error) => {
                tracing::error!(%error, "legacy replication TLS setup failed");
                None
            }
        }
    };
    let Some((client, peer, token, credential)) = transport else {
        observe.store_sync(SyncStatus {
            last_config_hash: None,
            last_sync: None,
            last_poll_ok: false,
            last_error: Some("node replication credential or pinned TLS setup unavailable".into()),
            synced_at_least_once: false,
        });
        return;
    };

    tracing::info!(%peer, interval_secs = interval.as_secs(), "cluster secondary: poll loop started");

    // The ledger survives restart; this observation requires a new session ack.
    let mut last_config_hash: Option<String> = None;

    // Observe-only telemetry locals (NOT convergence state): the time
    // of the last *successful* poll and whether we've ever synced. Mirrored
    // into `observe` at the end of every tick for the IPC reader; they never
    // feed a convergence decision.
    let mut last_sync: Option<Instant> = None;
    let mut synced_once = false;
    let mut management_ready = false;
    let mut management_retry_at = Instant::now();
    let mut primary_rebind_proof_complete = false;

    // `interval`'s first tick fires immediately, so the secondary converges on
    // boot without waiting a full period.
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Some(credential) = &credential {
            if let Err(error) = super::pairing::activate(credential).await {
                observe.store_sync(SyncStatus {
                    last_config_hash: last_config_hash.clone(),
                    last_sync,
                    last_poll_ok: false,
                    last_error: Some(error.to_string()),
                    synced_at_least_once: synced_once,
                });
                continue;
            }
        }
        let roster_error = if let Some(credential) = &credential {
            super::pairing::refresh_roster(credential, &config_path)
                .await
                .err()
        } else {
            None
        };
        let result = poll_once_v2_observed(
            &client,
            &peer,
            &token,
            &config_path,
            &reload_tx,
            &mut last_config_hash,
            stats.as_ref(),
            node_name.as_deref(),
            profiles.as_deref(),
            &candidate_runtime,
            Some(&observe),
        )
        .await;
        let pinned_poll_succeeded = result.is_ok();
        let result = result.and_then(|()| match roster_error {
            Some(error) => Err(error),
            None => Ok(()),
        });
        if pinned_poll_succeeded && !primary_rebind_proof_complete {
            if let Some(credential) = &credential {
                let endpoint = pinned_primary_endpoint(&credential.primary);
                match endpoint {
                    Ok(endpoint) => match node_controller
                        .confirm_primary_endpoint_rebind(endpoint, &credential.fingerprint)
                        .await
                    {
                        Ok(recorded) => {
                            primary_rebind_proof_complete = true;
                            if recorded {
                                tracing::info!(%endpoint, "new primary transport proved by pinned heartbeat");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "primary transport proof remains pending");
                        }
                    },
                    Err(error) => {
                        tracing::warn!(%error, "saved primary transport cannot be proved");
                    }
                }
            }
        }
        if pinned_poll_succeeded && !management_ready && Instant::now() >= management_retry_at {
            if let Some(credential) = &credential {
                match negotiate_management_capability(
                    &client,
                    &peer,
                    &token,
                    credential,
                    &node_controller,
                )
                .await
                {
                    Ok(ManagementNegotiation::Ready | ManagementNegotiation::NotNeeded) => {
                        management_ready = true;
                    }
                    Ok(ManagementNegotiation::UpgradeRequired) => {
                        management_retry_at = Instant::now() + MANAGEMENT_UPGRADE_RETRY;
                        tracing::warn!(
                            peer_node_id = %credential.primary_node_id,
                            "primary requires an explicit Nodes management capability upgrade"
                        );
                    }
                    Err(error) => {
                        management_retry_at = Instant::now() + interval;
                        tracing::warn!(%error, "Nodes management capability negotiation failed");
                    }
                }
            }
        }
        let (last_poll_ok, last_error) = match &result {
            Ok(()) => {
                last_sync = Some(Instant::now());
                synced_once = true;
                (true, None)
            }
            Err(e) => {
                // A closed reload channel means the daemon is shutting down —
                // stop cleanly rather than spin logging.
                if reload_tx.is_closed() {
                    tracing::info!("cluster secondary: reload channel closed; poll loop exiting");
                    return;
                }
                tracing::warn!(error = %e, "cluster secondary: poll failed; keeping last-good, retrying next tick");
                (false, Some(e.to_string()))
            }
        };

        // Write-through the lifted poll state for the IPC `ClusterStatus`
        // reader. The convergence locals above are unchanged — this only
        // mirrors them out for observation.
        observe.store_sync(SyncStatus {
            last_config_hash: last_config_hash.clone(),
            last_sync,
            last_poll_ok,
            last_error,
            synced_at_least_once: synced_once,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagementNegotiation {
    NotNeeded,
    Ready,
    UpgradeRequired,
}

async fn negotiate_management_capability(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    credential: &super::pairing::SecondaryCredential,
    controller: &super::node_control::NodeController,
) -> anyhow::Result<ManagementNegotiation> {
    let Some(offer) = controller.management_offer().await? else {
        return Ok(ManagementNegotiation::NotNeeded);
    };
    let exchange = async {
        let response = client
            .post(format!(
                "{}/api/cluster/v2/management-capability",
                peer.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .json(&super::dto::ManagementCapabilityRequest { offer })
            .send()
            .await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND
                | reqwest::StatusCode::METHOD_NOT_ALLOWED
                | reqwest::StatusCode::UPGRADE_REQUIRED
        ) {
            return Ok(None);
        }
        anyhow::ensure!(
            response.status().is_success(),
            "Nodes management capability HTTP {}",
            response.status()
        );
        let response = serde_json::from_slice(
            &read_body_capped(response, 16 * 1024, "management capability").await?,
        )?;
        Ok::<Option<super::dto::ManagementCapabilityResponse>, anyhow::Error>(Some(response))
    };
    let response = tokio::time::timeout(MANAGEMENT_NEGOTIATION_TIMEOUT, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("Nodes management capability request timed out"))??;
    let Some(response) = response else {
        controller
            .note_management_upgrade_required(&credential.primary_node_id)
            .await?;
        return Ok(ManagementNegotiation::UpgradeRequired);
    };
    let Some(grant) = response.grant else {
        controller
            .note_management_upgrade_required(&credential.primary_node_id)
            .await?;
        return Ok(ManagementNegotiation::UpgradeRequired);
    };
    anyhow::ensure!(
        grant.node_id == credential.primary_node_id,
        "management grant identity differs from authenticated primary"
    );
    let approved_ip = pinned_primary_endpoint(peer)?.ip();
    anyhow::ensure!(
        canonical_ip(grant.endpoint.ip()) == canonical_ip(approved_ip),
        "management grant endpoint differs from authenticated primary"
    );
    controller.accept_management_grant(grant).await?;
    Ok(ManagementNegotiation::Ready)
}

fn pinned_primary_endpoint(peer: &str) -> anyhow::Result<std::net::SocketAddr> {
    let url = reqwest::Url::parse(peer)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && matches!(url.path(), "" | "/"),
        "authenticated primary address is not a plain HTTPS origin"
    );
    let ip = url
        .host_str()
        .and_then(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .context("authenticated primary address is not a literal IP")?;
    let port = url
        .port_or_known_default()
        .context("authenticated primary port is absent")?;
    Ok(std::net::SocketAddr::new(ip, port))
}

fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
        ip => ip,
    }
}

async fn modern_membership(config_path: &Path) -> bool {
    let path = config_path.to_owned();
    // An unreadable modern configuration must not unlock origin transport.
    tokio::task::spawn_blocking(move || {
        crate::config::loader::load_config_v5(&path, time::OffsetDateTime::now_utc())
            .map(|loaded| loaded.config.cluster.membership_version == Some(1))
            .unwrap_or(true)
    })
    .await
    .unwrap_or(true)
}

/// Complete node parser-input acquisition before the daemon's list readiness wait.
/// A failed primary connection may reuse only a complete previously owned pair.
pub(crate) async fn bootstrap(
    config_path: &Path,
    candidate_runtime: Arc<crate::operator_rules::PolicyCandidateRuntime>,
) -> anyhow::Result<super::corpus::CorpusManifest> {
    let attempt = async {
        let path = config_path.to_owned();
        let credential =
            tokio::task::spawn_blocking(move || super::pairing::load_secondary_credential(&path))
                .await??;
        let client = super::pairing::secondary_client(&credential)?;
        super::pairing::activate(&credential).await?;
        if let Err(error) = super::pairing::refresh_roster(&credential, config_path).await {
            tracing::warn!(%error, "node roster refresh failed during bootstrap");
        }
        let (tx, _rx) = mpsc::channel(2);
        let mut last_hash = None;
        poll_once_v2_observed(
            &client,
            credential.primary.trim_end_matches('/'),
            &credential.credential.0,
            config_path,
            &tx,
            &mut last_hash,
            None,
            None,
            None,
            &candidate_runtime,
            None,
        )
        .await
    }
    .await;
    let path = config_path.to_owned();
    let local = tokio::task::spawn_blocking(move || {
        let ledger = super::apply::load_persisted(&path)?
            .ok_or_else(|| anyhow::anyhow!("CorpusBootstrapPending: no persisted policy"))?;
        let store = super::corpus::CorpusStore::open(&path)?;
        let manifest =
            store.recover_committed_pair(&super::dto::ArtifactIdentity::from(&ledger.manifest))?;
        Ok::<_, anyhow::Error>(manifest)
    })
    .await?;
    match local {
        Ok(manifest) => Ok(manifest),
        Err(local_error) => match attempt {
            Err(network_error) => Err(local_error.context(format!(
                "primary corpus acquisition failed: {network_error}"
            ))),
            Ok(()) => Err(local_error),
        },
    }
}

pub(crate) async fn fetch_corpus(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    config_path: &Path,
    identity: &super::dto::ArtifactIdentity,
    expected_generation: &str,
) -> anyhow::Result<super::corpus::CorpusManifest> {
    tokio::time::timeout(
        Duration::from_secs(30 * 60),
        fetch_corpus_inner(
            client,
            peer,
            token,
            config_path,
            identity,
            expected_generation,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("CorpusTransferDeadlineExceeded"))?
}

async fn fetch_corpus_inner(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    config_path: &Path,
    identity: &super::dto::ArtifactIdentity,
    expected_generation: &str,
) -> anyhow::Result<super::corpus::CorpusManifest> {
    let response = client
        .get(format!("{peer}/api/cluster/v2/corpus/manifest"))
        .query(&[("artifact", &identity.artifact_hash)])
        .bearer_auth(token)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "corpus manifest HTTP {}",
        response.status()
    );
    let manifest: super::corpus::CorpusManifest = serde_json::from_slice(
        &read_body_capped(
            response,
            super::corpus::MAX_MANIFEST_BYTES,
            "corpus manifest",
        )
        .await?,
    )?;
    manifest.validate()?;
    anyhow::ensure!(
        manifest.generation == expected_generation,
        "CorpusGenerationChanged: retry heartbeat"
    );
    anyhow::ensure!(
        &manifest.artifact == identity,
        "CorpusArtifactIdentityMismatch"
    );
    let store = Arc::new(super::corpus::CorpusStore::open(config_path)?);
    let _transfer_lease = store.record_desired(&manifest)?;
    let mut objects = std::collections::BTreeMap::new();
    for object in manifest.objects() {
        if let Some(previous) = objects.insert(object.sha256.clone(), object.clone()) {
            anyhow::ensure!(previous == *object, "CorpusConflictingObjectSize");
        }
    }
    for object in objects.into_values() {
        let owned_store = Arc::clone(&store);
        let checked = object.clone();
        if tokio::task::spawn_blocking(move || owned_store.has_object(&checked)).await? {
            continue;
        }
        let owned_store = Arc::clone(&store);
        let expected = object.clone();
        let mut stage = tokio::task::spawn_blocking(move || owned_store.stage(&expected)).await??;
        let mut response = client
            .get(format!(
                "{peer}/api/cluster/v2/corpus/objects/{}",
                object.sha256
            ))
            .bearer_auth(token)
            .timeout(Duration::from_secs(300))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "corpus object HTTP {}",
            response.status()
        );
        if let Some(length) = response.content_length() {
            anyhow::ensure!(length == object.bytes, "CorpusObjectLengthMismatch");
        }
        while let Some(chunk) = response.chunk().await? {
            stage = tokio::task::spawn_blocking(move || {
                stage.write_chunk(&chunk)?;
                Ok::<_, anyhow::Error>(stage)
            })
            .await??;
        }
        let owned_store = Arc::clone(&store);
        tokio::task::spawn_blocking(move || stage.finish(&owned_store)).await??;
    }
    let persisted = manifest.clone();
    tokio::task::spawn_blocking(move || store.prepare_manifest(&persisted)).await??;
    Ok(manifest)
}

#[cfg(test)]
#[path = "poll_v2_tests.rs"]
mod v2_tests;

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn poll_once_v2(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    config_path: &Path,
    reload_tx: &mpsc::Sender<Option<u32>>,
    last_config_hash: &mut Option<String>,
    stats: Option<&Arc<StatsEngine>>,
    node_name: Option<&str>,
    profiles: Option<&crate::profiles::ProfileResolver>,
    candidate_runtime: &Arc<crate::operator_rules::PolicyCandidateRuntime>,
) -> anyhow::Result<()> {
    poll_once_v2_observed(
        client,
        peer,
        token,
        config_path,
        reload_tx,
        last_config_hash,
        stats,
        node_name,
        profiles,
        candidate_runtime,
        None,
    )
    .await
}

fn corpus_ack_ready(
    modern: bool,
    observe: Option<&ClusterObserve>,
    identity: Option<&super::dto::ArtifactIdentity>,
    pair: &super::corpus::PairState,
) -> bool {
    if !modern {
        return true;
    }
    match (observe, identity, pair.active.as_deref()) {
        (Some(observe), Some(artifact), Some(generation)) => {
            pair.active == pair.persisted
                && pair.active == pair.desired
                && observe.active_pair_matches(artifact, generation)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_once_v2_observed(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    config_path: &Path,
    reload_tx: &mpsc::Sender<Option<u32>>,
    last_config_hash: &mut Option<String>,
    stats: Option<&Arc<StatsEngine>>,
    node_name: Option<&str>,
    profiles: Option<&crate::profiles::ProfileResolver>,
    candidate_runtime: &Arc<crate::operator_rules::PolicyCandidateRuntime>,
    observe: Option<&ClusterObserve>,
) -> anyhow::Result<()> {
    let active = profiles.map(crate::profiles::ProfileResolver::active_policy_identity);
    let active_for_attestation = active.clone();
    let master = config_path.to_path_buf();
    let (persisted, active_revision_attested) =
        tokio::task::spawn_blocking(move || match active_for_attestation {
            Some(active) => super::apply::load_persisted_with_active(&master, &active),
            None => super::apply::load_persisted(&master).map(|persisted| (persisted, false)),
        })
        .await??;
    let identity = persisted
        .as_ref()
        .map(|ledger| super::dto::ArtifactIdentity::from(&ledger.manifest));
    let modern = modern_membership(config_path).await;
    let pair = if modern {
        super::corpus::CorpusStore::open_existing(config_path)?
            .map(|store| store.pair_state())
            .transpose()?
            .unwrap_or_default()
    } else {
        Default::default()
    };
    let corpus_ack_ready = corpus_ack_ready(modern, observe, identity.as_ref(), &pair);
    let ack = active_artifact_ack(
        persisted.as_ref(),
        active.as_ref(),
        active_revision_attested,
        corpus_ack_ready,
    );
    let request = super::dto::HeartbeatV2Request {
        artifact_format: 2,
        schema_version: crate::config::schema::TARGET_SCHEMA_VERSION_V5,
        operator_rule_grammar: "1".into(),
        compiled_cost_version: crate::filter::operator_rules::CompiledCostV1::VERSION,
        node_name: node_name.map(str::to_owned),
        stats: current_stats(stats),
        persisted: identity.clone(),
        active: ack.clone(),
        persisted_corpus: pair.persisted.clone(),
        active_corpus: ack.as_ref().and(pair.active.clone()),
    };
    let response = client
        .post(format!("{peer}/api/cluster/v2/heartbeat"))
        .bearer_auth(token)
        .json(&request)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "artifact heartbeat HTTP {}",
        response.status()
    );
    let heartbeat: super::dto::HeartbeatV2Response =
        serde_json::from_slice(&read_body_capped(response, 16 * 1024, "heartbeat").await?)?;
    heartbeat.desired.validate()?;
    let corpus = if modern {
        Some(
            fetch_corpus(
                client,
                peer,
                token,
                config_path,
                &heartbeat.desired,
                heartbeat
                    .desired_corpus
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("CorpusPrimaryUnavailable"))?,
            )
            .await?,
        )
    } else {
        None
    };
    if identity.as_ref() != Some(&heartbeat.desired) {
        let manifest_response = client
            .get(format!(
                "{peer}/api/cluster/v2/artifacts/{}/manifest",
                heartbeat.desired.artifact_hash
            ))
            .bearer_auth(token)
            .send()
            .await?;
        anyhow::ensure!(
            manifest_response.status().is_success(),
            "artifact manifest HTTP {}",
            manifest_response.status()
        );
        let delivery: super::dto::ManifestResponse = serde_json::from_slice(
            &read_body_capped(
                manifest_response,
                super::manifest::MAX_MANIFEST_BYTES + 128,
                "manifest",
            )
            .await?,
        )?;
        delivery.manifest.validate()?;
        anyhow::ensure!(
            super::dto::ArtifactIdentity::from(&delivery.manifest) == heartbeat.desired,
            "ArtifactIdentityMismatch: heartbeat and manifest"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        anyhow::ensure!(
            delivery.available_until > now,
            "ArtifactAvailabilityExpired"
        );
        let mut expected = std::collections::BTreeMap::from([(
            delivery.manifest.policy_toml.sha256.clone(),
            delivery.manifest.policy_toml.clone(),
        )]);
        expected.extend(
            delivery
                .manifest
                .packs
                .iter()
                .map(|pack| (pack.sha256.clone(), pack.object())),
        );
        let mut objects = std::collections::BTreeMap::new();
        for (digest, object) in expected {
            let response = client
                .get(format!(
                    "{peer}/api/cluster/v2/artifacts/{}/objects/{digest}",
                    heartbeat.desired.artifact_hash
                ))
                .bearer_auth(token)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "artifact object HTTP {}",
                response.status()
            );
            let bytes =
                read_body_capped(response, usize::try_from(object.bytes)?, "artifact object")
                    .await?;
            object.verify(&bytes, super::manifest::MAX_TOML_BYTES)?;
            objects.insert(digest, Arc::from(bytes));
        }
        super::apply::apply_artifact(
            config_path,
            delivery.manifest,
            objects,
            reload_tx,
            Arc::clone(candidate_runtime),
        )
        .await?;
        anyhow::bail!(
            "ArtifactActivationPending: persisted policy awaits a fresh resolver acknowledgement"
        );
    }
    if let Some(manifest) = &corpus {
        let store = super::corpus::CorpusStore::open(config_path)?;
        if store.pair_state()?.persisted.as_deref() != Some(&manifest.generation) {
            let master = config_path.to_owned();
            let artifact = manifest.artifact.clone();
            tokio::task::spawn_blocking(move || {
                let loaded =
                    crate::config::loader::load_config_v5(&master, time::OffsetDateTime::now_utc())
                        .map_err(|errors| {
                            anyhow::anyhow!("candidate configuration invalid: {errors:?}")
                        })?;
                crate::cli::commands::start::preflight_received_corpus(
                    &master,
                    &loaded.config.validation_projection()?,
                    &artifact,
                )
            })
            .await??;
        }
        let pending = commit_received_corpus(config_path, manifest, reload_tx).await?;
        if pending {
            anyhow::bail!("CorpusActivationPending: persisted parser inputs await policy and corpus activation");
        }
    }
    ensure_active_convergence(
        identity.as_ref(),
        ack.as_ref(),
        &heartbeat.desired,
        heartbeat.active_acknowledged,
        reload_tx,
    )?;
    anyhow::ensure!(
        !modern || heartbeat.corpus_acknowledged,
        "CorpusAcknowledgementPending"
    );
    *last_config_hash = Some(heartbeat.desired.artifact_hash);
    Ok(())
}

fn active_artifact_ack(
    persisted: Option<&super::ledger::OwnershipLedger>,
    active: Option<&crate::operator_rules::activation::ActivePolicyIdentity>,
    active_revision_attested: bool,
    corpus_ack_ready: bool,
) -> Option<super::dto::ActiveArtifactAck> {
    let ledger = persisted?;
    let active = active?;
    (corpus_ack_ready
        && active.is_known()
        && active_revision_attested
        && active.operator_policy_hash == ledger.manifest.operator_policy_hash)
        .then(|| super::dto::ActiveArtifactAck {
            artifact: super::dto::ArtifactIdentity::from(&ledger.manifest),
            local_config_revision: active.config_revision.clone(),
            daemon_instance_id: active.daemon_instance_id.clone(),
            resolver_generation: active.resolver_generation,
        })
}

async fn commit_received_corpus(
    config_path: &Path,
    manifest: &super::corpus::CorpusManifest,
    reload_tx: &mpsc::Sender<Option<u32>>,
) -> anyhow::Result<bool> {
    let master = config_path.to_owned();
    let selected = manifest.clone();
    let reload = reload_tx.clone();
    tokio::task::spawn_blocking(move || {
            let guard = crate::config::write_lock::acquire_for_migration(&master)?;
            let loaded = crate::config::loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
                &guard,
                guard.canonical_master(),
                time::OffsetDateTime::now_utc(),
                None,
                None,
            ).map_err(|error| anyhow::anyhow!("node configuration invalid: {error:?}"))?;
            anyhow::ensure!(
                loaded.config.cluster.enabled
                    && loaded.config.cluster.membership_version == Some(1)
                    && loaded.config.cluster.role == crate::config::schema::ClusterRole::Secondary,
                "CorpusMembershipChanged"
            );
            let ownership = super::ledger::OwnershipStore::open(&guard)?;
            let ledger = ownership
                .current()
                .ok_or_else(|| anyhow::anyhow!("CorpusPolicyOwnershipMissing"))?;
            anyhow::ensure!(
                super::dto::ArtifactIdentity::from(&ledger.manifest) == selected.artifact
                    && ownership.pending().is_none(),
                "CorpusPolicyChangedDuringPreparation"
            );
            let store = super::corpus::CorpusStore::open(&master)?;
            store.install_manifest(&selected)?;
            let pending = store.pair_state()?.active.as_deref() != Some(&selected.generation);
            if pending {
                match reload.try_send(None) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        anyhow::bail!("reload channel closed")
                    }
                }
            }
            Ok::<_, anyhow::Error>(pending)
        })
    .await?
}

/// Ask the normal reload path to activate an already-persisted artifact.
///
/// A reload request is deliberately best-effort: a full one-slot channel
/// already contains the same activation work, so another request would only
/// amplify pressure. The next poll retries after a rejected or completed
/// reload until both the local resolver and the primary acknowledge the exact
/// artifact identity.
fn ensure_active_convergence(
    persisted: Option<&super::dto::ArtifactIdentity>,
    active: Option<&super::dto::ActiveArtifactAck>,
    desired: &super::dto::ArtifactIdentity,
    active_acknowledged: bool,
    reload_tx: &mpsc::Sender<Option<u32>>,
) -> anyhow::Result<()> {
    let acknowledged = active.is_some_and(|ack| {
        ack.artifact == *desired && super::acknowledgement::valid_active_ack(ack)
    }) && active_acknowledged;
    if acknowledged {
        return Ok(());
    }

    // This is only reachable after the fetch/apply branch, so a matching
    // persisted identity means all durable artifact bytes are already owned.
    // Never reapply them just to recover a failed activation.
    if persisted == Some(desired) {
        match reload_tx.try_send(None) {
            Ok(()) => tracing::debug!(
                artifact = %desired.artifact_hash,
                "cluster secondary: requested activation retry for persisted artifact"
            ),
            Err(mpsc::error::TrySendError::Full(_)) => tracing::debug!(
                artifact = %desired.artifact_hash,
                "cluster secondary: activation retry already queued"
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("reload channel closed; daemon shutting down?")
            }
        }
    }
    anyhow::bail!("ArtifactActivationPending: active policy is not freshly acknowledged")
}

/// Read `cluster.peer_cert` from the node's **merged** configuration.
///
/// Read here rather than threaded in from the daemon's already-loaded config
/// because [`run`]'s caller is outside this lane's ownership; the cost is one
/// extra load at loop start, which happens once per boot.
///
/// **Through the loader, not off the master.** An earlier version parsed the
/// master's raw TOML on the reasoning that `[cluster]` is node-local and never
/// replicated, so the master must be authoritative. That conflates two
/// different things: the section is never *replicated* to a secondary, not
/// that it always *lives in the master*. `cluster` is a known singleton top-level key
/// (`config::loader`), so an operator may legitimately put `[cluster]` in an
/// `includes` drop-in — and the raw read would then return `None` on a node
/// that is correctly configured, refusing to poll. The merged view is also
/// where `peer`, `token` and `node_name` come from, so this keeps every field
/// of the node's cluster identity reading from one source.
///
/// Every failure returns `None`, which
/// [`super::pinned::build_pinned_client`] turns into the operator-facing
/// refusal. That keeps one diagnostic for "no usable pin" instead of several
/// that differ by whether the file was missing, unparseable, or simply unset.
fn peer_cert_from_config(config_path: &Path) -> Option<String> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = crate::config::loader::load_config_v5(config_path, now).ok()?;
    loaded
        .config
        .cluster
        .peer_cert
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Buffer an HTTP response body with a hard ceiling. reqwest applies
/// no default size limit, so a malicious/compromised/MITM'd primary could stream
/// an unbounded (chunked, no `Content-Length`) body and exhaust memory before the
/// payload is even decoded. We accumulate `chunk()`s and abort the instant the
/// running total would exceed `max` — the `Content-Length` is attacker-controlled,
/// so only the streamed total is trustworthy.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
    what: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if chunk.len() > max.saturating_sub(buf.len()) {
            anyhow::bail!("{what} response exceeds the {max}-byte cap; aborting (possible resource-exhaustion)");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Snapshot this node's global counters for the heartbeat (mirrors the
/// primary's `routes::current_stats`).
fn current_stats(stats: Option<&Arc<StatsEngine>>) -> ClusterStats {
    match stats {
        Some(e) => ClusterStats {
            total_queries: e.global.total_queries.load(Ordering::Relaxed),
            total_blocked: e.global.total_blocked.load(Ordering::Relaxed),
            cache_hits: e.global.total_cache_hits.load(Ordering::Relaxed),
        },
        None => ClusterStats::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal config the loader actually accepts. `peer_cert_from_config`
    /// goes through the real loader, so the fixture must be loadable — a bare
    /// `[cluster]` table is not.
    const LOADABLE: &str = r#"schema_version = 5

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    fn write_config(extra: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{LOADABLE}{extra}")).expect("write config");
        (dir, path)
    }

    #[test]
    fn peer_cert_is_read_from_the_config() {
        let (_d, path) =
            write_config("\n[cluster]\npeer_cert = \"/etc/purge-warden/primary-cert.pem\"\n");
        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/purge-warden/primary-cert.pem")
        );
    }

    /// The regression that the raw-master read had.
    ///
    /// `cluster` is a known singleton top-level key, so an operator may put
    /// `[cluster]` in an `includes` drop-in. Reading the master's own TOML
    /// returns `None` there and the poll loop refuses on a node that is
    /// correctly configured. The section is never REPLICATED to a secondary —
    /// that does not mean it always lives in the master.
    #[test]
    fn peer_cert_is_found_when_the_cluster_section_lives_in_an_include() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        // `includes` must precede every section header — appended after
        // `[upstream]` it parses as `upstream.includes` and the drop-in is
        // never read. That mistake made this test fail against a correct
        // implementation the first time.
        std::fs::write(&path, format!("includes = [\"conf.d/*.toml\"]\n{LOADABLE}"))
            .expect("write master");
        let confd = dir.path().join("conf.d");
        std::fs::create_dir_all(&confd).expect("mkdir");
        std::fs::write(
            confd.join("cluster.toml"),
            "[cluster]\npeer_cert = \"/etc/purge-warden/primary-cert.pem\"\n",
        )
        .expect("write drop-in");

        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/purge-warden/primary-cert.pem"),
            "a [cluster] section in an include must be seen; the master is not the only home"
        );
    }

    /// Every "no usable pin" shape collapses to `None` so the poll client
    /// emits ONE refusal. A missing file, a section without the key, and a
    /// blank value are the same operator problem — an unpinned node — and
    /// splitting them would give several diagnostics for one remedy.
    #[test]
    fn every_unusable_shape_reads_as_no_pin() {
        for extra in [
            "",                                   // no [cluster] at all
            "\n[cluster]\nrole = \"primary\"\n",  // section, no key
            "\n[cluster]\npeer_cert = \"\"\n",    // empty
            "\n[cluster]\npeer_cert = \"   \"\n", // whitespace only
        ] {
            let (_d, path) = write_config(extra);
            assert!(
                peer_cert_from_config(&path).is_none(),
                "should read as no pin: {extra:?}"
            );
        }
        assert!(
            peer_cert_from_config(Path::new("/nonexistent/config.toml")).is_none(),
            "a missing config must read as no pin, not panic"
        );
    }

    /// A surrounding-whitespace path is trimmed rather than passed to
    /// `std::fs::read`, which would fail on a path the operator can see is
    /// correct.
    #[test]
    fn a_padded_peer_cert_path_is_trimmed() {
        let (_d, path) = write_config("\n[cluster]\npeer_cert = \"  /etc/primary.pem  \"\n");
        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/primary.pem")
        );
    }
}

#[cfg(test)]
#[path = "corpus_transport_tests.rs"]
mod corpus_transport_tests;
