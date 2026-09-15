//! Bounded pairing transport with exact-leaf authentication and no redirects.

use super::membership::{Invitation, SecretString};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentRequest {
    pub invitation: SecretString,
    pub cluster_id: String,
    pub primary_node_id: String,
    pub node_id: String,
    pub name: String,
    pub credential: SecretString,
}

/// Node-local credential; never projected into status or roster DTOs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecondaryCredential {
    pub cluster_id: String,
    pub node_id: String,
    pub primary_node_id: String,
    pub primary: String,
    pub fingerprint: String,
    pub credential: SecretString,
}

pub(crate) fn load_secondary_credential(master: &Path) -> anyhow::Result<SecondaryCredential> {
    let guard = crate::config::write_lock::acquire_for_migration(master)?;
    let files = super::store::PrivateStore::open(&guard, super::membership::STORE)?;
    let bytes = files
        .read("secondary.json", 8192)?
        .context("node credential absent; explicit association required")?;
    let credential: SecondaryCredential = serde_json::from_slice(&bytes)?;
    let loaded =
        crate::config::loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
            &guard,
            guard.canonical_master(),
            time::OffsetDateTime::now_utc(),
            None,
            None,
        )
        .map_err(|_| anyhow::anyhow!("secondary configuration unavailable"))?;
    let config = &loaded.config;
    ensure!(
        config.cluster.enabled
            && config.cluster.role == crate::config::schema::ClusterRole::Secondary
            && config.cluster.membership_version == Some(1)
            && config.node.id.as_deref() == Some(&credential.node_id)
            && config.cluster.cluster_id.as_deref() == Some(&credential.cluster_id)
            && config.cluster.primary_node_id.as_deref() == Some(&credential.primary_node_id)
            && config.cluster.primary_cert_fingerprint.as_deref() == Some(&credential.fingerprint)
            && config.cluster.peer.as_deref() == Some(&credential.primary),
        "secondary credential does not match saved membership"
    );
    Ok(credential)
}

pub(crate) fn secondary_client(
    credential: &SecondaryCredential,
) -> anyhow::Result<reqwest::Client> {
    super::pinned::build_fingerprint_client(
        &credential.primary,
        &credential.fingerprint,
        Duration::from_secs(30),
    )
}

pub(crate) async fn enroll(
    primary: &str,
    invitation: &Invitation,
    credential: &SecondaryCredential,
    name: &str,
) -> anyhow::Result<()> {
    let client = secondary_client(credential)?;
    let response = client
        .post(format!(
            "{}/api/cluster/v2/enroll",
            primary.trim_end_matches('/')
        ))
        .json(&EnrollmentRequest {
            invitation: invitation.secret.clone(),
            cluster_id: invitation.cluster_id.clone(),
            primary_node_id: invitation.primary_node_id.clone(),
            node_id: credential.node_id.clone(),
            name: name.into(),
            credential: credential.credential.clone(),
        })
        .send()
        .await
        .context("primary TLS connection or enrollment failed")?;
    ensure!(
        response.status().is_success(),
        "primary refused enrollment ({})",
        response.status()
    );
    Ok(())
}

pub(crate) async fn activate(credential: &SecondaryCredential) -> anyhow::Result<()> {
    let response = secondary_client(credential)?
        .post(format!(
            "{}/api/cluster/v2/activate",
            credential.primary.trim_end_matches('/')
        ))
        .bearer_auth(&credential.credential.0)
        .send()
        .await
        .context("primary activation connection failed")?;
    ensure!(
        response.status().is_success(),
        "primary refused activation ({})",
        response.status()
    );
    Ok(())
}

pub(crate) async fn cancel(credential: &SecondaryCredential) -> anyhow::Result<()> {
    let response = secondary_client(credential)?
        .post(format!(
            "{}/api/cluster/v2/cancel",
            credential.primary.trim_end_matches('/')
        ))
        .bearer_auth(&credential.credential.0)
        .send()
        .await
        .context("primary cancellation connection failed")?;
    ensure!(
        response.status().is_success(),
        "primary refused cancellation ({})",
        response.status()
    );
    Ok(())
}

pub(crate) async fn fetch_policy(
    credential: &SecondaryCredential,
) -> anyhow::Result<(super::manifest::Manifest, BTreeMap<String, Arc<[u8]>>)> {
    let client = secondary_client(credential)?;
    let origin = credential.primary.trim_end_matches('/');
    let status = client
        .get(format!("{origin}/api/cluster/v2/status"))
        .bearer_auth(&credential.credential.0)
        .send()
        .await?;
    let bytes = bounded(status, 256 * 1024).await?;
    #[derive(Deserialize)]
    struct Status {
        desired: Option<super::dto::ArtifactIdentity>,
    }
    let status: Status = serde_json::from_slice(&bytes)?;
    let identity = status.desired.context("primary has no published policy")?;
    let base = format!(
        "{origin}/api/cluster/v2/artifacts/{}",
        identity.artifact_hash
    );
    let bytes = bounded(
        client
            .get(format!("{base}/manifest"))
            .bearer_auth(&credential.credential.0)
            .send()
            .await?,
        (super::manifest::MAX_MANIFEST_BYTES + 128) as u64,
    )
    .await?;
    let delivery: super::dto::ManifestResponse = serde_json::from_slice(&bytes)?;
    ensure!(
        delivery.available_until > super::membership::now()?,
        "primary artifact availability expired"
    );
    let manifest = delivery.manifest;
    manifest.validate()?;
    ensure!(
        super::dto::ArtifactIdentity::from(&manifest) == identity,
        "primary policy changed during preview"
    );
    let mut objects = BTreeMap::new();
    let mut total = 0u64;
    for object in std::iter::once(manifest.policy_toml.clone())
        .chain(manifest.packs.iter().map(|pack| pack.object()))
    {
        if objects.contains_key(&object.sha256) {
            continue;
        }
        total = total
            .checked_add(object.bytes)
            .context("policy size overflow")?;
        ensure!(
            total <= super::manifest::MAX_APPLY_BYTES as u64,
            "policy exceeds join limit"
        );
        let bytes = bounded(
            client
                .get(format!("{base}/objects/{}", object.sha256))
                .bearer_auth(&credential.credential.0)
                .send()
                .await?,
            object.bytes,
        )
        .await?;
        ensure!(
            super::manifest::ObjectRef::of(&bytes) == object,
            "policy object digest mismatch"
        );
        objects.insert(object.sha256.clone(), Arc::from(bytes));
    }
    super::artifact::verify_objects(&manifest, &objects)?;
    Ok((manifest, objects))
}

async fn bounded(mut response: reqwest::Response, limit: u64) -> anyhow::Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "primary refused request ({})",
        response.status()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= limit),
        "primary response exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            (bytes.len() as u64).saturating_add(chunk.len() as u64) <= limit,
            "primary response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) async fn fetch_join_corpus(
    master: &Path,
    credential: &SecondaryCredential,
    identity: &super::dto::ArtifactIdentity,
) -> anyhow::Result<super::corpus::CorpusManifest> {
    #[derive(Deserialize)]
    struct Status {
        desired: Option<super::dto::ArtifactIdentity>,
        desired_corpus: Option<String>,
    }
    let client = secondary_client(credential)?;
    let peer = credential.primary.trim_end_matches('/');
    let response = client
        .get(format!("{peer}/api/cluster/v2/status"))
        .bearer_auth(&credential.credential.0)
        .send()
        .await?;
    let status: Status = serde_json::from_slice(&bounded(response, 256 * 1024).await?)?;
    ensure!(
        status.desired.as_ref() == Some(identity),
        "primary policy changed during preview"
    );
    let generation = status
        .desired_corpus
        .context("primary corpus not yet published")?;
    super::poll::fetch_corpus(
        &client,
        peer,
        &credential.credential.0,
        master,
        identity,
        &generation,
    )
    .await
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CachedRoster {
    pub cluster_id: String,
    pub primary_node_id: String,
    pub primary_name: String,
    pub observed_at: u64,
    pub peers: Vec<super::membership::MemberView>,
}

pub(crate) async fn refresh_roster(
    credential: &SecondaryCredential,
    master: &Path,
) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct Status {
        cluster_id: String,
        primary_node_id: String,
        primary_name: String,
        peers: Vec<super::membership::MemberView>,
    }
    let response = secondary_client(credential)?
        .get(format!(
            "{}/api/cluster/v2/status",
            credential.primary.trim_end_matches('/')
        ))
        .bearer_auth(&credential.credential.0)
        .send()
        .await?;
    let status: Status = serde_json::from_slice(&bounded(response, 128 * 1024).await?)?;
    ensure!(
        status.cluster_id == credential.cluster_id
            && status.primary_node_id == credential.primary_node_id
            && status.peers.len() <= 64,
        "roster identity mismatch"
    );
    super::membership::validate_name(&status.primary_name)?;
    let mut ids = std::collections::BTreeSet::new();
    for peer in &status.peers {
        ensure!(
            super::membership::valid_id(&peer.node_id) && ids.insert(peer.node_id.clone()),
            "invalid roster identity"
        );
        super::membership::validate_name(&peer.name)?;
        ensure!(
            peer.endpoint
                .as_ref()
                .is_none_or(|s| s.len() <= 256 && !s.chars().any(char::is_control))
                && peer
                    .sync
                    .as_deref()
                    .is_none_or(|s| matches!(s, "current" | "stale" | "pending" | "revoked"))
                && peer
                    .fingerprint
                    .as_deref()
                    .is_none_or(super::manifest::is_hash),
            "invalid roster metadata"
        );
    }
    let roster = CachedRoster {
        cluster_id: status.cluster_id,
        primary_node_id: status.primary_node_id,
        primary_name: status.primary_name,
        observed_at: super::membership::now()?,
        peers: status.peers,
    };
    let path = master.to_owned();
    tokio::task::spawn_blocking(move || {
        let guard = crate::config::write_lock::acquire_for_migration(&path)?;
        let files = super::store::PrivateStore::open(&guard, super::membership::STORE)?;
        let current: SecondaryCredential = serde_json::from_slice(
            &files
                .read("secondary.json", 8192)?
                .context("association ended while roster was fetched")?,
        )?;
        ensure!(
            current.cluster_id == roster.cluster_id
                && current.primary_node_id == roster.primary_node_id,
            "association changed while roster was fetched"
        );
        files.write("roster-cache.json", &serde_json::to_vec(&roster)?)
    })
    .await?
}
