//! Durable changes to the pinned primary transport used by a secondary.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::ensure;

use super::lifecycle::LifecyclePreview;

pub(crate) async fn prepare_secondary_primary_rebind(
    master: &Path,
    primary_node_id: &str,
    endpoint: SocketAddr,
    fingerprint: &str,
) -> anyhow::Result<LifecyclePreview> {
    super::lifecycle::preview_nodes_secondary_primary_rebind(
        master,
        primary_node_id.to_owned(),
        endpoint,
        fingerprint.to_owned(),
    )
    .await
}

pub(crate) async fn apply_secondary_primary_rebind(
    master: &Path,
    preview_id: &str,
    primary_node_id: &str,
    endpoint: SocketAddr,
    fingerprint: &str,
) -> anyhow::Result<()> {
    super::lifecycle::apply(master, preview_id).await?;
    ensure!(
        verify_secondary_primary_rebind(master, primary_node_id, endpoint, fingerprint)?,
        "secondary primary transport did not match the committed rebind"
    );
    Ok(())
}

pub(crate) fn verify_secondary_primary_rebind(
    master: &Path,
    primary_node_id: &str,
    endpoint: SocketAddr,
    fingerprint: &str,
) -> anyhow::Result<bool> {
    let credential = super::pairing::load_secondary_credential(master)?;
    Ok(credential.primary_node_id == primary_node_id
        && credential.primary == format!("https://{endpoint}")
        && credential.fingerprint == fingerprint)
}
