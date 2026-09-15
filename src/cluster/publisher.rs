//! Publication intent is durable before its policy transaction can promote files.

use anyhow::{ensure, Context};

use super::artifact::PolicySnapshot;
use super::publication::PublicationStore;
use super::publication_proof::{self, PreparationProof};
use super::transaction::{OperationBinding, PublicationIntent};
use crate::config::policy_revision::PolicyRevisionInventory;
use crate::config::policy_transaction::{
    self, BaseReceipt, Persistence, ReceiptStore, TransactionRequest,
};
use crate::config::write_lock::MigrationWriteLock;

#[cfg(test)]
#[path = "publisher_recovery_tests.rs"]
mod recovery_tests;

pub(crate) fn recover(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    store: &mut PublicationStore<'_>,
) -> anyhow::Result<()> {
    for (reservation, envelope) in store.pending_intents()? {
        let binding: OperationBinding = serde_json::from_value(envelope.clone())?;
        binding.validate()?;
        let Some(receipt) = policy_transaction::lookup_receipt(
            guard,
            receipts,
            &binding.actor,
            &binding.request_id,
        )?
        else {
            let proof = store.preparation_proof(&reservation)?.context(
                "ArtifactPublicationProofMissing: cannot retire an intent without a receipt or captured before state",
            )?;
            publication_proof::verify_unchanged(guard, &reservation, &envelope, &proof)?;
            store.abort(&reservation)?;
            continue;
        };
        binding.verify_receipt(&receipt, &envelope)?;
        if let Some(proof) = store.preparation_proof(&reservation)? {
            publication_proof::verify_receipt(&reservation, &envelope, &proof, &receipt)?;
        }
        match receipt.persistence {
            Persistence::Committed if receipt.rollback_restored => store.abort(&reservation)?,
            Persistence::Committed => PublicationIntent {
                reservation,
                binding,
            }
            .commit(store, &receipt, &envelope)?,
            Persistence::Aborted => store.abort(&reservation)?,
            Persistence::Prepared | Persistence::DurabilityUncertain => {}
        }
    }
    Ok(())
}

#[allow(dead_code, reason = "precommit publication coordinator entry point")]
pub(crate) fn reserve(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    snapshot: &PolicySnapshot,
    request: &TransactionRequest,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
) -> anyhow::Result<PublicationIntent> {
    let mut store = PublicationStore::open(guard)?;
    recover(guard, receipts, &mut store)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    store.gc(now)?;
    ensure!(
        !store.pending_intents()?.iter().any(|(_, value)| {
            value.get("actor").and_then(serde_json::Value::as_str) == Some(&request.actor)
                && value.get("request_id").and_then(serde_json::Value::as_str)
                    == Some(&request.request_id)
        }),
        "ArtifactPublicationPending: request already has a reserved epoch"
    );
    ensure!(
        after.revision().to_string() == snapshot.config_revision(),
        "ArtifactPublicationProofConflict: snapshot is not the complete transaction candidate"
    );
    let proof = PreparationProof::capture(guard, request, before, after)?;
    let mut binding = None;
    let reservation = store.reserve_bound(|lineage, epoch| {
        let candidate = snapshot.publication(lineage, epoch)?;
        let manifest = super::manifest::Manifest::decode(&candidate.manifest)?;
        let value = OperationBinding::for_publication(&manifest, request)?;
        let envelope = value.operation_manifest()?;
        let proof = proof.bind(&envelope)?;
        binding = Some(value);
        Ok((candidate, envelope, proof))
    })?;
    Ok(PublicationIntent {
        reservation,
        binding: binding.context("publication binding missing")?,
    })
}

#[allow(dead_code, reason = "publication finalization coordinator entry point")]
pub(crate) fn finalize(
    guard: &MigrationWriteLock,
    intent: &PublicationIntent,
    receipt: &BaseReceipt,
) -> anyhow::Result<()> {
    let mut store = PublicationStore::open(guard)?;
    let envelope = store
        .bound_intent(&intent.reservation)?
        .context("ArtifactPublicationPending: durable operation intent missing")?;
    if let Some(proof) = store.preparation_proof(&intent.reservation)? {
        publication_proof::verify_receipt(&intent.reservation, &envelope, &proof, receipt)?;
    }
    intent.commit(&mut store, receipt, &envelope)
}
