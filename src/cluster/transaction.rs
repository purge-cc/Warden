//! Typed transaction evidence binds artifact ownership to recorded member identities.
//!
//! Aggregate receipts cannot establish inode ownership. Evidence comes from a
//! verified accessor; callers must never parse the private journal themselves.

use std::collections::BTreeMap;

use anyhow::Context;
use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use super::artifact::PolicySnapshot;
use super::manifest::{digest, is_hash, Manifest, ObjectRef, MAX_MANIFEST_BYTES};
use super::publication::{PublicationStore, Reservation};
use crate::config::policy_revision::PolicyRevisionInventory;
use crate::config::policy_transaction::{
    self, BaseReceipt, MemberOperation, MemberRole, Persistence, ReceiptStore, RevisionScope,
    TransactionRequest,
};
use crate::config::write_lock::MigrationWriteLock;

pub(crate) const BUNDLE_PATH: &str = "cluster.d/00-cluster-policy.toml";
const APPLY_OPERATION: &str = "cluster.artifact.apply";
const PUBLISH_OPERATION: &str = "cluster.artifact.publish";
const OPERATOR_OPERATION: &str = "operator_rules.batch.v1";

/// File identity bound to a before inventory or verified transaction evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberIdentity {
    pub sha256: String,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
}

/// Before identity exposed by the verified receipt accessor and checked against
/// the complete identity already recorded by the ownership baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberBeforeState {
    pub sha256: String,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
}

impl From<&MemberIdentity> for MemberBeforeState {
    fn from(identity: &MemberIdentity) -> Self {
        Self {
            sha256: identity.sha256.clone(),
            bytes: identity.bytes,
            uid: identity.uid,
            gid: identity.gid,
            mode: identity.mode,
            device: identity.device,
            inode: identity.inode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberEvidence {
    pub path: String,
    pub role: MemberRole,
    pub operation: Option<MemberOperation>,
    pub before: Option<MemberBeforeState>,
    pub after: Option<MemberIdentity>,
    pub restored: Option<MemberIdentity>,
}

/// Trusted internal DTO. It is never deserialized from a peer or request body.
#[derive(Debug, Clone)]
pub(crate) struct OperationEvidence {
    pub receipt: BaseReceipt,
    pub operation_manifest: Value,
    pub members: Vec<MemberEvidence>,
}

/// Resolvers recover the journal before returning recorded members or `None`.
/// An unresolved transaction is an error, never a receipt-cache miss.
/// Resolve the aggregate receipt by actor/request ID, then member evidence by
/// actor/transaction ID, checking that the returned receipt and envelope match.
pub(crate) trait EvidenceResolver {
    fn lookup(
        &self,
        guard: &MigrationWriteLock,
        receipts: &ReceiptStore,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<Option<OperationEvidence>>;

    fn supports_member_evidence(&self) -> bool {
        true
    }
}

/// Resolve retained journal evidence without recapturing live paths.
pub(crate) struct ExistingReceiptAdapter;

impl EvidenceResolver for ExistingReceiptAdapter {
    fn lookup(
        &self,
        guard: &MigrationWriteLock,
        receipts: &ReceiptStore,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<Option<OperationEvidence>> {
        let Some(receipt) = policy_transaction::lookup_receipt(guard, receipts, actor, request_id)?
        else {
            return Ok(None);
        };
        let (recorded, members) = policy_transaction::lookup_operation_member_evidence(
            guard,
            receipts,
            actor,
            &receipt.transaction_id,
        )?
        .context("TransactionMemberEvidenceUnavailable: retained evidence missing")?;
        ensure!(
            recorded == receipt,
            "ArtifactIntentMismatch: evidence receipt differs"
        );
        let envelope = receipt
            .operation_manifest
            .clone()
            .context("ArtifactIntentMismatch: receipt operation manifest missing")?;
        let binding: OperationBinding = serde_json::from_value(envelope.clone())?;
        binding.verify_receipt(&receipt, &envelope)?;
        Ok(Some(OperationEvidence {
            receipt,
            operation_manifest: envelope,
            members: members
                .into_iter()
                .map(member_evidence)
                .collect::<anyhow::Result<_>>()?,
        }))
    }
}

fn member_evidence(
    member: policy_transaction::ReceiptMemberEvidence,
) -> anyhow::Result<MemberEvidence> {
    let before = recorded_identity((
        member.before_digest,
        member.before_length,
        member.before_uid,
        member.before_gid,
        member.before_mode,
        member.before_device,
        member.before_inode,
    ))?;
    let restored = recorded_identity((
        member.restored_digest,
        member.restored_length,
        member.restored_uid,
        member.restored_gid,
        member.restored_mode,
        member.restored_device,
        member.restored_inode,
    ))?;
    let after = match (
        member.operation,
        member.promoted_device,
        member.promoted_inode,
    ) {
        (None, None, None) => {
            let before = before.as_ref().context(
                "TransactionMemberEvidenceUnavailable: unchanged before identity missing",
            )?;
            let after = recorded_identity((
                member.after_digest,
                member.after_length,
                member.after_uid,
                member.after_gid,
                member.after_mode,
                Some(before.device),
                Some(before.inode),
            ))?;
            ensure!(
                after.as_ref() == Some(before) && restored.is_none(),
                "ArtifactIntentMismatch: unchanged member states differ or were restored"
            );
            after
        }
        (None, _, _) => bail!("ArtifactIntentMismatch: unchanged member has a promoted inode"),
        (Some(_), None, None) => None,
        (Some(_), Some(device), Some(inode)) => recorded_identity((
            member.after_digest,
            member.after_length,
            member.after_uid,
            member.after_gid,
            member.after_mode,
            Some(device),
            Some(inode),
        ))?,
        _ => bail!("TransactionMemberEvidenceUnavailable: incomplete promoted inode"),
    };
    Ok(MemberEvidence {
        path: member.path,
        role: member.role,
        operation: member.operation,
        before: before.as_ref().map(MemberBeforeState::from),
        after,
        restored,
    })
}

type RecordedIdentity = (
    Option<String>,
    Option<u64>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u64>,
    Option<u64>,
);

fn recorded_identity(fields: RecordedIdentity) -> anyhow::Result<Option<MemberIdentity>> {
    match fields {
        (None, None, None, None, None, None, None) => Ok(None),
        (
            Some(sha256),
            Some(bytes),
            Some(uid),
            Some(gid),
            Some(mode),
            Some(device),
            Some(inode),
        ) => Ok(Some(MemberIdentity {
            sha256,
            bytes,
            uid,
            gid,
            mode,
            device,
            inode,
        })),
        _ => bail!("TransactionMemberEvidenceUnavailable: incomplete recorded identity"),
    }
}

/// Versioned transaction envelope. The compact request payload binds its complete
/// canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationBinding {
    pub manifest_version: u32,
    pub operation: String,
    pub actor: String,
    pub request_id: String,
    pub request_payload_hash: Option<String>,
    pub primary_lineage: String,
    pub policy_epoch: u64,
    pub artifact_hash: String,
    pub source_config_revision: String,
    pub expected_after_revision: String,
    pub objects: BTreeMap<String, ObjectRef>,
}

impl OperationBinding {
    pub(crate) fn for_publication(
        manifest: &Manifest,
        request: &TransactionRequest,
    ) -> anyhow::Result<Self> {
        let mut binding = Self::new(
            manifest,
            &manifest.config_revision,
            &request.actor,
            &request.request_id,
            &request.operation,
        )?;
        binding.request_payload_hash = Some(digest(&request.payload));
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn for_apply(
        manifest: &Manifest,
        expected_after_revision: &str,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<Self> {
        Self::new(
            manifest,
            expected_after_revision,
            actor,
            request_id,
            APPLY_OPERATION,
        )
    }

    fn new(
        manifest: &Manifest,
        expected_after_revision: &str,
        actor: &str,
        request_id: &str,
        operation: &str,
    ) -> anyhow::Result<Self> {
        manifest.validate()?;
        let binding = Self {
            manifest_version: 1,
            operation: operation.into(),
            actor: actor.into(),
            request_id: request_id.into(),
            request_payload_hash: None,
            primary_lineage: manifest.primary_lineage.clone(),
            policy_epoch: manifest.policy_epoch,
            artifact_hash: manifest.artifact_hash.clone(),
            source_config_revision: manifest.config_revision.clone(),
            expected_after_revision: expected_after_revision.into(),
            objects: expected_objects(manifest),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.manifest_version == 1
                && matches!(
                    self.operation.as_str(),
                    APPLY_OPERATION | PUBLISH_OPERATION | OPERATOR_OPERATION
                ),
            "ArtifactIntentMismatch: manifest version or operation"
        );
        for value in [&self.actor, &self.request_id] {
            ensure!(
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
                "ArtifactIntentMismatch: request identity"
            );
        }
        ensure!(
            self.policy_epoch > 0
                && [
                    &self.primary_lineage,
                    &self.artifact_hash,
                    &self.source_config_revision,
                    &self.expected_after_revision
                ]
                .into_iter()
                .all(|v| is_hash(v)),
            "ArtifactIntentMismatch: artifact identity"
        );
        ensure!(
            self.request_payload_hash.as_deref().is_none_or(is_hash)
                && (self.operation != APPLY_OPERATION || self.request_payload_hash.is_none()),
            "ArtifactIntentMismatch: request payload binding"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_MANIFEST_BYTES,
            "ArtifactLimitExceeded: operation manifest"
        );
        Ok(())
    }

    pub(crate) fn operation_manifest(&self) -> anyhow::Result<Value> {
        self.validate()?;
        Ok(serde_json::to_value(self)?)
    }

    /// Keep the request below its 64 KiB ceiling even for 1,000 owned members.
    pub(crate) fn payload(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(&(
            "warden.cluster.operation/v1",
            digest(&serde_json::to_vec(self)?),
        ))?)
    }

    pub(crate) fn verify_receipt(
        &self,
        receipt: &BaseReceipt,
        envelope: &Value,
    ) -> anyhow::Result<()> {
        ensure!(
            *envelope == self.operation_manifest()?
                && receipt.operation_manifest.as_ref() == Some(envelope),
            "ArtifactIntentMismatch: operation manifest"
        );
        ensure!(
            receipt.revision_scope == RevisionScope::PolicyTreeV1
                && receipt.actor == self.actor
                && receipt.request_id == self.request_id
                && receipt.operation == self.operation
                && receipt.payload_hash
                    == self
                        .request_payload_hash
                        .clone()
                        .unwrap_or(digest(&self.payload()?))
                && receipt.after_revision == self.expected_after_revision
                && !receipt.transaction_id.is_empty(),
            "ArtifactIntentMismatch: transaction receipt"
        );
        Ok(())
    }
}

pub(crate) fn expected_objects(manifest: &Manifest) -> BTreeMap<String, ObjectRef> {
    let mut objects = BTreeMap::from([(BUNDLE_PATH.into(), manifest.policy_toml.clone())]);
    objects.extend(
        manifest
            .packs
            .iter()
            .map(|pack| (format!("packs/{}.txt", pack.id), pack.object())),
    );
    objects
}

/// The durable ownership intent contains the complete envelope before preparation.
/// Its compact payload binds that envelope even for aggregate receipt adapters.
#[cfg(test)]
pub(crate) fn prepare_apply<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    pending: &super::ledger::PendingApply,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<policy_transaction::PrepareOutcome<'g>> {
    prepare_apply_inner(guard, receipts, pending, before, after, None, validate)
}

pub(crate) fn prepare_apply_verified<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    pending: &super::ledger::PendingApply,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    verified_candidate: Option<&crate::operator_rules::VerifiedPolicyCandidate>,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<policy_transaction::PrepareOutcome<'g>> {
    prepare_apply_inner(
        guard,
        receipts,
        pending,
        before,
        after,
        verified_candidate,
        validate,
    )
}

fn prepare_apply_inner<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    pending: &super::ledger::PendingApply,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    verified_candidate: Option<&crate::operator_rules::VerifiedPolicyCandidate>,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<policy_transaction::PrepareOutcome<'g>> {
    ensure!(
        pending.binding.expected_after_revision == after.revision().to_string()
            && pending.before_revision == before.revision().to_string(),
        "ArtifactIntentMismatch: before or candidate revision"
    );
    let request = TransactionRequest {
        request_id: pending.binding.request_id.clone(),
        actor: pending.binding.actor.clone(),
        origin: "cluster".into(),
        operation: pending.binding.operation.clone(),
        payload: pending.payload()?,
        expected_revision: before.revision(),
        source_schema: crate::config::schema::TARGET_SCHEMA_VERSION_V5 as u64,
        target_schema: crate::config::schema::TARGET_SCHEMA_VERSION_V5 as u64,
    };
    policy_transaction::prepare_with_hook(
        guard,
        receipts,
        &request,
        policy_transaction::PolicyRevisionTransition::new(before, after)
            .with_verified_candidate(verified_candidate),
        policy_transaction::ReceiptPreparationContext {
            operator_plan_hash: None,
            semantic: policy_transaction::ReceiptSemanticContext {
                after_policy_hash: Some(pending.manifest.operator_policy_hash.clone()),
                ..Default::default()
            },
            operation_manifest: Some(pending.operation_manifest()?),
        },
        validate,
        |_| {},
    )
}

/// Reserve immutable objects and an epoch before preparing the policy transaction.
/// The returned envelope must be attached before Prepared; it is not a reload hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationIntent {
    pub reservation: Reservation,
    pub binding: OperationBinding,
}

impl PublicationIntent {
    #[cfg(test)]
    pub(crate) fn reserve_for_request(
        store: &mut PublicationStore<'_>,
        snapshot: &PolicySnapshot,
        request: &TransactionRequest,
    ) -> anyhow::Result<Self> {
        let mut binding = None;
        let reservation = store.reserve(|lineage, epoch| {
            let candidate = snapshot.publication(lineage, epoch)?;
            let value = OperationBinding::for_publication(
                &Manifest::decode(&candidate.manifest)?,
                request,
            )?;
            binding = Some(value);
            Ok(candidate)
        })?;
        Ok(Self {
            reservation,
            binding: binding.context("publication binding missing")?,
        })
    }

    /// `envelope` comes from the trusted transaction adapter and is never accepted
    /// from a peer.
    pub(crate) fn commit(
        &self,
        store: &mut PublicationStore<'_>,
        receipt: &BaseReceipt,
        envelope: &Value,
    ) -> anyhow::Result<()> {
        self.binding.verify_receipt(receipt, envelope)?;
        ensure!(
            receipt.persistence == Persistence::Committed && !receipt.rollback_restored,
            "ArtifactPublicationPending: policy transaction has not committed"
        );
        ensure!(
            self.reservation.primary_lineage == self.binding.primary_lineage
                && self.reservation.policy_epoch == self.binding.policy_epoch
                && self.reservation.artifact_hash == self.binding.artifact_hash
                && self.reservation.config_revision == self.binding.expected_after_revision,
            "ArtifactIntentMismatch: publication reservation"
        );
        store.commit(&self.reservation, &receipt.transaction_id)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::config::schema::{ConfigV5, Id};
    use crate::config::target_v5::PackBodiesV5;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::Arc;

    pub(crate) fn artifact(
        epoch: u64,
        packs: &[(&str, &str)],
    ) -> (Manifest, BTreeMap<String, Arc<[u8]>>) {
        let mut text = String::from("schema_version = 5\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n[custom_list_limits]\nmax_lists = 1000\n");
        let mut bodies = BTreeMap::new();
        for (id, body) in packs {
            text.push_str(&format!("\n[[custom_lists]]\nid = \"{id}\"\n"));
            let body = body
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    if line.starts_with("||") || line.starts_with("@@||") || line.starts_with('/') {
                        line.to_owned()
                    } else {
                        format!("||{}^", line.trim())
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            bodies.insert(Id::new(*id).unwrap(), Arc::from(body));
        }
        let config: ConfigV5 = toml::from_str(&text).unwrap();
        let snapshot =
            PolicySnapshot::from_target_v5(&config, &PackBodiesV5::new(bodies), "b".repeat(64))
                .unwrap();
        let candidate = snapshot.publication(&"a".repeat(64), epoch).unwrap();
        (
            Manifest::decode(&candidate.manifest).unwrap(),
            candidate.objects,
        )
    }

    pub(crate) fn receipt(binding: &OperationBinding, persistence: Persistence) -> BaseReceipt {
        serde_json::from_value(serde_json::json!({
            "revision_scope": "policy_tree_v1", "transaction_id": "0123456789abcdef0123456789abcdef",
            "request_id": binding.request_id, "actor": binding.actor, "origin": "cluster",
            "operation": binding.operation,
            "payload_hash": binding.request_payload_hash.clone().unwrap_or(digest(&binding.payload().unwrap())),
            "plan_hash": "b".repeat(64), "before_revision": "c".repeat(64),
            "after_revision": binding.expected_after_revision, "created_unix_seconds": 1,
            "persistence": persistence, "changed_members": binding.objects.len(),
            "rollback_restored": false, "audit_pending": false, "failure": null,
            "operation_manifest": binding.operation_manifest().unwrap()
        })).unwrap()
    }

    /// Capture identities only to construct a test fixture. Runtime resolvers
    /// must obtain these values from verified transaction evidence.
    pub(crate) fn fixture_members(root: &Path, manifest: &Manifest) -> Vec<MemberEvidence> {
        expected_objects(manifest)
            .into_iter()
            .map(|(path, object)| {
                let meta = std::fs::metadata(root.join(&path)).unwrap();
                MemberEvidence {
                    role: if path == BUNDLE_PATH {
                        MemberRole::Include
                    } else {
                        MemberRole::Pack
                    },
                    path,
                    operation: Some(MemberOperation::Create),
                    before: None,
                    after: Some(MemberIdentity {
                        sha256: object.sha256,
                        bytes: object.bytes,
                        uid: meta.uid(),
                        gid: meta.gid(),
                        mode: meta.mode() & 0o7777,
                        device: meta.dev(),
                        inode: meta.ino(),
                    }),
                    restored: None,
                }
            })
            .collect()
    }

    pub(crate) fn install(root: &Path, manifest: &Manifest, objects: &BTreeMap<String, Arc<[u8]>>) {
        for (path, object) in expected_objects(manifest) {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, objects[&object.sha256].as_ref()).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn recorded_identity_requires_every_field_or_none() {
        for mask in 0..128 {
            let present = |bit| mask & (1 << bit) != 0;
            let identity = recorded_identity((
                present(0).then(|| "a".repeat(64)),
                present(1).then_some(1),
                present(2).then_some(1000),
                present(3).then_some(1000),
                present(4).then_some(0o640),
                present(5).then_some(1),
                present(6).then_some(2),
            ));
            assert_eq!(identity.is_ok(), mask == 0 || mask == 127, "mask {mask}");
        }
    }

    fn planned_member() -> policy_transaction::ReceiptMemberEvidence {
        policy_transaction::ReceiptMemberEvidence {
            path: "packs/list.txt".into(),
            role: MemberRole::Pack,
            operation: Some(MemberOperation::Create),
            before_digest: None,
            before_length: None,
            before_uid: None,
            before_gid: None,
            before_mode: None,
            before_device: None,
            before_inode: None,
            after_digest: Some("a".repeat(64)),
            after_length: Some(10),
            after_uid: Some(1000),
            after_gid: Some(1000),
            after_mode: Some(0o640),
            promoted_device: None,
            promoted_inode: None,
            restored_digest: None,
            restored_length: None,
            restored_uid: None,
            restored_gid: None,
            restored_mode: None,
            restored_device: None,
            restored_inode: None,
        }
    }

    #[test]
    fn after_identity_requires_a_complete_recorded_promotion() {
        let member = planned_member();
        assert!(member_evidence(member.clone()).unwrap().after.is_none());
        for (device, inode) in [(Some(1), None), (None, Some(2))] {
            let mut partial = member.clone();
            partial.promoted_device = device;
            partial.promoted_inode = inode;
            assert!(member_evidence(partial).is_err());
        }
        let mut promoted = member;
        promoted.promoted_device = Some(1);
        promoted.promoted_inode = Some(2);
        assert_eq!(
            member_evidence(promoted.clone())
                .unwrap()
                .after
                .unwrap()
                .inode,
            2
        );
        promoted.after_digest = None;
        assert!(member_evidence(promoted).is_err());
    }

    #[test]
    fn unchanged_evidence_requires_identical_complete_states_without_promotion_or_restore() {
        let mut member = planned_member();
        member.operation = None;
        member.before_digest = member.after_digest.clone();
        member.before_length = member.after_length;
        member.before_uid = member.after_uid;
        member.before_gid = member.after_gid;
        member.before_mode = member.after_mode;
        member.before_device = Some(1);
        member.before_inode = Some(2);
        let evidence = member_evidence(member.clone()).unwrap();
        assert!(evidence.operation.is_none());
        assert_eq!(
            evidence.before,
            evidence.after.as_ref().map(MemberBeforeState::from)
        );
        for field in 0..10 {
            let mut invalid = member.clone();
            match field {
                0 => invalid.before_inode = None,
                1 => invalid.after_digest = None,
                2 => invalid.after_digest = Some("b".repeat(64)),
                3 => invalid.after_length = Some(11),
                4 => invalid.after_uid = Some(2000),
                5 => invalid.after_gid = Some(2000),
                6 => invalid.after_mode = Some(0o600),
                7 => invalid.promoted_inode = Some(2),
                8 => {
                    invalid.promoted_device = Some(1);
                    invalid.promoted_inode = Some(2);
                }
                9 => {
                    invalid.restored_digest = invalid.before_digest.clone();
                    invalid.restored_length = invalid.before_length;
                    invalid.restored_uid = invalid.before_uid;
                    invalid.restored_gid = invalid.before_gid;
                    invalid.restored_mode = invalid.before_mode;
                    invalid.restored_device = invalid.before_device;
                    invalid.restored_inode = invalid.before_inode;
                }
                _ => unreachable!(),
            }
            assert!(member_evidence(invalid).is_err(), "tamper {field}");
        }
    }

    #[test]
    fn receipt_requires_exact_payload_envelope_revision_and_actor() {
        let (manifest, _) = artifact(1, &[]);
        let binding =
            OperationBinding::for_apply(&manifest, &"b".repeat(64), "actor", "request").unwrap();
        let original = receipt(&binding, Persistence::Committed);
        binding
            .verify_receipt(&original, &binding.operation_manifest().unwrap())
            .unwrap();
        for field in [
            "payload_hash",
            "after_revision",
            "actor",
            "operation",
            "request_id",
        ] {
            let mut changed = serde_json::to_value(&original).unwrap();
            changed[field] = Value::String("changed".into());
            let changed: BaseReceipt = serde_json::from_value(changed).unwrap();
            assert!(
                binding
                    .verify_receipt(&changed, &binding.operation_manifest().unwrap())
                    .is_err(),
                "{field}"
            );
        }
        let mut envelope = binding.operation_manifest().unwrap();
        envelope["policy_epoch"] = Value::from(2);
        assert!(binding.verify_receipt(&original, &envelope).is_err());
        for manifest in [None, Some(envelope)] {
            let mut changed = original.clone();
            changed.operation_manifest = manifest;
            assert!(binding
                .verify_receipt(&changed, &binding.operation_manifest().unwrap())
                .is_err());
        }
    }

    #[test]
    fn original_operator_payload_is_preserved_by_publication_binding() {
        let (manifest, _) = artifact(1, &[]);
        let mut binding = OperationBinding::new(
            &manifest,
            &manifest.config_revision,
            "actor",
            "request",
            OPERATOR_OPERATION,
        )
        .unwrap();
        binding.request_payload_hash = Some(digest(b"original operator request"));
        let original = receipt(&binding, Persistence::Committed);
        assert_ne!(original.payload_hash, digest(&binding.payload().unwrap()));
        binding
            .verify_receipt(&original, &binding.operation_manifest().unwrap())
            .unwrap();
        assert!(ExistingReceiptAdapter.supports_member_evidence());
    }
}
