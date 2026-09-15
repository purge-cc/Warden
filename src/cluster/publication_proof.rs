//! A captured before state permits retiring an intent that has no transaction receipt.

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::manifest::{digest, is_hash};
use super::publication::Reservation;
use crate::config::policy_revision::{
    PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory,
};
use crate::config::policy_transaction::{BaseReceipt, TransactionRequest, MAX_POLICY_BYTES};
use crate::config::tree_io::inspect_at;
use crate::config::write_lock::{reserved_component, MigrationWriteLock};

const MAX_MEMBERS: usize = 4096;
const MAX_PARENTS: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    sha256: String,
    bytes: u64,
}

impl Content {
    fn of(bytes: &[u8]) -> Self {
        Self {
            sha256: digest(bytes),
            bytes: bytes.len() as u64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inode {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Inode {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    content: Content,
    identity: Inode,
    nlink: u64,
    ctime: i64,
    ctime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    kind: String,
    before: Option<FileIdentity>,
    after: Option<Content>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparationProof {
    format: u32,
    before_revision: String,
    after_revision: String,
    actor: String,
    request_id: String,
    operation: String,
    payload_hash: String,
    envelope_hash: String,
    members: BTreeMap<String, Member>,
    parents: BTreeMap<String, Option<Inode>>,
}

impl PreparationProof {
    /// These reads verify the transaction's before state; artifact bytes remain captured.
    pub(crate) fn capture(
        guard: &MigrationWriteLock,
        request: &TransactionRequest,
        before: &PolicyRevisionInventory,
        after: &PolicyRevisionInventory,
    ) -> anyhow::Result<Self> {
        ensure!(
            before.revision() == request.expected_revision,
            "ArtifactPublicationProofConflict: stale before revision"
        );
        let mut members = BTreeMap::new();
        let mut expected = BTreeMap::new();
        for (inventory, is_before) in [(before, true), (after, false)] {
            for member in inventory.members() {
                let path = member
                    .path()
                    .to_str()
                    .context("publication proof path must be UTF-8")?;
                check_path(path)?;
                let PolicyMemberState::Present(bytes) = member.state() else {
                    anyhow::bail!("ArtifactPublicationProofConflict: inventories must contain present members");
                };
                let kind = match member.kind() {
                    PolicyMemberKind::Master => "master",
                    PolicyMemberKind::Include => "include",
                    PolicyMemberKind::Pack => "pack",
                };
                let entry = members.entry(path.to_owned()).or_insert_with(|| Member {
                    kind: kind.into(),
                    before: None,
                    after: None,
                });
                ensure!(
                    entry.kind == kind,
                    "ArtifactPublicationProofConflict: target role changed"
                );
                if is_before {
                    expected.insert(path.to_owned(), Content::of(bytes));
                } else {
                    entry.after = Some(Content::of(bytes));
                }
            }
        }
        ensure!(
            members.len() <= MAX_MEMBERS,
            "publication proof member limit exceeded"
        );
        let mut parents = BTreeMap::new();
        let mut total = 0_u64;
        for (path, member) in &mut members {
            let observed = observe(guard, path, &mut parents)?;
            ensure!(observed.as_ref().map(|file| &file.content) == expected.get(path),
                "ArtifactPublicationProofConflict: before member or new destination changed: {path}");
            if let Some(file) = &observed {
                total = total
                    .checked_add(file.content.bytes)
                    .context("publication proof byte overflow")?;
            }
            member.before = observed;
        }
        ensure!(
            total <= MAX_POLICY_BYTES,
            "publication proof byte limit exceeded"
        );
        let proof = Self {
            format: 1,
            before_revision: before.revision().to_string(),
            after_revision: after.revision().to_string(),
            actor: request.actor.clone(),
            request_id: request.request_id.clone(),
            operation: request.operation.clone(),
            payload_hash: digest(&request.payload),
            envelope_hash: String::new(),
            members,
            parents,
        };
        proof.verify_tree(guard)?;
        Ok(proof)
    }

    pub(crate) fn bind(mut self, envelope: &Value) -> anyhow::Result<Value> {
        self.verify_request(envelope)?;
        self.envelope_hash = digest(&serde_json::to_vec(envelope)?);
        Ok(serde_json::to_value(self)?)
    }

    fn verify_request(&self, envelope: &Value) -> anyhow::Result<()> {
        for (name, expected) in [
            ("actor", self.actor.as_str()),
            ("request_id", self.request_id.as_str()),
            ("operation", self.operation.as_str()),
            ("request_payload_hash", self.payload_hash.as_str()),
            ("expected_after_revision", self.after_revision.as_str()),
        ] {
            ensure!(
                envelope.get(name).and_then(Value::as_str) == Some(expected),
                "ArtifactPublicationProofConflict: operation binding mismatch: {name}"
            );
        }
        Ok(())
    }

    fn verify_tree(&self, guard: &MigrationWriteLock) -> anyhow::Result<()> {
        guard.verify_root_linked()?;
        let mut parents = BTreeMap::new();
        for (path, member) in &self.members {
            ensure!(
                observe(guard, path, &mut parents)? == member.before,
                "ArtifactPublicationProofConflict: target changed before preparation: {path}"
            );
        }
        ensure!(
            parents == self.parents,
            "ArtifactPublicationProofConflict: target parent changed"
        );
        guard.verify_root_linked()
    }
}

pub(crate) fn verify_unchanged(
    guard: &MigrationWriteLock,
    reservation: &Reservation,
    envelope: &Value,
    value: &Value,
) -> anyhow::Result<()> {
    decode(reservation, envelope, value)?.verify_tree(guard)
}

pub(crate) fn verify_receipt(
    reservation: &Reservation,
    envelope: &Value,
    value: &Value,
    receipt: &BaseReceipt,
) -> anyhow::Result<()> {
    let proof = decode(reservation, envelope, value)?;
    ensure!(
        receipt.before_revision == proof.before_revision,
        "ArtifactPublicationProofConflict: receipt before revision mismatch"
    );
    Ok(())
}

fn decode(
    reservation: &Reservation,
    envelope: &Value,
    value: &Value,
) -> anyhow::Result<PreparationProof> {
    let proof: PreparationProof = serde_json::from_value(value.clone())?;
    ensure!(
        proof.format == 1
            && is_hash(&proof.before_revision)
            && proof.after_revision == reservation.config_revision
            && proof.envelope_hash == digest(&serde_json::to_vec(envelope)?),
        "ArtifactPublicationProofConflict: proof association mismatch"
    );
    ensure!(
        !proof.members.is_empty()
            && proof.members.len() <= MAX_MEMBERS
            && proof.parents.contains_key("")
            && proof.parents.len() <= MAX_PARENTS,
        "ArtifactPublicationProofConflict: incomplete target inventory"
    );
    let mut before_masters = 0;
    let mut after_masters = 0;
    let mut total = 0_u64;
    for (path, member) in &proof.members {
        check_path(path)?;
        ensure!(
            matches!(member.kind.as_str(), "master" | "include" | "pack")
                && (member.before.is_some() || member.after.is_some()),
            "invalid publication proof member"
        );
        if member.kind == "master" {
            before_masters += usize::from(member.before.is_some());
            after_masters += usize::from(member.after.is_some());
        }
        for content in [
            member.before.as_ref().map(|file| &file.content),
            member.after.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                is_hash(&content.sha256) && content.bytes <= MAX_POLICY_BYTES,
                "invalid publication proof content"
            );
        }
        if let Some(before) = &member.before {
            ensure!(
                before.nlink == 1 && before.identity.mode & libc::S_IFMT == libc::S_IFREG,
                "invalid publication proof file identity"
            );
            total = total
                .checked_add(before.content.bytes)
                .context("publication proof byte overflow")?;
        }
    }
    ensure!(
        before_masters == 1 && after_masters == 1 && total <= MAX_POLICY_BYTES,
        "ArtifactPublicationProofConflict: incomplete before inventory"
    );
    proof.verify_request(envelope)?;
    Ok(proof)
}

fn check_path(path: &str) -> anyhow::Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && !path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            && !Path::new(path)
                .components()
                .any(|part| reserved_component(part.as_os_str())),
        "invalid publication proof target path"
    );
    Ok(())
}

fn observe(
    guard: &MigrationWriteLock,
    path: &str,
    parents: &mut BTreeMap<String, Option<Inode>>,
) -> anyhow::Result<Option<FileIdentity>> {
    check_path(path)?;
    let tree = guard.tree_io();
    let plan = tree.plan_root_file_no_follow(Path::new(path))?;
    let destination = plan.destination()?;
    let observed = if let Some(meta) = plan.original_metadata() {
        ensure!(
            meta.len() <= MAX_POLICY_BYTES,
            "publication proof file byte limit exceeded"
        );
        Some(FileIdentity {
            content: Content {
                sha256: hex::encode(
                    plan.original_sha256()?
                        .context("publication proof member disappeared")?,
                ),
                bytes: meta.len(),
            },
            identity: Inode::of(meta),
            nlink: meta.nlink(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        })
    } else {
        None
    };
    let mut parent = Some(tree.root.try_clone()?);
    let mut relative = String::new();
    insert_parent(parents, &relative, Some(Inode::of(&tree.root.metadata()?)))?;
    for part in Path::new(path)
        .parent()
        .context("publication target parent")?
        .components()
    {
        let Component::Normal(name) = part else {
            anyhow::bail!("invalid publication target parent")
        };
        if !relative.is_empty() {
            relative.push('/');
        }
        relative.push_str(name.to_str().context("publication parent must be UTF-8")?);
        parent = match &parent {
            Some(directory) => inspect_at(directory, name)?,
            None => None,
        };
        let identity = parent
            .as_ref()
            .map(|directory| {
                let meta = directory.metadata()?;
                ensure!(
                    meta.is_dir(),
                    "publication target parent is not a directory"
                );
                Ok::<_, anyhow::Error>(Inode::of(&meta))
            })
            .transpose()?;
        insert_parent(parents, &relative, identity)?;
    }
    ensure!(
        tree.plan_root_file_no_follow(Path::new(path))?
            .destination()?
            == destination,
        "ArtifactPublicationProofConflict: member changed during capture"
    );
    Ok(observed)
}

fn insert_parent(
    parents: &mut BTreeMap<String, Option<Inode>>,
    path: &str,
    identity: Option<Inode>,
) -> anyhow::Result<()> {
    if let Some(previous) = parents.insert(path.to_owned(), identity.clone()) {
        ensure!(
            previous == identity,
            "ArtifactPublicationProofConflict: parent changed during capture"
        );
    }
    ensure!(
        parents.len() <= MAX_PARENTS,
        "publication proof parent limit exceeded"
    );
    Ok(())
}
