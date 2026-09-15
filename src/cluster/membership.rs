//! Durable invitation admission and revocable node credentials.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use anyhow::{ensure, Context};
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::store::PrivateStore;
use crate::auth::token::{generate_token, hash_token, verify_token};
use crate::config::write_lock::MigrationWriteLock;

pub const MEMBERSHIP_VERSION: u32 = 1;
pub const INVITE_TTL: u64 = 15 * 60;
pub const PENDING_TTL: u64 = 24 * 60 * 60;
pub(crate) const STORE: &str = ".warden-node-membership";
const MAX_MEMBERS: usize = 64;
const MAX_INVITES: usize = 64;

/// Explicit secret transport; diagnostics always redact its contents.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(pub String);
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u32,
    pub cluster_id: String,
    pub primary_node_id: String,
    pub fingerprint: String,
    pub expires_at: u64,
    pub secret: SecretString,
}
impl Invitation {
    pub fn encode(&self) -> anyhow::Result<SecretString> {
        Ok(SecretString(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?),
        ))
    }
    pub fn decode(secret: &SecretString, now: u64) -> anyhow::Result<Self> {
        ensure!(secret.0.len() <= 4096, "invalid invitation");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(secret.0.trim())
            .map_err(|_| anyhow::anyhow!("invalid invitation"))?;
        let invite: Self =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid invitation"))?;
        ensure!(
            invite.version == MEMBERSHIP_VERSION
                && invite.expires_at > now
                && invite.expires_at <= now.saturating_add(INVITE_TTL),
            "invitation expired or unsupported"
        );
        ensure!(
            super::manifest::is_hash(&invite.fingerprint)
                && valid_id(&invite.cluster_id)
                && valid_id(&invite.primary_node_id),
            "invalid invitation identity"
        );
        Ok(invite)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberState {
    Pending,
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberView {
    pub node_id: String,
    pub name: String,
    pub state: MemberState,
    pub admitted_at: u64,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub sync: Option<String>,
    #[serde(default)]
    pub last_confirmation_secs: Option<u64>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    view: MemberView,
    credential_hash: String,
    invitation_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingInvite {
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Roster {
    version: u32,
    cluster_id: String,
    primary_node_id: String,
    fingerprint: String,
    invites: BTreeMap<String, PendingInvite>,
    members: BTreeMap<String, Member>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedNode {
    pub node_id: String,
}

pub(crate) struct MembershipStore<'g> {
    files: PrivateStore<'g>,
    roster: Roster,
}
impl<'g> MembershipStore<'g> {
    pub(crate) fn initialize(
        guard: &'g MigrationWriteLock,
        cluster_id: &str,
        primary_node_id: &str,
        fingerprint: &str,
    ) -> anyhow::Result<Self> {
        ensure!(
            valid_id(cluster_id)
                && valid_id(primary_node_id)
                && super::manifest::is_hash(fingerprint),
            "invalid membership identity"
        );
        let files = PrivateStore::open(guard, STORE)?;
        let roster = Roster {
            version: MEMBERSHIP_VERSION,
            cluster_id: cluster_id.into(),
            primary_node_id: primary_node_id.into(),
            fingerprint: fingerprint.into(),
            invites: BTreeMap::new(),
            members: BTreeMap::new(),
        };
        files.create("roster.json", &serde_json::to_vec(&roster)?)?;
        Ok(Self { files, roster })
    }
    pub(crate) fn open(guard: &'g MigrationWriteLock) -> anyhow::Result<Self> {
        let files = PrivateStore::open(guard, STORE)?;
        let bytes = files
            .read("roster.json", 256 * 1024)?
            .context("modern membership is not initialized; explicit migration required")?;
        let roster: Roster = serde_json::from_slice(&bytes)?;
        ensure!(
            roster.version == MEMBERSHIP_VERSION
                && roster.members.len() <= MAX_MEMBERS
                && roster.invites.len() <= MAX_INVITES,
            "invalid membership store"
        );
        ensure!(
            valid_id(&roster.cluster_id)
                && valid_id(&roster.primary_node_id)
                && super::manifest::is_hash(&roster.fingerprint),
            "invalid membership identity"
        );
        for (id, member) in &roster.members {
            ensure!(
                id == &member.view.node_id
                    && valid_id(id)
                    && super::manifest::is_hash(&member.credential_hash),
                "invalid member identity"
            );
            validate_name(&member.view.name)?;
        }
        Ok(Self { files, roster })
    }
    fn save(&self) -> anyhow::Result<()> {
        self.files
            .write("roster.json", &serde_json::to_vec(&self.roster)?)
    }
    fn expire(&mut self, now: u64) {
        self.roster
            .invites
            .retain(|_, invite| invite.expires_at > now);
        for member in self.roster.members.values_mut() {
            if member.view.state == MemberState::Pending
                && member.view.expires_at.is_some_and(|until| until <= now)
            {
                member.view.state = MemberState::Revoked;
            }
        }
    }
    pub(crate) fn invite(&mut self, now: u64) -> anyhow::Result<Invitation> {
        self.expire(now);
        ensure!(
            self.roster.invites.len() < MAX_INVITES,
            "too many unexpired invitations"
        );
        let (secret, hash) = generate_token();
        let expires_at = now.checked_add(INVITE_TTL).context("clock overflow")?;
        self.roster
            .invites
            .insert(hash, PendingInvite { expires_at });
        self.save()?;
        Ok(Invitation {
            version: MEMBERSHIP_VERSION,
            cluster_id: self.roster.cluster_id.clone(),
            primary_node_id: self.roster.primary_node_id.clone(),
            fingerprint: self.roster.fingerprint.clone(),
            expires_at,
            secret: SecretString(secret),
        })
    }
    pub(crate) fn enroll(
        &mut self,
        invitation: &SecretString,
        node_id: &str,
        name: &str,
        credential: &SecretString,
        now: u64,
    ) -> anyhow::Result<MemberView> {
        ensure!(
            valid_id(node_id) && node_id != self.roster.primary_node_id,
            "invalid node identity"
        );
        validate_name(name)?;
        ensure!(
            credential.0.starts_with("ps_")
                && credential.0.len() == 67
                && credential.0[3..].bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid node credential"
        );
        self.expire(now);
        let invitation_hash = hash_token(&invitation.0);
        if let Some(member) = self
            .roster
            .members
            .get(node_id)
            .filter(|m| m.view.state != MemberState::Revoked)
        {
            ensure!(
                member.view.state != MemberState::Revoked
                    && member.invitation_hash == invitation_hash
                    && verify_token(&credential.0, &member.credential_hash),
                "node identity already enrolled"
            );
            return Ok(member.view.clone());
        }
        if self.roster.members.len() >= MAX_MEMBERS {
            let oldest = self
                .roster
                .members
                .iter()
                .filter(|(_, m)| m.view.state == MemberState::Revoked)
                .min_by_key(|(_, m)| m.view.admitted_at)
                .map(|(id, _)| id.clone());
            if let Some(id) = oldest {
                self.roster.members.remove(&id);
            }
        }
        ensure!(
            self.roster.members.len() < MAX_MEMBERS || self.roster.members.contains_key(node_id),
            "membership capacity reached"
        );
        ensure!(
            self.roster.invites.remove(&invitation_hash).is_some(),
            "invitation expired, consumed or invalid"
        );
        let view = MemberView {
            node_id: node_id.into(),
            name: name.into(),
            state: MemberState::Pending,
            admitted_at: now,
            endpoint: None,
            sync: None,
            last_confirmation_secs: None,
            fingerprint: None,
            expires_at: Some(now.checked_add(PENDING_TTL).context("clock overflow")?),
        };
        self.roster.members.insert(
            node_id.into(),
            Member {
                view: view.clone(),
                credential_hash: hash_token(&credential.0),
                invitation_hash,
            },
        );
        self.save()?;
        Ok(view)
    }

    /// Admit a target whose one-use destination authorization already bound the operation.
    pub(crate) fn admit_prepared(
        &mut self,
        operation_id: &str,
        node_id: &str,
        name: &str,
        endpoint: SocketAddr,
        credential: &SecretString,
        now: u64,
    ) -> anyhow::Result<MemberView> {
        ensure!(
            valid_id(operation_id),
            "invalid prepared operation identity"
        );
        ensure!(
            valid_id(node_id) && node_id != self.roster.primary_node_id,
            "invalid node identity"
        );
        validate_name(name)?;
        ensure!(endpoint.port() != 0, "invalid node endpoint");
        ensure!(
            credential.0.starts_with("ps_")
                && credential.0.len() == 67
                && credential.0[3..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid node credential"
        );
        self.expire(now);
        let binding = hash_token(&format!("nodes-v2:{operation_id}"));
        if let Some(member) = self.roster.members.get(node_id) {
            if member.invitation_hash == binding
                && verify_token(&credential.0, &member.credential_hash)
            {
                ensure!(
                    member.view.state != MemberState::Revoked,
                    "revoked admission cannot be replayed"
                );
                return Ok(member.view.clone());
            }
            ensure!(
                member.view.state == MemberState::Revoked,
                "node identity already enrolled by another operation"
            );
        }
        ensure!(
            self.roster.members.len() < MAX_MEMBERS || self.roster.members.contains_key(node_id),
            "membership capacity reached"
        );
        let view = MemberView {
            node_id: node_id.into(),
            name: name.into(),
            state: MemberState::Pending,
            admitted_at: now,
            expires_at: Some(now.checked_add(PENDING_TTL).context("clock overflow")?),
            endpoint: Some(endpoint_url(endpoint)),
            sync: None,
            last_confirmation_secs: None,
            fingerprint: None,
        };
        self.roster.members.insert(
            node_id.into(),
            Member {
                view: view.clone(),
                credential_hash: hash_token(&credential.0),
                invitation_hash: binding,
            },
        );
        self.save()?;
        Ok(view)
    }
    pub(crate) fn authenticate(&self, credential: &str, now: u64) -> Option<AuthenticatedNode> {
        // Compare every row; node names and source addresses carry no authority.
        let mut found = None;
        for member in self.roster.members.values() {
            if verify_token(credential, &member.credential_hash)
                && member.view.state != MemberState::Revoked
                && member.view.expires_at.is_none_or(|until| until > now)
            {
                found = Some(AuthenticatedNode {
                    node_id: member.view.node_id.clone(),
                });
            }
        }
        found
    }
    pub(crate) fn activate(
        &mut self,
        principal: &AuthenticatedNode,
        now: u64,
    ) -> anyhow::Result<()> {
        self.expire(now);
        let member = self
            .roster
            .members
            .get_mut(&principal.node_id)
            .context("unknown member")?;
        ensure!(
            member.view.state != MemberState::Revoked,
            "membership revoked or expired"
        );
        member.view.state = MemberState::Active;
        member.view.expires_at = None;
        self.save()
    }
    pub(crate) fn rename(&mut self, node_id: &str, name: &str) -> anyhow::Result<()> {
        validate_name(name)?;
        let member = self
            .roster
            .members
            .get_mut(node_id)
            .context("unknown member")?;
        ensure!(member.view.state != MemberState::Revoked, "member revoked");
        if member.view.name != name {
            member.view.name = name.into();
            self.save()?;
        }
        Ok(())
    }

    pub(crate) fn revoke(&mut self, node_id: &str) -> anyhow::Result<()> {
        let member = self
            .roster
            .members
            .get_mut(node_id)
            .context("unknown member")?;
        member.view.state = MemberState::Revoked;
        self.save()
    }
    pub(crate) fn views(&self, now: u64) -> Vec<MemberView> {
        self.roster
            .members
            .values()
            .map(|member| {
                let mut v = member.view.clone();
                if v.state == MemberState::Pending && v.expires_at.is_some_and(|t| t <= now) {
                    v.state = MemberState::Revoked;
                }
                v
            })
            .collect()
    }
    pub(crate) fn matches(&self, cluster_id: &str, primary: &str) -> bool {
        self.roster.cluster_id == cluster_id && self.roster.primary_node_id == primary
    }

    pub(crate) fn replace_primary_fingerprint(
        &mut self,
        cluster_id: &str,
        primary_node_id: &str,
        fingerprint: &str,
        now: u64,
    ) -> anyhow::Result<()> {
        ensure!(
            self.matches(cluster_id, primary_node_id) && super::manifest::is_hash(fingerprint),
            "primary fingerprint replacement identity mismatch"
        );
        self.expire(now);
        ensure!(
            self.roster
                .members
                .values()
                .all(|member| member.view.state == MemberState::Revoked),
            "primary fingerprint replacement requires peerless membership"
        );
        self.roster.fingerprint = fingerprint.into();
        self.save()
    }

    pub(crate) fn primary_fingerprint(&self) -> &str {
        &self.roster.fingerprint
    }
}

pub(crate) fn valid_id(id: &str) -> bool {
    crate::config::schema::node::valid_node_id(id)
}
pub(crate) fn random_id() -> String {
    crate::config::schema::node::generate_node_id().expect("OS entropy unavailable")
}
pub(crate) fn validate_name(name: &str) -> anyhow::Result<()> {
    ensure!(
        !name.trim().is_empty() && name.len() <= 64 && !name.chars().any(char::is_control),
        "node name must contain 1–64 bytes without control characters"
    );
    Ok(())
}
pub(crate) fn now() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn endpoint_url(endpoint: SocketAddr) -> String {
    format!("https://{endpoint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_lock::acquire_for_migration;
    #[test]
    fn invitation_is_one_use_with_idempotent_pending_recovery_and_individual_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let cluster = random_id();
        let primary = random_id();
        let id = random_id();
        let mut store =
            MembershipStore::initialize(&guard, &cluster, &primary, &"a".repeat(64)).unwrap();
        let invite = store.invite(100).unwrap();
        let credential = SecretString(generate_token().0);
        let pending = store
            .enroll(&invite.secret, &id, "same name", &credential, 101)
            .unwrap();
        assert_eq!(pending.state, MemberState::Pending);
        assert_eq!(
            store
                .enroll(&invite.secret, &id, "same name", &credential, 102)
                .unwrap(),
            pending
        );
        assert!(store
            .enroll(
                &invite.secret,
                &random_id(),
                "same name",
                &SecretString(generate_token().0),
                102
            )
            .is_err());
        assert!(store.authenticate(&invite.secret.0, 103).is_none());
        let principal = store.authenticate(&credential.0, 103).unwrap();
        assert_eq!(principal.node_id, id);
        store.activate(&principal, 104).unwrap();
        store.activate(&principal, 105).unwrap();
        drop(store);
        let mut store = MembershipStore::open(&guard).unwrap();
        assert!(store
            .authenticate(&credential.0, 100 + PENDING_TTL + 1)
            .is_some());
        store.revoke(&id).unwrap();
        assert!(store.authenticate(&credential.0, 106).is_none());
        assert!(store
            .enroll(&invite.secret, &id, "same name", &credential, 107)
            .is_err());
        let replacement = store.invite(108).unwrap();
        let rotated = SecretString(generate_token().0);
        store
            .enroll(&replacement.secret, &id, "same name", &rotated, 109)
            .unwrap();
        assert!(store.authenticate(&credential.0, 110).is_none());
        assert!(store.authenticate(&rotated.0, 110).is_some());
    }

    #[test]
    fn prepared_admission_is_idempotent_only_for_the_bound_operation_and_credential() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let cluster = random_id();
        let primary = random_id();
        let secondary = random_id();
        let operation = random_id();
        let credential = SecretString(generate_token().0);
        let mut store =
            MembershipStore::initialize(&guard, &cluster, &primary, &"a".repeat(64)).unwrap();
        let first = store
            .admit_prepared(
                &operation,
                &secondary,
                "secondary",
                "192.0.2.2:8053".parse().unwrap(),
                &credential,
                100,
            )
            .unwrap();
        let replay = store
            .admit_prepared(
                &operation,
                &secondary,
                "secondary renamed in replay",
                "192.0.2.3:8053".parse().unwrap(),
                &credential,
                101,
            )
            .unwrap();
        assert_eq!(replay, first);
        assert!(store
            .admit_prepared(
                &random_id(),
                &secondary,
                "secondary",
                "192.0.2.2:8053".parse().unwrap(),
                &credential,
                102,
            )
            .is_err());
        assert!(store
            .admit_prepared(
                &operation,
                &secondary,
                "secondary",
                "192.0.2.2:8053".parse().unwrap(),
                &SecretString(generate_token().0),
                102,
            )
            .is_err());
        store.revoke(&secondary).unwrap();
        assert!(store
            .admit_prepared(
                &operation,
                &secondary,
                "secondary",
                "192.0.2.2:8053".parse().unwrap(),
                &credential,
                103,
            )
            .is_err());
        let replacement_operation = random_id();
        let replacement_credential = SecretString(generate_token().0);
        let replacement = store
            .admit_prepared(
                &replacement_operation,
                &secondary,
                "secondary readmitted",
                "192.0.2.4:8053".parse().unwrap(),
                &replacement_credential,
                104,
            )
            .unwrap();
        assert_eq!(replacement.state, MemberState::Pending);
        assert_eq!(
            replacement.endpoint.as_deref(),
            Some("https://192.0.2.4:8053")
        );
        assert!(store.authenticate(&credential.0, 105).is_none());
        assert!(store.authenticate(&replacement_credential.0, 105).is_some());
        assert!(store
            .admit_prepared(
                &operation,
                &secondary,
                "secondary",
                "192.0.2.2:8053".parse().unwrap(),
                &credential,
                106,
            )
            .is_err());
    }
    #[test]
    fn expiration_boundaries_are_exact_and_debug_never_contains_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut store =
            MembershipStore::initialize(&guard, &random_id(), &random_id(), &"a".repeat(64))
                .unwrap();
        let invite = store.invite(100).unwrap();
        let encoded = invite.encode().unwrap();
        assert!(!format!("{invite:?}").contains(&invite.secret.0));
        assert!(!format!("{encoded:?}").contains(&encoded.0));
        assert!(Invitation::decode(&encoded, 999).is_ok());
        assert!(Invitation::decode(&encoded, 1000).is_err());
        assert!(store
            .enroll(
                &invite.secret,
                &random_id(),
                "node",
                &SecretString(generate_token().0),
                1000
            )
            .is_err());
        let invite = store.invite(1000).unwrap();
        let id = random_id();
        let secret = SecretString(generate_token().0);
        store
            .enroll(&invite.secret, &id, "node", &secret, 1001)
            .unwrap();
        assert!(store.authenticate(&secret.0, 1000 + PENDING_TTL).is_some());
        assert!(store.authenticate(&secret.0, 1001 + PENDING_TTL).is_none());
        assert_eq!(
            store.views(1001 + PENDING_TTL)[0].state,
            MemberState::Revoked
        );
    }
    #[test]
    fn duplicate_names_are_not_identities_and_revoked_history_does_not_exhaust_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut store =
            MembershipStore::initialize(&guard, &random_id(), &random_id(), &"a".repeat(64))
                .unwrap();
        for time in 0..(MAX_MEMBERS + 3) {
            let invite = store.invite(time as u64).unwrap();
            let id = random_id();
            let secret = SecretString(generate_token().0);
            store
                .enroll(&invite.secret, &id, "duplicate", &secret, time as u64)
                .unwrap();
            store.revoke(&id).unwrap();
        }
        assert!(store.views(200).len() <= MAX_MEMBERS);
    }
}
