//! Expected peers survive restart; proof of active policy requires a new session ack.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};

use crate::config::write_lock::MigrationWriteLock;

use super::dto::{ActiveArtifactAck, ArtifactIdentity};
use super::manifest::is_hash;
use super::store::PrivateStore;

pub(crate) const STORE_DIR: &str = ".warden-cluster-peers";
const STATE: &str = "state.json";
const MAX_PEERS: usize = 64;
const MAX_STATE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedPeers {
    format: u32,
    peers: Vec<IpAddr>,
}

#[derive(Debug, Default)]
struct PeerObservation {
    persisted: Option<ArtifactIdentity>,
    active: Option<ActiveArtifactAck>,
    last_ack: Option<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerAcknowledgementView {
    pub ip: IpAddr,
    pub persisted: Option<ArtifactIdentity>,
    pub active: Option<ActiveArtifactAck>,
    pub last_ack_secs: Option<u64>,
    pub fresh: bool,
}

pub(crate) struct PeerAcknowledgements {
    master: PathBuf,
    root_device: u64,
    root_inode: u64,
    peers: BTreeMap<IpAddr, PeerObservation>,
    available: bool,
}

impl PeerAcknowledgements {
    pub(crate) fn load(guard: &MigrationWriteLock) -> anyhow::Result<Self> {
        let files = PrivateStore::open(guard, STORE_DIR)?;
        check_entries(&files)?;
        let expected = match files.read(STATE, MAX_STATE_BYTES)? {
            Some(bytes) => decode_roster(&bytes)?,
            None => {
                let expected = ExpectedPeers {
                    format: 1,
                    peers: Vec::new(),
                };
                files.create(STATE, &serde_json::to_vec(&expected)?)?;
                expected
            }
        };
        let root = guard.tree_io().root.metadata()?;
        Ok(Self {
            master: guard.canonical_master().to_owned(),
            root_device: root.dev(),
            root_inode: root.ino(),
            peers: expected
                .peers
                .into_iter()
                .map(|ip| (ip, PeerObservation::default()))
                .collect(),
            available: true,
        })
    }

    /// The caller supplies the authenticated connection's source address.
    pub(crate) fn record(
        &mut self,
        guard: &MigrationWriteLock,
        ip: IpAddr,
        persisted: Option<ArtifactIdentity>,
        active: Option<ActiveArtifactAck>,
        now: Instant,
    ) -> anyhow::Result<()> {
        self.available = false;
        if let Some(previous) = self.peers.get_mut(&ip) {
            *previous = PeerObservation::default();
        }
        ensure!(
            guard.canonical_master() == self.master.as_path(),
            "ArtifactAcknowledgementConflict: different configuration master"
        );
        let root = guard.tree_io().root.metadata()?;
        ensure!(
            (root.dev(), root.ino()) == (self.root_device, self.root_inode),
            "ArtifactAcknowledgementConflict: configuration root changed"
        );
        let files = PrivateStore::open(guard, STORE_DIR)?;
        check_entries(&files)?;
        let bytes = files
            .read(STATE, MAX_STATE_BYTES)?
            .context("ArtifactAcknowledgementConflict: expected peer roster disappeared")?;
        let stored = decode_roster(&bytes)?;
        let mut expected: BTreeSet<_> = stored.peers.into_iter().collect();
        ensure!(
            self.peers.keys().all(|ip| expected.contains(ip)),
            "ArtifactAcknowledgementConflict: expected peer was removed"
        );
        if !expected.contains(&ip) {
            ensure!(
                expected.len() < MAX_PEERS,
                "ArtifactAcknowledgementLimit: expected peer roster is full"
            );
            expected.insert(ip);
            let next = ExpectedPeers {
                format: 1,
                peers: expected.iter().copied().collect(),
            };
            // Admission persists before an ack can make the new peer current.
            files.write(STATE, &serde_json::to_vec(&next)?)?;
        }
        for peer in expected {
            self.peers.entry(peer).or_default();
        }
        ensure!(
            persisted.as_ref().is_none_or(valid_identity),
            "ArtifactAcknowledgementInvalid: persisted identity"
        );
        ensure!(
            active.as_ref().is_none_or(valid_active_ack),
            "ArtifactAcknowledgementInvalid: active identity"
        );
        let last_ack = active.as_ref().map(|_| now);
        self.peers.insert(
            ip,
            PeerObservation {
                persisted,
                active,
                last_ack,
            },
        );
        self.available = true;
        Ok(())
    }

    pub(crate) fn converged(
        &self,
        desired: &ArtifactIdentity,
        now: Instant,
        stale: Duration,
    ) -> bool {
        self.available
            && !self.peers.is_empty()
            && valid_identity(desired)
            && self.peers.values().all(|peer| {
                fresh(peer.last_ack, now, stale)
                    && peer.persisted.as_ref() == Some(desired)
                    && peer
                        .active
                        .as_ref()
                        .is_some_and(|ack| valid_active_ack(ack) && &ack.artifact == desired)
            })
    }

    pub(crate) fn view(&self, now: Instant, stale: Duration) -> Vec<PeerAcknowledgementView> {
        self.peers
            .iter()
            .map(|(ip, peer)| PeerAcknowledgementView {
                ip: *ip,
                persisted: peer.persisted.clone(),
                active: peer.active.clone(),
                last_ack_secs: peer
                    .last_ack
                    .and_then(|at| now.checked_duration_since(at))
                    .map(|age| age.as_secs()),
                fresh: self.available && fresh(peer.last_ack, now, stale),
            })
            .collect()
    }
}

fn fresh(at: Option<Instant>, now: Instant, stale: Duration) -> bool {
    at.and_then(|at| now.checked_duration_since(at))
        .is_some_and(|age| age <= stale)
}

fn valid_identity(identity: &ArtifactIdentity) -> bool {
    identity.policy_epoch > 0
        && is_hash(&identity.primary_lineage)
        && is_hash(&identity.artifact_hash)
        && is_hash(&identity.config_revision)
        && is_hash(&identity.operator_policy_hash)
}

pub(crate) fn valid_active_ack(ack: &ActiveArtifactAck) -> bool {
    valid_identity(&ack.artifact)
        && is_hash(&ack.local_config_revision)
        && !ack.daemon_instance_id.is_empty()
        && ack.daemon_instance_id.len() <= 256
        && ack.resolver_generation > 0
}

fn check_entries(files: &PrivateStore<'_>) -> anyhow::Result<()> {
    ensure!(
        files.names(2)?.iter().all(|name| name == STATE),
        "ArtifactAcknowledgementConflict: unexpected roster entry"
    );
    Ok(())
}

fn decode_roster(bytes: &[u8]) -> anyhow::Result<ExpectedPeers> {
    let state: ExpectedPeers = serde_json::from_slice(bytes)
        .context("ArtifactAcknowledgementConflict: invalid expected peer roster")?;
    ensure!(
        state.format == 1
            && state.peers.len() <= MAX_PEERS
            && state.peers.windows(2).all(|pair| pair[0] < pair[1]),
        "ArtifactAcknowledgementConflict: invalid expected peer roster"
    );
    Ok(state)
}

pub(crate) struct NodeAcknowledgement {
    pub persisted: Option<ArtifactIdentity>,
    pub active: Option<ActiveArtifactAck>,
    pub persisted_corpus: Option<String>,
    pub active_corpus: Option<String>,
}

/// Expected identities come exclusively from the durable controlled membership.
#[derive(Default)]
pub(crate) struct NodeAcknowledgements {
    observations: BTreeMap<String, (PeerObservation, Option<String>, Option<String>, String)>,
}
impl NodeAcknowledgements {
    pub(crate) fn forget(&mut self, node_id: &str) {
        self.observations.remove(node_id);
    }

    pub(crate) fn record(
        &mut self,
        node_id: &str,
        endpoint: String,
        acknowledgement: NodeAcknowledgement,
        now: Instant,
    ) -> anyhow::Result<()> {
        let NodeAcknowledgement {
            persisted,
            active,
            persisted_corpus,
            active_corpus,
        } = acknowledgement;
        self.observations.remove(node_id);
        ensure!(
            persisted.as_ref().is_none_or(valid_identity)
                && active.as_ref().is_none_or(valid_active_ack),
            "invalid node acknowledgement"
        );
        ensure!(
            persisted_corpus.as_deref().is_none_or(is_hash)
                && active_corpus.as_deref().is_none_or(is_hash),
            "invalid corpus acknowledgement"
        );
        self.observations.insert(
            node_id.into(),
            (
                PeerObservation {
                    persisted,
                    active,
                    last_ack: Some(now),
                },
                persisted_corpus,
                active_corpus,
                endpoint,
            ),
        );
        Ok(())
    }
    pub(crate) fn enrich(
        &self,
        roster: &mut [super::membership::MemberView],
        desired: Option<&ArtifactIdentity>,
        corpus: Option<&str>,
        now: Instant,
        stale: Duration,
    ) {
        for member in roster {
            if let Some((observation, _, active_corpus, endpoint)) =
                self.observations.get(&member.node_id)
            {
                member.endpoint = Some(endpoint.clone());
                member.last_confirmation_secs = observation
                    .last_ack
                    .map(|at| now.saturating_duration_since(at).as_secs());
                let fresh = observation
                    .last_ack
                    .is_some_and(|at| now.saturating_duration_since(at) <= stale);
                member.sync = Some(
                    if member.state == super::membership::MemberState::Revoked {
                        "revoked"
                    } else if !fresh {
                        "stale"
                    } else if desired.is_some()
                        && observation.active.as_ref().map(|ack| &ack.artifact) == desired
                        && corpus.is_some()
                        && active_corpus.as_deref() == corpus
                    {
                        "current"
                    } else {
                        "pending"
                    }
                    .into(),
                );
            }
        }
    }
    pub(crate) fn converged(
        &self,
        expected: &[super::membership::MemberView],
        desired: &ArtifactIdentity,
        corpus: Option<&str>,
        now: Instant,
        stale: Duration,
    ) -> bool {
        valid_identity(desired)
            && corpus.is_some()
            && expected
                .iter()
                .filter(|member| member.state != super::membership::MemberState::Revoked)
                .all(|member| {
                    member.state == super::membership::MemberState::Active
                        && self.observations.get(&member.node_id).is_some_and(
                            |(observation, persisted_corpus, active_corpus, _)| {
                                observation
                                    .last_ack
                                    .is_some_and(|at| now.saturating_duration_since(at) <= stale)
                                    && observation.persisted.as_ref() == Some(desired)
                                    && observation.active.as_ref().is_some_and(|ack| {
                                        valid_active_ack(ack) && &ack.artifact == desired
                                    })
                                    && corpus.is_some()
                                    && persisted_corpus.as_deref() == corpus
                                    && active_corpus.as_deref() == corpus
                            },
                        )
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_lock::acquire_for_migration;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    fn desired() -> ArtifactIdentity {
        ArtifactIdentity {
            primary_lineage: "1".repeat(64),
            policy_epoch: 7,
            artifact_hash: "2".repeat(64),
            config_revision: "3".repeat(64),
            operator_policy_hash: "4".repeat(64),
        }
    }

    fn active(identity: &ArtifactIdentity) -> ActiveArtifactAck {
        ActiveArtifactAck {
            artifact: identity.clone(),
            local_config_revision: identity.config_revision.clone(),
            daemon_instance_id: "test-daemon-instance".into(),
            resolver_generation: 11,
        }
    }

    fn confirm(
        peers: &mut PeerAcknowledgements,
        guard: &MigrationWriteLock,
        ip: IpAddr,
        now: Instant,
    ) {
        let identity = desired();
        peers
            .record(
                guard,
                ip,
                Some(identity.clone()),
                Some(active(&identity)),
                now,
            )
            .unwrap();
    }

    #[test]
    fn restart_retains_all_expected_peers_but_requires_each_to_ack_again() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        assert!(!peers.converged(&desired(), now, stale));
        confirm(&mut peers, &guard, ip(1), now);
        confirm(&mut peers, &guard, ip(2), now);
        assert!(peers.converged(&desired(), now, stale));
        {
            let files = PrivateStore::open(&guard, STORE_DIR).unwrap();
            let payload = files.read(STATE, MAX_STATE_BYTES).unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "format": 1,
                    "peers": ["192.0.2.1", "192.0.2.2"],
                })
            );
        }
        drop(peers);
        drop(guard);

        let guard = acquire_for_migration(&master).unwrap();
        let mut restored = PeerAcknowledgements::load(&guard).unwrap();
        let view = restored.view(now, stale);
        assert_eq!(
            view.iter().map(|peer| peer.ip).collect::<Vec<_>>(),
            [ip(1), ip(2)]
        );
        assert!(view.iter().all(|peer| {
            peer.persisted.is_none()
                && peer.active.is_none()
                && peer.last_ack_secs.is_none()
                && !peer.fresh
        }));
        assert!(!restored.converged(&desired(), now, stale));
        confirm(&mut restored, &guard, ip(1), now);
        assert!(!restored.converged(&desired(), now, stale));
        confirm(&mut restored, &guard, ip(2), now);
        assert!(restored.converged(&desired(), now, stale));
    }

    #[test]
    fn restart_accepts_an_ack_with_a_node_local_revision_and_converges() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        confirm(&mut peers, &guard, ip(1), now);
        drop(peers);

        let mut restarted = PeerAcknowledgements::load(&guard).unwrap();
        let mut mismatched = active(&desired());
        mismatched.local_config_revision = "5".repeat(64);
        restarted
            .record(
                &guard,
                ip(1),
                Some(desired()),
                Some(mismatched.clone()),
                now,
            )
            .unwrap();
        assert!(restarted.converged(&desired(), now, stale));
        let view = restarted.view(now, stale);
        assert_eq!(view[0].active, Some(mismatched));
        assert!(view[0].fresh);
    }

    #[test]
    fn missing_active_ack_invalidates_previous_success_and_expiry_preserves_history() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        confirm(&mut peers, &guard, ip(1), now);
        assert!(peers.converged(&desired(), now + stale, stale));
        let expired = now + stale + Duration::from_nanos(1);
        assert!(!peers.converged(&desired(), expired, stale));
        let view = peers.view(expired, stale);
        assert_eq!(view[0].persisted.as_ref(), Some(&desired()));
        assert_eq!(view[0].active.as_ref(), Some(&active(&desired())));
        assert_eq!(view[0].last_ack_secs, Some(45));
        assert!(!view[0].fresh);
        assert!(!peers.converged(&desired(), now - Duration::from_nanos(1), stale));

        peers
            .record(&guard, ip(1), Some(desired()), None, expired)
            .unwrap();
        assert!(!peers.converged(&desired(), expired, stale));
        assert!(peers.view(expired, stale)[0].last_ack_secs.is_none());
        confirm(&mut peers, &guard, ip(1), expired);
        assert!(peers.converged(&desired(), expired, stale));
    }

    #[test]
    fn persisted_and_active_must_match_every_desired_identity_component() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        for field in 0..5 {
            let mut other = desired();
            match field {
                0 => other.primary_lineage = "a".repeat(64),
                1 => other.policy_epoch += 1,
                2 => other.artifact_hash = "b".repeat(64),
                3 => other.config_revision = "c".repeat(64),
                _ => other.operator_policy_hash = "d".repeat(64),
            }
            peers
                .record(
                    &guard,
                    ip(1),
                    Some(other.clone()),
                    Some(active(&desired())),
                    now,
                )
                .unwrap();
            assert!(!peers.converged(&desired(), now, stale));
            peers
                .record(&guard, ip(1), Some(desired()), Some(active(&other)), now)
                .unwrap();
            assert!(!peers.converged(&desired(), now, stale));
        }
        peers
            .record(&guard, ip(1), None, Some(active(&desired())), now)
            .unwrap();
        assert!(!peers.converged(&desired(), now, stale));
        confirm(&mut peers, &guard, ip(1), now);
        assert!(peers.converged(&desired(), now, stale));
        let mut invalid_desired = desired();
        invalid_desired.policy_epoch = 0;
        assert!(!peers.converged(&invalid_desired, now, stale));
    }

    #[test]
    fn invalid_active_metadata_clears_prior_success_and_can_recover() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        for field in 0..6 {
            confirm(&mut peers, &guard, ip(1), now);
            let mut bad = active(&desired());
            match field {
                0 => bad.local_config_revision = "invalid".into(),
                1 => bad.daemon_instance_id.clear(),
                2 => bad.daemon_instance_id = "x".repeat(257),
                3 => bad.resolver_generation = 0,
                4 => bad.artifact.policy_epoch = 0,
                _ => bad.artifact.artifact_hash = "G".repeat(64),
            }
            assert!(peers
                .record(&guard, ip(1), Some(desired()), Some(bad), now)
                .is_err());
            assert!(!peers.converged(&desired(), now, stale));
            assert!(peers.view(now, stale)[0].active.is_none());
        }
        confirm(&mut peers, &guard, ip(1), now);
        assert!(peers.converged(&desired(), now, stale));
        let mut invalid_persisted = desired();
        invalid_persisted.config_revision = "invalid".into();
        assert!(peers
            .record(&guard, ip(1), Some(invalid_persisted), None, now)
            .is_err());
        assert!(!peers.converged(&desired(), now, stale));
        assert!(peers.view(now, stale)[0].persisted.is_none());
    }

    #[test]
    fn a_peer_without_an_ack_is_durable_and_prevents_partial_convergence() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        confirm(&mut peers, &guard, ip(1), now);
        peers.record(&guard, ip(2), None, None, now).unwrap();
        assert!(!peers.converged(&desired(), now, stale));
        let view = PeerAcknowledgements::load(&guard).unwrap().view(now, stale);
        assert_eq!(view.len(), 2);
        assert!(view[1].active.is_none());
        confirm(&mut peers, &guard, ip(2), now);
        assert!(peers.converged(&desired(), now, stale));
    }

    #[test]
    fn stale_handles_merge_new_expected_peers_without_losing_roster_members() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut first = PeerAcknowledgements::load(&guard).unwrap();
        let mut second = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        confirm(&mut first, &guard, ip(1), now);
        confirm(&mut second, &guard, ip(2), now);
        assert!(!second.converged(&desired(), now, stale));
        confirm(&mut first, &guard, ip(1), now);
        assert!(!first.converged(&desired(), now, stale));
        assert_eq!(first.view(now, stale).len(), 2);
        confirm(&mut first, &guard, ip(2), now);
        assert!(first.converged(&desired(), now, stale));
        assert_eq!(
            PeerAcknowledgements::load(&guard)
                .unwrap()
                .view(now, stale)
                .len(),
            2
        );
    }

    #[test]
    fn a_foreign_tree_guard_cannot_update_or_reuse_the_roster() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let foreign = acquire_for_migration(&other.path().join("config.toml")).unwrap();
        let now = Instant::now();
        let stale = Duration::from_secs(45);
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        confirm(&mut peers, &guard, ip(1), now);
        assert!(peers.record(&foreign, ip(1), None, None, now).is_err());
        assert!(!peers.converged(&desired(), now, stale));
        assert!(PeerAcknowledgements::load(&foreign)
            .unwrap()
            .view(now, stale)
            .is_empty());
        confirm(&mut peers, &guard, ip(1), now);
        assert!(peers.converged(&desired(), now, stale));
    }

    #[test]
    fn full_roster_refuses_admission_without_evicting_an_expected_peer() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        PeerAcknowledgements::load(&guard).unwrap();
        {
            let files = PrivateStore::open(&guard, STORE_DIR).unwrap();
            let expected = ExpectedPeers {
                format: 1,
                peers: (1..=64).map(ip).collect(),
            };
            files
                .write(STATE, &serde_json::to_vec(&expected).unwrap())
                .unwrap();
        }
        let mut peers = PeerAcknowledgements::load(&guard).unwrap();
        let now = Instant::now();
        assert!(peers.record(&guard, ip(65), None, None, now).is_err());
        let restored = PeerAcknowledgements::load(&guard).unwrap();
        let view = restored.view(now, Duration::from_secs(45));
        assert_eq!(view.len(), 64);
        assert_eq!(view.first().unwrap().ip, ip(1));
        assert_eq!(view.last().unwrap().ip, ip(64));
    }

    #[test]
    fn malformed_duplicate_or_oversized_durable_rosters_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let files = PrivateStore::open(&guard, STORE_DIR).unwrap();
        let oversized = serde_json::to_vec(&ExpectedPeers {
            format: 1,
            peers: (1..=65).map(ip).collect(),
        })
        .unwrap();
        drop(files);
        for bytes in [
            br#"{"format":2,"peers":[]}"#.to_vec(),
            br#"{"format":1,"peers":["192.0.2.1","192.0.2.1"]}"#.to_vec(),
            br#"{"format":1,"peers":["192.0.2.2","192.0.2.1"]}"#.to_vec(),
            br#"{"format":1,"peers":[],"active":true}"#.to_vec(),
            oversized,
        ] {
            {
                let files = PrivateStore::open(&guard, STORE_DIR).unwrap();
                files.write(STATE, &bytes).unwrap();
            }
            assert!(PeerAcknowledgements::load(&guard).is_err());
        }
    }
}

#[cfg(test)]
mod node_tests {
    use super::super::membership::{random_id, MemberState, MemberView};
    use super::*;
    #[test]
    fn node_acknowledgements_require_each_enrolled_identity_even_behind_one_address() {
        let desired = ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        let active = ActiveArtifactAck {
            artifact: desired.clone(),
            local_config_revision: "e".repeat(64),
            daemon_instance_id: "instance".into(),
            resolver_generation: 1,
        };
        let mut roster = (0..2)
            .map(|_| MemberView {
                node_id: random_id(),
                name: "duplicate".into(),
                state: MemberState::Active,
                admitted_at: 1,
                expires_at: None,
                endpoint: None,
                sync: None,
                last_confirmation_secs: None,
                fingerprint: None,
            })
            .collect::<Vec<_>>();
        let mut acks = NodeAcknowledgements::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(45);
        let corpus = "f".repeat(64);
        acks.record(
            &roster[0].node_id,
            "192.0.2.1:8053".into(),
            NodeAcknowledgement {
                persisted: Some(desired.clone()),
                active: Some(active.clone()),
                persisted_corpus: Some(corpus.clone()),
                active_corpus: Some(corpus.clone()),
            },
            now,
        )
        .unwrap();
        assert!(!acks.converged(&roster, &desired, Some(&corpus), now, ttl));
        acks.record(
            &roster[1].node_id,
            "192.0.2.1:8053".into(),
            NodeAcknowledgement {
                persisted: Some(desired.clone()),
                active: Some(active),
                persisted_corpus: Some(corpus.clone()),
                active_corpus: Some(corpus.clone()),
            },
            now,
        )
        .unwrap();
        assert!(acks.converged(&roster, &desired, Some(&corpus), now, ttl));
        assert!(!acks.converged(
            &roster,
            &desired,
            Some(&corpus),
            now + ttl + Duration::from_secs(1),
            ttl
        ));
        roster[1].state = MemberState::Pending;
        assert!(!acks.converged(&roster, &desired, Some(&corpus), now, ttl));
        roster[1].state = MemberState::Revoked;
        assert!(acks.converged(&roster, &desired, Some(&corpus), now, ttl));
        assert!(!NodeAcknowledgements::default().converged(
            &roster,
            &desired,
            Some(&corpus),
            now,
            ttl
        ));
    }
}
