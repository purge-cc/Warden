//! Atomically advertised policy identity after durable object publication.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use arc_swap::ArcSwap;

use crate::config::cidr::Cidr;
use crate::config::schema::ClusterRole;
use crate::config::write_lock::MigrationWriteLock;

use super::artifact::PolicySnapshot;
use super::manifest::Manifest;
use super::publication::PublicationStore;
use crate::operator_rules::activation::ActivePolicyIdentity;

#[derive(Default)]
pub struct PolicyArtifact {
    pub toml: String,
    pub hash: String,
    pub config_generation: u64,
    pub(crate) epoch: u64,
    #[cfg(test)]
    pub(crate) snapshot: Option<Arc<PolicySnapshot>>,
    pub(crate) manifest: Option<Arc<Manifest>>,
}

pub(crate) struct PreparedPolicyArtifact {
    artifact: Arc<PolicyArtifact>,
}

pub(crate) struct MembershipContext {
    pub master: PathBuf,
    pub cluster_id: String,
    pub primary_node_id: String,
    pub acknowledgements: Mutex<super::acknowledgement::NodeAcknowledgements>,
}

struct ObservedMembership {
    roster: Vec<super::membership::MemberView>,
    observed: std::time::Instant,
}

/// Boot identity is immutable; each advertised policy is a complete capture.
pub struct ClusterState {
    pub role: ClusterRole,
    pub priority: u32,
    pub token_hash: String,
    pub allow_peer: Vec<Cidr>,
    membership: Option<MembershipContext>,
    corpus: Option<Arc<super::corpus::CorpusStore>>,
    policy: ArcSwap<PolicyArtifact>,
    primary_active: arc_swap::ArcSwapOption<ActivePolicyIdentity>,
    primary_corpus: arc_swap::ArcSwapOption<(super::dto::ArtifactIdentity, String)>,
    membership_roster: arc_swap::ArcSwapOption<ObservedMembership>,
    peers: Mutex<Option<super::acknowledgement::PeerAcknowledgements>>,
}

impl ClusterState {
    #[must_use]
    pub fn new(
        role: ClusterRole,
        priority: u32,
        token_hash: String,
        allow_peer: Vec<Cidr>,
    ) -> Self {
        Self {
            role,
            priority,
            token_hash,
            allow_peer,
            membership: None,
            corpus: None,
            policy: ArcSwap::from_pointee(PolicyArtifact::default()),
            primary_active: arc_swap::ArcSwapOption::empty(),
            primary_corpus: arc_swap::ArcSwapOption::empty(),
            membership_roster: arc_swap::ArcSwapOption::empty(),
            peers: Mutex::new(None),
        }
    }

    pub(crate) fn configure_membership(
        &mut self,
        master: PathBuf,
        cluster_id: String,
        primary_node_id: String,
    ) -> anyhow::Result<()> {
        self.corpus = Some(Arc::new(super::corpus::CorpusStore::open(&master)?));
        self.membership = Some(MembershipContext {
            master,
            cluster_id,
            primary_node_id,
            acknowledgements: Mutex::default(),
        });
        Ok(())
    }

    pub(crate) fn membership_context(&self) -> Option<&MembershipContext> {
        self.membership.as_ref()
    }

    pub(crate) fn corpus_store(&self) -> Option<&Arc<super::corpus::CorpusStore>> {
        self.corpus.as_ref()
    }

    pub(crate) fn set_primary_active_pair(
        &self,
        policy: super::dto::ArtifactIdentity,
        corpus: String,
    ) {
        self.primary_corpus.store(Some(Arc::new((policy, corpus))));
    }

    pub(crate) fn clear_primary_active_pair(&self) {
        self.primary_corpus.store(None);
    }

    pub(crate) fn record_membership_roster(&self, roster: Vec<super::membership::MemberView>) {
        self.membership_roster
            .store(Some(Arc::new(ObservedMembership {
                roster,
                observed: std::time::Instant::now(),
            })));
    }

    pub(crate) fn primary_pair_matches(
        &self,
        policy: &super::dto::ArtifactIdentity,
        corpus: Option<&str>,
    ) -> bool {
        self.primary_active_matches(policy)
            && self
                .primary_corpus
                .load()
                .as_ref()
                .is_some_and(|pair| &pair.0 == policy && corpus == Some(pair.1.as_str()))
    }

    /// Record the identity already swapped into the primary's local resolver.
    ///
    /// Publication follows that swap. This separate control-plane identity
    /// prevents a publication failure from certifying acknowledgements for the
    /// last advertised artifact as convergence of the newly active policy.
    pub(crate) fn set_primary_active_identity(&self, identity: ActivePolicyIdentity) {
        self.primary_active.store(Some(Arc::new(identity)));
    }

    /// Persist and validate a capture without advertising it as active.
    pub(crate) fn prepare_policy(
        &self,
        guard: &MigrationWriteLock,
        snapshot: Arc<PolicySnapshot>,
    ) -> anyhow::Result<PreparedPolicyArtifact> {
        {
            let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
            if peers.is_none() {
                *peers = Some(super::acknowledgement::PeerAcknowledgements::load(guard)?);
            }
        }
        let mut store = PublicationStore::open(guard)?;
        store.gc(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs())?;
        let current = store.current()?;
        let published = match current {
            Some(current) if current.reservation.config_revision == snapshot.config_revision() => {
                current
            }
            _ => {
                anyhow::ensure!(!store.pending_intents()?.iter().any(|(reservation,_)|
                    reservation.config_revision == snapshot.config_revision()),
                    "ArtifactPublicationPending: captured revision has an unresolved transaction intent");
                store.publish_capture(
                    |lineage, epoch| snapshot.publication(lineage, epoch),
                    &format!("capture:{}", snapshot.config_revision()),
                )?;
                store.current()?.context("committed artifact is absent")?
            }
        };
        let manifest = Manifest::decode(&published.manifest)?;
        tracing::debug!(receipt_id = %published.receipt_id, policy_epoch = manifest.policy_epoch,
            "prepared captured cluster artifact");
        anyhow::ensure!(
            manifest.operator_policy_hash == snapshot.operator_policy_hash()
                && manifest.policy_toml == super::manifest::ObjectRef::of(snapshot.toml()),
            "ArtifactSnapshotMismatch: publication disagrees with capture"
        );
        let artifact = PolicyArtifact {
            toml: std::str::from_utf8(snapshot.toml())?.to_owned(),
            hash: manifest.artifact_hash.clone(),
            config_generation: self
                .policy
                .load()
                .config_generation
                .checked_add(1)
                .context("cluster generation exhausted")?,
            epoch: manifest.policy_epoch,
            #[cfg(test)]
            snapshot: Some(snapshot),
            manifest: Some(Arc::new(manifest)),
        };
        store.gc(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs())?;
        if let Some(corpus) = &self.corpus {
            corpus.retain_policy_artifacts(&store.retained_artifact_hashes())?;
        }
        Ok(PreparedPolicyArtifact {
            artifact: Arc::new(artifact),
        })
    }

    /// Make a durably prepared capture active and advertised to peers.
    pub(crate) fn install_policy(&self, prepared: PreparedPolicyArtifact) {
        self.policy.store(prepared.artifact);
    }

    /// Persist a capture before making it active and advertised to peers.
    /// This control-plane writer consumes captured bytes and never opens packs.
    pub(crate) fn update_policy(
        &self,
        guard: &MigrationWriteLock,
        snapshot: Arc<PolicySnapshot>,
    ) -> anyhow::Result<()> {
        let prepared = self.prepare_policy(guard, snapshot)?;
        self.install_policy(prepared);
        Ok(())
    }

    #[must_use]
    pub fn config_generation(&self) -> u64 {
        self.policy.load().config_generation
    }

    #[must_use]
    pub fn policy(&self) -> Arc<PolicyArtifact> {
        self.policy.load_full()
    }

    pub(crate) fn acknowledge(
        &self,
        guard: &MigrationWriteLock,
        ip: std::net::IpAddr,
        persisted: Option<super::dto::ArtifactIdentity>,
        active: Option<super::dto::ActiveArtifactAck>,
        now: std::time::Instant,
    ) -> anyhow::Result<()> {
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        if peers.is_none() {
            *peers = Some(super::acknowledgement::PeerAcknowledgements::load(guard)?);
        }
        peers
            .as_mut()
            .unwrap()
            .record(guard, ip, persisted, active, now)
    }

    pub(crate) fn converged_for(
        &self,
        desired: &super::dto::ArtifactIdentity,
        now: std::time::Instant,
        stale: std::time::Duration,
    ) -> bool {
        if let Some(context) = &self.membership {
            let Some(roster) = self.membership_roster.load_full() else {
                return false;
            };
            let Some(pair) = self.primary_corpus.load_full() else {
                return false;
            };
            return now.saturating_duration_since(roster.observed) <= stale
                && self.primary_pair_matches(desired, Some(&pair.1))
                && context
                    .acknowledgements
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .converged(&roster.roster, desired, Some(&pair.1), now, stale);
        }
        self.primary_active_matches(desired)
            && self
                .peers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_some_and(|peers| peers.converged(desired, now, stale))
    }

    pub(crate) fn primary_active_matches(&self, desired: &super::dto::ArtifactIdentity) -> bool {
        self.primary_active.load_full().is_some_and(|active| {
            active.is_known()
                && super::manifest::is_hash(&active.config_revision)
                && super::manifest::is_hash(&active.operator_policy_hash)
                && active.config_revision == desired.config_revision
                && active.operator_policy_hash == desired.operator_policy_hash
        })
    }

    pub(crate) fn peer_acknowledgements(
        &self,
        now: std::time::Instant,
        stale: std::time::Duration,
    ) -> Vec<super::acknowledgement::PeerAcknowledgementView> {
        self.peers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map_or_else(Vec::new, |peers| peers.view(now, stale))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_convergence_requires_fresh_roster_and_live_corpus_proof() {
        let root = tempfile::tempdir().unwrap();
        let mut state = ClusterState::new(ClusterRole::Primary, 1, String::new(), Vec::new());
        state
            .configure_membership(
                root.path().join("config.toml"),
                "cluster".into(),
                "primary".into(),
            )
            .unwrap();
        let desired = super::super::dto::ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        };
        state.set_primary_active_identity(ActivePolicyIdentity {
            daemon_instance_id: "instance".into(),
            config_revision: desired.config_revision.clone(),
            operator_policy_hash: desired.operator_policy_hash.clone(),
            resolver_generation: 1,
        });
        state.set_primary_active_pair(desired.clone(), "e".repeat(64));
        let stale = std::time::Duration::from_secs(45);
        assert!(!state.converged_for(&desired, std::time::Instant::now(), stale));
        state.record_membership_roster(Vec::new());
        assert!(state.converged_for(&desired, std::time::Instant::now(), stale));
        assert!(!state.converged_for(&desired, std::time::Instant::now() + stale * 2, stale));
        state.clear_primary_active_pair();
        assert!(!state.converged_for(&desired, std::time::Instant::now(), stale));
        state.set_primary_active_pair(desired.clone(), "e".repeat(64));
        state.record_membership_roster(vec![super::super::membership::MemberView {
            node_id: "secondary".into(),
            name: "same name".into(),
            state: super::super::membership::MemberState::Active,
            admitted_at: 1,
            expires_at: None,
            endpoint: None,
            sync: None,
            last_confirmation_secs: None,
            fingerprint: None,
        }]);
        assert!(!state.converged_for(&desired, std::time::Instant::now(), stale));
    }
    use crate::config::write_lock::acquire_for_migration;
    use crate::config::{loader, policy_revision};
    use crate::operator_rules::activation::ActivePolicyIdentity;
    use std::path::Path;

    fn snapshot(master: &Path) -> Arc<PolicySnapshot> {
        let guard = acquire_for_migration(master).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
            &guard, master, now, None, None,
        )
        .unwrap();
        let (revision, loaded) =
            policy_revision::capture_coherent_loaded_v5_under_migration_guard(&guard, &loaded, now)
                .unwrap();
        Arc::new(
            PolicySnapshot::from_target_v5(
                &loaded.config,
                &loaded.pack_bodies,
                revision.revision().to_string(),
            )
            .unwrap(),
        )
    }

    fn active(snapshot: &PolicySnapshot) -> ActivePolicyIdentity {
        ActivePolicyIdentity {
            daemon_instance_id: "primary-test".into(),
            config_revision: snapshot.config_revision().to_owned(),
            operator_policy_hash: snapshot.operator_policy_hash().to_owned(),
            resolver_generation: 1,
        }
    }

    fn acknowledgement(
        artifact: super::super::dto::ArtifactIdentity,
    ) -> super::super::dto::ActiveArtifactAck {
        super::super::dto::ActiveArtifactAck {
            local_config_revision: artifact.config_revision.clone(),
            artifact,
            daemon_instance_id: "secondary-test".into(),
            resolver_generation: 1,
        }
    }

    #[test]
    fn epoch_survives_restart_and_pack_capture_survives_disk_edit() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        std::fs::create_dir(root.path().join("packs")).unwrap();
        std::fs::write(&master,"schema_version=5\n[[custom_lists]]\nid='rules'\n[profiles.home]\ncustom_lists=['rules']\n[server]\ndefault_profile='home'\n[upstream]\nservers=['192.0.2.1:53']\n").unwrap();
        let pack = root.path().join("packs/rules.txt");
        std::fs::write(&pack, "||before.example^\n").unwrap();
        let captured = snapshot(&master);
        std::fs::write(&pack, "||after.example^\n").unwrap();
        let state = ClusterState::new(ClusterRole::Primary, 1, "a".repeat(64), Vec::new());
        state
            .update_policy(
                &acquire_for_migration(&master).unwrap(),
                Arc::clone(&captured),
            )
            .unwrap();
        assert!(Arc::ptr_eq(
            state.policy().snapshot.as_ref().unwrap(),
            &captured
        ));
        let old = state.policy();
        state
            .update_policy(
                &acquire_for_migration(&master).unwrap(),
                Arc::clone(&captured),
            )
            .unwrap();
        assert_eq!(state.config_generation(), 2);
        assert_eq!(state.policy().epoch, old.epoch);
        assert_eq!(state.policy().hash, old.hash);
        let restarted = ClusterState::new(ClusterRole::Primary, 1, "a".repeat(64), Vec::new());
        restarted
            .update_policy(&acquire_for_migration(&master).unwrap(), captured)
            .unwrap();
        assert_eq!(restarted.policy().hash, old.hash);
        assert_eq!(restarted.policy().epoch, old.epoch);
        let fresh = snapshot(&master);
        restarted
            .update_policy(&acquire_for_migration(&master).unwrap(), fresh)
            .unwrap();
        assert!(restarted.policy().epoch > old.epoch);
        assert_eq!(restarted.config_generation(), 2);
        assert_ne!(restarted.policy().hash, old.hash);
        assert_ne!(
            restarted.policy().manifest.as_ref().unwrap().artifact_hash,
            old.manifest.as_ref().unwrap().artifact_hash
        );
        assert_ne!(
            restarted
                .policy()
                .snapshot
                .as_ref()
                .unwrap()
                .operator_policy_hash(),
            old.snapshot.as_ref().unwrap().operator_policy_hash()
        );
    }

    #[test]
    fn prepared_policy_is_not_advertised_until_install() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        std::fs::create_dir(root.path().join("packs")).unwrap();
        std::fs::write(&master, "schema_version=5\n[[custom_lists]]\nid='rules'\n[profiles.home]\ncustom_lists=['rules']\n[server]\ndefault_profile='home'\n[upstream]\nservers=['192.0.2.1:53']\n").unwrap();
        std::fs::write(root.path().join("packs/rules.txt"), "||blocked.example^\n").unwrap();
        let snapshot = snapshot(&master);
        let state = ClusterState::new(ClusterRole::Primary, 1, "a".repeat(64), Vec::new());

        let prepared = state
            .prepare_policy(
                &acquire_for_migration(&master).unwrap(),
                Arc::clone(&snapshot),
            )
            .unwrap();
        assert!(state.policy().manifest.is_none());
        assert_eq!(state.config_generation(), 0);

        state.install_policy(prepared);
        assert!(Arc::ptr_eq(
            state.policy().snapshot.as_ref().unwrap(),
            &snapshot
        ));
        assert_eq!(state.config_generation(), 1);
    }

    #[test]
    fn failed_publication_after_primary_swap_invalidates_fresh_old_acknowledgements() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        std::fs::create_dir(root.path().join("packs")).unwrap();
        std::fs::write(&master, "schema_version=5\n[[custom_lists]]\nid='rules'\n[profiles.home]\ncustom_lists=['rules']\n[server]\ndefault_profile='home'\n[upstream]\nservers=['192.0.2.1:53']\n").unwrap();
        let pack = root.path().join("packs/rules.txt");
        std::fs::write(&pack, "||old.example^\n").unwrap();
        let old = snapshot(&master);
        let state = ClusterState::new(ClusterRole::Primary, 1, "a".repeat(64), Vec::new());
        let (desired, now) = {
            let guard = acquire_for_migration(&master).unwrap();
            state.update_policy(&guard, Arc::clone(&old)).unwrap();
            state.set_primary_active_identity(active(&old));
            let desired = super::super::dto::ArtifactIdentity::from(
                state.policy().manifest.as_deref().unwrap(),
            );
            let now = std::time::Instant::now();
            state
                .acknowledge(
                    &guard,
                    "192.0.2.1".parse().unwrap(),
                    Some(desired.clone()),
                    Some(acknowledgement(desired.clone())),
                    now,
                )
                .unwrap();
            assert!(state.converged_for(&desired, now, std::time::Duration::from_secs(45)));
            (desired, now)
        };

        std::fs::write(&pack, "||new.example^\n").unwrap();
        let new = snapshot(&master);
        state.set_primary_active_identity(active(&new));
        super::super::publication::fail_next_publication_for_test();
        let guard = acquire_for_migration(&master).unwrap();
        assert!(state.update_policy(&guard, new).is_err());

        assert_eq!(
            state.policy().manifest.as_ref().unwrap().config_revision,
            desired.config_revision
        );
        assert!(state.peer_acknowledgements(now, std::time::Duration::from_secs(45))[0].fresh);
        assert!(
            !state.converged_for(&desired, now, std::time::Duration::from_secs(45)),
            "fresh acknowledgements for the advertised artifact cannot converge after the primary swapped a different policy"
        );
    }
}
