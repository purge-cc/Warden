//! Shared cluster serve-state (CS4) — the generation, content hash, and the
//! pre-serialised policy bundle the `/api/cluster/*` handlers return.
//!
//! One `Arc<ClusterState>` is shared between the readers (the API handlers + the
//! cluster auth middleware) and the writer: the reload path calls
//! [`ClusterState::update_policy`] (bumps `config_generation` every reload).
//! The Tier-1 domain map is deliberately NOT here — it is not replicated (see
//! `_docs/features/cluster_sync_policy_only.md` §3). Boot-time identity
//! (`role` / `priority` / `token_hash` / `allow_peer`) is captured once at
//! construction and never mutated — a live flip needs a restart in §4.11-2.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::cidr::Cidr;
use crate::config::schema::{ClusterRole, ConfigV1};

use super::policy::ClusterPolicyBundle;

/// The serialised policy bundle + its content hash (CS4). Recomputed on every
/// successful reload.
#[derive(Default)]
pub struct PolicyArtifact {
    pub toml: String,
    pub hash: String,
}

/// Shared cluster serve-state. Construct once at boot when
/// `cluster.enabled && role == primary && api.enabled`.
pub struct ClusterState {
    // ── boot identity (immutable after construction) ──
    /// This node's role. Mounting only happens for `Primary`, but the value is
    /// echoed in heartbeat/status responses.
    pub role: ClusterRole,
    /// Split-brain tiebreak (Phase 2); echoed to peers now.
    pub priority: u32,
    /// SHA-256 hex of the cluster bearer token (CS2) — DISTINCT from the API
    /// token. Verified constant-time by the cluster auth middleware.
    pub token_hash: String,
    /// Optional `allow_peer` CIDR gate (CS2 defence-in-depth), already parsed.
    /// Empty ⇒ no source-IP restriction on `/api/cluster/*`.
    pub allow_peer: Vec<Cidr>,

    // ── live artifacts ──
    config_generation: AtomicU64,
    policy: ArcSwap<PolicyArtifact>,
}

impl ClusterState {
    /// Build from the loaded `[cluster]` config. `allow_peer` is the
    /// already-parsed CIDR set (the validator guarantees each entry parses).
    /// Generations start at 0; the boot-time [`Self::update_policy`] seed takes
    /// `config_generation` to 1.
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
            config_generation: AtomicU64::new(0),
            policy: ArcSwap::from_pointee(PolicyArtifact::default()),
        }
    }

    // ── writers ──

    /// Re-serialise the policy bundle and bump `config_generation`.
    ///
    /// Called on every successful reload (CS4: the counter bumps every reload;
    /// the hash only changes on real content change). On a serialise error the
    /// previous artifact keeps serving and the generation is **not** bumped.
    pub fn update_policy(&self, config: &ConfigV1) {
        let bundle = ClusterPolicyBundle::from_config(config);
        match bundle.to_toml() {
            Ok(toml) => {
                let hash = ClusterPolicyBundle::hash_of(&toml);
                self.policy.store(Arc::new(PolicyArtifact { toml, hash }));
                let generation = self.config_generation.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::info!(
                    config_generation = generation,
                    "cluster policy artifact updated"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "cluster policy serialise failed; serving previous bundle"
                );
            }
        }
    }

    // ── readers ──

    #[must_use]
    pub fn config_generation(&self) -> u64 {
        self.config_generation.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn policy(&self) -> Arc<PolicyArtifact> {
        self.policy.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ClusterState {
        ClusterState::new(ClusterRole::Primary, 1, "a".repeat(64), Vec::new())
    }

    fn config() -> ConfigV1 {
        ConfigV1 {
            schema_version: 3,
            ..Default::default()
        }
    }

    #[test]
    fn config_generation_bumps_every_update() {
        let s = state();
        assert_eq!(s.config_generation(), 0);
        s.update_policy(&config());
        assert_eq!(s.config_generation(), 1);
        // Same content ⇒ counter still bumps (within-process convenience), hash
        // unchanged (the cross-restart signal).
        let h1 = s.policy().hash.clone();
        s.update_policy(&config());
        assert_eq!(s.config_generation(), 2);
        assert_eq!(s.policy().hash, h1);
    }
}
