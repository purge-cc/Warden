use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Identity of the operator policy published by one resolver generation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivePolicyIdentity {
    pub daemon_instance_id: String,
    pub config_revision: String,
    pub operator_policy_hash: String,
    pub resolver_generation: u64,
}

impl ActivePolicyIdentity {
    pub fn is_known(&self) -> bool {
        !self.daemon_instance_id.is_empty()
            && !self.config_revision.is_empty()
            && !self.operator_policy_hash.is_empty()
            && self.resolver_generation != 0
    }
}

/// A committed operation asking the daemon to publish an exact disk revision.
pub(crate) struct ActivationRequest {
    pub(crate) operation_id: String,
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) correlation_id: String,
    pub(crate) expected_config_revision: String,
    pub(crate) expected_policy_hash: String,
    pub(crate) completion: oneshot::Sender<ActivationResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivationResult {
    Applied(ActivePolicyIdentity),
    Superseded {
        active: ActivePolicyIdentity,
        superseding_operation_id: Option<String>,
    },
    Rejected {
        active: Option<ActivePolicyIdentity>,
        reason: String,
    },
    Unknown {
        active: Option<ActivePolicyIdentity>,
        reason: String,
    },
}

pub(crate) fn new_correlation_id() -> anyhow::Result<String> {
    random_id("reload correlation")
}

pub(crate) fn new_daemon_instance_id() -> anyhow::Result<String> {
    random_id("daemon instance")
}

fn random_id(label: &str) -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| anyhow::anyhow!("{label} identity entropy: {error}"))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_opaque_and_fixed_width() {
        for id in [
            new_correlation_id().unwrap(),
            new_daemon_instance_id().unwrap(),
        ] {
            assert_eq!(id.len(), 32);
            assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn identity_requires_every_publication_component() {
        assert!(!ActivePolicyIdentity::default().is_known());
        assert!(ActivePolicyIdentity {
            daemon_instance_id: "d".repeat(32),
            config_revision: "a".repeat(64),
            operator_policy_hash: "b".repeat(64),
            resolver_generation: 1,
        }
        .is_known());
    }
}
