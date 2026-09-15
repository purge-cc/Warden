//! Versioned operator-policy control plane shared by local and remote adapters.
pub mod activation;
pub mod dto;
pub mod error;
mod plan;
mod semantic;
mod service;
pub use dto::*;
pub use error::{ErrorCode, OperatorRulesError};
pub(crate) use semantic::{
    diff_policy_inventories, hash_policy_inventory, hash_schema4_migration_snapshot,
};
pub use semantic::{
    hash_policy_candidate, hash_profile_policy_candidate, OperatorPolicyHash, RuleClass, RuleDelta,
    RuleDeltaKind, SemanticDiff, SemanticDiffEntry, SemanticError, SemanticPack,
};
pub use service::OperatorRulesService;
pub(crate) use service::{PolicyCandidateRuntime, VerifiedPolicyCandidate};
