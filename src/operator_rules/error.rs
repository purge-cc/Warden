use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedContract,
    InvalidRequest,
    InvalidId,
    InvalidRule,
    SchemaUpgradeRequired,
    PolicyOwnedByPrimary,
    NotFound,
    AlreadyExists,
    ListMounted,
    RevisionConflict,
    RowConflict,
    PlanConflict,
    IdempotencyConflict,
    StaleCursor,
    TransportLimitExceeded,
    BudgetExceeded,
    UnsafePath,
    TreeChanged,
    StorageUnavailable,
    RecoveryRequired,
    RecoveryConflict,
    AdmissionRejected,
    ValidationFailed,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedContract => "unsupported_contract",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidId => "invalid_id",
            Self::InvalidRule => "invalid_rule",
            Self::SchemaUpgradeRequired => "schema_upgrade_required",
            Self::PolicyOwnedByPrimary => "policy_owned_by_primary",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::ListMounted => "list_mounted",
            Self::RevisionConflict => "revision_conflict",
            Self::RowConflict => "row_conflict",
            Self::PlanConflict => "plan_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::StaleCursor => "stale_cursor",
            Self::TransportLimitExceeded => "transport_limit_exceeded",
            Self::BudgetExceeded => "budget_exceeded",
            Self::UnsafePath => "unsafe_path",
            Self::TreeChanged => "tree_changed",
            Self::StorageUnavailable => "storage_unavailable",
            Self::RecoveryRequired => "recovery_required",
            Self::RecoveryConflict => "recovery_conflict",
            Self::AdmissionRejected => "admission_rejected",
            Self::ValidationFailed => "validation_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[error("{code:?}: {message}")]
pub struct OperatorRulesError {
    pub code: ErrorCode,
    pub message: String,
}
impl OperatorRulesError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub(crate) fn storage(error: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::StorageUnavailable, format!("{error:#}"))
    }
}
