use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ipc::protocol::ProfileUpdatePatch;
use crate::operator_rules::{BatchRequest, ErrorCode, Operation, PersistenceState, PlanSummary};
use crate::private_store::PrivateStore;

use super::adapter::{AdapterError, AdapterErrorKind, RetainedPlan};
use super::controller::PolicyOrigin;

const STORE: &str = ".warden-tui-uor";
const ENTRY: &str = "recovery.json";
const FORMAT: u32 = 1;
const MAX_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfilePrefix {
    pub(crate) profile_id: String,
    pub(crate) patch: ProfileUpdatePatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyEnvelope {
    pub(super) plan_ref: String,
    pub(super) plan_hash: String,
    pub(super) request_id: String,
    pub(super) summary: PlanSummary,
}

impl ApplyEnvelope {
    pub(super) fn from_plan(plan: &RetainedPlan) -> Self {
        Self {
            plan_ref: plan.plan_ref.clone(),
            plan_hash: plan.summary.plan_hash.clone(),
            request_id: plan.request_id.clone(),
            summary: plan.summary.clone(),
        }
    }

    pub(super) fn retained_plan(&self) -> RetainedPlan {
        RetainedPlan {
            plan_ref: self.plan_ref.clone(),
            request_id: self.request_id.clone(),
            summary: self.summary.clone(),
            impact_rows: Vec::new(),
            next_impact_cursor: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum JournalState {
    Empty,
    PropertyPending {
        origin: PolicyOrigin,
        operations: Vec<Operation>,
        prefix: ProfilePrefix,
    },
    PropertyCommitted {
        origin: PolicyOrigin,
        operations: Vec<Operation>,
        prefix: ProfilePrefix,
        message: String,
    },
    Submitted {
        origin: PolicyOrigin,
        request: BatchRequest,
        apply: ApplyEnvelope,
        prefix: Box<Option<ProfilePrefix>>,
        prefix_outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u32,
    state: JournalState,
}

impl Journal {
    fn new(state: JournalState) -> Self {
        Self {
            format: FORMAT,
            state,
        }
    }
}

pub(super) async fn load(config_path: PathBuf) -> Result<Option<JournalState>, AdapterError> {
    run_store(config_path, |store| {
        let Some(bytes) = store.read(ENTRY, MAX_BYTES).map_err(io_error)? else {
            return Ok(None);
        };
        let journal = decode(&bytes)?;
        Ok((journal.state != JournalState::Empty).then_some(journal.state))
    })
    .await
}

pub(super) async fn begin_property(
    config_path: PathBuf,
    origin: PolicyOrigin,
    operations: Vec<Operation>,
    prefix: ProfilePrefix,
) -> Result<(), AdapterError> {
    run_store(config_path, move |store| {
        match read_locked(store)? {
            None | Some(JournalState::Empty) => {}
            Some(_) => {
                return Err(journal_error(
                    ErrorCode::RecoveryRequired,
                    "another operator-policy intent requires recovery",
                ));
            }
        }
        write_locked(
            store,
            JournalState::PropertyPending {
                origin,
                operations,
                prefix,
            },
        )
    })
    .await
}

pub(super) async fn property_committed(
    config_path: PathBuf,
    expected: ProfilePrefix,
    message: String,
) -> Result<(), AdapterError> {
    run_store(config_path, move |store| {
        let Some(JournalState::PropertyPending {
            mut origin,
            operations,
            prefix,
        }) = read_locked(store)?
        else {
            return Err(journal_error(
                ErrorCode::RecoveryConflict,
                "property recovery journal is not pending",
            ));
        };
        if prefix != expected {
            return Err(journal_error(
                ErrorCode::RecoveryConflict,
                "property recovery journal does not match the submitted draft",
            ));
        }
        if let PolicyOrigin::ProfileMounts {
            properties_committed,
            ..
        } = &mut origin
        {
            *properties_committed = true;
        }
        write_locked(
            store,
            JournalState::PropertyCommitted {
                origin,
                operations,
                prefix,
                message,
            },
        )
    })
    .await
}

/// Abandon only the never-submitted mount suffix of an exactly identified
/// property-first intent. The already committed profile prefix is evidence,
/// not something this journal can roll back.
pub(super) async fn discard_property_committed(
    config_path: PathBuf,
    expected_origin: PolicyOrigin,
    expected_operations: Vec<Operation>,
    expected_prefix: ProfilePrefix,
) -> Result<(), AdapterError> {
    run_store(config_path, move |store| {
        let Some(JournalState::PropertyCommitted {
            origin,
            operations,
            prefix,
            ..
        }) = read_locked(store)?
        else {
            return Err(journal_error(
                ErrorCode::RecoveryConflict,
                "only a never-submitted property-committed mount intent can be discarded",
            ));
        };
        if origin != expected_origin
            || operations != expected_operations
            || prefix != expected_prefix
        {
            return Err(journal_error(
                ErrorCode::RecoveryConflict,
                "property-committed recovery journal does not match the open intent",
            ));
        }
        write_locked(store, JournalState::Empty)
    })
    .await
}

pub(super) async fn begin_submitted(
    config_path: PathBuf,
    origin: PolicyOrigin,
    request: BatchRequest,
    plan: RetainedPlan,
    prefix: Option<ProfilePrefix>,
    prefix_outcome: Option<String>,
) -> Result<(), AdapterError> {
    run_store(config_path, move |store| {
        let state = read_locked(store)?;
        let allowed = match &state {
            None | Some(JournalState::Empty) => prefix.is_none(),
            Some(JournalState::PropertyCommitted {
                origin: saved_origin,
                operations,
                prefix: saved_prefix,
                ..
            }) => {
                prefix.as_ref() == Some(saved_prefix)
                    && saved_origin == &origin
                    && operations == &request.operations
            }
            Some(JournalState::Submitted {
                origin: saved_origin,
                request: saved_request,
                apply,
                prefix: saved_prefix,
                ..
            }) => {
                saved_origin == &origin
                    && saved_request == &request
                    && apply == &ApplyEnvelope::from_plan(&plan)
                    && saved_prefix.as_ref() == &prefix
            }
            Some(JournalState::PropertyPending { .. }) => false,
        };
        if !allowed {
            return Err(journal_error(
                ErrorCode::RecoveryRequired,
                "an unmatched operator-policy intent requires recovery",
            ));
        }
        write_locked(
            store,
            JournalState::Submitted {
                origin,
                request,
                apply: ApplyEnvelope::from_plan(&plan),
                prefix: Box::new(prefix),
                prefix_outcome,
                operation_id: None,
            },
        )
    })
    .await
}

pub(super) async fn observe_receipt(
    config_path: PathBuf,
    request_id: String,
    operation_id: String,
    persistence: PersistenceState,
) -> Result<(), AdapterError> {
    run_store(config_path, move |store| {
        let Some(JournalState::Submitted {
            origin,
            request,
            apply,
            prefix,
            prefix_outcome,
            ..
        }) = read_locked(store)?
        else {
            return Err(journal_error(
                ErrorCode::RecoveryConflict,
                "submitted recovery journal is missing",
            ));
        };
        if request.request_id != request_id || apply.request_id != request_id {
            return Err(journal_error(
                ErrorCode::IdempotencyConflict,
                "receipt identity does not match the recovery journal",
            ));
        }
        let state = if matches!(
            persistence,
            PersistenceState::Committed | PersistenceState::Aborted
        ) {
            JournalState::Empty
        } else {
            JournalState::Submitted {
                origin,
                request,
                apply,
                prefix,
                prefix_outcome,
                operation_id: Some(operation_id),
            }
        };
        write_locked(store, state)
    })
    .await
}

async fn run_store<T: Send + 'static>(
    config_path: PathBuf,
    work: impl FnOnce(&PrivateStore<'_>) -> Result<T, AdapterError> + Send + 'static,
) -> Result<T, AdapterError> {
    tokio::task::spawn_blocking(move || {
        let guard = crate::config::write_lock::acquire_for_migration(&config_path)
            .map_err(|error| storage_error(format!("open policy recovery root: {error:#}")))?;
        let store = PrivateStore::open(&guard, STORE)
            .map_err(|error| storage_error(format!("open policy recovery store: {error:#}")))?;
        work(&store)
    })
    .await
    .map_err(|error| storage_error(format!("policy recovery task failed: {error}")))?
}

fn read_locked(store: &PrivateStore<'_>) -> Result<Option<JournalState>, AdapterError> {
    let Some(bytes) = store.read(ENTRY, MAX_BYTES).map_err(io_error)? else {
        return Ok(None);
    };
    Ok(Some(decode(&bytes)?.state))
}

fn write_locked(store: &PrivateStore<'_>, state: JournalState) -> Result<(), AdapterError> {
    let bytes = serde_json::to_vec(&Journal::new(state))
        .map_err(|error| journal_error(ErrorCode::InvalidRequest, error.to_string()))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(journal_error(
            ErrorCode::TransportLimitExceeded,
            "operator-policy recovery record exceeds its byte limit",
        ));
    }
    store.write(ENTRY, &bytes).map_err(io_error)
}

fn decode(bytes: &[u8]) -> Result<Journal, AdapterError> {
    let journal: Journal = serde_json::from_slice(bytes).map_err(|error| {
        journal_error(
            ErrorCode::RecoveryConflict,
            format!("operator-policy recovery record is corrupt: {error}"),
        )
    })?;
    if journal.format != FORMAT {
        return Err(journal_error(
            ErrorCode::RecoveryConflict,
            format!(
                "unsupported operator-policy recovery format {}",
                journal.format
            ),
        ));
    }
    Ok(journal)
}

fn io_error(error: impl std::fmt::Display) -> AdapterError {
    storage_error(format!("operator-policy recovery storage: {error}"))
}

fn storage_error(message: impl Into<String>) -> AdapterError {
    journal_error(ErrorCode::StorageUnavailable, message)
}

fn journal_error(code: ErrorCode, message: impl Into<String>) -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::Protocol,
        error: crate::operator_rules::OperatorRulesError::new(code, message),
    }
}

#[cfg(test)]
pub(super) fn entry_path(config_path: &std::path::Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    use sha2::{Digest, Sha256};

    let canonical = config_path
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(config_path.file_name().unwrap());
    let namespace = hex::encode(Sha256::digest(canonical.as_os_str().as_bytes()));
    config_path
        .parent()
        .unwrap()
        .join(STORE)
        .join(namespace)
        .join(ENTRY)
}
