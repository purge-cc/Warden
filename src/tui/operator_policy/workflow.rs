use rand_core::{OsRng, RngCore};

use crate::operator_rules::{
    BatchRequest, ErrorCode, Operation, PageRequest, PersistenceState, PlanImpactPage, Receipt,
    CONTRACT_VERSION,
};

use super::adapter::{AdapterError, AdapterErrorKind, RetainedPlan};

/// One logical edit. Its request identity is regenerated when the operator
/// changes the payload, but remains stable through plan, apply, and replay.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DraftPolicy {
    pub(crate) request: BatchRequest,
}

impl DraftPolicy {
    pub(crate) fn new(
        expected_config_revision: String,
        operations: Vec<Operation>,
    ) -> Result<Self, AdapterError> {
        Ok(Self {
            request: BatchRequest {
                contract_version: CONTRACT_VERSION,
                request_id: new_request_id()?,
                expected_config_revision,
                operations,
                expected_plan_hash: None,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkflowTicket {
    pub(super) generation: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlanAttempt {
    pub(crate) ticket: WorkflowTicket,
    pub(crate) request: BatchRequest,
    pub(crate) page: PageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImpactAttempt {
    pub(crate) ticket: WorkflowTicket,
    pub(crate) plan: RetainedPlan,
    pub(crate) cursor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApplyAttempt {
    pub(crate) ticket: WorkflowTicket,
    pub(crate) request: BatchRequest,
    pub(crate) plan: RetainedPlan,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReplayAttempt {
    pub(crate) ticket: WorkflowTicket,
    pub(crate) request: BatchRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperationAttempt {
    pub(crate) ticket: WorkflowTicket,
    pub(crate) operation_id: String,
}

/// The next safe recovery verb. In particular, a transport loss during apply
/// never becomes an implicit second apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    RetryPlan,
    RefreshAndRedraft,
    RetryExactApply,
    ReplayRequest,
    LookupOperation(String),
    ReturnToDraft,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecoveryState {
    pub(crate) draft: Option<DraftPolicy>,
    pub(crate) plan: Option<RetainedPlan>,
    pub(crate) last_receipt: Option<Receipt>,
    pub(crate) error: Option<AdapterError>,
    pub(crate) action: RecoveryAction,
    in_flight: Option<WorkflowTicket>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum WorkflowState {
    Draft(DraftPolicy),
    Planning {
        draft: DraftPolicy,
        ticket: WorkflowTicket,
    },
    Planned {
        draft: DraftPolicy,
        plan: RetainedPlan,
        impact_ticket: Option<WorkflowTicket>,
    },
    Applying {
        draft: DraftPolicy,
        plan: RetainedPlan,
        ticket: WorkflowTicket,
    },
    Outcome {
        draft: Option<DraftPolicy>,
        plan: Option<RetainedPlan>,
        receipt: Receipt,
    },
    Recovery(RecoveryState),
}

/// Small state machine used by the page controller. Completion methods reject
/// stale tickets before applying either successful data or errors.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OperatorPolicyWorkflow {
    pub(crate) state: WorkflowState,
    generation: u64,
}

impl OperatorPolicyWorkflow {
    pub(crate) fn new(
        expected_config_revision: String,
        operations: Vec<Operation>,
    ) -> Result<Self, AdapterError> {
        Ok(Self {
            state: WorkflowState::Draft(DraftPolicy::new(expected_config_revision, operations)?),
            generation: 0,
        })
    }

    pub(crate) fn begin_plan(&mut self) -> Option<PlanAttempt> {
        let draft = match &self.state {
            WorkflowState::Draft(draft) => draft.clone(),
            WorkflowState::Recovery(RecoveryState {
                draft: Some(draft),
                action: RecoveryAction::RetryPlan,
                in_flight: None,
                ..
            }) => draft.clone(),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let page = PageRequest {
            cursor: None,
            limit: None,
        };
        self.state = WorkflowState::Planning {
            draft: draft.clone(),
            ticket,
        };
        Some(PlanAttempt {
            ticket,
            request: draft.request,
            page,
        })
    }

    pub(crate) fn finish_plan(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<RetainedPlan, AdapterError>,
    ) -> bool {
        let WorkflowState::Planning {
            draft,
            ticket: pending,
        } = &self.state
        else {
            return false;
        };
        if *pending != ticket {
            return false;
        }
        let draft = draft.clone();
        self.state = match result {
            Ok(plan) => WorkflowState::Planned {
                draft,
                plan,
                impact_ticket: None,
            },
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_plan(&error),
                draft: Some(draft),
                plan: None,
                last_receipt: None,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    pub(crate) fn begin_more_impact(&mut self) -> Option<ImpactAttempt> {
        let (plan, cursor) = match &self.state {
            WorkflowState::Planned {
                plan,
                impact_ticket: None,
                ..
            } => (plan.clone(), plan.next_impact_cursor.clone()?),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let WorkflowState::Planned { impact_ticket, .. } = &mut self.state else {
            unreachable!();
        };
        *impact_ticket = Some(ticket);
        Some(ImpactAttempt {
            ticket,
            plan,
            cursor,
        })
    }

    pub(crate) fn finish_more_impact(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<PlanImpactPage, AdapterError>,
    ) -> bool {
        let WorkflowState::Planned {
            draft,
            plan,
            impact_ticket: Some(pending),
        } = &self.state
        else {
            return false;
        };
        if *pending != ticket {
            return false;
        }
        let draft = draft.clone();
        let mut plan = plan.clone();
        self.state = match result.and_then(|page| plan.append_impact(page)) {
            Ok(()) => WorkflowState::Planned {
                draft,
                plan,
                impact_ticket: None,
            },
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_impact(&error),
                draft: Some(draft),
                plan: Some(plan),
                last_receipt: None,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    pub(crate) fn begin_apply(&mut self) -> Option<ApplyAttempt> {
        let (draft, plan) = match &self.state {
            WorkflowState::Planned {
                draft,
                plan,
                impact_ticket: None,
            } => (draft.clone(), plan.clone()),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let request = draft.request.clone();
        self.state = WorkflowState::Applying {
            draft,
            plan: plan.clone(),
            ticket,
        };
        Some(ApplyAttempt {
            ticket,
            request,
            plan,
        })
    }

    pub(crate) fn finish_apply(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<Receipt, AdapterError>,
    ) -> bool {
        let WorkflowState::Applying {
            draft,
            plan,
            ticket: pending,
        } = &self.state
        else {
            return false;
        };
        if *pending != ticket {
            return false;
        }
        let draft = draft.clone();
        let plan = plan.clone();
        self.state = match result {
            Ok(receipt)
                if matches!(
                    receipt.persistence,
                    PersistenceState::Committed | PersistenceState::Aborted
                ) =>
            {
                WorkflowState::Outcome {
                    draft: Some(draft),
                    plan: Some(plan),
                    receipt,
                }
            }
            Ok(receipt) => WorkflowState::Recovery(RecoveryState {
                action: RecoveryAction::LookupOperation(receipt.operation_id.clone()),
                draft: Some(draft),
                plan: Some(plan),
                last_receipt: Some(receipt),
                error: None,
                in_flight: None,
            }),
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_apply(&error),
                draft: Some(draft),
                plan: Some(plan),
                last_receipt: None,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    /// Reject an apply before any daemon mutation was sent (for example,
    /// because the exact recovery envelope could not be durably journaled).
    pub(crate) fn finish_apply_not_submitted(
        &mut self,
        ticket: WorkflowTicket,
        error: AdapterError,
    ) -> bool {
        let WorkflowState::Applying {
            draft,
            plan,
            ticket: pending,
        } = &self.state
        else {
            return false;
        };
        if *pending != ticket {
            return false;
        }
        self.state = WorkflowState::Recovery(RecoveryState {
            action: RecoveryAction::ReturnToDraft,
            draft: Some(draft.clone()),
            plan: Some(plan.clone()),
            last_receipt: None,
            error: Some(error),
            in_flight: None,
        });
        true
    }

    /// Restore an exact submitted intent from the private client journal.
    /// The retained plan and request are never rebased under this identity.
    pub(crate) fn recover_submitted_with_error(
        request: BatchRequest,
        plan: RetainedPlan,
        error: Option<AdapterError>,
    ) -> Self {
        debug_assert_eq!(request.request_id, plan.request_id);
        Self {
            state: WorkflowState::Recovery(RecoveryState {
                draft: Some(DraftPolicy { request }),
                plan: Some(plan),
                last_receipt: None,
                error,
                action: RecoveryAction::RetryExactApply,
                in_flight: None,
            }),
            generation: 0,
        }
    }

    pub(crate) fn begin_exact_apply(&mut self) -> Option<ApplyAttempt> {
        let (request, plan) = match &self.state {
            WorkflowState::Recovery(RecoveryState {
                draft: Some(draft),
                plan: Some(plan),
                action: RecoveryAction::RetryExactApply,
                in_flight: None,
                ..
            }) => (draft.request.clone(), plan.clone()),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let WorkflowState::Recovery(recovery) = &mut self.state else {
            unreachable!();
        };
        recovery.in_flight = Some(ticket);
        Some(ApplyAttempt {
            ticket,
            request,
            plan,
        })
    }

    pub(crate) fn finish_exact_apply(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<Receipt, AdapterError>,
    ) -> bool {
        let WorkflowState::Recovery(recovery) = &self.state else {
            return false;
        };
        if recovery.in_flight != Some(ticket) {
            return false;
        }
        let draft = recovery.draft.clone();
        let plan = recovery.plan.clone();
        let last_receipt = recovery.last_receipt.clone();
        self.state = match result {
            Ok(receipt)
                if matches!(
                    receipt.persistence,
                    PersistenceState::Committed | PersistenceState::Aborted
                ) =>
            {
                WorkflowState::Outcome {
                    draft,
                    plan,
                    receipt,
                }
            }
            Ok(receipt) => WorkflowState::Recovery(RecoveryState {
                action: RecoveryAction::LookupOperation(receipt.operation_id.clone()),
                draft,
                plan,
                last_receipt: Some(receipt),
                error: None,
                in_flight: None,
            }),
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_exact_apply(&error),
                draft,
                plan,
                last_receipt,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    pub(crate) fn begin_replay(&mut self) -> Option<ReplayAttempt> {
        let request = match &self.state {
            WorkflowState::Recovery(RecoveryState {
                draft: Some(draft),
                action: RecoveryAction::ReplayRequest,
                in_flight: None,
                ..
            }) => draft.request.clone(),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let WorkflowState::Recovery(recovery) = &mut self.state else {
            unreachable!();
        };
        recovery.in_flight = Some(ticket);
        Some(ReplayAttempt { ticket, request })
    }

    pub(crate) fn finish_replay(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<Receipt, AdapterError>,
    ) -> bool {
        let WorkflowState::Recovery(recovery) = &self.state else {
            return false;
        };
        if recovery.in_flight != Some(ticket) {
            return false;
        }
        let draft = recovery.draft.clone();
        let plan = recovery.plan.clone();
        let last_receipt = recovery.last_receipt.clone();
        self.state = match result {
            Ok(receipt)
                if matches!(
                    receipt.persistence,
                    PersistenceState::Committed | PersistenceState::Aborted
                ) =>
            {
                WorkflowState::Outcome {
                    draft,
                    plan,
                    receipt,
                }
            }
            Ok(receipt) => WorkflowState::Recovery(RecoveryState {
                action: RecoveryAction::LookupOperation(receipt.operation_id.clone()),
                draft,
                plan,
                last_receipt: Some(receipt),
                error: None,
                in_flight: None,
            }),
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_replay(&error),
                draft,
                plan,
                last_receipt,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    /// Move an outcome back to durable lookup without conflating committed
    /// persistence with current activation.
    pub(crate) fn refresh_outcome(&mut self) -> bool {
        let WorkflowState::Outcome {
            draft,
            plan,
            receipt,
        } = &self.state
        else {
            return false;
        };
        let operation_id = receipt.operation_id.clone();
        self.state = WorkflowState::Recovery(RecoveryState {
            draft: draft.clone(),
            plan: plan.clone(),
            last_receipt: Some(receipt.clone()),
            error: None,
            action: RecoveryAction::LookupOperation(operation_id),
            in_flight: None,
        });
        true
    }

    pub(crate) fn begin_operation_lookup(&mut self) -> Option<OperationAttempt> {
        let operation_id = match &self.state {
            WorkflowState::Recovery(RecoveryState {
                action: RecoveryAction::LookupOperation(operation_id),
                in_flight: None,
                ..
            }) => operation_id.clone(),
            _ => return None,
        };
        let ticket = self.next_ticket();
        let WorkflowState::Recovery(recovery) = &mut self.state else {
            unreachable!();
        };
        recovery.in_flight = Some(ticket);
        Some(OperationAttempt {
            ticket,
            operation_id,
        })
    }

    pub(crate) fn finish_operation_lookup(
        &mut self,
        ticket: WorkflowTicket,
        result: Result<Receipt, AdapterError>,
    ) -> bool {
        let WorkflowState::Recovery(recovery) = &self.state else {
            return false;
        };
        if recovery.in_flight != Some(ticket) {
            return false;
        }
        let draft = recovery.draft.clone();
        let plan = recovery.plan.clone();
        let last_receipt = recovery.last_receipt.clone();
        let operation_id = match &recovery.action {
            RecoveryAction::LookupOperation(operation_id) => operation_id.clone(),
            _ => return false,
        };
        let has_exact_apply = draft.is_some() && plan.is_some();
        self.state = match result {
            Ok(receipt)
                if matches!(
                    receipt.persistence,
                    PersistenceState::Committed | PersistenceState::Aborted
                ) =>
            {
                WorkflowState::Outcome {
                    draft,
                    plan,
                    receipt,
                }
            }
            Ok(receipt) => WorkflowState::Recovery(RecoveryState {
                action: RecoveryAction::LookupOperation(receipt.operation_id.clone()),
                draft,
                plan,
                last_receipt: Some(receipt),
                error: None,
                in_flight: None,
            }),
            Err(error) => WorkflowState::Recovery(RecoveryState {
                action: recovery_after_operation(&error, has_exact_apply, operation_id),
                draft,
                plan,
                last_receipt,
                error: Some(error),
                in_flight: None,
            }),
        };
        true
    }

    fn next_ticket(&mut self) -> WorkflowTicket {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("operator-policy workflow generation exhausted");
        WorkflowTicket {
            generation: self.generation,
        }
    }
}

fn new_request_id() -> Result<String, AdapterError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| AdapterError {
            kind: AdapterErrorKind::Transport,
            error: crate::operator_rules::OperatorRulesError::new(
                ErrorCode::StorageUnavailable,
                format!("operator-policy request identity entropy: {error}"),
            ),
        })?;
    Ok(hex::encode(bytes))
}

fn recovery_after_plan(error: &AdapterError) -> RecoveryAction {
    match error.code() {
        ErrorCode::RevisionConflict | ErrorCode::StaleCursor => RecoveryAction::RefreshAndRedraft,
        _ if error.kind == AdapterErrorKind::Transport => RecoveryAction::RetryPlan,
        _ => RecoveryAction::ReturnToDraft,
    }
}

fn recovery_after_impact(error: &AdapterError) -> RecoveryAction {
    match error.code() {
        ErrorCode::StaleCursor | ErrorCode::PlanConflict | ErrorCode::RevisionConflict => {
            RecoveryAction::RefreshAndRedraft
        }
        _ if error.kind == AdapterErrorKind::Transport => RecoveryAction::RetryPlan,
        _ => RecoveryAction::ReturnToDraft,
    }
}

fn recovery_after_apply(error: &AdapterError) -> RecoveryAction {
    match error.code() {
        ErrorCode::PlanConflict => RecoveryAction::ReplayRequest,
        _ if matches!(
            error.kind,
            AdapterErrorKind::Transport | AdapterErrorKind::Protocol
        ) || error.code() == ErrorCode::StorageUnavailable =>
        {
            RecoveryAction::RetryExactApply
        }
        _ => RecoveryAction::ReturnToDraft,
    }
}

fn recovery_after_exact_apply(error: &AdapterError) -> RecoveryAction {
    if error.code() == ErrorCode::PlanConflict {
        RecoveryAction::ReplayRequest
    } else {
        RecoveryAction::RetryExactApply
    }
}

fn recovery_after_replay(error: &AdapterError) -> RecoveryAction {
    match error.code() {
        ErrorCode::NotFound | ErrorCode::RevisionConflict | ErrorCode::PlanConflict => {
            RecoveryAction::RetryExactApply
        }
        _ => RecoveryAction::ReplayRequest,
    }
}

fn recovery_after_operation(
    error: &AdapterError,
    has_exact_apply: bool,
    operation_id: String,
) -> RecoveryAction {
    if error.code() == ErrorCode::NotFound && has_exact_apply {
        RecoveryAction::RetryExactApply
    } else {
        RecoveryAction::LookupOperation(operation_id)
    }
}
