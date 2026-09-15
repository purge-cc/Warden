//! Bounded plan and mutation-job supervision shared by API adapters.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::config::policy_transaction::ReceiptCompletion;
use crate::config::{policy_transaction, state_dir, write_lock};
#[cfg(test)]
use crate::operator_rules::activation::ActivePolicyIdentity;
use crate::operator_rules::activation::{new_correlation_id, ActivationRequest, ActivationResult};
use crate::operator_rules::ErrorCode;
use crate::operator_rules::{
    Actor, BatchRequest, Capabilities, ExportChunk, ExportRequest, ListDetail, ListPage, Metadata,
    OperatorRulesError, OperatorRulesService, OwnedExport, PageRequest, PersistenceState, Plan,
    PlanImpactPage, PlanSummary, Receipt, RulePage, TransportLimits,
};
use crate::profiles::resolver::ProfileResolver;

pub type DurableIntentCallback = Arc<dyn Fn(&Receipt) + Send + Sync + 'static>;
type ResumptionWaiter = oneshot::Sender<Result<Receipt, OperatorRulesError>>;

#[derive(Debug, Clone)]
pub struct OperatorRuleJobConfig {
    pub max_plans: usize,
    pub max_jobs: usize,
    pub queue_capacity: usize,
    pub concurrency: usize,
    pub max_waiters_per_job: usize,
    pub blocking_concurrency: usize,
    pub plan_ttl: Duration,
    pub terminal_job_ttl: Duration,
}

impl Default for OperatorRuleJobConfig {
    fn default() -> Self {
        Self {
            max_plans: 128,
            max_jobs: 4096,
            queue_capacity: 32,
            concurrency: 2,
            max_waiters_per_job: 64,
            blocking_concurrency: 8,
            plan_ttl: Duration::from_secs(15 * 60),
            terminal_job_ttl: Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPlan {
    pub plan_id: String,
    pub summary: PlanSummary,
    pub first_impacts: PlanImpactPage,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SubmitOutcome {
    Accepted {
        operation_id: String,
        location: String,
        prepared: Receipt,
    },
    Replay {
        operation_id: String,
        location: String,
        receipt: Receipt,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoverySummary {
    pub state: String,
    pub operation_id: Option<String>,
    pub persistence: Option<PersistenceState>,
}

#[derive(Clone)]
pub struct OperatorRuleJobClient {
    inner: Arc<Inner>,
}

pub struct OperatorRuleJobSupervisor {
    inner: Arc<Inner>,
    receiver: mpsc::Receiver<JobRequest>,
}

struct Inner {
    service: Arc<OperatorRulesService>,
    config: OperatorRuleJobConfig,
    plans: Mutex<BTreeMap<String, StoredPlan>>,
    jobs: Mutex<BTreeMap<JobKey, JobRecord>>,
    resumptions: Mutex<BTreeMap<JobKey, Vec<ResumptionWaiter>>>,
    recovery_backlog: Mutex<VecDeque<ResumeJobRequest>>,
    plan_slots: Arc<Semaphore>,
    blocking_slots: Arc<Semaphore>,
    sender: mpsc::Sender<JobRequest>,
    activation_tx: Option<mpsc::Sender<ActivationRequest>>,
    profile_resolver: Mutex<Option<Arc<ProfileResolver>>>,
    on_durable_intent: DurableIntentCallback,
    recovered: AtomicBool,
    accepting: AtomicBool,
}

#[derive(Clone)]
struct StoredPlan {
    actor: String,
    plan: Plan,
    limits: TransportLimits,
    created: Instant,
    _reservation: Arc<OwnedSemaphorePermit>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct JobKey {
    actor: String,
    request_id: String,
}

struct JobRecord {
    fingerprint: String,
    expected_config_revision: String,
    state: JobState,
    updated: Instant,
    prepared_waiters: Vec<oneshot::Sender<Result<SubmitOutcome, OperatorRulesError>>>,
    terminal_waiters: Vec<oneshot::Sender<Result<Receipt, OperatorRulesError>>>,
}

enum JobState {
    Queued,
    Prepared(Receipt),
    Finished(Receipt),
}

enum ExistingSubmission {
    Replay(Box<SubmitOutcome>),
    Wait(oneshot::Receiver<Result<SubmitOutcome, OperatorRulesError>>),
    ReconcileUncertain,
}

enum ResumptionAdmission {
    Start(oneshot::Receiver<Result<Receipt, OperatorRulesError>>),
    Wait(oneshot::Receiver<Result<Receipt, OperatorRulesError>>),
    Current(Box<Receipt>),
    Live,
}

enum ResumptionResult {
    Complete(Receipt),
    Live(Receipt),
}

impl ResumptionResult {
    fn into_receipt(self) -> Receipt {
        match self {
            Self::Complete(receipt) | Self::Live(receipt) => receipt,
        }
    }
}

struct ApplyJobRequest {
    key: JobKey,
    actor: Actor,
    request: BatchRequest,
    limits: TransportLimits,
}

struct ResumeJobRequest {
    key: JobKey,
    actor: Actor,
    receipt: Receipt,
}

enum JobRequest {
    Apply(ApplyJobRequest),
    Resume(ResumeJobRequest),
}

impl OperatorRuleJobSupervisor {
    pub(crate) fn new(
        service: Arc<OperatorRulesService>,
        mut config: OperatorRuleJobConfig,
        activation_tx: Option<mpsc::Sender<ActivationRequest>>,
        on_durable_intent: DurableIntentCallback,
    ) -> (Self, OperatorRuleJobClient) {
        config.queue_capacity = config.queue_capacity.max(1);
        config.concurrency = config.concurrency.max(1);
        config.max_waiters_per_job = config.max_waiters_per_job.max(1);
        config.max_plans = config.max_plans.max(1);
        config.blocking_concurrency = config.blocking_concurrency.max(1);
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let plan_slots = Arc::new(Semaphore::new(config.max_plans));
        let blocking_slots = Arc::new(Semaphore::new(config.blocking_concurrency));
        let inner = Arc::new(Inner {
            service,
            config,
            plans: Mutex::new(BTreeMap::new()),
            jobs: Mutex::new(BTreeMap::new()),
            resumptions: Mutex::new(BTreeMap::new()),
            recovery_backlog: Mutex::new(VecDeque::new()),
            plan_slots,
            blocking_slots,
            sender,
            activation_tx,
            profile_resolver: Mutex::new(None),
            on_durable_intent,
            recovered: AtomicBool::new(false),
            accepting: AtomicBool::new(true),
        });
        (
            Self {
                inner: inner.clone(),
                receiver,
            },
            OperatorRuleJobClient { inner },
        )
    }

    pub async fn run(mut self, mut shutdown: oneshot::Receiver<()>) {
        let mut tasks = JoinSet::new();
        let concurrency = self.inner.config.concurrency;
        let mut stopping = false;
        loop {
            if stopping {
                while let Ok(job) = self.receiver.try_recv() {
                    let error = unavailable("operator-rule supervisor is shutting down");
                    match job {
                        JobRequest::Apply(job) => self.inner.fail_before_intent(&job.key, error),
                        JobRequest::Resume(job) => self.inner.fail_resumption(&job.key, error),
                    }
                }
                let abandoned = {
                    let mut backlog = self
                        .inner
                        .recovery_backlog
                        .lock()
                        .expect("recovery backlog poisoned");
                    backlog.drain(..).collect::<Vec<_>>()
                };
                for job in abandoned {
                    self.inner.fail_resumption(
                        &job.key,
                        unavailable("operator-rule supervisor is shutting down"),
                    );
                }
                if tasks.is_empty() {
                    break;
                }
                let _ = tasks.join_next().await;
                continue;
            }

            if tasks.len() < concurrency {
                let recovery_job = self
                    .inner
                    .recovery_backlog
                    .lock()
                    .expect("recovery backlog poisoned")
                    .pop_front();
                if let Some(job) = recovery_job {
                    let inner = self.inner.clone();
                    tasks.spawn(async move { run_resumption(inner, job).await });
                    continue;
                }
            }

            tokio::select! {
                _ = &mut shutdown => {
                    stopping = true;
                    self.inner.accepting.store(false, Ordering::Release);
                    self.receiver.close();
                }
                Some(job) = self.receiver.recv(), if tasks.len() < concurrency => {
                    let inner = self.inner.clone();
                    tasks.spawn(async move {
                        match job {
                            JobRequest::Apply(job) => run_job(inner, job).await,
                            JobRequest::Resume(job) => run_resumption(inner, job).await,
                        }
                    });
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::error!(error = %error, "operator-rule job task failed");
                    }
                }
                else => break,
            }
        }
        self.inner.accepting.store(false, Ordering::Release);
    }
}

impl OperatorRuleJobClient {
    pub async fn recover(&self) -> Result<RecoverySummary, OperatorRulesError> {
        let service = self.inner.service.clone();
        let result = tokio::task::spawn_blocking(move || {
            let guard = write_lock::acquire_for_migration(&service.master)
                .map_err(OperatorRulesError::storage)?;
            let data =
                state_dir::open_for_migration(&guard).map_err(OperatorRulesError::storage)?;
            let receipts = policy_transaction::ReceiptStore::open(&data, &guard)
                .map_err(OperatorRulesError::storage)?;
            policy_transaction::recover_active(&guard, &receipts)
                .map_err(OperatorRulesError::storage)
        })
        .await
        .map_err(|error| unavailable(format!("recovery worker failed: {error}")))??;

        let summary = match result {
            policy_transaction::RecoveryOutcome::Absent => RecoverySummary {
                state: "clean".into(),
                operation_id: None,
                persistence: None,
            },
            policy_transaction::RecoveryOutcome::SetupRemoved => RecoverySummary {
                state: "incomplete_setup_removed".into(),
                operation_id: None,
                persistence: None,
            },
            policy_transaction::RecoveryOutcome::Recovered(receipt) => RecoverySummary {
                state: "recovered".into(),
                operation_id: Some(receipt.transaction_id.clone()),
                persistence: Some(map_persistence(receipt.persistence)),
            },
            policy_transaction::RecoveryOutcome::LegacyActive => {
                return Err(OperatorRulesError::new(
                    ErrorCode::RecoveryConflict,
                    "a legacy migration journal requires its own recovery path",
                ));
            }
        };
        let service = self.inner.service.clone();
        let pending = blocking(self.inner.blocking_slots.clone(), move || {
            service.pending_completions()
        })
        .await?;
        if !pending.is_empty() {
            let mut resumptions = self
                .inner
                .resumptions
                .lock()
                .expect("resumption registry poisoned");
            let mut backlog = self
                .inner
                .recovery_backlog
                .lock()
                .expect("recovery backlog poisoned");
            for (actor, receipt) in pending {
                let key = JobKey {
                    actor: actor.identity.clone(),
                    request_id: receipt.request_id.clone(),
                };
                if !resumptions.contains_key(&key) {
                    // Keep the key live after the supervisor pops the backlog
                    // item, so a concurrent replay waits for this exact
                    // resumption instead of queueing a second activation.
                    resumptions.insert(key.clone(), Vec::new());
                    backlog.push_back(ResumeJobRequest {
                        key,
                        actor,
                        receipt,
                    });
                }
            }
        }
        self.inner.recovered.store(true, Ordering::Release);
        Ok(summary)
    }

    pub fn capabilities(&self, limits: TransportLimits) -> Capabilities {
        self.inner.service.capabilities(limits)
    }

    pub(crate) fn attach_profile_resolver(&self, profile_resolver: Option<Arc<ProfileResolver>>) {
        *self
            .inner
            .profile_resolver
            .lock()
            .expect("profile resolver attachment poisoned") = profile_resolver;
    }

    pub async fn metadata(&self) -> Result<Metadata, OperatorRulesError> {
        let service = self.inner.service.clone();
        let profile_resolver = self
            .inner
            .profile_resolver
            .lock()
            .expect("profile resolver attachment poisoned")
            .clone();
        blocking(self.inner.blocking_slots.clone(), move || {
            let mut metadata = service.metadata()?;
            let active_policy = profile_resolver
                .as_ref()
                .map(|resolver| resolver.active_policy_identity())
                .filter(|identity| identity.is_known());
            metadata.activation_in_sync = active_policy.as_ref().is_some_and(|identity| {
                identity.config_revision == metadata.config_revision
                    && identity.operator_policy_hash == metadata.desired_operator_policy_hash
            });
            metadata.active_policy = active_policy;
            Ok(metadata)
        })
        .await
    }

    pub async fn lists(
        &self,
        page: PageRequest,
        limits: TransportLimits,
    ) -> Result<ListPage, OperatorRulesError> {
        let service = self.inner.service.clone();
        blocking(self.inner.blocking_slots.clone(), move || {
            service.read(page, limits)
        })
        .await
    }

    pub async fn list(&self, id: String) -> Result<ListDetail, OperatorRulesError> {
        let service = self.inner.service.clone();
        blocking(self.inner.blocking_slots.clone(), move || service.show(&id)).await
    }

    pub async fn rules(
        &self,
        id: String,
        page: PageRequest,
        limits: TransportLimits,
    ) -> Result<RulePage, OperatorRulesError> {
        let service = self.inner.service.clone();
        blocking(self.inner.blocking_slots.clone(), move || {
            service.rules(&id, page, limits)
        })
        .await
    }

    pub async fn export(
        &self,
        request: ExportRequest,
        limits: TransportLimits,
    ) -> Result<ExportChunk, OperatorRulesError> {
        let service = self.inner.service.clone();
        blocking(self.inner.blocking_slots.clone(), move || {
            service.export(&request, limits)
        })
        .await
    }

    pub async fn export_owned(&self, id: String) -> Result<OwnedExport, OperatorRulesError> {
        let service = self.inner.service.clone();
        // The loaded tree's `custom_list_limits.max_file_bytes` is the
        // authoritative local-pack bound. REST's 1 MiB transport ceiling is
        // for JSON, not this binary stream.
        blocking(self.inner.blocking_slots.clone(), move || {
            service.export_owned(&id, usize::MAX)
        })
        .await
    }

    pub async fn plan(
        &self,
        actor: Actor,
        request: BatchRequest,
        page: PageRequest,
        limits: TransportLimits,
    ) -> Result<PreparedPlan, OperatorRulesError> {
        self.ensure_ready()?;
        {
            let mut plans = self.inner.plans.lock().expect("plan registry poisoned");
            let now = Instant::now();
            plans.retain(|_, entry| {
                now.saturating_duration_since(entry.created) < self.inner.config.plan_ttl
            });
        }
        let reservation = self
            .inner
            .plan_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                OperatorRulesError::new(
                    ErrorCode::AdmissionRejected,
                    "plan registry capacity reached; retry after an existing plan expires",
                )
            })?;
        let service = self.inner.service.clone();
        let (plan, reservation) = blocking(self.inner.blocking_slots.clone(), move || {
            service
                .plan(&request, limits)
                .map(|plan| (plan, reservation))
        })
        .await?;
        let first_impacts = OperatorRulesService::plan_impact_page(&plan, page, limits)?;
        let summary = OperatorRulesService::plan_summary(&plan);
        let mut plans = self.inner.plans.lock().expect("plan registry poisoned");
        let now = Instant::now();
        plans.retain(|_, entry| {
            now.saturating_duration_since(entry.created) < self.inner.config.plan_ttl
        });
        let plan_id = unique_id(&plans)?;
        plans.insert(
            plan_id.clone(),
            StoredPlan {
                actor: actor.identity,
                plan,
                limits,
                created: now,
                _reservation: Arc::new(reservation),
            },
        );
        Ok(PreparedPlan {
            plan_id,
            summary,
            first_impacts,
        })
    }

    pub async fn replay_request(
        &self,
        actor: Actor,
        request: BatchRequest,
        limits: TransportLimits,
    ) -> Result<Option<Receipt>, OperatorRulesError> {
        self.ensure_ready()?;
        let service = self.inner.service.clone();
        let key = JobKey {
            actor: actor.identity.clone(),
            request_id: request.request_id.clone(),
        };
        let lookup_actor = actor.clone();
        let receipt = blocking(self.inner.blocking_slots.clone(), move || {
            service.replay_request(&lookup_actor, &request, limits)
        })
        .await?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        self.inner.reconcile_uncertain(&key, receipt.clone());
        self.resume_verified_replay(actor, key, receipt)
            .await
            .map(ResumptionResult::into_receipt)
            .map(Some)
    }

    async fn resume_verified_replay(
        &self,
        actor: Actor,
        key: JobKey,
        receipt: Receipt,
    ) -> Result<ResumptionResult, OperatorRulesError> {
        if !requires_post_commit_completion(&receipt) {
            return Ok(ResumptionResult::Complete(receipt));
        }
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(unavailable("operator-rule supervisor is unavailable"));
        }
        match self.inner.admit_resumption(key.clone(), &receipt)? {
            ResumptionAdmission::Current(current) => Ok(ResumptionResult::Complete(*current)),
            ResumptionAdmission::Live => Ok(ResumptionResult::Live(receipt)),
            ResumptionAdmission::Wait(receiver) => receiver
                .await
                .map_err(|_| unavailable("operator-rule resumption channel closed"))?
                .map(ResumptionResult::Complete),
            ResumptionAdmission::Start(receiver) => {
                let job = ResumeJobRequest {
                    key: key.clone(),
                    actor,
                    receipt,
                };
                if let Err(error) = self.inner.sender.try_send(JobRequest::Resume(job)) {
                    let reason = match error {
                        mpsc::error::TrySendError::Full(_) => OperatorRulesError::new(
                            ErrorCode::AdmissionRejected,
                            "job queue is full",
                        ),
                        mpsc::error::TrySendError::Closed(_) => {
                            unavailable("operator-rule supervisor is unavailable")
                        }
                    };
                    self.inner.fail_resumption(&key, reason.clone());
                }
                receiver
                    .await
                    .map_err(|_| unavailable("operator-rule resumption channel closed"))?
                    .map(ResumptionResult::Complete)
            }
        }
    }

    pub fn plan_impacts(
        &self,
        actor: &Actor,
        plan_id: &str,
        page: PageRequest,
    ) -> Result<PlanImpactPage, OperatorRulesError> {
        self.ensure_ready()?;
        let stored = self.stored_plan(actor, plan_id)?;
        OperatorRulesService::plan_impact_page(&stored.plan, page, stored.limits)
    }

    pub fn stored_plan_summary(
        &self,
        actor: &Actor,
        plan_id: &str,
    ) -> Result<PlanSummary, OperatorRulesError> {
        self.ensure_ready()?;
        Ok(OperatorRulesService::plan_summary(
            &self.stored_plan(actor, plan_id)?.plan,
        ))
    }

    pub async fn submit(
        &self,
        actor: Actor,
        plan_id: String,
        plan_hash: String,
        request_id: String,
    ) -> Result<SubmitOutcome, OperatorRulesError> {
        self.submit_inner(actor, plan_id, plan_hash, request_id, None)
            .await
    }

    /// Submit with the transport's explicit configuration precondition.
    /// A missing or expired transient plan cannot reject the request until a
    /// durable replay lookup has been attempted.
    pub async fn submit_with_precondition(
        &self,
        actor: Actor,
        plan_id: String,
        plan_hash: String,
        request_id: String,
        expected_config_revision: String,
    ) -> Result<SubmitOutcome, OperatorRulesError> {
        self.submit_inner(
            actor,
            plan_id,
            plan_hash,
            request_id,
            Some(expected_config_revision),
        )
        .await
    }

    async fn submit_inner(
        &self,
        actor: Actor,
        plan_id: String,
        plan_hash: String,
        request_id: String,
        expected_config_revision: Option<String>,
    ) -> Result<SubmitOutcome, OperatorRulesError> {
        self.ensure_ready()?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(unavailable("operator-rule supervisor is unavailable"));
        }
        let key = JobKey {
            actor: actor.identity.clone(),
            request_id: request_id.clone(),
        };
        if let Some(existing) =
            self.existing_submission(&key, &plan_hash, expected_config_revision.as_deref())?
        {
            return match existing {
                ExistingSubmission::Replay(outcome) => match *outcome {
                    SubmitOutcome::Replay { receipt, .. } => {
                        self.resume_submit_receipt(actor, key, receipt).await
                    }
                    outcome => Ok(outcome),
                },
                ExistingSubmission::Wait(receiver) => receiver
                    .await
                    .map_err(|_| unavailable("operator-rule submission channel closed"))?,
                ExistingSubmission::ReconcileUncertain => {
                    let service = self.inner.service.clone();
                    let lookup_actor = actor.clone();
                    let lookup_request_id = request_id.clone();
                    let durable = blocking(self.inner.blocking_slots.clone(), move || {
                        service.operation_by_request(&lookup_actor, &lookup_request_id)
                    })
                    .await?;
                    let Some((receipt, before_revision, durable_plan_hash)) = durable else {
                        return Err(unavailable(
                            "uncertain operation is absent from durable receipt storage",
                        ));
                    };
                    if durable_plan_hash.as_deref() != Some(plan_hash.as_str())
                        || expected_config_revision
                            .as_ref()
                            .is_some_and(|expected| expected != &before_revision)
                    {
                        return Err(OperatorRulesError::new(
                            ErrorCode::IdempotencyConflict,
                            "request_id was already submitted with a different plan or precondition",
                        ));
                    }
                    self.inner.reconcile_uncertain(&key, receipt.clone());
                    self.resume_submit_receipt(actor, key, receipt).await
                }
            };
        }

        let stored = match self.transient_plan(&actor, &plan_id) {
            Some(stored) => stored,
            None => {
                let service = self.inner.service.clone();
                let lookup_actor = actor.clone();
                let lookup_request_id = request_id.clone();
                if let Some((receipt, before_revision, Some(durable_plan_hash))) =
                    blocking(self.inner.blocking_slots.clone(), move || {
                        service.operation_by_request(&lookup_actor, &lookup_request_id)
                    })
                    .await?
                {
                    if durable_plan_hash != plan_hash
                        || expected_config_revision
                            .as_ref()
                            .is_some_and(|expected| expected != &before_revision)
                    {
                        return Err(OperatorRulesError::new(
                            ErrorCode::IdempotencyConflict,
                            "request_id was already submitted with a different plan or precondition",
                        ));
                    }
                    return self.resume_submit_receipt(actor, key, receipt).await;
                }
                return Err(OperatorRulesError::new(
                    ErrorCode::PlanConflict,
                    "plan is unknown or expired",
                ));
            }
        };

        if stored.plan.plan_hash != plan_hash {
            return Err(OperatorRulesError::new(
                ErrorCode::PlanConflict,
                "plan hash does not match the stored plan",
            ));
        }
        if stored.plan.request.request_id != request_id {
            return Err(OperatorRulesError::new(
                ErrorCode::IdempotencyConflict,
                "request_id does not match the stored plan",
            ));
        }
        if expected_config_revision
            .as_ref()
            .is_some_and(|expected| expected != &stored.plan.base_config_revision)
        {
            return Err(OperatorRulesError::new(
                ErrorCode::RevisionConflict,
                "configuration precondition is stale for the stored plan",
            ));
        }
        let mut request = stored.plan.request.clone();
        request.expected_plan_hash = Some(stored.plan.plan_hash.clone());
        let (sender, receiver) = oneshot::channel();
        let mut enqueue = false;
        let mut immediate_replay = None;
        {
            let mut jobs = self.inner.jobs.lock().expect("job registry poisoned");
            cleanup_jobs(&mut jobs, &self.inner.config);
            if let Some(job) = jobs.get_mut(&key) {
                if job.fingerprint != plan_hash
                    || expected_config_revision
                        .as_deref()
                        .is_some_and(|expected| expected != job.expected_config_revision.as_str())
                {
                    return Err(OperatorRulesError::new(
                        ErrorCode::IdempotencyConflict,
                        "request_id was already submitted with a different plan or precondition",
                    ));
                }
                match &job.state {
                    JobState::Prepared(receipt) | JobState::Finished(receipt) => {
                        immediate_replay = Some(receipt.clone());
                    }
                    JobState::Queued => {
                        job.prepared_waiters.retain(|waiter| !waiter.is_closed());
                        if job.prepared_waiters.len() >= self.inner.config.max_waiters_per_job {
                            return Err(OperatorRulesError::new(
                                ErrorCode::AdmissionRejected,
                                "prepared waiter capacity reached for this job",
                            ));
                        }
                        job.prepared_waiters.push(sender);
                    }
                }
            } else {
                if jobs.len() >= self.inner.config.max_jobs {
                    return Err(OperatorRulesError::new(
                        ErrorCode::AdmissionRejected,
                        "job registry capacity reached",
                    ));
                }
                jobs.insert(
                    key.clone(),
                    JobRecord {
                        fingerprint: plan_hash,
                        expected_config_revision: stored.plan.base_config_revision.clone(),
                        state: JobState::Queued,
                        updated: Instant::now(),
                        prepared_waiters: vec![sender],
                        terminal_waiters: Vec::new(),
                    },
                );
                enqueue = true;
            }
        }
        if let Some(receipt) = immediate_replay {
            return self.resume_submit_receipt(actor, key, receipt).await;
        }
        if enqueue {
            if let Err(error) = self
                .inner
                .sender
                .try_send(JobRequest::Apply(ApplyJobRequest {
                    key: key.clone(),
                    actor,
                    request,
                    limits: stored.limits,
                }))
            {
                let reason = match error {
                    mpsc::error::TrySendError::Full(_) => {
                        OperatorRulesError::new(ErrorCode::AdmissionRejected, "job queue is full")
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        unavailable("operator-rule supervisor is unavailable")
                    }
                };
                self.inner.fail_before_intent(&key, reason.clone());
            }
        }
        receiver
            .await
            .map_err(|_| unavailable("operator-rule submission channel closed"))?
    }

    async fn resume_submit_receipt(
        &self,
        actor: Actor,
        key: JobKey,
        receipt: Receipt,
    ) -> Result<SubmitOutcome, OperatorRulesError> {
        let receipt = self
            .resume_verified_replay(actor, key, receipt)
            .await?
            .into_receipt();
        Ok(replay(receipt))
    }

    pub async fn operation(
        &self,
        actor: &Actor,
        operation_id: &str,
    ) -> Result<Receipt, OperatorRulesError> {
        // The transaction may still retain the configuration lock after
        // publishing durable intent, so serve that intermediate receipt locally.
        if let Some(receipt) = self.inner.locked_prepared_operation(actor, operation_id) {
            return Ok(receipt);
        }
        let service = self.inner.service.clone();
        let actor = actor.clone();
        let operation_id = operation_id.to_string();
        let receipt = blocking(self.inner.blocking_slots.clone(), move || {
            service.operation(&actor, &operation_id)
        })
        .await?;
        self.inner.reconcile_operation(&receipt);
        Ok(receipt)
    }

    /// Wait until an accepted operation has reached a terminal persistence
    /// state. REST deliberately does not use this: its apply request resolves
    /// at durable intent, while IPC can preserve its synchronous exit-status
    /// contract without running a second mutation worker.
    pub async fn wait_terminal(
        &self,
        actor: &Actor,
        operation_id: &str,
    ) -> Result<Receipt, OperatorRulesError> {
        self.ensure_ready()?;
        loop {
            let receiver = {
                let mut jobs = self.inner.jobs.lock().expect("job registry poisoned");
                cleanup_jobs(&mut jobs, &self.inner.config);
                let job = jobs.iter_mut().find_map(|(key, job)| {
                    if key.actor != actor.identity {
                        return None;
                    }
                    match &job.state {
                        JobState::Prepared(receipt) | JobState::Finished(receipt)
                            if receipt.operation_id == operation_id =>
                        {
                            Some(job)
                        }
                        _ => None,
                    }
                });
                match job {
                    Some(JobRecord {
                        state: JobState::Finished(receipt),
                        ..
                    }) if receipt.persistence != PersistenceState::DurabilityUncertain => {
                        return Ok(receipt.clone())
                    }
                    Some(JobRecord {
                        state: JobState::Finished(_),
                        ..
                    }) => None,
                    Some(job) => {
                        job.terminal_waiters.retain(|waiter| !waiter.is_closed());
                        if job.terminal_waiters.len() >= self.inner.config.max_waiters_per_job {
                            return Err(OperatorRulesError::new(
                                ErrorCode::AdmissionRejected,
                                "terminal waiter capacity reached for this job",
                            ));
                        }
                        let (sender, receiver) = oneshot::channel();
                        job.terminal_waiters.push(sender);
                        Some(receiver)
                    }
                    None => None,
                }
            };
            if let Some(receiver) = receiver {
                return receiver
                    .await
                    .map_err(|_| unavailable("operator-rule terminal channel closed"))?;
            }

            // A restarted daemon has no in-memory job entry. Resume a durable
            // receipt that still needs completion through the same per-key
            // registry used by replays, so this caller waits for that exact
            // activation instead of returning its intermediate state.
            let receipt = self.operation(actor, operation_id).await?;
            if requires_post_commit_completion(&receipt) {
                let key = JobKey {
                    actor: actor.identity.clone(),
                    request_id: receipt.request_id.clone(),
                };
                match self
                    .resume_verified_replay(actor.clone(), key, receipt)
                    .await?
                {
                    ResumptionResult::Complete(completed) => return Ok(completed),
                    ResumptionResult::Live(_) => {}
                }
                // An in-process apply owns this receipt. Its terminal waiter
                // is registered on the next pass without polling the disk.
                tokio::task::yield_now().await;
                continue;
            }
            if receipt.persistence != PersistenceState::Prepared {
                return Ok(receipt);
            }
            tokio::task::yield_now().await;
        }
    }

    fn ensure_ready(&self) -> Result<(), OperatorRulesError> {
        if self.inner.recovered.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(unavailable(
                "operator-rule recovery has not completed successfully",
            ))
        }
    }

    fn existing_submission(
        &self,
        key: &JobKey,
        plan_hash: &str,
        expected_config_revision: Option<&str>,
    ) -> Result<Option<ExistingSubmission>, OperatorRulesError> {
        let (sender, receiver) = oneshot::channel();
        let mut jobs = self.inner.jobs.lock().expect("job registry poisoned");
        cleanup_jobs(&mut jobs, &self.inner.config);
        let Some(job) = jobs.get_mut(key) else {
            return Ok(None);
        };
        if job.fingerprint != plan_hash
            || expected_config_revision
                .is_some_and(|expected| expected != job.expected_config_revision.as_str())
        {
            return Err(OperatorRulesError::new(
                ErrorCode::IdempotencyConflict,
                "request_id was already submitted with a different plan or precondition",
            ));
        }
        match &job.state {
            JobState::Prepared(receipt) => {
                let outcome = replay(receipt.clone());
                Ok(Some(ExistingSubmission::Replay(Box::new(outcome))))
            }
            JobState::Finished(receipt)
                if receipt.persistence == PersistenceState::DurabilityUncertain =>
            {
                Ok(Some(ExistingSubmission::ReconcileUncertain))
            }
            JobState::Finished(receipt) => {
                let outcome = replay(receipt.clone());
                Ok(Some(ExistingSubmission::Replay(Box::new(outcome))))
            }
            JobState::Queued => {
                job.prepared_waiters.retain(|waiter| !waiter.is_closed());
                if job.prepared_waiters.len() >= self.inner.config.max_waiters_per_job {
                    return Err(OperatorRulesError::new(
                        ErrorCode::AdmissionRejected,
                        "prepared waiter capacity reached for this job",
                    ));
                }
                job.prepared_waiters.push(sender);
                Ok(Some(ExistingSubmission::Wait(receiver)))
            }
        }
    }

    fn stored_plan(&self, actor: &Actor, plan_id: &str) -> Result<StoredPlan, OperatorRulesError> {
        self.transient_plan(actor, plan_id).ok_or_else(|| {
            OperatorRulesError::new(ErrorCode::PlanConflict, "plan is unknown or expired")
        })
    }

    fn transient_plan(&self, actor: &Actor, plan_id: &str) -> Option<StoredPlan> {
        let mut plans = self.inner.plans.lock().expect("plan registry poisoned");
        let now = Instant::now();
        plans.retain(|_, entry| {
            now.saturating_duration_since(entry.created) < self.inner.config.plan_ttl
        });
        let entry = plans.get(plan_id)?;
        if entry.actor != actor.identity {
            return None;
        }
        Some(entry.clone())
    }
}

impl Inner {
    fn locked_prepared_operation(&self, actor: &Actor, operation_id: &str) -> Option<Receipt> {
        let jobs = self.jobs.lock().expect("job registry poisoned");
        jobs.iter().find_map(|(key, job)| {
            (key.actor == actor.identity).then_some(())?;
            match &job.state {
                JobState::Prepared(receipt)
                    if receipt.operation_id == operation_id
                        && receipt.persistence == PersistenceState::Prepared =>
                {
                    Some(receipt.clone())
                }
                _ => None,
            }
        })
    }

    fn prepared(&self, key: &JobKey, receipt: Receipt) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        let Some(job) = jobs.get_mut(key) else { return };
        job.updated = Instant::now();
        job.state = JobState::Prepared(receipt.clone());
        let outcome = accepted(receipt);
        for waiter in std::mem::take(&mut job.prepared_waiters) {
            let _ = waiter.send(Ok(outcome.clone()));
        }
    }

    fn update_in_progress(&self, key: &JobKey, receipt: Receipt) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        let Some(job) = jobs.get_mut(key) else { return };
        if matches!(job.state, JobState::Prepared(_)) {
            job.updated = Instant::now();
            job.state = JobState::Prepared(receipt);
        }
    }

    fn finished(&self, key: &JobKey, receipt: Receipt) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        let Some(job) = jobs.get_mut(key) else { return };
        let was_queued = matches!(job.state, JobState::Queued);
        job.updated = Instant::now();
        job.state = JobState::Finished(receipt.clone());
        let terminal_receipt = receipt.clone();
        let outcome = if was_queued {
            accepted(receipt)
        } else {
            replay(receipt)
        };
        for waiter in std::mem::take(&mut job.prepared_waiters) {
            let _ = waiter.send(Ok(outcome.clone()));
        }
        for waiter in std::mem::take(&mut job.terminal_waiters) {
            let _ = waiter.send(Ok(terminal_receipt.clone()));
        }
    }

    fn fail_before_intent(&self, key: &JobKey, error: OperatorRulesError) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        if let Some(job) = jobs.remove(key) {
            for waiter in job.prepared_waiters {
                let _ = waiter.send(Err(error.clone()));
            }
            for waiter in job.terminal_waiters {
                let _ = waiter.send(Err(error.clone()));
            }
        }
    }

    fn admit_resumption(
        &self,
        key: JobKey,
        receipt: &Receipt,
    ) -> Result<ResumptionAdmission, OperatorRulesError> {
        let (sender, receiver) = oneshot::channel();
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        cleanup_jobs(&mut jobs, &self.config);
        let live = matches!(jobs.get(&key).map(|job| &job.state), Some(JobState::Queued))
            || matches!(
                jobs.get(&key).map(|job| &job.state),
                Some(JobState::Prepared(active)) if active.operation_id == receipt.operation_id
            );
        if live {
            return Ok(ResumptionAdmission::Live);
        }
        if let Some(JobState::Finished(current)) = jobs.get(&key).map(|job| &job.state) {
            if current.operation_id == receipt.operation_id
                && !requires_post_commit_completion(current)
            {
                return Ok(ResumptionAdmission::Current(Box::new(current.clone())));
            }
        }

        let mut resumptions = self
            .resumptions
            .lock()
            .expect("resumption registry poisoned");
        if let Some(waiters) = resumptions.get_mut(&key) {
            waiters.retain(|waiter| !waiter.is_closed());
            if waiters.len() >= self.config.max_waiters_per_job {
                return Err(OperatorRulesError::new(
                    ErrorCode::AdmissionRejected,
                    "resumption waiter capacity reached for this job",
                ));
            }
            waiters.push(sender);
            return Ok(ResumptionAdmission::Wait(receiver));
        }
        if jobs.len().saturating_add(resumptions.len()) >= self.config.max_jobs {
            return Err(OperatorRulesError::new(
                ErrorCode::AdmissionRejected,
                "job registry capacity reached",
            ));
        }
        resumptions.insert(key, vec![sender]);
        Ok(ResumptionAdmission::Start(receiver))
    }

    fn finish_resumption(&self, key: &JobKey, receipt: Receipt) {
        self.reconcile_operation(&receipt);
        let waiters = self
            .resumptions
            .lock()
            .expect("resumption registry poisoned")
            .remove(key)
            .unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(Ok(receipt.clone()));
        }
    }

    fn fail_resumption(&self, key: &JobKey, error: OperatorRulesError) {
        let waiters = self
            .resumptions
            .lock()
            .expect("resumption registry poisoned")
            .remove(key)
            .unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(Err(error.clone()));
        }
    }

    fn reconcile_uncertain(&self, key: &JobKey, receipt: Receipt) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        let Some(job) = jobs.get_mut(key) else { return };
        if matches!(
            &job.state,
            JobState::Finished(cached)
                if cached.persistence == PersistenceState::DurabilityUncertain
        ) {
            job.updated = Instant::now();
            job.state = JobState::Finished(receipt);
        }
    }

    fn reconcile_operation(&self, receipt: &Receipt) {
        let mut jobs = self.jobs.lock().expect("job registry poisoned");
        for job in jobs.values_mut() {
            if matches!(
                &job.state,
                JobState::Finished(cached) if cached.operation_id == receipt.operation_id
            ) {
                job.updated = Instant::now();
                job.state = JobState::Finished(receipt.clone());
                break;
            }
        }
    }
}

async fn run_job(inner: Arc<Inner>, job: ApplyJobRequest) {
    let service = inner.service.clone();
    let limits = job.limits;
    let actor = job.actor;
    let request = job.request;
    let key = job.key;
    let apply_actor = actor.clone();
    let callback_inner = inner.clone();
    let callback_key = key.clone();
    let callback = inner.on_durable_intent.clone();
    let result = tokio::task::spawn_blocking(move || {
        service.apply_with_prepared(&apply_actor, &request, limits, move |receipt| {
            let receipt = receipt.clone();
            callback_inner.prepared(&callback_key, receipt.clone());
            // The registry is the local hand-off for a durable intent. Publish
            // it before invoking an observer: an observer may be slow or its
            // original requester may disconnect, but neither may force a
            // terminal waiter back through the configuration lock this
            // transaction still holds.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(&receipt)));
        })
    })
    .await;

    let mut receipt = match result {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(error)) => {
            inner.fail_before_intent(&key, error);
            return;
        }
        Err(error) => {
            inner.fail_before_intent(
                &key,
                unavailable(format!("operator-rule worker failed: {error}")),
            );
            return;
        }
    };

    inner.update_in_progress(&key, receipt.clone());
    receipt = complete_post_commit(inner.clone(), &actor, receipt).await;
    inner.finished(&key, receipt);
}

async fn run_resumption(inner: Arc<Inner>, job: ResumeJobRequest) {
    let service = inner.service.clone();
    let lookup_actor = job.actor.clone();
    let operation_id = job.receipt.operation_id.clone();
    let current = blocking(inner.blocking_slots.clone(), move || {
        service.operation(&lookup_actor, &operation_id)
    })
    .await;
    match current {
        Ok(receipt) => {
            let receipt = complete_post_commit(inner.clone(), &job.actor, receipt).await;
            inner.finish_resumption(&job.key, receipt);
        }
        Err(error) => inner.fail_resumption(&job.key, error),
    }
}

async fn complete_post_commit(inner: Arc<Inner>, actor: &Actor, mut receipt: Receipt) -> Receipt {
    if receipt.persistence == PersistenceState::Committed
        && receipt.changed
        && receipt.activation.state == "pending"
    {
        receipt = activate_committed(inner.clone(), actor, receipt).await;
    }
    if is_durable_terminal(&receipt) && receipt.audit != "recorded" {
        receipt = record_receipt_audit(inner, actor, receipt).await;
    }
    receipt
}

fn is_durable_terminal(receipt: &Receipt) -> bool {
    matches!(
        receipt.persistence,
        PersistenceState::Committed | PersistenceState::Aborted
    )
}

fn requires_post_commit_completion(receipt: &Receipt) -> bool {
    (receipt.persistence == PersistenceState::Committed
        && receipt.changed
        && receipt.activation.state == "pending")
        || (is_durable_terminal(receipt) && receipt.audit != "recorded")
}

/// Record an activation request before handing it to the daemon, then retain
/// the daemon's exact publication observation on the same durable receipt.
async fn activate_committed(inner: Arc<Inner>, actor: &Actor, receipt: Receipt) -> Receipt {
    let operation_id = receipt.operation_id.clone();
    let request_id = receipt.request_id.clone();
    let correlation_id = match new_correlation_id() {
        Ok(correlation_id) => correlation_id,
        Err(error) => {
            return complete_activation(
                inner,
                actor,
                &request_id,
                &operation_id,
                ReceiptCompletion::Unknown {
                    correlation_id: None,
                    reload_outcome: "correlation_failed".into(),
                    failure: Some(error.to_string()),
                },
                receipt,
            )
            .await;
        }
    };

    let service = inner.service.clone();
    let queued_actor = actor.clone();
    let queued_request_id = request_id.clone();
    let queued_operation_id = operation_id.clone();
    let queued_correlation_id = correlation_id.clone();
    let queued = blocking(inner.blocking_slots.clone(), move || {
        service.record_activation_queued(
            &queued_actor,
            &queued_request_id,
            &queued_operation_id,
            queued_correlation_id,
        )
    })
    .await;
    let receipt = match queued {
        Ok(receipt) => receipt,
        Err(error) => {
            let mut cached = receipt;
            cached.diagnostics.push(format!(
                "policy persisted but activation queue state could not be recorded: {}",
                error.message
            ));
            return cached;
        }
    };

    let Some(sender) = inner.activation_tx.as_ref() else {
        return complete_activation(
            inner,
            actor,
            &request_id,
            &operation_id,
            ReceiptCompletion::Unknown {
                correlation_id: Some(correlation_id),
                reload_outcome: "not_configured".into(),
                failure: Some("activation delivery is not configured".into()),
            },
            receipt,
        )
        .await;
    };
    let Some(expected_policy_hash) = receipt.operator_policy_hash.clone() else {
        return complete_activation(
            inner,
            actor,
            &request_id,
            &operation_id,
            ReceiptCompletion::Unknown {
                correlation_id: Some(correlation_id),
                reload_outcome: "policy_hash_unavailable".into(),
                failure: Some("committed receipt has no operator policy hash".into()),
            },
            receipt,
        )
        .await;
    };

    let (completion, completion_rx) = oneshot::channel();
    let request = ActivationRequest {
        operation_id: operation_id.clone(),
        request_id: request_id.clone(),
        actor: actor.identity.clone(),
        correlation_id: correlation_id.clone(),
        expected_config_revision: receipt.config_revision.clone(),
        expected_policy_hash,
        completion,
    };
    match sender.try_send(request) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            return complete_activation(
                inner,
                actor,
                &request_id,
                &operation_id,
                ReceiptCompletion::Failed {
                    correlation_id,
                    reload_outcome: "queue_full".into(),
                    failure: "activation request queue is full".into(),
                },
                receipt,
            )
            .await;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            return complete_activation(
                inner,
                actor,
                &request_id,
                &operation_id,
                ReceiptCompletion::Failed {
                    correlation_id,
                    reload_outcome: "channel_closed".into(),
                    failure: "activation request channel is unavailable".into(),
                },
                receipt,
            )
            .await;
        }
    }

    let completion = match completion_rx.await {
        Ok(ActivationResult::Applied(active)) => ReceiptCompletion::Applied {
            correlation_id,
            active_config_revision: active.config_revision,
            active_policy_hash: active.operator_policy_hash,
            daemon_instance_id: active.daemon_instance_id,
        },
        Ok(ActivationResult::Superseded {
            active,
            superseding_operation_id,
        }) => ReceiptCompletion::Superseded {
            correlation_id,
            active_config_revision: active.config_revision,
            active_policy_hash: active.operator_policy_hash,
            daemon_instance_id: active.daemon_instance_id,
            superseded_by: superseding_operation_id,
        },
        Ok(ActivationResult::Rejected { reason, .. }) => ReceiptCompletion::Failed {
            correlation_id,
            reload_outcome: "rejected".into(),
            failure: reason,
        },
        Ok(ActivationResult::Unknown { reason, .. }) => ReceiptCompletion::Unknown {
            correlation_id: Some(correlation_id),
            reload_outcome: "unknown".into(),
            failure: Some(reason),
        },
        Err(_) => ReceiptCompletion::Unknown {
            correlation_id: Some(correlation_id),
            reload_outcome: "response_dropped".into(),
            failure: Some("activation receiver dropped without a result".into()),
        },
    };
    complete_activation(
        inner,
        actor,
        &request_id,
        &operation_id,
        completion,
        receipt,
    )
    .await
}

async fn complete_activation(
    inner: Arc<Inner>,
    actor: &Actor,
    request_id: &str,
    operation_id: &str,
    completion: ReceiptCompletion,
    mut fallback: Receipt,
) -> Receipt {
    let service = inner.service.clone();
    let actor = actor.clone();
    let request_id = request_id.to_owned();
    let operation_id = operation_id.to_owned();
    match blocking(inner.blocking_slots.clone(), move || {
        service.complete_activation(&actor, &request_id, &operation_id, completion)
    })
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            fallback.diagnostics.push(format!(
                "policy persisted but activation outcome could not be recorded: {}",
                error.message
            ));
            fallback
        }
    }
}

async fn record_receipt_audit(inner: Arc<Inner>, actor: &Actor, mut fallback: Receipt) -> Receipt {
    let service = inner.service.clone();
    let actor = actor.clone();
    let request_id = fallback.request_id.clone();
    let operation_id = fallback.operation_id.clone();
    match blocking(inner.blocking_slots.clone(), move || {
        service.record_receipt_audit(&actor, &request_id, &operation_id)
    })
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            fallback.audit = "pending".into();
            fallback.diagnostics.push(format!(
                "policy persisted but semantic audit delivery could not be recorded: {}",
                error.message
            ));
            fallback
        }
    }
}

async fn blocking<T: Send + 'static>(
    slots: Arc<Semaphore>,
    operation: impl FnOnce() -> Result<T, OperatorRulesError> + Send + 'static,
) -> Result<T, OperatorRulesError> {
    let permit = slots.try_acquire_owned().map_err(|_| {
        OperatorRulesError::new(
            ErrorCode::AdmissionRejected,
            "operator-rule blocking-work capacity reached",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|error| unavailable(format!("operator-rule worker failed: {error}")))?
}

fn cleanup_jobs(jobs: &mut BTreeMap<JobKey, JobRecord>, config: &OperatorRuleJobConfig) {
    let now = Instant::now();
    jobs.retain(|_, job| {
        !matches!(job.state, JobState::Finished(_))
            || now.saturating_duration_since(job.updated) < config.terminal_job_ttl
    });
}

fn unique_id(plans: &BTreeMap<String, StoredPlan>) -> Result<String, OperatorRulesError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| unavailable(format!("plan identity entropy failed: {error}")))?;
        let id = hex::encode(bytes);
        if !plans.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(unavailable("could not allocate a unique plan identity"))
}

fn accepted(receipt: Receipt) -> SubmitOutcome {
    SubmitOutcome::Accepted {
        operation_id: receipt.operation_id.clone(),
        location: operation_location(&receipt.operation_id),
        prepared: receipt,
    }
}

fn replay(receipt: Receipt) -> SubmitOutcome {
    SubmitOutcome::Replay {
        operation_id: receipt.operation_id.clone(),
        location: operation_location(&receipt.operation_id),
        receipt,
    }
}

pub fn operation_location(operation_id: &str) -> String {
    format!("/api/v1/operator-rules/operations/{operation_id}")
}

fn unavailable(message: impl Into<String>) -> OperatorRulesError {
    OperatorRulesError::new(ErrorCode::StorageUnavailable, message)
}

fn map_persistence(value: policy_transaction::Persistence) -> PersistenceState {
    match value {
        policy_transaction::Persistence::Prepared => PersistenceState::Prepared,
        policy_transaction::Persistence::Committed => PersistenceState::Committed,
        policy_transaction::Persistence::Aborted => PersistenceState::Aborted,
        policy_transaction::Persistence::DurabilityUncertain => {
            PersistenceState::DurabilityUncertain
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASYNC_IO_WATCHDOG: Duration = Duration::from_secs(30);

    const CONFIG: &str = r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Household"
lists = {}
"#;

    fn actor() -> Actor {
        Actor {
            identity: "api-admin".into(),
            origin: "test".into(),
        }
    }

    async fn fixture(
        callback: DurableIntentCallback,
    ) -> (
        tempfile::TempDir,
        OperatorRuleJobClient,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            None,
            callback,
        );
        client.recover().await.unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(supervisor.run(shutdown_rx));
        (temp, client, shutdown_tx, handle)
    }

    async fn fixture_with_activation(
        callback: DurableIntentCallback,
    ) -> (
        tempfile::TempDir,
        OperatorRuleJobClient,
        mpsc::Receiver<ActivationRequest>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (activation_tx, activation_rx) = mpsc::channel(1);
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            Some(activation_tx),
            callback,
        );
        client.recover().await.unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(supervisor.run(shutdown_rx));
        (temp, client, activation_rx, shutdown_tx, handle)
    }

    async fn create_plan(client: &OperatorRuleJobClient, request_id: &str) -> PreparedPlan {
        let revision = client
            .lists(PageRequest::default(), TransportLimits::REST)
            .await
            .unwrap()
            .config_revision;
        client
            .plan(
                actor(),
                BatchRequest {
                    contract_version: 1,
                    request_id: request_id.into(),
                    expected_config_revision: revision,
                    operations: vec![crate::operator_rules::Operation::CreateList {
                        id: "local".into(),
                        display_name: "Local".into(),
                        description: String::new(),
                        into: None,
                    }],
                    expected_plan_hash: None,
                },
                PageRequest::default(),
                TransportLimits::REST,
            )
            .await
            .unwrap()
    }

    fn offline_committed_request(
        service: &OperatorRulesService,
        request_id: &str,
    ) -> (BatchRequest, Receipt) {
        let mut request = BatchRequest {
            contract_version: 1,
            request_id: request_id.into(),
            expected_config_revision: service.metadata().unwrap().config_revision,
            operations: vec![crate::operator_rules::Operation::CreateList {
                id: format!("offline-{request_id}"),
                display_name: "Offline local".into(),
                description: String::new(),
                into: None,
            }],
            expected_plan_hash: None,
        };
        let plan = service.plan(&request, TransportLimits::IPC).unwrap();
        request.expected_plan_hash = Some(plan.plan_hash);
        let receipt = service
            .apply_with_prepared(&actor(), &request, TransportLimits::IPC, |_| {})
            .unwrap();
        assert_eq!(receipt.persistence, PersistenceState::Committed);
        assert_eq!(receipt.activation.state, "pending");
        assert_eq!(receipt.audit, "pending");
        (request, receipt)
    }

    #[tokio::test]
    async fn offline_replay_resumes_pending_activation_once_and_returns_applied_receipt() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (activation_tx, mut activation_rx) = mpsc::channel(1);
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service.clone(),
            OperatorRuleJobConfig::default(),
            Some(activation_tx),
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));
        let (request, committed) = offline_committed_request(&service, "offline-replay");

        let first_client = client.clone();
        let first_request = request.clone();
        let first = tokio::spawn(async move {
            first_client
                .replay_request(actor(), first_request, TransportLimits::IPC)
                .await
        });
        let activation = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(activation.operation_id, committed.operation_id);
        assert_eq!(activation.request_id, committed.request_id);
        assert_eq!(activation.actor, actor().identity);

        let duplicate_client = client.clone();
        let duplicate_request = request.clone();
        let duplicate = tokio::spawn(async move {
            duplicate_client
                .replay_request(actor(), duplicate_request, TransportLimits::IPC)
                .await
        });
        let key = JobKey {
            actor: actor().identity,
            request_id: request.request_id.clone(),
        };
        tokio::time::timeout(ASYNC_IO_WATCHDOG, async {
            loop {
                if client
                    .inner
                    .resumptions
                    .lock()
                    .unwrap()
                    .get(&key)
                    .is_some_and(|waiters| waiters.len() == 2)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        activation
            .completion
            .send(ActivationResult::Applied(ActivePolicyIdentity {
                daemon_instance_id: "d".repeat(32),
                config_revision: activation.expected_config_revision.clone(),
                operator_policy_hash: activation.expected_policy_hash.clone(),
                resolver_generation: 1,
            }))
            .unwrap();
        let replayed = first.await.unwrap().unwrap().unwrap();
        let duplicate = duplicate.await.unwrap().unwrap().unwrap();
        assert_eq!(duplicate, replayed);
        assert_eq!(replayed.activation.state, "applied");
        assert_eq!(replayed.audit, "recorded");

        let stale = client
            .resume_verified_replay(actor(), key, committed)
            .await
            .unwrap()
            .into_receipt();
        assert_eq!(stale, replayed);
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn startup_recovery_resumes_commit_left_before_activation_queueing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (request, committed) = offline_committed_request(&service, "restart-resume");

        let (activation_tx, mut activation_rx) = mpsc::channel(1);
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            Some(activation_tx),
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));

        let activation = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(activation.operation_id, committed.operation_id);

        let actor = actor();
        let waiting_client = client.clone();
        let waiting_actor = actor.clone();
        let operation_id = committed.operation_id.clone();
        let waiting = tokio::spawn(async move {
            waiting_client
                .wait_terminal(&waiting_actor, &operation_id)
                .await
        });
        let replay_client = client.clone();
        let replay_actor = actor.clone();
        let replay = tokio::spawn(async move {
            replay_client
                .replay_request(replay_actor, request, TransportLimits::IPC)
                .await
        });
        let key = JobKey {
            actor: actor.identity.clone(),
            request_id: committed.request_id.clone(),
        };
        tokio::time::timeout(ASYNC_IO_WATCHDOG, async {
            loop {
                if client
                    .inner
                    .resumptions
                    .lock()
                    .unwrap()
                    .get(&key)
                    .is_some_and(|waiters| waiters.len() == 2)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        activation
            .completion
            .send(ActivationResult::Applied(ActivePolicyIdentity {
                daemon_instance_id: "d".repeat(32),
                config_revision: activation.expected_config_revision.clone(),
                operator_policy_hash: activation.expected_policy_hash.clone(),
                resolver_generation: 1,
            }))
            .unwrap();

        let observed = waiting.await.unwrap().unwrap();
        let replayed = replay.await.unwrap().unwrap().unwrap();
        assert_eq!(observed.activation.state, "applied");
        assert_eq!(observed.audit, "recorded");
        assert_eq!(replayed, observed);
        assert_eq!(
            client
                .operation(&actor, &committed.operation_id)
                .await
                .unwrap(),
            observed,
            "startup completion must also be durable"
        );
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn restart_wait_returns_after_one_failed_audit_attempt() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (_, committed) = offline_committed_request(&service, "audit-stays-pending");
        let pending = service
            .complete_activation(
                &actor(),
                &committed.request_id,
                &committed.operation_id,
                ReceiptCompletion::Failed {
                    correlation_id: "audit-failure".into(),
                    reload_outcome: "rejected".into(),
                    failure: "test rejection".into(),
                },
            )
            .unwrap();
        assert_eq!(pending.activation.state, "failed");
        assert_eq!(pending.audit, "pending");
        std::fs::write(
            temp.path().join(crate::config::audit::AUDIT_DIR_NAME),
            b"blocks audit directory creation",
        )
        .unwrap();

        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            None,
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));

        let observed = tokio::time::timeout(
            ASYNC_IO_WATCHDOG,
            client.wait_terminal(&actor(), &committed.operation_id),
        )
        .await
        .expect("a failed recovery attempt must not spin forever")
        .unwrap();
        assert_eq!(observed.activation.state, "failed");
        assert_eq!(observed.audit, "pending");
        assert!(observed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("audit")));

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_rejects_waiters_for_unstarted_recovery_jobs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (_, first) = offline_committed_request(&service, "shutdown-first");
        let (_, second) = offline_committed_request(&service, "shutdown-second");
        let (activation_tx, mut activation_rx) = mpsc::channel(2);
        let config = OperatorRuleJobConfig {
            concurrency: 1,
            ..OperatorRuleJobConfig::default()
        };
        let (supervisor, client) =
            OperatorRuleJobSupervisor::new(service, config, Some(activation_tx), Arc::new(|_| {}));
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));
        let active = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let abandoned = if active.operation_id == first.operation_id {
            second
        } else {
            first
        };
        let abandoned_key = JobKey {
            actor: actor().identity,
            request_id: abandoned.request_id.clone(),
        };
        let waiting_client = client.clone();
        let operation_id = abandoned.operation_id.clone();
        let waiting =
            tokio::spawn(
                async move { waiting_client.wait_terminal(&actor(), &operation_id).await },
            );
        tokio::time::timeout(ASYNC_IO_WATCHDOG, async {
            loop {
                if client
                    .inner
                    .resumptions
                    .lock()
                    .unwrap()
                    .get(&abandoned_key)
                    .is_some_and(|waiters| !waiters.is_empty())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        shutdown.send(()).unwrap();
        let error = tokio::time::timeout(ASYNC_IO_WATCHDOG, waiting)
            .await
            .expect("shutdown must release recovery waiters")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StorageUnavailable);
        active
            .completion
            .send(ActivationResult::Unknown {
                active: None,
                reason: "test shutdown".into(),
            })
            .unwrap();
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_waiters_do_not_consume_per_job_capacity() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (_, receipt) = offline_committed_request(&service, "cancelled-waiters");
        let config = OperatorRuleJobConfig {
            max_waiters_per_job: 1,
            ..OperatorRuleJobConfig::default()
        };
        let (_supervisor, client) =
            OperatorRuleJobSupervisor::new(service, config, None, Arc::new(|_| {}));
        client.inner.recovered.store(true, Ordering::Release);
        let key = JobKey {
            actor: actor().identity,
            request_id: receipt.request_id.clone(),
        };

        let (closed_prepared, prepared_receiver) = oneshot::channel();
        drop(prepared_receiver);
        client.inner.jobs.lock().unwrap().insert(
            key.clone(),
            JobRecord {
                fingerprint: "plan".into(),
                expected_config_revision: "revision".into(),
                state: JobState::Queued,
                updated: Instant::now(),
                prepared_waiters: vec![closed_prepared],
                terminal_waiters: Vec::new(),
            },
        );
        let prepared = client
            .existing_submission(&key, "plan", Some("revision"))
            .unwrap();
        assert!(matches!(prepared, Some(ExistingSubmission::Wait(_))));
        drop(prepared);

        let (closed_terminal, terminal_receiver) = oneshot::channel();
        drop(terminal_receiver);
        client.inner.jobs.lock().unwrap().insert(
            key.clone(),
            JobRecord {
                fingerprint: "plan".into(),
                expected_config_revision: "revision".into(),
                state: JobState::Prepared(receipt.clone()),
                updated: Instant::now(),
                prepared_waiters: Vec::new(),
                terminal_waiters: vec![closed_terminal],
            },
        );
        let terminal_client = client.clone();
        let terminal_operation = receipt.operation_id.clone();
        let terminal = tokio::spawn(async move {
            terminal_client
                .wait_terminal(&actor(), &terminal_operation)
                .await
        });
        tokio::time::timeout(ASYNC_IO_WATCHDOG, async {
            loop {
                if client
                    .inner
                    .jobs
                    .lock()
                    .unwrap()
                    .get(&key)
                    .is_some_and(|job| {
                        job.terminal_waiters.len() == 1 && !job.terminal_waiters[0].is_closed()
                    })
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        client.inner.finished(&key, receipt.clone());
        assert_eq!(terminal.await.unwrap().unwrap(), receipt);
        client.inner.jobs.lock().unwrap().clear();

        let resumption_key = JobKey {
            actor: actor().identity,
            request_id: "cancelled-resumption".into(),
        };
        let (closed_resumption, resumption_receiver) = oneshot::channel();
        drop(resumption_receiver);
        client
            .inner
            .resumptions
            .lock()
            .unwrap()
            .insert(resumption_key.clone(), vec![closed_resumption]);
        let admission = client
            .inner
            .admit_resumption(resumption_key, &receipt)
            .unwrap();
        assert!(matches!(admission, ResumptionAdmission::Wait(_)));
    }

    #[tokio::test]
    async fn terminal_replay_retries_audit_without_reactivating() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (activation_tx, mut activation_rx) = mpsc::channel(1);
        let (supervisor, client) = OperatorRuleJobSupervisor::new(
            service.clone(),
            OperatorRuleJobConfig::default(),
            Some(activation_tx),
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));
        let (request, _) = offline_committed_request(&service, "terminal-replay");

        let first_client = client.clone();
        let first_request = request.clone();
        let first = tokio::spawn(async move {
            first_client
                .replay_request(actor(), first_request, TransportLimits::IPC)
                .await
        });
        let activation = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        activation
            .completion
            .send(ActivationResult::Rejected {
                active: None,
                reason: "reload rejected".into(),
            })
            .unwrap();
        let terminal = first.await.unwrap().unwrap().unwrap();
        assert_eq!(terminal.activation.state, "failed");
        assert_eq!(terminal.audit, "recorded");

        let replayed = client
            .replay_request(actor(), request, TransportLimits::IPC)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replayed, terminal);
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn rest_apply_replay_resumes_pending_audit_without_reactivation() {
        let (temp, client, mut activation_rx, shutdown, supervisor) =
            fixture_with_activation(Arc::new(|_| {})).await;
        let plan = create_plan(&client, "rest-audit-retry").await;
        let audit_dir = temp.path().join(crate::config::audit::AUDIT_DIR_NAME);
        std::fs::write(&audit_dir, b"blocks audit directory creation").unwrap();

        let accepted = client
            .submit(
                actor(),
                plan.plan_id.clone(),
                plan.summary.plan_hash.clone(),
                "rest-audit-retry".into(),
            )
            .await
            .unwrap();
        let operation_id = match accepted {
            SubmitOutcome::Accepted { operation_id, .. } => operation_id,
            SubmitOutcome::Replay { .. } => panic!("first submission must be accepted"),
        };
        let activation = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        activation
            .completion
            .send(ActivationResult::Applied(ActivePolicyIdentity {
                daemon_instance_id: "d".repeat(32),
                config_revision: activation.expected_config_revision.clone(),
                operator_policy_hash: activation.expected_policy_hash.clone(),
                resolver_generation: 1,
            }))
            .unwrap();
        let pending = client.wait_terminal(&actor(), &operation_id).await.unwrap();
        assert_eq!(pending.activation.state, "applied");
        assert_eq!(pending.audit, "pending");

        std::fs::remove_file(&audit_dir).unwrap();
        let replayed = client
            .submit(
                actor(),
                plan.plan_id,
                plan.summary.plan_hash,
                "rest-audit-retry".into(),
            )
            .await
            .unwrap();
        let receipt = match replayed {
            SubmitOutcome::Replay { receipt, .. } => receipt,
            SubmitOutcome::Accepted { .. } => panic!("retry must reuse the durable operation"),
        };
        assert_eq!(receipt.operation_id, operation_id);
        assert_eq!(receipt.activation.state, "applied");
        assert_eq!(receipt.audit, "recorded");
        assert!(matches!(
            activation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn dropping_submit_after_intent_does_not_cancel_the_job() {
        let (intent_tx, intent_rx) = std::sync::mpsc::channel::<Receipt>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let callback: DurableIntentCallback = Arc::new(move |receipt| {
            intent_tx.send(receipt.clone()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        });
        let (temp, client, shutdown, supervisor) = fixture(callback).await;
        let plan = create_plan(&client, "disconnect").await;
        let submit_client = client.clone();
        let plan_id = plan.plan_id.clone();
        let plan_hash = plan.summary.plan_hash.clone();
        let submit = tokio::spawn(async move {
            submit_client
                .submit(actor(), plan_id, plan_hash, "disconnect".into())
                .await
        });
        let prepared = tokio::task::spawn_blocking(move || intent_rx.recv().unwrap())
            .await
            .unwrap();
        {
            let jobs = client.inner.jobs.lock().unwrap();
            let job = jobs
                .get(&JobKey {
                    actor: actor().identity,
                    request_id: "disconnect".into(),
                })
                .expect("durable intent must remain in the local registry");
            assert!(matches!(
                &job.state,
                JobState::Prepared(receipt) if receipt.operation_id == prepared.operation_id
            ));
        }
        let observed = tokio::time::timeout(
            Duration::from_secs(2),
            client.operation(&actor(), &prepared.operation_id),
        )
        .await
        .expect("prepared operation lookup must not wait for the configuration lock")
        .unwrap();
        assert_eq!(observed, prepared);
        submit.abort();
        release_tx.send(()).unwrap();

        let receipt = client
            .wait_terminal(&actor(), &prepared.operation_id)
            .await
            .unwrap();
        assert_eq!(receipt.persistence, PersistenceState::Committed);
        assert!(receipt.operator_policy_hash.is_some());
        assert_eq!(receipt.activation.state, "unknown");
        assert!(temp.path().join("packs/local.txt").exists());
        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn retry_reuses_location_and_restart_reads_durable_state() {
        let (temp, client, shutdown, supervisor) = fixture(Arc::new(|_| {})).await;
        let plan = create_plan(&client, "replay").await;
        let plan_id = plan.plan_id.clone();
        let plan_hash = plan.summary.plan_hash.clone();
        let base_revision = plan.summary.base_config_revision.clone();
        let first = client
            .submit(actor(), plan_id.clone(), plan_hash.clone(), "replay".into())
            .await
            .unwrap();
        let (operation_id, location) = match first {
            SubmitOutcome::Accepted {
                operation_id,
                location,
                ..
            } => (operation_id, location),
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let terminal = client.wait_terminal(&actor(), &operation_id).await.unwrap();
        assert_eq!(terminal.persistence, PersistenceState::Committed);
        let second = client
            .submit(actor(), plan_id.clone(), plan_hash.clone(), "replay".into())
            .await
            .unwrap();
        match second {
            SubmitOutcome::Replay {
                operation_id: replay_id,
                location: replay_location,
                ..
            } => {
                assert_eq!(replay_id, operation_id);
                assert_eq!(replay_location, location);
            }
            other => panic!("unexpected replay outcome: {other:?}"),
        }
        let _ = shutdown.send(());
        supervisor.await.unwrap();

        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (restarted, restarted_client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            None,
            Arc::new(|_| {}),
        );
        let recovery = restarted_client.recover().await.unwrap();
        assert!(matches!(recovery.state.as_str(), "clean" | "recovered"));
        let durable = restarted_client
            .operation(&actor(), &operation_id)
            .await
            .unwrap();
        assert_eq!(durable.persistence, PersistenceState::Committed);
        assert!(durable.operator_policy_hash.is_some());
        assert_eq!(durable.activation.state, "unknown");
        let restarted_replay = restarted_client
            .submit_with_precondition(
                actor(),
                plan_id.clone(),
                plan_hash.clone(),
                "replay".into(),
                base_revision.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(
            restarted_replay,
            SubmitOutcome::Replay {
                ref operation_id,
                ref location,
                ..
            } if operation_id == &durable.operation_id
                && location == &operation_location(&durable.operation_id)
        ));
        let changed_hash = restarted_client
            .submit_with_precondition(
                actor(),
                plan_id.clone(),
                "0".repeat(64),
                "replay".into(),
                base_revision.clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(changed_hash.code, ErrorCode::IdempotencyConflict);
        let changed_precondition = restarted_client
            .submit_with_precondition(actor(), plan_id, plan_hash, "replay".into(), "0".repeat(64))
            .await
            .unwrap_err();
        assert_eq!(changed_precondition.code, ErrorCode::IdempotencyConflict);
        assert_eq!(
            restarted_client
                .wait_terminal(&actor(), &operation_id)
                .await
                .unwrap(),
            durable
        );
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(restarted.run(shutdown_rx));
        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn plan_registry_is_actor_scoped_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let config = OperatorRuleJobConfig {
            max_plans: 1,
            ..OperatorRuleJobConfig::default()
        };
        let (_supervisor, client) =
            OperatorRuleJobSupervisor::new(service, config, None, Arc::new(|_| {}));
        client.recover().await.unwrap();
        let plan = create_plan(&client, "one").await;
        let other = Actor {
            identity: "other".into(),
            origin: "test".into(),
        };
        assert_eq!(
            client
                .plan_impacts(&other, &plan.plan_id, PageRequest::default())
                .unwrap_err()
                .code,
            ErrorCode::PlanConflict
        );
        let revision = client
            .lists(PageRequest::default(), TransportLimits::REST)
            .await
            .unwrap()
            .config_revision;
        std::fs::write(temp.path().join("config.toml"), "not valid TOML").unwrap();
        let error = client
            .plan(
                actor(),
                BatchRequest {
                    contract_version: 1,
                    request_id: "two".into(),
                    expected_config_revision: revision,
                    operations: vec![crate::operator_rules::Operation::CreateList {
                        id: "other".into(),
                        display_name: String::new(),
                        description: String::new(),
                        into: None,
                    }],
                    expected_plan_hash: None,
                },
                PageRequest::default(),
                TransportLimits::REST,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AdmissionRejected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_admission_survives_handler_cancellation() {
        let slots = Arc::new(Semaphore::new(1));
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_slots = slots.clone();
        let worker = tokio::spawn(async move {
            blocking(worker_slots, move || {
                let _ = entered_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
        });
        entered_rx.await.unwrap();
        worker.abort();

        let error = blocking(slots.clone(), || Ok(())).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::AdmissionRejected);

        release_tx.send(()).unwrap();
        tokio::time::timeout(ASYNC_IO_WATCHDOG, async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        blocking(slots, || Ok(())).await.unwrap();
    }

    #[tokio::test]
    async fn operation_and_replay_refresh_an_uncertain_cache() {
        let (_temp, client, shutdown, supervisor) = fixture(Arc::new(|_| {})).await;
        let plan = create_plan(&client, "reconcile").await;
        let first = client
            .submit(
                actor(),
                plan.plan_id.clone(),
                plan.summary.plan_hash.clone(),
                "reconcile".into(),
            )
            .await
            .unwrap();
        let operation_id = match first {
            SubmitOutcome::Accepted { operation_id, .. } => operation_id,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let committed = client.wait_terminal(&actor(), &operation_id).await.unwrap();
        assert_eq!(committed.persistence, PersistenceState::Committed);
        let key = JobKey {
            actor: actor().identity,
            request_id: "reconcile".into(),
        };
        let poison_cache = || {
            let mut jobs = client.inner.jobs.lock().unwrap();
            let job = jobs.get_mut(&key).unwrap();
            let mut uncertain = committed.clone();
            uncertain.persistence = PersistenceState::DurabilityUncertain;
            job.state = JobState::Finished(uncertain);
        };

        poison_cache();
        let observed = client.operation(&actor(), &operation_id).await.unwrap();
        assert_eq!(observed.persistence, PersistenceState::Committed);

        poison_cache();
        let replay = client
            .submit(
                actor(),
                plan.plan_id,
                plan.summary.plan_hash,
                "reconcile".into(),
            )
            .await
            .unwrap();
        let SubmitOutcome::Replay { receipt, .. } = replay else {
            panic!("uncertain cache must resolve as a replay")
        };
        assert_eq!(receipt.persistence, PersistenceState::Committed);

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn activation_result_is_durable_and_operation_reconciles_cached_receipt() {
        let (_temp, client, mut activation_rx, shutdown, supervisor) =
            fixture_with_activation(Arc::new(|_| {})).await;
        let plan = create_plan(&client, "activation-ack").await;
        let submitted = client
            .submit(
                actor(),
                plan.plan_id,
                plan.summary.plan_hash,
                "activation-ack".into(),
            )
            .await
            .unwrap();
        let operation_id = match submitted {
            SubmitOutcome::Accepted { operation_id, .. } => operation_id,
            other => panic!("unexpected submission outcome: {other:?}"),
        };
        let activation = tokio::time::timeout(ASYNC_IO_WATCHDOG, activation_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(activation.operation_id, operation_id);
        assert_eq!(activation.request_id, "activation-ack");
        assert_eq!(activation.actor, actor().identity);
        assert_eq!(activation.expected_config_revision.len(), 64);
        assert_eq!(activation.expected_policy_hash.len(), 64);
        let queued = client.operation(&actor(), &operation_id).await.unwrap();
        assert_eq!(queued.activation.state, "pending");
        assert_eq!(queued.activation.reload_outcome.as_deref(), Some("queued"));
        assert_eq!(
            queued.activation.correlation_id.as_deref(),
            Some(activation.correlation_id.as_str())
        );
        activation
            .completion
            .send(ActivationResult::Unknown {
                active: None,
                reason: "daemon stopped before publication could be observed".into(),
            })
            .unwrap();

        let terminal = client.wait_terminal(&actor(), &operation_id).await.unwrap();
        let durable_after_completion = client.operation(&actor(), &operation_id).await.unwrap();
        assert_eq!(
            durable_after_completion.activation.state, "unknown",
            "activation diagnostics: {:?}; cached terminal: {:?}",
            durable_after_completion.diagnostics, terminal
        );
        assert_eq!(terminal, durable_after_completion);
        assert_eq!(
            terminal.activation.reload_outcome.as_deref(),
            Some("unknown")
        );
        assert_eq!(terminal.audit, "recorded");

        let key = JobKey {
            actor: actor().identity,
            request_id: "activation-ack".into(),
        };
        {
            let mut jobs = client.inner.jobs.lock().unwrap();
            let job = jobs.get_mut(&key).unwrap();
            let mut stale = terminal.clone();
            stale.activation.state = "pending".into();
            stale.activation.reload_outcome = Some("queued".into());
            job.state = JobState::Finished(stale);
        }
        let observed = client.operation(&actor(), &operation_id).await.unwrap();
        assert_eq!(observed, terminal);

        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }

    #[tokio::test]
    async fn stored_plan_freezes_the_originating_transport_limits() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (_supervisor, client) = OperatorRuleJobSupervisor::new(
            service,
            OperatorRuleJobConfig::default(),
            None,
            Arc::new(|_| {}),
        );
        client.recover().await.unwrap();
        let limits = TransportLimits {
            default_page_size: 1,
            max_page_size: 1,
            ..TransportLimits::IPC
        };
        let revision = client
            .lists(PageRequest::default(), limits)
            .await
            .unwrap()
            .config_revision;
        let plan = client
            .plan(
                actor(),
                BatchRequest {
                    contract_version: 1,
                    request_id: "ipc-limits".into(),
                    expected_config_revision: revision,
                    operations: vec![
                        crate::operator_rules::Operation::CreateList {
                            id: "local".into(),
                            display_name: String::new(),
                            description: String::new(),
                            into: None,
                        },
                        crate::operator_rules::Operation::Mount {
                            id: "local".into(),
                            profile_id: "household".into(),
                        },
                    ],
                    expected_plan_hash: None,
                },
                PageRequest::default(),
                limits,
            )
            .await
            .unwrap();
        let error = client
            .plan_impacts(
                &actor(),
                &plan.plan_id,
                PageRequest {
                    cursor: None,
                    limit: Some(2),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::TransportLimitExceeded);
    }

    #[tokio::test]
    async fn queue_and_per_job_waiters_reject_excess_work() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = Arc::new(OperatorRulesService::new(temp.path().join("config.toml")));
        let (intent_tx, intent_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let callback: DurableIntentCallback = Arc::new(move |_| {
            intent_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        });
        let config = OperatorRuleJobConfig {
            queue_capacity: 1,
            concurrency: 1,
            max_waiters_per_job: 1,
            ..OperatorRuleJobConfig::default()
        };
        let (supervisor, client) = OperatorRuleJobSupervisor::new(service, config, None, callback);
        client.recover().await.unwrap();
        let first = create_plan(&client, "first").await;
        let second = create_plan(&client, "second").await;
        let third = create_plan(&client, "third").await;
        let first_client = client.clone();
        let first_id = first.plan_id.clone();
        let first_hash = first.summary.plan_hash.clone();
        let first_submit = tokio::spawn(async move {
            first_client
                .submit(actor(), first_id, first_hash, "first".into())
                .await
        });
        while client.inner.sender.capacity() != 0 {
            tokio::task::yield_now().await;
        }

        let duplicate = client
            .submit(
                actor(),
                first.plan_id.clone(),
                first.summary.plan_hash.clone(),
                "first".into(),
            )
            .await
            .unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::AdmissionRejected);

        let (shutdown, shutdown_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run(shutdown_rx));
        tokio::task::spawn_blocking(move || intent_rx.recv().unwrap())
            .await
            .unwrap();

        let prepared_replay = client
            .submit(
                actor(),
                first.plan_id,
                first.summary.plan_hash,
                "first".into(),
            )
            .await
            .unwrap();
        assert!(matches!(prepared_replay, SubmitOutcome::Replay { .. }));

        let second_client = client.clone();
        let second_submit = tokio::spawn(async move {
            second_client
                .submit(
                    actor(),
                    second.plan_id,
                    second.summary.plan_hash,
                    "second".into(),
                )
                .await
        });
        while client.inner.sender.capacity() != 0 {
            tokio::task::yield_now().await;
        }
        let overflow = client
            .submit(
                actor(),
                third.plan_id,
                third.summary.plan_hash,
                "third".into(),
            )
            .await
            .unwrap_err();
        assert_eq!(overflow.code, ErrorCode::AdmissionRejected);

        release_tx.send(()).unwrap();
        assert!(matches!(
            first_submit.await.unwrap().unwrap(),
            SubmitOutcome::Accepted { .. }
        ));
        assert_eq!(
            second_submit.await.unwrap().unwrap_err().code,
            ErrorCode::RevisionConflict
        );
        let _ = shutdown.send(());
        supervisor.await.unwrap();
    }
}
