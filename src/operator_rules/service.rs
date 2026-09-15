use super::dto::*;
use super::error::{ErrorCode, OperatorRulesError as Error};
use super::plan;
use crate::config::{
    custom_list::PackOverlay,
    loader::{self, GuardedLoadFailure, LoadedConfigV5, LoaderOverlay},
    policy_revision::{
        self, PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionSnapshot,
    },
    policy_transaction::{
        self, BaseReceipt, Persistence, PrepareOutcome, ReceiptStore, TransactionRequest,
    },
    write_lock,
};
use base64::Engine;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// One complete policy candidate compiled under the daemon's shared admission.
///
/// The revision and semantic hash bind these in-memory objects to the exact
/// durable inventory that may later be activated.
#[derive(Debug)]
pub(crate) struct VerifiedPolicyCandidate {
    revision: String,
    policy_hash: String,
    config: Arc<crate::config::schema::ConfigV5>,
    #[cfg(feature = "cluster")]
    pack_bodies: crate::config::target_v5::PackBodiesV5,
    compiled: Arc<crate::filter::operator_rules::CompiledOperatorRules>,
}

impl VerifiedPolicyCandidate {
    pub(crate) fn compile(
        revision: String,
        policy_hash: String,
        config: &crate::config::schema::ConfigV5,
        pack_bodies: &crate::config::target_v5::PackBodiesV5,
        admission: &crate::filter::operator_rules::CompileAdmission,
    ) -> Result<Arc<Self>, crate::config::target_v5::TargetV5Error> {
        let compiled = Arc::new(crate::config::target_v5::compile_v5_operator_rules(
            config,
            pack_bodies,
            admission,
        )?);
        Ok(Arc::new(Self {
            revision,
            policy_hash,
            config: Arc::new(config.clone()),
            #[cfg(feature = "cluster")]
            pack_bodies: pack_bodies.clone(),
            compiled,
        }))
    }

    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }

    pub(crate) fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub(crate) fn config(&self) -> &crate::config::schema::ConfigV5 {
        &self.config
    }

    #[cfg(feature = "cluster")]
    pub(crate) fn pack_bodies(&self) -> &crate::config::target_v5::PackBodiesV5 {
        &self.pack_bodies
    }

    pub(crate) fn compiled(&self) -> Arc<crate::filter::operator_rules::CompiledOperatorRules> {
        Arc::clone(&self.compiled)
    }
}

/// Daemon-wide compiler admission and the latest committed activation candidate.
#[derive(Debug)]
pub(crate) struct PolicyCandidateRuntime {
    admission: crate::filter::operator_rules::CompileAdmission,
    committed: Mutex<Option<Arc<VerifiedPolicyCandidate>>>,
}

impl PolicyCandidateRuntime {
    pub(crate) fn new(admission: crate::filter::operator_rules::CompileAdmission) -> Self {
        Self {
            admission,
            committed: Mutex::new(None),
        }
    }

    pub(crate) fn compile(
        &self,
        revision: String,
        policy_hash: String,
        config: &crate::config::schema::ConfigV5,
        pack_bodies: &crate::config::target_v5::PackBodiesV5,
    ) -> Result<Arc<VerifiedPolicyCandidate>, crate::config::target_v5::TargetV5Error> {
        VerifiedPolicyCandidate::compile(
            revision,
            policy_hash,
            config,
            pack_bodies,
            &self.admission,
        )
    }

    pub(crate) fn remember_candidate(
        &self,
        candidate: Arc<VerifiedPolicyCandidate>,
    ) -> anyhow::Result<()> {
        *self
            .committed
            .lock()
            .map_err(|_| anyhow::anyhow!("policy candidate cache lock poisoned"))? =
            Some(candidate);
        Ok(())
    }

    pub(crate) fn matching(
        &self,
        revision: &str,
        policy_hash: &str,
    ) -> anyhow::Result<Option<Arc<VerifiedPolicyCandidate>>> {
        Ok(self
            .committed
            .lock()
            .map_err(|_| anyhow::anyhow!("policy candidate cache lock poisoned"))?
            .as_ref()
            .filter(|candidate| {
                candidate.revision() == revision && candidate.policy_hash() == policy_hash
            })
            .map(Arc::clone))
    }
}

#[derive(Debug, Clone)]
pub struct OperatorRulesService {
    pub(crate) master: PathBuf,
    runtime: Option<Arc<PolicyCandidateRuntime>>,
}
impl OperatorRulesService {
    pub fn new(master: impl Into<PathBuf>) -> Self {
        Self {
            master: master.into(),
            runtime: None,
        }
    }

    pub(crate) fn with_runtime(
        master: impl Into<PathBuf>,
        runtime: Arc<PolicyCandidateRuntime>,
    ) -> Self {
        Self {
            master: master.into(),
            runtime: Some(runtime),
        }
    }

    pub fn capabilities(&self, limits: TransportLimits) -> Capabilities {
        Capabilities {
            contract_version: 1,
            schema_version: 5,
            operator_rule_grammar: 1,
            operations: [
                "create_list",
                "set_metadata",
                "add_domain_rule",
                "add_raw_rule",
                "replace_rule",
                "remove_rule",
                "mount",
                "unmount",
                "delete_list",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            semantic_hash: true,
            activation_ack: true,
            cluster_artifact: cfg!(feature = "cluster"),
            limits,
        }
    }

    pub fn metadata(&self) -> Result<Metadata, Error> {
        self.with_read(|_, snapshot, loaded| {
            let mounted: BTreeSet<_> = loaded
                .config
                .profiles
                .values()
                .flat_map(|profile| &profile.custom_lists)
                .collect();
            Ok(Metadata {
                contract_version: 1,
                schema_version: 5,
                config_revision: snapshot.revision().to_string(),
                desired_operator_policy_hash: super::hash_policy_inventory(
                    snapshot.inventory(),
                    &loaded.config,
                )
                .map_err(semantic_error)?
                .to_string(),
                active_policy: None,
                activation_in_sync: false,
                lists: loaded.config.custom_lists.len(),
                mounted_lists: mounted.len(),
                orphan_packs: snapshot.orphan_packs().len(),
            })
        })
    }

    pub fn read(&self, request: PageRequest, limits: TransportLimits) -> Result<ListPage, Error> {
        self.with_read(|_, snapshot, loaded| {
            let revision = snapshot.revision().to_string();
            let offset = cursor_offset(request.cursor.as_deref(), &revision, "lists")?;
            let limit = page_size(&request, limits)?;
            let mut ids: Vec<_> = loaded
                .config
                .custom_lists
                .iter()
                .map(|list| list.id.as_str())
                .collect();
            ids.sort_unstable();
            if offset > ids.len() {
                return Err(Error::new(
                    ErrorCode::StaleCursor,
                    "cursor offset exceeds inventory",
                ));
            }
            let mut result = ListPage {
                contract_version: 1,
                config_revision: revision.clone(),
                lists: vec![],
                next_cursor: None,
                orphan_packs: snapshot
                    .orphan_packs()
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
            };
            for id in ids.iter().skip(offset).take(limit) {
                result.lists.push(detail(id, snapshot, loaded)?);
                result.next_cursor =
                    Some(make_cursor(&revision, "lists", offset + result.lists.len()));
                if !fits(&result, limits) {
                    result.lists.pop();
                    if result.lists.is_empty() {
                        return Err(transport_error());
                    }
                    break;
                }
            }
            let next = offset + result.lists.len();
            result.next_cursor = (next < ids.len()).then(|| make_cursor(&revision, "lists", next));
            bounded(result, limits)
        })
    }

    pub fn show(&self, id: &str) -> Result<ListDetail, Error> {
        self.with_read(|_, snapshot, loaded| detail(id, snapshot, loaded))
    }

    pub fn rules(
        &self,
        id: &str,
        request: PageRequest,
        limits: TransportLimits,
    ) -> Result<RulePage, Error> {
        self.with_read(|_, snapshot, loaded| {
            require_list(id, loaded)?;
            let body = pack_text(id, snapshot)?;
            let config_revision = snapshot.revision().to_string();
            let pack_revision = plan::digest(body.as_bytes());
            let revision = format!("{config_revision}:{pack_revision}");
            let offset = cursor_offset(request.cursor.as_deref(), &revision, id)?;
            let limit = page_size(&request, limits)?;
            let page = plan::row_page(id, body, offset, limit);
            if offset > page.total {
                return Err(Error::new(
                    ErrorCode::StaleCursor,
                    "cursor offset exceeds pack",
                ));
            }
            let total = page.total;
            let mut result = RulePage {
                contract_version: 1,
                id: id.into(),
                config_revision,
                pack_revision,
                rows: Vec::with_capacity(page.rows.len()),
                next_cursor: None,
            };
            for row in page.rows {
                result.rows.push(row);
                result.next_cursor = Some(make_cursor(&revision, id, offset + result.rows.len()));
                if !fits(&result, limits) {
                    result.rows.pop();
                    if result.rows.is_empty() {
                        return Err(transport_error());
                    }
                    break;
                }
            }
            let next = offset + result.rows.len();
            result.next_cursor = (next < total).then(|| make_cursor(&revision, id, next));
            bounded(result, limits)
        })
    }

    pub fn export(
        &self,
        request: &ExportRequest,
        limits: TransportLimits,
    ) -> Result<ExportChunk, Error> {
        self.with_read(|_, snapshot, loaded| {
            require_list(&request.id, loaded)?;
            let bytes = pack_text(&request.id, snapshot)?.as_bytes();
            let pack_revision = plan::digest(bytes);
            if request
                .expected_pack_revision
                .as_ref()
                .is_some_and(|r| r != &pack_revision)
                || (request.offset > 0 && request.expected_pack_revision.is_none())
            {
                return Err(Error::new(
                    ErrorCode::RevisionConflict,
                    "export requires the same pack revision for every chunk",
                ));
            }
            if request.max_bytes == 0
                || request.max_bytes > limits.max_export_bytes
                || request.offset > bytes.len()
            {
                return Err(transport_error());
            }
            let end = request
                .offset
                .saturating_add(request.max_bytes)
                .min(bytes.len());
            bounded(
                ExportChunk {
                    contract_version: 1,
                    id: request.id.clone(),
                    pack_revision,
                    offset: request.offset,
                    total_bytes: bytes.len(),
                    data_base64: base64::engine::general_purpose::STANDARD
                        .encode(&bytes[request.offset..end]),
                    eof: end == bytes.len(),
                },
                limits,
            )
        })
    }

    pub fn export_owned(&self, id: &str, max_bytes: usize) -> Result<OwnedExport, Error> {
        if max_bytes == 0 {
            return Err(transport_error());
        }
        self.with_read(|_, snapshot, loaded| {
            require_list(id, loaded)?;
            let bytes = pack_text(id, snapshot)?.as_bytes();
            if bytes.len() > max_bytes {
                return Err(transport_error());
            }
            Ok(OwnedExport {
                pack_revision: plan::digest(bytes),
                bytes: bytes.to_vec(),
            })
        })
    }

    pub fn plan(&self, request: &BatchRequest, limits: TransportLimits) -> Result<Plan, Error> {
        self.with_read(|guard, snapshot, loaded| {
            let mut candidate = plan::build(request, snapshot, loaded, limits)?;
            let (toml, packs) =
                overlays(guard.tree_io(), snapshot.inventory(), &candidate.inventory)?;
            let validated = loader::load_config_v5_with_policy_overlays_under_service_read_guard(
                guard,
                &loaded.master_path,
                OffsetDateTime::now_utc(),
                Some(&toml),
                Some(&packs),
            )
            .map_err(guarded_load_error)?;
            validate_closed(&candidate.inventory, &validated)?;
            let semantic = super::diff_policy_inventories(
                snapshot.inventory(),
                &loaded.config,
                &candidate.inventory,
                &validated.config,
            )
            .map_err(semantic_error)?;
            plan::attach_semantic(
                &mut candidate.plan,
                &semantic,
                request.expected_plan_hash.as_deref(),
            )?;
            Ok(candidate.plan)
        })
    }

    pub fn apply_with_prepared(
        &self,
        actor: &Actor,
        request: &BatchRequest,
        limits: TransportLimits,
        on_prepared: impl FnOnce(&Receipt),
    ) -> Result<Receipt, Error> {
        plan::validate_request(request, limits)?;
        validate_actor(actor)?;
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        recover_before_service_access(&guard, &receipts)?;
        let payload = transaction_payload(request)?;
        if let Some(receipt) = policy_transaction::lookup_receipt(
            &guard,
            &receipts,
            &actor.identity,
            &request.request_id,
        )
        .map_err(Error::storage)?
        {
            return verified_replay(request, receipt);
        }
        let now = OffsetDateTime::now_utc();
        let loaded = loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
            &guard,
            guard.canonical_master(),
            now,
            None,
            None,
        )
        .map_err(guarded_load_error)?;
        let (snapshot, loaded) =
            policy_revision::capture_coherent_loaded_v5_under_migration_guard(&guard, &loaded, now)
                .map_err(policy_revision_error)?;
        plan::primary_only(&loaded)?;
        #[cfg(feature = "cluster")]
        if !crate::cluster::lifecycle::policy_edit_allowed_under_migration_guard(&guard)
            .map_err(Error::storage)?
        {
            return Err(Error::new(
                ErrorCode::PolicyOwnedByPrimary,
                "node transition is pending; policy editing is temporarily locked",
            ));
        }
        let mut candidate = plan::build(request, &snapshot, &loaded, limits)?;
        let (toml, packs) = overlays(guard.tree_io(), snapshot.inventory(), &candidate.inventory)?;
        let validated = loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
            &guard,
            guard.canonical_master(),
            now,
            Some(&toml),
            Some(&packs),
        )
        .map_err(guarded_load_error)?;
        validate_closed(&candidate.inventory, &validated)?;
        let semantic = super::diff_policy_inventories(
            snapshot.inventory(),
            &loaded.config,
            &candidate.inventory,
            &validated.config,
        )
        .map_err(semantic_error)?;
        plan::attach_semantic(
            &mut candidate.plan,
            &semantic,
            request.expected_plan_hash.as_deref(),
        )?;
        let verified_candidate = candidate.plan.changed.then(|| {
            self.compile_candidate(
                candidate.inventory.revision().to_string(),
                candidate.plan.candidate_operator_policy_hash.clone(),
                &validated.config,
                &validated.pack_bodies,
            )
        });
        let verified_candidate = verified_candidate.transpose()?;
        let transaction = TransactionRequest {
            request_id: request.request_id.clone(),
            actor: actor.identity.clone(),
            origin: actor.origin.clone(),
            operation: "operator_rules.batch.v1".into(),
            payload,
            expected_revision: snapshot.revision(),
            source_schema: 5,
            target_schema: 5,
        };
        #[cfg(feature = "cluster")]
        let publication = if loaded.config.cluster.enabled
            && loaded.config.cluster.role == crate::config::schema::ClusterRole::Primary
            && candidate.plan.changed
        {
            let snapshot_for_publication =
                crate::cluster::artifact::PolicySnapshot::from_verified_candidate(
                    verified_candidate
                        .as_ref()
                        .expect("changed primary candidate was compiled"),
                )
                .map_err(Error::storage)?;
            Some(
                crate::cluster::publisher::reserve(
                    &guard,
                    &receipts,
                    &snapshot_for_publication,
                    &transaction,
                    snapshot.inventory(),
                    &candidate.inventory,
                )
                .map_err(Error::storage)?,
            )
        } else {
            None
        };
        #[cfg(feature = "cluster")]
        let operation_manifest = publication
            .as_ref()
            .map(|intent| intent.binding.operation_manifest())
            .transpose()
            .map_err(Error::storage)?;
        #[cfg(not(feature = "cluster"))]
        let operation_manifest = None;
        let mut initial = None;
        let prepared_result = policy_transaction::prepare_with_hook(
            &guard,
            &receipts,
            &transaction,
            policy_transaction::PolicyRevisionTransition::new(
                snapshot.inventory(),
                &candidate.inventory,
            )
            .with_verified_candidate(verified_candidate.as_deref()),
            policy_transaction::ReceiptPreparationContext {
                operator_plan_hash: Some(&candidate.plan.plan_hash),
                semantic: policy_transaction::ReceiptSemanticContext {
                    before_policy_hash: Some(candidate.plan.base_operator_policy_hash.clone()),
                    after_policy_hash: Some(candidate.plan.candidate_operator_policy_hash.clone()),
                    audit: receipt_audit_context(&candidate.plan),
                },
                operation_manifest,
            },
            || {
                #[cfg(test)]
                if let Some(before_failure) = FAIL_PREPARATION.with(|fail| fail.borrow_mut().take())
                {
                    before_failure();
                    anyhow::bail!("injected prepare validation failure");
                }
                Ok(())
            },
            |base| {
                let receipt = public_receipt(base.clone());
                on_prepared(&receipt);
                initial = Some(receipt);
            },
        );
        let prepared = match prepared_result {
            Ok(prepared) => prepared,
            Err(error) => {
                return failure_receipt(
                    "prepare",
                    &error,
                    initial,
                    recover_failed_transaction(
                        &guard,
                        &receipts,
                        &actor.identity,
                        &request.request_id,
                    ),
                );
            }
        };
        let result = match prepared {
            PrepareOutcome::Replay(receipt) => public_receipt(*receipt),
            PrepareOutcome::Prepared(prepared) => match prepared.commit() {
                Ok(receipt) => {
                    if receipt.persistence != Persistence::Committed || receipt.rollback_restored {
                        let failure = anyhow::anyhow!(receipt.failure.clone().unwrap_or_else(
                            || format!("policy transaction returned {:?}", receipt.persistence)
                        ));
                        return failure_receipt(
                            "commit",
                            &failure,
                            Some(public_receipt(receipt)),
                            recover_failed_transaction(
                                &guard,
                                &receipts,
                                &actor.identity,
                                &request.request_id,
                            ),
                        );
                    }
                    let candidate_cache_error = match (&self.runtime, &verified_candidate) {
                        (Some(runtime), Some(candidate)) => {
                            runtime.remember_candidate(Arc::clone(candidate)).err()
                        }
                        _ => None,
                    };
                    #[cfg(feature = "cluster")]
                    let publication_error = publication
                        .as_ref()
                        .filter(|_| {
                            receipt.persistence == Persistence::Committed
                                && !receipt.rollback_restored
                        })
                        .and_then(|intent| {
                            crate::cluster::publisher::finalize(&guard, intent, &receipt).err()
                        });
                    let receipt = public_receipt(receipt);
                    #[cfg(feature = "cluster")]
                    let receipt = {
                        let mut receipt = receipt;
                        if let Some(error) = candidate_cache_error {
                            receipt.diagnostics.push(bounded_diagnostic(format!(
                                "ActivationCandidateUnavailable: committed policy will be recompiled during reload: {error:#}"
                            )));
                        }
                        if let Some(error) = publication_error {
                            receipt.diagnostics.push(bounded_diagnostic(format!(
                                    "ArtifactPublicationPending: committed policy awaits publication recovery: {error:#}"
                                )));
                        }
                        receipt
                    };
                    #[cfg(not(feature = "cluster"))]
                    let receipt = {
                        let mut receipt = receipt;
                        if let Some(error) = candidate_cache_error {
                            receipt.diagnostics.push(bounded_diagnostic(format!(
                                "ActivationCandidateUnavailable: committed policy will be recompiled during reload: {error:#}"
                            )));
                        }
                        receipt
                    };
                    receipt
                }
                Err(error) => {
                    return failure_receipt(
                        "commit",
                        &error,
                        initial,
                        recover_failed_transaction(
                            &guard,
                            &receipts,
                            &actor.identity,
                            &request.request_id,
                        ),
                    );
                }
            },
        };
        Ok(result)
    }

    /// Resolve a direct-command retry without planning or creating a new intent.
    ///
    /// Direct CLI verbs do not retain the approved plan hash after their first
    /// process exits. The durable receipt supplies that one missing field; all
    /// original operations and preconditions must still reproduce the exact
    /// authenticated transaction payload.
    pub fn replay_request(
        &self,
        actor: &Actor,
        request: &BatchRequest,
        limits: TransportLimits,
    ) -> Result<Option<Receipt>, Error> {
        plan::validate_request(request, limits)?;
        validate_actor(actor)?;
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        recover_before_service_access(&guard, &receipts)?;
        policy_transaction::lookup_receipt(&guard, &receipts, &actor.identity, &request.request_id)
            .map_err(Error::storage)?
            .map(|receipt| verified_replay(request, receipt))
            .transpose()
    }

    pub(crate) fn record_activation_queued(
        &self,
        actor: &Actor,
        request_id: &str,
        operation_id: &str,
        correlation_id: String,
    ) -> Result<Receipt, Error> {
        self.update_activation(
            actor,
            request_id,
            operation_id,
            policy_transaction::ReceiptCompletion::Queued { correlation_id },
        )
    }

    pub(crate) fn complete_activation(
        &self,
        actor: &Actor,
        request_id: &str,
        operation_id: &str,
        completion: policy_transaction::ReceiptCompletion,
    ) -> Result<Receipt, Error> {
        self.update_activation(actor, request_id, operation_id, completion)
    }

    pub(crate) fn record_receipt_audit(
        &self,
        actor: &Actor,
        request_id: &str,
        operation_id: &str,
    ) -> Result<Receipt, Error> {
        validate_actor(actor)?;
        let base = {
            let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
            let data =
                crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
            let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
            recover_before_service_access(&guard, &receipts)?;
            let base =
                policy_transaction::lookup_receipt(&guard, &receipts, &actor.identity, request_id)
                    .map_err(Error::storage)?
                    .filter(|receipt| receipt.transaction_id == operation_id)
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "operation does not exist"))?;
            if base.audit_pending {
                policy_transaction::freeze_receipt_audit(
                    &guard,
                    &receipts,
                    &actor.identity,
                    request_id,
                    operation_id,
                )
                .map_err(Error::storage)?
            } else {
                base
            }
        };
        if !base.audit_pending {
            return Ok(public_receipt(base));
        }
        let event = audit_event(&base);
        let audit_path = crate::config::state_dir::for_config_parent(
            self.master
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        )
        .join(crate::config::audit::AUDIT_DIR_NAME)
        .join(crate::config::audit::AUDIT_FILE_NAME);
        let delivery = crate::config::audit::AuditWriter::open(audit_path)
            .and_then(|writer| writer.operator_rules_sink())
            .map_err(|error| error.to_string())
            .and_then(|sink| {
                sink.record_for_receipt(&event, base.created_unix_seconds)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = delivery {
            let mut receipt = public_receipt(base);
            receipt
                .diagnostics
                .push(bounded_diagnostic(format!("audit pending: {error}")));
            return Ok(receipt);
        }
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        policy_transaction::mark_receipt_audit_recorded(
            &guard,
            &receipts,
            &actor.identity,
            request_id,
            operation_id,
        )
        .map(public_receipt)
        .map_err(Error::storage)
    }

    fn update_activation(
        &self,
        actor: &Actor,
        request_id: &str,
        operation_id: &str,
        completion: policy_transaction::ReceiptCompletion,
    ) -> Result<Receipt, Error> {
        validate_actor(actor)?;
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        policy_transaction::complete_receipt_activation(
            &guard,
            &receipts,
            &actor.identity,
            request_id,
            operation_id,
            completion,
        )
        .map(public_receipt)
        .map_err(Error::storage)
    }

    pub fn operation(&self, actor: &Actor, operation_id: &str) -> Result<Receipt, Error> {
        validate_actor(actor)?;
        if operation_id.len() != 32 || !operation_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::new(ErrorCode::NotFound, "operation does not exist"));
        }
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        recover_before_service_access(&guard, &receipts)?;
        policy_transaction::lookup_operation_receipt(
            &guard,
            &receipts,
            &actor.identity,
            operation_id,
        )
        .map_err(Error::storage)?
        .map(public_receipt)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "operation does not exist for this actor",
            )
        })
    }

    /// Return durable completion work left by a process exit after the
    /// transaction decision. The caller resumes activation before audit so
    /// the one logical audit event records a stable outcome.
    pub(crate) fn pending_completions(&self) -> Result<Vec<(Actor, Receipt)>, Error> {
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        policy_transaction::pending_completion_receipts(&guard, &receipts)
            .map_err(Error::storage)
            .map(|receipts| {
                receipts
                    .into_iter()
                    .map(|receipt| {
                        let actor = Actor {
                            identity: receipt.actor.clone(),
                            origin: receipt.origin.clone(),
                        };
                        (actor, public_receipt(receipt))
                    })
                    .collect()
            })
    }

    /// Find an actor-owned durable operation by its idempotency request key.
    ///
    /// The tuple retains the persisted precondition and optional public plan
    /// fingerprint needed by adapters to validate a replay without retaining
    /// the transient prepared plan. A `None` fingerprint identifies a legacy
    /// receipt and must not be used for plan-free replay.
    pub fn operation_by_request(
        &self,
        actor: &Actor,
        request_id: &str,
    ) -> Result<Option<(Receipt, String, Option<String>)>, Error> {
        validate_actor(actor)?;
        if request_id.is_empty()
            || request_id.len() > 128
            || request_id.chars().any(char::is_control)
        {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "request_id must contain 1–128 non-control bytes",
            ));
        }
        let guard = write_lock::acquire_for_migration(&self.master).map_err(Error::storage)?;
        let data = crate::config::state_dir::open_for_migration(&guard).map_err(Error::storage)?;
        let receipts = ReceiptStore::open(&data, &guard).map_err(Error::storage)?;
        recover_before_service_access(&guard, &receipts)?;
        policy_transaction::lookup_receipt(&guard, &receipts, &actor.identity, request_id)
            .map_err(Error::storage)
            .map(|receipt| {
                receipt.map(|receipt| {
                    let before_revision = receipt.before_revision.clone();
                    let operator_plan_hash = receipt.operator_plan_hash.clone();
                    (public_receipt(receipt), before_revision, operator_plan_hash)
                })
            })
    }

    pub fn plan_summary(plan: &Plan) -> PlanSummary {
        PlanSummary {
            contract_version: 1,
            plan_hash: plan.plan_hash.clone(),
            base_config_revision: plan.base_config_revision.clone(),
            candidate_config_revision: plan.candidate_config_revision.clone(),
            base_operator_policy_hash: plan.base_operator_policy_hash.clone(),
            candidate_operator_policy_hash: plan.candidate_operator_policy_hash.clone(),
            semantic_changed: plan.semantic_diff.semantic_changed,
            cosmetic_changed: plan.semantic_diff.cosmetic_changed,
            changed: plan.changed,
            operation_count: plan.request.operations.len(),
            touched_member_count: plan.touched_members.len(),
            impacted_profile_count: plan.impacted_profiles.len(),
            impacted_recipient_count: plan.impacted_recipients.len(),
            warning_count: plan.warnings.len(),
            pack_bytes_after: plan.pack_bytes_after,
            rules_after: plan.rules_after,
        }
    }

    pub fn plan_impact_page(
        plan: &Plan,
        request: PageRequest,
        limits: TransportLimits,
    ) -> Result<PlanImpactPage, Error> {
        let offset = cursor_offset(request.cursor.as_deref(), &plan.plan_hash, "impact")?;
        let limit = page_size(&request, limits)?;
        let all = [
            ("member", &plan.touched_members),
            ("profile", &plan.impacted_profiles),
            ("recipient", &plan.impacted_recipients),
            ("warning", &plan.warnings),
        ];
        let total: usize = all.iter().map(|(_, entries)| entries.len()).sum();
        if offset > total {
            return Err(Error::new(
                ErrorCode::StaleCursor,
                "cursor offset exceeds plan impact",
            ));
        }
        let mut result = PlanImpactPage {
            contract_version: 1,
            plan_hash: plan.plan_hash.clone(),
            rows: vec![],
            next_cursor: None,
        };
        for (kind, value) in all
            .iter()
            .flat_map(|(kind, entries)| entries.iter().map(move |value| (*kind, value)))
            .skip(offset)
            .take(limit)
        {
            result.rows.push(PlanImpactRow {
                kind: kind.into(),
                value: value.clone(),
            });
            result.next_cursor = Some(make_cursor(
                &plan.plan_hash,
                "impact",
                offset + result.rows.len(),
            ));
            if !fits(&result, limits) {
                result.rows.pop();
                if result.rows.is_empty() {
                    return Err(transport_error());
                }
                break;
            }
        }
        let next = offset + result.rows.len();
        result.next_cursor = (next < total).then(|| make_cursor(&plan.plan_hash, "impact", next));
        bounded(result, limits)
    }

    fn with_read<T>(
        &self,
        read: impl FnOnce(
            &write_lock::ConfigReadLock,
            &PolicyRevisionSnapshot,
            &LoadedConfigV5,
        ) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let guard = write_lock::acquire_for_read(&self.master).map_err(Error::storage)?;
        let now = OffsetDateTime::now_utc();
        let loaded = loader::load_config_v5_with_policy_overlays_under_service_read_guard(
            &guard,
            &self.master,
            now,
            None,
            None,
        )
        .map_err(guarded_load_error)?;
        let (snapshot, loaded) =
            policy_revision::capture_coherent_loaded_v5_under_read_guard(&guard, &loaded, now)
                .map_err(policy_revision_error)?;
        read(&guard, &snapshot, &loaded)
    }

    fn compile_candidate(
        &self,
        revision: String,
        policy_hash: String,
        config: &crate::config::schema::ConfigV5,
        pack_bodies: &crate::config::target_v5::PackBodiesV5,
    ) -> Result<Arc<VerifiedPolicyCandidate>, Error> {
        if let Some(runtime) = &self.runtime {
            return runtime
                .compile(revision, policy_hash, config, pack_bodies)
                .map_err(target_v5_error);
        }

        // Offline callers have no daemon snapshot to retain. Their explicit,
        // one-build controller still exercises the same admission limits.
        let limits =
            crate::filter::operator_rules::RuleCompileLimits::try_from(&config.custom_list_limits)
                .map_err(target_v5_error)?;
        let admission = crate::filter::operator_rules::CompileAdmission::new(
            limits.max_compiled_bytes_total,
            1,
        )
        .map_err(budget_error)?;
        VerifiedPolicyCandidate::compile(revision, policy_hash, config, pack_bodies, &admission)
            .map_err(target_v5_error)
    }
}

fn semantic_error(error: super::semantic::SemanticError) -> Error {
    Error::new(ErrorCode::ValidationFailed, error.to_string())
}

fn budget_error(error: crate::filter::operator_rules::BudgetExceeded) -> Error {
    let code = match error.limit {
        "admission_bytes" | "concurrent_builds" => ErrorCode::AdmissionRejected,
        _ => ErrorCode::BudgetExceeded,
    };
    Error::new(code, error.to_string())
}

fn compile_error(error: crate::filter::operator_rules::CompileError) -> Error {
    use crate::filter::operator_rules::CompileError;

    let code = match &error {
        CompileError::BudgetExceeded(error) => return budget_error(error.clone()),
        CompileError::InvalidId(_) => ErrorCode::InvalidId,
        CompileError::InvalidRule { .. }
        | CompileError::InvalidRegex { .. }
        | CompileError::RegexConstruction { .. } => ErrorCode::InvalidRule,
        CompileError::RegexBudgetExceeded { source, .. } => {
            return budget_error(source.clone());
        }
        CompileError::DuplicateList(_)
        | CompileError::DuplicateProfile(_)
        | CompileError::DuplicateMount { .. }
        | CompileError::UnknownMount { .. } => ErrorCode::ValidationFailed,
    };
    Error::new(code, error.to_string())
}

fn target_v5_error(error: crate::config::target_v5::TargetV5Error) -> Error {
    use crate::config::target_v5::TargetV5Error;

    match error {
        TargetV5Error::Limits(error) => budget_error(error),
        TargetV5Error::Compiler(error) => compile_error(error),
        error @ TargetV5Error::LimitConversion { .. } => {
            Error::new(ErrorCode::BudgetExceeded, error.to_string())
        }
        error @ (TargetV5Error::Validation(_) | TargetV5Error::MissingBodies(_)) => {
            Error::new(ErrorCode::ValidationFailed, error.to_string())
        }
    }
}

fn validate_actor(actor: &Actor) -> Result<(), Error> {
    if actor.identity.is_empty()
        || actor.identity.len() > 256
        || actor.origin.is_empty()
        || actor.origin.len() > 64
        || actor
            .identity
            .chars()
            .chain(actor.origin.chars())
            .any(char::is_control)
    {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "invalid authenticated actor",
        ));
    }
    Ok(())
}

fn bounded_diagnostic(mut text: String) -> String {
    if text.len() > 4096 {
        let mut end = 4096;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(" [diagnostic shortened]");
    }
    text
}

fn overlays(
    tree: crate::config::tree_io::TreeIo<'_>,
    before: &PolicyRevisionInventory,
    inventory: &PolicyRevisionInventory,
) -> Result<(LoaderOverlay, PackOverlay), Error> {
    let mut toml = LoaderOverlay::default();
    let mut packs = PackOverlay::default();
    for member in inventory.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            continue;
        };
        if member.kind() == PolicyMemberKind::Pack {
            let id = crate::config::schema::Id::new(
                member
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| Error::new(ErrorCode::UnsafePath, "invalid pack path"))?,
            )
            .map_err(Error::storage)?;
            packs.stage(id, bytes.clone());
        } else {
            let target = tree
                .plan_target(&tree.identity.root.join(member.path()))
                .map_err(Error::storage)?;
            if !before
                .members()
                .iter()
                .any(|old| old.path() == member.path())
                && !target.is_new()
            {
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    "destination is an existing file outside the policy inventory",
                ));
            }
            toml.stage_plan_reachable_only(
                &target,
                String::from_utf8(bytes.clone()).map_err(Error::storage)?,
            )
            .map_err(Error::storage)?;
        }
    }
    for member in before.members().iter().filter(|old| {
        old.kind() == PolicyMemberKind::Pack
            && !inventory
                .members()
                .iter()
                .any(|new| new.path() == old.path())
    }) {
        let id =
            crate::config::schema::Id::new(member.path().file_stem().unwrap().to_str().unwrap())
                .map_err(Error::storage)?;
        packs.omit(id);
    }
    Ok((toml, packs))
}

fn validate_closed(
    inventory: &PolicyRevisionInventory,
    loaded: &LoadedConfigV5,
) -> Result<(), Error> {
    let root = loaded
        .master_path
        .parent()
        .ok_or_else(|| Error::new(ErrorCode::UnsafePath, "master has no parent"))?;
    let expected: BTreeSet<_> = inventory
        .members()
        .iter()
        .filter(|m| m.kind() != PolicyMemberKind::Pack)
        .map(|m| root.join(m.path()))
        .collect();
    let actual: BTreeSet<_> = loaded.files_loaded.iter().cloned().collect();
    let expected_packs: BTreeSet<_> = inventory
        .members()
        .iter()
        .filter(|m| m.kind() == PolicyMemberKind::Pack)
        .map(|m| m.path().file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    let actual_packs: BTreeSet<_> = loaded
        .config
        .custom_lists
        .iter()
        .map(|list| list.id.to_string())
        .collect();
    if expected != actual || expected_packs != actual_packs {
        return Err(Error::new(
            ErrorCode::TreeChanged,
            "candidate does not resolve the closed TOML and pack inventory",
        ));
    }
    Ok(())
}

fn public_receipt(receipt: BaseReceipt) -> Receipt {
    let policy_hash = if receipt.persistence == Persistence::Committed {
        receipt.after_policy_hash.clone()
    } else {
        receipt.before_policy_hash.clone()
    };
    let mut diagnostics: Vec<_> = receipt
        .failure
        .iter()
        .map(|failure| bounded_diagnostic(failure.clone()))
        .collect();
    if let Some(failure) = &receipt.activation.failure {
        diagnostics.push(bounded_diagnostic(failure.clone()));
    }
    Receipt {
        contract_version: 1,
        operation_id: receipt.transaction_id,
        request_id: receipt.request_id,
        changed: receipt.changed_members != 0,
        persistence: match receipt.persistence {
            Persistence::Prepared => PersistenceState::Prepared,
            Persistence::Committed => PersistenceState::Committed,
            Persistence::Aborted => PersistenceState::Aborted,
            Persistence::DurabilityUncertain => PersistenceState::DurabilityUncertain,
        },
        config_revision: if receipt.persistence == Persistence::Committed {
            receipt.after_revision
        } else {
            receipt.before_revision
        },
        operator_policy_hash: policy_hash,
        activation: Activation {
            state: match receipt.activation.state {
                policy_transaction::ReceiptActivationState::NotRequired => "not_required",
                policy_transaction::ReceiptActivationState::Pending => "pending",
                policy_transaction::ReceiptActivationState::Applied => "applied",
                policy_transaction::ReceiptActivationState::Superseded => "superseded",
                policy_transaction::ReceiptActivationState::Failed => "failed",
                policy_transaction::ReceiptActivationState::Unknown => "unknown",
            }
            .into(),
            correlation_id: receipt.activation.correlation_id,
            reload_outcome: receipt.activation.reload_outcome,
            active_config_revision: receipt.activation.active_config_revision,
            active_policy_hash: receipt.activation.active_policy_hash,
            daemon_instance_id: receipt.activation.daemon_instance_id,
            superseded_by: receipt.activation.superseded_by,
        },
        replication: "unavailable".into(),
        audit: if receipt.audit_pending {
            "pending"
        } else {
            "recorded"
        }
        .into(),
        diagnostics,
    }
}

fn audit_event(receipt: &BaseReceipt) -> crate::config::audit::UorOperationAuditEvent {
    use crate::config::audit::{
        UorAuditActivation, UorAuditCounts, UorAuditEntities, UorAuditIdentity, UorAuditImpact,
        UorAuditOrigin, UorAuditOutcome, UorAuditPersistence, UorAuditReplication,
        UorAuditRevisions, UorOperationAuditEvent,
    };
    let origin = match receipt.origin.as_str() {
        "cli" | "offline" => UorAuditOrigin::Cli,
        "ipc" => UorAuditOrigin::Ipc,
        "rest" | "api" => UorAuditOrigin::Rest,
        "replica" | "cluster" => UorAuditOrigin::Replica,
        "migration" => UorAuditOrigin::Migration,
        "external" => UorAuditOrigin::External,
        _ => UorAuditOrigin::Unknown,
    };
    UorOperationAuditEvent {
        identity: UorAuditIdentity {
            operation_id: receipt.transaction_id.clone(),
            request_id: receipt.request_id.clone(),
            actor: receipt.actor.clone(),
            origin,
            operation: receipt.operation.clone(),
        },
        revisions: UorAuditRevisions {
            before_config_revision: receipt.before_revision.clone(),
            after_config_revision: receipt.after_revision.clone(),
            before_operator_policy_hash: receipt.before_policy_hash.clone(),
            after_operator_policy_hash: receipt.after_policy_hash.clone(),
        },
        entities: UorAuditEntities {
            list_ids: receipt.audit_context.list_ids.clone(),
            profile_ids: receipt.audit_context.profile_ids.clone(),
        },
        counts: UorAuditCounts {
            operations: receipt.audit_context.operations,
            changed_members: receipt.changed_members.try_into().unwrap_or(u32::MAX),
            rules_added: receipt.audit_context.rules_added,
            rules_removed: receipt.audit_context.rules_removed,
            rules_replaced: receipt.audit_context.rules_replaced,
            mounts_added: receipt.audit_context.mounts_added,
            mounts_removed: receipt.audit_context.mounts_removed,
        },
        impact: UorAuditImpact {
            affected_profiles: receipt.audit_context.affected_profiles,
            affected_destinations: receipt.audit_context.affected_destinations,
            potential_destinations: receipt.audit_context.potential_destinations,
            truncated: receipt.audit_context.truncated,
        },
        outcome: UorAuditOutcome {
            persistence: match receipt.persistence {
                Persistence::Prepared => UorAuditPersistence::Prepared,
                Persistence::Committed => UorAuditPersistence::Committed,
                Persistence::Aborted => UorAuditPersistence::Aborted,
                Persistence::DurabilityUncertain => UorAuditPersistence::DurabilityUncertain,
            },
            activation: match receipt.audit_activation.unwrap_or(receipt.activation.state) {
                policy_transaction::ReceiptActivationState::NotRequired => {
                    UorAuditActivation::NotRequested
                }
                policy_transaction::ReceiptActivationState::Pending => UorAuditActivation::Pending,
                policy_transaction::ReceiptActivationState::Applied => UorAuditActivation::Active,
                policy_transaction::ReceiptActivationState::Superseded => {
                    UorAuditActivation::Superseded
                }
                policy_transaction::ReceiptActivationState::Failed => UorAuditActivation::Failed,
                policy_transaction::ReceiptActivationState::Unknown => UorAuditActivation::Unknown,
            },
            replication: UorAuditReplication::NotConfigured,
        },
        changed: receipt.changed_members != 0,
    }
}

fn receipt_audit_context(plan: &Plan) -> policy_transaction::ReceiptAuditContext {
    const MAX_IDS: usize = crate::config::audit::MAX_UOR_AUDIT_ENTITY_IDS;

    let mut list_ids = BTreeSet::new();
    let mut profile_ids: BTreeSet<String> = plan.impacted_profiles.iter().cloned().collect();
    let mut rules_replaced = 0_usize;
    let mut mounts_added = 0_usize;
    let mut mounts_removed = 0_usize;
    for operation in &plan.request.operations {
        match operation {
            Operation::CreateList { id, .. }
            | Operation::SetMetadata { id, .. }
            | Operation::AddDomainRule { id, .. }
            | Operation::AddRawRule { id, .. }
            | Operation::ReplaceRule { id, .. }
            | Operation::RemoveRule { id, .. }
            | Operation::DeleteList { id, .. } => {
                list_ids.insert(id.clone());
            }
            Operation::Mount { id, profile_id } => {
                list_ids.insert(id.clone());
                profile_ids.insert(profile_id.clone());
                mounts_added += 1;
            }
            Operation::Unmount { id, profile_id } => {
                list_ids.insert(id.clone());
                profile_ids.insert(profile_id.clone());
                mounts_removed += 1;
            }
        }
        if matches!(operation, Operation::ReplaceRule { .. }) {
            rules_replaced += 1;
        }
    }

    let direct = plan
        .impacted_recipients
        .iter()
        .filter(|recipient| recipient.starts_with("device:"))
        .count();
    let potential = plan.impacted_recipients.len().saturating_sub(direct);
    let mut truncated = list_ids.len() > MAX_IDS
        || profile_ids.len() > MAX_IDS
        || plan.semantic_diff.omitted_entries != 0;
    let mut list_ids: Vec<_> = list_ids.into_iter().take(MAX_IDS).collect();
    let mut profile_ids: Vec<_> = profile_ids.into_iter().take(MAX_IDS).collect();
    list_ids.sort();
    profile_ids.sort();

    let bounded = |value: usize, truncated: &mut bool| {
        if value > u32::MAX as usize {
            *truncated = true;
            u32::MAX
        } else {
            value as u32
        }
    };
    policy_transaction::ReceiptAuditContext {
        list_ids,
        profile_ids,
        operations: bounded(plan.request.operations.len(), &mut truncated),
        rules_added: bounded(plan.semantic_diff.rules_added, &mut truncated),
        rules_removed: bounded(plan.semantic_diff.rules_removed, &mut truncated),
        rules_replaced: bounded(rules_replaced, &mut truncated),
        mounts_added: bounded(mounts_added, &mut truncated),
        mounts_removed: bounded(mounts_removed, &mut truncated),
        affected_profiles: bounded(plan.impacted_profiles.len(), &mut truncated),
        affected_destinations: bounded(direct, &mut truncated),
        potential_destinations: bounded(potential, &mut truncated),
        truncated,
    }
}

fn transaction_payload(request: &BatchRequest) -> Result<Vec<u8>, Error> {
    let request_bytes = serde_json::to_vec(request).map_err(Error::storage)?;
    Ok(format!("warden/uor/request/v1\0{}", plan::digest(&request_bytes)).into_bytes())
}

fn verified_replay(request: &BatchRequest, receipt: BaseReceipt) -> Result<Receipt, Error> {
    if receipt.before_revision != request.expected_config_revision {
        return Err(Error::new(
            ErrorCode::IdempotencyConflict,
            "request_id was already used with different payload or preconditions",
        ));
    }
    let Some(durable_plan_hash) = receipt.operator_plan_hash.as_ref() else {
        return Err(Error::new(
            ErrorCode::IdempotencyConflict,
            "request_id belongs to a receipt without an operator-rule plan",
        ));
    };
    match request.expected_plan_hash.as_ref() {
        Some(expected) if expected != durable_plan_hash => {
            return Err(Error::new(
                ErrorCode::IdempotencyConflict,
                "request_id was already used with a different plan",
            ));
        }
        Some(_) | None => {}
    }
    let mut candidates = vec![request.clone(), plan::canonicalize_request(request)?];
    if request.expected_plan_hash.is_none() {
        let mut with_hash = request.clone();
        with_hash.expected_plan_hash = Some(durable_plan_hash.clone());
        candidates.push(with_hash);
        let mut canonical_with_hash = plan::canonicalize_request(request)?;
        canonical_with_hash.expected_plan_hash = Some(durable_plan_hash.clone());
        candidates.push(canonical_with_hash);
    }
    let mut matched = false;
    for candidate in candidates {
        if receipt.payload_hash == plan::digest(&transaction_payload(&candidate)?) {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err(Error::new(
            ErrorCode::IdempotencyConflict,
            "request_id was already used with different payload or preconditions",
        ));
    }
    Ok(public_receipt(receipt))
}

fn detail(
    id: &str,
    snapshot: &PolicyRevisionSnapshot,
    loaded: &LoadedConfigV5,
) -> Result<ListDetail, Error> {
    let list = require_list(id, loaded)?;
    let body = pack_text(id, snapshot)?;
    let (rule_count, invalid_rows) = plan::pack_counts(body);
    let mut profiles: Vec<_> = loaded
        .config
        .profiles
        .iter()
        .filter(|(_, profile)| profile.custom_lists.iter().any(|list| list.as_str() == id))
        .map(|(id, _)| id.to_string())
        .collect();
    profiles.sort();
    Ok(ListDetail {
        id: id.into(),
        display_name: list.display_name.clone(),
        description: list.description.clone(),
        config_revision: snapshot.revision().to_string(),
        pack_revision: plan::digest(body.as_bytes()),
        bytes: body.len(),
        rule_count,
        invalid_rows,
        profiles,
    })
}

fn require_list<'a>(
    id: &str,
    loaded: &'a LoadedConfigV5,
) -> Result<&'a crate::config::schema::CustomList, Error> {
    loaded
        .config
        .custom_lists
        .iter()
        .find(|list| list.id.as_str() == id)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "custom list does not exist"))
}
fn pack_text<'a>(id: &str, snapshot: &'a PolicyRevisionSnapshot) -> Result<&'a str, Error> {
    let path = PathBuf::from(format!("packs/{id}.txt"));
    snapshot
        .inventory()
        .members()
        .iter()
        .find_map(|member| {
            if member.kind() == PolicyMemberKind::Pack && member.path() == path {
                if let PolicyMemberState::Present(bytes) = member.state() {
                    return Some(std::str::from_utf8(bytes).map_err(Error::storage));
                }
            }
            None
        })
        .unwrap_or_else(|| Err(Error::new(ErrorCode::NotFound, "pack does not exist")))
}
fn page_size(request: &PageRequest, limits: TransportLimits) -> Result<usize, Error> {
    let value = request.limit.unwrap_or(limits.default_page_size);
    if value == 0 || value > limits.max_page_size {
        return Err(transport_error());
    }
    Ok(value)
}
fn make_cursor(revision: &str, scope: &str, offset: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{revision}\n{scope}\n{offset}"))
}
fn cursor_offset(cursor: Option<&str>, revision: &str, scope: &str) -> Result<usize, Error> {
    let Some(cursor) = cursor else { return Ok(0) };
    if cursor.len() > 1024 {
        return Err(Error::new(ErrorCode::StaleCursor, "invalid cursor"));
    }
    let stale = || {
        Error::new(
            ErrorCode::StaleCursor,
            "cursor does not belong to this revision or scope",
        )
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| stale())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| stale())?;
    let parts: Vec<_> = text.split('\n').collect();
    if parts.len() != 3 || parts[0] != revision || parts[1] != scope {
        return Err(stale());
    }
    parts[2].parse().map_err(|_| stale())
}
fn fits(value: &impl serde::Serialize, limits: TransportLimits) -> bool {
    serde_json::to_vec(value)
        .is_ok_and(|bytes| bytes.len() <= limits.max_response_bytes.saturating_sub(1024))
}
fn bounded<T: serde::Serialize>(value: T, limits: TransportLimits) -> Result<T, Error> {
    if fits(&value, limits) {
        Ok(value)
    } else {
        Err(transport_error())
    }
}
fn transport_error() -> Error {
    Error::new(
        ErrorCode::TransportLimitExceeded,
        "entry or payload exceeds transport limit; use REST",
    )
}
fn validation(errors: Vec<crate::config::error::ConfigError>) -> Error {
    Error::new(
        ErrorCode::ValidationFailed,
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn guarded_load_error(failure: GuardedLoadFailure) -> Error {
    match failure {
        GuardedLoadFailure::Diagnostics(errors) => validation(errors),
        GuardedLoadFailure::UnsafePath(error) => {
            Error::new(ErrorCode::UnsafePath, format!("{error:#}"))
        }
        GuardedLoadFailure::BudgetExceeded(error) => {
            Error::new(ErrorCode::BudgetExceeded, format!("{error:#}"))
        }
        GuardedLoadFailure::TreeChanged(error) => {
            Error::new(ErrorCode::TreeChanged, format!("{error:#}"))
        }
        GuardedLoadFailure::RecoveryRequired(error) => {
            Error::new(ErrorCode::RecoveryRequired, format!("{error:#}"))
        }
        GuardedLoadFailure::Storage(error) => {
            Error::new(ErrorCode::StorageUnavailable, format!("{error:#}"))
        }
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_PREPARATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn recover_before_service_access(
    guard: &write_lock::MigrationWriteLock,
    receipts: &ReceiptStore,
) -> Result<(), Error> {
    match policy_transaction::recover_active(guard, receipts).map_err(recovery_error)? {
        policy_transaction::RecoveryOutcome::LegacyActive => Err(Error::new(
            ErrorCode::RecoveryRequired,
            "an unfinished legacy migration must be recovered before operator-rule access",
        )),
        policy_transaction::RecoveryOutcome::Absent
        | policy_transaction::RecoveryOutcome::Recovered(_)
        | policy_transaction::RecoveryOutcome::SetupRemoved => Ok(()),
    }?;
    recover_publications(guard, receipts).map_err(recovery_error)?;
    Ok(())
}

fn recover_publications(
    _guard: &write_lock::MigrationWriteLock,
    _receipts: &ReceiptStore,
) -> anyhow::Result<()> {
    #[cfg(feature = "cluster")]
    {
        let mut store = crate::cluster::publication::PublicationStore::open(_guard)?;
        crate::cluster::publisher::recover(_guard, _receipts, &mut store)?;
    }
    Ok(())
}

fn failure_receipt(
    phase: &str,
    failure: &anyhow::Error,
    initial: Option<Receipt>,
    recovery: Result<Option<Receipt>, Error>,
) -> Result<Receipt, Error> {
    let error = match recovery {
        Ok(Some(receipt)) => return Ok(receipt),
        Ok(None) => Error::new(
            ErrorCode::RecoveryRequired,
            format!("{phase} failed: {failure:#}; recovery found no terminal receipt"),
        ),
        Err(recovery) => Error::new(
            recovery.code,
            format!("{phase} failed: {failure:#}; recovery failed: {recovery}"),
        ),
    };
    let Some(mut receipt) = initial else {
        return Err(error);
    };
    if !matches!(
        receipt.persistence,
        PersistenceState::Committed | PersistenceState::Aborted
    ) {
        receipt.persistence = PersistenceState::DurabilityUncertain;
    }
    receipt.diagnostics.push(bounded_diagnostic(error.message));
    Ok(receipt)
}

/// A publication failure must not erase a terminal policy result.
fn recover_failed_transaction(
    guard: &write_lock::MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
) -> Result<Option<Receipt>, Error> {
    if policy_transaction::recover_active(guard, receipts).map_err(recovery_error)?
        == policy_transaction::RecoveryOutcome::LegacyActive
    {
        return Err(Error::new(
            ErrorCode::RecoveryRequired,
            "legacy migration remains active",
        ));
    }
    let publication = recover_publications(guard, receipts);
    let receipt = policy_transaction::lookup_receipt(guard, receipts, actor, request_id)
        .map_err(recovery_error)?;
    if let Some(receipt) = receipt.filter(|receipt| {
        matches!(
            receipt.persistence,
            Persistence::Committed | Persistence::Aborted
        )
    }) {
        let mut receipt = public_receipt(receipt);
        if let Err(error) = publication {
            receipt.diagnostics.push(bounded_diagnostic(format!(
                "ArtifactPublicationPending: publication recovery required: {error:#}"
            )));
        }
        return Ok(Some(receipt));
    }
    publication.map_err(recovery_error)?;
    Ok(None)
}

fn recovery_error(error: anyhow::Error) -> Error {
    if error.downcast_ref::<std::io::Error>().is_some() {
        Error::storage(error)
    } else {
        Error::new(ErrorCode::RecoveryConflict, format!("{error:#}"))
    }
}

fn policy_revision_error(error: policy_revision::PolicyRevisionError) -> Error {
    use policy_revision::PolicyRevisionError;

    let code = match error {
        PolicyRevisionError::UnsafePath { .. } | PolicyRevisionError::UnsafePackPath { .. } => {
            ErrorCode::UnsafePath
        }
        PolicyRevisionError::TomlLimitExceeded { .. }
        | PolicyRevisionError::PackLimitExceeded { .. }
        | PolicyRevisionError::PackMembersLimitExceeded { .. }
        | PolicyRevisionError::PackBytesLimitExceeded { .. } => ErrorCode::BudgetExceeded,
        // The loader has already validated semantics. A missing declared
        // member or a changed guarded tree therefore means the snapshot
        // changed between validation and capture, not a new user error.
        PolicyRevisionError::MissingDeclaredPack { .. }
        | PolicyRevisionError::IncoherentSnapshot { .. }
        | PolicyRevisionError::Tree { .. } => ErrorCode::TreeChanged,
        // These can only be a malformed candidate inventory, so surface
        // them with the same correction path as validation diagnostics.
        PolicyRevisionError::DuplicatePath { .. }
        | PolicyRevisionError::InvalidInventory { .. } => ErrorCode::ValidationFailed,
    };
    Error::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONFIG: &str = r#"# operator comment
schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Whole household"
block_all = true
blocked_ttl_secs = 42
lists = {}
"#;

    fn fixture() -> (tempfile::TempDir, OperatorRulesService) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let service = OperatorRulesService::new(temp.path().join("config.toml"));
        (temp, service)
    }
    fn actor() -> Actor {
        Actor {
            identity: "uid:123".into(),
            origin: "test".into(),
        }
    }
    fn request(
        service: &OperatorRulesService,
        id: &str,
        operations: Vec<Operation>,
    ) -> BatchRequest {
        BatchRequest {
            contract_version: 1,
            request_id: id.into(),
            expected_config_revision: service
                .read(PageRequest::default(), TransportLimits::IPC)
                .unwrap()
                .config_revision,
            operations,
            expected_plan_hash: None,
        }
    }
    fn create() -> Operation {
        Operation::CreateList {
            id: "local".into(),
            display_name: "Local".into(),
            description: "test".into(),
            into: None,
        }
    }
    fn apply(service: &OperatorRulesService, request: &BatchRequest) -> Receipt {
        service
            .apply_with_prepared(&actor(), request, TransportLimits::IPC, |_| {})
            .unwrap()
    }

    #[test]
    fn artifact_capability_matches_the_binary_feature() {
        let (_temp, service) = fixture();
        let capabilities = service.capabilities(TransportLimits::IPC);
        assert_eq!(capabilities.schema_version, 5);
        assert_eq!(capabilities.operator_rule_grammar, 1);
        assert_eq!(capabilities.cluster_artifact, cfg!(feature = "cluster"));
    }

    #[test]
    fn daemon_service_retains_the_exact_compiled_candidate_after_commit() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), CONFIG).unwrap();
        let runtime = Arc::new(PolicyCandidateRuntime::new(
            crate::filter::operator_rules::CompileAdmission::new(
                crate::filter::operator_rules::RuleCompileLimits::HARD_CEILINGS
                    .max_compiled_bytes_total
                    * 2,
                1,
            )
            .unwrap(),
        ));
        let service = OperatorRulesService::with_runtime(
            temp.path().join("config.toml"),
            Arc::clone(&runtime),
        );
        let proposal = request(
            &service,
            "retained-candidate",
            vec![
                create(),
                Operation::AddRawRule {
                    id: "local".into(),
                    rule: "/blocked/".into(),
                },
                Operation::Mount {
                    id: "local".into(),
                    profile_id: "household".into(),
                },
            ],
        );
        let receipt = apply(&service, &proposal);
        let candidate = runtime
            .matching(
                &receipt.config_revision,
                receipt.operator_policy_hash.as_deref().unwrap(),
            )
            .unwrap()
            .expect("committed candidate must remain available for activation");
        assert_eq!(candidate.revision(), receipt.config_revision);
        assert!(candidate
            .compiled()
            .profile(&crate::config::schema::Id::new("household").unwrap())
            .is_some());
    }

    #[test]
    fn post_prepared_and_commit_recovery_failures_preserve_uncertain_receipt() {
        for fail_prepare in [false, true] {
            let (_temp, service) = fixture();
            let proposal = request(&service, "recovery-conflict", vec![create()]);
            if fail_prepare {
                policy_transaction::fail_after_prepared_for_test();
            }
            let mut operation_id = None;
            let receipt = service
                .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |prepared| {
                    operation_id = Some(prepared.operation_id.clone());
                    std::fs::write(&service.master, "conflicting external policy edit").unwrap();
                })
                .unwrap();
            assert_eq!(Some(&receipt.operation_id), operation_id.as_ref());
            assert_eq!(receipt.persistence, PersistenceState::DurabilityUncertain);
            let diagnostic = receipt.diagnostics.join("; ");
            assert!(
                diagnostic.contains(if fail_prepare {
                    "prepare failed:"
                } else {
                    "commit failed:"
                }),
                "{diagnostic}"
            );
            assert!(diagnostic.contains("recovery failed:"), "{diagnostic}");
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn prereceipt_recovery_failure_returns_a_combined_error() {
        let (_temp, service) = cluster_fixture("primary", true);
        let proposal = request(&service, "recovery-conflict", vec![create()]);
        let path = publication_state_path(&service);
        FAIL_PREPARATION.with(|fail| {
            *fail.borrow_mut() = Some(Box::new(move || {
                std::fs::write(path, b"invalid publication state").unwrap();
            }))
        });
        let error = service
            .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {
                panic!("prepare must fail before issuing a receipt")
            })
            .unwrap_err();
        assert!(error.message.contains("prepare failed:"), "{error}");
        assert!(error.message.contains("recovery failed:"), "{error}");
        assert!(
            error.message.contains("invalid cluster publication state"),
            "{error}"
        );
    }

    #[cfg(feature = "cluster")]
    fn cluster_fixture(role: &str, enabled: bool) -> (tempfile::TempDir, OperatorRulesService) {
        let (temp, service) = fixture();
        let master = if role == "secondary" && enabled {
            std::fs::create_dir(temp.path().join("cluster.d")).unwrap();
            std::fs::write(temp.path().join("cluster.d/policy.toml"), CONFIG).unwrap();
            "schema_version = 5\nincludes = ['cluster.d/*.toml']\n"
        } else {
            CONFIG
        };
        std::fs::write(&service.master, format!(
            "{master}\n[cluster]\nenabled = {enabled}\nrole = '{role}'\ntoken_hash = 'fixture-token'\npeer = 'https://192.0.2.1'\n"
        )).unwrap();
        (temp, service)
    }

    #[cfg(feature = "cluster")]
    fn publication_state_path(service: &OperatorRulesService) -> PathBuf {
        let namespace = crate::cluster::manifest::digest(
            service
                .master
                .canonicalize()
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
        );
        service
            .master
            .parent()
            .unwrap()
            .join(crate::cluster::publication::STORE_DIR)
            .join(namespace)
            .join("state.json")
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn primary_reserves_before_prepared_and_finalizes_the_exact_receipt() {
        let (temp, service) = cluster_fixture("primary", true);
        let proposal = request(&service, "publish", vec![create()]);
        let original = std::fs::read(&service.master).unwrap();
        let receipt = service
            .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |prepared| {
                assert_eq!(prepared.persistence, PersistenceState::Prepared);
                assert_eq!(std::fs::read(&service.master).unwrap(), original);
                assert!(!temp.path().join("packs/local.txt").exists());
                let state: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(publication_state_path(&service)).unwrap(),
                )
                .unwrap();
                assert_eq!(state["high_water"], 1);
            })
            .unwrap();
        assert_eq!(receipt.persistence, PersistenceState::Committed);
        assert_eq!(receipt.replication, "unavailable");
        {
            let guard = write_lock::acquire_for_migration(&service.master).unwrap();
            let receipts = ReceiptStore::open(
                &crate::config::state_dir::open_for_migration(&guard).unwrap(),
                &guard,
            )
            .unwrap();
            let base = policy_transaction::lookup_receipt(
                &guard,
                &receipts,
                &actor().identity,
                &proposal.request_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                base.payload_hash,
                crate::cluster::manifest::digest(&transaction_payload(&proposal).unwrap())
            );
            let envelope = base.operation_manifest.as_ref().unwrap();
            assert_eq!(envelope["manifest_version"], 1);
            assert!(envelope.get("format").is_none());
            let store = crate::cluster::publication::PublicationStore::open(&guard).unwrap();
            let published = store.current().unwrap().unwrap();
            assert_eq!(published.receipt_id, receipt.operation_id);
            assert_eq!(
                published.reservation.artifact_hash,
                envelope["artifact_hash"].as_str().unwrap()
            );
            assert!(store.pending_intents().unwrap().is_empty());
        }
        assert_eq!(apply(&service, &proposal), receipt);
        let noop = request(
            &service,
            "noop",
            vec![Operation::SetMetadata {
                id: "local".into(),
                display_name: Some("Local".into()),
                description: None,
            }],
        );
        assert!(!apply(&service, &noop).changed);
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(publication_state_path(&service)).unwrap())
                .unwrap();
        assert_eq!(state["high_water"], 1);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn disabled_and_secondary_do_not_reserve_epochs() {
        for (role, enabled) in [("primary", false), ("secondary", true)] {
            let (temp, service) = cluster_fixture(role, enabled);
            let proposal = request(&service, "create", vec![create()]);
            let result =
                service.apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {});
            if enabled {
                assert_eq!(result.unwrap_err().code, ErrorCode::PolicyOwnedByPrimary);
                assert!(!temp.path().join("packs/local.txt").exists());
            } else {
                assert_eq!(result.unwrap().persistence, PersistenceState::Committed);
            }
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(publication_state_path(&service)).unwrap())
                    .unwrap();
            assert_eq!(state["high_water"], 0);
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn finalize_failure_preserves_commit_and_replay_recovers_publication() {
        let (_temp, service) = cluster_fixture("primary", true);
        let proposal = request(&service, "publish", vec![create()]);
        let mut saved = None;
        let receipt = service
            .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {
                let path = publication_state_path(&service);
                saved = Some(std::fs::read(&path).unwrap());
                std::fs::write(path, b"invalid publication state").unwrap();
            })
            .unwrap();
        assert_eq!(receipt.persistence, PersistenceState::Committed);
        assert_eq!(receipt.replication, "unavailable");
        assert!(receipt
            .diagnostics
            .iter()
            .any(|message| message.contains("ArtifactPublicationPending")));
        std::fs::write(publication_state_path(&service), saved.unwrap()).unwrap();
        // Recovery precedes replay and does not depend on loading the current policy.
        std::fs::write(&service.master, "invalid config").unwrap();
        let replay = service
            .replay_request(&actor(), &proposal, TransportLimits::IPC)
            .unwrap()
            .unwrap();
        assert_eq!(replay.operation_id, receipt.operation_id);
        assert_eq!(replay.persistence, PersistenceState::Committed);
        let guard = write_lock::acquire_for_migration(&service.master).unwrap();
        let store = crate::cluster::publication::PublicationStore::open(&guard).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        assert_eq!(
            store.current().unwrap().unwrap().receipt_id,
            receipt.operation_id
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn prepare_failures_reconcile_publication_with_and_without_a_receipt() {
        for after_prepared in [false, true] {
            let (_temp, service) = cluster_fixture("primary", true);
            let proposal = request(&service, "failed-prepare", vec![create()]);
            if after_prepared {
                policy_transaction::fail_after_prepared_for_test();
            } else {
                FAIL_PREPARATION.with(|fail| *fail.borrow_mut() = Some(Box::new(|| {})));
            }
            let result =
                service.apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {});
            if after_prepared {
                assert_eq!(result.unwrap().persistence, PersistenceState::Aborted);
            } else {
                assert!(result.is_err());
            }
            let guard = write_lock::acquire_for_migration(&service.master).unwrap();
            let receipts = ReceiptStore::open(
                &crate::config::state_dir::open_for_migration(&guard).unwrap(),
                &guard,
            )
            .unwrap();
            assert_eq!(
                policy_transaction::lookup_receipt(
                    &guard,
                    &receipts,
                    &actor().identity,
                    &proposal.request_id
                )
                .unwrap()
                .is_some(),
                after_prepared
            );
            let store = crate::cluster::publication::PublicationStore::open(&guard).unwrap();
            assert!(store.pending_intents().unwrap().is_empty());
            assert!(store.current().unwrap().is_none());
        }
    }

    #[test]
    fn planning_is_read_only_and_preserves_original_bytes() {
        let (temp, service) = fixture();
        let request = request(&service, "one", vec![create()]);
        let before: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let plan = service.plan(&request, TransportLimits::IPC).unwrap();
        assert!(plan.changed);
        assert_eq!(
            before,
            std::fs::read_dir(temp.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("config.toml")).unwrap(),
            CONFIG
        );
    }

    #[test]
    fn guarded_loader_semantic_diagnostics_remain_validation_failures() {
        let (temp, service) = fixture();
        std::fs::write(
            temp.path().join("config.toml"),
            CONFIG.replace(
                "default_profile = \"household\"",
                "default_profile = \"missing\"",
            ),
        )
        .unwrap();

        assert_eq!(
            service.metadata().unwrap_err().code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn guarded_loader_refuses_unsafe_pack_tree() {
        let (temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        std::fs::remove_file(temp.path().join("packs/local.txt")).unwrap();
        std::os::unix::fs::symlink(
            temp.path().join("outside.txt"),
            temp.path().join("packs/local.txt"),
        )
        .unwrap();

        assert_eq!(service.metadata().unwrap_err().code, ErrorCode::UnsafePath);
    }

    #[test]
    fn guarded_loader_pack_limit_is_a_budget_failure() {
        let (temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        std::fs::write(
            temp.path().join("config.toml"),
            CONFIG
                .replacen(
                    "schema_version = 5",
                    "schema_version = 5\n[custom_list_limits]\nmax_file_bytes = 1",
                    1,
                )
                .replace(
                    "[profiles.household]",
                    "[[custom_lists]]\nid = \"local\"\n\n[profiles.household]",
                ),
        )
        .unwrap();
        std::fs::write(temp.path().join("packs/local.txt"), "ab").unwrap();

        assert_eq!(
            service.metadata().unwrap_err().code,
            ErrorCode::BudgetExceeded
        );
    }

    #[test]
    fn guarded_loader_storage_failure_is_not_inferred_from_text() {
        let temp = tempfile::tempdir().unwrap();
        let service = OperatorRulesService::new(temp.path().join("missing.toml"));

        assert_eq!(
            service.metadata().unwrap_err().code,
            ErrorCode::StorageUnavailable
        );
    }

    #[test]
    fn tree_drift_and_recovery_are_typed_service_codes() {
        assert_eq!(
            guarded_load_error(GuardedLoadFailure::TreeChanged(anyhow::anyhow!("opaque"))).code,
            ErrorCode::TreeChanged
        );
        assert_eq!(
            guarded_load_error(GuardedLoadFailure::RecoveryRequired(anyhow::anyhow!(
                "opaque"
            )))
            .code,
            ErrorCode::RecoveryRequired
        );
        assert_eq!(
            recovery_error(anyhow::anyhow!("opaque")).code,
            ErrorCode::RecoveryConflict
        );
        assert_eq!(
            recovery_error(anyhow::Error::new(std::io::Error::other("offline"))).code,
            ErrorCode::StorageUnavailable
        );
        assert_eq!(
            policy_revision_error(policy_revision::PolicyRevisionError::Tree {
                path: PathBuf::from("config.toml"),
                detail: "replaced".into(),
            })
            .code,
            ErrorCode::TreeChanged
        );
        assert_eq!(
            policy_revision_error(policy_revision::PolicyRevisionError::TomlLimitExceeded {
                bytes: 2,
                cap: 1,
            })
            .code,
            ErrorCode::BudgetExceeded
        );
        assert_eq!(
            policy_revision_error(policy_revision::PolicyRevisionError::InvalidInventory {
                detail: "invalid".into(),
            })
            .code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn batch_commit_replay_and_actor_scoped_operation() {
        let (temp, service) = fixture();
        let mut request = request(
            &service,
            "batch",
            vec![
                create(),
                Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "Ads.Example".into(),
                    action: RuleAction::Deny,
                },
                Operation::Mount {
                    id: "local".into(),
                    profile_id: "household".into(),
                },
            ],
        );
        let plan = service.plan(&request, TransportLimits::IPC).unwrap();
        let audit = receipt_audit_context(&plan);
        assert_eq!(audit.list_ids, ["local"]);
        assert_eq!(audit.profile_ids, ["household"]);
        assert_eq!(audit.operations, 3);
        assert_eq!(audit.rules_added, 1);
        assert_eq!(audit.mounts_added, 1);
        assert_eq!(audit.affected_profiles, 1);
        assert!(!audit.truncated);
        request.expected_plan_hash = Some(plan.plan_hash);
        let receipt = service
            .apply_with_prepared(&actor(), &request, TransportLimits::IPC, |receipt| {
                assert_eq!(receipt.persistence, PersistenceState::Prepared);
                assert_eq!(
                    std::fs::read_to_string(temp.path().join("config.toml")).unwrap(),
                    CONFIG
                );
            })
            .unwrap();
        assert_eq!(receipt.persistence, PersistenceState::Committed);
        assert_eq!(receipt.activation.active_policy_hash, None);
        assert_eq!(apply(&service, &request), receipt);
        let mut direct_retry = request.clone();
        direct_retry.expected_plan_hash = None;
        assert_eq!(
            service
                .replay_request(&actor(), &direct_retry, TransportLimits::IPC)
                .unwrap(),
            Some(receipt.clone())
        );
        let mut conflicting_retry = direct_retry.clone();
        conflicting_retry.operations.push(Operation::Unmount {
            id: "local".into(),
            profile_id: "household".into(),
        });
        assert_eq!(
            service
                .replay_request(&actor(), &conflicting_retry, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::IdempotencyConflict
        );
        assert_eq!(
            service.operation(&actor(), &receipt.operation_id).unwrap(),
            receipt
        );
        assert_eq!(
            service
                .operation(
                    &Actor {
                        identity: "uid:other".into(),
                        origin: "test".into()
                    },
                    &receipt.operation_id
                )
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        request.operations.push(Operation::Unmount {
            id: "local".into(),
            profile_id: "household".into(),
        });
        assert_eq!(
            service
                .apply_with_prepared(&actor(), &request, TransportLimits::IPC, |_| {})
                .unwrap_err()
                .code,
            ErrorCode::IdempotencyConflict
        );
        let after = std::fs::read_to_string(temp.path().join("config.toml")).unwrap();
        assert!(after.starts_with("# operator comment"));
        let value: toml::Value = toml::from_str(&after).unwrap();
        let mut profile = value["profiles"]["household"].clone();
        profile.as_table_mut().unwrap().remove("custom_lists");
        let original: toml::Value = toml::from_str(CONFIG).unwrap();
        assert_eq!(profile, original["profiles"]["household"]);
        assert_eq!(
            std::fs::read_to_string(temp.path().join("packs/local.txt")).unwrap(),
            "||ads.example^\n"
        );
    }

    #[test]
    fn audit_failure_keeps_commit_pending_and_retry_uses_frozen_enriched_event() {
        let (temp, service) = fixture();
        let mut request = request(
            &service,
            "audit-retry",
            vec![
                create(),
                Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "ads.example".into(),
                    action: RuleAction::Deny,
                },
                Operation::Mount {
                    id: "local".into(),
                    profile_id: "household".into(),
                },
            ],
        );
        let plan = service.plan(&request, TransportLimits::IPC).unwrap();
        request.expected_plan_hash = Some(plan.plan_hash);
        let receipt = apply(&service, &request);
        let receipt = service
            .complete_activation(
                &actor(),
                &receipt.request_id,
                &receipt.operation_id,
                policy_transaction::ReceiptCompletion::Unknown {
                    correlation_id: Some("first-attempt".into()),
                    reload_outcome: "daemon_unreachable".into(),
                    failure: Some("temporary failure".into()),
                },
            )
            .unwrap();

        let audit_dir = temp.path().join(crate::config::audit::AUDIT_DIR_NAME);
        std::fs::write(&audit_dir, b"blocks audit directory creation").unwrap();
        let pending = service
            .record_receipt_audit(&actor(), &receipt.request_id, &receipt.operation_id)
            .unwrap();
        assert_eq!(pending.persistence, PersistenceState::Committed);
        assert_eq!(pending.audit, "pending");
        assert_eq!(service.pending_completions().unwrap().len(), 1);

        let applied = service
            .complete_activation(
                &actor(),
                &receipt.request_id,
                &receipt.operation_id,
                policy_transaction::ReceiptCompletion::Applied {
                    correlation_id: "second-attempt".into(),
                    active_config_revision: receipt.config_revision.clone(),
                    active_policy_hash: receipt.operator_policy_hash.clone().unwrap(),
                    daemon_instance_id: "daemon-test".into(),
                },
            )
            .unwrap();
        assert_eq!(applied.activation.state, "applied");

        std::fs::remove_file(&audit_dir).unwrap();
        let recorded = service
            .record_receipt_audit(&actor(), &receipt.request_id, &receipt.operation_id)
            .unwrap();
        assert_eq!(recorded.activation.state, "applied");
        assert_eq!(recorded.audit, "recorded");
        assert!(service.pending_completions().unwrap().is_empty());

        let records = crate::config::audit::tail(
            &audit_dir.join(crate::config::audit::AUDIT_FILE_NAME),
            usize::MAX,
        )
        .unwrap();
        let event = records
            .into_iter()
            .filter_map(|(_, record)| record.ok()?.uor_operation)
            .find(|event| event.identity.operation_id == receipt.operation_id)
            .unwrap();
        assert_eq!(event.entities.list_ids, ["local"]);
        assert_eq!(event.entities.profile_ids, ["household"]);
        assert_eq!(event.counts.operations, 3);
        assert_eq!(event.counts.rules_added, 1);
        assert_eq!(event.counts.mounts_added, 1);
        assert_eq!(
            event.outcome.activation,
            crate::config::audit::UorAuditActivation::Unknown,
            "the first attempted logical event remains stable across retry"
        );
    }

    #[test]
    fn invalid_existing_rows_block_schema5_reads_and_plans() {
        let (temp, service) = fixture();
        let mut create_request = request(
            &service,
            "create-for-skipped-row",
            vec![
                create(),
                Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "ads.example".into(),
                    action: RuleAction::Deny,
                },
                Operation::Mount {
                    id: "local".into(),
                    profile_id: "household".into(),
                },
            ],
        );
        let plan = service.plan(&create_request, TransportLimits::IPC).unwrap();
        create_request.expected_plan_hash = Some(plan.plan_hash);
        apply(&service, &create_request);
        service.metadata().unwrap();

        std::fs::write(
            temp.path().join("packs/local.txt"),
            "||ads.example^\nunsupported historical row\n",
        )
        .unwrap();
        let before = std::fs::read(&service.master).unwrap();
        assert_eq!(
            service.metadata().unwrap_err().code,
            ErrorCode::ValidationFailed
        );
        let pending_plan = request(
            &service,
            "metadata-after-invalid-row",
            vec![Operation::SetMetadata {
                id: "local".into(),
                display_name: Some("Renamed".into()),
                description: None,
            }],
        );
        assert_eq!(
            service
                .plan(&pending_plan, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::ValidationFailed
        );
        assert_eq!(std::fs::read(&service.master).unwrap(), before);
    }

    #[test]
    fn invalid_regex_compile_is_rejected_before_prepare() {
        let (temp, service) = fixture();
        let mut proposal = request(
            &service,
            "invalid-regex-compile",
            vec![
                create(),
                Operation::AddRawRule {
                    id: "local".into(),
                    rule: "/(invalid/".into(),
                },
            ],
        );
        let plan = service.plan(&proposal, TransportLimits::IPC).unwrap();
        proposal.expected_plan_hash = Some(plan.plan_hash);
        let before = std::fs::read(&service.master).unwrap();

        assert_eq!(
            service
                .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {
                    panic!("invalid regex must fail before prepare")
                })
                .unwrap_err()
                .code,
            ErrorCode::InvalidRule
        );
        assert_eq!(std::fs::read(&service.master).unwrap(), before);
        assert!(!temp.path().join("packs/local.txt").exists());
    }

    #[test]
    fn runtime_admission_refusal_is_reported_before_prepare() {
        let temp = tempfile::tempdir().unwrap();
        let master = temp.path().join("config.toml");
        std::fs::write(&master, CONFIG).unwrap();
        let runtime = Arc::new(PolicyCandidateRuntime::new(
            crate::filter::operator_rules::CompileAdmission::new(1, 1).unwrap(),
        ));
        let service = OperatorRulesService::with_runtime(master.clone(), runtime);
        let mut proposal = request(&service, "admission-refusal", vec![create()]);
        let plan = service.plan(&proposal, TransportLimits::IPC).unwrap();
        proposal.expected_plan_hash = Some(plan.plan_hash);
        let before = std::fs::read(&master).unwrap();

        assert_eq!(
            service
                .apply_with_prepared(&actor(), &proposal, TransportLimits::IPC, |_| {
                    panic!("admission refusal must fail before prepare")
                })
                .unwrap_err()
                .code,
            ErrorCode::AdmissionRejected
        );
        assert_eq!(std::fs::read(&master).unwrap(), before);
        assert!(!temp.path().join("packs/local.txt").exists());
    }

    #[test]
    fn advanced_rules_are_accepted_but_record_injection_is_rejected() {
        let (temp, service) = fixture();
        for rule in [
            "||ads.example^$important",
            "/ads/",
            "||*.ads.example^",
            "@@||*.allowed.example^$important,noapex",
        ] {
            let mut proposal = request(
                &service,
                &format!("advanced-{}", plan::digest(rule.as_bytes())),
                vec![
                    create(),
                    Operation::AddRawRule {
                        id: "local".into(),
                        rule: rule.into(),
                    },
                ],
            );
            let planned = service.plan(&proposal, TransportLimits::IPC).unwrap();
            proposal.expected_plan_hash = Some(planned.plan_hash);
            let receipt = apply(&service, &proposal);
            assert_eq!(receipt.persistence, PersistenceState::Committed, "{rule}");
            let remove = request(
                &service,
                &format!("remove-{}", plan::digest(rule.as_bytes())),
                vec![Operation::DeleteList {
                    id: "local".into(),
                    cascade_unmount: false,
                }],
            );
            apply(&service, &remove);
        }
        for (rule, code) in [
            ("||ads.example^$invalid", ErrorCode::InvalidRule),
            ("||ads.example^\n||other.example^", ErrorCode::InvalidRule),
            ("||ads.example^\r||other.example^", ErrorCode::InvalidRule),
            ("\t||ads.example^", ErrorCode::InvalidRule),
            (
                "||ads.example^\u{85}||other.example^",
                ErrorCode::InvalidRule,
            ),
        ] {
            let before = std::fs::read(&service.master).unwrap();
            let request = request(
                &service,
                "bad",
                vec![
                    create(),
                    Operation::AddRawRule {
                        id: "local".into(),
                        rule: rule.into(),
                    },
                ],
            );
            assert_eq!(
                service
                    .apply_with_prepared(&actor(), &request, TransportLimits::IPC, |_| panic!(
                        "unexpected intent"
                    ))
                    .unwrap_err()
                    .code,
                code,
                "{rule}"
            );
            assert_eq!(std::fs::read(&service.master).unwrap(), before);
            assert!(!temp.path().join("packs/local.txt").exists());
        }
    }

    #[test]
    fn stale_revision_and_plan_cannot_write() {
        let (_temp, service) = fixture();
        let mut old = request(&service, "old", vec![create()]);
        old.expected_plan_hash = Some("wrong".into());
        assert_eq!(
            service.plan(&old, TransportLimits::IPC).unwrap_err().code,
            ErrorCode::PlanConflict
        );
        old.expected_plan_hash = None;
        apply(&service, &request(&service, "new", vec![create()]));
        assert_eq!(
            service
                .apply_with_prepared(&actor(), &old, TransportLimits::IPC, |_| {})
                .unwrap_err()
                .code,
            ErrorCode::RevisionConflict
        );
    }

    #[test]
    fn remove_occurrence_keeps_other_direction_comments_and_duplicates() {
        let (temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        std::fs::write(
            temp.path().join("packs/local.txt"),
            "# keep\n||ads.example^\n@@||ads.example^\n||ads.example^\n",
        )
        .unwrap();
        let page = service
            .rules("local", PageRequest::default(), TransportLimits::IPC)
            .unwrap();
        assert!(page.rows[3].duplicate);
        apply(
            &service,
            &request(
                &service,
                "remove",
                vec![Operation::RemoveRule {
                    id: "local".into(),
                    row_ref: page.rows[1].row_ref.clone(),
                }],
            ),
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("packs/local.txt")).unwrap(),
            "# keep\n@@||ads.example^\n||ads.example^\n"
        );
    }

    #[test]
    fn duplicate_add_is_noop_and_delete_needs_cascade() {
        let (_temp, service) = fixture();
        let add = Operation::AddDomainRule {
            id: "local".into(),
            domain: "ads.example".into(),
            action: RuleAction::Deny,
        };
        apply(
            &service,
            &request(
                &service,
                "create",
                vec![
                    create(),
                    add.clone(),
                    Operation::Mount {
                        id: "local".into(),
                        profile_id: "household".into(),
                    },
                ],
            ),
        );
        let noop = request(&service, "noop", vec![add]);
        let noop_plan = service.plan(&noop, TransportLimits::IPC).unwrap();
        assert!(!noop_plan.changed);
        assert!(noop_plan.impacted_profiles.is_empty());
        assert!(noop_plan.impacted_recipients.is_empty());
        assert!(!apply(&service, &noop).changed);
        let delete = request(
            &service,
            "delete",
            vec![Operation::DeleteList {
                id: "local".into(),
                cascade_unmount: false,
            }],
        );
        assert_eq!(
            service
                .plan(&delete, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::ListMounted
        );
        apply(
            &service,
            &request(
                &service,
                "cascade",
                vec![Operation::DeleteList {
                    id: "local".into(),
                    cascade_unmount: true,
                }],
            ),
        );
        assert_eq!(service.metadata().unwrap().lists, 0);
    }

    #[test]
    fn cancelling_mounts_do_not_report_filtering_impact() {
        let (_temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        let mount = Operation::Mount {
            id: "local".into(),
            profile_id: "household".into(),
        };
        let unmount = Operation::Unmount {
            id: "local".into(),
            profile_id: "household".into(),
        };

        let cancelled = service
            .plan(
                &request(
                    &service,
                    "cancelled-mount",
                    vec![mount.clone(), unmount.clone()],
                ),
                TransportLimits::IPC,
            )
            .unwrap();
        assert!(!cancelled.changed);
        assert!(cancelled.impacted_profiles.is_empty());
        assert!(cancelled.impacted_recipients.is_empty());

        let with_metadata_change = service
            .plan(
                &request(
                    &service,
                    "cancelled-mount-with-metadata",
                    vec![
                        mount,
                        unmount,
                        Operation::SetMetadata {
                            id: "local".into(),
                            display_name: Some("Renamed".into()),
                            description: None,
                        },
                    ],
                ),
                TransportLimits::IPC,
            )
            .unwrap();
        assert!(with_metadata_change.changed);
        assert!(with_metadata_change.impacted_profiles.is_empty());
        assert!(with_metadata_change.impacted_recipients.is_empty());
    }

    #[test]
    fn cursor_and_export_are_revision_bound() {
        let (_temp, service) = fixture();
        apply(
            &service,
            &request(
                &service,
                "create",
                vec![
                    create(),
                    Operation::AddDomainRule {
                        id: "local".into(),
                        domain: "first.example".into(),
                        action: RuleAction::Allow,
                    },
                    Operation::AddDomainRule {
                        id: "local".into(),
                        domain: "second.example".into(),
                        action: RuleAction::Deny,
                    },
                ],
            ),
        );
        let page = service
            .rules(
                "local",
                PageRequest {
                    limit: Some(1),
                    cursor: None,
                },
                TransportLimits::IPC,
            )
            .unwrap();
        let chunk = service
            .export(
                &ExportRequest {
                    id: "local".into(),
                    offset: 0,
                    max_bytes: 3,
                    expected_pack_revision: None,
                },
                TransportLimits::IPC,
            )
            .unwrap();
        assert_eq!(chunk.data_base64, "QEB8");
        apply(
            &service,
            &request(
                &service,
                "edit",
                vec![Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "third.example".into(),
                    action: RuleAction::Deny,
                }],
            ),
        );
        assert_eq!(
            service
                .rules(
                    "local",
                    PageRequest {
                        limit: Some(1),
                        cursor: page.next_cursor
                    },
                    TransportLimits::IPC
                )
                .unwrap_err()
                .code,
            ErrorCode::StaleCursor
        );
        assert_eq!(
            service
                .export(
                    &ExportRequest {
                        id: "local".into(),
                        offset: 3,
                        max_bytes: 3,
                        expected_pack_revision: Some(chunk.pack_revision)
                    },
                    TransportLimits::IPC
                )
                .unwrap_err()
                .code,
            ErrorCode::RevisionConflict
        );
    }

    #[test]
    fn large_blank_pack_only_materializes_the_requested_page() {
        let (temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        let body = "\n".repeat(1024 * 1024);
        std::fs::write(temp.path().join("packs/local.txt"), &body).unwrap();

        let page = service
            .rules(
                "local",
                PageRequest {
                    cursor: None,
                    limit: Some(1),
                },
                TransportLimits::IPC,
            )
            .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows.capacity(), 1);
        assert!(page.next_cursor.is_some());
        assert_eq!(service.show("local").unwrap().bytes, body.len());

        let chunk = service
            .export(
                &ExportRequest {
                    id: "local".into(),
                    offset: 0,
                    max_bytes: 1,
                    expected_pack_revision: None,
                },
                TransportLimits::IPC,
            )
            .unwrap();
        assert_eq!(chunk.data_base64, "Cg==");
        let owned = service.export_owned("local", body.len()).unwrap();
        assert_eq!(owned.bytes, body.as_bytes());
        assert_eq!(owned.pack_revision, chunk.pack_revision);
    }

    #[test]
    fn orphan_pack_is_visible_and_cannot_be_adopted_by_create() {
        let (temp, service) = fixture();
        std::fs::create_dir(temp.path().join("packs")).unwrap();
        std::fs::write(temp.path().join("packs/local.txt"), "").unwrap();
        assert_eq!(service.metadata().unwrap().orphan_packs, 1);
        assert_eq!(
            service
                .plan(
                    &request(&service, "create", vec![create()]),
                    TransportLimits::IPC
                )
                .unwrap_err()
                .code,
            ErrorCode::AlreadyExists
        );
    }

    #[test]
    fn strict_json_rejects_unknown_fields_and_versions() {
        assert!(serde_json::from_value::<Operation>(
            serde_json::json!({"op":"create_list","id":"local","unknown":true})
        )
        .is_err());
        let (_temp, service) = fixture();
        let mut unsupported_version = request(&service, "create", vec![create()]);
        unsupported_version.contract_version = 2;
        assert_eq!(
            service
                .plan(&unsupported_version, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedContract
        );
        let invalid = request(
            &service,
            "invalid-id",
            vec![Operation::CreateList {
                id: "NOT_VALID".into(),
                display_name: String::new(),
                description: String::new(),
                into: None,
            }],
        );
        assert_eq!(
            service
                .plan(&invalid, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::InvalidId
        );
    }

    #[test]
    fn replay_survives_later_invalid_config_and_new_service_instance() {
        let (temp, service) = fixture();
        let request = request(&service, "create", vec![create()]);
        let receipt = apply(&service, &request);
        std::fs::write(temp.path().join("config.toml"), "not a valid config").unwrap();
        let restarted = OperatorRulesService::new(temp.path().join("config.toml"));
        assert_eq!(apply(&restarted, &request), receipt);
        assert_eq!(
            restarted
                .operation(&actor(), &receipt.operation_id)
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn new_include_must_be_reachable_and_cannot_escape_tree() {
        let (temp, service) = fixture();
        let into = |path: &str| Operation::CreateList {
            id: "local".into(),
            display_name: String::new(),
            description: String::new(),
            into: Some(path.into()),
        };
        for path in ["../outside.toml", "/tmp/outside.toml"] {
            assert_eq!(
                service
                    .plan(
                        &request(&service, "bad", vec![into(path)]),
                        TransportLimits::IPC
                    )
                    .unwrap_err()
                    .code,
                ErrorCode::UnsafePath
            );
        }
        assert_eq!(
            service
                .plan(
                    &request(&service, "unreachable", vec![into("other.toml")]),
                    TransportLimits::IPC
                )
                .unwrap_err()
                .code,
            ErrorCode::ValidationFailed
        );
        std::fs::write(
            temp.path().join("config.toml"),
            CONFIG.replacen(
                "schema_version = 5",
                "schema_version = 5\nincludes = [\"declarations-*.toml\"]",
                1,
            ),
        )
        .unwrap();
        let proposal = request(&service, "reachable", vec![into("declarations-local.toml")]);
        let plan = service.plan(&proposal, TransportLimits::IPC).unwrap();
        assert!(plan
            .touched_members
            .contains(&"declarations-local.toml".into()));
        apply(&service, &proposal);
        assert!(temp.path().join("declarations-local.toml").exists());
    }

    #[test]
    fn row_reference_cannot_cross_lists_with_identical_bytes() {
        let (_temp, service) = fixture();
        let other = Operation::CreateList {
            id: "other".into(),
            display_name: String::new(),
            description: String::new(),
            into: None,
        };
        let add = |id: &str| Operation::AddDomainRule {
            id: id.into(),
            domain: "ads.example".into(),
            action: RuleAction::Deny,
        };
        apply(
            &service,
            &request(
                &service,
                "create",
                vec![create(), other, add("local"), add("other")],
            ),
        );
        let rows = service
            .rules("local", PageRequest::default(), TransportLimits::IPC)
            .unwrap();
        let operation = Operation::RemoveRule {
            id: "other".into(),
            row_ref: rows.rows[0].row_ref.clone(),
        };
        assert_eq!(
            service
                .plan(
                    &request(&service, "cross", vec![operation]),
                    TransportLimits::IPC
                )
                .unwrap_err()
                .code,
            ErrorCode::RowConflict
        );
    }

    #[test]
    fn only_snapshot_row_references_are_editable_and_each_at_most_once() {
        let (temp, service) = fixture();
        apply(&service, &request(&service, "create", vec![create()]));
        std::fs::write(
            temp.path().join("packs/local.txt"),
            "||one.example^\n||two.example^\n||three.example^\n",
        )
        .unwrap();
        let rows = service
            .rules("local", PageRequest::default(), TransportLimits::IPC)
            .unwrap()
            .rows;

        let remove_two_original_rows = request(
            &service,
            "stable-refs",
            vec![
                Operation::RemoveRule {
                    id: "local".into(),
                    row_ref: rows[0].row_ref.clone(),
                },
                Operation::RemoveRule {
                    id: "local".into(),
                    row_ref: rows[2].row_ref.clone(),
                },
            ],
        );
        apply(&service, &remove_two_original_rows);
        assert_eq!(
            std::fs::read_to_string(temp.path().join("packs/local.txt")).unwrap(),
            "||two.example^\n"
        );

        let page = service
            .rules("local", PageRequest::default(), TransportLimits::IPC)
            .unwrap();
        let same_ref = page.rows[0].row_ref.clone();
        let repeated = request(
            &service,
            "repeated-ref",
            vec![
                Operation::ReplaceRule {
                    id: "local".into(),
                    row_ref: same_ref.clone(),
                    rule: "||changed.example^".into(),
                },
                Operation::RemoveRule {
                    id: "local".into(),
                    row_ref: same_ref,
                },
            ],
        );
        assert_eq!(
            service
                .plan(&repeated, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::RowConflict
        );

        let unissued = request(
            &service,
            "unissued-ref",
            vec![
                Operation::AddDomainRule {
                    id: "local".into(),
                    domain: "new.example".into(),
                    action: RuleAction::Deny,
                },
                Operation::RemoveRule {
                    id: "local".into(),
                    row_ref: String::new(),
                },
            ],
        );
        assert_eq!(
            service
                .plan(&unissued, TransportLimits::IPC)
                .unwrap_err()
                .code,
            ErrorCode::RowConflict
        );
    }

    #[test]
    fn plan_impact_pages_are_bounded_and_hash_scoped() {
        let (_temp, service) = fixture();
        let plan = service
            .plan(
                &request(&service, "create", vec![create()]),
                TransportLimits::IPC,
            )
            .unwrap();
        let summary = OperatorRulesService::plan_summary(&plan);
        assert_eq!(summary.plan_hash, plan.plan_hash);
        let page = OperatorRulesService::plan_impact_page(
            &plan,
            PageRequest {
                cursor: None,
                limit: Some(1),
            },
            TransportLimits::IPC,
        )
        .unwrap();
        assert_eq!(page.rows.len(), 1);
        let next = OperatorRulesService::plan_impact_page(
            &plan,
            PageRequest {
                cursor: page.next_cursor.clone(),
                limit: Some(1),
            },
            TransportLimits::IPC,
        )
        .unwrap();
        assert_eq!(next.rows.len(), 1);
        let mut other = plan;
        other.plan_hash = "other".into();
        assert_eq!(
            OperatorRulesService::plan_impact_page(
                &other,
                PageRequest {
                    cursor: page.next_cursor,
                    limit: Some(1)
                },
                TransportLimits::IPC
            )
            .unwrap_err()
            .code,
            ErrorCode::StaleCursor
        );
    }

    #[test]
    fn schedule_impacts_expand_device_group_and_both_membership_directions() {
        let temp = tempfile::tempdir().unwrap();
        let config = r#"schema_version = 5
[upstream]
servers = ["192.0.2.1:53"]
[server]
default_profile = "household"
[profiles.household]
display_name = "Household"
[profiles.scheduled]
display_name = "Scheduled"

[[devices]]
id = "direct"
display_name = "Direct target"
ip = "192.0.2.10"
profile = "household"

[[devices]]
id = "member-a"
display_name = "Group member from group"
ip = "192.0.2.11"
profile = "household"

[[devices]]
id = "member-b"
display_name = "Group member from device"
ip = "192.0.2.12"
profile = "household"
groups = ["target-group"]

[[groups]]
id = "target-group"
display_name = "Target group"
profile = "household"
devices = ["member-a"]

[[schedules]]
id = "direct-window"
display_name = "Direct window"
target_type = "device"
target_id = "direct"
profile = "scheduled"
days = ["all"]
hours = "00:00-23:59"

[[schedules]]
id = "group-window"
display_name = "Group window"
target_type = "group"
target_id = "target-group"
profile = "scheduled"
days = ["all"]
hours = "00:00-23:59"
"#;
        let master = temp.path().join("config.toml");
        std::fs::write(&master, config).unwrap();
        let service = OperatorRulesService::new(master);
        let plan = service
            .plan(
                &request(
                    &service,
                    "schedule-impact",
                    vec![
                        create(),
                        Operation::Mount {
                            id: "local".into(),
                            profile_id: "scheduled".into(),
                        },
                    ],
                ),
                TransportLimits::IPC,
            )
            .unwrap();
        for recipient in [
            "schedule:direct-window",
            "device:direct",
            "schedule:group-window",
            "group:target-group",
            "device:member-a",
            "device:member-b",
        ] {
            assert!(
                plan.impacted_recipients.iter().any(|row| row == recipient),
                "missing {recipient}: {:?}",
                plan.impacted_recipients
            );
        }
    }

    #[test]
    fn failure_after_durable_hook_recovers_the_same_operation() {
        let (temp, service) = fixture();
        let request = request(&service, "fault", vec![create()]);
        let mut operation_id = None;
        policy_transaction::fail_after_prepared_for_test();
        let receipt = service
            .apply_with_prepared(&actor(), &request, TransportLimits::IPC, |receipt| {
                assert_eq!(receipt.persistence, PersistenceState::Prepared);
                assert_eq!(
                    std::fs::read_to_string(temp.path().join("config.toml")).unwrap(),
                    CONFIG
                );
                operation_id = Some(receipt.operation_id.clone());
            })
            .unwrap();
        assert_eq!(Some(&receipt.operation_id), operation_id.as_ref());
        assert_eq!(receipt.persistence, PersistenceState::Aborted);
        assert_eq!(
            service.operation(&actor(), &receipt.operation_id).unwrap(),
            receipt
        );
        assert_eq!(apply(&service, &request), receipt);
        assert_eq!(
            std::fs::read_to_string(temp.path().join("config.toml")).unwrap(),
            CONFIG
        );
        assert!(!temp.path().join("packs/local.txt").exists());
        let audited = service
            .record_receipt_audit(&actor(), &receipt.request_id, &receipt.operation_id)
            .unwrap();
        assert_eq!(audited.persistence, PersistenceState::Aborted);
        assert_eq!(audited.activation.state, "not_required");
        assert_eq!(audited.audit, "recorded");
        assert!(service.pending_completions().unwrap().is_empty());
    }
}
