use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

use crate::operator_rules::{
    ErrorCode, ListDetail, Metadata, Operation, OperatorRulesError, PageRequest, PersistenceState,
    Receipt, RuleAction, RulePage, RuleRow,
};
use crate::tui::actions::Surface;
use crate::tui::{actions, App, IpcPoller};

use super::adapter::{AdapterErrorKind, OperatorPolicyAdapter};
use super::recovery::{self, JournalState, ProfilePrefix};
use super::workflow::{OperatorPolicyWorkflow, RecoveryAction, WorkflowState};
use super::AdapterError;

#[derive(Debug, Clone)]
pub(crate) enum PolicyChange {
    Operations(Vec<Operation>),
    ReplaceRule {
        id: String,
        expected_config_revision: String,
        expected_pack_revision: String,
        row_ref: String,
        replacement: String,
    },
    RemoveRules {
        id: String,
        expected_config_revision: String,
        expected_pack_revision: String,
        row_refs: Vec<String>,
    },
    QueryRules {
        ids: Vec<String>,
        domain: String,
        action: RuleAction,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PolicyOrigin {
    Recovery,
    CustomList,
    Mount,
    QueryRules {
        ids: Vec<String>,
        already_present: Vec<bool>,
    },
    QueryNewList {
        id: String,
        display_name: String,
    },
    ProfileMounts {
        profile_id: String,
        properties_committed: bool,
    },
}

impl PolicyOrigin {
    fn resource(&self) -> String {
        match self {
            Self::Recovery => "Operator policy recovery".into(),
            Self::CustomList => "Custom List".into(),
            Self::Mount => "Custom List mounts".into(),
            Self::QueryRules { ids, .. } => format!("Query Log rule · {} list(s)", ids.len()),
            Self::QueryNewList { id, .. } => format!("Custom List {id}"),
            Self::ProfileMounts {
                profile_id,
                properties_committed,
            } => {
                if *properties_committed {
                    format!("Profile {profile_id} mounts · properties committed")
                } else {
                    format!("Profile {profile_id} mounts")
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyDialog {
    pub(crate) id: u64,
    pub(crate) origin: PolicyOrigin,
    pub(crate) workflow: Option<OperatorPolicyWorkflow>,
    pub(crate) adapter: Option<OperatorPolicyAdapter>,
    pub(crate) preparing: bool,
    pub(crate) preparation_error: Option<String>,
    pub(crate) prefix_outcome: Option<String>,
    pub(crate) discard_operations: Option<Vec<Operation>>,
}

impl PolicyDialog {
    fn loading(id: u64, origin: PolicyOrigin) -> Self {
        Self {
            id,
            origin,
            workflow: None,
            adapter: None,
            preparing: true,
            preparation_error: None,
            prefix_outcome: None,
            discard_operations: None,
        }
    }

    pub(crate) fn resource(&self) -> String {
        self.origin.resource()
    }
}

struct PreparedDialog {
    origin: PolicyOrigin,
    workflow: OperatorPolicyWorkflow,
    adapter: Option<OperatorPolicyAdapter>,
    prefix_outcome: Option<String>,
    prefix: Option<ProfilePrefix>,
    config: Option<Box<crate::tui::app::ConfigSnapshot>>,
    discard_operations: Option<Vec<Operation>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyCatalog {
    pub(crate) capabilities: crate::operator_rules::Capabilities,
    pub(crate) metadata: Metadata,
    pub(crate) lists: Vec<ListDetail>,
    pub(crate) orphan_packs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRules {
    pub(crate) id: String,
    pub(crate) config_revision: String,
    pub(crate) pack_revision: String,
    pub(crate) rows: Vec<RuleRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRuleCounts {
    pub(crate) id: String,
    pub(crate) config_revision: String,
    pub(crate) pack_revision: String,
    pub(crate) result: Result<(usize, usize, usize), String>,
}

pub(crate) async fn read_catalog(socket_path: PathBuf) -> Result<PolicyCatalog, AdapterError> {
    let adapter = OperatorPolicyAdapter::connect(socket_path).await?;
    read_catalog_with(&adapter).await
}

async fn read_catalog_with(adapter: &OperatorPolicyAdapter) -> Result<PolicyCatalog, AdapterError> {
    let capabilities = adapter.capabilities().clone();
    let metadata = adapter.metadata().await?;
    let mut page = adapter.inventory(PageRequest::default()).await?;
    let config_revision = page.config_revision.clone();
    if config_revision != metadata.config_revision {
        return Err(protocol_error(
            ErrorCode::RevisionConflict,
            "Custom List metadata and inventory use different revisions",
        ));
    }
    let mut lists = std::mem::take(&mut page.lists);
    let mut orphan_packs = std::mem::take(&mut page.orphan_packs);
    while let Some(mut next) = adapter.next_inventory(&page).await? {
        if next.config_revision != config_revision {
            return Err(protocol_error(
                ErrorCode::StaleCursor,
                "Custom List inventory changed while paging",
            ));
        }
        lists.append(&mut next.lists);
        orphan_packs.append(&mut next.orphan_packs);
        page = next;
    }
    Ok(PolicyCatalog {
        capabilities,
        metadata,
        lists,
        orphan_packs,
    })
}

pub(crate) async fn read_rules(
    socket_path: PathBuf,
    id: String,
    expected_config_revision: String,
    expected_pack_revision: String,
) -> Result<PolicyRules, AdapterError> {
    let adapter = OperatorPolicyAdapter::connect(socket_path).await?;
    read_rules_with(
        &adapter,
        id,
        expected_config_revision,
        expected_pack_revision,
    )
    .await
}

/// Read every requested pack to completion through the paged operator-rules
/// contract. The caller supplies inventory revisions and publishes a count
/// only when the complete page chain retains both fences.
pub(crate) async fn read_rule_counts(
    socket_path: PathBuf,
    lists: Vec<(String, String, String)>,
) -> Result<Vec<PolicyRuleCounts>, AdapterError> {
    let adapter = OperatorPolicyAdapter::connect(socket_path).await?;
    let mut counts = Vec::with_capacity(lists.len());
    for (id, config_revision, pack_revision) in lists {
        let result = read_rules_with(
            &adapter,
            id.clone(),
            config_revision.clone(),
            pack_revision.clone(),
        )
        .await
        .map(|rules| semantic_rule_counts(&rules.rows))
        .map_err(|error| error.to_string());
        counts.push(PolicyRuleCounts {
            id,
            config_revision,
            pack_revision,
            result,
        });
    }
    Ok(counts)
}

fn semantic_rule_counts(rows: &[RuleRow]) -> (usize, usize, usize) {
    rows.iter().fold((0, 0, 0), |mut totals, row| {
        let semantic = row.action.is_some() || !row.valid;
        if semantic && (!row.valid || row.duplicate) {
            totals.2 += 1;
        } else if row.valid && !row.duplicate {
            match row.action {
                Some(RuleAction::Allow) => totals.0 += 1,
                Some(RuleAction::Deny) => totals.1 += 1,
                None => {}
            }
        }
        totals
    })
}

async fn read_rules_with(
    adapter: &OperatorPolicyAdapter,
    id: String,
    expected_config_revision: String,
    expected_pack_revision: String,
) -> Result<PolicyRules, AdapterError> {
    let mut page = adapter.rules(id.clone(), PageRequest::default()).await?;
    let mut rows = Vec::new();
    let mut seen_cursors = BTreeSet::new();
    loop {
        let has_next = accept_rule_page(
            &mut page,
            &expected_config_revision,
            &expected_pack_revision,
            &mut seen_cursors,
            &mut rows,
        )?;
        if !has_next {
            break;
        }
        let Some(next) = adapter.next_rules(&page).await? else {
            return Err(protocol_error(
                ErrorCode::StaleCursor,
                "Custom List rule pagination ended before its advertised next page",
            ));
        };
        page = next;
    }
    Ok(PolicyRules {
        id,
        config_revision: expected_config_revision,
        pack_revision: expected_pack_revision,
        rows,
    })
}

fn accept_rule_page(
    page: &mut RulePage,
    expected_config_revision: &str,
    expected_pack_revision: &str,
    seen_cursors: &mut BTreeSet<String>,
    rows: &mut Vec<RuleRow>,
) -> Result<bool, AdapterError> {
    if page.config_revision != expected_config_revision
        || page.pack_revision != expected_pack_revision
    {
        return Err(protocol_error(
            ErrorCode::StaleCursor,
            "Custom List rules no longer match the inventory revision",
        ));
    }
    let has_next = match page.next_cursor.as_ref() {
        Some(cursor) if !seen_cursors.insert(cursor.clone()) => {
            return Err(protocol_error(
                ErrorCode::StaleCursor,
                "Custom List rule pagination repeated a cursor",
            ));
        }
        Some(_) => true,
        None => false,
    };
    rows.append(&mut page.rows);
    Ok(has_next)
}

pub(crate) async fn open(
    app: &mut App,
    poller: &IpcPoller,
    origin: PolicyOrigin,
    change: PolicyChange,
) -> bool {
    if app.operator_policy.is_some() || app.pending_action.is_some() {
        return false;
    }
    let dialog_id = app.action_serial.wrapping_add(1);
    app.operator_policy_scroll.set(0);
    app.operator_policy_prefix = None;
    app.operator_policy = Some(PolicyDialog::loading(dialog_id, origin.clone()));
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        Surface::Global,
        "Planning policy change",
        async move { prepare(socket, origin, change, None, None, None).await },
        move |app, _, result| apply_prepared(app, dialog_id, result),
    )
    .await
}

pub(crate) async fn open_profile_after(
    app: &mut App,
    poller: &IpcPoller,
    origin: PolicyOrigin,
    change: PolicyChange,
    config_path: PathBuf,
    prefix: ProfilePrefix,
) -> bool {
    if app.operator_policy.is_some() || app.pending_action.is_some() {
        return false;
    }
    let dialog_id = app.action_serial.wrapping_add(1);
    app.operator_policy_scroll.set(0);
    app.operator_policy_prefix = Some(prefix.clone());
    let discard_operations = match &change {
        PolicyChange::Operations(operations) => Some(operations.clone()),
        _ => None,
    };
    let mut dialog = PolicyDialog::loading(dialog_id, origin.clone());
    dialog.discard_operations = discard_operations;
    app.operator_policy = Some(dialog);
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        Surface::Global,
        "Saving profile properties",
        prepare_profile(socket, config_path, origin, change, prefix),
        move |app, _, result| apply_prepared(app, dialog_id, result),
    )
    .await
}

/// Schedule startup recovery without performing filesystem or socket I/O on
/// the event-loop task. A submitted record is restored as an explicit exact
/// retry; merely starting the TUI never invents or rebases an intent.
pub(crate) fn spawn_startup_resume(app: &mut App, poller: &IpcPoller, config_path: &Path) -> bool {
    if app.operator_policy.is_some() || app.pending_action.is_some() {
        return false;
    }
    let dialog_id = app.action_serial.wrapping_add(1);
    let socket = poller.socket_path().to_owned();
    let config_path = config_path.to_owned();
    app.operator_policy_scroll.set(0);
    app.operator_policy = Some(PolicyDialog::loading(dialog_id, PolicyOrigin::Recovery));
    let started = actions::start(
        app,
        Surface::Global,
        "Checking operator-policy recovery",
        startup_resume(socket, config_path),
        move |app, _, result| match result {
            None => {
                if app
                    .operator_policy
                    .as_ref()
                    .is_some_and(|dialog| dialog.id == dialog_id)
                {
                    app.operator_policy = None;
                }
            }
            Some(result) => apply_prepared(app, dialog_id, result),
        },
    );
    if !started {
        app.operator_policy = None;
    }
    started
}

async fn startup_resume(
    socket: PathBuf,
    config_path: PathBuf,
) -> Option<Result<PreparedDialog, PreparationFailure>> {
    let state = match recovery::load(config_path.clone()).await {
        Ok(state) => state?,
        Err(error) => {
            return Some(Err(PreparationFailure::Policy {
                error,
                origin: PolicyOrigin::Recovery,
                prefix_outcome: None,
                prefix: None,
                config: None,
                operations: None,
            }));
        }
    };
    match state {
        JournalState::Empty => None,
        JournalState::PropertyPending {
            origin,
            operations,
            prefix,
        } => {
            let config = load_snapshot(config_path.clone()).await;
            if !config
                .as_deref()
                .is_some_and(|snapshot| profile_matches_prefix(snapshot, &prefix))
            {
                return Some(Err(PreparationFailure::Prefix {
                    error: "profile property outcome remains unknown; the property prefix was not repeated"
                        .into(),
                    origin,
                    prefix,
                    config,
                    properties_committed: false,
                    operations: Some(operations),
                }));
            }
            let message = format!(
                "Profile {} properties confirmed from disk; mount policy remains",
                prefix.profile_id
            );
            if let Err(error) =
                recovery::property_committed(config_path.clone(), prefix.clone(), message.clone())
                    .await
            {
                return Some(Err(PreparationFailure::Prefix {
                    error: format_policy_error(&error),
                    origin,
                    prefix,
                    config,
                    properties_committed: true,
                    operations: Some(operations),
                }));
            }
            Some(
                prepare(
                    socket,
                    origin,
                    PolicyChange::Operations(operations),
                    Some(message),
                    Some(prefix),
                    config,
                )
                .await,
            )
        }
        JournalState::PropertyCommitted {
            origin,
            operations,
            prefix,
            message,
        } => {
            let config = load_snapshot(config_path).await;
            Some(
                prepare(
                    socket,
                    origin,
                    PolicyChange::Operations(operations),
                    Some(message),
                    Some(prefix),
                    config,
                )
                .await,
            )
        }
        JournalState::Submitted {
            origin,
            request,
            apply,
            prefix,
            prefix_outcome,
            ..
        } => {
            let prefix = *prefix;
            let config = if prefix.is_some() {
                load_snapshot(config_path).await
            } else {
                None
            };
            let (adapter, connect_error) = match OperatorPolicyAdapter::connect(socket).await {
                Ok(adapter) => (Some(adapter), None),
                Err(error) => (None, Some(error)),
            };
            let plan = apply.retained_plan();
            if request.request_id != plan.request_id || plan.summary.plan_hash != apply.plan_hash {
                return Some(Err(PreparationFailure::Policy {
                    error: protocol_error(
                        ErrorCode::RecoveryConflict,
                        "submitted recovery identities do not agree",
                    ),
                    origin,
                    prefix_outcome,
                    prefix,
                    config,
                    operations: None,
                }));
            }
            Some(Ok(PreparedDialog {
                origin,
                workflow: OperatorPolicyWorkflow::recover_submitted_with_error(
                    request,
                    plan,
                    connect_error,
                ),
                adapter,
                prefix_outcome,
                prefix,
                config,
                discard_operations: None,
            }))
        }
    }
}

#[cfg(test)]
pub(super) async fn startup_resume_probe(
    socket: PathBuf,
    config_path: PathBuf,
) -> Option<(bool, RecoveryAction, Option<ErrorCode>, bool)> {
    let prepared = startup_resume(socket, config_path).await?.ok()?;
    let WorkflowState::Recovery(state) = &prepared.workflow.state else {
        return None;
    };
    let action = state.action.clone();
    let error = state.error.as_ref().map(AdapterError::code);
    let dialog = PolicyDialog {
        id: 1,
        origin: prepared.origin,
        workflow: Some(prepared.workflow.clone()),
        adapter: prepared.adapter.clone(),
        preparing: false,
        preparation_error: None,
        prefix_outcome: prepared.prefix_outcome,
        discard_operations: prepared.discard_operations,
    };
    Some((
        prepared.adapter.is_some(),
        action,
        error,
        dialog_can_close(&dialog),
    ))
}

async fn load_snapshot(config_path: PathBuf) -> Option<Box<crate::tui::app::ConfigSnapshot>> {
    tokio::task::spawn_blocking(move || Box::new(crate::tui::load_config_snapshot(&config_path)))
        .await
        .ok()
}

enum PreparationFailure {
    Prefix {
        error: String,
        origin: PolicyOrigin,
        prefix: ProfilePrefix,
        config: Option<Box<crate::tui::app::ConfigSnapshot>>,
        properties_committed: bool,
        operations: Option<Vec<Operation>>,
    },
    Policy {
        error: AdapterError,
        origin: PolicyOrigin,
        prefix_outcome: Option<String>,
        prefix: Option<ProfilePrefix>,
        config: Option<Box<crate::tui::app::ConfigSnapshot>>,
        operations: Option<Vec<Operation>>,
    },
}

async fn prepare_profile(
    socket: PathBuf,
    config_path: PathBuf,
    origin: PolicyOrigin,
    change: PolicyChange,
    prefix: ProfilePrefix,
) -> Result<PreparedDialog, PreparationFailure> {
    let operations = match &change {
        PolicyChange::Operations(operations) => operations.clone(),
        _ => {
            return Err(PreparationFailure::Prefix {
                error: "profile mount preparation requires one explicit operation batch".into(),
                origin,
                prefix,
                config: None,
                properties_committed: false,
                operations: None,
            });
        }
    };
    recovery::begin_property(
        config_path.clone(),
        origin.clone(),
        operations.clone(),
        prefix.clone(),
    )
    .await
    .map_err(|error| PreparationFailure::Prefix {
        error: format_policy_error(&error),
        origin: origin.clone(),
        prefix: prefix.clone(),
        config: None,
        properties_committed: false,
        operations: Some(operations.clone()),
    })?;

    let property_result = IpcPoller::new(&socket)
        .send_profile_update(prefix.profile_id.clone(), prefix.patch.clone())
        .await;
    let snapshot_path = config_path.clone();
    let config = tokio::task::spawn_blocking(move || {
        Box::new(crate::tui::load_config_snapshot(&snapshot_path))
    })
    .await
    .ok();
    let properties_committed = property_result.is_ok()
        || config
            .as_deref()
            .is_some_and(|snapshot| profile_matches_prefix(snapshot, &prefix));
    if !properties_committed {
        return Err(PreparationFailure::Prefix {
            error: format!(
                "profile properties outcome is unknown and was not repeated: {}",
                property_result.unwrap_err()
            ),
            origin,
            prefix,
            config,
            properties_committed: false,
            operations: Some(operations.clone()),
        });
    }

    let message = format!(
        "Profile {} properties committed; mount policy follows",
        prefix.profile_id
    );
    if let Err(error) =
        recovery::property_committed(config_path, prefix.clone(), message.clone()).await
    {
        return Err(PreparationFailure::Prefix {
            error: format!(
                "{message}; recovery journal could not advance: {}",
                format_policy_error(&error)
            ),
            origin,
            prefix,
            config,
            properties_committed: true,
            operations: Some(operations),
        });
    }
    prepare(socket, origin, change, Some(message), Some(prefix), config).await
}

async fn prepare(
    socket: PathBuf,
    mut origin: PolicyOrigin,
    change: PolicyChange,
    prefix_outcome: Option<String>,
    prefix: Option<ProfilePrefix>,
    config: Option<Box<crate::tui::app::ConfigSnapshot>>,
) -> Result<PreparedDialog, PreparationFailure> {
    let requested_operations = match &change {
        PolicyChange::Operations(operations) => Some(operations.clone()),
        _ => None,
    };
    if let PolicyOrigin::ProfileMounts {
        properties_committed,
        ..
    } = &mut origin
    {
        *properties_committed = prefix_outcome.is_some();
    }
    let adapter = match OperatorPolicyAdapter::connect(socket).await {
        Ok(adapter) => adapter,
        Err(error) => {
            return Err(policy_preparation_failure(
                error,
                &origin,
                &prefix_outcome,
                &prefix,
                config,
                requested_operations,
            ));
        }
    };
    let catalog = match read_catalog_with(&adapter).await {
        Ok(catalog) => catalog,
        Err(error) => {
            return Err(policy_preparation_failure(
                error,
                &origin,
                &prefix_outcome,
                &prefix,
                config,
                requested_operations,
            ));
        }
    };
    let expected_config_revision = catalog.metadata.config_revision.clone();
    let operations = match resolve_change(&adapter, &catalog, &mut origin, change).await {
        Ok(operations) => operations,
        Err(error) => {
            return Err(policy_preparation_failure(
                error,
                &origin,
                &prefix_outcome,
                &prefix,
                config,
                requested_operations,
            ));
        }
    };
    let discard_operations = Some(operations.clone());
    let mut workflow = match OperatorPolicyWorkflow::new(expected_config_revision, operations) {
        Ok(workflow) => workflow,
        Err(error) => {
            return Err(policy_preparation_failure(
                error,
                &origin,
                &prefix_outcome,
                &prefix,
                config,
                requested_operations,
            ));
        }
    };
    let attempt = workflow
        .begin_plan()
        .expect("new workflow starts as a draft");
    let result = adapter
        .create_plan(attempt.request.clone(), attempt.page.clone())
        .await;
    workflow.finish_plan(attempt.ticket, result);
    Ok(PreparedDialog {
        origin,
        workflow,
        adapter: Some(adapter),
        prefix_outcome,
        prefix,
        config,
        discard_operations,
    })
}

fn policy_preparation_failure(
    error: AdapterError,
    origin: &PolicyOrigin,
    prefix_outcome: &Option<String>,
    prefix: &Option<ProfilePrefix>,
    config: Option<Box<crate::tui::app::ConfigSnapshot>>,
    operations: Option<Vec<Operation>>,
) -> PreparationFailure {
    PreparationFailure::Policy {
        error,
        origin: origin.clone(),
        prefix_outcome: prefix_outcome.clone(),
        prefix: prefix.clone(),
        config,
        operations,
    }
}

fn apply_prepared(
    app: &mut App,
    dialog_id: u64,
    mut result: Result<PreparedDialog, PreparationFailure>,
) {
    let (config, committed_prefix) = match &mut result {
        Ok(prepared) => (prepared.config.take(), prepared.prefix.clone()),
        Err(PreparationFailure::Prefix {
            config,
            prefix,
            properties_committed,
            ..
        }) => (config.take(), properties_committed.then(|| prefix.clone())),
        Err(PreparationFailure::Policy { config, prefix, .. }) => (config.take(), prefix.clone()),
    };
    if let Some(config) = config {
        crate::tui::apply_config_snapshot(app, *config);
    }
    if let Some(prefix) = &committed_prefix {
        refresh_profile_form_original(app, prefix);
    }
    let (failure, next_prefix) = {
        let Some(dialog) = app
            .operator_policy
            .as_mut()
            .filter(|dialog| dialog.id == dialog_id)
        else {
            return;
        };
        dialog.preparing = false;
        match result {
            Ok(prepared) => {
                dialog.origin = prepared.origin;
                dialog.workflow = Some(prepared.workflow);
                dialog.adapter = prepared.adapter;
                dialog.prefix_outcome = prepared.prefix_outcome;
                dialog.discard_operations = prepared.discard_operations;
                (None, prepared.prefix)
            }
            Err(PreparationFailure::Prefix {
                error,
                origin,
                properties_committed,
                operations,
                ..
            }) => {
                dialog.origin = origin;
                dialog.discard_operations = operations;
                if properties_committed {
                    dialog.prefix_outcome = Some(
                        "Profile properties committed; mount policy remains outstanding".into(),
                    );
                }
                dialog.preparation_error = Some(error.clone());
                (Some((dialog.origin.clone(), error)), committed_prefix)
            }
            Err(PreparationFailure::Policy {
                error,
                origin,
                prefix_outcome,
                prefix,
                operations,
                ..
            }) => {
                dialog.origin = origin;
                dialog.discard_operations = operations;
                dialog.prefix_outcome = prefix_outcome.clone();
                let policy_message = format_policy_error(&error);
                let message = match prefix_outcome {
                    Some(prefix) => format!("{prefix}; mount policy not planned: {policy_message}"),
                    None => policy_message,
                };
                dialog.preparation_error = Some(message.clone());
                (Some((dialog.origin.clone(), message)), prefix)
            }
        }
    };
    app.operator_policy_prefix = next_prefix;
    if let Some((origin, error)) = failure {
        apply_origin_error(app, &origin, &error);
    }
}

async fn resolve_change(
    adapter: &OperatorPolicyAdapter,
    catalog: &PolicyCatalog,
    origin: &mut PolicyOrigin,
    change: PolicyChange,
) -> Result<Vec<Operation>, AdapterError> {
    match change {
        PolicyChange::Operations(operations) => Ok(operations),
        PolicyChange::ReplaceRule {
            id,
            expected_config_revision,
            expected_pack_revision,
            row_ref,
            replacement,
        } => {
            verify_captured_list(
                catalog,
                &id,
                &expected_config_revision,
                &expected_pack_revision,
            )?;
            Ok(vec![Operation::ReplaceRule {
                id,
                row_ref,
                rule: replacement,
            }])
        }
        PolicyChange::RemoveRules {
            id,
            expected_config_revision,
            expected_pack_revision,
            row_refs,
        } => {
            verify_captured_list(
                catalog,
                &id,
                &expected_config_revision,
                &expected_pack_revision,
            )?;
            let mut operations = Vec::with_capacity(row_refs.len());
            for row_ref in row_refs {
                operations.push(Operation::RemoveRule {
                    id: id.clone(),
                    row_ref,
                });
            }
            Ok(operations)
        }
        PolicyChange::QueryRules {
            ids,
            domain,
            action,
        } => {
            let mut already_present = Vec::with_capacity(ids.len());
            for id in &ids {
                let list = catalog
                    .lists
                    .iter()
                    .find(|list| list.id == *id)
                    .ok_or_else(|| {
                        protocol_error(ErrorCode::NotFound, "selected Custom List no longer exists")
                    })?;
                already_present.push(
                    all_rules(adapter, list)
                        .await?
                        .iter()
                        .any(|row| row.action == Some(action) && row_matches_domain(row, &domain)),
                );
            }
            *origin = PolicyOrigin::QueryRules {
                ids: ids.clone(),
                already_present,
            };
            Ok(ids
                .into_iter()
                .map(|id| Operation::AddDomainRule {
                    id,
                    domain: domain.clone(),
                    action,
                })
                .collect())
        }
    }
}

fn verify_captured_list(
    catalog: &PolicyCatalog,
    id: &str,
    expected_config_revision: &str,
    expected_pack_revision: &str,
) -> Result<(), AdapterError> {
    let list = catalog
        .lists
        .iter()
        .find(|list| list.id == id)
        .ok_or_else(|| {
            protocol_error(ErrorCode::NotFound, "selected Custom List no longer exists")
        })?;
    if catalog.metadata.config_revision != expected_config_revision
        || list.config_revision != expected_config_revision
        || list.pack_revision != expected_pack_revision
    {
        return Err(protocol_error(
            ErrorCode::RevisionConflict,
            "captured Custom List rule snapshot is stale; reopen the rule",
        ));
    }
    Ok(())
}

async fn all_rules(
    adapter: &OperatorPolicyAdapter,
    list: &ListDetail,
) -> Result<Vec<RuleRow>, AdapterError> {
    let mut page = adapter
        .rules(list.id.clone(), PageRequest::default())
        .await?;
    if page.config_revision != list.config_revision || page.pack_revision != list.pack_revision {
        return Err(protocol_error(
            ErrorCode::StaleCursor,
            "Custom List changed while checking its rules",
        ));
    }
    let mut rows = std::mem::take(&mut page.rows);
    while let Some(mut next) = adapter.next_rules(&page).await? {
        if next.config_revision != list.config_revision || next.pack_revision != list.pack_revision
        {
            return Err(protocol_error(
                ErrorCode::StaleCursor,
                "Custom List changed while paging its rules",
            ));
        }
        rows.append(&mut next.rows);
        page = next;
    }
    Ok(rows)
}

fn row_matches_domain(row: &RuleRow, domain: &str) -> bool {
    let Ok(expected) =
        crate::config::custom_list::compose_line(domain, row.action == Some(RuleAction::Allow))
    else {
        return false;
    };
    match (
        crate::config::custom_list::parse_pack_line(&row.raw),
        crate::config::custom_list::parse_pack_line(&expected),
    ) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

fn profile_matches_prefix(
    snapshot: &crate::tui::app::ConfigSnapshot,
    prefix: &ProfilePrefix,
) -> bool {
    let Some(profile) = snapshot
        .loaded_config
        .as_ref()
        .and_then(|loaded| loaded.config.profiles.get(&prefix.profile_id))
    else {
        return false;
    };
    let patch = &prefix.patch;
    if patch.retired_tags.is_some() || patch.custom_lists.is_some() {
        return false;
    }
    if patch
        .display_name
        .as_ref()
        .is_some_and(|value| profile.display_name != *value)
        || patch
            .block_response
            .as_ref()
            .is_some_and(|value| profile.block_response != *value)
        || patch
            .blocked_ttl_secs
            .as_ref()
            .is_some_and(|value| profile.blocked_ttl_secs != *value)
        || patch
            .block_all
            .is_some_and(|value| profile.block_all != value)
    {
        return false;
    }
    if let Some(delta) = &patch.admin_rules {
        if delta.add.iter().any(|id| {
            !profile
                .admin_rules
                .iter()
                .any(|actual| actual.as_str() == id)
        }) || delta.remove.iter().any(|id| {
            profile
                .admin_rules
                .iter()
                .any(|actual| actual.as_str() == id)
        }) {
            return false;
        }
    }
    if let Some(delta) = &patch.lists {
        for (id, policy) in &delta.set {
            let Ok(id) = crate::config::schema::Id::new(id.clone()) else {
                return false;
            };
            if profile.lists.get(&id) != Some(policy) {
                return false;
            }
        }
        for id in &delta.clear {
            let Ok(id) = crate::config::schema::Id::new(id.clone()) else {
                return false;
            };
            if profile.lists.contains_key(&id) {
                return false;
            }
        }
    }
    if let Some(ecs) = &patch.ecs {
        if ecs.clear {
            if profile.ecs.is_some() {
                return false;
            }
        } else {
            let Some(actual) = &profile.ecs else {
                return false;
            };
            if ecs.mode.is_some_and(|value| actual.mode != Some(value))
                || ecs
                    .source_prefix_v4
                    .is_some_and(|value| actual.source_prefix_v4 != Some(value))
                || ecs
                    .source_prefix_v6
                    .is_some_and(|value| actual.source_prefix_v6 != Some(value))
            {
                return false;
            }
        }
    }
    true
}

fn refresh_profile_form_original(app: &mut App, prefix: &ProfilePrefix) {
    let profile = app
        .loaded_config
        .as_ref()
        .and_then(|loaded| loaded.config.profiles.get(&prefix.profile_id));
    let Some(crate::tui::profile_modal::Stage::EditingForm(form)) =
        app.profiles.modal.as_mut().map(|modal| &mut modal.stage)
    else {
        return;
    };
    let Some(original) = form
        .original
        .as_mut()
        .filter(|original| original.id == prefix.profile_id)
    else {
        return;
    };
    if let Some(profile) = profile {
        original.display_name = profile.display_name.clone();
        original.block_response = profile.block_response;
        original.blocked_ttl_secs = profile.blocked_ttl_secs;
        original.block_all = profile.block_all;
        original.admin_rules = profile
            .admin_rules
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();
        original.ecs = profile.ecs.clone();
        original.lists = profile.lists.clone();
        original.custom_lists = profile.custom_lists.iter().cloned().collect();
        return;
    }

    // The daemon acknowledged the prefix but the follow-up snapshot could
    // not be parsed. Advance only the captured original by the exact patch;
    // the editable buffers (especially mount drafts) remain untouched.
    let patch = &prefix.patch;
    if let Some(value) = &patch.display_name {
        original.display_name = value.clone();
    }
    if let Some(value) = patch.block_response {
        original.block_response = value;
    }
    if let Some(value) = patch.blocked_ttl_secs {
        original.blocked_ttl_secs = value;
    }
    if let Some(value) = patch.block_all {
        original.block_all = value;
    }
    if let Some(delta) = &patch.admin_rules {
        for id in &delta.add {
            if !original.admin_rules.contains(id) {
                original.admin_rules.push(id.clone());
            }
        }
        original
            .admin_rules
            .retain(|id| !delta.remove.iter().any(|removed| removed == id));
    }
    if let Some(delta) = &patch.lists {
        for (id, policy) in &delta.set {
            if let Ok(id) = crate::config::schema::Id::new(id.clone()) {
                original.lists.insert(id, *policy);
            }
        }
        for id in &delta.clear {
            if let Ok(id) = crate::config::schema::Id::new(id.clone()) {
                original.lists.remove(&id);
            }
        }
    }
    if let Some(delta) = &patch.ecs {
        if delta.clear {
            original.ecs = None;
        } else {
            let ecs = original.ecs.get_or_insert_with(Default::default);
            if let Some(value) = delta.mode {
                ecs.mode = Some(value);
            }
            if let Some(value) = delta.source_prefix_v4 {
                ecs.source_prefix_v4 = Some(value);
            }
            if let Some(value) = delta.source_prefix_v6 {
                ecs.source_prefix_v6 = Some(value);
            }
        }
    }
}

pub(crate) async fn handle_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) -> bool {
    if app.operator_policy.is_none() {
        return false;
    }
    if app.pending_action.is_some() {
        return true;
    }
    if key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        || matches!(
            key.code,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('1'..='5') | KeyCode::Char('[' | ']')
        )
    {
        return false;
    }
    match (key.code, key.modifiers) {
        (KeyCode::Esc, _) => close_dialog(app, config_path).await,
        (KeyCode::Enter, _) | (KeyCode::Char('s'), KeyModifiers::CONTROL)
            if !begin_apply(app, config_path).await =>
        {
            close_terminal_dialog(app, config_path).await;
        }
        (KeyCode::Enter, _) | (KeyCode::Char('s'), KeyModifiers::CONTROL) => {}
        (KeyCode::Char('n'), _) => {
            begin_more_impact(app).await;
        }
        (KeyCode::Up, _) => scroll_by(app, -1),
        (KeyCode::Down, _) => scroll_by(app, 1),
        (KeyCode::PageUp, _) => scroll_by(app, -8),
        (KeyCode::PageDown, _) => scroll_by(app, 8),
        (KeyCode::Home, _) => app.operator_policy_scroll.set(0),
        (KeyCode::End, _) => app
            .operator_policy_scroll
            .set(app.operator_policy_extent.get().saturating_sub(1)),
        (KeyCode::Char('r'), _) => recover(app, poller, config_path).await,
        _ => {}
    }
    true
}

fn scroll_by(app: &App, delta: isize) {
    let current = app.operator_policy_scroll.get();
    let next = current.saturating_add_signed(delta);
    app.operator_policy_scroll
        .set(next.min(app.operator_policy_extent.get().saturating_sub(1)));
}

#[derive(Debug)]
enum ApplyWork {
    NotSubmitted(AdapterError),
    Submitted {
        result: Box<Result<Receipt, AdapterError>>,
        journal_error: Option<AdapterError>,
    },
}

async fn begin_apply(app: &mut App, config_path: &Path) -> bool {
    let retained_prefix = app.operator_policy_prefix.clone();
    let Some((dialog_id, adapter, attempt, origin, prefix, prefix_outcome)) =
        app.operator_policy.as_mut().and_then(|d| {
            let attempt = d.workflow.as_mut()?.begin_apply()?;
            Some((
                d.id,
                d.adapter.clone()?,
                attempt,
                d.origin.clone(),
                retained_prefix,
                d.prefix_outcome.clone(),
            ))
        })
    else {
        return false;
    };
    let ticket = attempt.ticket;
    let config_path = config_path.to_owned();
    actions::dispatch(
        app,
        Surface::Global,
        "Applying policy change",
        async move {
            if let Err(error) = recovery::begin_submitted(
                config_path.clone(),
                origin,
                attempt.request.clone(),
                attempt.plan.clone(),
                prefix,
                prefix_outcome,
            )
            .await
            {
                return ApplyWork::NotSubmitted(error);
            }
            let result = adapter.apply(&attempt.plan).await;
            let journal_error = observe_result(config_path, &attempt.request, &result).await;
            ApplyWork::Submitted {
                result: Box::new(result),
                journal_error,
            }
        },
        move |app, _, result| {
            let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            else {
                return;
            };
            let (accepted, journal_error) = match result {
                ApplyWork::NotSubmitted(error) => (
                    dialog
                        .workflow
                        .as_mut()
                        .is_some_and(|workflow| workflow.finish_apply_not_submitted(ticket, error)),
                    None,
                ),
                ApplyWork::Submitted {
                    result,
                    journal_error,
                } => (
                    dialog
                        .workflow
                        .as_mut()
                        .is_some_and(|workflow| workflow.finish_apply(ticket, *result)),
                    journal_error,
                ),
            };
            if !accepted {
                return;
            }
            apply_current_outcome(app, dialog_id);
            if let Some(error) = journal_error {
                app.status_err(format!(
                    "receipt received but recovery journal could not advance: {}",
                    format_policy_error(&error)
                ));
            }
        },
    )
    .await
}

async fn observe_result(
    config_path: PathBuf,
    request: &crate::operator_rules::BatchRequest,
    result: &Result<Receipt, AdapterError>,
) -> Option<AdapterError> {
    let receipt = result.as_ref().ok()?;
    recovery::observe_receipt(
        config_path,
        request.request_id.clone(),
        receipt.operation_id.clone(),
        receipt.persistence,
    )
    .await
    .err()
}

async fn begin_more_impact(app: &mut App) -> bool {
    let Some((dialog_id, adapter, attempt)) = app.operator_policy.as_mut().and_then(|d| {
        let attempt = d.workflow.as_mut()?.begin_more_impact()?;
        Some((d.id, d.adapter.clone()?, attempt))
    }) else {
        return false;
    };
    let ticket = attempt.ticket;
    actions::dispatch(
        app,
        Surface::Global,
        "Loading plan impact",
        async move {
            adapter
                .plan_impact(&attempt.plan, attempt.cursor.clone())
                .await
        },
        move |app, _, result| {
            if let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            {
                let _ = dialog
                    .workflow
                    .as_mut()
                    .is_some_and(|workflow| workflow.finish_more_impact(ticket, result));
            }
        },
    )
    .await
}

async fn recover(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    let action = app
        .operator_policy
        .as_ref()
        .and_then(|dialog| dialog.workflow.as_ref())
        .and_then(|workflow| match &workflow.state {
            WorkflowState::Recovery(recovery) => Some(recovery.action.clone()),
            WorkflowState::Outcome { .. } => Some(RecoveryAction::LookupOperation(String::new())),
            _ => None,
        });
    match action {
        Some(RecoveryAction::RetryExactApply) => begin_exact_apply(app, poller, config_path).await,
        Some(RecoveryAction::ReplayRequest) => begin_replay(app, config_path).await,
        Some(RecoveryAction::LookupOperation(_)) => begin_operation_lookup(app, config_path).await,
        Some(RecoveryAction::RetryPlan) => retry_plan(app).await,
        Some(RecoveryAction::RefreshAndRedraft) => rebase_and_plan(app, poller).await,
        Some(RecoveryAction::ReturnToDraft) | None => {}
    }
}

async fn retry_plan(app: &mut App) {
    let Some((dialog_id, adapter, attempt)) = app.operator_policy.as_mut().and_then(|d| {
        let attempt = d.workflow.as_mut()?.begin_plan()?;
        Some((d.id, d.adapter.clone()?, attempt))
    }) else {
        return;
    };
    let ticket = attempt.ticket;
    actions::dispatch(
        app,
        Surface::Global,
        "Retrying policy plan",
        async move {
            adapter
                .create_plan(attempt.request.clone(), attempt.page.clone())
                .await
        },
        move |app, _, result| {
            if let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            {
                let _ = dialog
                    .workflow
                    .as_mut()
                    .is_some_and(|workflow| workflow.finish_plan(ticket, result));
            }
        },
    )
    .await;
}

async fn rebase_and_plan(app: &mut App, poller: &IpcPoller) {
    let Some(dialog) = app.operator_policy.as_ref() else {
        return;
    };
    let Some(workflow) = dialog.workflow.as_ref() else {
        return;
    };
    let WorkflowState::Recovery(recovery) = &workflow.state else {
        return;
    };
    let Some(draft) = recovery.draft.clone() else {
        return;
    };
    let operations = draft.request.operations;
    let origin = dialog.origin.clone();
    let prefix = dialog.prefix_outcome.clone();
    let socket = poller.socket_path().to_owned();
    let dialog_id = dialog.id;
    let retained_prefix = app.operator_policy_prefix.clone();
    actions::dispatch(
        app,
        Surface::Global,
        "Refreshing policy revision",
        async move {
            prepare(
                socket,
                origin,
                PolicyChange::Operations(operations),
                prefix,
                retained_prefix,
                None,
            )
            .await
        },
        move |app, _, result| apply_prepared(app, dialog_id, result),
    )
    .await;
}

async fn begin_exact_apply(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    let Some((dialog_id, adapter, attempt)) = app.operator_policy.as_mut().and_then(|dialog| {
        let attempt = dialog.workflow.as_mut()?.begin_exact_apply()?;
        Some((dialog.id, dialog.adapter.clone(), attempt))
    }) else {
        return;
    };
    let request = attempt.request.clone();
    let plan = attempt.plan.clone();
    let config_path = config_path.to_owned();
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        Surface::Global,
        "Retrying exact policy submission",
        async move {
            let adapter = match adapter {
                Some(adapter) => adapter,
                None => match OperatorPolicyAdapter::connect(socket).await {
                    Ok(adapter) => adapter,
                    Err(error) => return (Err(error), None, None),
                },
            };
            let result = adapter.apply(&plan).await;
            let journal_error = observe_result(config_path, &request, &result).await;
            (result, journal_error, Some(adapter))
        },
        move |app, _, result| {
            let (apply_result, journal_error, connected_adapter) = result;
            let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            else {
                return;
            };
            if let Some(adapter) = connected_adapter {
                dialog.adapter = Some(adapter);
            }
            let accepted = dialog
                .workflow
                .as_mut()
                .is_some_and(|workflow| workflow.finish_exact_apply(attempt.ticket, apply_result));
            if accepted {
                apply_current_outcome(app, dialog_id);
            }
            if let Some(error) = journal_error {
                app.status_err(format!(
                    "exact retry returned a receipt but journal could not advance: {}",
                    format_policy_error(&error)
                ));
            }
        },
    )
    .await;
}

async fn begin_replay(app: &mut App, config_path: &Path) {
    let Some((dialog_id, adapter, attempt)) = app.operator_policy.as_mut().and_then(|d| {
        let attempt = d.workflow.as_mut()?.begin_replay()?;
        Some((d.id, d.adapter.clone()?, attempt))
    }) else {
        return;
    };
    actions::dispatch(
        app,
        Surface::Global,
        "Recovering policy outcome",
        {
            let config_path = config_path.to_owned();
            let request = attempt.request.clone();
            async move {
                let result = adapter.replay(request.clone()).await;
                let journal_error = observe_result(config_path, &request, &result).await;
                (result, journal_error)
            }
        },
        move |app, _, result| {
            let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            else {
                return;
            };
            let accepted = dialog
                .workflow
                .as_mut()
                .is_some_and(|workflow| workflow.finish_replay(attempt.ticket, result.0));
            if accepted {
                apply_current_outcome(app, dialog_id);
            }
            if let Some(error) = result.1 {
                app.status_err(format!(
                    "recovery receipt received but journal could not advance: {}",
                    format_policy_error(&error)
                ));
            }
        },
    )
    .await;
}

async fn begin_operation_lookup(app: &mut App, config_path: &Path) {
    let Some((dialog_id, adapter, attempt, request)) = app.operator_policy.as_mut().and_then(|d| {
        let workflow = d.workflow.as_mut()?;
        let terminal_outcome = matches!(workflow.state, WorkflowState::Outcome { .. });
        if terminal_outcome {
            workflow.refresh_outcome();
        }
        let attempt = workflow.begin_operation_lookup()?;
        let request = match (&workflow.state, terminal_outcome) {
            (_, true) => None,
            (WorkflowState::Recovery(recovery), false) => {
                recovery.draft.as_ref().map(|draft| draft.request.clone())
            }
            _ => None,
        };
        Some((d.id, d.adapter.clone()?, attempt, request))
    }) else {
        return;
    };
    let ticket = attempt.ticket;
    let operation_id = attempt.operation_id;
    actions::dispatch(
        app,
        Surface::Global,
        "Refreshing policy receipt",
        {
            let config_path = config_path.to_owned();
            async move {
                let result = adapter.operation(operation_id).await;
                let journal_error = match &request {
                    Some(request) => observe_result(config_path, request, &result).await,
                    None => None,
                };
                (result, journal_error)
            }
        },
        move |app, _, result| {
            let Some(dialog) = app
                .operator_policy
                .as_mut()
                .filter(|dialog| dialog.id == dialog_id)
            else {
                return;
            };
            let accepted = dialog
                .workflow
                .as_mut()
                .is_some_and(|workflow| workflow.finish_operation_lookup(ticket, result.0));
            if accepted {
                apply_current_outcome(app, dialog_id);
            }
            if let Some(error) = result.1 {
                app.status_err(format!(
                    "receipt lookup succeeded but journal could not advance: {}",
                    format_policy_error(&error)
                ));
            }
        },
    )
    .await;
}

fn apply_current_outcome(app: &mut App, dialog_id: u64) {
    let outcome = app.operator_policy.as_ref().and_then(|dialog| {
        if dialog.id != dialog_id {
            return None;
        }
        let workflow = dialog.workflow.as_ref()?;
        let WorkflowState::Outcome { receipt, .. } = &workflow.state else {
            return None;
        };
        Some((dialog.origin.clone(), receipt.clone()))
    });
    let Some((origin, receipt)) = outcome else {
        return;
    };
    if receipt.persistence == PersistenceState::Committed {
        apply_origin_success(app, &origin, &receipt);
        let message = receipt_message(&receipt);
        match receipt.activation.state.as_str() {
            "applied" | "not_required" => app.status_ok(message),
            "pending" => app.status_info(message),
            _ => app.status_err(message),
        }
    } else {
        let message = receipt_message(&receipt);
        apply_origin_error(app, &origin, &message);
        app.status_err(message);
    }
}

async fn close_dialog(app: &mut App, config_path: &Path) {
    if app
        .operator_policy
        .as_ref()
        .is_some_and(|dialog| !dialog_can_close(dialog))
    {
        app.status_info(
            "policy outcome is unresolved — recover the exact submitted request first".into(),
        );
        return;
    }
    let discard = app.operator_policy.as_ref().and_then(|dialog| {
        let prefix = app.operator_policy_prefix.clone()?;
        let operations = dialog.discard_operations.clone()?;
        let never_submitted = match dialog.workflow.as_ref().map(|workflow| &workflow.state) {
            None => dialog.preparation_error.is_some(),
            Some(
                WorkflowState::Draft(_)
                | WorkflowState::Planning { .. }
                | WorkflowState::Planned { .. },
            ) => true,
            Some(WorkflowState::Recovery(recovery)) => matches!(
                recovery.action,
                RecoveryAction::RetryPlan
                    | RecoveryAction::RefreshAndRedraft
                    | RecoveryAction::ReturnToDraft
            ),
            Some(WorkflowState::Applying { .. } | WorkflowState::Outcome { .. }) => false,
        };
        (dialog.prefix_outcome.is_some() && never_submitted)
            .then(|| (dialog.id, dialog.origin.clone(), operations, prefix))
    });
    if let Some((dialog_id, origin, operations, prefix)) = discard {
        let config_path = config_path.to_owned();
        actions::dispatch(
            app,
            Surface::Global,
            "Discarding outstanding mount intent",
            recovery::discard_property_committed(config_path, origin, operations, prefix),
            move |app, _, result| match result {
                Ok(()) => finish_close_dialog(app, dialog_id),
                Err(error) => app.status_err(format!(
                    "mount intent was not discarded: {}",
                    format_policy_error(&error)
                )),
            },
        )
        .await;
        return;
    }
    let Some(dialog_id) = app.operator_policy.as_ref().map(|dialog| dialog.id) else {
        return;
    };
    finish_close_dialog(app, dialog_id);
}

fn finish_close_dialog(app: &mut App, dialog_id: u64) {
    if app
        .operator_policy
        .as_ref()
        .is_none_or(|dialog| dialog.id != dialog_id)
    {
        return;
    }
    let error = app.operator_policy.as_ref().and_then(|dialog| {
        dialog
            .preparation_error
            .clone()
            .map(|error| (dialog.origin.clone(), error))
    });
    app.operator_policy = None;
    if let Some((origin, error)) = error {
        apply_origin_error(app, &origin, &error);
    }
}

async fn close_terminal_dialog(app: &mut App, config_path: &Path) {
    let terminal = app.operator_policy.as_ref().is_some_and(|dialog| {
        dialog.preparation_error.is_some()
            || dialog.workflow.as_ref().is_some_and(|workflow| {
                matches!(
                    &workflow.state,
                    WorkflowState::Outcome { receipt, .. }
                        if matches!(
                            receipt.persistence,
                            PersistenceState::Committed | PersistenceState::Aborted
                        )
                )
            })
    });
    if terminal {
        close_dialog(app, config_path).await;
    }
}

pub(super) fn dialog_can_close(dialog: &PolicyDialog) -> bool {
    if dialog.preparing || dialog.preparation_error.is_some() {
        return !dialog.preparing;
    }
    let Some(workflow) = &dialog.workflow else {
        return true;
    };
    match &workflow.state {
        WorkflowState::Applying { .. } => false,
        WorkflowState::Outcome { receipt, .. } => matches!(
            receipt.persistence,
            PersistenceState::Committed | PersistenceState::Aborted
        ),
        WorkflowState::Recovery(recovery) => !matches!(
            recovery.action,
            RecoveryAction::RetryExactApply
                | RecoveryAction::ReplayRequest
                | RecoveryAction::LookupOperation(_)
        ),
        _ => true,
    }
}

fn apply_origin_success(app: &mut App, origin: &PolicyOrigin, receipt: &Receipt) {
    let message = receipt_message(receipt);
    match origin {
        PolicyOrigin::Recovery => {}
        PolicyOrigin::CustomList => {
            if let Some(modal) = app.custom_lists.modal.as_mut() {
                modal.finish(crate::tui::custom_list_modal::SubmitOutcome::Ok(message));
            }
        }
        PolicyOrigin::Mount => {
            if let Some(picker) = app.custom_lists.mount_picker.as_mut() {
                for row in &mut picker.rows {
                    row.mounted = row.staged;
                }
                picker.error = None;
                picker.failed = false;
                picker.outcome = Some(message);
            }
        }
        PolicyOrigin::QueryRules {
            ids,
            already_present,
        } => {
            let reports = ids
                .iter()
                .zip(already_present)
                .map(
                    |(id, present)| crate::tui::query_log_rule_modal::RuleReport {
                        id: id.clone(),
                        outcome: if *present {
                            crate::tui::query_log_rule_modal::RuleOutcome::AlreadyPresent
                        } else {
                            crate::tui::query_log_rule_modal::RuleOutcome::Added
                        },
                    },
                )
                .collect();
            if let Some(modal) = app.query_log_rule_modal.as_mut() {
                modal.finish(reports);
            }
        }
        PolicyOrigin::QueryNewList { id, display_name } => {
            if let Some(modal) = app.query_log_rule_modal.as_mut() {
                let mut rows = modal.rows.clone();
                if !rows.iter().any(|row| row.id == *id) {
                    rows.push(crate::tui::query_log_rule_modal::ListRow::new(
                        id.clone(),
                        display_name.clone(),
                        Vec::new(),
                    ));
                    rows.sort_by(|left, right| left.id.cmp(&right.id));
                }
                modal.adopt_lists(rows, Some(id));
            }
        }
        PolicyOrigin::ProfileMounts { .. } => {
            if let Some(modal) = app.profiles.modal.as_mut() {
                modal.finish(crate::tui::profile_modal::SubmitOutcome::Ok(message));
            }
        }
    }
}

fn apply_origin_error(app: &mut App, origin: &PolicyOrigin, message: &str) {
    match origin {
        PolicyOrigin::Recovery => {}
        PolicyOrigin::CustomList => {
            if let Some(modal) = app.custom_lists.modal.as_mut() {
                match &mut modal.stage {
                    crate::tui::custom_list_modal::Stage::EditingForm(form) => {
                        form.error_message = Some(message.into())
                    }
                    crate::tui::custom_list_modal::Stage::AddingRule(form) => {
                        form.error_message = Some(message.into())
                    }
                    _ => modal.finish(crate::tui::custom_list_modal::SubmitOutcome::Failed(
                        message.into(),
                    )),
                }
            }
        }
        PolicyOrigin::Mount => {
            if let Some(picker) = app.custom_lists.mount_picker.as_mut() {
                picker.error = Some(message.into());
            }
        }
        PolicyOrigin::QueryRules { .. } => {
            if let Some(modal) = app.query_log_rule_modal.as_mut() {
                modal.error = Some(message.into());
            }
        }
        PolicyOrigin::QueryNewList { .. } => {
            if let Some(modal) = app.query_log_rule_modal.as_mut() {
                if let crate::tui::query_log_rule_modal::Stage::NewList(inner) = &mut modal.stage {
                    if let crate::tui::custom_list_modal::Stage::EditingForm(form) =
                        &mut inner.stage
                    {
                        form.error_message = Some(message.into());
                    }
                }
            }
        }
        PolicyOrigin::ProfileMounts { .. } => {
            if let Some(modal) = app.profiles.modal.as_mut() {
                if let crate::tui::profile_modal::Stage::EditingForm(form) = &mut modal.stage {
                    form.error_message = Some(message.into());
                }
            }
        }
    }
}

pub(super) fn receipt_message(receipt: &Receipt) -> String {
    let persistence = match receipt.persistence {
        PersistenceState::Prepared => "prepared",
        PersistenceState::Committed => "committed",
        PersistenceState::Aborted => "aborted",
        PersistenceState::DurabilityUncertain => "durability uncertain",
    };
    format!(
        "policy {persistence}; activation {} · operation {}",
        receipt.activation.state, receipt.operation_id
    )
}

pub(super) fn format_policy_error(error: &AdapterError) -> String {
    format!("{}: {}", error.code().as_str(), error.message())
}

fn protocol_error(code: ErrorCode, message: &str) -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::Protocol,
        error: OperatorRulesError::new(code, message),
    }
}

#[cfg(test)]
mod rule_count_tests {
    use super::*;

    fn row(action: Option<RuleAction>, valid: bool, duplicate: bool) -> RuleRow {
        RuleRow {
            line: 1,
            raw: String::new(),
            row_ref: "row-1".into(),
            rule_key: None,
            action,
            valid,
            duplicate,
        }
    }

    #[test]
    fn semantic_counts_exclude_comments_and_classify_duplicate_rules_as_skipped() {
        let rows = [
            row(Some(RuleAction::Allow), true, false),
            row(Some(RuleAction::Deny), true, false),
            row(Some(RuleAction::Allow), true, true),
            row(Some(RuleAction::Deny), true, true),
            row(None, true, true),
            row(None, true, false),
            row(None, false, false),
        ];
        assert_eq!(semantic_rule_counts(&rows), (1, 1, 3));
    }

    fn page(next_cursor: Option<&str>, rows: Vec<RuleRow>) -> RulePage {
        RulePage {
            contract_version: crate::operator_rules::CONTRACT_VERSION,
            id: "local".into(),
            config_revision: "config-r1".into(),
            pack_revision: "pack-r1".into(),
            rows,
            next_cursor: next_cursor.map(str::to_string),
        }
    }

    #[test]
    fn complete_page_chain_is_accumulated_before_counting() {
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        let mut first = page(
            Some("next-1"),
            vec![row(Some(RuleAction::Allow), true, false)],
        );
        assert!(
            accept_rule_page(&mut first, "config-r1", "pack-r1", &mut seen, &mut rows,).unwrap()
        );
        let mut last = page(None, vec![row(Some(RuleAction::Deny), true, false)]);
        assert!(
            !accept_rule_page(&mut last, "config-r1", "pack-r1", &mut seen, &mut rows,).unwrap()
        );
        assert_eq!(semantic_rule_counts(&rows), (1, 1, 0));
    }

    #[test]
    fn repeated_pagination_cursor_is_rejected_before_its_rows_are_accepted() {
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        let mut first = page(Some("next-1"), Vec::new());
        assert!(
            accept_rule_page(&mut first, "config-r1", "pack-r1", &mut seen, &mut rows,).unwrap()
        );
        let mut repeated = page(
            Some("next-1"),
            vec![row(Some(RuleAction::Allow), true, false)],
        );
        assert!(
            accept_rule_page(&mut repeated, "config-r1", "pack-r1", &mut seen, &mut rows,).is_err()
        );
        assert!(
            rows.is_empty(),
            "a rejected page cannot contribute a partial count"
        );
    }
}
