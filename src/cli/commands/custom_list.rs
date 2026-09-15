use std::io::Write;
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::{CustomListAction, OperatorMutationArgs};
use crate::ipc::protocol::{
    CustomListsReadRequest, CustomListsReadResponse, IpcCommand, IpcResponse,
};
use crate::operator_rules::{
    Actor, BatchRequest, ErrorCode, ExportRequest, Operation, OperatorRulesError, PageRequest,
    PersistenceState, Plan, PlanSummary, Receipt, RuleAction, TransportLimits, CONTRACT_VERSION,
};

const EXIT_OK: i32 = 0;
const EXIT_INPUT: i32 = 2;
const EXIT_CONFLICT: i32 = 3;
const EXIT_PRE_COMMIT: i32 = 4;
const EXIT_COMMITTED_PENDING: i32 = 5;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPlan {
    contract_version: u32,
    transport: String,
    plan_ref: Option<String>,
    plan_hash: String,
    request_id: String,
    request: Option<BatchRequest>,
    summary: PlanSummary,
}

pub async fn run(
    action: CustomListAction,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> anyhow::Result<i32> {
    let error_json = action_json(&action);
    let result = match action {
        CustomListAction::List {
            cursor,
            limit,
            json,
        } => {
            read_command(
                CustomListsReadRequest::List {
                    page: PageRequest { cursor, limit },
                },
                offline,
                config_path,
                socket_path,
                json,
            )
            .await
        }
        CustomListAction::Show { id, json } => {
            read_command(
                CustomListsReadRequest::Show { id },
                offline,
                config_path,
                socket_path,
                json,
            )
            .await
        }
        CustomListAction::Rules {
            id,
            cursor,
            limit,
            json,
        } => {
            read_command(
                CustomListsReadRequest::Rules {
                    id,
                    page: PageRequest { cursor, limit },
                },
                offline,
                config_path,
                socket_path,
                json,
            )
            .await
        }
        CustomListAction::Create {
            id,
            display_name,
            description,
            into,
            mutation,
        } => {
            mutate(
                vec![Operation::CreateList {
                    id,
                    display_name,
                    description,
                    into,
                }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::Set {
            id,
            display_name,
            description,
            mutation,
        } => {
            if display_name.is_none() && description.is_none() {
                Err(OperatorRulesError::new(
                    ErrorCode::InvalidRequest,
                    "set requires --display-name or --description",
                ))
            } else {
                mutate(
                    vec![Operation::SetMetadata {
                        id,
                        display_name,
                        description,
                    }],
                    mutation,
                    offline,
                    config_path,
                    socket_path,
                )
                .await
            }
        }
        CustomListAction::Add {
            id,
            domain,
            allow,
            deny: _,
            mutation,
        } => {
            mutate(
                vec![Operation::AddDomainRule {
                    id,
                    domain,
                    action: if allow {
                        RuleAction::Allow
                    } else {
                        RuleAction::Deny
                    },
                }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::AddRule { id, rule, mutation } => {
            mutate(
                vec![Operation::AddRawRule { id, rule }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::ReplaceRule {
            id,
            row_ref,
            rule,
            mutation,
        } => {
            mutate(
                vec![Operation::ReplaceRule { id, row_ref, rule }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::RemoveRule {
            id,
            row_ref,
            mutation,
        } => {
            mutate(
                vec![Operation::RemoveRule { id, row_ref }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::Export { id, json } => {
            export(&id, offline, config_path, socket_path, json).await
        }
        CustomListAction::Delete {
            id,
            cascade_unmount,
            mutation,
        } => {
            mutate(
                vec![Operation::DeleteList {
                    id,
                    cascade_unmount,
                }],
                mutation,
                offline,
                config_path,
                socket_path,
            )
            .await
        }
        CustomListAction::Plan {
            operations,
            mutation,
        } => plan_file(&operations, mutation, offline, config_path, socket_path).await,
        CustomListAction::Apply {
            plan,
            expect_plan_hash,
            json,
        } => {
            apply_saved_plan(
                &plan,
                &expect_plan_hash,
                offline,
                config_path,
                socket_path,
                json,
            )
            .await
        }
        CustomListAction::Operation { operation_id, json } => {
            operation(&operation_id, offline, config_path, socket_path, json).await
        }
    };
    Ok(match result {
        Ok(code) => code,
        Err(error) => {
            print_error(&error, error_json)?;
            error_exit(&error)
        }
    })
}

pub async fn run_profile_mount(
    profile_id: String,
    custom_list: String,
    mount: bool,
    mutation: OperatorMutationArgs,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> anyhow::Result<i32> {
    let error_json = mutation.json;
    let operation = if mount {
        Operation::Mount {
            id: custom_list,
            profile_id,
        }
    } else {
        Operation::Unmount {
            id: custom_list,
            profile_id,
        }
    };
    Ok(
        match mutate(vec![operation], mutation, offline, config_path, socket_path).await {
            Ok(code) => code,
            Err(error) => {
                print_error(&error, error_json)?;
                error_exit(&error)
            }
        },
    )
}

async fn read_command(
    request: CustomListsReadRequest,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
    json: bool,
) -> Result<i32, OperatorRulesError> {
    let response = if offline {
        let service = crate::operator_rules::OperatorRulesService::new(config_path);
        match request {
            CustomListsReadRequest::List { page } => service
                .read(page, TransportLimits::IPC)
                .map(CustomListsReadResponse::List),
            CustomListsReadRequest::Show { id } => {
                service.show(&id).map(CustomListsReadResponse::Show)
            }
            CustomListsReadRequest::Rules { id, page } => service
                .rules(&id, page, TransportLimits::IPC)
                .map(CustomListsReadResponse::Rules),
        }?
    } else {
        match send(
            socket_path,
            IpcCommand::CustomListsRead {
                request,
                token: None,
            },
        )
        .await?
        {
            IpcResponse::CustomListsRead { response } => response,
            other => return Err(unexpected(other)),
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).map_err(storage)?
        );
    } else {
        match response {
            CustomListsReadResponse::List(page) => {
                for list in page.lists {
                    println!(
                        "{}\t{}\t{} rules",
                        list.id, list.display_name, list.rule_count
                    );
                }
                if let Some(cursor) = page.next_cursor {
                    println!("next cursor: {cursor}");
                }
            }
            CustomListsReadResponse::Show(list) => {
                println!("{}", list.id);
                println!("  name: {}", list.display_name);
                println!("  description: {}", list.description);
                println!("  rules: {}", list.rule_count);
                println!("  bytes: {}", list.bytes);
                println!("  pack revision: {}", list.pack_revision);
                if !list.profiles.is_empty() {
                    println!("  profiles: {}", list.profiles.join(", "));
                }
            }
            CustomListsReadResponse::Rules(page) => {
                for row in page.rows {
                    println!("{}\t{}\t{}", row.line, row.row_ref, row.raw);
                }
                if let Some(cursor) = page.next_cursor {
                    println!("next cursor: {cursor}");
                }
            }
        }
    }
    Ok(EXIT_OK)
}

async fn mutate(
    operations: Vec<Operation>,
    mutation: OperatorMutationArgs,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> Result<i32, OperatorRulesError> {
    let request = build_request(operations, &mutation, offline, config_path, socket_path).await?;
    if offline {
        let service = crate::operator_rules::OperatorRulesService::new(config_path);
        let plan = match service.plan(&request, TransportLimits::IPC) {
            Ok(plan) => plan,
            Err(plan_error) if mutation.dry_run => return Err(plan_error),
            Err(plan_error) => {
                let Some(mut receipt) = service.replay_request(
                    &local_actor("offline"),
                    &request,
                    TransportLimits::IPC,
                )?
                else {
                    return Err(plan_error);
                };
                activate_after_offline(&mut receipt, request, socket_path, mutation.json).await;
                print_receipt(&receipt, mutation.json)?;
                return Ok(receipt_exit(&receipt));
            }
        };
        if mutation.dry_run {
            print_plan(&plan, mutation.json)?;
            return Ok(EXIT_OK);
        }
        let mut apply_request = request;
        apply_request.expected_plan_hash = Some(plan.plan_hash);
        let mut receipt = service.apply_with_prepared(
            &local_actor("offline"),
            &apply_request,
            TransportLimits::IPC,
            |_| {},
        )?;
        activate_after_offline(&mut receipt, apply_request, socket_path, mutation.json).await;
        print_receipt(&receipt, mutation.json)?;
        return Ok(receipt_exit(&receipt));
    }

    let request_id = request.request_id.clone();
    let (plan_ref, summary) = match ipc_plan(socket_path, request.clone()).await {
        Ok(plan) => plan,
        Err(plan_error) if mutation.dry_run => return Err(plan_error),
        Err(plan_error) => {
            let Some(receipt) = ipc_replay(socket_path, request).await? else {
                return Err(plan_error);
            };
            print_receipt(&receipt, mutation.json)?;
            return Ok(receipt_exit(&receipt));
        }
    };
    if mutation.dry_run {
        print_value(&summary, mutation.json)?;
        return Ok(EXIT_OK);
    }
    match send(
        socket_path,
        IpcCommand::OperatorRulesApply {
            plan_ref,
            plan_hash: summary.plan_hash,
            request_id,
            token: None,
        },
    )
    .await?
    {
        IpcResponse::OperatorRulesApply { receipt } => {
            print_receipt(&receipt, mutation.json)?;
            Ok(receipt_exit(&receipt))
        }
        other => Err(unexpected(other)),
    }
}

async fn build_request(
    operations: Vec<Operation>,
    mutation: &OperatorMutationArgs,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> Result<BatchRequest, OperatorRulesError> {
    let revision = match &mutation.expect_revision {
        Some(revision) => revision.clone(),
        None => current_revision(offline, config_path, socket_path).await?,
    };
    Ok(BatchRequest {
        contract_version: CONTRACT_VERSION,
        request_id: mutation.request_id.clone().unwrap_or_else(new_request_id),
        expected_config_revision: revision,
        operations,
        expected_plan_hash: None,
    })
}

async fn current_revision(
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> Result<String, OperatorRulesError> {
    if offline {
        return crate::operator_rules::OperatorRulesService::new(config_path)
            .read(PageRequest::default(), TransportLimits::IPC)
            .map(|page| page.config_revision);
    }
    match send(
        socket_path,
        IpcCommand::CustomListsRead {
            request: CustomListsReadRequest::List {
                page: PageRequest {
                    cursor: None,
                    limit: Some(1),
                },
            },
            token: None,
        },
    )
    .await?
    {
        IpcResponse::CustomListsRead {
            response: CustomListsReadResponse::List(page),
        } => Ok(page.config_revision),
        other => Err(unexpected(other)),
    }
}

async fn ipc_plan(
    socket_path: &Path,
    request: BatchRequest,
) -> Result<(String, PlanSummary), OperatorRulesError> {
    match send(
        socket_path,
        IpcCommand::OperatorRulesPlan {
            request: Some(request),
            plan_ref: None,
            page: PageRequest::default(),
            token: None,
        },
    )
    .await?
    {
        IpcResponse::OperatorRulesPlan {
            plan_ref, summary, ..
        } => Ok((plan_ref, summary)),
        other => Err(unexpected(other)),
    }
}

async fn ipc_replay(
    socket_path: &Path,
    request: BatchRequest,
) -> Result<Option<Receipt>, OperatorRulesError> {
    match send(
        socket_path,
        IpcCommand::OperatorRulesReplay {
            request,
            token: None,
        },
    )
    .await
    {
        Ok(IpcResponse::OperatorRulesApply { receipt }) => Ok(Some(receipt)),
        Ok(other) => Err(unexpected(other)),
        Err(error) if error.code == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

async fn plan_file(
    operations_path: &Path,
    mutation: OperatorMutationArgs,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
) -> Result<i32, OperatorRulesError> {
    let bytes = std::fs::read(operations_path).map_err(storage)?;
    let operations: Vec<Operation> = serde_json::from_slice(&bytes).map_err(|error| {
        OperatorRulesError::new(
            ErrorCode::InvalidRequest,
            format!("operations file is not a JSON operation array: {error}"),
        )
    })?;
    let request = build_request(operations, &mutation, offline, config_path, socket_path).await?;
    let saved = if offline {
        let plan = crate::operator_rules::OperatorRulesService::new(config_path)
            .plan(&request, TransportLimits::IPC)?;
        SavedPlan {
            contract_version: CONTRACT_VERSION,
            transport: "offline".into(),
            plan_ref: None,
            plan_hash: plan.plan_hash.clone(),
            request_id: plan.request.request_id.clone(),
            request: Some(plan.request.clone()),
            summary: crate::operator_rules::OperatorRulesService::plan_summary(&plan),
        }
    } else {
        let request_id = request.request_id.clone();
        let (plan_ref, summary) = ipc_plan(socket_path, request).await?;
        SavedPlan {
            contract_version: CONTRACT_VERSION,
            transport: "ipc".into(),
            plan_ref: Some(plan_ref),
            plan_hash: summary.plan_hash.clone(),
            request_id,
            request: None,
            summary,
        }
    };
    print_value(&saved, mutation.json)?;
    Ok(EXIT_OK)
}

async fn apply_saved_plan(
    path: &Path,
    expected_hash: &str,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
    json: bool,
) -> Result<i32, OperatorRulesError> {
    let saved: SavedPlan =
        serde_json::from_slice(&std::fs::read(path).map_err(storage)?).map_err(|error| {
            OperatorRulesError::new(
                ErrorCode::InvalidRequest,
                format!("invalid plan file: {error}"),
            )
        })?;
    if saved.contract_version != CONTRACT_VERSION || saved.plan_hash != expected_hash {
        return Err(OperatorRulesError::new(
            ErrorCode::PlanConflict,
            "plan file does not match --expect-plan-hash",
        ));
    }
    let mut offline_request = None;
    let mut receipt = if offline {
        let mut request = saved.request.ok_or_else(|| {
            OperatorRulesError::new(
                ErrorCode::PlanConflict,
                "IPC plan files cannot be applied offline; create an offline plan",
            )
        })?;
        request.expected_plan_hash = Some(expected_hash.into());
        offline_request = Some(request.clone());
        crate::operator_rules::OperatorRulesService::new(config_path).apply_with_prepared(
            &local_actor("offline"),
            &request,
            TransportLimits::IPC,
            |_| {},
        )?
    } else {
        let plan_ref = saved.plan_ref.ok_or_else(|| {
            OperatorRulesError::new(
                ErrorCode::PlanConflict,
                "offline plan files cannot cross the IPC boundary; plan again through the daemon",
            )
        })?;
        match send(
            socket_path,
            IpcCommand::OperatorRulesApply {
                plan_ref,
                plan_hash: expected_hash.into(),
                request_id: saved.request_id,
                token: None,
            },
        )
        .await?
        {
            IpcResponse::OperatorRulesApply { receipt } => receipt,
            other => return Err(unexpected(other)),
        }
    };
    if offline {
        activate_after_offline(
            &mut receipt,
            offline_request.expect("offline apply retains its exact request"),
            socket_path,
            json,
        )
        .await;
    }
    print_receipt(&receipt, json)?;
    Ok(receipt_exit(&receipt))
}

async fn operation(
    operation_id: &str,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
    json: bool,
) -> Result<i32, OperatorRulesError> {
    let receipt = if offline {
        crate::operator_rules::OperatorRulesService::new(config_path)
            .operation(&local_actor("offline"), operation_id)?
    } else {
        match send(
            socket_path,
            IpcCommand::OperatorRulesOperation {
                operation_id: operation_id.into(),
                token: None,
            },
        )
        .await?
        {
            IpcResponse::OperatorRulesOperation { receipt } => receipt,
            other => return Err(unexpected(other)),
        }
    };
    print_receipt(&receipt, json)?;
    Ok(receipt_exit(&receipt))
}

async fn export(
    id: &str,
    offline: bool,
    config_path: &Path,
    socket_path: &Path,
    json: bool,
) -> Result<i32, OperatorRulesError> {
    let mut bytes = Vec::new();
    let mut revision = None;
    let mut total = None;
    loop {
        let request = ExportRequest {
            id: id.into(),
            offset: bytes.len(),
            max_bytes: TransportLimits::IPC.max_export_bytes,
            expected_pack_revision: revision.clone(),
        };
        let chunk = if offline {
            crate::operator_rules::OperatorRulesService::new(config_path)
                .export(&request, TransportLimits::IPC)?
        } else {
            match send(
                socket_path,
                IpcCommand::CustomListExportChunk {
                    request,
                    token: None,
                },
            )
            .await?
            {
                IpcResponse::CustomListExportChunk { chunk } => chunk,
                other => return Err(unexpected(other)),
            }
        };
        if chunk.offset != bytes.len()
            || revision
                .as_ref()
                .is_some_and(|value| value != &chunk.pack_revision)
            || total.is_some_and(|value| value != chunk.total_bytes)
        {
            return Err(OperatorRulesError::new(
                ErrorCode::RevisionConflict,
                "export chunks do not describe one complete pack revision",
            ));
        }
        revision = Some(chunk.pack_revision);
        total = Some(chunk.total_bytes);
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(chunk.data_base64)
                .map_err(storage)?,
        );
        if chunk.eof {
            break;
        }
    }
    let revision = revision.unwrap_or_default();
    if bytes.len() != total.unwrap_or_default() || hex::encode(Sha256::digest(&bytes)) != revision {
        return Err(OperatorRulesError::new(
            ErrorCode::RevisionConflict,
            "export length or final SHA-256 verification failed",
        ));
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "contract_version": CONTRACT_VERSION,
                "id": id,
                "pack_revision": revision,
                "data_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }))
            .map_err(storage)?
        );
    } else {
        std::io::stdout().write_all(&bytes).map_err(storage)?;
    }
    Ok(EXIT_OK)
}

async fn send(socket_path: &Path, command: IpcCommand) -> Result<IpcResponse, OperatorRulesError> {
    match crate::ipc::socket_client::send_command(socket_path, &command).await {
        Ok(IpcResponse::OperatorRulesError { error }) => Err(error),
        Ok(response) => Ok(response),
        Err(error) => Err(storage(error)),
    }
}

async fn activate_after_offline(
    receipt: &mut Receipt,
    request: BatchRequest,
    socket_path: &Path,
    quiet: bool,
) {
    if !receipt.changed || receipt.persistence != PersistenceState::Committed {
        return;
    }
    match ipc_replay(socket_path, request).await {
        Ok(Some(active)) => *receipt = active,
        Ok(None) => {
            receipt.activation.reload_outcome = Some("receipt_not_visible".into());
            if !quiet {
                eprintln!(
                    "committed change is pending activation; daemon could not correlate its receipt"
                );
            }
        }
        Err(error) => {
            receipt.activation.reload_outcome = Some("activation_unavailable".into());
            receipt
                .diagnostics
                .push(format!("activation request failed: {}", error.message));
            if !quiet {
                eprintln!(
                    "committed change is pending activation; daemon did not acknowledge it: {}",
                    error.message
                );
            }
        }
    }
}

fn local_actor(origin: &str) -> Actor {
    Actor {
        identity: format!("uid:{}", crate::ipc::socket_server::current_euid()),
        origin: origin.into(),
    }
}

fn new_request_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn print_plan(plan: &Plan, json: bool) -> Result<(), OperatorRulesError> {
    if json {
        println!("{}", serde_json::to_string_pretty(plan).map_err(storage)?);
    } else {
        println!("plan {}", plan.plan_hash);
        println!("  changed: {}", plan.changed);
        println!("  operations: {}", plan.request.operations.len());
        println!("  affected profiles: {}", plan.impacted_profiles.len());
    }
    Ok(())
}

fn print_receipt(receipt: &Receipt, json: bool) -> Result<(), OperatorRulesError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(receipt).map_err(storage)?
        );
    } else {
        println!("operation {}", receipt.operation_id);
        println!("  persistence: {:?}", receipt.persistence);
        println!("  activation: {}", receipt.activation.state);
        println!("  config revision: {}", receipt.config_revision);
    }
    Ok(())
}

fn print_value(value: &impl Serialize, json: bool) -> Result<(), OperatorRulesError> {
    if json {
        println!("{}", serde_json::to_string_pretty(value).map_err(storage)?);
    } else {
        println!("{}", serde_json::to_string(value).map_err(storage)?);
    }
    Ok(())
}

fn print_error(error: &OperatorRulesError, json: bool) -> anyhow::Result<()> {
    if json {
        eprintln!("{}", serde_json::to_string(error)?);
    } else {
        eprintln!("{error}");
    }
    Ok(())
}

fn receipt_exit(receipt: &Receipt) -> i32 {
    match (receipt.persistence, receipt.changed) {
        (PersistenceState::Committed, false) => EXIT_OK,
        (PersistenceState::Committed | PersistenceState::DurabilityUncertain, true) => {
            EXIT_COMMITTED_PENDING
        }
        (PersistenceState::Prepared | PersistenceState::Aborted, _) => EXIT_PRE_COMMIT,
        (PersistenceState::DurabilityUncertain, false) => EXIT_COMMITTED_PENDING,
    }
}

fn error_exit(error: &OperatorRulesError) -> i32 {
    match error.code {
        ErrorCode::UnsupportedContract
        | ErrorCode::InvalidRequest
        | ErrorCode::InvalidId
        | ErrorCode::InvalidRule
        | ErrorCode::SchemaUpgradeRequired
        | ErrorCode::BudgetExceeded
        | ErrorCode::ValidationFailed => EXIT_INPUT,
        ErrorCode::RevisionConflict
        | ErrorCode::RowConflict
        | ErrorCode::PlanConflict
        | ErrorCode::IdempotencyConflict
        | ErrorCode::StaleCursor
        | ErrorCode::AlreadyExists
        | ErrorCode::ListMounted => EXIT_CONFLICT,
        ErrorCode::PolicyOwnedByPrimary
        | ErrorCode::NotFound
        | ErrorCode::TransportLimitExceeded
        | ErrorCode::UnsafePath
        | ErrorCode::TreeChanged
        | ErrorCode::StorageUnavailable
        | ErrorCode::RecoveryRequired
        | ErrorCode::RecoveryConflict
        | ErrorCode::AdmissionRejected => EXIT_PRE_COMMIT,
    }
}

fn unexpected(response: IpcResponse) -> OperatorRulesError {
    match response {
        IpcResponse::Error { message } => {
            OperatorRulesError::new(ErrorCode::StorageUnavailable, message)
        }
        other => OperatorRulesError::new(
            ErrorCode::UnsupportedContract,
            format!("unexpected daemon response: {other:?}"),
        ),
    }
}

fn storage(error: impl std::fmt::Display) -> OperatorRulesError {
    OperatorRulesError::new(ErrorCode::StorageUnavailable, error.to_string())
}

fn action_json(action: &CustomListAction) -> bool {
    match action {
        CustomListAction::List { json, .. }
        | CustomListAction::Show { json, .. }
        | CustomListAction::Rules { json, .. }
        | CustomListAction::Export { json, .. }
        | CustomListAction::Apply { json, .. }
        | CustomListAction::Operation { json, .. } => *json,
        CustomListAction::Create { mutation, .. }
        | CustomListAction::Set { mutation, .. }
        | CustomListAction::Add { mutation, .. }
        | CustomListAction::AddRule { mutation, .. }
        | CustomListAction::ReplaceRule { mutation, .. }
        | CustomListAction::RemoveRule { mutation, .. }
        | CustomListAction::Delete { mutation, .. }
        | CustomListAction::Plan { mutation, .. } => mutation.json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn add_requires_exactly_one_direction() {
        for args in [
            vec!["warden", "custom-list", "add", "local", "ads.example"],
            vec![
                "warden",
                "custom-list",
                "add",
                "local",
                "ads.example",
                "--allow",
                "--deny",
            ],
        ] {
            assert!(crate::cli::Cli::try_parse_from(args).is_err());
        }
        assert!(crate::cli::Cli::try_parse_from([
            "warden",
            "custom-list",
            "add",
            "local",
            "ads.example",
            "--allow",
        ])
        .is_ok());
    }

    #[test]
    fn receipt_exit_codes_keep_commit_uncertainty_distinct() {
        let mut receipt = Receipt {
            contract_version: 1,
            operation_id: "operation".into(),
            request_id: "request".into(),
            changed: true,
            persistence: PersistenceState::Committed,
            config_revision: "revision".into(),
            operator_policy_hash: None,
            activation: crate::operator_rules::Activation {
                state: "pending".into(),
                correlation_id: None,
                reload_outcome: None,
                active_config_revision: None,
                active_policy_hash: None,
                daemon_instance_id: None,
                superseded_by: None,
            },
            replication: "unavailable".into(),
            audit: "intent_recorded".into(),
            diagnostics: vec![],
        };
        assert_eq!(receipt_exit(&receipt), 5);
        receipt.changed = false;
        assert_eq!(receipt_exit(&receipt), 0);
        receipt.persistence = PersistenceState::Aborted;
        assert_eq!(receipt_exit(&receipt), 4);
    }

    #[test]
    fn invalid_id_is_an_input_error() {
        assert_eq!(
            error_exit(&OperatorRulesError::new(ErrorCode::InvalidId, "redacted")),
            2
        );
    }
}
