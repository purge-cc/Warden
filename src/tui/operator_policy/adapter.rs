use std::path::{Path, PathBuf};

use crate::ipc::protocol::{
    CustomListsReadRequest, CustomListsReadResponse, IpcCommand, IpcResponse,
    OPERATOR_RULES_MAX_BYTES,
};
use crate::operator_rules::{
    BatchRequest, Capabilities, ErrorCode, ListPage, Metadata, Operation, OperatorRulesError,
    PageRequest, PlanImpactPage, PlanSummary, Receipt, RulePage, TransportLimits, CONTRACT_VERSION,
};

#[cfg(test)]
static TEST_TOKENS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, String>>,
> = std::sync::OnceLock::new();

/// Whether a failure came from the daemon, the local transport, or validation
/// of a response that cannot satisfy contract v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorKind {
    Remote,
    Transport,
    Protocol,
}

/// A structured operator-policy failure. Daemon errors retain their exact
/// [`ErrorCode`]; local failures use the closest contract code without losing
/// their origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterError {
    pub(crate) kind: AdapterErrorKind,
    pub(crate) error: OperatorRulesError,
}

impl AdapterError {
    pub(crate) fn code(&self) -> ErrorCode {
        self.error.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.error.message
    }

    fn remote(error: OperatorRulesError) -> Self {
        Self {
            kind: AdapterErrorKind::Remote,
            error,
        }
    }

    fn transport(error: impl std::fmt::Display) -> Self {
        Self {
            kind: AdapterErrorKind::Transport,
            error: OperatorRulesError::new(ErrorCode::StorageUnavailable, error.to_string()),
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            kind: AdapterErrorKind::Protocol,
            error: OperatorRulesError::new(ErrorCode::UnsupportedContract, message),
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            kind: AdapterErrorKind::Protocol,
            error: OperatorRulesError::new(ErrorCode::InvalidRequest, message),
        }
    }

    fn transport_limit(message: impl Into<String>) -> Self {
        Self {
            kind: AdapterErrorKind::Protocol,
            error: OperatorRulesError::new(ErrorCode::TransportLimitExceeded, message),
        }
    }
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

impl std::error::Error for AdapterError {}

/// An opaque daemon-retained plan plus the impact rows accumulated by the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetainedPlan {
    pub(crate) plan_ref: String,
    pub(crate) request_id: String,
    pub(crate) summary: PlanSummary,
    pub(crate) impact_rows: Vec<crate::operator_rules::PlanImpactRow>,
    pub(crate) next_impact_cursor: Option<String>,
}

impl RetainedPlan {
    fn from_first_page(
        plan_ref: String,
        request_id: String,
        summary: PlanSummary,
        impact: PlanImpactPage,
    ) -> Result<Self, AdapterError> {
        validate_plan_response(&plan_ref, &summary, &impact)?;
        Ok(Self {
            plan_ref,
            request_id,
            summary,
            impact_rows: impact.rows,
            next_impact_cursor: impact.next_cursor,
        })
    }

    pub(crate) fn append_impact(&mut self, page: PlanImpactPage) -> Result<(), AdapterError> {
        validate_contract(page.contract_version, "plan impact")?;
        if page.plan_hash != self.summary.plan_hash {
            return Err(AdapterError::protocol(
                "plan impact hash does not match the retained plan",
            ));
        }
        self.impact_rows.extend(page.rows);
        self.next_impact_cursor = page.next_cursor;
        Ok(())
    }
}

/// A negotiated, typed IPC connection for operator-policy reads and writes.
///
/// `connect` performs the ReadOnly capability handshake. Admin calls leave the
/// token empty so `socket_client::send_command` uses the standard token file.
#[derive(Debug, Clone)]
pub(crate) struct OperatorPolicyAdapter {
    socket_path: PathBuf,
    token: Option<String>,
    capabilities: Capabilities,
}

impl OperatorPolicyAdapter {
    pub(crate) async fn connect(socket_path: impl Into<PathBuf>) -> Result<Self, AdapterError> {
        let socket_path = socket_path.into();
        #[cfg(test)]
        let token = test_token_for(&socket_path);
        #[cfg(not(test))]
        let token = None;
        Self::connect_inner(socket_path, token).await
    }

    #[cfg(test)]
    pub(crate) async fn connect_with_token(
        socket_path: impl Into<PathBuf>,
        token: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        Self::connect_inner(socket_path.into(), Some(token.into())).await
    }

    async fn connect_inner(
        socket_path: PathBuf,
        token: Option<String>,
    ) -> Result<Self, AdapterError> {
        let response = send(&socket_path, &IpcCommand::OperatorRulesCapabilities).await?;
        let IpcResponse::OperatorRulesCapabilities { capabilities } = response else {
            return Err(unexpected("operator-rules capabilities"));
        };
        validate_capabilities(&capabilities)?;
        Ok(Self {
            socket_path,
            token,
            capabilities,
        })
    }

    pub(crate) fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub(crate) async fn metadata(&self) -> Result<Metadata, AdapterError> {
        let response = self.send(IpcCommand::CustomListsMetadata).await?;
        let IpcResponse::CustomListsMetadata { metadata } = response else {
            return Err(unexpected("Custom List metadata"));
        };
        validate_contract(metadata.contract_version, "metadata")?;
        if metadata.schema_version != self.capabilities.schema_version {
            return Err(AdapterError::protocol(
                "metadata schema_version changed after capability negotiation",
            ));
        }
        Ok(metadata)
    }

    pub(crate) async fn inventory(&self, page: PageRequest) -> Result<ListPage, AdapterError> {
        self.validate_page(&page)?;
        let response = self
            .send(IpcCommand::CustomListsRead {
                request: CustomListsReadRequest::List { page },
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::CustomListsRead {
            response: CustomListsReadResponse::List(page),
        } = response
        else {
            return Err(unexpected("Custom List inventory"));
        };
        validate_contract(page.contract_version, "inventory")?;
        Ok(page)
    }

    pub(crate) async fn next_inventory(
        &self,
        current: &ListPage,
    ) -> Result<Option<ListPage>, AdapterError> {
        let Some(cursor) = current.next_cursor.clone() else {
            return Ok(None);
        };
        let next = self
            .inventory(PageRequest {
                cursor: Some(cursor),
                limit: Some(self.capabilities.limits.max_page_size),
            })
            .await?;
        if next.config_revision != current.config_revision {
            return Err(AdapterError::protocol(
                "inventory page crossed configuration revisions",
            ));
        }
        Ok(Some(next))
    }

    pub(crate) async fn rules(
        &self,
        id: String,
        page: PageRequest,
    ) -> Result<RulePage, AdapterError> {
        self.validate_page(&page)?;
        let response = self
            .send(IpcCommand::CustomListsRead {
                request: CustomListsReadRequest::Rules {
                    id: id.clone(),
                    page,
                },
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::CustomListsRead {
            response: CustomListsReadResponse::Rules(page),
        } = response
        else {
            return Err(unexpected("Custom List rules"));
        };
        validate_contract(page.contract_version, "rule page")?;
        if page.id != id {
            return Err(AdapterError::protocol(
                "rule page identity does not match the request",
            ));
        }
        Ok(page)
    }

    pub(crate) async fn next_rules(
        &self,
        current: &RulePage,
    ) -> Result<Option<RulePage>, AdapterError> {
        let Some(cursor) = current.next_cursor.clone() else {
            return Ok(None);
        };
        let next = self
            .rules(
                current.id.clone(),
                PageRequest {
                    cursor: Some(cursor),
                    limit: Some(self.capabilities.limits.max_page_size),
                },
            )
            .await?;
        if next.config_revision != current.config_revision
            || next.pack_revision != current.pack_revision
        {
            return Err(AdapterError::protocol(
                "rule page crossed configuration or pack revisions",
            ));
        }
        Ok(Some(next))
    }

    pub(crate) async fn create_plan(
        &self,
        request: BatchRequest,
        page: PageRequest,
    ) -> Result<RetainedPlan, AdapterError> {
        self.validate_request(&request)?;
        self.validate_page(&page)?;
        let response = self
            .send(IpcCommand::OperatorRulesPlan {
                request: Some(request.clone()),
                plan_ref: None,
                page,
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::OperatorRulesPlan {
            plan_ref,
            summary,
            impact,
        } = response
        else {
            return Err(unexpected("operator-rules plan"));
        };
        if summary.base_config_revision != request.expected_config_revision {
            return Err(AdapterError::protocol(
                "plan base revision does not match the requested revision",
            ));
        }
        if summary.operation_count != request.operations.len() {
            return Err(AdapterError::protocol(
                "plan operation count does not match the request",
            ));
        }
        RetainedPlan::from_first_page(plan_ref, request.request_id, summary, impact)
    }

    pub(crate) async fn plan_impact(
        &self,
        plan: &RetainedPlan,
        cursor: String,
    ) -> Result<PlanImpactPage, AdapterError> {
        let page = PageRequest {
            cursor: Some(cursor),
            limit: Some(self.capabilities.limits.max_page_size),
        };
        let response = self
            .send(IpcCommand::OperatorRulesPlan {
                request: None,
                plan_ref: Some(plan.plan_ref.clone()),
                page,
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::OperatorRulesPlan {
            plan_ref,
            summary,
            impact,
        } = response
        else {
            return Err(unexpected("operator-rules plan impact"));
        };
        validate_plan_response(&plan_ref, &summary, &impact)?;
        if plan_ref != plan.plan_ref || summary.plan_hash != plan.summary.plan_hash {
            return Err(AdapterError::protocol(
                "plan impact response changed retained-plan identity",
            ));
        }
        Ok(impact)
    }

    pub(crate) async fn apply(&self, plan: &RetainedPlan) -> Result<Receipt, AdapterError> {
        let response = self
            .send(IpcCommand::OperatorRulesApply {
                plan_ref: plan.plan_ref.clone(),
                plan_hash: plan.summary.plan_hash.clone(),
                request_id: plan.request_id.clone(),
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::OperatorRulesApply { receipt } = response else {
            return Err(unexpected("operator-rules apply"));
        };
        validate_receipt(&receipt, Some(&plan.request_id), None)?;
        Ok(receipt)
    }

    pub(crate) async fn replay(&self, request: BatchRequest) -> Result<Receipt, AdapterError> {
        self.validate_request(&request)?;
        let response = self
            .send(IpcCommand::OperatorRulesReplay {
                request: request.clone(),
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::OperatorRulesApply { receipt } = response else {
            return Err(unexpected("operator-rules replay"));
        };
        validate_receipt(&receipt, Some(&request.request_id), None)?;
        Ok(receipt)
    }

    pub(crate) async fn operation(&self, operation_id: String) -> Result<Receipt, AdapterError> {
        let response = self
            .send(IpcCommand::OperatorRulesOperation {
                operation_id: operation_id.clone(),
                token: self.token.clone(),
            })
            .await?;
        let IpcResponse::OperatorRulesOperation { receipt } = response else {
            return Err(unexpected("operator-rules operation"));
        };
        validate_receipt(&receipt, None, Some(&operation_id))?;
        Ok(receipt)
    }

    async fn send(&self, command: IpcCommand) -> Result<IpcResponse, AdapterError> {
        send(&self.socket_path, &command).await
    }

    fn validate_page(&self, page: &PageRequest) -> Result<(), AdapterError> {
        if page
            .limit
            .is_some_and(|limit| limit == 0 || limit > self.capabilities.limits.max_page_size)
        {
            return Err(AdapterError::transport_limit(format!(
                "page size must be between 1 and {}",
                self.capabilities.limits.max_page_size
            )));
        }
        Ok(())
    }

    fn validate_request(&self, request: &BatchRequest) -> Result<(), AdapterError> {
        validate_contract(request.contract_version, "batch request")?;
        if request.request_id.is_empty()
            || request.request_id.len() > 128
            || request.request_id.chars().any(char::is_control)
        {
            return Err(AdapterError::invalid_request(
                "request_id must contain 1–128 non-control bytes",
            ));
        }
        if request.operations.is_empty() {
            return Err(AdapterError::invalid_request(
                "operator-policy draft has no operations",
            ));
        }
        if request.operations.len() > self.capabilities.limits.max_operations {
            return Err(AdapterError::transport_limit(format!(
                "batch exceeds the negotiated {} operation IPC limit",
                self.capabilities.limits.max_operations
            )));
        }
        for operation in &request.operations {
            let capability = operation_capability(operation);
            if !self
                .capabilities
                .operations
                .iter()
                .any(|available| available == capability)
            {
                return Err(AdapterError::protocol(format!(
                    "daemon does not advertise required operation {capability}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn register_test_token(socket_path: &Path, token: impl Into<String>) {
    TEST_TOKENS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .expect("test token registry poisoned")
        .insert(socket_path.to_owned(), token.into());
}

#[cfg(test)]
fn test_token_for(socket_path: &Path) -> Option<String> {
    // Kept in a function-local singleton so production has no alternate
    // credential path. Each test registers only its unique temporary socket.
    TEST_TOKENS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .expect("test token registry poisoned")
        .get(socket_path)
        .cloned()
}

async fn send(socket_path: &Path, command: &IpcCommand) -> Result<IpcResponse, AdapterError> {
    match crate::ipc::socket_client::send_command(socket_path, command).await {
        Ok(IpcResponse::OperatorRulesError { error }) => Err(AdapterError::remote(error)),
        Ok(response) => Ok(response),
        Err(error) => Err(AdapterError::transport(error)),
    }
}

fn validate_capabilities(capabilities: &Capabilities) -> Result<(), AdapterError> {
    validate_contract(capabilities.contract_version, "capabilities")?;
    if capabilities.schema_version != 5 || capabilities.operator_rule_grammar != 1 {
        return Err(AdapterError::protocol(format!(
            "unsupported operator-policy schema/grammar {}/{}",
            capabilities.schema_version, capabilities.operator_rule_grammar
        )));
    }
    let limits = capabilities.limits;
    if limits.max_operations == 0
        || limits.max_operations > TransportLimits::IPC.max_operations
        || limits.default_page_size == 0
        || limits.default_page_size > limits.max_page_size
        || limits.max_page_size > TransportLimits::IPC.max_page_size
        || limits.max_response_bytes == 0
        || limits.max_response_bytes > OPERATOR_RULES_MAX_BYTES
        || limits.max_export_bytes == 0
        || limits.max_export_bytes > TransportLimits::IPC.max_export_bytes
    {
        return Err(AdapterError::protocol(
            "daemon advertised invalid contract-v1 IPC limits",
        ));
    }
    Ok(())
}

fn validate_contract(version: u32, object: &str) -> Result<(), AdapterError> {
    if version != CONTRACT_VERSION {
        return Err(AdapterError::protocol(format!(
            "{object} uses contract_version {version}; expected {CONTRACT_VERSION}"
        )));
    }
    Ok(())
}

fn validate_plan_response(
    plan_ref: &str,
    summary: &PlanSummary,
    impact: &PlanImpactPage,
) -> Result<(), AdapterError> {
    validate_contract(summary.contract_version, "plan summary")?;
    validate_contract(impact.contract_version, "plan impact")?;
    if plan_ref.is_empty() || summary.plan_hash.is_empty() {
        return Err(AdapterError::protocol(
            "daemon returned an empty retained-plan identity",
        ));
    }
    if impact.plan_hash != summary.plan_hash {
        return Err(AdapterError::protocol(
            "plan summary and impact page have different hashes",
        ));
    }
    Ok(())
}

fn validate_receipt(
    receipt: &Receipt,
    request_id: Option<&str>,
    operation_id: Option<&str>,
) -> Result<(), AdapterError> {
    validate_contract(receipt.contract_version, "receipt")?;
    if receipt.operation_id.is_empty() || receipt.request_id.is_empty() {
        return Err(AdapterError::protocol(
            "daemon returned a receipt without durable identity",
        ));
    }
    if request_id.is_some_and(|expected| receipt.request_id != expected) {
        return Err(AdapterError::protocol(
            "receipt request identity does not match the submitted draft",
        ));
    }
    if operation_id.is_some_and(|expected| receipt.operation_id != expected) {
        return Err(AdapterError::protocol(
            "receipt operation identity does not match the lookup",
        ));
    }
    Ok(())
}

fn operation_capability(operation: &Operation) -> &'static str {
    match operation {
        Operation::CreateList { .. } => "create_list",
        Operation::SetMetadata { .. } => "set_metadata",
        Operation::AddDomainRule { .. } => "add_domain_rule",
        Operation::AddRawRule { .. } => "add_raw_rule",
        Operation::ReplaceRule { .. } => "replace_rule",
        Operation::RemoveRule { .. } => "remove_rule",
        Operation::Mount { .. } => "mount",
        Operation::Unmount { .. } => "unmount",
        Operation::DeleteList { .. } => "delete_list",
    }
}

fn unexpected(expected: &str) -> AdapterError {
    AdapterError::protocol(format!("unexpected daemon response for {expected}"))
}
