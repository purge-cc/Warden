//! Nodes presentation state, guarded forms, and recoverable controller actions.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use ratatui::widgets::TableState;

use crate::cluster::lifecycle::{LifecycleStatus, NodeRole};
use crate::cluster::membership::SecretString;
use crate::cluster::node_control::{
    NodeControlCommand, NodeControlReply, NodeControlStatus, NodeOperationKind, NodeOperationPhase,
    NodeOperationProgress, NodePreview,
};
use crate::config::schema::node::validate_node_name;

use super::{actions, App, IpcPoller, Leaf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum NodeSort {
    #[default]
    Name,
    Address,
    Role,
    Status,
}

impl NodeSort {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Name => Self::Address,
            Self::Address => Self::Role,
            Self::Role => Self::Status,
            Self::Status => Self::Name,
        }
    }

    pub(crate) fn from_column(column: usize) -> Option<Self> {
        match column {
            0 => Some(Self::Name),
            1 => Some(Self::Address),
            2 => Some(Self::Role),
            3 => Some(Self::Status),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeFormKind {
    Add,
    Edit,
}

#[derive(Clone)]
pub(crate) struct NodeDraft {
    pub(crate) kind: NodeFormKind,
    pub(crate) node_id: Option<String>,
    pub(crate) name: String,
    pub(crate) address: String,
    pub(crate) token: String,
    pub(crate) port: String,
    original_endpoint: Option<SocketAddr>,
    pub(crate) advanced: bool,
    pub(crate) focus: usize,
    pub(crate) error: Option<String>,
}

impl NodeDraft {
    fn add(name: String) -> Self {
        Self {
            kind: NodeFormKind::Add,
            node_id: None,
            name,
            address: String::new(),
            token: String::new(),
            port: "8053".into(),
            original_endpoint: None,
            advanced: false,
            focus: 0,
            error: None,
        }
    }

    fn edit(node_id: String, name: String, endpoint: Option<SocketAddr>) -> Self {
        Self {
            kind: NodeFormKind::Edit,
            node_id: Some(node_id),
            name,
            address: endpoint
                .map(|endpoint| endpoint.ip().to_string())
                .unwrap_or_default(),
            token: String::new(),
            port: endpoint
                .map(|endpoint| endpoint.port().to_string())
                .unwrap_or_else(|| "8053".into()),
            original_endpoint: endpoint,
            advanced: endpoint.is_some(),
            focus: 0,
            error: None,
        }
    }

    pub(crate) fn visible_fields(&self) -> usize {
        match self.kind {
            NodeFormKind::Add => 3 + usize::from(self.advanced),
            NodeFormKind::Edit => 2 + usize::from(self.advanced),
        }
    }

    pub(crate) fn field_label(&self, index: usize) -> &'static str {
        match (self.kind, index) {
            (_, 0) => "Name",
            (_, 1) => "IP address",
            (NodeFormKind::Add, 2) => "Token",
            _ => "HTTPS port",
        }
    }

    pub(crate) fn field_value(&self, index: usize) -> &str {
        match (self.kind, index) {
            (_, 0) => &self.name,
            (_, 1) => &self.address,
            (NodeFormKind::Add, 2) => &self.token,
            _ => &self.port,
        }
    }

    pub(crate) fn field_value_mut(&mut self, index: usize) -> &mut String {
        match (self.kind, index) {
            (_, 0) => &mut self.name,
            (_, 1) => &mut self.address,
            (NodeFormKind::Add, 2) => &mut self.token,
            _ => &mut self.port,
        }
    }

    pub(crate) fn request(&self) -> Result<NodeControlCommand, String> {
        validate_node_name(&self.name)?;
        match self.kind {
            NodeFormKind::Add => {
                let endpoint = endpoint(&self.address, &self.port)?;
                if self.token.trim().is_empty() {
                    return Err("Association token is required".into());
                }
                Ok(NodeControlCommand::PreviewAdd {
                    name: self.name.clone(),
                    endpoint,
                    token: SecretString(self.token.clone()),
                })
            }
            NodeFormKind::Edit => {
                let endpoint = if self.address.trim().is_empty() {
                    None
                } else {
                    let endpoint = endpoint(&self.address, &self.port)?;
                    (Some(endpoint) != self.original_endpoint).then_some(endpoint)
                };
                Ok(NodeControlCommand::PreviewEdit {
                    node_id: self.node_id.clone().unwrap_or_default(),
                    name: self.name.clone(),
                    endpoint,
                })
            }
        }
    }
}

fn endpoint(address: &str, port: &str) -> Result<SocketAddr, String> {
    let ip = address
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| "IP address is required; use a literal IPv4 or IPv6 address".to_owned())?;
    let port = port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "HTTPS port must be between 1 and 65535".to_owned())?;
    Ok(SocketAddr::new(ip, port))
}

#[derive(Clone)]
pub(crate) enum NodesDialog {
    Form(NodeDraft),
    Review {
        preview: NodePreview,
        error: Option<String>,
    },
    Applying {
        operation_id: String,
        kind: NodeOperationKind,
        error: Option<String>,
    },
    Recovery {
        progress: NodeOperationProgress,
        error: Option<String>,
    },
    Outcome {
        message: String,
    },
}

#[derive(Clone, Default)]
pub(crate) struct NodesState {
    pub(crate) last_observation: Option<LifecycleStatus>,
    pub(crate) last_control_observation: Option<NodeControlStatus>,
    pub(crate) last_observed_at: Option<Instant>,
    pub(crate) last_poll_error: Option<String>,
    pub(crate) selected_id: Option<String>,
    pub(crate) table_state: TableState,
    pub(crate) search: String,
    pub(crate) sort: NodeSort,
    pub(crate) descending: bool,
    pub(crate) dialog: Option<NodesDialog>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyAccess {
    pub(crate) editable: bool,
    pub(crate) reason: &'static str,
    pub(crate) primary: Option<String>,
}

pub(crate) fn policy_access(app: &App) -> PolicyAccess {
    let status = app
        .nodes_status
        .as_ref()
        .or(app.nodes.last_observation.as_ref());
    let primary = status.and_then(|status| {
        status
            .primary_name
            .clone()
            .or_else(|| status.primary_address.clone())
    });
    let Some(status) = status else {
        return PolicyAccess {
            editable: false,
            reason: "node role unavailable",
            primary,
        };
    };
    if status.pending_join
        || status.saved_role == NodeRole::Secondary
        || status.active_role == Some(NodeRole::Secondary)
    {
        return PolicyAccess {
            editable: false,
            reason: if status.pending_join {
                "join pending restart"
            } else {
                "policy is replicated from the primary"
            },
            primary,
        };
    }
    if app.nodes_status.is_none() {
        return PolicyAccess {
            editable: false,
            reason: "node role status is stale",
            primary,
        };
    }
    let editable = status.can_edit_policy
        && matches!(
            status.active_role,
            Some(NodeRole::Standalone | NodeRole::Primary)
        );
    PolicyAccess {
        editable,
        reason: if editable {
            "local policy authority"
        } else {
            "active node role is unavailable"
        },
        primary,
    }
}

pub(crate) fn is_replicated_leaf(leaf: Leaf) -> bool {
    matches!(
        leaf,
        Leaf::Dashboard
            | Leaf::QueryLog
            | Leaf::Devices
            | Leaf::Subnets
            | Leaf::Groups
            | Leaf::LocalDns
            | Leaf::Profiles
            | Leaf::Lists
            | Leaf::CustomLists
            | Leaf::Rules
            | Leaf::Labels
            | Leaf::File
    )
}

pub(crate) fn mutation_key(leaf: Leaf, key: crossterm::event::KeyCode) -> bool {
    use crossterm::event::KeyCode;
    match leaf {
        Leaf::QueryLog => matches!(key, KeyCode::Enter),
        Leaf::Devices => matches!(key, KeyCode::Enter | KeyCode::Char('a' | 'e' | 'd')),
        Leaf::Subnets | Leaf::Profiles | Leaf::Groups | Leaf::Labels => matches!(
            key,
            KeyCode::Enter | KeyCode::Delete | KeyCode::Char('a' | 'e' | 'd')
        ),
        Leaf::LocalDns => matches!(
            key,
            KeyCode::Enter | KeyCode::Delete | KeyCode::Char('a' | 'e' | 'd')
        ),
        Leaf::Lists => matches!(
            key,
            KeyCode::Enter | KeyCode::Delete | KeyCode::Char('a' | 'e' | 'd' | 'm' | 'K' | 'B')
        ),
        Leaf::CustomLists => matches!(
            key,
            KeyCode::Enter | KeyCode::Delete | KeyCode::Char('a' | 'e' | 'd' | 'm')
        ),
        Leaf::Rules => matches!(
            key,
            KeyCode::Enter | KeyCode::Delete | KeyCode::Char('a' | 'd')
        ),
        Leaf::File => matches!(key, KeyCode::Char('e')),
        Leaf::Settings => matches!(key, KeyCode::Char('R')),
        Leaf::Dashboard | Leaf::Logs | Leaf::Nodes => false,
    }
}

pub(crate) fn policy_banner(app: &App) -> Option<String> {
    if !is_replicated_leaf(app.active_leaf) {
        return None;
    }
    let access = policy_access(app);
    (!access.editable).then(|| policy_refusal_message(&access))
}

fn policy_refusal_message(access: &PolicyAccess) -> String {
    match access.primary.as_ref() {
        Some(primary) => format!("READ-ONLY POLICY · edit on {primary} · {}", access.reason),
        None => format!("READ-ONLY POLICY · {}", access.reason),
    }
}

pub(crate) fn block_policy_mutation(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    use crossterm::event::{KeyCode, KeyModifiers};
    let reload = app.active_leaf == Leaf::Settings
        && key.code == KeyCode::Char('r')
        && key.modifiers.contains(KeyModifiers::CONTROL);
    if policy_access(app).editable || (!reload && !mutation_key(app.active_leaf, key.code)) {
        return false;
    }
    app.status_err(policy_refusal_message(&policy_access(app)));
    true
}

pub(crate) fn close_replicated_editor_if_locked(app: &mut App) -> bool {
    if policy_access(app).editable {
        return false;
    }
    let closed_policy = app.operator_policy.take().is_some();
    let closed_leaf = match app.active_leaf {
        Leaf::QueryLog => app.query_log_rule_modal.take().is_some(),
        Leaf::Devices => app.devices.modal.take().is_some(),
        Leaf::Subnets => app.subnets.modal.take().is_some(),
        Leaf::Groups => app.groups.modal.take().is_some(),
        Leaf::LocalDns => app.local_dns.modal.take().is_some(),
        Leaf::Profiles => app.profiles.modal.take().is_some(),
        Leaf::Lists => {
            app.lists.import_source.take().is_some()
                | app.lists.catalog_picker.take().is_some()
                | app.lists.kind_confirm.take().is_some()
                | app.lists.edit_modal.take().is_some()
        }
        Leaf::CustomLists => {
            app.custom_lists.modal.take().is_some() | app.custom_lists.mount_picker.take().is_some()
        }
        Leaf::Rules => app.rules.edit_modal.take().is_some() | app.rules.add_modal.take().is_some(),
        Leaf::Labels => app.labels.modal.take().is_some(),
        Leaf::Settings => app.settings.restore_modal.take().is_some(),
        Leaf::Dashboard | Leaf::File | Leaf::Logs | Leaf::Nodes => false,
    };
    let closed = closed_policy | closed_leaf;
    if closed {
        app.status_err(policy_banner(app).unwrap_or_else(|| "Policy is read-only".into()));
    }
    closed
}

pub(crate) fn status_for_display(app: &App) -> Option<&LifecycleStatus> {
    app.nodes_status
        .as_ref()
        .or(app.nodes.last_observation.as_ref())
}
pub(crate) fn control_status_for_display(app: &App) -> Option<&NodeControlStatus> {
    app.node_control_status
        .as_ref()
        .or(app.nodes.last_control_observation.as_ref())
}

pub(crate) fn is_legacy_detached_add_recovery(progress: &NodeOperationProgress) -> bool {
    progress.kind == NodeOperationKind::Add
        && progress.phase == NodeOperationPhase::Cancelled
        && progress.message == "Review expired; temporary association authorization was revoked."
}

pub(crate) fn is_cancelled_add_cleanup_pending(
    status: &NodeControlStatus,
    progress: &NodeOperationProgress,
) -> bool {
    progress.kind == NodeOperationKind::Add
        && progress.phase == NodeOperationPhase::Cancelled
        && status.peers.iter().any(|peer| {
            peer.node_id == progress.target_node_id
                && peer.state == crate::cluster::node_control::NodePeerState::Pending
        })
        && !status.operations.iter().any(|candidate| {
            candidate.operation_id != progress.operation_id
                && candidate.kind == NodeOperationKind::Add
                && !is_terminal(candidate.phase)
                && candidate.target_node_id == progress.target_node_id
        })
}

pub(crate) fn controls_available(app: &App) -> bool {
    let (Some(legacy), Some(control)) =
        (app.nodes_status.as_ref(), app.node_control_status.as_ref())
    else {
        return false;
    };
    !legacy.pending_join
        && !control.membership.pending_join
        && !legacy.restart_required
        && !control.membership.restart_required
        && legacy.node_id == control.membership.node_id
        && legacy.active_role == control.membership.active_role
        && legacy.saved_role == control.membership.saved_role
        && legacy.active_role.is_some()
        && legacy.active_role == Some(legacy.saved_role)
}

pub(crate) fn can_add_node(app: &App) -> bool {
    controls_available(app)
        && matches!(
            app.nodes_status
                .as_ref()
                .and_then(|status| status.active_role),
            Some(NodeRole::Standalone | NodeRole::Primary)
        )
}

pub(crate) fn can_remove_node(app: &App) -> bool {
    controls_available(app)
        && app
            .nodes_status
            .as_ref()
            .and_then(|status| status.active_role)
            == Some(NodeRole::Primary)
}

pub(crate) fn open_add(app: &mut App) {
    if !can_add_node(app) {
        app.status_err("Nodes authority is unavailable; refresh before editing nodes".into());
        return;
    }
    app.nodes.dialog = Some(NodesDialog::Form(NodeDraft::add(String::new())));
}

pub(crate) fn open_edit(
    app: &mut App,
    node_id: String,
    name: String,
    endpoint: Option<SocketAddr>,
) {
    if !controls_available(app) {
        app.status_err("Nodes authority is unavailable; refresh before editing nodes".into());
        return;
    }
    if !can_add_node(app) {
        app.status_err("Edit node connections and names on the primary".into());
        return;
    }
    if !super::tabs::nodes::build_rows(app)
        .iter()
        .any(|row| row.id == node_id && row.management_available)
    {
        app.status_err("Upgrade this peer before using guided node management".into());
        return;
    }
    app.nodes.dialog = Some(NodesDialog::Form(NodeDraft::edit(node_id, name, endpoint)));
}

pub(crate) async fn preview_remove(app: &mut App, node_id: String, poller: &IpcPoller) {
    if !can_remove_node(app) {
        app.status_err("Nodes authority is unavailable; refresh before removing nodes".into());
        return;
    }
    if app
        .nodes_status
        .as_ref()
        .and_then(|status| status.node_id.as_ref())
        == Some(&node_id)
    {
        app.status_err("This node cannot be removed".into());
        return;
    }
    if !super::tabs::nodes::build_rows(app)
        .iter()
        .any(|row| row.id == node_id && row.management_available)
    {
        app.status_err("Upgrade this peer before using guided node management".into());
        return;
    }
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        actions::Surface::Nodes,
        "Preparing Nodes review",
        async move {
            IpcPoller::new(&socket)
                .node_control(NodeControlCommand::PreviewRemove { node_id })
                .await
                .map_err(|error| error.to_string())
        },
        |app, attached, result: Result<NodeControlReply, String>| match result {
            Ok(reply) => {
                app.node_control_status = Some(reply.status);
                match reply.preview {
                    Some(preview) if attached => {
                        app.nodes.dialog = Some(NodesDialog::Review {
                            preview,
                            error: None,
                        })
                    }
                    Some(_) => {
                        app.status_info("Nodes review is ready; reopen Nodes to continue".into())
                    }
                    None => app.status_err(reply.message),
                }
            }
            Err(error) => app.status_err(error),
        },
    )
    .await;
}

pub(crate) fn open_recovery(app: &mut App) {
    let Some(progress) = control_status_for_display(app)
        .and_then(|status| {
            let selected = app.nodes.selected_id.as_deref();
            status
                .operations
                .iter()
                .find(|progress| {
                    selected == Some(progress.target_node_id.as_str())
                        && !is_terminal(progress.phase)
                })
                .or_else(|| {
                    status
                        .operations
                        .iter()
                        .find(|progress| !is_terminal(progress.phase))
                })
                .or_else(|| {
                    status
                        .operations
                        .iter()
                        .find(|progress| is_cancelled_add_cleanup_pending(status, progress))
                })
                .or_else(|| {
                    status.operations.iter().find(|progress| {
                        selected == Some(progress.target_node_id.as_str())
                            && is_legacy_detached_add_recovery(progress)
                    })
                })
                .or_else(|| {
                    status
                        .operations
                        .iter()
                        .find(|progress| is_legacy_detached_add_recovery(progress))
                })
        })
        .cloned()
    else {
        app.status_info("No recoverable Nodes operation is reported by the daemon".into());
        return;
    };
    app.nodes.dialog = Some(NodesDialog::Recovery {
        progress,
        error: None,
    });
}

fn is_terminal(phase: NodeOperationPhase) -> bool {
    matches!(
        phase,
        NodeOperationPhase::Complete | NodeOperationPhase::Cancelled
    )
}

pub(crate) async fn submit_preview(app: &mut App, poller: &IpcPoller) {
    let request = match app.nodes.dialog.as_ref() {
        Some(NodesDialog::Form(draft)) => match draft.request() {
            Ok(request) => request,
            Err(error) => {
                if let Some(NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() {
                    draft.error = Some(error);
                }
                return;
            }
        },
        _ => return,
    };
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        actions::Surface::Nodes,
        "Preparing Nodes review",
        async move {
            let poller = IpcPoller::new(&socket);
            match poller.node_control(request).await {
                Ok(reply) => (Ok(reply), None),
                Err(error) => (
                    Err(error.to_string()),
                    poller.fetch_node_control_status().await.ok(),
                ),
            }
        },
        |app, attached, (result, refreshed): (Result<NodeControlReply, String>, Option<NodeControlStatus>)| {
            if let Some(status) = refreshed {
                app.node_control_status = Some(status);
                app.nodes.last_control_observation = None;
                app.nodes.last_poll_error = None;
            }
            match result {
            Ok(reply) => {
                app.node_control_status = Some(reply.status);
                app.nodes.last_control_observation = None;
                app.nodes.last_poll_error = None;
                match reply.preview {
                    Some(preview) if attached => {
                        app.nodes.dialog = Some(NodesDialog::Review {
                            preview,
                            error: None,
                        })
                    }
                    Some(_) => {
                        app.status_info("Nodes review is ready; reopen Nodes to continue".into())
                    }
                    None if attached => set_preview_error(app, reply.message),
                    None => app.status_err(reply.message),
                }
            }
            Err(error) if attached => set_preview_error(app, error),
            Err(error) => app.status_err(error),
            }
        },
    )
    .await;
}

fn set_preview_error(app: &mut App, error: String) {
    match app.nodes.dialog.as_mut() {
        Some(NodesDialog::Form(draft)) => draft.error = Some(error),
        Some(NodesDialog::Review { error: slot, .. }) => *slot = Some(error),
        _ => app.status_err(error),
    }
}

pub(crate) async fn submit_apply(app: &mut App, poller: &IpcPoller) {
    let Some(NodesDialog::Review { preview, .. }) = app.nodes.dialog.as_ref() else {
        return;
    };
    let operation_id = preview.id.clone();
    let kind = preview.kind;
    let socket = poller.socket_path().to_owned();
    app.nodes.dialog = Some(NodesDialog::Applying {
        operation_id: operation_id.clone(),
        kind,
        error: None,
    });
    dispatch_operation(
        app,
        &socket,
        "Applying Nodes operation",
        NodeControlCommand::Apply {
            preview_id: operation_id,
        },
    )
    .await;
}
pub(crate) async fn submit_cancel(app: &mut App, poller: &IpcPoller) {
    let preview_id = match app.nodes.dialog.as_ref() {
        Some(NodesDialog::Review { preview, .. }) => preview.id.clone(),
        Some(NodesDialog::Recovery { progress, .. }) => progress.operation_id.clone(),
        _ => return,
    };
    let socket = poller.socket_path().to_owned();
    dispatch_operation(
        app,
        &socket,
        "Cancelling Nodes operation",
        NodeControlCommand::Cancel { preview_id },
    )
    .await;
}
pub(crate) async fn submit_resume(app: &mut App, poller: &IpcPoller) {
    let Some(NodesDialog::Recovery { progress, .. }) = app.nodes.dialog.as_ref() else {
        return;
    };
    let operation_id = progress.operation_id.clone();
    let socket = poller.socket_path().to_owned();
    dispatch_operation(
        app,
        &socket,
        "Resuming Nodes operation",
        NodeControlCommand::Resume { operation_id },
    )
    .await;
}
async fn dispatch_operation(
    app: &mut App,
    socket: &std::path::Path,
    label: &'static str,
    request: NodeControlCommand,
) {
    let expected_operation_id = match &request {
        NodeControlCommand::Apply { preview_id } | NodeControlCommand::Cancel { preview_id } => {
            Some(preview_id.clone())
        }
        NodeControlCommand::Resume { operation_id } => Some(operation_id.clone()),
        _ => None,
    };
    let socket = socket.to_owned();
    actions::dispatch(
        app,
        actions::Surface::Nodes,
        label,
        async move {
            IpcPoller::new(&socket)
                .node_control(request)
                .await
                .map_err(|e| e.to_string())
        },
        move |app, attached, result: Result<NodeControlReply, String>| match result {
            Ok(reply) => {
                let progress = reply
                    .status
                    .operations
                    .iter()
                    .find(|progress| {
                        (!is_terminal(progress.phase)
                            || is_cancelled_add_cleanup_pending(&reply.status, progress))
                            && expected_operation_id.as_deref()
                                == Some(progress.operation_id.as_str())
                    })
                    .cloned();
                app.node_control_status = Some(reply.status);
                if !attached {
                    app.status_info(reply.message);
                } else if let Some(preview) = reply.preview {
                    app.nodes.dialog = Some(NodesDialog::Review {
                        preview,
                        error: None,
                    });
                } else if let Some(progress) = progress {
                    app.nodes.dialog = Some(NodesDialog::Recovery {
                        progress,
                        error: None,
                    });
                } else {
                    app.nodes.dialog = Some(NodesDialog::Outcome {
                        message: reply.message,
                    });
                }
            }
            Err(error) if attached => match app.nodes.dialog.as_mut() {
                Some(NodesDialog::Applying { error: slot, .. }) => *slot = Some(error),
                Some(NodesDialog::Recovery { error: slot, .. }) => *slot = Some(error),
                _ => app.status_err(error),
            },
            Err(error) => app.status_err(error),
        },
    )
    .await;
}

pub(crate) fn role_label(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Standalone => "standalone",
        NodeRole::Primary => "primary",
        NodeRole::Secondary => "secondary",
    }
}
pub(crate) fn operation_label(kind: NodeOperationKind) -> &'static str {
    match kind {
        NodeOperationKind::Add => "Add node",
        NodeOperationKind::Edit => "Edit node",
        NodeOperationKind::Remove => "Remove node",
    }
}
