//! Nodes master/detail surface backed by the managed HTTPS controller.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::cluster::lifecycle::NodeRole;
use crate::cluster::node_control::NodePeerState;
use crate::tui::app::{App, InputMode, Leaf};
use crate::tui::mouse::{self, MouseAction};
use crate::tui::nodes::{
    can_add_node, can_remove_node, control_status_for_display, is_cancelled_add_cleanup_pending,
    is_legacy_detached_add_recovery, role_label, status_for_display, NodeSort,
};
use crate::tui::theme::CardRole;
use crate::tui::theme::{self, T};

const HEADERS: [&str; 4] = ["NAME", "ADDRESS", "ROLE", "STATUS"];

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NodeRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) is_self: bool,
    pub(crate) role: Option<NodeRole>,
    pub(crate) endpoint: Option<std::net::SocketAddr>,
    pub(crate) status: String,
    pub(crate) last_error: Option<String>,
    pub(crate) management_available: bool,
}

pub(crate) fn build_rows(app: &App) -> Vec<NodeRow> {
    let control = control_status_for_display(app);
    let membership = control
        .map(|status| &status.membership)
        .or_else(|| status_for_display(app));
    let local_id = membership
        .and_then(|membership| membership.node_id.clone())
        .or_else(|| {
            app.loaded_config
                .as_ref()
                .and_then(|loaded| loaded.config.node.id.clone())
        })
        .unwrap_or_else(|| "unassigned".into());
    let local_name = membership
        .map(|membership| membership.node_name.as_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            app.loaded_config
                .as_ref()
                .map(|loaded| loaded.config.node.display_name().to_owned())
        })
        .unwrap_or_else(|| "Warden".into());
    let local = NodeRow {
        id: local_id,
        name: local_name,
        is_self: true,
        role: membership.and_then(|membership| membership.active_role),
        endpoint: control
            .and_then(|status| status.control_endpoint)
            .or_else(|| {
                app.loaded_config
                    .as_ref()
                    .and_then(|loaded| loaded.config.node.control_listen)
            }),
        status: if control.is_some() {
            "this node"
        } else {
            "authority unavailable"
        }
        .into(),
        last_error: membership.and_then(|membership| membership.last_error.clone()),
        management_available: true,
    };
    let mut peers = control
        .into_iter()
        .flat_map(|status| {
            status.peers.iter().filter_map(|peer| {
                let cancellation_cleanup_pending = status.operations.iter().any(|operation| {
                    operation.target_node_id == peer.node_id
                        && is_cancelled_add_cleanup_pending(status, operation)
                });
                let unresolved_add = cancellation_cleanup_pending
                    || status.operations.iter().any(|operation| {
                        (operation.kind == crate::cluster::node_control::NodeOperationKind::Add
                            && operation.target_node_id == peer.node_id
                            && operation.phase
                                == crate::cluster::node_control::NodeOperationPhase::PreparingTarget)
                            || (operation.target_node_id == peer.node_id
                                && is_legacy_detached_add_recovery(operation))
                    });
                (peer.state != NodePeerState::Detached || unresolved_add)
                    .then_some((peer, unresolved_add, cancellation_cleanup_pending))
            })
        })
        .map(|(peer, unresolved_add, cancellation_cleanup_pending)| NodeRow {
            id: peer.node_id.clone(),
            name: peer.name.clone(),
            is_self: false,
            role: Some(peer.role),
            endpoint: Some(peer.endpoint),
            status: if cancellation_cleanup_pending {
                "recovery: cleanup".into()
            } else if unresolved_add && peer.state == NodePeerState::Detached {
                "recovery: detached".into()
            } else {
                peer_state_label(peer.state).into()
            },
            last_error: peer.last_error.clone(),
            management_available: peer.capabilities.supports_v2_management(),
        })
        .collect::<Vec<_>>();
    if let Some(membership) = membership {
        for member in &membership.roster {
            if member.state == crate::cluster::membership::MemberState::Revoked
                || member.node_id == local.id
                || peers.iter().any(|peer| peer.id == member.node_id)
            {
                continue;
            }
            peers.push(NodeRow {
                id: member.node_id.clone(),
                name: member.name.clone(),
                is_self: false,
                role: Some(NodeRole::Secondary),
                endpoint: member.endpoint.as_deref().and_then(|endpoint| {
                    endpoint
                        .trim_start_matches("https://")
                        .trim_end_matches('/')
                        .parse()
                        .ok()
                }),
                status: match member.state {
                    crate::cluster::membership::MemberState::Pending => "pending",
                    crate::cluster::membership::MemberState::Active => "active",
                    crate::cluster::membership::MemberState::Revoked => "standalone",
                }
                .into(),
                last_error: None,
                management_available: false,
            });
        }
    }
    let needle = app.nodes.search.trim().to_ascii_lowercase();
    if !needle.is_empty() {
        peers.retain(|row| {
            let endpoint = address(row.endpoint);
            [
                row.id.as_str(),
                row.name.as_str(),
                endpoint.as_str(),
                row.role.map(role_label).unwrap_or("unknown"),
                row.status.as_str(),
            ]
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(&needle))
        });
    }
    peers.sort_by(|a, b| {
        let order = match app.nodes.sort {
            NodeSort::Name => a
                .name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase()),
            NodeSort::Address => address(a.endpoint).cmp(&address(b.endpoint)),
            NodeSort::Role => a
                .role
                .map(role_label)
                .unwrap_or("unknown")
                .cmp(b.role.map(role_label).unwrap_or("unknown")),
            NodeSort::Status => a.status.cmp(&b.status),
        };
        (if app.nodes.descending {
            order.reverse()
        } else {
            order
        })
        .then_with(|| a.id.cmp(&b.id))
    });
    let mut rows = vec![local];
    rows.extend(peers);
    rows
}

pub(crate) fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let columns = crate::tui::detail_panel::columns(area);
    let editing = matches!(
        app.nodes.dialog.as_ref(),
        Some(crate::tui::nodes::NodesDialog::Form(_))
    );
    let rows = build_rows(app);
    if app
        .nodes
        .selected_id
        .as_deref()
        .is_none_or(|id| !rows.iter().any(|row| row.id == id))
    {
        app.nodes.selected_id = rows.first().map(|row| row.id.clone());
    }
    let detail_key = app
        .nodes
        .selected_id
        .as_deref()
        .filter(|id| rows.iter().any(|row| &row.id == id))
        .or_else(|| rows.first().map(|row| row.id.as_str()))
        .unwrap_or_default();
    crate::tui::detail_panel::prepare(app, Leaf::Nodes, detail_key);
    if editing && columns.is_none() {
        if let Some(crate::tui::nodes::NodesDialog::Form(draft)) = &app.nodes.dialog {
            crate::tui::node_modal::render_inline_editor(f, area, draft);
        }
        return;
    }
    if columns.is_none() {
        if crate::tui::detail_panel::focused(app, Leaf::Nodes) {
            render_detail(f, area, app, &rows);
        } else {
            let subtitle = list_subtitle(app, &rows);
            let body = theme::filled_card(
                f.buffer_mut(),
                area,
                "Nodes",
                &subtitle,
                CardRole::Analytics,
            );
            render_table(f, body, app, &rows);
        }
        crate::tui::node_modal::render(f, area, app);
        return;
    }
    if !editing || columns.is_some() {
        let list = columns.map_or(area, |columns| columns[0]);
        let subtitle = list_subtitle(app, &rows);
        let body = theme::filled_card(
            f.buffer_mut(),
            list,
            "Nodes",
            &subtitle,
            CardRole::Analytics,
        );
        render_table(f, body, app, &rows);
    }
    if editing {
        if let Some(crate::tui::nodes::NodesDialog::Form(draft)) = &app.nodes.dialog {
            crate::tui::node_modal::render_inline_editor(
                f,
                columns.map_or(area, |columns| columns[1]),
                draft,
            );
        }
    } else {
        if let Some(columns) = columns {
            render_detail(f, columns[1], app, &rows);
        }
        crate::tui::node_modal::render(f, area, app);
    }
}

fn list_subtitle(app: &App, rows: &[NodeRow]) -> String {
    let mut text = if control_status_for_display(app).is_some() {
        let noun = if rows.len() == 1 { "node" } else { "nodes" };
        format!("{} {noun} · Nodes HTTPS", rows.len())
    } else {
        "Waiting for authoritative Nodes status".into()
    };
    if let InputMode::FilterNodes(search) = &app.input_mode {
        text.push_str(&format!(" · search> {search}"));
    } else if !app.nodes.search.is_empty() {
        text.push_str(&format!(" · search: {}", app.nodes.search));
    }
    if let Some(error) = &app.nodes.last_poll_error {
        text.push_str(&format!(" · {error}"));
    }
    text
}

fn render_table(f: &mut Frame, area: Rect, app: &mut App, rows: &[NodeRow]) {
    let constraints = [
        Constraint::Min(11),
        Constraint::Min(15),
        Constraint::Length(10),
        Constraint::Length(12),
    ];
    let columns = crate::tui::ui::table_column_rects(area, &constraints, 1, 0);
    let active = match app.nodes.sort {
        NodeSort::Name => 0,
        NodeSort::Address => 1,
        NodeSort::Role => 2,
        NodeSort::Status => 3,
    };
    let header = Row::new(HEADERS.iter().enumerate().map(|(column, label)| {
        let title = if column == active {
            format!("{label} {}", if app.nodes.descending { "↓" } else { "↑" })
        } else {
            (*label).into()
        };
        Cell::from(title).style(theme::table_heading_style(column == active))
    }))
    .style(theme::table_heading_style(false));
    let table_rows = rows.iter().map(|row| {
        Row::new(vec![
            Cell::from(row.name.clone()),
            Cell::from(address(row.endpoint)),
            Cell::from(row.role.map(role_label).unwrap_or("unknown")),
            Cell::from(Span::styled(row.status.clone(), status_style(row))),
        ])
    });
    let selected = app
        .nodes
        .selected_id
        .as_ref()
        .and_then(|id| rows.iter().position(|row| &row.id == id))
        .or_else(|| (!rows.is_empty()).then_some(0));
    if let Some(index) = selected {
        app.nodes.selected_id = Some(rows[index].id.clone());
    }
    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(theme::highlight_style());
    super::render_table(f, area, table, &mut app.nodes.table_state, selected);
    for (column, rect) in columns.iter().enumerate() {
        mouse::register(app, *rect, MouseAction::Sort(Leaf::Nodes, column));
    }
    let visible = area.height.saturating_sub(1) as usize;
    let offset = app.nodes.table_state.offset();
    for (visible_index, row_index) in (offset..rows.len()).take(visible).enumerate() {
        mouse::register(
            app,
            Rect::new(area.x, area.y + 1 + visible_index as u16, area.width, 1),
            MouseAction::Row(Leaf::Nodes, row_index),
        );
    }
}

fn render_detail(f: &mut Frame, area: Rect, app: &App, rows: &[NodeRow]) {
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "Node details",
        "Connection and policy state",
        CardRole::History,
    );
    let Some(row) = app
        .nodes
        .selected_id
        .as_ref()
        .and_then(|id| rows.iter().find(|row| &row.id == id))
    else {
        f.render_widget(Paragraph::new(" No matching nodes"), content);
        return;
    };
    let details = detail_lines(app, row, content.width);
    let detail = Rect::new(
        content.x,
        content.y,
        content.width,
        content.height.saturating_sub(2),
    );
    crate::tui::detail_panel::render(f, detail, app, Leaf::Nodes, &row.id, details);
    if content.height > 2 {
        if can_add_node(app) && row.management_available {
            let edit = Rect::new(
                content.right().saturating_sub(6),
                content.bottom() - 1,
                6,
                1,
            );
            f.render_widget(
                Paragraph::new(" Edit ").style(theme::highlight_style()),
                edit,
            );
            mouse::register(
                app,
                edit,
                MouseAction::Key(crossterm::event::KeyCode::Char('e')),
            );
            if !row.is_self && can_remove_node(app) {
                let remove = Rect::new(edit.x.saturating_sub(8), edit.y, 8, 1);
                f.render_widget(
                    Paragraph::new(" Remove ").style(theme::highlight_style()),
                    remove,
                );
                mouse::register(
                    app,
                    remove,
                    MouseAction::Key(crossterm::event::KeyCode::Char('d')),
                );
            }
        } else {
            let label = if !row.management_available {
                " Peer upgrade required "
            } else if crate::tui::nodes::controls_available(app) {
                " Edit on primary "
            } else {
                " Authority unavailable "
            };
            let action = Rect::new(
                content.right().saturating_sub(label.len() as u16),
                content.bottom() - 1,
                label.len() as u16,
                1,
            );
            f.render_widget(
                Paragraph::new(label).style(Style::default().fg(T.text_muted)),
                action,
            );
        }
    }
}

fn detail_lines(app: &App, row: &NodeRow, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![
        crate::tui::modal_form::section_rule("Identity", width, CardRole::Summary),
        kv("Name", row.name.clone()),
        kv("Role", row.role.map(role_label).unwrap_or("unknown")),
        kv(
            "Membership",
            if row.is_self {
                "This node · cannot be removed"
            } else {
                "Managed peer"
            },
        ),
        Line::default(),
        crate::tui::modal_form::section_rule("Connection", width, CardRole::History),
        kv("Nodes HTTPS", address(row.endpoint)),
        kv("Status", row.status.clone()),
    ];
    if let Some(error) = &row.last_error {
        lines.push(kv("Last error", error.clone()));
    }
    if !row.management_available {
        lines.push(kv("Management", "Upgrade peer for guided node changes"));
    }
    if row.is_self {
        if let Some(status) = status_for_display(app) {
            lines.push(Line::default());
            lines.push(crate::tui::modal_form::section_rule(
                "Sync",
                width,
                CardRole::Analytics,
            ));
            lines.push(kv("Saved role", role_label(status.saved_role)));
            lines.push(kv(
                "Active role",
                status.active_role.map(role_label).unwrap_or("unknown"),
            ));
            lines.push(kv(
                "Policy",
                artifact_state(
                    status
                        .desired_policy
                        .as_ref()
                        .map(|policy| &policy.artifact_hash),
                    status
                        .active_policy
                        .as_ref()
                        .map(|policy| &policy.artifact_hash),
                ),
            ));
            lines.push(kv(
                "Corpus",
                artifact_state(
                    status.desired_corpus.as_ref(),
                    status.active_corpus.as_ref(),
                ),
            ));
        }
    }
    lines.push(Line::default());
    lines.push(crate::tui::modal_form::section_rule(
        "Advanced",
        width,
        CardRole::Summary,
    ));
    lines.push(kv("Stable ID", row.id.clone()));
    lines
}

fn artifact_state<T: PartialEq>(desired: Option<&T>, active: Option<&T>) -> &'static str {
    match (desired, active) {
        (Some(desired), Some(active)) if desired == active => "current",
        (Some(_), Some(_)) | (Some(_), None) => "pending",
        (None, Some(_)) => "active (desired unknown)",
        (None, None) => "unknown",
    }
}

pub(crate) fn information(app: &App) -> crate::tui::detail_panel::Information {
    let rows = build_rows(app);
    let row = rows
        .iter()
        .find(|row| Some(&row.id) == app.nodes.selected_id.as_ref())
        .or(rows.first());
    crate::tui::detail_panel::Information::new(
        "Node details",
        "Connection and policy state",
        row.map(|row| detail_lines(app, row, 72))
            .unwrap_or_else(|| vec![Line::from("No matching nodes")]),
    )
}

fn address(endpoint: Option<std::net::SocketAddr>) -> String {
    endpoint
        .map(|endpoint| format!("https://{endpoint}"))
        .unwrap_or_else(|| "unavailable".into())
}
fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {label:<15}"), Style::default().fg(T.text_muted)),
        Span::styled(value.into(), Style::default().fg(T.text_primary)),
    ])
}
fn peer_state_label(state: NodePeerState) -> &'static str {
    match state {
        NodePeerState::Pending => "pending",
        NodePeerState::Active => "online",
        NodePeerState::PendingDetach => "pending offline",
        NodePeerState::Detached => "standalone",
        NodePeerState::Unreachable => "offline",
    }
}
fn status_style(row: &NodeRow) -> Style {
    let color = match row.status.as_str() {
        "this node" | "online" => T.success,
        "offline" | "pending offline" => T.warning,
        _ => T.text_muted,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}
