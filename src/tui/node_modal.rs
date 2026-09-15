//! Nodes inline forms and the one central daemon-generated review.

use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::Frame;

use crate::cluster::node_control::{NodeOperationPhase, NodePreview};

use super::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};
use super::nodes::{operation_label, role_label, NodeDraft, NodeFormKind, NodesDialog};
use super::App;

const MODAL_W: u16 = 74;

pub(crate) fn render(f: &mut Frame, area: Rect, app: &App) {
    let Some(dialog) = app.nodes.dialog.as_ref() else {
        return;
    };
    match dialog {
        NodesDialog::Form(draft) => render_draft(f, area, draft),
        NodesDialog::Review { preview, error } => {
            let mut spec = preview_spec(preview);
            spec.error = error.clone();
            modal_form::render_modal(f, area, MODAL_W, |width| {
                (modal_form::notice_body(&spec, width), ())
            });
        }
        NodesDialog::Applying {
            operation_id,
            kind,
            error,
        } => {
            let mut spec = NoticeSpec {
                title: format!("{} · IN PROGRESS", operation_label(*kind)),
                desc: if error.is_some() {
                    "The daemon result was not received; recover this same operation.".into()
                } else {
                    "The daemon accepted this operation and persists its recovery state.".into()
                },
                prose: vec![
                    ProseRow::plain(format!("Operation  {operation_id}")),
                    ProseRow::plain(
                        "You may close this screen. Reopen Nodes and press u to recover progress.",
                    ),
                    ProseRow::emphasis(
                        "Do not repeat the request while the daemon reports it in progress.",
                        ValueKind::Caution,
                    ),
                ],
                keys: "Esc close · operation continues".into(),
                ..NoticeSpec::default()
            };
            spec.error = error.clone();
            modal_form::render_modal(f, area, MODAL_W, |width| {
                (modal_form::notice_body(&spec, width), ())
            });
        }
        NodesDialog::Recovery { progress, error } => {
            let cancelled = progress.phase == NodeOperationPhase::Cancelled;
            let cancellation_cleanup_pending = cancelled
                && super::nodes::control_status_for_display(app).is_some_and(|status| {
                    super::nodes::is_cancelled_add_cleanup_pending(status, progress)
                });
            let can_cancel = progress.kind == crate::cluster::node_control::NodeOperationKind::Add
                && matches!(
                    progress.phase,
                    NodeOperationPhase::PreparingTarget
                        | NodeOperationPhase::Prepared
                        | NodeOperationPhase::Paused
                );
            let mut actions = Vec::new();
            if can_cancel {
                actions.push(
                    Action::new(
                        "  Cancel  ",
                        false,
                        ActionKind::Neutral,
                        "Cancel the unconfirmed review",
                    )
                    .on_key(KeyCode::Char('c')),
                );
            }
            if !cancelled || cancellation_cleanup_pending {
                actions.push(
                    Action::new(
                        "  Resume  ",
                        true,
                        ActionKind::Primary,
                        "Resume this operation",
                    )
                    .on_key(KeyCode::Enter),
                );
            }
            let mut prose = vec![
                ProseRow::plain(format!("Operation  {}", progress.operation_id)),
                ProseRow::plain(progress.message.clone()),
            ];
            if let Some(until) = progress.recover_until {
                prose.push(ProseRow::plain(format!("Recovery retained until  {until}")));
            }
            if !progress.restart_steps.is_empty() {
                prose.push(ProseRow::plain(
                    "Restart steps are persisted and consumed once by the daemon.",
                ));
            }
            let mut spec = NoticeSpec {
                title: format!(
                    "{} · {}",
                    operation_label(progress.kind),
                    phase_label(progress.phase)
                ),
                desc: if cancellation_cleanup_pending {
                    "Cancellation cleanup is still pending".into()
                } else if cancelled {
                    "Retained Nodes recovery record".into()
                } else {
                    "Recoverable daemon operation".into()
                },
                prose,
                hint: if cancellation_cleanup_pending {
                    "Resume completes cancellation cleanup without changing active policy.".into()
                } else if cancelled {
                    "This record remains visible for target-local recovery; use the exact operation ID shown here.".into()
                } else {
                    "Resume continues the same durable operation.".into()
                },
                keys: if cancellation_cleanup_pending {
                    "Enter resume · Esc close"
                } else if cancelled {
                    "Esc close"
                } else if can_cancel {
                    "Enter resume · c cancel · Esc close"
                } else {
                    "Enter resume · Esc close"
                }
                .into(),
                actions,
                ..NoticeSpec::default()
            };
            spec.error = error.clone();
            modal_form::render_modal(f, area, MODAL_W, |width| {
                (modal_form::notice_body(&spec, width), ())
            });
        }
        NodesDialog::Outcome { message } => {
            let spec = NoticeSpec {
                title: "NODES · COMPLETE".into(),
                desc: "Authoritative daemon result".into(),
                prose: vec![ProseRow::emphasis(message.clone(), ValueKind::Healthy)],
                keys: "Enter or Esc close".into(),
                actions: vec![Action::new(
                    "  Done  ",
                    true,
                    ActionKind::Primary,
                    "Return to Nodes",
                )
                .on_key(KeyCode::Enter)],
                ..NoticeSpec::default()
            };
            modal_form::render_modal(f, area, MODAL_W, |width| {
                (modal_form::notice_body(&spec, width), ())
            });
        }
    }
}

fn draft_body(draft: &NodeDraft, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let title = match draft.kind {
        NodeFormKind::Add => "ADD NODE",
        NodeFormKind::Edit => "EDIT NODE",
    };
    let description = match draft.kind {
        NodeFormKind::Add => "Name, destination IP, and a destination-issued association token",
        NodeFormKind::Edit => "Update name, IP, or Nodes HTTPS port without changing identity",
    };
    let mut rows = modal_form::FormRows::new(title, description, width);
    rows.section("Connection");
    for index in 0..draft.visible_fields() {
        let focused = draft.focus == index;
        let actual = draft.field_value(index);
        let shown = if draft.kind == NodeFormKind::Add && index == 2 {
            "•".repeat(actual.chars().count())
        } else {
            actual.to_owned()
        };
        rows.text_field(
            modal_form::value_row(
                draft.field_label(index),
                &shown,
                focused,
                ValueKind::Editable,
                Some(field_placeholder(draft, index)),
                width,
            ),
            focused,
            field_hint(draft, index),
            shown.chars().count() as u16,
        );
    }
    let advanced_focus = draft.focus == draft.visible_fields();
    rows.line(modal_form::state_row(
        "Advanced",
        if draft.advanced {
            "Hide HTTPS port"
        } else {
            "Show HTTPS port"
        },
        if advanced_focus {
            ValueKind::Editable
        } else {
            ValueKind::Identity
        },
        "Enter to toggle",
        width,
    ));
    rows.spacer();
    rows.line(Line::from(
        "No change is made until the daemon-generated review is applied.",
    ));
    let cancel_focus = draft.focus == draft.visible_fields() + 1;
    let review_focus = draft.focus == draft.visible_fields() + 2;
    let actions = [
        Action::new(
            "  Cancel  ",
            cancel_focus,
            ActionKind::Neutral,
            "Discard this form",
        )
        .on_key(KeyCode::Esc),
        Action::new(
            "  Review  ",
            review_focus,
            ActionKind::Primary,
            "Ask the daemon for an exact review",
        )
        .on_save(),
    ];
    let tail = modal_form::form_tail(
        &rows,
        draft.error.as_deref(),
        "Review comes before apply",
        "Tab move · Enter toggle/review · Ctrl+S review · Esc cancel",
        &actions,
    );
    rows.finish(tail)
}

fn render_draft(f: &mut Frame, area: Rect, draft: &NodeDraft) {
    let render = modal_form::render_modal(f, area, MODAL_W, |width| draft_body(draft, width));
    if let Some((row, caret)) = render.cursor {
        render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
    }
}

pub(crate) fn render_inline_editor(f: &mut Frame, area: Rect, draft: &NodeDraft) {
    let title = match draft.kind {
        NodeFormKind::Add => "Add node",
        NodeFormKind::Edit => "Edit node",
    };
    let content = super::theme::filled_card(
        f.buffer_mut(),
        area,
        title,
        "Nodes HTTPS association",
        super::theme::CardRole::History,
    );
    let (mut body, cursor) = draft_body(draft, content.width.saturating_sub(1));
    body.head = vec![Line::default()];
    let view = modal_form::render_scroll_body(f, content, &body);
    if let Some((row, caret)) = cursor {
        if row >= view.offset && row < view.offset + view.view_h {
            let x = content.x + modal_form::VALUE_COL as u16 + caret;
            let y = content.y + (view.head_h + row - view.offset) as u16;
            if x < content.right() && y < content.bottom() {
                f.set_cursor_position((x, y));
            }
        }
    }
}

fn preview_spec(preview: &NodePreview) -> NoticeSpec {
    let local_without_listener = preview.source_node_id == preview.target_node_id
        && preview.source_endpoint.is_none()
        && preview.restart_steps.iter().all(|step| step.acknowledged);
    let destination = if local_without_listener {
        preview.target_name.clone()
    } else {
        format!("{} ({})", preview.target_name, preview.target_endpoint)
    };
    let mut prose = vec![
        ProseRow::plain(format!("Source  {}", preview.source_name)),
        ProseRow::plain(format!("Destination  {destination}")),
        ProseRow::plain(format!("Role  {}", role_label(preview.target_role))),
    ];
    if let Some(endpoint) = preview.source_endpoint {
        prose.push(ProseRow::plain(format!("Source HTTPS  {endpoint}")));
    }
    if preview.replacement_summary.is_empty() {
        prose.push(ProseRow::plain(
            "Replacement  no policy or corpus replacement",
        ));
    } else {
        prose.extend(
            preview
                .replacement_summary
                .iter()
                .map(|line| ProseRow::plain(format!("Replacement  {line}"))),
        );
    }
    for step in preview
        .restart_steps
        .iter()
        .filter(|step| !step.acknowledged)
    {
        prose.push(ProseRow::plain(format!(
            "Restart  {:?} · pending",
            step.target
        )));
    }
    prose.push(ProseRow::emphasis("Review applies this exact preview once. The daemon retains recoverable progress if this screen closes.", ValueKind::Caution));
    NoticeSpec {
        title: format!("{} · FINAL REVIEW", operation_label(preview.kind)),
        desc: "Verify source, destination, replacement, backup, and restarts".into(),
        prose,
        hint: "Enter applies this exact review; c cancels it on the daemon.".into(),
        keys: "Enter apply · c cancel · Esc keep and close".into(),
        actions: vec![
            Action::new(
                "  Cancel  ",
                false,
                ActionKind::Neutral,
                "Discard the exact review",
            )
            .on_key(KeyCode::Char('c')),
            Action::new(
                "  Apply  ",
                true,
                ActionKind::Primary,
                "Apply the reviewed operation",
            )
            .on_key(KeyCode::Enter),
        ],
        ..NoticeSpec::default()
    }
}

fn field_placeholder(draft: &NodeDraft, index: usize) -> &'static str {
    match (draft.kind, index) {
        (_, 0) => "recognizable node name",
        (_, 1) => "destination IP",
        (NodeFormKind::Add, 2) => "paste association token",
        _ => "8053",
    }
}
fn field_hint(draft: &NodeDraft, index: usize) -> &'static str {
    match (draft.kind, index) {
        (_, 0) => "1–64 characters; the stable Node ID does not change",
        (_, 1) => "LAN IPv4 or IPv6 address; this is Nodes HTTPS, not DNS",
        (NodeFormKind::Add, 2) => "Masked locally; only sent to prepare the reviewed association",
        _ => "Default 8053; change only when the destination uses another Nodes HTTPS port",
    }
}
fn phase_label(phase: NodeOperationPhase) -> &'static str {
    match phase {
        NodeOperationPhase::Prepared => "prepared",
        NodeOperationPhase::ApplyingPrimary => "applying primary",
        NodeOperationPhase::RestartingPrimary => "restarting primary",
        NodeOperationPhase::PreparingTarget => "preparing target",
        NodeOperationPhase::ApplyingTarget => "applying target",
        NodeOperationPhase::RestartingTarget => "restarting target",
        NodeOperationPhase::AwaitingDetach => "awaiting detach",
        NodeOperationPhase::Complete => "complete",
        NodeOperationPhase::Cancelled => "cancelled",
        NodeOperationPhase::Paused => "paused",
        NodeOperationPhase::Failed => "failed",
    }
}
