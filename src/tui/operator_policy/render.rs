use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::operator_rules::PersistenceState;
use crate::tui::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};
use crate::tui::App;

use super::controller::PolicyDialog;
use super::workflow::{RecoveryAction, WorkflowState};

pub(crate) fn render(frame: &mut Frame, content: Rect, app: &App) {
    let Some(dialog) = app.operator_policy.as_ref() else {
        return;
    };
    let spec = spec(dialog);
    modal_form::render_modal(frame, content, 72, |width| {
        let mut body = modal_form::notice_body(&spec, width);
        app.operator_policy_extent.set(body.fields.len());
        body.scrollable = true;
        body.focus_row = (!body.fields.is_empty()).then(|| {
            let focus = app
                .operator_policy_scroll
                .get()
                .min(body.fields.len().saturating_sub(1));
            app.operator_policy_scroll.set(focus);
            focus
        });
        (body, ())
    });
}

fn spec(dialog: &PolicyDialog) -> NoticeSpec {
    if dialog.preparing {
        return plain(
            "Planning policy change",
            &dialog.resource(),
            vec!["Negotiating daemon capabilities and current revision…".into()],
            "wait for the retained plan",
            "",
        );
    }
    if let Some(error) = &dialog.preparation_error {
        return NoticeSpec {
            title: "Policy plan unavailable".into(),
            desc: dialog.resource(),
            prose: prefix_rows(dialog),
            choices: Vec::new(),
            error: Some(error.clone()),
            hint: "the underlying draft was preserved".into(),
            hint_rows: None,
            keys: "[↑↓/PgUp/PgDn] scroll   [Esc/Enter] close".into(),
            actions: vec![
                Action::new("  [Enter] Close  ", false, ActionKind::Neutral, "")
                    .on_key(KeyCode::Enter),
            ],
        };
    }
    let Some(workflow) = &dialog.workflow else {
        return plain(
            "Policy workflow",
            &dialog.resource(),
            vec!["No workflow result is available.".into()],
            "",
            "[Esc] close",
        );
    };
    match &workflow.state {
        WorkflowState::Draft(_) | WorkflowState::Planning { .. } => plain(
            "Planning policy change",
            &dialog.resource(),
            prefix_text(dialog, "Validating the complete candidate…"),
            "wait for the retained plan",
            "",
        ),
        WorkflowState::Planned { plan, .. } => {
            let mut prose = prefix_rows(dialog);
            prose.extend([
                ProseRow::emphasis(
                    format!("{} operation(s)", plan.summary.operation_count),
                    ValueKind::Identity,
                ),
                ProseRow::plain(format!(
                    "profiles {} · recipients {} · rules after {}",
                    plan.summary.impacted_profile_count,
                    plan.summary.impacted_recipient_count,
                    plan.summary.rules_after
                )),
                ProseRow::plain("persistence not started · activation not started".to_string()),
            ]);
            prose.extend(
                plan.impact_rows
                    .iter()
                    .map(|row| ProseRow::plain(format!("{} · {}", row.kind, row.value))),
            );
            NoticeSpec {
                title: "Review policy plan".into(),
                desc: dialog.resource(),
                prose,
                choices: Vec::new(),
                error: None,
                hint: if plan.next_impact_cursor.is_some() {
                    "n loads more impact rows; arrows and Page keys scroll".into()
                } else {
                    "the daemon will revalidate the retained plan on apply".into()
                },
                hint_rows: None,
                keys: "[Enter/Ctrl+S] apply   [n] more   [↑↓/PgUp/PgDn] scroll   [Esc] back".into(),
                actions: vec![
                    Action::new("  [Esc] Back  ", false, ActionKind::Neutral, "")
                        .on_key(KeyCode::Esc),
                    Action::new("  [Ctrl+S] Apply  ", true, ActionKind::Primary, "").on_save(),
                ],
            }
        }
        WorkflowState::Applying { .. } => plain(
            "Applying policy change",
            &dialog.resource(),
            prefix_text(
                dialog,
                "Waiting for the durable receipt; closing the socket is not cancellation…",
            ),
            "do not submit a second identity",
            "",
        ),
        WorkflowState::Outcome { receipt, .. } => {
            let persistence = match receipt.persistence {
                PersistenceState::Prepared => "prepared",
                PersistenceState::Committed => "committed",
                PersistenceState::Aborted => "aborted",
                PersistenceState::DurabilityUncertain => "durability uncertain",
            };
            let mut prose = prefix_rows(dialog);
            prose.extend([
                ProseRow::emphasis(
                    format!("Persistence · {persistence}"),
                    if receipt.persistence == PersistenceState::Committed {
                        ValueKind::Editable
                    } else {
                        ValueKind::Blocking
                    },
                ),
                ProseRow::plain(format!("Activation · {}", receipt.activation.state)),
                ProseRow::plain(format!("Replication · {}", receipt.replication)),
                ProseRow::plain(format!("Audit · {}", receipt.audit)),
                ProseRow::plain(format!("Operation · {}", receipt.operation_id)),
                ProseRow::plain(format!("Revision · {}", short(&receipt.config_revision))),
            ]);
            prose.extend(
                receipt
                    .diagnostics
                    .iter()
                    .map(|diagnostic| ProseRow::plain(format!("Diagnostic · {diagnostic}"))),
            );
            let mut actions = vec![
                Action::new("  [r] Refresh  ", false, ActionKind::Neutral, "")
                    .on_key(KeyCode::Char('r')),
            ];
            if super::controller::dialog_can_close(dialog) {
                actions.push(
                    Action::new("  [Enter] Close  ", true, ActionKind::Primary, "")
                        .on_key(KeyCode::Enter),
                );
            }
            NoticeSpec {
                title: "Policy outcome".into(),
                desc: dialog.resource(),
                prose,
                choices: Vec::new(),
                error: None,
                hint: if receipt.persistence == PersistenceState::Committed
                    && receipt.activation.state != "applied"
                    && receipt.activation.state != "not_required"
                {
                    "persisted is not active; r refreshes the durable receipt".into()
                } else {
                    "persistence and activation are reported separately".into()
                },
                hint_rows: None,
                keys: if super::controller::dialog_can_close(dialog) {
                    "[↑↓/PgUp/PgDn] scroll   [r] refresh   [Esc/Enter] close".into()
                } else {
                    "[↑↓/PgUp/PgDn] scroll   [r] refresh unresolved receipt".into()
                },
                actions,
            }
        }
        WorkflowState::Recovery(recovery) => {
            let mut prose = prefix_rows(dialog);
            if let Some(receipt) = &recovery.last_receipt {
                prose.push(ProseRow::plain(format!(
                    "Last receipt · persistence {} · activation {}",
                    persistence_name(receipt.persistence),
                    receipt.activation.state
                )));
            }
            let action = match &recovery.action {
                RecoveryAction::RetryPlan => "retry the unchanged plan request",
                RecoveryAction::RefreshAndRedraft => {
                    "refresh metadata and create a new request identity"
                }
                RecoveryAction::RetryExactApply => {
                    "retry the exact retained plan, payload, and request identity"
                }
                RecoveryAction::ReplayRequest => "replay the exact submitted batch and identity",
                RecoveryAction::LookupOperation(_) => "look up the same durable operation",
                RecoveryAction::ReturnToDraft => "return to the preserved draft",
            };
            prose.push(ProseRow::plain(format!("Safe next step · {action}")));
            let mut actions = Vec::new();
            if super::controller::dialog_can_close(dialog) {
                actions.push(
                    Action::new("  [Esc] Keep draft  ", false, ActionKind::Neutral, "")
                        .on_key(KeyCode::Esc),
                );
            }
            if recovery.action != RecoveryAction::ReturnToDraft {
                actions.push(
                    Action::new("  [r] Recover  ", true, ActionKind::Primary, "")
                        .on_key(KeyCode::Char('r')),
                );
            }
            NoticeSpec {
                title: "Policy recovery".into(),
                desc: dialog.resource(),
                prose,
                choices: Vec::new(),
                error: recovery
                    .error
                    .as_ref()
                    .map(super::controller::format_policy_error),
                hint: "recovery preserves the submitted identity; Replay NotFound stays unknown"
                    .into(),
                hint_rows: None,
                keys: if recovery.action == RecoveryAction::ReturnToDraft {
                    "[↑↓/PgUp/PgDn] scroll   [Esc] return to draft".into()
                } else if super::controller::dialog_can_close(dialog) {
                    "[↑↓/PgUp/PgDn] scroll   [r] recover   [Esc] keep draft".into()
                } else {
                    "[↑↓/PgUp/PgDn] scroll   [r] recover exact identity".into()
                },
                actions,
            }
        }
    }
}

fn plain(title: &str, desc: &str, rows: Vec<String>, hint: &str, keys: &str) -> NoticeSpec {
    NoticeSpec {
        title: title.into(),
        desc: desc.into(),
        prose: rows.into_iter().map(ProseRow::plain).collect(),
        choices: Vec::new(),
        error: None,
        hint: hint.into(),
        hint_rows: None,
        keys: keys.into(),
        actions: Vec::new(),
    }
}

fn prefix_rows(dialog: &PolicyDialog) -> Vec<ProseRow> {
    dialog
        .prefix_outcome
        .iter()
        .map(|message| ProseRow::plain(message.clone()))
        .collect()
}

fn prefix_text(dialog: &PolicyDialog, text: &str) -> Vec<String> {
    dialog
        .prefix_outcome
        .iter()
        .cloned()
        .chain(std::iter::once(text.into()))
        .collect()
}

fn persistence_name(state: PersistenceState) -> &'static str {
    match state {
        PersistenceState::Prepared => "prepared",
        PersistenceState::Committed => "committed",
        PersistenceState::Aborted => "aborted",
        PersistenceState::DurabilityUncertain => "durability uncertain",
    }
}

fn short(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}
