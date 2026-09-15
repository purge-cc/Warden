//! Settings tab — the configuration as an **administered thing**: the
//! Tracking form, backup, restore, and the auto-backup status those verbs
//! produce.
//!
//! The TOML *document* lives in [`super::file`]. What is
//! left here is deliberate: a knob, a backup and the health of the backup
//! belong together, and none of them is the file's text.
//!
//! With the viewer gone this leaf needed a default view — before the split
//! it had none of its own, rendering either the Tracking form or the
//! document. `render_landing` is that view.
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_settings_key` (`t` opens Tracking, `b`/`R` open backup/restore)
//! - Form:  `tui::backup_restore_modal` for backup/restore; Tracking is an
//!   inline form (`TrackingPanelState`), not a separate `*_modal.rs`
//! - State: `app::SettingsState` (`tracking_panel`, `restore_modal`, `backup_modal`, `auto_backup`)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::config::settings::LogMode;
use crate::tui::app::{App, TrackingFocus, TrackingPanelState};
use crate::tui::mouse::{self, MouseAction};
use crate::tui::theme::{self, T};

// Frozen strings for the Tracking form. Tests below pin these; changing
// them without updating the frozen-string audit is a regression.
pub const TRACKING_VALIDATION_RETENTION_OUT_OF_RANGE: &str =
    "retention_days must be between 1 and 365.";
#[cfg(test)]
pub const TRACKING_SAMPLED_LABEL: &str = "Sampled (10%)";

// Frozen strings for the auto-backup status line and the failure
// banner. Pinned by the `auto_backup_*` tests below;
// the re-enable hint must stay verbatim with the `warden config backup
// --reset-auto-failure` CLI verb it points at.
pub const AUTO_BACKUP_LABEL: &str = "Last auto-backup: ";
pub const AUTO_BACKUP_NEVER: &str = "Last auto-backup: never (no archives yet)";
pub const AUTO_BACKUP_FAILED_PREFIX: &str = "auto-backup failed: ";
pub const AUTO_BACKUP_DISABLED_PREFIX: &str = "auto-backup disabled after ";
pub const AUTO_BACKUP_REENABLE_HINT: &str = "re-enable: warden config backup --reset-auto-failure";

const ITEMS: [(&str, &str); 3] = [
    ("Tracking", "Query Log, Sampling & Retention"),
    ("Backup", "Archives & Automatic Backup Status"),
    ("Restore", "Browse Available Restore Points"),
];

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let columns = crate::tui::detail_panel::columns(area);
    if app.settings.tracking_panel.is_none() || columns.is_some() {
        let body = theme::filled_card(
            f.buffer_mut(),
            columns.map_or(area, |c| c[0]),
            "Settings",
            "Tracking, Backup & Restore",
            theme::CardRole::Analytics,
        );
        for (index, (title, subtitle)) in ITEMS.iter().enumerate() {
            let y = body.y + index as u16 * 3;
            if y >= body.bottom() {
                break;
            }
            let rect = Rect::new(body.x, y, body.width, 2.min(body.bottom() - y));
            let lines = vec![
                Line::styled(*title, Style::default().add_modifier(Modifier::BOLD)),
                Line::styled(*subtitle, Style::default().fg(T.text_secondary)),
            ];
            f.render_widget(
                Paragraph::new(lines).style(if index == app.settings.selected {
                    theme::highlight_style()
                } else {
                    Style::default()
                }),
                rect,
            );
            mouse::register(
                app,
                rect,
                MouseAction::Row(crate::tui::app::Leaf::Settings, index),
            );
        }
    }
    if let Some(panel) = app.settings.tracking_panel.as_ref() {
        render_tracking_panel(f, columns.map_or(area, |c| c[1]), app, panel);
    } else if let Some(cols) = columns {
        let info = information_with_width(app, cols[1].width.saturating_sub(4));
        let body = theme::filled_card(
            f.buffer_mut(),
            cols[1],
            &info.title,
            &info.subtitle,
            theme::CardRole::History,
        );
        crate::tui::detail_panel::render(
            f,
            Rect::new(body.x, body.y, body.width, body.height.saturating_sub(2)),
            app,
            crate::tui::app::Leaf::Settings,
            ITEMS[app.settings.selected.min(2)].0,
            info.lines,
        );
        if body.height > 2 {
            use crate::tui::modal_form::{self, Action, ActionKind};
            let row = Rect::new(body.x, body.bottom() - 1, body.width, 1);
            let label = ["Edit", "Create Backup", "Choose Archive"][app.settings.selected.min(2)];
            let actions = [
                Action::new(label, false, ActionKind::Primary, "Open setting")
                    .on_key(KeyCode::Enter),
            ];
            f.render_widget(
                Paragraph::new(modal_form::action_row(&actions, row.width)),
                row,
            );
            for (area, key) in modal_form::action_regions(&actions, row) {
                mouse::register(app, area, MouseAction::Key(key.code));
            }
        }
    }
}

pub fn information(app: &App) -> crate::tui::detail_panel::Information {
    information_with_width(app, 74)
}

fn information_with_width(app: &App, width: u16) -> crate::tui::detail_panel::Information {
    let selected = app.settings.selected.min(2);
    let mut lines = Vec::new();
    if selected == 0 {
        if let Some(loaded) = app.loaded_config.as_ref() {
            let tracking = &loaded.config.tracking;
            lines.extend([
                crate::tui::modal_form::section_rule(
                    "Query Logging",
                    width,
                    theme::CardRole::Summary,
                ),
                detail_value(
                    "Query Log",
                    if tracking.query_log_enabled {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                ),
                detail_value("Mode", log_mode_label(&tracking.log_mode)),
                Line::default(),
                crate::tui::modal_form::section_rule("Retention", width, theme::CardRole::History),
                detail_value("Keep History", format!("{} Days", tracking.retention_days)),
                detail_value("Allowed Range", "1–365 Days"),
            ]);
        } else {
            lines.push(Line::from("Tracking configuration unavailable"));
        }
    } else {
        let av = &app.settings.auto_backup;
        let now = time::OffsetDateTime::now_utc();
        lines.push(crate::tui::modal_form::section_rule(
            if selected == 1 {
                "Automatic Backup"
            } else {
                "Restore Points"
            },
            width,
            if selected == 1 {
                theme::CardRole::Summary
            } else {
                theme::CardRole::History
            },
        ));
        if selected == 1 {
            lines.extend([
                detail_value(
                    "Status",
                    if av.disabled {
                        "Disabled"
                    } else if av.consecutive_failures > 0 {
                        "Failing"
                    } else {
                        "No failures recorded"
                    },
                ),
                last_archive_detail(av.last_archive, now),
                detail_value("Failures", av.consecutive_failures.to_string()),
            ]);
            lines.extend(auto_backup_banner_lines(
                av.consecutive_failures,
                av.last_error.as_deref(),
                av.disabled,
            ));
            lines.push(Line::default());
            lines.push(crate::tui::modal_form::section_rule(
                "Archive Storage",
                width,
                theme::CardRole::History,
            ));
        } else {
            lines.push(last_archive_detail(av.last_archive, now));
        }
        if let Some(loaded) = app.loaded_config.as_ref() {
            lines.push(detail_value(
                "Directory",
                loaded
                    .config
                    .backup
                    .resolve_dir(&loaded.master_path)
                    .display()
                    .to_string(),
            ));
        }
        lines.push(detail_value("Scope", "Complete configuration tree"));
        if selected == 2 {
            lines.push(Line::styled(
                "Browse archives to choose a restore point.",
                Style::default().fg(T.text_primary),
            ));
        }
    }
    let title = ["Tracking Details", "Backup Details", "Restore Details"][selected];
    crate::tui::detail_panel::Information::new(title, ITEMS[selected].1, lines)
}

fn detail_value(label: &str, value: impl Into<String>) -> Line<'static> {
    let value = value.into();
    Line::from(vec![
        Span::styled(format!("{label:<14} "), Style::default().fg(T.text_muted)),
        Span::styled(
            if value.is_empty() {
                "—".into()
            } else {
                value
            },
            Style::default().fg(T.text_primary),
        ),
    ])
}

fn last_archive_detail(
    last_archive: Option<time::OffsetDateTime>,
    now: time::OffsetDateTime,
) -> Line<'static> {
    let status = auto_backup_status_line(last_archive, now);
    let text = status
        .spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect::<String>();
    let value = text
        .trim_start()
        .strip_prefix(AUTO_BACKUP_LABEL)
        .unwrap_or(text.trim_start())
        .to_string();
    detail_value("Last Archive", value)
}

fn log_mode_label(mode: &LogMode) -> String {
    match mode {
        LogMode::All => "All".into(),
        LogMode::BlockedOnly => "Blocked Only".into(),
        LogMode::Sampled { allowed_rate } => format!("Sampled ({:.0}%)", allowed_rate * 100.0),
    }
}

/// The "Last auto-backup" status line. `None` archive ⇒ a
/// muted "never" state; otherwise `<date> (<age>)`, reusing the restore
/// modal's `format_date`/`format_age` so the formatting matches the
/// restore picker. `now` is injected so the relative age is testable.
pub(crate) fn auto_backup_status_line(
    last_archive: Option<time::OffsetDateTime>,
    now: time::OffsetDateTime,
) -> Line<'static> {
    match last_archive {
        None => Line::from(Span::styled(
            format!("  {AUTO_BACKUP_NEVER}"),
            Style::default().fg(T.text_muted),
        )),
        Some(ts) => {
            let date = crate::tui::backup_restore_modal::format_date(ts);
            let age = crate::tui::backup_restore_modal::format_age(now, ts);
            Line::from(Span::styled(
                format!("  {AUTO_BACKUP_LABEL}{date} ({age})"),
                Style::default().fg(T.text_secondary),
            ))
        }
    }
}

/// The failure banner. Empty when healthy. One red
/// `✗ auto-backup failed: <reason>` line when failing but not disabled.
/// Two lines when the disable-after-N-failures latch tripped — a stronger
/// `✗ auto-backup disabled after N failures: <reason>` line plus a muted
/// hint naming the `--reset-auto-failure` recovery verb. `<reason>`
/// falls back to "unknown" when no error message was recorded.
pub(crate) fn auto_backup_banner_lines(
    consecutive_failures: u32,
    last_error: Option<&str>,
    disabled: bool,
) -> Vec<Line<'static>> {
    if consecutive_failures == 0 && !disabled {
        return Vec::new();
    }
    let reason = last_error.unwrap_or("unknown");
    if disabled {
        vec![
            Line::from(Span::styled(
                format!(
                    "  \u{2717} {AUTO_BACKUP_DISABLED_PREFIX}{consecutive_failures} failures: {reason}"
                ),
                Style::default().fg(T.error),
            )),
            Line::from(Span::styled(
                format!("    {AUTO_BACKUP_REENABLE_HINT}"),
                Style::default().fg(T.text_muted),
            )),
        ]
    } else {
        vec![Line::from(Span::styled(
            format!("  \u{2717} {AUTO_BACKUP_FAILED_PREFIX}{reason}"),
            Style::default().fg(T.error),
        ))]
    }
}

/// Render the Tracking form — three stacked rows
/// (checkbox / radio / numeric input) plus a help + footer line.
/// Focused row is highlighted; unfocused rows render at muted
/// intensity so the operator always sees WHICH control is live.
pub fn render_tracking_panel(f: &mut Frame, area: Rect, app: &App, panel: &TrackingPanelState) {
    use crate::tui::modal_form::{self, Action, ActionKind, FormRows, ValueKind};
    let body_area = theme::filled_card(
        f.buffer_mut(),
        area,
        "Edit Tracking",
        "Query Logging & Retention",
        theme::CardRole::History,
    );
    let mut rows = FormRows::new("", "", body_area.width.saturating_sub(1));
    for line in
        modal_form::section_band_with_role("Query Logging", rows.width(), theme::CardRole::Summary)
    {
        rows.line(line);
    }
    rows.choice_field(
        modal_form::value_row(
            "Query Log",
            if panel.query_log_enabled {
                "Enabled"
            } else {
                "Disabled"
            },
            panel.focus == TrackingFocus::Enabled,
            ValueKind::Editable,
            None,
            body_area.width.saturating_sub(1),
        ),
        panel.focus == TrackingFocus::Enabled,
        "Space changes query logging",
    );
    rows.choice_field(
        modal_form::value_row(
            "Mode",
            &log_mode_label(&panel.log_mode),
            panel.focus == TrackingFocus::Mode,
            ValueKind::Editable,
            None,
            body_area.width.saturating_sub(1),
        ),
        panel.focus == TrackingFocus::Mode,
        "Left/Right changes the logging mode",
    );
    for line in
        modal_form::section_band_with_role("Retention", rows.width(), theme::CardRole::History)
    {
        rows.line(line);
    }
    rows.text_field(
        modal_form::value_row(
            "Keep Days",
            &panel.retention_input,
            panel.focus == TrackingFocus::Retention,
            ValueKind::Editable,
            None,
            body_area.width.saturating_sub(1),
        ),
        panel.focus == TrackingFocus::Retention,
        "Keep 1–365 days",
        panel.retention_input.len() as u16,
    );
    let actions = [
        Action::new(
            " Discard ",
            panel.focus == TrackingFocus::Discard,
            ActionKind::Neutral,
            "Discard draft",
        )
        .on_key(KeyCode::Esc),
        Action::new(
            " Save ",
            panel.focus == TrackingFocus::Save,
            ActionKind::Primary,
            "Save tracking settings",
        )
        .on_save(),
    ];
    let tail = modal_form::form_tail(
        &rows,
        panel.submit_message.as_deref(),
        "",
        "Tab Move · Ctrl+S Save · Esc Discard",
        &actions,
    );
    let (mut body, cursor) = rows.finish(tail);
    body.head = vec![Line::default()];
    let view = modal_form::render_scroll_body(f, body_area, &body);
    if let Some((row, caret)) = cursor {
        if row >= view.offset && row < view.offset + view.view_h {
            let x = body_area.x + modal_form::VALUE_COL as u16 + caret;
            let y = body_area.y + (view.head_h + row - view.offset) as u16;
            if x < body_area.right() && y < body_area.bottom() {
                f.set_cursor_position((x, y));
            }
        }
    }
    let _ = app;
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    // Mirrors the `backup_submitted_*_color` color-assertion
    // idiom: build the pure Line(s), then assert the foreground colour
    // and the frozen text on `spans[0]`.

    #[test]
    fn auto_backup_status_line_never() {
        let now = datetime!(2026-05-29 12:00:00 UTC);
        let line = auto_backup_status_line(None, now);
        assert!(
            line.spans[0].content.contains("never"),
            "no archives ⇒ never state"
        );
        assert_eq!(
            line.spans[0].style.fg,
            Some(T.text_muted),
            "never state renders muted"
        );
    }

    #[test]
    fn auto_backup_status_line_populated() {
        let now = datetime!(2026-05-29 12:00:00 UTC);
        let ts = datetime!(2026-05-29 00:00:00 UTC);
        let line = auto_backup_status_line(Some(ts), now);
        let text = &line.spans[0].content;
        assert!(
            text.contains("Last auto-backup: 2026-05-29 00:00"),
            "populated line carries the formatted date: {text}"
        );
        assert!(
            text.contains("12 hours ago"),
            "and the relative age: {text}"
        );
        assert_eq!(line.spans[0].style.fg, Some(T.text_secondary));
    }

    #[test]
    fn auto_backup_banner_healthy_is_empty() {
        assert!(
            auto_backup_banner_lines(0, None, false).is_empty(),
            "no failures + not disabled ⇒ no banner"
        );
    }

    #[test]
    fn auto_backup_banner_failed_uses_error_color() {
        let lines = auto_backup_banner_lines(1, Some("tar exited with 1"), false);
        assert_eq!(lines.len(), 1, "failing-but-not-disabled ⇒ single line");
        assert_eq!(
            lines[0].spans[0].style.fg,
            Some(T.error),
            "failure banner must render in the error colour"
        );
        assert!(lines[0].spans[0]
            .content
            .contains("auto-backup failed: tar exited with 1"));
    }

    #[test]
    fn auto_backup_banner_disabled_has_reenable_hint() {
        let lines = auto_backup_banner_lines(3, Some("tar exited with 1"), true);
        assert_eq!(lines.len(), 2, "disabled ⇒ banner + re-enable hint");
        assert_eq!(
            lines[0].spans[0].style.fg,
            Some(T.error),
            "disabled banner is red"
        );
        assert!(lines[0].spans[0]
            .content
            .contains("disabled after 3 failures"));
        assert_eq!(
            lines[1].spans[0].style.fg,
            Some(T.text_muted),
            "re-enable hint is muted"
        );
        assert!(
            lines[1].spans[0]
                .content
                .contains("warden config backup --reset-auto-failure"),
            "hint must name the recovery verb"
        );
    }

    #[test]
    fn auto_backup_banner_failed_without_reason_falls_back() {
        let lines = auto_backup_banner_lines(2, None, false);
        assert!(
            lines[0].spans[0].content.contains("unknown"),
            "missing last_outcome ⇒ 'unknown' reason"
        );
    }
}
