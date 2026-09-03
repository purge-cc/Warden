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

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::config::settings::LogMode;
use crate::tui::app::{App, TrackingFocus, TrackingPanelState};
use crate::tui::theme::T;
use crate::tui::ui::render_section_chrome;

// Frozen strings for the Tracking form. Tests below pin these; changing
// them without updating the frozen-string audit is a regression.
pub const TRACKING_VALIDATION_RETENTION_OUT_OF_RANGE: &str =
    "retention_days must be between 1 and 365.";
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

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    match app.settings.tracking_panel.as_ref() {
        Some(panel) => render_tracking_panel(f, area, panel),
        None => render_landing(f, area, app),
    }
}

/// The actions this leaf owns, spelled out on screen. The footer carries
/// them too, but the footer is chrome an operator learns to stop reading —
/// without this, the pane would otherwise be a status line on an
/// empty rectangle.
const LANDING_ACTIONS: &[(&str, &str)] = &[
    ("t", "Tracking — query-log retention and sampling"),
    ("b", "Backup — write a config archive now"),
    ("R", "Restore — pick an archive to roll back to"),
];

/// The default view of `Leaf::Settings`.
///
/// The card is titled after its LEAF, which is what every other tab does
/// (Devices → "Devices", Lists → "Lists", …). This module was the single
/// exception before the split — it titled its card "Configuration" while
/// its leaf said "Settings". Fixed here rather than inherited.
fn render_landing(f: &mut Frame, area: Rect, app: &App) {
    let content = render_section_chrome(f, area, "Settings", T.text_secondary);

    let now = time::OffsetDateTime::now_utc();
    let av = &app.settings.auto_backup;

    let mut lines: Vec<Line> = Vec::new();
    lines.push(auto_backup_status_line(av.last_archive, now));
    lines.extend(auto_backup_banner_lines(
        av.consecutive_failures,
        av.last_error.as_deref(),
        av.disabled,
    ));
    lines.push(Line::from(""));

    for (key, what) in LANDING_ACTIONS {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("[{key}]"),
                Style::default()
                    .fg(T.brand_red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled((*what).to_string(), Style::default().fg(T.text_secondary)),
        ]));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content);
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
pub fn render_tracking_panel(f: &mut Frame, area: Rect, panel: &TrackingPanelState) {
    let content = render_section_chrome(f, area, "Tracking", T.text_secondary);

    // Reserve the bottom row for the submit/validation message FIRST so it
    // can never be starved: on a short panel ratatui shrinks trailing
    // constraints, and the submit line — the only feedback channel,
    // including TRACKING_VALIDATION_* errors — used to be the lowest-
    // priority `Min(1)` row and collapsed first. The dismissable help line
    // absorbs the squeeze instead. (set-02)
    let outer = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(content);
    let body = outer[0];
    let footer = outer[1];

    // 1 checkbox + 1 radio + 1 numeric + blank + help
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(body);

    f.render_widget(
        Paragraph::new(row_enabled(panel)).wrap(Wrap { trim: false }),
        rows[0],
    );
    f.render_widget(
        Paragraph::new(row_mode(panel)).wrap(Wrap { trim: false }),
        rows[1],
    );
    f.render_widget(
        Paragraph::new(row_retention(panel)).wrap(Wrap { trim: false }),
        rows[2],
    );

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "  Tab: next field · Space/Enter: toggle · ←/→: mode · digits: retention · s: submit · Esc: back",
            Style::default().fg(T.text_muted),
        ))),
        rows[4],
    );

    if let Some(msg) = &panel.submit_message {
        let color = if msg.starts_with("error:") {
            T.error
        } else {
            T.success
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("  {msg}"),
                Style::default().fg(color),
            ))),
            footer,
        );
    }
}

fn row_enabled(panel: &TrackingPanelState) -> Line<'static> {
    let focused = panel.focus == TrackingFocus::Enabled;
    let marker = if focused { "▸" } else { " " };
    let check = if panel.query_log_enabled {
        "[x]"
    } else {
        "[ ]"
    };
    let style = if focused {
        Style::default()
            .fg(T.text_primary)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(T.text_secondary)
    };
    Line::from(vec![
        Span::styled(format!("{marker} "), style),
        Span::styled(check.to_string(), style),
        Span::styled(" Query log enabled".to_string(), style),
    ])
}

fn row_mode(panel: &TrackingPanelState) -> Line<'static> {
    let focused = panel.focus == TrackingFocus::Mode;
    let marker = if focused { "▸" } else { " " };
    let label_style = if focused {
        Style::default()
            .fg(T.text_primary)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(T.text_secondary)
    };
    let current = match &panel.log_mode {
        LogMode::All => "All",
        LogMode::BlockedOnly => "Blocked only",
        LogMode::Sampled { .. } => TRACKING_SAMPLED_LABEL,
    };
    Line::from(vec![
        Span::styled(format!("{marker} Log mode: "), label_style),
        Span::styled(
            format!("< {current} >"),
            Style::default().fg(if focused {
                T.brand_red
            } else {
                T.text_secondary
            }),
        ),
    ])
}

fn row_retention(panel: &TrackingPanelState) -> Line<'static> {
    let focused = panel.focus == TrackingFocus::Retention;
    let marker = if focused { "▸" } else { " " };
    let label_style = if focused {
        Style::default()
            .fg(T.text_primary)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(T.text_secondary)
    };
    let value = if focused {
        format!("[ {} _ ]", panel.retention_input)
    } else {
        format!("  {}  ", panel.retention_days)
    };
    Line::from(vec![
        Span::styled(format!("{marker} Retention days (1..365): "), label_style),
        Span::styled(value, Style::default().fg(T.warning)),
    ])
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
