//! Settings-tab backup + restore modals.
//!
//! [`RestoreModal`] opens over [`crate::tui::app::Leaf::Settings`] via `R`;
//! lists the restore points in the configured backup dir, takes a
//! single-keypress `y`/`n` confirmation, then runs the restore through the
//! shared engine core [`crate::cli::commands::config::restore_archive`] and
//! reloads the daemon over IPC (the same `Ctrl+r` path).
//!
//! [`BackupModal`] opens via `b`; a two-phase confirm → result card around
//! [`crate::cli::commands::config::create_backup`]. Replaces the prior
//! silent one-shot which routed both success and failure into
//! `app.last_error` (rendered red-with-`✗` — wrong styling for the
//! success case). The Submitted card reuses [`outcome_notice`] so the
//! colour switches on `ok` exactly like the restore outcome.
//!
//! ## Chrome
//! Both flows use the shared modal frame and body rows. Every stage declares
//! a [`NoticeSpec`] for its actions and outcome semantics; the archive picker
//! and confirmations compose the configuration-specific table and sections.
//!
//! ## State machine
//! ```text
//! Picking { entries, selected } ──Enter──▶ Confirming { point }
//!                               ──Esc──▶ closed
//! Confirming { point }          ──[y]──▶ Restoring { point }
//!                               ──[n / Esc]──▶ Picking
//! Restoring { point }           ──job──▶ Submitted(Ok | Failed)
//!                               ──any key──▶ (swallowed)
//! Submitted(..)                 ──any key──▶ closed
//!
//! Confirm { dir }               ──[y]──▶ Running { dir }
//!                               ──[n / Esc]──▶ closed
//! Running { dir }               ──job──▶ Submitted { msg, ok }
//!                               ──any key──▶ (swallowed)
//! Submitted { .. }              ──any key──▶ closed
//! ```
//! Both `Restoring` and `Running` are in-flight stages: the filesystem work
//! runs on the blocking pool and the outcome comes home through the `UiJob`
//! channel, so the event loop stays free to paint the progress card.
//!
//! ## Capture-at-open invariant
//! `from_config` snapshots each archive's display fields (date / age / size)
//! and full path when the picker opens, so a background list refresh cannot
//! shift the row under the operator — confirm always restores the captured
//! path.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::tui::modal_form::{
    self, Action, ActionKind, ChoiceRow, FormRows, NoticeSpec, ProseRow, ValueKind,
};
use crate::tui::theme::{self, CardRole, T};

/// Settings-tab backup confirm + result modal. Opened by `b`; closed by
/// dropping the `Option` (n / Esc on Confirm, any key on Submitted).
#[derive(Debug, Clone)]
pub enum BackupModal {
    /// Awaiting `y` / `n` / Esc on the "back up now?" prompt. Carries
    /// the resolved backup dir captured at open time so the confirm
    /// card can show where the archive will land.
    Confirm { dir: PathBuf },
    /// The backup is in flight on a background task (tui-14) — tar + gzip of
    /// the whole config tree. The event loop keeps running, so THIS card
    /// actually paints; the old inline call froze the loop for the length of
    /// the archive, which is why a "backing up…" flag set before it could never
    /// have been drawn.
    ///
    /// Every key is swallowed while this stage is live — deliberately, and the
    /// card must not advertise one. The output lock serializes owners; this is
    /// defense in depth against duplicate jobs and orphaned outcomes.
    Running { dir: PathBuf },
    /// Terminal — render the outcome. Any key closes the modal. `ok`
    /// switches the colour via [`outcome_notice`], shared with the
    /// restore flow's own terminal stage.
    Submitted { msg: String, ok: bool },
}

#[derive(Debug, Clone)]
pub struct RestoreModal {
    pub stage: RestoreStage,
}

#[derive(Debug, Clone)]
pub enum RestoreStage {
    /// Choosing among the restore points (newest first).
    Picking {
        entries: Vec<RestorePoint>,
        selected: usize,
    },
    /// Single-keypress confirm for the chosen point.
    Confirming { point: RestorePoint },
    /// The restore is in flight on a background task (tui-02) — untar,
    /// validate, atomic swap, then the daemon reload. The event loop keeps
    /// running, so THIS card actually paints; the old inline call froze the
    /// loop for the whole extraction, which is why a "restoring…" flag set
    /// before it could never have been drawn.
    ///
    /// Every key is swallowed while this stage is live — deliberately, and the
    /// card must not advertise one. A second `y` would race a second extraction
    /// against the same live config tree, and an `Esc` would only hide a card
    /// whose disk writes it cannot call back.
    Restoring { point: RestorePoint },
    /// Terminal — render the outcome; any key closes the modal.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

/// Display-ready snapshot of one backup archive, captured at open time.
#[derive(Debug, Clone)]
pub struct RestorePoint {
    /// Full archive path — what `restore_archive` receives on confirm.
    pub path: PathBuf,
    /// Absolute time from the archive name, e.g. `2026-05-27 14:59`.
    pub date: String,
    /// Relative age at open time, e.g. `2 minutes ago`.
    pub age: String,
    /// Human archive size, e.g. `151 B` / `1.2 KiB`.
    pub size: String,
}

impl RestoreModal {
    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, RestoreStage::Submitted(_))
    }

    /// Build the picker from the backups in the config's resolved backup
    /// dir, newest first. Returns `None` when there are no restore points,
    /// so the caller can surface "no backups" in the footer instead of
    /// opening an empty modal.
    pub fn from_config(config_path: &Path) -> Option<RestoreModal> {
        use crate::cli::commands::config::backup::human_bytes;
        use crate::cli::commands::config::{list_backups, resolved_backup_dir};

        let dir = resolved_backup_dir(config_path);
        let backups = list_backups(&dir);
        if backups.is_empty() {
            return None;
        }
        let now = time::OffsetDateTime::now_utc();
        let entries = backups
            .into_iter()
            .map(|b| RestorePoint {
                date: format_date(b.timestamp),
                age: format_age(now, b.timestamp),
                size: human_bytes(b.size),
                path: b.path,
            })
            .collect();
        Some(RestoreModal {
            stage: RestoreStage::Picking {
                entries,
                selected: 0,
            },
        })
    }
}

/// `YYYY-MM-DD HH:MM` — minute precision is enough for an operator to
/// recognise a restore point; seconds live in the archive filename.
/// `pub(crate)` so the Settings tab's "Last auto-backup" line reuses the
/// same formatting.
pub(crate) fn format_date(ts: time::OffsetDateTime) -> String {
    use time::macros::format_description;
    const FMT: &[time::format_description::FormatItem<'static>] =
        format_description!("[year]-[month]-[day] [hour]:[minute]");
    ts.format(&FMT)
        .unwrap_or_else(|_| "????-??-?? ??:??".to_string())
}

/// Coarse relative age — mirrors the Devices tab's "last seen" buckets.
/// `pub(crate)` so the Settings tab's "Last auto-backup" line reuses it.
pub(crate) fn format_age(now: time::OffsetDateTime, ts: time::OffsetDateTime) -> String {
    let secs = (now - ts).whole_seconds().max(0) as u64;
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        let m = secs / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else if secs < 86_400 {
        let h = secs / 3600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let d = secs / 86_400;
        format!("{d} day{} ago", if d == 1 { "" } else { "s" })
    }
}

/// Settings overlays compare paths and archive names, so they use the wider
/// configuration-dialog measure while still clamping at the terminal floor.
const MODAL_W: u16 = 82;
const STANDARD_H: u16 = 17;
const RESTORE_PICKER_H: u16 = 24;
const RESTORE_CONFIRM_H: u16 = 20;

/// Key legend for a terminal stage. Verbatim from `scope_modal`, which is
/// Archetype C's reference implementation.
const KEYS_DONE: &str = "[any key] close";

/// The one warning both restore stages have to carry. It rides
/// [`NoticeSpec::hint`] rather than a prose row because `scroll_layout`
/// allocates the tail **first**: pinned there it survives a 30-archive
/// list, where a prose row would scroll out of the viewport the moment
/// the operator walked past the eighth entry.
const DOT_D_NOTE: &str =
    "Current master is saved as .pre-restore-<ts>. Files under *.d/ not in the archive are DELETED.";

/// Archetype-C overlay for the restore flow's four stages
/// (`Picking` → `Confirming` → `Restoring` → `Submitted`).
///
/// The anchor is the tab content rect, so the header, the
/// menu card and the footer legend stay visible behind the modal —
/// nothing transient may cover either permanent surface.
/// That anchor has to land in the same commit as the
/// `ScrollBody` migration: on its own it would cut the budget and clip.
pub fn render_overlay(
    f: &mut Frame,
    anchor: Rect,
    modal: &RestoreModal,
    primary: bool,
    report_scroll: usize,
    report_max_scroll: &Cell<usize>,
) {
    let mut spec = restore_notice(modal);
    focus_confirmation(&mut spec, primary);
    match &modal.stage {
        RestoreStage::Picking { entries, selected } => {
            report_max_scroll.set(0);
            render_fixed_height(f, anchor, RESTORE_PICKER_H, |w, _| {
                restore_picker_body(&spec, entries, *selected, w)
            });
        }
        RestoreStage::Confirming { point } => {
            report_max_scroll.set(0);
            render_fixed_height(f, anchor, RESTORE_CONFIRM_H, |w, _| {
                restore_confirm_body(&spec, point, w)
            });
        }
        RestoreStage::Restoring { .. } => {
            report_max_scroll.set(0);
            render_fixed_height(f, anchor, STANDARD_H, |w, _| {
                modal_form::notice_body(&spec, w)
            });
        }
        RestoreStage::Submitted(outcome) => {
            let (message, ok) = match outcome {
                SubmitOutcome::Ok(message) => (message.as_str(), true),
                SubmitOutcome::Failed(message) => (message.as_str(), false),
            };
            render_fixed_height(f, anchor, STANDARD_H, |w, h| {
                report_body(&spec, message, ok, report_scroll, report_max_scroll, w, h)
            });
        }
    }
}

fn render_fixed_height(
    f: &mut Frame,
    anchor: Rect,
    height: u16,
    build: impl Fn(u16, u16) -> modal_form::ScrollBody,
) {
    let nominal_w = MODAL_W.min(anchor.width).saturating_sub(4);
    let expected_inner_h = height.min(anchor.height).saturating_sub(2);
    let body = build(nominal_w, expected_inner_h);
    let surface =
        modal_form::render_chrome_in(f, anchor, MODAL_W, height, "", T.text_primary, true);
    let inner = modal_form::content_rect(surface);
    let scrolls = body.scrollable
        && modal_form::will_scroll(
            inner.height as usize,
            body.head.len(),
            body.fields.len(),
            body.tail.len(),
        );
    let target_w = if scrolls {
        inner.width.saturating_sub(1)
    } else {
        inner.width
    };
    let body = if target_w == nominal_w {
        body
    } else {
        build(target_w, inner.height)
    };
    modal_form::render_scroll_body(f, inner, &body);
}

fn report_body(
    spec: &NoticeSpec,
    message: &str,
    ok: bool,
    report_scroll: usize,
    report_max_scroll: &Cell<usize>,
    width: u16,
    height: u16,
) -> modal_form::ScrollBody {
    let mut rows = FormRows::new(&spec.title, &spec.desc, width);
    let lines = crate::tui::text::wrap(message, usize::from(width).max(1));

    // Title, description, and action regions stay pinned while the report
    // consumes the remaining rows.
    const REPORT_HEAD_ROWS: usize = 3;
    const REPORT_TAIL_ROWS: usize = 4;
    let field_budget = usize::from(height)
        .saturating_sub(REPORT_HEAD_ROWS + REPORT_TAIL_ROWS)
        .max(1);
    let max_scroll = lines.len().saturating_sub(field_budget);
    report_max_scroll.set(max_scroll);
    let offset = report_scroll.min(max_scroll);
    let first = if lines.is_empty() { 0 } else { offset + 1 };
    let last = (offset + field_budget).min(lines.len());
    let status = format!(
        "Lines {first}–{last} of {} · ↑/↓ scroll · PgUp/PgDn page · Home/End jump",
        lines.len()
    );
    let tail = modal_form::form_tail(&rows, None, &status, "", &spec.actions);
    let color = if ok {
        ValueKind::Healthy.color()
    } else {
        ValueKind::Blocking.color()
    };
    for line in lines.iter().skip(offset).take(field_budget) {
        rows.line(Line::from(Span::styled(
            line.clone(),
            theme::highlight_style().bg(T.bg_elevated).fg(color),
        )));
    }
    let (mut body, _) = rows.finish(tail);
    body.fields.resize_with(field_budget, Line::default);
    body.scrollable = false;
    body
}

fn archive_name(point: &RestorePoint) -> String {
    point
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| point.path.display().to_string())
}

fn archive_columns(date: &str, size: &str, archive: &str, width: u16) -> String {
    const DATE_W: usize = 18;
    const SIZE_W: usize = 10;
    let archive_w = usize::from(width).saturating_sub(DATE_W + SIZE_W + 2);
    format!(
        "{} {} {}",
        crate::tui::text::pad(date, DATE_W),
        crate::tui::text::pad(size, SIZE_W),
        crate::tui::text::fit(archive, archive_w)
    )
}

fn archive_table_line(
    date: &str,
    size: &str,
    archive: &str,
    width: u16,
    selected: bool,
) -> Line<'static> {
    let text = crate::tui::text::pad(
        &archive_columns(date, size, archive, width),
        usize::from(width),
    );
    let style = if selected {
        theme::highlight_style()
    } else {
        theme::highlight_style().bg(T.bg_elevated)
    };
    Line::styled(text, style)
}

fn restore_picker_body(
    spec: &NoticeSpec,
    entries: &[RestorePoint],
    selected: usize,
    width: u16,
) -> modal_form::ScrollBody {
    let mut rows = FormRows::new(&spec.title, &spec.desc, width);
    for (index, point) in entries.iter().enumerate() {
        rows.choice_field(
            archive_table_line(
                &point.date,
                &point.size,
                &archive_name(point),
                width,
                index == selected,
            ),
            index == selected,
            &spec.hint,
        );
    }
    let tail = modal_form::form_tail(&rows, None, &spec.hint, "", &spec.actions);
    let (mut body, _) = rows.finish(tail);
    body.head.push(Line::styled(
        crate::tui::text::pad(
            &archive_columns("DATE", "SIZE", "ARCHIVE", width),
            usize::from(width),
        ),
        theme::table_heading_style(false),
    ));
    body
}

fn read_only_value(label: &str, value: &str, width: u16) -> Line<'static> {
    const LABEL_W: usize = 14;
    let lead = format!("{} ", crate::tui::text::pad(label, LABEL_W));
    let value = crate::tui::text::fit(value, usize::from(width).saturating_sub(LABEL_W + 1));
    Line::from(vec![
        Span::styled(
            lead,
            theme::table_heading_style(false)
                .bg(T.bg_elevated)
                .remove_modifier(ratatui::style::Modifier::BOLD),
        ),
        Span::styled(value, theme::highlight_style().bg(T.bg_elevated)),
    ])
}

fn restore_confirm_body(
    spec: &NoticeSpec,
    point: &RestorePoint,
    width: u16,
) -> modal_form::ScrollBody {
    let mut rows = FormRows::new(&spec.title, &spec.desc, width);
    rows.section_with_role("Selected archive", CardRole::History);
    rows.line(read_only_value("Archive", &archive_name(point), width));
    rows.line(read_only_value("Created", &point.date, width));
    rows.line(read_only_value("Size", &point.size, width));
    rows.spacer();
    rows.section_with_role("Restore scope", CardRole::History);
    rows.line("Replaces the complete live configuration tree.");
    let tail = modal_form::form_tail(&rows, None, &spec.hint, "", &spec.actions);
    let (mut body, _) = rows.finish(tail);
    body.fields.resize_with(11, Line::default);
    body.scrollable = false;
    body
}

/// The fixed-height renderer may rebuild one column narrower when a scrollbar
/// is needed. These specs keep their row counts stable across both widths;
/// the configuration-specific builders truncate values instead of wrapping.
fn restore_notice(modal: &RestoreModal) -> NoticeSpec {
    match &modal.stage {
        RestoreStage::Picking { entries, selected } => picking_notice(entries, *selected),
        RestoreStage::Confirming { .. } => restore_confirm_notice(),
        RestoreStage::Restoring { point } => restoring_notice(point),
        RestoreStage::Submitted(SubmitOutcome::Ok(msg)) => outcome_notice(
            "Restore \u{2014} done",
            "the config was replaced and the daemon reloaded",
            msg,
            true,
        ),
        RestoreStage::Submitted(SubmitOutcome::Failed(msg)) => {
            outcome_notice("Restore \u{2014} failed", "", msg, false)
        }
    }
}

/// The picker. Restore points are [`ChoiceRow`]s, which buys the
/// focus-following viewport and the scrollbar that the hand-rolled
/// `visible_window` + `▲ newer` / `▼ older` markers used to fake — with
/// the auto-backup retention default at 30 archives the list always
/// outgrows the field region, so this path is the normal one.
fn picking_notice(entries: &[RestorePoint], selected: usize) -> NoticeSpec {
    let choices = entries
        .iter()
        .enumerate()
        .map(|(i, e)| ChoiceRow {
            label: e.date.clone(),
            detail: Some(format!("{} \u{00b7} {}", e.age, e.size)),
            // What choosing it *means*: this row replaces the live config.
            kind: ValueKind::Blocking,
            focused: i == selected,
            note: None,
        })
        .collect();

    NoticeSpec {
        title: "Restore points".to_string(),
        desc: "Select an archive · newest first".to_string(),
        prose: Vec::new(),
        choices,
        error: None,
        hint: DOT_D_NOTE.to_string(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            Action::new("Cancel", false, ActionKind::Neutral, "")
                .on_key(crossterm::event::KeyCode::Esc),
            Action::new("Choose", false, ActionKind::Primary, "")
                .on_key(crossterm::event::KeyCode::Enter),
        ],
    }
}

fn restore_confirm_notice() -> NoticeSpec {
    NoticeSpec {
        title: "Confirm restore".to_string(),
        desc: "Replace the live full configuration tree".to_string(),
        prose: Vec::new(),
        choices: Vec::new(),
        error: None,
        hint: DOT_D_NOTE.to_string(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            Action::new("Cancel", false, ActionKind::Neutral, "")
                .on_key(crossterm::event::KeyCode::Esc),
            Action::new("Restore", false, ActionKind::Destructive, "")
                .on_key(crossterm::event::KeyCode::Char('y')),
        ],
    }
}

/// In-flight card (tui-02). Advertises NO key — no `keys` legend and no
/// action row: the handler swallows every keystroke while the restore
/// runs, and a card that promises a binding it then eats is the same
/// defect the audit filed against the profile modal. "Please wait" is the
/// honest hint, and it is pinned in the tail so it cannot scroll away.
fn restoring_notice(point: &RestorePoint) -> NoticeSpec {
    NoticeSpec {
        title: "Restore \u{2014} in progress".to_string(),
        desc: "extracting the archive and validating the staged config".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("Restoring from {} ({})\u{2026}", point.date, point.size),
                ValueKind::Caution,
            ),
            ProseRow::plain(String::new()),
            ProseRow::plain("The daemon reloads once the swap lands."),
        ],
        choices: Vec::new(),
        error: None,
        hint: "Please wait \u{2014} the dashboard stays live.".to_string(),
        // One line by construction, and this stage cannot raise a
        // validation error, so the second HINT_ROWS row would be
        // permanently blank.
        hint_rows: Some(1),
        keys: String::new(),
        actions: Vec::new(),
    }
}

/// The terminal stage of **both** flows.
///
/// A failure goes in the `error` slot rather than the prose, following
/// `scope_modal::outcome_notice`: that region hard-wraps to
/// [`modal_form::HINT_ROWS`] and the failure strings are the long ones —
/// on a prose row a rejected restore would lose the half of the message
/// that says why. Success stays prose, in the `Healthy` kind. The colour
/// still switches on `ok`; it is now the ecosystem's pair rather than the
/// bespoke `T.success` / `T.error`.
fn outcome_notice(title: &str, ok_desc: &str, msg: &str, ok: bool) -> NoticeSpec {
    let (desc, prose, error) = if ok {
        (
            ok_desc.to_string(),
            vec![ProseRow::emphasis(msg.to_string(), ValueKind::Healthy)],
            None,
        )
    } else {
        (
            "nothing further was written \u{2014} close and try again".to_string(),
            Vec::new(),
            Some(msg.to_string()),
        )
    };
    NoticeSpec {
        title: title.to_string(),
        desc,
        prose,
        choices: Vec::new(),
        error,
        hint: String::new(),
        hint_rows: None,
        keys: KEYS_DONE.to_string(),
        actions: vec![Action::new("  Close  ", false, ActionKind::Primary, "")
            .on_key(crossterm::event::KeyCode::Esc)],
    }
}

/// Archetype-C overlay for the backup flow's three stages
/// (`Confirm` → `Running` → `Submitted`). Same anchor contract as
/// [`render_overlay`]; shares [`outcome_notice`] so both flows report
/// their result in one shape.
pub fn render_backup_overlay(
    f: &mut Frame,
    anchor: Rect,
    modal: &BackupModal,
    primary: bool,
    report_scroll: usize,
    report_max_scroll: &Cell<usize>,
) {
    let mut spec = backup_notice(modal);
    focus_confirmation(&mut spec, primary);
    render_fixed_height(f, anchor, STANDARD_H, |w, h| match modal {
        BackupModal::Confirm { dir } => {
            report_max_scroll.set(0);
            backup_confirm_body(&spec, dir, w)
        }
        BackupModal::Running { .. } => {
            report_max_scroll.set(0);
            modal_form::notice_body(&spec, w)
        }
        BackupModal::Submitted { msg, ok } => {
            report_body(&spec, msg, *ok, report_scroll, report_max_scroll, w, h)
        }
    });
}

fn focus_confirmation(spec: &mut NoticeSpec, primary: bool) {
    if spec.choices.is_empty() && spec.actions.len() == 2 {
        spec.actions[0].focused = !primary;
        spec.actions[1].focused = primary;
    } else if spec.actions.len() == 1 {
        spec.actions[0].focused = true;
    }
}

fn backup_notice(modal: &BackupModal) -> NoticeSpec {
    match modal {
        BackupModal::Confirm { .. } => backup_confirm_notice(),
        BackupModal::Running { dir } => backup_running_notice(dir),
        BackupModal::Submitted { msg, ok } => outcome_notice(
            if *ok {
                "Backup \u{2014} done"
            } else {
                "Backup \u{2014} failed"
            },
            "the archive is on disk",
            msg,
            *ok,
        ),
    }
}

fn backup_confirm_notice() -> NoticeSpec {
    NoticeSpec {
        title: "Create backup".to_string(),
        desc: "Full config tree · compressed archive on disk".to_string(),
        prose: Vec::new(),
        choices: Vec::new(),
        error: None,
        hint: "Writes a durable archive on disk; live config files are not changed.".to_string(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            Action::new("Cancel", false, ActionKind::Neutral, "")
                .on_key(crossterm::event::KeyCode::Esc),
            Action::new("Create", false, ActionKind::Primary, "")
                .on_key(crossterm::event::KeyCode::Char('y')),
        ],
    }
}

fn backup_confirm_body(spec: &NoticeSpec, dir: &Path, width: u16) -> modal_form::ScrollBody {
    let mut rows = FormRows::new(&spec.title, &spec.desc, width);
    rows.section_with_role("Archive", CardRole::History);
    rows.line(read_only_value(
        "Directory",
        &dir.display().to_string(),
        width,
    ));
    rows.spacer();
    rows.line("Create an archive of the complete configuration tree?");
    let tail = modal_form::form_tail(&rows, None, &spec.hint, "", &spec.actions);
    let (mut body, _) = rows.finish(tail);
    body.fields.resize_with(8, Line::default);
    body.scrollable = false;
    body
}

/// In-flight card (tui-14), the mirror of [`restoring_notice`].
/// Advertises NO key for the same reason.
fn backup_running_notice(dir: &Path) -> NoticeSpec {
    NoticeSpec {
        title: "Backup \u{2014} in progress".to_string(),
        desc: "archiving and compressing the config tree".to_string(),
        prose: vec![
            ProseRow::plain("Backing up the config tree\u{2026}"),
            ProseRow::plain(String::new()),
            ProseRow::emphasis(
                format!("Archive written to {}", dir.display()),
                ValueKind::Identity,
            ),
        ],
        choices: Vec::new(),
        error: None,
        hint: "Please wait \u{2014} the dashboard stays live.".to_string(),
        hint_rows: Some(1),
        keys: String::new(),
        actions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::{App, Leaf};
    use time::macros::datetime;

    // ---- floor harness -------------------------------------------------
    //
    // The anchor a Settings overlay actually receives at the declared
    // 80×24 floor. `ui::layout_chunks` hands the content region
    // 24 − 4 header − 3 menu card − 1 footer = **16** rows (Settings is a
    // singleton section, so its card is 3 rows, not 5), leaving a 14-row
    // modal interior.
    //
    // Rendering against `f.area()` of a full 24-row terminal would prove
    // nothing: `overlay::centered_rect` CLAMPS, so an oversized modal is
    // silently **cut** while focus still moves onto the cut rows.
    const FLOOR_W: u16 = 80;
    const FLOOR_H: u16 = 16;

    fn dump_buffer(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn restore_buffer_at_scroll(
        stage: RestoreStage,
        width: u16,
        height: u16,
        scroll: usize,
    ) -> (ratatui::buffer::Buffer, usize) {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let modal = RestoreModal { stage };
        let max_scroll = Cell::new(0);
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal, false, scroll, &max_scroll))
            .unwrap();
        (term.backend().buffer().clone(), max_scroll.get())
    }

    fn restore_buffer_at(stage: RestoreStage, width: u16, height: u16) -> ratatui::buffer::Buffer {
        restore_buffer_at_scroll(stage, width, height, 0).0
    }

    fn restore_buffer(stage: RestoreStage) -> ratatui::buffer::Buffer {
        restore_buffer_at(stage, FLOOR_W, FLOOR_H)
    }

    fn restore_dump(stage: RestoreStage) -> String {
        dump_buffer(&restore_buffer(stage))
    }

    fn assert_selected(buffer: &ratatui::buffer::Buffer, needle: &str) {
        let y = (0..buffer.area.height)
            .find(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, *y)].symbol())
                    .collect::<String>()
                    .contains(needle)
            })
            .expect("selected archive stays visible");
        assert!(
            (0..buffer.area.width).any(|x| buffer[(x, y)].bg == crate::tui::theme::T.bg_highlight)
        );
    }

    fn backup_buffer_at_scroll(
        modal: BackupModal,
        width: u16,
        height: u16,
        scroll: usize,
    ) -> (ratatui::buffer::Buffer, usize) {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let max_scroll = Cell::new(0);
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        term.draw(|f| render_backup_overlay(f, f.area(), &modal, false, scroll, &max_scroll))
            .unwrap();
        (term.backend().buffer().clone(), max_scroll.get())
    }

    fn backup_buffer_at(modal: BackupModal, width: u16, height: u16) -> ratatui::buffer::Buffer {
        backup_buffer_at_scroll(modal, width, height, 0).0
    }

    fn backup_dump(modal: BackupModal) -> String {
        dump_buffer(&backup_buffer_at(modal, FLOOR_W, FLOOR_H))
    }

    fn modal_rect(buffer: &ratatui::buffer::Buffer) -> Rect {
        let (left, top) = (0..buffer.area.height)
            .find_map(|y| {
                (0..buffer.area.width)
                    .find(|x| buffer[(*x, y)].symbol() == "┌")
                    .map(|x| (x, y))
            })
            .expect("modal top-left border");
        let right = (left..buffer.area.width)
            .find(|x| buffer[(*x, top)].symbol() == "┐")
            .expect("modal top-right border");
        let bottom = (top..buffer.area.height)
            .find(|y| buffer[(left, *y)].symbol() == "└")
            .expect("modal bottom-left border");
        Rect::new(left, top, right - left + 1, bottom - top + 1)
    }

    /// Distinct restore points. The date doubles as each entry's **unique
    /// needle** (`00:00`, `00:01`, … `00:29`) so an assertion that the
    /// selected row is on screen cannot be satisfied by a neighbour — the
    /// Devices floor test earned this the hard way.
    fn mk_points(n: usize) -> Vec<RestorePoint> {
        (0..n)
            .map(|i| RestorePoint {
                path: PathBuf::from(format!("/b/{i}.tar.gz")),
                date: format!("2026-06-10 {:02}:{:02}", i / 60, i % 60),
                age: format!("{i} hours ago"),
                size: "1.0 KB".to_string(),
            })
            .collect()
    }

    fn a_point() -> RestorePoint {
        RestorePoint {
            path: PathBuf::from("/b/x.tar.gz"),
            date: "2026-07-12 12:00".to_string(),
            age: "1 hour ago".to_string(),
            size: "1.0 KiB".to_string(),
        }
    }

    const BACKUP_DIR: &str = "/var/lib/purge-warden/backups";

    #[test]
    fn age_buckets() {
        let now = datetime!(2026-05-27 12:00:00 UTC);
        assert_eq!(
            format_age(now, datetime!(2026-05-27 11:59:30 UTC)),
            "just now"
        );
        assert_eq!(
            format_age(now, datetime!(2026-05-27 11:58:00 UTC)),
            "2 minutes ago"
        );
        assert_eq!(
            format_age(now, datetime!(2026-05-27 11:00:00 UTC)),
            "1 hour ago"
        );
        assert_eq!(
            format_age(now, datetime!(2026-05-25 12:00:00 UTC)),
            "2 days ago"
        );
    }

    #[test]
    fn date_is_minute_precision() {
        assert_eq!(
            format_date(datetime!(2026-05-27 14:59:30 UTC)),
            "2026-05-27 14:59"
        );
    }

    // ---- stage 1/7 — restore · Picking ---------------------------------

    #[test]
    fn roomy_settings_modals_use_reference_geometry() {
        let picker = restore_buffer_at(
            RestoreStage::Picking {
                entries: mk_points(30),
                selected: 15,
            },
            164,
            46,
        );
        assert_eq!(modal_rect(&picker), Rect::new(41, 11, 82, 24));

        let confirm = restore_buffer_at(RestoreStage::Confirming { point: a_point() }, 164, 46);
        assert_eq!(modal_rect(&confirm), Rect::new(41, 13, 82, 20));

        let backup = backup_buffer_at(
            BackupModal::Confirm {
                dir: PathBuf::from(BACKUP_DIR),
            },
            164,
            46,
        );
        assert_eq!(modal_rect(&backup), Rect::new(41, 14, 82, 17));

        let result = restore_buffer_at(
            RestoreStage::Submitted(SubmitOutcome::Ok("restored".to_string())),
            164,
            46,
        );
        assert_eq!(modal_rect(&result), Rect::new(41, 14, 82, 17));
    }

    /// The two things a clip silently takes away: the operator's own
    /// cursor and the action row. Asserted on the rendered buffer, never
    /// on the line vector — the vector was correct in every past instance
    /// of this defect (`lists-modal-min-height-clip`), only the render was
    /// wrong.
    ///
    /// 30 entries is the auto-backup retention default, i.e. the steady
    /// state after a month, so the scrolling path is the normal one.
    #[test]
    fn floor_picker_keeps_the_selected_entry_and_the_action_row_together() {
        assert_selected(
            &restore_buffer(RestoreStage::Picking {
                entries: mk_points(30),
                selected: 15,
            }),
            "2026-06-10 00:15",
        );
        let dump = restore_dump(RestoreStage::Picking {
            entries: mk_points(30),
            selected: 15,
        });
        assert!(
            dump.contains("2026-06-10 00:15"),
            "the selected entry must be on screen wearing the focus bar:\n{dump}"
        );
        assert!(
            dump.contains("Choose"),
            "action row cut at the floor:\n{dump}"
        );
        assert!(
            dump.contains("Cancel"),
            "the cancel action must survive too:\n{dump}"
        );
        assert!(
            dump.contains("DATE") && dump.contains("SIZE") && dump.contains("ARCHIVE"),
            "restore points must use the reference archive table:\n{dump}"
        );
        assert!(
            dump.contains("15.tar.gz"),
            "the selected row must expose the real archive filename:\n{dump}"
        );
    }

    #[test]
    fn picker_note_states_the_dot_d_blast_radius() {
        let dump = restore_dump(RestoreStage::Picking {
            entries: mk_points(30),
            selected: 15,
        });
        assert!(
            dump.contains("*.d/") && dump.contains("DELETED"),
            "picker note must warn about .d/ deletion:\n{dump}"
        );
        assert!(
            dump.contains(".pre-restore"),
            "picker note must scope the reassurance to the master:\n{dump}"
        );
    }

    /// The note rides `NoticeSpec::hint`, which `scroll_layout` allocates
    /// **before** the field region — so walking to the end of a 30-archive
    /// list cannot scroll the deletion warning off the card. A prose row
    /// would have.
    #[test]
    fn picker_note_survives_scrolling_to_the_last_entry() {
        assert_selected(
            &restore_buffer(RestoreStage::Picking {
                entries: mk_points(30),
                selected: 29,
            }),
            "2026-06-10 00:29",
        );
        let dump = restore_dump(RestoreStage::Picking {
            entries: mk_points(30),
            selected: 29,
        });
        assert!(
            dump.contains("2026-06-10 00:29"),
            "the last entry must be reachable:\n{dump}"
        );
        assert!(
            dump.contains("DELETED"),
            "the deletion warning scrolled away with the list:\n{dump}"
        );
    }

    // ---- stage 2/7 — restore · Confirming ------------------------------

    #[test]
    fn floor_restore_confirm_states_the_blast_radius_and_keeps_its_actions() {
        let dump = restore_dump(RestoreStage::Confirming { point: a_point() });
        assert!(
            dump.contains("SELECTED ARCHIVE")
                && dump.contains("x.tar.gz")
                && dump.contains("2026-07-12 12:00")
                && dump.contains("1.0 KiB"),
            "the confirm must identify the selected archive:\n{dump}"
        );
        assert!(
            dump.contains("*.d/") && dump.contains("DELETED"),
            "confirm card must warn about .d/ deletion:\n{dump}"
        );
        assert!(
            dump.contains("master is saved as .pre-restore"),
            "reassurance must be scoped to the master:\n{dump}"
        );
        assert!(
            !dump.contains("current config is saved"),
            "the stale full-tree reassurance must be gone:\n{dump}"
        );
        assert!(
            dump.contains("Restore") && dump.contains("Cancel"),
            "confirmation actions missing:\n{dump}"
        );
    }

    // ---- stage 3/7 — restore · Restoring -------------------------------

    /// tui-02: the in-flight card must actually say something — the whole
    /// point of moving the extraction off the loop is that this frame gets
    /// painted at all — and must advertise NO key, because the handler
    /// swallows every one of them while the restore runs. A card promising
    /// `[Esc] cancel` that then eats Esc is the same defect the audit filed
    /// against the profile modal.
    #[test]
    fn floor_restoring_card_shows_progress_and_advertises_no_key() {
        let dump = restore_dump(RestoreStage::Restoring { point: a_point() });
        assert!(
            dump.contains("Restoring from 2026-07-12 12:00"),
            "the card must name the restore point it is working on:\n{dump}"
        );
        assert!(
            dump.contains("Please wait"),
            "the card must tell the operator to wait:\n{dump}"
        );
        for dead_key in ["[Esc]", "[y]", "[n]", "[Enter]", "Cancel", "Close"] {
            assert!(
                !dump.contains(dead_key),
                "the in-flight card must not advertise `{dead_key}` — it is swallowed:\n{dump}"
            );
        }
    }

    // ---- stage 4/7 — restore · Submitted -------------------------------

    #[test]
    fn floor_restore_outcome_shows_the_message_and_the_close_action() {
        let ok = restore_dump(RestoreStage::Submitted(SubmitOutcome::Ok(
            "ZZOK restored 12 files".to_string(),
        )));
        assert!(
            ok.contains("ZZOK restored 12 files"),
            "the success message must be on screen:\n{ok}"
        );
        assert!(ok.contains("Close"), "action row cut:\n{ok}");

        let bad = restore_dump(RestoreStage::Submitted(SubmitOutcome::Failed(
            "ZZBAD staged config rejected".to_string(),
        )));
        assert!(
            bad.contains("ZZBAD staged config rejected"),
            "the failure message must be on screen:\n{bad}"
        );
        assert!(bad.contains("Close"), "action row cut:\n{bad}");
    }

    #[test]
    fn submitted_failure_report_keeps_every_line_reachable_with_close_pinned() {
        let message = (0..24)
            .map(|index| format!("failure line {index:02} sentinel"))
            .collect::<Vec<_>>()
            .join("\n");
        let (first, max_scroll) = restore_buffer_at_scroll(
            RestoreStage::Submitted(SubmitOutcome::Failed(message.clone())),
            80,
            24,
            0,
        );
        let first = dump_buffer(&first);
        assert!(max_scroll > 0, "long failure must expose a scroll range");
        assert!(first.contains("failure line 00 sentinel"));
        assert!(!first.contains("failure line 23 sentinel"));
        assert!(
            first.contains("Close"),
            "close action must stay pinned:\n{first}"
        );

        let (last, observed_max) = restore_buffer_at_scroll(
            RestoreStage::Submitted(SubmitOutcome::Failed(message)),
            80,
            24,
            max_scroll,
        );
        let last = dump_buffer(&last);
        assert_eq!(observed_max, max_scroll);
        assert!(
            last.contains("failure line 23 sentinel"),
            "last failure line must be reachable:\n{last}"
        );
        assert!(
            last.contains("Close"),
            "close action must stay pinned:\n{last}"
        );
    }

    /// The outcome still switches colour on `ok`; it is now the ecosystem
    /// pair (`ValueKind::Healthy` prose vs the `error` slot) rather than
    /// the bespoke `T.success` / `T.error`, matching
    /// `scope_modal::outcome_notice`.
    #[test]
    fn outcome_colour_switches_on_ok() {
        let ok = outcome_notice("t", "d", "saved", true);
        assert!(ok.error.is_none(), "a success must not use the error slot");
        assert_eq!(
            ok.prose[0].kind,
            Some(ValueKind::Healthy),
            "ok=true message must render in the Healthy kind"
        );

        let bad = outcome_notice("t", "d", "denied", false);
        assert_eq!(
            bad.error.as_deref(),
            Some("denied"),
            "ok=false message must ride the error slot, which renders in T.error \
             and hard-wraps rather than truncating the half that says why"
        );
        assert!(bad.prose.is_empty(), "a failure must not also be prose");
    }

    // ---- stage 5/7 — backup · Confirm ----------------------------------

    #[test]
    fn floor_backup_confirm_carries_the_dir_and_keeps_its_actions() {
        let dump = backup_dump(BackupModal::Confirm {
            dir: PathBuf::from(BACKUP_DIR),
        });
        assert!(
            dump.contains("Create an archive of the complete configuration tree?"),
            "confirm card must surface the prompt:\n{dump}"
        );
        assert!(
            dump.contains(BACKUP_DIR),
            "confirm card must surface the resolved backup dir:\n{dump}"
        );
        assert!(
            dump.contains("ARCHIVE") && dump.contains("Directory"),
            "confirm card must use the archive section:\n{dump}"
        );
        assert!(
            dump.contains("Create") && dump.contains("Cancel"),
            "confirmation actions missing:\n{dump}"
        );
    }

    // ---- stage 6/7 — backup · Running ----------------------------------

    /// tui-14, the mirror of `floor_restoring_card_shows_progress_and_advertises_no_key`.
    #[test]
    fn floor_backup_running_card_shows_progress_and_advertises_no_key() {
        let dump = backup_dump(BackupModal::Running {
            dir: PathBuf::from(BACKUP_DIR),
        });
        assert!(
            dump.contains("Backing up"),
            "the card must say the backup is under way:\n{dump}"
        );
        assert!(
            dump.contains(BACKUP_DIR),
            "the card must name where the archive lands:\n{dump}"
        );
        assert!(
            dump.contains("Please wait"),
            "the card must tell the operator to wait:\n{dump}"
        );
        for dead_key in ["[Esc]", "[y]", "[n]", "[Enter]", "Cancel", "Close"] {
            assert!(
                !dump.contains(dead_key),
                "the in-flight card must not advertise `{dead_key}` — it is swallowed:\n{dump}"
            );
        }
    }

    // ---- stage 7/7 — backup · Submitted --------------------------------

    #[test]
    fn floor_backup_outcome_shows_the_message_and_the_close_action() {
        let ok = backup_dump(BackupModal::Submitted {
            msg: "ZZOK backup saved (1 entry)".to_string(),
            ok: true,
        });
        assert!(
            ok.contains("ZZOK backup saved (1 entry)"),
            "the success message must be on screen:\n{ok}"
        );
        assert!(ok.contains("Close"), "action row cut:\n{ok}");

        let bad = backup_dump(BackupModal::Submitted {
            msg: "ZZBAD permission denied".to_string(),
            ok: false,
        });
        assert!(
            bad.contains("ZZBAD permission denied"),
            "the failure message must be on screen:\n{bad}"
        );
        assert!(bad.contains("Close"), "action row cut:\n{bad}");
    }

    #[test]
    fn submitted_success_report_preserves_multiline_output() {
        let message = (0..18)
            .map(|index| format!("success line {index:02} sentinel"))
            .collect::<Vec<_>>()
            .join("\n");
        let (_, max_scroll) = backup_buffer_at_scroll(
            BackupModal::Submitted {
                msg: message.clone(),
                ok: true,
            },
            80,
            24,
            0,
        );
        assert!(max_scroll > 0, "long success must expose a scroll range");
        let (last, _) = backup_buffer_at_scroll(
            BackupModal::Submitted {
                msg: message,
                ok: true,
            },
            80,
            24,
            max_scroll,
        );
        let last = dump_buffer(&last);
        assert!(
            last.contains("success line 17 sentinel"),
            "last success line must be reachable:\n{last}"
        );
        assert!(
            last.contains("Close"),
            "close action must stay pinned:\n{last}"
        );
    }

    // ---- No red borders anywhere in this file ---------------------------

    /// Eyeball all seven stages at the floor:
    /// `cargo test --lib backup_visual_dump -- --ignored --nocapture`.
    #[test]
    #[ignore = "visual aid, not an assertion"]
    fn backup_visual_dump() {
        for (name, dump) in [
            (
                "1/7 restore · Picking (30 archives, selected 15)",
                restore_dump(RestoreStage::Picking {
                    entries: mk_points(30),
                    selected: 15,
                }),
            ),
            (
                "2/7 restore · Confirming",
                restore_dump(RestoreStage::Confirming { point: a_point() }),
            ),
            (
                "3/7 restore · Restoring",
                restore_dump(RestoreStage::Restoring { point: a_point() }),
            ),
            (
                "4/7 restore · Submitted(Ok)",
                restore_dump(RestoreStage::Submitted(SubmitOutcome::Ok(
                    "config restored from 2026-07-12 12:00; daemon reloaded".to_string(),
                ))),
            ),
            (
                "4/7 restore · Submitted(Failed)",
                restore_dump(RestoreStage::Submitted(SubmitOutcome::Failed(
                    "staged config rejected: unknown key `filterng` in [server]".to_string(),
                ))),
            ),
            (
                "5/7 backup · Confirm",
                backup_dump(BackupModal::Confirm {
                    dir: PathBuf::from(BACKUP_DIR),
                }),
            ),
            (
                "6/7 backup · Running",
                backup_dump(BackupModal::Running {
                    dir: PathBuf::from(BACKUP_DIR),
                }),
            ),
            (
                "7/7 backup · Submitted(Ok)",
                backup_dump(BackupModal::Submitted {
                    msg: "backup saved: 2026-07-30_120000.tar.gz (14 entries)".to_string(),
                    ok: true,
                }),
            ),
        ] {
            println!("\n=== {name} ===\n{dump}");
        }
    }

    /// The chrome comes from `modal_form::render_chrome_in` and
    /// `modal_form::render_scroll_body`, which own the border, its colour,
    /// scrolling, and the elevated surface. No red
    /// border, no wrapping body, and "zero hand-rolled colour"
    /// as a test rather than a claim in a commit message.
    ///
    /// Needles are split with `concat!` so this assertion cannot match
    /// itself — the house pattern, see `scope_modal`.
    #[test]
    fn no_red_border_and_no_hand_rolled_chrome_in_this_module() {
        let src = include_str!("backup_restore_modal.rs");
        for needle in [
            concat!("Borders", "::ALL"),
            concat!("T", ".brand_red"),
            concat!("Wrap", " { trim"),
            concat!("Color", "::Rgb("),
            concat!("Style::default()", ".fg("),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in backup_restore_modal.rs — the chrome and the colour \
                 belong in modal_form"
            );
        }
    }

    // ---- The permanent orientation surfaces ------------------------------
    //
    fn full_frame_dump(app: &mut App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::tui::ui::render(f, app)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// The observable form of the anchor rule: opening the overlay must
    /// change the content region while preserving the header and the shared
    /// contextual footer. Comparing the two
    /// frames row-by-row rather than grepping for a legend needle is
    /// deliberate — a needle that also occurs inside the modal gives a
    /// false green.
    fn assert_only_the_content_region_changed(before: &str, after: &str, what: &str, app: &App) {
        let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
        assert_eq!(b.len(), a.len(), "frame height changed");
        let content = crate::tui::ui::content_area_for_test(
            ratatui::layout::Rect::new(0, 0, crate::tui::text::width(b[0]) as u16, b.len() as u16),
            &settings_app(),
        );
        for (y, (bl, al)) in b.iter().zip(a.iter()).enumerate() {
            if y + 1 < b.len() && !(content.y as usize..content.bottom() as usize).contains(&y) {
                assert_eq!(
                    bl, al,
                    "{what} repainted row {y}, which is header / menu card / footer \
                     — the overlay anchors on the content rect and must not occlude \
                     either permanent surface\n--- without the overlay ---\n{before}\n\
                     --- with the overlay ---\n{after}"
                );
            }
        }
        // The footer changes grammar with the overlay, but remains entirely
        // owned by the shared footer renderer and retains the version.
        let mut footer = ratatui::Terminal::new(ratatui::backend::TestBackend::new(
            crate::tui::text::width(b[0]) as u16,
            1,
        ))
        .unwrap();
        footer
            .draw(|f| crate::tui::ui::render_footer_for_test(f, f.area(), app))
            .unwrap();
        let expected = dump_buffer(footer.backend().buffer());
        assert_eq!(a.last().unwrap(), &expected.lines().next().unwrap());
        assert!(a
            .last()
            .unwrap()
            .contains(concat!("v", env!("CARGO_PKG_VERSION"))));
        // Control arm: if the overlay did not draw at all the loop above
        // passes vacuously. Prove the frames really do differ somewhere.
        assert_ne!(
            before, after,
            "{what} changed nothing — the overlay did not render, so the \
             assertion above proved nothing"
        );
    }

    fn settings_app() -> App {
        let mut app = App::new();
        app.active_leaf = Leaf::Settings;
        app
    }

    #[test]
    fn restore_overlay_never_occludes_the_menu_card_or_the_footer_legend() {
        let mut app = settings_app();
        let before = full_frame_dump(&mut app, 80, 24);
        app.settings.restore_modal = Some(RestoreModal {
            stage: RestoreStage::Picking {
                entries: mk_points(30),
                selected: 15,
            },
        });
        let after = full_frame_dump(&mut app, 80, 24);
        assert_only_the_content_region_changed(&before, &after, "the restore picker", &app);
    }

    #[test]
    fn backup_overlay_never_occludes_the_menu_card_or_the_footer_legend() {
        let mut app = settings_app();
        let before = full_frame_dump(&mut app, 80, 24);
        app.settings.backup_modal = Some(BackupModal::Confirm {
            dir: PathBuf::from(BACKUP_DIR),
        });
        let after = full_frame_dump(&mut app, 80, 24);
        assert_only_the_content_region_changed(&before, &after, "the backup confirm", &app);
    }
}
