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
//! Both flows are **Archetype C** (§4.61 §4): [`NoticeSpec`] →
//! `modal_form::notice_body` → `modal_form::render_modal`, anchored on the
//! tab content rect per **D18**. Seven stages across the two — four
//! restore, three backup — and every one of them is a `NoticeSpec`.
//!
//! ## State machine
//! ```text
//! Picking { entries, selected } ──Enter──▶ Confirming { point }
//!                               ──Esc──▶ closed
//! Confirming { point }          ──[y]──▶ Restoring { point }
//!                               ──[n / Esc]──▶ closed
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

use std::path::{Path, PathBuf};

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{
    self, Action, ActionKind, ChoiceRow, NoticeSpec, ProseRow, ValueKind,
};

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
    /// card must not advertise one. A second `y` would race a second
    /// `create_backup` against the same backup dir (which, unlike the
    /// `run_backup_managed` CLI path, takes no lock), and an `Esc` would only
    /// hide a card whose outcome is still coming.
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
/// same formatting (Sprint 5).
pub(crate) fn format_date(ts: time::OffsetDateTime) -> String {
    use time::macros::format_description;
    const FMT: &[time::format_description::FormatItem<'static>] =
        format_description!("[year]-[month]-[day] [hour]:[minute]");
    ts.format(&FMT)
        .unwrap_or_else(|_| "????-??-?? ??:??".to_string())
}

/// Coarse relative age — mirrors the Devices tab's "last seen" buckets.
/// `pub(crate)` so the Settings tab's "Last auto-backup" line reuses it
/// (Sprint 5).
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

/// Ecosystem modal width (§4.61 Archetype C). 64 is the house figure every
/// migrated overlay uses — interior 62, or 61 once the body scrolls.
const MODAL_W: u16 = 64;

/// Key legend for a terminal stage. Verbatim from `scope_modal`, which is
/// Archetype C's reference implementation.
const KEYS_DONE: &str = "[any key] close";

/// The one warning both restore stages have to carry. It rides
/// [`NoticeSpec::hint`] rather than a prose row because `scroll_layout`
/// allocates the tail **first**: pinned there it survives a 30-archive
/// list, where a prose row would scroll out of the viewport the moment
/// the operator walked past the eighth entry.
const DOT_D_NOTE: &str =
    "Master saved as .pre-restore-<ts>. Files under *.d/ not in the archive are DELETED.";

/// Archetype-C overlay for the restore flow's four stages
/// (`Picking` → `Confirming` → `Restoring` → `Submitted`).
///
/// §4.61 **D18**: the anchor is the tab content rect, so the header, the
/// menu card and the footer legend stay visible behind the modal —
/// §4.62 **N1** forbids anything transient from covering the last two.
/// **D18′** is why the anchor lands in the same commit as the
/// `ScrollBody` migration: on its own it would cut the budget and clip.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &RestoreModal) {
    modal_form::render_modal(f, anchor, MODAL_W, |w| {
        (modal_form::notice_body(&restore_notice(modal), w), ())
    });
}

/// Per §2.1 of the modal contract a body's **row count** must depend only
/// on the spec, never on the width — `render_modal` builds twice, at
/// `width - 2` and again at `width - 3` when the body scrolls, and a count
/// that differed between the two passes would mis-size the frame. None of
/// these stages takes a width at all, which makes that structurally
/// impossible rather than merely true today.
fn restore_notice(modal: &RestoreModal) -> NoticeSpec {
    match &modal.stage {
        RestoreStage::Picking { entries, selected } => picking_notice(entries, *selected),
        RestoreStage::Confirming { point } => restore_confirm_notice(point),
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
        title: "Restore config from backup".to_string(),
        desc: "pick a restore point \u{2014} this replaces the live config".to_string(),
        prose: Vec::new(),
        choices,
        error: None,
        hint: DOT_D_NOTE.to_string(),
        hint_rows: None,
        keys: "[\u{2191}/\u{2193} or j/k] choose".to_string(),
        actions: vec![
            Action::new("  [Esc] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [Enter] Restore  ", false, ActionKind::Destructive, ""),
        ],
    }
}

/// D7′: the input contract is unchanged — this stage still answers to a
/// single `y` / `n`, and the action labels spell those keys rather than
/// implying `Enter`.
fn restore_confirm_notice(point: &RestorePoint) -> NoticeSpec {
    NoticeSpec {
        title: "Confirm restore".to_string(),
        desc: "this replaces the live config and reloads the daemon".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("Restore from {} ({})?", point.date, point.size),
                ValueKind::Blocking,
            ),
            ProseRow::plain(String::new()),
            ProseRow::plain("Files under *.d/ not in the archive are DELETED."),
        ],
        choices: Vec::new(),
        error: None,
        hint: "Your current master is saved as .pre-restore-<ts>.".to_string(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            Action::new("  [n / Esc] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [y] Restore  ", false, ActionKind::Destructive, ""),
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
        actions: vec![Action::new("  Close  ", false, ActionKind::Primary, "")],
    }
}

/// Archetype-C overlay for the backup flow's three stages
/// (`Confirm` → `Running` → `Submitted`). Same anchor contract as
/// [`render_overlay`]; shares [`outcome_notice`] so both flows report
/// their result in one shape.
pub fn render_backup_overlay(f: &mut Frame, anchor: Rect, modal: &BackupModal) {
    modal_form::render_modal(f, anchor, MODAL_W, |w| {
        (modal_form::notice_body(&backup_notice(modal), w), ())
    });
}

fn backup_notice(modal: &BackupModal) -> NoticeSpec {
    match modal {
        BackupModal::Confirm { dir } => backup_confirm_notice(dir),
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

/// The context line surfaces the resolved backup dir so the operator sees
/// where the archive will land before pressing `y`.
fn backup_confirm_notice(dir: &Path) -> NoticeSpec {
    NoticeSpec {
        title: "Confirm backup".to_string(),
        desc: "archives the whole config tree \u{2014} nothing is overwritten".to_string(),
        prose: vec![
            ProseRow::plain("Back up the config tree now?"),
            ProseRow::plain(String::new()),
            ProseRow::emphasis(
                format!("Archive written to {}", dir.display()),
                ValueKind::Identity,
            ),
        ],
        choices: Vec::new(),
        error: None,
        hint: String::new(),
        hint_rows: None,
        keys: String::new(),
        actions: vec![
            Action::new("  [n / Esc] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [y] Back up  ", false, ActionKind::Primary, ""),
        ],
    }
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

    fn restore_dump(stage: RestoreStage) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let modal = RestoreModal { stage };
        let mut term = Terminal::new(TestBackend::new(FLOOR_W, FLOOR_H)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    fn backup_dump(modal: BackupModal) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(FLOOR_W, FLOOR_H)).unwrap();
        term.draw(|f| render_backup_overlay(f, f.area(), &modal))
            .unwrap();
        dump_buffer(term.backend().buffer())
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

    /// The focus bar `modal_form` paints in front of the focused row.
    /// Asserting on `FOCUS + label` is what makes a needle discriminating:
    /// the bare label also appears on every unfocused row.
    const FOCUS: &str = "\u{258c} ";

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
        let dump = restore_dump(RestoreStage::Picking {
            entries: mk_points(30),
            selected: 15,
        });
        assert!(
            dump.contains(&format!("{FOCUS}2026-06-10 00:15")),
            "the selected entry must be on screen wearing the focus bar:\n{dump}"
        );
        assert!(
            dump.contains("[Enter] Restore"),
            "action row cut at the floor:\n{dump}"
        );
        assert!(
            dump.contains("[Esc] Cancel"),
            "the cancel action must survive too:\n{dump}"
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
        let dump = restore_dump(RestoreStage::Picking {
            entries: mk_points(30),
            selected: 29,
        });
        assert!(
            dump.contains(&format!("{FOCUS}2026-06-10 00:29")),
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
            dump.contains("Restore from 2026-07-12 12:00 (1.0 KiB)?"),
            "the confirm must name the point it would restore:\n{dump}"
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
        // D7': the input contract is still a single `y` / `n`.
        assert!(
            dump.contains("[y] Restore") && dump.contains("[n / Esc] Cancel"),
            "action row cut, or it stopped spelling the y/n contract:\n{dump}"
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
            dump.contains("Back up the config tree now?"),
            "confirm card must surface the prompt:\n{dump}"
        );
        assert!(
            dump.contains(BACKUP_DIR),
            "confirm card must surface the resolved backup dir:\n{dump}"
        );
        assert!(
            dump.contains("[y] Back up") && dump.contains("[n / Esc] Cancel"),
            "action row cut, or it stopped spelling the y/n contract:\n{dump}"
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

    // ---- D15 — no red borders anywhere in this file --------------------

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

    /// The chrome now comes from `modal_form::render_modal`, which owns
    /// the border, its colour and the elevated surface. **D15** (no red
    /// border), **D13** (no wrapping body) and "zero hand-rolled colour"
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

    // ---- D18 / §4.62 N1 — the permanent orientation surfaces -----------
    //
    // At the 80×24 floor `ui::layout_chunks` splits the frame into
    // header 4 (rows 0..=3) · menu card 3 (rows 4..=6, Settings is a
    // singleton section) · content 16 (rows 7..=22) · footer 1 (row 23).
    // Everything outside 7..=22 is a permanent affordance that nothing
    // transient may repaint.
    const CONTENT_ROWS: std::ops::RangeInclusive<usize> = 7..=22;

    fn full_frame_dump(app: &App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::tui::ui::render(f, app)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// The observable form of D18 and N1: opening the overlay must change
    /// the content region and **nothing else**. Comparing the two frames
    /// row-by-row rather than grepping for a legend needle is deliberate —
    /// a needle that also occurs inside the modal gives a false green, and
    /// this workstream has shipped that mistake twice.
    fn assert_only_the_content_region_changed(before: &str, after: &str, what: &str) {
        let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
        assert_eq!(b.len(), a.len(), "frame height changed");
        for (y, (bl, al)) in b.iter().zip(a.iter()).enumerate() {
            if !CONTENT_ROWS.contains(&y) {
                assert_eq!(
                    bl, al,
                    "{what} repainted row {y}, which is header / menu card / footer \
                     — D18 anchors on the content rect and N1 forbids occluding either \
                     permanent surface\n--- without the overlay ---\n{before}\n\
                     --- with the overlay ---\n{after}"
                );
            }
        }
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
        let before = full_frame_dump(&app, 80, 24);
        app.settings.restore_modal = Some(RestoreModal {
            stage: RestoreStage::Picking {
                entries: mk_points(30),
                selected: 15,
            },
        });
        let after = full_frame_dump(&app, 80, 24);
        assert_only_the_content_region_changed(&before, &after, "the restore picker");
    }

    #[test]
    fn backup_overlay_never_occludes_the_menu_card_or_the_footer_legend() {
        let mut app = settings_app();
        let before = full_frame_dump(&app, 80, 24);
        app.settings.backup_modal = Some(BackupModal::Confirm {
            dir: PathBuf::from(BACKUP_DIR),
        });
        let after = full_frame_dump(&app, 80, 24);
        assert_only_the_content_region_changed(&before, &after, "the backup confirm");
    }
}
