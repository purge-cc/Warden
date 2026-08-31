//! `warden config …` subcommands.
//!
//! Split into one file per action to keep each handler focused:
//! - [`show`] — print merged config, optionally annotated / resolved / filtered.
//! - [`lint`] — validate without touching the daemon.
//! - [`diff`] — structured diff between two v1 config files.
//! - [`edit`] — open config in `$EDITOR` then validate.
//! - [`backup`] — timestamped tar.gz snapshot of the config tree.
//! - [`restore`] — staged replace of the live config from a tar.gz.
//! - [`render_default`] — print the built-in scaffold config (packaging seed).

pub mod backup;
pub mod diff;
pub mod edit;
pub mod lint;
pub mod render_default;
pub mod restore;
pub mod show;

pub use backup::{
    create_backup, latest_archive, list_backups, resolved_backup_dir, run_backup,
    run_backup_managed, run_list_restore_points, run_reset_auto_failure, BackupEntry, BackupReport,
};
pub use diff::run_diff;
pub use edit::run_edit;
pub use lint::run_lint;
pub use render_default::run_render_default;
pub use restore::{restore_archive, run_restore, RestoreOutcome};
pub use show::run_show;

use time::format_description::FormatItem;
use time::macros::format_description;

/// Shared backup-archive / pre-restore timestamp format
/// (`YYYYMMDDThhmmssZ`): filesystem-safe and lexicographically sortable.
/// Used for backup archive naming, restore's `.pre-restore-<ts>` suffix,
/// and parsing archive names back in [`backup::list_backups`].
pub(crate) const TIMESTAMP_FORMAT: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");
