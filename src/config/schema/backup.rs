//! [`BackupConfig`] — the `[backup]` section: where `warden config backup`
//! writes archives and where the TUI restore picker reads them.
//!
//! Tooling-only — the daemon never reads this section. Fully optional;
//! omit `[backup]` from the master config and the directory defaults to
//! `<config-parent>/backups` (the historical `warden config backup`
//! default, so existing archives stay where operators expect them).
//!
//! Sprint 4 (`v0.20.0-auto-backup-cli`) extends this with five optional
//! scheduler fields driven by the `purge-warden-backup.timer` systemd
//! unit. Spec: `_docs/features/backup_restore_post_v1.md` §5 Q1-Q7.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Minimum allowed `auto_interval`.
const MIN_INTERVAL_HOURS: u64 = 1;
/// Maximum allowed `auto_interval` (30 days).
const MAX_INTERVAL_HOURS: u64 = 720;
/// Default `disable_after_failures` when the field is absent.
const DEFAULT_DISABLE_AFTER_FAILURES: u32 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfig {
    /// Directory for backup archives + the TUI restore picker. `None`
    /// (the default) resolves to `<config-parent>/backups`.
    #[serde(default)]
    pub dir: Option<PathBuf>,

    /// Q1+Q2: auto-backup interval. Format `[0-9]+(h|d)`, range
    /// 1h..=720h (30d). Absent ⇒ auto-backup off (the systemd `.timer`
    /// still wakes up hourly, but `--auto` exits 0 without running).
    #[serde(default)]
    pub auto_interval: Option<String>,

    /// Q2 secondary toggle: when true (and a Sprint 6 `.path` unit is
    /// installed) a backup is triggered on every config mutation.
    /// Sprint 4 only parses this; the action wiring lands later.
    #[serde(default)]
    pub on_change: Option<bool>,

    /// Q3: keep at most N timestamped archives. `None` or `Some(0)`
    /// ⇒ unbounded. OR'd with [`Self::retention_days`].
    #[serde(default)]
    pub retention_count: Option<u32>,

    /// Q3: drop archives older than D days. `None` or `Some(0)`
    /// ⇒ unbounded. OR'd with [`Self::retention_count`].
    #[serde(default)]
    pub retention_days: Option<u32>,

    /// Q5: auto-disable the scheduler after N consecutive auto-backup
    /// failures. `None` ⇒ default 3. `Some(0)` ⇒ never auto-disable.
    #[serde(default)]
    pub disable_after_failures: Option<u32>,
}

impl BackupConfig {
    /// Resolve the effective backup directory: the configured `dir` if
    /// set, else `<config-parent>/backups`. Single source of the default
    /// so the CLI (`backup`, `restore --list`) and the TUI agree.
    pub fn resolve_dir(&self, config_path: &Path) -> PathBuf {
        self.dir.clone().unwrap_or_else(|| {
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("backups")
        })
    }

    /// Parse [`Self::auto_interval`] into a [`time::Duration`].
    /// `Ok(None)` if the field is absent (⇒ scheduler off).
    pub fn auto_interval_parsed(&self) -> Result<Option<time::Duration>, IntervalParseError> {
        match self.auto_interval.as_deref() {
            None => Ok(None),
            Some(s) => parse_duration(s).map(Some),
        }
    }

    /// Effective threshold for failure auto-disable. `None` ⇒ 3.
    /// `Some(0)` ⇒ 0, which the scheduler treats as "never disable"
    /// (mirrors the retention 0-sentinel pattern).
    pub fn disable_threshold(&self) -> u32 {
        self.disable_after_failures
            .unwrap_or(DEFAULT_DISABLE_AFTER_FAILURES)
    }
}

/// Errors returned by [`parse_duration`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntervalParseError {
    #[error("auto_interval is empty")]
    Empty,
    #[error("auto_interval {input:?} must end in `h` or `d`")]
    BadSuffix { input: String },
    #[error("auto_interval {input:?} numeric part is not a positive integer")]
    BadNumber { input: String },
    #[error("auto_interval {hours}h out of range (must be {min}h..={max}h)",
        min = MIN_INTERVAL_HOURS, max = MAX_INTERVAL_HOURS)]
    OutOfRange { hours: u64 },
    #[error("auto_interval {input:?} overflows u64 hours")]
    Overflow { input: String },
}

/// Parse `[0-9]+(h|d)` into a [`time::Duration`].
///
/// Range-checked against 1h..=720h. Days are converted to hours
/// (`Nd` ≡ `(N*24)h`) before the range check, so `30d` is the
/// canonical maximum.
pub fn parse_duration(s: &str) -> Result<time::Duration, IntervalParseError> {
    if s.is_empty() {
        return Err(IntervalParseError::Empty);
    }
    let bytes = s.as_bytes();
    let suffix = bytes[bytes.len() - 1];
    let (multiplier, suffix_ok) = match suffix {
        b'h' => (1u64, true),
        b'd' => (24u64, true),
        _ => (0, false),
    };
    if !suffix_ok {
        return Err(IntervalParseError::BadSuffix {
            input: s.to_string(),
        });
    }
    let num_str = &s[..s.len() - 1];
    if num_str.is_empty() {
        return Err(IntervalParseError::BadNumber {
            input: s.to_string(),
        });
    }
    let n: u64 = num_str.parse().map_err(|_| IntervalParseError::BadNumber {
        input: s.to_string(),
    })?;
    let hours = n
        .checked_mul(multiplier)
        .ok_or_else(|| IntervalParseError::Overflow {
            input: s.to_string(),
        })?;
    if !(MIN_INTERVAL_HOURS..=MAX_INTERVAL_HOURS).contains(&hours) {
        return Err(IntervalParseError::OutOfRange { hours });
    }
    Ok(time::Duration::hours(hours as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir_is_config_parent_backups() {
        let cfg = BackupConfig::default();
        assert_eq!(
            cfg.resolve_dir(Path::new("/etc/purge-warden/config.toml")),
            PathBuf::from("/etc/purge-warden/backups")
        );
    }

    #[test]
    fn explicit_dir_wins() {
        let cfg = BackupConfig {
            dir: Some(PathBuf::from("/srv/backups")),
            ..Default::default()
        };
        assert_eq!(
            cfg.resolve_dir(Path::new("/etc/purge-warden/config.toml")),
            PathBuf::from("/srv/backups")
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<BackupConfig>("mystery = 1\n");
        assert!(err.is_err(), "deny_unknown_fields must reject typos");
    }

    // ── parse_duration ────────────────────────────────────────────────

    #[test]
    fn parse_duration_accepts_24h() {
        assert_eq!(parse_duration("24h").unwrap(), time::Duration::hours(24));
    }

    #[test]
    fn parse_duration_accepts_7d() {
        assert_eq!(parse_duration("7d").unwrap(), time::Duration::hours(168));
    }

    #[test]
    fn parse_duration_accepts_1h_lower_bound() {
        assert_eq!(parse_duration("1h").unwrap(), time::Duration::hours(1));
    }

    #[test]
    fn parse_duration_accepts_720h_upper_bound() {
        assert_eq!(parse_duration("720h").unwrap(), time::Duration::hours(720));
    }

    #[test]
    fn parse_duration_accepts_30d_upper_bound() {
        assert_eq!(parse_duration("30d").unwrap(), time::Duration::hours(720));
    }

    #[test]
    fn parse_duration_rejects_0h() {
        assert!(matches!(
            parse_duration("0h"),
            Err(IntervalParseError::OutOfRange { hours: 0 })
        ));
    }

    #[test]
    fn parse_duration_rejects_721h() {
        assert!(matches!(
            parse_duration("721h"),
            Err(IntervalParseError::OutOfRange { hours: 721 })
        ));
    }

    #[test]
    fn parse_duration_rejects_31d() {
        assert!(matches!(
            parse_duration("31d"),
            Err(IntervalParseError::OutOfRange { hours: 744 })
        ));
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(matches!(parse_duration(""), Err(IntervalParseError::Empty)));
        assert!(matches!(
            parse_duration("24m"),
            Err(IntervalParseError::BadSuffix { .. })
        ));
        assert!(matches!(
            parse_duration("abc"),
            Err(IntervalParseError::BadSuffix { .. })
        ));
        assert!(matches!(
            parse_duration("h"),
            Err(IntervalParseError::BadNumber { .. })
        ));
        assert!(matches!(
            parse_duration("d"),
            Err(IntervalParseError::BadNumber { .. })
        ));
        assert!(matches!(
            parse_duration("-5h"),
            Err(IntervalParseError::BadNumber { .. })
        ));
    }

    // ── BackupConfig helpers ──────────────────────────────────────────

    #[test]
    fn auto_interval_absent_means_off() {
        let cfg = BackupConfig::default();
        assert_eq!(cfg.auto_interval_parsed().unwrap(), None);
    }

    #[test]
    fn auto_interval_parsed_passes_through() {
        let cfg = BackupConfig {
            auto_interval: Some("12h".into()),
            ..Default::default()
        };
        assert_eq!(
            cfg.auto_interval_parsed().unwrap(),
            Some(time::Duration::hours(12))
        );
    }

    #[test]
    fn disable_after_failures_defaults_3() {
        let cfg = BackupConfig::default();
        assert_eq!(cfg.disable_threshold(), 3);
    }

    #[test]
    fn disable_after_failures_zero_never_disables() {
        // `Some(0)` is the operator-opt-out sentinel — matches the
        // retention `0 = unbounded` convention.
        let cfg = BackupConfig {
            disable_after_failures: Some(0),
            ..Default::default()
        };
        assert_eq!(cfg.disable_threshold(), 0);
    }

    #[test]
    fn parses_full_locked_block() {
        // The exact Q7 TOML from the design doc, minus the `dir` field
        // (no environment context here — just verifies the new fields
        // all parse to the documented defaults).
        let src = r#"
auto_interval          = "24h"
on_change              = false
retention_count        = 30
retention_days         = 90
disable_after_failures = 3
"#;
        let cfg: BackupConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.auto_interval.as_deref(), Some("24h"));
        assert_eq!(cfg.on_change, Some(false));
        assert_eq!(cfg.retention_count, Some(30));
        assert_eq!(cfg.retention_days, Some(90));
        assert_eq!(cfg.disable_after_failures, Some(3));
        assert_eq!(
            cfg.auto_interval_parsed().unwrap(),
            Some(time::Duration::hours(24))
        );
        assert_eq!(cfg.disable_threshold(), 3);
    }

    #[test]
    fn partial_block_keeps_defaults_for_omitted_fields() {
        let cfg: BackupConfig = toml::from_str(r#"dir = "/srv/x""#).unwrap();
        assert_eq!(cfg.dir.as_deref(), Some(Path::new("/srv/x")));
        assert_eq!(cfg.auto_interval, None);
        assert_eq!(cfg.on_change, None);
        assert_eq!(cfg.retention_count, None);
        assert_eq!(cfg.retention_days, None);
        assert_eq!(cfg.disable_after_failures, None);
    }
}
