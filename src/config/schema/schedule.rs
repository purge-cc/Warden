//! [`Schedule`] — time-window profile override for a device or group.
//!
//! Schedules override the underlying device/group/subnet resolution for
//! the duration of their active window (resolver level 2).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::id::Id;

/// What kind of entity the schedule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleTargetType {
    Device,
    Group,
}

/// ```toml
/// [[schedules]]
/// id = "kids-night"
/// display_name = "Kids: night lockdown"
/// target_type = "group"
/// target_id = "kids"
/// profile = "kids-night"
/// days = ["all"]
/// hours = "21:00-07:00"
/// expires_at = "2026-12-31T23:59:59Z"
/// ```
///
/// `days` accepts the same vocabulary as the legacy schedule engine:
/// `all` / `weekdays` / `weekends` or a list of abbreviations
/// (`mon`, `tue`, …). `hours` is `HH:MM-HH:MM` with midnight wrap
/// (`22:00-06:00` spans two calendar days). Both fields are validated
/// semantically in [`super::validator`].
///
/// `expires_at` is optional. When set, the schedule stops matching after
/// that instant (`ParsedSchedule::is_active` checks expiry first), so an
/// expired row on disk is inert. The validator WARNs on — never refuses —
/// an already-expired entry: refusing would brick boot/reload/CLI for a
/// row that no longer does anything. Expired rows are pruned from disk by the daemon's 60-second schedule
/// tick and by `warden device quiet`'s pre-clean; `warden schedule
/// remove <id>` drops one on demand.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub id: Id,
    pub display_name: String,
    pub target_type: ScheduleTargetType,
    pub target_id: Id,
    /// Profile to overlay during the active window.
    pub profile: Id,
    pub days: Vec<String>,
    pub hours: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_schedule_deserialises() {
        let toml_src = r#"
id = "kids-night"
display_name = "Kids night"
target_type = "group"
target_id = "kids"
profile = "kids-night"
days = ["all"]
hours = "21:00-07:00"
"#;
        let s: Schedule = toml::from_str(toml_src).unwrap();
        assert_eq!(s.id.as_str(), "kids-night");
        assert_eq!(s.target_type, ScheduleTargetType::Group);
        assert_eq!(s.target_id.as_str(), "kids");
        assert_eq!(s.days, vec!["all"]);
        assert_eq!(s.hours, "21:00-07:00");
        assert!(s.expires_at.is_none());
    }

    #[test]
    fn device_target_parses() {
        let s: Schedule = toml::from_str(
            r#"
id = "focus"
display_name = "Focus mode"
target_type = "device"
target_id = "edo-laptop"
profile = "focus-only"
days = ["weekdays"]
hours = "09:00-12:00"
"#,
        )
        .unwrap();
        assert_eq!(s.target_type, ScheduleTargetType::Device);
    }

    #[test]
    fn expires_at_parses_rfc3339() {
        let s: Schedule = toml::from_str(
            r#"
id = "holiday"
display_name = "Holiday"
target_type = "group"
target_id = "kids"
profile = "kids-holiday"
days = ["all"]
hours = "00:00-23:59"
expires_at = "2026-12-31T23:59:59Z"
"#,
        )
        .unwrap();
        assert!(s.expires_at.is_some());
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Schedule>(
            r#"
id = "x"
display_name = "x"
target_type = "group"
target_id = "k"
profile = "k"
days = ["all"]
hours = "00:00-23:59"
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn unknown_target_type_rejected() {
        let err = toml::from_str::<Schedule>(
            r#"
id = "x"
display_name = "x"
target_type = "panel"
target_id = "k"
profile = "k"
days = ["all"]
hours = "00:00-23:59"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }
}
