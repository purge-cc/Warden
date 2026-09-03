//! [`RetiredEntry`] — id retirement policy.
//!
//! When an entity is deleted, its id enters a 90-day quarantine list in
//! the config. Attempting to create a new entity with a retired id inside
//! that window fails with [`crate::config::error::ConfigError::IdRecentlyRetired`]
//! so that stale references elsewhere (stats archives, external docs,
//! muscle memory of the admin) don't silently land on a new, unrelated
//! entity.
//!
//! After 90 days the id can be reused. Nothing prunes the ledger
//! automatically — no writer touches `[[retired]]`, and the validator does
//! not drop expired entries during the check pass — so it grows until an
//! operator removes expired entries by hand.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::id::Id;

/// The kinds of entities subject to id retirement. One string per kind
/// keeps the TOML surface ergonomic (`type = "device"` vs a typed enum
/// discriminator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RetiredType {
    Blocklist,
    Profile,
    Device,
    Group,
    Subnet,
    Schedule,
    AdminRule,
}

/// ```toml
/// [[retired]]
/// id = "legacy-iot"
/// type = "group"
/// retired_at = "2026-01-15T00:00:00Z"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredEntry {
    pub id: Id,
    #[serde(rename = "type")]
    pub entity_type: RetiredType,
    #[serde(with = "time::serde::rfc3339")]
    pub retired_at: OffsetDateTime,
}

/// How long a retired id stays quarantined before reuse is allowed.
pub const RETIREMENT_WINDOW_DAYS: i64 = 90;

impl RetiredEntry {
    /// True if `retired_at` is inside the retirement window measured from
    /// `now`.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        now - self.retired_at < time::Duration::days(RETIREMENT_WINDOW_DAYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn retired_entry_deserialises() {
        let r: RetiredEntry = toml::from_str(
            r#"
id = "legacy-iot"
type = "group"
retired_at = "2026-01-15T00:00:00Z"
"#,
        )
        .unwrap();
        assert_eq!(r.id.as_str(), "legacy-iot");
        assert_eq!(r.entity_type, RetiredType::Group);
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<RetiredEntry>(
            r#"
id = "x"
type = "device"
retired_at = "2026-01-15T00:00:00Z"
reason = "unexpected"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn unknown_type_rejected() {
        let err = toml::from_str::<RetiredEntry>(
            r#"
id = "x"
type = "widget"
retired_at = "2026-01-15T00:00:00Z"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn active_within_window() {
        let r = RetiredEntry {
            id: Id::new("x").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2026-04-01 00:00:00 UTC),
        };
        let now = datetime!(2026-04-22 00:00:00 UTC);
        assert!(r.is_active(now));
    }

    #[test]
    fn expired_after_window() {
        let r = RetiredEntry {
            id: Id::new("x").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2026-01-01 00:00:00 UTC),
        };
        let now = datetime!(2026-04-22 00:00:00 UTC); // 111 days later
        assert!(!r.is_active(now));
    }

    #[test]
    fn boundary_89_days_still_active() {
        let r = RetiredEntry {
            id: Id::new("x").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2026-01-01 00:00:00 UTC),
        };
        let now = datetime!(2026-03-31 23:59:59 UTC); // 89d 23h 59m 59s
        assert!(r.is_active(now));
    }

    #[test]
    fn boundary_exactly_90_days_expired() {
        // The check is strict `<` not `<=` so exactly 90 days is expired.
        let r = RetiredEntry {
            id: Id::new("x").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2026-01-01 00:00:00 UTC),
        };
        let now = datetime!(2026-04-01 00:00:00 UTC); // exactly 90 days
        assert!(!r.is_active(now));
    }
}
