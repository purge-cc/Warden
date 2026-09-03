//! Schedule matching — day-of-week + time-range evaluation.
//!
//! Schedules are parsed once from config and evaluated every 60 seconds
//! by the background profile-rebuild task. The DNS hot path never touches
//! this module.

use crate::config::settings::ScheduleConfig;

/// Parsed, validated schedule ready for matching.
#[derive(Debug, Clone)]
pub struct ParsedSchedule {
    pub client: String,
    pub profile: String,
    /// Bitmask of active days (bit 0 = Monday, bit 6 = Sunday).
    days: u8,
    start_hour: u8,
    start_min: u8,
    end_hour: u8,
    end_min: u8,
    wraps_midnight: bool,
    /// Optional one-shot expiry. `None` for recurring schedules. When `Some`,
    /// `is_active` returns false once `expires_at <= now_utc` REGARDLESS
    /// of the day/hour window — a one-shot schedule is dead the moment
    /// its expiry passes, even mid-window.
    expires_at: Option<time::OffsetDateTime>,
}

impl ParsedSchedule {
    /// Parse a schedule config entry. Returns None if days or hours are invalid.
    pub fn parse(config: &ScheduleConfig) -> Option<Self> {
        let days = parse_days(&config.days)?;
        let (start_hour, start_min, end_hour, end_min) = parse_hours(&config.hours)?;
        let start_total = start_hour as u16 * 60 + start_min as u16;
        let end_total = end_hour as u16 * 60 + end_min as u16;
        let wraps_midnight = start_total >= end_total;
        // Reject a zero-length window (start == end), which the wrap logic
        // above would otherwise treat as permanently active. The sole
        // exception is 00:00-00:00 (midnight-to-midnight = the whole day),
        // the canonical always-on form the resolver fixtures and
        // `full_day_range` rely on. Any other equal pair (e.g. 09:00-09:00)
        // is almost certainly an operator typo. Mirrors the schema
        // validator's `check_schedules` carve-out, so the invariant holds
        // even on a parse-without-validate path (`build_resolver_map` →
        // `parse_v1`).
        if start_total == end_total && start_total != 0 {
            return None;
        }

        Some(Self {
            client: config.client.clone(),
            profile: config.profile.clone(),
            days,
            start_hour,
            start_min,
            end_hour,
            end_min,
            wraps_midnight,
            expires_at: config.expires_at,
        })
    }

    /// Parse a v1 [`Schedule`](crate::config::schema::Schedule) into the
    /// same time-match engine as the legacy schedule. The v1 schedule's
    /// `target_id`/`profile` ids are carried in the `client`/`profile`
    /// string fields for reuse by the existing matcher; the v1 resolver
    /// never consults those fields, because it dispatches by the outer
    /// `target_type` + `target_id` directly.
    pub fn parse_v1(schedule: &crate::config::schema::Schedule) -> Option<Self> {
        let days = parse_days(&schedule.days)?;
        let (start_hour, start_min, end_hour, end_min) = parse_hours(&schedule.hours)?;
        let start_total = start_hour as u16 * 60 + start_min as u16;
        let end_total = end_hour as u16 * 60 + end_min as u16;
        let wraps_midnight = start_total >= end_total;
        // Reject zero-length windows except 00:00-00:00 — same guard as
        // `parse` above. The v1 build path parses directly via
        // `build_resolver_map` without a validator pass, so the check
        // cannot live only in `check_schedules`.
        if start_total == end_total && start_total != 0 {
            return None;
        }

        Some(Self {
            client: schedule.target_id.as_str().to_string(),
            profile: schedule.profile.as_str().to_string(),
            days,
            start_hour,
            start_min,
            end_hour,
            end_min,
            wraps_midnight,
            expires_at: schedule.expires_at,
        })
    }

    /// Check if this schedule is active at the given local time.
    ///
    /// `weekday`: 0=Monday .. 6=Sunday (ISO 8601).
    ///
    /// One-shot schedules with `expires_at` set return false once the
    /// expiry is in the past, regardless of the day/hour window. The
    /// expiry check happens FIRST so it short-circuits the day/hour
    /// math — important for the common case where most of a tablet's
    /// configured schedules are recurring and just one is a temporary
    /// `warden client quiet` override that's about to expire.
    pub fn is_active(&self, weekday: u8, hour: u8, minute: u8) -> bool {
        if let Some(expires_at) = self.expires_at {
            if time::OffsetDateTime::now_utc() >= expires_at {
                return false;
            }
        }
        if self.days & (1 << weekday) == 0 {
            return false;
        }
        let now = hour as u16 * 60 + minute as u16;
        let start = self.start_hour as u16 * 60 + self.start_min as u16;
        let end = self.end_hour as u16 * 60 + self.end_min as u16;

        if self.wraps_midnight {
            // e.g. 22:00-06:00: active if now >= 22:00 OR now < 06:00
            now >= start || now < end
        } else {
            // e.g. 09:00-17:00: active if 09:00 <= now < 17:00
            now >= start && now < end
        }
    }

    /// True if this schedule has an expiry that is already in the past.
    /// Recurring schedules (no expiry) always return false.
    ///
    /// The on-disk prune (`cli::commands::schedules::prune_expired_schedules`,
    /// called by the 60 s schedule tick and `device quiet`) compares
    /// `expires_at` on the schema type directly, so this engine-side
    /// helper stays test-facing only.
    #[allow(dead_code)] // mirror of the schema-side expiry comparison; kept for tests
    pub fn is_expired(&self, now_utc: time::OffsetDateTime) -> bool {
        match self.expires_at {
            Some(exp) => now_utc >= exp,
            None => false,
        }
    }
}

/// Get current local time as (weekday_iso, hour, minute).
///
/// weekday_iso: 0=Monday .. 6=Sunday.
/// Uses libc::localtime_r which is thread-safe on Linux (glibc).
pub fn local_now() -> (u8, u8, u8) {
    // VM cold boot can briefly have the wall clock pre-epoch; fall back to
    // 1970-01-01 rather than panic the 60s profile-rebuild loop. Mirrors the
    // pattern in tracking/engine.rs.
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let epoch_t = epoch as libc::time_t;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    // SAFETY: `localtime_r` writes the broken-down time into `tm` (which we
    // own and have zero-initialised) and returns a pointer to it on success,
    // or NULL on failure. We keep the return to detect that failure.
    let ret = unsafe { libc::localtime_r(&epoch_t, &mut tm) };
    components_from_localtime(ret, &tm, epoch)
}

/// Map a `localtime_r` result into the bounded `(weekday_iso, hour, minute)`
/// tuple. Split out of [`local_now`] so the NULL-return branch is testable
/// without forging a real `localtime_r` failure (near-impossible for a valid
/// `time_t`).
///
/// On a NULL return `localtime_r` leaves `*tm` unspecified — here it stays
/// all-zero from `mem::zeroed`, which `convert_libc_tm_components` would
/// silently read as "Sunday 00:00". Surface the failure with a `warn!` and
/// fall back to the documented `(Monday, 0, 0)` this module already uses
/// for out-of-range components, rather than a silent wrong-time schedule
/// evaluation. `ret` is only inspected for nullness, never dereferenced;
/// the validated read goes through the `&tm` we own.
fn components_from_localtime(ret: *const libc::tm, tm: &libc::tm, epoch: u64) -> (u8, u8, u8) {
    if ret.is_null() {
        tracing::warn!(
            epoch,
            "localtime_r returned NULL; falling back to Monday 00:00"
        );
        return (0, 0, 0);
    }
    convert_libc_tm_components(tm.tm_wday, tm.tm_hour, tm.tm_min)
}

/// Convert raw libc `tm` fields (`tm_wday`, `tm_hour`, `tm_min`, all `c_int`)
/// to the bounded `(weekday_iso, hour, minute)` tuple used by the schedule
/// matcher.
///
/// POSIX guarantees `tm_wday ∈ 0..=6`, `tm_hour ∈ 0..=23`, `tm_min ∈ 0..=59`,
/// but the previous `as u8` casts wrapped silently on out-of-range input
/// (e.g. a `-1` `c_int` would land at `254`, misfiring the day mask). This
/// helper rejects out-of-range values, logs a warn, and falls back to
/// `(Monday, 0, 0)` rather than panicking the 60 s profile-rebuild loop.
fn convert_libc_tm_components(
    tm_wday: libc::c_int,
    tm_hour: libc::c_int,
    tm_min: libc::c_int,
) -> (u8, u8, u8) {
    // libc tm_wday: 0=Sunday, 1=Monday, ..., 6=Saturday
    // Convert to ISO: 0=Monday, ..., 6=Sunday
    let weekday_iso = match tm_wday {
        0 => 6,
        1..=6 => (tm_wday - 1) as u8,
        _ => {
            tracing::warn!(
                tm_wday,
                "localtime_r returned out-of-range tm_wday; falling back to Monday"
            );
            0
        }
    };
    let hour = u8::try_from(tm_hour)
        .ok()
        .filter(|&h| h <= 23)
        .unwrap_or_else(|| {
            tracing::warn!(
                tm_hour,
                "localtime_r returned out-of-range tm_hour; falling back to 0"
            );
            0
        });
    let minute = u8::try_from(tm_min)
        .ok()
        .filter(|&m| m <= 59)
        .unwrap_or_else(|| {
            tracing::warn!(
                tm_min,
                "localtime_r returned out-of-range tm_min; falling back to 0"
            );
            0
        });
    (weekday_iso, hour, minute)
}

/// Parse day specifications into a bitmask (bit 0=Mon .. bit 6=Sun).
fn parse_days(specs: &[String]) -> Option<u8> {
    let mut mask: u8 = 0;
    for spec in specs {
        match spec.to_ascii_lowercase().as_str() {
            "mon" => mask |= 1 << 0,
            "tue" => mask |= 1 << 1,
            "wed" => mask |= 1 << 2,
            "thu" => mask |= 1 << 3,
            "fri" => mask |= 1 << 4,
            "sat" => mask |= 1 << 5,
            "sun" => mask |= 1 << 6,
            "weekdays" => mask |= 0b0011111, // Mon-Fri
            "weekends" => mask |= 0b1100000, // Sat-Sun
            "all" => mask |= 0b1111111,
            _ => return None,
        }
    }
    if mask == 0 {
        return None;
    }
    Some(mask)
}

/// Parse "HH:MM-HH:MM" into (start_h, start_m, end_h, end_m).
fn parse_hours(hours: &str) -> Option<(u8, u8, u8, u8)> {
    let parts: Vec<&str> = hours.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let (sh, sm) = parse_time(parts[0])?;
    let (eh, em) = parse_time(parts[1])?;
    Some((sh, sm, eh, em))
}

/// Parse "HH:MM" into (hour, minute). Validates ranges.
fn parse_time(s: &str) -> Option<(u8, u8)> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u8 = parts[0].parse().ok()?;
    let m: u8 = parts[1].parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some((h, m))
}

/// Find the active schedule for a given client name at the current time.
/// Returns the profile name to use, or None if no schedule matches.
/// First match wins (top to bottom in config order).
pub fn active_schedule_profile<'a>(
    schedules: &'a [ParsedSchedule],
    client_name: &str,
    weekday: u8,
    hour: u8,
    minute: u8,
) -> Option<&'a str> {
    schedules
        .iter()
        .find(|s| s.client == client_name && s.is_active(weekday, hour, minute))
        .map(|s| s.profile.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_schedule(client: &str, profile: &str, days: &[&str], hours: &str) -> ScheduleConfig {
        ScheduleConfig {
            client: client.into(),
            profile: profile.into(),
            days: days.iter().map(|s| s.to_string()).collect(),
            hours: hours.into(),
            expires_at: None,
        }
    }

    fn make_schedule_with_expiry(
        client: &str,
        profile: &str,
        days: &[&str],
        hours: &str,
        expires_at: time::OffsetDateTime,
    ) -> ScheduleConfig {
        ScheduleConfig {
            client: client.into(),
            profile: profile.into(),
            days: days.iter().map(|s| s.to_string()).collect(),
            hours: hours.into(),
            expires_at: Some(expires_at),
        }
    }

    // ── Day parsing ────────────────────────────────

    #[test]
    fn parse_individual_days() {
        let days = parse_days(&["mon".into(), "wed".into(), "fri".into()]).unwrap();
        assert_eq!(days, 0b0010101); // bits 0, 2, 4
    }

    #[test]
    fn parse_weekdays_shortcut() {
        let days = parse_days(&["weekdays".into()]).unwrap();
        assert_eq!(days, 0b0011111); // Mon-Fri
    }

    #[test]
    fn parse_weekends_shortcut() {
        let days = parse_days(&["weekends".into()]).unwrap();
        assert_eq!(days, 0b1100000); // Sat-Sun
    }

    #[test]
    fn parse_all_days() {
        let days = parse_days(&["all".into()]).unwrap();
        assert_eq!(days, 0b1111111);
    }

    #[test]
    fn parse_combined_shortcuts() {
        // weekdays + sun = all except sat
        let days = parse_days(&["weekdays".into(), "sun".into()]).unwrap();
        assert_eq!(days, 0b1011111);
    }

    #[test]
    fn parse_invalid_day_rejected() {
        assert!(parse_days(&["monday".into()]).is_none());
        assert!(parse_days(&["".into()]).is_none());
    }

    #[test]
    fn parse_empty_days_rejected() {
        assert!(parse_days(&[]).is_none());
    }

    #[test]
    fn parse_case_insensitive() {
        let days = parse_days(&["MON".into(), "Fri".into()]).unwrap();
        assert_eq!(days, 0b0010001);
    }

    // ── Time parsing ───────────────────────────────

    #[test]
    fn parse_normal_hours() {
        let (sh, sm, eh, em) = parse_hours("09:00-17:00").unwrap();
        assert_eq!((sh, sm, eh, em), (9, 0, 17, 0));
    }

    #[test]
    fn parse_midnight_wrap_hours() {
        let (sh, sm, eh, em) = parse_hours("22:00-06:00").unwrap();
        assert_eq!((sh, sm, eh, em), (22, 0, 6, 0));
    }

    #[test]
    fn parse_hours_with_minutes() {
        let (sh, sm, eh, em) = parse_hours("21:30-07:15").unwrap();
        assert_eq!((sh, sm, eh, em), (21, 30, 7, 15));
    }

    #[test]
    fn parse_invalid_hours() {
        assert!(parse_hours("25:00-06:00").is_none());
        assert!(parse_hours("09:00").is_none());
        assert!(parse_hours("09-17").is_none());
        assert!(parse_hours("").is_none());
        assert!(parse_hours("ab:cd-ef:gh").is_none());
        assert!(parse_hours("09:60-17:00").is_none());
    }

    // ── Schedule matching ──────────────────────────

    #[test]
    fn normal_range_active() {
        let cfg = make_schedule("tablet", "kids", &["all"], "09:00-17:00");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        // Monday 12:00 → active
        assert!(s.is_active(0, 12, 0));
        // Monday 09:00 → active (inclusive start)
        assert!(s.is_active(0, 9, 0));
        // Monday 16:59 → active
        assert!(s.is_active(0, 16, 59));
        // Monday 17:00 → inactive (exclusive end)
        assert!(!s.is_active(0, 17, 0));
        // Monday 08:59 → inactive
        assert!(!s.is_active(0, 8, 59));
    }

    #[test]
    fn midnight_wrap_active() {
        let cfg = make_schedule("tablet", "night", &["weekdays"], "22:00-06:00");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        // Monday 23:00 → active
        assert!(s.is_active(0, 23, 0));
        // Monday 22:00 → active (inclusive start)
        assert!(s.is_active(0, 22, 0));
        // Monday 00:00 → active (after midnight)
        assert!(s.is_active(0, 0, 0));
        // Monday 05:59 → active
        assert!(s.is_active(0, 5, 59));
        // Monday 06:00 → inactive (exclusive end)
        assert!(!s.is_active(0, 6, 0));
        // Monday 12:00 → inactive
        assert!(!s.is_active(0, 12, 0));
        // Saturday 23:00 → inactive (weekdays only)
        assert!(!s.is_active(5, 23, 0));
    }

    #[test]
    fn day_filtering() {
        let cfg = make_schedule("tablet", "night", &["mon", "wed"], "20:00-23:00");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        // Monday 21:00 → active
        assert!(s.is_active(0, 21, 0));
        // Wednesday 21:00 → active
        assert!(s.is_active(2, 21, 0));
        // Tuesday 21:00 → inactive (wrong day)
        assert!(!s.is_active(1, 21, 0));
    }

    #[test]
    fn full_day_range() {
        // 00:00-00:00 wraps midnight: start >= end, so wraps_midnight=true
        // now >= 00:00 || now < 00:00 → now >= 0 is always true → always active
        let cfg = make_schedule("tablet", "blocked", &["all"], "00:00-00:00");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        assert!(s.is_active(0, 0, 0));
        assert!(s.is_active(3, 12, 0));
        assert!(s.is_active(6, 23, 59));
    }

    #[test]
    fn parse_rejects_zero_length_window() {
        // A non-midnight start == end is a zero-length window the wrap
        // logic would misread as always-active — reject it.
        assert!(
            ParsedSchedule::parse(&make_schedule("tablet", "p", &["all"], "09:00-09:00")).is_none()
        );
        assert!(
            ParsedSchedule::parse(&make_schedule("tablet", "p", &["all"], "12:30-12:30")).is_none()
        );
        // 00:00-00:00 is the canonical whole-day form and stays valid.
        assert!(
            ParsedSchedule::parse(&make_schedule("tablet", "p", &["all"], "00:00-00:00")).is_some()
        );
    }

    #[test]
    fn parse_v1_rejects_zero_length_window() {
        // The v1 build path (`build_resolver_map` → `parse_v1`) bypasses
        // `validate_schedule`, so the same guard must hold here.
        use crate::config::schema::{Id, Schedule, ScheduleTargetType};
        let mk = |hours: &str| Schedule {
            id: Id::new("sched").unwrap(),
            display_name: "Sched".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("tablet").unwrap(),
            profile: Id::new("prof").unwrap(),
            days: vec!["all".into()],
            hours: hours.into(),
            expires_at: None,
        };
        assert!(ParsedSchedule::parse_v1(&mk("09:00-09:00")).is_none());
        assert!(ParsedSchedule::parse_v1(&mk("00:00-00:00")).is_some());
    }

    #[test]
    fn parse_v1_quiet_window_covers_2359() {
        // The window `warden device quiet` writes (`00:00-00:00`,
        // days=all) must be active at EVERY minute, including 23:59 — a
        // `00:00-23:59` shape would leave that minute unfiltered
        // (end-exclusive matcher).
        use crate::config::schema::{Id, Schedule, ScheduleTargetType};
        let quiet = Schedule {
            id: Id::new("quiet-tablet-001122").unwrap(),
            display_name: "Quiet device tablet".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("tablet").unwrap(),
            profile: Id::new("blocked").unwrap(),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(),
            expires_at: None,
        };
        let s = ParsedSchedule::parse_v1(&quiet).expect("quiet shape parses");
        for weekday in 0..7u8 {
            assert!(s.is_active(weekday, 23, 59), "hole at day {weekday} 23:59");
            assert!(s.is_active(weekday, 0, 0));
            assert!(s.is_active(weekday, 12, 30));
        }
    }

    // ── First match wins ───────────────────────────

    #[test]
    fn first_match_wins() {
        let schedules: Vec<ParsedSchedule> = vec![
            ParsedSchedule::parse(&make_schedule("tablet", "night", &["all"], "22:00-06:00"))
                .unwrap(),
            ParsedSchedule::parse(&make_schedule("tablet", "kids", &["all"], "06:00-22:00"))
                .unwrap(),
        ];
        // 23:00 matches first schedule → "night"
        assert_eq!(
            active_schedule_profile(&schedules, "tablet", 0, 23, 0),
            Some("night")
        );
        // 12:00 matches second schedule → "kids"
        assert_eq!(
            active_schedule_profile(&schedules, "tablet", 0, 12, 0),
            Some("kids")
        );
        // Different client → no match
        assert_eq!(
            active_schedule_profile(&schedules, "laptop", 0, 23, 0),
            None
        );
    }

    // ── local_now sanity ───────────────────────────

    #[test]
    fn local_now_returns_valid_ranges() {
        let (weekday, hour, minute) = local_now();
        assert!(weekday <= 6);
        assert!(hour <= 23);
        assert!(minute <= 59);
    }

    // ── expires_at ──────────────────────────────────

    #[test]
    fn schedule_without_expiry_is_active_normally() {
        let cfg = make_schedule("tablet", "night", &["all"], "00:00-23:59");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        assert!(s.is_active(0, 12, 0), "no-expiry schedule active in window");
        assert!(!s.is_expired(time::OffsetDateTime::now_utc()));
    }

    #[test]
    fn schedule_with_future_expiry_is_active_in_window() {
        let one_hour_later = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let cfg =
            make_schedule_with_expiry("tablet", "blocked", &["all"], "00:00-23:59", one_hour_later);
        let s = ParsedSchedule::parse(&cfg).unwrap();
        assert!(
            s.is_active(0, 12, 0),
            "future-expiry schedule active in window"
        );
        assert!(!s.is_expired(time::OffsetDateTime::now_utc()));
    }

    #[test]
    fn schedule_with_past_expiry_is_inactive_even_in_window() {
        // Expiry in the past: even though we're inside the day/hour
        // window, is_active returns false. This is the load-bearing
        // invariant — operators expect `warden client quiet --for 1m`
        // to STOP blocking after one minute, not at the next day
        // boundary.
        let one_hour_ago = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        let cfg =
            make_schedule_with_expiry("tablet", "blocked", &["all"], "00:00-23:59", one_hour_ago);
        let s = ParsedSchedule::parse(&cfg).unwrap();
        assert!(
            !s.is_active(0, 12, 0),
            "expired schedule must be inactive even mid-window"
        );
        assert!(s.is_expired(time::OffsetDateTime::now_utc()));
    }

    #[test]
    fn schedule_is_expired_recurring_returns_false() {
        let cfg = make_schedule("tablet", "night", &["all"], "00:00-23:59");
        let s = ParsedSchedule::parse(&cfg).unwrap();
        // Recurring schedule has no expiry → never expires
        assert!(!s.is_expired(time::OffsetDateTime::now_utc()));
        // Even with a "now" 100 years in the future
        let far_future = time::OffsetDateTime::now_utc() + time::Duration::days(36500);
        assert!(!s.is_expired(far_future));
    }

    #[test]
    fn parse_schedule_carries_expires_at_through() {
        // Pin the round trip: parsing a config with expires_at must
        // store it on the ParsedSchedule. Sanity check that the field
        // doesn't get dropped on the floor by the parser.
        let exp = time::OffsetDateTime::now_utc() + time::Duration::hours(2);
        let cfg = make_schedule_with_expiry("x", "p", &["all"], "00:00-23:59", exp);
        let s = ParsedSchedule::parse(&cfg).unwrap();
        assert_eq!(s.expires_at, Some(exp));
    }

    #[test]
    fn pre_epoch_systemtime_does_not_panic() {
        // Pre-epoch wall clock (e.g. VM cold boot) must not panic the 60s
        // profile-rebuild loop. Pinning the contract local_now() relies on:
        // duration_since(UNIX_EPOCH).unwrap_or_default() returns ZERO
        // instead of panicking when the clock is briefly behind 1970.
        let pre_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(60);
        let dur = pre_epoch
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        assert_eq!(dur, std::time::Duration::ZERO);
    }

    #[test]
    fn local_now_returns_bounded_components() {
        // Smoke-pin local_now() — no panic, returns valid weekday/hour/minute
        // ranges. Today's clock is post-epoch so we cannot directly exercise
        // the unwrap_or_default branch from this test, but the call site is
        // covered by `pre_epoch_systemtime_does_not_panic`.
        let (weekday, hour, minute) = local_now();
        assert!(weekday < 7, "weekday {weekday} out of range");
        assert!(hour < 24, "hour {hour} out of range");
        assert!(minute < 60, "minute {minute} out of range");
    }

    // ── libc tm component validation ───────────────

    #[test]
    fn convert_libc_tm_in_range_maps_correctly() {
        // libc convention: 0=Sunday, 1=Monday, ..., 6=Saturday.
        // ISO convention: 0=Monday, ..., 6=Sunday.
        assert_eq!(convert_libc_tm_components(0, 0, 0), (6, 0, 0)); // Sun → 6
        assert_eq!(convert_libc_tm_components(1, 9, 30), (0, 9, 30)); // Mon → 0
        assert_eq!(convert_libc_tm_components(2, 12, 0), (1, 12, 0)); // Tue → 1
        assert_eq!(convert_libc_tm_components(6, 23, 59), (5, 23, 59)); // Sat → 5
    }

    #[test]
    fn convert_libc_tm_negative_wday_falls_back_to_monday() {
        // Pre-fix `(d - 1) as u8` on d=-1 produced 254; bit-shift of 254
        // wraps the day mask and mis-fires arbitrary days. Now: warn + 0.
        assert_eq!(convert_libc_tm_components(-1, 12, 0), (0, 12, 0));
    }

    #[test]
    fn convert_libc_tm_oversized_wday_falls_back_to_monday() {
        // d=7 (impossible per POSIX but let's not trust libc blindly)
        // would have wrapped to weekday 6 = Sunday, not Monday.
        assert_eq!(convert_libc_tm_components(7, 12, 0), (0, 12, 0));
        assert_eq!(convert_libc_tm_components(99, 0, 0), (0, 0, 0));
    }

    #[test]
    fn convert_libc_tm_negative_hour_falls_back_to_zero() {
        // `as u8` on -1 = 255; would have wrapped the hour-of-day window
        // and silently mis-fired the schedule.
        assert_eq!(convert_libc_tm_components(1, -1, 0), (0, 0, 0));
    }

    #[test]
    fn convert_libc_tm_oversized_hour_falls_back_to_zero() {
        // hour 24 is out-of-range; clamp to 0.
        assert_eq!(convert_libc_tm_components(1, 24, 0), (0, 0, 0));
        assert_eq!(convert_libc_tm_components(1, 99, 0), (0, 0, 0));
    }

    #[test]
    fn convert_libc_tm_oversized_minute_falls_back_to_zero() {
        assert_eq!(convert_libc_tm_components(1, 9, -1), (0, 9, 0));
        assert_eq!(convert_libc_tm_components(1, 9, 60), (0, 9, 0));
        assert_eq!(convert_libc_tm_components(1, 9, 999), (0, 9, 0));
    }

    #[test]
    fn convert_libc_tm_independent_field_validation() {
        // Each field validates independently — bad wday + good hour/minute
        // still preserves the good ones (and vice versa).
        assert_eq!(convert_libc_tm_components(-1, 14, 30), (0, 14, 30));
        assert_eq!(convert_libc_tm_components(3, -1, 30), (2, 0, 30));
        assert_eq!(convert_libc_tm_components(3, 14, -1), (2, 14, 0));
    }

    // ── localtime_r NULL-return guard ───────────────

    #[test]
    fn components_from_localtime_null_falls_back_to_monday() {
        // A NULL localtime_r return (near-impossible for a valid time_t)
        // must surface as Monday 00:00, not a silently zeroed "Sunday
        // 00:00".
        let tm = unsafe { std::mem::zeroed::<libc::tm>() };
        assert_eq!(
            components_from_localtime(std::ptr::null(), &tm, 0),
            (0, 0, 0)
        );
    }

    #[test]
    fn components_from_localtime_non_null_converts() {
        // Non-NULL: real localtime_r returns a pointer to the same tm it
        // filled. Model that faithfully (ret = &tm) and confirm we delegate
        // to convert_libc_tm_components — libc Tuesday 14:30 → ISO (1,14,30).
        let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
        tm.tm_wday = 2;
        tm.tm_hour = 14;
        tm.tm_min = 30;
        let ret: *const libc::tm = &tm;
        assert_eq!(
            components_from_localtime(ret, &tm, 1_700_000_000),
            (1, 14, 30)
        );
    }
}
