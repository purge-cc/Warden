//! §4.7 Phase 2 T2 integration: TUI Stale badge fires only when
//! `now - dto.last_refresh_at > staleness_threshold_secs`.
//!
//! The unit tests in `src/tui/tabs/lists.rs` already cover the
//! row-level render assertion. This integration test isolates the
//! pure predicate (`is_stale_for_dto`) against fixtures the daemon
//! would actually serve over IPC — including the back-compat case
//! where a pre-T2 daemon sends `last_refresh_at = None` and the
//! badge must be suppressed across the wire.

use purge_warden::lists::status::BlocklistStatusDto;
use purge_warden::tui::is_stale_for_dto;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn dto_with_last_refresh(ts: Option<OffsetDateTime>) -> BlocklistStatusDto {
    BlocklistStatusDto {
        source: "privacy/ads".into(),
        id: Some("privacy-ads".into()),
        entries: 1_000,
        last_outcome: "ok".into(),
        last_refresh_at: ts.and_then(|t| t.format(&Rfc3339).ok()),
        ..Default::default()
    }
}

#[test]
fn stale_predicate_fires_past_24h_default() {
    let now = OffsetDateTime::now_utc();
    let two_days_ago = now - time::Duration::hours(48);
    let dto = dto_with_last_refresh(Some(two_days_ago));
    assert!(
        is_stale_for_dto(&dto, 86_400, now),
        "48h-old refresh against the default 24h threshold must trigger the badge"
    );
}

#[test]
fn stale_predicate_suppressed_within_window() {
    let now = OffsetDateTime::now_utc();
    let one_hour_ago = now - time::Duration::hours(1);
    let dto = dto_with_last_refresh(Some(one_hour_ago));
    assert!(
        !is_stale_for_dto(&dto, 86_400, now),
        "1h-old refresh against 24h threshold must NOT trigger the badge"
    );
}

#[test]
fn stale_predicate_suppressed_on_none_and_clock_skew() {
    let now = OffsetDateTime::now_utc();

    // Pre-T2 daemon: no last_refresh_at on the wire => None on decode
    // => badge suppressed (operator sees `never` in the status column).
    let dto_none = dto_with_last_refresh(None);
    assert!(
        !is_stale_for_dto(&dto_none, 86_400, now),
        "None last_refresh_at must suppress the badge (back-compat with pre-T2 daemons)"
    );

    // Clock skew: timestamp in the future. Predicate must NOT flag stale
    // — it would surprise the operator with a badge that vanishes when
    // the clock fixes itself.
    let future = now + time::Duration::hours(1);
    let dto_future = dto_with_last_refresh(Some(future));
    assert!(
        !is_stale_for_dto(&dto_future, 86_400, now),
        "future timestamp (clock skew) must be treated as fresh, not stale"
    );

    // Corrupted RFC 3339 timestamp: defensive fallback returns false.
    let dto_garbage = BlocklistStatusDto {
        source: "x".into(),
        last_refresh_at: Some("not-a-timestamp".into()),
        ..Default::default()
    };
    assert!(
        !is_stale_for_dto(&dto_garbage, 86_400, now),
        "unparseable timestamp must be treated as fresh, not stale"
    );
}
