use super::*;
use crate::config::settings::{LogMode, TrackingConfig};
use crate::tui::app::{TrackingFocus, TrackingPanelState};

fn baseline_panel() -> TrackingPanelState {
    TrackingPanelState::from_config(&TrackingConfig::default())
}

#[test]
fn panel_loads_from_config_defaults() {
    let panel = baseline_panel();
    assert!(panel.query_log_enabled);
    assert_eq!(panel.retention_days, 7);
    assert!(matches!(panel.log_mode, LogMode::All));
    assert_eq!(panel.focus, TrackingFocus::Enabled);
    assert_eq!(panel.retention_input, "7");
}

#[test]
fn focus_cycles_through_three_fields() {
    let panel = baseline_panel();
    let f0 = panel.focus;
    let f1 = f0.next();
    let f2 = f1.next();
    let f3 = f2.next();
    assert_eq!(f1, TrackingFocus::Mode);
    assert_eq!(f2, TrackingFocus::Retention);
    assert_eq!(f3, TrackingFocus::Enabled, "cycle wraps around");
    assert_eq!(f0.prev(), TrackingFocus::Retention);
}

#[test]
fn log_mode_cycle_next_and_prev_wrap() {
    let m0 = LogMode::All;
    let m1 = cycle_log_mode_next(&m0);
    let m2 = cycle_log_mode_next(&m1);
    let m3 = cycle_log_mode_next(&m2);
    assert!(matches!(m1, LogMode::BlockedOnly));
    assert!(matches!(m2, LogMode::Sampled { .. }));
    assert!(matches!(m3, LogMode::All));
    // prev inverts
    assert!(matches!(cycle_log_mode_prev(&m0), LogMode::Sampled { .. }));
}

#[test]
fn sampled_cycle_uses_frozen_ten_percent_rate() {
    // Frozen per design doc §3 QLP5: TUI emits allowed_rate =
    // 0.1 regardless of what was on disk. Operators who want a
    // different rate edit config.toml directly.
    let m = cycle_log_mode_next(&LogMode::BlockedOnly);
    match m {
        LogMode::Sampled { allowed_rate } => {
            assert!((allowed_rate - 0.1).abs() < f32::EPSILON);
        }
        other => panic!("expected Sampled, got {other:?}"),
    }
}

#[test]
fn commit_retention_parses_buffer() {
    let mut panel = baseline_panel();
    panel.retention_input = "14".into();
    commit_retention_from_input(&mut panel);
    assert_eq!(panel.retention_days, 14);

    // Empty buffer is a no-op (mid-edit clearing shouldn't
    // clobber the committed value).
    panel.retention_input.clear();
    commit_retention_from_input(&mut panel);
    assert_eq!(panel.retention_days, 14);
}

#[test]
fn to_patch_sends_all_three_fields() {
    let mut panel = baseline_panel();
    panel.query_log_enabled = false;
    panel.retention_days = 3;
    panel.log_mode = LogMode::BlockedOnly;
    let patch = panel.to_patch();
    assert_eq!(patch.query_log_enabled, Some(false));
    assert_eq!(patch.retention_days, Some(3));
    assert!(matches!(patch.log_mode, Some(LogMode::BlockedOnly)));
}

#[test]
fn frozen_strings_are_pinned() {
    // Sprint 39: the Settings panel emits these two strings
    // byte-for-byte per design doc §3 QLP5. Test pins them so a
    // future refactor can't silently drift.
    assert_eq!(
        crate::tui::tabs::settings::TRACKING_VALIDATION_RETENTION_OUT_OF_RANGE,
        "retention_days must be between 1 and 365."
    );
    assert_eq!(
        crate::tui::tabs::settings::TRACKING_SAMPLED_LABEL,
        "Sampled (10%)"
    );
}
