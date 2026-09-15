//! Exceptional list states surfaced in the Dashboard and persistent header.
use crate::lists::status::{CycleOutcome, ServedState};
use crate::tui::app::App;
use crate::tui::theme::T;
use ratatui::style::Color;

pub(super) fn issue(app: &App) -> Option<(String, Color)> {
    let status = app.daemon_status.as_ref()?;
    let cycle = status.lists_cycle;
    let outcome = cycle.and_then(|c| c.outcome);
    let coverage = cycle.is_some_and(|c| c.source_coverage_incomplete || c.generation_degraded);
    let mut issues = Vec::new();
    let mut color = T.warning;
    if outcome == Some(CycleOutcome::ConfigRejected) {
        issues.push("List configuration rejected");
        color = T.error;
    } else if status.lists_corpus_refusal.is_some() || outcome == Some(CycleOutcome::Refused) {
        issues.push("List update refused");
    }
    if status.domain_count == 0 {
        match cycle.map(|c| c.served_state) {
            Some(ServedState::IntentionalEmpty) => issues.push("Lists intentionally empty"),
            Some(ServedState::Cleared) => issues.push("Lists cleared; no list filtering"),
            Some(ServedState::Uninitialized) => {
                issues.push("List protection unavailable");
                color = T.error;
            }
            _ if outcome == Some(CycleOutcome::ClearedNoSources) => {
                issues.push("Lists cleared; no list filtering")
            }
            _ => issues.push("No list corpus"),
        }
    }
    if coverage {
        issues.push(match cycle.map(|c| c.served_state) {
            Some(ServedState::Complete) => "Coverage incomplete; serving previous corpus",
            Some(ServedState::Partial) => "Coverage incomplete; partial corpus",
            _ => "List coverage incomplete",
        });
    }
    if status.lists_corpus_freeze.is_some() {
        issues.push("List generation frozen");
    }
    if status.lists_truncated > 0 {
        issues.push("Source refusals since start");
    }
    if app
        .lists
        .entries
        .iter()
        .any(|entry| !matches!(entry.last_outcome.as_str(), "ok" | "never_fetched"))
    {
        issues.push("List refresh failures");
    }
    (!issues.is_empty()).then(|| (issues.join(" · "), color))
}

pub(super) fn format_age_short(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

pub(super) fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours:02}h {mins:02}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}
