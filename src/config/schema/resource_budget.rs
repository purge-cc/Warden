//! [`ResourceBudgetConfig`] — `[resource_budget]` knobs for the §4.13
//! sampler.
//!
//! Holds two operator-tunables:
//!
//! - `tick_secs` — sampling cadence (default 5). The sampler reads
//!   `/proc/self/status`, `/proc/self/stat`, and `/proc/self/fd` once per
//!   tick and publishes a snapshot through an `ArcSwap`. Lower values
//!   cost more `/proc` reads; higher values delay the TUI's reaction to
//!   load spikes.
//! - `rss_warn_mb` — RSS threshold (megabytes) above which the Dashboard
//!   colourises the Resources row yellow (>80%) or red (>100%). Default
//!   is 50% of `/proc/meminfo` `MemTotal` (the conservative, Pi-class
//!   friendly choice), falling back to 256 MB if `/proc/meminfo` is
//!   unreadable. Validator enforces `rss_warn_mb >= 1`.
//!
//! Section is fully optional. Omit `[resource_budget]` from the master
//! config and the defaults kick in.

use serde::{Deserialize, Serialize};

use crate::resource_budget::proc_reader;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudgetConfig {
    #[serde(default = "default_tick_secs")]
    pub tick_secs: u64,
    #[serde(default = "default_rss_warn_mb")]
    pub rss_warn_mb: u64,
}

fn default_tick_secs() -> u64 {
    5
}

fn default_rss_warn_mb() -> u64 {
    meminfo_50pct_or_256()
}

/// 50% of `/proc/meminfo:MemTotal` in megabytes, falling back to 256 MB
/// if the file is unreadable or malformed. The 50% factor is the
/// conservative, Pi-class friendly default — design doc proposed 70%
/// but operator preference for early warning won out for Sprint 1.
///
/// Floored at 1 MB (resource-budget-02, rev-2606): a host reporting
/// `MemTotal < 2048 kB` would otherwise compute 0, which the validator
/// itself rejects — the DEFAULT config unloadable through no operator
/// fault.
///
/// Reads `/proc/meminfo` on every call. On the boot path that's once
/// per daemon start, so caching would buy nothing. (See follow-up
/// `s-4.13-meminfo-cache`.)
fn meminfo_50pct_or_256() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            if let Some(total_kb) = proc_reader::parse_meminfo_total_kb(&text) {
                return ((total_kb / 1024) / 2).max(1);
            }
        }
    }
    256
}

/// Manual `Default` so the Rust-side construction matches the serde-side
/// `#[serde(default = …)]` expressions. `#[derive(Default)]` would give
/// `tick_secs = 0` (which the validator rejects) and `rss_warn_mb = 0`
/// (which disables the threshold rendering) — both surprising.
impl Default for ResourceBudgetConfig {
    fn default() -> Self {
        Self {
            tick_secs: default_tick_secs(),
            rss_warn_mb: default_rss_warn_mb(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_via_serde_match_impl_default() {
        let from_empty: ResourceBudgetConfig = toml::from_str("").unwrap();
        let from_default = ResourceBudgetConfig::default();
        assert_eq!(from_empty.tick_secs, from_default.tick_secs);
        assert_eq!(from_empty.rss_warn_mb, from_default.rss_warn_mb);
    }

    #[test]
    fn default_tick_secs_is_5() {
        assert_eq!(ResourceBudgetConfig::default().tick_secs, 5);
    }

    #[test]
    fn default_rss_warn_mb_is_nonzero() {
        // Structural since resource-budget-02 (rev-2606): the derivation
        // floors at 1 MB, so even a MemTotal < 2048 kB host cannot compute
        // a 0 the validator would then reject. The 256 MB fallback is
        // nonzero by construction.
        assert!(ResourceBudgetConfig::default().rss_warn_mb > 0);
    }

    #[test]
    fn override_tick_secs_via_toml() {
        let cfg: ResourceBudgetConfig = toml::from_str("tick_secs = 30").unwrap();
        assert_eq!(cfg.tick_secs, 30);
    }

    #[test]
    fn override_rss_warn_mb_via_toml() {
        let cfg: ResourceBudgetConfig = toml::from_str("rss_warn_mb = 64").unwrap();
        assert_eq!(cfg.rss_warn_mb, 64);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let res: Result<ResourceBudgetConfig, _> = toml::from_str("not_a_field = 1");
        assert!(res.is_err(), "deny_unknown_fields should reject typos");
    }
}
