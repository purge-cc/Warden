//! Shared DTO for the resource budget sampler.
//!
//! Mirrored on the IPC wire (`IpcResponse::Status.resource_budget`) and
//! consumed by the TUI Dashboard's `pulse_row_resource` helper. Kept
//! `Copy + serde` so the daemon, IPC layer, and TUI can pass it by
//! value without lifetime gymnastics.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// One-shot snapshot of the daemon's resource footprint.
///
/// Produced once per `tick_secs` by [`super::sampler::spawn_sampler`] and
/// stored into a [`ResourceBudgetStore`]. The IPC handler reads the
/// latest stored value and forwards it as `Option<Self>` — `None` means
/// "sampler hasn't produced a first sample yet, or the daemon is running
/// on a non-Linux target".
///
/// `cpu_user_pct` saturates at 255 so a single multi-core spike can't
/// roll over. Daemon CPU% is expected to stay well below that on every
/// supported deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResourceBudgetSnapshot {
    /// Resident set size in MiB, sourced from `/proc/self/status:VmRSS`.
    pub rss_mb: u64,
    /// Virtual memory size in MiB, sourced from `/proc/self/status:VmSize`.
    pub vsz_mb: u64,
    /// File descriptors held by the daemon, counted from `/proc/self/fd`.
    pub fd_count: u32,
    /// User-mode CPU% delta since the previous sample (saturating `u8`).
    /// `0` on the first tick (no prior sample to diff against). Excludes
    /// kernel/system time (stime) — see follow-up `s-4.13-cpu-sys`.
    pub cpu_user_pct: u8,
    /// Configured `rss_warn_mb` threshold, mirrored each tick so the TUI
    /// renderer doesn't need a second IPC field to colour the row.
    pub rss_warn_mb: u64,
    /// Process swap (VmSwap), in MiB; absent when unavailable.
    #[serde(default)]
    pub swap_mb: Option<u64>,
    /// Process RSS high-water mark since startup (VmHWM), in MiB.
    #[serde(default)]
    pub peak_rss_mb: Option<u64>,
    /// Machine memory available to applications (MemAvailable), in MiB.
    #[serde(default)]
    pub mem_available_mb: Option<u64>,
    /// Machine memory visible to the daemon (MemTotal), in MiB.
    #[serde(default)]
    pub mem_total_mb: Option<u64>,
    /// Unix seconds of this successful sample; preserved on sampling failure.
    #[serde(default)]
    pub sampled_at: Option<u64>,
}

/// Lock-free handle to the latest [`ResourceBudgetSnapshot`]. `None` means
/// "no sample produced yet" (sampler still in its first-tick wait, or
/// non-Linux build).
pub type ResourceBudgetStore = Arc<ArcSwap<Option<ResourceBudgetSnapshot>>>;

/// Construct an empty store. `Arc::new(ArcSwap::from_pointee(None))`
/// reads ugly at the call site; this keeps the daemon wiring tidy.
pub fn new_store() -> ResourceBudgetStore {
    Arc::new(ArcSwap::from_pointee(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_snapshot_keeps_new_readings_unavailable() {
        let snapshot: ResourceBudgetSnapshot = serde_json::from_str(
            r#"{"rss_mb":10,"vsz_mb":30,"fd_count":4,"cpu_user_pct":2,"rss_warn_mb":256}"#,
        )
        .unwrap();
        assert_eq!(snapshot.swap_mb, None);
        assert_eq!(snapshot.peak_rss_mb, None);
        assert_eq!(snapshot.mem_available_mb, None);
        assert_eq!(snapshot.mem_total_mb, None);
        assert_eq!(snapshot.sampled_at, None);
    }
}
