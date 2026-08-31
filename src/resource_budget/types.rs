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
    /// Resident set size in megabytes, sourced from `/proc/self/status:VmRSS`.
    pub rss_mb: u64,
    /// Virtual memory size in megabytes, sourced from `/proc/self/status:VmSize`.
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
