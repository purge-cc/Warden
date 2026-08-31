//! §4.13 Sprint 1 — Resource Budget / RAM Meter.
//!
//! Background sampler that reads the daemon's own RSS / VSZ / FD count /
//! user-mode CPU% from `/proc/self/*` on Linux every `tick_secs` and
//! publishes the latest sample through a lock-free [`ResourceBudgetStore`]
//! handle. The IPC `status` handler reads through this handle on each
//! reply; the TUI Dashboard's "Global Pulse" card surfaces the values as
//! a labelled `Resources` row colourised against the configured
//! `rss_warn_mb` threshold.
//!
//! On non-Linux targets `spawn_sampler` is a no-op stub so the daemon
//! still builds and the snapshot stays `None` — keeps the
//! `aarch64-unknown-linux-musl` cross-build (Linux) active while not
//! breaking any future macOS / BSD dev box.
//!
//! Hot-path invariant: the sampler is its own tokio task and writes
//! only into a sampler-owned [`ArcSwap`](arc_swap::ArcSwap). It never
//! touches DNS-query state.

pub mod proc_reader;
pub mod sampler;
pub mod types;

pub use sampler::spawn_sampler;
pub use types::{ResourceBudgetSnapshot, ResourceBudgetStore};
