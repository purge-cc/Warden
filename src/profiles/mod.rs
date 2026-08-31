//! Per-client filtering profiles and resolution.
//!
//! Profiles define WHAT gets filtered (which lists, custom allow/deny rules).
//! Clients map to profiles. The resolver provides the hot-path lookup:
//! source IP → ResolvedProfile (via ArcSwap, zero locks).
//!
//! Schedules add a time dimension: a background task re-evaluates every 60s
//! and swaps the profile map if a schedule boundary was crossed.

pub mod arp;
pub mod profile;
pub mod resolver;
pub mod safesearch;
pub mod schedule;

pub use profile::DeviceOverlay;
pub use resolver::{
    apply_overlay, AttribSource, LayerHits, OverlayDecision, ProfileResolver, Resolution,
    ResolveLevel,
};
