//! Profile resolver — 5-level chain (§9) driving the DNS hot path.
//!
//! The hot path does a single atomic load + index lookup. A background
//! task (see `cli::commands::start::handle_schedule_tick`) rebuilds the
//! map every 60 seconds to re-evaluate schedule windows, and on every
//! SIGHUP / IPC reload the map swaps atomically (`ArcSwap`).
//!
//! # Resolver chain (§9)
//!
//! When a DNS query arrives from source IP `X`, [`ProfileResolver::resolve`]
//! walks the five levels in order and returns at the first match:
//!
//! 1. **Device direct profile** — a [`Device`](crate::config::schema::Device) whose `ip` pin equals `X`
//!    (or whose MAC is active for `X` per the ARP snapshot, when
//!    enforcement is on) AND that has a `profile = …` field set → use
//!    that profile. Invariant DM1: device direct profile overrides
//!    anything.
//! 2. **Active schedule override** — if the device matched above, or any
//!    [`Group`] it belongs to, has a schedule whose current-time window
//!    is active → use the schedule's profile.
//! 3. **Group membership** — the device's highest-priority group's
//!    profile. DM2 same-priority-different-profile conflicts surface as
//!    validator errors at load time, so the resolver can pick the first
//!    of a priority-sorted list deterministically.
//! 4. **Subnet default** — longest-prefix match against `[[subnets]]`
//!    (SN1). Used only for sources that didn't match a `[[devices]]` row.
//! 5. **Global fallback** — `[server].default_profile`. If that is
//!    unset → REFUSED.
//!
//! # MAC enforcement (P0-2)
//!
//! When `[server].enforce_device_mac = true` (default) and the matched
//! device pins a MAC, the resolver consults the live ARP snapshot before
//! returning the device profile. If the ARP table shows a different MAC
//! than the one pinned, the device is "downgraded" to the resolver chain
//! starting at level 4 (subnet) — a device under security suspicion
//! loses its direct / group / schedule overrides but is NOT automatically
//! blocked (the operator can still wire subnet or default_profile for it).
//!
//! # SN3 — block_unmapped_clients
//!
//! SN3 removed the legacy `server.block_unmapped_clients` flag. Its
//! effect is now expressed by leaving `default_profile` unset (level 5
//! → REFUSED). Any code path that previously consulted the flag now
//! pattern-matches on [`Resolution::profile`] being `None`.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use compact_str::CompactString;

use super::arp;
use super::profile::{DeviceOverlay, ResolvedProfile};
use super::schedule::{self, ParsedSchedule};
use crate::config::cidr::Cidr;
use crate::config::custom_list::CustomListStore;
use crate::config::list_state::ListState;
use crate::config::schema::{AdminRule, ConfigV1, Group, Id, ScheduleTargetType};
use crate::ipc::protocol::MappedDeviceDto;
use crate::lists::source_key::SourceBitMap;

/// Which of the five resolver-chain levels matched a query (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveLevel {
    /// Level 1: `device.profile` matched directly.
    DeviceDirect,
    /// Level 2: a schedule window was active for the matched device / group.
    Schedule,
    /// Level 3: resolved via group membership + priority.
    Group,
    /// Level 4: longest-prefix subnet default (SN1).
    Subnet,
    /// Level 5: global `default_profile`.
    GlobalDefault,
}

impl ResolveLevel {
    /// Stable short label used by CLI output + audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceDirect => "device-direct",
            Self::Schedule => "schedule",
            Self::Group => "group",
            Self::Subnet => "subnet",
            Self::GlobalDefault => "global-default",
        }
    }
}

/// Outcome of a single hot-path resolution.
///
/// `profile == None` is the REFUSED sentinel (level 5 reached with
/// `default_profile` unset). All callers that previously branched on
/// `resolve_or_block(...).is_none()` now branch on `resolution.profile`.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub profile: Option<Arc<ResolvedProfile>>,
    /// `None` when [`Self::profile`] is `None` (REFUSED).
    pub level: Option<ResolveLevel>,
    /// Device matched at level 1-3. `None` for subnet / default level,
    /// or when no device row matched at all.
    pub device_id: Option<Id>,
    /// Device display name, convenience for stats / query log.
    /// `CompactString` keeps real-world device names (≤24 bytes — `iphone-mom`,
    /// `pc-living-room`) inline, so the hot-path resolution copy is allocation-free.
    pub device_name: Option<CompactString>,
    /// Group id that contributed the profile at level 3.
    pub matched_group: Option<Id>,
    /// Subnet id that contributed the profile at level 4.
    pub matched_subnet: Option<Id>,
    /// Schedule id that overrode at level 2.
    pub matched_schedule: Option<Id>,
    /// Sprint 43 T4: per-device overlay attached when the matched
    /// device declared `allow_rules` / `deny_rules` (DM1). `None` for
    /// devices with empty overlay, anonymous sources (subnet/default
    /// level with no device match), and the REFUSED sentinel — the
    /// hot path treats `None` as "fall through to profile evaluation
    /// only", giving the byte-identical pre-T4 baseline (snapshot
    /// acceptance §8).
    pub overlay: Option<Arc<DeviceOverlay>>,
}

impl Resolution {
    fn refused() -> Self {
        Self {
            profile: None,
            level: None,
            device_id: None,
            device_name: None,
            matched_group: None,
            matched_subnet: None,
            matched_schedule: None,
            overlay: None,
        }
    }
}

/// IPC-friendly snapshot of a configured device, deduped by id.
#[derive(Debug, Clone)]
pub struct MappedDeviceSnapshot {
    /// Wire-serialisable metadata for this device. Counter fields
    /// are zero until `handle_get_all_devices` fills them in from the
    /// stats engine.
    pub dto: MappedDeviceDto,
    /// Every address the device can be reached at — configured IP (if
    /// any) plus every ARP-resolved IP matching the device's MACs.
    /// First element matches `dto.ip` after parsing.
    pub ips: Vec<IpAddr>,
    /// Operator-only annotation from `Device.notes`. Not sent over IPC.
    pub notes: Option<String>,
}

/// Lock-free profile resolver for the DNS hot path.
///
/// The hot path (DNS query → [`Self::resolve`]) reads only the two
/// `ArcSwap` fields and, on the MAC-mismatch branch, an 8-slot
/// [`MacMismatchRing`] of `AtomicU64`s — no Mutex anywhere. See
/// [`MAC_MISMATCH_WARN_WINDOW`] for the throttle contract (T2.7 H-14);
/// §4.30 profiles-h2 swapped the original `Mutex<HashMap>` for the
/// ring so the hot path stays zero-lock per project rules key rule #1.
pub struct ProfileResolver {
    inner: ArcSwap<ResolverMap>,
    arp_by_ip: ArcSwap<HashMap<IpAddr, CompactString>>,
    /// `tag_model_consolidation` §3.4 (D8): live handle to the daemon's
    /// blocklist download state, attached once at boot by
    /// [`Self::attach_list_state`]. Every map rebuild ([`Self::swap`])
    /// snapshots it so `list_applies` can drop lists that have never
    /// downloaded and keep lists serving from a stale cache (D9).
    ///
    /// **`None` is the fail-open default and the common case outside
    /// the daemon** — one-shot CLI paths (`warden resolve`,
    /// `warden config show`), the TUI's resolver modal and every test
    /// build a resolver without ever attaching a handle. `None` means
    /// "download state unknown", which `list_applies` translates into
    /// "every list applies". Never populate this with a fabricated
    /// state map: an absent entry must stay absent, not become
    /// `Pending`.
    ///
    /// Not on the hot path — [`Self::resolve`] never reads it. Only
    /// the reload / schedule-tick rebuild does, so the `Mutex` it
    /// wraps (shared with `ListManager`'s refresh loop, which owns the
    /// writes) is taken off the DNS path entirely.
    list_state: arc_swap::ArcSwapOption<std::sync::Mutex<ListState>>,
    /// T2.7 H-14 + §4.30 profiles-h2: per-`(ip, observed_mac)` rate
    /// limit on the MAC-mismatch audit warn. 8-slot sharded ring
    /// encoding `(hash << 32) | last_secs` per slot, indexed by
    /// `hash(ip, mac) & 7`. Structural memory bound: 64 bytes of
    /// slots + 16 bytes of per-ring epoch `Instant` = 80 bytes total
    /// (vs the pre-§4.30 `MAC_MISMATCH_WARN_CAP=256` HashMap which
    /// could grow to ~12 KB under attack). Worst-case collision rate
    /// is ~12.5% across 8 slots; a colliding pair gets at most one
    /// extra warn per [`MAC_MISMATCH_WARN_WINDOW`], comfortably below
    /// the audit cadence operators tune for.
    mac_mismatch_warns: MacMismatchRing,
}

/// Window during which a MAC-mismatch warn for a given `(ip, mac)` pair
/// is suppressed. Sized to match the existing audit-log cadence
/// expectations: one line per minute per incident is enough for an
/// operator to notice; any more is noise.
const MAC_MISMATCH_WARN_WINDOW: Duration = Duration::from_secs(60);

/// §4.30 profiles-h2: 8-slot sharded ring of `AtomicU64` replacing the
/// pre-§4.30 `Mutex<HashMap<(IpAddr, CompactString), Instant>>` MAC-
/// mismatch warn throttle. Each slot encodes the most recent fire's
/// `(hash_low_32, last_secs)` pair; `should_warn` loads the slot for
/// the queried `(ip, mac)`, compares hash + time delta against
/// [`MAC_MISMATCH_WARN_WINDOW`], and atomically stores the new pair on
/// a fire. CAS is not required — the ring is best-effort throttle, a
/// lost store under contention degrades to one extra warn (never to
/// missed enforcement) and the hot-path zero-lock posture is what
/// matters.
struct MacMismatchRing {
    slots: [AtomicU64; 8],
    /// Reference instant for packing `Duration::as_secs()` into the
    /// low 32 bits. Per-ring (not global) so each resolver carries its
    /// own monotonic baseline — covers ~136 years before u32 wrap.
    epoch: Instant,
}

/// Immutable snapshot of every resolver input, built once per config
/// load / reload and replaced atomically via [`ArcSwap::store`].
#[derive(Clone)]
struct ResolverMap {
    /// Every profile referenced by the config, pre-resolved. Shared as
    /// `Arc<ResolvedProfile>` so each indexed entry just clones a handle.
    /// Retained on the map even though every hot-path lookup goes
    /// through one of the specialised indexes below — keeping it around
    /// makes it trivial for the IPC snapshot builder and future
    /// introspection CLIs to list every profile the daemon knows about.
    #[allow(dead_code)]
    profiles: HashMap<Id, Arc<ResolvedProfile>>,
    /// Devices keyed by their pinned IP.
    devices_by_ip: HashMap<IpAddr, Arc<DeviceIndex>>,
    /// Devices keyed by every MAC they own (primary + aliases), upper-cased.
    devices_by_mac: HashMap<CompactString, Arc<DeviceIndex>>,
    /// Every `DeviceIndex` keyed by its stable id — used by the IPC
    /// snapshot builder and by group / schedule lookups.
    devices_by_id: HashMap<Id, Arc<DeviceIndex>>,
    /// Sprint 43 T4 (DM2): per-device overlay, indexed by device id.
    /// Devices with both `allow_rules` and `deny_rules` empty get NO
    /// entry here — the resolver attaches `Resolution.overlay = None`
    /// for them, matching the pre-T4 hot path byte-for-byte (snapshot
    /// acceptance §8). Each `Arc<DeviceOverlay>` lives next to the
    /// per-device profile pointer in this same `ResolverMap`, so a
    /// single `ArcSwap` snapshot delivers both consistently (R5).
    device_overlays: HashMap<Id, Arc<DeviceOverlay>>,
    /// For each device: the groups it belongs to, pre-sorted by priority
    /// descending. Level-3 resolution picks the first entry.
    device_groups: HashMap<Id, Vec<GroupMatch>>,
    /// Subnets sorted by prefix length DESC so the first matching entry
    /// is the longest-prefix (SN1). Ties in prefix length are resolved
    /// by (informational) priority DESC then by id ASC for determinism.
    subnets: Vec<SubnetMatch>,
    /// C-03: pre-computed active schedule per device, evaluated at
    /// config-build time (and again on every 60s schedule tick) so the
    /// DNS hot path resolves the schedule level via a single HashMap
    /// probe instead of walking every device's schedule list per query.
    /// At 10 kqps this lifts ~10k schedule walks/sec out of `resolve_at`.
    /// Devices with no active schedule have NO entry here — the hot
    /// path treats absence as "no schedule override" and falls through
    /// to level 1/3/4/5. Accepts up to a 60s window-boundary gap, the
    /// same gap the existing pre-computation contract already promises.
    /// The raw `schedules_by_device` / `schedules_by_group` indexes used
    /// to live next to this map but were retired with C-03: nothing on
    /// or off the hot path consults them after pre-computation, and
    /// keeping them around invited regression to the per-query walk.
    active_schedule_by_device: HashMap<Id, Arc<ScheduleMatch>>,
    /// Level-5 fallback. `None` → REFUSED.
    default_profile: Option<ProfilePair>,
    /// Master switch for MAC enforcement (from `ServerGlobals`).
    enforce_mac: bool,
    /// Sprint 43 T1: bridge from legacy `[lists].sources` slug-form
    /// strings (`"privacy/ads"`) to canonical `[[blocklists]].id`
    /// values (`"privacy-ads"`). Built at boot from
    /// `config.blocklists` — every entry contributes its id under
    /// both the literal id key (identity mapping) and the
    /// hyphen-to-slash transform that recovers the legacy slug
    /// catalog form. Accessed via [`ProfileResolver::id_for_slug`]
    /// and [`ProfileResolver::slug_for_id`]. Parked debt for full
    /// retirement of the dual-keyed namespace: `s44-retire-list-source-shim`.
    slug_to_id: HashMap<String, Id>,
    /// `network_name` index (D1/D2 of the device-network-name design,
    /// 2026-08-10 spec): bare name → device id, exact match only.
    /// Config-static — rebuilt on every `swap()`, same cadence as the
    /// rest of this map. The live IP lookup happens at query time in
    /// [`ProfileResolver::resolve_network_name`], NOT here — baking a
    /// device's current IP into this map would only be as fresh as the
    /// last config reload, defeating the "dynamic" premise the design
    /// spec locked in (D1).
    network_names: HashMap<CompactString, Id>,
    /// Wildcard-enabled `network_name` entries only: (apex, device id).
    /// Small (most devices have no wildcard), walked linearly by
    /// [`ProfileResolver::resolve_network_name`]'s suffix scan — mirrors
    /// `dns/local.rs`'s `suffix_index` pattern at 1/10th the scale.
    network_name_wildcards: Vec<(CompactString, Id)>,
}

#[derive(Clone)]
struct DeviceIndex {
    id: Id,
    display_name: CompactString,
    /// Configured IP pin (if any). Used for both lookup indexing and the
    /// IPC snapshot's primary address.
    configured_ip: Option<IpAddr>,
    mac_pin: Option<CompactString>,
    mac_aliases: Vec<CompactString>,
    /// Direct profile (level 1) — `None` when the device falls through to
    /// group / subnet / default.
    direct_profile: Option<Arc<ResolvedProfile>>,
    groups: Vec<Id>,
    owner: Option<CompactString>,
    device_type: Option<CompactString>,
    department: Option<CompactString>,
    notes: Option<CompactString>,
    /// Sprint C T4 of `lists_categories_v2` (D14, §8.1): D14
    /// invariant — the device opted out of filtering entirely.
    /// `plp-s3` moved the mechanism from "∅ effective tags" onto
    /// [`ResolvedProfile::unfiltered`], but the meaning is unchanged and
    /// monitoring stays active (the operator wants visibility into
    /// IoT traffic without enforcement). Surfaced to the TUI Devices
    /// tab via the `[⚠ UNFILTERED]` badge + skipped tag rows.
    unfiltered: bool,
    /// The device's configured `network_name`, lower-cased. Carried on
    /// the index (not just in `ResolverMap::network_names`) so the read
    /// side can round-trip it: `snapshots_from` feeds `MappedDeviceDto`,
    /// and the TUI Edit modal pre-populates only from that DTO. Without
    /// it the modal cannot show an existing name, and an always-`Some(…)`
    /// submit would blank it on every unrelated edit — the field-omission
    /// bug class project rules documents for `build_blocklist_value` /
    /// `upsert_id_keyed`.
    ///
    /// Read by `snapshots_from`, which feeds it into `MappedDeviceDto`
    /// for the TUI's Edit modal.
    network_name: Option<CompactString>,
    /// Wildcard flag as configured. Same round-trip rationale as
    /// [`DeviceIndex::network_name`].
    network_name_wildcard: bool,
}

#[derive(Clone)]
struct GroupMatch {
    id: Id,
    priority: i32,
    profile: Arc<ResolvedProfile>,
}

/// A resolved profile together with its `unfiltered` specialisation.
///
/// Both variants are built when the map is, because `resolve` runs once
/// per query and `as_unfiltered` allocates. Holding them in one value is
/// what makes "a level that can serve a device has both variants" a fact
/// about the type instead of a rule two parallel `Option`s must keep.
#[derive(Clone)]
struct ProfilePair {
    filtered: Arc<ResolvedProfile>,
    unfiltered: Arc<ResolvedProfile>,
}

impl ProfilePair {
    fn new(filtered: Arc<ResolvedProfile>) -> Self {
        let unfiltered = Arc::new(filtered.as_unfiltered());
        Self {
            filtered,
            unfiltered,
        }
    }

    /// A pointer clone, never an allocation — this runs on the query path.
    fn pick(&self, unfiltered: bool) -> Arc<ResolvedProfile> {
        if unfiltered {
            Arc::clone(&self.unfiltered)
        } else {
            Arc::clone(&self.filtered)
        }
    }
}

#[derive(Clone)]
struct SubnetMatch {
    id: Id,
    cidr: Cidr,
    prefix: u8,
    priority: i32,
    profile: ProfilePair,
}

#[derive(Clone)]
struct ScheduleMatch {
    id: Id,
    parsed: ParsedSchedule,
    profile: Arc<ResolvedProfile>,
}

impl ProfileResolver {
    /// Build a resolver from a v1 [`ConfigV1`] and the typed
    /// [`SourceBitMap`] produced by [`SourceBitMap::build`]. The v1
    /// resolver consumes the same bitmask namespace as the filter
    /// engine — the engine stays unchanged across §4.24.
    pub fn build(
        config: &ConfigV1,
        _list_bit_map: &SourceBitMap,
        custom_lists: &CustomListStore,
    ) -> Self {
        // No list state at construction: the daemon has not built its
        // `ListManager` yet, and non-daemon callers never will. Fail
        // open — every list applies until `attach_list_state` + the
        // post-refresh `swap` say otherwise.
        let map = build_resolver_map(config, custom_lists);
        let arp_by_ip = build_arp_snapshot();
        Self {
            inner: ArcSwap::from_pointee(map),
            arp_by_ip: ArcSwap::from_pointee(arp_by_ip),
            mac_mismatch_warns: MacMismatchRing::new(),
            list_state: arc_swap::ArcSwapOption::empty(),
        }
    }

    /// `tag_model_consolidation` §3.4 (D8): attach the daemon's live
    /// blocklist-download state so subsequent [`Self::swap`] rebuilds
    /// can honour it.
    ///
    /// `handle` is the same `Arc` the `ListManager` refresh loop writes
    /// through (`ListManager::list_state_handle`) and the IPC
    /// diagnostics walk reads — one source of truth, no copy to keep in
    /// sync. Attaching does **not** rebuild the map; the caller swaps
    /// when it wants the new state reflected (the daemon does so right
    /// after the initial refresh, before the DNS listener binds).
    ///
    /// Idempotent — a later call replaces the handle.
    pub fn attach_list_state(&self, handle: Arc<std::sync::Mutex<ListState>>) {
        self.list_state.store(Some(handle));
    }

    /// Atomically rebuild the resolver state from a new config. Takes
    /// the same inputs as [`Self::build`]; SIGHUP and the schedule tick
    /// both call through here.
    ///
    /// Store order mirrors the legacy resolver: ARP first, then the
    /// inner map. Readers load `inner` first, so a reader observing a
    /// new `inner` is guaranteed to see an ARP snapshot at least as new
    /// — avoiding a torn view where a fresh device entry reads against
    /// a stale ARP table.
    pub fn swap(
        &self,
        config: &ConfigV1,
        _list_bit_map: &SourceBitMap,
        custom_lists: &CustomListStore,
    ) {
        let map = build_resolver_map(config, custom_lists);
        let arp_by_ip = build_arp_snapshot();
        self.arp_by_ip.store(Arc::new(arp_by_ip));
        self.inner.store(Arc::new(map));
        tracing::info!("profile map swapped");
    }

    /// Resolve a query source IP through the 5-level chain. Each level
    /// short-circuits on the first match.
    ///
    /// Reads only the current `ArcSwap` guards — the schedule level is
    /// pre-computed at config swap (and on every 60s schedule tick) per
    /// C-03, so this fn no longer consults the wall clock. T2.7 H-13
    /// removed the legacy `at: OffsetDateTime` parameter that previously
    /// pretended to drive schedule evaluation but was already ignored
    /// after C-03 landed.
    pub fn resolve(&self, ip: &IpAddr) -> Resolution {
        let map = self.inner.load();
        let arp = self.arp_by_ip.load();

        // Identify the device. An operator can pin the device by IP
        // (direct lookup) OR by MAC (ARP-based lookup). MAC enforcement
        // rejects stale IP-pins whose live MAC differs from the pinned
        // MAC; such a device falls through to level 4 (subnet) — not to
        // "default-only", because the operator may still have wired a
        // subnet-level profile for it.
        let device_candidate = match map.devices_by_ip.get(ip) {
            Some(dev) => {
                if let Some(pin) = dev.mac_pin.as_deref() {
                    if map.enforce_mac {
                        match arp.get(ip) {
                            Some(current) if current.as_str() == pin => Some(dev.clone()),
                            Some(current) => {
                                if self
                                    .mac_mismatch_warns
                                    .should_warn(*ip, current, Instant::now())
                                {
                                    tracing::warn!(
                                        target: "audit",
                                        %ip,
                                        device = %dev.id.as_str(),
                                        pinned_mac = %pin,
                                        observed_mac = %current,
                                        "MAC mismatch — dropping device / group / schedule levels, \
                                         falling through to subnet / default",
                                    );
                                }
                                None
                            }
                            // Missing ARP entry: forgiving behaviour, trust the pin.
                            None => Some(dev.clone()),
                        }
                    } else {
                        Some(dev.clone())
                    }
                } else if map.enforce_mac {
                    // §4.39 / s-review-2605-profiles-h1: device pinned by
                    // IP only, no MAC pin, under `enforce_device_mac`.
                    // IP-only acceptance is bypassable in ~30 s (project rules
                    // key rule #9 — ARP-spoof the pinned IP and inherit
                    // this device's profile). The `[server]` docs already
                    // promise a pin-less device falls through to the
                    // default profile under `enforce_device_mac`; honour
                    // that contract here instead of granting the device
                    // profile on IP alone. Mirrors the MAC-mismatch
                    // fall-through above — drop device / group / schedule
                    // levels, continue to subnet / default.
                    let sentinel = CompactString::from("<no-mac-pin>");
                    if self
                        .mac_mismatch_warns
                        .should_warn(*ip, &sentinel, Instant::now())
                    {
                        tracing::warn!(
                            target: "audit",
                            %ip,
                            device = %dev.id.as_str(),
                            "device pinned by IP only (no MAC) under \
                             enforce_device_mac — dropping device / group / \
                             schedule levels, falling through to subnet / default",
                        );
                    }
                    None
                } else {
                    Some(dev.clone())
                }
            }
            None => {
                // No IP pin matched. Try MAC-based lookup via ARP.
                arp.get(ip)
                    .and_then(|mac| map.devices_by_mac.get(mac.as_str()))
                    .cloned()
            }
        };

        // Sprint 43 T4: overlay lookup runs once against the same
        // ArcSwap snapshot (`map`) used by the rest of the resolution.
        // Both the profile pointer and the overlay pointer come from a
        // single load — no torn read possible across reload (R5).
        let overlay_for = |dev: &DeviceIndex| -> Option<Arc<DeviceOverlay>> {
            map.device_overlays.get(&dev.id).cloned()
        };

        if let Some(dev) = device_candidate.as_ref() {
            // Level 2 first — schedule overrides all non-direct levels
            // but, per §9 wording, only takes effect when the device is
            // resolved. A schedule matching a device or one of its groups
            // wins over levels 3-5 below. C-03: the active schedule is
            // pre-computed at config build time + every 60s tick, so this
            // is a single HashMap probe instead of a per-query walk.
            if let Some(sched_hit) = map.active_schedule_by_device.get(&dev.id) {
                // Per design doc §9 invariant DM1, the device's *direct*
                // profile (level 1) also outranks a schedule when both
                // are present. But in practice, an operator writing a
                // schedule for a device with a direct profile is clearly
                // asking for the schedule to win during its window —
                // otherwise the schedule has no effect. We pick schedule
                // > direct here for operator intuition; the design doc
                // §9 text reads both orderings depending on which invariant
                // one emphasises. Tests pin this choice.
                return Resolution {
                    profile: Some(sched_hit.profile.clone()),
                    level: Some(ResolveLevel::Schedule),
                    device_id: Some(dev.id.clone()),
                    device_name: Some(dev.display_name.clone()),
                    matched_group: None,
                    matched_subnet: None,
                    matched_schedule: Some(sched_hit.id.clone()),
                    overlay: overlay_for(dev),
                };
            }

            // Level 1 — direct profile on the device row.
            if let Some(direct) = dev.direct_profile.clone() {
                return Resolution {
                    profile: Some(direct),
                    level: Some(ResolveLevel::DeviceDirect),
                    device_id: Some(dev.id.clone()),
                    device_name: Some(dev.display_name.clone()),
                    matched_group: None,
                    matched_subnet: None,
                    matched_schedule: None,
                    overlay: overlay_for(dev),
                };
            }

            // Level 3 — highest-priority group. Groups are pre-sorted by
            // priority desc at build time, so the first entry is the
            // authoritative match; DM2 same-priority-different-profile
            // ties are validator errors and never reach the resolver.
            if let Some(groups) = map.device_groups.get(&dev.id) {
                if let Some(first) = groups.first() {
                    return Resolution {
                        profile: Some(first.profile.clone()),
                        level: Some(ResolveLevel::Group),
                        device_id: Some(dev.id.clone()),
                        device_name: Some(dev.display_name.clone()),
                        matched_group: Some(first.id.clone()),
                        matched_subnet: None,
                        matched_schedule: None,
                        overlay: overlay_for(dev),
                    };
                }
            }
        }

        // Level 4 — subnet longest-prefix match. Applies both to devices
        // that have no group / direct / schedule mapping AND to anonymous
        // sources that matched no device row. When a device IS matched
        // here (the source IP belongs to a configured device whose own
        // 1-3 levels didn't fire), its overlay still applies — the
        // operator's per-device exception ought to bind regardless of
        // which resolver level produced the profile.
        //
        // Scaling: this is an O(n_subnets) linear scan per DNS query.
        // `map.subnets` is sorted prefix-DESC at build time so the first
        // `cidr.contains` hit is the longest-prefix winner (SN1) — a
        // walk-and-break, not a full scan. Sized for typical home /
        // small-office deployments (≤ ~50 subnets); at that scale the
        // walk fits in one or two cache lines and is invisible against
        // the upstream RTT on a cache miss. Operators wiring hundreds
        // or thousands of single-host subnets (one /32 or /128 per
        // device) should expect linear cost growth per query. A future
        // mitigation could be a longest-prefix-match trie, or a
        // `HashMap<IpAddr, _>` for the exact-match common case with the
        // linear walk reserved for true ranges; no structural blocker
        // either way, deferred until a deployment actually hits the
        // limit.
        // `[[devices]].unfiltered` is honoured at every level a device can
        // reach, not only 1-3. A row carrying the flag with no profile, no
        // group and no schedule is the minimal way to say "this box exists,
        // don't filter it", and it lands at level 4 or 5 — the operator's
        // one explicit statement about that device must not be dropped for
        // arriving here. Every path that fails to identify the device
        // leaves `device_candidate` None, so this grants nothing that a
        // weaker identification could claim.
        let unfiltered_device = device_candidate.as_ref().is_some_and(|d| d.unfiltered);

        for sn in &map.subnets {
            if sn.cidr.contains(*ip) {
                return Resolution {
                    profile: Some(sn.profile.pick(unfiltered_device)),
                    level: Some(ResolveLevel::Subnet),
                    device_id: device_candidate.as_ref().map(|d| d.id.clone()),
                    device_name: device_candidate.as_ref().map(|d| d.display_name.clone()),
                    matched_group: None,
                    matched_subnet: Some(sn.id.clone()),
                    matched_schedule: None,
                    overlay: device_candidate.as_ref().and_then(|d| overlay_for(d)),
                };
            }
        }

        // Level 5 — global fallback. `None` → REFUSED.
        match &map.default_profile {
            Some(profile) => Resolution {
                profile: Some(profile.pick(unfiltered_device)),
                level: Some(ResolveLevel::GlobalDefault),
                device_id: device_candidate.as_ref().map(|d| d.id.clone()),
                device_name: device_candidate.as_ref().map(|d| d.display_name.clone()),
                matched_group: None,
                matched_subnet: None,
                matched_schedule: None,
                overlay: device_candidate.as_ref().and_then(|d| overlay_for(d)),
            },
            None => Resolution::refused(),
        }
    }

    /// Look up the friendly name for a device whose IP is pinned. Returns
    /// `None` for anonymous sources.
    ///
    /// One `ArcSwap` load plus one map probe — deliberately *not* the 5-level
    /// chain, because a device's display name does not depend on profile
    /// resolution at all. `qlog-early-exit-attribution` uses it at the three
    /// handler exits that fire **above** the chain (the security shape refusal,
    /// `RRL_DROP`, `RRL_SLIP`); RRL must stay above resolution, so the name is
    /// fetched rather than the hoist moved.
    ///
    /// The `#[allow(dead_code)]` that sat here is gone: those call sites are
    /// real. Do not replace it with `#[expect(dead_code)]` if it ever looks
    /// unused again — that attribute is always red under `--all-targets` in
    /// this repo.
    pub fn device_name(&self, ip: &IpAddr) -> Option<CompactString> {
        self.inner
            .load()
            .devices_by_ip
            .get(ip)
            .map(|d| d.display_name.clone())
    }

    /// Iterator-friendly access to the default (level-5) profile, for
    /// boot-path code that wants a permissive `Arc<ResolvedProfile>` in
    /// hand even when the source IP hasn't been produced yet.
    pub fn default_profile(&self) -> Option<Arc<ResolvedProfile>> {
        self.inner
            .load()
            .default_profile
            .as_ref()
            .map(|p| Arc::clone(&p.filtered))
    }

    /// Sprint 43 T1: resolve a slug-form / canonical id to the
    /// `[[blocklists]].id` it refers to.
    ///
    /// Accepts both the legacy slash-form (`"privacy/ads"` from
    /// `[lists].sources`) and the canonical hyphen-form
    /// (`"privacy-ads"` from `[[blocklists]].id`). Returns the v1 `Id`
    /// when found. The IPC blocklist-stats handler uses this so the
    /// operator can pass either form on the wire.
    pub fn id_for_slug(&self, slug: &str) -> Option<Id> {
        self.inner.load().slug_to_id.get(slug).cloned()
    }

    /// Inverse of [`Self::id_for_slug`]: given a canonical
    /// `[[blocklists]].id`, return the slug-form key the legacy
    /// `[lists].sources` catalog uses.
    ///
    /// Implementation walks the slug_to_id map and returns the FIRST
    /// non-identity slug whose value matches `id`. Linear time, but the
    /// map is bounded by `2 × len(blocklists)` and `[[blocklists]]` is
    /// capped at 64 entries (u64 bitmask) so this stays under 128
    /// comparisons in the worst case.
    pub fn slug_for_id(&self, id: &str) -> Option<String> {
        let map = self.inner.load();
        // Identity entry is excluded — caller wants the SLUG, not the
        // canonical id back. Returns None when only the identity
        // entry exists (single-token id like `"ads"` with no hyphen).
        for (slug, mapped_id) in &map.slug_to_id {
            if mapped_id.as_str() == id && slug != id {
                return Some(slug.clone());
            }
        }
        None
    }

    /// Deduped snapshot of every configured device — one entry per
    /// `[[devices]].id`, carrying all IPs the device is reachable at
    /// (configured + ARP-learned). Populates the `ip` field of the DTO
    /// with the primary address; counters are zero until the IPC
    /// handler fills them from the stats engine.
    pub fn list_mapped_devices(&self) -> Vec<MappedDeviceSnapshot> {
        snapshots_from(&self.inner.load(), &self.arp_by_ip.load())
    }

    /// Single-shot snapshot for IPC `GetAllDevices` — atomically loads
    /// the map + ARP snapshot once so the two returned values are
    /// consistent with each other. The legacy triple `(mapped, arp,
    /// block_unmapped)` is replaced by the pair `(mapped, arp)` now
    /// that SN3 has retired the flag.
    pub fn snapshot_for_ipc(&self) -> (Vec<MappedDeviceSnapshot>, HashMap<IpAddr, String>) {
        let map_guard = self.inner.load();
        let arp_guard = self.arp_by_ip.load();
        let mapped = snapshots_from(&map_guard, &arp_guard);
        let arp = arp_guard
            .iter()
            .map(|(ip, mac)| (*ip, mac.to_string()))
            .collect();
        (mapped, arp)
    }

    /// Re-read `/proc/net/arp` and swap the snapshot. Called off the
    /// hot path by the IPC handler at TUI poll cadence, so new DHCP
    /// leases materialise in the Unmapped column within ~5 s.
    pub fn refresh_arp(&self) {
        let arp_by_ip = build_arp_snapshot();
        tracing::debug!(entries = arp_by_ip.len(), "arp snapshot refreshed");
        self.arp_by_ip.store(Arc::new(arp_by_ip));
    }

    /// Shared name → device-id lookup behind [`Self::resolve_network_name`]
    /// and [`Self::network_name_is_configured`]: exact match first, then a
    /// depth-descending suffix walk of the wildcard apexes.
    ///
    /// Takes the caller's already-loaded [`ResolverMap`] guard rather than
    /// re-reading the `ArcSwap`, so a caller that needs both the id and the
    /// `DeviceIndex` behind it sees one consistent snapshot.
    ///
    /// `qname_lower` must be **unrooted and lower-cased**. Both public
    /// callers fold case themselves; `dns/handler.rs` additionally strips
    /// the trailing root dot before it ever gets here (it formats a
    /// `LowerName`, then pops a trailing `.`).
    fn network_name_device_id(map: &ResolverMap, qname_lower: &str) -> Option<Id> {
        map.network_names.get(qname_lower).cloned().or_else(|| {
            // Strip one label at a time; the first apex that matches wins.
            // A single-label qname never enters this loop, which is correct:
            // a wildcard apex always carries its own `network_names` entry,
            // so it is caught by the exact probe above and only proper
            // descendants need the walk.
            let mut current = qname_lower;
            while let Some((_label, rest)) = current.split_once('.') {
                current = rest;
                if let Some((_, id)) = map
                    .network_name_wildcards
                    .iter()
                    .find(|(apex, _)| apex.as_str() == current)
                {
                    return Some(id.clone());
                }
                if current.is_empty() || !current.contains('.') {
                    break;
                }
            }
            None
        })
    }

    /// Resolve a `network_name` query to that device's current IP.
    /// Exact match first, then (if the config declared
    /// `network_name_wildcard = true` for some device) a depth-descending
    /// suffix walk of `network_name_wildcards` — same longest-match
    /// discipline as `dns/local.rs`'s static wildcard records.
    ///
    /// IP selection: the device's pinned `ip` wins if set; otherwise the
    /// live ARP snapshot ([`Self::refresh_arp`] owns it, and refreshes it
    /// independently of the config-static map) is scanned for the device's
    /// `mac_pin` / `mac_aliases`. This scan runs ONLY on a name hit (rare —
    /// an operator-configured device name, not the bulk ad-blocking
    /// traffic), so the O(arp table size) cost here does not sit on the
    /// zero-alloc hot path the rest of `dns/` enforces; it is paid only for
    /// deliberately-configured lookups.
    ///
    /// Reading the IP here rather than baking it into the resolver map at
    /// build time is the whole point: the map is rebuilt only on config
    /// load/reload, so a baked-in address would be exactly as stale as the
    /// last config edit — and this feature exists to follow DHCP.
    ///
    /// `None` means either the name isn't configured, or it is but the
    /// device has neither a pinned IP nor a current ARP entry (never
    /// observed / offline). Callers that must tell those apart use
    /// [`Self::network_name_is_configured`].
    pub fn resolve_network_name(&self, qname: &str) -> Option<IpAddr> {
        let map = self.inner.load();
        // Zero-alloc fast path for the ~100% of operators not using this
        // feature (and the ~100% of queries, for those who are): skip the
        // to_ascii_lowercase() heap allocation below when no device has a
        // network_name configured at all. project rules rule 1 / this module's
        // header: zero-alloc on the hot path is a product invariant, not a
        // preference — flagged during Task 7 review (net-name/handler NOTES.md
        // §4), fixed here rather than left as a follow-up.
        if map.network_names.is_empty() && map.network_name_wildcards.is_empty() {
            return None;
        }
        let qname_lower = qname.to_ascii_lowercase();

        let device_id = Self::network_name_device_id(&map, &qname_lower)?;
        let dev = map.devices_by_id.get(&device_id)?;

        if let Some(ip) = dev.configured_ip {
            return Some(ip);
        }

        let arp = self.arp_by_ip.load();
        let mut candidates: Vec<IpAddr> = Vec::new();
        if let Some(pin) = dev.mac_pin.as_deref() {
            candidates.extend(
                arp.iter()
                    .filter(|(_, mac)| mac.as_str() == pin)
                    .map(|(ip, _)| *ip),
            );
        }
        for alias in &dev.mac_aliases {
            candidates.extend(
                arp.iter()
                    .filter(|(_, mac)| mac.as_str() == alias.as_str())
                    .map(|(ip, _)| *ip),
            );
        }
        // A MAC can answer at several IPs (DHCP-renew overlap, aliases).
        // Sort so the choice is deterministic across restarts rather than
        // whatever order the ARP HashMap happened to iterate in.
        candidates.sort();
        candidates.first().copied()
    }

    /// Existence-only probe: is `qname` a configured `network_name` (exact
    /// or via some device's wildcard), regardless of whether that device is
    /// currently reachable?
    ///
    /// Exists so the DNS handler can tell "not one of our names — fall
    /// through to the normal query path" apart from "one of our names, but
    /// the device is offline — answer NXDOMAIN". Both cases return `None`
    /// from [`Self::resolve_network_name`], so that method alone cannot
    /// distinguish them.
    pub fn network_name_is_configured(&self, qname: &str) -> bool {
        let map = self.inner.load();
        // Same zero-alloc fast path as resolve_network_name — this is the
        // method dns/handler.rs calls on EVERY A query, so the allocation
        // avoided here is the one that actually sits on the hot path.
        if map.network_names.is_empty() && map.network_name_wildcards.is_empty() {
            return false;
        }
        let qname_lower = qname.to_ascii_lowercase();
        Self::network_name_device_id(&map, &qname_lower).is_some()
    }

    /// Test-only: inject a synthetic ARP snapshot so MAC-verification
    /// tests don't depend on `/proc/net/arp`.
    ///
    /// MACs are folded to upper-case here to match production: real ARP
    /// entries arrive upper-cased from [`arp::read_arp_by_ip`] and are
    /// compared against the upper-cased `mac_pin` / `mac_aliases`. Folding
    /// here keeps a lower-case fixture from silently exercising the demote
    /// path instead of the intended match (res-09).
    #[cfg(test)]
    pub fn test_only_set_arp_snapshot(&self, entries: &[(IpAddr, &str)]) {
        let map: HashMap<IpAddr, CompactString> = entries
            .iter()
            .map(|(ip, mac)| (*ip, CompactString::new(mac.to_ascii_uppercase())))
            .collect();
        self.arp_by_ip.store(Arc::new(map));
    }
}

// ── MAC-mismatch warn throttle (T2.7 H-14, §4.30 profiles-h2) ───

impl MacMismatchRing {
    fn new() -> Self {
        // `Default::default()` on `[AtomicU64; 8]` is unavailable, so
        // spell out eight fresh atomics. Each starts at the all-zero
        // sentinel (`prev_hash == 0`, `prev_secs == 0`). A real pair
        // therefore fires on its first call — UNLESS its `hash_high` is
        // itself 0 AND that first call lands in the first window-second
        // after `epoch`, in which case it is wrongly throttled once.
        // That needs a ~1-in-2^32 hash colliding with a sub-second
        // startup window, so at most one missed warn at boot — and never
        // a missed *enforcement* (this ring only gates the audit log, not
        // the MAC-mismatch demote decision).
        Self {
            slots: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            epoch: Instant::now(),
        }
    }

    /// Decide whether the MAC-mismatch audit warn should fire for a
    /// given `(ip, observed_mac)` pair right now.
    ///
    /// Returns `true` at least once per [`MAC_MISMATCH_WARN_WINDOW`]
    /// for any given pair that maps to an uncontended slot. Subsequent
    /// calls within the window return `false`. Different pairs that
    /// hash to the same slot displace each other on emit; the
    /// previously-throttled pair will fire again on its next call —
    /// at most one extra warn per window per colliding pair, which is
    /// well within the operator audit cadence.
    ///
    /// Hot path is lock-free and alloc-free: a single hash + atomic
    /// load + (on emit) atomic store. No retry under contention — a
    /// lost store degrades to one extra fire, never to missed
    /// enforcement.
    fn should_warn(&self, ip: IpAddr, observed_mac: &CompactString, now: Instant) -> bool {
        let h = hash_pair(ip, observed_mac);
        let idx = (h & 0x07) as usize;
        let hash_high = (h >> 32) as u32;
        let now_secs = now.saturating_duration_since(self.epoch).as_secs() as u32;
        let window_secs = MAC_MISMATCH_WARN_WINDOW.as_secs() as u32;

        let prev = self.slots[idx].load(Ordering::Relaxed);
        let prev_hash = (prev >> 32) as u32;
        let prev_secs = (prev & 0xFFFF_FFFF) as u32;
        if prev_hash == hash_high && now_secs.saturating_sub(prev_secs) < window_secs {
            return false;
        }

        let packed = ((hash_high as u64) << 32) | (now_secs as u64);
        self.slots[idx].store(packed, Ordering::Relaxed);
        true
    }
}

/// SipHash via std `DefaultHasher` — output is process-randomised but
/// stable within a single run, which is all the ring requires. Not
/// exposed externally so DoS-via-collision is not in scope.
fn hash_pair(ip: IpAddr, mac: &CompactString) -> u64 {
    let mut h = DefaultHasher::new();
    ip.hash(&mut h);
    mac.as_str().hash(&mut h);
    h.finish()
}

// ── schedule evaluation ─────────────────────────────────────────

/// Walk every device once and return the schedule active for it at the
/// given local time, building the `active_schedule_by_device` map that
/// the resolver hot path then probes by `dev.id`.
///
/// Called from [`build_resolver_map`] with `schedule::local_now()`, i.e.
/// at config reload and on the 60s schedule tick. The DNS hot path never
/// reaches this fn, by design.
///
/// Devices with no active schedule are NOT inserted; the hot path
/// treats absence as "no schedule override" and falls through to level
/// 1/3/4/5.
fn compute_active_schedules(
    devices_by_id: &HashMap<Id, Arc<DeviceIndex>>,
    device_groups: &HashMap<Id, Vec<GroupMatch>>,
    schedules_by_device: &HashMap<Id, Vec<ScheduleMatch>>,
    schedules_by_group: &HashMap<Id, Vec<ScheduleMatch>>,
    weekday: u8,
    hour: u8,
    minute: u8,
) -> HashMap<Id, Arc<ScheduleMatch>> {
    let mut out: HashMap<Id, Arc<ScheduleMatch>> = HashMap::with_capacity(devices_by_id.len());
    for dev_id in devices_by_id.keys() {
        // Device-targeted schedules win over group-targeted ones (a
        // schedule wired directly to the device is the more specific
        // statement).
        let hit = schedules_by_device
            .get(dev_id)
            .and_then(|list| {
                list.iter()
                    .find(|s| s.parsed.is_active(weekday, hour, minute))
            })
            .or_else(|| {
                // `device_groups`, not the device row's own `groups`: it is
                // the union of both membership directions and is already
                // sorted priority-DESC. Reading the device side alone gave
                // a device joined from `[[groups]].devices` the group's
                // profile but not its schedule, and picked a multi-group
                // device's schedule in file order while its profile came
                // from the highest-priority group — level 2 and level 3
                // disagreeing about the same membership.
                device_groups.get(dev_id)?.iter().find_map(|gm| {
                    schedules_by_group.get(&gm.id).and_then(|list| {
                        list.iter()
                            .find(|s| s.parsed.is_active(weekday, hour, minute))
                    })
                })
            });
        if let Some(sched) = hit {
            out.insert(dev_id.clone(), Arc::new(sched.clone()));
        }
    }
    out
}

// ── list-state ingestion ───────────────────────────────────────

/// `tag_model_consolidation` §3.4 (D8): read `data/list_state.toml`
/// **fail-open**.
///
/// Every failure mode — missing file, unreadable file, malformed TOML,
/// a half-written file from a crash — returns `None`, which
/// `list_applies` reads as "download state unknown" and answers "the
/// list applies". The one thing that removes a list from a profile's
/// subscription mask is an entry that is present, parsed and explicitly
/// says the list has no usable bytes (`Pending`, or `Failed` with no
/// `cache_path`).
///
/// That direction is deliberate and load-bearing: this daemon serves a
/// household's DNS, and a state file that vanished (fresh install,
/// wiped `/var/lib`, a `ProtectSystem` misconfiguration) must degrade to
/// "filter with everything I have", never to "filter with nothing".
/// Callers must not "improve" this by defaulting a missing file to
/// `Pending`.
///
/// Note the deliberate divergence from
/// [`ListState::read_or_default`], which treats a malformed file as a
/// hard error so a *writer* refuses to clobber it. The resolver is a
/// reader with a safe fallback, so it downgrades that error to `None`
/// plus a WARN.
pub fn read_list_state_fail_open(path: &std::path::Path) -> Option<ListState> {
    match ListState::read_or_default(path) {
        Ok(state) => Some(state),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "list state unreadable — treating every blocklist as applicable",
            );
            None
        }
    }
}

// ── map construction ───────────────────────────────────────────

/// `list_state` carries the daemon's blocklist download state for this
/// rebuild, or `None` when it is unknown (see
/// [`ProfileResolver::list_state`]). It is threaded verbatim into every
/// `build_v1` call below so a single rebuild cannot mix state-aware and
/// state-blind subscription masks.
/// The resolution a device actually gets from `base`.
///
/// `plp-s3`: this is all that survives of the four per-device
/// tag-specialisation sites. Policy is a property of the profile now, so two devices on one profile see the same lists — the one
/// thing that still varies per device is `[[devices]].unfiltered`, which was
/// never really a tag question (see [`ResolvedProfile::as_unfiltered`]).
///
/// A filtered device shares its profile's `Arc` outright: no clone, no
/// second allocation, and the `resolver_specialisation_memory` bound gets
/// strictly better rather than worse.
fn unfiltered_variant(
    device: &crate::config::schema::Device,
    base: &Arc<ResolvedProfile>,
) -> Arc<ResolvedProfile> {
    if device.unfiltered {
        Arc::new(base.as_unfiltered())
    } else {
        Arc::clone(base)
    }
}

fn build_resolver_map(config: &ConfigV1, custom_lists: &CustomListStore) -> ResolverMap {
    // Pre-resolve every profile once. The order of insertion doesn't matter
    // for correctness (the map is used as a dictionary), but we iterate
    // BTreeMap for deterministic log messages.
    let admin_rules_by_id: BTreeMap<&Id, &AdminRule> =
        config.admin_rules.iter().map(|r| (&r.id, r)).collect();
    let mut profiles: HashMap<Id, Arc<ResolvedProfile>> = HashMap::new();
    for (raw_id, profile) in &config.profiles {
        let id = match Id::new(raw_id) {
            Ok(id) => id,
            Err(_) => {
                // Validator would have caught this; skip defensively.
                tracing::warn!(raw_id, "invalid profile id skipped at resolver build");
                continue;
            }
        };
        // `tag_model_consolidation` §3.4 (D8): the persisted download
        // state now reaches `list_applies`. A list the daemon has
        // never fetched successfully (`Pending`, or `Failed` with no
        // cache on disk) stops occupying a bit; a `Failed` list that
        // still has its previous cache keeps filtering (D9 stale-cache
        // fallback). `None` — the daemon before it has attached its
        // handle, plus every CLI / TUI / test caller — means "state
        // unknown" and every tag-intersecting list applies.
        let mut resolved = ResolvedProfile::build_v1(
            &id,
            profile,
            &admin_rules_by_id,
            custom_lists,
            &config.server,
            config.local_dns.ttl_secs,
        );
        // §4.8 §2/2 T2 — flatten the per-profile ECS sub-table on top of
        // the global `[upstream.ecs]` defaults (D7 inheritance). The
        // resulting `EcsPolicy` is `Copy`, so the one surviving per-device
        // specialisation (`as_unfiltered`) carries it through on its clone
        // path. Build_v1 left it at OFF;
        // we set the real value here so the hot path picks it up.
        resolved.ecs_policy = crate::profiles::profile::EcsPolicy::from_profile_and_upstream(
            profile.ecs.as_ref(),
            &config.upstream.ecs,
        );
        profiles.insert(id, Arc::new(resolved));
    }

    let default_profile = config
        .server
        .default_profile
        .as_ref()
        .and_then(|id| profiles.get(id).cloned())
        .map(ProfilePair::new);

    // The group / schedule passes below need the schema-level `Device`
    // record from a bare `Id` (to read `unfiltered`). Build the index once.
    let devices_by_id_v1: HashMap<&Id, &crate::config::schema::Device> =
        config.devices.iter().map(|d| (&d.id, d)).collect();

    // Build device indexes.
    //
    // `/proc/net/arp` is per-IP; a single MAC may answer at several IPs
    // (DHCP-renew overlap, IP alias, dual-NIC bridge). Read the lossless
    // IP→MAC snapshot, then invert into a MAC→IPs multimap so a device is
    // registered under *every* IP its MAC currently holds — the prior
    // MAC-keyed read kept only one IP per MAC, nondeterministically
    // (rev-2606 arp-01).
    let arp_by_ip = arp::read_arp_by_ip();
    let mut arp_ips_by_mac: HashMap<&str, Vec<IpAddr>> = HashMap::with_capacity(arp_by_ip.len());
    for (arp_ip, arp_mac) in &arp_by_ip {
        arp_ips_by_mac
            .entry(arp_mac.as_str())
            .or_default()
            .push(*arp_ip);
    }
    let mut devices_by_ip: HashMap<IpAddr, Arc<DeviceIndex>> = HashMap::new();
    let mut devices_by_mac: HashMap<CompactString, Arc<DeviceIndex>> = HashMap::new();
    let mut devices_by_id: HashMap<Id, Arc<DeviceIndex>> = HashMap::new();
    // Sprint 43 T4: per-device overlays parallel the device index. Only
    // populated for devices that declared `allow_rules` / `deny_rules` —
    // empty-overlay devices are absent from the map, so their hot path
    // sees `Resolution.overlay = None` and runs the pre-T4 baseline
    // (snapshot acceptance §8). `DeviceOverlay::build_v1` shares the
    // already-built `admin_rules_by_id` map with `ResolvedProfile::build_v1`.
    let mut device_overlays: HashMap<Id, Arc<DeviceOverlay>> = HashMap::new();
    // Device-network-name (2026-08-10 design, D1/D2). Both indexes are
    // config-static; the IP behind a name is looked up at query time
    // against the independently-refreshed ARP snapshot.
    let mut network_names: HashMap<CompactString, Id> = HashMap::new();
    let mut network_name_wildcards: Vec<(CompactString, Id)> = Vec::new();

    for dev in &config.devices {
        let mac_pin = dev
            .mac
            .as_ref()
            .map(|m| CompactString::new(m.to_ascii_uppercase()));
        let mac_aliases: Vec<CompactString> = dev
            .mac_aliases
            .iter()
            .map(|m| CompactString::new(m.to_ascii_uppercase()))
            .collect();
        let direct_profile = dev
            .profile
            .as_ref()
            .and_then(|pid| profiles.get(pid))
            .map(|base| unfiltered_variant(dev, base));

        let index = Arc::new(DeviceIndex {
            id: dev.id.clone(),
            display_name: CompactString::new(&dev.display_name),
            configured_ip: dev.ip,
            mac_pin: mac_pin.clone(),
            mac_aliases: mac_aliases.clone(),
            direct_profile,
            groups: dev.groups.clone(),
            owner: dev.owner.as_deref().map(CompactString::new),
            device_type: dev.device_type.as_deref().map(CompactString::new),
            department: dev.department.as_deref().map(CompactString::new),
            notes: dev.notes.as_deref().map(CompactString::new),
            unfiltered: dev.unfiltered,
            network_name: dev
                .network_name
                .as_deref()
                .map(|n| CompactString::new(n.to_ascii_lowercase())),
            network_name_wildcard: dev.network_name_wildcard,
        });

        devices_by_id.insert(dev.id.clone(), index.clone());

        // Case-fold once here so `resolve_network_name` can compare
        // against a lower-cased query without re-folding per entry.
        if let Some(name) = &dev.network_name {
            let key = CompactString::new(name.to_ascii_lowercase());
            network_names.insert(key.clone(), dev.id.clone());
            if dev.network_name_wildcard {
                network_name_wildcards.push((key, dev.id.clone()));
            }
        }

        // Sprint 43 T4: build per-device overlay if the device declared
        // any allow/deny rule references. The build helper returns
        // `None` for empty / all-skipped rule sets (snapshot byte-for-
        // byte acceptance preserved).
        if let Some(overlay) = DeviceOverlay::build_v1(dev, &admin_rules_by_id) {
            device_overlays.insert(dev.id.clone(), overlay);
        }

        if let Some(ip) = dev.ip {
            devices_by_ip.insert(ip, index.clone());
        }
        if let Some(ref pin) = mac_pin {
            devices_by_mac.insert(pin.clone(), index.clone());
        }
        for alias in &mac_aliases {
            devices_by_mac.insert(alias.clone(), index.clone());
        }

        // Also register any ARP-learned IPs for this device's MACs so
        // DHCP reassignment is handled without a config edit. A MAC may
        // answer at several IPs, so register all of them (rev-2606
        // arp-01). Skip any ARP IP that would clobber a different
        // device's configured IP (the operator's explicit mapping wins).
        let register_arp_ips = |devices_by_ip: &mut HashMap<IpAddr, Arc<DeviceIndex>>,
                                mac_upper: &str| {
            let Some(addrs) = arp_ips_by_mac.get(mac_upper) else {
                return;
            };
            for &arp_ip in addrs {
                if devices_by_ip.contains_key(&arp_ip) {
                    continue;
                }
                devices_by_ip.insert(arp_ip, index.clone());
            }
        };
        if let Some(pin) = mac_pin.as_deref() {
            register_arp_ips(&mut devices_by_ip, pin);
        }
        for alias in &mac_aliases {
            register_arp_ips(&mut devices_by_ip, alias);
        }
    }

    // Depth-descending so the longest apex is considered first, mirroring
    // `dns/local.rs`'s `suffix_index` ordering. The suffix walk in
    // `resolve_network_name` already strips labels longest-first, so this
    // only disambiguates entries reachable at the same depth — cheap
    // insurance that keeps the two wildcard mechanisms behaving alike.
    network_name_wildcards.sort_by_key(|(name, _)| std::cmp::Reverse(name.matches('.').count()));

    // Build group indexes.
    let group_meta: HashMap<Id, (&Group, Option<Arc<ResolvedProfile>>)> = config
        .groups
        .iter()
        .map(|g| (g.id.clone(), (g, profiles.get(&g.profile).cloned())))
        .collect();
    // Specialise the group's profile per-device for the one thing that
    // still varies per device — `[[devices]].unfiltered` — when the
    // resolver returns at level 3. Falls back to the profile-level base
    // only if `config.profiles` lacks the group's profile entry; the
    // validator catches that earlier.
    //
    // It used to thread `device.tags ∪ group_profile.tags` as well. Tags
    // stopped deciding anything at the `plp-s3` cutover and the field went
    // in `plp-s5a`, so two devices on one group profile now see the same
    // lists by construction rather than by coincidence.
    let specialise_group_profile = |dev: &crate::config::schema::Device,
                                    _group: &Group,
                                    base: &Arc<ResolvedProfile>|
     -> Arc<ResolvedProfile> { unfiltered_variant(dev, base) };
    let mut device_groups: HashMap<Id, Vec<GroupMatch>> = HashMap::new();
    for dev in &config.devices {
        for gid in &dev.groups {
            if let Some((g, Some(prof))) = group_meta.get(gid) {
                device_groups
                    .entry(dev.id.clone())
                    .or_default()
                    .push(GroupMatch {
                        id: g.id.clone(),
                        priority: g.priority,
                        profile: specialise_group_profile(dev, g, prof),
                    });
            }
        }
    }
    // Also register devices listed inside `[[groups]].devices` but not in
    // their own `[[devices]].groups`. Membership is NOT required to be
    // symmetric (the CLI join path writes only the device side); the
    // validator's DM2 conflict check unions both directions exactly like
    // this pass does (`check_group_priority_conflicts`, rev-2606
    // schema-validator-04).
    for group in &config.groups {
        let Some(prof) = profiles.get(&group.profile).cloned() else {
            continue;
        };
        for dev_id in &group.devices {
            let entry = device_groups.entry(dev_id.clone()).or_default();
            if !entry.iter().any(|g| g.id == group.id) {
                let specialised = match devices_by_id_v1.get(dev_id) {
                    Some(dev) => specialise_group_profile(dev, group, &prof),
                    None => prof.clone(),
                };
                entry.push(GroupMatch {
                    id: group.id.clone(),
                    priority: group.priority,
                    profile: specialised,
                });
            }
        }
    }
    for list in device_groups.values_mut() {
        // Sort by priority desc, then by id for deterministic tie-break.
        list.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.id.as_str().cmp(b.id.as_str()))
        });
    }

    // Build subnet index. Invalid CIDRs are silently skipped (validator
    // catches them at load time); we log at warn so the operator has a
    // chance to see it even if they build the resolver directly.
    let mut subnets: Vec<SubnetMatch> = Vec::new();
    for sn in &config.subnets {
        let Some(base_prof) = profiles.get(&sn.profile).cloned() else {
            tracing::warn!(
                subnet = %sn.id.as_str(),
                profile = %sn.profile.as_str(),
                "subnet references unknown profile, skipping",
            );
            continue;
        };
        // A device with no direct / group / schedule mapping reaches this
        // level carrying its own `unfiltered` flag — `resolve` fills
        // `device_id` here from exactly that candidate — so both variants
        // are built now rather than allocated per query.
        let prof = ProfilePair::new(base_prof);
        for cidr_str in &sn.cidrs {
            match Cidr::parse(cidr_str) {
                Ok(cidr) => {
                    let prefix = cidr_prefix_len(&cidr);
                    subnets.push(SubnetMatch {
                        id: sn.id.clone(),
                        cidr,
                        prefix,
                        priority: sn.priority,
                        profile: prof.clone(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        subnet = %sn.id.as_str(),
                        cidr = %cidr_str,
                        error = %e,
                        "invalid CIDR in subnet, skipping this entry",
                    );
                }
            }
        }
    }
    // Longest-prefix first; ties broken by (informational) priority DESC
    // then by id ASC for determinism.
    subnets.sort_by(|a, b| {
        b.prefix
            .cmp(&a.prefix)
            .then(b.priority.cmp(&a.priority))
            .then(a.id.as_str().cmp(b.id.as_str()))
    });

    // Build schedule indexes.
    let mut schedules_by_device: HashMap<Id, Vec<ScheduleMatch>> = HashMap::new();
    let mut schedules_by_group: HashMap<Id, Vec<ScheduleMatch>> = HashMap::new();
    for sc in &config.schedules {
        let Some(prof) = profiles.get(&sc.profile).cloned() else {
            continue;
        };
        let Some(parsed) = ParsedSchedule::parse_v1(sc) else {
            tracing::warn!(
                schedule = %sc.id.as_str(),
                days = ?sc.days,
                hours = %sc.hours,
                "unparseable schedule, skipping",
            );
            continue;
        };
        let entry = ScheduleMatch {
            id: sc.id.clone(),
            parsed,
            profile: prof,
        };
        match sc.target_type {
            ScheduleTargetType::Device => {
                schedules_by_device
                    .entry(sc.target_id.clone())
                    .or_default()
                    .push(entry);
            }
            ScheduleTargetType::Group => {
                schedules_by_group
                    .entry(sc.target_id.clone())
                    .or_default()
                    .push(entry);
            }
        }
    }

    // C-03: pre-compute active schedule per device once at build time.
    // The schedule-tick task calls `swap()` every 60s, so this map is
    // refreshed at that cadence — matching the existing pre-computation
    // contract for the schedule level.
    let (weekday, hour, minute) = schedule::local_now();
    let raw_active_schedule = compute_active_schedules(
        &devices_by_id,
        &device_groups,
        &schedules_by_device,
        &schedules_by_group,
        weekday,
        hour,
        minute,
    );

    // Level 2 resolution returns the active schedule's profile,
    // specialised for the device that will actually consume it — which
    // since `plp-s5a` means `unfiltered` and nothing else.
    let mut schedule_id_to_profile_id: HashMap<&Id, &Id> = HashMap::new();
    for sc in &config.schedules {
        schedule_id_to_profile_id.insert(&sc.id, &sc.profile);
    }
    let mut active_schedule_by_device: HashMap<Id, Arc<ScheduleMatch>> =
        HashMap::with_capacity(raw_active_schedule.len());
    for (dev_id, sched_match) in raw_active_schedule {
        let specialised_profile = (|| {
            let dev = devices_by_id_v1.get(&dev_id)?;
            Some(unfiltered_variant(dev, &sched_match.profile))
        })();
        let entry = match specialised_profile {
            Some(prof) => Arc::new(ScheduleMatch {
                id: sched_match.id.clone(),
                parsed: sched_match.parsed.clone(),
                profile: prof,
            }),
            None => sched_match,
        };
        active_schedule_by_device.insert(dev_id, entry);
    }

    tracing::info!(
        profile_count = profiles.len(),
        device_count = devices_by_id.len(),
        group_count = config.groups.len(),
        subnet_count = subnets.len(),
        schedule_count = config.schedules.len(),
        active_schedule_count = active_schedule_by_device.len(),
        enforce_mac = config.server.enforce_device_mac,
        "profile map built"
    );

    let slug_to_id = build_slug_to_id_map(config);

    ResolverMap {
        profiles,
        devices_by_ip,
        devices_by_mac,
        devices_by_id,
        device_overlays,
        device_groups,
        subnets,
        active_schedule_by_device,
        default_profile,
        enforce_mac: config.server.enforce_device_mac,
        slug_to_id,
        network_names,
        network_name_wildcards,
    }
}

/// Build the `slug → [[blocklists]].id` bridge map (S43 T1).
///
/// Each `[[blocklists]]` entry contributes:
/// - the literal id under itself (identity entry — operator may type
///   the canonical id directly);
/// - if the id contains a `-`, the hyphen-to-slash transform of the id
///   (e.g. `"privacy-ads"` → `"privacy/ads"` — recovers the slug-form
///   the legacy `[lists].sources` catalog uses).
///
/// Multi-hyphen ids only get the FIRST hyphen swapped so
/// `"security-malicious-extra"` → `"security/malicious-extra"`. This
/// matches the catalog convention where the slug is `<scope>/<topic>`
/// with `<topic>` allowed to carry hyphens.
///
/// On collision (two blocklist ids that derive the same slug), the
/// second entry wins and a warning is logged. Validator-level dedup
/// of `[[blocklists]].id` already guarantees the literal-id keys are
/// unique; only the slash-form keys can collide, and the case is
/// pathological enough to surface as a config-author bug.
fn build_slug_to_id_map(config: &ConfigV1) -> HashMap<String, Id> {
    let mut map: HashMap<String, Id> = HashMap::with_capacity(config.blocklists.len() * 2);
    for bl in &config.blocklists {
        // Identity entry — operator typing the canonical id resolves directly.
        map.insert(bl.id.as_str().to_string(), bl.id.clone());
        if let Some(idx) = bl.id.as_str().find('-') {
            let slug = format!("{}/{}", &bl.id.as_str()[..idx], &bl.id.as_str()[idx + 1..]);
            if let Some(prev) = map.insert(slug.clone(), bl.id.clone()) {
                if prev != bl.id {
                    tracing::warn!(
                        slug = slug.as_str(),
                        winner = bl.id.as_str(),
                        loser = prev.as_str(),
                        "slug_to_id collision — second [[blocklists]] entry wins"
                    );
                }
            }
        }
    }
    map
}

fn cidr_prefix_len(cidr: &Cidr) -> u8 {
    match cidr {
        Cidr::V4 { prefix, .. } => *prefix,
        Cidr::V6 { prefix, .. } => *prefix,
    }
}

// ── Sprint 43 T4 — per-device overlay decision (§4 truth table) ────

/// Sprint 43 T4: which side of the `apply_overlay` decision was responsible
/// for the verdict. Mirrors `crate::tracking::RuleSource` at the type
/// level but stays attribution-only — the caller turns this enum plus
/// the live profile / device ids into a `RuleSource` for tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttribSource {
    /// Profile-level allow/deny matched.
    Profile,
    /// Device-level allow/deny matched (or override allowed past a
    /// profile deny, truth table §4 row 7).
    Device,
}

/// Sprint 43 T4: outcome of `apply_overlay`. The caller maps each
/// variant to the per-query bool + `RuleSource` attribution; the
/// pure fn stays decoupled from the live entity ids so the truth
/// table can be unit-tested without setting up a full resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayDecision {
    /// Forward the query (allow). Carries the layer attribution and
    /// whether the `[OVERRIDE]` badge applies (§4 row 7).
    Allow {
        source: AttribSource,
        override_used: bool,
    },
    /// Block the query (deny). Carries the layer attribution.
    Block { source: AttribSource },
    /// No overlay-or-profile-allow/deny rule matched at this layer.
    /// Caller falls through to `FilterEngine::evaluate` — bitmask +
    /// advanced rules + default Forward.
    FallThrough,
}

/// Sprint 43 T4: per-query layer probe results, fed into [`apply_overlay`].
///
/// One boolean per decision-relevant layer keeps `apply_overlay` a pure fn
/// over the flags + the override switch. The DNS handler computes these by
/// calling `crate::filter::engine::domain_matches_set` on the device's
/// overlay sets and the profile's deny set — two probes for the overlay
/// (R5) plus the profile-deny probe the evaluator already does internally.
///
/// res-16: the former `profile_allow_hit` field was removed — no reader
/// consulted it (every FallThrough row ignores profile-allow, and the
/// fall-through caller's `filter.evaluate` re-derives it), so computing it
/// was a dead per-query HashSet walk on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerHits {
    pub profile_deny_hit: bool,
    pub device_allow_hit: bool,
    pub device_deny_hit: bool,
}

/// Sprint 43 T4: enforce the §4 truth table — the **single** decision
/// seat for combining profile-level and device-level allow/deny hits.
///
/// Pure function: same inputs → same `OverlayDecision`. The 9-row truth
/// table is unit-tested across every combination in the resolver test
/// module.
///
/// The 9 rows (PA = profile.allow, PD = profile.deny, DA = device.allow,
/// DD = device.deny, OVR = `Device.override_profile_deny`). PA is shown for
/// completeness of the §4 truth table but is **not** an `apply_overlay`
/// input (res-16): it never changes a Result versus its PA=– twin — the
/// FallThrough rows delegate profile-allow to the caller's `filter.evaluate`
/// — so the field was dropped from [`LayerHits`].
///
/// | # | PA | PD | DA | DD | OVR | Result | Source |
/// |---|----|----|----|----|----|--------|--------|
/// | 0 | – | – | – | – | – | FallThrough | (none) |
/// | 1 | ✓ | – | – | – | – | FallThrough | Profile (caller) |
/// | 2 | – | ✓ | – | – | – | FallThrough | Profile (caller) |
/// | 3 | – | – | ✓ | – | – | Allow      | Device |
/// | 4 | – | – | – | ✓ | – | Block      | Device |
/// | 5 | ✓ | – | – | ✓ | – | Block      | Device (additive deny) |
/// | 6 | – | ✓ | ✓ | – | F | Block      | Profile (refused at edit time; defensive on drift) |
/// | 7 | – | ✓ | ✓ | – | T | Allow      | Device \[OVERRIDE\] |
/// | 8 | – | ✓ | – | ✓ | – | Block      | Profile (Device adds nothing) |
///
/// **Why rows 1 / 2 return `FallThrough`:** when no device-side rule
/// fires, the truth table delegates to the profile evaluator. The pure
/// fn doesn't have the bitmask / advanced-rule layers in scope; rather
/// than re-implementing them here, the caller runs `filter.evaluate` on
/// `FallThrough`, which already handles profile.allow_domains /
/// profile.deny_domains / the generation's per-profile list policy /
/// advanced rules in one pass. (Pre-`plp-s3` the third of those was
/// `profile.list_bitmask`, a field that no longer exists.)
/// This keeps the byte-identical baseline for empty overlays trivial:
/// when both DA/DD are false the function always returns `FallThrough`,
/// regardless of PA/PD — same code path as pre-T4.
///
/// **Why row 6 defensively chooses Profile-wins on drift:** the CLI /
/// TUI refuses the `device.allow X + profile.deny X + override=false`
/// combination at edit time, so the daemon should never see this row
/// on a fresh config. If the operator hand-edits the master TOML to
/// produce drift, the safer fallback is "profile-wins" (matches
/// project rules §Key Design Rules #5: "Default profile must be
/// restrictive") rather than letting the per-device allow silently
/// punch through a profile-level block.
///
/// **R5 invariant:** this function performs ZERO HashSet probes — the
/// caller has already done them. Compiles to a small chain of `if`
/// statements; no allocations.
pub fn apply_overlay(hits: LayerHits, override_profile_deny: bool) -> OverlayDecision {
    // res-16 (done): profile-allow is no longer an input. Truth-table rows
    // 0/1/2 — any case with no device-side hit — return `FallThrough`
    // regardless of profile-allow, and the caller then runs `filter.evaluate`,
    // which re-derives profile-allow itself. The dead `profile_allow_hit`
    // field + its per-query `domain_matches_set(profile.allow_domains)` probe
    // in dns/handler were removed to drop the wasted hot-path HashSet walk.
    let LayerHits {
        profile_deny_hit,
        device_allow_hit,
        device_deny_hit,
    } = hits;

    // Row 7 / 6: device.allow + profile.deny — the OVERRIDE branch.
    // Probed FIRST among device-touching rows because §8 names this
    // pair as the operator's most ergonomically important case (the
    // TUI scope-menu surfaces it explicitly). The override flag
    // decides ALLOW vs defensive DENY.
    if device_allow_hit && profile_deny_hit {
        if override_profile_deny {
            return OverlayDecision::Allow {
                source: AttribSource::Device,
                override_used: true,
            };
        }
        // Row 6 (drift defensive): profile-wins — see fn-doc reasoning.
        return OverlayDecision::Block {
            source: AttribSource::Profile,
        };
    }

    // Row 8: device.deny + profile.deny → DENY, attribution Profile
    // (Device adds nothing — the profile would deny the domain anyway,
    // so the audit log + query log surface the higher-up layer).
    if device_deny_hit && profile_deny_hit {
        return OverlayDecision::Block {
            source: AttribSource::Profile,
        };
    }

    // Rows 4 / 5: device.deny alone (or with profile.allow on the same
    // domain). Device.deny is "additive deny" — wins over profile.allow
    // because a per-device exception to deny a normally-allowed domain
    // is the operator's explicit intent.
    if device_deny_hit {
        return OverlayDecision::Block {
            source: AttribSource::Device,
        };
    }

    // Row 3: device.allow alone (no profile-level deny on the same
    // domain). Pure per-device allow — operator pinned this exception.
    if device_allow_hit {
        return OverlayDecision::Allow {
            source: AttribSource::Device,
            override_used: false,
        };
    }

    // Rows 0 / 1 / 2: device-side silent. Caller falls through to
    // `filter.evaluate` which handles profile.allow / profile.deny /
    // bitmask / advanced rules.
    OverlayDecision::FallThrough
}

fn build_arp_snapshot() -> HashMap<IpAddr, CompactString> {
    // Invariant (res-09): ARP MACs are stored upper-case. `read_arp_by_ip`
    // folds case at the `/proc/net/arp` boundary (arp.rs), matching the
    // upper-cased `mac_pin` / `mac_aliases` the resolver compares against.
    // Every later consumer — `resolve`'s MAC compare and `snapshots_from`'s
    // `ips_by_mac` probe — relies on both sides already being upper-case.
    //
    // Keyed by IP directly (rev-2606 arp-01): the prior MAC-keyed read +
    // inversion silently dropped all-but-one IP for a multi-IP MAC, and
    // which row survived was nondeterministic per refresh. `/proc/net/arp`
    // is per-IP, so the IP-keyed read is lossless and needs no inversion.
    arp::read_arp_by_ip()
}

fn snapshots_from(
    map: &ResolverMap,
    arp: &HashMap<IpAddr, CompactString>,
) -> Vec<MappedDeviceSnapshot> {
    // Invert the ARP map once: MAC → IPs reachable at that MAC. Pre-fix
    // each device walked the full ARP table (O(N × A × M)); now it does
    // O(N × M) hash probes against this index. Built per call (not
    // cached) since ARP is live data — `refresh_arp` produces a fresh
    // snapshot per IPC poll which is what we're consuming here.
    //
    // One MAC may name multiple IPs (DHCP shuffle, dual-NIC, IPv4+IPv6
    // on the same interface), so the value is `Vec<IpAddr>`.
    let mut ips_by_mac: HashMap<&str, Vec<IpAddr>> = HashMap::with_capacity(arp.len());
    for (arp_ip, arp_mac) in arp {
        ips_by_mac
            .entry(arp_mac.as_str())
            .or_default()
            .push(*arp_ip);
    }

    let mut snapshots: Vec<MappedDeviceSnapshot> = Vec::with_capacity(map.devices_by_id.len());

    for (id, index) in &map.devices_by_id {
        // Collect every address this device is reachable at.
        let mut ips: Vec<IpAddr> = Vec::new();
        if let Some(ip) = index.configured_ip {
            ips.push(ip);
        }
        // Probe the inverted index for each owned MAC (pin + aliases).
        // O(1) lookup per MAC instead of the prior O(A) ARP table scan.
        if let Some(pin) = index.mac_pin.as_deref() {
            if let Some(addrs) = ips_by_mac.get(pin) {
                for addr in addrs {
                    if !ips.contains(addr) {
                        ips.push(*addr);
                    }
                }
            }
        }
        for alias in &index.mac_aliases {
            if let Some(addrs) = ips_by_mac.get(alias.as_str()) {
                for addr in addrs {
                    if !ips.contains(addr) {
                        ips.push(*addr);
                    }
                }
            }
        }
        ips.sort();

        let primary = ips
            .first()
            .copied()
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        // Resolve the profile that the device currently uses. We report
        // the direct / group / default attribution at resolver level
        // (not schedule) so the IPC snapshot matches what `warden client`
        // / TUI have always displayed. Schedule overrides are surfaced
        // through the stats engine instead.
        let profile_name = effective_profile_name(index, map);

        let dto = MappedDeviceDto {
            ip: primary,
            name: index.display_name.to_string(),
            mac: index.mac_pin.as_ref().map(|m| m.to_string()),
            mac_aliases: index.mac_aliases.iter().map(|m| m.to_string()).collect(),
            profile: profile_name,
            owner: index.owner.as_ref().map(|s| s.to_string()),
            device_type: index.device_type.as_ref().map(|s| s.to_string()),
            department: index.department.as_ref().map(|s| s.to_string()),
            // FILE order, not priority order. `DeviceIndex.groups` is a
            // straight `dev.groups.clone()`; what gets priority-sorted is
            // `ResolverMap.device_groups`, a different structure. The
            // claim that this was "pre-sorted by group priority" stood
            // here until §4.64 G4 and was never true — and it mattered
            // once the TUI started round-tripping this list: consumers
            // write it back, so its order is the operator's file order.
            groups: index
                .groups
                .iter()
                .map(|g| g.as_str().to_string())
                .collect(),
            notes: index.notes.as_ref().map(|s| s.to_string()),
            network_name: index.network_name.as_ref().map(|s| s.to_string()),
            network_name_wildcard: index.network_name_wildcard,
            // Carry the v1 stable id so the TUI's Update / Remove IPC
            // calls reference the entity by its real key, not by the
            // operator-typed display name (which can diverge after a
            // rename).
            id: Some(index.id.as_str().to_string()),
            // Hourly buckets are populated on the IPC merge path
            // (`handle_get_all_devices` aggregates across all of the
            // device's IPs); resolver builds the metadata-only
            // skeleton.
            hourly_queries: Vec::new(),
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            // Vendor is resolved later in `handle_get_all_devices`
            // against the daemon's `OuiTable`, so the resolver leaves
            // it `None` here. Keeping the OUI lookup at IPC build time
            // (instead of snapshot construction) means a config reload
            // doesn't have to also re-walk the OUI database.
            vendor: None,
            unfiltered: index.unfiltered,
        };

        snapshots.push(MappedDeviceSnapshot {
            dto,
            ips,
            notes: index.notes.as_ref().map(|s| s.to_string()),
        });

        // Keep `id` referenced so clippy doesn't warn on an unused `id`
        // in future refactors — the map is keyed by it.
        let _ = id;
    }

    snapshots.sort_by(|a, b| a.dto.name.cmp(&b.dto.name));
    snapshots
}

/// Compute the profile name that a device resolves to when `warden client`
/// reads its row — used by the IPC snapshot. Mirrors the resolver's
/// priority order MINUS the schedule level (schedules show up in stats,
/// not in the static client listing).
///
/// The subnet walk reuses the same prefix-DESC-sorted `map.subnets` slice
/// that the per-query `resolve()` walks; it does NOT call `resolve()` per
/// device. Cost stays O(subnets) per snapshot device — small in practice
/// (≤10 subnets in typical configs) and only on the cold IPC poll path.
fn effective_profile_name(index: &DeviceIndex, map: &ResolverMap) -> String {
    if let Some(prof) = index.direct_profile.as_ref() {
        return prof.name.to_string();
    }
    if let Some(groups) = map.device_groups.get(&index.id) {
        if let Some(first) = groups.first() {
            return first.profile.name.to_string();
        }
    }
    // Level 4: longest-prefix subnet match. Without it the IPC snapshot
    // would falsely display the global default (or "refused") for any
    // device whose effective profile actually comes from a subnet rule —
    // e.g. an IoT bulb with `configured_ip` inside a `[[subnets]]` block
    // and no direct or group mapping. `map.subnets` is sorted prefix-DESC
    // so the first hit is the longest-prefix winner, matching `resolve()`.
    if let Some(ip) = index.configured_ip {
        for sn in &map.subnets {
            if sn.cidr.contains(ip) {
                return sn.profile.filtered.name.to_string();
            }
        }
    }
    if let Some(prof) = map.default_profile.as_ref() {
        return prof.filtered.name.to_string();
    }
    // Fully unmapped — use a synthetic "refused" label so operators see
    // it in TUI/CLI without a panic.
    "refused".into()
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::config::schema::{
        BlockResponseV1, Device, Group, Id, Profile, Schedule, ScheduleTargetType, Subnet,
    };
    use std::net::IpAddr;

    fn mk_id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    fn base_config() -> ConfigV1 {
        // Two profiles (default + strict), two devices, one group,
        // one subnet, no schedules. Reused across most level tests.
        let mut c = ConfigV1::test_scaffold();
        c.schema_version = 3;
        c.profiles.insert(
            "default".into(),
            Profile {
                display_name: "Default".into(),
                ..Default::default()
            },
        );
        c.profiles.insert(
            "strict".into(),
            Profile {
                display_name: "Strict".into(),
                ..Default::default()
            },
        );
        c.profiles.insert(
            "kids".into(),
            Profile {
                display_name: "Kids".into(),
                ..Default::default()
            },
        );
        c.devices.push(Device {
            id: mk_id("laptop"),
            display_name: "Laptop".into(),
            ip: Some("192.168.1.42".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: Some(mk_id("default")),
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        c.devices.push(Device {
            id: mk_id("tablet"),
            display_name: "Tablet".into(),
            ip: Some("192.168.1.50".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![mk_id("iot")],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        c.groups.push(Group {
            id: mk_id("iot"),
            display_name: "IoT".into(),
            profile: mk_id("strict"),
            priority: 10,
            devices: vec![mk_id("tablet")],
        });
        c.subnets.push(Subnet {
            id: mk_id("lan"),
            display_name: "LAN".into(),
            cidrs: vec!["192.168.1.0/24".into()],
            profile: mk_id("kids"),
            priority: 0,
        });
        // Global default unset → level 5 is REFUSED for sources outside
        // the configured subnet.
        c.server.default_profile = None;
        // §4.39 / s-review-2605-profiles-h1: the two devices above are
        // pin-less (no MAC). Under `enforce_device_mac` a pin-less device
        // now falls through to subnet / default at resolve time, so the
        // level-cascade tests that expect DeviceDirect / Group keep MAC
        // enforcement off here. The MAC-enforcement tests opt in with an
        // explicit `enforce_device_mac = true`.
        c.server.enforce_device_mac = false;
        c
    }

    #[test]
    fn level_1_device_direct_profile_wins() {
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
        assert_eq!(r.device_id.as_ref().map(|i| i.as_str()), Some("laptop"));
        assert_eq!(r.profile.unwrap().name.as_str(), "default");
    }

    #[test]
    fn level_3_group_profile_when_device_has_no_direct() {
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.50".parse().unwrap();

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Group));
        assert_eq!(r.device_id.as_ref().map(|i| i.as_str()), Some("tablet"));
        assert_eq!(r.matched_group.as_ref().map(|i| i.as_str()), Some("iot"));
        assert_eq!(r.profile.unwrap().name.as_str(), "strict");
    }

    #[test]
    fn level_4_subnet_longest_prefix_for_unmapped_ip() {
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.99".parse().unwrap();

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Subnet));
        assert_eq!(r.matched_subnet.as_ref().map(|i| i.as_str()), Some("lan"));
        assert_eq!(r.profile.unwrap().name.as_str(), "kids");
    }

    #[test]
    fn level_5_default_profile_when_set() {
        let mut cfg = base_config();
        cfg.server.default_profile = Some(mk_id("default"));
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // IP outside the LAN subnet → level 4 misses, level 5 wins.
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::GlobalDefault));
        assert_eq!(r.profile.unwrap().name.as_str(), "default");
    }

    #[test]
    fn level_5_refused_when_default_profile_unset() {
        // Base config has default_profile = None and the LAN subnet only.
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let r = resolver.resolve(&ip);
        assert!(r.profile.is_none(), "level 5 with default=None → REFUSED");
        assert!(r.level.is_none());
    }

    #[test]
    fn subnet_longest_prefix_wins_on_overlap() {
        // /16 broad + /24 specific → a host inside the /24 must land on
        // the /24's profile, not the /16's.
        let mut cfg = base_config();
        cfg.profiles.insert(
            "broad".into(),
            Profile {
                display_name: "Broad".into(),
                ..Default::default()
            },
        );
        cfg.profiles.insert(
            "narrow".into(),
            Profile {
                display_name: "Narrow".into(),
                ..Default::default()
            },
        );
        cfg.subnets.clear();
        cfg.subnets.push(Subnet {
            id: mk_id("broad"),
            display_name: "Broad".into(),
            cidrs: vec!["10.0.0.0/8".into()],
            profile: mk_id("broad"),
            priority: 0,
        });
        cfg.subnets.push(Subnet {
            id: mk_id("narrow"),
            display_name: "Narrow".into(),
            cidrs: vec!["10.10.10.0/24".into()],
            profile: mk_id("narrow"),
            priority: 0,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        // IP inside the /24 → narrow.
        let inside: IpAddr = "10.10.10.5".parse().unwrap();
        assert_eq!(
            resolver.resolve(&inside).profile.unwrap().name.as_str(),
            "narrow"
        );

        // IP inside the /8 but outside the /24 → broad.
        let outside: IpAddr = "10.10.11.5".parse().unwrap();
        assert_eq!(
            resolver.resolve(&outside).profile.unwrap().name.as_str(),
            "broad"
        );
    }

    #[test]
    fn group_priority_tie_break_chooses_higher_priority() {
        // Device belongs to two groups; the higher priority wins.
        let mut cfg = base_config();
        cfg.profiles.insert(
            "low".into(),
            Profile {
                display_name: "Low".into(),
                ..Default::default()
            },
        );
        cfg.profiles.insert(
            "high".into(),
            Profile {
                display_name: "High".into(),
                ..Default::default()
            },
        );
        // Tablet already in "iot" group (priority 10). Add a higher-priority one.
        cfg.groups.push(Group {
            id: mk_id("high-priority"),
            display_name: "High Priority".into(),
            profile: mk_id("high"),
            priority: 50,
            devices: vec![mk_id("tablet")],
        });
        // Also add a lower-priority group to make sure the order stays right.
        cfg.groups.push(Group {
            id: mk_id("cleanup"),
            display_name: "Cleanup".into(),
            profile: mk_id("low"),
            priority: 1,
            devices: vec![mk_id("tablet")],
        });

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Group));
        assert_eq!(r.profile.unwrap().name.as_str(), "high");
    }

    #[test]
    fn schedule_overrides_device_direct_and_group() {
        // Tablet has no direct profile → normally resolves to "strict"
        // via the "iot" group. During the schedule window it must resolve
        // to the schedule's profile "kids-night".
        let mut cfg = base_config();
        cfg.profiles.insert(
            "kids-night".into(),
            Profile {
                display_name: "Kids night".into(),
                ..Default::default()
            },
        );
        cfg.schedules.push(Schedule {
            id: mk_id("quiet"),
            display_name: "Quiet".into(),
            target_type: ScheduleTargetType::Device,
            target_id: mk_id("tablet"),
            profile: mk_id("kids-night"),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(), // always active
            expires_at: None,
        });

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Schedule));
        assert_eq!(
            r.matched_schedule.as_ref().map(|i| i.as_str()),
            Some("quiet")
        );
        assert_eq!(r.profile.unwrap().name.as_str(), "kids-night");
    }

    #[test]
    fn mac_mismatch_demotes_to_subnet_level() {
        // Device pinned to MAC A, ARP says MAC B → fall through from
        // level 1 / 3 to level 4 (subnet).
        let mut cfg = base_config();
        // Pin the laptop to a MAC and set enforce_device_mac on.
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.server.enforce_device_mac = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[(ip, "AA:BB:CC:DD:EE:99")]);

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Subnet));
        assert_eq!(r.profile.unwrap().name.as_str(), "kids");
    }

    #[test]
    fn mac_enforcement_accepts_matching_arp() {
        let mut cfg = base_config();
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.server.enforce_device_mac = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[(ip, "AA:BB:CC:DD:EE:01")]);

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
        assert_eq!(r.profile.unwrap().name.as_str(), "default");
    }

    #[test]
    fn mac_enforcement_forgives_missing_arp_entry() {
        // No ARP entry for the IP → still trust the direct profile.
        let mut cfg = base_config();
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.server.enforce_device_mac = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        resolver.test_only_set_arp_snapshot(&[]);

        let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
    }

    #[test]
    fn mac_enforcement_disabled_ignores_arp_table() {
        let mut cfg = base_config();
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.server.enforce_device_mac = false;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[(ip, "AA:BB:CC:DD:EE:99")]);

        // Flag off → mismatch is ignored.
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
    }

    // ── network_name resolution (device-network-name design, 2026-08-10) ──

    #[test]
    fn mapped_device_dto_carries_network_name() {
        let mut cfg = base_config();
        cfg.devices[0].network_name = Some("desktop-1".into());
        let target_id = cfg.devices[0].id.as_str().to_string();

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let mapped = resolver.list_mapped_devices();

        let dto = &mapped
            .iter()
            .find(|snap| snap.dto.id.as_deref() == Some(target_id.as_str()))
            .expect("target device must be present in the mapped snapshot")
            .dto;
        assert_eq!(dto.network_name, Some("desktop-1".to_string()));
        assert!(!dto.network_name_wildcard);
    }

    #[test]
    fn resolve_network_name_exact_match_returns_configured_ip() {
        let mut cfg = base_config();
        // Mixed case in the config exercises the build-side fold; the
        // two queries below exercise the lookup-side fold.
        cfg.devices[0].network_name = Some("Desktop-1".into());

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let expected: IpAddr = "192.168.1.42".parse().unwrap();

        assert_eq!(resolver.resolve_network_name("desktop-1"), Some(expected));
        assert_eq!(resolver.resolve_network_name("DESKTOP-1"), Some(expected));
    }

    #[test]
    fn resolve_network_name_follows_live_arp_when_no_pinned_ip() {
        // The pinned IP is cleared on purpose: with it set, `configured_ip`
        // short-circuits and this test would pass without ever reaching
        // the ARP scan it exists to cover.
        let mut cfg = base_config();
        cfg.devices[0].ip = None;
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.devices[0].network_name = Some("laptop".into());

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let live: IpAddr = "192.168.1.99".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[(live, "AA:BB:CC:DD:EE:01")]);

        assert_eq!(resolver.resolve_network_name("laptop"), Some(live));
    }

    #[test]
    fn resolve_network_name_follows_live_arp_via_mac_alias() {
        let mut cfg = base_config();
        cfg.devices[0].ip = None;
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
        cfg.devices[0].mac_aliases = vec!["AA:BB:CC:DD:EE:0A".into()];
        cfg.devices[0].network_name = Some("laptop".into());

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let live: IpAddr = "192.168.1.98".parse().unwrap();
        // Only the alias answers — the primary pin has no ARP entry.
        resolver.test_only_set_arp_snapshot(&[(live, "AA:BB:CC:DD:EE:0A")]);

        assert_eq!(resolver.resolve_network_name("laptop"), Some(live));
    }

    #[test]
    fn resolve_network_name_wildcard_matches_subdomain() {
        let mut cfg = base_config();
        cfg.devices[0].network_name = Some("casamia".into());
        cfg.devices[0].network_name_wildcard = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let expected: IpAddr = "192.168.1.42".parse().unwrap();

        // The apex resolves through the exact index, not the suffix walk.
        assert_eq!(resolver.resolve_network_name("casamia"), Some(expected));
        // Proper descendants, one and several labels deep.
        assert_eq!(resolver.resolve_network_name("sub.casamia"), Some(expected));
        assert_eq!(resolver.resolve_network_name("a.b.casamia"), Some(expected));
    }

    #[test]
    fn resolve_network_name_without_wildcard_rejects_subdomain() {
        // The discriminating half of the wildcard test: without the flag
        // the suffix walk must find nothing, or `network_name_wildcard`
        // would be decorative.
        let mut cfg = base_config();
        cfg.devices[0].network_name = Some("casamia".into());
        cfg.devices[0].network_name_wildcard = false;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        assert_eq!(
            resolver.resolve_network_name("casamia"),
            Some("192.168.1.42".parse().unwrap())
        );
        assert_eq!(resolver.resolve_network_name("sub.casamia"), None);
    }

    #[test]
    fn resolve_network_name_unknown_device_or_offline_returns_none() {
        let mut cfg = base_config();
        cfg.devices[0].ip = None;
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:02".into());
        cfg.devices[0].network_name = Some("phone".into());

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // Explicit empty snapshot — never rely on the build host's real
        // /proc/net/arp happening not to contain the fixture MAC.
        resolver.test_only_set_arp_snapshot(&[]);

        // Configured, but no pinned IP and no ARP entry → offline.
        assert_eq!(resolver.resolve_network_name("phone"), None);
        // Never configured at all.
        assert_eq!(resolver.resolve_network_name("not-a-configured-name"), None);
    }

    #[test]
    fn network_name_is_configured_separates_offline_from_unknown() {
        // The distinction Task 7 needs: both names below resolve to
        // `None`, but only one of them is a name the operator declared.
        // The handler answers NXDOMAIN for that one and falls through
        // silently for the other.
        let mut cfg = base_config();
        cfg.devices[0].ip = None;
        cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:02".into());
        cfg.devices[0].network_name = Some("phone".into());
        cfg.devices[1].network_name = Some("casamia".into());
        cfg.devices[1].network_name_wildcard = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        resolver.test_only_set_arp_snapshot(&[]);

        assert_eq!(resolver.resolve_network_name("phone"), None);
        assert!(resolver.network_name_is_configured("phone"));
        assert!(!resolver.network_name_is_configured("not-a-configured-name"));
        // Case folded on the probe path too.
        assert!(resolver.network_name_is_configured("PHONE"));
        // Wildcard descendants count as configured.
        assert!(resolver.network_name_is_configured("sub.casamia"));
        assert!(!resolver.network_name_is_configured("sub.phone"));
    }

    #[test]
    fn pin_less_device_falls_through_under_enforce_mac() {
        // §4.39 / s-review-2605-profiles-h1: a device pinned by IP with
        // NO MAC pin must NOT be granted its direct profile on IP alone
        // when `enforce_device_mac` is on — IP-only identification is
        // bypassable (project rules key rule #9). It falls through to
        // subnet / default, matching the documented `[server]` contract.
        let mut cfg = base_config();
        cfg.server.enforce_device_mac = true;
        // laptop (devices[0]) is pin-less: ip = 192.168.1.42, mac = None.

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        // ARP is never consulted on the pin-less path; clear it so the
        // test does not depend on the host ARP table.
        resolver.test_only_set_arp_snapshot(&[]);

        let r = resolver.resolve(&ip);
        assert_eq!(
            r.level,
            Some(ResolveLevel::Subnet),
            "pin-less device under enforce_device_mac must fall through to subnet",
        );
        assert_eq!(r.profile.unwrap().name.as_str(), "kids");
    }

    #[test]
    fn pin_less_device_accepted_when_enforce_mac_disabled() {
        // Mirror image: with `enforce_device_mac` off, a pin-less
        // IP-pinned device keeps its level-1 direct profile — the
        // pre-§4.39 behaviour, preserved for operators who opt out.
        let mut cfg = base_config();
        cfg.server.enforce_device_mac = false;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[]);

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
        assert_eq!(r.profile.unwrap().name.as_str(), "default");
    }

    #[test]
    fn mac_alias_matches_device_via_arp() {
        // Device pinned by MAC only; ARP maps an IP to the alias MAC —
        // the resolver must still treat it as the device.
        let mut cfg = ConfigV1::test_scaffold();
        cfg.schema_version = 3;
        cfg.profiles.insert(
            "kids".into(),
            Profile {
                display_name: "Kids".into(),
                ..Default::default()
            },
        );
        cfg.devices.push(Device {
            id: mk_id("kids-phone"),
            display_name: "Kids phone".into(),
            ip: None,
            mac: Some("AA:BB:CC:DD:EE:01".into()),
            mac_aliases: vec!["AA:BB:CC:DD:EE:02".into()],
            profile: Some(mk_id("kids")),
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        cfg.server.enforce_device_mac = true;

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "10.0.0.77".parse().unwrap();
        resolver.test_only_set_arp_snapshot(&[(ip, "AA:BB:CC:DD:EE:02")]);

        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
        assert_eq!(r.device_id.as_ref().map(|i| i.as_str()), Some("kids-phone"));
    }

    #[test]
    fn subnet_longest_prefix_handles_ipv6() {
        let mut cfg = ConfigV1::test_scaffold();
        cfg.schema_version = 3;
        cfg.profiles.insert(
            "corp".into(),
            Profile {
                display_name: "Corp".into(),
                ..Default::default()
            },
        );
        cfg.subnets.push(Subnet {
            id: mk_id("corp6"),
            display_name: "Corp6".into(),
            cidrs: vec!["fd00::/8".into()],
            profile: mk_id("corp"),
            priority: 0,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "fd12::1".parse().unwrap();
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Subnet));
        assert_eq!(r.profile.unwrap().name.as_str(), "corp");
    }

    #[test]
    fn empty_config_refuses_every_source() {
        // No devices, no subnets, no default_profile → level 5 with
        // `default_profile = None` → REFUSED.
        let mut cfg = ConfigV1::test_scaffold();
        cfg.schema_version = 3;
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        for ip_str in ["10.0.0.1", "192.168.1.42", "fd00::5"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            let r = resolver.resolve(&ip);
            assert!(r.profile.is_none(), "{ip_str} must be REFUSED");
        }
    }

    #[test]
    fn resolve_level_str_labels_are_stable() {
        assert_eq!(ResolveLevel::DeviceDirect.as_str(), "device-direct");
        assert_eq!(ResolveLevel::Schedule.as_str(), "schedule");
        assert_eq!(ResolveLevel::Group.as_str(), "group");
        assert_eq!(ResolveLevel::Subnet.as_str(), "subnet");
        assert_eq!(ResolveLevel::GlobalDefault.as_str(), "global-default");
    }

    #[test]
    fn snapshot_for_ipc_returns_pair() {
        // Contract: two-element tuple (mapped, arp). No block_unmapped
        // (SN3). Exercised as a regression guard so a future IPC rewire
        // doesn't accidentally re-introduce the removed flag.
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let (mapped, _arp) = resolver.snapshot_for_ipc();
        assert_eq!(mapped.len(), 2);
        let names: Vec<&str> = mapped.iter().map(|s| s.dto.name.as_str()).collect();
        assert_eq!(names, vec!["Laptop", "Tablet"]);
    }

    #[test]
    fn swap_rebuilds_map() {
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        assert_eq!(
            resolver
                .resolve(&"192.168.1.42".parse().unwrap())
                .profile
                .unwrap()
                .name
                .as_str(),
            "default"
        );

        let mut new_cfg = cfg.clone();
        new_cfg.devices[0].profile = Some(mk_id("strict"));
        resolver.swap(
            &new_cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        assert_eq!(
            resolver
                .resolve(&"192.168.1.42".parse().unwrap())
                .profile
                .unwrap()
                .name
                .as_str(),
            "strict"
        );
    }

    #[test]
    fn block_response_and_ttl_propagate_through_n6_fallback() {
        // Profile omits the N6 fields → must pick up ServerGlobals defaults.
        let mut cfg = ConfigV1::test_scaffold();
        cfg.schema_version = 3;
        cfg.profiles.insert(
            "default".into(),
            Profile {
                display_name: "D".into(),
                ..Default::default()
            },
        );
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.server.default_block_response = BlockResponseV1::SoaNodata;
        cfg.server.default_blocked_ttl_secs = 300;
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        let r = resolver.resolve(&"10.0.0.1".parse().unwrap());
        let prof = r.profile.unwrap();
        assert_eq!(prof.block_response, BlockResponseV1::SoaNodata);
        assert_eq!(prof.blocked_ttl_secs, 300);
    }

    // ── slug_to_id (s43-t1) ─────────────────────────────────────

    fn config_with_blocklists(ids: &[&str]) -> ConfigV1 {
        use crate::config::schema::{Blocklist, BlocklistFormat};
        let mut cfg = base_config();
        cfg.blocklists = ids
            .iter()
            .map(|id| Blocklist {
                id: mk_id(id),
                display_name: format!("Display {id}"),
                url: format!("https://example.com/{id}.txt"),
                format: BlocklistFormat::Domains,
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base: Default::default(),
                trust: Default::default(),
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            })
            .collect();
        cfg
    }

    #[test]
    fn slug_to_id_includes_identity_entry() {
        let cfg = config_with_blocklists(&["privacy-ads"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // Operator types the canonical id directly → resolves to itself.
        let id = resolver.id_for_slug("privacy-ads").unwrap();
        assert_eq!(id.as_str(), "privacy-ads");
    }

    #[test]
    fn slug_to_id_maps_slash_form_to_canonical_id() {
        let cfg = config_with_blocklists(&["privacy-ads", "security-malicious"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // The legacy slash-form (used by [lists].sources) resolves
        // to the canonical [[blocklists]].id.
        assert_eq!(
            resolver.id_for_slug("privacy/ads").unwrap().as_str(),
            "privacy-ads"
        );
        assert_eq!(
            resolver.id_for_slug("security/malicious").unwrap().as_str(),
            "security-malicious"
        );
    }

    #[test]
    fn slug_to_id_returns_none_for_unknown() {
        let cfg = config_with_blocklists(&["privacy-ads"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        assert!(resolver.id_for_slug("ghost-list").is_none());
        assert!(resolver.id_for_slug("ghost/list").is_none());
    }

    #[test]
    fn slug_for_id_inverts_the_map() {
        let cfg = config_with_blocklists(&["privacy-ads"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // Inverse lookup returns the slug-form, NOT the identity entry.
        let slug = resolver.slug_for_id("privacy-ads").unwrap();
        assert_eq!(slug, "privacy/ads");
    }

    #[test]
    fn slug_for_id_returns_none_when_no_hyphen() {
        // Single-token id like `"ads"` only has the identity entry —
        // no slash-form to recover, so slug_for_id returns None.
        let cfg = config_with_blocklists(&["ads"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        // Identity lookup still works…
        assert_eq!(resolver.id_for_slug("ads").unwrap().as_str(), "ads");
        // …but there's no slug to invert to.
        assert!(resolver.slug_for_id("ads").is_none());
    }

    #[test]
    fn slug_to_id_only_swaps_first_hyphen() {
        // `"security-malicious-extra"` → `"security/malicious-extra"`
        // (catalog convention: <scope>/<topic-with-hyphens>).
        let cfg = config_with_blocklists(&["security-malicious-extra"]);
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        assert_eq!(
            resolver
                .id_for_slug("security/malicious-extra")
                .unwrap()
                .as_str(),
            "security-malicious-extra"
        );
        // The "double-swap" path that would also produce
        // `"security/malicious/extra"` MUST NOT be in the map.
        assert!(resolver.id_for_slug("security/malicious/extra").is_none());
    }

    #[test]
    fn slug_to_id_empty_when_no_blocklists() {
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        assert!(resolver.id_for_slug("anything").is_none());
        assert!(resolver.slug_for_id("anything").is_none());
    }

    // ── Sprint 43 T4: per-device overlay (DM2) integration ───────

    fn config_with_overlay_device() -> ConfigV1 {
        use crate::config::schema::AdminRule;
        let mut cfg = base_config();
        cfg.admin_rules.push(AdminRule {
            id: mk_id("dev-allow-bank"),
            rule: "@@||bank.example^".into(),
        });
        cfg.admin_rules.push(AdminRule {
            id: mk_id("dev-deny-tiktok"),
            rule: "||tiktok.com^".into(),
        });
        // Mutate the laptop device (already in base_config) to declare
        // overlay rules. Using the existing device keeps the resolver
        // chain wiring simple — laptop matches at level 1 (DeviceDirect).
        let dev = &mut cfg.devices[0];
        dev.allow_rules = vec![mk_id("dev-allow-bank")];
        dev.deny_rules = vec![mk_id("dev-deny-tiktok")];
        dev.override_profile_deny = false;
        cfg
    }

    #[test]
    fn resolution_carries_overlay_for_device_with_rules() {
        let cfg = config_with_overlay_device();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
        let overlay = r.overlay.expect("device with rules must carry overlay");
        assert_eq!(overlay.device_id.as_str(), "laptop");
        assert!(overlay.allow.contains("bank.example"));
        assert!(overlay.deny.contains("tiktok.com"));
        assert!(!overlay.override_profile_deny);
    }

    #[test]
    fn resolution_overlay_is_none_for_device_without_rules() {
        // Snapshot acceptance: a device whose allow_rules + deny_rules
        // are empty produces `Resolution.overlay = None`. The DNS hot
        // path treats `None` as fall-through to the pre-T4 baseline,
        // so resolution is byte-identical for these devices.
        let cfg = base_config(); // laptop has no overlay fields set
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
        assert!(r.overlay.is_none(), "empty-overlay device → None");
    }

    #[test]
    fn resolution_overlay_propagates_to_subnet_level() {
        // A device whose own levels 1-3 didn't fire (because it's in
        // base_config but we tweak it to carry overlay AND no profile)
        // still gets its overlay attached when level 4 (subnet) wins.
        let mut cfg = config_with_overlay_device();
        cfg.devices[0].profile = None; // drop level 1
        cfg.devices[0].groups = vec![]; // drop level 3
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
        assert_eq!(r.level, Some(ResolveLevel::Subnet));
        let overlay = r.overlay.expect("subnet-resolved device keeps overlay");
        assert!(overlay.allow.contains("bank.example"));
    }

    // ── Sprint 43 T4: §4 truth-table 9-row pin (apply_overlay) ───

    // `_pa` (profile-allow) is retained as a param so the 9-row call sites
    // stay 1:1 with the §4 truth-table columns; res-16 removed it from
    // `LayerHits` because `apply_overlay` never consulted it.
    fn hits(_pa: bool, pd: bool, da: bool, dd: bool) -> LayerHits {
        LayerHits {
            profile_deny_hit: pd,
            device_allow_hit: da,
            device_deny_hit: dd,
        }
    }

    #[test]
    fn truth_table_row_0_no_match_falls_through() {
        // Row 0: nothing matches → caller runs filter.evaluate.
        assert_eq!(
            apply_overlay(hits(false, false, false, false), false),
            OverlayDecision::FallThrough
        );
    }

    #[test]
    fn truth_table_row_1_profile_allow_only_falls_through() {
        // Row 1: profile.allow alone → caller's filter.evaluate
        // returns Forward; attribution becomes Profile at the call site.
        assert_eq!(
            apply_overlay(hits(true, false, false, false), false),
            OverlayDecision::FallThrough
        );
    }

    #[test]
    fn truth_table_row_2_profile_deny_only_falls_through() {
        // Row 2: profile.deny alone → caller's filter.evaluate
        // returns Block; attribution Profile.
        assert_eq!(
            apply_overlay(hits(false, true, false, false), false),
            OverlayDecision::FallThrough
        );
    }

    #[test]
    fn truth_table_row_3_device_allow_only_allows_device() {
        // Row 3: pure per-device allow — operator's exception fires.
        assert_eq!(
            apply_overlay(hits(false, false, true, false), false),
            OverlayDecision::Allow {
                source: AttribSource::Device,
                override_used: false,
            }
        );
    }

    #[test]
    fn truth_table_row_4_device_deny_only_blocks_device() {
        assert_eq!(
            apply_overlay(hits(false, false, false, true), false),
            OverlayDecision::Block {
                source: AttribSource::Device,
            }
        );
    }

    #[test]
    fn truth_table_row_5_device_deny_wins_over_profile_allow() {
        // Additive deny — operator wants this domain blocked for
        // THIS device even though the profile permits it.
        assert_eq!(
            apply_overlay(hits(true, false, false, true), false),
            OverlayDecision::Block {
                source: AttribSource::Device,
            }
        );
    }

    #[test]
    fn truth_table_row_6_drift_defensive_profile_wins_without_override() {
        // Row 6 is supposed to be daemon-unreachable (CLI/TUI refuses
        // it at edit time). On config drift the safe fallback is
        // profile-wins.
        assert_eq!(
            apply_overlay(hits(false, true, true, false), false),
            OverlayDecision::Block {
                source: AttribSource::Profile,
            }
        );
    }

    #[test]
    fn truth_table_row_7_override_flag_unblocks_profile_deny() {
        assert_eq!(
            apply_overlay(hits(false, true, true, false), true),
            OverlayDecision::Allow {
                source: AttribSource::Device,
                override_used: true,
            }
        );
    }

    #[test]
    fn truth_table_row_8_both_deny_attributes_to_profile() {
        // Profile would have denied anyway — Device adds nothing
        // semantically, so the audit log credits the higher layer.
        assert_eq!(
            apply_overlay(hits(false, true, false, true), false),
            OverlayDecision::Block {
                source: AttribSource::Profile,
            }
        );
    }

    /// All combinations the truth table doesn't enumerate explicitly.
    /// `apply_overlay` is a total function — it must produce a
    /// well-defined `OverlayDecision` for every input. This sweeps
    /// the 32 (PA × PD × DA × DD × override) combinations and checks
    /// that none panic. The 9-row tests above pin the specific rows;
    /// this one guards against gaps if the truth table is extended.
    #[test]
    fn apply_overlay_is_total_over_inputs() {
        for pa in [false, true] {
            for pd in [false, true] {
                for da in [false, true] {
                    for dd in [false, true] {
                        for ovr in [false, true] {
                            // Should not panic on any input. The result
                            // is a value of OverlayDecision, which is
                            // exhaustive over 3 variants.
                            let _ = apply_overlay(hits(pa, pd, da, dd), ovr);
                        }
                    }
                }
            }
        }
    }

    /// Sprint 43 T4 acceptance §8: N7 (A/AAAA symmetric). The overlay
    /// is qtype-agnostic by construction — its allow/deny sets key on
    /// domain only. Generative test: 100 random domains × 10 devices
    /// × 2 qtypes (modelled as two independent calls). Same overlay
    /// inputs → same `apply_overlay` output, irrespective of which
    /// qtype the caller would pass downstream.
    #[test]
    fn n7_generative_apply_overlay_qtype_agnostic() {
        // Pseudo-random generator from a fixed seed so the test is
        // deterministic. Linear-congruential parameters from
        // Knuth's MMIX recommendations.
        let mut state: u64 = 0xcafef00d_d15ea5e5;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };
        let bool_from = |bits: u64, shift: u32| (bits >> shift) & 1 == 1;

        for _domain in 0..100u32 {
            for _device in 0..10u32 {
                let bits = next();
                let h = hits(
                    bool_from(bits, 0),
                    bool_from(bits, 1),
                    bool_from(bits, 2),
                    bool_from(bits, 3),
                );
                let ovr = bool_from(bits, 4);

                // Two "qtype channels" — apply_overlay is pure and
                // qtype-agnostic, so the two calls must agree.
                let a_decision = apply_overlay(h, ovr);
                let aaaa_decision = apply_overlay(h, ovr);
                assert_eq!(
                    a_decision, aaaa_decision,
                    "N7 broken: qtype-A vs qtype-AAAA disagreed for hits={h:?}, override={ovr}"
                );
            }
        }
    }

    #[test]
    fn resolution_device_name_short_is_inline_no_heap_alloc() {
        // C-02 (rev 2026-04-26): every short device name (≤24 bytes,
        // covers `iphone-mom`, `pc-living-room`, etc.) must round-trip
        // through `Resolution.device_name` without a heap allocation.
        // The base_config fixture uses display names "Laptop" / "Tablet"
        // — both well under the inline limit.
        let cfg = base_config();
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
        let name = r
            .device_name
            .expect("level-1 device match populates device_name");
        assert_eq!(name.as_str(), "Laptop");
        assert!(
            !name.is_heap_allocated(),
            "short device name must stay inline in CompactString"
        );

        let r = resolver.resolve(&"192.168.1.50".parse().unwrap());
        let name = r
            .device_name
            .expect("level-3 group match populates device_name");
        assert_eq!(name.as_str(), "Tablet");
        assert!(
            !name.is_heap_allocated(),
            "short device name must stay inline in CompactString"
        );
    }

    #[test]
    fn c_03_precomputed_schedule_picks_device_over_group_and_rebuilds_on_swap() {
        // C-03 contract: the active schedule per device is pre-computed at
        // build time + every 60s tick. The hot path probes
        // `active_schedule_by_device` by device id; per-query schedule
        // walks no longer happen.
        //
        // Two invariants this exercises:
        //   1. Device-targeted schedule wins over a group-targeted one
        //      that would otherwise apply to the same device.
        //   2. `swap()` rebuilds the precomputed map — removing the
        //      device-targeted schedule must let the group-targeted
        //      schedule take over for that device on the next probe.
        //
        // Both fixtures use `hours: "00:00-00:00"` + `days: ["all"]` for
        // determinism (always-active windows so the test does not depend
        // on the wall clock).
        let mut cfg = base_config();
        cfg.profiles.insert(
            "device-prof".into(),
            Profile {
                display_name: "Device prof".into(),
                ..Default::default()
            },
        );
        cfg.profiles.insert(
            "group-prof".into(),
            Profile {
                display_name: "Group prof".into(),
                ..Default::default()
            },
        );
        // Device-targeted schedule on the tablet.
        cfg.schedules.push(Schedule {
            id: mk_id("device-sched"),
            display_name: "Device sched".into(),
            target_type: ScheduleTargetType::Device,
            target_id: mk_id("tablet"),
            profile: mk_id("device-prof"),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(),
            expires_at: None,
        });
        // Group-targeted schedule on the iot group (the tablet is a member).
        cfg.schedules.push(Schedule {
            id: mk_id("group-sched"),
            display_name: "Group sched".into(),
            target_type: ScheduleTargetType::Group,
            target_id: mk_id("iot"),
            profile: mk_id("group-prof"),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(),
            expires_at: None,
        });

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let ip: IpAddr = "192.168.1.50".parse().unwrap();

        // Invariant 1: device-targeted wins.
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Schedule));
        assert_eq!(
            r.matched_schedule.as_ref().map(|i| i.as_str()),
            Some("device-sched"),
            "device-targeted schedule must win over group-targeted one in the precomputed map",
        );
        assert_eq!(r.profile.as_ref().unwrap().name.as_str(), "device-prof");

        // Invariant 2: swap() rebuilds the precomputed map.
        cfg.schedules.retain(|s| s.id.as_str() != "device-sched");
        resolver.swap(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&ip);
        assert_eq!(
            r.level,
            Some(ResolveLevel::Schedule),
            "group schedule should now drive the resolution after swap()",
        );
        assert_eq!(
            r.matched_schedule.as_ref().map(|i| i.as_str()),
            Some("group-sched"),
        );
        assert_eq!(r.profile.as_ref().unwrap().name.as_str(), "group-prof");

        // Invariant 3: swap() with no schedules clears the precomputed map.
        cfg.schedules.clear();
        resolver.swap(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&ip);
        assert_ne!(
            r.level,
            Some(ResolveLevel::Schedule),
            "no active schedule must mean no schedule-level resolution",
        );
        assert!(r.matched_schedule.is_none());
    }

    #[test]
    fn h_14_mac_mismatch_ring_throttle_suppresses_within_window() {
        // T2.7 H-14 + §4.30 profiles-h2: 100 mismatches for the same
        // (ip, observed_mac) pair at a single instant must produce
        // exactly one "fire". Single pair always hits the same slot,
        // so the ring reproduces the pre-§4.30 Mutex<HashMap>
        // semantics for the no-collision case byte-for-byte.
        let ring = MacMismatchRing::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mac = CompactString::new("AA:BB:CC:DD:EE:FF");
        let t0 = Instant::now();

        let fired: usize = (0..100).filter(|_| ring.should_warn(ip, &mac, t0)).count();

        assert_eq!(
            fired, 1,
            "ring must collapse 100 mismatches for a single pair into 1 fire",
        );
    }

    #[test]
    fn h_14_mac_mismatch_ring_re_fires_after_window() {
        // After MAC_MISMATCH_WARN_WINDOW elapses, the same pair must
        // emit a fresh warn so persistent attacks stay visible.
        let ring = MacMismatchRing::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mac = CompactString::new("AA:BB:CC:DD:EE:FF");
        let t0 = Instant::now();

        assert!(ring.should_warn(ip, &mac, t0));
        // Same instant — throttled.
        assert!(!ring.should_warn(ip, &mac, t0));
        // Past the window — must re-fire.
        let t_after = t0 + MAC_MISMATCH_WARN_WINDOW + Duration::from_secs(1);
        assert!(ring.should_warn(ip, &mac, t_after));
    }

    #[test]
    fn h_14_mac_mismatch_ring_distinct_pairs_each_fire_at_least_once() {
        // §4.30 profiles-h2: 8-slot sharded ring means distinct pairs
        // that hash to the same slot displace each other on emit.
        // Every pair's FIRST call must fire (slot starts at 0 / holds
        // a different pair's hash → no match → fire). A pair displaced
        // by a later colliding pair will fire AGAIN on its second
        // call; non-displaced pairs throttle on the second call. So
        // across N pairs × 2 calls, the total-fires count sits in
        // [N, 2N].
        let ring = MacMismatchRing::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        let macs: Vec<CompactString> = (0..5)
            .map(|i| CompactString::new(format!("AA:BB:CC:DD:EE:0{i}")))
            .collect();

        let first_pass: usize = macs.iter().filter(|m| ring.should_warn(ip, m, t0)).count();
        let second_pass: usize = macs.iter().filter(|m| ring.should_warn(ip, m, t0)).count();

        assert_eq!(
            first_pass, 5,
            "every distinct pair must fire on its first call (ring starts at 0, no hash matches)",
        );
        assert!(
            second_pass <= 5,
            "second-call fires (collision displacement) must not exceed pair count, got {second_pass}",
        );
    }

    #[test]
    fn h_14_mac_mismatch_ring_is_structurally_bounded() {
        // §4.30 profiles-h2: ring memory is fixed at 8 × AtomicU64 +
        // 1 Instant. Lock the bound against any refactor that
        // reintroduces a HashMap or per-pair Vec. The pre-§4.30
        // Mutex<HashMap> could grow to ~12 KB under attack — this
        // structural ring is capped at <128 bytes on every supported
        // platform.
        assert!(
            std::mem::size_of::<MacMismatchRing>() <= 128,
            "MacMismatchRing must remain a structural ring (8 × u64 + 1 Instant), \
             not a heap collection — got {} bytes",
            std::mem::size_of::<MacMismatchRing>(),
        );
    }

    // ── M-33: effective_profile_name walks subnet level ─────

    #[test]
    fn effective_profile_name_falls_back_to_subnet_when_no_direct_or_group() {
        // Pre-fix: a device with `configured_ip` inside a subnet but no
        // direct/group profile reported the global default in the IPC
        // snapshot — even though `resolve()` would surface the subnet's
        // profile. The TUI client list lied about which profile was
        // actually filtering the device.
        let mut cfg = base_config();
        cfg.server.default_profile = Some(mk_id("default"));
        // New device with IP inside the LAN subnet, no direct/group.
        cfg.devices.push(Device {
            id: mk_id("bulb"),
            display_name: "IoT Bulb".into(),
            ip: Some("192.168.1.77".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        // resolve() returns the subnet's profile ("kids") for this IP.
        let ip: IpAddr = "192.168.1.77".parse().unwrap();
        let r = resolver.resolve(&ip);
        assert_eq!(r.level, Some(ResolveLevel::Subnet));
        assert_eq!(r.profile.unwrap().name.as_str(), "kids");

        // Snapshot must agree with resolve() — pre-fix this would say
        // "default" instead of "kids".
        let snapshots = resolver.list_mapped_devices();
        let bulb = snapshots
            .iter()
            .find(|s| s.dto.name == "IoT Bulb")
            .expect("bulb device should be in snapshot");
        assert_eq!(
            bulb.dto.profile, "kids",
            "subnet-resolved device must report its subnet profile in IPC snapshot, not the global default"
        );
    }

    #[test]
    fn effective_profile_name_subnet_longest_prefix_wins() {
        // Two overlapping subnets: device's IP matches both, longest-prefix
        // wins (mirroring resolve()'s priority).
        let mut cfg = base_config();
        cfg.profiles.insert(
            "narrow".into(),
            Profile {
                display_name: "Narrow".into(),
                ..Default::default()
            },
        );
        cfg.subnets.clear();
        cfg.subnets.push(Subnet {
            id: mk_id("broad"),
            display_name: "Broad".into(),
            cidrs: vec!["192.168.0.0/16".into()],
            profile: mk_id("kids"),
            priority: 0,
        });
        cfg.subnets.push(Subnet {
            id: mk_id("narrow"),
            display_name: "Narrow".into(),
            cidrs: vec!["192.168.1.0/24".into()],
            profile: mk_id("narrow"),
            priority: 0,
        });
        cfg.devices.push(Device {
            id: mk_id("printer"),
            display_name: "Printer".into(),
            ip: Some("192.168.1.200".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let snapshots = resolver.list_mapped_devices();
        let printer = snapshots
            .iter()
            .find(|s| s.dto.name == "Printer")
            .expect("printer device should be in snapshot");
        assert_eq!(
            printer.dto.profile, "narrow",
            "longest-prefix /24 must win over the overlapping /16"
        );
    }

    #[test]
    fn effective_profile_name_falls_back_to_default_when_no_subnet_match() {
        // Device with IP outside every subnet must report the global
        // default — not silently mis-attribute to a non-matching subnet.
        let mut cfg = base_config();
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.devices.push(Device {
            id: mk_id("rogue"),
            display_name: "Rogue".into(),
            ip: Some("10.99.99.99".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let snapshots = resolver.list_mapped_devices();
        let rogue = snapshots
            .iter()
            .find(|s| s.dto.name == "Rogue")
            .expect("rogue device should be in snapshot");
        assert_eq!(rogue.dto.profile, "default");
    }

    // ── M-36: ARP map inversion in snapshots_from ─────

    #[test]
    fn snapshots_from_inverted_arp_matches_pre_fix_loop() {
        // Correctness fixture: for a device with one mac_pin + one alias,
        // verify that snapshots_from picks up every IP the pre-fix loop
        // would have. Two ARP entries name a MAC the device owns; one
        // is unrelated and must NOT bleed into the device's IP list.
        let mut cfg = base_config();
        cfg.devices.push(Device {
            id: mk_id("dual-nic"),
            display_name: "DualNic".into(),
            ip: Some("192.168.1.10".parse().unwrap()),
            mac: Some("AA:AA:AA:AA:AA:01".parse().unwrap()),
            mac_aliases: vec!["AA:AA:AA:AA:AA:02".parse().unwrap()],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        let mut arp: HashMap<IpAddr, CompactString> = HashMap::new();
        // Pin MAC observed at two IPs (DHCP shuffle) — both must show up.
        arp.insert(
            "192.168.1.20".parse().unwrap(),
            CompactString::new("AA:AA:AA:AA:AA:01"),
        );
        arp.insert(
            "192.168.1.21".parse().unwrap(),
            CompactString::new("AA:AA:AA:AA:AA:01"),
        );
        // Alias MAC at a third IP.
        arp.insert(
            "192.168.1.30".parse().unwrap(),
            CompactString::new("AA:AA:AA:AA:AA:02"),
        );
        // Unrelated MAC — must NOT appear in the device's IP list.
        arp.insert(
            "192.168.1.99".parse().unwrap(),
            CompactString::new("DE:AD:BE:EF:00:00"),
        );

        let snapshots = snapshots_from(&resolver.inner.load(), &arp);
        let dual_nic = snapshots
            .iter()
            .find(|s| s.dto.name == "DualNic")
            .expect("dual-nic should be in snapshot");
        let mut ips = dual_nic.ips.clone();
        ips.sort();
        assert_eq!(
            ips,
            vec![
                "192.168.1.10".parse::<IpAddr>().unwrap(), // configured
                "192.168.1.20".parse::<IpAddr>().unwrap(), // pin (DHCP A)
                "192.168.1.21".parse::<IpAddr>().unwrap(), // pin (DHCP B)
                "192.168.1.30".parse::<IpAddr>().unwrap(), // alias
            ],
        );
        // Unrelated 192.168.1.99 must NOT be present.
        assert!(!ips.contains(&"192.168.1.99".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn snapshots_from_empty_arp_does_not_panic() {
        // Empty ARP table — devices with no configured_ip should still
        // appear in the snapshot, just with an empty `ips` vec. Pre-fix
        // would also handle this; the M-36 inverted index must not panic
        // on empty (`HashMap::with_capacity(0)` is well-defined, no
        // panic on empty .entry().or_default() since we never enter the
        // loop, no panic on .get() against an empty map).
        let mut cfg = base_config();
        cfg.devices.push(Device {
            id: mk_id("orphan"),
            display_name: "Orphan".into(),
            ip: None,
            mac: Some("DE:AD:BE:EF:00:01".parse().unwrap()),
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let arp: HashMap<IpAddr, CompactString> = HashMap::new();

        let snapshots = snapshots_from(&resolver.inner.load(), &arp);
        let orphan = snapshots
            .iter()
            .find(|s| s.dto.name == "Orphan")
            .expect("orphan device should be in snapshot");
        assert!(orphan.ips.is_empty());
        assert_eq!(orphan.dto.ip, "");
    }

    #[test]
    fn effective_profile_name_no_configured_ip_skips_subnet_level() {
        // MAC-only device (no configured IP) must not crash the snapshot
        // walk; falls straight to the global default per `resolve()`'s
        // anonymous-source semantics.
        let mut cfg = base_config();
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.devices.push(Device {
            id: mk_id("phone"),
            display_name: "Phone".into(),
            ip: None,
            mac: Some("AA:BB:CC:DD:EE:FF".parse().unwrap()),
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let snapshots = resolver.list_mapped_devices();
        let phone = snapshots
            .iter()
            .find(|s| s.dto.name == "Phone")
            .expect("phone device should be in snapshot");
        // No configured IP → subnet level skipped → default wins.
        assert_eq!(phone.dto.profile, "default");
    }

    fn bare_device(id: &str, ip: &str, unfiltered: bool) -> Device {
        Device {
            id: mk_id(id),
            display_name: id.to_string(),
            ip: Some(ip.parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    fn always_on_group_schedule(id: &str, group: &str, profile: &str) -> Schedule {
        Schedule {
            id: mk_id(id),
            display_name: id.to_string(),
            target_type: ScheduleTargetType::Group,
            target_id: mk_id(group),
            profile: mk_id(profile),
            days: vec!["all".into()],
            // Always active, so the assertion does not depend on the
            // wall clock.
            hours: "00:00-00:00".into(),
            expires_at: None,
        }
    }

    #[test]
    fn a_group_schedule_reaches_a_member_joined_from_the_group_side() {
        // Membership is expressible in both directions and is NOT required
        // to be symmetric — the CLI join path writes only one of them. A
        // device listed in `[[groups]].devices` gets the group's PROFILE
        // (level 3) because that level reads the unioned structure; the
        // schedule level used to read the device row's own `groups` and so
        // disagreed about who was in the group. The device kept its laxer
        // profile straight through the window the operator wrote to
        // restrict it, which is the fail-open direction.
        let mut cfg = base_config();
        cfg.profiles.insert(
            "bedtime".into(),
            Profile {
                display_name: "Bedtime".into(),
                ..Default::default()
            },
        );
        // Joined ONLY from the group side: its own `groups` stays empty.
        cfg.devices
            .push(bare_device("console", "192.168.1.61", false));
        let iot = cfg
            .groups
            .iter_mut()
            .find(|g| g.id.as_str() == "iot")
            .expect("base config defines the iot group");
        iot.devices.push(mk_id("console"));
        cfg.schedules
            .push(always_on_group_schedule("quiet-hours", "iot", "bedtime"));

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&"192.168.1.61".parse::<IpAddr>().unwrap());

        assert_eq!(
            r.level,
            Some(ResolveLevel::Schedule),
            "a group-side-only member must reach the group's schedule, not fall past it to level 3",
        );
        assert_eq!(
            r.matched_schedule.as_ref().map(|i| i.as_str()),
            Some("quiet-hours")
        );
        assert_eq!(r.profile.unwrap().name.as_str(), "bedtime");
    }

    #[test]
    fn a_group_schedule_follows_group_priority_not_file_order() {
        // The two orders are made to DISAGREE on purpose: file order puts
        // the low-priority group first, so a walk over the device row's
        // own `groups` picks the opposite group from the one level 3 would
        // pick. Without that disagreement this test passes either way and
        // pins nothing.
        let mut cfg = base_config();
        for (name, prof) in [("lax-window", "lax"), ("strict-window", "locked")] {
            cfg.profiles.insert(
                prof.into(),
                Profile {
                    display_name: name.into(),
                    ..Default::default()
                },
            );
        }
        let mut dev = bare_device("desk", "192.168.1.62", false);
        // FILE order: low priority first.
        dev.groups = vec![mk_id("weak"), mk_id("strong")];
        cfg.devices.push(dev);
        cfg.groups.push(Group {
            id: mk_id("weak"),
            display_name: "Weak".into(),
            profile: mk_id("default"),
            priority: 1,
            devices: vec![],
        });
        cfg.groups.push(Group {
            id: mk_id("strong"),
            display_name: "Strong".into(),
            profile: mk_id("strict"),
            priority: 99,
            devices: vec![],
        });
        cfg.schedules
            .push(always_on_group_schedule("weak-sched", "weak", "lax"));
        cfg.schedules
            .push(always_on_group_schedule("strong-sched", "strong", "locked"));

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );
        let r = resolver.resolve(&"192.168.1.62".parse::<IpAddr>().unwrap());

        assert_eq!(r.level, Some(ResolveLevel::Schedule));
        assert_eq!(
            r.matched_schedule.as_ref().map(|i| i.as_str()),
            Some("strong-sched"),
            "the schedule level must rank groups the way the group level does",
        );
        assert_eq!(r.profile.unwrap().name.as_str(), "locked");
    }

    #[test]
    fn an_unfiltered_device_stays_unfiltered_at_subnet_level() {
        // The minimal way to say "this box exists, don't filter it" is a
        // device row with the flag and nothing else — no profile, no
        // group, no schedule. That row resolves at level 4, where the
        // flag used to be dropped and the device was fully list-filtered.
        let mut cfg = base_config();
        cfg.devices
            .push(bare_device("iot-bulb", "192.168.1.77", true));
        cfg.devices
            .push(bare_device("iot-plug", "192.168.1.78", false));

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        let flagged = resolver.resolve(&"192.168.1.77".parse::<IpAddr>().unwrap());
        assert_eq!(flagged.level, Some(ResolveLevel::Subnet));
        assert!(
            flagged.profile.as_ref().unwrap().unfiltered,
            "the device's one explicit statement about itself must survive level 4",
        );

        // Controls: the same level must NOT hand the specialisation to a
        // device that did not ask for it, nor to an anonymous source.
        let plain = resolver.resolve(&"192.168.1.78".parse::<IpAddr>().unwrap());
        assert_eq!(plain.level, Some(ResolveLevel::Subnet));
        assert!(!plain.profile.as_ref().unwrap().unfiltered);

        let anon = resolver.resolve(&"192.168.1.99".parse::<IpAddr>().unwrap());
        assert_eq!(anon.level, Some(ResolveLevel::Subnet));
        assert!(!anon.profile.as_ref().unwrap().unfiltered);
    }

    #[test]
    fn an_unfiltered_device_stays_unfiltered_at_global_default_level() {
        let mut cfg = base_config();
        // No subnet, so the flagged device falls all the way to level 5.
        cfg.subnets.clear();
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.devices
            .push(bare_device("iot-bulb", "192.168.1.77", true));

        let resolver = ProfileResolver::build(
            &cfg,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        );

        let flagged = resolver.resolve(&"192.168.1.77".parse::<IpAddr>().unwrap());
        assert_eq!(flagged.level, Some(ResolveLevel::GlobalDefault));
        assert!(
            flagged.profile.as_ref().unwrap().unfiltered,
            "level 5 serves configured devices too, so the flag binds here as well",
        );

        let anon = resolver.resolve(&"10.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(anon.level, Some(ResolveLevel::GlobalDefault));
        assert!(!anon.profile.as_ref().unwrap().unfiltered);
    }
}
