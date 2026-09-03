//! Profile resolver — 5-level chain driving the DNS hot path.
//!
//! The hot path does a single atomic load + index lookup. A background
//! task (see `cli::commands::start::handle_schedule_tick`) rebuilds the
//! map every 60 seconds to re-evaluate schedule windows, and on every
//! SIGHUP / IPC reload the map swaps atomically (`ArcSwap`).
//!
//! # Resolver chain
//!
//! When a DNS query arrives from source IP `X`, [`ProfileResolver::resolve`]
//! walks the five levels in order and returns at the first match:
//!
//! 1. **Device direct profile** — a [`Device`](crate::config::schema::Device) whose `ip` pin equals `X`
//!    (or whose MAC is active for `X` per the ARP snapshot, when
//!    enforcement is on) AND that has a `profile = …` field set → use
//!    that profile. Device direct profile overrides anything.
//! 2. **Active schedule override** — if the device matched above, or any
//!    [`Group`] it belongs to, has a schedule whose current-time window
//!    is active → use the schedule's profile.
//! 3. **Group membership** — the device's highest-priority group's
//!    profile. Same-priority-different-profile conflicts surface as
//!    validator errors at load time, so the resolver can pick the first
//!    of a priority-sorted list deterministically.
//! 4. **Subnet default** — longest-prefix match against `[[subnets]]`.
//!    Used only for sources that didn't match a `[[devices]]` row.
//! 5. **Global fallback** — `[server].default_profile`. If that is
//!    unset → REFUSED.
//!
//! # MAC enforcement
//!
//! When `[server].enforce_device_mac = true` (default) and the matched
//! device pins a MAC, the resolver consults the live ARP snapshot before
//! returning the device profile. If the ARP table shows a different MAC
//! than the one pinned, the device is "downgraded" to the resolver chain
//! starting at level 4 (subnet) — a device under security suspicion
//! loses its direct / group / schedule overrides but is NOT automatically
//! blocked (the operator can still wire subnet or default_profile for it).
//!
//! # block_unmapped_clients
//!
//! There is no `server.block_unmapped_clients` flag. Its effect is
//! expressed by leaving `default_profile` unset (level 5 → REFUSED).
//! Any code path checking for that behaviour pattern-matches on
//! [`Resolution::profile`] being `None`.

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

/// Which of the five resolver-chain levels matched a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveLevel {
    /// Level 1: `device.profile` matched directly.
    DeviceDirect,
    /// Level 2: a schedule window was active for the matched device / group.
    Schedule,
    /// Level 3: resolved via group membership + priority.
    Group,
    /// Level 4: longest-prefix subnet default.
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
    /// Per-device overlay attached when the matched device declared
    /// `allow_rules` / `deny_rules`. `None` for devices with empty
    /// overlay, anonymous sources (subnet/default level with no device
    /// match), and the REFUSED sentinel — the hot path treats `None` as
    /// "fall through to profile evaluation only".
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
/// [`MAC_MISMATCH_WARN_WINDOW`] for the throttle contract; the ring
/// replaced an earlier `Mutex<HashMap>` so the hot path stays zero-lock
/// per CLAUDE.md key rule #1.
pub struct ProfileResolver {
    inner: ArcSwap<ResolverMap>,
    arp_by_ip: ArcSwap<HashMap<IpAddr, CompactString>>,
    /// Live handle to the daemon's blocklist download state, attached
    /// once at boot by [`Self::attach_list_state`]. Every map rebuild
    /// ([`Self::swap`]) snapshots it so `list_applies` can drop lists
    /// that have never downloaded and keep lists serving from a stale
    /// cache.
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
    /// Per-`(ip, observed_mac)` rate limit on the MAC-mismatch audit
    /// warn. 8-slot sharded ring encoding `(hash << 32) | last_secs`
    /// per slot, indexed by `hash(ip, mac) & 7`. Structural memory
    /// bound: 64 bytes of slots + 16 bytes of per-ring epoch `Instant`
    /// = 80 bytes total (vs an unbounded `HashMap` which could grow
    /// arbitrarily under attack). Worst-case collision rate
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

/// 8-slot sharded ring of `AtomicU64` replacing a
/// `Mutex<HashMap<(IpAddr, CompactString), Instant>>` MAC-
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
    /// Devices keyed by their pinned IP, always in [`canonical_ip`] form.
    /// Both sides of every probe must agree on one spelling per address,
    /// or an IPv4 pin is unreachable from a dual-stack listener.
    devices_by_ip: HashMap<IpAddr, Arc<DeviceIndex>>,
    /// Devices keyed by every MAC they own (primary + aliases), upper-cased.
    devices_by_mac: HashMap<CompactString, Arc<DeviceIndex>>,
    /// Every `DeviceIndex` keyed by its stable id — used by the IPC
    /// snapshot builder and by group / schedule lookups.
    devices_by_id: HashMap<Id, Arc<DeviceIndex>>,
    /// Per-device overlay, indexed by device id. Devices with both
    /// `allow_rules` and `deny_rules` empty get NO entry here — the
    /// resolver attaches `Resolution.overlay = None` for them, matching
    /// the hot path byte-for-byte for devices with no overlay state.
    /// Each `Arc<DeviceOverlay>` lives next to the per-device profile
    /// pointer in this same `ResolverMap`, so a single `ArcSwap`
    /// snapshot delivers both consistently.
    device_overlays: HashMap<Id, Arc<DeviceOverlay>>,
    /// For each device: the groups it belongs to, pre-sorted by priority
    /// descending. Level-3 resolution picks the first entry.
    device_groups: HashMap<Id, Vec<GroupMatch>>,
    /// Subnets sorted by prefix length DESC so the first matching entry
    /// is the longest-prefix. Ties in prefix length are resolved
    /// by (informational) priority DESC then by id ASC for determinism.
    subnets: Vec<SubnetMatch>,
    /// Pre-computed active schedule per device, evaluated at
    /// config-build time (and again on every 60s schedule tick) so the
    /// DNS hot path resolves the schedule level via a single HashMap
    /// probe instead of walking every device's schedule list per query.
    /// At 10 kqps this lifts ~10k schedule walks/sec out of `resolve_at`.
    /// Devices with no active schedule have NO entry here — the hot
    /// path treats absence as "no schedule override" and falls through
    /// to level 1/3/4/5. Accepts up to a 60s window-boundary gap, the
    /// same gap the pre-computation contract promises. There is
    /// deliberately no raw `schedules_by_device` / `schedules_by_group`
    /// index next to this map: nothing on or off the hot path consults
    /// per-device schedule lists after pre-computation, and keeping
    /// such an index around would invite regression to a per-query
    /// walk.
    active_schedule_by_device: HashMap<Id, Arc<ScheduleMatch>>,
    /// Level-5 fallback. `None` → REFUSED.
    default_profile: Option<ProfilePair>,
    /// Master switch for MAC enforcement (from `ServerGlobals`).
    enforce_mac: bool,
    /// Bridge from legacy `[lists].sources` slug-form strings
    /// (`"privacy/ads"`) to canonical `[[blocklists]].id` values
    /// (`"privacy-ads"`). Built at boot from `config.blocklists` —
    /// every entry contributes its id under both the literal id key
    /// (identity mapping) and the hyphen-to-slash transform that
    /// recovers the legacy slug catalog form. Accessed via
    /// [`ProfileResolver::id_for_slug`] and
    /// [`ProfileResolver::slug_for_id`]. Parked debt for full
    /// retirement of the dual-keyed namespace.
    slug_to_id: HashMap<String, Id>,
    /// `network_name` index: bare name → device id, exact match only.
    /// Config-static — rebuilt on every `swap()`, same cadence as the
    /// rest of this map. The live IP lookup happens at query time in
    /// [`ProfileResolver::resolve_network_name`], NOT here — baking a
    /// device's current IP into this map would only be as fresh as the
    /// last config reload, defeating the "dynamic" premise the network-
    /// name resolution model depends on.
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
    /// The device opted out of filtering entirely, expressed via
    /// [`ResolvedProfile::unfiltered`]; monitoring stays active (the
    /// operator wants visibility into IoT traffic without enforcement).
    /// Surfaced to the TUI Devices tab via the `[⚠ UNFILTERED]` badge +
    /// skipped tag rows.
    unfiltered: bool,
    /// The device's configured `network_name`, lower-cased. Carried on
    /// the index (not just in `ResolverMap::network_names`) so the read
    /// side can round-trip it: `snapshots_from` feeds `MappedDeviceDto`,
    /// and the TUI Edit modal pre-populates only from that DTO. Without
    /// it the modal cannot show an existing name, and an always-`Some(…)`
    /// submit would blank it on every unrelated edit — the field-omission
    /// bug class CLAUDE.md documents for `build_blocklist_value` /
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
    /// engine — the engine itself does not need to know about it.
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

    /// Attach the daemon's live blocklist-download state so subsequent
    /// [`Self::swap`] rebuilds can honour it.
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
    /// pre-computed at config swap (and on every 60s schedule tick), so
    /// this fn never consults the wall clock directly.
    pub fn resolve(&self, ip: &IpAddr) -> Resolution {
        let map = self.inner.load();
        let arp = self.arp_by_ip.load();

        // Normalise once and probe everything below with it. Doing it
        // per-lookup is how the levels drift apart: a mapped source that
        // hit the device index but missed the IPv4-keyed ARP snapshot
        // would take the "no ARP entry, trust the pin" arm and skip MAC
        // enforcement entirely.
        let ip = canonical_ip(*ip);

        // Identify the device. An operator can pin the device by IP
        // (direct lookup) OR by MAC (ARP-based lookup). MAC enforcement
        // rejects stale IP-pins whose live MAC differs from the pinned
        // MAC; such a device falls through to level 4 (subnet) — not to
        // "default-only", because the operator may still have wired a
        // subnet-level profile for it.
        let device_candidate = match map.devices_by_ip.get(&ip) {
            Some(dev) => {
                if let Some(pin) = dev.mac_pin.as_deref() {
                    if map.enforce_mac {
                        match arp.get(&ip) {
                            Some(current) if current.as_str() == pin => Some(dev.clone()),
                            Some(current) => {
                                if self
                                    .mac_mismatch_warns
                                    .should_warn(ip, current, Instant::now())
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
                    // Device pinned by IP only, no MAC pin, under
                    // `enforce_device_mac`.
                    // IP-only acceptance is bypassable in ~30 s (CLAUDE.md
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
                        .should_warn(ip, &sentinel, Instant::now())
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
                arp.get(&ip)
                    .and_then(|mac| map.devices_by_mac.get(mac.as_str()))
                    .cloned()
            }
        };

        // Overlay lookup runs once against the same ArcSwap snapshot
        // (`map`) used by the rest of the resolution. Both the profile
        // pointer and the overlay pointer come from a single load — no
        // torn read possible across reload.
        let overlay_for = |dev: &DeviceIndex| -> Option<Arc<DeviceOverlay>> {
            map.device_overlays.get(&dev.id).cloned()
        };

        if let Some(dev) = device_candidate.as_ref() {
            // Level 2 first — schedule overrides all non-direct levels,
            // but only takes effect when the device is resolved. A
            // schedule matching a device or one of its groups wins over
            // levels 3-5 below. The active schedule is pre-computed at
            // config build time + every 60s tick, so this is a single
            // HashMap probe instead of a per-query walk.
            if let Some(sched_hit) = map.active_schedule_by_device.get(&dev.id) {
                // The device's *direct* profile (level 1) could also be
                // read as outranking a schedule when both are present.
                // But in practice, an operator writing a schedule for a
                // device with a direct profile is clearly asking for the
                // schedule to win during its window — otherwise the
                // schedule has no effect. We pick schedule > direct here
                // for operator intuition. Tests pin this choice.
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
            // authoritative match; same-priority-different-profile
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
        // `cidr.contains` hit is the longest-prefix winner — a
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
            if sn.cidr.contains(ip) {
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
            .get(&canonical_ip(*ip))
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

    /// Resolve a slug-form / canonical id to the
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
    /// consistent with each other. Returns the pair `(mapped, arp)`;
    /// there is no `block_unmapped_clients` flag to carry alongside it.
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
        // network_name configured at all. CLAUDE.md rule 1 / this module's
        // header: zero-alloc on the hot path is a product invariant, not a
        // preference.
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
    /// path instead of the intended match.
    #[cfg(test)]
    pub fn test_only_set_arp_snapshot(&self, entries: &[(IpAddr, &str)]) {
        let map: HashMap<IpAddr, CompactString> = entries
            .iter()
            .map(|(ip, mac)| (*ip, CompactString::new(mac.to_ascii_uppercase())))
            .collect();
        self.arp_by_ip.store(Arc::new(map));
    }
}

// ── MAC-mismatch warn throttle ──────────────────────────────────

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

/// Read `data/list_state.toml` **fail-open**.
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
/// Policy is a property of the profile, so two devices on one profile
/// see the same lists — the one thing that still varies per device is
/// `[[devices]].unfiltered`, which was never really a tag question (see
/// [`ResolvedProfile::as_unfiltered`]).
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
        // The persisted download state reaches `list_applies`. A list
        // the daemon has never fetched successfully (`Pending`, or
        // `Failed` with no cache on disk) stops occupying a bit; a
        // `Failed` list that still has its previous cache keeps
        // filtering (stale-cache fallback). `None` — the daemon before
        // it has attached its handle, plus every CLI / TUI / test
        // caller — means "state unknown" and every tag-intersecting
        // list applies.
        let mut resolved = ResolvedProfile::build_v1(
            &id,
            profile,
            &admin_rules_by_id,
            custom_lists,
            &config.server,
            config.local_dns.ttl_secs,
        );
        // Flatten the per-profile ECS sub-table on top of the global
        // `[upstream.ecs]` defaults. The resulting `EcsPolicy` is
        // `Copy`, so the one surviving per-device specialisation
        // (`as_unfiltered`) carries it through on its clone path.
        // `build_v1` left it at OFF; we set the real value here so the
        // hot path picks it up.
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
    // registered under *every* IP its MAC currently holds — a
    // MAC-keyed read would keep only one IP per MAC, nondeterministically.
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
    // Per-device overlays parallel the device index. Only
    // populated for devices that declared `allow_rules` / `deny_rules` —
    // empty-overlay devices are absent from the map, so their hot path
    // sees `Resolution.overlay = None` and runs the unchanged hot path.
    // `DeviceOverlay::build_v1` shares the already-built
    // `admin_rules_by_id` map with `ResolvedProfile::build_v1`.
    let mut device_overlays: HashMap<Id, Arc<DeviceOverlay>> = HashMap::new();
    // Device-network-name indexes. Both are config-static; the IP
    // behind a name is looked up at query time against the
    // independently-refreshed ARP snapshot.
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

        // Build per-device overlay if the device declared
        // any allow/deny rule references. The build helper returns
        // `None` for empty / all-skipped rule sets.
        if let Some(overlay) = DeviceOverlay::build_v1(dev, &admin_rules_by_id) {
            device_overlays.insert(dev.id.clone(), overlay);
        }

        if let Some(ip) = dev.ip {
            devices_by_ip.insert(canonical_ip(ip), index.clone());
        }
        if let Some(ref pin) = mac_pin {
            devices_by_mac.insert(pin.clone(), index.clone());
        }
        for alias in &mac_aliases {
            devices_by_mac.insert(alias.clone(), index.clone());
        }

        // Also register any ARP-learned IPs for this device's MACs so
        // DHCP reassignment is handled without a config edit. A MAC may
        // answer at several IPs, so register all of them. Skip any ARP
        // IP that would clobber a different device's configured IP (the
        // operator's explicit mapping wins).
        let register_arp_ips = |devices_by_ip: &mut HashMap<IpAddr, Arc<DeviceIndex>>,
                                mac_upper: &str| {
            let Some(addrs) = arp_ips_by_mac.get(mac_upper) else {
                return;
            };
            for &arp_ip in addrs {
                // One canonical binding, so the guard below and the insert
                // cannot disagree on the key and let an ARP-learned address
                // clobber another device's configured pin.
                let arp_ip = canonical_ip(arp_ip);
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
    // Two devices on one group profile see the same lists by
    // construction: list policy is a property of the profile, not a
    // per-device tag intersection.
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
    // validator's conflict check (`check_group_priority_conflicts`)
    // unions both directions exactly like this pass does.
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

    // Pre-compute active schedule per device once at build time.
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
    // means `unfiltered` and nothing else.
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

/// Build the `slug → [[blocklists]].id` bridge map.
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

// ── per-device overlay decision (truth table) ───────────────────

/// Which side of the `apply_overlay` decision was responsible
/// for the verdict. Mirrors `crate::tracking::RuleSource` at the type
/// level but stays attribution-only — the caller turns this enum plus
/// the live profile / device ids into a `RuleSource` for tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttribSource {
    /// Profile-level allow/deny matched.
    Profile,
    /// Device-level allow/deny matched (or override allowed past a
    /// profile deny, truth table row 7).
    Device,
}

/// Outcome of `apply_overlay`. The caller maps each
/// variant to the per-query bool + `RuleSource` attribution; the
/// pure fn stays decoupled from the live entity ids so the truth
/// table can be unit-tested without setting up a full resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayDecision {
    /// Forward the query (allow). Carries the layer attribution and
    /// whether the `[OVERRIDE]` badge applies (row 7).
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

/// Per-query layer probe results, fed into [`apply_overlay`].
///
/// One boolean per decision-relevant layer keeps `apply_overlay` a pure fn
/// over the flags + the override switch. The DNS handler computes these by
/// calling `crate::filter::engine::domain_matches_set` on the device's
/// overlay sets and the profile's deny set — two probes for the overlay
/// plus the profile-deny probe the evaluator already does internally.
///
/// There is no `profile_allow_hit` field: no reader would consult it
/// (every FallThrough row ignores profile-allow, and the fall-through
/// caller's `filter.evaluate` re-derives it), so computing it would be a
/// dead per-query HashSet walk on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerHits {
    pub profile_deny_hit: bool,
    pub device_allow_hit: bool,
    pub device_deny_hit: bool,
}

/// Enforce the truth table below — the **single** decision seat for
/// combining profile-level and device-level allow/deny hits.
///
/// Pure function: same inputs → same `OverlayDecision`. The 9-row truth
/// table is unit-tested across every combination in the resolver test
/// module.
///
/// The 9 rows (PA = profile.allow, PD = profile.deny, DA = device.allow,
/// DD = device.deny, OVR = `Device.override_profile_deny`). PA is shown
/// for completeness but is **not** an `apply_overlay` input: it never
/// changes a Result versus its PA=– twin — the FallThrough rows delegate
/// profile-allow to the caller's `filter.evaluate` — so the field was
/// dropped from [`LayerHits`].
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
/// advanced rules in one pass.
/// This keeps the byte-identical baseline for empty overlays trivial:
/// when both DA/DD are false the function always returns `FallThrough`,
/// regardless of PA/PD — same code path as a device with no overlay.
///
/// **Why row 6 defensively chooses Profile-wins on drift:** the CLI /
/// TUI refuses the `device.allow X + profile.deny X + override=false`
/// combination at edit time, so the daemon should never see this row
/// on a fresh config. If the operator hand-edits the master TOML to
/// produce drift, the safer fallback is "profile-wins" (the default
/// profile must be restrictive) rather than letting the per-device
/// allow silently punch through a profile-level block.
///
/// This function performs ZERO HashSet probes — the caller has already
/// done them. Compiles to a small chain of `if` statements; no
/// allocations.
pub fn apply_overlay(hits: LayerHits, override_profile_deny: bool) -> OverlayDecision {
    // profile-allow is not an input. Truth-table rows 0/1/2 — any case
    // with no device-side hit — return `FallThrough` regardless of
    // profile-allow, and the caller then runs `filter.evaluate`, which
    // re-derives profile-allow itself.
    let LayerHits {
        profile_deny_hit,
        device_allow_hit,
        device_deny_hit,
    } = hits;

    // Row 7 / 6: device.allow + profile.deny — the OVERRIDE branch.
    // Probed FIRST among device-touching rows because this is the
    // operator's most ergonomically important case (the TUI scope-menu
    // surfaces it explicitly). The override flag decides ALLOW vs
    // defensive DENY.
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

/// One spelling per address. `::ffff:10.0.0.5` and `10.0.0.5` are the same
/// host, so every index and every compare here has to agree on which of the
/// two it means.
///
/// A dual-stack listener (`listen = "[::]:53"`) hands every IPv4 peer as
/// `::ffff:a.b.c.d` while the operator pins `10.0.0.5`; without this the
/// device is unreachable, and `Cidr::contains` being family-strict makes the
/// subnet level miss too.
///
/// Only the IPv4-*mapped* prefix folds. The deprecated IPv4-*compatible*
/// `::a.b.c.d` is a different address and `to_ipv4` would wrongly fold it.
///
/// Branch-only, `Copy` in and out: this runs per DNS query.
#[inline]
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn build_arp_snapshot() -> HashMap<IpAddr, CompactString> {
    // Invariant: ARP MACs are stored upper-case. `read_arp_by_ip`
    // folds case at the `/proc/net/arp` boundary (arp.rs), matching the
    // upper-cased `mac_pin` / `mac_aliases` the resolver compares against.
    // Every later consumer — `resolve`'s MAC compare and `snapshots_from`'s
    // `ips_by_mac` probe — relies on both sides already being upper-case.
    //
    // Keyed by IP directly: a MAC-keyed read + inversion would silently
    // drop all-but-one IP for a multi-IP MAC, nondeterministically per
    // refresh. `/proc/net/arp` is per-IP, so the IP-keyed read is
    // lossless and needs no inversion.
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
            // `ResolverMap.device_groups`, a different structure. This
            // matters because the TUI round-trips this list: consumers
            // write it back, so its order must be the operator's file
            // order.
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
        // Same normalisation `resolve` applies to the query source, or a pin
        // written in mapped form is shown the global default while the
        // resolver actually hands that device the subnet's profile.
        let ip = canonical_ip(ip);
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
mod tests;
