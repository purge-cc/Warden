//! `s-review-2605-profiles-m3`: per-device profile specialisation must
//! **share** the profile-static rule sets, not deep-copy them.
//!
//! **What is measured.** `ResolvedProfile::specialise_with_effective_tags`
//! is called once per device / group / subnet / schedule by
//! `build_resolver_map`. Only `effective_tags` and the recomputed
//! `list_bitmask` actually vary per resolution; `allow_domains`,
//! `deny_domains` and `rules` are profile-static. If those three are
//! plain `HashSet` / `Vec` fields they are deep-copied on every
//! specialisation, and — because each specialised profile is stored in
//! the `ResolverMap` behind an `Arc` and read by the DNS hot path —
//! those copies stay **resident for the lifetime of the config
//! generation**. That is the cost this test pins.
//!
//! **Why an allocator, not a timer.** Specialisation is cold (reload
//! only), so wall-clock is the wrong instrument — the defect is
//! steady-state resident memory. This binary installs its own counting
//! `#[global_allocator]` (an integration test is a separate crate, so
//! this does not disturb the daemon's jemalloc) and measures *net live*
//! bytes — allocations minus deallocations — across a real
//! `ProfileResolver::build`. Net live, not gross allocated: the claim is
//! about memory that stays resident, and gross would also count
//! transient churn during the build and overstate the win.
//!
//! **Why the threshold needs no magic constant.** The budget is derived
//! at runtime from the base profile's own `.len()` accessors — a
//! conservative *lower bound* on the cost of a single deep copy of the
//! three fields. It under-counts (it ignores hash-table load factor and
//! any heap owned inside a `DnsRule`), which is exactly the safe
//! direction for a threshold. `.len()` reads identically through `Arc`
//! deref, so this file compiles and means the same thing before and
//! after the fix.
//!
//! **Single test fn by construction.** The counter is process-global and
//! `#[test]` fns run on parallel threads, so a sibling test in this file
//! would pollute the measurement. Keep this file at one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicIsize, Ordering};

use purge_warden::config::schema::id::Id;
use purge_warden::config::schema::{
    AdminRule, Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, ConfigV1, Device,
    Profile, ServerGlobals,
};
use purge_warden::filter::rules::DnsRule;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::profile::ResolvedProfile;
use purge_warden::profiles::resolver::ProfileResolver;

// ── counting allocator ────────────────────────────────────────────────

static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let np = System.realloc(p, l, new_size);
        if !np.is_null() {
            LIVE.fetch_add(new_size as isize - l.size() as isize, Ordering::Relaxed);
        }
        np
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Resident set size in bytes, read from `/proc/self/statm` field 2
/// (resident pages). The operator-facing number: this is what `ps` and
/// systemd's `MemoryCurrent` report.
fn rss_bytes() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = s
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

// ── synthetic config ──────────────────────────────────────────────────

/// Devices in the measured config. The backlog entry cites N≈1000; a
/// household install is far smaller, so the per-device unit cost printed
/// below is the number to reason from — it scales linearly.
const DEVICES: usize = 1_000;

/// Exact-allow admin rules → `allow_domains`.
const ALLOW_RULES: usize = 120;
/// Exact-deny admin rules → `deny_domains`.
const DENY_RULES: usize = 120;
/// Wildcard admin rules → `rules` (the Tier 2 advanced vector).
const WILDCARD_RULES: usize = 40;

/// Domain shapes chosen to span `CompactString`'s 24-byte inline
/// threshold in both directions, because that threshold decides whether
/// a domain costs a heap allocation on top of its 24-byte slot. Lengths
/// are reported in the output rather than tuned to flatter the result.
fn allow_domain(i: usize) -> String {
    // ~22 bytes — inline in CompactString.
    format!("a{i:03}.example.com")
}

fn deny_domain(i: usize) -> String {
    // ~38 bytes — exceeds the inline threshold, so it also heap-allocates.
    format!("tracker-{i:03}.metrics.example.net")
}

fn build_config() -> (ConfigV1, SourceBitMap, Vec<AdminRule>) {
    let mut admin_rules = Vec::new();
    for i in 0..ALLOW_RULES {
        admin_rules.push(AdminRule {
            id: Id::new(format!("allow-{i:03}")).unwrap(),
            rule: format!("@@||{}^", allow_domain(i)),
        });
    }
    for i in 0..DENY_RULES {
        admin_rules.push(AdminRule {
            id: Id::new(format!("deny-{i:03}")).unwrap(),
            rule: format!("||{}^", deny_domain(i)),
        });
    }
    for i in 0..WILDCARD_RULES {
        admin_rules.push(AdminRule {
            id: Id::new(format!("wild-{i:03}")).unwrap(),
            rule: format!("||*.ads{i:03}.example.org^"),
        });
    }

    let blocklists = vec![Blocklist {
        id: Id::new("ads").unwrap(),
        display_name: "ads".into(),
        url: "https://lists.purge.cc/ads.txt".into(),
        format: BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: 5_000_000,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }];

    let bit_map = SourceBitMap::build(
        &blocklists
            .iter()
            .map(|b| b.id.to_string())
            .collect::<Vec<_>>(),
        &blocklists,
    )
    .expect("bit map builds");

    let profile = Profile {
        display_name: "default".into(),
        admin_rules: admin_rules.iter().map(|r| r.id.clone()).collect(),
        ..Default::default()
    };

    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), profile);

    // Every device carries a direct profile assignment, so each one
    // takes the level-1 device branch in `build_resolver_map` — one
    // specialisation per device.
    let devices: Vec<Device> = (0..DEVICES)
        .map(|i| Device {
            id: Id::new(format!("dev-{i:04}")).unwrap(),
            display_name: format!("device {i}"),
            ip: None,
            mac: None,
            mac_aliases: Vec::new(),
            profile: Some(Id::new("default").unwrap()),
            groups: Vec::new(),
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        })
        .collect();

    let config = ConfigV1 {
        schema_version: 1,
        blocklists: blocklists.clone(),
        profiles,
        devices,
        admin_rules: admin_rules.clone(),
        ..Default::default()
    };

    (config, bit_map, admin_rules)
}

#[test]
fn specialisation_shares_profile_static_rule_sets() {
    let (config, bit_map, admin_rules) = build_config();

    // ── calibration: build the profile-level base once and read its
    // shape through `.len()` (identical through `Arc` deref) ──────────
    let by_id: BTreeMap<&Id, &AdminRule> = admin_rules.iter().map(|r| (&r.id, r)).collect();
    let base = ResolvedProfile::build_v1(
        &Id::new("default").unwrap(),
        config.profiles.get("default").unwrap(),
        &by_id,
        &purge_warden::config::custom_list::CustomListStore::new(),
        &ServerGlobals::default(),
        60,
    );

    let allow_len = base.allow_domains.len();
    let deny_len = base.deny_domains.len();
    let rules_len = base.rules.len();

    // Conservative lower bound on ONE deep copy of the three fields:
    // the slot arrays only. Ignores hash-table load factor (~1/0.875),
    // the heap tail of every domain longer than CompactString's inline
    // threshold, and any heap owned inside a DnsRule — so the real
    // deep-copy cost is strictly larger than this.
    let one_copy_floor: usize = (allow_len + deny_len) * size_of::<compact_str::CompactString>()
        + rules_len * size_of::<DnsRule>();

    drop(base);

    // ── measurement ──────────────────────────────────────────────────
    let live_before = live();
    let rss_before = rss_bytes();

    let resolver = ProfileResolver::build(
        &config,
        &bit_map,
        &purge_warden::config::custom_list::CustomListStore::new(),
    );

    let live_after = live();
    let rss_after = rss_bytes();

    let resident = (live_after - live_before).max(0) as usize;
    let per_device = resident / DEVICES;

    println!("\n=== profiles-m3: resolver-map resident cost ===");
    println!("devices (1 specialisation each) : {DEVICES}");
    println!("allow_domains (~22B, inline)    : {allow_len}");
    println!("deny_domains                    : {deny_len} (exact + wildcard-apex expansion)");
    println!("rules (Tier 2 advanced)         : {rules_len}");
    println!(
        "size_of::<CompactString>()      : {}",
        size_of::<compact_str::CompactString>()
    );
    println!("size_of::<DnsRule>()            : {}", size_of::<DnsRule>());
    println!("---");
    println!(
        "net-live bytes for whole map    : {resident} ({:.2} MB)",
        resident as f64 / 1_048_576.0
    );
    println!("  → per specialised profile     : {per_device} B");
    println!(
        "RSS delta                       : {} B ({:.2} MB)",
        rss_after.saturating_sub(rss_before),
        rss_after.saturating_sub(rss_before) as f64 / 1_048_576.0
    );
    println!("---");
    println!("one deep copy, LOWER bound      : {one_copy_floor} B");
    println!("budget (floor / 2)              : {} B", one_copy_floor / 2);
    println!("===============================================\n");

    // Keep the map alive across the measurement so nothing is freed
    // before `live_after` is read.
    drop(resolver);

    assert!(
        allow_len > 0 && deny_len > 0 && rules_len > 0,
        "calibration is meaningless if the base profile is empty: \
         allow={allow_len} deny={deny_len} rules={rules_len}"
    );

    assert!(
        per_device < one_copy_floor / 2,
        "each specialised profile costs {per_device} B of resident memory, which is not \
         materially below the {} B lower bound on a single deep copy of allow_domains + \
         deny_domains + rules. The profile-static rule sets are being copied per device \
         instead of shared.",
        one_copy_floor
    );
}
