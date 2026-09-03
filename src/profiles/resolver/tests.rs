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

// ── IPv4-mapped source normalisation ──

#[test]
fn device_pinned_ipv4_resolves_from_mapped_source() {
    // A dual-stack listener hands every IPv4 peer as `::ffff:a.b.c.d`
    // while the operator pinned `192.168.1.42`.
    let cfg = base_config();
    let resolver = ProfileResolver::build(
        &cfg,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    );

    let r = resolver.resolve(&"::ffff:192.168.1.42".parse().unwrap());
    assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
    assert_eq!(r.profile.unwrap().name.as_str(), "default");
}

#[test]
fn device_pinned_in_mapped_form_resolves_from_bare_source() {
    // Mirror case: the pin itself carries the mapped spelling.
    let mut cfg = base_config();
    cfg.devices[0].ip = Some("::ffff:192.168.1.42".parse().unwrap());

    let resolver = ProfileResolver::build(
        &cfg,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    );

    let r = resolver.resolve(&"192.168.1.42".parse().unwrap());
    assert_eq!(r.level, Some(ResolveLevel::DeviceDirect));
    assert_eq!(r.profile.unwrap().name.as_str(), "default");
}

#[test]
fn mapped_source_does_not_bypass_mac_enforcement() {
    // Trip-wire against a half-normalisation. Canonicalise only the
    // `devices_by_ip` probe and the device is found, the IPv4-keyed ARP
    // snapshot is missed, and the forgiving "no ARP entry" arm hands over
    // the device profile with the MAC never compared. A mismatch must
    // demote to subnet for a mapped source exactly as for a bare one.
    let mut cfg = base_config();
    cfg.devices[0].mac = Some("AA:BB:CC:DD:EE:01".into());
    cfg.server.enforce_device_mac = true;

    let resolver = ProfileResolver::build(
        &cfg,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    );
    // `/proc/net/arp` is IPv4-keyed, so a mapped spelling never appears.
    resolver.test_only_set_arp_snapshot(&[("192.168.1.42".parse().unwrap(), "AA:BB:CC:DD:EE:99")]);

    let r = resolver.resolve(&"::ffff:192.168.1.42".parse().unwrap());
    assert_eq!(r.level, Some(ResolveLevel::Subnet));
    assert_eq!(r.profile.unwrap().name.as_str(), "kids");
}

#[test]
fn ipv4_compatible_source_is_not_folded_like_a_mapped_one() {
    // `::192.168.1.42` is the deprecated IPv4-*compatible* form and is a
    // different address from `192.168.1.42`; only the IPv4-*mapped*
    // `::ffff:` form names the same host. `to_ipv4` folds both and would
    // hand this source the laptop's profile.
    let cfg = base_config();
    let resolver = ProfileResolver::build(
        &cfg,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    );

    let r = resolver.resolve(&"::192.168.1.42".parse().unwrap());
    assert_eq!(
        r.level, None,
        "an IPv4-compatible source must not match an IPv4 pin"
    );
}

#[test]
fn device_name_resolves_from_mapped_source() {
    // Query-log attribution probes `devices_by_ip` directly, above the
    // resolution chain, so it needs the same normalisation.
    let cfg = base_config();
    let resolver = ProfileResolver::build(
        &cfg,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    );

    assert_eq!(
        resolver
            .device_name(&"::ffff:192.168.1.42".parse().unwrap())
            .as_deref(),
        Some("Laptop")
    );
}

#[test]
fn mapped_pin_reports_its_subnet_profile_in_ipc_snapshot() {
    // The snapshot's level-4 walk compares the *configured* pin against
    // the subnet CIDRs, and `Cidr::contains` is family-strict — a pin in
    // `::ffff:` form reported the global default while `resolve()` hands
    // that device the subnet's profile.
    let mut cfg = base_config();
    cfg.server.default_profile = Some(mk_id("default"));
    cfg.devices.push(Device {
        id: mk_id("bulb"),
        display_name: "IoT Bulb".into(),
        ip: Some("::ffff:192.168.1.77".parse().unwrap()),
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

    let r = resolver.resolve(&"192.168.1.77".parse().unwrap());
    assert_eq!(r.level, Some(ResolveLevel::Subnet));
    assert_eq!(r.profile.unwrap().name.as_str(), "kids");

    let snapshots = resolver.list_mapped_devices();
    let bulb = snapshots
        .iter()
        .find(|s| s.dto.name == "IoT Bulb")
        .expect("bulb device should be in snapshot");
    assert_eq!(
        bulb.dto.profile, "kids",
        "a mapped-form pin must report the same profile resolve() gives it"
    );
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
    // bypassable (CLAUDE.md key rule #9). It falls through to
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
