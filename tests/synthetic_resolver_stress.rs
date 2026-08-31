//! Synthetic 100-device stress test for the v1 resolver (S34 step 7).
//!
//! Builds a fixture with 100 devices, 5 groups, 3 overlapping subnets,
//! 10 schedules, and 50 blocklists. Loads it via the production v1
//! loader + validator + [`ProfileResolver`]. Cross-checks 10 000 random
//! IP resolutions against an independent reference implementation of
//! the 5-level chain from `_docs/features/config_architecture.md` §9.
//!
//! This test does not exercise level 2 (schedules): active-window
//! resolution is time-dependent and has its own unit coverage. What we
//! care about here is that a large, cross-entity configuration with
//! overlapping subnets survives the loader + builder + hot-path without
//! drift.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use purge_warden::config::loader::load_config;
use purge_warden::config::schema::{
    AdminRule, Blocklist, BlocklistFormat, ConfigV1, Device, Group, Id, Profile, Schedule,
    ScheduleTargetType, Subnet,
};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use time::OffsetDateTime;

// ── fixture construction ──────────────────────────────────────────────

const DEVICE_COUNT: usize = 100;
const GROUP_COUNT: usize = 5;
const SUBNET_COUNT: usize = 3;
const SCHEDULE_COUNT: usize = 10;
const BLOCKLIST_COUNT: usize = 50;

const RANDOM_IP_SAMPLES: usize = 10_000;

const PROFILE_DEFAULT: &str = "default";
const PROFILE_KIDS: &str = "kids";
const PROFILE_GUEST: &str = "guest";

/// Build the 100-device synthetic config as an in-memory `ConfigV1`.
fn build_synthetic_config() -> ConfigV1 {
    let mut config = ConfigV1 {
        schema_version: 3,
        ..Default::default()
    };

    // allow_from so the validator doesn't reject the 0.0.0.0 listen.
    config.server.allow_from = vec!["10.0.0.0/8".to_string(), "127.0.0.0/8".to_string()];
    // neutrality-10: `upstream.servers` has no default any more — warden
    // names no resolver for the operator — so a fixture that must lint clean
    // has to name one itself. RFC 5737 TEST-NET-1: documentation-only,
    // unroutable, names nobody. (`ConfigV1::test_scaffold()` is `#[cfg(test)]`
    // on the lib and so is invisible from an integration test.)
    config.upstream.servers = vec!["192.0.2.1:53".to_string()];
    config.server.default_profile = Some(new_id(PROFILE_DEFAULT));
    // §4.39 / profiles-h1: all 100 synthetic devices are pin-less
    // (mac: None). This test exercises the device/group/subnet/default
    // resolution cascade, not MAC enforcement — keep `enforce_device_mac`
    // off so pin-less devices resolve device-direct and the real
    // resolver still matches `reference_resolve` (which models the
    // cascade, not the ARP-pin guard).
    config.server.enforce_device_mac = false;

    // Legacy `[lists].sources` is derived post-load from blocklists in the
    // migration tool; in tests we populate it directly so the downloader's
    // kebab→slash shim has something to match.
    for i in 0..BLOCKLIST_COUNT {
        let id = new_id(&format!("list-{i:02}"));
        let scope = if i % 2 == 0 { "privacy" } else { "security" };
        let slug = format!("auto-{i:02}");
        config.blocklists.push(Blocklist {
            id,
            display_name: format!("Synthetic {scope}/{slug}"),
            url: format!("https://lists.purge.cc/{scope}/{slug}.txt"),
            format: if i % 5 == 0 {
                BlocklistFormat::Adguard
            } else {
                BlocklistFormat::Domains
            },
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: None,
            base: Default::default(),
            trust: Default::default(),
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        });
        config.lists.sources.push(format!("{scope}/{slug}"));
    }

    // Three profiles covering the resolver's worldview.
    config.profiles.insert(
        PROFILE_DEFAULT.to_string(),
        profile_default(&config.blocklists),
    );
    config
        .profiles
        .insert(PROFILE_KIDS.to_string(), profile_kids(&config.blocklists));
    config
        .profiles
        .insert(PROFILE_GUEST.to_string(), profile_guest(&config.blocklists));

    // 100 devices: IPs in 10.100.0.<n> with n = 1..=100, rotating
    // between the three profiles plus a small "no direct profile" slice
    // that forces group/subnet/default resolution.
    for i in 0..DEVICE_COUNT {
        let ip = Ipv4Addr::new(10, 100, 0, (i + 1) as u8);
        let direct_profile = match i % 5 {
            0 => Some(new_id(PROFILE_KIDS)),
            1 => Some(new_id(PROFILE_GUEST)),
            2 => Some(new_id(PROFILE_DEFAULT)),
            // 3 and 4 leave the device with no direct profile so the
            // resolver has to fall through to group / subnet / default.
            _ => None,
        };
        config.devices.push(Device {
            id: new_id(&format!("dev-{i:03}")),
            display_name: format!("Synthetic Device {i:03}"),
            ip: Some(IpAddr::V4(ip)),
            mac: None,
            mac_aliases: Vec::new(),
            profile: direct_profile,
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
        });
    }

    // 5 groups. Each group has 10-20 members (total membership ~70).
    // Every group points at the `default` profile so group resolution
    // (level 3) is deterministic and easy to cross-check.
    for g in 0..GROUP_COUNT {
        let start = g * 15; // 0, 15, 30, 45, 60
        let len = 10 + g; // 10, 11, 12, 13, 14
        let devices: Vec<Id> = (start..start + len)
            .filter(|i| *i < DEVICE_COUNT)
            .map(|i| new_id(&format!("dev-{i:03}")))
            .collect();
        let profile = if g % 2 == 0 {
            PROFILE_DEFAULT
        } else {
            PROFILE_KIDS
        };
        config.groups.push(Group {
            id: new_id(&format!("grp-{g:02}")),
            display_name: format!("Synthetic Group {g:02}"),
            profile: new_id(profile),
            priority: g as i32, // distinct priorities so no tie
            devices: devices.clone(),
        });

        // Wire the group back onto each device's `groups` list so
        // the validator sees a symmetric reference.
        for id in &devices {
            if let Some(dev) = config.devices.iter_mut().find(|d| d.id == *id) {
                dev.groups.push(new_id(&format!("grp-{g:02}")));
            }
        }
    }

    // 3 overlapping subnets, longest-prefix-match order.
    // /8  — 10.0.0.0/8    → default
    // /16 — 10.100.0.0/16 → guest
    // /24 — 10.100.0.0/24 → kids
    // An IP in 10.100.0.X should land on "kids" (longest prefix).
    // An IP in 10.100.1.X should land on "guest" (16 wins over 8).
    // An IP in 10.99.0.X  should land on "default" (only /8 matches).
    config.subnets.push(Subnet {
        id: new_id("net-broad"),
        display_name: "broad /8".into(),
        cidrs: vec!["10.0.0.0/8".into()],
        profile: new_id(PROFILE_DEFAULT),
        priority: 0,
    });
    config.subnets.push(Subnet {
        id: new_id("net-middle"),
        display_name: "middle /16".into(),
        cidrs: vec!["10.100.0.0/16".into()],
        profile: new_id(PROFILE_GUEST),
        priority: 0,
    });
    config.subnets.push(Subnet {
        id: new_id("net-narrow"),
        display_name: "narrow /24".into(),
        cidrs: vec!["10.100.0.0/24".into()],
        profile: new_id(PROFILE_KIDS),
        priority: 0,
    });

    assert_eq!(
        SUBNET_COUNT, 3,
        "keep SUBNET_COUNT in sync with the hand-written subnets above"
    );

    // 10 schedules. We don't assert on schedule activation — we just
    // want the loader + resolver to tolerate a non-trivial schedule set.
    // Each schedule targets a device in the middle of the /24 so its
    // active-window resolution (level 2) would cover that device only.
    for s in 0..SCHEDULE_COUNT {
        let target_dev = format!("dev-{:03}", 50 + s);
        config.schedules.push(Schedule {
            id: new_id(&format!("sch-{s:02}")),
            display_name: format!("Synthetic schedule {s:02}"),
            target_type: ScheduleTargetType::Device,
            target_id: new_id(&target_dev),
            profile: new_id(PROFILE_KIDS),
            days: vec!["all".into()],
            // Use an hours range whose midnight-wrap passes through "now"
            // _occasionally_ — we don't assert, but this exercises the
            // active-window math.
            hours: format!("{:02}:00-{:02}:00", s, (s + 2) % 24),
            expires_at: None,
        });
    }

    // A couple of admin rules the default profile references. Not
    // cross-referenced from the resolver test, but required for a
    // realistic fixture that exercises the full validator.
    config.admin_rules.push(AdminRule {
        id: new_id("admin-allow-github"),
        rule: "@@||github.com^".into(),
    });
    config.admin_rules.push(AdminRule {
        id: new_id("admin-deny-tiktok"),
        rule: "||tiktok.com^".into(),
    });

    config
}

fn profile_default(_blocklists: &[Blocklist]) -> Profile {
    // Sprint A of `lists_categories_v2` (D1, D5): Profile.blocklists +
    // Profile.categories are gone. Sprint B reintroduces equivalent
    // via tag intersection on profile.tags.
    Profile {
        display_name: "Synthetic default".into(),
        block_response: None,
        blocked_ttl_secs: None,
        admin_rules: vec![new_id("admin-allow-github"), new_id("admin-deny-tiktok")],
        block_all: false,
        local_records: Vec::new(),
        ecs: None,
        rewrite_rules: Vec::new(),
        safe_search: false,
        custom_lists: Vec::new(),
        lists: std::collections::BTreeMap::new(),
    }
}

fn profile_kids(_blocklists: &[Blocklist]) -> Profile {
    Profile {
        display_name: "Synthetic kids".into(),
        block_response: None,
        blocked_ttl_secs: None,
        admin_rules: Vec::new(),
        block_all: false,
        local_records: Vec::new(),
        ecs: None,
        rewrite_rules: Vec::new(),
        safe_search: false,
        custom_lists: Vec::new(),
        lists: std::collections::BTreeMap::new(),
    }
}

fn profile_guest(_blocklists: &[Blocklist]) -> Profile {
    Profile {
        display_name: "Synthetic guest".into(),
        block_response: None,
        blocked_ttl_secs: None,
        admin_rules: Vec::new(),
        block_all: false,
        local_records: Vec::new(),
        ecs: None,
        rewrite_rules: Vec::new(),
        safe_search: false,
        custom_lists: Vec::new(),
        lists: std::collections::BTreeMap::new(),
    }
}

fn new_id(s: &str) -> Id {
    Id::new(s.to_string()).unwrap_or_else(|_| panic!("invalid synthetic id: {s:?}"))
}

/// Write the synthetic config to a multi-file `.d/` tree on disk, mirroring
/// what `warden migrate v0-to-v1` would produce. Returns the master path.
fn write_fixture_tree(dir: &Path, config: &ConfigV1) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();

    // Master: clear entity collections, keep everything else.
    let mut master = config.clone();
    master.includes = vec![
        "devices.d/*.toml".into(),
        "profiles.d/*.toml".into(),
        "groups.d/*.toml".into(),
        "blocklists.d/*.toml".into(),
        "subnets.d/*.toml".into(),
        "schedules.d/*.toml".into(),
        "rules.d/*.toml".into(),
    ];
    master.devices.clear();
    master.groups.clear();
    master.subnets.clear();
    master.schedules.clear();
    master.blocklists.clear();
    master.admin_rules.clear();
    master.profiles.clear();
    let master_path = dir.join("config.toml");
    std::fs::write(&master_path, toml::to_string_pretty(&master).unwrap()).unwrap();

    write_array(dir, "devices.d", "devices", &config.devices);
    write_array(dir, "groups.d", "groups", &config.groups);
    write_array(dir, "subnets.d", "subnets", &config.subnets);
    write_array(dir, "blocklists.d", "blocklists", &config.blocklists);
    write_array(dir, "schedules.d", "schedules", &config.schedules);
    write_array(dir, "rules.d", "admin_rules", &config.admin_rules);

    let profiles_dir = dir.join("profiles.d");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    for (name, prof) in &config.profiles {
        let mut outer = toml::value::Table::new();
        let mut profiles = toml::value::Table::new();
        profiles.insert(name.clone(), toml::Value::try_from(prof).unwrap());
        outer.insert("profiles".to_string(), toml::Value::Table(profiles));
        std::fs::write(
            profiles_dir.join(format!("{name}.toml")),
            toml::to_string_pretty(&toml::Value::Table(outer)).unwrap(),
        )
        .unwrap();
    }

    master_path
}

fn write_array<T: serde::Serialize>(dir: &Path, subdir: &str, key: &str, items: &[T]) {
    if items.is_empty() {
        return;
    }
    let d = dir.join(subdir);
    std::fs::create_dir_all(&d).unwrap();
    let arr: Vec<toml::Value> = items
        .iter()
        .map(|i| toml::Value::try_from(i).unwrap())
        .collect();
    let mut root = toml::value::Table::new();
    root.insert(key.to_string(), toml::Value::Array(arr));
    std::fs::write(
        d.join("auto-migrated.toml"),
        toml::to_string_pretty(&toml::Value::Table(root)).unwrap(),
    )
    .unwrap();
}

// ── reference resolver ────────────────────────────────────────────────

/// Mirrors §9 levels 1, 3, 4, 5 for cross-checking the production resolver.
///
/// Level 2 (schedule) is skipped: it is time-dependent and covered by
/// dedicated unit tests. This reference looks at `ip → device →
/// (direct profile | group priority | subnet longest-prefix | default)`.
fn reference_resolve(config: &ConfigV1, ip: &IpAddr) -> Option<String> {
    // Level 1 / 3: any device that pins this IP.
    if let Some(dev) = config.devices.iter().find(|d| d.ip == Some(*ip)) {
        if let Some(p) = &dev.profile {
            return Some(p.as_str().to_string());
        }
        // Level 3 — group membership, highest priority wins, ties already
        // rejected by the validator (so we can assume all priorities on
        // this device are distinct).
        let mut candidates: Vec<(i32, &Id)> = config
            .groups
            .iter()
            .filter(|g| g.devices.contains(&dev.id))
            .map(|g| (g.priority, &g.profile))
            .collect();
        candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
        if let Some((_, pid)) = candidates.first() {
            return Some(pid.as_str().to_string());
        }
    }

    // Level 4 — longest-prefix subnet match.
    let mut best: Option<(u8, &Id)> = None;
    for subnet in &config.subnets {
        for cidr in &subnet.cidrs {
            if let Some(prefix) = cidr_contains(cidr, ip) {
                let better = best.map(|(p, _)| prefix > p).unwrap_or(true);
                if better {
                    best = Some((prefix, &subnet.profile));
                }
            }
        }
    }
    if let Some((_, pid)) = best {
        return Some(pid.as_str().to_string());
    }

    // Level 5 — global default, may be None (REFUSED).
    config
        .server
        .default_profile
        .as_ref()
        .map(|p| p.as_str().to_string())
}

/// If `cidr` contains `ip`, return its prefix length; otherwise `None`.
fn cidr_contains(cidr: &str, ip: &IpAddr) -> Option<u8> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;
    let cidr_ip: IpAddr = addr_str.parse().ok()?;
    match (cidr_ip, ip) {
        (IpAddr::V4(c), IpAddr::V4(q)) if prefix <= 32 => {
            let c_bits = u32::from(c);
            let q_bits = u32::from(*q);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            if c_bits & mask == q_bits & mask {
                Some(prefix)
            } else {
                None
            }
        }
        (IpAddr::V6(c), IpAddr::V6(q)) if prefix <= 128 => {
            let c_bits = u128::from(c);
            let q_bits = u128::from(*q);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            if c_bits & mask == q_bits & mask {
                Some(prefix)
            } else {
                None
            }
        }
        _ => None,
    }
}

// Deterministic LCG so the 10k IPs are reproducible across runs.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
}

fn random_ip(rng: &mut Lcg) -> IpAddr {
    // Mix IPs drawn from four regions: inside the /24, inside the /16 but
    // outside the /24, inside the /8 but outside the /16, and outside the
    // /8 entirely. Four-way distribution forces each resolver level to
    // fire.
    let bucket = rng.next() % 4;
    let octet = rng.next() as u8;
    let random_lower = (rng.next() & 0xFFFF) as u16;
    let a = match bucket {
        0 => Ipv4Addr::new(10, 100, 0, octet),
        1 => Ipv4Addr::new(10, 100, (random_lower >> 8) as u8 | 1, octet),
        2 => Ipv4Addr::new(10, (random_lower >> 8) as u8 | 101, octet, octet),
        _ => Ipv4Addr::new(
            172 + (random_lower & 15) as u8,
            octet,
            octet,
            (random_lower >> 8) as u8,
        ),
    };
    IpAddr::V4(a)
}

// ── tests ─────────────────────────────────────────────────────────────

#[test]
fn synthetic_fixture_loads_and_lints() {
    let tmp = tempfile::tempdir().unwrap();
    let config = build_synthetic_config();
    let master = write_fixture_tree(tmp.path(), &config);
    let loaded = load_config(&master, OffsetDateTime::now_utc())
        .expect("synthetic fixture should lint clean");
    assert_eq!(loaded.config.devices.len(), DEVICE_COUNT);
    assert_eq!(loaded.config.groups.len(), GROUP_COUNT);
    assert_eq!(loaded.config.subnets.len(), SUBNET_COUNT);
    assert_eq!(loaded.config.schedules.len(), SCHEDULE_COUNT);
    assert_eq!(loaded.config.blocklists.len(), BLOCKLIST_COUNT);
    // Three profiles
    assert_eq!(loaded.config.profiles.len(), 3);
}

#[test]
fn synthetic_resolver_matches_reference_on_handful_of_ips() {
    let tmp = tempfile::tempdir().unwrap();
    let config = build_synthetic_config();
    let master = write_fixture_tree(tmp.path(), &config);
    let loaded = load_config(&master, OffsetDateTime::now_utc()).unwrap();

    let resolver = ProfileResolver::build(
        &loaded.config,
        &SourceBitMap::default(),
        &loaded.custom_lists,
    );

    // Device with direct profile (i = 0 → profile kids via rotation)
    let ip0 = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
    let exp0 = reference_resolve(&loaded.config, &ip0);
    let got0 = resolver.resolve(&ip0);
    assert_eq!(
        got0.profile.as_ref().map(|p| p.name.to_string()),
        exp0,
        "device-direct resolution must match reference for {ip0:?}"
    );

    // IP in /24 but not a device pin → level 4, profile kids (longest
    // prefix).
    let ip_sub = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 254));
    let got_sub = resolver.resolve(&ip_sub);
    assert_eq!(
        got_sub.profile.as_ref().map(|p| p.name.to_string()),
        Some(PROFILE_KIDS.to_string()),
        "unmapped IP in 10.100.0.0/24 must land on kids (longest prefix)"
    );

    // IP in /16 but outside /24 → level 4, profile guest.
    let ip_middle = IpAddr::V4(Ipv4Addr::new(10, 100, 5, 7));
    let got_middle = resolver.resolve(&ip_middle);
    assert_eq!(
        got_middle.profile.as_ref().map(|p| p.name.to_string()),
        Some(PROFILE_GUEST.to_string()),
        "unmapped IP in 10.100/16 must land on guest (middle prefix)"
    );

    // IP outside /16 but inside /8 → level 4, profile default.
    let ip_broad = IpAddr::V4(Ipv4Addr::new(10, 55, 3, 9));
    let got_broad = resolver.resolve(&ip_broad);
    assert_eq!(
        got_broad.profile.as_ref().map(|p| p.name.to_string()),
        Some(PROFILE_DEFAULT.to_string()),
        "unmapped IP in 10/8 must land on default (broadest prefix)"
    );

    // IP outside every subnet → level 5, server.default_profile = default.
    let ip_default = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5));
    let got_default = resolver.resolve(&ip_default);
    assert_eq!(
        got_default.profile.as_ref().map(|p| p.name.to_string()),
        Some(PROFILE_DEFAULT.to_string()),
        "IP outside all subnets must land on server.default_profile"
    );
}

#[test]
fn synthetic_resolver_matches_reference_on_10k_random_ips() {
    let tmp = tempfile::tempdir().unwrap();
    let config = build_synthetic_config();
    let master = write_fixture_tree(tmp.path(), &config);
    let loaded = load_config(&master, OffsetDateTime::now_utc()).unwrap();

    let resolver = ProfileResolver::build(
        &loaded.config,
        &SourceBitMap::default(),
        &loaded.custom_lists,
    );
    let mut rng = Lcg::new(0xCAFEBABE);
    let mut mismatches = 0usize;
    let mut first_mismatch: Option<(IpAddr, Option<String>, Option<String>)> = None;

    for _ in 0..RANDOM_IP_SAMPLES {
        let ip = random_ip(&mut rng);
        let expected = reference_resolve(&loaded.config, &ip);
        let actual = resolver
            .resolve(&ip)
            .profile
            .as_ref()
            .map(|p| p.name.to_string());

        // Schedule can override at level 2. We don't model schedules in
        // the reference; if the resolver returned a schedule match, skip
        // the compare to avoid a spurious failure. This keeps the test
        // deterministic without depending on the wall-clock.
        let resolved_level = resolver.resolve(&ip).level;
        if matches!(
            resolved_level,
            Some(purge_warden::profiles::ResolveLevel::Schedule)
        ) {
            continue;
        }

        if actual != expected {
            mismatches += 1;
            if first_mismatch.is_none() {
                first_mismatch = Some((ip, expected.clone(), actual.clone()));
            }
        }
    }

    assert_eq!(
        mismatches, 0,
        "resolver diverged from the reference chain on {mismatches}/{RANDOM_IP_SAMPLES} samples (first: {:?})",
        first_mismatch
    );
}
