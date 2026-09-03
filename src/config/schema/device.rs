//! [`Device`] — a single client endpoint in the LAN, identified by IP or
//! one-or-more MAC addresses (primary + aliases for randomising phones).
//!
//! Devices are the leaf entities of the resolver chain: their optional
//! `profile` wins over group / subnet.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::id::Id;

/// ```toml
/// [[devices]]
/// id = "operator-iphone-01"
/// display_name = "iPhone di Operator"
/// ip = "10.10.1.107"
/// mac = "AA:BB:CC:DD:EE:FF"
/// mac_aliases = ["22:33:44:55:66:77"]
/// profile = "default"
/// groups = ["famiglia"]
/// allow_rules = ["operator-allow-bank"]
/// deny_rules = ["operator-deny-tiktok"]
/// override_profile_deny = false
/// ```
///
/// All identity fields (`ip`, `mac`, `mac_aliases`) are optional because a
/// device can legitimately be keyed by any subset of them. The validator
/// enforces that at least one is set, and that MACs are unique across all
/// devices.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: Id,
    pub display_name: String,
    /// Static IP pin. `None` → device is identified only by MAC.
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// Primary MAC. Format validated at load: `XX:XX:XX:XX:XX:XX`.
    #[serde(default)]
    pub mac: Option<String>,
    /// Additional MACs for randomising clients (iOS private-wifi, Android
    /// rotating MAC). Any match identifies this device.
    #[serde(default)]
    pub mac_aliases: Vec<String>,
    /// Direct profile assignment. Wins over groups and subnets. If
    /// `None`, resolution falls through to groups → subnet → default.
    #[serde(default)]
    pub profile: Option<Id>,
    /// Groups this device is a member of. A group can impose its profile
    /// only if the device has no direct [`Self::profile`] and the group's
    /// priority is the highest among memberships.
    #[serde(default)]
    pub groups: Vec<Id>,
    #[serde(default)]
    pub owner: Option<String>,
    /// Free-form device type / category (e.g. `"iPhone personale"`,
    /// `"Smart TV"`, `"Stampante"`). Human-only metadata — never read by
    /// the resolver, stats, or schedules.
    ///
    /// Accepts the legacy field name `device` via serde alias so TOML
    /// files written before the v0.4.3 rename continue to load. Writers
    /// (IPC, CLI, TUI) always emit `device_type` from that version on.
    #[serde(default, alias = "device")]
    pub device_type: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Per-device allow overlay — references to `[[admin_rules]]` ids
    /// whose parsed `||domain^` form the device's allow set. Wired into
    /// the resolver chain as a
    /// [`DeviceOverlay`](crate::profiles::DeviceOverlay) — the hot path
    /// checks the overlay BEFORE the profile's allow/deny tables (two
    /// `HashSet::contains` probes per query).
    ///
    /// Combined cap (allow_rules + deny_rules) is 64 (soft, emits
    /// `LIST_PRUNE_WARN` at validator pass) / 128 (hard, refused).
    #[serde(default)]
    pub allow_rules: Vec<Id>,
    /// Per-device deny overlay. Same shape as [`Self::allow_rules`] —
    /// additive deny over a profile-level allow.
    #[serde(default)]
    pub deny_rules: Vec<Id>,
    /// When `true`, an entry on [`Self::allow_rules`] is allowed to
    /// override a profile-level `||domain^` deny on the same domain.
    /// When `false` (default), the CLI / TUI refuses to add an
    /// `allow_rules` entry that would conflict with an existing
    /// profile-level deny — emitting `RULE_REFUSED_OVERRIDE`. Audited;
    /// surfaced in red on the TUI Resolver tab.
    #[serde(default)]
    pub override_profile_deny: bool,
    /// Explicit opt-out from filtering. When `true`, the filter step is
    /// skipped entirely. DNS resolution, caching, query log, and stats
    /// remain active (the operator monitors IoT traffic without
    /// filtering).
    #[serde(default)]
    pub unfiltered: bool,
    /// Bare DNS name this device answers to. No suffix is enforced —
    /// the operator's chosen name is the exact query name. `None`
    /// (default) means the device has no resolvable name (opt-in).
    /// Validated at load with the same FQDN-label rule as `local_dns`
    /// records (`crate::config::validator::is_valid_fqdn_syntax`).
    /// Resolves dynamically to this device's live IP (config `ip` pin,
    /// else the current ARP-observed address for its MAC) — see
    /// `crate::profiles::resolver::ProfileResolver::resolve_network_name`.
    #[serde(default)]
    pub network_name: Option<String>,
    /// When `true`, every subdomain of `network_name` also resolves to
    /// this device's current IP (reverse-proxy-apex use case). Meaningless,
    /// and rejected by the validator, when `network_name` is `None`.
    #[serde(default)]
    pub network_name_wildcard: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_device_deserialises() {
        let toml_src = r#"
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert_eq!(d.id.as_str(), "iphone");
        assert_eq!(d.ip, Some("10.10.1.107".parse().unwrap()));
        assert!(d.mac.is_none());
        assert!(d.profile.is_none());
        assert!(d.groups.is_empty());
    }

    #[test]
    fn full_device_deserialises() {
        let toml_src = r#"
id = "operator-iphone-01"
display_name = "iPhone di Operator"
ip = "10.10.1.107"
mac = "AA:BB:CC:DD:EE:FF"
mac_aliases = ["22:33:44:55:66:77", "33:44:55:66:77:88"]
profile = "default"
groups = ["famiglia", "iot-lite"]
owner = "Operator"
device_type = "iPhone personale"
department = "famiglia"
notes = "compleanno gennaio"
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert_eq!(d.mac_aliases.len(), 2);
        assert_eq!(d.groups.len(), 2);
        assert_eq!(d.owner.as_deref(), Some("Operator"));
        assert_eq!(d.device_type.as_deref(), Some("iPhone personale"));
        assert_eq!(d.profile.as_ref().unwrap().as_str(), "default");
    }

    #[test]
    fn network_name_defaults_to_none_and_wildcard_to_false() {
        let toml_src = r#"
id = "desktop-1"
display_name = "Desktop-1"
ip = "10.10.1.50"
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert!(d.network_name.is_none());
        assert!(!d.network_name_wildcard);
    }

    #[test]
    fn network_name_and_wildcard_deserialise() {
        let toml_src = r#"
id = "casamia-proxy"
display_name = "Caddy"
ip = "10.10.10.10"
network_name = "casamia"
network_name_wildcard = true
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert_eq!(d.network_name.as_deref(), Some("casamia"));
        assert!(d.network_name_wildcard);
    }

    #[test]
    fn legacy_device_field_alias_accepted() {
        // TOML written before the v0.4.3 rename used `device = "..."`.
        // Serde alias keeps those files loadable — value lands in
        // `device_type` transparently.
        let toml_src = r#"
id = "legacy"
display_name = "legacy"
ip = "10.10.1.1"
device = "iPad personale"
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert_eq!(d.device_type.as_deref(), Some("iPad personale"));
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Device>(
            r#"
id = "iphone"
display_name = "x"
ip = "10.10.1.107"
made_up = 7
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn ipv6_accepted() {
        let d: Device = toml::from_str(
            r#"
id = "ipv6-only"
display_name = "v6"
ip = "fe80::1"
"#,
        )
        .unwrap();
        assert!(d.ip.unwrap().is_ipv6());
    }

    #[test]
    fn invalid_ip_rejected() {
        let err = toml::from_str::<Device>(
            r#"
id = "x"
display_name = "x"
ip = "not-an-ip"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    // ── per-device overlay schema ──────────────────────────────────

    /// Old configs that pre-date the overlay fields must continue to
    /// deserialise. `#[serde(default)]` on every new field —
    /// `allow_rules`, `deny_rules`, `override_profile_deny` — keeps a
    /// v0.4.5 TOML loadable as `Vec::new()` / `false`.
    #[test]
    fn pre_t4_device_loads_with_default_overlay_fields() {
        let toml_src = r#"
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert!(d.allow_rules.is_empty());
        assert!(d.deny_rules.is_empty());
        assert!(!d.override_profile_deny);
    }

    /// All three new fields round-trip when set explicitly.
    #[test]
    fn t4_device_overlay_fields_roundtrip() {
        let toml_src = r#"
id = "operator-iphone"
display_name = "iPhone di Operator"
ip = "10.10.1.107"
allow_rules = ["operator-allow-bank", "operator-allow-airbnb"]
deny_rules = ["operator-deny-tiktok"]
override_profile_deny = true
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        assert_eq!(d.allow_rules.len(), 2);
        assert_eq!(d.allow_rules[0].as_str(), "operator-allow-bank");
        assert_eq!(d.allow_rules[1].as_str(), "operator-allow-airbnb");
        assert_eq!(d.deny_rules.len(), 1);
        assert_eq!(d.deny_rules[0].as_str(), "operator-deny-tiktok");
        assert!(d.override_profile_deny);
    }

    /// Empty arrays + `false` flag are the same shape as the default —
    /// no surprise at the schema level.
    #[test]
    fn t4_overlay_empty_arrays_match_defaults() {
        let toml_src = r#"
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
allow_rules = []
deny_rules = []
override_profile_deny = false
"#;
        let d: Device = toml::from_str(toml_src).unwrap();
        let default_d: Device = toml::from_str(
            r#"
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
"#,
        )
        .unwrap();
        assert_eq!(d.allow_rules, default_d.allow_rules);
        assert_eq!(d.deny_rules, default_d.deny_rules);
        assert_eq!(d.override_profile_deny, default_d.override_profile_deny);
    }

    // ── unfiltered opt-out ──────────────────────────────────────────

    /// `unfiltered` defaults to `false` — every pre-existing device
    /// deserialises unchanged.
    #[test]
    fn lc2_unfiltered_default_false() {
        let d: Device = toml::from_str(
            r#"
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
"#,
        )
        .unwrap();
        assert!(!d.unfiltered);
    }

    #[test]
    fn lc2_unfiltered_true_deserialises() {
        let d: Device = toml::from_str(
            r#"
id = "guest-laptop"
display_name = "Guest laptop"
ip = "10.10.99.5"
unfiltered = true
"#,
        )
        .unwrap();
        assert!(d.unfiltered);
    }
}
