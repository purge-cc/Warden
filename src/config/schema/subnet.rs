//! [`Subnet`] — CIDR-based default profile for unmapped devices (SN1).
//!
//! Per design doc §8.5. Subnet matching uses longest-prefix-match (SN1)
//! so operators can write `10.0.0.0/8 → broad-profile` plus
//! `10.10.5.0/24 → kids-profile`, and hosts in the `/24` get kids-profile
//! regardless of how many looser supersets exist.

use serde::{Deserialize, Serialize};

use super::id::Id;

fn default_priority() -> i32 {
    0
}

/// ```toml
/// [[subnets]]
/// id = "vlan-marketing"
/// display_name = "VLAN Marketing (piano 2)"
/// cidrs = ["10.10.10.0/24"]
/// profile = "marketing-default"
/// priority = 50
/// ```
///
/// `priority` is informational only (SN1 uses longest-prefix regardless);
/// operators may display or sort by it in TUIs.
///
/// `tags` (Sprint A of `lists_categories_v2`, decision D6) contributes
/// to the effective tag set of devices whose source IP falls inside any
/// of [`Self::cidrs`] **and** that have no explicit `[[devices]]`
/// record. Devices with an explicit record use only `device.tags ∪
/// profile.tags`; subnet tags do not override.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subnet {
    pub id: Id,
    pub display_name: String,
    /// One or more CIDR ranges. Both v4 (`10.0.0.0/8`) and v6 (`fd00::/8`)
    /// are accepted. Validated via [`crate::config::cidr::Cidr::parse`].
    pub cidrs: Vec<String>,
    /// Default profile for unmapped devices whose source IP falls inside
    /// any of [`Self::cidrs`].
    pub profile: Id,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_subnet_deserialises() {
        let toml_src = r#"
id = "vlan-dmz"
display_name = "DMZ"
cidrs = ["10.10.10.0/24"]
profile = "dmz"
"#;
        let s: Subnet = toml::from_str(toml_src).unwrap();
        assert_eq!(s.id.as_str(), "vlan-dmz");
        assert_eq!(s.cidrs, vec!["10.10.10.0/24"]);
        assert_eq!(s.priority, 0);
    }

    #[test]
    fn multiple_cidrs_ok() {
        let s: Subnet = toml::from_str(
            r#"
id = "corp"
display_name = "Corp"
cidrs = ["10.0.0.0/8", "fd00::/8"]
profile = "corp"
priority = 5
"#,
        )
        .unwrap();
        assert_eq!(s.cidrs.len(), 2);
        assert_eq!(s.priority, 5);
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Subnet>(
            r#"
id = "x"
display_name = "y"
cidrs = ["10.0.0.0/8"]
profile = "z"
foo = 1
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
