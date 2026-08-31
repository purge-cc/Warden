//! [`Group`] — a named set of device ids with a shared profile, used to
//! scale profiles across tens or hundreds of devices without per-device
//! duplication (A4).
//!
//! Per design doc §8.4. Group priority (DM2) resolves conflicts when a
//! device belongs to multiple groups; same-priority different-profile
//! memberships are a validator error.

use serde::{Deserialize, Serialize};

use super::id::Id;

fn default_priority() -> i32 {
    0
}

/// ```toml
/// [[groups]]
/// id = "iot-strict"
/// display_name = "IoT devices (strict profile)"
/// profile = "iot-strict"
/// priority = 10
/// devices = ["hue-bulb-1", "hue-bulb-2"]
/// ```
///
/// Higher `priority` wins when a device is a member of multiple groups
/// with different profiles (DM2). A tie with different profiles surfaces
/// as a validator error at load time — the operator must either change a
/// group's priority or remove the conflicting membership.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: Id,
    pub display_name: String,
    /// Profile applied to members of this group unless a member has its
    /// own direct profile (DM1) or a higher-priority group overrides.
    pub profile: Id,
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Devices in this group by id. Cross-checked against `[[devices]]`.
    #[serde(default)]
    pub devices: Vec<Id>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_group_deserialises() {
        let toml_src = r#"
id = "iot-strict"
display_name = "IoT strict"
profile = "iot-strict"
"#;
        let g: Group = toml::from_str(toml_src).unwrap();
        assert_eq!(g.id.as_str(), "iot-strict");
        assert_eq!(g.profile.as_str(), "iot-strict");
        assert_eq!(g.priority, 0);
        assert!(g.devices.is_empty());
    }

    #[test]
    fn full_group_deserialises() {
        let toml_src = r#"
id = "iot-strict"
display_name = "IoT strict"
profile = "iot-strict"
priority = 10
devices = ["hue-1", "hue-2", "thermostat"]
"#;
        let g: Group = toml::from_str(toml_src).unwrap();
        assert_eq!(g.priority, 10);
        assert_eq!(g.devices.len(), 3);
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Group>(
            r#"
id = "x"
display_name = "y"
profile = "z"
members = ["a"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn priority_can_be_negative() {
        let g: Group = toml::from_str(
            r#"
id = "low"
display_name = "low"
profile = "perm"
priority = -5
"#,
        )
        .unwrap();
        assert_eq!(g.priority, -5);
    }
}
