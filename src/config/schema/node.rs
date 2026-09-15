//! Local node identity, independent of cluster membership and network address.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    /// This node's HTTPS management endpoint, independent of DNS and REST API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<std::net::SocketAddr>,
}

impl NodeConfig {
    /// Initialize missing fields during an explicit installation or lifecycle
    /// operation. Reading configuration never assigns an identity.
    pub fn ensure_identity(&mut self) -> Result<(), String> {
        if self.id.is_none() {
            self.id = Some(generate_node_id()?);
        }
        if self.name.is_none() {
            self.name = Some(hostname_suggestion());
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(id) = &self.id {
            if !valid_node_id(id) {
                return Err("node.id must be a canonical lowercase UUID".into());
            }
        }
        if let Some(name) = &self.name {
            validate_node_name(name)?;
        }
        if let Some(endpoint) = self.control_listen {
            let ip = endpoint.ip().to_canonical();
            if endpoint.port() == 0
                || ip.is_unspecified()
                || ip.is_multicast()
                || matches!(ip, std::net::IpAddr::V4(address) if address.is_broadcast())
            {
                return Err(
                    "node.control_listen requires a specific unicast IP and nonzero port".into(),
                );
            }
        }
        Ok(())
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("Warden")
    }
}

pub fn generate_node_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| format!("cannot generate node identity: {error}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

pub fn valid_node_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub fn validate_node_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty()
        || name != name.trim()
        || name.len() > 256
        || name.chars().count() > 64
        || name.chars().any(char::is_control)
    {
        return Err(
            "node.name must contain 1–64 characters without control characters or surrounding whitespace"
                .into(),
        );
    }
    Ok(())
}

pub fn hostname_suggestion() -> String {
    let mut bytes = [0u8; 256];
    // The writable buffer is bounded; a hostname without a terminator is
    // handled by the same slice bound instead of reading past it.
    let result = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) };
    if result == 0 {
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if let Ok(hostname) = std::str::from_utf8(&bytes[..length]) {
            if validate_node_name(hostname).is_ok() {
                return hostname.to_owned();
            }
        }
    }
    "Warden".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_do_not_generate_identity() {
        let node: NodeConfig = toml::from_str("").unwrap();
        assert_eq!(node, NodeConfig::default());
    }

    #[test]
    fn explicit_initialization_is_stable_and_distinct() {
        let mut first = NodeConfig::default();
        first.ensure_identity().unwrap();
        let saved = first.clone();
        first.ensure_identity().unwrap();
        assert_eq!(first, saved);
        let mut second = NodeConfig::default();
        second.ensure_identity().unwrap();
        assert_ne!(first.id, second.id);
        first.name = Some("Office resolver".into());
        first.ensure_identity().unwrap();
        assert_eq!(first.id, saved.id);
    }

    #[test]
    fn display_values_cannot_inject_terminal_controls() {
        for value in ["", " ", " x", "x\n", "x\u{1b}[31m"] {
            assert!(validate_node_name(value).is_err());
        }
        assert!(validate_node_name("Nodo ufficio – DNS").is_ok());
        assert!(!valid_node_id("../../cluster-membership"));
    }

    #[test]
    fn control_endpoint_is_optional_and_must_be_reachable_as_a_specific_address() {
        for address in [
            "0.0.0.0:8053",
            "[::]:8053",
            "127.0.0.1:0",
            "224.0.0.1:8053",
            "255.255.255.255:8053",
            "[::ffff:0.0.0.0]:8053",
            "[::ffff:224.0.0.1]:8053",
        ] {
            let node = NodeConfig {
                control_listen: Some(address.parse().unwrap()),
                ..NodeConfig::default()
            };
            assert!(node.validate().is_err(), "{address}");
        }
        let node: NodeConfig = toml::from_str("control_listen = '127.0.0.1:8053'").unwrap();
        node.validate().unwrap();
        assert_eq!(node.id, None);
    }
}
