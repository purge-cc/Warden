//! Pure, I/O-free shape validation for upstream server strings.
//!
//! The transport constructors (`plain`, `plain_raw`, `doh`, `dot`, `doq`)
//! each parse their `servers`/`urls` entries at boot — but they also build
//! live resources (sockets, reqwest clients, TLS configs) and, for DoT/DoQ
//! hostnames, *resolve via OS DNS*. `warden config lint` must validate the
//! same entries **offline** and **without** constructing transports, so the
//! pure shape decision lives here and is called from BOTH the constructors
//! (single source of truth) and the config validator
//! (`schema::validator::check_upstream_servers`) — they cannot drift.
//!
//! **Faithfulness (rev-2606 `rev2606-upstream-server-shape-lint`).** For
//! `plain` and `doh` the check is byte-identical to the constructor. For
//! `dot`/`doq` the constructor additionally *resolves* the hostname (I/O);
//! lint validates host:port **syntax** only (an `IP:port` literal, or a
//! syntactically-valid TLS server name + numeric port) and does not resolve.
//! The lint check is therefore equal-or-looser than boot, never stricter: it
//! rejects exactly the strings the constructor rejects at the parse/SNI
//! stage, and accepts a syntactically-valid host that may fail to resolve at
//! boot (a runtime/environmental condition, not a config typo). Cold path
//! only — never runs per query.

use std::fmt;
use std::net::SocketAddr;

use crate::config::settings::UpstreamMode;

/// Why an upstream server string is malformed. Cold path; `Display` is the
/// operator-facing reason embedded in the `config lint` error line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamShapeError {
    /// A `plain` entry is not a literal `IP:port`.
    NotSocketAddr { value: String, detail: String },
    /// A `doh` entry is not an `https://` URL.
    NotHttpsUrl { value: String },
    /// A `dot`/`doq` entry has no `:port`.
    MissingPort { value: String },
    /// A `dot`/`doq` port is not a number in `0..=65535`.
    BadPort { value: String, port: String },
    /// A `dot`/`doq` host is empty or not a usable TLS server name.
    BadHost { value: String, host: String },
}

impl fmt::Display for UpstreamShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamShapeError::NotSocketAddr { value, detail } => write!(
                f,
                "\"{value}\" is not a valid IP:port address ({detail}) — a plain \
                 upstream needs a literal address, e.g. \"192.0.2.53:53\""
            ),
            UpstreamShapeError::NotHttpsUrl { value } => write!(
                f,
                "\"{value}\" is not an https:// URL — a DoH upstream needs an \
                 RFC 8484 endpoint, e.g. \"https://192.0.2.53/dns-query\""
            ),
            UpstreamShapeError::MissingPort { value } => write!(
                f,
                "\"{value}\" has no :port — a DoT/DoQ upstream needs host:port, \
                 e.g. \"dns.example.net:853\""
            ),
            UpstreamShapeError::BadPort { value, port } => write!(
                f,
                "\"{value}\" has an invalid port \"{port}\" — expected a number 0–65535"
            ),
            UpstreamShapeError::BadHost { value, host } => write!(
                f,
                "\"{value}\" has an invalid host \"{host}\" — not a usable IP or DNS name"
            ),
        }
    }
}

impl std::error::Error for UpstreamShapeError {}

/// `plain` (and the raw-socket plain client): a literal `IP:port`. Returns
/// the parsed [`SocketAddr`] so the constructor reuses it. Byte-identical to
/// `PlainUpstream`/`PlainRawClient`'s boot-time parse.
pub fn validate_plain_server(s: &str) -> Result<SocketAddr, UpstreamShapeError> {
    s.parse::<SocketAddr>()
        .map_err(|e| UpstreamShapeError::NotSocketAddr {
            value: s.to_string(),
            detail: e.to_string(),
        })
}

/// `doh`: an `https://` endpoint. Mirrors `DohUpstream::new` exactly — the
/// constructor checks only the scheme prefix, so lint must not be stricter
/// (no full URL parse the boot path would have accepted).
pub fn validate_doh_url(s: &str) -> Result<(), UpstreamShapeError> {
    if s.starts_with("https://") {
        Ok(())
    } else {
        Err(UpstreamShapeError::NotHttpsUrl {
            value: s.to_string(),
        })
    }
}

/// `dot`/`doq`: `IP:port` or `host:port`. Validates **syntax** only — no DNS
/// resolution (that is the constructor's boot-time I/O). Accepts an `IP:port`
/// literal, or a `host:port` whose port parses as `u16` and whose host is a
/// valid `rustls` server name (the same gate the DoT constructor applies to
/// the SNI name after it resolves).
pub fn validate_host_port_server(s: &str) -> Result<(), UpstreamShapeError> {
    // IP:port fast path — identical to the DoT/DoQ constructors.
    if s.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    // host:port — split on the LAST colon, mirroring the constructors'
    // `rsplit_once(':')`.
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| UpstreamShapeError::MissingPort {
            value: s.to_string(),
        })?;
    if port.parse::<u16>().is_err() {
        return Err(UpstreamShapeError::BadPort {
            value: s.to_string(),
            port: port.to_string(),
        });
    }
    if host.is_empty() || rustls::pki_types::ServerName::try_from(host.to_owned()).is_err() {
        return Err(UpstreamShapeError::BadHost {
            value: s.to_string(),
            host: host.to_string(),
        });
    }
    Ok(())
}

/// Dispatch shape validation on the upstream mode. Used by the config
/// validator to lint primary, fallback, and forwarding-zone server lists
/// offline. The `doq` arm needs no `cfg` gate — host:port syntax is plain
/// Rust; the missing-`--features doq` case is a boot concern (`build_upstream`
/// bails), not a shape one.
pub fn validate_server_shape(mode: UpstreamMode, s: &str) -> Result<(), UpstreamShapeError> {
    match mode {
        UpstreamMode::Plain => validate_plain_server(s).map(|_| ()),
        UpstreamMode::Doh => validate_doh_url(s),
        UpstreamMode::Dot | UpstreamMode::Doq => validate_host_port_server(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── plain (IP:port, byte-identical to the constructor) ──────────
    #[test]
    fn plain_accepts_ip_port() {
        assert!(validate_plain_server("1.1.1.1:53").is_ok());
        assert!(validate_plain_server("8.8.8.8:5353").is_ok());
        assert!(validate_plain_server("[2606:4700:4700::1111]:53").is_ok());
    }

    #[test]
    fn plain_rejects_non_socketaddr() {
        assert!(validate_plain_server("1.1.1.1").is_err()); // no port
        assert!(validate_plain_server("dns.google:53").is_err()); // hostname, not IP
        assert!(validate_plain_server("1.1.1.1:").is_err()); // empty port
        assert!(validate_plain_server("256.1.1.1:53").is_err()); // bad octet
        assert!(validate_plain_server("").is_err());
    }

    // ── doh (https:// prefix, byte-identical to the constructor) ─────
    #[test]
    fn doh_accepts_https_url() {
        assert!(validate_doh_url("https://1.1.1.1/dns-query").is_ok());
        assert!(validate_doh_url("https://dns.google/dns-query").is_ok());
    }

    #[test]
    fn doh_rejects_non_https() {
        assert!(validate_doh_url("http://1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("1.1.1.1/dns-query").is_err());
        assert!(validate_doh_url("htps://typo").is_err());
        assert!(validate_doh_url("").is_err());
    }

    // ── dot/doq (host:port or IP:port syntax, NO resolution) ────────
    #[test]
    fn host_port_accepts_ip_and_syntactic_host() {
        assert!(validate_host_port_server("1.1.1.1:853").is_ok());
        assert!(validate_host_port_server("dns.quad9.net:853").is_ok());
        assert!(validate_host_port_server("[2606:4700:4700::1111]:853").is_ok());
    }

    #[test]
    fn host_port_rejects_malformed() {
        assert!(validate_host_port_server("dns.quad9.net").is_err()); // no port
        assert!(validate_host_port_server("dns.quad9.net:notaport").is_err());
        assert!(validate_host_port_server("dns.quad9.net:99999").is_err()); // > u16
        assert!(validate_host_port_server(":853").is_err()); // empty host
        assert!(validate_host_port_server("bad host:853").is_err()); // space in host
    }

    // ── dispatcher ──────────────────────────────────────────────────
    #[test]
    fn dispatch_routes_by_mode() {
        assert!(validate_server_shape(UpstreamMode::Plain, "1.1.1.1:53").is_ok());
        assert!(validate_server_shape(UpstreamMode::Plain, "https://x/dns-query").is_err());
        assert!(validate_server_shape(UpstreamMode::Doh, "https://x/dns-query").is_ok());
        assert!(validate_server_shape(UpstreamMode::Doh, "1.1.1.1:53").is_err());
        assert!(validate_server_shape(UpstreamMode::Dot, "1.1.1.1:853").is_ok());
        assert!(validate_server_shape(UpstreamMode::Doq, "dns.quad9.net:853").is_ok());
        assert!(validate_server_shape(UpstreamMode::Doq, "dns.quad9.net").is_err());
    }

    /// Parity on the offline-decidable set: the shared validator agrees with
    /// the live `parse::<SocketAddr>()` the plain constructors run, and with
    /// the `https://` prefix the DoH constructor runs. The DoT/DoQ
    /// hostname-resolution case is the documented non-parity boundary (lint
    /// is offline) and is intentionally not asserted here.
    #[test]
    fn parity_with_constructor_parse_layer() {
        for s in ["1.1.1.1:53", "8.8.8.8:853", "192.168.0.1:5353"] {
            assert_eq!(
                validate_plain_server(s).is_ok(),
                s.parse::<SocketAddr>().is_ok(),
                "plain parity for {s}"
            );
            // IP:port is accepted identically by the host:port path.
            assert!(
                validate_host_port_server(s).is_ok(),
                "dot/doq IP parity for {s}"
            );
        }
        for s in ["1.1.1.1", "garbage", "dns.google:53", "1.1.1.1:"] {
            assert_eq!(
                validate_plain_server(s).is_ok(),
                s.parse::<SocketAddr>().is_ok(),
                "plain reject parity for {s}"
            );
        }
        for s in ["https://1.1.1.1/dns-query", "http://x", "1.1.1.1", ""] {
            assert_eq!(
                validate_doh_url(s).is_ok(),
                s.starts_with("https://"),
                "doh parity for {s}"
            );
        }
    }
}
