//! rev-2606 `rev2606-upstream-server-shape-lint` — frozen-strings test.
//!
//! Pins the operator-facing strings coined when `config lint` gained
//! upstream server-shape validation: the two new emptiness consts for the
//! fallback / forwarding lists, and the [`UpstreamShapeError`] `Display`
//! variants embedded in the per-entry `config lint` error line. Each names
//! the bad value and the expected form so the operator fixes the config
//! without reading source.
//!
//! When one MUST change (UX re-wording, typo fix), update the literal here
//! AND the matching row in `CONFIG_GUIDE.md` + `CONFIG_GUIDE.public.md` +
//! `DOCUMENTATION.md` in the same commit. Byte-for-byte equality has no
//! escape hatch — that is the entire point of this trip-wire.
//!
//! `NotSocketAddr` is pinned by its stable framing only: its parenthetical
//! detail comes from `std`'s `AddrParseError`, whose wording is not ours to
//! freeze.

use purge_warden::config::schema::validator::{
    FORWARDING_SERVERS_EMPTY, UPSTREAM_FALLBACK_SERVERS_EMPTY,
};
use purge_warden::config::settings::UpstreamMode;
use purge_warden::upstream::shape::validate_server_shape;

#[test]
fn upstream_fallback_servers_empty_const_is_frozen() {
    assert_eq!(
        UPSTREAM_FALLBACK_SERVERS_EMPTY,
        "upstream.fallback: `servers` is empty — a fallback with no resolver can \
         never take over. Remove the [upstream.fallback] table or list at least \
         one server."
    );
}

#[test]
fn forwarding_servers_empty_const_is_frozen() {
    assert_eq!(
        FORWARDING_SERVERS_EMPTY,
        "forwarding: `servers` is empty — a forwarding zone with no resolver drops \
         every matching query. List at least one server or remove the zone."
    );
}

#[test]
fn shape_not_socketaddr_framing_is_frozen() {
    // plain mode rejects a non-IP:port string; the std parse-error detail
    // inside the parentheses is NOT pinned (not ours), the framing is.
    let e = validate_server_shape(UpstreamMode::Plain, "garbage").unwrap_err();
    let s = e.to_string();
    assert!(
        s.starts_with("\"garbage\" is not a valid IP:port address ("),
        "got: {s}"
    );
    assert!(
        s.ends_with(") — a plain upstream needs a literal address, e.g. \"192.0.2.53:53\""),
        "got: {s}"
    );
}

#[test]
fn shape_not_https_url_display_is_frozen() {
    // neutrality-03: the example in the message is an RFC 5737
    // documentation address now — an operator-facing string must not
    // recommend a named provider. The INPUT stays a realistic URL: what is
    // being pinned is warden's own wording, not the operator's typo.
    let e = validate_server_shape(UpstreamMode::Doh, "http://192.0.2.53/dns-query").unwrap_err();
    assert_eq!(
        e.to_string(),
        "\"http://192.0.2.53/dns-query\" is not an https:// URL — a DoH upstream needs \
         an RFC 8484 endpoint, e.g. \"https://192.0.2.53/dns-query\""
    );
}

#[test]
fn shape_missing_port_display_is_frozen() {
    let e = validate_server_shape(UpstreamMode::Dot, "dns.example.net").unwrap_err();
    assert_eq!(
        e.to_string(),
        "\"dns.example.net\" has no :port — a DoT/DoQ upstream needs host:port, e.g. \
         \"dns.example.net:853\""
    );
}

#[test]
fn shape_bad_port_display_is_frozen() {
    let e = validate_server_shape(UpstreamMode::Dot, "dns.example.net:99999").unwrap_err();
    assert_eq!(
        e.to_string(),
        "\"dns.example.net:99999\" has an invalid port \"99999\" — expected a number \
         0–65535"
    );
}

#[test]
fn shape_bad_host_display_is_frozen() {
    let e = validate_server_shape(UpstreamMode::Doq, "bad host:853").unwrap_err();
    assert_eq!(
        e.to_string(),
        "\"bad host:853\" has an invalid host \"bad host\" — not a usable IP or DNS \
         name"
    );
}
