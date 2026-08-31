//! neutrality-10 — a config that names no upstream is REFUSED, not
//! silently pointed at a resolver warden picked for the operator.
//!
//! `upstream.servers` used to default to a named provider's address pair.
//! Any config that did not spell the section out therefore routed the
//! household's entire query stream to a company the operator never chose,
//! and `config lint` reported VALID while doing it (measured 2026-08-06).
//! No non-empty value is neutral — the fix is no default at all, matching
//! `init`'s `NO_DEFAULT_UPSTREAMS` (neutrality-03) and the scaffold's empty
//! `upstream.servers`.
//!
//! ## Why there are two refusal tests and not one
//!
//! The default is reachable by two *mutually exclusive* serde paths, and a
//! single config exercises exactly one of them:
//!
//! - **`[upstream]` absent entirely** → `ConfigV1`'s `#[serde(default)]`
//!   calls [`UpstreamConfig::default`]. The per-field attribute on
//!   `servers` is never consulted.
//! - **`[upstream]` present, `servers` key absent** (an operator who set
//!   only `mode` or `timeout_ms`) → serde deserialises the struct
//!   field-by-field and takes `servers`' own `#[serde(default)]`.
//!   `UpstreamConfig::default` is never consulted.
//!
//! Repairing one branch leaves the other wide open, and a test written
//! against the wrong branch passes on the unrepaired code. Mutation-verified
//! both ways: restoring the provider pair in `impl Default` reddens ONLY
//! `section_absent_is_refused`; restoring it as `#[serde(default = "…")]`
//! on the field reddens ONLY `servers_key_absent_is_refused`.
//!
//! `declared_upstream_still_loads` is the control that makes the two
//! refusals mean something: it proves `BASE` is otherwise valid, so the
//! refusals above are the upstream gate firing and not some unrelated
//! defect in the fixture.

use purge_warden::config::error::ConfigError;
use purge_warden::config::schema::load::load_from_str;
use purge_warden::config::schema::validator::UPSTREAM_SERVERS_EMPTY;
use time::OffsetDateTime;

/// Fixed instant — the N8 retirement window is time-sensitive, and this
/// fixture declares no `[[retired]]` entries, but pinning `now` keeps the
/// test deterministic if one is ever added.
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_715_500_000).expect("fixed timestamp is in range")
}

/// An otherwise-valid v1 master that declares no upstream in any form.
/// Deliberately minimal: every section present is one the validator
/// requires, so a failure here can only come from the upstream gate.
const BASE: &str = "\
schema_version = 3

[server]
default_profile = \"default\"

[profiles.default]
display_name = \"Default\"
";

/// Assert that `src` is refused, and that the *only* thing wrong with it is
/// the missing upstream. Returning the whole error list on mismatch matters:
/// a fixture that breaks for a second reason would otherwise still satisfy a
/// bare `is_err()` and prove nothing about this gate.
fn assert_refused_for_empty_upstream(src: &str) {
    let errs = match load_from_str(src, None, now()) {
        Ok(_) => panic!("config with no upstream must be refused, but it loaded"),
        Err(errs) => errs,
    };
    assert_eq!(
        errs.len(),
        1,
        "expected exactly the upstream refusal, got: {errs:#?}"
    );
    let err = &errs[0];
    assert!(
        matches!(err, ConfigError::ValidationFailed(_)),
        "expected a ValidationFailed, got: {err:#?}"
    );
    let text = err.to_string();
    assert!(
        text.contains(UPSTREAM_SERVERS_EMPTY),
        "refusal must carry the frozen UPSTREAM_SERVERS_EMPTY text, got: {text}"
    );
    // The frozen message points at the flag rather than naming a resolver
    // (neutrality-08). Re-asserted here so a future re-wording that smuggles
    // a provider back into the operator-facing text fails on this path too,
    // not only in the frozen-strings pin.
    assert!(
        text.contains("warden does not choose one for you"),
        "refusal must state that warden picks nobody, got: {text}"
    );
}

/// Branch 1 — the whole `[upstream]` table is missing. Hits
/// `UpstreamConfig::default()` via `ConfigV1`'s `#[serde(default)]`.
#[test]
fn section_absent_is_refused() {
    assert_refused_for_empty_upstream(BASE);
}

/// Branch 2 — `[upstream]` exists but never names a server. Hits the
/// `#[serde(default)]` on the `servers` field itself. `timeout_ms` is set
/// so the table is non-empty for a reason an operator would actually have.
#[test]
fn servers_key_absent_is_refused() {
    let src = format!("{BASE}\n[upstream]\nmode = \"plain\"\ntimeout_ms = 3000\n");
    assert_refused_for_empty_upstream(&src);
}

/// Branch 2, explicit-empty form. This one was ALREADY refused before
/// neutrality-10 — serde takes the written value, never a default — so it
/// proves nothing new on its own and is kept only to pin that the fix did
/// not disturb the path that already worked.
#[test]
fn servers_written_empty_is_still_refused() {
    let src = format!("{BASE}\n[upstream]\nservers = []\n");
    assert_refused_for_empty_upstream(&src);
}

/// Control — the same base with an upstream the operator actually chose
/// loads clean. Without this, the three refusals above are compatible with
/// `BASE` being broken for some unrelated reason.
#[test]
fn declared_upstream_still_loads() {
    // RFC 5737 TEST-NET-1: a documentation address, unroutable, names nobody.
    let src = format!("{BASE}\n[upstream]\nservers = [\"192.0.2.1:53\"]\n");
    let cfg = load_from_str(&src, None, now()).expect("a config naming its upstream must load");
    assert_eq!(cfg.upstream.servers, vec!["192.0.2.1:53".to_string()]);
}

/// The in-code default itself, asserted directly rather than through a
/// config. Guards the case where someone reintroduces a default at the
/// struct level while every TOML fixture in the suite happens to declare
/// the section — the state in which this defect originally survived.
#[test]
fn upstream_config_default_names_no_resolver() {
    let d = purge_warden::config::settings::UpstreamConfig::default();
    assert!(
        d.servers.is_empty(),
        "UpstreamConfig::default() must name no resolver, got: {:?}",
        d.servers
    );
}
