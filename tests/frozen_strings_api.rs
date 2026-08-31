//! rev-2606 §07 `[api]` validation — frozen-strings test.
//!
//! Pins every operator-facing recovery-hint const emitted by
//! `check_api` byte-for-byte. If a string drifts the test fails:
//! update the literal here in the same commit, deliberately.

use purge_warden::config::schema::validator::{
    format_api_metrics_public_unauth, API_ENABLED_REQUIRES_TOKEN_HASH, API_METRICS_PUBLIC_UNAUTH,
    API_NONLOOPBACK_REQUIRES_TLS, API_TLS_PAIR_INCOMPLETE,
};

#[test]
fn enabled_requires_token_hash_byte_for_byte() {
    assert_eq!(
        API_ENABLED_REQUIRES_TOKEN_HASH,
        "api: `token_hash` is required when `enabled = true`. \
         Run `warden token generate` to create one."
    );
}

#[test]
fn nonloopback_requires_tls_byte_for_byte() {
    assert_eq!(
        API_NONLOOPBACK_REQUIRES_TLS,
        "api: `listen` is non-loopback but TLS is not configured — bearer \
         tokens would travel in cleartext. Set both `tls_cert` and `tls_key`, \
         or bind a loopback address (default 127.0.0.1:8053)."
    );
}

#[test]
fn tls_pair_incomplete_byte_for_byte() {
    assert_eq!(
        API_TLS_PAIR_INCOMPLETE,
        "api: `tls_cert` and `tls_key` must be set together — with only one, \
         the server silently falls back to plain HTTP."
    );
}

#[test]
fn metrics_public_unauth_byte_for_byte() {
    assert_eq!(
        API_METRICS_PUBLIC_UNAUTH,
        "api: `metrics_enabled = true` with a non-loopback `listen` ({addr}) serves \
         GET /metrics (query rate, block ratio, device count) UNAUTHENTICATED to the \
         whole network — TLS encrypts but does not authenticate it. Bind the API to \
         loopback, restrict /metrics with your own network ACL, or set \
         `metrics_enabled = false` if this is unintended."
    );
}

#[test]
fn metrics_public_unauth_format_helper_substitutes() {
    let got = format_api_metrics_public_unauth(&"10.0.0.1:8053".parse().unwrap());
    assert!(got.contains("(10.0.0.1:8053)"));
    assert!(!got.contains("{addr}"));
}

#[test]
fn api_consts_are_scoped_and_nonempty() {
    for s in [
        API_ENABLED_REQUIRES_TOKEN_HASH,
        API_METRICS_PUBLIC_UNAUTH,
        API_NONLOOPBACK_REQUIRES_TLS,
        API_TLS_PAIR_INCOMPLETE,
    ] {
        assert!(!s.is_empty());
        assert!(s.starts_with("api:"), "must be scoped: {s}");
    }
}
