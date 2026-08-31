//! §4.9-2 integration: a `mode = "doq"` upstream config wires end-to-end
//! through `UpstreamResolver::from_config` (DoQ primary + plain fallback),
//! constructing without panic. Plus an `#[ignore]`d real-network DoQ lookup.
//!
//! The whole file is gated on the `doq` feature: without it the test crate is
//! empty (compiles, 0 tests), proving the default build is unaffected.
#![cfg(feature = "doq")]

use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use purge_warden::config::settings::UpstreamConfig;
use purge_warden::upstream::doq::DoqUpstream;
use purge_warden::upstream::{Upstream, UpstreamResolver};

/// Config → resolver wiring: `mode = "doq"` builds as the primary, `plain` as
/// the fallback, with no network I/O (endpoint bind only). Asserts the resolver
/// constructs and reports the primary healthy.
#[tokio::test]
async fn doq_primary_plain_fallback_wires_from_config() {
    let cfg: UpstreamConfig = toml::from_str(
        r#"
mode = "doq"
servers = ["dns.quad9.net:853"]

[fallback]
mode = "plain"
servers = ["1.1.1.1:53"]
"#,
    )
    .expect("doq+plain upstream config parses");

    let client = reqwest::Client::new();
    let resolver =
        UpstreamResolver::from_config(&cfg, &client).expect("doq primary + plain fallback build");

    assert!(
        resolver.is_primary_healthy(),
        "a freshly-built DoQ primary should not be circuit-broken"
    );
}

/// Real DoQ round-trip against a public resolver. Network-dependent, so
/// `#[ignore]`d; run with `cargo test --features doq -- --ignored real_doq_lookup_quad9`.
#[tokio::test]
#[ignore = "requires network access to dns.quad9.net:853"]
async fn real_doq_lookup_quad9() {
    let upstream = DoqUpstream::new(
        &["dns.quad9.net:853".to_string()],
        Duration::from_secs(10),
        false,
    )
    .unwrap();
    let name: Name = "example.com.".parse().unwrap();

    let resp = upstream
        .lookup(&name, RecordType::A, None)
        .await
        .expect("real DoQ lookup should succeed");

    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert!(
        !resp.records.is_empty(),
        "example.com should resolve to at least one A record"
    );
}
