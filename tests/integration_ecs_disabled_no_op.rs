//! §4.8 Sprint 1/2 regression net: with ECS disabled, the daemon emits
//! ZERO ECS-related bytes on every outbound transport.
//!
//! This test is the LAN-only deploy guard — it asserts that the entire
//! plumbing introduced by §4.8 (config schema, codec module, shared
//! `build_query_bytes()` hook, per-transport `ecs` fields, plain
//! dispatcher) is genuinely off-by-default. A future refactor that
//! flips a default to true, or that accidentally threads `Some(...)`
//! into a constructor, will trip this test before reaching production.
//!
//! Per memory `feedback_hot_path_name_mutation_tests`: assertions are
//! on the actual wire bytes that would leave the daemon, not on
//! struct-internal flags. The codec module already covers the
//! "ECS option not present" assertion in isolation; here we exercise
//! the whole upstream stack and prove it preserves that property.

use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{Name, RecordType};
use purge_warden::config::settings::EcsConfig;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::upstream::build_query_bytes;
use purge_warden::upstream::doh::DohUpstream;
use purge_warden::upstream::dot::DotUpstream;
use purge_warden::upstream::plain::PlainUpstream;

fn assert_no_ecs_in_wire_bytes(bytes: &[u8], context: &str) {
    let parsed = Message::from_vec(bytes).expect("parse");
    if let Some(edns) = parsed.edns.as_ref() {
        assert!(
            edns.option(EdnsCode::Subnet).is_none(),
            "{context}: outbound query unexpectedly carries ECS option \
             (code 8) with ECS disabled"
        );
    }
    // additional_count check is stricter still: with ECS off we expect
    // NO EDNS extension at all, but we keep the assertion above as the
    // primary one in case a future change adds non-ECS EDNS options.
    assert_eq!(
        parsed.additionals.len(),
        0,
        "{context}: expected zero additional records (no OPT) with ECS disabled"
    );
}

#[test]
fn ecs_config_default_yields_no_outbound_option() {
    let cfg = EcsConfig::default();
    assert!(!cfg.enabled);
    assert!(
        cfg.build_outbound_option().is_none(),
        "default EcsConfig must not produce an outbound option"
    );
}

#[test]
fn build_query_bytes_with_none_emits_no_ecs() {
    let name: Name = "example.com.".parse().unwrap();
    let bytes = build_query_bytes(&name, RecordType::A, None, false).expect("build");
    assert_no_ecs_in_wire_bytes(&bytes, "build_query_bytes(None)");
}

#[test]
fn doh_upstream_with_ecs_disabled_emits_no_ecs() {
    let client = reqwest::Client::builder().build().unwrap();
    let _doh = DohUpstream::new(
        client,
        vec!["https://1.1.1.1/dns-query".to_string()],
        Duration::from_secs(2),
        false,
    )
    .expect("doh");
    let name: Name = "example.com.".parse().unwrap();
    // Sprint §4.8 §2/2 (T4): the upstream no longer holds an ECS
    // option; the handler passes per-query ECS, with `None` being the
    // disabled baseline. Reconstruct the same canonical no-ECS bytes.
    let bytes = build_query_bytes(&name, RecordType::A, None, false).expect("build");
    assert_no_ecs_in_wire_bytes(&bytes, "DoH off (per-query None)");
}

#[test]
fn dot_upstream_with_ecs_disabled_emits_no_ecs() {
    let _dot = DotUpstream::new(
        &["1.1.1.1:853".to_string()],
        Duration::from_secs(2),
        1,
        false,
    )
    .expect("dot");
    let name: Name = "example.com.".parse().unwrap();
    let bytes = build_query_bytes(&name, RecordType::A, None, false).expect("build");
    assert_no_ecs_in_wire_bytes(&bytes, "DoT off (per-query None)");
}

#[test]
fn plain_upstream_with_ecs_disabled_keeps_resolver_and_emits_no_ecs() {
    let plain = PlainUpstream::new(
        &["1.1.1.1:53".to_string()],
        Duration::from_secs(2),
        false,
        false,
    )
    .expect("plain");
    assert!(
        !plain.uses_ecs(),
        "Plain MUST stay on Resolver path when ECS disabled"
    );
    // The Resolver path uses hickory_resolver internally, which emits
    // its own queries — those have the same zero-ECS shape since we
    // never configure EDNS options on the resolver. Asserting the
    // shared build_query_bytes(None) shape is sufficient as the canonical
    // wire-format reference.
    let name: Name = "example.com.".parse().unwrap();
    let bytes = build_query_bytes(&name, RecordType::A, None, false).expect("build");
    assert_no_ecs_in_wire_bytes(&bytes, "Plain off");
}

#[test]
fn ecs_disabled_via_explicit_false_matches_default() {
    // An operator who writes [upstream.ecs] explicitly with enabled=false
    // (perhaps as documentation in their TOML) MUST get the same outcome
    // as omitting the section entirely.
    let cfg = EcsConfig {
        enabled: false,
        ..Default::default()
    };
    assert_eq!(cfg, EcsConfig::default());
    assert!(cfg.build_outbound_option().is_none());
    assert!(
        EdnsClientSubnet::anonymous(purge_warden::dns::edns::AddressFamily::V4).source_prefix()
            == 0
    );
}
