//! §4.8 Sprint 1/2 regression guard: with `[upstream.ecs] enabled = false`,
//! the plain transport stays on `hickory_resolver::Resolver` and the
//! pre-§4.8 wire behaviour is preserved bit-for-bit. LAN-only deploys
//! must observe ZERO behavioural change.
//!
//! The test does not need to hit a real upstream — it asserts the
//! dispatcher choice via `PlainUpstream::uses_ecs()`. The Resolver path
//! itself is still exercised by every existing integration test that
//! constructs a daemon without a `[upstream.ecs]` section.

use std::time::Duration;

use purge_warden::upstream::plain::PlainUpstream;

#[test]
fn plain_upstream_with_ecs_disabled_keeps_resolver_path() {
    let p = PlainUpstream::new(
        &["1.1.1.1:53".to_string()],
        Duration::from_secs(2),
        false,
        false,
    )
    .expect("construct");
    assert!(
        !p.uses_ecs(),
        "ECS off MUST keep the hickory_resolver path — found raw-socket dispatch"
    );
}

#[test]
fn plain_upstream_with_ecs_enabled_dispatches_raw_socket() {
    // §4.8 §2/2 (T4): dispatch is driven by the global [upstream.ecs]
    // master switch, not a per-query option. The handler still passes
    // per-query ECS via `Upstream::lookup`, but the construction-time
    // flag picks Resolver vs Raw.
    let p = PlainUpstream::new(
        &["1.1.1.1:53".to_string()],
        Duration::from_secs(2),
        true,
        false,
    )
    .expect("construct");
    assert!(
        p.uses_ecs(),
        "ECS-enabled master switch MUST dispatch to the raw-socket client — \
         found Resolver path"
    );
}

#[test]
fn ecs_config_default_omits_section_yields_resolver_path() {
    use purge_warden::config::settings::EcsConfig;
    let cfg = EcsConfig::default();
    assert!(!cfg.enabled, "default config must keep ECS off");
    assert!(
        cfg.build_outbound_option().is_none(),
        "default outbound option must be None — Resolver path stays selected"
    );
}
