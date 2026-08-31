//! §4.8 §2/2 (T5) — `[profile.X.ecs]` TOML round-trip + inheritance pinning.
//!
//! T5's original scope ("TUI radio in profile editor") assumed a TUI
//! surface that does not exist — `src/tui/app.rs` carries no Profile
//! tab. The v1 schema `Profile` (with the T1 `[profile.X.ecs]`
//! sub-table) is the runtime path the daemon actually uses
//! (handler.rs reads `ResolvedProfile.ecs_policy`).
//!
//! Until a v1-aware CLI/TUI ships in a follow-up sprint, the operator
//! workflow is hand-edit `[profile.X.ecs]` in `config.toml` + reload.
//! These tests pin that workflow end-to-end:
//!
//! 1. The TOML parses through `ConfigV1` with the new sub-table.
//! 2. The v1 validator accepts well-formed values and rejects out-of-
//!    range Subnet prefixes (frozen-string text already pinned by
//!    `tests/frozen_strings_s48_ecs_profile.rs`).
//! 3. The resolver chain `Profile.ecs` → `[upstream.ecs]` → `OFF`
//!    flattens into `EcsPolicy` correctly under the inheritance rules
//!    (D7) and the master kill-switch.

use purge_warden::config::schema::validator::validate;
use purge_warden::config::schema::ConfigV1;
use purge_warden::config::settings::EcsMode;
use purge_warden::profiles::profile::EcsPolicy;
use time::OffsetDateTime;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_715_500_000).unwrap()
}

#[test]
fn profile_ecs_full_subtable_roundtrips_via_toml() {
    let src = r#"
schema_version = 3

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[upstream.ecs]
enabled = true
source_prefix_v4 = 24
source_prefix_v6 = 56
mode = "coarse"

[profiles.work]
display_name = "Work laptops"

[profiles.work.ecs]
mode = "subnet"
source_prefix_v4 = 28
source_prefix_v6 = 64
"#;
    let cfg: ConfigV1 = toml::from_str(src).expect("parse");
    validate(&cfg, now()).expect("validator passes");
    let prof = cfg.profiles.get("work").unwrap();
    let pe = prof.ecs.as_ref().unwrap();
    assert_eq!(pe.mode, Some(EcsMode::Subnet));
    assert_eq!(pe.source_prefix_v4, Some(28));
    assert_eq!(pe.source_prefix_v6, Some(64));

    // EcsPolicy flatten layers the per-profile override onto the
    // upstream defaults (D7).
    let policy = EcsPolicy::from_profile_and_upstream(prof.ecs.as_ref(), &cfg.upstream.ecs);
    assert_eq!(policy.mode, EcsMode::Subnet);
    assert_eq!(policy.source_prefix_v4, 28);
    assert_eq!(policy.source_prefix_v6, 64);
}

#[test]
fn profile_ecs_partial_override_inherits_per_field_from_upstream() {
    // Profile sets mode only; source_prefix_* inherit from upstream
    // defaults. Mirrors the D7 inheritance contract at the TOML edge.
    let src = r#"
schema_version = 3

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[upstream.ecs]
enabled = true
source_prefix_v4 = 24
source_prefix_v6 = 56
mode = "coarse"

[profiles.kids]
display_name = "Kids"

[profiles.kids.ecs]
mode = "subnet"
"#;
    let cfg: ConfigV1 = toml::from_str(src).expect("parse");
    validate(&cfg, now()).expect("validator passes");
    let prof = cfg.profiles.get("kids").unwrap();
    let pe = prof.ecs.as_ref().unwrap();
    assert_eq!(pe.mode, Some(EcsMode::Subnet));
    assert!(pe.source_prefix_v4.is_none());
    assert!(pe.source_prefix_v6.is_none());

    let policy = EcsPolicy::from_profile_and_upstream(prof.ecs.as_ref(), &cfg.upstream.ecs);
    assert_eq!(policy.mode, EcsMode::Subnet);
    // Prefixes inherited from [upstream.ecs].
    assert_eq!(policy.source_prefix_v4, 24);
    assert_eq!(policy.source_prefix_v6, 56);
}

#[test]
fn profile_ecs_master_kill_switch_overrides_profile_via_toml() {
    // Master switch off: even an explicit `mode = "subnet"` on the
    // profile resolves to `EcsPolicy::OFF`. Operator emergency stop
    // sanity at the TOML edge.
    let src = r#"
schema_version = 3

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[upstream.ecs]
enabled = false

[profiles.guest]
display_name = "Guest"

[profiles.guest.ecs]
mode = "subnet"
source_prefix_v4 = 24
source_prefix_v6 = 56
"#;
    let cfg: ConfigV1 = toml::from_str(src).expect("parse");
    validate(&cfg, now()).expect("validator passes");
    let prof = cfg.profiles.get("guest").unwrap();
    let policy = EcsPolicy::from_profile_and_upstream(prof.ecs.as_ref(), &cfg.upstream.ecs);
    assert_eq!(policy, EcsPolicy::OFF);
}

#[test]
fn profile_ecs_absent_subtable_inherits_upstream_defaults_fully() {
    // Profile carries no `[profile.X.ecs]` — every field inherits.
    let src = r#"
schema_version = 3

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[upstream.ecs]
enabled = true
source_prefix_v4 = 16
source_prefix_v6 = 48
mode = "subnet"

[profiles.default]
display_name = "Default"
"#;
    let cfg: ConfigV1 = toml::from_str(src).expect("parse");
    validate(&cfg, now()).expect("validator passes");
    let prof = cfg.profiles.get("default").unwrap();
    assert!(prof.ecs.is_none(), "no sub-table means None on the field");
    let policy = EcsPolicy::from_profile_and_upstream(prof.ecs.as_ref(), &cfg.upstream.ecs);
    assert_eq!(policy.mode, EcsMode::Subnet);
    assert_eq!(policy.source_prefix_v4, 16);
    assert_eq!(policy.source_prefix_v6, 48);
}

#[test]
fn profile_ecs_subnet_out_of_range_prefix_v4_is_rejected_via_validator() {
    // The frozen-strings test pins the operator-facing text; this
    // pins the validator + TOML parse interaction.
    let src = r#"
schema_version = 3

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[upstream.ecs]
enabled = true

[profiles.busted]
display_name = "Busted"

[profiles.busted.ecs]
mode = "subnet"
source_prefix_v4 = 99
"#;
    let cfg: ConfigV1 = toml::from_str(src).expect("parse");
    let errs = validate(&cfg, now()).expect_err("validator rejects");
    assert!(
        errs.iter()
            .any(|e| format!("{e:?}").contains("source_prefix_v4")),
        "expected v4 prefix-range error: {errs:?}"
    );
}
