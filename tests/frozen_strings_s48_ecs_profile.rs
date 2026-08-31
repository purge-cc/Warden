//! Sprint §4.8 §2/2 — per-profile ECS validator frozen-strings test.
//!
//! Pins byte-for-byte the two operator-facing validator errors coined in
//! Sprint §4.8 Phase 2/2. Both live inside
//! `src/config/schema/validator.rs::check_profiles` in the
//! `if let Some(ecs) = &profile.ecs { ... }` branch and fire whenever a
//! per-profile source prefix is set outside the legal range, regardless
//! of `mode` (cfg-validator-05, rev-2606 — pre-fix the checks were
//! gated on an explicit `mode = "subnet"`, so inherited-mode profiles
//! loaded out-of-range prefixes clean and ECS silently never fired).
//!
//! When one of these strings MUST change for legitimate reasons (UX
//! re-wording, typo fix), update the literal here AND the corresponding
//! row in `CONFIG_GUIDE.md` + `CONFIG_GUIDE.public.md` in the same
//! commit. Byte-for-byte equality has no escape hatch — that is the
//! entire point of this trip-wire.

use purge_warden::config::schema::validator::{
    format_ecs_profile_prefix_v4_out_of_range, format_ecs_profile_prefix_v6_out_of_range,
    ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE, ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE,
};

const PROFILE_V4_ERR: &str = "profiles.{key}.ecs.source_prefix_v4: {n} is out of range 0..=32 — typical 24 \
                              for CDN-routing accuracy, 0 to opt out of address forwarding per RFC 7871 \
                              §7.1.2; drop the field to inherit from [upstream.ecs] or set mode = \"off\" \
                              to disable ECS for this profile";

const PROFILE_V6_ERR: &str = "profiles.{key}.ecs.source_prefix_v6: {n} is out of range 0..=128 — typical 56 \
                              for CDN-routing accuracy, 0 to opt out of address forwarding per RFC 7871 \
                              §7.1.2; drop the field to inherit from [upstream.ecs] or set mode = \"off\" \
                              to disable ECS for this profile";

#[test]
fn ecs_profile_prefix_v4_out_of_range_const_is_frozen() {
    assert_eq!(ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE, PROFILE_V4_ERR);
}

#[test]
fn ecs_profile_prefix_v6_out_of_range_const_is_frozen() {
    assert_eq!(ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE, PROFILE_V6_ERR);
}

#[test]
fn ecs_profile_prefix_v4_format_helper_substitutes() {
    let got = format_ecs_profile_prefix_v4_out_of_range("kids", 33);
    assert!(got.contains("profiles.kids.ecs.source_prefix_v4"));
    assert!(got.contains("33 is out of range 0..=32"));
    assert!(!got.contains("{key}"));
    assert!(!got.contains("{n}"));
}

#[test]
fn ecs_profile_prefix_v6_format_helper_substitutes() {
    let got = format_ecs_profile_prefix_v6_out_of_range("work", 129);
    assert!(got.contains("profiles.work.ecs.source_prefix_v6"));
    assert!(got.contains("129 is out of range 0..=128"));
    assert!(!got.contains("{key}"));
    assert!(!got.contains("{n}"));
}
