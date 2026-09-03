//! [`Profile`] — a named bundle of filter rules (blocklists, admin_rules,
//! response behaviour) referenced by devices / groups / subnets / schedules.
//!
//! Profiles are flat in v1 (no `extends`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::blocklist::ListPolicy;
use super::id::Id;
use crate::config::settings::{EcsMode, LocalDnsRecord, RewriteRule};

/// Wire-level response shape for blocked queries.
///
/// This is the v1 schema enum, scoped to `config::schema` — the sole
/// block-response type in the codebase.
///
/// Four variants:
///
/// - `zero` — canned `0.0.0.0 / ::0`. Fast client giveup, default.
/// - `nxdomain` — `RCODE=NXDOMAIN`. Client treats as a missing record.
/// - `refused` — `RCODE=REFUSED`. Stubs fall through to next DNS.
/// - `soa_nodata` — `NOERROR` with an empty answer + authority SOA.
///   RFC 2308 negative-caching friendly; the response caches for the
///   SOA minimum TTL instead of being replayed repeatedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseV1 {
    #[default]
    Zero,
    Nxdomain,
    Refused,
    SoaNodata,
}

/// ```toml
/// [profiles.default]
/// display_name = "Default household profile"
/// block_response = "zero"
/// blocked_ttl_secs = 60
/// admin_rules = ["default-allow-github"]
/// ```
///
/// `block_response` and `blocked_ttl_secs` are `Option` so that absence
/// means "fall back to the `[server]` globals". The profile's *id* is
/// the map key in the parent `BTreeMap<String, Profile>` — the key string
/// is validated as an [`Id`](super::id::Id) by `collect_profile_ids` at
/// load, not enforced by the serde map type; it does not live on this
/// struct.
///
/// The v1 schema has no `blocklists: Vec<Id>` or `categories: Vec<Id>`
/// fields. Profile keeps its behavioural role (schedule, response, admin
/// rules, local_records); list applicability is derived from tag
/// intersection instead — profiles do not enumerate lists directly.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub display_name: String,
    /// Per-profile wire-level block response. `None` → inherit from
    /// `[server].default_block_response`.
    #[serde(default)]
    pub block_response: Option<BlockResponseV1>,
    /// Per-profile TTL applied to block responses, in seconds. `None`
    /// → inherit from `[server].default_blocked_ttl_secs`.
    #[serde(default)]
    pub blocked_ttl_secs: Option<u32>,
    /// Admin-rule ids applied to this profile. Only admin rules can use
    /// AdGuard `@@` overrides and `$important`; external blocklists are
    /// sandboxed (CLAUDE.md rule 4).
    #[serde(default)]
    pub admin_rules: Vec<Id>,
    /// Block every query unless an admin-rule allow (`@@||domain^`) matches.
    /// Useful for "kids night" profiles where only a narrow allow list
    /// survives. Defaults to `false`; carried forward unchanged from the
    /// legacy v0 profile model.
    #[serde(default)]
    pub block_all: bool,
    /// Profile-scoped local DNS records. Empty by default, so every
    /// pre-existing config deserialises byte-identical. When non-empty,
    /// queries from clients resolving to this profile consult these
    /// records BEFORE the global `[local_dns]` table. Validation runs
    /// through `crate::config::validator::validate_local_records_v2`
    /// scoped per-profile.
    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
    /// Per-profile EDNS Client Subnet policy. `None` →
    /// inherit `[upstream.ecs]` defaults. `Some(...)` → per-profile
    /// override (and per-field inheritance via inner `Option`s; see
    /// [`ProfileEcsConfig`]). The master kill-switch
    /// `[upstream.ecs].enabled` still gates every outbound emission —
    /// when it is `false`, this field is ignored regardless of value.
    #[serde(default)]
    pub ecs: Option<ProfileEcsConfig>,
    /// Profile-scoped name-to-name rewrites. Empty by default, so every
    /// pre-existing config deserialises byte-identical.
    /// Engine in `crate::dns::rewrite::ProfileRewriteRules`. Hot-path hook
    /// runs AFTER filter+blocked check + BEFORE upstream forward, so a
    /// rewrite cannot bypass blocklist enforcement on the original qname.
    /// Validation runs through
    /// `crate::config::validator::validate_rewrite_rules` per-profile.
    #[serde(default)]
    pub rewrite_rules: Vec<RewriteRule>,
    /// Opt-in per-profile SafeSearch enforcement. When `true`, the
    /// resolver injects a fixed set of search-engine rewrite rules at
    /// resolve-time (inside [`crate::profiles::profile::ResolvedProfile::build_v1`]),
    /// after validation and before the rewrite engine is built. Default
    /// `false`, so every pre-existing config deserialises byte-identical.
    /// Operator-authored `[[rewrites]]` entries with
    /// the same `from` take precedence — see `crate::profiles::safesearch`.
    #[serde(default)]
    pub safe_search: bool,
    /// Custom lists mounted on this profile. Each id must name a
    /// `[[custom_lists]]` entry; the validator refuses a dangling
    /// reference, the same way it does for `admin_rules`.
    ///
    /// Declared before `lists` on purpose: TOML cannot emit a bare value
    /// after a table within the same table, so this array has to precede
    /// the map-valued field. Pinned by a round-trip test over a profile
    /// carrying both.
    ///
    /// **On `skip_serializing_if`.** Same argument as the `lists` map below:
    /// an empty mount list declares nothing, and without the skip every
    /// config-rewriting path would grow `custom_lists = []` in every profile
    /// of every operator's file, including profiles that never opted in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_lists: Vec<Id>,
    /// Per-list direction override, scoped to this profile.
    ///
    /// Keyed by [`Blocklist::id`](super::blocklist::Blocklist::id). An id
    /// present here overrides that list's own
    /// [`base`](super::blocklist::Blocklist::base) **for this profile
    /// only**; an id absent here inherits it:
    ///
    /// ```text
    /// effective(profile, list) = profile.lists[list.id]   if present
    ///                          = list.base                otherwise
    /// ```
    ///
    /// Empty by default, so every pre-existing config deserialises
    /// byte-identical. **Absence and `lists = {}` are the same state** —
    /// both mean "inherit everything" — which is why this is the one field
    /// on `Profile` carrying `skip_serializing_if`; see the note on that
    /// attribute below.
    ///
    /// Validated by `check_profiles` in
    /// [`crate::config::schema::validator`]: every id named here must exist
    /// among the `[[blocklists]]`, or the config is refused with
    /// [`ConfigError::CrossRefMiss`](crate::config::error::ConfigError::CrossRefMiss).
    /// That refusal is the point — the model this replaces accepted a
    /// profile naming a tag no list carried, kept no record of it, and
    /// filtered nothing.
    ///
    /// ```toml
    /// [profiles.finance]
    /// lists = { social = "deny" }
    ///
    /// [profiles.marketing]
    /// lists = { social = "allow" }
    /// ```
    ///
    /// **On `skip_serializing_if`.** The sibling precedent
    /// `accept_unsigned_allow` deliberately carries none
    /// (`accept_unsigned_allow_is_always_serialised_even_when_false`),
    /// because a `false` there is a *standing declaration* about risk and
    /// must stay legible in the operator's own TOML. That reasoning does not
    /// transfer: an empty override map declares nothing. Without the skip,
    /// every config-rewriting path (TUI save, `blocklist` verbs, backup
    /// round-trip, cluster policy) would grow an empty `[profiles.X.lists]`
    /// table in every profile of every operator's file, including profiles
    /// that never opted in. Pinned in both directions by
    /// `plp_s2_empty_lists_is_not_serialised` and
    /// `plp_s2_non_empty_lists_round_trips`.
    ///
    /// Declared last on the struct on purpose: TOML cannot emit a bare
    /// scalar after a table within the same table, so a map-valued field
    /// has to follow the scalars.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub lists: BTreeMap<Id, ListPolicy>,
}

/// Per-profile EDNS Client Subnet override.
///
/// Three knobs in this sub-table; each is `Option<...>` so an operator
/// can override one without enumerating the others (the omitted fields
/// fall back to `[upstream.ecs]`). The resolver chain is:
///
/// 1. `Profile.ecs.<field>` if `Some`
/// 2. else `[upstream.ecs].<field>`
/// 3. fallback `mode = Off`, prefixes `0`
///
/// ```toml
/// [profiles.kids]
/// display_name = "Kids"
///
/// [profiles.kids.ecs]
/// mode = "off"            # explicit override — no ECS even if upstream defaults to coarse
///
/// [profiles.work]
/// display_name = "Work laptops"
///
/// [profiles.work.ecs]
/// mode = "subnet"
/// source_prefix_v4 = 24   # forward /24 for CDN routing accuracy
/// source_prefix_v6 = 56
/// ```
///
/// `mode = "coarse"` ignores `source_prefix_v{4,6}` (hardcoded `/24` v4
/// and `/56` v6 per RFC 7871 §11 privacy-preserving recommendation).
/// `mode = "subnet"` uses the configured prefix; the validator rejects
/// `source_prefix_v4 > 32` and `source_prefix_v6 > 128`. `mode = "off"`
/// suppresses ECS injection regardless of upstream defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileEcsConfig {
    /// ECS routing mode. `None` → inherit from `[upstream.ecs].mode`.
    /// `Some(Off)` → force-off (overrides upstream default).
    /// `Some(Coarse)` → /24 v4 + /56 v6 fixed mask.
    /// `Some(Subnet)` → per-profile mask from
    /// [`Self::source_prefix_v4`] / [`Self::source_prefix_v6`].
    #[serde(default)]
    pub mode: Option<EcsMode>,
    /// IPv4 source prefix length (0..=32). Used only when
    /// `mode = "subnet"`. `None` → inherit
    /// `[upstream.ecs].source_prefix_v4`. Ignored under `coarse` (fixed
    /// `/24`) and `off`.
    #[serde(default)]
    pub source_prefix_v4: Option<u8>,
    /// IPv6 source prefix length (0..=128). Used only when
    /// `mode = "subnet"`. `None` → inherit
    /// `[upstream.ecs].source_prefix_v6`. Ignored under `coarse` (fixed
    /// `/56`) and `off`.
    #[serde(default)]
    pub source_prefix_v6: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_profile_deserialises() {
        let toml_src = r#"
display_name = "Default"
"#;
        let p: Profile = toml::from_str(toml_src).unwrap();
        assert_eq!(p.display_name, "Default");
        assert!(p.block_response.is_none());
        assert!(p.blocked_ttl_secs.is_none());
        assert!(p.admin_rules.is_empty());
    }

    #[test]
    fn full_profile_deserialises() {
        let toml_src = r#"
display_name = "Kids night"
block_response = "soa_nodata"
blocked_ttl_secs = 300
admin_rules = ["kids-allow-education"]
"#;
        let p: Profile = toml::from_str(toml_src).unwrap();
        assert_eq!(p.block_response, Some(BlockResponseV1::SoaNodata));
        assert_eq!(p.blocked_ttl_secs, Some(300));
        assert_eq!(p.admin_rules[0].as_str(), "kids-allow-education");
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "x"
made_up = true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    /// The v1 fields `blocklists` and `categories` are gone.
    /// `deny_unknown_fields` rejects them so a config carried over from
    /// v1 fails loudly instead of silently dropping its blocklist
    /// references.
    #[test]
    fn lc2_legacy_blocklists_field_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "default"
blocklists = ["privacy-ads"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn lc2_legacy_categories_field_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "default"
categories = ["privacy"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn all_block_response_variants_parse() {
        for (raw, want) in [
            ("zero", BlockResponseV1::Zero),
            ("nxdomain", BlockResponseV1::Nxdomain),
            ("refused", BlockResponseV1::Refused),
            ("soa_nodata", BlockResponseV1::SoaNodata),
        ] {
            let p: Profile =
                toml::from_str(&format!("display_name = \"x\"\nblock_response = \"{raw}\""))
                    .unwrap();
            assert_eq!(p.block_response, Some(want));
        }
    }

    #[test]
    fn unknown_block_response_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "x"
block_response = "panic"
"#,
        )
        .unwrap_err();
        // serde uses "unknown variant" not "invalid value" here.
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn ecs_subtable_absent_defaults_to_none() {
        let p: Profile = toml::from_str(r#"display_name = "x""#).unwrap();
        assert!(p.ecs.is_none());
    }

    #[test]
    fn ecs_off_deserialises() {
        let p: Profile = toml::from_str(
            r#"
display_name = "x"

[ecs]
mode = "off"
"#,
        )
        .unwrap();
        let ecs = p.ecs.expect("ecs subtable parsed");
        assert_eq!(ecs.mode, Some(EcsMode::Off));
        assert!(ecs.source_prefix_v4.is_none());
        assert!(ecs.source_prefix_v6.is_none());
    }

    #[test]
    fn ecs_coarse_deserialises() {
        let p: Profile = toml::from_str(
            r#"
display_name = "x"

[ecs]
mode = "coarse"
"#,
        )
        .unwrap();
        assert_eq!(p.ecs.unwrap().mode, Some(EcsMode::Coarse));
    }

    #[test]
    fn ecs_subnet_with_prefixes_deserialises() {
        let p: Profile = toml::from_str(
            r#"
display_name = "x"

[ecs]
mode = "subnet"
source_prefix_v4 = 24
source_prefix_v6 = 56
"#,
        )
        .unwrap();
        let ecs = p.ecs.unwrap();
        assert_eq!(ecs.mode, Some(EcsMode::Subnet));
        assert_eq!(ecs.source_prefix_v4, Some(24));
        assert_eq!(ecs.source_prefix_v6, Some(56));
    }

    #[test]
    fn ecs_inherit_partial_fields() {
        // Only mode is set — prefixes inherit from upstream defaults.
        let p: Profile = toml::from_str(
            r#"
display_name = "x"

[ecs]
mode = "subnet"
"#,
        )
        .unwrap();
        let ecs = p.ecs.unwrap();
        assert_eq!(ecs.mode, Some(EcsMode::Subnet));
        assert!(ecs.source_prefix_v4.is_none());
        assert!(ecs.source_prefix_v6.is_none());
    }

    #[test]
    fn ecs_unknown_field_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "x"

[ecs]
mode = "off"
mystery = 1
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn ecs_unknown_mode_rejected() {
        let err = toml::from_str::<Profile>(
            r#"
display_name = "x"

[ecs]
mode = "panic"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }
}
