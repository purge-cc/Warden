//! Profile types for per-client DNS filtering.
//!
//! A `ResolvedProfile` is the pre-computed, hot-path-ready form of a profile.
//! It contains a list bitmask for fast filter lookups, plus pre-parsed allow/deny
//! domain sets for subdomain-walk matching.
//!
//! Rules are split across two paths:
//! - **Fast path**: Simple exact domain rules → `HashSet` with O(1) subdomain walk
//! - **Slow path**: Advanced rules (wildcard, regex, `$important`) → `Vec<DnsRule>`

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use ahash::RandomState;
use compact_str::CompactString;

use crate::config::custom_list::CustomListStore;
use crate::config::schema::{
    effective_direction, AdminRule, BlockResponseV1, Blocklist, Device, Group, Id, ListPolicy,
    Profile, ProfileEcsConfig, ServerGlobals,
};
use crate::config::settings::{EcsConfig, EcsMode};
use crate::dns::edns::{AddressFamily, EdnsClientSubnet};
use crate::dns::local_profile::ProfileLocalRecords;
use crate::dns::rewrite::ProfileRewriteRules;
use crate::filter::rules::{self, DnsRule, RuleAction};

/// The per-resolution ECS knob carried by every
/// [`ResolvedProfile`]. Pre-flattened from `Profile.ecs` + the global
/// `[upstream.ecs]` defaults at resolver-map build time, so the DNS
/// hot path only reads `Copy` scalars — no Option chains, no dictionary
/// lookups.
///
/// Two-mode-plus-off model:
///
/// - `EcsMode::Off` → [`Self::build_option`] returns `None`; the
///   upstream wire carries no ECS option at all.
/// - `EcsMode::Coarse` → fixed `/24` IPv4 or `/56` IPv6 mask (RFC 7871
///   §11 privacy-preserving recommendation). [`Self::source_prefix_v4`]
///   and [`Self::source_prefix_v6`] are **ignored** under this mode.
/// - `EcsMode::Subnet` → uses the configured prefix lengths, masking
///   the client IP at query time.
///
/// The struct is `Copy` so the hot path can pass it by value to the
/// upstream without `Arc::clone`. Two `u8` fields + one enum tag fit in
/// a single register; the compiler is free to inline `build_option`
/// into the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcsPolicy {
    pub mode: EcsMode,
    pub source_prefix_v4: u8,
    pub source_prefix_v6: u8,
}

impl EcsPolicy {
    /// Privacy-preserving default: never emit ECS. Matches the
    /// behaviour of any config that leaves `[upstream.ecs].enabled =
    /// false` (the master kill-switch).
    pub const OFF: Self = Self {
        mode: EcsMode::Off,
        source_prefix_v4: 0,
        source_prefix_v6: 0,
    };

    /// IPv4 prefix when [`EcsMode::Coarse`] is selected. RFC 7871 §11
    /// "privacy considerations" suggests `/24` as the default
    /// privacy-vs-utility trade-off — it identifies the CDN region but
    /// not the household.
    pub const COARSE_PREFIX_V4: u8 = 24;

    /// IPv6 prefix when [`EcsMode::Coarse`] is selected. `/56` matches
    /// the typical IPv6 delegation boundary (RFC 6177 §4.4) — broad
    /// enough that a single residential prefix maps to one ECS bucket.
    pub const COARSE_PREFIX_V6: u8 = 56;

    /// Resolve the per-profile policy from a (possibly absent)
    /// `Profile.ecs` sub-table layered onto the global `[upstream.ecs]`
    /// defaults. Inner-`Option` fields on
    /// [`ProfileEcsConfig`] inherit per-field.
    ///
    /// **Master kill-switch:** when
    /// [`crate::config::settings::EcsConfig::enabled`] is `false`, the
    /// resolved policy short-circuits to [`Self::OFF`] regardless of
    /// any per-profile override. This is the operator's emergency stop
    /// — flip the global flag and every profile stops emitting ECS at
    /// once, even if a profile carries `mode = "subnet"`.
    pub fn from_profile_and_upstream(
        profile_ecs: Option<&ProfileEcsConfig>,
        upstream_ecs: &EcsConfig,
    ) -> Self {
        if !upstream_ecs.enabled {
            return Self::OFF;
        }
        let (mode, p4, p6) = match profile_ecs {
            Some(pe) => (
                pe.mode.unwrap_or(upstream_ecs.mode),
                pe.source_prefix_v4.unwrap_or(upstream_ecs.source_prefix_v4),
                pe.source_prefix_v6.unwrap_or(upstream_ecs.source_prefix_v6),
            ),
            None => (
                upstream_ecs.mode,
                upstream_ecs.source_prefix_v4,
                upstream_ecs.source_prefix_v6,
            ),
        };
        Self {
            mode,
            source_prefix_v4: p4,
            source_prefix_v6: p6,
        }
    }

    /// Build the per-query ECS option for `client_ip`. Returns `None`
    /// when the policy is [`EcsMode::Off`], when the codec rejects the
    /// inputs, or when the client address family is otherwise
    /// unsupported. The address is masked to `source_prefix` bits
    /// (Coarse: hardcoded; Subnet: configured) and the codec performs
    /// the RFC 7871 §6 zero-bit padding inside the wrapper.
    ///
    /// **Hot path:** called once per upstream-bound query when ECS is
    /// active. The function is pure, branch-light, and the returned
    /// [`EdnsClientSubnet`] is `Clone + Copy`-ish (currently the inner
    /// `hickory_proto::rr::rdata::opt::ClientSubnet` clones via
    /// `derive(Clone)`).
    pub fn build_option(&self, client_ip: IpAddr) -> Option<EdnsClientSubnet> {
        let prefix = match self.mode {
            EcsMode::Off => return None,
            EcsMode::Coarse => match client_ip {
                IpAddr::V4(_) => Self::COARSE_PREFIX_V4,
                IpAddr::V6(_) => Self::COARSE_PREFIX_V6,
            },
            EcsMode::Subnet => match client_ip {
                IpAddr::V4(_) => self.source_prefix_v4,
                IpAddr::V6(_) => self.source_prefix_v6,
            },
        };
        EdnsClientSubnet::new(client_ip, prefix).ok()
    }

    /// Family helper for the rare call site that needs to know what
    /// address family the policy would mask if it had to emit. Useful
    /// for the audit log when [`Self::build_option`] returns `None`
    /// because the codec rejected the prefix.
    pub fn family_for(client_ip: IpAddr) -> AddressFamily {
        match client_ip {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

impl Default for EcsPolicy {
    fn default() -> Self {
        Self::OFF
    }
}

/// The groups a device belongs to.
///
/// Membership is symmetric and either direction counts: `group.devices`
/// listing the device, or `device.groups` listing the group. The
/// validator already treats both as binding (`check_groups`), so the
/// resolver must too, or a config that validates clean would filter
/// differently from what it was validated as.
pub fn groups_for_device<'a>(device: &Device, all: &'a [Group]) -> Vec<&'a Group> {
    all.iter()
        .filter(|g| g.devices.contains(&device.id) || device.groups.contains(&g.id))
        .collect()
}

/// Pre-computed profile ready for the DNS hot path.
///
/// Built from v1 [`Profile`] + [`AdminRule`] + [`ServerGlobals`] + a list-to-bit
/// mapping. All fields are immutable after construction — profiles are
/// replaced atomically via `ArcSwap`.
#[derive(Debug)]
pub struct ResolvedProfile {
    /// Profile id (e.g. "default", "kids").
    pub name: CompactString,
    /// This resolution opts out of **list** filtering entirely
    /// (`[[devices]].unfiltered = true`).
    ///
    /// # Why this is a bool and not a mask
    ///
    /// Subscription and direction are one per-profile pair
    /// ([`crate::filter::engine::ProfileMasks`]) held **beside the corpus**,
    /// materialised at publish time against the bit assignment that will
    /// actually serve the query.
    ///
    /// A mask could not stay here. List bits are **positional**
    /// (`lists::source_key`, `enumerate()`), and this struct is published by
    /// the config-reload path under a *different* `ArcSwap` from the corpus,
    /// so a mask travelling with a profile can meet a corpus that has since
    /// re-assigned the bits it names — and the superset error puts a
    /// deny-list's bit on the allow side, where allow beats block and the
    /// list silently stops blocking.
    ///
    /// A **boolean** is safe in a way a mask is not: it names no list, so it
    /// cannot point at the wrong one. Stale it can only be by one reload, and
    /// it is rebuilt by the same pass that rebuilds everything else here.
    pub unfiltered: bool,
    /// Domains that override blocks (parsed from `@@||domain^` admin rules).
    /// Checked with subdomain walk — allowing "example.com" also allows "sub.example.com".
    ///
    /// **Shared, not copied.** This set is
    /// profile-static: [`Self::as_unfiltered`] varies only
    /// [`Self::unfiltered`], so every specialised profile
    /// clones the `Arc` rather than the table. Before the change a config
    /// with 1000 devices carried 1000 private copies — all of them resident
    /// for the lifetime of the config generation, because each specialised
    /// profile is stored in the `ResolverMap` and read by the hot path.
    /// Matches the `Arc` convention the struct already uses for
    /// [`Self::local_records`] / [`Self::rewrite_rules`].
    pub allow_domains: Arc<HashSet<CompactString, RandomState>>,
    /// Domains explicitly blocked by this profile (parsed from `||domain^` admin rules).
    /// Checked with subdomain walk.
    ///
    /// Shared across specialisations — see [`Self::allow_domains`].
    pub deny_domains: Arc<HashSet<CompactString, RandomState>>,
    /// If true, block ALL queries unless an allow rule matches. Ported
    /// 1:1 from the legacy v0 profile model.
    pub block_all: bool,
    /// Advanced rules: wildcard, regex, and `$important` admin rules that
    /// don't fit in the HashSet fast path. Evaluated by
    /// `filter::evaluator::evaluate_rules`.
    ///
    /// Shared across specialisations — see [`Self::allow_domains`].
    pub rules: Arc<Vec<DnsRule>>,
    /// Wire-level response when a query is blocked under this profile.
    /// Pre-resolved at build time (either the profile's own
    /// `block_response` or the global
    /// `ServerGlobals::default_block_response`).
    pub block_response: BlockResponseV1,
    /// TTL (seconds) applied to the canned block response. Pre-resolved
    /// at build time.
    pub blocked_ttl_secs: u32,
    /// Profile-scoped local DNS records (A/AAAA/CNAME). Built
    /// once at resolver-map construction from `Profile.local_records`
    /// (already validated) + the global `[local_dns].ttl_secs` fallback.
    /// Hot-path probe is `Arc::clone` (free, the resolver loaded the
    /// `ResolvedProfile` already) + one `HashMap::get` + an optional
    /// bounded suffix walk gated on `has_subdomain_records`. Empty by
    /// default, so a profile with no local records pays zero overhead.
    pub local_records: Arc<ProfileLocalRecords>,
    /// Profile-scoped name-to-name rewrite engine. Empty by default —
    /// a profile with no rewrites pays zero overhead. Hot-path probe is
    /// `Arc::clone` (free) + one `HashMap::get` + optional bounded suffix
    /// walk gated on `has_subdomain_rules`. Engine in
    /// [`crate::dns::rewrite::ProfileRewriteRules`].
    pub rewrite_rules: Arc<ProfileRewriteRules>,
    /// Per-resolution ECS policy. Pre-flattened from
    /// the per-profile [`Profile::ecs`] override + the global
    /// `[upstream.ecs]` defaults at resolver-map build time, so the
    /// DNS hot path reads a `Copy` value with zero pointer chasing.
    ///
    /// **Default-OFF construction:** [`Self::build_v1`]
    /// leaves this at [`EcsPolicy::OFF`]. The production resolver-map
    /// builder (`crate::profiles::resolver::build_resolver_map`)
    /// overrides it after construction with
    /// [`EcsPolicy::from_profile_and_upstream`] so tests that hit
    /// `build_v1` directly stay on the baseline. The
    /// `[upstream.ecs].enabled` master kill-switch is enforced at the
    /// call site — when `enabled = false`, the upstream skips the
    /// build_option call regardless of policy value.
    pub ecs_policy: EcsPolicy,
}

impl ResolvedProfile {
    /// Build a resolved profile from v1 schema entities.
    ///
    /// `admin_rules_by_id` maps every admin-rule id declared in the config
    /// to its parsed entity, so the profile's `admin_rules` list can resolve
    /// to real patterns. Rules are classified the same way the legacy
    /// `Self::build` did: simple exact domains (no `$important`, no
    /// wildcard) go into the [`Self::allow_domains`] / [`Self::deny_domains`]
    /// fast-path HashSets; everything else goes into [`Self::rules`].
    ///
    /// **No list state reaches this struct.** Which lists a profile
    /// subscribes to, and in which direction, is one question with one
    /// answer — `profiles.<id>.lists` over each list's `base` — projected
    /// onto the corpus generation's bits by
    /// `lists::source_key::SourceBitMap::project_policy` and published in the
    /// same `Arc` as the entries it interprets.
    ///
    /// `server` supplies the fallbacks for `block_response` and
    /// `blocked_ttl_secs`: the profile's own value wins when set, otherwise
    /// the daemon-wide default applies. The fallback is applied here so the
    /// DNS hot path does a single `Arc::load` and reads the final values
    /// without an extra lookup.
    ///
    pub fn build_v1(
        id: &Id,
        profile: &Profile,
        admin_rules_by_id: &BTreeMap<&Id, &AdminRule>,
        custom_lists: &CustomListStore,
        server: &ServerGlobals,
        default_local_dns_ttl_secs: u32,
    ) -> Self {
        let mut allow_domains = HashSet::with_hasher(RandomState::new());
        let mut deny_domains = HashSet::with_hasher(RandomState::new());
        let mut adv_rules = Vec::new();

        for rule_ref in &profile.admin_rules {
            let Some(rule_def) = admin_rules_by_id.get(rule_ref) else {
                // Validator should have caught a dangling reference, but
                // in case it slips through we skip rather than panic: the
                // profile simply has one less rule, and the validator
                // will reject the next reload.
                continue;
            };
            let parsed = rules::parse_rules(&rule_def.rule);
            if parsed.is_empty() && !rule_def.rule.trim().is_empty() {
                // Drift guard: the validator
                // dry-runs the same parser, so this fires only if a config
                // bypassed validation (or the two paths diverged). Cold
                // path — the double parse is for the error detail only.
                let reason = rules::parse_rule_checked(&rule_def.rule)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                tracing::warn!(
                    profile = %id.as_str(),
                    rule_id = %rule_def.id.as_str(),
                    rule = %rule_def.rule,
                    %reason,
                    "admin rule failed to parse at resolver build — rule enforces nothing"
                );
            }
            for r in parsed {
                match r.action {
                    RuleAction::Allow if r.is_simple_exact() => {
                        if let Some(d) = r.exact_domain() {
                            allow_domains.insert(d.clone());
                        }
                    }
                    RuleAction::Block if r.is_simple_exact() => {
                        if let Some(d) = r.exact_domain() {
                            deny_domains.insert(d.clone());
                        }
                    }
                    _ => adv_rules.push(r),
                }
            }
        }

        // Custom lists occupy the same seat as the operator's own admin
        // rules and land straight in the two hash sets. The grammar admits
        // only two forms, so nothing here can reach the advanced-rule
        // vector, which is walked linearly on every query.
        for list_ref in &profile.custom_lists {
            let Some(compiled) = custom_lists.get(list_ref) else {
                // Validator refuses a dangling mount; skip rather than
                // panic if one slips through, exactly as the admin-rule
                // arm above does.
                continue;
            };
            allow_domains.extend(compiled.allow.iter().cloned());
            deny_domains.extend(compiled.deny.iter().cloned());
        }

        let block_response = profile
            .block_response
            .unwrap_or(server.default_block_response);
        let blocked_ttl_secs = profile
            .blocked_ttl_secs
            .unwrap_or(server.default_blocked_ttl_secs);

        let local_records = Arc::new(ProfileLocalRecords::build(
            &profile.local_records,
            default_local_dns_ttl_secs,
        ));
        let rewrite_rules = if profile.safe_search {
            let mut effective = profile.rewrite_rules.clone();
            crate::profiles::safesearch::populate(&mut effective);
            Arc::new(ProfileRewriteRules::build(&effective))
        } else {
            Arc::new(ProfileRewriteRules::build(&profile.rewrite_rules))
        };

        Self {
            name: CompactString::new(id.as_str()),
            unfiltered: false,
            allow_domains: Arc::new(allow_domains),
            deny_domains: Arc::new(deny_domains),
            block_all: profile.block_all,
            rules: Arc::new(adv_rules),
            block_response,
            blocked_ttl_secs,
            local_records,
            rewrite_rules,
            ecs_policy: EcsPolicy::OFF,
        }
    }

    /// Build a permissive default profile — forwards everything, filters
    /// nothing.
    ///
    /// **Test scaffolding. No resolution path may reach it.** A client the
    /// chain cannot place gets a
    /// [`Resolution`](crate::profiles::resolver::Resolution) carrying no
    /// profile, and the query is refused. Handing that client this profile
    /// instead would make the *unknown* client the least filtered one on the
    /// network, which inverts the rule that an unrecognised client gets the
    /// strictest treatment, not the loosest.
    ///
    /// Not `#[cfg(test)]`-gated only because integration tests in `tests/`
    /// build against the library without that cfg.
    pub fn permissive_default() -> Self {
        Self {
            name: CompactString::new("default"),
            unfiltered: true,
            allow_domains: Arc::new(HashSet::with_hasher(RandomState::new())),
            deny_domains: Arc::new(HashSet::with_hasher(RandomState::new())),
            block_all: false,
            rules: Arc::new(Vec::new()),
            block_response: BlockResponseV1::Zero,
            blocked_ttl_secs: 60,
            local_records: Arc::new(ProfileLocalRecords::default()),
            rewrite_rules: Arc::new(ProfileRewriteRules::default()),
            ecs_policy: EcsPolicy::OFF,
        }
    }

    /// The same profile, with **list** filtering switched off for one
    /// resolution — `[[devices]].unfiltered = true`.
    ///
    /// # Why list policy is not per-device
    ///
    /// Policy is a property of the *profile*: two devices on one profile
    /// cannot see different lists. `warden migrate v2-to-v3` refuses a
    /// config that has devices carrying per-device list tags rather than
    /// flattening it silently.
    ///
    /// `unfiltered` is not a list-policy question: it is a device saying
    /// "do not filter me", independent of which lists the profile
    /// subscribes to.
    ///
    /// Every other field is profile-static and shares its `Arc` — see
    /// [`Self::allow_domains`] for the measurement that made that matter.
    /// **Only the list layer is skipped.** `block_all`, admin rules and the
    /// `allow_domains` / `deny_domains` sets still apply, exactly as they did
    /// when `unfiltered` worked by emptying the tag set.
    #[must_use]
    pub fn as_unfiltered(&self) -> Self {
        Self {
            name: self.name.clone(),
            unfiltered: true,
            allow_domains: self.allow_domains.clone(),
            deny_domains: self.deny_domains.clone(),
            block_all: self.block_all,
            rules: self.rules.clone(),
            block_response: self.block_response,
            blocked_ttl_secs: self.blocked_ttl_secs,
            local_records: self.local_records.clone(),
            rewrite_rules: self.rewrite_rules.clone(),
            ecs_policy: self.ecs_policy,
        }
    }
}

/// Per-device overlay attached to the resolver state.
///
/// Holds two `Arc<HashSet>` carrying the *exact-or-subdomain* allow / deny
/// domains derived from the device's `allow_rules` / `deny_rules` admin
/// rule references. Lives next to [`Arc<ResolvedProfile>`] in the
/// resolver's private `ResolverMap` so a single atomic
/// `ArcSwap` snapshot delivers both pointers consistently — no torn
/// reads possible across reload boundaries.
///
/// Hot-path access: two `HashSet::contains` probes per query, zero
/// allocation, zero lock. The overlay is computed at config build /
/// reload time, not at query time, so adding rules to a device costs
/// at most one rebuild + one ArcSwap store.
///
/// **Qtype invariant:** the sets are keyed on domain only.
/// `apply_overlay` therefore returns the same decision for `A` and
/// `AAAA` of the same name — preserving the symmetric-block invariant
/// the rest of the daemon relies on. Input validation rejects any
/// rule that uses `$dnstype=` modifier so this invariant cannot be
/// undermined at write time.
#[derive(Debug, Clone)]
pub struct DeviceOverlay {
    /// Stable id of the device this overlay is attached to. Used by the
    /// hot path to populate `RuleSource::Device(id)` attribution when a
    /// probe hits.
    pub device_id: Id,
    /// Domains whose admin-rule was an `@@||domain^`-form allow. Subdomain
    /// walk applies (allowing `example.com` also allows `sub.example.com`).
    pub allow: Arc<HashSet<CompactString, RandomState>>,
    /// Domains whose admin-rule was a `||domain^`-form deny. Subdomain
    /// walk applies.
    pub deny: Arc<HashSet<CompactString, RandomState>>,
    /// When `true`, an `allow` hit is permitted to override a
    /// profile-level deny on the same domain. When `false`, the CLI / TUI
    /// refuses such writes at edit time, and the daemon defensively
    /// prefers the profile deny on any drift it observes.
    pub override_profile_deny: bool,
}

impl DeviceOverlay {
    /// Build a `DeviceOverlay` for `device` from the deduplicated
    /// `admin_rules_by_id` map shared with [`ResolvedProfile::build_v1`].
    ///
    /// Returns `None` when both `device.allow_rules` and
    /// `device.deny_rules` are empty — there is no overlay state to
    /// carry, and the resolver's `Resolution.overlay = None` triggers
    /// the unchanged hot path. Empty-overlay devices pay zero overhead.
    ///
    /// Domain extraction mirrors [`ResolvedProfile::build_v1`]: simple
    /// exact `||domain^` / `@@||domain^` forms land in the HashSets;
    /// wildcard / `$important` / regex rules are dropped silently —
    /// the per-device overlay only models exact-or-subdomain matching
    /// ("device-allow has effect ONLY if the profile does not have an
    /// explicit deny on the same domain"). The input validator rejects
    /// non-exact rule shapes at write time so this branch should be
    /// unreachable on a fresh config; defensive on drift.
    ///
    /// Dangling rule references (id not in `admin_rules_by_id`) are
    /// also skipped — the validator catches them earlier with a
    /// cross-ref error; in case of drift the overlay simply has one
    /// less rule, never panics.
    pub fn build_v1(
        device: &Device,
        admin_rules_by_id: &BTreeMap<&Id, &AdminRule>,
    ) -> Option<Arc<Self>> {
        if device.allow_rules.is_empty() && device.deny_rules.is_empty() {
            return None;
        }

        let mut allow = HashSet::with_hasher(RandomState::new());
        let mut deny = HashSet::with_hasher(RandomState::new());

        for rule_id in &device.allow_rules {
            let Some(rule_def) = admin_rules_by_id.get(rule_id) else {
                continue;
            };
            let mut contributed = false;
            for r in rules::parse_rules(&rule_def.rule) {
                if r.action == RuleAction::Allow && r.is_simple_exact() {
                    if let Some(d) = r.exact_domain() {
                        allow.insert(d.clone());
                        contributed = true;
                    }
                }
            }
            // A referenced rule that yields no simple-exact allow
            // domain is silently dropped from the overlay (only exact
            // `||domain^` / `@@||domain^` forms are modelled). Make the
            // drop observable so hand-edited drift past the validator
            // shows up in the log instead of failing open in silence.
            if !contributed {
                tracing::warn!(
                    device = %device.id.as_str(),
                    rule = %rule_id.as_str(),
                    "device allow rule dropped from overlay: only simple exact \
                     forms are honoured (wildcard / $important / regex unsupported)",
                );
            }
        }

        for rule_id in &device.deny_rules {
            let Some(rule_def) = admin_rules_by_id.get(rule_id) else {
                continue;
            };
            let mut contributed = false;
            for r in rules::parse_rules(&rule_def.rule) {
                if r.action == RuleAction::Block && r.is_simple_exact() {
                    if let Some(d) = r.exact_domain() {
                        deny.insert(d.clone());
                        contributed = true;
                    }
                }
            }
            if !contributed {
                tracing::warn!(
                    device = %device.id.as_str(),
                    rule = %rule_id.as_str(),
                    "device deny rule dropped from overlay: only simple exact \
                     forms are honoured (wildcard / $important / regex unsupported)",
                );
            }
        }

        // After parsing, both sets may end up empty when every referenced
        // rule was non-simple (wildcard / important / regex). Returning
        // `None` here keeps the byte-identical baseline for the empty
        // case — no overlay attached, hot path unchanged.
        if allow.is_empty() && deny.is_empty() {
            return None;
        }

        Some(Arc::new(Self {
            device_id: device.id.clone(),
            allow: Arc::new(allow),
            deny: Arc::new(deny),
            override_profile_deny: device.override_profile_deny,
        }))
    }
}

/// TUI-facing offline accessor: the blocklist ids a profile actually
/// filters on, computed the SAME way the daemon does at publish time.
///
/// The question is "every enabled list whose effective direction for
/// this profile is not `ignore`" — `profiles.<id>.lists` over each
/// list's own `base`, via the one canonical predicate
/// [`crate::config::schema::effective_direction`].
///
/// Kept as a single public entry point for the same reason it was created:
/// the read-only Profiles-tab "What it blocks" summary and
/// `warden lists …` must ask the *engine's* question, not a second copy of
/// it.
///
/// Disabled lists are excluded: they never reach the merged sources vector,
/// so they hold no bit and cannot contribute a verdict.
///
/// Returned sorted, so callers can diff two profiles without re-sorting.
#[must_use]
pub fn resolve_profile_blocklist_ids(profile: &Profile, blocklists: &[Blocklist]) -> Vec<Id> {
    let mut ids: Vec<Id> = blocklists
        .iter()
        .filter(|b| b.enabled && effective_direction(profile, b) != ListPolicy::Ignore)
        .map(|b| b.id.clone())
        .collect();
    ids.sort();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{AdminRule, Group, Id, Profile, ServerGlobals};

    fn mk_rule(id: &str, rule: &str) -> AdminRule {
        AdminRule {
            id: Id::new(id).unwrap(),
            rule: rule.to_string(),
        }
    }

    fn rules_by_id(rules: &[AdminRule]) -> BTreeMap<&Id, &AdminRule> {
        rules.iter().map(|r| (&r.id, r)).collect()
    }

    #[test]
    fn build_v1_routes_simple_rules_into_hashsets() {
        let rules = vec![
            mk_rule("allow-wiki", "@@||wikipedia.org^"),
            mk_rule("deny-tik", "||tiktok.com^"),
        ];
        let profile = Profile {
            display_name: "kids".into(),
            admin_rules: vec![Id::new("allow-wiki").unwrap(), Id::new("deny-tik").unwrap()],
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("kids").unwrap(),
            &profile,
            &rules_by_id(&rules),
            &crate::config::custom_list::CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        assert_eq!(rp.allow_domains.len(), 1);
        assert!(rp.allow_domains.contains("wikipedia.org"));
        assert_eq!(rp.deny_domains.len(), 1);
        assert!(rp.deny_domains.contains("tiktok.com"));
        assert!(rp.rules.is_empty());
    }

    #[test]
    fn build_v1_propagates_wildcard_and_important_into_rules() {
        let rules = vec![
            mk_rule("important-allow", "@@||safe.com^$important"),
            mk_rule("wild-deny", "||*.ads.example.com^"),
        ];
        let profile = Profile {
            display_name: "mixed".into(),
            admin_rules: vec![
                Id::new("important-allow").unwrap(),
                Id::new("wild-deny").unwrap(),
            ],
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("mixed").unwrap(),
            &profile,
            &rules_by_id(&rules),
            &crate::config::custom_list::CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        // Important allow → rules; wildcard apex auto-expansion → deny_domains.
        assert!(rp.deny_domains.contains("ads.example.com"));
        assert!(!rp.rules.is_empty());
    }

    #[test]
    fn build_v1_applies_n6_block_response_fallback() {
        // Profile leaves block_response unset → must inherit from server.
        let profile = Profile {
            display_name: "p".into(),
            ..Default::default()
        };
        let server = ServerGlobals {
            default_block_response: BlockResponseV1::SoaNodata,
            default_blocked_ttl_secs: 180,
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("p").unwrap(),
            &profile,
            &BTreeMap::new(),
            &crate::config::custom_list::CustomListStore::new(),
            &server,
            60,
        );
        assert_eq!(rp.block_response, BlockResponseV1::SoaNodata);
        assert_eq!(rp.blocked_ttl_secs, 180);
    }

    #[test]
    fn build_v1_profile_override_wins_over_server_default() {
        let profile = Profile {
            display_name: "strict".into(),
            block_response: Some(BlockResponseV1::Nxdomain),
            blocked_ttl_secs: Some(30),
            ..Default::default()
        };
        let server = ServerGlobals {
            default_block_response: BlockResponseV1::Zero,
            default_blocked_ttl_secs: 300,
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("strict").unwrap(),
            &profile,
            &BTreeMap::new(),
            &crate::config::custom_list::CustomListStore::new(),
            &server,
            60,
        );
        assert_eq!(rp.block_response, BlockResponseV1::Nxdomain);
        assert_eq!(rp.blocked_ttl_secs, 30);
    }

    #[test]
    fn build_v1_unknown_admin_rule_reference_is_skipped() {
        // Dangling reference (validator would have caught it). Build must
        // not panic and must simply produce a rule-less profile.
        let profile = Profile {
            display_name: "dangling".into(),
            admin_rules: vec![Id::new("does-not-exist").unwrap()],
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("p").unwrap(),
            &profile,
            &BTreeMap::new(),
            &crate::config::custom_list::CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        assert!(rp.allow_domains.is_empty());
        assert!(rp.deny_domains.is_empty());
        assert!(rp.rules.is_empty());
    }

    #[test]
    fn build_v1_preserves_block_all() {
        let profile = Profile {
            display_name: "night".into(),
            block_all: true,
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("night").unwrap(),
            &profile,
            &BTreeMap::new(),
            &crate::config::custom_list::CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        assert!(rp.block_all);
    }

    fn store_with(id: &str, allow: &[&str], deny: &[&str]) -> CustomListStore {
        let mut s = CustomListStore::new();
        s.insert(
            Id::new(id).unwrap(),
            crate::config::custom_list::CompiledCustomList {
                allow: allow.iter().map(|d| CompactString::new(d)).collect(),
                deny: deny.iter().map(|d| CompactString::new(d)).collect(),
                skipped: 0,
            },
        );
        s
    }

    #[test]
    fn a_custom_list_allow_rule_reaches_allow_domains() {
        // Falsifies directly the hypothesis that these files pass through
        // the external-list parser, whose sandbox strips `@@`.
        let profile = Profile {
            custom_lists: vec![Id::new("minecraft").unwrap()],
            ..Default::default()
        };
        let store = store_with("minecraft", &["cdn.example.com"], &["ads.example.com"]);
        let rp = ResolvedProfile::build_v1(
            &Id::new("kids").unwrap(),
            &profile,
            &BTreeMap::new(),
            &store,
            &ServerGlobals::default(),
            60,
        );
        assert!(rp.allow_domains.contains("cdn.example.com"));
        assert!(rp.deny_domains.contains("ads.example.com"));
    }

    #[test]
    fn the_advanced_rule_vector_stays_empty_whatever_a_custom_list_holds() {
        // The hot-path guard. `priority_scan` walks this vector linearly on
        // every query; a file the operator can grow to tens of thousands of
        // lines must not be able to add to it. The grammar already refuses
        // the advanced forms, so nothing reaching the store can land here —
        // this pins that the routing keeps it that way.
        let profile = Profile {
            custom_lists: vec![Id::new("minecraft").unwrap()],
            ..Default::default()
        };
        let store = store_with(
            "minecraft",
            &["a.example.com", "b.example.com"],
            &["c.example.com", "d.example.com"],
        );
        let rp = ResolvedProfile::build_v1(
            &Id::new("kids").unwrap(),
            &profile,
            &BTreeMap::new(),
            &store,
            &ServerGlobals::default(),
            60,
        );
        assert!(
            rp.rules.is_empty(),
            "a custom list must never reach the linearly scanned rule vector"
        );
    }

    #[test]
    fn build_v1_does_not_touch_the_disk() {
        // The 60-second schedule tick rebuilds every profile. File I/O in
        // here would be N reads a minute AND a third code path — neither
        // cold start nor reload — that nothing specifies. There is no
        // packs/ directory anywhere in this test.
        let profile = Profile {
            custom_lists: vec![Id::new("minecraft").unwrap()],
            ..Default::default()
        };
        let store = store_with("minecraft", &["cdn.example.com"], &[]);
        for _ in 0..3 {
            let rp = ResolvedProfile::build_v1(
                &Id::new("kids").unwrap(),
                &profile,
                &BTreeMap::new(),
                &store,
                &ServerGlobals::default(),
                60,
            );
            assert!(rp.allow_domains.contains("cdn.example.com"));
        }
    }

    #[test]
    fn two_mounted_lists_both_contribute() {
        // Cardinality two, not one: a fixture with a single element cannot
        // tell `all` from `any`, or a loop from a `first()`.
        let profile = Profile {
            custom_lists: vec![Id::new("a").unwrap(), Id::new("b").unwrap()],
            ..Default::default()
        };
        let mut store = store_with("a", &["one.example.com"], &[]);
        store.extend(store_with("b", &["two.example.com"], &[]));
        let rp = ResolvedProfile::build_v1(
            &Id::new("kids").unwrap(),
            &profile,
            &BTreeMap::new(),
            &store,
            &ServerGlobals::default(),
            60,
        );
        assert!(rp.allow_domains.contains("one.example.com"));
        assert!(rp.allow_domains.contains("two.example.com"));
    }

    #[test]
    fn a_mount_missing_from_the_store_is_skipped_not_panicked_on() {
        // The validator refuses a dangling reference, so this is the
        // defensive arm — same shape as the existing admin-rule miss.
        let profile = Profile {
            custom_lists: vec![Id::new("ghost").unwrap()],
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("kids").unwrap(),
            &profile,
            &BTreeMap::new(),
            &CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        assert!(rp.allow_domains.is_empty() && rp.deny_domains.is_empty());
    }

    // ── DeviceOverlay::build_v1 ───────────────────────────────────

    fn empty_device(id: &str) -> Device {
        Device {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            ip: Some("10.0.0.1".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    #[test]
    fn overlay_build_returns_none_when_device_has_no_rules() {
        // Empty allow_rules + deny_rules → no overlay attached → the
        // hot path is unchanged.
        let dev = empty_device("phone");
        let overlay = DeviceOverlay::build_v1(&dev, &BTreeMap::new());
        assert!(overlay.is_none());
    }

    #[test]
    fn overlay_build_routes_simple_allow_into_set() {
        let rules = vec![mk_rule("allow-bank", "@@||bank.example^")];
        let mut dev = empty_device("phone");
        dev.allow_rules = vec![Id::new("allow-bank").unwrap()];

        let overlay = DeviceOverlay::build_v1(&dev, &rules_by_id(&rules)).unwrap();
        assert_eq!(overlay.device_id.as_str(), "phone");
        assert!(overlay.allow.contains("bank.example"));
        assert!(overlay.deny.is_empty());
        assert!(!overlay.override_profile_deny);
    }

    #[test]
    fn overlay_build_routes_simple_deny_into_set() {
        let rules = vec![mk_rule("deny-tiktok", "||tiktok.com^")];
        let mut dev = empty_device("phone");
        dev.deny_rules = vec![Id::new("deny-tiktok").unwrap()];

        let overlay = DeviceOverlay::build_v1(&dev, &rules_by_id(&rules)).unwrap();
        assert!(overlay.deny.contains("tiktok.com"));
        assert!(overlay.allow.is_empty());
    }

    #[test]
    fn overlay_build_preserves_override_flag() {
        // override_profile_deny is the per-device gate enabling an
        // allow to win over a profile-level deny on the same domain.
        // Always carried on the overlay so the hot path can read it
        // without consulting the original DeviceConfig (which lives
        // behind a separate ArcSwap snapshot).
        let rules = vec![mk_rule("allow-bank", "@@||bank.example^")];
        let mut dev = empty_device("phone");
        dev.allow_rules = vec![Id::new("allow-bank").unwrap()];
        dev.override_profile_deny = true;

        let overlay = DeviceOverlay::build_v1(&dev, &rules_by_id(&rules)).unwrap();
        assert!(overlay.override_profile_deny);
    }

    #[test]
    fn overlay_build_skips_unknown_rule_id() {
        // Validator catches dangling refs earlier; defensive in case
        // of drift the overlay just has fewer rules.
        let mut dev = empty_device("phone");
        dev.allow_rules = vec![Id::new("does-not-exist").unwrap()];
        dev.deny_rules = vec![Id::new("also-missing").unwrap()];

        // No rule in the map → both sets resolve empty → overlay is None.
        let overlay = DeviceOverlay::build_v1(&dev, &BTreeMap::new());
        assert!(overlay.is_none());
    }

    #[test]
    fn overlay_build_drops_non_simple_rules() {
        // Wildcards / regex / $important shapes are not modelled by
        // the per-device overlay (the input validator rejects them at
        // write time). Defensive on drift: rule is silently skipped.
        let rules = vec![
            mk_rule("wild-allow", "@@||*.bank.example^"),
            mk_rule("important-allow", "@@||safe.com^$important"),
        ];
        let mut dev = empty_device("phone");
        dev.allow_rules = vec![
            Id::new("wild-allow").unwrap(),
            Id::new("important-allow").unwrap(),
        ];

        // Wildcard rule auto-expands to apex (`bank.example`) per the
        // existing `parse_rules` helper, so it DOES land in the set.
        // The `$important` form, on the other hand, fails
        // `is_simple_exact()` and is dropped.
        let overlay = DeviceOverlay::build_v1(&dev, &rules_by_id(&rules)).unwrap();
        assert!(overlay.allow.contains("bank.example"));
        assert!(!overlay.allow.contains("safe.com"));
    }

    fn empty_dev_for_tags(id: &str) -> Device {
        Device {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            ip: Some("10.0.0.1".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    fn group_named(id: &str, priority: i32) -> Group {
        Group {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            profile: Id::new("default").unwrap(),
            priority,
            devices: vec![],
        }
    }

    /// Membership is symmetric: `group.devices` listing the device and
    /// `device.groups` listing the group both bind, matching what
    /// `check_groups` accepts in the validator.
    #[test]
    fn tmc_groups_for_device_matches_both_join_directions() {
        let mut dev = empty_dev_for_tags("hue-bulb-1");
        dev.groups = vec![Id::new("via-device").unwrap()];

        let mut via_group = group_named("via-group", 0);
        via_group.devices = vec![dev.id.clone()];
        let via_device = group_named("via-device", 0);
        let unrelated = group_named("unrelated", 0);

        let all = vec![via_group, via_device, unrelated];
        let got = groups_for_device(&dev, &all);
        let ids: Vec<&str> = got.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(
            ids,
            ["via-group", "via-device"],
            "both join directions bind, unrelated group must not"
        );
    }

    // ── EcsPolicy ──────────────────────────────────────────────

    use std::net::{Ipv4Addr, Ipv6Addr};

    fn upstream_default() -> EcsConfig {
        EcsConfig::default()
    }

    fn upstream_coarse() -> EcsConfig {
        EcsConfig {
            enabled: true,
            source_prefix_v4: 16,
            source_prefix_v6: 48,
            mode: EcsMode::Coarse,
        }
    }

    #[test]
    fn ecs_policy_default_is_off() {
        let p: EcsPolicy = Default::default();
        assert_eq!(p.mode, EcsMode::Off);
        assert_eq!(p.source_prefix_v4, 0);
        assert_eq!(p.source_prefix_v6, 0);
    }

    #[test]
    fn ecs_policy_off_emits_none_for_any_ip() {
        let p = EcsPolicy::OFF;
        assert!(p
            .build_option(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50)))
            .is_none());
        assert!(p
            .build_option(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .is_none());
    }

    #[test]
    fn ecs_policy_coarse_emits_slash_24_for_v4() {
        let p = EcsPolicy {
            mode: EcsMode::Coarse,
            source_prefix_v4: 8, // ignored under coarse
            source_prefix_v6: 8,
        };
        let opt = p
            .build_option(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50)))
            .expect("coarse v4 emits option");
        assert_eq!(opt.source_prefix(), 24);
    }

    #[test]
    fn ecs_policy_coarse_emits_slash_56_for_v6() {
        let p = EcsPolicy {
            mode: EcsMode::Coarse,
            source_prefix_v4: 8,
            source_prefix_v6: 8, // ignored under coarse
        };
        let opt = p
            .build_option(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .expect("coarse v6 emits option");
        assert_eq!(opt.source_prefix(), 56);
    }

    #[test]
    fn ecs_policy_subnet_uses_configured_v4_prefix() {
        let p = EcsPolicy {
            mode: EcsMode::Subnet,
            source_prefix_v4: 20,
            source_prefix_v6: 56,
        };
        let opt = p
            .build_option(IpAddr::V4(Ipv4Addr::new(192, 168, 17, 50)))
            .expect("subnet v4 emits option");
        assert_eq!(opt.source_prefix(), 20);
    }

    #[test]
    fn ecs_policy_subnet_uses_configured_v6_prefix() {
        let p = EcsPolicy {
            mode: EcsMode::Subnet,
            source_prefix_v4: 24,
            source_prefix_v6: 48,
        };
        let opt = p
            .build_option(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)))
            .expect("subnet v6 emits option");
        assert_eq!(opt.source_prefix(), 48);
    }

    #[test]
    fn ecs_policy_inherits_from_upstream_when_profile_absent() {
        let p = EcsPolicy::from_profile_and_upstream(None, &upstream_coarse());
        assert_eq!(p.mode, EcsMode::Coarse);
        assert_eq!(p.source_prefix_v4, 16);
        assert_eq!(p.source_prefix_v6, 48);
    }

    #[test]
    fn ecs_policy_profile_mode_overrides_upstream() {
        let prof = ProfileEcsConfig {
            mode: Some(EcsMode::Off),
            source_prefix_v4: None,
            source_prefix_v6: None,
        };
        let p = EcsPolicy::from_profile_and_upstream(Some(&prof), &upstream_coarse());
        assert_eq!(p.mode, EcsMode::Off);
        // Prefix fields still inherit even when the override turns mode off —
        // they're inert under Off but the inheritance chain is field-wise.
        assert_eq!(p.source_prefix_v4, 16);
        assert_eq!(p.source_prefix_v6, 48);
    }

    #[test]
    fn ecs_policy_partial_profile_override_field_by_field() {
        // Profile sets mode=Subnet + a custom v4 prefix; v6 prefix
        // inherits from upstream.
        let prof = ProfileEcsConfig {
            mode: Some(EcsMode::Subnet),
            source_prefix_v4: Some(28),
            source_prefix_v6: None,
        };
        let p = EcsPolicy::from_profile_and_upstream(Some(&prof), &upstream_coarse());
        assert_eq!(p.mode, EcsMode::Subnet);
        assert_eq!(p.source_prefix_v4, 28);
        assert_eq!(p.source_prefix_v6, 48);
    }

    #[test]
    fn ecs_policy_default_upstream_yields_off() {
        // EcsConfig::default() has enabled=false + mode=Off. A profile
        // that doesn't override anything should resolve to OFF.
        let p = EcsPolicy::from_profile_and_upstream(None, &upstream_default());
        assert_eq!(p, EcsPolicy::OFF);
    }

    #[test]
    fn ecs_policy_master_kill_switch_off_overrides_profile_subnet() {
        // Operator emergency stop: even an explicit `mode = "subnet"`
        // on the profile must yield OFF when `[upstream.ecs].enabled
        // = false`. Validates the master kill-switch path.
        let upstream_disabled = EcsConfig {
            enabled: false,
            source_prefix_v4: 24,
            source_prefix_v6: 56,
            mode: EcsMode::Subnet,
        };
        let prof = ProfileEcsConfig {
            mode: Some(EcsMode::Subnet),
            source_prefix_v4: Some(28),
            source_prefix_v6: Some(64),
        };
        let p = EcsPolicy::from_profile_and_upstream(Some(&prof), &upstream_disabled);
        assert_eq!(p, EcsPolicy::OFF);
    }

    #[test]
    fn ecs_policy_subnet_with_oversize_prefix_returns_none() {
        // Defensive: if a Subnet policy somehow carries an out-of-range
        // prefix (e.g. validator was bypassed), the codec rejects it
        // and build_option returns None rather than panicking.
        let p = EcsPolicy {
            mode: EcsMode::Subnet,
            source_prefix_v4: 99, // invalid, > 32
            source_prefix_v6: 8,
        };
        assert!(p
            .build_option(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .is_none());
    }

    #[test]
    fn resolved_profile_default_ecs_policy_is_off() {
        // build_v1 leaves ecs_policy at OFF; the production resolver
        // overrides it after construction. Verify the default so a
        // future regression that drops the override surfaces here.
        let profile = Profile {
            display_name: "default".into(),
            ..Default::default()
        };
        let rp = ResolvedProfile::build_v1(
            &Id::new("default").unwrap(),
            &profile,
            &BTreeMap::new(),
            &crate::config::custom_list::CustomListStore::new(),
            &ServerGlobals::default(),
            60,
        );
        assert_eq!(rp.ecs_policy, EcsPolicy::OFF);
    }
}
