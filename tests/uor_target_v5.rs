use std::collections::BTreeSet;
use std::sync::Arc;

use purge_warden::config::error::ConfigError;
use purge_warden::config::schema::validator::AuditWarnings;
use purge_warden::config::schema::{
    load_from_str_collect_for_schema, ConfigV1, ConfigV5, CustomListLimitsV5, DeviceV5, Id,
    ProfileV5, NODE_LOCAL_SECTIONS, REPLICATED_SECTIONS, SCHEMA_VERSION_V1,
    SECTIONS_EXCLUDED_FROM_REPLICATION, TARGET_SCHEMA_VERSION_V5, TARGET_V5_NODE_LOCAL_SECTIONS,
    TARGET_V5_REPLICATED_SECTIONS, TARGET_V5_SECTIONS_EXCLUDED_FROM_REPLICATION,
};
use purge_warden::config::target_v5::{
    compile_v5_operator_rules, validate_v5_collect, PackBodiesV5, TargetV5Error,
};
use purge_warden::filter::operator_rules::{
    CompileAdmission, ExternalMatches, RuleCompileLimits, RuleTier, Verdict,
};
use time::macros::datetime;

const CONFIG: &str = include_str!("fixtures/target-v5/config.toml");
const STREAMING_PACK: &str = include_str!("fixtures/target-v5/packs/streaming.txt");
const ARCHIVE_PACK: &str = include_str!("fixtures/target-v5/packs/archive.txt");

fn now() -> time::OffsetDateTime {
    datetime!(2026-09-10 12:00:00 UTC)
}

fn config() -> ConfigV5 {
    toml::from_str(CONFIG).expect("schema-5 fixture parses")
}

fn bodies() -> PackBodiesV5 {
    let mut bodies = PackBodiesV5::default();
    bodies.insert(
        Id::new("streaming").unwrap(),
        Arc::<str>::from(STREAMING_PACK),
    );
    bodies.insert(Id::new("archive").unwrap(), Arc::<str>::from(ARCHIVE_PACK));
    bodies
}

fn admission() -> CompileAdmission {
    CompileAdmission::new(128 << 20, 4).unwrap()
}

#[test]
fn schema_5_fixture_round_trips_every_target_section() {
    let config = config();
    assert_eq!(config.schema_version, TARGET_SCHEMA_VERSION_V5);
    assert_eq!(
        config.profiles["streaming"].custom_lists[0].as_str(),
        "streaming"
    );
    assert_eq!(config.devices[0].display_name, "Apple TV");
    assert_eq!(config.devices[1].display_name, "NVIDIA SHIELD");

    validate_v5_collect(&config, now(), &mut AuditWarnings::silent(), None)
        .expect("fixture reuses the complete semantic validator");

    let encoded = toml::to_string(&config).expect("target serializes");
    for removed in [
        "admin_rules",
        "allow_rules",
        "deny_rules",
        "override_profile_deny",
    ] {
        assert!(!encoded.contains(removed), "target emitted {removed}");
    }
    let decoded: ConfigV5 = toml::from_str(&encoded).expect("emitted target parses");
    assert_eq!(toml::to_string(&decoded).unwrap(), encoded);

    let table = toml::Value::try_from(&decoded).unwrap();
    let keys: BTreeSet<&str> = table
        .as_table()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = TARGET_V5_REPLICATED_SECTIONS
        .iter()
        .chain(TARGET_V5_NODE_LOCAL_SECTIONS)
        .chain(TARGET_V5_SECTIONS_EXCLUDED_FROM_REPLICATION)
        .copied()
        .collect();
    assert_eq!(keys, expected);
}

#[test]
fn current_schema_stays_4_and_rejects_the_schema_5_fixture() {
    assert_eq!(SCHEMA_VERSION_V1, 4);
    let result = load_from_str_collect_for_schema(
        CONFIG,
        SCHEMA_VERSION_V1,
        None,
        now(),
        &mut AuditWarnings::silent(),
        None,
        None,
    );
    assert!(
        result.is_err(),
        "the live decoder must not accept the target fixture"
    );
}

#[test]
fn removed_rule_seats_are_rejected_even_when_empty_or_false() {
    let cases = [
        (
            "top-level admin_rules",
            "schema_version = 5\nadmin_rules = []\n",
        ),
        (
            "profile admin_rules",
            "schema_version = 5\n[profiles.p]\nadmin_rules = []\n",
        ),
        (
            "device allow_rules",
            "schema_version = 5\n[[devices]]\nid = \"d\"\ndisplay_name = \"D\"\nip = \"192.0.2.1\"\nallow_rules = []\n",
        ),
        (
            "device deny_rules",
            "schema_version = 5\n[[devices]]\nid = \"d\"\ndisplay_name = \"D\"\nip = \"192.0.2.1\"\ndeny_rules = []\n",
        ),
        (
            "device override_profile_deny",
            "schema_version = 5\n[[devices]]\nid = \"d\"\ndisplay_name = \"D\"\nip = \"192.0.2.1\"\noverride_profile_deny = false\n",
        ),
    ];
    for (name, source) in cases {
        let error = toml::from_str::<ConfigV5>(source)
            .expect_err("removed schema-4 field must be unknown")
            .to_string();
        assert!(error.contains("unknown field"), "{name}: {error}");
    }
}

#[test]
fn unknown_fields_are_rejected_at_each_target_layer() {
    for source in [
        "schema_version = 5\nunknown = true\n",
        "schema_version = 5\n[profiles.p]\nunknown = true\n",
        "schema_version = 5\n[[devices]]\nid = \"d\"\ndisplay_name = \"D\"\nip = \"192.0.2.1\"\nunknown = true\n",
        "schema_version = 5\n[custom_list_limits]\nunknown = 1\n",
    ] {
        assert!(
            toml::from_str::<ConfigV5>(source)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
}

#[test]
fn target_field_sets_are_exhaustive_compile_time_tripwires() {
    let ConfigV5 {
        schema_version: _,
        includes: _,
        server: _,
        retired: _,
        blocklists: _,
        profiles: _,
        devices: _,
        groups: _,
        subnets: _,
        schedules: _,
        custom_lists: _,
        custom_list_limits: _,
        labels: _,
        upstream: _,
        dnssec: _,
        cache: _,
        tracking: _,
        security: _,
        anti_bypass: _,
        socket: _,
        api: _,
        forwarding: _,
        local_dns: _,
        ip_blocklists: _,
        lists: _,
        resource_budget: _,
        backup: _,
        cluster: _,
        node: _,
    } = ConfigV5::default();
    let ProfileV5 {
        display_name: _,
        block_response: _,
        blocked_ttl_secs: _,
        block_all: _,
        local_records: _,
        ecs: _,
        rewrite_rules: _,
        safe_search: _,
        custom_lists: _,
        lists: _,
        migration_origin: _,
    } = ProfileV5::default();
    let DeviceV5 {
        id: _,
        display_name: _,
        ip: _,
        mac: _,
        mac_aliases: _,
        profile: _,
        groups: _,
        owner: _,
        device_type: _,
        department: _,
        notes: _,
        unfiltered: _,
        network_name: _,
        network_name_wildcard: _,
    } = config().devices.remove(0);
    let CustomListLimitsV5 {
        max_lists: _,
        max_file_bytes: _,
        max_total_bytes: _,
        max_rules_per_list: _,
        max_indexed_rules_per_profile: _,
        max_indexed_rules_total: _,
        max_advanced_rules_per_profile: _,
        max_advanced_rules_total: _,
        max_regex_rules_per_profile: _,
        max_regex_rules_total: _,
        max_store_indexed_rules: _,
        max_store_advanced_rules: _,
        max_store_regex_rules: _,
        max_rule_bytes: _,
        max_regex_program_bytes: _,
        max_store_compiled_bytes: _,
        max_compiled_bytes_per_profile: _,
        max_compiled_bytes_total: _,
    } = CustomListLimitsV5::default();
}

#[test]
fn projection_preserves_fields_and_synthesizes_only_removed_rule_seats() {
    let target = config();
    let projection = target.validation_projection().unwrap();
    assert_eq!(projection.schema_version, 5);
    assert_eq!(projection.includes, target.includes);
    assert_eq!(projection.server, target.server);
    assert_eq!(projection.custom_lists, target.custom_lists);
    assert_eq!(projection.custom_list_limits.max_file_bytes, 1 << 20);
    assert!(projection.admin_rules.is_empty());
    let profile = &projection.profiles["streaming"];
    assert!(profile.admin_rules.is_empty());
    assert_eq!(
        profile.custom_lists,
        target.profiles["streaming"].custom_lists
    );
    assert_eq!(profile.ecs, target.profiles["streaming"].ecs);
    for device in &projection.devices {
        assert!(device.allow_rules.is_empty());
        assert!(device.deny_rules.is_empty());
        assert!(!device.override_profile_deny);
    }
    assert_eq!(
        projection.devices[0].network_name,
        target.devices[0].network_name
    );
    assert_eq!(
        projection.devices[1].network_name_wildcard,
        target.devices[1].network_name_wildcard
    );
}

#[test]
fn profile_serialization_keeps_custom_lists_before_map_valued_lists() {
    use purge_warden::config::schema::ListPolicy;

    let mut target = config();
    target
        .profiles
        .get_mut("streaming")
        .unwrap()
        .lists
        .insert(Id::new("external-example").unwrap(), ListPolicy::Deny);
    let encoded = toml::to_string(&target).unwrap();
    let mount = encoded.find("custom_lists = [\"streaming\"]").unwrap();
    let map = encoded.find("[profiles.streaming.lists]").unwrap();
    assert!(mount < map);
    let back: ConfigV5 = toml::from_str(&encoded).unwrap();
    assert_eq!(back.profiles["streaming"].lists.len(), 1);
}

#[test]
fn target_replication_sets_are_disjoint_and_keep_receiver_limits_local() {
    let all: Vec<&str> = TARGET_V5_REPLICATED_SECTIONS
        .iter()
        .chain(TARGET_V5_NODE_LOCAL_SECTIONS)
        .chain(TARGET_V5_SECTIONS_EXCLUDED_FROM_REPLICATION)
        .copied()
        .collect();
    let unique: BTreeSet<&str> = all.iter().copied().collect();
    assert_eq!(all.len(), unique.len());
    assert!(TARGET_V5_REPLICATED_SECTIONS.contains(&"custom_lists"));
    assert!(TARGET_V5_NODE_LOCAL_SECTIONS.contains(&"custom_list_limits"));
    assert!(TARGET_V5_SECTIONS_EXCLUDED_FROM_REPLICATION.contains(&"includes"));
    assert!(!unique.contains("admin_rules"));

    assert!(REPLICATED_SECTIONS.contains(&"admin_rules"));
    assert!(REPLICATED_SECTIONS.contains(&"custom_lists"));
    assert!(!NODE_LOCAL_SECTIONS.contains(&"custom_lists"));
    assert!(NODE_LOCAL_SECTIONS.contains(&"custom_list_limits"));
    assert_eq!(SECTIONS_EXCLUDED_FROM_REPLICATION, &["includes"]);
}

#[test]
fn target_limit_defaults_match_the_compiler_exactly() {
    let target = CustomListLimitsV5::default();
    assert_eq!(
        RuleCompileLimits::try_from(&target).unwrap(),
        RuleCompileLimits::default()
    );
}

#[test]
fn every_target_limit_rejects_zero_and_hard_ceiling_plus_one() {
    macro_rules! rejects_boundaries {
        ($($field:ident),+ $(,)?) => {$({
            let mut zero = CustomListLimitsV5::default();
            zero.$field = 0;
            assert!(matches!(
                RuleCompileLimits::try_from(&zero),
                Err(TargetV5Error::Limits(ref error)) if error.limit == stringify!($field)
            ));

            let mut high = CustomListLimitsV5::default();
            high.$field = RuleCompileLimits::HARD_CEILINGS.$field + 1;
            assert!(matches!(
                RuleCompileLimits::try_from(&high),
                Err(TargetV5Error::Limits(ref error)) if error.limit == stringify!($field)
            ));
        })+};
    }
    rejects_boundaries!(
        max_lists,
        max_file_bytes,
        max_total_bytes,
        max_rules_per_list,
        max_indexed_rules_per_profile,
        max_indexed_rules_total,
        max_advanced_rules_per_profile,
        max_advanced_rules_total,
        max_regex_rules_per_profile,
        max_regex_rules_total,
        max_store_indexed_rules,
        max_store_advanced_rules,
        max_store_regex_rules,
        max_rule_bytes,
        max_regex_program_bytes,
        max_store_compiled_bytes,
        max_compiled_bytes_per_profile,
        max_compiled_bytes_total,
    );
}

#[test]
fn validation_projection_returns_all_semantic_errors_together() {
    let mut target = config();
    let device = &mut target.devices[0];
    device.ip = None;
    device.mac = None;
    device.mac_aliases.clear();
    device.profile = Some(Id::new("missing-profile").unwrap());
    target
        .profiles
        .get_mut("streaming")
        .unwrap()
        .custom_lists
        .push(Id::new("missing-list").unwrap());

    let error =
        validate_v5_collect(&target, now(), &mut AuditWarnings::silent(), None).unwrap_err();
    let errors = error
        .validation_errors()
        .expect("semantic validation error");
    assert!(errors.len() >= 3, "errors must be aggregated: {errors:?}");
    assert!(errors
        .iter()
        .any(|error| matches!(error, ConfigError::CrossRefMiss(_))));
    assert!(errors.iter().any(|error| {
        matches!(error, ConfigError::ValidationFailed(context) if context.reason.contains("no identity field"))
    }));
}

#[test]
fn adapter_reports_every_missing_declared_body() {
    let error =
        compile_v5_operator_rules(&config(), &PackBodiesV5::default(), &admission()).unwrap_err();
    let missing: Vec<&str> = error
        .missing_bodies()
        .unwrap()
        .iter()
        .map(Id::as_str)
        .collect();
    assert_eq!(missing, ["archive", "streaming"]);
}

#[test]
fn adapter_ignores_undeclared_orphan_bodies() {
    let mut target = config();
    target.profiles.get_mut("streaming").unwrap().block_all = false;
    let mut bodies = bodies();
    bodies.insert(
        Id::new("orphan").unwrap(),
        Arc::<str>::from("this is deliberately invalid\n"),
    );
    let compiled = compile_v5_operator_rules(&target, &bodies, &admission()).unwrap();
    assert!(compiled.store().pack(&Id::new("orphan").unwrap()).is_none());
    assert_eq!(
        compiled
            .profile(&Id::new("streaming").unwrap())
            .unwrap()
            .evaluate("orphan.example", ExternalMatches::None),
        Verdict::Forward
    );
}

#[test]
fn adapter_retains_and_charges_unmounted_declarations() {
    let compiled = compile_v5_operator_rules(&config(), &bodies(), &admission()).unwrap();
    let archive = compiled
        .store()
        .pack(&Id::new("archive").unwrap())
        .expect("unmounted declaration remains in the store");
    assert_eq!(archive.source_rule_rows(), 1);
    assert!(compiled.cost().store_counts.indexed >= 1);
    let profile = compiled.profile(&Id::new("streaming").unwrap()).unwrap();
    assert!(profile
        .mounted_rules()
        .all(|rule| rule.origin().list_id().as_str() == "streaming"));
}

#[test]
fn invalid_pack_rejects_the_whole_candidate_and_releases_admission() {
    let mut bodies = bodies();
    bodies.insert(
        Id::new("streaming").unwrap(),
        Arc::<str>::from("||good.example^\n/[\n"),
    );
    let admission = admission();
    let error = compile_v5_operator_rules(&config(), &bodies, &admission).unwrap_err();
    assert!(matches!(error, TargetV5Error::Compiler(_)));
    assert_eq!(admission.reserved_bytes(), 0);
    assert_eq!(admission.active_builds(), 0);
}

#[test]
fn target_semantics_cover_lattice_wildcard_noapex_regex_block_all_and_grants() {
    let compiled = compile_v5_operator_rules(&config(), &bodies(), &admission()).unwrap();
    let profile = compiled.profile(&Id::new("streaming").unwrap()).unwrap();

    let exact = profile.evaluate_attributed("media.example", ExternalMatches::None);
    assert_eq!(exact.verdict(), Verdict::Forward);
    assert_eq!(
        exact.grant_tier(),
        Some(purge_warden::filter::operator_rules::GrantTier::Ordinary)
    );
    assert_eq!(exact.response_ip_verdict(true, true), Verdict::Forward);

    let important_allow = profile.evaluate_attributed("priority.example", ExternalMatches::None);
    assert_eq!(important_allow.verdict(), Verdict::Forward);
    assert_eq!(
        important_allow.winning_rule().unwrap().tier(),
        RuleTier::ImportantAllow
    );

    let important_deny = profile.evaluate_attributed("conflict.example", ExternalMatches::None);
    assert_eq!(important_deny.verdict(), Verdict::Block);
    assert_eq!(
        important_deny.winning_rule().unwrap().tier(),
        RuleTier::ImportantDeny
    );

    assert_eq!(
        profile.evaluate("games.example", ExternalMatches::None),
        Verdict::Block
    );
    assert_eq!(
        profile.evaluate("child.games.example", ExternalMatches::None),
        Verdict::Block
    );
    assert_eq!(
        profile.evaluate("trusted.example", ExternalMatches::None),
        Verdict::Block
    );
    let noapex = profile.evaluate_attributed("child.trusted.example", ExternalMatches::None);
    assert_eq!(noapex.verdict(), Verdict::Forward);
    assert!(noapex.grant_tier().is_some());

    let regex = profile.evaluate_attributed("rx42.example", ExternalMatches::None);
    assert_eq!(regex.verdict(), Verdict::Forward);
    assert!(regex.grant_tier().is_some());
    assert_eq!(
        profile.evaluate("other.example", ExternalMatches::Allow),
        Verdict::Block
    );
}

#[test]
fn validation_projection_is_a_complete_config_v1_literal_tripwire() {
    let projection: ConfigV1 = config().validation_projection().unwrap();
    let ConfigV1 {
        schema_version: _,
        includes: _,
        server: _,
        retired: _,
        blocklists: _,
        profiles: _,
        devices: _,
        groups: _,
        subnets: _,
        schedules: _,
        admin_rules: _,
        custom_lists: _,
        custom_list_limits: _,
        labels: _,
        upstream: _,
        dnssec: _,
        cache: _,
        tracking: _,
        security: _,
        anti_bypass: _,
        socket: _,
        api: _,
        forwarding: _,
        local_dns: _,
        ip_blocklists: _,
        lists: _,
        resource_budget: _,
        backup: _,
        cluster: _,
        node: _,
    } = projection;
}
