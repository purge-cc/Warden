//! §4.12 Domain Rewrite Rules — integration tests.
//!
//! Exercises config → validator → resolver-map → `ResolvedProfile.rewrite_rules`
//! → `ProfileRewriteRules::apply` end-to-end. Where the unit tests in
//! `src/dns/rewrite.rs` cover the engine in isolation, these tests cover
//! the **wiring**: that a `[[profiles.X.rewrite_rules]]` stanza survives
//! the loader, validator, and `ResolverMap::build`, and ends up reachable
//! as `Arc<ProfileRewriteRules>` on the right `ResolvedProfile`.
//!
//! End-to-end DNS handler tests (`dig @127.0.0.1 -p 15353`) live in the
//! CT smoke matrix on `the lab host` — those need real listener bind +
//! upstream resolver + cache and are out of scope for `cargo test`.

use std::net::{IpAddr, Ipv4Addr};

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::RewriteRule;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;

fn rule(from: &str, to: &str, match_subdomains: bool) -> RewriteRule {
    RewriteRule {
        from: from.into(),
        to: to.into(),
        match_subdomains,
    }
}

fn resolver_with(profile_id: &str, profile: Profile, device_ip: Ipv4Addr) -> ProfileResolver {
    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.allow_from = vec!["10.0.0.0/8".into(), "127.0.0.0/8".into()];
    config.server.default_profile = Some(Id::new(profile_id).unwrap());
    config.profiles.insert(profile_id.to_string(), profile);
    config.devices.push(Device {
        id: Id::new("test-dev").unwrap(),
        display_name: "test".into(),
        ip: Some(IpAddr::V4(device_ip)),
        mac: None,
        mac_aliases: vec![],
        profile: Some(Id::new(profile_id).unwrap()),
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
    });

    let list_bit_map = SourceBitMap::default();
    ProfileResolver::build(
        &config,
        &list_bit_map,
        &purge_warden::config::custom_list::CustomListStore::new(),
    )
}

#[test]
fn s412_int_rewrite_resolves_via_pipeline() {
    let profile = Profile {
        display_name: "demo".into(),
        rewrite_rules: vec![rule(
            "api.old-corp.example-int",
            "api.new-corp.example-int",
            false,
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1));
    let resolution = resolver.resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    let resolved = resolution
        .profile
        .expect("device must resolve to its named profile");
    let rewrote = resolved.rewrite_rules.apply("api.old-corp.example-int");
    assert_eq!(
        rewrote.as_deref(),
        Some("api.new-corp.example-int"),
        "pipeline must deliver the rewrite to the hot path"
    );
}

#[test]
fn s412_int_rewrite_subdomain_preserves_prefix_through_pipeline() {
    let profile = Profile {
        display_name: "demo".into(),
        rewrite_rules: vec![rule(
            "old-corp.example-int",
            "new-corp.example-int",
            true, // match_subdomains
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 2));
    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .profile
        .expect("device must resolve");
    // Prefix `api.v2.` is preserved through subdomain rewrite.
    let rewrote = resolved.rewrite_rules.apply("api.v2.old-corp.example-int");
    assert_eq!(
        rewrote.as_deref(),
        Some("api.v2.new-corp.example-int"),
        "subdomain rule must preserve prefix end-to-end"
    );
}

#[test]
fn s412_int_rewrite_cycle_rejected_at_config_validate() {
    // Cycle A→B→A is refused by `validate_rewrite_rules`; the v1 schema
    // validator surfaces the error in its returned set, blocking
    // `ResolverMap::build` from ever seeing the bad config.
    use purge_warden::config::schema::SCHEMA_VERSION_V1;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    let mut profiles: BTreeMap<String, Profile> = BTreeMap::new();
    profiles.insert(
        "bad".into(),
        Profile {
            display_name: "Cycle".into(),
            rewrite_rules: vec![
                rule("a.example-int", "b.example-int", false),
                rule("b.example-int", "a.example-int", false),
            ],
            ..Profile::default()
        },
    );
    let cfg = ConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        profiles,
        ..ConfigV1::default()
    };
    let now = OffsetDateTime::now_utc();
    let errs = purge_warden::config::schema::validator::validate(&cfg, now)
        .expect_err("validator must refuse cyclic rewrite config");
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("rewrite cycle detected")),
        "expected REWRITE_CYCLE on the schema-level validator output, got: {errs:?}"
    );
}
