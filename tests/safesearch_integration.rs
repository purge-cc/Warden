//! §4.53 SafeSearch Toggle — integration tests, rewritten for
//! `neutrality-04` (2026-08-16).
//!
//! Exercises config → resolver-map → `ResolvedProfile.rewrite_rules` →
//! `ProfileRewriteRules::apply` end-to-end. Where the in-module tests in
//! `src/profiles/safesearch.rs` cover the populator in isolation, these
//! cover the **wiring**: what a device actually gets served once the
//! resolver has built its profile.
//!
//! **What changed.** These four tests used to assert that flipping
//! `safe_search = true` made eight vendor hostnames rewrite to four
//! vendor CNAME targets that were compiled into the binary. That table
//! was the `neutrality-04` violation — warden changing what it did to
//! named domains, chosen by warden, invisible in the operator's TOML and
//! unchangeable without a new build. The table is gone, so the tests
//! that pinned it are inverted: they now prove the injection does not
//! happen, and that an operator who *wants* those rewrites gets exactly
//! them by writing them.
//!
//! Vendor names below sit in a test file on purpose. Per CLAUDE.md
//! §Neutrality that is the right home for one — proving the absence of
//! a behaviour.
//!
//! End-to-end DNS handler tests live in the CT smoke matrix — those need
//! real listener bind + upstream resolver + cache and are out of scope
//! for `cargo test`.

use std::net::{IpAddr, Ipv4Addr};

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::RewriteRule;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;

/// The eight `(from, to)` pairs `SAFE_SEARCH_PRESETS` used to inject.
/// Asserted as pairs, never as bare hostnames: an operator is free to
/// write a rewrite for any of these names — that is the entire point of
/// moving the set into their config — so a needle matching the hostname
/// alone would go red on correct operator config instead of on a
/// regression.
const RETIRED_PRESETS: &[(&str, &str)] = &[
    ("google.com", "forcesafesearch.google.com"),
    ("www.google.com", "forcesafesearch.google.com"),
    ("www.youtube.com", "restrict.youtube.com"),
    ("m.youtube.com", "restrict.youtube.com"),
    ("www.youtube-nocookie.com", "restrict.youtube.com"),
    ("www.bing.com", "strict.bing.com"),
    ("edgeservices.bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"),
];

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
fn neutrality04_safe_search_true_injects_no_vendor_rewrite() {
    // The inverse of `s453_safe_search_true_injects_engine_rewrites`.
    // A profile that asks for SafeSearch and supplies no rewrites of its
    // own now rewrites nothing at all — warden contributes no opinion
    // about any named search engine.
    let profile = Profile {
        display_name: "kids".into(),
        safe_search: true,
        ..Default::default()
    };
    let resolver = resolver_with("kids", profile, Ipv4Addr::new(10, 0, 0, 1));
    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .expect("device must resolve to its named profile");

    for (from, to) in RETIRED_PRESETS {
        assert_eq!(
            resolved.rewrite_rules.apply(from),
            None,
            "safe_search=true must not inject {from} -> {to}"
        );
    }
}

#[test]
fn neutrality04_operator_rewrites_are_the_only_source() {
    // The migration path, end to end: an operator who wants the old
    // behaviour writes the rows and gets exactly them — no rebuild, and
    // visible in `warden rewrite list` / `profile show`, which the
    // injected presets never were. Two of the eight are authored here;
    // the other six must stay absent, which is what makes this a
    // discriminating test rather than a restatement of the one above.
    let profile = Profile {
        display_name: "kids".into(),
        safe_search: true,
        rewrite_rules: vec![
            rule("www.google.com", "forcesafesearch.google.com", false),
            rule("duckduckgo.com", "safe.duckduckgo.com", false),
        ],
        ..Default::default()
    };
    let resolver = resolver_with("kids", profile, Ipv4Addr::new(10, 0, 0, 5));
    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        .profile
        .expect("device must resolve");

    assert_eq!(
        resolved.rewrite_rules.apply("www.google.com").as_deref(),
        Some("forcesafesearch.google.com"),
        "an authored rewrite must be served"
    );
    assert_eq!(
        resolved.rewrite_rules.apply("duckduckgo.com").as_deref(),
        Some("safe.duckduckgo.com"),
        "an authored rewrite must be served"
    );
    for (from, to) in RETIRED_PRESETS {
        if *from == "www.google.com" || *from == "duckduckgo.com" {
            continue;
        }
        assert_eq!(
            resolved.rewrite_rules.apply(from),
            None,
            "{from} was not authored — nothing may supply {to} on the operator's behalf"
        );
    }
}

#[test]
fn neutrality04_safe_search_flag_no_longer_changes_the_served_set() {
    // `safe_search` is now inert: the same `[[rewrites]]` produce the
    // same served set with the flag on and off. Stated as a test because
    // it is the honest consequence of the fix and the thing an operator
    // most needs to know — the flag they set is not doing anything. If
    // the flag ever regains meaning, this test is the one that must be
    // deliberately changed, which is exactly where that decision belongs.
    let authored = vec![rule("www.bing.com", "strict.bing.com", false)];

    let on = resolver_with(
        "flag-on",
        Profile {
            display_name: "on".into(),
            safe_search: true,
            rewrite_rules: authored.clone(),
            ..Default::default()
        },
        Ipv4Addr::new(10, 0, 0, 6),
    );
    let off = resolver_with(
        "flag-off",
        Profile {
            display_name: "off".into(),
            safe_search: false,
            rewrite_rules: authored,
            ..Default::default()
        },
        Ipv4Addr::new(10, 0, 0, 7),
    );

    let on = on
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)))
        .profile
        .expect("device must resolve");
    let off = off
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        .profile
        .expect("device must resolve");

    for probe in ["www.bing.com", "google.com", "duckduckgo.com", "other.lan"] {
        assert_eq!(
            on.rewrite_rules.apply(probe),
            off.rewrite_rules.apply(probe),
            "safe_search must not change what is served for {probe}"
        );
    }
    assert_eq!(
        on.rewrite_rules.apply("www.bing.com").as_deref(),
        Some("strict.bing.com"),
        "…and the authored rule is served in both cases"
    );
}

#[test]
fn rev2606_explicit_exact_beats_operator_wildcard_on_the_apex() {
    // Survivor of `rev2606_safe_search_explicit_wildcard_keeps_the_apex`.
    // The property that test really covered belongs to the rewrite
    // engine, not to SafeSearch: `ProfileRewriteRules::build` is
    // two-pass, so an exact rule takes the apex from a wildcard rule
    // covering the same name. That is worth keeping and needs no vendor
    // name to state, so it is restated here on neutral hostnames — and
    // with `safe_search = true` set, which additionally proves the flag
    // does not disturb operator precedence.
    let profile = Profile {
        display_name: "wildcard".into(),
        safe_search: true,
        rewrite_rules: vec![
            rule("search.example-int", "proxy.example-int", true),
            rule("www.search.example-int", "exact.example-int", false),
        ],
        ..Default::default()
    };
    let resolver = resolver_with("wildcard", profile, Ipv4Addr::new(10, 0, 0, 4));
    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)))
        .profile
        .expect("device must resolve");

    assert_eq!(
        resolved
            .rewrite_rules
            .apply("search.example-int")
            .as_deref(),
        Some("proxy.example-int"),
        "the wildcard owns its own apex"
    );
    assert_eq!(
        resolved
            .rewrite_rules
            .apply("maps.search.example-int")
            .as_deref(),
        Some("maps.proxy.example-int"),
        "descendants follow the wildcard"
    );
    assert_eq!(
        resolved
            .rewrite_rules
            .apply("www.search.example-int")
            .as_deref(),
        Some("exact.example-int"),
        "an exact rule beats the wildcard suffix walk for its own name"
    );
}
