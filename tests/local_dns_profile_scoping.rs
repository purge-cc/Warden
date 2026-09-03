//! Sprint 44 T2 — Local DNS Scoping v2 integration tests.
//!
//! Exercises the full config → validator → resolver-map → `ResolvedProfile.local_records`
//! pipeline with realistic TOML inputs. Where the unit tests in
//! `src/dns/local_profile.rs` cover the lookup semantics in isolation,
//! these tests cover the **wiring**: that a `[[profiles.X.local_records]]`
//! TOML stanza survives the loader, the validator, and `ResolverMap::build`,
//! and ends up reachable as `Arc<ProfileLocalRecords>` on the right
//! `ResolvedProfile` — the same path the DNS hot path consumes.
//!
//! End-to-end DNS handler tests (`dig @127.0.0.1 -p 15353` style) live in
//! the CT smoke matrix on `the lab host` per the §11 T2 exit criteria;
//! those need a real listener bind + ARP table and are out of scope for
//! `cargo test`.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use hickory_proto::rr::{Name, RData, RecordType};

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{LocalDnsRecord, LocalDnsRecordType};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;

/// Helper: build a minimal `ConfigV1` with one device pinned to a profile,
/// returning the live `ProfileResolver` ready for `.resolve(&ip)`.
fn resolver_with(
    profile_id: &str,
    profile: Profile,
    device_ip: Ipv4Addr,
    global_records: Vec<LocalDnsRecord>,
) -> ProfileResolver {
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

    config.local_dns.records = global_records;

    let list_bit_map = SourceBitMap::default();
    ProfileResolver::build(
        &config,
        &list_bit_map,
        &purge_warden::config::custom_list::CustomListStore::new(),
    )
}

fn rec(domain: &str, rt: LocalDnsRecordType, value: &str, sub: bool) -> LocalDnsRecord {
    LocalDnsRecord {
        domain: domain.into(),
        record_type: rt,
        value: value.into(),
        match_subdomains: sub,
        ttl_secs: None,
    }
}

#[test]
fn t2_int_profile_scoped_record_resolves_via_pipeline() {
    // The `example.test → 10.10.1.50` record on the demo profile must travel
    // from TOML-equivalent struct → validator → resolver-map → `ResolvedProfile`
    // → `ProfileLocalRecords::lookup`, all without intervention. This is
    // the canonical happy path the operator will hit on day one.
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "10.10.1.50",
            false,
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), vec![]);

    let resolution = resolver.resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let resolved = resolution.profile.expect("device should resolve to demo");
    assert_eq!(resolved.name.as_str(), "demo");

    let records = resolved
        .local_records
        .lookup("example.test", RecordType::A)
        .expect("profile-scope hit");
    assert_eq!(records.len(), 1);
    match records[0].data {
        RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 10, 1, 50)),
        _ => panic!("expected A"),
    }
}

#[test]
fn t2_int_subdomain_wildcard_via_pipeline() {
    // `example.test` with match_subdomains=true → `app.example.test` must resolve
    // to the same IP. End-to-end: validator must accept it (example.test is
    // not a public suffix in the embedded PSL); resolver-map must build
    // the suffix index; lookup must walk and hit.
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "10.10.1.50",
            true,
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), vec![]);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .unwrap();
    let records = resolved
        .local_records
        .lookup("app.example.test", RecordType::A)
        .expect("subdomain walk must hit");
    // localdns-wildcard-owner: the descendant answer must be OWNED by the
    // queried name end-to-end, else RFC-conformant stub resolvers (glibc
    // getanswer_r does strcasecmp(qname, rr_owner)) discard it and the
    // client gets no address despite the LOCAL hit.
    assert_eq!(
        &records[0].name,
        &Name::from_str("app.example.test.").unwrap(),
        "wildcard descendant RR must be owned by the queried name"
    );
    match records[0].data {
        RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 10, 1, 50)),
        _ => panic!("expected A"),
    }
}

#[test]
fn t2_int_profile_shadows_global_silently() {
    // Same domain + type in BOTH global and profile scope: the resolver
    // hands the operator BOTH tables, and the hot path probes profile
    // first (per §6 — code in src/dns/handler.rs). Here we assert the
    // pipeline plumbing: the resolved profile carries its OWN record set
    // distinct from the global, with the profile's IP value.
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.99",
            false,
        )],
        ..Default::default()
    };
    let global = vec![rec("example.test", LocalDnsRecordType::A, "1.1.1.1", false)];
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), global);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .unwrap();
    let records = resolved
        .local_records
        .lookup("example.test", RecordType::A)
        .expect("profile-scope hit");
    match records[0].data {
        RData::A(ref a) => assert_eq!(
            a.0,
            Ipv4Addr::new(10, 0, 0, 99),
            "profile must shadow global silently"
        ),
        _ => panic!("expected A"),
    }
}

#[test]
fn t2_int_unmapped_profile_has_no_local_records() {
    // A different profile, with NO local_records, must produce an empty
    // `ProfileLocalRecords`. The hot path then falls through to global.
    // This pin protects against a regression where Default::default()
    // (or an Arc::clone of the wrong table) leaks records across profiles.
    let profile = Profile {
        display_name: "vanilla".into(),
        ..Default::default()
    };
    let resolver = resolver_with("vanilla", profile, Ipv4Addr::new(10, 0, 0, 2), vec![]);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .profile
        .unwrap();
    assert!(resolved.local_records.is_empty());
    assert!(resolved
        .local_records
        .lookup("example.test", RecordType::A)
        .is_none());
}

#[test]
fn t2_int_dr4_non_addr_qtype_returns_none() {
    // DR4: an MX or TXT query for a domain that DOES have a profile-scope
    // A record must NOT match. The hot path then forwards upstream — even
    // though we return None at the lookup boundary here.
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "10.10.1.50",
            false,
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), vec![]);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .unwrap();
    for qtype in [
        RecordType::MX,
        RecordType::TXT,
        RecordType::SRV,
        RecordType::NS,
        RecordType::SOA,
    ] {
        assert!(
            resolved
                .local_records
                .lookup("example.test", qtype)
                .is_none(),
            "qtype {qtype:?} must bypass profile-scope local records"
        );
    }
}

#[test]
fn t2_int_per_record_ttl_overrides_global_default() {
    // DR5: per-record `ttl_secs = Some(900)` overrides the global
    // `[local_dns].ttl_secs` (default 3600). Verify the resolved record
    // carries 900, not 3600.
    let mut record = rec("nas.home", LocalDnsRecordType::A, "192.168.1.50", false);
    record.ttl_secs = Some(900);
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![record],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), vec![]);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .unwrap();
    let records = resolved
        .local_records
        .lookup("nas.home", RecordType::A)
        .unwrap();
    assert_eq!(records[0].ttl, 900);
}

#[test]
fn t2_int_default_ttl_inherited_from_global_local_dns_section() {
    // DR5 fallback: per-record `ttl_secs = None` → fall back to the
    // global `[local_dns].ttl_secs` value (default 3600). Verify the
    // wiring runs through ConfigV1.local_dns.ttl_secs → resolver-map
    // → ProfileLocalRecords::build's default_ttl arg.
    let profile = Profile {
        display_name: "demo".into(),
        local_records: vec![rec(
            "nas.home",
            LocalDnsRecordType::A,
            "192.168.1.50",
            false,
        )],
        ..Default::default()
    };
    let resolver = resolver_with("demo", profile, Ipv4Addr::new(10, 0, 0, 1), vec![]);

    let resolved = resolver
        .resolve(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .profile
        .unwrap();
    let records = resolved
        .local_records
        .lookup("nas.home", RecordType::A)
        .unwrap();
    // Default in `default_local_dns_ttl_secs` is 3600 (settings.rs:87).
    assert_eq!(records[0].ttl, 3600);
}
