// ── S44 T1: Local DNS Scoping v2 ────────────────────────────
//
// Tests below pin every frozen-string path declared in
// `_docs/features/local_dns_scoping.md` §2 plus PSL hits/misses,
// reserved-IP corners, generalised CNAME cycle, A+CNAME conflict,
// and Sprint 18 backward compat.

use super::super::settings::{LocalDnsRecord, LocalDnsRecordType};
use super::{
    audit_safesearch_effective_rewrites, find_cname_cycle, is_private_v6, is_public_suffix,
    validate_local_records_v2, LOCAL_RECORDS_CNAME_LOOP, LOCAL_RECORDS_DUPLICATE,
    LOCAL_RECORDS_INVALID_TARGET_A, LOCAL_RECORDS_INVALID_TARGET_AAAA,
    LOCAL_RECORDS_PUBLIC_TARGET_WARN, LOCAL_RECORDS_RESERVED_TARGET_REFUSAL,
    LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL, LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL,
    LOCAL_RECORDS_TTL_OUT_OF_RANGE,
};

/// cfg-validator-09 (rev-2606): fe80::/10 link-local targets are
/// operator-internal, not "public" — parity with the v4 side's
/// 169.254/16 handling.
#[test]
fn private_v6_covers_ula_and_link_local() {
    assert!(is_private_v6("fc00::1".parse().unwrap()));
    assert!(is_private_v6("fd12:3456::1".parse().unwrap()));
    assert!(is_private_v6("fe80::1".parse().unwrap()));
    // Top of fe80::/10 (febf:…) is still link-local…
    assert!(is_private_v6("febf:ffff::1".parse().unwrap()));
    // …but fec0:: (deprecated site-local) and documentation/public
    // ranges are not.
    assert!(!is_private_v6("fec0::1".parse().unwrap()));
    assert!(!is_private_v6("fe00::1".parse().unwrap()));
    assert!(!is_private_v6("2001:db8::1".parse().unwrap()));
}

fn rec(domain: &str, kind: LocalDnsRecordType, value: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        domain: domain.into(),
        record_type: kind,
        value: value.into(),
        match_subdomains: false,
        ttl_secs: None,
    }
}

fn rec_sub(domain: &str, kind: LocalDnsRecordType, value: &str) -> LocalDnsRecord {
    let mut r = rec(domain, kind, value);
    r.match_subdomains = true;
    r
}

fn rec_ttl(domain: &str, kind: LocalDnsRecordType, value: &str, ttl: u32) -> LocalDnsRecord {
    let mut r = rec(domain, kind, value);
    r.ttl_secs = Some(ttl);
    r
}

fn run_v2(records: &[LocalDnsRecord]) -> Vec<String> {
    let mut errs = Vec::new();
    validate_local_records_v2(records, "local_dns", &mut errs);
    errs
}

// ── frozen-string sanity (every const non-empty) ─────────────

#[test]
fn s44_t1_frozen_string_consts_non_empty() {
    // Lightweight smoke: every frozen-string const is referenced by
    // at least one test below and is non-empty here. T4's dedicated
    // `tests/frozen_strings_local_dns_v2.rs` pins them byte-for-byte
    // (R3 BLOCK).
    for s in [
        LOCAL_RECORDS_DUPLICATE,
        LOCAL_RECORDS_INVALID_TARGET_A,
        LOCAL_RECORDS_INVALID_TARGET_AAAA,
        LOCAL_RECORDS_RESERVED_TARGET_REFUSAL,
        LOCAL_RECORDS_PUBLIC_TARGET_WARN,
        LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL,
        LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL,
        LOCAL_RECORDS_TTL_OUT_OF_RANGE,
        LOCAL_RECORDS_CNAME_LOOP,
    ] {
        assert!(!s.is_empty());
        assert!(s.starts_with("local_records:"));
    }
}

// ── DR9 — PSL guard ─────────────────────────────────────────

#[test]
fn s44_t1_psl_hit_com_rejected_with_match_subdomains() {
    let errs = run_v2(&[rec_sub("com", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(
        errs.iter().any(|e| e.contains("public suffix")
            && e.contains("'com'")
            && e.contains("match_subdomains")),
        "expected PSL refusal, got: {errs:?}"
    );
}

#[test]
fn s44_t1_psl_hit_it_rejected_with_match_subdomains() {
    let errs = run_v2(&[rec_sub("it", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("public suffix") && e.contains("'it'")),
        "expected PSL refusal for 'it', got: {errs:?}"
    );
}

#[test]
fn s44_t1_psl_hit_couk_rejected() {
    let errs = run_v2(&[rec_sub("co.uk", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("public suffix") && e.contains("'co.uk'")),
        "expected PSL refusal for 'co.uk', got: {errs:?}"
    );
}

#[test]
fn s44_t1_psl_miss_example_com_accepts_match_subdomains() {
    // `example.com` is NOT a public suffix — match_subdomains: true
    // is a perfectly valid wildcard for an apex.
    let errs = run_v2(&[rec_sub("example.com", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(
        !errs.iter().any(|e| e.contains("public suffix")),
        "example.com must not trigger PSL refusal, got: {errs:?}"
    );
}

#[test]
fn s44_t1_psl_miss_nas_home_accepts_match_subdomains() {
    // Internal-only TLD — not in PSL, must accept match_subdomains.
    let errs = run_v2(&[rec_sub("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
    assert!(
        !errs.iter().any(|e| e.contains("public suffix")),
        "nas.home must not trigger PSL refusal, got: {errs:?}"
    );
}

#[test]
fn s44_t1_is_public_suffix_helper_basic() {
    // Direct exercise of the helper: equality match, case insensitive,
    // trailing-dot tolerant.
    assert!(is_public_suffix("com"));
    assert!(is_public_suffix("COM"));
    assert!(is_public_suffix("com."));
    assert!(is_public_suffix("co.uk"));
    assert!(!is_public_suffix("example.com"));
    assert!(!is_public_suffix(""));
    assert!(!is_public_suffix("nas.home"));
}

// ── DR10 — empty-domain + match_subdomains guard ────────────

#[test]
fn s44_t1_empty_domain_with_match_subdomains_refused() {
    let errs = run_v2(&[rec_sub("", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("empty domain") && e.contains("match every query")),
        "expected root-refusal, got: {errs:?}"
    );
}

// ── DR16 — reserved-IP target refusal ───────────────────────

#[test]
fn s44_t1_reserved_v4_unspecified_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "0.0.0.0")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast") && e.contains("'0.0.0.0'")),
        "expected reserved-IP refusal for 0.0.0.0, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v4_loopback_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "127.0.0.1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast") && e.contains("'127.0.0.1'")),
        "expected reserved-IP refusal for 127.0.0.1, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v4_broadcast_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "255.255.255.255")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast") && e.contains("'255.255.255.255'")),
        "expected reserved-IP refusal for broadcast, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v4_multicast_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "224.0.0.1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast") && e.contains("'224.0.0.1'")),
        "expected reserved-IP refusal for multicast 224.0.0.1, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v4_class_e_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "240.0.0.5")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast") && e.contains("'240.0.0.5'")),
        "expected reserved-IP refusal for class-E, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v6_unspecified_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::AAAA, "::")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast")),
        "expected reserved-IP refusal for ::, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v6_loopback_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::AAAA, "::1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast")),
        "expected reserved-IP refusal for ::1, got: {errs:?}"
    );
}

#[test]
fn s44_t1_reserved_v6_multicast_refused() {
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::AAAA, "ff02::1")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved/loopback/multicast")),
        "expected reserved-IP refusal for ff02::1, got: {errs:?}"
    );
}

// ── DR6 — RFC1918 and ULA accept; public IP warn (non-error) ─

#[test]
fn s44_t1_rfc1918_target_accepted() {
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 all pass silently.
    for ip in ["10.10.0.5", "172.16.5.5", "192.168.1.10"] {
        let errs = run_v2(&[rec("nas.lan", LocalDnsRecordType::A, ip)]);
        assert!(
            errs.is_empty(),
            "RFC1918 target {ip} must pass silently, got: {errs:?}"
        );
    }
}

#[test]
fn s44_t1_ula_v6_target_accepted() {
    let errs = run_v2(&[rec("nas.lan", LocalDnsRecordType::AAAA, "fc00::1")]);
    assert!(
        errs.is_empty(),
        "ULA target fc00::1 must pass silently, got: {errs:?}"
    );
}

#[test]
fn s44_t1_link_local_v4_target_accepted() {
    // 169.254.0.0/16 — link-local. Treated as "internal" for this
    // posture (matches the use case of redirecting to a local proxy
    // discovered via APIPA).
    let errs = run_v2(&[rec("trap.lan", LocalDnsRecordType::A, "169.254.1.1")]);
    assert!(
        errs.is_empty(),
        "link-local must pass silently, got: {errs:?}"
    );
}

#[test]
fn s44_t1_public_ip_v4_target_accepted_with_warn() {
    // DR6: public IP is a deliberate-but-unusual operator MITM
    // choice. Validator emits an audit-only WARN, NOT a hard error.
    let errs = run_v2(&[rec("bank.it", LocalDnsRecordType::A, "8.8.8.8")]);
    assert!(
        errs.is_empty(),
        "public-IP target must not be a hard error (DR6), got: {errs:?}"
    );
}

#[test]
fn s44_t1_public_ip_v6_target_accepted_with_warn() {
    let errs = run_v2(&[rec(
        "bank.it",
        LocalDnsRecordType::AAAA,
        "2001:4860:4860::8888",
    )]);
    assert!(
        errs.is_empty(),
        "public-IP v6 target must not be a hard error (DR6), got: {errs:?}"
    );
}

// ── DR5 — TTL range guard ───────────────────────────────────

#[test]
fn s44_t1_ttl_zero_rejected() {
    let errs = run_v2(&[rec_ttl("nas.lan", LocalDnsRecordType::A, "10.0.0.1", 0)]);
    assert!(
        errs.iter().any(|e| e.contains("ttl_secs=0")
            && e.contains("out of range")
            && e.contains("1..=86400")),
        "expected TTL=0 refusal, got: {errs:?}"
    );
}

#[test]
fn s44_t1_ttl_too_high_rejected() {
    let errs = run_v2(&[rec_ttl(
        "nas.lan",
        LocalDnsRecordType::A,
        "10.0.0.1",
        86_401,
    )]);
    assert!(
        errs.iter()
            .any(|e| e.contains("ttl_secs=86401") && e.contains("out of range")),
        "expected TTL>86400 refusal, got: {errs:?}"
    );
}

#[test]
fn s44_t1_ttl_at_min_accepted() {
    let errs = run_v2(&[rec_ttl("nas.lan", LocalDnsRecordType::A, "10.0.0.1", 1)]);
    assert!(errs.is_empty(), "TTL=1 must accept, got: {errs:?}");
}

#[test]
fn s44_t1_ttl_at_max_accepted() {
    let errs = run_v2(&[rec_ttl(
        "nas.lan",
        LocalDnsRecordType::A,
        "10.0.0.1",
        86_400,
    )]);
    assert!(errs.is_empty(), "TTL=86400 must accept, got: {errs:?}");
}

#[test]
fn s44_t1_ttl_unset_falls_back_silently() {
    let errs = run_v2(&[rec("nas.lan", LocalDnsRecordType::A, "10.0.0.1")]);
    assert!(errs.is_empty(), "ttl_secs=None must accept, got: {errs:?}");
}

// ── DR8 — per-scope duplicate ───────────────────────────────

#[test]
fn s44_t1_duplicate_a_in_same_scope_rejected() {
    let errs = run_v2(&[
        rec("nas.lan", LocalDnsRecordType::A, "10.0.0.1"),
        rec("nas.lan", LocalDnsRecordType::A, "10.0.0.2"),
    ]);
    assert!(
        errs.iter().any(|e| e.contains("duplicate A record")
            && e.contains("'nas.lan'")
            && e.contains("match_subdomains=false")),
        "expected v2 dup A error, got: {errs:?}"
    );
}

#[test]
fn s44_t1_duplicate_aaaa_in_same_scope_rejected() {
    let errs = run_v2(&[
        rec("nas.lan", LocalDnsRecordType::AAAA, "fc00::1"),
        rec("nas.lan", LocalDnsRecordType::AAAA, "fc00::2"),
    ]);
    assert!(
        errs.iter()
            .any(|e| e.contains("duplicate AAAA record") && e.contains("'nas.lan'")),
        "expected v2 dup AAAA error, got: {errs:?}"
    );
}

#[test]
fn s44_t1_duplicate_cname_in_same_scope_rejected() {
    let errs = run_v2(&[
        rec("alias.lan", LocalDnsRecordType::CNAME, "host1.lan"),
        rec("alias.lan", LocalDnsRecordType::CNAME, "host2.lan"),
    ]);
    assert!(
        errs.iter()
            .any(|e| e.contains("duplicate CNAME record") && e.contains("'alias.lan'")),
        "expected v2 dup CNAME error, got: {errs:?}"
    );
}

#[test]
fn s44_t1_same_domain_a_and_aaaa_no_conflict() {
    // Dual-stack pattern — must accept.
    let errs = run_v2(&[
        rec("nas.lan", LocalDnsRecordType::A, "10.0.0.1"),
        rec("nas.lan", LocalDnsRecordType::AAAA, "fc00::1"),
    ]);
    assert!(
        errs.is_empty(),
        "A+AAAA dual-stack must accept, got: {errs:?}"
    );
}

// ── A+CNAME conflict per scope ──────────────────────────────

#[test]
fn s44_t1_a_plus_cname_per_scope_rejected() {
    let errs = run_v2(&[
        rec("nas.lan", LocalDnsRecordType::A, "10.0.0.1"),
        rec("nas.lan", LocalDnsRecordType::CNAME, "alt.lan"),
    ]);
    assert!(
        errs.iter()
            .any(|e| e.contains("nas.lan") && e.contains("A record") && e.contains("CNAME")),
        "expected A+CNAME conflict, got: {errs:?}"
    );
}

#[test]
fn s44_t1_aaaa_plus_cname_per_scope_rejected() {
    let errs = run_v2(&[
        rec("nas.lan", LocalDnsRecordType::AAAA, "fc00::1"),
        rec("nas.lan", LocalDnsRecordType::CNAME, "alt.lan"),
    ]);
    assert!(
        errs.iter()
            .any(|e| e.contains("nas.lan") && e.contains("AAAA record") && e.contains("CNAME")),
        "expected AAAA+CNAME conflict, got: {errs:?}"
    );
}

// ── Generalised CNAME loop ──────────────────────────────────

#[test]
fn s44_t1_cname_self_loop_detected() {
    let errs = run_v2(&[rec("a.lan", LocalDnsRecordType::CNAME, "a.lan")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("CNAME loop") && e.contains("'a.lan'")),
        "expected self-loop detection, got: {errs:?}"
    );
}

#[test]
fn s44_t1_cname_two_hop_cycle_detected() {
    // a → b → a
    let errs = run_v2(&[
        rec("a.lan", LocalDnsRecordType::CNAME, "b.lan"),
        rec("b.lan", LocalDnsRecordType::CNAME, "a.lan"),
    ]);
    assert!(
        errs.iter().any(|e| e.contains("CNAME loop")),
        "expected 2-hop cycle detection, got: {errs:?}"
    );
}

#[test]
fn s44_t1_cname_three_hop_cycle_detected() {
    // a → b → c → a
    let errs = run_v2(&[
        rec("a.lan", LocalDnsRecordType::CNAME, "b.lan"),
        rec("b.lan", LocalDnsRecordType::CNAME, "c.lan"),
        rec("c.lan", LocalDnsRecordType::CNAME, "a.lan"),
    ]);
    assert!(
        errs.iter().any(|e| e.contains("CNAME loop")),
        "expected 3-hop cycle detection, got: {errs:?}"
    );
}

#[test]
fn s44_t1_cname_chain_terminating_outside_set_no_cycle() {
    // a → b → external.example — no cycle, must accept.
    let errs = run_v2(&[
        rec("a.lan", LocalDnsRecordType::CNAME, "b.lan"),
        rec("b.lan", LocalDnsRecordType::CNAME, "external.example"),
    ]);
    assert!(
        !errs.iter().any(|e| e.contains("CNAME loop")),
        "chain terminating outside set must not flag, got: {errs:?}"
    );
}

#[test]
fn s44_t1_find_cname_cycle_helper_returns_none_on_acyclic() {
    let records = vec![
        rec("a.lan", LocalDnsRecordType::CNAME, "b.lan"),
        rec("b.lan", LocalDnsRecordType::A, "10.0.0.5"),
    ];
    assert!(find_cname_cycle(&records).is_none());
}

// ── Invalid IP target for A / AAAA ──────────────────────────

#[test]
fn s44_t1_invalid_ipv4_value_rejected_with_v2_string() {
    let errs = run_v2(&[rec("nas.lan", LocalDnsRecordType::A, "not-an-ip")]);
    assert!(
        errs.iter().any(|e| e.contains("not a valid IPv4 address")
            && e.contains("'not-an-ip'")
            && e.contains("'nas.lan'")),
        "expected v2 invalid-IPv4 error, got: {errs:?}"
    );
}

#[test]
fn s44_t1_invalid_ipv6_value_rejected_with_v2_string() {
    let errs = run_v2(&[rec("nas.lan", LocalDnsRecordType::AAAA, "not-v6")]);
    assert!(
        errs.iter()
            .any(|e| e.contains("not a valid IPv6 address") && e.contains("'not-v6'")),
        "expected v2 invalid-IPv6 error, got: {errs:?}"
    );
}

// ── Per-profile vs global scope independence (DR7 hint) ─────
//
// The helper takes a slice + scope label; each call is independent.
// This proves that the "same (domain, type) appears in profile A and
// profile B" case does not collide when validated as separate scopes.

#[test]
fn s44_t1_per_scope_independence() {
    let global_records = vec![rec("nas.lan", LocalDnsRecordType::A, "10.0.0.1")];
    let mut e1 = Vec::new();
    validate_local_records_v2(&global_records, "local_dns", &mut e1);

    let profile_records = vec![rec("nas.lan", LocalDnsRecordType::A, "10.0.0.99")];
    let mut e2 = Vec::new();
    validate_local_records_v2(&profile_records, "profiles.kids.local_records", &mut e2);

    assert!(e1.is_empty(), "global scope clean, got: {e1:?}");
    assert!(e2.is_empty(), "profile scope clean, got: {e2:?}");
}

// ── Sprint 18 backward compat ───────────────────────────────

#[test]
fn s44_t1_serde_default_match_subdomains_is_false() {
    // R1 additive: new field deserialises to false when absent.
    let toml_src = r#"
domain = "nas.home"
type = "A"
value = "192.168.1.50"
"#;
    let r: LocalDnsRecord = toml::from_str(toml_src).unwrap();
    assert!(!r.match_subdomains);
    assert!(r.ttl_secs.is_none());
}

#[test]
fn s44_t1_serde_explicit_match_subdomains_parses() {
    let toml_src = r#"
domain = "example.test"
type = "A"
value = "10.10.1.50"
match_subdomains = true
ttl_secs = 300
"#;
    let r: LocalDnsRecord = toml::from_str(toml_src).unwrap();
    assert!(r.match_subdomains);
    assert_eq!(r.ttl_secs, Some(300));
}

#[test]
fn s44_t1_v1_profile_local_records_defaults_empty() {
    // Profile in the v1 schema gets `local_records` as an empty
    // Vec by default (DM1, R1 additive).
    use crate::config::schema::Profile;
    let toml_src = r#"
display_name = "Default"
"#;
    let p: Profile = toml::from_str(toml_src).unwrap();
    assert!(p.local_records.is_empty());
}

#[test]
fn s44_t1_v1_profile_local_records_parses() {
    use crate::config::schema::Profile;
    let toml_src = r#"
display_name = "Employees"

[[local_records]]
domain = "example.test"
type = "A"
value = "10.10.1.50"
match_subdomains = true
ttl_secs = 600
"#;
    let p: Profile = toml::from_str(toml_src).unwrap();
    assert_eq!(p.local_records.len(), 1);
    assert_eq!(p.local_records[0].domain, "example.test");
    assert!(p.local_records[0].match_subdomains);
    assert_eq!(p.local_records[0].ttl_secs, Some(600));
}

// ── Combined / aggregate ────────────────────────────────────

#[test]
fn s44_t1_full_use_case_passes() {
    // The actual scenario from the design doc §1: redirect example.test
    // (and every subdomain) to an internal proxy on a profile.
    let errs = run_v2(&[
        rec_sub("example.test", LocalDnsRecordType::A, "10.10.1.50"),
        rec("auth.example.test", LocalDnsRecordType::A, "10.10.1.51"),
    ]);
    assert!(
        errs.is_empty(),
        "headline use case must pass cleanly, got: {errs:?}"
    );
}

#[test]
fn s44_t1_multiple_violations_aggregated() {
    // Validator returns ALL errors, not just the first.
    let errs = run_v2(&[
        rec("trap.lan", LocalDnsRecordType::A, "0.0.0.0"),
        rec_sub("com", LocalDnsRecordType::A, "10.0.0.1"),
        rec_ttl("nas.lan", LocalDnsRecordType::A, "10.0.0.2", 0),
    ]);
    assert!(
        errs.len() >= 3,
        "expected at least 3 errors aggregated, got {}: {errs:?}",
        errs.len()
    );
}

// ── Per-profile validation via v1 schema validator ──────────

#[test]
fn s44_t1_v1_schema_validator_runs_per_profile_records() {
    use crate::config::schema::{ConfigV1, Profile, SCHEMA_VERSION_V1};
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    let mut profiles: BTreeMap<String, Profile> = BTreeMap::new();
    let bad_profile = Profile {
        display_name: "Bad".into(),
        local_records: vec![rec("trap.lan", LocalDnsRecordType::A, "0.0.0.0")],
        ..Profile::default()
    };
    profiles.insert("bad".into(), bad_profile);

    let cfg = ConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        profiles,
        ..ConfigV1::test_scaffold()
    };
    let now = OffsetDateTime::now_utc();
    let errs = crate::config::schema::validator::validate(&cfg, now).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("reserved/loopback/multicast")),
        "v1 schema validator must surface reserved-IP refusal on profile.local_records, got: {errs:?}"
    );
}

// ── §4.12 Domain Rewrite Rules — validator coverage ─────────

use super::super::settings::RewriteRule;
use super::{
    find_rewrite_cycle, is_reserved_tld, is_valid_fqdn_syntax, validate_rewrite_rules,
    REWRITE_CYCLE, REWRITE_DUPLICATE, REWRITE_IDENTITY, REWRITE_INVALID_FQDN_FROM,
    REWRITE_INVALID_FQDN_TO, REWRITE_RESERVED_DOMAIN_REFUSAL, REWRITE_SUBDOMAIN_ROOT_REFUSAL,
    REWRITE_SUBDOMAIN_TLD_REFUSAL,
};

fn rule(from: &str, to: &str) -> RewriteRule {
    RewriteRule {
        from: from.into(),
        to: to.into(),
        match_subdomains: false,
    }
}

fn rule_sub(from: &str, to: &str) -> RewriteRule {
    let mut r = rule(from, to);
    r.match_subdomains = true;
    r
}

fn run_rewrites(rules: &[RewriteRule]) -> Vec<String> {
    let mut errs = Vec::new();
    let mut warns = Vec::new();
    validate_rewrite_rules(
        rules,
        "profiles.x.rewrite_rules",
        &[],
        &[],
        &mut errs,
        &mut warns,
    );
    errs
}

/// Like [`run_rewrites`] but returns the audit-channel warnings.
fn run_rewrites_warnings(
    rules: &[RewriteRule],
    local_records: &[LocalDnsRecord],
    global_records: &[LocalDnsRecord],
) -> Vec<String> {
    let mut errs = Vec::new();
    let mut warns = Vec::new();
    validate_rewrite_rules(
        rules,
        "profiles.x.rewrite_rules",
        local_records,
        global_records,
        &mut errs,
        &mut warns,
    );
    warns
}

#[test]
fn s412_rewrite_happy_path_passes() {
    // example-int is not in PSL nor reserved-TLD; fqdn is valid.
    let rules = vec![
        rule("api.old-corp.example-int", "api.new-corp.example-int"),
        rule_sub("legacy.svc.example-int", "modern.svc.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(errs.is_empty(), "happy path must pass cleanly: {errs:?}");
}

#[test]
fn s412_rewrite_empty_from_refused() {
    let rules = vec![rule("", "api.new.example-int")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("must not be empty")),
        "expected ROOT_REFUSAL frozen, got: {errs:?}"
    );
    // Frozen string still byte-accessible:
    assert!(REWRITE_SUBDOMAIN_ROOT_REFUSAL.contains("must not be empty"));
}

#[test]
fn s412_rewrite_invalid_fqdn_from() {
    // Space inside a label is not a valid FQDN character.
    let rules = vec![rule("foo bar.example-int", "api.new.example-int")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("not a valid FQDN")),
        "expected INVALID_FQDN_FROM, got: {errs:?}"
    );
    assert!(REWRITE_INVALID_FQDN_FROM.contains("not a valid FQDN"));
}

#[test]
fn s412_rewrite_invalid_fqdn_to() {
    let rules = vec![rule("ok.from.example-int", "-leading-hyphen.example-int")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter()
            .any(|e| e.contains("not a valid FQDN") && e.contains(".to:")),
        "expected INVALID_FQDN_TO with .to: prefix, got: {errs:?}"
    );
    assert!(REWRITE_INVALID_FQDN_TO.contains("not a valid FQDN"));
}

#[test]
fn s412_rewrite_subdomain_tld_refusal() {
    // match_subdomains on a public suffix (`com`).
    let rules = vec![rule_sub("com", "io")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("public suffix")),
        "expected SUBDOMAIN_TLD_REFUSAL, got: {errs:?}"
    );
    assert!(REWRITE_SUBDOMAIN_TLD_REFUSAL.contains("public suffix"));
}

#[test]
fn s412_rewrite_reserved_tld_refused_from() {
    let rules = vec![rule("api.localhost", "api.real.example-int")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved") && e.contains("from")),
        "expected RESERVED_DOMAIN_REFUSAL on from side, got: {errs:?}"
    );
    assert!(REWRITE_RESERVED_DOMAIN_REFUSAL.contains("reserved"));
}

#[test]
fn s412_rewrite_reserved_tld_refused_to() {
    let rules = vec![rule("api.real.example-int", "api.invalid")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter()
            .any(|e| e.contains("reserved") && e.contains("to")),
        "expected RESERVED_DOMAIN_REFUSAL on to side, got: {errs:?}"
    );
}

#[test]
fn s412_rewrite_identity_refused() {
    let rules = vec![rule("same.example-int", "same.example-int")];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("identical")),
        "expected IDENTITY refusal, got: {errs:?}"
    );
    assert!(REWRITE_IDENTITY.contains("identical"));
}

#[test]
fn s412_rewrite_duplicate_pair_refused() {
    let rules = vec![
        rule("api.x.example-int", "api.y.example-int"),
        rule("api.x.example-int", "api.z.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter()
            .any(|e| e.contains("duplicate rule for 'api.x.example-int'")),
        "expected DUPLICATE, got: {errs:?}"
    );
    assert!(REWRITE_DUPLICATE.contains("duplicate rule for"));
}

#[test]
fn s412_rewrite_distinct_match_subdomains_allowed_same_from() {
    // Same `from` with match_subdomains true and false should NOT
    // trigger duplicate — the (from, flag) tuple is the key.
    let rules = vec![
        rule("api.example-int", "api.new.example-int"),
        rule_sub("api.example-int", "wild.new.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        !errs.iter().any(|e| e.contains("duplicate")),
        "distinct flag must not duplicate, got: {errs:?}"
    );
}

#[test]
fn s412_rewrite_cycle_detected_validator() {
    let rules = vec![
        rule("a.example-int", "b.example-int"),
        rule("b.example-int", "a.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("rewrite cycle detected")),
        "expected CYCLE error, got: {errs:?}"
    );
    assert!(REWRITE_CYCLE.contains("rewrite cycle detected"));
}

#[test]
fn s412_rewrite_cycle_three_hop_detected() {
    let rules = vec![
        rule("a.example-int", "b.example-int"),
        rule("b.example-int", "c.example-int"),
        rule("c.example-int", "a.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        errs.iter().any(|e| e.contains("rewrite cycle detected")),
        "expected N-hop CYCLE error, got: {errs:?}"
    );
}

#[test]
fn s412_rewrite_acyclic_chain_passes() {
    // a → b, b → c — no cycle.
    let rules = vec![
        rule("a.example-int", "b.example-int"),
        rule("b.example-int", "c.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        !errs.iter().any(|e| e.contains("cycle")),
        "acyclic chain must not trigger cycle error, got: {errs:?}"
    );
    // find_rewrite_cycle exposed for the engine layer:
    assert!(find_rewrite_cycle(&rules).is_none());
}

#[test]
fn s412_rewrite_subdomain_rule_excluded_from_cycle_walk() {
    // A subdomain-matching rule does not participate in the
    // static graph — its cycle potential is bounded by the
    // runtime depth=1 single-pass guard. Two subdomain rules
    // that LOOK cyclic (a.com → b.com, b.com → a.com both with
    // match_subdomains) must NOT trigger CYCLE.
    let rules = vec![
        rule_sub("a.example-int", "b.example-int"),
        rule_sub("b.example-int", "a.example-int"),
    ];
    let errs = run_rewrites(&rules);
    assert!(
        !errs.iter().any(|e| e.contains("cycle")),
        "subdomain rules excluded from static cycle check, got: {errs:?}"
    );
}

#[test]
fn s412_fqdn_syntax_helper_paths() {
    assert!(is_valid_fqdn_syntax("api.example-int.example"));
    assert!(is_valid_fqdn_syntax("api.example-int.example."));
    assert!(is_valid_fqdn_syntax("_acme-challenge.example.example-int"));
    assert!(!is_valid_fqdn_syntax(""));
    assert!(!is_valid_fqdn_syntax("-leading.example"));
    assert!(!is_valid_fqdn_syntax("trailing-.example"));
    assert!(!is_valid_fqdn_syntax("has space.example"));
    assert!(!is_valid_fqdn_syntax(".."));
    let too_long_label = "a".repeat(64);
    assert!(!is_valid_fqdn_syntax(&format!("{too_long_label}.example")));
}

#[test]
fn s412_reserved_tld_helper_paths() {
    assert!(is_reserved_tld("api.localhost"));
    assert!(is_reserved_tld("foo.local"));
    assert!(is_reserved_tld("hidden.onion"));
    assert!(is_reserved_tld("ipv4.arpa"));
    assert!(is_reserved_tld("router.invalid"));
    assert!(is_reserved_tld("anything.example"));
    assert!(is_reserved_tld("ci.test"));
    assert!(!is_reserved_tld("example.com"));
    assert!(!is_reserved_tld("example-int"));
    // rev-2606 cfg-validator-06 — RFC 8375 home-network domain is
    // usable; the rest of arpa stays reserved.
    assert!(!is_reserved_tld("home.arpa"));
    assert!(!is_reserved_tld("nas.home.arpa"));
    assert!(!is_reserved_tld("NAS.Home.Arpa."));
    assert!(is_reserved_tld("1.168.192.in-addr.arpa"));
    assert!(is_reserved_tld("ip6.arpa"));
    assert!(is_reserved_tld("arpa"));
    // No suffix-confusion: "myhome.arpa" is NOT under home.arpa.
    assert!(is_reserved_tld("myhome.arpa"));
}

#[test]
fn home_arpa_rewrite_accepted_end_to_end() {
    // The full validator path: a home.arpa rewrite lints clean.
    let rules = vec![RewriteRule {
        from: "printer.home.arpa".into(),
        to: "nas.home.arpa".into(),
        match_subdomains: false,
    }];
    let errs = run_rewrites(&rules);
    assert!(
        errs.is_empty(),
        "home.arpa rewrite must lint clean: {errs:?}"
    );
}

fn local_rec(domain: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        domain: domain.into(),
        record_type: LocalDnsRecordType::A,
        value: "192.168.1.10".into(),
        match_subdomains: false,
        ttl_secs: None,
    }
}

#[test]
fn rev2606_shadow_warns_profile_and_global_scopes() {
    // cfg-validator-07: a rewrite `from` shadowed by a PROFILE record
    // warns with the same-scope message; shadowed by a GLOBAL record
    // warns with the global message; present in both → both.
    let rules = vec![RewriteRule {
        from: "nas.lan".into(),
        to: "other.lan".into(),
        match_subdomains: false,
    }];

    let warns = run_rewrites_warnings(&rules, &[local_rec("nas.lan")], &[]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("in the same scope"));

    let warns = run_rewrites_warnings(&rules, &[], &[local_rec("NAS.Lan.")]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("global [[local_dns.records]]"));

    let warns = run_rewrites_warnings(&rules, &[local_rec("nas.lan")], &[local_rec("nas.lan")]);
    assert_eq!(warns.len(), 2, "{warns:?}");

    let warns = run_rewrites_warnings(&rules, &[], &[]);
    assert!(warns.is_empty(), "{warns:?}");
}

#[test]
fn s4_m2_underscore_service_name_on_from_warns() {
    // config-m2. The MitM primitive lives on `from` — the name the
    // victim actually queries. `to` can be any ordinary hostname, so a
    // check on `to` (which the backlog entry prescribed) would defend
    // nothing. Name-neutral by construction: the predicate reads the
    // leading byte of each label and never consults a service name.
    let rules = vec![rule(
        "_dmarc.corp.example-int",
        "collector.vendor.example-int",
    )];
    let warns = run_rewrites_warnings(&rules, &[], &[]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("underscore-prefixed service name"),
        "{warns:?}"
    );
    assert!(warns[0].contains("_dmarc.corp.example-int"), "{warns:?}");

    // WARN, not refusal — the rule stays legal. An operator running a
    // split-horizon ACME responder or migrating a SRV-published service
    // is doing something legitimate; warden reports, it does not veto.
    assert!(run_rewrites(&rules).is_empty(), "must not be a refusal");

    // The `_service._proto` scoped form puts the underscore label in the
    // middle. Same RFC 8552 namespace, same warning.
    let warns = run_rewrites_warnings(
        &[rule("_sip._tcp.corp.example-int", "pbx.example-int")],
        &[],
        &[],
    );
    assert_eq!(warns.len(), 1, "{warns:?}");

    // An ordinary migration stays silent. This half is what keeps the
    // check from degrading into noise the operator learns to skip.
    let warns = run_rewrites_warnings(
        &[rule("api.old-corp.example-int", "api.new-corp.example-int")],
        &[],
        &[],
    );
    assert!(warns.is_empty(), "{warns:?}");
}

/// `neutrality-04` (2026-08-16) — inverted from
/// `rev2606_safesearch_preset_shadowed_by_local_record_warns`.
///
/// **The injected defaults this test used to assert on were the
/// violation.** It passed only because `populate` appended
/// `www.google.com` and `duckduckgo.com` to every `safe_search`
/// profile — vendor hostnames chosen by warden, absent from the
/// operator's TOML and unchangeable without a new build. So the
/// inversion is the substance of the fix, not fallout from it: a
/// version of this test that still went green would mean the table
/// had survived somewhere.
///
/// What is asserted now is the shadow audit finding **nothing to
/// audit** when the operator authored nothing. The audit itself is
/// deliberately kept — see `audit_safesearch_effective_rewrites` —
/// so that if an operator-supplied engine table ever lands, the
/// diagnostic is already wired to the served set.
#[test]
fn neutrality04_no_preset_is_injected_to_be_shadowed() {
    // Zero authored rewrites + a local record on a hostname the
    // retired table used to inject: nothing is injected, so nothing
    // can be shadowed, so no WARN.
    let mut warns = Vec::new();
    audit_safesearch_effective_rewrites(&[], &[local_rec("www.google.com")], &[], &mut warns);
    assert!(
        warns.is_empty(),
        "a preset was injected and shadowed — the retired table is back: {warns:?}"
    );

    // Same via the global-scope record union (cfg-validator-07).
    let mut warns = Vec::new();
    audit_safesearch_effective_rewrites(&[], &[], &[local_rec("duckduckgo.com")], &mut warns);
    assert!(warns.is_empty(), "{warns:?}");
}

/// `neutrality-04` — inverted from
/// `rev2606_safesearch_cycle_with_preset_warns_not_errors`.
///
/// The old test built a cycle that existed **only** in the combined
/// graph: the operator's rule pointed at `forcesafesearch.google.com`
/// and warden's injected preset pointed back. With nothing injected
/// there is no second edge, so the same operator rule is a clean
/// one-hop rewrite — which is the correct reading of it. warden was
/// manufacturing both the second edge and the warning about it.
#[test]
fn neutrality04_operator_rule_alone_cannot_form_a_preset_cycle() {
    let rules = vec![RewriteRule {
        from: "forcesafesearch.google.com".into(),
        to: "google.com".into(),
        match_subdomains: false,
    }];
    assert!(run_rewrites(&rules).is_empty(), "raw slice must stay clean");

    let mut warns = Vec::new();
    audit_safesearch_effective_rewrites(&rules, &[], &[], &mut warns);
    assert!(
        warns.is_empty(),
        "a cycle can only appear here if something injected the return edge: {warns:?}"
    );

    // Control arm: cycle detection is still alive. Without it the
    // assertion above would pass just as happily on a detector that
    // had been accidentally disabled — "no warning" is evidence only
    // when something can still produce one. An operator who authors
    // both edges gets the hard refusal the raw slice has always
    // carried.
    let both_edges = vec![
        RewriteRule {
            from: "a.example-int".into(),
            to: "b.example-int".into(),
            match_subdomains: false,
        },
        RewriteRule {
            from: "b.example-int".into(),
            to: "a.example-int".into(),
            match_subdomains: false,
        },
    ];
    assert!(
        !run_rewrites(&both_edges).is_empty(),
        "an operator-authored cycle must still be refused"
    );
}

#[test]
fn rev2606_safesearch_clean_profile_stays_silent() {
    let rules = vec![RewriteRule {
        from: "ads.lan".into(),
        to: "safe.lan".into(),
        match_subdomains: false,
    }];
    let mut warns = Vec::new();
    audit_safesearch_effective_rewrites(&rules, &[local_rec("other.lan")], &[], &mut warns);
    assert!(warns.is_empty(), "{warns:?}");
}

#[test]
fn rev2606_safesearch_operator_override_not_reaudited() {
    // Operator explicitly overrides a preset source AND has a local
    // record for it: the operator rule's shadow is validate's duty
    // (not the audit's), and populate skips the preset — so the audit
    // emits nothing for that hostname.
    let rules = vec![RewriteRule {
        from: "www.google.com".into(),
        to: "intranet.lan".into(),
        match_subdomains: false,
    }];
    let mut warns = Vec::new();
    audit_safesearch_effective_rewrites(&rules, &[local_rec("www.google.com")], &[], &mut warns);
    assert!(
        warns.is_empty(),
        "occupied preset must not re-warn via the audit: {warns:?}"
    );
}
