//! rev-2606 cfg-validator-03 (+04): lint↔engine agreement for local-DNS
//! records and rewrite rules.
//!
//! The campaign's central property — a record or rewrite spelling that
//! `warden config lint` accepts MUST resolve at runtime, and a spelling
//! lint refuses MUST be one the engine would have silently dropped.
//! Both sides now share `config::validator::canonicalize_domain` (trim →
//! strip trailing dots → ASCII-lowercase); this file pins the agreement
//! so a future fork of the two paths fails loudly instead of re-creating
//! the lint-clean-but-dead-record bug (`"nas.home."` validated, then
//! dropped at `Name::from_str("nas.home..")`).
//!
//! Per fixture: (1) the lint verdict via the public `load_from_str`
//! (full config load + validate), (2) the engine verdict by building the
//! runtime table from the SAME loaded config and probing it with the
//! handler-shaped query string (lowercase, no trailing dot).

use hickory_proto::rr::{RData, RecordType};
use purge_warden::config::schema::load::load_from_str;
use purge_warden::config::schema::ConfigV1;
use purge_warden::dns::local::{LocalLookup, LocalRecords};
use purge_warden::dns::local_profile::ProfileLocalRecords;
use purge_warden::dns::rewrite::ProfileRewriteRules;

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_600)
}

/// Minimal valid config wrapping the probe snippet (a `[local_dns]`
/// section or profile `rewrite_rules` / `local_records` rows).
fn config_with(snippet: &str) -> String {
    format!(
        r#"
schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

{snippet}

[upstream]
servers = ["192.0.2.1:53"]
"#
    )
}

fn load_ok(snippet: &str) -> ConfigV1 {
    match load_from_str(&config_with(snippet), None, now()) {
        Ok(cfg) => cfg,
        Err(errs) => panic!("expected lint-clean, got errors: {errs:?}"),
    }
}

fn load_err(snippet: &str) -> Vec<String> {
    match load_from_str(&config_with(snippet), None, now()) {
        Ok(_) => panic!("expected lint refusal, config loaded clean"),
        Err(errs) => errs.iter().map(|e| e.to_string()).collect(),
    }
}

// ── accepted spellings resolve (global scope) ───────────────────

#[test]
fn trailing_dot_global_record_lints_clean_and_resolves() {
    let cfg = load_ok(
        r#"
[[local_dns.records]]
domain = "NAS.Home."
type = "A"
value = "192.168.1.50"
"#,
    );
    let local = LocalRecords::build(&cfg.local_dns);
    // Handler-shaped probe: lowercase, no trailing dot.
    assert!(
        local.lookup("nas.home", RecordType::A).hit().is_some(),
        "validated trailing-dot spelling must build a reachable table entry"
    );
}

#[test]
fn whitespace_padded_global_record_lints_clean_and_resolves() {
    let cfg = load_ok(
        r#"
[[local_dns.records]]
domain = " printer.lan "
type = "A"
value = "192.168.1.60"
"#,
    );
    let local = LocalRecords::build(&cfg.local_dns);
    assert!(local.lookup("printer.lan", RecordType::A).hit().is_some());
}

#[test]
fn dotted_cname_target_follows_to_local_a_record() {
    let cfg = load_ok(
        r#"
[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"

[[local_dns.records]]
domain = "media.home"
type = "CNAME"
value = "NAS.Home."
"#,
    );
    let local = LocalRecords::build(&cfg.local_dns);
    let records = local
        .lookup("media.home", RecordType::A)
        .hit()
        .expect("CNAME with dotted target must resolve");
    // CNAME + followed local A record — the dotted spelling must not
    // break the in-table target probe.
    assert_eq!(
        records.len(),
        2,
        "expected CNAME + target A, got {records:?}"
    );
}

#[test]
fn wildcard_global_record_lints_clean_and_resolves_descendant() {
    // rev-2606 global-localdns-wildcard-dead: a global `match_subdomains = true`
    // record on a non-public-suffix apex lints clean (DR9 passes — `example.test`
    // is not a public suffix) AND must now resolve its descendants at runtime.
    // Pre-fix the engine ignored the flag, so this lint-clean record was
    // silently dead — exactly the lint-vs-engine split this suite guards.
    let cfg = load_ok(
        r#"
[[local_dns.records]]
domain = "example.test"
type = "A"
value = "192.0.2.50"
match_subdomains = true
"#,
    );
    let local = LocalRecords::build(&cfg.local_dns);
    let records = local
        .lookup("app.example.test", RecordType::A)
        .hit()
        .expect("a lint-clean global wildcard must resolve its descendants");
    assert_eq!(records.len(), 1);
    match records[0].data {
        RData::A(ref a) => assert_eq!(a.0, std::net::Ipv4Addr::new(192, 0, 2, 50)),
        _ => panic!("expected A record"),
    }
}

// ── accepted spellings resolve (profile scope) ──────────────────

#[test]
fn trailing_dot_profile_record_lints_clean_and_resolves() {
    let cfg = load_ok(
        r#"
[[profiles.default.local_records]]
domain = "Intranet.Corp."
type = "A"
value = "10.0.0.5"
"#,
    );
    let profile = &cfg.profiles["default"];
    let table = ProfileLocalRecords::build(&profile.local_records, cfg.local_dns.ttl_secs);
    assert!(table.lookup("intranet.corp", RecordType::A).is_some());
}

// ── canonical duplicates refuse (were silently dead before) ─────

#[test]
fn canonical_duplicate_global_records_refused() {
    // Pre-fix: "X.COM." was a distinct seen-set key (lint clean) and a
    // dead table entry (Name::from_str("x.com..") fails). Post-fix the
    // pair is one canonical spelling → duplicate refusal at lint.
    let errs = load_err(
        r#"
[[local_dns.records]]
domain = "x.com"
type = "A"
value = "192.168.1.1"

[[local_dns.records]]
domain = "X.COM."
type = "A"
value = "192.168.1.2"
"#,
    );
    assert!(
        errs.iter().any(|e| e.contains("duplicate")),
        "expected canonical-duplicate refusal, got: {errs:?}"
    );
}

#[test]
fn canonical_identity_rewrite_refused() {
    // from/to differing only by case + trailing dot is a no-op rule
    // post-canonicalization — the identity check must see one spelling.
    let errs = load_err(
        r#"
[[profiles.default.rewrite_rules]]
from = "x.corp"
to = "X.Corp."
"#,
    );
    assert!(
        errs.iter().any(|e| e.contains("identical")),
        "expected canonical-identity refusal, got: {errs:?}"
    );
}

#[test]
fn canonical_duplicate_rewrite_rules_refused() {
    let errs = load_err(
        r#"
[[profiles.default.rewrite_rules]]
from = "ads.corp"
to = "safe.corp"

[[profiles.default.rewrite_rules]]
from = "Ads.Corp."
to = "other.corp"
"#,
    );
    assert!(
        errs.iter().any(|e| e.contains("duplicate")),
        "expected canonical-duplicate refusal, got: {errs:?}"
    );
}

// ── accepted rewrite spellings fire at runtime ──────────────────

#[test]
fn dotted_mixed_case_rewrite_lints_clean_and_fires() {
    let cfg = load_ok(
        r#"
[[profiles.default.rewrite_rules]]
from = "Ads.Example.Com."
to = "Safe.Example.Com"
"#,
    );
    let profile = &cfg.profiles["default"];
    let rules = ProfileRewriteRules::build(&profile.rewrite_rules);
    assert_eq!(
        rules.apply("ads.example.com").as_deref(),
        Some("safe.example.com"),
        "validated dotted spelling must fire on the handler-shaped query"
    );
}

#[test]
fn dotted_wildcard_rewrite_fires_on_descendants() {
    let cfg = load_ok(
        r#"
[[profiles.default.rewrite_rules]]
from = "Old.Corp."
to = "New.Corp."
match_subdomains = true
"#,
    );
    let profile = &cfg.profiles["default"];
    let rules = ProfileRewriteRules::build(&profile.rewrite_rules);
    assert_eq!(rules.apply("api.old.corp").as_deref(), Some("api.new.corp"));
    // Apex shortcut too.
    assert_eq!(rules.apply("old.corp").as_deref(), Some("new.corp"));
}

// ── FQDN gate: lint refuses what the engine silently dropped ────
// (rev-2606 cfg-validator-04)

#[test]
fn malformed_domain_refused_and_engine_dead() {
    use purge_warden::config::settings::{LocalDnsConfig, LocalDnsRecord, LocalDnsRecordType};

    // Engine side: the builder drops the record (no table entry).
    let cfg = LocalDnsConfig {
        ttl_secs: 3600,
        dynamic_ttl_secs: 30,
        nodata_for_missing_types: true,
        records: vec![LocalDnsRecord {
            domain: "bad domain!".into(),
            record_type: LocalDnsRecordType::A,
            value: "192.168.1.1".into(),
            match_subdomains: false,
            ttl_secs: None,
        }],
    };
    let local = LocalRecords::build(&cfg);
    assert!(
        matches!(
            local.lookup("bad domain!", RecordType::A),
            LocalLookup::Miss
        ),
        "engine must not serve a structurally broken name"
    );

    // Lint side: the same spelling is now a load refusal.
    let errs = load_err(
        r#"
[[local_dns.records]]
domain = "bad domain!"
type = "A"
value = "192.168.1.1"
"#,
    );
    assert!(
        errs.iter().any(|e| e.contains("not a valid FQDN")),
        "expected FQDN refusal, got: {errs:?}"
    );
}

#[test]
fn unicode_domain_refused() {
    // hickory IDNA-parses "café.lan" into a UTF-8 table key while wire
    // queries arrive punycode — a permanently dead record. The ASCII-only
    // FQDN gate refuses it at lint.
    let errs = load_err(
        r#"
[[local_dns.records]]
domain = "café.lan"
type = "A"
value = "192.168.1.1"
"#,
    );
    assert!(errs.iter().any(|e| e.contains("not a valid FQDN")));
}

#[test]
fn malformed_cname_target_refused() {
    let errs = load_err(
        r#"
[[local_dns.records]]
domain = "media.home"
type = "CNAME"
value = "@@garbage"
"#,
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("CNAME target") && e.contains("not a valid FQDN")),
        "expected CNAME-target FQDN refusal, got: {errs:?}"
    );
}

#[test]
fn bare_dot_domain_refused() {
    // "." canonicalizes to empty — previously lint-clean and silently
    // dead (Name::from_str("..") fails at build).
    let errs = load_err(
        r#"
[[local_dns.records]]
domain = "."
type = "A"
value = "192.168.1.1"
"#,
    );
    assert!(errs.iter().any(|e| e.contains("not a valid FQDN")));
}

#[test]
fn profile_scope_gets_the_same_fqdn_gate() {
    let errs = load_err(
        r#"
[[profiles.default.local_records]]
domain = "under_score ok but space not"
type = "A"
value = "10.0.0.1"
"#,
    );
    assert!(errs.iter().any(|e| e.contains("not a valid FQDN")));
}

// ── NODATA synthesis still keyed on the canonical name ──────────

#[test]
fn trailing_dot_record_synthesises_nodata_for_missing_qtype() {
    let cfg = load_ok(
        r#"
[[local_dns.records]]
domain = "nas.home."
type = "A"
value = "192.168.1.50"
"#,
    );
    let local = LocalRecords::build(&cfg.local_dns);
    assert!(
        matches!(
            local.lookup("nas.home", RecordType::AAAA),
            LocalLookup::NodataSynthesis { .. }
        ),
        "locally-defined (dotted-spelling) name must NODATA, not leak upstream"
    );
}

// ── [local_dns].ttl_secs fallback bound (rev-2606 cfg-validator-01) ──
// The value actually served (fallback records + NODATA + profile-scope
// fallback) now carries the same 1..=86_400 bound DR5 always enforced on
// the per-record override.

#[test]
fn global_ttl_secs_bound_matrix() {
    for ttl in [1u32, 3600, 86_400] {
        let snippet = format!("[local_dns]\nttl_secs = {ttl}");
        assert!(
            load_from_str(&config_with(&snippet), None, now()).is_ok(),
            "ttl_secs = {ttl} must lint clean"
        );
    }
    for ttl in [0u64, 86_401, 4_000_000_000] {
        let snippet = format!("[local_dns]\nttl_secs = {ttl}");
        let errs = match load_from_str(&config_with(&snippet), None, now()) {
            Ok(_) => panic!("ttl_secs = {ttl} must refuse"),
            Err(e) => e,
        };
        assert!(
            errs.iter().any(|e| e.to_string().contains("ttl_secs")),
            "ttl_secs = {ttl}: expected the ttl gate, got {errs:?}"
        );
    }
}

#[test]
fn global_ttl_secs_checked_even_with_no_global_records() {
    // Profile-scope records inherit the fallback, so the bound must fire
    // with an empty global records list too.
    let errs = match load_from_str(&config_with("[local_dns]\nttl_secs = 0"), None, now()) {
        Ok(_) => panic!("ttl_secs = 0 with no records must still refuse"),
        Err(e) => e,
    };
    assert!(errs.iter().any(|e| e.to_string().contains("ttl_secs")));
}
