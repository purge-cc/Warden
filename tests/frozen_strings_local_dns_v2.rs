//! Sprint 44 T4 — Local DNS Scoping v2 frozen-strings test (R3 BLOCK).
//!
//! Pins every operator-facing line declared in
//! `_docs/features/local_dns_scoping.md` §2 byte-for-byte. The test BLOCKS
//! the `v0.4.7-local-dns-scoping` tag: if any const drifts from the
//! table the tag step refuses to cut.
//!
//! Layout: one `*_byte_for_byte` assertion per const + one substitution
//! test per format helper that exercises the placeholder replacement
//! against a concrete expected output. The 16 consts live in two home
//! modules (per §14.3 quick start):
//!
//!   - `src/cli/commands/local_dns.rs`  — 7 consts shipped in T3
//!   - `src/config/validator.rs`        — 9 consts shipped in T1
//!
//! Plus the welcome-banner copy (`welcome_copy` from
//! `src/tui/welcome_banner.rs`), locked here so it stays part of the same
//! R3 gate. It is now evergreen (built from the running build version), so
//! the pin checks the stable parts — the live `g l` Local DNS key and the
//! absence of the retired `[5]` / "0.4.7" framing — not a byte literal.
//!
//! When a string MUST change for legitimate reasons (UX re-wording,
//! typo fix), update both the literal here AND the §2 frozen-strings
//! table in the design doc in the same commit, then add a §14.N
//! delta-vs-intent note documenting why the byte-for-byte pin slipped.

use purge_warden::cli::commands::local_dns::{
    format_local_records_added_global, format_local_records_added_profile,
    format_local_records_profile_not_found, format_local_records_remove_not_found,
    format_local_records_removed, format_local_records_tab_empty_profile,
    LOCAL_RECORDS_ADDED_GLOBAL, LOCAL_RECORDS_ADDED_PROFILE, LOCAL_RECORDS_PROFILE_NOT_FOUND,
    LOCAL_RECORDS_REMOVED, LOCAL_RECORDS_REMOVE_NOT_FOUND, LOCAL_RECORDS_TAB_EMPTY_GLOBAL,
    LOCAL_RECORDS_TAB_EMPTY_PROFILE,
};
use purge_warden::config::validator::{
    LOCAL_RECORDS_CNAME_LOOP, LOCAL_RECORDS_DUPLICATE, LOCAL_RECORDS_INVALID_FQDN_CNAME_TARGET,
    LOCAL_RECORDS_INVALID_FQDN_DOMAIN, LOCAL_RECORDS_INVALID_TARGET_A,
    LOCAL_RECORDS_INVALID_TARGET_AAAA, LOCAL_RECORDS_PUBLIC_TARGET_WARN,
    LOCAL_RECORDS_RESERVED_TARGET_REFUSAL, LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL,
    LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL, LOCAL_RECORDS_TTL_OUT_OF_RANGE,
};
use purge_warden::tui::welcome_banner::welcome_copy;

// ── T1 — validator strings (9 consts) ────────────────────────────────

#[test]
fn local_records_duplicate_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_DUPLICATE,
        "local_records: duplicate {kind} record for '{domain}' (match_subdomains={flag}). \
         Each (domain, type) pair must appear at most once per profile."
    );
}

#[test]
fn local_records_invalid_target_a_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_INVALID_TARGET_A,
        "local_records: '{value}' is not a valid IPv4 address (record '{domain}' type A)."
    );
}

#[test]
fn local_records_invalid_target_aaaa_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_INVALID_TARGET_AAAA,
        "local_records: '{value}' is not a valid IPv6 address (record '{domain}' type AAAA)."
    );
}

#[test]
fn local_records_reserved_target_refusal_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_RESERVED_TARGET_REFUSAL,
        "local_records: target '{ip}' is in a reserved/loopback/multicast range — \
         never legitimate for a redirect. (record '{domain}')"
    );
}

#[test]
fn local_records_public_target_warn_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_PUBLIC_TARGET_WARN,
        "local_records: '{domain}' rewrites to a public IP '{ip}'. \
         This is a deliberate operator-controlled redirect; review if unintended."
    );
}

#[test]
fn local_records_subdomain_tld_refusal_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL,
        "local_records: cannot enable match_subdomains on '{domain}' — that is a public suffix \
         (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace."
    );
}

#[test]
fn local_records_subdomain_root_refusal_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL,
        "local_records: cannot enable match_subdomains with an empty domain (would match every query)."
    );
}

#[test]
fn local_records_ttl_out_of_range_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_TTL_OUT_OF_RANGE,
        "local_records: ttl_secs={n} is out of range (allowed: 1..=86400). (record '{domain}')"
    );
}

// rev-2606 cfg-validator-04 — FQDN syntax gate (additive pins).

#[test]
fn local_records_invalid_fqdn_domain_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_INVALID_FQDN_DOMAIN,
        "local_records: domain '{domain}' is not a valid FQDN \
         (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen)."
    );
}

#[test]
fn local_records_invalid_fqdn_cname_target_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_INVALID_FQDN_CNAME_TARGET,
        "local_records: CNAME target '{value}' is not a valid FQDN \
         (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen). (record '{domain}')"
    );
}

#[test]
fn local_records_cname_loop_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_CNAME_LOOP,
        "local_records: CNAME loop — '{domain}' points to itself \
         (directly or via the local-record chain)."
    );
}

// ── T3 — CLI / TUI strings (7 consts) ────────────────────────────────

#[test]
fn local_records_profile_not_found_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_PROFILE_NOT_FOUND,
        "local_records: profile '{id}' referenced by --profile does not exist. Known profiles: {list}."
    );
}

#[test]
fn local_records_added_global_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_ADDED_GLOBAL,
        "Added global local DNS record '{domain}' {type} → {value}. To remove: warden local-dns remove '{domain}'"
    );
}

#[test]
fn local_records_added_profile_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_ADDED_PROFILE,
        "Added local DNS record '{domain}' {type} → {value} on profile '{profile}'. Affects {n} device(s) currently. To remove: warden local-dns remove '{domain}' --profile '{profile}'"
    );
}

#[test]
fn local_records_removed_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_REMOVED,
        "Removed local DNS record '{domain}' from {scope}."
    );
}

#[test]
fn local_records_remove_not_found_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_REMOVE_NOT_FOUND,
        "local_records: no record '{domain}' found in {scope} — nothing to remove."
    );
}

#[test]
fn local_records_tab_empty_global_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_TAB_EMPTY_GLOBAL,
        "No global local DNS records. Add with `warden local-dns add <domain> <type> <value>`."
    );
}

#[test]
fn local_records_tab_empty_profile_byte_for_byte() {
    assert_eq!(
        LOCAL_RECORDS_TAB_EMPTY_PROFILE,
        "No local DNS records on profile '{profile}'. Add with `warden local-dns add <domain> <type> <value> --profile '{profile}'`."
    );
}

// ── Format helpers — placeholder substitution invariants ─────────────

#[test]
fn format_profile_not_found_substitutes_id_and_lists_known() {
    let s = format_local_records_profile_not_found("kids", &["default", "guests"]);
    assert_eq!(
        s,
        "local_records: profile 'kids' referenced by --profile does not exist. Known profiles: default, guests."
    );
}

#[test]
fn format_profile_not_found_renders_empty_known_list() {
    let s = format_local_records_profile_not_found("kids", &[]);
    assert!(s.contains("'kids'"), "{s}");
    assert!(s.contains("(none configured)"), "{s}");
}

#[test]
fn format_added_global_substitutes_domain_type_value() {
    let s = format_local_records_added_global("nas.home", "A", "192.168.1.50");
    assert_eq!(
        s,
        "Added global local DNS record 'nas.home' A → 192.168.1.50. To remove: warden local-dns remove 'nas.home'"
    );
}

#[test]
fn format_added_profile_substitutes_domain_type_value_profile_n() {
    // CT smoke 2026-05-01 will emit exactly this string for
    // `warden local-dns add example.test A 10.10.1.50 --profile default`
    // when the `default` profile resolves 3 devices — pin that shape.
    let s = format_local_records_added_profile("example.test", "A", "10.10.1.50", "default", 3);
    assert_eq!(
        s,
        "Added local DNS record 'example.test' A → 10.10.1.50 on profile 'default'. Affects 3 device(s) currently. To remove: warden local-dns remove 'example.test' --profile 'default'"
    );
}

#[test]
fn format_removed_substitutes_domain_and_scope() {
    let global = format_local_records_removed("example.test", "global");
    assert_eq!(
        global,
        "Removed local DNS record 'example.test' from global."
    );
    let profile = format_local_records_removed("example.test", "profile 'default'");
    assert_eq!(
        profile,
        "Removed local DNS record 'example.test' from profile 'default'."
    );
}

#[test]
fn format_remove_not_found_substitutes_domain_and_scope() {
    let s = format_local_records_remove_not_found("missing.example", "profile 'kids'");
    assert_eq!(
        s,
        "local_records: no record 'missing.example' found in profile 'kids' — nothing to remove."
    );
}

#[test]
fn format_tab_empty_profile_substitutes_profile_id() {
    let s = format_local_records_tab_empty_profile("default");
    assert_eq!(
        s,
        "No local DNS records on profile 'default'. Add with `warden local-dns add <domain> <type> <value> --profile 'default'`."
    );
}

// ── Welcome banner — evergreen copy (version- + key-accurate) ─────────

#[test]
fn welcome_banner_copy_is_the_first_run_setup_checklist() {
    // Mirrors the in-module pins in `src/tui/welcome_banner.rs`. Two
    // independent gates so a bypass of one still surfaces here at tag time —
    // and this one is genuinely independent, because `Leaf` is private to the
    // crate and unreachable from here. In-module the `g <letter>` hints are
    // GENERATED from `Leaf::mnemonic`; here they are FROZEN to the letters.
    // That is the point: a mnemonic remap silently rewrites the generated
    // copy, and this test is what turns that silence into a decision.
    let copy = welcome_copy();

    // The three things a fresh install actually needs, in the operator's
    // order. Byte offsets, not presence: a copy that leads with lists sends
    // someone to subscribe a blocklist on a box that cannot resolve.
    let up = copy.find("Upstreams").expect("no upstreams step");
    let lists = copy.find("2  Lists").expect("no lists step");
    let point = copy.find("Point your clients").expect("no client-DNS step");
    assert!(up < lists && lists < point, "steps out of order: {copy}");

    // The leaf jumps, frozen. If a mnemonic moved, fix the letter here
    // deliberately — do not delete the assertion.
    for (what, hint) in [
        ("Dashboard", "(g d)"),
        ("File", "(g f)"),
        ("Lists", "(g i)"),
        ("Query Log", "(g q)"),
    ] {
        assert!(
            copy.contains(hint),
            "the {what} jump {hint} is no longer in the copy: {copy}"
        );
    }

    // The leaf-local keys, in the copy's own two-space highlight form so the
    // needle cannot be satisfied by an indefinite article.
    for key in ["  B  ", "  a  ", "  e  "] {
        assert!(copy.contains(key), "key hint {key:?} is gone: {copy}");
    }

    // Retired copy must not resurface: the Local DNS advert this replaced,
    // and the `[5]` / 0.4.7 pair that froze in once already
    // (welcome_banner-01). The build version left the BODY on purpose — it
    // rides the title band now, pinned at the render in-module by
    // `welcome_shows_the_running_build_version_on_screen`.
    for dead in ["local DNS records", "[5]", "What's new in 0.4.7", "(g l)"] {
        assert!(
            !copy.contains(dead),
            "retired welcome copy resurfaced ({dead:?}): {copy}"
        );
    }
}
