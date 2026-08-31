//! §4.12 Domain Rewrite Rules — frozen-strings test (R3).
//!
//! Pins every operator-facing const from `validate_rewrite_rules`
//! byte-for-byte. Blocks the `v0.10.4-domain-rewrite` tag step: if any
//! const drifts the test fails and the tag cannot cut.
//!
//! When a string MUST change for legitimate reasons (UX rewording,
//! typo fix), update both the literal here AND the design doc's
//! `## As-landed` frozen-strings table in the same commit.

use purge_warden::config::validator::{
    REWRITE_CYCLE, REWRITE_DUPLICATE, REWRITE_IDENTITY, REWRITE_INVALID_FQDN_FROM,
    REWRITE_INVALID_FQDN_TO, REWRITE_RESERVED_DOMAIN_REFUSAL, REWRITE_SHADOWED_BY_GLOBAL_RECORD,
    REWRITE_SHADOWED_BY_LOCAL_RECORD, REWRITE_SUBDOMAIN_ROOT_REFUSAL,
    REWRITE_SUBDOMAIN_TLD_REFUSAL, REWRITE_UNDERSCORE_SERVICE_NAME, SAFESEARCH_EFFECTIVE_CYCLE,
    SAFESEARCH_PRESET_SHADOWED,
};

#[test]
fn rewrite_duplicate_byte_for_byte() {
    assert_eq!(
        REWRITE_DUPLICATE,
        "rewrite_rules: duplicate rule for '{from}' (match_subdomains={flag}). \
         Each (from, match_subdomains) pair must appear at most once per profile."
    );
}

/// s4 config-m2. Doubles as a §Neutrality pin: the message must stay
/// name-neutral, so the assertion below is also the thing that fails if a
/// later edit "helpfully" names a service in operator-facing copy.
#[test]
fn rewrite_underscore_service_name_byte_for_byte() {
    assert_eq!(
        REWRITE_UNDERSCORE_SERVICE_NAME,
        "rewrite_rules: '{from}' is an underscore-prefixed service name (RFC 8552). \
         Names in that namespace carry policy and key material — mail authentication, \
         certificate and service pinning, service discovery — rather than addresses, \
         so redirecting one answers the lookup with a policy the zone's owner never \
         published. Rewrite it only if you control both the source zone and the target."
    );
}

#[test]
fn rewrite_invalid_fqdn_from_byte_for_byte() {
    assert_eq!(
        REWRITE_INVALID_FQDN_FROM,
        "rewrite_rules: 'from' value '{from}' is not a valid FQDN \
         (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen)."
    );
}

#[test]
fn rewrite_invalid_fqdn_to_byte_for_byte() {
    assert_eq!(
        REWRITE_INVALID_FQDN_TO,
        "rewrite_rules: 'to' value '{to}' is not a valid FQDN \
         (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen)."
    );
}

#[test]
fn rewrite_subdomain_tld_refusal_byte_for_byte() {
    assert_eq!(
        REWRITE_SUBDOMAIN_TLD_REFUSAL,
        "rewrite_rules: cannot enable match_subdomains on '{from}' — that is a public suffix \
         (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace."
    );
}

#[test]
fn rewrite_subdomain_root_refusal_byte_for_byte() {
    assert_eq!(
        REWRITE_SUBDOMAIN_ROOT_REFUSAL,
        "rewrite_rules: 'from' must not be empty (would match every query)."
    );
}

#[test]
fn rewrite_reserved_domain_refusal_byte_for_byte() {
    assert_eq!(
        REWRITE_RESERVED_DOMAIN_REFUSAL,
        "rewrite_rules: '{domain}' is a reserved / special-use TLD per RFC 2606 / 6761 / 7686 \
         ({side}). Refusing to rewrite — reserved names cannot participate."
    );
}

#[test]
fn rewrite_identity_byte_for_byte() {
    assert_eq!(
        REWRITE_IDENTITY,
        "rewrite_rules: 'from' and 'to' are identical ('{from}') — \
         no-op rule. Either remove it or change one side."
    );
}

#[test]
fn rewrite_cycle_byte_for_byte() {
    assert_eq!(
        REWRITE_CYCLE,
        "rewrite_rules: rewrite cycle detected — '{domain}' participates in a from→to chain that \
         returns to itself (directly or via the rewrite-rule chain)."
    );
}

#[test]
fn rewrite_shadowed_by_local_record_byte_for_byte() {
    assert_eq!(
        REWRITE_SHADOWED_BY_LOCAL_RECORD,
        "rewrite_rules: '{from}' is also a [[local_records]] entry in the same scope — \
         local DNS records take precedence; this rewrite will not fire for matching clients."
    );
}

// rev-2606 cfg-validator-07 + profile-02 — additive pins.

#[test]
fn rewrite_shadowed_by_global_record_byte_for_byte() {
    assert_eq!(
        REWRITE_SHADOWED_BY_GLOBAL_RECORD,
        "rewrite_rules: '{from}' is also a global [[local_dns.records]] entry — \
         local DNS records take precedence; this rewrite will not fire for matching clients."
    );
}

#[test]
fn safesearch_preset_shadowed_byte_for_byte() {
    assert_eq!(
        SAFESEARCH_PRESET_SHADOWED,
        "safe_search: the injected preset for '{from}' is shadowed by a local DNS record — \
         SafeSearch will not be enforced for that hostname on this profile."
    );
}

#[test]
fn safesearch_effective_cycle_byte_for_byte() {
    assert_eq!(
        SAFESEARCH_EFFECTIVE_CYCLE,
        "safe_search: operator rewrite_rules plus the injected presets form a rewrite chain \
         that returns to '{domain}'. Harmless at runtime (rewrites apply once per query), \
         but review intent."
    );
}
