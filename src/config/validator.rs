//! Shared semantic validators for v1-schema local-DNS records and
//! rewrite rules — the business rules serde and the type system cannot
//! express on their own (RFC 1034 conflicts, reserved-IP targets,
//! CNAME / rewrite cycles, FQDN syntax).
//!
//! Consumed by `config::schema::validator` (the v1 config validator) and
//! the `local-dns` / `rewrite` CLI commands. The frozen-string `pub
//! const`s are pinned byte-for-byte by `tests/frozen_strings_local_dns_v2.rs`
//! and `tests/frozen_strings_rewrite.rs`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::settings::{LocalDnsRecord, LocalDnsRecordType, RewriteRule};

// ── S44 T1: Local DNS Scoping v2 — validator helpers ───────────
//
// Source of truth: `_docs/features/local_dns_scoping.md` §2 (frozen strings)
// and §7 (validator semantics). Strings here are pinned byte-for-byte
// by `tests/frozen_strings_local_dns_v2.rs` (R3 BLOCK) in T4.

/// DR8 — duplicate `(domain, type)` within a single scope.
///
/// Visibility: `pub` (T4 R3 BLOCK — pinned byte-for-byte by
/// `tests/frozen_strings_local_dns_v2.rs` which lives in an external
/// integration-test crate and cannot reach `pub(crate)` symbols).
pub const LOCAL_RECORDS_DUPLICATE: &str =
    "local_records: duplicate {kind} record for '{domain}' (match_subdomains={flag}). \
     Each (domain, type) pair must appear at most once per profile.";

/// DR6 — invalid IPv4 target on an A record.
pub const LOCAL_RECORDS_INVALID_TARGET_A: &str =
    "local_records: '{value}' is not a valid IPv4 address (record '{domain}' type A).";

/// DR6 — invalid IPv6 target on an AAAA record.
pub const LOCAL_RECORDS_INVALID_TARGET_AAAA: &str =
    "local_records: '{value}' is not a valid IPv6 address (record '{domain}' type AAAA).";

/// DR16 — A/AAAA target in a reserved / loopback / multicast range.
pub const LOCAL_RECORDS_RESERVED_TARGET_REFUSAL: &str =
    "local_records: target '{ip}' is in a reserved/loopback/multicast range — \
     never legitimate for a redirect. (record '{domain}')";

/// DR6 — A/AAAA target outside RFC1918 / ULA / loopback. Audit-only WARN
/// (not a refusal), emitted via `tracing::warn!(target: "audit", ...)`.
pub const LOCAL_RECORDS_PUBLIC_TARGET_WARN: &str =
    "local_records: '{domain}' rewrites to a public IP '{ip}'. \
     This is a deliberate operator-controlled redirect; review if unintended.";

/// DR9 — `match_subdomains: true` on a public suffix (TLD or eTLD+0).
pub const LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL: &str =
    "local_records: cannot enable match_subdomains on '{domain}' — that is a public suffix \
     (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace.";

/// DR10 — `match_subdomains: true` with empty domain (would match every query).
pub const LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL: &str =
    "local_records: cannot enable match_subdomains with an empty domain (would match every query).";

/// DR5 — `ttl_secs` outside `1..=86_400`.
pub const LOCAL_RECORDS_TTL_OUT_OF_RANGE: &str =
    "local_records: ttl_secs={n} is out of range (allowed: 1..=86400). (record '{domain}')";

/// rev-2606 cfg-validator-04 — record domain not a syntactically valid
/// FQDN. Without this gate a structurally broken name ("bad domain!",
/// "café.lan") loads clean and is silently dropped — or IDNA-parsed into
/// an unreachable table key — at build time.
pub const LOCAL_RECORDS_INVALID_FQDN_DOMAIN: &str =
    "local_records: domain '{domain}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// rev-2606 cfg-validator-04 — CNAME target not a syntactically valid
/// FQDN. Same silent-drop sink as the domain side.
pub const LOCAL_RECORDS_INVALID_FQDN_CNAME_TARGET: &str =
    "local_records: CNAME target '{value}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen). (record '{domain}')";

/// DR9 — generalised CNAME loop (self-loop or N-hop cycle inside a scope).
pub const LOCAL_RECORDS_CNAME_LOOP: &str =
    "local_records: CNAME loop — '{domain}' points to itself \
     (directly or via the local-record chain).";

/// Hand-rolled public-suffix list (DR9, threat T6). Lean-deps stance —
/// we deliberately avoid pulling in the `publicsuffix` crate. Covers
/// the ~60 commonest TLDs and eTLDs an operator could plausibly try
/// `match_subdomains: true` against. Reviewed at every sprint close;
/// false-negatives just mean the operator can build their own footgun,
/// false-positives would be a usability bug (no entry in this list
/// blocks a legitimate apex like `example.test` — only suffix-equality
/// or label-prefix rejects).
const PSL: &[&str] = &[
    // gTLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "io", "co",
    "app", "dev", "tech", "online", "site", "store", "blog", "xyz",
    // ccTLDs (most common)
    "us", "uk", "de", "fr", "it", "es", "nl", "pl", "ru", "cn", "jp", "kr", "in", "br", "mx", "ca",
    "au", "nz", "se", "no", "fi", "dk", "ch", "at", "be", "pt", "ie", "gr", "cz",
    // common eTLDs (label-tail forms)
    "co.uk", "co.it", "com.au", "co.nz", "co.jp", "ac.uk", "gov.uk", "co.in", "com.br", "com.mx",
    "co.kr", "or.jp", "ne.jp", "go.jp",
];

/// True if `domain` (case-insensitive, trimmed) **is** a public suffix.
/// We deliberately match on full-suffix equality, not on "ends-with" —
/// `example.test` is NOT a suffix, but `it` is. The intent is to refuse
/// `match_subdomains: true` only when the domain itself is the suffix
/// (which would wildcard the entire namespace).
pub(crate) fn is_public_suffix(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    PSL.iter().any(|suffix| *suffix == d)
}

/// True if the IPv4 is reserved / loopback / multicast / unspecified
/// per DR16. Refuses redirects to addresses that are never legitimate
/// targets for "send this domain to my internal proxy".
fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return true;
    }
    // 240.0.0.0/4 — reserved future use (RFC 1112 §4).
    if ip.octets()[0] >= 240 {
        return true;
    }
    false
}

/// True if the IPv6 is reserved / loopback / multicast / unspecified
/// per DR16.
fn is_reserved_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) carries an embedded v4 that the
    // predicates above do NOT see — e.g. `::ffff:127.0.0.1` is loopback in
    // v4 terms but `Ipv6Addr::is_loopback()` only matches `::1`. Mirror the
    // v4 refusals (broadcast / Class-E / loopback / …) on the embedded
    // address so a mapped-reserved target is refused symmetrically.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_reserved_v4(v4);
    }
    false
}

/// True if the IPv4 is in an RFC 1918 private range or the link-local
/// `169.254.0.0/16` range. These are the targets the use case actually
/// wants — "redirect this public domain to my internal proxy".
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 10.0.0.0/8
    if o[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return true;
    }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // 169.254.0.0/16 — link-local. Same posture as RFC1918 here:
    // operator-internal traffic, not a "public IP" target.
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    false
}

/// True if the IPv6 is in the ULA range `fc00::/7` or link-local
/// `fe80::/10`. Same posture as RFC1918 + 169.254/16 for v4 — these are
/// the "internal target" use case (cfg-validator-09, rev-2606: fe80::
/// used to fall through to the "public IP" WARN, a factually wrong
/// message and asymmetric with the v4 side).
fn is_private_v6(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    // fc00::/7  — first byte is 0xFC or 0xFD.
    if o[0] == 0xFC || o[0] == 0xFD {
        return true;
    }
    // fe80::/10 — first byte 0xFE, top two bits of the second byte 10.
    o[0] == 0xFE && (o[1] & 0xC0) == 0x80
}

/// THE canonical domain spelling — the single normalization shared by the
/// validator's bookkeeping (duplicate seen-sets, identity check, cycle
/// graphs, DR6 shadow sets) and the runtime lookup-table builders
/// ([`crate::dns::local`], [`crate::dns::local_profile`],
/// [`crate::dns::rewrite`]). rev-2606 cfg-validator-03: lint and engine
/// MUST agree on one spelling, or records that lint clean are silently
/// dead at query time (`"nas.home."` validated, then dropped at build).
///
/// Canonical form = `trim` → strip **all** trailing dots → ASCII-lowercase.
/// Strip-all (not one) mirrors [`is_valid_fqdn_syntax`] / [`is_public_suffix`]
/// / [`is_reserved_tld`], so no gate-accepted spelling can fail the
/// builders' `Name::from_str("{domain}.")` re-parse. Matches the query-side
/// shape the handler probes with (LowerName is lowercase; the root dot is
/// stripped before lookup).
///
/// Cold path only: config validation and table builds (boot, SIGHUP,
/// schedule re-eval). Never call this per-query.
pub(crate) fn canonicalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// S44 T1 — Local DNS Scoping v2 validator. Runs the full v2 check suite
/// against a slice of records scoped by `scope_label` (e.g. `"local_dns"`
/// for global, `"profiles.<id>.local_records"` for profile-scoped). The
/// helper is shape-agnostic: every check is local to the slice plus the
/// scope label, so the same function drives both the global path (called
/// from `crate::config::schema::validator::check_local_dns`) and the
/// v1-schema per-profile path (called from
/// `crate::config::schema::validator::check_profiles`).
///
/// Emits errors into `errors` (string-formatted, matching the legacy
/// `validate_settings` aggregation). Public-IP target violations emit a
/// `tracing::warn!(target: "audit", ...)` rather than an error — DR6
/// classifies them as audit-only.
///
/// Frozen strings (R3) are pinned in `tests/frozen_strings_local_dns_v2.rs`
/// at T4. Every constant referenced below MUST stay byte-identical.
pub(crate) fn validate_local_records_v2(
    records: &[LocalDnsRecord],
    scope_label: &str,
    errors: &mut Vec<String>,
) {
    validate_local_records_v2_collect(
        records,
        scope_label,
        errors,
        &mut crate::config::schema::validator::AuditWarnings::emitting(),
    );
}

/// [`validate_local_records_v2`] plus an
/// [`AuditWarnings`](crate::config::schema::validator::AuditWarnings)
/// collector, so `warden config lint` receives the DR6 public-IP-target
/// WARNs as data instead of having to scrape them back off the `tracing`
/// dispatcher. The `tracing::warn!` calls below are unchanged — this only
/// adds a second, in-band destination.
pub(crate) fn validate_local_records_v2_collect(
    records: &[LocalDnsRecord],
    scope_label: &str,
    errors: &mut Vec<String>,
    warns: &mut crate::config::schema::validator::AuditWarnings,
) {
    use std::collections::HashSet;

    // ── per-record checks ──────────────────────────────────────
    let mut seen_a: HashSet<String> = HashSet::new();
    let mut seen_aaaa: HashSet<String> = HashSet::new();
    let mut seen_cname: HashSet<String> = HashSet::new();

    for (i, rec) in records.iter().enumerate() {
        let domain_trimmed = rec.domain.trim();
        // Canonical key for all bookkeeping (duplicate sets, conflicts) —
        // MUST match what the runtime builders key their tables on
        // (cfg-validator-03). Error messages keep `domain_trimmed` so the
        // operator sees their own spelling.
        let domain_lower = canonicalize_domain(&rec.domain);
        let prefix = format!("{scope_label}[{i}]");

        // DR10 — empty domain + match_subdomains.
        if domain_trimmed.is_empty() && rec.match_subdomains {
            errors.push(format!(
                "{prefix}: {}",
                LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL.trim_start_matches("local_records: "),
            ));
        }
        // Pre-existing Sprint 18 "domain must not be empty" (carried forward
        // unchanged for backward-compatible UX — the operator gets a clear
        // message regardless of match_subdomains).
        if domain_trimmed.is_empty() {
            errors.push(format!("{prefix}.domain: must not be empty"));
        }

        // rev-2606 cfg-validator-04 — FQDN syntax gate. Mirrors the §4.12
        // rewrite-side gate so no structurally broken name can reach the
        // builders' silent-drop fallback. Skipped when empty (already
        // reported above).
        if !domain_trimmed.is_empty() && !is_valid_fqdn_syntax(domain_trimmed) {
            errors.push(format!(
                "{prefix}.domain: {}",
                LOCAL_RECORDS_INVALID_FQDN_DOMAIN
                    .replace("{domain}", domain_trimmed)
                    .trim_start_matches("local_records: "),
            ));
        }

        // DR9 — public-suffix wildcard.
        if rec.match_subdomains && is_public_suffix(&domain_lower) {
            errors.push(format!(
                "{prefix}: {}",
                LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL
                    .replace("{domain}", domain_trimmed)
                    .trim_start_matches("local_records: "),
            ));
        }

        // DR5 — TTL range.
        if let Some(n) = rec.ttl_secs {
            if !(1..=86_400).contains(&n) {
                errors.push(format!(
                    "{prefix}: {}",
                    LOCAL_RECORDS_TTL_OUT_OF_RANGE
                        .replace("{n}", &n.to_string())
                        .replace("{domain}", domain_trimmed)
                        .trim_start_matches("local_records: "),
                ));
            }
        }

        // Per-type checks: target validity, reserved/public IP posture,
        // duplicate domain set tracking.
        match rec.record_type {
            LocalDnsRecordType::A => {
                match rec.value.parse::<Ipv4Addr>() {
                    Ok(ip) => {
                        if is_reserved_v4(ip) {
                            errors.push(format!(
                                "{prefix}: {}",
                                LOCAL_RECORDS_RESERVED_TARGET_REFUSAL
                                    .replace("{ip}", &ip.to_string())
                                    .replace("{domain}", domain_trimmed)
                                    .trim_start_matches("local_records: "),
                            ));
                        } else if !is_private_v4(ip) {
                            // DR6 — public-IP target. Audit-only WARN.
                            let msg = LOCAL_RECORDS_PUBLIC_TARGET_WARN
                                .replace("{domain}", domain_trimmed)
                                .replace("{ip}", &ip.to_string());
                            if warns.emit() {
                                tracing::warn!(target: "audit", "{msg}");
                            }
                            warns.push(msg);
                        }
                    }
                    Err(_) => {
                        errors.push(format!(
                            "{prefix}: {}",
                            LOCAL_RECORDS_INVALID_TARGET_A
                                .replace("{value}", &rec.value)
                                .replace("{domain}", domain_trimmed)
                                .trim_start_matches("local_records: "),
                        ));
                    }
                }
                if !domain_lower.is_empty() && !seen_a.insert(domain_lower.clone()) {
                    errors.push(format!(
                        "{prefix}.domain: {}",
                        LOCAL_RECORDS_DUPLICATE
                            .replace("{kind}", "A")
                            .replace("{domain}", domain_trimmed)
                            .replace("{flag}", &rec.match_subdomains.to_string())
                            .trim_start_matches("local_records: "),
                    ));
                }
            }
            LocalDnsRecordType::AAAA => {
                match rec.value.parse::<Ipv6Addr>() {
                    Ok(ip) => {
                        if is_reserved_v6(ip) {
                            errors.push(format!(
                                "{prefix}: {}",
                                LOCAL_RECORDS_RESERVED_TARGET_REFUSAL
                                    .replace("{ip}", &ip.to_string())
                                    .replace("{domain}", domain_trimmed)
                                    .trim_start_matches("local_records: "),
                            ));
                        } else if !is_private_v6(ip) {
                            let msg = LOCAL_RECORDS_PUBLIC_TARGET_WARN
                                .replace("{domain}", domain_trimmed)
                                .replace("{ip}", &ip.to_string());
                            if warns.emit() {
                                tracing::warn!(target: "audit", "{msg}");
                            }
                            warns.push(msg);
                        }
                    }
                    Err(_) => {
                        errors.push(format!(
                            "{prefix}: {}",
                            LOCAL_RECORDS_INVALID_TARGET_AAAA
                                .replace("{value}", &rec.value)
                                .replace("{domain}", domain_trimmed)
                                .trim_start_matches("local_records: "),
                        ));
                    }
                }
                if !domain_lower.is_empty() && !seen_aaaa.insert(domain_lower.clone()) {
                    errors.push(format!(
                        "{prefix}.domain: {}",
                        LOCAL_RECORDS_DUPLICATE
                            .replace("{kind}", "AAAA")
                            .replace("{domain}", domain_trimmed)
                            .replace("{flag}", &rec.match_subdomains.to_string())
                            .trim_start_matches("local_records: "),
                    ));
                }
            }
            LocalDnsRecordType::CNAME => {
                let value_trimmed = rec.value.trim();
                if value_trimmed.is_empty() {
                    errors.push(format!("{prefix}.value: CNAME target must not be empty"));
                } else if !is_valid_fqdn_syntax(value_trimmed) {
                    // rev-2606 cfg-validator-04 — same gate as the domain
                    // side; a malformed target was silently dropped at
                    // build before.
                    errors.push(format!(
                        "{prefix}.value: {}",
                        LOCAL_RECORDS_INVALID_FQDN_CNAME_TARGET
                            .replace("{value}", value_trimmed)
                            .replace("{domain}", domain_trimmed)
                            .trim_start_matches("local_records: "),
                    ));
                }
                if !domain_lower.is_empty() && !seen_cname.insert(domain_lower.clone()) {
                    errors.push(format!(
                        "{prefix}.domain: {}",
                        LOCAL_RECORDS_DUPLICATE
                            .replace("{kind}", "CNAME")
                            .replace("{domain}", domain_trimmed)
                            .replace("{flag}", &rec.match_subdomains.to_string())
                            .trim_start_matches("local_records: "),
                    ));
                }
            }
        }
    }

    // ── A+CNAME conflict per scope (RFC 1034 §3.6.2, generalised) ──
    for cname in &seen_cname {
        if seen_a.contains(cname) {
            errors.push(format!(
                "{scope_label}: \"{cname}\" has both an A record and a CNAME — \
                 RFC 1034 forbids CNAME alongside other record types"
            ));
        }
        if seen_aaaa.contains(cname) {
            errors.push(format!(
                "{scope_label}: \"{cname}\" has both an AAAA record and a CNAME — \
                 RFC 1034 forbids CNAME alongside other record types"
            ));
        }
    }

    // ── CNAME loop detection (generalised, DR9) ──────────────────
    if let Some(loop_domain) = find_cname_cycle(records) {
        errors.push(format!(
            "{scope_label}: {}",
            LOCAL_RECORDS_CNAME_LOOP
                .replace("{domain}", &loop_domain)
                .trim_start_matches("local_records: "),
        ));
    }
}

// ── §4.12 Domain Rewrite Rules — frozen strings ─────────────────

/// §4.12 — duplicate `(from, match_subdomains)` pair in the same scope.
/// Pinned in `tests/frozen_strings_rewrite.rs`.
pub const REWRITE_DUPLICATE: &str =
    "rewrite_rules: duplicate rule for '{from}' (match_subdomains={flag}). \
     Each (from, match_subdomains) pair must appear at most once per profile.";

/// §4.12 — `from` not a syntactically valid FQDN.
pub const REWRITE_INVALID_FQDN_FROM: &str =
    "rewrite_rules: 'from' value '{from}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// §4.12 — `to` not a syntactically valid FQDN.
pub const REWRITE_INVALID_FQDN_TO: &str = "rewrite_rules: 'to' value '{to}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// §4.12 (DR8) — `match_subdomains: true` on a public suffix.
pub const REWRITE_SUBDOMAIN_TLD_REFUSAL: &str =
    "rewrite_rules: cannot enable match_subdomains on '{from}' — that is a public suffix \
     (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace.";

/// §4.12 — empty `from` (matches every query — would be a footgun).
pub const REWRITE_SUBDOMAIN_ROOT_REFUSAL: &str =
    "rewrite_rules: 'from' must not be empty (would match every query).";

/// §4.12 — `from` or `to` in IANA reserved / special-use TLDs.
/// Refused on both sides because rewriting `localhost`, `arpa`, `invalid`,
/// `example`, `test`, `onion`, or `local` is never a legitimate operator
/// intent — these names are reserved by RFCs / IANA for specific purposes.
pub const REWRITE_RESERVED_DOMAIN_REFUSAL: &str =
    "rewrite_rules: '{domain}' is a reserved / special-use TLD per RFC 2606 / 6761 / 7686 \
     ({side}). Refusing to rewrite — reserved names cannot participate.";

/// §4.12 — `from == to` after canonicalisation (no-op rule, footgun).
pub const REWRITE_IDENTITY: &str = "rewrite_rules: 'from' and 'to' are identical ('{from}') — \
     no-op rule. Either remove it or change one side.";

/// §4.12 (DR2) — `from → to → … → from` cycle detected at config-load.
/// Runtime depth=1 guard catches any cycle the validator misses, but the
/// validator catches them config-time so the operator gets early feedback.
pub const REWRITE_CYCLE: &str =
    "rewrite_rules: rewrite cycle detected — '{domain}' participates in a from→to chain that \
     returns to itself (directly or via the rewrite-rule chain).";

/// §4.12 (DR6) — WARNING (not error): same `(profile, from)` appears as a
/// local DNS record AND as a rewrite source. Local DNS wins at runtime;
/// rewrite is shadowed. Frozen so operators can grep for it.
pub const REWRITE_SHADOWED_BY_LOCAL_RECORD: &str =
    "rewrite_rules: '{from}' is also a [[local_records]] entry in the same scope — \
     local DNS records take precedence; this rewrite will not fire for matching clients.";

/// rev-2606 cfg-validator-07 — DR6's blind half: global
/// `[[local_dns.records]]` also precede rewrites at runtime (the handler
/// probes profile-local then global local records before the rewrite
/// hook), so a rewrite shadowed by a *global* record was equally dead but
/// never warned. Frozen so operators can grep for it.
pub const REWRITE_SHADOWED_BY_GLOBAL_RECORD: &str =
    "rewrite_rules: '{from}' is also a global [[local_dns.records]] entry — \
     local DNS records take precedence; this rewrite will not fire for matching clients.";

/// s4 config-m2 — audit WARN for a rewrite whose `from` sits in the RFC 8552
/// underscore-name namespace. WARN and not a refusal: split-horizon ACME
/// validation and SRV-published service migrations are legitimate operator
/// uses of exactly this shape, and warden executes the operator's policy
/// rather than vetoing it (project rules §Neutrality). What was missing was
/// visibility, not permission.
///
/// Carries no service name — the trigger is a leading `_` byte. See
/// [`is_underscore_service_name`].
pub const REWRITE_UNDERSCORE_SERVICE_NAME: &str =
    "rewrite_rules: '{from}' is an underscore-prefixed service name (RFC 8552). \
     Names in that namespace carry policy and key material — mail authentication, \
     certificate and service pinning, service discovery — rather than addresses, \
     so redirecting one answers the lookup with a policy the zone's owner never \
     published. Rewrite it only if you control both the source zone and the target.";

/// rev-2606 profile-02 — §4.53 SafeSearch presets are injected at
/// resolve-time, after validation; a local DNS record for a preset source
/// (e.g. `www.google.com`) silently out-precedences the preset. WARN, not
/// refusal — the injected rules are invisible in the operator's TOML.
pub const SAFESEARCH_PRESET_SHADOWED: &str =
    "safe_search: the injected preset for '{from}' is shadowed by a local DNS record — \
     SafeSearch will not be enforced for that hostname on this profile.";

/// rev-2606 profile-02 — an operator rule whose `from` is a preset target
/// (e.g. `forcesafesearch.google.com → google.com`) closes a cycle with
/// the injected set; the static cycle check never saw the presets. WARN —
/// harmless at runtime (DR2 single-pass apply).
pub const SAFESEARCH_EFFECTIVE_CYCLE: &str =
    "safe_search: operator rewrite_rules plus the injected presets form a rewrite chain \
     that returns to '{domain}'. Harmless at runtime (rewrites apply once per query), \
     but review intent.";

/// §4.12 — syntactic FQDN check. Per-label: 1-63 chars, alphanumeric +
/// hyphen, no leading/trailing hyphen. Total ≤253 chars. Underscores are
/// permitted in some contexts (`_dmarc`, `_acme-challenge`, SRV) — we
/// accept them for the source/destination both because operators may
/// realistically rewrite these. Trailing dot accepted and stripped.
///
/// s4 config-m2: that permissiveness is retained deliberately — see
/// [`is_underscore_service_name`] for the audit WARN that now makes the
/// consequence visible instead of tightening the syntax.
pub(crate) fn is_valid_fqdn_syntax(s: &str) -> bool {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        for &b in bytes {
            let alnum = b.is_ascii_alphanumeric();
            let allowed = alnum || b == b'-' || b == b'_';
            if !allowed {
                return false;
            }
        }
    }
    true
}

/// s4 config-m2 — true when any label of `s` begins with `_`, i.e. the name
/// lives in the RFC 8552 *global underscore-name* namespace.
///
/// Structural, not editorial: this reads the leading byte of each label and
/// consults no list of service names. Same class as [`is_reserved_tld`]
/// (RFC 2606 / 6761 / 7686) — a fact about DNS, not an opinion about a
/// vendor. Adding `_dmarc`, `_domainkey` or any other literal here would be
/// a §Neutrality violation; the byte test is why none is needed.
///
/// Both the leftmost form (`_dmarc.example.com`) and the scoped
/// `_service._proto` form (`_sip._tcp.example.com`, `_25._tcp.mail…`) are
/// the same namespace, so every label is checked rather than just the first.
fn is_underscore_service_name(s: &str) -> bool {
    s.trim()
        .trim_end_matches('.')
        .split('.')
        .any(|label| label.as_bytes().first() == Some(&b'_'))
}

/// IANA reserved / special-use TLDs per RFC 2606 / 6761 / 7686.
/// Rewriting these is never legitimate.
const RESERVED_TLDS: &[&str] = &[
    "localhost",
    "local",
    "arpa",
    "invalid",
    "example",
    "test",
    "onion",
];

/// True if `domain` (case-insensitive, trimmed) is a reserved / special-use
/// TLD per RFC 2606 / 6761 / 7686. We match the TLD label, not the full
/// suffix — `example.com` is NOT reserved, but `example` is.
///
/// Carve-out (rev-2606 cfg-validator-06): `home.arpa` and its descendants
/// are NOT reserved — RFC 8375 designates `home.arpa` as the residential
/// home-network domain, i.e. exactly this product's audience; refusing
/// `nas.home.arpa` rewrites blocked the names operators are *supposed*
/// to use. Everything else under `arpa` (`in-addr.arpa`, `ip6.arpa`, the
/// bare TLD) stays refused — those are PTR / infrastructure namespaces.
fn is_reserved_tld(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    if d == "home.arpa" || d.ends_with(".home.arpa") {
        return false;
    }
    let tld = d.rsplit('.').next().unwrap_or("");
    RESERVED_TLDS.contains(&tld)
}

/// §4.12 — validator for `rewrite_rules`. Scoped per-profile (no global
/// rewrites in §4.12, DR1). The record slices are consulted only for the
/// shadow-warning (DR6): `local_records` is the same profile's records,
/// `global_records` the `[local_dns]` table (rev-2606 cfg-validator-07 —
/// both precede rewrites at runtime, so both shadow).
///
/// Emits hard refusals into `errors` and audit-only shadow warnings into
/// `warnings` — the CALLER routes warnings to
/// `tracing::warn!(target: "audit", ...)`; returning them keeps the
/// check unit-testable.
///
/// Frozen strings (R3) pinned in `tests/frozen_strings_rewrite.rs`.
pub(crate) fn validate_rewrite_rules(
    rules: &[RewriteRule],
    scope_label: &str,
    local_records: &[LocalDnsRecord],
    global_records: &[LocalDnsRecord],
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    use std::collections::HashSet;

    let mut seen: HashSet<(String, bool)> = HashSet::new();
    let local_record_domains: HashSet<String> = local_records
        .iter()
        .map(|r| canonicalize_domain(&r.domain))
        .filter(|s| !s.is_empty())
        .collect();
    let global_record_domains: HashSet<String> = global_records
        .iter()
        .map(|r| canonicalize_domain(&r.domain))
        .filter(|s| !s.is_empty())
        .collect();

    for (i, rule) in rules.iter().enumerate() {
        let from_trimmed = rule.from.trim();
        let to_trimmed = rule.to.trim();
        // Canonical keys (cfg-validator-03) — identity, duplicate, and
        // shadow checks all compare what the runtime table will be keyed
        // on, so `"x.com"` vs `"X.COM."` is one rule, not two.
        let from_lower = canonicalize_domain(&rule.from);
        let to_lower = canonicalize_domain(&rule.to);
        let prefix = format!("{scope_label}[{i}]");

        if from_trimmed.is_empty() {
            errors.push(format!(
                "{prefix}: {}",
                REWRITE_SUBDOMAIN_ROOT_REFUSAL.trim_start_matches("rewrite_rules: "),
            ));
            continue;
        }

        if !is_valid_fqdn_syntax(from_trimmed) {
            errors.push(format!(
                "{prefix}.from: {}",
                REWRITE_INVALID_FQDN_FROM
                    .replace("{from}", from_trimmed)
                    .trim_start_matches("rewrite_rules: "),
            ));
        }
        if !is_valid_fqdn_syntax(to_trimmed) {
            errors.push(format!(
                "{prefix}.to: {}",
                REWRITE_INVALID_FQDN_TO
                    .replace("{to}", to_trimmed)
                    .trim_start_matches("rewrite_rules: "),
            ));
        }

        if rule.match_subdomains && is_public_suffix(&from_lower) {
            errors.push(format!(
                "{prefix}: {}",
                REWRITE_SUBDOMAIN_TLD_REFUSAL
                    .replace("{from}", from_trimmed)
                    .trim_start_matches("rewrite_rules: "),
            ));
        }

        if is_reserved_tld(&from_lower) {
            errors.push(format!(
                "{prefix}.from: {}",
                REWRITE_RESERVED_DOMAIN_REFUSAL
                    .replace("{domain}", from_trimmed)
                    .replace("{side}", "from")
                    .trim_start_matches("rewrite_rules: "),
            ));
        }
        if is_reserved_tld(&to_lower) {
            errors.push(format!(
                "{prefix}.to: {}",
                REWRITE_RESERVED_DOMAIN_REFUSAL
                    .replace("{domain}", to_trimmed)
                    .replace("{side}", "to")
                    .trim_start_matches("rewrite_rules: "),
            ));
        }

        if !from_lower.is_empty() && from_lower == to_lower {
            errors.push(format!(
                "{prefix}: {}",
                REWRITE_IDENTITY
                    .replace("{from}", from_trimmed)
                    .trim_start_matches("rewrite_rules: "),
            ));
        }

        if !from_lower.is_empty() && !seen.insert((from_lower.clone(), rule.match_subdomains)) {
            errors.push(format!(
                "{prefix}: {}",
                REWRITE_DUPLICATE
                    .replace("{from}", from_trimmed)
                    .replace("{flag}", &rule.match_subdomains.to_string())
                    .trim_start_matches("rewrite_rules: "),
            ));
        }

        // s4 config-m2 — underscore-name audit WARN. Checked on `from`
        // ONLY, and that asymmetry is the finding: `apply()` keys on
        // `from` (the name the victim resolver queries) and the handler
        // bridges the answer back under that original qname, so the
        // target can be any ordinary hostname. The backlog entry
        // prescribed the `to` side; a check there constrains the
        // attacker's choice of host name and nothing else.
        //
        // Bound worth knowing: this covers exact-match rules. A
        // `match_subdomains` rule over a zone apex captures the same
        // namespace with no underscore in the config at all — the suffix
        // walk preserves the queried prefix, so `_dmarc.<zone>` follows
        // the wildcard to `_dmarc.<target>`. Which underscore names exist
        // under a zone is not knowable at config time, so that case is
        // not statically flaggable.
        if !from_lower.is_empty() && is_underscore_service_name(&from_lower) {
            warnings.push(REWRITE_UNDERSCORE_SERVICE_NAME.replace("{from}", from_trimmed));
        }

        // DR6 — shadow warnings. Audit-only, not refusals. Profile-scope
        // and global records each get their own message; a `from` present
        // in both surfaces warns twice (both statements are true).
        if !from_lower.is_empty() && local_record_domains.contains(&from_lower) {
            warnings.push(REWRITE_SHADOWED_BY_LOCAL_RECORD.replace("{from}", from_trimmed));
        }
        if !from_lower.is_empty() && global_record_domains.contains(&from_lower) {
            warnings.push(REWRITE_SHADOWED_BY_GLOBAL_RECORD.replace("{from}", from_trimmed));
        }
    }

    if let Some(cycle_domain) = find_rewrite_cycle(rules) {
        errors.push(format!(
            "{scope_label}: {}",
            REWRITE_CYCLE
                .replace("{domain}", &cycle_domain)
                .trim_start_matches("rewrite_rules: "),
        ));
    }
}

/// rev-2606 profile-02 — audit the §4.53 SafeSearch *effective* rewrite
/// set (operator rules + injected presets), built via THE SAME
/// [`crate::profiles::safesearch::populate`] the resolver uses at
/// runtime (lint↔engine same-function principle). The raw operator slice
/// was already validated; this pass covers only what injection adds:
///
/// 1. presets shadowed by a local DNS record (profile or global scope) —
///    the preset silently never fires;
/// 2. a rewrite cycle that only exists in the combined graph (operator
///    rule targeting a preset source).
///
/// WARN-only by design: the injected rules are invisible in the
/// operator's TOML, runtime is cycle-safe (DR2 single-pass apply), and a
/// hard refusal naming rules the operator never wrote would be
/// indecipherable. Caller routes `warnings` to the `audit` tracing target
/// (journald on hot-reload + `warden config lint`; NOT the persistent
/// audit.log — no audit-target layer writes to AuditWriter, audit-02).
///
/// Layering note: config → profiles is an inversion tolerated for the
/// same-function guarantee — duplicating the preset list here is exactly
/// the drift this finding is about.
pub(crate) fn audit_safesearch_effective_rewrites(
    rules: &[RewriteRule],
    local_records: &[LocalDnsRecord],
    global_records: &[LocalDnsRecord],
    warnings: &mut Vec<String>,
) {
    use std::collections::HashSet;

    let mut effective = rules.to_vec();
    crate::profiles::safesearch::populate(&mut effective);

    let shadow_domains: HashSet<String> = local_records
        .iter()
        .chain(global_records.iter())
        .map(|r| canonicalize_domain(&r.domain))
        .filter(|s| !s.is_empty())
        .collect();

    // Only the injected tail — operator rules already got their DR6
    // warnings in `validate_rewrite_rules`.
    for preset in &effective[rules.len()..] {
        let from = canonicalize_domain(&preset.from);
        if shadow_domains.contains(&from) {
            warnings.push(SAFESEARCH_PRESET_SHADOWED.replace("{from}", &preset.from));
        }
    }

    // A cycle in the raw slice is already a hard refusal — only report
    // cycles that appear with the presets in the graph.
    if find_rewrite_cycle(rules).is_none() {
        if let Some(domain) = find_rewrite_cycle(&effective) {
            warnings.push(SAFESEARCH_EFFECTIVE_CYCLE.replace("{domain}", &domain));
        }
    }
}

/// §4.12 — walks the rewrite graph (exact-match edges only) and returns
/// the first domain that participates in a cycle. Subdomain-matching rules
/// do NOT participate in the static graph — their cycle potential is
/// catched at runtime by the depth=1 single-pass guard in
/// `ProfileRewriteRules::apply`. Mirrors `find_cname_cycle` algorithmically.
fn find_rewrite_cycle(rules: &[RewriteRule]) -> Option<String> {
    use std::collections::HashMap;

    let mut graph: HashMap<String, String> = HashMap::new();
    for rule in rules {
        if rule.match_subdomains {
            continue;
        }
        let from = canonicalize_domain(&rule.from);
        let to = canonicalize_domain(&rule.to);
        if !from.is_empty() && !to.is_empty() {
            graph.entry(from).or_insert(to);
        }
    }

    let mut state: HashMap<String, bool> = HashMap::new();

    for start in graph.keys() {
        if state.get(start) == Some(&true) {
            continue;
        }
        let mut stack: Vec<String> = Vec::new();
        let mut current = start.clone();
        loop {
            if state.get(&current) == Some(&false) {
                return Some(current);
            }
            if state.get(&current) == Some(&true) {
                break;
            }
            state.insert(current.clone(), false);
            stack.push(current.clone());
            match graph.get(&current) {
                Some(next) => current = next.clone(),
                None => break,
            }
        }
        for node in stack {
            state.insert(node, true);
        }
    }
    None
}

/// Walks the CNAME graph induced by `records`, returning the first domain
/// that participates in a cycle (self-loop, 2-hop, or N-hop). Returns
/// `None` if every CNAME chain terminates outside the local-record set.
///
/// Generalises the Sprint 18 self-loop check at the prior `validator.rs:673`
/// site — that check only caught `domain == value`. This walks the full
/// chain via DFS with a colour-set so a chain like `a → b → a` or
/// `a → b → c → a` is also detected. Targets outside the local-record set
/// terminate the walk cleanly (they'd be resolved upstream — not our
/// concern for cycle detection).
fn find_cname_cycle(records: &[LocalDnsRecord]) -> Option<String> {
    use std::collections::HashMap;

    // Build a domain → CNAME-target lookup. Canonicalized so the match is
    // case- and trailing-dot-insensitive, agreeing with the runtime
    // builders' keys (project rules "Don't forget case normalization").
    let mut cname_map: HashMap<String, String> = HashMap::new();
    for rec in records {
        if rec.record_type == LocalDnsRecordType::CNAME {
            let domain = canonicalize_domain(&rec.domain);
            let target = canonicalize_domain(&rec.value);
            if !domain.is_empty() && !target.is_empty() {
                // First-write wins; duplicate-CNAME is reported separately
                // by the duplicate-domain pass.
                cname_map.entry(domain).or_insert(target);
            }
        }
    }

    // DFS from each CNAME source. Three-colour set:
    // - absent  = unvisited
    // - false   = on the current DFS stack (grey)
    // - true    = fully processed (black)
    use std::collections::HashMap as Map;
    let mut state: Map<String, bool> = Map::new();

    for start in cname_map.keys() {
        if state.get(start) == Some(&true) {
            continue;
        }
        let mut stack: Vec<String> = Vec::new();
        let mut current = start.clone();
        loop {
            // Cycle: current is grey on the active stack.
            if state.get(&current) == Some(&false) {
                return Some(current);
            }
            if state.get(&current) == Some(&true) {
                break;
            }
            state.insert(current.clone(), false);
            stack.push(current.clone());
            match cname_map.get(&current) {
                Some(next) => current = next.clone(),
                None => break, // chain exits the local-record set — no cycle.
            }
        }
        // Mark every node visited in this DFS path as black.
        for node in stack {
            state.insert(node, true);
        }
    }
    None
}

#[cfg(test)]
mod tests {
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
                .any(|e| e.contains("reserved/loopback/multicast")
                    && e.contains("'255.255.255.255'")),
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
value = "192.0.2.50"
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
value = "192.0.2.50"
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
            rec_sub("example.test", LocalDnsRecordType::A, "192.0.2.50"),
            rec("auth.example.test", LocalDnsRecordType::A, "192.0.2.51"),
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
        audit_safesearch_effective_rewrites(
            &rules,
            &[local_rec("www.google.com")],
            &[],
            &mut warns,
        );
        assert!(
            warns.is_empty(),
            "occupied preset must not re-warn via the audit: {warns:?}"
        );
    }
}
