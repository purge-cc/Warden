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

// ── Local DNS Scoping v2 — validator helpers ───────────
//
// Strings here are pinned byte-for-byte by `tests/frozen_strings_local_dns_v2.rs`.

/// Duplicate `(domain, type)` within a single scope.
///
/// Visibility: `pub` — pinned byte-for-byte by
/// `tests/frozen_strings_local_dns_v2.rs`, which lives in an external
/// integration-test crate and cannot reach `pub(crate)` symbols.
pub const LOCAL_RECORDS_DUPLICATE: &str =
    "local_records: duplicate {kind} record for '{domain}' (match_subdomains={flag}). \
     Each (domain, type) pair must appear at most once per profile.";

/// Invalid IPv4 target on an A record.
pub const LOCAL_RECORDS_INVALID_TARGET_A: &str =
    "local_records: '{value}' is not a valid IPv4 address (record '{domain}' type A).";

/// Invalid IPv6 target on an AAAA record.
pub const LOCAL_RECORDS_INVALID_TARGET_AAAA: &str =
    "local_records: '{value}' is not a valid IPv6 address (record '{domain}' type AAAA).";

/// A/AAAA target in a reserved / loopback / multicast range.
pub const LOCAL_RECORDS_RESERVED_TARGET_REFUSAL: &str =
    "local_records: target '{ip}' is in a reserved/loopback/multicast range — \
     never legitimate for a redirect. (record '{domain}')";

/// A/AAAA target outside RFC1918 / ULA / loopback. Audit-only WARN
/// (not a refusal), emitted via `tracing::warn!(target: "audit", ...)`.
pub const LOCAL_RECORDS_PUBLIC_TARGET_WARN: &str =
    "local_records: '{domain}' rewrites to a public IP '{ip}'. \
     This is a deliberate operator-controlled redirect; review if unintended.";

/// `match_subdomains: true` on a public suffix (TLD or eTLD+0).
pub const LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL: &str =
    "local_records: cannot enable match_subdomains on '{domain}' — that is a public suffix \
     (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace.";

/// `match_subdomains: true` with empty domain (would match every query).
pub const LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL: &str =
    "local_records: cannot enable match_subdomains with an empty domain (would match every query).";

/// `ttl_secs` outside `1..=86_400`.
pub const LOCAL_RECORDS_TTL_OUT_OF_RANGE: &str =
    "local_records: ttl_secs={n} is out of range (allowed: 1..=86400). (record '{domain}')";

/// Record domain not a syntactically valid FQDN. Without this gate a
/// structurally broken name ("bad domain!", "café.lan") loads clean and
/// is silently dropped — or IDNA-parsed into an unreachable table key —
/// at build time.
pub const LOCAL_RECORDS_INVALID_FQDN_DOMAIN: &str =
    "local_records: domain '{domain}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// CNAME target not a syntactically valid FQDN. Same silent-drop sink
/// as the domain side.
pub const LOCAL_RECORDS_INVALID_FQDN_CNAME_TARGET: &str =
    "local_records: CNAME target '{value}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen). (record '{domain}')";

/// Generalised CNAME loop (self-loop or N-hop cycle inside a scope).
pub const LOCAL_RECORDS_CNAME_LOOP: &str =
    "local_records: CNAME loop — '{domain}' points to itself \
     (directly or via the local-record chain).";

/// Hand-rolled public-suffix list. Lean-deps stance — we deliberately
/// avoid pulling in the `publicsuffix` crate. Covers the ~60 commonest
/// TLDs and eTLDs an operator could plausibly try `match_subdomains:
/// true` against. Reviewed periodically as new TLDs gain adoption;
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

/// True if the IPv4 is reserved / loopback / multicast / unspecified.
/// Refuses redirects to addresses that are never legitimate targets for
/// "send this domain to my internal proxy".
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

/// True if the IPv6 is reserved / loopback / multicast / unspecified.
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
/// the "internal target" use case (`fe80::` used to fall through to the
/// "public IP" WARN, a factually wrong message and asymmetric with the
/// v4 side).
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
/// graphs, shadow sets) and the runtime lookup-table builders
/// ([`crate::dns::local`], [`crate::dns::local_profile`],
/// [`crate::dns::rewrite`]). Lint and engine MUST agree on one spelling,
/// or records that lint clean are silently dead at query time
/// (`"nas.home."` validated, then dropped at build).
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

/// Local DNS Scoping v2 validator. Runs the full v2 check suite
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
/// `tracing::warn!(target: "audit", ...)` rather than an error — classified
/// as audit-only.
///
/// Frozen strings are pinned in `tests/frozen_strings_local_dns_v2.rs`.
/// Every constant referenced below MUST stay byte-identical.
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
/// collector, so `warden config lint` receives the public-IP-target
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
        // MUST match what the runtime builders key their tables on.
        // Error messages keep `domain_trimmed` so the operator sees their
        // own spelling.
        let domain_lower = canonicalize_domain(&rec.domain);
        let prefix = format!("{scope_label}[{i}]");

        // Empty domain + match_subdomains.
        if domain_trimmed.is_empty() && rec.match_subdomains {
            errors.push(format!(
                "{prefix}: {}",
                LOCAL_RECORDS_SUBDOMAIN_ROOT_REFUSAL.trim_start_matches("local_records: "),
            ));
        }
        // Also flagged independently of match_subdomains, so the operator
        // always gets a plain "must not be empty" message.
        if domain_trimmed.is_empty() {
            errors.push(format!("{prefix}.domain: must not be empty"));
        }

        // FQDN syntax gate — mirrors the rewrite-side gate so no
        // structurally broken name can reach the builders' silent-drop
        // fallback. Skipped when empty (already reported above).
        if !domain_trimmed.is_empty() && !is_valid_fqdn_syntax(domain_trimmed) {
            errors.push(format!(
                "{prefix}.domain: {}",
                LOCAL_RECORDS_INVALID_FQDN_DOMAIN
                    .replace("{domain}", domain_trimmed)
                    .trim_start_matches("local_records: "),
            ));
        }

        // Public-suffix wildcard.
        if rec.match_subdomains && is_public_suffix(&domain_lower) {
            errors.push(format!(
                "{prefix}: {}",
                LOCAL_RECORDS_SUBDOMAIN_TLD_REFUSAL
                    .replace("{domain}", domain_trimmed)
                    .trim_start_matches("local_records: "),
            ));
        }

        // TTL range.
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
                            // Public-IP target. Audit-only WARN.
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
                    // Same gate as the domain side; a malformed target
                    // was silently dropped at build before.
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

    // ── CNAME loop detection (generalised) ──────────────────
    if let Some(loop_domain) = find_cname_cycle(records) {
        errors.push(format!(
            "{scope_label}: {}",
            LOCAL_RECORDS_CNAME_LOOP
                .replace("{domain}", &loop_domain)
                .trim_start_matches("local_records: "),
        ));
    }
}

// ── Domain Rewrite Rules — frozen strings ─────────────────

/// Duplicate `(from, match_subdomains)` pair in the same scope.
/// Pinned in `tests/frozen_strings_rewrite.rs`.
pub const REWRITE_DUPLICATE: &str =
    "rewrite_rules: duplicate rule for '{from}' (match_subdomains={flag}). \
     Each (from, match_subdomains) pair must appear at most once per profile.";

/// `from` not a syntactically valid FQDN.
pub const REWRITE_INVALID_FQDN_FROM: &str =
    "rewrite_rules: 'from' value '{from}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// `to` not a syntactically valid FQDN.
pub const REWRITE_INVALID_FQDN_TO: &str = "rewrite_rules: 'to' value '{to}' is not a valid FQDN \
     (labels 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// `match_subdomains: true` on a public suffix.
pub const REWRITE_SUBDOMAIN_TLD_REFUSAL: &str =
    "rewrite_rules: cannot enable match_subdomains on '{from}' — that is a public suffix \
     (TLD or eTLD+0). A wildcard at this level would rewrite the entire namespace.";

/// Empty `from` (matches every query — would be a footgun).
pub const REWRITE_SUBDOMAIN_ROOT_REFUSAL: &str =
    "rewrite_rules: 'from' must not be empty (would match every query).";

/// `from` or `to` in IANA reserved / special-use TLDs.
/// Refused on both sides because rewriting `localhost`, `arpa`, `invalid`,
/// `example`, `test`, `onion`, or `local` is never a legitimate operator
/// intent — these names are reserved by RFCs / IANA for specific purposes.
pub const REWRITE_RESERVED_DOMAIN_REFUSAL: &str =
    "rewrite_rules: '{domain}' is a reserved / special-use TLD per RFC 2606 / 6761 / 7686 \
     ({side}). Refusing to rewrite — reserved names cannot participate.";

/// `from == to` after canonicalisation (no-op rule, footgun).
pub const REWRITE_IDENTITY: &str = "rewrite_rules: 'from' and 'to' are identical ('{from}') — \
     no-op rule. Either remove it or change one side.";

/// `from → to → … → from` cycle detected at config-load.
/// Runtime depth=1 guard catches any cycle the validator misses, but the
/// validator catches them config-time so the operator gets early feedback.
pub const REWRITE_CYCLE: &str =
    "rewrite_rules: rewrite cycle detected — '{domain}' participates in a from→to chain that \
     returns to itself (directly or via the rewrite-rule chain).";

/// WARNING (not error): same `(profile, from)` appears as a local DNS
/// record AND as a rewrite source. Local DNS wins at runtime; rewrite is
/// shadowed. Frozen so operators can grep for it.
pub const REWRITE_SHADOWED_BY_LOCAL_RECORD: &str =
    "rewrite_rules: '{from}' is also a [[local_records]] entry in the same scope — \
     local DNS records take precedence; this rewrite will not fire for matching clients.";

/// A global `[[local_dns.records]]` entry also precedes rewrites at
/// runtime (the handler probes profile-local then global local records
/// before the rewrite hook), so a rewrite shadowed by a *global* record
/// is equally dead — this warns for that case, symmetric to the
/// profile-scoped shadow warning above. Frozen so operators can grep
/// for it.
pub const REWRITE_SHADOWED_BY_GLOBAL_RECORD: &str =
    "rewrite_rules: '{from}' is also a global [[local_dns.records]] entry — \
     local DNS records take precedence; this rewrite will not fire for matching clients.";

/// Audit WARN for a rewrite whose `from` sits in the RFC 8552
/// underscore-name namespace. WARN and not a refusal: split-horizon ACME
/// validation and SRV-published service migrations are legitimate operator
/// uses of exactly this shape, and warden executes the operator's policy
/// rather than vetoing it (CLAUDE.md §Neutrality). What was missing was
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

/// SafeSearch presets are injected at resolve-time, after validation; a
/// local DNS record for a preset source (e.g. `www.google.com`)
/// silently out-precedences the preset. WARN, not refusal — the injected
/// rules are invisible in the operator's TOML.
pub const SAFESEARCH_PRESET_SHADOWED: &str =
    "safe_search: the injected preset for '{from}' is shadowed by a local DNS record — \
     SafeSearch will not be enforced for that hostname on this profile.";

/// An operator rule whose `from` is a preset target (e.g.
/// `forcesafesearch.google.com → google.com`) closes a cycle with the
/// injected set; the static cycle check never saw the presets. WARN —
/// harmless at runtime (single-pass apply).
pub const SAFESEARCH_EFFECTIVE_CYCLE: &str =
    "safe_search: operator rewrite_rules plus the injected presets form a rewrite chain \
     that returns to '{domain}'. Harmless at runtime (rewrites apply once per query), \
     but review intent.";

/// Syntactic FQDN check. Per-label: 1-63 chars, alphanumeric + hyphen,
/// no leading/trailing hyphen. Total ≤253 chars. Underscores are
/// permitted in some contexts (`_dmarc`, `_acme-challenge`, SRV) — we
/// accept them for the source/destination both because operators may
/// realistically rewrite these. Trailing dot accepted and stripped.
///
/// That permissiveness is retained deliberately — see
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

/// True when any label of `s` begins with `_`, i.e. the name
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
/// Carve-out: `home.arpa` and its descendants are NOT reserved — RFC
/// 8375 designates `home.arpa` as the residential
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

/// Validator for `rewrite_rules`. Scoped per-profile (no global
/// rewrites). The record slices are consulted only for the
/// shadow-warning: `local_records` is the same profile's records,
/// `global_records` the `[local_dns]` table — both precede rewrites at
/// runtime, so both shadow.
///
/// Emits hard refusals into `errors` and audit-only shadow warnings into
/// `warnings` — the CALLER routes warnings to
/// `tracing::warn!(target: "audit", ...)`; returning them keeps the
/// check unit-testable.
///
/// Frozen strings pinned in `tests/frozen_strings_rewrite.rs`.
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
        // Canonical keys — identity, duplicate, and shadow checks all
        // compare what the runtime table will be keyed on, so
        // `"x.com"` vs `"X.COM."` is one rule, not two.
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

        // Underscore-name audit WARN. Checked on `from` ONLY, and that
        // asymmetry is deliberate: `apply()` keys on `from` (the name
        // the victim resolver queries) and the handler bridges the
        // answer back under that original qname, so the target can be
        // any ordinary hostname. Checking `to` instead would only
        // constrain the attacker's choice of host name and nothing else.
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

        // Shadow warnings. Audit-only, not refusals. Profile-scope
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

/// Audit the SafeSearch *effective* rewrite set (operator rules +
/// injected presets), built via THE SAME
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
/// operator's TOML, runtime is cycle-safe (single-pass apply), and a
/// hard refusal naming rules the operator never wrote would be
/// indecipherable. Caller routes `warnings` to the `audit` tracing target
/// (journald on hot-reload + `warden config lint`; NOT the persistent
/// audit.log — no audit-target layer writes to AuditWriter).
///
/// Layering note: config → profiles is an inversion tolerated for the
/// same-function guarantee — duplicating the preset list here would be
/// exactly the drift this design avoids.
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

    // Only the injected tail — operator rules already got their shadow
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

/// Walks the rewrite graph (exact-match edges only) and returns
/// the first domain that participates in a cycle. Subdomain-matching rules
/// do NOT participate in the static graph — their cycle potential is
/// caught at runtime by the depth=1 single-pass guard in
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
/// Generalises a self-loop-only check (`domain == value`) into a full
/// walk via DFS with a colour-set so a chain like `a → b → a` or
/// `a → b → c → a` is also detected. Targets outside the local-record set
/// terminate the walk cleanly (they'd be resolved upstream — not our
/// concern for cycle detection).
fn find_cname_cycle(records: &[LocalDnsRecord]) -> Option<String> {
    use std::collections::HashMap;

    // Build a domain → CNAME-target lookup. Canonicalized so the match is
    // case- and trailing-dot-insensitive, agreeing with the runtime
    // builders' keys.
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
mod tests;
