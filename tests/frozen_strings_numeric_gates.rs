//! rev-2606 `validator-numeric-gates` — frozen-strings test.
//!
//! Pins byte-for-byte the operator-facing validator errors coined by the
//! numeric/scalar range-gate sprint (settings-02/-03/-11/-12/-13,
//! config-01, schema-validator-02, blocklist-02). These strings are
//! recovery surfaces: each names the field, the valid range, and the
//! default, so the operator can fix the config without reading source.
//!
//! When one of these strings MUST change for legitimate reasons (UX
//! re-wording, typo fix), update the literal here AND any corresponding
//! row in `CONFIG_GUIDE.md` + `CONFIG_GUIDE.public.md` in the same
//! commit. Byte-for-byte equality has no escape hatch — that is the
//! entire point of this trip-wire.

use purge_warden::config::schema::validator::format_security_tunneling_exempt_broad;
use purge_warden::config::schema::validator::{
    format_cache_cname_max_depth_above_cap, format_cache_prefetch_threshold_invalid,
    format_cache_stale_buffer_too_large, format_cache_ttl_bounds_inverted, format_dnssec_cap_zero,
    format_local_dns_ttl_out_of_range, format_security_rrl_window_out_of_range,
    format_security_tunneling_entropy_invalid, CACHE_CNAME_MAX_DEPTH_ABOVE_CAP,
    CACHE_CNAME_MAX_DEPTH_ZERO, CACHE_PREFETCH_THRESHOLD_INVALID, CACHE_STALE_BUFFER_TOO_LARGE,
    CACHE_TTL_BOUNDS_INVERTED, DNSSEC_CAP_ZERO, LISTS_MAX_BODY_BYTES_ZERO, LISTS_MAX_ENTRIES_ZERO,
    LISTS_SHRINK_GUARD_PCT_INVALID, LISTS_UPDATE_INTERVAL_ZERO, LOCAL_DNS_TTL_OUT_OF_RANGE,
    SECURITY_RATE_LIMIT_BURST_ZERO, SECURITY_RATE_LIMIT_QPS_ZERO, SECURITY_RRL_RPS_ZERO,
    SECURITY_RRL_WINDOW_OUT_OF_RANGE, SECURITY_TUNNELING_ENTROPY_INVALID,
    SECURITY_TUNNELING_ENTROPY_MIN_LEN_ZERO, SECURITY_TUNNELING_EXEMPT_BROAD,
    SECURITY_TUNNELING_EXEMPT_MALFORMED, SECURITY_TUNNELING_EXEMPT_SINGLE_LABEL,
    SECURITY_TUNNELING_LABEL_LEN_ZERO, SECURITY_TUNNELING_MAX_RUN_ZERO,
    SECURITY_TUNNELING_SUBDOMAIN_RATE_ZERO, SECURITY_TUNNELING_WINDOW_ZERO, UPSTREAM_SERVERS_EMPTY,
};

#[test]
fn lists_update_interval_zero_const_is_frozen() {
    assert_eq!(
        LISTS_UPDATE_INTERVAL_ZERO,
        "lists: `update_interval_secs` must be >= 1 (0 would stall the refresh \
         timer). The default is 43200 (12 hours)."
    );
}

#[test]
fn lists_max_entries_zero_const_is_frozen() {
    assert_eq!(
        LISTS_MAX_ENTRIES_ZERO,
        "lists: `max_entries` must be >= 1 — 0 truncates every list to zero \
         domains, silently disabling filtering. The default is 20000000; raise \
         the value instead of using 0 for \"unlimited\"."
    );
}

#[test]
fn lists_max_body_bytes_zero_const_is_frozen() {
    assert_eq!(
        LISTS_MAX_BODY_BYTES_ZERO,
        "lists: `max_body_bytes` must be >= 1 — 0 refuses every list download. \
         The default is 536870912 (512 MB)."
    );
}

#[test]
fn lists_shrink_guard_pct_invalid_const_is_frozen() {
    assert_eq!(
        LISTS_SHRINK_GUARD_PCT_INVALID,
        "lists: `shrink_guard_max_drop_pct` must be 1..=100 — it is the percent \
         a list may shrink in one refresh before the prior list is kept. The \
         default is 90; set `shrink_guard_enabled = false` to disable the guard \
         instead of using 0."
    );
}

#[test]
fn security_rrl_rps_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_RRL_RPS_ZERO,
        "security.rrl: `responses_per_second` must be >= 1 when rrl is enabled \
         (0 throttles every response — a self-DoS). The default is 100; set \
         `enabled = false` to turn RRL off instead."
    );
}

#[test]
fn security_rrl_window_out_of_range_const_is_frozen() {
    assert_eq!(
        SECURITY_RRL_WINDOW_OUT_OF_RANGE,
        "security.rrl: `window_secs` must be 1..=86400 (got {n}). The default \
         is 15."
    );
}

#[test]
fn security_rrl_window_format_helper_substitutes() {
    let got = format_security_rrl_window_out_of_range(4294967296);
    assert!(got.contains("got 4294967296"));
    assert!(!got.contains("{n}"));
}

#[test]
fn local_dns_ttl_out_of_range_const_is_frozen() {
    assert_eq!(
        LOCAL_DNS_TTL_OUT_OF_RANGE,
        "local_dns: `ttl_secs` must be 1..=86400 (got {n}) — it is the served \
         TTL for every record without a per-record override, the NODATA \
         negative TTL, and the fallback for profile-scope records. The default \
         is 3600."
    );
}

#[test]
fn local_dns_ttl_format_helper_substitutes() {
    let got = format_local_dns_ttl_out_of_range(0);
    assert!(got.contains("got 0"));
    assert!(!got.contains("{n}"));
}

#[test]
fn security_rate_limit_qps_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_RATE_LIMIT_QPS_ZERO,
        "security.rate_limit: `queries_per_second` must be >= 1 when rate_limit \
         is enabled (0 starves every client once its burst is spent). The \
         default is 100; set `enabled = false` to turn rate limiting off \
         instead."
    );
}

#[test]
fn security_rate_limit_burst_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_RATE_LIMIT_BURST_ZERO,
        "security.rate_limit: `burst` must be >= 1 when rate_limit is enabled \
         (0 rejects every query from every client). The default is 200."
    );
}

#[test]
fn security_tunneling_entropy_invalid_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_ENTROPY_INVALID,
        "security.tunneling: `entropy_threshold` must be a finite number > 0.0 \
         (got {n}). NaN silently disables entropy detection; 0 refuses nearly \
         every subdomain query. The default is 3.5."
    );
}

#[test]
fn security_tunneling_entropy_format_helper_substitutes() {
    let got = format_security_tunneling_entropy_invalid(f64::NAN);
    assert!(got.contains("got NaN"));
    assert!(!got.contains("{n}"));
}

#[test]
fn security_tunneling_label_len_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_LABEL_LEN_ZERO,
        "security.tunneling: `label_len_threshold` must be >= 1 when tunneling \
         detection is enabled (0 refuses every subdomain query). The default \
         is 48."
    );
}

#[test]
fn security_tunneling_max_run_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_MAX_RUN_ZERO,
        "security.tunneling: `max_unbroken_run` must be >= 1 when tunneling \
         detection is enabled (0 refuses every subdomain query). The default \
         is 40."
    );
}

#[test]
fn security_tunneling_entropy_min_len_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_ENTROPY_MIN_LEN_ZERO,
        "security.tunneling: `entropy_min_len` must be >= 1 when tunneling \
         detection is enabled (0 lets the entropy heuristic fire on names too \
         short for it to mean anything). The default is 64."
    );
}

#[test]
fn security_tunneling_exempt_malformed_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_EXEMPT_MALFORMED,
        "security.tunneling: every `exempt_domains` entry must be a non-empty \
         domain name (no empty strings, no bare dots, no whitespace)."
    );
}

#[test]
fn security_tunneling_exempt_single_label_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_EXEMPT_SINGLE_LABEL,
        "security.tunneling: `exempt_domains` entries must have at least two \
         labels (got a single-label entry). Exempting a whole TLD disables \
         tunneling detection for most of the namespace — use `enabled = false` \
         if that is the intent."
    );
}

#[test]
fn security_tunneling_exempt_broad_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_EXEMPT_BROAD,
        "security.tunneling: `exempt_domains` entry `{d}` covers an entire \
         registrable domain — every name under it skips both the shape gates \
         and the per-client subdomain rate counter. Narrow it to the specific \
         hostname if you can."
    );
}

#[test]
fn security_tunneling_exempt_broad_helper_substitutes() {
    let got = format_security_tunneling_exempt_broad("a2z.com");
    assert!(got.contains("`a2z.com`"));
    assert!(!got.contains("{d}"));
}

#[test]
fn security_tunneling_subdomain_rate_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_SUBDOMAIN_RATE_ZERO,
        "security.tunneling: `subdomain_rate` must be >= 1 when tunneling \
         detection is enabled (0 refuses the first upstream lookup per base \
         domain). The default is 50."
    );
}

#[test]
fn security_tunneling_window_zero_const_is_frozen() {
    assert_eq!(
        SECURITY_TUNNELING_WINDOW_ZERO,
        "security.tunneling: `window_secs` must be >= 1 when tunneling \
         detection is enabled (0 disables the rate check). The default is 60."
    );
}

#[test]
fn cache_ttl_bounds_inverted_const_is_frozen() {
    assert_eq!(
        CACHE_TTL_BOUNDS_INVERTED,
        "cache: `min_ttl_secs` ({min}) must be <= `max_ttl_secs` ({max}) — an \
         inverted pair silently pins every cached TTL to max_ttl_secs. The \
         defaults are 60 and 3600."
    );
}

#[test]
fn cache_ttl_bounds_format_helper_substitutes() {
    let got = format_cache_ttl_bounds_inverted(7200, 3600);
    assert!(got.contains("(7200)"));
    assert!(got.contains("(3600)"));
    assert!(!got.contains("{min}"));
    assert!(!got.contains("{max}"));
}

#[test]
fn cache_prefetch_threshold_invalid_const_is_frozen() {
    assert_eq!(
        CACHE_PREFETCH_THRESHOLD_INVALID,
        "cache: `prefetch_threshold` must be a finite fraction strictly between \
         0.0 and 1.0 (got {n}). The default is 0.1 — refresh when 10% of the \
         TTL remains; set `prefetch = false` to turn prefetching off instead."
    );
}

#[test]
fn cache_prefetch_threshold_format_helper_substitutes() {
    let got = format_cache_prefetch_threshold_invalid(1.5);
    assert!(got.contains("got 1.5"));
    assert!(!got.contains("{n}"));
}

#[test]
fn cache_stale_buffer_too_large_const_is_frozen() {
    assert_eq!(
        CACHE_STALE_BUFFER_TOO_LARGE,
        "cache: `stale_buffer_secs` must be <= 86400 (24 h) — the serve-stale \
         window (RFC 8767) is capped so a single failed refresh can't pin a dead \
         answer indefinitely (got {n}). The default is 300."
    );
}

#[test]
fn cache_stale_buffer_format_helper_substitutes() {
    let got = format_cache_stale_buffer_too_large(99999);
    assert!(got.contains("got 99999"));
    assert!(!got.contains("{n}"));
}

#[test]
fn cache_cname_max_depth_zero_const_is_frozen() {
    assert_eq!(
        CACHE_CNAME_MAX_DEPTH_ZERO,
        "cache: `cname_max_depth` must be >= 1 — at 0 the first CNAME record \
         already exceeds the cap, and a chain past the cap counts as blocked, so \
         every CNAME'd name stops resolving. It is a depth limit, not an on/off \
         switch. The default is 16."
    );
}

#[test]
fn cache_cname_max_depth_above_cap_const_is_frozen() {
    assert_eq!(
        CACHE_CNAME_MAX_DEPTH_ABOVE_CAP,
        "cache: `cname_max_depth` is {n}, but both CNAME chain walkers clamp to \
         16 hops, so the extra depth is never followed. Set it to 16 or lower so \
         the config says what warden does."
    );
}

#[test]
fn cache_cname_max_depth_above_cap_format_helper_substitutes() {
    let got = format_cache_cname_max_depth_above_cap(64);
    assert!(got.contains("is 64,"));
    assert!(!got.contains("{n}"));
}

#[test]
fn dnssec_cap_zero_const_is_frozen() {
    assert_eq!(
        DNSSEC_CAP_ZERO,
        "dnssec: `{field}` must be >= 1 when `mode` is not \"off\" (a zero cap \
         makes every signed zone fail validation — the engine is fail-closed). \
         The default is {default}."
    );
}

#[test]
fn dnssec_cap_zero_format_helper_substitutes() {
    let got = format_dnssec_cap_zero("max_chain_depth", 10);
    assert!(got.contains("`max_chain_depth`"));
    assert!(got.contains("The default is 10."));
    assert!(!got.contains("{field}"));
    assert!(!got.contains("{default}"));
}

/// neutrality-03: re-frozen. The previous text ended `The default is
/// ["https://1.1.1.1/dns-query"].` — an operator-facing string in which
/// warden recommended one named provider. There is no default any more,
/// and warden names nobody; the message points at the flag instead.
#[test]
fn upstream_servers_empty_const_is_frozen() {
    assert_eq!(
        UPSTREAM_SERVERS_EMPTY,
        "upstream: `servers` must list at least one resolver — with none, every \
         cache miss fails. warden does not choose one for you: set it with \
         `warden init --upstream <addr:port>` or edit `upstream.servers`."
    );
}
