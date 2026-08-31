//! DNS query handler — the hot path.
//!
//! For each incoming query: security check → validate → profile resolve →
//! filter evaluate → cache (with stampede protection) → forward or block.
//! All operations are zero-lock; the filter engine and profile resolver use ArcSwap for reads.

use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use arc_swap::ArcSwapOption;
use compact_str::CompactString;

use hickory_net::runtime::Time;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HINFO, SOA};
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use super::cache::{CacheLookup, DnsCache, FetchFailure};
use super::edns::EcsPrefix;
use super::error::DnsError;
use super::local::{LocalLookup, LocalRecords};
use super::validation::validate_query;
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult, AuditWriter};
use crate::config::cidr::{any_contains, Cidr};
use crate::config::settings::SecurityConfig;
use crate::filter::cname::{walk_response, BlockSource, NamePolicy, Verdict};
use crate::filter::engine::{domain_matches_set, FilterResult};
use crate::filter::ip_filter::IpFilter;
use crate::filter::FilterEngine;
use crate::lists::readiness::ReadinessGate;
use crate::profiles::profile::ResolvedProfile;
use crate::profiles::{
    apply_overlay, AttribSource, DeviceOverlay, LayerHits, OverlayDecision, ProfileResolver,
};
use crate::security::anti_bypass::AntiBypass;
use crate::security::query_validator;
use crate::security::rate_limiter::RateLimiter;
use crate::security::rrl::{Rrl, RrlAction};
use crate::security::tunneling::{is_reverse_zone, TunnelingDetector, TunnelingVerdict};
use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey, StatsEngine};
use crate::upstream::Upstream;

#[cfg(feature = "dnssec")]
use super::dnssec_validator::{DnssecDecision, DnssecValidator};

/// handler-07 — rewrite-aware upstream `Name` reconstruction, shared by the
/// prefetch-spawn and cache-miss forward paths so the §4.12 / §4.30-disc-1
/// coherence rule lives in exactly ONE place.
///
/// When a per-profile rewrite fired (`rewrote`), `domain` carries the rewritten
/// qname and the upstream `Name` must be rebuilt from it via `from_ascii`,
/// otherwise the engine would query the *original* name (the §4.12 leak — a
/// wrong qname on the wire, invisible to client-response assertions; see
/// `feedback_hot_path_name_mutation_tests`). The validator guarantees the
/// rewrite target parses at config-load, so the `from_ascii` fallback to the
/// original `name` is defence-in-depth. When no rewrite fired, `domain` equals
/// the original parsed query name — reuse `name` directly and skip the
/// `format!` String alloc + `from_ascii` parse on every non-rewritten cache
/// miss (the §4.30 disc-1 perf win). It drifted once when this was two
/// copy-pasted blocks; the single helper makes that drift impossible.
#[inline]
fn fwd_name_for(domain: &str, rewrote: bool, name: &LowerName) -> Name {
    if rewrote {
        Name::from_ascii(format!("{domain}.")).unwrap_or_else(|_| Name::from(name.clone()))
    } else {
        Name::from(name.clone())
    }
}

/// Map a `RecordType` to a static string for the query log, avoiding
/// an allocation on the hot path. Unknown/uncommon types fold into a
/// single `"OTHER"` bucket — the TUI only uses this field for display.
#[inline]
fn record_type_str(rt: RecordType) -> &'static str {
    match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::MX => "MX",
        RecordType::TXT => "TXT",
        RecordType::NS => "NS",
        RecordType::SRV => "SRV",
        RecordType::PTR => "PTR",
        RecordType::SOA => "SOA",
        RecordType::HTTPS => "HTTPS",
        RecordType::SVCB => "SVCB",
        RecordType::TLSA => "TLSA",
        _ => "OTHER",
    }
}

/// Aggregates all security checks into a single interface for the handler.
/// Each component is optional — disabled sub-features are None.
pub struct SecurityLayer {
    pub rate_limiter: Option<RateLimiter>,
    pub rrl: Option<Rrl>,
    pub tunneling: Option<TunnelingDetector>,
    pub anti_bypass: Option<AntiBypass>,
}

impl SecurityLayer {
    /// Build from config. Disabled sub-features become None.
    pub fn from_config(
        security: &SecurityConfig,
        anti_bypass_config: &crate::config::settings::AntiBypassConfig,
    ) -> Self {
        if !security.enabled {
            return Self {
                rate_limiter: None,
                rrl: None,
                tunneling: None,
                anti_bypass: None,
            };
        }

        Self {
            rate_limiter: if security.rate_limit.enabled {
                Some(RateLimiter::new(&security.rate_limit))
            } else {
                None
            },
            rrl: if security.rrl.enabled {
                Some(Rrl::new(&security.rrl))
            } else {
                None
            },
            tunneling: if security.tunneling.enabled {
                Some(TunnelingDetector::new(&security.tunneling))
            } else {
                None
            },
            // neutrality-01: with no compiled-in provider list, an operator
            // who never set `extra_domains` yields an empty checker. Drop it
            // rather than pay a per-query subdomain walk that cannot match.
            //
            // N1: the drop stays — it is the right call for the hot path —
            // but it is no longer silent. `enabled = true` with an empty
            // set is now reported by
            // `config::schema::validator::check_anti_bypass` (every
            // `load_config`, so `warden config lint` and hot reload) and
            // re-emitted at boot by
            // `cli::commands::start::toothless_anti_bypass_warning`, which
            // exists because the boot load runs before `init_tracing`.
            // Do not "fix" this by keeping a `Some(_)` around an empty
            // set: that would charge every query for a walk that cannot
            // match, and it would still protect nothing.
            //
            // Not covered by that diagnostic: the early return above
            // discards this checker wholesale when `security.enabled` is
            // false, even with a populated `extra_domains`. Same silence,
            // different condition — see the predicate's doc comment.
            anti_bypass: if anti_bypass_config.enabled {
                let ab = AntiBypass::new(anti_bypass_config);
                if ab.is_empty() {
                    None
                } else {
                    Some(ab)
                }
            } else {
                None
            },
        }
    }

    /// Pre-query checks: rate limiting and query validation.
    /// Returns Err if the query should be refused (SERVFAIL or drop).
    ///
    /// query-validator-01 (rev-2606): the domain-shape heuristics are
    /// qtype-gated. PTR names legitimately embed IP addresses (every IPv4
    /// reverse name is four consecutive numeric labels) and an IPv6
    /// reverse name is 32 random hex nibbles (concat Shannon entropy
    /// ~3.7-4.0, above the tunneling threshold) — pre-fix every IPv4 PTR
    /// on a default install was REFUSED as "rebinding" (live-confirmed
    /// via dig -x against the CT), and warden's own local-records PTR
    /// feature was unreachable behind this gate.
    fn check_pre_query(
        &self,
        client_ip: &IpAddr,
        domain: &str,
        record_type: RecordType,
    ) -> Result<(), &'static str> {
        // Rate limiter — cheapest check first
        if let Some(ref rl) = self.rate_limiter {
            if !rl.check(client_ip) {
                return Err("rate limited");
            }
        }

        // Character validation (all qtypes — PTR labels are plain
        // digits/hex and pass untouched).
        if query_validator::validate_domain_chars(domain).is_err() {
            return Err("invalid domain characters");
        }
        // Rebinding pattern: only address-bearing qtypes. A rebinding
        // attack requires the browser to *forward-resolve* an IP-embedded
        // name to that address — qtypes that can't carry an address can't
        // rebind, and PTR names embed IPs by construction.
        if matches!(
            record_type,
            RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
        ) && query_validator::has_rebinding_pattern(domain)
        {
            return Err("DNS rebinding pattern detected");
        }

        // Anti-bypass: block queries to known DoH/DoT resolvers
        if let Some(ref ab) = self.anti_bypass {
            if ab.is_bypass_domain(domain) {
                return Err("bypass domain blocked");
            }
        }

        // Tunneling shape detection — skipped for PTR (mechanically
        // generated IP-shaped names; the nibble-entropy false positive
        // above). All other qtypes stay covered: TXT/NULL/CNAME are the
        // classic exfil carriers.
        if record_type != RecordType::PTR {
            if let Some(ref td) = self.tunneling {
                if td.check(domain) == TunnelingVerdict::Suspicious {
                    return Err("tunneling detected");
                }
            }
        }

        Ok(())
    }

    /// Post-response check: RRL on outgoing responses.
    ///
    /// `per_client` narrows the budget from the /24 to the exact address.
    /// The caller passes `true` only for sources it has confirmed are
    /// inside a configured `server.allow_from` CIDR — see
    /// [`crate::security::rrl::Rrl::check`].
    fn check_response(&self, dest_ip: &IpAddr, per_client: bool) -> RrlAction {
        if let Some(ref rrl) = self.rrl {
            rrl.check(dest_ip, per_client)
        } else {
            RrlAction::Allow
        }
    }

    /// Cache-miss tunneling rate check (tunneling-rate-01). Bumps the
    /// per-`(client, base domain)` counter and returns true when the
    /// budget is exceeded. The handler calls this only for queries that
    /// are about to go upstream — cache hits prove repetition, not the
    /// unique-name fan-out tunneling produces, so they no longer count.
    fn check_tunneling_rate(&self, client_ip: &IpAddr, domain: &str) -> bool {
        self.tunneling
            .as_ref()
            .is_some_and(|td| td.check_rate(client_ip, domain))
    }

    /// Periodic cleanup of stale tracking state. Call from a background task.
    pub fn cleanup(&self) {
        if let Some(ref rl) = self.rate_limiter {
            rl.cleanup();
        }
        if let Some(ref rrl) = self.rrl {
            rrl.cleanup();
        }
        if let Some(ref td) = self.tunneling {
            td.cleanup();
        }
    }
}

/// Does the cache-miss tunneling **rate** gate apply to this query?
///
/// Extracted from the inline condition on the forward path so the qtype
/// rule is testable on its own — it is the only part of that `async fn`
/// with a rule worth pinning.
///
/// sec-ptr-skips-both-tunneling-gates: PTR keeps its exemption **only
/// inside the reverse zones**. There it is load-bearing — every reverse
/// name a client sends shares one base domain (`in-addr.arpa` is not an
/// eTLD `compute_base_domain` splits), so a scanner doing 51 reverse
/// lookups a minute would exhaust a single bucket and be REFUSED.
/// Outside them the exemption is a hole: nothing requires a PTR query to
/// sit under `.arpa`, the shape gate already skips PTR by design (an IPv6
/// nibble name is indistinguishable from a payload — see
/// `check_pre_query`), and fan-out does not care about the qtype, so a
/// payload carried as PTR was checked by neither gate.
fn tunneling_rate_gate_applies(record_type: RecordType, domain: &str) -> bool {
    record_type != RecordType::PTR || !is_reverse_zone(domain)
}

/// Fallback TTL stamped on a dynamic device `network_name` answer when the
/// boot path never handed the handler the operator's value.
///
/// Must stay equal to `LocalDnsConfig::default().dynamic_ttl_secs` — a
/// handler that silently answered with a different TTL than the config
/// documents would be indistinguishable from a broken reload. Pinned by
/// `default_dynamic_ttl_matches_config_default` so drift fails the build
/// rather than the operator's cache.
const DEFAULT_DYNAMIC_TTL_SECS: u32 = 30;

/// Forwards non-blocked queries to upstream, returns canned responses for blocked ones.
/// Cache sits between filter and upstream on the hot path.
pub struct ForwardHandler {
    upstream: Arc<dyn Upstream>,
    filter: Arc<FilterEngine>,
    cache: DnsCache,
    profiles: Option<Arc<ProfileResolver>>,
    stats: Option<Arc<StatsEngine>>,
    security: Option<Arc<SecurityLayer>>,
    local_records: Option<Arc<LocalRecords>>,
    ip_filter: Option<Arc<IpFilter>>,
    /// Source-IP allow list (P0-5). Inner `None` or empty means accept all
    /// sources. Pre-parsed so the hot path only does bitwise CIDR compares.
    ///
    /// Wrapped in `Arc<ArcSwapOption<_>>` so a config reload can re-derive the
    /// ACL live (`cli::commands::start::handle_reload`) without a daemon
    /// restart: the reload path holds a clone of this same `Arc` (handed out
    /// by [`Self::allow_from_handle`]) and calls `.store(..)`. Per-query reads
    /// stay lock-free — a single `ArcSwapOption::load` (project rules rule #1).
    allow_from: Arc<ArcSwapOption<Vec<Cidr>>>,
    blocked_ttl: u32,
    /// Bounded semaphore for TTL-triggered prefetch tasks. None = prefetch disabled.
    prefetch_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Fraction of TTL remaining that triggers a background prefetch (e.g. 0.1 = 10%).
    prefetch_threshold: f64,
    /// Maximum CNAME chain depth to inspect for blocked targets.
    cname_max_depth: usize,
    /// S44 T3: per-record hit counter for local DNS records. Bumped
    /// after each profile-scope or global probe hit. `None` skips the
    /// increment — used by tests / fixtures that don't need the
    /// counter wired.
    local_records_hits: Option<Arc<LocalRecordsHits>>,
    /// `local_dns.dynamic_ttl_secs` — the TTL stamped on a dynamic device
    /// `network_name` answer. Short by design: the address it carries is
    /// whatever ARP saw a moment ago, so a long TTL would outlive the DHCP
    /// lease it was derived from.
    ///
    /// `Arc<AtomicU32>` for the same reason `allow_from` is an
    /// `Arc<ArcSwapOption<_>>` and not a plain field: the handler is moved
    /// into hickory's `ServerFuture` by value, so the reload path cannot
    /// reach it through a reference. It holds a clone of this `Arc`
    /// (handed out by [`Self::dynamic_ttl_handle`]) and stores the new
    /// value directly. A plain `u32` here would make the setting
    /// boot-only, which is the one behaviour an operator editing a TTL
    /// would never expect — `local_dns.ttl_secs` already hot-reloads via
    /// `LocalRecords::swap`.
    ///
    /// Read once per *matched* network-name query (a single relaxed load),
    /// never on the general hot path.
    dynamic_ttl_secs: Arc<AtomicU32>,
    /// `local_dns.nodata_for_missing_types` — whether a configured device
    /// `network_name` answers NODATA (instead of falling through to
    /// upstream) for a qtype other than A. Same anti-leak rationale as the
    /// static `local_dns` `NodataSynthesis` path (incident local-01).
    /// Default `true`, matching the config default. Plain `bool`, not an
    /// `Arc<Atomic*>` like `dynamic_ttl_secs`: no reload path exists for
    /// any of `[local_dns]` today (`LocalRecords::swap` is never called in
    /// production either — verified during Task 7 follow-up review), so
    /// this setting is boot-only, consistent with the rest of the section
    /// rather than a regression against it.
    nodata_for_missing_types_network_name: bool,
    /// §4.5 Sprint 2/2 — append-only handle to the daemon audit log.
    /// `Some(writer)` in production (wired by `cli::commands::start`);
    /// `None` in unit tests that don't care about audit. Used by
    /// `emit_cname_block_audit` to record CNAME-chain block events
    /// off-hot-path via `tokio::task::spawn_blocking`.
    audit_writer: Option<Arc<AuditWriter>>,
    /// Latching readiness gate: `false` until a filter generation has
    /// been installed. Defaults to **open** so every construction that
    /// does not opt in is unaffected; `start.rs` seeds it closed on the
    /// nodes that build their own map (its `spawn_lists` predicate) and
    /// open on the ones that do not — a cluster secondary among them,
    /// whose map arrives from the primary. See
    /// `_docs/features/boot_list_persistence.md` §2.4.
    ///
    /// [`ReadinessGate`] is one-way by construction: it has no `close`,
    /// and its atomic is private to `lists::readiness`, so no module —
    /// this one or the list manager — can put it back. The handler only
    /// ever reads it.
    filter_ready: ReadinessGate,
    /// One-shot latch for the `filter_ready` refusal log: `false` until
    /// the first query is refused for a closed gate, `true` forever
    /// after (never reset — this state is not supposed to recur once
    /// the primary boot guard, §2.4, is in place, so it never needs to
    /// re-arm). Per-handler, not shared like `filter_ready` — each
    /// `ForwardHandler` warns once on its own.
    ///
    /// Exists because a closed gate is, by construction, the only
    /// pre-parse refusal in `handle_inner` with no upper bound on
    /// volume: it fires for every client and every query, unlike the
    /// ACL refusal a few lines above (which the `handler-05` comment
    /// there already gates to `debug!` — non-allowed sources only). A
    /// plain per-query `warn!` here would be the exact log-flood /
    /// journald-write amplification vector that comment describes,
    /// triggered at boot — precisely when the box is least able to
    /// absorb it. First refusal: `warn!` (an operator needs to see this
    /// at all). Every one after: `debug!` (they've seen it).
    gate_refusal_logged: std::sync::atomic::AtomicBool,
    /// §4.10-4b — DNSSEC response-path validator. `Some` only when
    /// `dnssec.mode != Off` (and only on the `dnssec` build); `None`
    /// disables all DNSSEC processing with zero hot-path cost. Built once
    /// at boot by `cli::commands::start` over a DO-enabled upstream.
    #[cfg(feature = "dnssec")]
    dnssec_validator: Option<Arc<DnssecValidator>>,
}

impl ForwardHandler {
    /// Create a new handler with shared upstream resolver, filter engine, and cache.
    /// If `profiles` is None, falls back to `is_blocked()` (legacy flat filter).
    /// If `stats` is Some, records per-query statistics (atomics only).
    /// If `security` is Some, applies rate limiting, RRL, tunneling detection, anti-bypass.
    /// If `allow_from` is Some and non-empty, queries from sources outside the
    /// listed CIDRs are refused (P0-5 open-resolver guard).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: Arc<dyn Upstream>,
        filter: Arc<FilterEngine>,
        cache: DnsCache,
        profiles: Option<Arc<ProfileResolver>>,
        stats: Option<Arc<StatsEngine>>,
        security: Option<Arc<SecurityLayer>>,
        local_records: Option<Arc<LocalRecords>>,
        ip_filter: Option<Arc<IpFilter>>,
        allow_from: Option<Arc<Vec<Cidr>>>,
        blocked_ttl: u32,
        prefetch_semaphore: Option<Arc<tokio::sync::Semaphore>>,
        prefetch_threshold: f64,
        cname_max_depth: usize,
    ) -> Self {
        Self {
            upstream,
            filter,
            cache,
            profiles,
            stats,
            security,
            local_records,
            ip_filter,
            allow_from: Arc::new(ArcSwapOption::new(allow_from)),
            blocked_ttl,
            prefetch_semaphore,
            prefetch_threshold,
            cname_max_depth,
            local_records_hits: None,
            dynamic_ttl_secs: Arc::new(AtomicU32::new(DEFAULT_DYNAMIC_TTL_SECS)),
            nodata_for_missing_types_network_name: true,
            audit_writer: None,
            filter_ready: ReadinessGate::new(true),
            gate_refusal_logged: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "dnssec")]
            dnssec_validator: None,
        }
    }

    /// S44 T3: attach a [`LocalRecordsHits`] counter so the handler bumps
    /// it on every local-record probe hit. Called once at daemon boot
    /// after the counter is built. Kept as a separate setter (instead
    /// of widening [`Self::new`]) so existing callers that don't care
    /// about the counter continue to compile unchanged.
    pub fn with_local_records_hits(mut self, hits: Arc<LocalRecordsHits>) -> Self {
        self.local_records_hits = Some(hits);
        self
    }

    /// §4.5 Sprint 2/2: attach the daemon audit writer so the handler can
    /// append `cname_block` records on CNAME-chain block events. Same
    /// post-construction setter pattern as [`Self::with_local_records_hits`]
    /// — keeps existing test fixtures that don't need audit unchanged.
    pub fn with_audit_writer(mut self, writer: Arc<AuditWriter>) -> Self {
        self.audit_writer = Some(writer);
        self
    }

    /// Attach the shared readiness gate. Until it opens, every query is
    /// refused with SERVFAIL.
    ///
    /// This is a backstop, not the primary guard: `start.rs` already
    /// refuses to bind the listener without a map. The difference is
    /// where the invariant lives — "do not bind without a map" holds
    /// only if every branch reaching the bind is correct, a proof by
    /// enumeration that expires when someone adds a branch; this holds
    /// at the point the query is served, where a new branch cannot
    /// bypass it without touching it.
    pub fn with_filter_ready(mut self, gate: ReadinessGate) -> Self {
        self.filter_ready = gate;
        self
    }

    /// Set `local_dns.dynamic_ttl_secs` — the TTL on dynamic device
    /// `network_name` answers. Same post-construction setter pattern as
    /// [`Self::with_local_records_hits`]: widening [`Self::new`] would break
    /// every existing caller and integration-test fixture for a value only
    /// the daemon boot path knows.
    ///
    /// Unset, the handler answers with `DEFAULT_DYNAMIC_TTL_SECS`, which is
    /// the config default — so a caller that forgets this is wrong only for
    /// operators who tuned the value, never for the default install.
    pub fn with_dynamic_ttl_secs(self, secs: u32) -> Self {
        self.dynamic_ttl_secs
            .store(secs, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Hand out a clone of the shared dynamic-TTL cell so a config reload can
    /// apply a new `local_dns.dynamic_ttl_secs` without a daemon restart.
    /// Mirrors [`Self::allow_from_handle`] exactly, and for the same reason:
    /// the handler is moved into the DNS server by value, so grab the handle
    /// right before that move.
    pub fn dynamic_ttl_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.dynamic_ttl_secs)
    }

    /// Set `local_dns.nodata_for_missing_types` for dynamic device
    /// `network_name` answers. Same post-construction setter pattern as
    /// [`Self::with_dynamic_ttl_secs`]. Unset, the handler defaults to
    /// `true` — the config default — so a caller that forgets this only
    /// gets it wrong for operators who deliberately opted out.
    pub fn with_nodata_for_missing_types_network_name(mut self, enabled: bool) -> Self {
        self.nodata_for_missing_types_network_name = enabled;
        self
    }

    /// Hand out a clone of the shared source-ACL cell (P0-5). The handler is
    /// moved into hickory's `ServerFuture` by value, so the reload path can't
    /// reach it through a reference — it holds this `Arc` clone instead and
    /// live-swaps the ACL by calling `.store()` on the cell directly, so a
    /// tightened `server.allow_from` applies without a daemon restart. `None`
    /// (or an empty Vec) accepts all sources; the store is lock-free and the
    /// hot path picks up the new value on its next `load`. Grab the handle
    /// right before the handler is moved into the DNS server.
    pub fn allow_from_handle(&self) -> Arc<ArcSwapOption<Vec<Cidr>>> {
        Arc::clone(&self.allow_from)
    }

    /// §4.10-4b: attach the DNSSEC response-path validator. Same
    /// post-construction setter pattern as [`Self::with_audit_writer`].
    /// Called once at boot only when `dnssec.mode != Off`; absent it, the
    /// handler does no DNSSEC processing.
    #[cfg(feature = "dnssec")]
    pub fn with_dnssec_validator(mut self, validator: Arc<DnssecValidator>) -> Self {
        self.dnssec_validator = Some(validator);
        self
    }

    /// §4.10-4b — the single DNSSEC hook on the response path. Wraps the free
    /// [`send_cached`] (the convergence point of the cache-hit / fresh-upstream
    /// / stale paths) so a validated answer can get the AD bit, a bogus one a
    /// SERVFAIL, behind `dnssec.mode`. With no validator (default build, or
    /// `mode = Off`) it is a zero-cost passthrough to `send_cached` and the
    /// response bytes are byte-identical to baseline.
    ///
    /// `rewrote` is `true` when a §4.12 / §4.53 rewrite fired on this query; it
    /// both suppresses the DNSSEC verdict (see below) and tells `send_cached` to
    /// synthesize the CNAME bridge back to the original qname.
    #[cfg_attr(not(feature = "dnssec"), allow(clippy::unused_self))]
    async fn send_cached_validated(
        &self,
        request: &Request,
        entry: &super::cache::CacheEntry,
        rewrote: bool,
        response_handle: &mut impl ResponseHandler,
    ) -> ResponseInfo {
        #[cfg(feature = "dnssec")]
        if let Some(validator) = &self.dnssec_validator {
            match validator
                .decide(request, entry.is_negative(), rewrote)
                .await
            {
                // A rewritten answer carries records for a name the client
                // never asked for, fronted by a CNAME *we* synthesized — and a
                // synthesized CNAME is unsigned by construction. So neither
                // wire verdict is honest here and both are suppressed:
                //
                // - never AD: we cannot claim authenticated data for an answer
                //   whose first record nothing signed. `send_cached` re-asserts
                //   this at the `set_authentic_data` site.
                // - never SERVFAIL: a rewrite is operator policy, not a
                //   validation failure. Failing closed would turn one Bogus
                //   verdict into a network-wide outage of `safe_search = true`.
                //
                // `dnssec-validator-validates-unserved-name`: validation no
                // longer *runs* on this path — `decide` now takes `rewrote` and
                // short-circuits to `Serve` before the fetch, because the walk
                // it used to perform was of the pre-rewrite qname and its
                // verdict was discarded here anyway. See the reasoning on
                // `DnssecValidator::decide`.
                //
                // This arm is therefore unreachable-by-construction and is kept
                // as a second gate, deliberately. It costs nothing, and the
                // failure it guards against is severe and asymmetric: a stray
                // SERVFAIL on a rewritten answer is a household-wide outage of
                // `safe_search`. `send_cached` keeps the matching belt on the
                // AD side (`authentic && !rewrote`), and that redundancy is an
                // established idiom here rather than an oversight.
                _ if rewrote => {}
                DnssecDecision::Servfail => return send_servfail(request, response_handle).await,
                DnssecDecision::SetAd => {
                    return send_cached(request, entry, true, rewrote, response_handle).await
                }
                DnssecDecision::Serve => {}
            }
        }
        send_cached(request, entry, false, rewrote, response_handle).await
    }

    /// §4.5 Sprint 2/2: append a `cname_block` audit record off the hot
    /// path. The synchronous `write_all + sync_data` in
    /// [`AuditWriter::append`] is detached via
    /// [`tokio::task::spawn_blocking`] so the DNS query response is not
    /// stalled by the disk write. Failures land in `tracing::warn!` —
    /// the operator sees them in `journalctl -u purge-warden` and the
    /// query response still goes out.
    fn emit_cname_block_audit(
        &self,
        qname: &str,
        offending: &str,
        source_label: &'static str,
        rewrote_from: Option<&str>,
    ) {
        let Some(writer) = self.audit_writer.as_ref().cloned() else {
            return;
        };
        let qname = qname.to_owned();
        let offending = offending.to_owned();
        let source_label = source_label.to_owned();
        // §4.39 — carry the original qname when a §4.12 rewrite fired
        // on this query, so the audit log matches the wire packet
        // (which echoes the original qname per §4.29 h5) instead of
        // diverging to the post-rewrite effective name in `qname`.
        let rewrote_from = rewrote_from.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            let record = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
                .with_action("cname_block")
                .with_domain(qname)
                .with_cname_target(offending)
                .with_cname_source(source_label)
                .with_rewrote_from(rewrote_from.as_deref());
            if let Err(e) = writer.append(&record) {
                tracing::warn!(error = %e, "audit append failed for cname_block");
            }
        });
    }
}

#[async_trait::async_trait]
impl RequestHandler for ForwardHandler {
    // 0.26 added a second generic `T: Time` to the trait method (runtime clock
    // abstraction); mirror it here. Unused in the body — a pure declaration.
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        match self.handle_inner(request, &mut response_handle).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("request failed: {e}");
                send_servfail(request, &mut response_handle).await
            }
        }
    }
}

/// Per-query telemetry payload, consumed by [`ForwardHandler::record_outcome`].
///
/// Replaces 11 inline `s.record_query(...) + s.log_query_event(...)` repetitions
/// in the request path. All fields are Copy/borrowed — the struct lives on the
/// stack for one query and disappears at the end of `handle_inner`, so this
/// stays zero-allocation per project rules hot-path discipline.
struct QueryDecision<'a> {
    client_ip: IpAddr,
    domain: &'a str,
    client_name: Option<&'a str>,
    client_profile: Option<&'a str>,
    /// Hickory query type — drives the `TypeBucket` classification on
    /// `record_query` so per-type counters land in the right bucket.
    /// Carried alongside `record_type_str` (the static label used by the
    /// query log writer); both come from the same `query.query_type()`
    /// extraction so they cannot drift.
    record_type: RecordType,
    record_type_str: &'static str,
    outcome: &'static str,
    elapsed_micros: u64,
    blocked: bool,
    cached: bool,
    /// Set when the served entry is a negative cache hit (NXDOMAIN/NODATA).
    /// Drives the `record_cache_negative_hit` increment alongside the
    /// regular cached counter.
    cache_negative_hit: bool,
    /// §4.5 Sprint 2/2 — offending hop in a CNAME chain block.
    /// `Some(name)` only on the two CNAME-chain-block exit branches
    /// (cache-hit re-check + post-upstream-fetch); `None` everywhere
    /// else. The `record_outcome` helper reads it and forwards to
    /// `log_query_event` so the offending hop ends up in the JSONL row
    /// alongside the original qname.
    cname_chain_via: Option<&'a str>,
    /// Sprint B Dashboard v2 — set to `Some(bit)` only when the
    /// BLOCKED outcome is attributable to a single Tier 1 blocklist
    /// (`BlockSource::List(bit)`). `None` for admin / rule / cname /
    /// IP blocks — those don't pin to one list. The bit is forwarded
    /// to `StatsEngine::record_query`, which atomically increments
    /// the corresponding `list_blocked` slot. Stack-only `Copy`
    /// field; zero-allocation invariant preserved.
    block_list_bit: Option<u8>,
    /// §4.12 — set to `Some(original_qname)` when a per-profile
    /// rewrite fired on this query. `decision.domain` carries the
    /// rewritten (effective) name. Forwarded to the query log writer
    /// so audit can show `from=… to=…`. `None` on every query that
    /// passed through without rewriting (typical case — zero cost).
    rewrote_from: Option<&'a str>,
}

/// handler-06 — per-query context bundle for the block-dispatch helpers
/// ([`ForwardHandler::dispatch_cname_block`] /
/// [`ForwardHandler::dispatch_ip_block`]).
///
/// Replaces the 13 shared positional args those two helpers used to take.
/// Several were transposition-prone — three adjacent `Option<&str>`
/// (`client_name`, `client_profile`, `rewrote_from`) plus `client_ip` and the
/// `u32` TTL — that the compiler can't tell apart on a swap. Mirrors the
/// existing [`QueryDecision`] shape.
///
/// All fields are borrows or `Copy`; the struct is **moved** into the helper
/// (pointer/scalar memcpy, no heap), so the block path stays alloc-free per the
/// project rules hot-path discipline. Each helper destructures it on entry so its
/// body reads byte-for-byte identical to the pre-refactor positional form.
struct BlockDispatchCtx<'a> {
    cache: &'a DnsCache,
    domain: &'a str,
    record_type: RecordType,
    dns_class: DNSClass,
    ecs_cache_prefix: Option<EcsPrefix>,
    client_ip: IpAddr,
    client_name: Option<&'a str>,
    client_profile: Option<&'a str>,
    rewrote_from: Option<&'a str>,
    start: Instant,
    request: &'a Request,
    qname: &'a Name,
    client_blocked_ttl: u32,
    client_block_response: crate::config::schema::BlockResponseV1,
}

impl ForwardHandler {
    /// Single point of stats recording for the request path. Pre-fix, the
    /// 11 outcome sites in `handle_inner` each open-coded
    /// `if let Some(s) = stats { s.record_query(...); s.log_query_event(...); }`,
    /// which made it easy to add a new outcome without wiring all three
    /// counters consistently.
    #[inline]
    fn record_outcome(&self, decision: &QueryDecision<'_>) {
        let Some(stats) = self.stats.as_deref() else {
            return;
        };
        stats.record_query(
            decision.client_ip,
            decision.domain,
            decision.client_name,
            decision.client_profile,
            decision.record_type,
            decision.blocked,
            decision.cached,
            decision.block_list_bit,
        );
        // engine-03 (rev-2606): security refusals (REFUSED / RRL_DROP)
        // also land in total_blocked (9f60205 keeps them visible in
        // stats); tally them in a dedicated counter so the content-block
        // signal stays interpretable. One pointer compare on a &'static
        // str — no alloc, no lock.
        if matches!(decision.outcome, "REFUSED" | "RRL_DROP") {
            stats.record_security_refusal();
        }
        if decision.cache_negative_hit {
            stats.record_cache_negative_hit();
        } else if decision.cached {
            // Sprint §4.4 P1: feed the hit-frequency tracker on positive
            // cache hits only. Tracker short-circuits when disabled.
            stats.record_cache_hit(decision.domain);
        }
        stats.log_query_event(
            decision.client_ip,
            decision.client_name,
            decision.domain,
            decision.record_type_str,
            decision.outcome,
            decision.blocked,
            decision.elapsed_micros,
            decision.cname_chain_via,
            decision.rewrote_from,
        );
    }

    /// §4.42 — block-dispatch helper for the CNAME-chain re-check axis.
    ///
    /// Performs the shared "block detected → invalidate cache tuple → emit
    /// cname_block audit → record BLOCKED outcome → send canned block
    /// response" sequence used by the cache-hit, post-upstream, and
    /// stale-fallback CNAME-block branches. `site` rides as a structured
    /// tracing field so operators can tell which branch fired without
    /// proliferating message parentheticals.
    ///
    /// Cold path: only entered on a block decision. May allocate (the
    /// audit emit hands off to a spawn_blocking task that owns its own
    /// `String`s).
    async fn dispatch_cname_block(
        &self,
        ctx: BlockDispatchCtx<'_>,
        offending: &str,
        source: &BlockSource,
        response_handle: &mut impl ResponseHandler,
        site: &'static str,
    ) -> ResponseInfo {
        let BlockDispatchCtx {
            cache,
            domain,
            record_type,
            dns_class,
            ecs_cache_prefix,
            client_ip,
            client_name,
            client_profile,
            rewrote_from,
            start,
            request,
            qname,
            client_blocked_ttl,
            client_block_response,
        } = ctx;
        tracing::debug!(
            domain,
            cname = %offending,
            source = source.label(),
            site = site,
            "BLOCKED via CNAME chain"
        );
        invalidate_current_bucket(cache, domain, record_type, dns_class, ecs_cache_prefix).await;
        self.emit_cname_block_audit(domain, offending, source.label(), rewrote_from);
        // Sprint B Dashboard v2 — pin the Tier 1 bit when the CNAME-block
        // source is an attributable list hit.
        let block_list_bit = match source {
            BlockSource::List(b) => Some(*b),
            _ => None,
        };
        self.record_outcome(&QueryDecision {
            client_ip,
            domain,
            client_name,
            client_profile,
            record_type,
            record_type_str: record_type_str(record_type),
            outcome: "BLOCKED",
            elapsed_micros: start.elapsed().as_micros() as u64,
            blocked: true,
            cached: false,
            cache_negative_hit: false,
            cname_chain_via: Some(offending),
            rewrote_from,
            block_list_bit,
        });
        send_block_response(
            request,
            qname,
            record_type,
            client_blocked_ttl,
            client_block_response,
            response_handle,
        )
        .await
    }

    /// §4.42 — block-dispatch helper for the IP-blocklist re-check axis.
    ///
    /// Mirror of [`ForwardHandler::dispatch_cname_block`] but for
    /// IP-blocklist hits: no audit emit, `cname_chain_via: None`,
    /// `block_list_bit: None`. Cold path.
    async fn dispatch_ip_block(
        &self,
        ctx: BlockDispatchCtx<'_>,
        blocked_ip: IpAddr,
        response_handle: &mut impl ResponseHandler,
        site: &'static str,
    ) -> ResponseInfo {
        let BlockDispatchCtx {
            cache,
            domain,
            record_type,
            dns_class,
            ecs_cache_prefix,
            client_ip,
            client_name,
            client_profile,
            rewrote_from,
            start,
            request,
            qname,
            client_blocked_ttl,
            client_block_response,
        } = ctx;
        tracing::debug!(
            domain,
            ip = %blocked_ip,
            site = site,
            "BLOCKED via IP blocklist"
        );
        invalidate_current_bucket(cache, domain, record_type, dns_class, ecs_cache_prefix).await;
        self.record_outcome(&QueryDecision {
            client_ip,
            domain,
            client_name,
            client_profile,
            record_type,
            record_type_str: record_type_str(record_type),
            outcome: "BLOCKED",
            elapsed_micros: start.elapsed().as_micros() as u64,
            blocked: true,
            cached: false,
            cache_negative_hit: false,
            cname_chain_via: None,
            rewrote_from,
            block_list_bit: None,
        });
        send_block_response(
            request,
            qname,
            record_type,
            client_blocked_ttl,
            client_block_response,
            response_handle,
        )
        .await
    }

    async fn handle_inner(
        &self,
        request: &Request,
        response_handle: &mut impl ResponseHandler,
    ) -> Result<ResponseInfo, DnsError> {
        // Locals shadow `self.X` so the body reads identically to the
        // pre-refactor free function. Hot-path discipline: these are all
        // `&` borrows or `Copy` reads, no clones.
        let upstream = &self.upstream;
        let filter = &self.filter;
        let cache = &self.cache;
        let profiles = self.profiles.as_deref();
        let stats = self.stats.as_deref();
        let security = self.security.as_deref();
        let local_records = self.local_records.as_deref();
        let local_records_hits = self.local_records_hits.as_deref();
        let ip_filter = self.ip_filter.as_deref();
        let blocked_ttl = self.blocked_ttl;
        let prefetch_semaphore = self.prefetch_semaphore.as_ref();
        let prefetch_threshold = self.prefetch_threshold;
        let cname_max_depth = self.cname_max_depth;
        // P0-5 ACL gate — runs before *anything* else, so a refused source
        // never reaches validation, security, profiles, or the upstream. The
        // check is a tiny number of bitwise CIDR compares (see config::cidr).
        let client_ip = request.src().ip();
        // Read the ACL into a bool inside a tight scope so the `ArcSwapOption`
        // load guard drops BEFORE any `.await` below — holding it across the
        // upstream await would pin a hazard slot for the whole request (and
        // could make this handler future `!Send`). The read stays lock-free.
        let client_permitted = {
            let acl = self.allow_from.load();
            source_allowed(client_ip, acl.as_deref().map(|v| v.as_slice()))
        };
        if !client_permitted {
            if let Some(s) = stats {
                s.global
                    .total_refused_acl
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // handler-05: debug, not warn. A spoofed-source UDP flood at a
            // non-allowed IP would otherwise emit one formatted warn! +
            // journald write per packet — a log-flood / CPU+disk amplification
            // vector. The total_refused_acl counter above is the
            // operator-facing signal; the other refusal paths also log at debug.
            tracing::debug!(
                %client_ip,
                "ACL: query refused — source not in server.allow_from"
            );
            return Ok(send_refused(request, response_handle).await);
        }

        // Readiness backstop (`boot_list_persistence.md` §2.4). Refuse
        // everything — not just filterable names — while no generation
        // is installed: answering ANY query is the thing being
        // prevented, and a partial exemption for local records or
        // rewrites would be a hole with no upside.
        //
        // `is_open` is one `Relaxed` load, and that is correct and
        // deliberate. This flag does not publish the map; `ArcSwap`
        // does, with its own ordering. All the flag has to be is
        // eventually-visible and monotone, and a one-way `bool` needs no
        // fence for that. Do not "harden" it to `SeqCst` — that is a
        // fence on every query for no property. (The ordering now lives
        // in `ReadinessGate::is_open`, one place instead of every call
        // site.)
        if !self.filter_ready.is_open() {
            // handler-05 applies here too, more sharply than on the ACL
            // path it was written for: this fires for EVERY client and
            // EVERY query while closed, not just non-allowed sources,
            // and the window it fires in is boot — the worst possible
            // moment for a per-packet `warn!` + journald write. Warn
            // once so an operator sees it at all; every refusal after
            // that (same cause, already reported) is `debug!`. See
            // `gate_refusal_logged`'s doc comment.
            if !self
                .gate_refusal_logged
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    %client_ip,
                    "REFUSING ALL QUERIES: no filter generation has been \
                     installed yet, so every query is being refused. Run \
                     `warden lists show` and check the daemon's boot log \
                     for why no generation loaded. (Further refusals for \
                     this cause are logged at debug level.)"
                );
            } else {
                tracing::debug!(
                    %client_ip,
                    "query refused: no filter generation installed yet"
                );
            }
            return Ok(send_servfail(request, response_handle).await);
        }

        let query = match request.queries.queries().first() {
            Some(q) => q,
            None => return Ok(send_servfail(request, response_handle).await),
        };

        let name = query.name();

        if let Err(e) = validate_query(name) {
            tracing::debug!(domain = %name, "query validation failed: {e}");
            return Ok(send_servfail(request, response_handle).await);
        }

        let record_type = query.query_type();
        let dns_class = query.query_class();

        // Extract domain string. LowerName is already lowercase; strip trailing root dot.
        // Write directly into CompactString to avoid an intermediate String allocation —
        // domains ≤24 bytes (most of them) stay inline on the stack.
        let mut domain_buf = CompactString::default();
        let _ = write!(domain_buf, "{}", name);
        if domain_buf.ends_with('.') {
            domain_buf.pop();
        }
        let domain = domain_buf.as_str();
        // §4.12 — set to `Some(original)` when the rewrite hook fires
        // (between blocked-check and cache lookup). Declared up-front so
        // every QueryDecision in the function body — including the
        // pre-hook BLOCKED/LOCAL/REFUSED outcomes that never trigger a
        // rewrite — can wire `rewrote_from: rewrote_from.as_deref()`
        // uniformly. Stays `None` on the vast majority of queries.
        let mut rewrote_from: Option<CompactString> = None;

        let start = Instant::now();
        // client_ip already extracted at the top for the ACL gate.

        // Security pre-query checks: rate limiting, char validation, anti-bypass, tunneling
        if let Some(sec) = security {
            if let Err(reason) = sec.check_pre_query(&client_ip, domain, record_type) {
                tracing::debug!(domain, %client_ip, reason, "security: query refused");
                // handler-03 (rev-2606): security refusals are recorded
                // outcomes — pre-fix they bypassed stats + query log
                // entirely, leaving the operator blind to attack volume
                // exactly when these paths fire. Profile attribution is
                // None (refused before resolution).
                //
                // qlog-early-exit-attribution: the *device* name, unlike the
                // profile, does not need the 5-level chain — it is a direct
                // IP→device probe. Bound here rather than hoisted so the
                // ALLOWED / BLOCKED path never pays for it. Without this the
                // Query Log falls back to the raw client IP and an operator
                // reads a correctly-mapped device as a broken mapping.
                let client_name = profiles.and_then(|p| p.device_name(&client_ip));
                self.record_outcome(&QueryDecision {
                    client_ip,
                    domain,
                    client_name: client_name.as_deref(),
                    client_profile: None,
                    record_type,
                    record_type_str: record_type_str(record_type),
                    outcome: "REFUSED",
                    elapsed_micros: start.elapsed().as_micros() as u64,
                    blocked: true,
                    cached: false,
                    cache_negative_hit: false,
                    cname_chain_via: None,
                    rewrote_from: rewrote_from.as_deref(),
                    block_list_bit: None,
                });
                return Ok(send_refused(request, response_handle).await);
            }

            // handler-04 (rev-2606): RRL hoisted above the local-records /
            // blocked / unmapped-client-REFUSED exits — pre-fix it sat
            // below them, so those responses went out at unbounded rate to
            // (potentially spoofed) sources. rrl-03: two refusal classes
            // exit BEFORE this check and are deliberately uncovered — the
            // ACL refusal and the security pre-query refusal above. Both
            // are header-only (amplification ≤ 1, ~nil reflection value),
            // and RRL-dropping a security refusal would hide exactly the
            // attack visibility handler-03 added to stats/query-log.
            // Per-client RRL budgets for sources the operator vouched for.
            // An empty / absent ACL means "no source has been vouched for",
            // so keying stays at the /24 — an open resolver must not hand
            // out 254 budgets per prefix. Reads the same `ArcSwapOption`
            // the ACL check above used, so a hot-reloaded `allow_from`
            // narrows or widens this on the next query with no restart.
            let rrl_per_client = {
                let acl = self.allow_from.load();
                acl.as_deref()
                    .is_some_and(|c| !c.is_empty() && source_allowed(client_ip, Some(c)))
            };
            match sec.check_response(&client_ip, rrl_per_client) {
                RrlAction::Allow => {}
                RrlAction::Drop => {
                    tracing::debug!(domain, %client_ip, "RRL: dropping response");
                    // handler-03: drops are visible in stats + query log.
                    // blocked: true — service was refused for this query.
                    //
                    // qlog-early-exit-attribution: RRL sits deliberately ABOVE
                    // resolution (it bounds the rate of refusals to spoofed
                    // sources), so the name is probed directly rather than by
                    // moving the hoist. One `ArcSwap` load + one map probe, on
                    // a path that is already refusing the query.
                    let client_name = profiles.and_then(|p| p.device_name(&client_ip));
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: client_name.as_deref(),
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "RRL_DROP",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: true,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(servfail_info()); // Drop silently
                }
                RrlAction::Slip => {
                    tracing::debug!(domain, %client_ip, "RRL: slipping TC response");
                    // blocked: false — the TC bit invites a TCP retry, the
                    // client still gets served (anti-spoofing probe, not a
                    // service refusal).
                    // qlog-early-exit-attribution: same probe as RRL_DROP.
                    let client_name = profiles.and_then(|p| p.device_name(&client_ip));
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: client_name.as_deref(),
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "RRL_SLIP",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: false,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_truncated(request, response_handle).await);
                }
            }
        }

        // S44 T2: profile resolution moves AHEAD of the local-record checks
        // so the profile-scope probe (which precedes global per §4 truth
        // table) has a `ResolvedProfile` to consult. The Sprint 18
        // anonymous-client-still-sees-global-records semantics is
        // preserved: the REFUSED dispatch for `profile == None` only fires
        // AFTER both local-record probes miss (R1, byte-for-byte).
        let resolution_opt = profiles.map(|r| r.resolve(&client_ip));
        let resolved_profile = resolution_opt
            .as_ref()
            .and_then(|r| r.profile.as_ref().cloned());
        // qlog-early-exit-attribution: the LOCAL-record exits between here and
        // the big `match (profiles, resolution_opt)` below all recorded
        // `client_name: None`, and were filed as "pre-resolution exits". They
        // are not — resolution has already run, one line up. The device name
        // was simply never read off it, so a mapped device rendered in the
        // Query Log as a bare IP.
        //
        // A **borrow**, not a clone: `resolution_opt` outlives every exit that
        // reads this, and the borrow ends before the `match` below consumes it
        // by value. Costs the hot path nothing.
        let early_device_name: Option<&str> = resolution_opt
            .as_ref()
            .and_then(|r| r.device_name.as_deref());

        // §4.8 §2/2 T4 — derive the per-query EDNS Client Subnet option
        // once per request from the resolved profile's `EcsPolicy` and
        // the client IP. Both the cache (T3 partitioning key) and the
        // upstream call (T4 lookup arg) receive the result. When the
        // master switch is off, when the profile/upstream mode is
        // `Off`, or when the codec rejects the inputs, `ecs_option` is
        // `None` — byte-identical to pre-§4.8 wire baseline.
        let ecs_option = resolved_profile
            .as_ref()
            .and_then(|p| p.ecs_policy.build_option(client_ip));
        let ecs_cache_prefix = ecs_option.as_ref().and_then(|opt| opt.as_cache_prefix());

        // S44 T2: profile-scoped local DNS records (DM4). Probed BEFORE
        // the global table so `[[profile.X.local_records]]` shadows
        // `[[local_dns.records]]` silently for clients on profile X
        // (DR7, §4 truth table). DR4: only A/AAAA/CNAME participate —
        // `ProfileLocalRecords::lookup` enforces this internally and
        // returns `None` for any other qtype, falling through to the
        // global table and then upstream. DR11: not inserted into moka.
        if let Some(ref profile) = resolved_profile {
            if let Some(hit) = profile.local_records.lookup_with_apex(domain, record_type) {
                tracing::debug!(
                    domain,
                    ?record_type,
                    profile = %profile.name,
                    "LOCAL DNS (profile-scope)"
                );
                // S44 T3: record the hit on the per-(scope, apex) counter so
                // the TUI Local DNS tab can show "which records actually
                // fire". Keyed by the matched record's apex (`hit.apex`), not
                // the raw QNAME, so a wildcard subdomain flood rolls up under
                // one key (perfmem T1). Cheap atomic — DashMap entry probe +
                // fetch_add(Relaxed). Skipped when the counter is not attached
                // (test / fixture handlers).
                if let Some(hits) = local_records_hits {
                    hits.record_hit(
                        LocalRecordsScopeKey::Profile(profile.name.clone()),
                        &hit.apex,
                    );
                }
                self.record_outcome(&QueryDecision {
                    client_ip,
                    domain,
                    client_name: early_device_name,
                    client_profile: Some(profile.name.as_str()),
                    record_type,
                    record_type_str: record_type_str(record_type),
                    outcome: "LOCAL",
                    elapsed_micros: start.elapsed().as_micros() as u64,
                    blocked: false,
                    cached: false,
                    cache_negative_hit: false,
                    cname_chain_via: None,
                    rewrote_from: rewrote_from.as_deref(),
                    block_list_bit: None,
                });
                return Ok(send_local(request, &hit.records, response_handle).await);
            }
        }

        // Local DNS records — bypass filter, cache, and upstream entirely.
        // (Global table — Sprint 18 path, unchanged. Owns PTR / reverse-DNS
        // synthesis, which profile-scope deliberately skips per DR13.)
        if let Some(local) = local_records {
            match local.lookup(domain, record_type) {
                LocalLookup::Hit { records, apex } => {
                    tracing::debug!(domain, ?record_type, "LOCAL DNS");
                    // S44 T3: bump the global-scope hit counter, keyed by the
                    // matched record's apex (not the raw QNAME) so a wildcard
                    // subdomain flood rolls up under one key (perfmem T1).
                    if let Some(hits) = local_records_hits {
                        hits.record_hit(LocalRecordsScopeKey::Global, &apex);
                    }
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: early_device_name,
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "LOCAL",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: false,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_local(request, &records, response_handle).await);
                }
                // local-01: the name is locally authoritative but holds no
                // records of this qtype — answer NODATA instead of leaking
                // the internal hostname upstream (where a private-TLD
                // NXDOMAIN would negative-cache the whole *name*, RFC 2308,
                // breaking the types we DO hold). No hit-counter bump: the
                // TUI counter tracks record fires, and no record fired.
                LocalLookup::NodataSynthesis { ttl } => {
                    tracing::debug!(
                        domain,
                        ?record_type,
                        "LOCAL DNS (name defined, qtype NODATA)"
                    );
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: early_device_name,
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "LOCAL",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: false,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_soa_nodata(request, ttl, response_handle).await);
                }
                LocalLookup::Miss => {}
            }
        }

        // Dynamic device network names (2026-08-10 design spec, D1/D2/D5).
        // Probed AFTER the static `local_dns` miss so an operator-authored
        // record always wins an exact collision — the validator already
        // refuses such a collision at load time, so this ordering is defence
        // in depth, not the primary guarantee.
        //
        // A-only for the actual answer: there is no IPv6/NDP tracking to
        // resolve against (D5), so a device `network_name` never carries an
        // AAAA. But a configured name that has no A answer still leaks
        // upstream if left to fall through — the exact incident `local-01`
        // fixed for static `local_dns` records: an upstream NXDOMAIN for a
        // private/internal name negative-caches the whole NAME (RFC 2308
        // §5), not just the queried type, and `getaddrinfo` fires A and AAAA
        // in parallel, so the NXDOMAIN from the AAAA race can suppress the A
        // query that would have answered. Mirrors `LocalLookup::NodataSynthesis`
        // immediately above: qtype ≠ A on a configured name answers NODATA
        // (gated on the same `nodata_for_missing_types` operator escape
        // hatch), not a silent fall-through.
        //
        // The existence probe runs first because `resolve_network_name`
        // returning `None` conflates two answers that must diverge here:
        // "not one of our names" (fall through, silently) and "ours, but the
        // device is offline" (NXDOMAIN).
        if let Some(resolver) = profiles {
            if resolver.network_name_is_configured(domain) {
                if record_type == RecordType::A {
                    match resolver.resolve_network_name(domain) {
                        Some(IpAddr::V4(ip)) => {
                            // Owner = the QNAME itself, taken from the already
                            // parsed query rather than rebuilt from `domain`:
                            // infallible, allocation-free, and automatically
                            // correct for a wildcard descendant, where the
                            // answer must be owned by the queried name and NOT
                            // by the device's apex (the rule
                            // `LocalRecords::lookup` spends a `format!` on).
                            // Safe because no rewrite has fired yet at this
                            // point — `domain` is still `name` minus its root
                            // dot.
                            let ttl = self
                                .dynamic_ttl_secs
                                .load(std::sync::atomic::Ordering::Relaxed);
                            let record =
                                Record::from_rdata(Name::from(name.clone()), ttl, RData::A(A(ip)));
                            tracing::debug!(domain, %ip, "LOCAL DNS (device network name)");
                            self.record_outcome(&QueryDecision {
                                client_ip,
                                domain,
                                client_name: early_device_name,
                                client_profile: None,
                                record_type,
                                record_type_str: record_type_str(record_type),
                                outcome: "LOCAL",
                                elapsed_micros: start.elapsed().as_micros() as u64,
                                blocked: false,
                                cached: false,
                                cache_negative_hit: false,
                                cname_chain_via: None,
                                rewrote_from: rewrote_from.as_deref(),
                                block_list_bit: None,
                            });
                            return Ok(send_local(request, &[record], response_handle).await);
                        }
                        Some(IpAddr::V6(_)) => {
                            // The device pins a v6 address, which an A query
                            // cannot carry. Falls through instead of answering
                            // negatively — deliberately inconsistent with the
                            // `None` arm below (both are "the name exists but
                            // has no A"), and specified that way by the plan's
                            // Task 7. Flagged in NOTES.md rather than silently
                            // harmonised.
                        }
                        None => {
                            // Configured, but the device has neither a pinned
                            // IP nor a live ARP entry — never observed, or
                            // offline. NXDOMAIN rather than a silent
                            // fall-through: this bare name is warden's to
                            // answer, not the public resolver's, and leaking
                            // it upstream would both fail and disclose the
                            // operator's internal naming.
                            tracing::debug!(
                                domain,
                                "device network name configured but unresolvable — NXDOMAIN"
                            );
                            // Recorded like the `NodataSynthesis` arm above:
                            // a locally-authoritative negative answer is still
                            // an answer warden gave. handler-03 (rev-2606) is
                            // the precedent — an exit that skips
                            // `record_outcome` leaves the operator blind in
                            // stats and query log exactly when they are
                            // debugging why a device name went dark.
                            self.record_outcome(&QueryDecision {
                                client_ip,
                                domain,
                                client_name: early_device_name,
                                client_profile: None,
                                record_type,
                                record_type_str: record_type_str(record_type),
                                outcome: "LOCAL",
                                elapsed_micros: start.elapsed().as_micros() as u64,
                                blocked: false,
                                cached: false,
                                cache_negative_hit: false,
                                cname_chain_via: None,
                                rewrote_from: rewrote_from.as_deref(),
                                block_list_bit: None,
                            });
                            return Ok(send_nxdomain(request, response_handle).await);
                        }
                    }
                } else if self.nodata_for_missing_types_network_name {
                    // qtype ≠ A on a configured network_name (AAAA is the
                    // common case — see the comment above this block for
                    // the local-01-shaped race this closes). NODATA rather
                    // than a silent fall-through to upstream.
                    let ttl = self
                        .dynamic_ttl_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    tracing::debug!(
                        domain,
                        ?record_type,
                        "LOCAL DNS (device network name, qtype NODATA)"
                    );
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: early_device_name,
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "LOCAL",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: false,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_soa_nodata(request, ttl, response_handle).await);
                }
                // else: operator set `nodata_for_missing_types = false` —
                // the same deliberate split-horizon escape hatch the static
                // `local_dns` table already gives (see its doc comment).
                // Falls through unchanged.
            }
        }

        // Resolve the 5-level chain. `Resolution::profile` is `None` when
        // the chain reaches level 5 with `server.default_profile` unset —
        // the SN3 "no match" REFUSED sentinel (the pre-v1
        // `block_unmapped_clients` flag). Anonymous / unknown sources
        // still take the REFUSED path here, not a canned 0.0.0.0 response:
        // REFUSED is not cached by stub resolvers, so recovery is immediate
        // when the operator wires a `default_profile` or subnet for them.
        // The REFUSED path is intentionally hardcoded and ignores any
        // profile's `block_response` — predictable recovery beats
        // per-profile flexibility on this axis.
        //
        // S44 T2: the resolution was performed early (above) so
        // profile-scope local records could be probed; we re-use the
        // already-resolved value here instead of resolving twice.
        // F5 (incident 2026-07-27): `device_overlay` rides out of this
        // match alongside the block verdict. It is the *only* place the
        // resolved device's overlay is in scope, and the response-path
        // filters below need it to resolve the queried name's policy
        // once — see the `NamePolicy::resolve` call after the rewrite
        // hook. Moving the field out (rather than cloning the Arc) keeps
        // the hot path refcount-neutral.
        let (
            blocked,
            block_source,
            client_name,
            client_block_response,
            client_blocked_ttl,
            device_overlay,
        ) = match (profiles, resolution_opt) {
            (Some(_resolver), Some(resolution)) => {
                let Some(profile) = resolution.profile.clone() else {
                    tracing::info!(
                        %client_ip,
                        domain,
                        "REFUSED (no match in 5-level resolver chain — \
                         set server.default_profile or map a subnet to recover)"
                    );
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        // qlog-early-exit-attribution: the chain matched no
                        // *profile*, which does not mean it matched no
                        // *device* — a device row with no usable profile lands
                        // exactly here, and it is the case an operator is most
                        // likely to be debugging. `resolution` is bound by this
                        // very arm, so the name is free.
                        client_name: resolution.device_name.as_deref(),
                        client_profile: None,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "REFUSED",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: true,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_refused(request, response_handle).await);
                };
                // Sprint 43 T4: per-device overlay applies between
                // resolution and the profile evaluator. When the
                // resolved client has no overlay (empty rule sets, or
                // anonymous source), `evaluate_with_overlay` is
                // byte-identical to the pre-T4 `filter.evaluate` path.
                //
                // Sprint B Dashboard v2: now also returns the
                // attributing `BlockSource` so we can pin a per-
                // list bit on the BLOCKED stats record.
                let (is_blocked, block_source) =
                    evaluate_with_overlay(domain, &profile, resolution.overlay.as_ref(), filter);
                // handler-01 (rev-2606): move `device_name` out of the owned
                // `resolution` (was `.clone()`) and stop materialising an
                // owned profile-name String per query — `client_profile`
                // borrows from `resolved_profile` below, which holds the
                // same Arc for the whole request. Zero-alloc hot path.
                let device_name = resolution.device_name;
                let overlay = resolution.overlay;
                // N6: the profile carries `block_response` / `blocked_ttl_secs`
                // with the server-globals fallback already applied at build
                // time, so the hot path just reads them.
                let br = profile.block_response;
                let ttl = profile.blocked_ttl_secs;
                (is_blocked, block_source, device_name, br, ttl, overlay)
            }
            (None, _) | (Some(_), None) => {
                // L-3 (rev-2026-04-unreachable-profile): pre-fix this was an
                // `unreachable!` keyed to the construction invariant that
                // `start.rs` always builds a profile resolver. A future
                // refactor that broke the invariant would panic the per-
                // request task on every query. Fail-closed REFUSED matches
                // the "default profile must be restrictive" rule
                // (project rules §Key Design Rules #5) and the "no silent
                // fallback" security posture; a warn-log surfaces the
                // construction breakage to operators without paging.
                //
                // S44 T2: the `(Some(_), None)` arm is structurally
                // unreachable — `resolution_opt` is `Some(_)` whenever
                // `profiles` is `Some(_)` (we built it from the same
                // `Option`). Listed for exhaustiveness only.
                tracing::warn!(
                    %client_ip,
                    domain,
                    "REFUSED (profile resolver missing — construction invariant in start.rs broken; \
                     daemon staying up but refusing queries until rebuilt)"
                );
                self.record_outcome(&QueryDecision {
                    client_ip,
                    domain,
                    // qlog-early-exit-attribution: `None` is CORRECT here and
                    // is the one site the sweep deliberately leaves alone.
                    // This arm is reached when `profiles` itself is `None` —
                    // there is no resolver, hence no device map to consult.
                    // Probing would be a lookup against nothing.
                    client_name: None,
                    client_profile: None,
                    record_type,
                    record_type_str: record_type_str(record_type),
                    outcome: "REFUSED",
                    elapsed_micros: start.elapsed().as_micros() as u64,
                    blocked: true,
                    cached: false,
                    cache_negative_hit: false,
                    cname_chain_via: None,
                    rewrote_from: rewrote_from.as_deref(),
                    block_list_bit: None,
                });
                return Ok(send_refused(request, response_handle).await);
            }
        };
        // handler-01 (rev-2606): the profile name for stats / query-log
        // attribution is borrowed straight out of `resolved_profile` (alive
        // for the whole request body) — `Some` whenever we got past the
        // REFUSED arms above. Replaces a per-query `String` allocation.
        let client_profile: Option<&str> = resolved_profile.as_ref().map(|p| p.name.as_str());
        // N7 — A/AAAA symmetric block invariant.
        //
        // `send_block_response` dispatches by `record_type`: A → 0.0.0.0,
        // AAAA → ::, everything else → NODATA. Because the resolver's
        // decision that `blocked == true` is computed from the domain alone
        // (record_type is not an input), a blocked name hands back a block
        // response for EVERY type the caller asks about — A, AAAA, CNAME,
        // MX, … — never a single-family block. Any future refactor that
        // threads record_type INTO the resolver decision breaks N7 and
        // must add a counter-test first.
        let _n7_invariant_ack = blocked;

        if blocked {
            tracing::debug!(domain, ?record_type, "BLOCKED");
            // Sprint B Dashboard v2 — pin a Tier 1 list bit when the
            // BlockSource attributes the block to a single list. Admin /
            // rule / cname-walker variants stay unattributed (None) to
            // preserve the "one list per blocked-list count" semantics.
            let block_list_bit = match &block_source {
                Some(BlockSource::List(b)) => Some(*b),
                _ => None,
            };
            self.record_outcome(&QueryDecision {
                client_ip,
                domain,
                client_name: client_name.as_deref(),
                client_profile,
                record_type,
                record_type_str: record_type_str(record_type),
                outcome: "BLOCKED",
                elapsed_micros: start.elapsed().as_micros() as u64,
                blocked: true,
                cached: false,
                cache_negative_hit: false,
                cname_chain_via: None,
                rewrote_from: rewrote_from.as_deref(),
                block_list_bit,
            });
            let qname = Name::from(name.clone());
            return Ok(send_block_response(
                request,
                &qname,
                record_type,
                client_blocked_ttl,
                client_block_response,
                response_handle,
            )
            .await);
        }

        // §4.12 — Domain rewrite hook. Runs AFTER the filter+blocked check
        // (so a rewrite cannot bypass blocklist enforcement on the original
        // qname) and BEFORE the cache lookup (so the cache key uses the
        // rewritten name — bonus hit-rate when multiple sources of the
        // legacy domain converge on the migrated target). Single-pass: no
        // chaining (DR2 runtime guard inside `ProfileRewriteRules::apply`).
        //
        // The client DOES see the target. The response's Question section
        // echoes the original qname, and every serve path bridges it to the
        // target with a synthesized `original CNAME target` record — see
        // `prepend_rewrite_cname`. The comment that stood here until
        // 2026-07-09 claimed "the client never sees the internal target":
        // true of the Question section, false of the Answer section, which
        // carried target-owned RRs with nothing bridging them. glibc's
        // `getanswer()` discards RRs it cannot reach from the question name,
        // so `safe_search = true` made Google/Bing/DDG/YouTube resolve to no
        // addresses at all. Pinned now by `tests/rewrite_client_answer_shape.rs`.
        if let Some(ref profile) = resolved_profile {
            if let Some(new_domain) = profile.rewrite_rules.apply(domain) {
                tracing::debug!(
                    from = %domain,
                    to = %new_domain,
                    profile = %profile.name,
                    "DNS REWRITE"
                );
                rewrote_from = Some(std::mem::replace(&mut domain_buf, new_domain));
            }
        }
        let domain = domain_buf.as_str();

        // F5 (incident 2026-07-27) — resolve the operator's policy for the
        // queried name ONCE, here, and hand it to every site below that
        // inspects the *answer*: the three `walk_response` call sites
        // (cache-hit re-check, post-upstream, stale fallback) and the three
        // `IpFilter::check_response` ones next to them.
        //
        // Before this, each of those sites re-derived "is this allowed?"
        // from whatever policy it happened to hold — the walker saw only
        // `profile.allow_domains`, the IP filter saw nothing at all — so an
        // allow the operator had attached to a *device* was honoured
        // pre-upstream and then silently discarded on the response path.
        // That is the whole defect class, not two instances of it.
        //
        // **Placement is load-bearing, twice over:**
        //
        // 1. AFTER the §4.12 / §4.53 rewrite hook above. That hook
        //    `mem::replace`s `domain_buf`, so `domain` here can differ from
        //    the name evaluated pre-upstream — with SafeSearch on, eight
        //    rewrites are populated and it routinely does. Every consumer
        //    below filters the post-rewrite name, so the policy must be
        //    keyed on the post-rewrite name too. Resolving it earlier
        //    regresses F1 on any deployment with a rewrite rule; pinned by
        //    `tests/integration_name_policy_once.rs`.
        // 2. From the ALLOW SETS, never from `blocked == false`. Reaching
        //    this line only means the name was not blocked, which is the
        //    state nearly all traffic is in and which must stay fully
        //    filterable on the response path. `NamePolicy::resolve` probes
        //    `profile.allow_domains` and `overlay.allow` and nothing else.
        //
        // `resolved_profile` is `Some` at this point by construction (the
        // two REFUSED arms above return early); the `map` is defensive and
        // falls back to `Neutral`, i.e. to filtering.
        let name_policy = resolved_profile
            .as_ref()
            .map(|p| NamePolicy::resolve(domain, p.as_ref(), device_overlay.as_deref()))
            .unwrap_or_default();

        // (handler-04: the RRL check formerly here moved up next to the
        // pre-query security gate so blocked / local / unmapped-REFUSED
        // responses are rate-limited too. ACL and security refusals exit
        // before it — see the rrl-03 note at the hoist site.)

        // Cache lookup — single operation returning Fresh, Stale, or Miss.
        // §4.8 §2/2 T4: `ecs_cache_prefix` partitions the lookup by ECS
        // bucket when a per-profile policy emits a non-anonymous option.
        // `None` keeps the baseline pre-§4.8 byte-identical wire/cache
        // behaviour for every profile that opts out or stays on the
        // anonymous form.
        // cache-01 (rev-2606): keyed lookup — the returned key is reused by
        // `fetch_with_keyed_state` on the miss/stale path below, saving one
        // key construction + one cache probe per forwarded query.
        let (cache_key, cache_result) = cache
            .lookup_keyed(domain, record_type, dns_class, ecs_cache_prefix)
            .await;

        if let CacheLookup::Fresh(ref entry) = cache_result {
            // s44-arch-cache-invalidate-on-block (M-12 follow-up):
            // re-run the post-fetch filter checks against the cached
            // records before serving them. Direct domain blocks are
            // already caught above at `evaluate_with_overlay` (line ~517,
            // BEFORE this lookup), so the only race window left is for
            // CNAME-chain blocks (cached `D CNAME → C` where `C` was
            // added to a deny rule after the cache populated) and
            // IP-blocklist blocks (cached `D A 1.2.3.4` where 1.2.3.4
            // was added to the IP blocklist after the cache populated).
            // On trip we invalidate the precise tuple, record a BLOCKED
            // outcome, and send the canned block response — same shape
            // as the post-upstream BLOCKED-via-CNAME / BLOCKED-via-IP
            // branches below. Cost on the happy path: at most one CNAME
            // walk + one IP HashSet probe per cache hit (typically 1-3
            // records × O(1) lookups, sub-µs).
            // §4.5 Sprint 2/2 — replaces the §4.4 P2 `check_cname_chain`
            // wrapper here. `walk_response` returns a typed `Verdict` so the
            // audit log + Query Log enrichment can name `BlockSource` (list /
            // rule / admin_block / cname_loop / cname_depth_exceeded) without
            // a second filter probe at log time. By construction (the
            // `(None, _) | (Some(_), None)` REFUSED arms above) we only reach
            // this site with `resolved_profile = Some(profile)`; the
            // `if let` is defensive.
            if let Some(profile_arc) = resolved_profile.as_ref() {
                if let Verdict::Block { offending, source } = walk_response(
                    entry.records(),
                    filter,
                    profile_arc.as_ref(),
                    name_policy,
                    cname_max_depth,
                ) {
                    let qname = Name::from(name.clone());
                    return Ok(self
                        .dispatch_cname_block(
                            BlockDispatchCtx {
                                cache,
                                domain,
                                record_type,
                                dns_class,
                                ecs_cache_prefix,
                                client_ip,
                                client_name: client_name.as_deref(),
                                client_profile,
                                rewrote_from: rewrote_from.as_deref(),
                                start,
                                request,
                                qname: &qname,
                                client_blocked_ttl,
                                client_block_response,
                            },
                            offending.as_str(),
                            &source,
                            response_handle,
                            "cache-hit re-check",
                        )
                        .await);
                }
            }
            if let Some(ipf) = ip_filter {
                if let Some(blocked_ip) = ipf.check_response(entry.records(), name_policy) {
                    let qname = Name::from(name.clone());
                    return Ok(self
                        .dispatch_ip_block(
                            BlockDispatchCtx {
                                cache,
                                domain,
                                record_type,
                                dns_class,
                                ecs_cache_prefix,
                                client_ip,
                                client_name: client_name.as_deref(),
                                client_profile,
                                rewrote_from: rewrote_from.as_deref(),
                                start,
                                request,
                                qname: &qname,
                                client_blocked_ttl,
                                client_block_response,
                            },
                            blocked_ip,
                            response_handle,
                            "cache-hit re-check",
                        )
                        .await);
                }
            }

            tracing::debug!(domain, ?record_type, "CACHE HIT");
            self.record_outcome(&QueryDecision {
                client_ip,
                domain,
                client_name: client_name.as_deref(),
                client_profile,
                record_type,
                record_type_str: record_type_str(record_type),
                outcome: "CACHED",
                elapsed_micros: start.elapsed().as_micros() as u64,
                blocked: false,
                cached: true,
                cache_negative_hit: entry.is_negative(),
                cname_chain_via: None,
                rewrote_from: rewrote_from.as_deref(),
                block_list_bit: None,
            });

            // TTL-triggered prefetch: if near expiry, spawn a background refresh
            if let Some(sem) = prefetch_semaphore {
                if entry.needs_prefetch(prefetch_threshold) {
                    if let Ok(permit) = sem.clone().try_acquire_owned() {
                        let upstream = Arc::clone(upstream);
                        let cache = cache.clone();
                        let filter = Arc::clone(filter);
                        // handler-02 (rev-2606): the refreshed entry must
                        // pass the same IP-blocklist gate the serve paths
                        // run — pre-fix prefetch skipped it entirely.
                        let ip_filter = self.ip_filter.clone();
                        // handler-07: rewrite-aware upstream Name via the
                        // shared `fwd_name_for` helper — one definition for
                        // the prefetch + forward paths (its doc carries the
                        // §4.12 / §4.30-disc-1 coherence rule).
                        let fwd_name = fwd_name_for(domain, rewrote_from.is_some(), name);
                        let domain_owned = CompactString::new(domain);
                        // §4.8 §2/2 T4: capture the per-query ECS bundle
                        // for the spawned refresh — the prefetched answer
                        // must land in the same cache bucket the client
                        // queried, otherwise the refresh would populate a
                        // sibling slot the client never sees.
                        let ecs_for_prefetch = ecs_option.clone();
                        let ecs_prefix_for_prefetch = ecs_cache_prefix;
                        tokio::spawn(async move {
                            let _permit = permit;
                            match upstream
                                .lookup_domain(
                                    domain_owned.as_str(),
                                    &fwd_name,
                                    record_type,
                                    ecs_for_prefetch,
                                )
                                .await
                            {
                                Ok(resp)
                                    if resp.response_code == ResponseCode::NoError
                                        && !resp.records.is_empty() =>
                                {
                                    // L-8 (rev-2026-04-cname-prefetch-cap):
                                    // bound the CNAME inspection to cname_max_depth
                                    // — symmetry with check_cname_chain on the
                                    // request path. M-31: shares the unified
                                    // `cname_chain_blocked` walker; the prefetch
                                    // task has no per-client profile context (the
                                    // refreshed entry is shared cache, not
                                    // per-client), so the closure consults
                                    // `filter.is_blocked` directly.
                                    let has_blocked_cname =
                                        cname_chain_blocked(&resp.records, cname_max_depth, |t| {
                                            filter.is_blocked(t)
                                        })
                                        .is_some();
                                    // handler-02: IP-blocklist parity with the
                                    // cache-hit / post-upstream / stale guards.
                                    //
                                    // F5: `NamePolicy::Neutral`, not the
                                    // query's `name_policy`. This refresh
                                    // populates the SHARED (None-bucket)
                                    // cache slot, which other clients read
                                    // under their own policy, so the entry
                                    // it stores must be one every client
                                    // may see. Fail-closed cost is
                                    // hit-rate only: a name the operator
                                    // allowed whose answer is otherwise
                                    // blocked simply is not prefetched —
                                    // the serve paths above still allow it,
                                    // they just pay the upstream round trip.
                                    let has_blocked_ip = ip_filter
                                        .as_deref()
                                        .and_then(|f| {
                                            f.check_response(&resp.records, NamePolicy::Neutral)
                                        })
                                        .is_some();
                                    if has_blocked_cname || has_blocked_ip {
                                        tracing::debug!(
                                            domain = %domain_owned,
                                            cname = has_blocked_cname,
                                            ip = has_blocked_ip,
                                            "prefetch: blocked content, skipping"
                                        );
                                    } else {
                                        // M-13: prefetch is the path that
                                        // most benefits from move-into-insert
                                        // — `resp.records` is built by the
                                        // upstream call and never read again
                                        // inside this spawned task, so no
                                        // clone is needed.
                                        cache
                                            .insert(
                                                &domain_owned,
                                                record_type,
                                                dns_class,
                                                resp.records,
                                                ResponseCode::NoError,
                                                None,
                                                ecs_prefix_for_prefetch,
                                            )
                                            .await;
                                        tracing::debug!(
                                            domain = %domain_owned,
                                            "prefetch complete"
                                        );
                                    }
                                }
                                _ => {}
                            }
                        });
                    }
                }
            }

            return Ok(self
                .send_cached_validated(request, entry, rewrote_from.is_some(), response_handle)
                .await);
        }

        // RFC 8482 §6 — refuse QTYPE=ANY with a synthesised HINFO record
        // instead of forwarding upstream. A wildcard ANY response can be
        // kilobytes and turns the resolver into a reflection/amplification
        // vector that RRL only dampens. Cloudflare, Knot, and modern BIND
        // all implement this the same way.
        //
        // Intercepted AFTER the profile filter (so an explicitly-blocked
        // domain still takes the block path) and AFTER the cache check
        // (so a cached negative still serves). Placed BEFORE upstream so
        // we never pay the forwarding cost.
        if record_type == RecordType::ANY {
            tracing::debug!(domain, "RFC 8482: ANY intercepted, returning HINFO");
            self.record_outcome(&QueryDecision {
                client_ip,
                domain,
                client_name: client_name.as_deref(),
                client_profile,
                record_type,
                record_type_str: record_type_str(record_type),
                outcome: "HINFO",
                elapsed_micros: start.elapsed().as_micros() as u64,
                blocked: false,
                cached: false,
                cache_negative_hit: false,
                cname_chain_via: None,
                rewrote_from: rewrote_from.as_deref(),
                block_list_bit: None,
            });
            let qname = Name::from(name.clone());
            return Ok(send_rfc8482(request, &qname, blocked_ttl, response_handle).await);
        }

        // tunneling-rate-01 (rev-2606): per-(client, base) tunneling rate,
        // counted on the cache-MISS path only. Pre-fix the bump lived in
        // check_pre_query (pre-cache, keyed on base alone), so cache hits
        // and every LAN client drew down one shared per-base budget —
        // 50 aggregate queries/min to a popular base (googlevideo.com,
        // amazonaws.com) REFUSED it network-wide. Tunneling fan-out is
        // inherently cache-missing unique names; hits prove repetition.
        // Stale entries also skip the bump (a stale name was cached
        // before — repetition, not fan-out).
        //
        // sec-ptr-skips-both-tunneling-gates: the PTR exemption
        // (query-validator-01) is now scoped to the reverse zones by
        // `tunneling_rate_gate_applies`. Inside them it still holds —
        // every reverse name shares the base `in-addr.arpa` / `ip6.arpa`,
        // so counting them re-creates the one-bucket footgun. Outside
        // them a PTR query is ordinary fan-out and is counted.
        if matches!(cache_result, CacheLookup::Miss)
            && tunneling_rate_gate_applies(record_type, domain)
        {
            if let Some(sec) = security {
                if sec.check_tunneling_rate(&client_ip, domain) {
                    tracing::debug!(domain, %client_ip, "security: tunneling rate exceeded");
                    self.record_outcome(&QueryDecision {
                        client_ip,
                        domain,
                        client_name: client_name.as_deref(),
                        client_profile,
                        record_type,
                        record_type_str: record_type_str(record_type),
                        outcome: "REFUSED",
                        elapsed_micros: start.elapsed().as_micros() as u64,
                        blocked: true,
                        cached: false,
                        cache_negative_hit: false,
                        cname_chain_via: None,
                        rewrote_from: rewrote_from.as_deref(),
                        block_list_bit: None,
                    });
                    return Ok(send_refused(request, response_handle).await);
                }
            }
        }

        tracing::debug!(domain, ?record_type, "forwarding query");

        // T3.2.b M-12: forward via cache.lookup_or_fetch — moka's
        // try_get_with collapses N concurrent fetches for the same key
        // into 1 upstream call (singleflight). The closure carries the
        // SOA-min hint out for negative-response TTL math, and returns
        // Err(Uncacheable) for SERVFAIL/Refused so try_get_with skips
        // caching them (mirrors insert's pre-fix guard, now structural).
        // FetchFailure carries any pre-existing stale entry for
        // upstream-failure fallback — the previous local stale_entry
        // capture moves into lookup_or_fetch.
        //
        // Cost on cache MISS path (vs pre-fix): +1 Name clone + 1
        // CompactString alloc + 1 Arc<dyn Upstream> atomic increment for
        // the closure capture; moka's try_get_with adds an internal
        // hashmap probe on the singleflight registry. Cache HIT path is
        // untouched (the lookup() above short-circuits before we reach
        // this code). The win on a concurrent uncached burst (cert
        // renewal, social-login storm) is N→1 upstream RTTs.
        //
        // handler-07: rewrite-aware upstream Name via the shared
        // `fwd_name_for` helper — one definition for the prefetch + forward
        // paths (its doc carries the §4.12 / §4.30-disc-1 coherence rule).
        let fwd_name = fwd_name_for(domain, rewrote_from.is_some(), name);
        let upstream_for_closure = Arc::clone(upstream);
        let fwd_name_for_closure = fwd_name.clone();
        let domain_for_closure = CompactString::new(domain);

        // §4.8 §2/2 T6 — audit emit on ECS injection. Fires once per
        // upstream-bound query (cache MISS path) when the resolved
        // policy contributes an option; cache HIT path skips because
        // the on-the-wire option is what we already cached. Lives at
        // `target = "audit"`, level `debug` per D5: the volume can be
        // high (one emit per upstream RTT) so info is too loud, but
        // operators who flip `RUST_LOG=audit=debug` see every record
        // exactly. Frozen-string format pinned by
        // `tests/frozen_strings_s48_audit.rs` against the constants
        // defined alongside this module.
        if let Some(ref ecs_emit) = ecs_option {
            let profile_id = resolved_profile
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or(crate::dns::audit_ecs::ANONYMOUS_PROFILE_TAG);
            tracing::debug!(
                target: crate::dns::audit_ecs::AUDIT_TARGET,
                event = crate::dns::audit_ecs::AUDIT_ECS_INJECT_EVENT,
                profile_id = %profile_id,
                client_ip = %client_ip,
                ecs_addr = %ecs_emit.address(),
                ecs_prefix = ecs_emit.source_prefix(),
                qname = %domain,
                qtype = ?record_type,
                "ECS injected into upstream query"
            );
        }

        let ecs_for_fetch = ecs_option.clone();
        // cache-01 (rev-2606): reaching this site means the keyed lookup
        // above returned Stale or Miss (Fresh returned early). Hand the
        // already-built key + the stale entry (upstream-failure fallback)
        // to the singleflight fetch — no re-probe, no second key build.
        let stale_prior = match cache_result {
            CacheLookup::Stale(entry) => Some(entry),
            _ => None,
        };
        let lookup_result = cache
            // §4.8 §2/2 T4: ECS-bucket cache key dimension. The
            // singleflight fetcher closure also gets the per-query ECS
            // option so the upstream sees the right `OPT` record.
            .fetch_with_keyed_state(cache_key, stale_prior, move || async move {
                match upstream_for_closure
                    .lookup_domain(
                        domain_for_closure.as_str(),
                        &fwd_name_for_closure,
                        record_type,
                        ecs_for_fetch,
                    )
                    .await
                {
                    Ok(resp) => {
                        // SERVFAIL/Refused must NOT cache — return Err
                        // so try_get_with skips the insert and the
                        // handler can forward the response_code.
                        if matches!(
                            resp.response_code,
                            ResponseCode::ServFail | ResponseCode::Refused
                        ) {
                            Err(DnsError::Uncacheable(resp.response_code))
                        } else {
                            Ok((resp.records, resp.response_code, resp.soa_minimum_ttl))
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .await;

        // Stats: count the upstream attempt as ALLOWED. If the post-fetch
        // CNAME / IP filter trips below we ALSO record a BLOCKED outcome,
        // matching the pre-T3.2.b double-count for forwards-attempted vs
        // forwards-blocked.
        self.record_outcome(&QueryDecision {
            client_ip,
            domain,
            client_name: client_name.as_deref(),
            client_profile,
            record_type,
            record_type_str: record_type_str(record_type),
            outcome: "ALLOWED",
            elapsed_micros: start.elapsed().as_micros() as u64,
            blocked: false,
            cached: false,
            cache_negative_hit: false,
            cname_chain_via: None,
            rewrote_from: rewrote_from.as_deref(),
            block_list_bit: None,
        });

        match lookup_result {
            Ok(entry) => {
                // §4.29 h5 — the BLOCKED response must echo the Question
                // section's qname, not the post-§4.12 rewrite target stored
                // in `fwd_name`. Mirrors the cache-hit branches above (lines
                // 850, 884) which build the same `Name::from(name.clone())`.
                // Hoisted here so both the CNAME-block and IP-block early-
                // return branches below pick it up without duplicating the
                // construction.
                let qname = Name::from(name.clone());
                // Post-fetch filter checks on the freshly-cached entry.
                // Mirrors the s44-arch filter-on-cache-hit guard at the
                // CACHE HIT branch above — running both means we block on
                // the FIRST request when the rule pre-existed (this site)
                // AND on subsequent requests when the cache populated
                // before the rule was added (cache-hit site). Negative
                // responses (empty records) skip — nothing to filter.
                //
                // [s-4.29-disc-2] KNOWN ASYMMETRY, deliberately left in place —
                // do not "tidy" it in either direction without reading this.
                //
                // The `response_code() == NoError` conjunct is NOT justified by
                // the comment above it, which argues only for the emptiness
                // test. It additionally skips a **non-empty** answer:
                //
                //   RFC 2308 §2.1 — a CNAME chain terminating in NXDOMAIN
                //   carries its CNAMEs in the ANSWER section with
                //   `RCODE = NXDOMAIN`, and `parse_response_bytes`
                //   (`upstream/mod.rs`) keeps `msg.answers` regardless of
                //   rcode. So on the raw / DoH / DoT / DoQ transports such an
                //   entry reaches here with records present and a non-NoError
                //   rcode, and skips both the chain walk and the IP check.
                //   (The hickory-`Resolver` plain path discards them, so the
                //   case is transport-dependent.)
                //
                // The two sibling sites — the cache-hit `CacheLookup::Fresh`
                // branch and the stale fallback — carry NO rcode predicate, so
                // the same entry IS walked on the next query for that name.
                // First query serves NXDOMAIN and logs it as such; second
                // serves the canned block response and logs BLOCKED.
                //
                // This answers the question `s-4.29-disc-2`'s verdict left
                // open ("can a BLOCKED response escape via the cache or stale
                // branch?"): **no** — a guard is a *skip*, so the two
                // unguarded sites check strictly more. What can escape is the
                // *guarded* site, which is the opposite of the filed remedy
                // (that remedy would have added this guard to the other two,
                // widening the skip to the only places these entries are
                // inspected at all).
                //
                // Narrowing it to `!is_empty()` is the right fix, and is NOT
                // applied here because it is a **wire-visible** change — the
                // first query would start returning the canned block response
                // instead of NXDOMAIN — and the site sits inside the
                // post-upstream-fetch branch, unreachable from any current test
                // harness (`CacheEntry::for_test` is
                // `cfg(all(test, feature = "dnssec"))` and only reaches
                // `send_cached`). Shipping an untested wire change to satisfy a
                // P3 style nit is the wrong trade. Whoever takes it needs a
                // handler harness that can drive a post-fetch entry.
                if !entry.records().is_empty() && entry.response_code() == ResponseCode::NoError {
                    // §4.5 Sprint 2/2 — post-upstream chain inspection,
                    // mirror of the cache-hit re-check above. Same defensive
                    // `if let Some(profile)` for parity (REFUSED early-return
                    // above guarantees `Some` at this site).
                    if let Some(profile_arc) = resolved_profile.as_ref() {
                        if let Verdict::Block { offending, source } = walk_response(
                            entry.records(),
                            filter,
                            profile_arc.as_ref(),
                            name_policy,
                            cname_max_depth,
                        ) {
                            return Ok(self
                                .dispatch_cname_block(
                                    BlockDispatchCtx {
                                        cache,
                                        domain,
                                        record_type,
                                        dns_class,
                                        ecs_cache_prefix,
                                        client_ip,
                                        client_name: client_name.as_deref(),
                                        client_profile,
                                        rewrote_from: rewrote_from.as_deref(),
                                        start,
                                        request,
                                        qname: &qname,
                                        client_blocked_ttl,
                                        client_block_response,
                                    },
                                    offending.as_str(),
                                    &source,
                                    response_handle,
                                    "post-upstream",
                                )
                                .await);
                        }
                    }

                    if let Some(ipf) = ip_filter {
                        if let Some(blocked_ip) = ipf.check_response(entry.records(), name_policy) {
                            return Ok(self
                                .dispatch_ip_block(
                                    BlockDispatchCtx {
                                        cache,
                                        domain,
                                        record_type,
                                        dns_class,
                                        ecs_cache_prefix,
                                        client_ip,
                                        client_name: client_name.as_deref(),
                                        client_profile,
                                        rewrote_from: rewrote_from.as_deref(),
                                        start,
                                        request,
                                        qname: &qname,
                                        client_blocked_ttl,
                                        client_block_response,
                                    },
                                    blocked_ip,
                                    response_handle,
                                    "post-upstream",
                                )
                                .await);
                        }
                    }
                }

                Ok(self
                    .send_cached_validated(request, &entry, rewrote_from.is_some(), response_handle)
                    .await)
            }
            Err(FetchFailure { stale, error }) => match error.as_ref() {
                DnsError::Uncacheable(rc) => {
                    // Forward SERVFAIL/Refused without caching. Same wire
                    // shape as the pre-T3.2.b negative-response branch but
                    // takes only this exit when the closure flagged the
                    // response as non-cacheable.
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let mut metadata = Metadata::response_from_request(&request.metadata);
                    metadata.authoritative = false;
                    metadata.recursion_available = true;
                    metadata.response_code = *rc;

                    let response = builder.build_no_records(metadata);
                    let info = response_handle
                        .send_response(response)
                        .await
                        .map_err(|e| DnsError::ServerError(e.to_string()))?;
                    Ok(info)
                }
                _ => {
                    // Network-layer failure — serve stale fallback if any
                    // (L-2 stats-stale-hit semantics preserved). Otherwise
                    // surface the inner error message; we cannot Clone the
                    // typed variant out of the Arc, so we wrap into
                    // UpstreamRequestFailed for downstream classification.
                    if let Some(entry) = stale {
                        // §4.42 — re-run the same CNAME-chain + IP-blocklist
                        // guards the fresh-cache-hit and post-upstream paths
                        // run before serving. A deny rule added at runtime
                        // while upstream is unreachable was silently bypassed
                        // for any pre-existing cached entry until this fix.
                        // Cold path (only entered on upstream failure with a
                        // stale entry present); helper handles invalidate +
                        // audit + record + canned-block dispatch. `entry`
                        // stays owned here so `entry.records()` borrow lives
                        // across both guards; no clone.
                        let qname = Name::from(name.clone());
                        if let Some(profile_arc) = resolved_profile.as_ref() {
                            if let Verdict::Block { offending, source } = walk_response(
                                entry.records(),
                                filter,
                                profile_arc.as_ref(),
                                name_policy,
                                cname_max_depth,
                            ) {
                                return Ok(self
                                    .dispatch_cname_block(
                                        BlockDispatchCtx {
                                            cache,
                                            domain,
                                            record_type,
                                            dns_class,
                                            ecs_cache_prefix,
                                            client_ip,
                                            client_name: client_name.as_deref(),
                                            client_profile,
                                            rewrote_from: rewrote_from.as_deref(),
                                            start,
                                            request,
                                            qname: &qname,
                                            client_blocked_ttl,
                                            client_block_response,
                                        },
                                        offending.as_str(),
                                        &source,
                                        response_handle,
                                        "stale-fallback re-check",
                                    )
                                    .await);
                            }
                        }
                        if let Some(ipf) = ip_filter {
                            if let Some(blocked_ip) =
                                ipf.check_response(entry.records(), name_policy)
                            {
                                return Ok(self
                                    .dispatch_ip_block(
                                        BlockDispatchCtx {
                                            cache,
                                            domain,
                                            record_type,
                                            dns_class,
                                            ecs_cache_prefix,
                                            client_ip,
                                            client_name: client_name.as_deref(),
                                            client_profile,
                                            rewrote_from: rewrote_from.as_deref(),
                                            start,
                                            request,
                                            qname: &qname,
                                            client_blocked_ttl,
                                            client_block_response,
                                        },
                                        blocked_ip,
                                        response_handle,
                                        "stale-fallback re-check",
                                    )
                                    .await);
                            }
                        }
                        tracing::warn!(
                            domain,
                            ?record_type,
                            error = %error,
                            "upstream failed, serving stale cache"
                        );
                        self.record_outcome(&QueryDecision {
                            client_ip,
                            domain,
                            client_name: client_name.as_deref(),
                            client_profile,
                            record_type,
                            record_type_str: record_type_str(record_type),
                            outcome: "STALE",
                            elapsed_micros: start.elapsed().as_micros() as u64,
                            blocked: false,
                            cached: true,
                            cache_negative_hit: entry.is_negative(),
                            cname_chain_via: None,
                            rewrote_from: rewrote_from.as_deref(),
                            block_list_bit: None,
                        });
                        return Ok(self
                            .send_cached_validated(
                                request,
                                &entry,
                                rewrote_from.is_some(),
                                response_handle,
                            )
                            .await);
                    }
                    Err(DnsError::UpstreamRequestFailed(error.to_string()))
                }
            },
        }
    }
}

/// §4.29 — invalidate the cache slot for the exact (domain, qtype, class,
/// ecs_prefix) tuple the current request was served from. Wraps
/// [`DnsCache::invalidate_key`] solely to force every call site to pass an
/// `ecs_cache_prefix` arg explicitly (no `None` short-circuit): pre-§4.29 four
/// post-block invalidate sites passed literal `None` while an ECS-bucketed
/// entry sat in `Some(prefix)`, leaving the stale slot live until natural
/// TTL.
async fn invalidate_current_bucket(
    cache: &DnsCache,
    domain: &str,
    record_type: RecordType,
    dns_class: DNSClass,
    ecs_cache_prefix: Option<EcsPrefix>,
) {
    cache
        .invalidate_key(domain, record_type, dns_class, ecs_cache_prefix)
        .await;
}

/// Send a canned blocked response.
///
/// - A queries → 0.0.0.0 (sinkhole)
/// - AAAA queries → :: (sinkhole)
/// - All other types → NOERROR with zero answers (NODATA), NOT NXDOMAIN.
///   Using NODATA avoids polluting downstream negative caches, which would
///   prevent the 0.0.0.0 sinkhole from working on subsequent A queries.
async fn send_blocked(
    request: &Request,
    qname: &Name,
    record_type: RecordType,
    ttl: u32,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.recursion_available = true;

    match record_type {
        RecordType::A => {
            let rdata = RData::A(A(Ipv4Addr::UNSPECIFIED)); // 0.0.0.0
            let record = Record::from_rdata(qname.clone(), ttl, rdata);
            metadata.response_code = ResponseCode::NoError;
            let response = builder.build(metadata, std::iter::once(&record), &[], &[], &[]);
            match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    tracing::error!("failed to send blocked A response: {e}");
                    servfail_info()
                }
            }
        }
        RecordType::AAAA => {
            let rdata = RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)); // ::
            let record = Record::from_rdata(qname.clone(), ttl, rdata);
            metadata.response_code = ResponseCode::NoError;
            let response = builder.build(metadata, std::iter::once(&record), &[], &[], &[]);
            match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    tracing::error!("failed to send blocked AAAA response: {e}");
                    servfail_info()
                }
            }
        }
        _ => {
            // NODATA: NOERROR with zero answers + SOA in authority (RFC 2308 §2.1).
            // The SOA tells resolvers how long to cache this negative answer.
            // Do NOT return NXDOMAIN — that would tell caches "this domain doesn't
            // exist" and suppress future A/AAAA queries for the same domain.
            metadata.response_code = ResponseCode::NoError;
            let soa = blocked_soa(ttl);
            let response = builder.build(metadata, &[], std::iter::once(&soa), &[], &[]);
            match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    tracing::error!("failed to send blocked NODATA response: {e}");
                    servfail_info()
                }
            }
        }
    }
}

/// Send a synthesised RFC 8482 §6 HINFO reply for QTYPE=ANY queries.
/// Answer section contains one HINFO record with CPU="RFC8482" and OS=""
/// at the query name. Header is NOERROR with AA=0.
async fn send_rfc8482(
    request: &Request,
    qname: &Name,
    ttl: u32,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.recursion_available = true;
    metadata.response_code = ResponseCode::NoError;

    let rdata = RData::HINFO(HINFO::new("RFC8482".to_string(), String::new()));
    let record = Record::from_rdata(qname.clone(), ttl, rdata);
    let response = builder.build(metadata, std::iter::once(&record), &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send RFC 8482 ANY response: {e}");
            servfail_info()
        }
    }
}

/// Send a local DNS response (static records from config).
async fn send_local(
    request: &Request,
    records: &[Record],
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.recursion_available = true;
    metadata.response_code = ResponseCode::NoError;
    let response = builder.build(metadata, records.iter(), &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send local DNS response: {e}");
            servfail_info()
        }
    }
}

/// Send a cached DNS response with TTL adjusted to remaining freshness.
///
/// L-5 (rev-2026-04-cached-neg-soa): cached negative responses (NXDOMAIN
/// or NODATA) include a synthesized SOA in the authority section per
/// RFC 2308 §3, mirroring the fresh-blocked NODATA path. The SOA's
/// minimum TTL drives downstream resolver negative-cache duration, so
/// omitting it caused intermediaries to fall back to defaults instead of
/// honoring the operator's `negative_ttl` floor. The SOA is synthesized
/// via `blocked_soa(remaining_ttl)` because the upstream's authority
/// section is not preserved in `CacheEntry` — sufficient for negative-
/// cache TTL signaling; carrying the original SOA verbatim is a future
/// improvement out of L-5 scope.
/// Ceiling for the TTL of the CNAME we synthesize in front of a rewritten
/// answer (see [`prepend_rewrite_cname`]).
///
/// The served TTL is `min(entry.remaining_ttl(), this)`, which pins two bounds:
///
/// - **It never outlives the RRs it fronts.** A downstream cache that kept the
///   CNAME after the target's records expired would hold a redirect to a name
///   it has no answer for, and would have to re-query anyway.
/// - **It drains fast when policy changes.** This record is *config*, not DNS
///   data: it exists only because a rewrite rule or `safe_search = true` said
///   so. Five minutes bounds how long a downstream resolver keeps following a
///   redirect the operator has already deleted. Long TTLs buy nothing — the
///   next query re-derives the same bridge from the same cache entry for free.
const REWRITE_CNAME_TTL_SECS: u32 = 300;

/// Bridge a rewritten answer back to the name the client actually asked for.
///
/// After a §4.12 / §4.53 rewrite the cached records are owned by the rewrite
/// **target**, while the response's Question section still carries the original
/// qname. Served as-is that answer is dangling: glibc's stub (`getanswer()` in
/// `resolv/nss_dns/dns-host.c`) walks the CNAME chain outward from the question
/// name and discards every RR whose owner it never reaches, so `getaddrinfo`
/// returns *no addresses*. `dig` prints such a packet happily with exit 0, which
/// is why this shipped for two sprints.
///
/// So we prepend the record a conformant recursor would have emitted —
/// `original CNAME target` — and leave every fetched RR untouched. Prepending
/// rather than relabelling the fetched RRs' owners is required twice over:
///
/// - a rewritten answer is routinely a multi-hop CNAME chain (CDN flattening),
///   and a blanket relabel would orphan `hop1 A ip` from the CNAME that pointed
///   at `hop1`;
/// - a DNSSEC RRSIG covers the owner name, so relabelling an RRset invalidates
///   its signature.
///
/// The target is read off the first cached record rather than rebuilt from the
/// rewritten domain string: it is already a parsed `Name`, so the bridge costs
/// one small-buffer `Name` clone instead of the `format!` + `Name::from_ascii`
/// label re-parse that `fwd_name_for` exists to keep off the cache-hit path.
///
/// Cost is confined to the rewrite branch — `rewrote == false` never calls this,
/// so a passthrough query allocates and copies exactly what it did before.
fn prepend_rewrite_cname(request: &Request, remaining_ttl_secs: u32, records: &mut Vec<Record>) {
    // Positive answers only: `send_cached`'s negative branch serves an authority
    // SOA and zero answer RRs, so there is no owner name to mislabel there.
    let Some(target) = records.first().map(|r| r.name.clone()) else {
        return;
    };
    let Some(query) = request.queries.queries().first() else {
        return;
    };
    let original = Name::from(query.name().clone());
    // Defence in depth: an identity rule would make us emit `X CNAME X`, a
    // self-loop that costs a resolver a chain walk. `ProfileRewriteRules::apply`
    // returns `None` on a no-op today, so this is unreachable. `Name`'s `PartialEq`
    // is case-insensitive (RFC 4343), which is what we want.
    if original == target {
        return;
    }
    let ttl = remaining_ttl_secs.min(REWRITE_CNAME_TTL_SECS);
    records.insert(
        0,
        Record::from_rdata(original, ttl, RData::CNAME(CNAME(target))),
    );
}

async fn send_cached(
    request: &Request,
    entry: &super::cache::CacheEntry,
    authentic: bool,
    rewrote: bool,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.recursion_available = true;
    // §4.10-4b: the AD bit is *ours* — set deliberately from our own verdict,
    // never echoed from an upstream/request. `Header::response_from_request`
    // above already clears AD (`authentic_data = false`), so this write only
    // ever *raises* AD (on a Secure verdict); writing `false` is a no-op. It is
    // therefore never a wire difference vs the feature-off build, which leaves
    // AD clear. The write only exists on the `dnssec` build, so the default
    // binary's response bytes are unchanged.
    //
    // `!rewrote` is the second half of the rewrite suppression documented in
    // `send_cached_validated`: an answer fronted by our unsigned synthesized
    // CNAME can never honestly assert authenticated data, whatever the validator
    // decided about the original name.
    #[cfg(feature = "dnssec")]
    {
        metadata.authentic_data = authentic && !rewrote;
    }
    #[cfg(not(feature = "dnssec"))]
    let _ = authentic;

    if entry.is_negative() {
        metadata.response_code = entry.response_code();
        let ttl = entry.remaining_ttl().as_secs().max(1) as u32;
        let soa = blocked_soa(ttl);
        let response = builder.build(metadata, &[], std::iter::once(&soa), &[], &[]);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("failed to send cached negative response: {e}");
                servfail_info()
            }
        }
    } else {
        let mut records = entry.records_with_remaining_ttl();
        if rewrote {
            // Same `remaining` the records above were stamped with, so the
            // bridge is provably never longer-lived than what it fronts.
            let remaining = entry.remaining_ttl().as_secs().max(1) as u32;
            prepend_rewrite_cname(request, remaining, &mut records);
        }
        let response = builder.build(metadata, records.iter(), &[], &[], &[]);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("failed to send cached response: {e}");
                servfail_info()
            }
        }
    }
}

fn servfail_info() -> ResponseInfo {
    // 0.26 removed Header::new() and split Header into Metadata + HeaderCounts.
    // Rebuild a minimal SERVFAIL header (no request context on this fallback
    // path, so id=0 — cosmetic here, the send already failed).
    let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

async fn send_servfail(
    request: &Request,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.response_code = ResponseCode::ServFail;

    let response = builder.build_no_records(metadata);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send SERVFAIL: {e}");
            servfail_info()
        }
    }
}

/// Send REFUSED response — used for security-rejected queries.
async fn send_refused(
    request: &Request,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.response_code = ResponseCode::Refused;

    let response = builder.build_no_records(metadata);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send REFUSED: {e}");
            servfail_info()
        }
    }
}

/// Send NXDOMAIN response — `RCODE=3 (NXDOMAIN)`, no records.
///
/// Sprint 23 s23-block-response-handler. Used by the per-profile
/// `block_response = "nxdomain"` path. Stub resolvers cache the
/// negative answer aggressively (typically the SOA's negative TTL),
/// so subsequent queries for the same name return without hitting
/// this daemon — useful when the operator wants ad/tracker blocks
/// to "feel like" the host doesn't exist instead of returning
/// 0.0.0.0 (which some clients still try to connect to before
/// failing).
async fn send_nxdomain(
    request: &Request,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.response_code = ResponseCode::NXDomain;

    let response = builder.build_no_records(metadata);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send NXDOMAIN: {e}");
            servfail_info()
        }
    }
}

/// Dispatch a blocked-query response through the variant configured on
/// the client's resolved profile (v1
/// [`BlockResponseV1`](crate::config::schema::BlockResponseV1) — `Zero` /
/// `Nxdomain` / `Refused` / `SoaNodata`).
///
/// **The REFUSED-on-no-match path does NOT call this function.** It
/// calls [`send_refused`] directly — predictable secondary-DNS fallthrough
/// for sources the operator hasn't wired a profile for.
///
/// N7 (A/AAAA symmetric block): regardless of the variant, the response
/// is built from `record_type` without consulting the filter decision, so
/// A and AAAA queries for the same blocked name both come back with a
/// blocked answer (0.0.0.0 / :: for `Zero`, NODATA+SOA for `SoaNodata`,
/// the full-rcode variants for `Nxdomain` / `Refused`).
async fn send_block_response(
    request: &Request,
    qname: &Name,
    record_type: RecordType,
    ttl: u32,
    block_response: crate::config::schema::BlockResponseV1,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    use crate::config::schema::BlockResponseV1;
    match block_response {
        BlockResponseV1::Zero => {
            send_blocked(request, qname, record_type, ttl, response_handle).await
        }
        BlockResponseV1::Nxdomain => send_nxdomain(request, response_handle).await,
        BlockResponseV1::Refused => send_refused(request, response_handle).await,
        BlockResponseV1::SoaNodata => {
            // NOERROR + authority SOA (RFC 2308 §2.1). Same wire shape as
            // the "other record type" arm of `send_blocked`, reused here
            // so operators who pick `soa_nodata` on a profile get the
            // negative-caching-friendly response for *every* type —
            // including A / AAAA where `Zero` would have returned a
            // canned 0.0.0.0 / ::.
            send_soa_nodata(request, ttl, response_handle).await
        }
    }
}

/// Send a `NOERROR` response with zero answers + a synthesised SOA in
/// the authority section. RFC 2308 §2.1. Used by the v1
/// `BlockResponseV1::SoaNodata` variant.
async fn send_soa_nodata(
    request: &Request,
    ttl: u32,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.recursion_available = true;
    metadata.response_code = ResponseCode::NoError;
    let soa = blocked_soa(ttl);
    let response = builder.build(metadata, &[], std::iter::once(&soa), &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send soa_nodata response: {e}");
            servfail_info()
        }
    }
}

/// Send truncated response (TC bit) — used by RRL slip mechanism.
/// Forces the client to retry via TCP, proving it's not using a spoofed IP.
async fn send_truncated(
    request: &Request,
    response_handle: &mut impl ResponseHandler,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.authoritative = false;
    metadata.truncation = true;
    metadata.recursion_available = true;

    let response = builder.build_no_records(metadata);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to send TC response: {e}");
            servfail_info()
        }
    }
}

/// Cached parses of the three static `Name`s used by every blocked NODATA
/// SOA. Pre-fix this re-ran `Name::from_ascii(...).unwrap()` on each
/// blocked response — at thousands of blocks/min that contradicts the
/// zero-allocation hot-path discipline. `Name`'s internal labels are
/// Arc-backed, so `.clone()` is a refcount bump.
fn blocked_soa_zone() -> &'static Name {
    static ZONE: OnceLock<Name> = OnceLock::new();
    ZONE.get_or_init(|| Name::from_ascii("block.purge-warden.local.").unwrap())
}

fn blocked_soa_mname() -> &'static Name {
    static MNAME: OnceLock<Name> = OnceLock::new();
    MNAME.get_or_init(|| Name::from_ascii("ns.purge-warden.local.").unwrap())
}

fn blocked_soa_rname() -> &'static Name {
    static RNAME: OnceLock<Name> = OnceLock::new();
    RNAME.get_or_init(|| Name::from_ascii("admin.purge-warden.local.").unwrap())
}

/// Synthesize a canned SOA for blocked NODATA responses (RFC 2308 §2.1).
///
/// The SOA goes in the authority section and tells resolvers how long to
/// cache this negative answer. Uses a synthetic zone `block.purge-warden.local.`
/// so the record is clearly identifiable as originating from purge-warden.
fn blocked_soa(ttl: u32) -> Record {
    Record::from_rdata(
        blocked_soa_zone().clone(),
        ttl,
        RData::SOA(SOA::new(
            blocked_soa_mname().clone(),
            blocked_soa_rname().clone(),
            1,     // serial
            3600,  // refresh
            600,   // retry
            86400, // expire
            ttl,   // minimum (negative cache TTL)
        )),
    )
}

/// True if `client_ip` is permitted to query, given the configured ACL.
///
/// Semantics:
/// - `None`              → no ACL configured → accept all sources.
/// - `Some(empty slice)` → no ACL configured → accept all sources.
///   (We treat empty as "no ACL" because the validator already refuses
///   the dangerous combination of `0.0.0.0` listen + empty `allow_from`.)
/// - `Some(non-empty)`   → accept iff at least one CIDR contains the source.
fn source_allowed(client_ip: IpAddr, allow_from: Option<&[Cidr]>) -> bool {
    match allow_from {
        None | Some([]) => true,
        Some(acl) => any_contains(acl, client_ip),
    }
}

/// Sprint 43 T4: combined per-device overlay + profile evaluator.
///
/// Implements the §4 truth table at the DNS hot-path call site:
/// when the resolved client carries a non-empty
/// [`crate::profiles::DeviceOverlay`], two new `HashSet::contains`
/// probes (R5) feed [`apply_overlay`] for the 9-row decision; on
/// `OverlayDecision::FallThrough` we run the existing profile
/// evaluator unchanged.
///
/// `overlay = None` (the common case for devices that haven't pinned
/// any per-device exception, plus anonymous sources at level 4 / 5)
/// short-circuits to `filter.evaluate(domain, profile)` — byte-identical
/// pre-T4 behaviour, snapshot acceptance §8.
///
/// **Attribution side-effect:** this is the natural seat for
/// [`crate::tracking::RuleSource`] computation (DM5). T4 logs the
/// attribution at `tracing::debug!` only — T5 wires it into the query
/// log + per-device stats once the wire format extends. Computing it
/// here keeps the layer mapping in one place; T5 just adds the
/// downstream consumer.
///
/// **N7 invariant:** the `DeviceOverlay` allow / deny sets key on
/// domain only — qtype is not consulted at this layer. The hot path
/// therefore returns the same Block/Forward verdict for `A` and
/// `AAAA` of the same name, preserving the §4 caveat ("the overlay
/// is qtype-agnostic by construction").
/// Sprint B Dashboard v2 — return widened from `bool` to
/// `(bool, Option<BlockSource>)` so the BLOCKED-outcome stats path can
/// pin a per-list bit when the block is attributable to a single Tier
/// 1 blocklist hit. The overlay-Block branch returns
/// `Some(BlockSource::AdminBlock)` because per-device deny is
/// admin-grade. The fall-through profile path defers to
/// `evaluate_attributed`, which already names the source authoritatively.
#[inline]
fn evaluate_with_overlay(
    domain: &str,
    profile: &Arc<ResolvedProfile>,
    overlay: Option<&Arc<DeviceOverlay>>,
    filter: &FilterEngine,
) -> (bool, Option<BlockSource>) {
    if let Some(ov) = overlay {
        let hits = LayerHits {
            profile_deny_hit: domain_matches_set(domain, &profile.deny_domains),
            device_allow_hit: domain_matches_set(domain, &ov.allow),
            device_deny_hit: domain_matches_set(domain, &ov.deny),
        };
        match apply_overlay(hits, ov.override_profile_deny) {
            OverlayDecision::Allow {
                source,
                override_used,
            } => {
                tracing::debug!(
                    domain,
                    profile = %profile.name,
                    device = %ov.device_id.as_str(),
                    source = source_label(source),
                    override_used,
                    "overlay decision: ALLOW",
                );
                return (false, None);
            }
            OverlayDecision::Block { source } => {
                tracing::debug!(
                    domain,
                    profile = %profile.name,
                    device = %ov.device_id.as_str(),
                    source = source_label(source),
                    "overlay decision: BLOCK",
                );
                return (true, Some(BlockSource::AdminBlock));
            }
            OverlayDecision::FallThrough => {
                // No device-side rule fired; fall through to the
                // profile evaluator below — bitmask + advanced rules.
            }
        }
    }
    let (verdict, source) = filter.evaluate_attributed(domain, profile);
    match verdict {
        FilterResult::Block => (true, source),
        FilterResult::Forward => (false, None),
    }
}

#[inline]
fn source_label(source: AttribSource) -> &'static str {
    match source {
        AttribSource::Profile => "profile",
        AttribSource::Device => "device",
    }
}

/// Walk CNAME records in `records`, applying `is_blocked` to each target.
///
/// Stops after `cname_max_depth` CNAME records to prevent runaway chains.
/// Returns the first blocked target, if any.
///
/// M-31: the closure pattern lets the prefetch path and the request path
/// share the walking + parsing logic while supplying their own per-target
/// predicate. Pre-fix two near-identical walkers diverged only on the
/// predicate, and the request-path version recomputed
/// `resolver.resolve(client_ip)` inside the loop on every CNAME hop —
/// callers now hoist that resolution before the call so the lookup runs
/// once per query, not up to `cname_max_depth` times.
/// Walk the CNAME records in an upstream response, returning the first
/// blocked target if any. Sprint §4.4 P2's background refresh worker
/// reuses this walker to mirror Approach A's CNAME safety check on
/// proactively-refreshed entries (`prefetch_worker::refresh_one`).
pub(crate) fn cname_chain_blocked(
    records: &[Record],
    cname_max_depth: usize,
    mut is_blocked: impl FnMut(&str) -> bool,
) -> Option<CompactString> {
    // The same clamp `walk_response` applies. Both bound and direction have
    // to match: the serve path refuses past `MAX_HOPS` whatever the operator
    // configured, so a prefetch path that tolerates deeper chains caches
    // entries the serve-time re-check can never hand out.
    let cap = cname_max_depth.min(crate::filter::cname::MAX_HOPS);
    let mut checked = 0usize;
    for record in records {
        if record.record_type() != RecordType::CNAME {
            continue;
        }
        let RData::CNAME(ref cname) = record.data else {
            continue;
        };
        let mut target = CompactString::default();
        let _ = write!(target, "{}", &**cname);
        if target.ends_with('.') {
            target.pop();
        }
        target.make_ascii_lowercase();
        if checked >= cap {
            // Fail CLOSED: a chain past the cap counts as blocked, the same
            // verdict `walk_response` reaches via
            // `BlockSource::CnameDepthExceeded`. Failing open here would
            // cache entries the serve-time re-check then refuses.
            tracing::warn!("CNAME chain depth exceeded {cap}, treating as blocked");
            return Some(target);
        }
        if is_blocked(&target) {
            return Some(target);
        }
        checked += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// handler-07: `fwd_name_for` must forward the REWRITTEN qname when a
    /// rewrite fired (the §4.12-leak guard — a client-response assertion can't
    /// see a wrong name reach the wire) and reuse the original parsed name
    /// verbatim when none did (the §4.30 disc-1 cheap branch). This is the
    /// behavioural complement to the source-shape pin in
    /// `tests/integration_fwd_name_branch_disc1.rs`.
    #[test]
    fn fwd_name_for_rewrite_vs_passthrough() {
        let original = LowerName::from(Name::from_ascii("api.old.example.").unwrap());

        // No rewrite: reuse the parsed name directly.
        let passthrough = fwd_name_for("api.old.example", false, &original);
        assert_eq!(passthrough, Name::from(original.clone()));

        // Rewrite fired: the upstream Name is rebuilt from the rewritten
        // `domain`, NOT the original — otherwise the engine would query the old
        // name (the §4.12 leak the shared helper exists to prevent).
        let rewritten = fwd_name_for("api.new.example", true, &original);
        assert_eq!(rewritten, Name::from_ascii("api.new.example.").unwrap());
        assert_ne!(rewritten, Name::from(original));
    }

    fn a_record(domain: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(domain).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )
    }

    fn cname_record(alias: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str(alias).unwrap(),
            ttl,
            RData::CNAME(CNAME(Name::from_str(target).unwrap())),
        )
    }

    fn filter_with_blocked(domains: &[&str]) -> FilterEngine {
        let set: ahash::HashSet<CompactString> =
            domains.iter().map(|d| CompactString::from(*d)).collect();
        FilterEngine::with_domains(set)
    }

    #[test]
    fn cname_to_blocked_domain_detected() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![
            cname_record("alias.example.com.", "tracker.evil.com.", 300),
            a_record("tracker.evil.com.", 300),
        ];
        let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(result.as_deref(), Some("tracker.evil.com"));
    }

    #[test]
    fn cname_to_allowed_domain_passes() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![
            cname_record("alias.example.com.", "cdn.cloudflare.net.", 300),
            a_record("cdn.cloudflare.net.", 300),
        ];
        assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
    }

    #[test]
    fn no_cname_records_returns_none() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![a_record("example.com.", 300)];
        assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
    }

    #[test]
    fn empty_records_returns_none() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        assert!(cname_chain_blocked(&[], 16, |t| filter.is_blocked(t)).is_none());
    }

    // --- check_pre_query qtype gate (query-validator-01, rev-2606) ---

    fn default_security_layer() -> SecurityLayer {
        SecurityLayer::from_config(
            &SecurityConfig::default(),
            &crate::config::settings::AntiBypassConfig::default(),
        )
    }

    fn test_client() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// neutrality-01 — a default install builds NO anti-bypass checker.
    ///
    /// `anti_bypass.enabled` still defaults to `true`, but with the
    /// compiled-in provider list gone the resulting set is empty. Keeping
    /// a `Some(_)` there would make every query walk its subdomains
    /// against a set that can never match. `None` is both the honest
    /// state and the free one.
    #[test]
    fn neutrality01_default_config_builds_no_anti_bypass_checker() {
        let layer = default_security_layer();
        assert!(
            layer.anti_bypass.is_none(),
            "an empty domain set must not become a per-query check"
        );
    }

    /// The converse: an operator who lists a domain still gets the check.
    #[test]
    fn neutrality01_operator_supplied_domain_still_builds_the_checker() {
        let layer = SecurityLayer::from_config(
            &SecurityConfig::default(),
            &crate::config::settings::AntiBypassConfig {
                enabled: true,
                extra_domains: vec!["doh.example.net".to_string()],
            },
        );
        let ab = layer
            .anti_bypass
            .as_ref()
            .expect("an operator-listed domain must produce a checker");
        assert!(ab.is_bypass_domain("foo.doh.example.net"));
    }

    /// Live-confirmed regression: every IPv4 PTR was REFUSED under default
    /// config because four consecutive numeric labels matched the
    /// rebinding heuristic (`dig -x` vs the CT returned REFUSED).
    #[test]
    fn ipv4_ptr_passes_pre_query_under_default_config() {
        let sec = default_security_layer();
        assert!(sec
            .check_pre_query(&test_client(), "94.1.10.10.in-addr.arpa", RecordType::PTR)
            .is_ok());
    }

    /// IPv6 PTR pin: random hex nibble labels concat to entropy ≥3.5,
    /// which the tunneling shape check would flag — the PTR gate must
    /// skip it. The same name as an A query trips it (gate is on qtype,
    /// not on the threshold). 14 distinct nibbles (entropy log2(14)≈3.81)
    /// keep the name at 16 labels, inside the shape check's stack-array
    /// cap — a full 32-nibble name would fail open there and pin nothing.
    #[test]
    fn ipv6_ptr_nibbles_skip_tunneling_shape() {
        let sec = default_security_layer();
        let nibbles: Vec<String> = "0123456789abcd".chars().map(|c| c.to_string()).collect();
        let domain = format!("{}.ip6.arpa", nibbles.join("."));
        assert!(sec
            .check_pre_query(&test_client(), &domain, RecordType::PTR)
            .is_ok());
        // As a forward type the same name is still refused — digit nibbles
        // trip rebinding (4 consecutive u8 labels) ahead of the entropy
        // check; either way the heuristics stay armed for non-PTR.
        assert!(
            sec.check_pre_query(&test_client(), &domain, RecordType::A)
                .is_err(),
            "same name as a forward type must still be refused"
        );
        // The real-world full reverse name (32 nibbles + ip6 + arpa = 34
        // labels) must also pass as PTR end-to-end.
        let full: Vec<String> = "0123456789abcdef0123456789abcdef"
            .chars()
            .map(|c| c.to_string())
            .collect();
        let full_domain = format!("{}.ip6.arpa", full.join("."));
        assert!(sec
            .check_pre_query(&test_client(), &full_domain, RecordType::PTR)
            .is_ok());
    }

    /// Forward rebinding detection unchanged: address-bearing qtypes
    /// still refuse IP-embedded names.
    #[test]
    fn rebinding_still_refused_for_address_types() {
        let sec = default_security_layer();
        for rt in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
            assert_eq!(
                sec.check_pre_query(&test_client(), "192.168.1.1.evil.com", rt),
                Err("DNS rebinding pattern detected"),
                "qtype {rt:?}"
            );
        }
    }

    /// Non-address qtypes can't rebind (no address in the answer) — the
    /// heuristic no longer fires for them.
    #[test]
    fn rebinding_not_checked_for_non_address_types() {
        let sec = default_security_layer();
        assert!(sec
            .check_pre_query(&test_client(), "192.168.1.1.evil.com", RecordType::TXT)
            .is_ok());
    }

    /// Tunneling shape stays armed for every non-PTR qtype — TXT is the
    /// classic exfil carrier and must not ride the PTR exemption.
    ///
    /// The payload used to be a 20-char base64-shaped label, caught by
    /// the concatenated-entropy gate. That gate is now floored behind
    /// `entropy_min_len`, so the fixture is a 63-char unbroken run —
    /// the shape iodine and dnscat2 actually emit. **The property under
    /// test is unchanged**: it is the qtype exemption, not the gate that
    /// happens to fire.
    ///
    /// Both arms are asserted deliberately. A one-armed version proves
    /// only that *something* refused TXT; the PTR arm is what shows the
    /// exemption is qtype-scoped rather than name-scoped.
    #[test]
    fn txt_payload_shape_still_trips_tunneling_but_ptr_rides_the_exemption() {
        let sec = default_security_layer();
        let name = format!("{}.tunnel.example.com", "0".repeat(63));

        assert_eq!(
            sec.check_pre_query(&test_client(), &name, RecordType::TXT),
            Err("tunneling detected"),
            "TXT must not inherit the PTR exemption"
        );
        assert!(
            sec.check_pre_query(&test_client(), &name, RecordType::PTR)
                .is_ok(),
            "PTR skips the shape gate — that is the exemption this test brackets"
        );
    }

    /// sec-ptr-skips-both-tunneling-gates: the **shape** exemption for PTR
    /// is correct and stays (an IPv6 reverse name is 32 hex nibbles and
    /// looks exactly like a payload), but nothing requires a PTR query to
    /// sit under a reverse zone, and fan-out does not care about the
    /// qtype. Pre-fix a payload carried as PTR got no shape check *and*
    /// created no rate bucket: unbounded.
    #[test]
    fn ptr_outside_the_reverse_zones_counts_against_the_rate_gate() {
        // Genuine reverse lookups stay exempt — both families, and the
        // zone apex itself. These share one base domain per client
        // (`in-addr.arpa` is not an eTLD the detector splits), so counting
        // them re-creates the one-bucket-per-client footgun.
        for name in [
            "94.1.10.10.in-addr.arpa",
            "50.1.168.192.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
            "in-addr.arpa",
            "ip6.arpa",
        ] {
            assert!(
                !tunneling_rate_gate_applies(RecordType::PTR, name),
                "{name} is a genuine reverse lookup and must create no bucket"
            );
        }

        // A PTR query outside those zones is fan-out like any other.
        for name in [
            "aGVsbG8td29ybGQ.tun.example.com",
            "home.arpa",
            "example.com",
            // Label-boundary anchored: merely *ending with* the zone text
            // does not inherit the exemption, exactly as `is_exempt` in
            // the tunneling module refuses `evil-<exempt>`.
            "evil-in-addr.arpa",
            "notip6.arpa",
        ] {
            assert!(
                tunneling_rate_gate_applies(RecordType::PTR, name),
                "{name} is not a reverse zone — the rate gate must apply"
            );
        }

        // Unchanged for every other qtype, including under a reverse
        // zone: only PTR ever had the exemption, and only PTR keeps it.
        assert!(tunneling_rate_gate_applies(
            RecordType::A,
            "94.1.10.10.in-addr.arpa"
        ));
        assert!(tunneling_rate_gate_applies(
            RecordType::TXT,
            "x.tun.example.com"
        ));
    }

    /// The two gates now deliberately disagree on the same name, and that
    /// split is the whole fix: shape stays exempt for PTR (nibble names
    /// are indistinguishable from payloads), rate does not.
    #[test]
    fn ptr_payload_skips_the_shape_gate_but_not_the_rate_gate() {
        let sec = default_security_layer();
        let name = format!("{}.tunnel.example.com", "0".repeat(63));

        assert!(
            sec.check_pre_query(&test_client(), &name, RecordType::PTR)
                .is_ok(),
            "the shape gate's PTR exemption is unchanged"
        );
        assert!(
            tunneling_rate_gate_applies(RecordType::PTR, &name),
            "the same name is not in a reverse zone, so the rate gate applies"
        );
    }

    /// End to end on the detector: a PTR flood of unique names under an
    /// attacker-controlled domain trips, and genuine reverse lookups
    /// create no bucket at all — so there is nothing for them to be
    /// refused from, no matter how many a scanner sends.
    #[test]
    fn ptr_flood_trips_the_rate_gate_while_reverse_lookups_never_create_a_bucket() {
        let sec = default_security_layer();
        let ip = test_client();
        let td = sec
            .tunneling
            .as_ref()
            .expect("default config builds the tunneling detector");

        // 400 distinct genuine reverse lookups — 8× the default budget.
        for i in 0..400u32 {
            let name = format!("{}.{}.168.192.in-addr.arpa", i % 256, i / 256);
            assert!(!tunneling_rate_gate_applies(RecordType::PTR, &name));
        }
        assert_eq!(
            td.entry_count(),
            0,
            "reverse lookups must never reach the detector, so no bucket exists"
        );

        // The same volume as PTR under an attacker's own domain does
        // reach it, and trips on the name after the budget is spent.
        let mut refused_at = None;
        for i in 0..200u32 {
            let name = format!("p{i}.tun.example.com");
            assert!(tunneling_rate_gate_applies(RecordType::PTR, &name));
            if sec.check_tunneling_rate(&ip, &name) {
                refused_at = Some(i);
                break;
            }
        }
        assert_eq!(
            refused_at,
            Some(50),
            "default subdomain_rate is 50: names 0..=49 fit, the 51st trips"
        );
    }

    #[test]
    fn cname_chain_depth_exceeded_fails_closed() {
        // handler-02 (rev-2606): a chain longer than the cap counts as
        // BLOCKED — mirrors walk_response's CnameDepthExceeded on the
        // request path. Pre-fix the walker returned None here (fail
        // open) and the prefetch paths cached the over-long chain.
        let filter = filter_with_blocked(&["blocked.com"]);
        // Build 20 CNAME records — none of them blocked.
        let records: Vec<Record> = (0..20)
            .map(|i| {
                cname_record(
                    &format!("hop{i}.example.com."),
                    &format!("hop{}.example.com.", i + 1),
                    300,
                )
            })
            .collect();

        // With depth=16, the 17th record trips the cap → treated as blocked
        // even though no target matches the filter.
        assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_some());
        // A chain within the cap and with no blocked target stays clean.
        assert!(cname_chain_blocked(&records[..10], 16, |t| filter.is_blocked(t)).is_none());

        // A blocked target sitting beyond the cap is still reported (the
        // cap-trip return carries the offending hop, not a filter match).
        let mut with_blocked = records;
        with_blocked[16] = cname_record("hop16.example.com.", "blocked.com.", 300);
        assert!(cname_chain_blocked(&with_blocked, 17, |t| filter.is_blocked(t)).is_some());
    }

    #[test]
    fn cname_subdomain_walk_works() {
        // "sub.tracker.evil.com" is not in the blocklist directly,
        // but "tracker.evil.com" is — subdomain walk should catch it.
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![cname_record(
            "alias.example.com.",
            "sub.tracker.evil.com.",
            300,
        )];
        let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(result.as_deref(), Some("sub.tracker.evil.com"));
    }

    #[test]
    fn cname_trailing_dot_stripped() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        // hickory Name always includes trailing dot in Display
        let records = vec![cname_record("alias.example.com.", "tracker.evil.com.", 300)];
        let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        // Trailing dot should be stripped so it matches "tracker.evil.com"
        assert_eq!(result.as_deref(), Some("tracker.evil.com"));
    }

    #[test]
    fn cname_mixed_case_target_is_lowercased_before_lookup() {
        // Regression: CNAME targets must be case-normalized before filter
        // lookup, otherwise a mixed-case target from upstream bypasses the
        // blocklist (which is always lowercase per ingestion rule).
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![cname_record("alias.example.com.", "Tracker.Evil.COM.", 300)];
        let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(result.as_deref(), Some("tracker.evil.com"));
    }

    #[test]
    fn multiple_cnames_first_allowed_second_blocked() {
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let records = vec![
            cname_record("alias1.example.com.", "cdn.cloudflare.net.", 300),
            cname_record("alias2.example.com.", "tracker.evil.com.", 300),
            a_record("tracker.evil.com.", 300),
        ];
        let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(result.as_deref(), Some("tracker.evil.com"));
    }

    // --- source_allowed (P0-5) ---

    fn cidr(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn source_allowed_none_acl_accepts_all() {
        assert!(source_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), None));
        assert!(source_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), None));
    }

    #[test]
    fn source_allowed_empty_acl_accepts_all() {
        let empty: Vec<Cidr> = vec![];
        assert!(source_allowed(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            Some(&empty)
        ));
    }

    #[test]
    fn source_allowed_inside_cidr() {
        let acl = vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")];
        assert!(source_allowed(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            Some(&acl)
        ));
        assert!(source_allowed(
            IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)),
            Some(&acl)
        ));
    }

    #[test]
    fn source_allowed_outside_cidr_refused() {
        let acl = vec![cidr("10.0.0.0/8")];
        assert!(!source_allowed(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            Some(&acl)
        ));
        assert!(!source_allowed(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Some(&acl)
        ));
    }

    #[test]
    fn source_allowed_v6_inside_cidr() {
        let acl = vec![cidr("fd00::/8")];
        assert!(source_allowed(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            Some(&acl)
        ));
    }

    /// On `listen = "[::]:53"` every IPv4 peer arrives as `::ffff:a.b.c.d`.
    /// `Cidr::contains` is family-strict, so an IPv4 `allow_from` used to
    /// refuse the whole LAN the moment the operator went dual-stack. Fails
    /// closed, which is why it presents as "DNS stopped" rather than as a
    /// breach. `cargo test` never opens a dual-stack socket, so this pins
    /// the ACL decision rather than the socket behaviour.
    #[test]
    fn source_allowed_ipv4_mapped_source_matches_v4_acl() {
        let acl = vec![cidr("192.0.2.0/24")];
        assert!(source_allowed(
            "::ffff:192.0.2.5".parse().unwrap(),
            Some(&acl)
        ));
        assert!(
            !source_allowed("::ffff:10.10.2.5".parse().unwrap(), Some(&acl)),
            "a mapped address outside the ACL stays refused"
        );
    }

    #[test]
    fn source_allowed_family_mismatch_refused() {
        // v4-only ACL should refuse a v6 source.
        let acl = vec![cidr("10.0.0.0/8")];
        assert!(!source_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(&acl)));
    }

    // ── send_block_response dispatch (Sprint 23 s23-block-response-handler) ──

    /// Capturing mock for the hickory `ResponseHandler` trait. Stores
    /// the `ResponseCode` of the most recent `send_response` call so
    /// the dispatcher tests can assert which DNS rcode landed on the
    /// wire without spinning up a real socket. Drops every record set
    /// — only the header response code matters here.
    #[derive(Clone)]
    struct CapturingHandler {
        captured_rcode: Arc<Mutex<Option<ResponseCode>>>,
        captured_answer_count: Arc<Mutex<u16>>,
        captured_aa: Arc<Mutex<Option<bool>>>,
        captured_name_server_count: Arc<Mutex<u16>>,
        /// The parsed answer section. The rcode + count fields above are
        /// enough for the dispatcher tests, but the device-network-name
        /// tests must assert the *contents* of the answer — its RDATA, its
        /// TTL, and its owner name. Kept on this handler rather than in a
        /// second recorder so every existing assertion keeps working.
        captured_answers: Arc<Mutex<Vec<Record>>>,
        /// §4.10-4b — the AD (authentic-data) bit, captured so the DNSSEC wire
        /// tests can assert it lands on (and only on) the answers we validated.
        #[cfg(feature = "dnssec")]
        captured_ad: Arc<Mutex<Option<bool>>>,
    }

    impl CapturingHandler {
        fn new() -> Self {
            Self {
                captured_rcode: Arc::new(Mutex::new(None)),
                captured_answer_count: Arc::new(Mutex::new(0)),
                captured_aa: Arc::new(Mutex::new(None)),
                captured_name_server_count: Arc::new(Mutex::new(0)),
                captured_answers: Arc::new(Mutex::new(Vec::new())),
                #[cfg(feature = "dnssec")]
                captured_ad: Arc::new(Mutex::new(None)),
            }
        }
        fn rcode(&self) -> Option<ResponseCode> {
            *self.captured_rcode.lock().unwrap()
        }
        fn answer_count(&self) -> u16 {
            *self.captured_answer_count.lock().unwrap()
        }
        fn aa(&self) -> Option<bool> {
            *self.captured_aa.lock().unwrap()
        }
        fn name_server_count(&self) -> u16 {
            *self.captured_name_server_count.lock().unwrap()
        }
        fn answers(&self) -> Vec<Record> {
            self.captured_answers.lock().unwrap().clone()
        }
        #[cfg(feature = "dnssec")]
        fn ad(&self) -> Option<bool> {
            *self.captured_ad.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl ResponseHandler for CapturingHandler {
        async fn send_response<'a>(
            &mut self,
            response: hickory_server::zone_handler::MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
            >,
        ) -> Result<ResponseInfo, hickory_net::NetError> {
            use hickory_proto::op::Message;
            use hickory_proto::serialize::binary::BinEncoder;
            // 0.26: MessageResponse no longer exposes a pre-emit Header/counts.
            // Emit to wire and parse back — reads flags + section counts off the
            // real bytes, which is a stronger check than the old pre-emit header.
            let mut buf = Vec::with_capacity(512);
            let info = {
                let mut encoder = BinEncoder::new(&mut buf);
                response
                    .destructive_emit(&mut encoder)
                    .expect("emit response")
            };
            let parsed = Message::from_vec(&buf).expect("parse emitted response");
            *self.captured_rcode.lock().unwrap() = Some(parsed.metadata.response_code);
            *self.captured_answer_count.lock().unwrap() = parsed.answers.len() as u16;
            *self.captured_answers.lock().unwrap() = parsed.answers.clone();
            *self.captured_aa.lock().unwrap() = Some(parsed.metadata.authoritative);
            *self.captured_name_server_count.lock().unwrap() = parsed.authorities.len() as u16;
            #[cfg(feature = "dnssec")]
            {
                *self.captured_ad.lock().unwrap() = Some(parsed.metadata.authentic_data);
            }
            Ok(info)
        }
    }

    use std::sync::Mutex;

    /// Build a minimal `Request` for the dispatcher tests. The handler
    /// helpers only read the request to clone the message header into
    /// the response, so a default-constructed message is sufficient.
    fn test_request() -> Request {
        use hickory_net::xfer::Protocol;
        use hickory_proto::op::Message;
        use std::net::SocketAddr;
        // 0.26: Request::from_message + MessageRequest ctors are `testing`-gated;
        // Request::from_bytes(Vec<u8>, ..) is the public ungated path.
        let bytes = Message::query().to_vec().unwrap();
        let src: SocketAddr = "127.0.0.1:53".parse().unwrap();
        Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
    }

    /// Build a `Request` with the AA bit set in its header. Used by the
    /// L-6 regression test to confirm we strip AA on the response side
    /// regardless of what the request had.
    fn test_request_with_aa_set() -> Request {
        use hickory_net::xfer::Protocol;
        use hickory_proto::op::Message;
        use std::net::SocketAddr;
        let mut msg = Message::query();
        msg.metadata.authoritative = true;
        let bytes = msg.to_vec().unwrap();
        let src: SocketAddr = "127.0.0.1:53".parse().unwrap();
        Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
    }

    // ── §4.10-4b — DNSSEC AD-bit wiring on the cached response path ──────────
    // The verdict→decision mapping is tested in `dns::dnssec_validator`; these
    // pin the wire effect: `send_cached`'s `authentic` flag flips (and only
    // flips) the AD bit. The default build clears the AD write entirely, so
    // these only exist under `--features dnssec`.

    #[cfg(feature = "dnssec")]
    fn one_a_entry() -> crate::dns::cache::CacheEntry {
        let rec = Record::from_rdata(
            Name::from_str("a.example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        );
        crate::dns::cache::CacheEntry::for_test(vec![rec], ResponseCode::NoError)
    }

    #[cfg(feature = "dnssec")]
    #[tokio::test]
    async fn send_cached_sets_ad_when_authentic() {
        let req = test_request();
        let entry = one_a_entry();
        let mut h = CapturingHandler::new();
        send_cached(&req, &entry, true, false, &mut h).await;
        assert_eq!(h.ad(), Some(true), "authentic=true must set the AD bit");
        assert_eq!(h.rcode(), Some(ResponseCode::NoError));
        assert_eq!(h.answer_count(), 1);
    }

    #[cfg(feature = "dnssec")]
    #[tokio::test]
    async fn send_cached_clears_ad_when_not_authentic() {
        let req = test_request();
        let entry = one_a_entry();
        let mut h = CapturingHandler::new();
        send_cached(&req, &entry, false, false, &mut h).await;
        assert_eq!(h.ad(), Some(false), "authentic=false must leave AD clear");
        assert_eq!(h.rcode(), Some(ResponseCode::NoError));
    }

    /// The rewrite suppression, at the one site that writes AD. A validator that
    /// returned `SetAd` for the *original* name must still not raise AD on an
    /// answer we fronted with an unsigned synthesized CNAME.
    #[cfg(feature = "dnssec")]
    #[tokio::test]
    async fn send_cached_rewritten_never_sets_ad() {
        let req = test_request();
        let entry = one_a_entry();
        let mut h = CapturingHandler::new();
        send_cached(&req, &entry, true, true, &mut h).await;
        assert_eq!(
            h.ad(),
            Some(false),
            "a rewritten answer is fronted by an unsigned synthesized CNAME — \
             it must never carry AD, even when the validator said Secure"
        );
    }

    #[tokio::test]
    async fn send_block_response_zero_returns_noerror_and_canned_record() {
        // Zero variant goes through send_blocked → NoError + canned
        // 0.0.0.0 record. This pins the retrocompat path so a future
        // refactor can't accidentally route Zero through NXDOMAIN.
        let req = test_request();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::A,
            60,
            crate::config::schema::BlockResponseV1::Zero,
            &mut handler,
        )
        .await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
    }

    #[tokio::test]
    async fn send_block_response_zero_aaaa_returns_noerror_and_canned_record() {
        // AAAA branch of send_blocked — mirror of the A test. Pins the
        // explicit set_response_code(NoError) call so a refactor that
        // drops it leaves the test failing instead of silently
        // depending on hickory's default. Closes Sprint 9 audit bug #1
        // for the IPv6 path.
        let req = test_request();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::AAAA,
            60,
            crate::config::schema::BlockResponseV1::Zero,
            &mut handler,
        )
        .await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
    }

    #[tokio::test]
    async fn send_block_response_zero_other_type_returns_nodata() {
        // Non-A/AAAA record types (TXT, MX, SRV, …) hit the NODATA
        // branch: NOERROR + zero answers + SOA in authority per RFC
        // 2308 §2.1. Critically NOT NXDOMAIN — that would tell caches
        // the domain doesn't exist at all and suppress future A/AAAA
        // queries for the same name, defeating the 0.0.0.0 sinkhole.
        // Pins the third branch of send_blocked against that regression.
        let req = test_request();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::TXT,
            60,
            crate::config::schema::BlockResponseV1::Zero,
            &mut handler,
        )
        .await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
    }

    #[tokio::test]
    async fn send_block_response_nxdomain_returns_nxdomain_rcode() {
        let req = test_request();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::A,
            60,
            crate::config::schema::BlockResponseV1::Nxdomain,
            &mut handler,
        )
        .await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
    }

    #[tokio::test]
    async fn send_block_response_refused_returns_refused_rcode() {
        let req = test_request();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::A,
            60,
            crate::config::schema::BlockResponseV1::Refused,
            &mut handler,
        )
        .await;
        assert_eq!(handler.rcode(), Some(ResponseCode::Refused));
    }

    #[tokio::test]
    async fn send_rfc8482_returns_noerror_with_single_hinfo_answer() {
        // RFC 8482 §6: ANY queries get a synthesised HINFO reply with
        // NOERROR + exactly one answer record. This pins the amplification
        // guard against a refactor that drops the answer_count=1 or flips
        // to NXDOMAIN (which would suppress subsequent A/AAAA queries at
        // client caches, same pitfall as the send_blocked NODATA path).
        let req = test_request();
        let qname = Name::from_str("example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_rfc8482(&req, &qname, 60, &mut handler).await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
        assert_eq!(handler.answer_count(), 1);
    }

    #[tokio::test]
    async fn send_nxdomain_helper_sets_nxdomain_directly() {
        // Regression guard: a future refactor that "simplifies"
        // send_nxdomain by removing the explicit set_response_code
        // call would silently leave the rcode as NoError. Pin the
        // contract.
        let req = test_request();
        let mut handler = CapturingHandler::new();
        send_nxdomain(&req, &mut handler).await;
        assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
    }

    #[tokio::test]
    async fn send_refused_emits_refused_rcode() {
        // L-3 (rev-2026-04-unreachable-profile) supporting pin: the fail-
        // closed fallback for the missing-profile-resolver branch in
        // handle_request_inner uses send_refused. Pin that send_refused
        // emits ResponseCode::Refused — if a future refactor turned this
        // into NoError or NXDomain, the L-3 fallback would silently allow
        // queries through during a broken construction invariant. The
        // integration-level pin (handle_request_inner with profiles=None
        // returns Refused) is out of scope here — it requires constructing
        // a 14-parameter mock handler stack — but this contract pin
        // catches the failure mode the L-3 fix depends on.
        let req = test_request();
        let mut handler = CapturingHandler::new();
        send_refused(&req, &mut handler).await;
        assert_eq!(handler.rcode(), Some(ResponseCode::Refused));
    }

    #[tokio::test]
    async fn aa_bit_cleared_on_blocked_response_even_when_request_had_it_set() {
        // L-6 (rev-2026-04-aa-bit-clear) regression pin: hickory's
        // Header::response_from_request preserves the request's AA flag.
        // We're a recursive resolver — the AA bit on our responses must
        // always be 0. send_blocked is one of the canonical answer-path
        // sites; pin that even with AA=1 in the request, the response
        // emerges with AA=0.
        let req = test_request_with_aa_set();
        let qname = Name::from_str("ads.example.com").unwrap();
        let mut handler = CapturingHandler::new();
        send_block_response(
            &req,
            &qname,
            RecordType::A,
            60,
            crate::config::schema::BlockResponseV1::Zero,
            &mut handler,
        )
        .await;
        assert_eq!(handler.aa(), Some(false), "AA must be cleared on response");
    }

    #[tokio::test]
    async fn aa_bit_cleared_on_nxdomain_response_even_when_request_had_it_set() {
        // L-6 regression pin sibling — covers the send_nxdomain path,
        // a separate Header::response_from_request site.
        let req = test_request_with_aa_set();
        let mut handler = CapturingHandler::new();
        send_nxdomain(&req, &mut handler).await;
        assert_eq!(handler.aa(), Some(false), "AA must be cleared on NXDOMAIN");
    }

    fn cache_test_config() -> crate::config::settings::CacheConfig {
        crate::config::settings::CacheConfig {
            max_entries: 100,
            max_ttl_secs: 3600,
            min_ttl_secs: 5,
            negative_ttl_secs: 60,
            stale_buffer_secs: 300,
            prefetch: false,
            prefetch_threshold: 0.1,
            prefetch_max_concurrent: 16,
            cname_max_depth: 16,
            prefetch_tracker_enabled: false,
            prefetch_tracker_window_secs: 300,
            prefetch_tracker_min_hits: 3,
            prefetch_tracker_max_pool_size: 1024,
            prefetch_tracker_tick_secs: 30,
            prefetch_tracker_lead_secs: 10,
        }
    }

    #[tokio::test]
    async fn cached_nxdomain_response_includes_soa_in_authority() {
        // L-5 (rev-2026-04-cached-neg-soa) regression pin: cached NXDOMAIN
        // responses must include a SOA in the authority section per
        // RFC 2308 §3, mirroring the fresh-blocked NODATA path. Pre-fix
        // send_cached used build_no_records for the negative branch, which
        // sent the NXDOMAIN with an empty authority section — downstream
        // resolvers fell back to default negative-cache TTL instead of
        // honoring the operator's `negative_ttl` floor.
        use hickory_proto::rr::DNSClass;
        let cache = DnsCache::new(&cache_test_config());
        cache
            .insert(
                "nxdomain.example.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("nxdomain.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .expect("freshly inserted entry must be Fresh");

        let req = test_request();
        let mut handler = CapturingHandler::new();
        send_cached(&req, &entry, false, false, &mut handler).await;

        assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
        assert_eq!(
            handler.name_server_count(),
            1,
            "cached NXDOMAIN must carry SOA in authority section (RFC 2308 §3)"
        );
        assert_eq!(handler.answer_count(), 0);
    }

    #[test]
    fn blocked_soa_static_names_match_from_ascii_parse() {
        // H-01 regression pin: the OnceLock'd cached `Name`s for the
        // blocked-NODATA SOA must be byte-for-byte equal to the
        // `Name::from_ascii(...)` output that the pre-fix code re-parsed
        // on every blocked response. Compare wire labels, not just
        // Display, so a future refactor that switches the literal can't
        // pass this test by coincidence.
        let zone_expected = Name::from_ascii("block.purge-warden.local.").unwrap();
        let mname_expected = Name::from_ascii("ns.purge-warden.local.").unwrap();
        let rname_expected = Name::from_ascii("admin.purge-warden.local.").unwrap();
        assert_eq!(blocked_soa_zone(), &zone_expected);
        assert_eq!(blocked_soa_mname(), &mname_expected);
        assert_eq!(blocked_soa_rname(), &rname_expected);

        // And the SOA record built from the cached names must carry
        // those names verbatim — covers `.clone()` returning a value
        // that compares equal, which is the contract the SOA depends on.
        let record = blocked_soa(60);
        assert_eq!(&record.name, &zone_expected);
        let RData::SOA(ref soa) = record.data else {
            panic!("blocked_soa must produce an SOA record");
        };
        assert_eq!(&soa.mname, &mname_expected);
        assert_eq!(&soa.rname, &rname_expected);
        assert_eq!(soa.minimum, 60);
    }

    #[test]
    fn prefetch_helper_blocked_cname_short_chain() {
        let filter = filter_with_blocked(&["bad.example.com"]);
        let records = vec![cname_record("alias.example.com.", "bad.example.com.", 300)];
        let blocked = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(blocked.as_deref(), Some("bad.example.com"));
    }

    #[test]
    fn prefetch_helper_unblocked_cname_short_chain() {
        let filter = filter_with_blocked(&["bad.example.com"]);
        let records = vec![cname_record("alias.example.com.", "good.example.net.", 300)];
        assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
    }

    #[test]
    fn prefetch_helper_depth_capped_at_configured_limit() {
        // L-8 (rev-2026-04-cname-prefetch-cap) regression pin: the
        // pre-fix prefetch CNAME inspection used `iter().any(...)` and
        // walked the entire chain unbounded. The cap still stops the
        // scan at cname_max_depth — but per handler-02 (rev-2606) the
        // cap trip now FAILS CLOSED (returns the hop at the cap as
        // blocked) instead of returning None, mirroring walk_response's
        // CnameDepthExceeded. The filter probe count check below pins
        // that scanning genuinely stops at the cap.
        let filter = filter_with_blocked(&["blocked.example.com"]);
        let mut records: Vec<Record> = (0..20)
            .map(|i| {
                cname_record(
                    &format!("hop{i}.example.com."),
                    &format!("hop{}.example.com.", i + 1),
                    300,
                )
            })
            .collect();
        records[16] = cname_record("hop16.example.com.", "blocked.example.com.", 300);
        // depth=16 → the 17th record trips the cap: fail-closed (blocked),
        // and the predicate ran at most 16 times (the cap bounds the scan).
        let mut probes = 0usize;
        let result = cname_chain_blocked(&records, 16, |t| {
            probes += 1;
            filter.is_blocked(t)
        });
        assert!(result.is_some());
        assert!(probes <= 16, "scan must stop at the cap, ran {probes}");
        // depth=17 → reaches the blocked record via a genuine filter match.
        assert_eq!(
            cname_chain_blocked(&records, 17, |t| filter.is_blocked(t)).as_deref(),
            Some("blocked.example.com")
        );
    }

    /// M-31 regression pin: the request-path walker hoists
    /// `resolver.resolve(client_ip)` once before the chain walk. This test
    /// confirms behaviour-equivalence with the pre-refactor per-iteration
    /// resolution by exercising a profile-aware block in a 3-hop chain.
    #[test]
    fn check_cname_chain_blocks_via_resolved_profile() {
        let filter = filter_with_blocked(&["evil.example.com"]);
        let records = vec![
            cname_record("alias.example.com.", "hop1.example.com.", 300),
            cname_record("hop1.example.com.", "evil.example.com.", 300),
        ];
        // §4.5 Sprint 2/2: post wire-in the request-path uses
        // `walk_response` directly. The flat-filter fallback this test
        // pinned now lives in `cname_chain_blocked` (still pub(crate) for
        // the prefetch path).
        let blocked = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
        assert_eq!(blocked.as_deref(), Some("evil.example.com"));
    }

    #[tokio::test]
    async fn cached_nodata_response_includes_soa_in_authority() {
        // L-5 sibling: NODATA (NoError + empty records) is the second
        // negative-cache shape. Pin that it also receives the SOA fix —
        // is_negative() routes both NXDomain and NoError-with-empty
        // through the new SOA-bearing branch.
        use hickory_proto::rr::DNSClass;
        let cache = DnsCache::new(&cache_test_config());
        cache
            .insert(
                "nodata.example.com",
                RecordType::AAAA,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("nodata.example.com", RecordType::AAAA, DNSClass::IN, None)
            .await
            .fresh()
            .expect("freshly inserted entry must be Fresh");

        let req = test_request();
        let mut handler = CapturingHandler::new();
        send_cached(&req, &entry, false, false, &mut handler).await;

        assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
        assert_eq!(
            handler.name_server_count(),
            1,
            "cached NODATA must carry SOA in authority section (RFC 2308 §3)"
        );
        assert_eq!(handler.answer_count(), 0);
    }

    // ── Sprint 43 T4: per-device overlay path ─────────────────

    use ahash::RandomState;
    use std::collections::HashSet;

    fn empty_profile() -> Arc<ResolvedProfile> {
        Arc::new(ResolvedProfile::permissive_default())
    }

    fn overlay_with(allow: &[&str], deny: &[&str], override_flag: bool) -> Arc<DeviceOverlay> {
        let allow_set: HashSet<CompactString, RandomState> =
            allow.iter().map(|d| CompactString::from(*d)).collect();
        let deny_set: HashSet<CompactString, RandomState> =
            deny.iter().map(|d| CompactString::from(*d)).collect();
        Arc::new(DeviceOverlay {
            device_id: crate::config::schema::Id::new("dev-test").unwrap(),
            allow: Arc::new(allow_set),
            deny: Arc::new(deny_set),
            override_profile_deny: override_flag,
        })
    }

    /// Snapshot acceptance §8: device with empty overlay produces
    /// byte-identical resolution to the pre-T4 baseline. We verify
    /// this by calling `evaluate_with_overlay` with `overlay = None`
    /// and asserting it agrees with `filter.evaluate(...) == Block`
    /// across both block and forward outcomes.
    #[test]
    fn evaluate_with_overlay_none_overlay_is_byte_identical_baseline() {
        let filter = filter_with_blocked(&[]);
        // Use profile.deny_domains so the block path doesn't depend on
        // list-policy wiring: permissive_default subscribes to nothing, so
        // the generation's masks for it are inert. (Pre-`plp-s3` this was
        // spelled `list_bitmask = 0`, on a field that no longer exists.)
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("evil.com"));
        let profile = Arc::new(profile);

        let (blocked, _) = evaluate_with_overlay("evil.com", &profile, None, &filter);
        let baseline = filter.evaluate("evil.com", &profile) == FilterResult::Block;
        assert_eq!(blocked, baseline, "None overlay must match pre-T4 baseline");
        assert!(blocked, "evil.com is in profile.deny_domains");

        // Allowed domain — both must report Forward.
        let (blocked, _) = evaluate_with_overlay("good.com", &profile, None, &filter);
        let baseline = filter.evaluate("good.com", &profile) == FilterResult::Block;
        assert_eq!(blocked, baseline);
        assert!(!blocked);
    }

    /// Truth table row 4: device.deny alone blocks the query, no
    /// profile rule matches.
    #[test]
    fn evaluate_with_overlay_device_deny_blocks() {
        let filter = filter_with_blocked(&[]); // empty list
        let profile = empty_profile();
        let overlay = overlay_with(&[], &["tiktok.com"], false);

        let (blocked, _) = evaluate_with_overlay("tiktok.com", &profile, Some(&overlay), &filter);
        assert!(blocked, "device.deny → BLOCK");
    }

    /// Sprint B Dashboard v2 — the overlay-Block path returns
    /// `Some(BlockSource::AdminBlock)`. Per-device deny is admin-grade,
    /// so the IPC `top_blocked_lists` aggregator must NOT pin a
    /// Tier 1 list bit for this branch.
    #[test]
    fn evaluate_with_overlay_returns_admin_block_source() {
        let filter = filter_with_blocked(&[]);
        let profile = empty_profile();
        let overlay = overlay_with(&[], &["evil.com"], false);

        let (blocked, source) =
            evaluate_with_overlay("evil.com", &profile, Some(&overlay), &filter);
        assert!(blocked, "device.deny → BLOCK");
        assert_eq!(
            source,
            Some(BlockSource::AdminBlock),
            "overlay-deny is admin-grade, not a list bit"
        );
    }

    /// Truth table row 3: device.allow alone allows the query even
    /// when the filter would default-forward (so this test is more
    /// about exercising the FallThrough path with a hit).
    #[test]
    fn evaluate_with_overlay_device_allow_lets_through() {
        let filter = filter_with_blocked(&[]); // empty
        let profile = empty_profile();
        let overlay = overlay_with(&["bank.example"], &[], false);

        let (blocked, _) = evaluate_with_overlay("bank.example", &profile, Some(&overlay), &filter);
        assert!(!blocked, "device.allow → FORWARD");
    }

    /// Truth table row 5: profile.allow + device.deny → DENY
    /// (Device, additive deny). The HashSet on profile.allow_domains
    /// is populated; the device deny still wins.
    #[test]
    fn evaluate_with_overlay_device_deny_wins_over_profile_allow() {
        let filter = filter_with_blocked(&[]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.allow_domains)
            .insert(CompactString::from("bank.example"));
        let profile = Arc::new(profile);
        let overlay = overlay_with(&[], &["bank.example"], false);

        let (blocked, _) = evaluate_with_overlay("bank.example", &profile, Some(&overlay), &filter);
        assert!(blocked, "additive deny: device.deny over profile.allow");
    }

    /// Truth table row 7: profile.deny + device.allow + override=true
    /// → ALLOW [OVERRIDE]. The most ergonomically important case for
    /// the operator.
    #[test]
    fn evaluate_with_overlay_override_unblocks_profile_deny() {
        let filter = filter_with_blocked(&[]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::from("youtube.com"));
        let profile = Arc::new(profile);
        let overlay = overlay_with(&["youtube.com"], &[], true); // override = true

        let (blocked, _) = evaluate_with_overlay("youtube.com", &profile, Some(&overlay), &filter);
        assert!(!blocked, "override flag must allow past profile.deny");
    }

    /// Truth table row 6 (drift defensive): profile.deny +
    /// device.allow + override=false → DENY (Profile). The CLI
    /// refuses this combination at edit time, but if drift slips
    /// through the daemon must default to profile-wins.
    #[test]
    fn evaluate_with_overlay_drift_falls_back_to_profile_deny() {
        let filter = filter_with_blocked(&[]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::from("youtube.com"));
        let profile = Arc::new(profile);
        let overlay = overlay_with(&["youtube.com"], &[], false); // no override

        let (blocked, _) = evaluate_with_overlay("youtube.com", &profile, Some(&overlay), &filter);
        assert!(blocked, "without override flag, profile.deny wins on drift");
    }

    /// Truth table row 8: both deny → BLOCK (Profile attribution).
    /// The block result is the same as row 4; only the attribution
    /// differs (covered by `apply_overlay` unit tests in resolver.rs).
    #[test]
    fn evaluate_with_overlay_both_deny_blocks() {
        let filter = filter_with_blocked(&[]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("evil.com"));
        let profile = Arc::new(profile);
        let overlay = overlay_with(&[], &["evil.com"], false);

        let (blocked, _) = evaluate_with_overlay("evil.com", &profile, Some(&overlay), &filter);
        assert!(blocked);
    }

    /// FallThrough rows (0/1/2): no device-side hit — the profile
    /// evaluator decides. We pin via `profile.deny_domains` so the
    /// block path doesn't depend on list-policy wiring: the permissive
    /// default subscribes to nothing, so its masks are inert. (Pre-`plp-s3`:
    /// `list_bitmask = 0`, a field that no longer exists.)
    #[test]
    fn evaluate_with_overlay_fall_through_uses_profile_evaluator() {
        let filter = filter_with_blocked(&[]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::from("blocked.example"));
        let profile = Arc::new(profile);
        // Overlay exists but neither set matches the queried domain.
        let overlay = overlay_with(&["bank.example"], &["tiktok.com"], false);

        // Non-matching domain falls through to filter.evaluate which
        // hits profile.deny_domains.
        let (blocked, _) =
            evaluate_with_overlay("blocked.example", &profile, Some(&overlay), &filter);
        assert!(blocked, "profile.deny takes effect on FallThrough");
        let (blocked, _) =
            evaluate_with_overlay("nothing.example", &profile, Some(&overlay), &filter);
        assert!(!blocked, "domain not in any layer → forward");
    }

    /// N7 invariant on the full DNS-handler path: the overlay sets
    /// are domain-only, and `apply_overlay` ignores qtype, so
    /// `evaluate_with_overlay` produces an identical answer
    /// regardless of whether the caller would later return A or AAAA.
    /// We model the qtype-symmetric property as "two independent
    /// invocations produce the same answer".
    // s44-arch-cache-invalidate-on-block (M-12 follow-up):
    // post-cache-hit re-check tests. The splice in `handle_inner`
    // re-runs `check_cname_chain` + `IpFilter::check_response` against
    // the cached `entry.records()` before serving. On trip, the cache
    // tuple is invalidated and a canned block is sent. These tests
    // exercise the wiring at the data-flow level (insert → lookup →
    // re-check predicate → invalidate_key → re-lookup) without the
    // full request/response_handle plumbing — sufficient because the
    // splice composes three already-tested primitives.
    fn cache_filter_test_config() -> crate::config::settings::CacheConfig {
        crate::config::settings::CacheConfig {
            max_entries: 100,
            max_ttl_secs: 3600,
            min_ttl_secs: 5,
            negative_ttl_secs: 60,
            stale_buffer_secs: 300,
            prefetch: false,
            prefetch_threshold: 0.1,
            prefetch_max_concurrent: 16,
            cname_max_depth: 16,
            prefetch_tracker_enabled: false,
            prefetch_tracker_window_secs: 300,
            prefetch_tracker_min_hits: 3,
            prefetch_tracker_max_pool_size: 1024,
            prefetch_tracker_tick_secs: 30,
            prefetch_tracker_lead_secs: 10,
        }
    }

    #[tokio::test]
    async fn cache_hit_cname_chain_blocked_invalidates_entry() {
        // M-12 race scenario: cache stores `D CNAME → C` from an earlier
        // upstream fetch. Operator later adds `C` to a deny rule. Next
        // query for D: filter-evaluate(D) is allow, cache hit, but the
        // CNAME re-check now catches `C` and the entry must be evicted.
        use hickory_proto::rr::DNSClass;
        let cache = DnsCache::new(&cache_filter_test_config());
        let records = vec![
            cname_record("alias.example.com.", "tracker.evil.com.", 300),
            a_record("tracker.evil.com.", 300),
        ];
        cache
            .insert(
                "alias.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .expect("populated entry must be fresh");
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let trip = cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t));
        assert_eq!(
            trip.as_deref(),
            Some("tracker.evil.com"),
            "cache-hit re-check must catch the newly-blocked CNAME target"
        );
        cache
            .invalidate_key("alias.example.com", RecordType::A, DNSClass::IN, None)
            .await;
        assert!(
            matches!(
                cache
                    .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
                    .await,
                CacheLookup::Miss
            ),
            "M-12: post-trip invalidation must remove the cached entry"
        );
    }

    #[tokio::test]
    async fn cache_hit_cname_chain_clean_passes_through() {
        // Negative case: the cached CNAME target is NOT in the filter's
        // blocklist, so the re-check returns None and the cache hit
        // would proceed to `send_cached` unchanged. Pins the no-op cost
        // of the splice on the happy path.
        use hickory_proto::rr::DNSClass;
        let cache = DnsCache::new(&cache_filter_test_config());
        let records = vec![
            cname_record("api.example.com.", "cdn.cloudflare.net.", 300),
            a_record("cdn.cloudflare.net.", 300),
        ];
        cache
            .insert(
                "api.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("api.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        assert!(cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t)).is_none());
        // Entry still present after the no-op re-check.
        assert!(cache
            .lookup("api.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
    }

    #[tokio::test]
    async fn cache_hit_ip_blocklist_match_invalidates_entry() {
        // M-12 race scenario, IP-blocklist variant: cache stores
        // `D A 1.2.3.4`. Operator later adds 1.2.3.4 to the IP
        // blocklist. Next query for D: filter-evaluate(D) is allow,
        // cache hit, but the IP re-check now catches 1.2.3.4 and the
        // entry must be evicted.
        use hickory_proto::rr::DNSClass;
        use std::collections::HashSet;
        let cache = DnsCache::new(&cache_filter_test_config());
        cache
            .insert(
                "fastflux.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![a_record("fastflux.example.com.", 300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        let mut blocked_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
        blocked_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let ipf = IpFilter::with_ips(blocked_ips);
        let hit = ipf.check_response(entry.records(), NamePolicy::Neutral);
        assert_eq!(
            hit,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            "cache-hit IP re-check must catch the newly-blocked address"
        );
        cache
            .invalidate_key("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(
            cache
                .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn cache_hit_ip_blocklist_clean_passes_through() {
        // Negative case for IP path: cached A record is not in the
        // blocklist, re-check returns None, entry stays.
        use hickory_proto::rr::DNSClass;
        use std::collections::HashSet;
        let cache = DnsCache::new(&cache_filter_test_config());
        cache
            .insert(
                "clean.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![a_record("clean.example.com.", 300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("clean.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        let mut other_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
        other_ips.insert(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        let ipf = IpFilter::with_ips(other_ips);
        assert!(ipf
            .check_response(entry.records(), NamePolicy::Neutral)
            .is_none());
        assert!(cache
            .lookup("clean.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
    }

    #[tokio::test]
    async fn cache_hit_invalidate_key_targets_only_matched_qtype() {
        // The post-cache-hit splice invalidates the precise tuple it
        // looked up, NOT the whole domain. If the operator's deny rule
        // affects only the A-record CNAME chain, the cached AAAA tuple
        // (which has different records and a different CNAME chain or
        // none at all) stays put. This pins the precision of
        // `invalidate_key` against the broader `invalidate_domain`.
        use hickory_proto::rr::DNSClass;
        let cache = DnsCache::new(&cache_filter_test_config());
        cache
            .insert(
                "site.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![cname_record("site.example.com.", "tracker.evil.com.", 300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "site.example.com",
                RecordType::AAAA,
                DNSClass::IN,
                vec![a_record("site.example.com.", 300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        // Simulate the splice firing on the A-record cache hit only.
        cache
            .invalidate_key("site.example.com", RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(
            cache
                .lookup("site.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
        assert!(
            cache
                .lookup("site.example.com", RecordType::AAAA, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "AAAA tuple must survive A-only invalidation"
        );
    }

    #[test]
    fn evaluate_with_overlay_is_qtype_agnostic_n7() {
        let filter = filter_with_blocked(&["a.example", "b.example"]);
        let mut profile = ResolvedProfile::permissive_default();
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::from("c.example"));
        let profile = Arc::new(profile);
        let overlay = overlay_with(&["x.example"], &["d.example"], false);

        for domain in [
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "x.example",
            "z.example",
        ] {
            let (r1, _) = evaluate_with_overlay(domain, &profile, Some(&overlay), &filter);
            let (r2, _) = evaluate_with_overlay(domain, &profile, Some(&overlay), &filter);
            assert_eq!(r1, r2, "N7: qtype-agnostic for {domain}");
        }
    }

    // §4.29 — ECS Cache Invalidation Hardening regression tests.
    //
    // Pre-§4.29, the four post-block invalidate sites in `handle_inner`
    // (cache-hit CNAME, cache-hit IP, post-fetch CNAME, post-fetch IP)
    // all passed literal `None` to `invalidate_key`, which targeted the
    // non-ECS slot instead of the bucketed slot the lookup actually
    // returned. The fix routes all four sites through
    // `invalidate_current_bucket`, whose signature forces the call site
    // to pass `ecs_cache_prefix` explicitly. These tests pin the helper's
    // semantics on the bucketed path and confirm the non-ECS sentinel
    // slot is not collateral-damaged.
    fn ecs_test_prefix() -> EcsPrefix {
        EcsPrefix {
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix: 24,
        }
    }

    /// h1 regression — cache-hit CNAME-block site (handler.rs:825).
    #[tokio::test]
    async fn ecs_bucketed_cache_hit_cname_block_invalidates_correct_bucket() {
        let cache = DnsCache::new(&cache_filter_test_config());
        let prefix = Some(ecs_test_prefix());
        let records = vec![
            cname_record("alias.example.com.", "tracker.evil.com.", 300),
            a_record("tracker.evil.com.", 300),
        ];
        cache
            .insert(
                "alias.example.com",
                RecordType::A,
                DNSClass::IN,
                records.clone(),
                ResponseCode::NoError,
                None,
                prefix,
            )
            .await;
        cache
            .insert(
                "alias.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("alias.example.com", RecordType::A, DNSClass::IN, prefix)
            .await
            .fresh()
            .expect("bucketed entry must be fresh");
        let filter = filter_with_blocked(&["tracker.evil.com"]);
        let trip = cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t));
        assert_eq!(trip.as_deref(), Some("tracker.evil.com"));
        invalidate_current_bucket(
            &cache,
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            prefix,
        )
        .await;
        assert!(
            matches!(
                cache
                    .lookup("alias.example.com", RecordType::A, DNSClass::IN, prefix)
                    .await,
                CacheLookup::Miss
            ),
            "§4.29 h1: ECS-bucketed slot must be evicted by helper"
        );
        assert!(
            cache
                .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "§4.29 h1: non-ECS sentinel slot must NOT be collateral-damaged"
        );
    }

    /// h2 regression — cache-hit IP-block site (handler.rs:866).
    #[tokio::test]
    async fn ecs_bucketed_cache_hit_ip_block_invalidates_correct_bucket() {
        use std::collections::HashSet;
        let cache = DnsCache::new(&cache_filter_test_config());
        let prefix = Some(ecs_test_prefix());
        let records = vec![a_record("fastflux.example.com.", 300)];
        cache
            .insert(
                "fastflux.example.com",
                RecordType::A,
                DNSClass::IN,
                records.clone(),
                ResponseCode::NoError,
                None,
                prefix,
            )
            .await;
        cache
            .insert(
                "fastflux.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, prefix)
            .await
            .fresh()
            .expect("bucketed entry must be fresh");
        let mut blocked_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
        blocked_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let ipf = IpFilter::with_ips(blocked_ips);
        assert_eq!(
            ipf.check_response(entry.records(), NamePolicy::Neutral),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        invalidate_current_bucket(
            &cache,
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            prefix,
        )
        .await;
        assert!(
            matches!(
                cache
                    .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, prefix)
                    .await,
                CacheLookup::Miss
            ),
            "§4.29 h2: ECS-bucketed slot must be evicted by helper"
        );
        assert!(
            cache
                .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "§4.29 h2: non-ECS sentinel slot must NOT be collateral-damaged"
        );
    }

    /// h3 regression — post-fetch CNAME-block site (handler.rs:1181). Mirrors
    /// h1 at the data-flow level; in production the entry was just inserted
    /// by `lookup_or_fetch` rather than pre-existing. Helper behavior is
    /// identical.
    #[tokio::test]
    async fn ecs_bucketed_post_fetch_cname_block_invalidates_correct_bucket() {
        let cache = DnsCache::new(&cache_filter_test_config());
        let prefix = Some(ecs_test_prefix());
        let records = vec![
            cname_record("freshly.example.com.", "tracker.evil.com.", 300),
            a_record("tracker.evil.com.", 300),
        ];
        cache
            .insert(
                "freshly.example.com",
                RecordType::A,
                DNSClass::IN,
                records.clone(),
                ResponseCode::NoError,
                None,
                prefix,
            )
            .await;
        cache
            .insert(
                "freshly.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        invalidate_current_bucket(
            &cache,
            "freshly.example.com",
            RecordType::A,
            DNSClass::IN,
            prefix,
        )
        .await;
        assert!(
            matches!(
                cache
                    .lookup("freshly.example.com", RecordType::A, DNSClass::IN, prefix)
                    .await,
                CacheLookup::Miss
            ),
            "§4.29 h3: ECS-bucketed slot must be evicted by helper after post-fetch CNAME-block"
        );
        assert!(
            cache
                .lookup("freshly.example.com", RecordType::A, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "§4.29 h3: non-ECS sentinel slot must NOT be collateral-damaged"
        );
    }

    /// h4 regression — post-fetch IP-block site (handler.rs:1222). Mirrors
    /// h2 at the data-flow level.
    #[tokio::test]
    async fn ecs_bucketed_post_fetch_ip_block_invalidates_correct_bucket() {
        let cache = DnsCache::new(&cache_filter_test_config());
        let prefix = Some(ecs_test_prefix());
        let records = vec![a_record("freshly-ip.example.com.", 300)];
        cache
            .insert(
                "freshly-ip.example.com",
                RecordType::A,
                DNSClass::IN,
                records.clone(),
                ResponseCode::NoError,
                None,
                prefix,
            )
            .await;
        cache
            .insert(
                "freshly-ip.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        invalidate_current_bucket(
            &cache,
            "freshly-ip.example.com",
            RecordType::A,
            DNSClass::IN,
            prefix,
        )
        .await;
        assert!(
            matches!(
                cache
                    .lookup(
                        "freshly-ip.example.com",
                        RecordType::A,
                        DNSClass::IN,
                        prefix
                    )
                    .await,
                CacheLookup::Miss
            ),
            "§4.29 h4: ECS-bucketed slot must be evicted by helper after post-fetch IP-block"
        );
        assert!(
            cache
                .lookup("freshly-ip.example.com", RecordType::A, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "§4.29 h4: non-ECS sentinel slot must NOT be collateral-damaged"
        );
    }

    /// Defensive: helper called with `None` (no-ECS-policy profile) targets
    /// the non-ECS slot and leaves any concurrent `Some(prefix)` bucketed
    /// slot intact. Mirror of h1-h4 from the other direction — pins backward
    /// compatibility for non-ECS-routed profiles.
    #[tokio::test]
    async fn helper_with_none_does_not_touch_ecs_bucketed_slot() {
        let cache = DnsCache::new(&cache_filter_test_config());
        let prefix = Some(ecs_test_prefix());
        let records = vec![a_record("dual.example.com.", 300)];
        cache
            .insert(
                "dual.example.com",
                RecordType::A,
                DNSClass::IN,
                records.clone(),
                ResponseCode::NoError,
                None,
                prefix,
            )
            .await;
        cache
            .insert(
                "dual.example.com",
                RecordType::A,
                DNSClass::IN,
                records,
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        invalidate_current_bucket(
            &cache,
            "dual.example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        )
        .await;
        assert!(
            matches!(
                cache
                    .lookup("dual.example.com", RecordType::A, DNSClass::IN, None)
                    .await,
                CacheLookup::Miss
            ),
            "helper with None must evict the non-ECS slot"
        );
        assert!(
            cache
                .lookup("dual.example.com", RecordType::A, DNSClass::IN, prefix)
                .await
                .fresh()
                .is_some(),
            "helper with None must NOT touch the bucketed slot"
        );
    }

    // ── device network names (2026-08-10 design spec, D1/D2/D5) ─────────────

    /// Recording mock upstream.
    ///
    /// **Records rather than traps.** Every test below turns on *whether the
    /// query left this daemon*, and a `panic!` inside the handler's async
    /// path can be swallowed instead of failing the test. What it answers is
    /// irrelevant — the assertions read `calls()`.
    #[derive(Default)]
    struct RecordingUpstream {
        calls: std::sync::atomic::AtomicUsize,
        last_name: Mutex<Option<String>>,
    }

    impl RecordingUpstream {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn last_name(&self) -> Option<String> {
            self.last_name.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Upstream for RecordingUpstream {
        async fn lookup(
            &self,
            name: &Name,
            _record_type: RecordType,
            _ecs: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<crate::upstream::UpstreamResponse, DnsError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_name.lock().unwrap() = Some(name.to_string());
            Ok(crate::upstream::UpstreamResponse {
                records: vec![Record::from_rdata(
                    name.clone(),
                    60,
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
                )],
                response_code: ResponseCode::NoError,
                soa_minimum_ttl: None,
                #[cfg(feature = "dnssec")]
                authority: Vec::new(),
            })
        }
    }

    /// Query source for the network-name tests. Matches no device, so the
    /// 5-level chain lands on `server.default_profile` — without that, a
    /// fall-through would stop at the SN3 REFUSED sentinel and never reach
    /// upstream, silently defeating the `calls()` assertions.
    const NET_NAME_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

    /// A resolver holding exactly one device with a `network_name`.
    /// `device_ip = None` builds the offline case: no pinned IP and no MAC,
    /// so `resolve_network_name` finds nothing to answer with while
    /// `network_name_is_configured` still reports the name as ours.
    fn resolver_with_network_name(
        network_name: &str,
        wildcard: bool,
        device_ip: Option<IpAddr>,
    ) -> Arc<ProfileResolver> {
        use crate::config::schema::{ConfigV1, Device, Id, Profile};
        use crate::lists::source_key::SourceBitMap;

        let mut config = ConfigV1 {
            schema_version: 1,
            ..Default::default()
        };
        config.server.default_profile = Some(Id::new("demo").unwrap());
        config.profiles.insert(
            "demo".to_string(),
            Profile {
                display_name: "demo".into(),
                ..Default::default()
            },
        );
        config.devices.push(Device {
            id: Id::new("named-dev").unwrap(),
            display_name: "named".into(),
            ip: device_ip,
            mac: None,
            mac_aliases: vec![],
            profile: Some(Id::new("demo").unwrap()),
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: Some(network_name.to_string()),
            network_name_wildcard: wildcard,
        });
        Arc::new(ProfileResolver::build(
            &config,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        ))
    }

    /// `local_records = None` — a static-table miss is this branch's
    /// precondition, so every test but the precedence pin wants it absent.
    fn handler_with_resolver(
        resolver: Arc<ProfileResolver>,
        upstream: Arc<RecordingUpstream>,
        dynamic_ttl: u32,
    ) -> ForwardHandler {
        handler_with(resolver, upstream, dynamic_ttl, None)
    }

    fn handler_with(
        resolver: Arc<ProfileResolver>,
        upstream: Arc<RecordingUpstream>,
        dynamic_ttl: u32,
        local_records: Option<Arc<LocalRecords>>,
    ) -> ForwardHandler {
        ForwardHandler::new(
            upstream,
            Arc::new(FilterEngine::new()),
            DnsCache::new(&crate::config::settings::CacheConfig::default()),
            Some(resolver),
            None, // stats
            None, // security — no pre-query gate in the way
            local_records,
            None, // ip_filter
            None, // allow_from: accept every source
            60,
            None, // prefetch disabled
            0.0,
            16,
        )
        .with_dynamic_ttl_secs(dynamic_ttl)
    }

    fn net_name_request(qname: &str, record_type: RecordType) -> Request {
        use hickory_net::xfer::Protocol;
        use hickory_proto::op::{Message, Query};
        use std::net::SocketAddr;

        let mut msg = Message::new(0x2607, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii(format!("{qname}.")).unwrap(),
            record_type,
        ));
        let bytes = msg.to_vec().unwrap();
        let src = SocketAddr::new(IpAddr::V4(NET_NAME_CLIENT), 40000);
        Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
    }

    async fn drive(handler: &ForwardHandler, request: &Request) -> CapturingHandler {
        let mut sink = CapturingHandler::new();
        handler
            .handle_inner(request, &mut sink)
            .await
            .expect("handler must not error");
        sink
    }

    /// The fallback the handler uses when the boot path never called
    /// [`ForwardHandler::with_dynamic_ttl_secs`] must be the value the
    /// config documents. Drift makes warden answer with a TTL no config
    /// file mentions — invisible until an operator wonders why their name
    /// went stale.
    #[test]
    fn default_dynamic_ttl_matches_config_default() {
        assert_eq!(
            DEFAULT_DYNAMIC_TTL_SECS,
            crate::config::settings::LocalDnsConfig::default().dynamic_ttl_secs,
        );
    }

    #[tokio::test]
    async fn network_name_exact_hit_answers_a_record() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = handler_with_resolver(
            resolver_with_network_name(
                "desktop-1",
                false,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            ),
            Arc::clone(&upstream),
            // Deliberately NOT the default: a test asserting 30 would pass
            // whether or not the TTL plumbing works at all.
            77,
        );

        let sink = drive(&handler, &net_name_request("desktop-1", RecordType::A)).await;

        assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
        let answers = sink.answers();
        assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 50))));
        assert_eq!(
            answers[0].ttl, 77,
            "the answer's TTL must come from local_dns.dynamic_ttl_secs"
        );
        assert_eq!(
            answers[0].name,
            Name::from_ascii("desktop-1.").unwrap(),
            "the answer must be owned by the QNAME"
        );
        assert_eq!(
            upstream.calls(),
            0,
            "a locally-answered name must never reach upstream"
        );
    }

    #[tokio::test]
    async fn network_name_unknown_device_falls_through_to_nxdomain_path() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = handler_with_resolver(
            resolver_with_network_name(
                "desktop-1",
                false,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            ),
            Arc::clone(&upstream),
            77,
        );

        let sink = drive(&handler, &net_name_request("not-a-device", RecordType::A)).await;

        // The discriminating assertion. "No A for 192.0.2.50" would pass with
        // the whole branch deleted; "the query left the daemon" would not.
        assert_eq!(
            upstream.calls(),
            1,
            "an unrecognised name must fall through to the normal query path"
        );
        assert_eq!(upstream.last_name().as_deref(), Some("not-a-device."));
        assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
    }

    #[tokio::test]
    async fn network_name_configured_but_device_offline_answers_nxdomain() {
        let upstream = Arc::new(RecordingUpstream::default());
        // No configured IP and no MAC — nothing for the ARP walk to match.
        let handler = handler_with_resolver(
            resolver_with_network_name("offline-box", false, None),
            Arc::clone(&upstream),
            77,
        );

        let sink = drive(&handler, &net_name_request("offline-box", RecordType::A)).await;

        assert_eq!(sink.rcode(), Some(ResponseCode::NXDomain));
        assert_eq!(sink.answer_count(), 0);
        // Without this half, an upstream that happened to answer NXDOMAIN
        // would make the test pass with the branch deleted.
        assert_eq!(
            upstream.calls(),
            0,
            "a name warden owns must not leak upstream, even when unresolvable"
        );
    }

    /// The wildcard case is what justifies owning the answer with the parsed
    /// QNAME rather than the device's apex: glibc's `getanswer()` silently
    /// discards an answer whose owner is unreachable from the question.
    #[tokio::test]
    async fn network_name_wildcard_descendant_is_owned_by_the_qname() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = handler_with_resolver(
            resolver_with_network_name(
                "casamia",
                true,
                Some(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))),
            ),
            Arc::clone(&upstream),
            77,
        );

        let sink = drive(&handler, &net_name_request("app.casamia", RecordType::A)).await;

        let answers = sink.answers();
        assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
        assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(10, 10, 10, 10))));
        assert_eq!(
            answers[0].name,
            Name::from_ascii("app.casamia.").unwrap(),
            "a wildcard descendant must be owned by the queried name, not the apex"
        );
        assert_eq!(upstream.calls(), 0);
    }

    /// A-only for the actual *answer* (D5: no IPv6/NDP tracking exists), but
    /// a configured name with no A must not leak upstream either — same
    /// local-01 anti-leak rationale as the static `local_dns`
    /// `NodataSynthesis` path immediately above this branch in
    /// `handle_inner`. Default (`nodata_for_missing_types = true`, the
    /// config default): NODATA, upstream never touched.
    #[tokio::test]
    async fn network_name_aaaa_query_answers_nodata_by_default() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = handler_with_resolver(
            resolver_with_network_name(
                "desktop-1",
                false,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            ),
            Arc::clone(&upstream),
            77,
        );

        let sink = drive(&handler, &net_name_request("desktop-1", RecordType::AAAA)).await;

        assert_eq!(
            upstream.calls(),
            0,
            "a configured network_name must never leak an AAAA query upstream"
        );
        assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
        assert_eq!(sink.answer_count(), 0);
        assert!(
            sink.name_server_count() >= 1,
            "NODATA must carry a synthesized SOA in the authority section"
        );
    }

    /// The operator escape hatch: `nodata_for_missing_types = false` is the
    /// same deliberate split-horizon opt-out the static `local_dns` table
    /// already offers (its own doc comment: "Metti false solo se usi
    /// deliberatamente split-horizon"). With it off, a device network_name
    /// reverts to the old plain fall-through for a non-A qtype.
    #[tokio::test]
    async fn network_name_aaaa_query_falls_through_when_nodata_disabled() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = ForwardHandler::new(
            Arc::clone(&upstream) as Arc<dyn Upstream>,
            Arc::new(FilterEngine::new()),
            DnsCache::new(&crate::config::settings::CacheConfig::default()),
            Some(resolver_with_network_name(
                "desktop-1",
                false,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            )),
            None,
            None,
            None,
            None,
            None,
            60,
            None,
            0.0,
            16,
        )
        .with_dynamic_ttl_secs(77)
        .with_nodata_for_missing_types_network_name(false);

        let sink = drive(&handler, &net_name_request("desktop-1", RecordType::AAAA)).await;

        assert_eq!(
            upstream.calls(),
            1,
            "AAAA must fall through to the 5-level chain when the operator opted out"
        );
        assert_eq!(upstream.last_name().as_deref(), Some("desktop-1."));
        assert_ne!(sink.rcode(), Some(ResponseCode::NXDomain));
    }

    /// The ordering claim the inserted comment makes: a static `local_dns`
    /// record wins an exact collision because this branch is probed only
    /// after the static table misses.
    ///
    /// Unpinned, that claim is a comment — a refactor hoisting the branch
    /// above the `local_records` block would break it and stay green, since
    /// every other test here passes `local_records = None`. Only a test can
    /// reach this state at all: the validator refuses a config where a
    /// device `network_name` collides with a `local_dns` record, so the
    /// ordering is defence in depth and this is the only way to exercise it.
    ///
    /// The two paths answer different addresses *and* different TTLs, so the
    /// assertion names which one replied rather than merely that someone did.
    #[tokio::test]
    async fn static_local_dns_record_wins_over_a_colliding_network_name() {
        use crate::config::settings::{LocalDnsConfig, LocalDnsRecord, LocalDnsRecordType};

        let static_table = LocalRecords::build(&LocalDnsConfig {
            ttl_secs: 3600,
            dynamic_ttl_secs: 30,
            nodata_for_missing_types: true,
            records: vec![LocalDnsRecord {
                domain: "desktop-1".into(),
                record_type: LocalDnsRecordType::A,
                value: "192.0.2.1".into(),
                match_subdomains: false,
                ttl_secs: None,
            }],
        });
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = handler_with(
            resolver_with_network_name(
                "desktop-1",
                false,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            ),
            Arc::clone(&upstream),
            77,
            Some(Arc::new(static_table)),
        );

        let sink = drive(&handler, &net_name_request("desktop-1", RecordType::A)).await;

        let answers = sink.answers();
        assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
        assert_eq!(
            answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            "the operator's explicit local_dns record must beat the device's \
             dynamic network_name"
        );
        assert_eq!(
            answers[0].ttl, 3600,
            "TTL must come from local_dns.ttl_secs, not dynamic_ttl_secs — \
             a matching address alone would not say which path answered"
        );
        assert_eq!(upstream.calls(), 0);
    }

    // ── boot list persistence — readiness gate backstop (Task 2, §2.4) ──────

    /// A resolver with one `default_profile`, empty rules, no devices.
    /// Every client falls through to it, so a query is neither blocked
    /// nor caught by the `(None, _)` fail-closed arm in `handle_inner`
    /// (L-3): passing `profiles: None` there REFUSES every query for a
    /// reason unrelated to the readiness gate and would defeat these
    /// tests regardless of gate state — the doc comment on
    /// [`ForwardHandler::new`] claiming a `None`-profiles fallback to
    /// legacy `is_blocked()` predates L-3 and is no longer accurate.
    fn permissive_test_resolver() -> Arc<ProfileResolver> {
        use crate::config::schema::{ConfigV1, Id, Profile};
        use crate::lists::source_key::SourceBitMap;

        let mut config = ConfigV1 {
            schema_version: 1,
            ..Default::default()
        };
        config.server.default_profile = Some(Id::new("demo").unwrap());
        config.profiles.insert(
            "demo".to_string(),
            Profile {
                display_name: "demo".into(),
                ..Default::default()
            },
        );
        Arc::new(ProfileResolver::build(
            &config,
            &SourceBitMap::default(),
            &crate::config::custom_list::CustomListStore::new(),
        ))
    }

    /// A handler with security/stats/local-records/ACL disabled and a
    /// permissive resolver (see [`permissive_test_resolver`]), backed by
    /// `upstream` so an unblocked query resolves normally instead of
    /// erroring. Takes the upstream by reference (mirrors
    /// [`handler_with_resolver`]) rather than building its own, so a
    /// test can keep its own handle and assert on `calls()` — the only
    /// way to pin "never evaluates the filter", not just "answers
    /// SERVFAIL", per `boot_list_persistence.md` §4 obligation 5.
    fn build_test_handler(upstream: Arc<RecordingUpstream>) -> ForwardHandler {
        ForwardHandler::new(
            upstream,
            Arc::new(FilterEngine::new()),
            DnsCache::new(&crate::config::settings::CacheConfig::default()),
            Some(permissive_test_resolver()),
            None, // stats
            None, // security
            None, // local_records
            None, // ip_filter
            None, // allow_from: accept every source
            60,
            None, // prefetch disabled
            0.0,
            16,
        )
    }

    /// Drive a single query for `domain` through `handler` and return the
    /// captured response. Reuses [`net_name_request`]'s message-building —
    /// despite its name, that helper just builds a query for an arbitrary
    /// qname/record type from a fixed private source address.
    async fn query_handler(
        handler: &ForwardHandler,
        domain: &str,
        record_type: RecordType,
    ) -> CapturingHandler {
        drive(handler, &net_name_request(domain, record_type)).await
    }

    /// A closed gate refuses every query with SERVFAIL, before the
    /// filter is consulted at all — pinned by `upstream.calls() == 0`,
    /// not just the rcode. The rcode alone proves only that a later
    /// SERVFAIL fired somewhere on the path; a refactor that hoists the
    /// gate check below the point the query already leaked upstream
    /// would still read SERVFAIL and pass a rcode-only assertion.
    #[tokio::test]
    async fn closed_readiness_gate_servfails_every_query() {
        let gate = ReadinessGate::new(false);
        let upstream = Arc::new(RecordingUpstream::default());
        // Build the handler exactly as the neighbouring tests do, then
        // attach the gate.
        let handler = build_test_handler(Arc::clone(&upstream)).with_filter_ready(gate.clone());

        let response = query_handler(&handler, "example.com", RecordType::A).await;

        assert_eq!(
            response.rcode(),
            Some(ResponseCode::ServFail),
            "a daemon with no installed generation must refuse, not answer"
        );
        assert_eq!(
            upstream.calls(),
            0,
            "a closed gate must refuse before the filter/upstream path is \
             ever reached — not merely end up SERVFAIL some other way"
        );
    }

    /// The default is OPEN, so every construction that does not opt in —
    /// including every other test in this file — behaves exactly as
    /// before. `start.rs` is the only place that seeds it closed.
    ///
    /// Asserts the positive shape (`NoError` + one upstream call), not
    /// just `!= ServFail`: a handler that returned `Ok` without ever
    /// calling `send_response` would leave `rcode() == None`, which
    /// also satisfies `!= Some(ServFail)` without proving anything
    /// answered. `calls() == 1` is also the discriminator against the
    /// closed-gate test above: if both read 0, the fixture never
    /// reaches upstream at all and neither test means what it claims.
    #[tokio::test]
    async fn readiness_gate_defaults_open() {
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = build_test_handler(Arc::clone(&upstream));

        let response = query_handler(&handler, "example.com", RecordType::A).await;

        assert_eq!(
            response.rcode(),
            Some(ResponseCode::NoError),
            "a handler with no gate attached must answer normally"
        );
        assert_eq!(upstream.calls(), 1);
    }

    /// handler-05 applies here too: an unconditional `warn!` per refused
    /// query while the gate is closed is the same log-flood / journald
    /// amplification vector the ACL path's comment (`handler.rs:952`)
    /// already warns against — worse, here it fires for EVERY client,
    /// not just non-allowed sources, at the worst possible
    /// moment (boot, when the box is least able to absorb it).
    ///
    /// This one asserts on the **latch**, not on the log level:
    /// `gate_refusal_logged` is what the warn/debug branch reads, so
    /// proving it is `false` before any refusal, `true` after the first
    /// and still `true` after the second proves the branch was taken
    /// once and only once.
    ///
    /// That is necessary but NOT sufficient, and the gap is precisely
    /// the mutation this repo has already named
    /// (`feedback_mutation_swap_not_delete`): swap the two arms and the
    /// latch behaves identically while every refusal *after* the first
    /// warns — the same log-flood vector, delayed by one packet.
    /// [`closed_gate_logs_warn_first_then_debug`] closes that by
    /// capturing the levels; the two together are the whole property.
    #[tokio::test]
    async fn closed_gate_warns_once_then_stays_quiet() {
        let gate = ReadinessGate::new(false);
        let upstream = Arc::new(RecordingUpstream::default());
        let handler = build_test_handler(Arc::clone(&upstream)).with_filter_ready(gate.clone());

        assert!(
            !handler
                .gate_refusal_logged
                .load(std::sync::atomic::Ordering::Relaxed),
            "fixture sanity: nothing has refused yet"
        );

        let first = query_handler(&handler, "example.com", RecordType::A).await;
        assert_eq!(first.rcode(), Some(ResponseCode::ServFail));
        assert!(
            handler
                .gate_refusal_logged
                .load(std::sync::atomic::Ordering::Relaxed),
            "the first refusal must latch — this is what routes it to warn!"
        );

        let second = query_handler(&handler, "example.org", RecordType::A).await;
        assert_eq!(second.rcode(), Some(ResponseCode::ServFail));
        assert!(
            handler
                .gate_refusal_logged
                .load(std::sync::atomic::Ordering::Relaxed),
            "the latch must never reset — a second refusal must still take \
             the quiet debug! arm, not warn again"
        );
        assert_eq!(
            upstream.calls(),
            0,
            "both refusals must still refuse before reaching upstream — \
             this test is about log volume, not a regression on the gate \
             itself"
        );
    }

    /// Substring common to BOTH arms of the gate-refusal log — the
    /// `warn!`'s "…no filter generation has been installed yet…" and the
    /// `debug!`'s "…no filter generation installed yet". Filtering on it
    /// rather than counting levels matters: the query path emits other
    /// events, and a bare "one WARN, one DEBUG" count would be satisfied
    /// by any two of them. Filtering on a substring unique to one arm
    /// would be worse still — the filter would then decide the answer.
    const GATE_REFUSAL_MARKER: &str = "no filter generation";

    thread_local! {
        /// Levels of gate-refusal events seen on THIS thread, in order.
        /// `Some` only between [`arm_gate_refusal_capture`] and
        /// [`take_gate_refusal_levels`]; libtest gives each test its own
        /// thread and `#[tokio::test]` is a current-thread runtime, so
        /// no other test can write here.
        static GATE_REFUSAL_LEVELS: std::cell::RefCell<Option<Vec<tracing::Level>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Pulls the formatted `message` field out of an event. `tracing`
    /// exposes it only through the visitor API — there is no
    /// `event.message()`.
    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    /// A minimal `tracing::Subscriber` that files gate-refusal events
    /// into the armed thread's buffer and drops everything else.
    ///
    /// **Installed GLOBALLY, and it has to be** — the obvious design is
    /// a `tracing_subscriber::Layer` under
    /// `tracing::subscriber::set_default`, thread-local so it cannot
    /// disturb neighbours. That version is *flaky*: measured 8 failures
    /// in 16 runs. `tracing` caches each callsite's `Interest` in a
    /// process-global slot, so a neighbouring test that drives a refusal
    /// with no subscriber on its thread (there are several) can get
    /// `Interest::never()` cached for the `warn!` callsite, after which
    /// this thread's subscriber is never consulted for it and the
    /// capture silently loses the event. A global default is registered
    /// in that cache, so every callsite resolves to `always` and the
    /// capture is deterministic. Neighbours stay unaffected: their
    /// thread has no buffer armed, so `event` returns after one
    /// thread-local read.
    struct GateRefusalCapture;

    impl tracing::Subscriber for GateRefusalCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn event(&self, event: &tracing::Event<'_>) {
            // `try_with` because this can run while a thread is being
            // torn down and its thread-locals are already destroyed.
            let _ = GATE_REFUSAL_LEVELS.try_with(|cell| {
                let Ok(mut slot) = cell.try_borrow_mut() else {
                    return;
                };
                let Some(levels) = slot.as_mut() else {
                    return; // not the capturing thread — the common case
                };
                let mut visitor = MessageVisitor(String::new());
                event.record(&mut visitor);
                if visitor.0.contains(GATE_REFUSAL_MARKER) {
                    levels.push(*event.metadata().level());
                }
            });
        }

        // Spans are irrelevant here and deliberately not stored: this
        // subscriber is live for every test in the binary once armed.
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Install the capture (once per process) and start recording on
    /// this thread.
    fn arm_gate_refusal_capture() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            tracing::subscriber::set_global_default(GateRefusalCapture)
                .expect("no other lib test may install a global tracing subscriber");
        });
        GATE_REFUSAL_LEVELS.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
    }

    /// Stop recording on this thread and return what was seen, in order.
    fn take_gate_refusal_levels() -> Vec<tracing::Level> {
        GATE_REFUSAL_LEVELS.with(|cell| {
            cell.borrow_mut()
                .take()
                .expect("capture was never armed on this thread")
        })
    }

    /// The first refusal logs at WARN, every one after at DEBUG —
    /// asserted on the **levels themselves**, which is the half
    /// [`closed_gate_warns_once_then_stays_quiet`] structurally cannot
    /// reach.
    ///
    /// The wrong implementation this kills is arms-swapped —
    /// `if !flag.swap(true, ..) { debug! } else { warn! }` — which
    /// leaves the latch behaving exactly as it does now and reintroduces
    /// the per-packet `warn!` + journald write that `ce6f25e5` exists to
    /// prevent, one packet later. Nothing else produces the sequence
    /// `[WARN, DEBUG]`: both-warn, both-debug and swapped each yield a
    /// different one, and a capture that silently caught nothing yields
    /// an empty vec and fails rather than passing vacuously.
    ///
    /// See [`GateRefusalCapture`] for why the subscriber is installed
    /// globally rather than per-thread — the per-thread version was
    /// measurably flaky, and a flaky log-capture test is worse than none.
    #[tokio::test]
    async fn closed_gate_logs_warn_first_then_debug() {
        arm_gate_refusal_capture();

        let upstream = Arc::new(RecordingUpstream::default());
        let handler =
            build_test_handler(Arc::clone(&upstream)).with_filter_ready(ReadinessGate::new(false));

        let first = query_handler(&handler, "example.com", RecordType::A).await;
        let second = query_handler(&handler, "example.org", RecordType::A).await;

        assert_eq!(first.rcode(), Some(ResponseCode::ServFail));
        assert_eq!(second.rcode(), Some(ResponseCode::ServFail));

        assert_eq!(
            take_gate_refusal_levels(),
            vec![tracing::Level::WARN, tracing::Level::DEBUG],
            "the FIRST refusal must warn and every one after must drop to \
             debug. Swapping the two arms keeps `gate_refusal_logged` \
             behaving identically while flooding the journal from the \
             second packet on"
        );
    }
}
