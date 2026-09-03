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

/// Rewrite-aware upstream `Name` reconstruction, shared by the
/// prefetch-spawn and cache-miss forward paths so this coherence rule
/// lives in exactly ONE place.
///
/// When a per-profile rewrite fired (`rewrote`), `domain` carries the rewritten
/// qname and the upstream `Name` must be rebuilt from it via `from_ascii`,
/// otherwise the engine would query the *original* name — a wrong qname on
/// the wire, invisible to client-response assertions. The validator
/// guarantees the rewrite target parses at config-load, so the `from_ascii`
/// fallback to the original `name` is defence-in-depth. When no rewrite
/// fired, `domain` equals the original parsed query name — reuse `name`
/// directly and skip the `format!` String alloc + `from_ascii` parse on
/// every non-rewritten cache miss. It drifted once when this was two
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
            // With no compiled-in provider list, an operator who never set
            // `extra_domains` yields an empty checker. Drop it rather than
            // pay a per-query subdomain walk that cannot match.
            //
            // The drop is the right call for the hot path, but it is not
            // silent. `enabled = true` with an empty set is reported by
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
    /// The domain-shape heuristics are qtype-gated. PTR names legitimately
    /// embed IP addresses (every IPv4 reverse name is four consecutive
    /// numeric labels) and an IPv6 reverse name is 32 random hex nibbles
    /// (concatenated, Shannon entropy ~3.7-4.0, above the tunneling
    /// threshold) — without this gate, every IPv4 PTR query would be
    /// refused as a rebinding attempt, and warden's own local-records PTR
    /// feature would be unreachable behind it.
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

    /// Cache-miss tunneling rate check. Bumps the per-`(client, base
    /// domain)` counter and returns true when the budget is exceeded. The
    /// handler calls this only for queries that are about to go upstream —
    /// cache hits prove repetition, not the unique-name fan-out tunneling
    /// produces, so they no longer count.
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
/// PTR keeps its exemption **only inside the reverse zones**. There it
/// is load-bearing — every reverse name a client sends shares one base
/// domain (`in-addr.arpa` is not an eTLD `compute_base_domain` splits),
/// so a scanner doing 51 reverse lookups a minute would exhaust a single
/// bucket and be REFUSED. Outside them the exemption is a hole: nothing
/// requires a PTR query to sit under `.arpa`, the shape gate already
/// skips PTR by design (an IPv6 nibble name is indistinguishable from a
/// payload — see `check_pre_query`), and fan-out does not care about the
/// qtype, so a payload carried as PTR was checked by neither gate.
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
    /// Source-IP allow list. Inner `None` or empty means accept all
    /// sources. Pre-parsed so the hot path only does bitwise CIDR compares.
    ///
    /// Wrapped in `Arc<ArcSwapOption<_>>` so a config reload can re-derive the
    /// ACL live (`cli::commands::start::handle_reload`) without a daemon
    /// restart: the reload path holds a clone of this same `Arc` (handed out
    /// by [`Self::allow_from_handle`]) and calls `.store(..)`. Per-query reads
    /// stay lock-free — a single `ArcSwapOption::load`.
    allow_from: Arc<ArcSwapOption<Vec<Cidr>>>,
    blocked_ttl: u32,
    /// Bounded semaphore for TTL-triggered prefetch tasks. None = prefetch disabled.
    prefetch_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Fraction of TTL remaining that triggers a background prefetch (e.g. 0.1 = 10%).
    prefetch_threshold: f64,
    /// Maximum CNAME chain depth to inspect for blocked targets.
    cname_max_depth: usize,
    /// Per-record hit counter for local DNS records. Bumped after each
    /// profile-scope or global probe hit. `None` skips the increment —
    /// used by tests / fixtures that don't need the counter wired.
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
    /// static `local_dns` `NodataSynthesis` path.
    /// Default `true`, matching the config default. Plain `bool`, not an
    /// `Arc<Atomic*>` like `dynamic_ttl_secs`: no reload path exists for
    /// any of `[local_dns]` today (`LocalRecords::swap` is never called in
    /// production either — verified separately), so
    /// this setting is boot-only, consistent with the rest of the section
    /// rather than a regression against it.
    nodata_for_missing_types_network_name: bool,
    /// Append-only handle to the daemon audit log. `Some(writer)` in
    /// production (wired by `cli::commands::start`); `None` in unit tests
    /// that don't care about audit. Used by `emit_cname_block_audit` to
    /// record CNAME-chain block events off-hot-path via
    /// `tokio::task::spawn_blocking`.
    audit_writer: Option<Arc<AuditWriter>>,
    /// Latching readiness gate: `false` until a filter generation has
    /// been installed. Defaults to **open** so every construction that
    /// does not opt in is unaffected; `start.rs` seeds it closed on the
    /// nodes that build their own map (its `spawn_lists` predicate) and
    /// open on the ones that do not — a cluster secondary among them,
    /// whose map arrives from the primary.
    ///
    /// [`ReadinessGate`] is one-way by construction: it has no `close`,
    /// and its atomic is private to `lists::readiness`, so no module —
    /// this one or the list manager — can put it back. The handler only
    /// ever reads it.
    filter_ready: ReadinessGate,
    /// One-shot latch for the `filter_ready` refusal log: `false` until
    /// the first query is refused for a closed gate, `true` forever
    /// after (never reset — this state is not supposed to recur once
    /// the primary boot guard is in place, so it never needs to re-arm).
    /// Per-handler, not shared like `filter_ready` — each
    /// `ForwardHandler` warns once on its own.
    ///
    /// Exists because a closed gate is, by construction, the only
    /// pre-parse refusal in `handle_inner` with no upper bound on
    /// volume: it fires for every client and every query, unlike the
    /// ACL refusal a few lines above (which already gates to `debug!` —
    /// non-allowed sources only). A plain per-query `warn!` here would
    /// be the exact log-flood / journald-write amplification vector
    /// that comment describes, triggered at boot — precisely when the
    /// box is least able to absorb it. First refusal: `warn!` (an
    /// operator needs to see this at all). Every one after: `debug!`
    /// (they've seen it).
    gate_refusal_logged: std::sync::atomic::AtomicBool,
    /// DNSSEC response-path validator. `Some` only when
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
    /// listed CIDRs are refused (open-resolver guard).
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

    /// Attach a [`LocalRecordsHits`] counter so the handler bumps it on
    /// every local-record probe hit. Called once at daemon boot after
    /// the counter is built. Kept as a separate setter (instead of
    /// widening [`Self::new`]) so existing callers that don't care about
    /// the counter continue to compile unchanged.
    pub fn with_local_records_hits(mut self, hits: Arc<LocalRecordsHits>) -> Self {
        self.local_records_hits = Some(hits);
        self
    }

    /// Attach the daemon audit writer so the handler can append
    /// `cname_block` records on CNAME-chain block events. Same
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

    /// Hand out a clone of the shared source-ACL cell. The handler is
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

    /// Attach the DNSSEC response-path validator. Same post-construction
    /// setter pattern as [`Self::with_audit_writer`]. Called once at boot
    /// only when `dnssec.mode != Off`; absent it, the handler does no
    /// DNSSEC processing.
    #[cfg(feature = "dnssec")]
    pub fn with_dnssec_validator(mut self, validator: Arc<DnssecValidator>) -> Self {
        self.dnssec_validator = Some(validator);
        self
    }

    /// The single DNSSEC hook on the response path. Wraps the free
    /// [`send_cached`] (the convergence point of the cache-hit / fresh-upstream
    /// / stale paths) so a validated answer can get the AD bit, a bogus one a
    /// SERVFAIL, behind `dnssec.mode`. With no validator (default build, or
    /// `mode = Off`) it is a zero-cost passthrough to `send_cached` and the
    /// response bytes are byte-identical to baseline.
    ///
    /// `rewrote` is `true` when a rewrite fired on this query; it
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
                // Validation does not *run* on this path — `decide` takes
                // `rewrote` and short-circuits to `Serve` before the fetch,
                // because the walk it would otherwise perform is of the
                // pre-rewrite qname and its verdict would be discarded here
                // anyway. See the reasoning on `DnssecValidator::decide`.
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

    /// Append a `cname_block` audit record off the hot path. The
    /// synchronous `write_all + sync_data` in
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
        // Carry the original qname when a rewrite fired on this query, so
        // the audit log matches the wire packet (which echoes the
        // original qname) instead of diverging to the post-rewrite
        // effective name in `qname`.
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
/// stays zero-allocation per the hot-path discipline.
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
    /// Offending hop in a CNAME chain block.
    /// `Some(name)` only on the two CNAME-chain-block exit branches
    /// (cache-hit re-check + post-upstream-fetch); `None` everywhere
    /// else. The `record_outcome` helper reads it and forwards to
    /// `log_query_event` so the offending hop ends up in the JSONL row
    /// alongside the original qname.
    cname_chain_via: Option<&'a str>,
    /// Set to `Some(bit)` only when the BLOCKED outcome is attributable
    /// to a single Tier 1 blocklist (`BlockSource::List(bit)`). `None`
    /// for admin / rule / cname / IP blocks — those don't pin to one
    /// list. The bit is forwarded to `StatsEngine::record_query`, which
    /// atomically increments the corresponding `list_blocked` slot.
    /// Stack-only `Copy` field; zero-allocation invariant preserved.
    block_list_bit: Option<u8>,
    /// Set to `Some(original_qname)` when a per-profile rewrite fired
    /// on this query. `decision.domain` carries the
    /// rewritten (effective) name. Forwarded to the query log writer
    /// so audit can show `from=… to=…`. `None` on every query that
    /// passed through without rewriting (typical case — zero cost).
    rewrote_from: Option<&'a str>,
}

/// Per-query context bundle for the block-dispatch helpers
/// ([`ForwardHandler::dispatch_cname_block`] /
/// [`ForwardHandler::dispatch_ip_block`]).
///
/// Replaces 13 shared positional args those two helpers would otherwise take.
/// Several would be transposition-prone — three adjacent `Option<&str>`
/// (`client_name`, `client_profile`, `rewrote_from`) plus `client_ip` and the
/// `u32` TTL — that the compiler can't tell apart on a swap. Mirrors the
/// existing [`QueryDecision`] shape.
///
/// All fields are borrows or `Copy`; the struct is **moved** into the helper
/// (pointer/scalar memcpy, no heap), so the block path stays alloc-free per
/// the hot-path discipline. Each helper destructures it on entry so its body
/// reads as if it still took the fields as positional arguments.
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
    /// Single point of stats recording for the request path. Without it,
    /// each of the 11 outcome sites in `handle_inner` would open-code
    /// `if let Some(s) = stats { s.record_query(...); s.log_query_event(...); }`,
    /// which makes it easy to add a new outcome without wiring all three
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
        // Security refusals (REFUSED / RRL_DROP) also land in
        // total_blocked, which keeps them visible in stats; tally them
        // in a dedicated counter so the content-block signal stays
        // interpretable. One pointer compare on a &'static str — no
        // alloc, no lock.
        if matches!(decision.outcome, "REFUSED" | "RRL_DROP") {
            stats.record_security_refusal();
        }
        if decision.cache_negative_hit {
            stats.record_cache_negative_hit();
        } else if decision.cached {
            // Feed the hit-frequency tracker on positive cache hits only.
            // Tracker short-circuits when disabled.
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

    /// Block-dispatch helper for the CNAME-chain re-check axis.
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
        // Pin the Tier 1 bit when the CNAME-block source is an
        // attributable list hit.
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

    /// Block-dispatch helper for the IP-blocklist re-check axis.
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
        // ACL gate — runs before *anything* else, so a refused source
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
            // Debug, not warn. A spoofed-source UDP flood at a
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

        // Readiness backstop. Refuse everything — not just filterable
        // names — while no generation
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
            // The same amplification concern applies here too, more
            // sharply than on the ACL path above: this fires for EVERY
            // client and EVERY query while closed, not just non-allowed
            // sources,
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
        // Set to `Some(original)` when the rewrite hook fires (between
        // blocked-check and cache lookup). Declared up-front so
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
                // Security refusals are recorded outcomes, so the operator
                // is not blind to attack volume exactly when these paths
                // fire. Profile attribution is None (refused before
                // resolution).
                //
                // The *device* name, unlike the profile, does not need the
                // 5-level chain — it is a direct IP→device probe. Bound
                // here rather than hoisted so the ALLOWED / BLOCKED path
                // never pays for it. Without this the Query Log falls back
                // to the raw client IP and an operator reads a
                // correctly-mapped device as a broken mapping.
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

            // RRL runs above the local-records / blocked /
            // unmapped-client-REFUSED exits, so those responses are also
            // rate-limited rather than going out at unbounded rate to
            // (potentially spoofed) sources. Two refusal classes exit
            // BEFORE this check and are deliberately uncovered — the ACL
            // refusal and the security pre-query refusal above. Both are
            // header-only (amplification ≤ 1, ~nil reflection value), and
            // RRL-dropping a security refusal would hide the attack
            // visibility that recording those refusals as outcomes is
            // meant to add to stats/query-log.
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
                    // Drops are visible in stats + query log.
                    // blocked: true — service was refused for this query.
                    //
                    // RRL sits deliberately ABOVE resolution (it bounds the
                    // rate of refusals to spoofed sources), so the name is
                    // probed directly rather than by moving the hoist. One
                    // `ArcSwap` load + one map probe, on a path that is
                    // already refusing the query.
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
                    // Same probe as RRL_DROP.
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

        // Profile resolution moves AHEAD of the local-record checks so the
        // profile-scope probe (which precedes the global one) has a
        // `ResolvedProfile` to consult. The anonymous-client-still-sees-
        // global-records semantics is preserved: the REFUSED dispatch for
        // `profile == None` only fires AFTER both local-record probes
        // miss.
        let resolution_opt = profiles.map(|r| r.resolve(&client_ip));
        let resolved_profile = resolution_opt
            .as_ref()
            .and_then(|r| r.profile.as_ref().cloned());
        // The LOCAL-record exits between here and the big
        // `match (profiles, resolution_opt)` below run before that match,
        // but resolution has already happened one line up — so they can
        // still attribute a device name. `early_device_name` below reads
        // it off `resolution_opt` so those exits don't fall back to a bare
        // client IP in the Query Log.
        //
        // A **borrow**, not a clone: `resolution_opt` outlives every exit that
        // reads this, and the borrow ends before the `match` below consumes it
        // by value. Costs the hot path nothing.
        let early_device_name: Option<&str> = resolution_opt
            .as_ref()
            .and_then(|r| r.device_name.as_deref());

        // Derive the per-query EDNS Client Subnet option once per request
        // from the resolved profile's `EcsPolicy` and the client IP. Both
        // the cache (partitioning key) and the upstream call (lookup arg)
        // receive the result. When the master switch is off, when the
        // profile/upstream mode is `Off`, or when the codec rejects the
        // inputs, `ecs_option` is `None` — byte-identical to the wire
        // baseline without ECS.
        let ecs_option = resolved_profile
            .as_ref()
            .and_then(|p| p.ecs_policy.build_option(client_ip));
        let ecs_cache_prefix = ecs_option.as_ref().and_then(|opt| opt.as_cache_prefix());

        // Profile-scoped local DNS records. Probed BEFORE the global
        // table so `[[profile.X.local_records]]` shadows
        // `[[local_dns.records]]` silently for clients on profile X.
        // Only A/AAAA/CNAME participate — `ProfileLocalRecords::lookup`
        // enforces this internally and returns `None` for any other
        // qtype, falling through to the global table and then upstream.
        // Not inserted into moka.
        if let Some(ref profile) = resolved_profile {
            if let Some(hit) = profile.local_records.lookup_with_apex(domain, record_type) {
                tracing::debug!(
                    domain,
                    ?record_type,
                    profile = %profile.name,
                    "LOCAL DNS (profile-scope)"
                );
                // Record the hit on the per-(scope, apex) counter so the
                // TUI Local DNS tab can show "which records actually
                // fire". Keyed by the matched record's apex (`hit.apex`), not
                // the raw QNAME, so a wildcard subdomain flood rolls up under
                // one key. Cheap atomic — DashMap entry probe +
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
        // (Global table. Owns PTR / reverse-DNS synthesis, which
        // profile-scope deliberately skips.)
        if let Some(local) = local_records {
            match local.lookup(domain, record_type) {
                LocalLookup::Hit { records, apex } => {
                    tracing::debug!(domain, ?record_type, "LOCAL DNS");
                    // Bump the global-scope hit counter, keyed by the
                    // matched record's apex (not the raw QNAME) so a wildcard
                    // subdomain flood rolls up under one key.
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
                // The name is locally authoritative but holds no records
                // of this qtype — answer NODATA instead of leaking the
                // internal hostname upstream (where a private-TLD
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

        // Dynamic device network names. Probed AFTER the static
        // `local_dns` miss so an operator-authored record always wins an
        // exact collision — the validator already refuses such a
        // collision at load time, so this ordering is defence in depth,
        // not the primary guarantee.
        //
        // A-only for the actual answer: there is no IPv6/NDP tracking to
        // resolve against, so a device `network_name` never carries an
        // AAAA. But a configured name that has no A answer still leaks
        // upstream if left to fall through — the same incident that
        // static `local_dns` records already fixed: an upstream NXDOMAIN
        // for a private/internal name negative-caches the whole NAME
        // (RFC 2308 §5), not just the queried type, and `getaddrinfo`
        // fires A and AAAA in parallel, so the NXDOMAIN from the AAAA
        // race can suppress the A query that would have answered. Mirrors
        // `LocalLookup::NodataSynthesis` immediately above: qtype ≠ A on
        // a configured name answers NODATA (gated on the same
        // `nodata_for_missing_types` operator escape hatch), not a
        // silent fall-through.
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
                            // has no A"), by design rather than an oversight.
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
                            // an answer warden gave. An exit that skips
                            // `record_outcome` would leave the operator blind
                            // in stats and query log exactly when they are
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
        // the chain reaches level 5 with `server.default_profile` unset.
        // Anonymous / unknown sources still take the REFUSED path here,
        // not a canned 0.0.0.0 response: REFUSED is not cached by stub
        // resolvers, so recovery is immediate when the operator wires a
        // `default_profile` or subnet for them. The REFUSED path is
        // intentionally hardcoded and ignores any profile's
        // `block_response` — predictable recovery beats per-profile
        // flexibility on this axis.
        //
        // The resolution was performed early (above) so profile-scope
        // local records could be probed; the already-resolved value is
        // reused here instead of resolving twice.
        //
        // `device_overlay` rides out of this match alongside the block
        // verdict. It is the *only* place the resolved device's overlay
        // is in scope, and the response-path filters below need it to
        // resolve the queried name's policy once — see the
        // `NamePolicy::resolve` call after the rewrite hook. Moving the
        // field out (rather than cloning the Arc) keeps the hot path
        // refcount-neutral.
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
                        // The chain matched no *profile*, which does not mean
                        // it matched no *device* — a device row with no
                        // usable profile lands exactly here, and it is the
                        // case an operator is most likely to be debugging.
                        // `resolution` is bound by this very arm, so the name
                        // is free.
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
                // Per-device overlay applies between resolution and the
                // profile evaluator. When the resolved client has no
                // overlay (empty rule sets, or anonymous source),
                // `evaluate_with_overlay` is byte-identical to the plain
                // `filter.evaluate` path.
                //
                // Also returns the attributing `BlockSource` so a per-list
                // bit can be pinned on the BLOCKED stats record.
                let (is_blocked, block_source) =
                    evaluate_with_overlay(domain, &profile, resolution.overlay.as_ref(), filter);
                // Move `device_name` out of the owned `resolution` (rather
                // than `.clone()`), and avoid materialising an owned
                // profile-name String per query — `client_profile` borrows
                // from `resolved_profile` below, which holds the same Arc
                // for the whole request. Zero-alloc hot path.
                let device_name = resolution.device_name;
                let overlay = resolution.overlay;
                // The profile carries `block_response` / `blocked_ttl_secs`
                // with the server-globals fallback already applied at build
                // time, so the hot path just reads them.
                let br = profile.block_response;
                let ttl = profile.blocked_ttl_secs;
                (is_blocked, block_source, device_name, br, ttl, overlay)
            }
            (None, _) | (Some(_), None) => {
                // Fail-closed REFUSED rather than an `unreachable!` keyed
                // to the construction invariant that `start.rs` always
                // builds a profile resolver: a future refactor that broke
                // the invariant would otherwise panic the per-request task
                // on every query. This matches the "default profile must
                // be restrictive" rule and the "no silent fallback"
                // security posture; a warn-log surfaces the construction
                // breakage to operators without paging.
                //
                // The `(Some(_), None)` arm is structurally unreachable —
                // `resolution_opt` is `Some(_)` whenever `profiles` is
                // `Some(_)` (both are built from the same `Option`).
                // Listed for exhaustiveness only.
                tracing::warn!(
                    %client_ip,
                    domain,
                    "REFUSED (profile resolver missing — construction invariant in start.rs broken; \
                     daemon staying up but refusing queries until rebuilt)"
                );
                self.record_outcome(&QueryDecision {
                    client_ip,
                    domain,
                    // `None` is correct here: this arm is reached when
                    // `profiles` itself is `None` — there is no resolver,
                    // hence no device map to consult. Probing would be a
                    // lookup against nothing.
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
        // The profile name for stats / query-log attribution is borrowed
        // straight out of `resolved_profile` (alive for the whole request
        // body) — `Some` whenever we got past the REFUSED arms above.
        // Replaces a per-query `String` allocation.
        let client_profile: Option<&str> = resolved_profile.as_ref().map(|p| p.name.as_str());
        // A/AAAA symmetric block invariant.
        //
        // `send_block_response` dispatches by `record_type`: A → 0.0.0.0,
        // AAAA → ::, everything else → NODATA. Because the resolver's
        // decision that `blocked == true` is computed from the domain alone
        // (record_type is not an input), a blocked name hands back a block
        // response for EVERY type the caller asks about — A, AAAA, CNAME,
        // MX, … — never a single-family block. Any future refactor that
        // threads record_type INTO the resolver decision breaks this
        // invariant and must add a counter-test first.
        let _n7_invariant_ack = blocked;

        if blocked {
            tracing::debug!(domain, ?record_type, "BLOCKED");
            // Pin a Tier 1 list bit when the BlockSource attributes the
            // block to a single list. Admin /
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

        // Domain rewrite hook. Runs AFTER the filter+blocked check (so a
        // rewrite cannot bypass blocklist enforcement on the original
        // qname) and BEFORE the cache lookup (so the cache key uses the
        // rewritten name — bonus hit-rate when multiple sources of the
        // legacy domain converge on the migrated target). Single-pass: no
        // chaining (a runtime guard inside `ProfileRewriteRules::apply`
        // enforces this).
        //
        // The client DOES see the target. The response's Question section
        // echoes the original qname, and every serve path bridges it to the
        // target with a synthesized `original CNAME target` record — see
        // `prepend_rewrite_cname`. The Answer section carries target-owned
        // RRs, and those must be bridged: glibc's `getanswer()` discards any
        // RR it cannot reach from the question name, so an unbridged
        // rewrite resolves the client to no addresses at all. Pinned by
        // `tests/rewrite_client_answer_shape.rs`.
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

        // Resolve the operator's policy for the queried name ONCE, here,
        // and hand it to every site below that inspects the *answer*: the
        // three `walk_response` call sites (cache-hit re-check,
        // post-upstream, stale fallback) and the three
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
        // 1. AFTER the rewrite hook above. That hook `mem::replace`s
        //    `domain_buf`, so `domain` here can differ from the name
        //    evaluated pre-upstream — with SafeSearch on, several rewrites
        //    are populated and it routinely does. Every consumer below
        //    filters the post-rewrite name, so the policy must be keyed on
        //    the post-rewrite name too. Resolving it earlier reopens the
        //    same defect class on any deployment with a rewrite rule;
        //    pinned by `tests/integration_name_policy_once.rs`.
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

        // (The RRL check formerly here moved up next to the pre-query
        // security gate so blocked / local / unmapped-REFUSED responses
        // are rate-limited too. ACL and security refusals exit before it
        // — see the note at the hoist site.)

        // Cache lookup — single operation returning Fresh, Stale, or Miss.
        // `ecs_cache_prefix` partitions the lookup by ECS bucket when a
        // per-profile policy emits a non-anonymous option. `None` keeps
        // the wire/cache behaviour byte-identical to a build without ECS,
        // for every profile that opts out or stays on the anonymous form.
        // Keyed lookup — the returned key is reused by
        // `fetch_with_keyed_state` on the miss/stale path below, saving
        // one key construction + one cache probe per forwarded query.
        let (cache_key, cache_result) = cache
            .lookup_keyed(domain, record_type, dns_class, ecs_cache_prefix)
            .await;

        if let CacheLookup::Fresh(ref entry) = cache_result {
            // Re-run the post-fetch filter checks against the cached
            // records before serving them. Direct domain blocks are
            // already caught above (before this lookup), so the only race
            // window left is for CNAME-chain blocks (cached `D CNAME → C`
            // where `C` was added to a deny rule after the cache
            // populated) and IP-blocklist blocks (cached `D A 1.2.3.4`
            // where 1.2.3.4 was added to the IP blocklist after the cache
            // populated). On trip we invalidate the precise tuple, record
            // a BLOCKED outcome, and send the canned block response —
            // same shape as the post-upstream BLOCKED-via-CNAME /
            // BLOCKED-via-IP branches below. Cost on the happy path: at
            // most one CNAME walk + one IP HashSet probe per cache hit
            // (typically 1-3 records × O(1) lookups, sub-µs).
            //
            // `walk_response` returns a typed `Verdict` so the audit log +
            // Query Log enrichment can name `BlockSource` (list / rule /
            // admin_block / cname_loop / cname_depth_exceeded) without a
            // second filter probe at log time. By construction (the
            // `(None, _) | (Some(_), None)` REFUSED arms above) we only
            // reach this site with `resolved_profile = Some(profile)`;
            // the `if let` is defensive.
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
                        // The refreshed entry must pass the same
                        // IP-blocklist gate the serve paths run — without
                        // this, prefetch would skip it entirely.
                        let ip_filter = self.ip_filter.clone();
                        // Rewrite-aware upstream Name via the shared
                        // `fwd_name_for` helper — one definition for the
                        // prefetch + forward paths (see its doc for the
                        // coherence rule).
                        let fwd_name = fwd_name_for(domain, rewrote_from.is_some(), name);
                        let domain_owned = CompactString::new(domain);
                        // Capture the per-query ECS bundle for the spawned
                        // refresh — the prefetched answer must land in the
                        // same cache bucket the client queried, otherwise
                        // the refresh would populate a sibling slot the
                        // client never sees.
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
                                    // Bound the CNAME inspection to
                                    // cname_max_depth — symmetry with the
                                    // request path's own CNAME check.
                                    // Shares the unified
                                    // `cname_chain_blocked` walker; the
                                    // prefetch task has no per-client
                                    // profile context (the refreshed entry
                                    // is shared cache, not per-client), so
                                    // the closure consults
                                    // `filter.is_blocked` directly.
                                    let has_blocked_cname =
                                        cname_chain_blocked(&resp.records, cname_max_depth, |t| {
                                            filter.is_blocked(t)
                                        })
                                        .is_some();
                                    // IP-blocklist parity with the
                                    // cache-hit / post-upstream / stale
                                    // guards.
                                    //
                                    // Uses `NamePolicy::Neutral`, not the
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
                                        // Prefetch is the path that most
                                        // benefits from move-into-insert —
                                        // `resp.records` is built by the
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
        // vector that RRL only dampens. This is standard practice among
        // modern resolver implementations.
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

        // Per-(client, base) tunneling rate, counted on the cache-MISS
        // path only. Counting cache hits too would draw down one shared
        // per-base budget across cache hits and every LAN client — a
        // burst of 50 aggregate queries/min to one popular base domain
        // would REFUSE it network-wide. Tunneling fan-out is inherently
        // cache-missing unique names; hits prove repetition. Stale
        // entries also skip the bump (a stale name was cached before —
        // repetition, not fan-out).
        //
        // The PTR exemption is scoped to the reverse zones by
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

        // Forward via cache.lookup_or_fetch — moka's try_get_with
        // collapses N concurrent fetches for the same key into 1 upstream
        // call (singleflight). The closure carries the SOA-min hint out
        // for negative-response TTL math, and returns Err(Uncacheable)
        // for SERVFAIL/Refused so try_get_with skips caching them (this
        // is structural, mirroring insert's own guard). FetchFailure
        // carries any pre-existing stale entry for upstream-failure
        // fallback — the previous local stale_entry capture moves into
        // lookup_or_fetch.
        //
        // Cost on the cache MISS path: +1 Name clone + 1 CompactString
        // alloc + 1 Arc<dyn Upstream> atomic increment for the closure
        // capture; moka's try_get_with adds an internal hashmap probe on
        // the singleflight registry. Cache HIT path is untouched (the
        // lookup() above short-circuits before we reach this code). The
        // win on a concurrent uncached burst (cert renewal, social-login
        // storm) is N→1 upstream RTTs.
        //
        // Rewrite-aware upstream Name via the shared `fwd_name_for`
        // helper — one definition for the prefetch + forward paths (see
        // its doc for the coherence rule).
        let fwd_name = fwd_name_for(domain, rewrote_from.is_some(), name);
        let upstream_for_closure = Arc::clone(upstream);
        let fwd_name_for_closure = fwd_name.clone();
        let domain_for_closure = CompactString::new(domain);

        // Audit emit on ECS injection. Fires once per upstream-bound
        // query (cache MISS path) when the resolved policy contributes an
        // option; cache HIT path skips because the on-the-wire option is
        // what we already cached. Lives at `target = "audit"`, level
        // `debug`: the volume can be high (one emit per upstream RTT) so
        // info is too loud, but operators who flip `RUST_LOG=audit=debug`
        // see every record exactly. Frozen-string format pinned by
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
        // Reaching this site means the keyed lookup above returned Stale
        // or Miss (Fresh returned early). Hand the already-built key +
        // the stale entry (upstream-failure fallback) to the singleflight
        // fetch — no re-probe, no second key build.
        let stale_prior = match cache_result {
            CacheLookup::Stale(entry) => Some(entry),
            _ => None,
        };
        let lookup_result = cache
            // ECS-bucket cache key dimension. The singleflight fetcher
            // closure also gets the per-query ECS option so the upstream
            // sees the right `OPT` record.
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
        // CNAME / IP filter trips below we ALSO record a BLOCKED outcome —
        // the double-count for forwards-attempted vs forwards-blocked is
        // deliberate.
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
                // The BLOCKED response must echo the Question section's
                // qname, not the post-rewrite target stored in `fwd_name`.
                // Mirrors the cache-hit branches above, which build the
                // same `Name::from(name.clone())`. Hoisted here so both
                // the CNAME-block and IP-block early-return branches below
                // pick it up without duplicating the construction.
                let qname = Name::from(name.clone());
                // Post-fetch filter checks on the freshly-cached entry.
                // Mirrors the filter-on-cache-hit guard at the CACHE HIT
                // branch above — running both means we block on the FIRST
                // request when the rule pre-existed (this site) AND on
                // subsequent requests when the cache populated before the
                // rule was added (cache-hit site). Negative responses
                // (empty records) skip — nothing to filter.
                //
                // KNOWN ASYMMETRY, deliberately left in place — do not
                // "tidy" it in either direction without reading this.
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
                // So: can a BLOCKED response escape via the cache or stale
                // branch? **No** — a guard is a *skip*, so the two
                // unguarded sites check strictly more. What can escape is
                // the *guarded* site, which is the opposite of adding this
                // same guard to the other two — that would widen the skip
                // to the only places these entries are inspected at all.
                //
                // Narrowing it to `!is_empty()` is the right fix, and is NOT
                // applied here because it is a **wire-visible** change — the
                // first query would start returning the canned block response
                // instead of NXDOMAIN — and the site sits inside the
                // post-upstream-fetch branch, unreachable from any current test
                // harness (`CacheEntry::for_test` is
                // `cfg(all(test, feature = "dnssec"))` and only reaches
                // `send_cached`). Shipping an untested wire change to satisfy a
                // minor style nit is the wrong trade. Whoever takes it needs a
                // handler harness that can drive a post-fetch entry.
                if !entry.records().is_empty() && entry.response_code() == ResponseCode::NoError {
                    // Post-upstream chain inspection, mirror of the
                    // cache-hit re-check above. Same defensive
                    // `if let Some(profile)` for parity (the REFUSED
                    // early-return above guarantees `Some` at this site).
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
                    // Forward SERVFAIL/Refused without caching. Takes only
                    // this exit when the closure flagged the response as
                    // non-cacheable.
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
                    // Network-layer failure — serve stale fallback if any.
                    // Otherwise surface the inner error message; we cannot
                    // Clone the typed variant out of the Arc, so we wrap
                    // into UpstreamRequestFailed for downstream
                    // classification.
                    if let Some(entry) = stale {
                        // Re-run the same CNAME-chain + IP-blocklist
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

/// Invalidate the cache slot for the exact (domain, qtype, class,
/// ecs_prefix) tuple the current request was served from. Wraps
/// [`DnsCache::invalidate_key`] solely to force every call site to pass an
/// `ecs_cache_prefix` arg explicitly (no `None` short-circuit) — without
/// it, a post-block invalidate site could pass literal `None` while an
/// ECS-bucketed entry sat in `Some(prefix)`, leaving the stale slot live
/// until natural TTL.
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
/// After a rewrite, the cached records are owned by the rewrite
/// **target**, while the response's Question section still carries the original
/// qname. Served as-is that answer is dangling: glibc's stub (`getanswer()` in
/// `resolv/nss_dns/dns-host.c`) walks the CNAME chain outward from the question
/// name and discards every RR whose owner it never reaches, so `getaddrinfo`
/// returns *no addresses*. `dig` prints such a packet happily with exit 0, which
/// is why this kind of bug can hide behind a manual check.
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

/// Send a cached DNS response with TTL adjusted to remaining freshness.
///
/// Cached negative responses (NXDOMAIN or NODATA) include a synthesized
/// SOA in the authority section per RFC 2308 §3, mirroring the
/// fresh-blocked NODATA path. The SOA's minimum TTL drives downstream
/// resolver negative-cache duration, so omitting it caused intermediaries
/// to fall back to defaults instead of honoring the operator's
/// `negative_ttl` floor. The SOA is synthesized via
/// `blocked_soa(remaining_ttl)` because the upstream's authority section
/// is not preserved in `CacheEntry` — sufficient for negative-cache TTL
/// signaling; carrying the original SOA verbatim would be a future
/// improvement.
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
    // The AD bit is *ours* — set deliberately from our own verdict,
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
/// Used by the per-profile `block_response = "nxdomain"` path. Stub
/// resolvers cache the
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
/// The A/AAAA symmetric block invariant holds here too: regardless of the
/// variant, the response is built from `record_type` without consulting
/// the filter decision, so
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
/// SOA. Re-running `Name::from_ascii(...).unwrap()` on each blocked
/// response would contradict the zero-allocation hot-path discipline at
/// thousands of blocks/min. `Name`'s internal labels are Arc-backed, so
/// `.clone()` is a refcount bump.
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

/// Combined per-device overlay + profile evaluator.
///
/// When the resolved client carries a non-empty
/// [`crate::profiles::DeviceOverlay`], two `HashSet::contains` probes
/// feed [`apply_overlay`] for a 9-row allow/deny/fall-through decision;
/// on `OverlayDecision::FallThrough` the existing profile evaluator runs
/// unchanged.
///
/// `overlay = None` (the common case for devices that haven't pinned
/// any per-device exception, plus anonymous sources at the lower
/// resolution levels) short-circuits to `filter.evaluate(domain,
/// profile)` — byte-identical to the no-overlay behaviour.
///
/// **Attribution side-effect:** this is the natural seat for
/// [`crate::tracking::RuleSource`] computation. The attribution is
/// logged at `tracing::debug!`; wiring it into the query log +
/// per-device stats is future work for whoever extends the wire
/// format. Computing it here keeps the layer mapping in one place.
///
/// **Invariant:** the `DeviceOverlay` allow / deny sets key on domain
/// only — qtype is not consulted at this layer. The hot path therefore
/// returns the same Block/Forward verdict for `A` and `AAAA` of the
/// same name; the overlay is qtype-agnostic by construction.
///
/// Return is `(bool, Option<BlockSource>)` rather than a bare `bool` so
/// the BLOCKED-outcome stats path can pin a per-list bit when the block
/// is attributable to a single Tier 1 blocklist hit. The overlay-Block
/// branch returns `Some(BlockSource::AdminBlock)` because per-device
/// deny is admin-grade. The fall-through profile path defers to
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

/// Walk the CNAME records in a response, applying `is_blocked` to each
/// target. Shared by the request path and the background prefetch
/// worker (`prefetch_worker::refresh_one`), which reuses it to mirror
/// the same CNAME safety check on proactively-refreshed entries.
///
/// Stops after `cname_max_depth` CNAME records to prevent runaway chains.
/// Returns the first blocked target, if any.
///
/// The closure pattern lets the prefetch path and the request path share
/// the walking + parsing logic while supplying their own per-target
/// predicate — the request-path predicate resolves the client's profile
/// once, before the call, rather than re-resolving it on every CNAME hop.
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
mod tests;
