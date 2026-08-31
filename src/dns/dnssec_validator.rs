//! DNSSEC response-path consumer (§4.10-4b) — the `dnssec.mode` wiring.
//!
//! This is the **only client-visible** piece of the §4.10 workstream. It bolts
//! the frozen validation engine in [`crate::dnssec`] onto the live response path:
//! for a positive answer about to be served it produces one [`crate::dns::dnssec_validator::DnssecDecision`]
//! (set the AD bit / SERVFAIL / serve unchanged), behind the `dnssec.mode`
//! config.
//!
//! ## Where it runs
//!
//! [`crate::dns::handler::ForwardHandler`] holds an `Option<Arc<DnssecValidator>>`
//! — `Some` only when `dnssec.mode != Off`. The handler's response convergence
//! point (`send_cached`) calls [`crate::dns::dnssec_validator::DnssecValidator::decide`] for genuine answers
//! and maps the verdict onto the wire. `Off` / the default (feature-off) build
//! never construct a validator, so they pay nothing and stay byte-identical.
//!
//! ## How it validates
//!
//! The client-facing upstream is `dnssec_ok = false`, so the answer we cache and
//! serve carries **no** RRSIG. The validator therefore fetches its **own** signed
//! copy of the queried name through a separate DO-enabled upstream
//! ([`crate::dnssec::fetcher::UpstreamChainFetcher`]), derives the signed zone apex from the answer's
//! RRSIG `signer_name`, and walks the chain of trust with the frozen
//! [`crate::dnssec::chain::validate_chain`]. A [`crate::dnssec::cache::VerdictCache`] absorbs repeats so only the first query
//! for a name pays the walk.
//!
//! ## Policy (decided §4.10-4b, see the sprint plan)
//!
//! - `Secure` → set AD. `Insecure` (incl. an unsigned answer with no RRSIG) →
//!   serve, no AD. `Bogus` → SERVFAIL under `validate`.
//! - `Indeterminate` is **soft-split** under `validate`: the transient subset
//!   ([`crate::dnssec::chain::Indeterminate::FetchFailed`] / [`crate::dnssec::chain::Indeterminate::NoAnchorMatch`]) serves
//!   without AD (validator-upstream flakiness must not become a client outage —
//!   it degrades to *unvalidated*, never to *trusting forgery*); the structural
//!   subset (DoS-cap trips + [`crate::dnssec::chain::Indeterminate::DenialProofRequired`]) → SERVFAIL.
//! - `log-only` **never alters the wire** (no AD, no SERVFAIL): it validates and
//!   logs only, a true dry-run for staged rollout.
//! - A client query with the **CD** bit set bypasses validation entirely and
//!   never gets AD (RFC 4035 §3.2.2). (Distinct from the *upstream*-facing CD bit
//!   §4.10-4a bakes into the validator's own queries.)
//!
//! Known limitations recorded as follow-up TODOs: the served bytes come from the
//! resolution path, not the (separately fetched) validated bytes; a stripped-
//! signature answer downgrades to unvalidated; negative answers and CNAME-chain
//! links are not authenticated. See the sprint plan / TODO backlog.

use std::sync::Arc;

use hickory_proto::rr::{Name, RecordType};
use hickory_server::server::Request;

use crate::config::settings::{DnssecConfig, DnssecMode};
use crate::dnssec::{
    validate_chain, ChainFetcher, ChainResult, Indeterminate, InsecureReason, RootTrustAnchors,
    UpstreamChainFetcher, VerdictCache,
};
use crate::upstream::Upstream;

/// What the response path should do with one answer, per the validation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecDecision {
    /// Serve the answer unchanged, with the AD bit cleared (not authenticated).
    Serve,
    /// Serve the answer with the AD bit set (authenticated).
    SetAd,
    /// Replace the answer with SERVFAIL (bogus / unvalidatable under `validate`).
    Servfail,
}

/// Response-path DNSSEC validator. Cheap to clone-share via `Arc`; built once at
/// daemon boot only when `dnssec.mode != Off`.
pub struct DnssecValidator {
    /// DO-enabled fetcher (its upstream was built `dnssec_ok = true`).
    fetcher: UpstreamChainFetcher,
    /// Embedded IANA root trust anchors.
    anchors: RootTrustAnchors,
    /// Per-(name, type) verdict cache so repeats skip the chain walk.
    cache: VerdictCache,
    /// Validation mode + DoS caps.
    cfg: DnssecConfig,
}

impl DnssecValidator {
    /// Build a validator over a DO-enabled upstream. The caller is responsible
    /// for having built `do_upstream` with `dnssec_ok = true`
    /// ([`crate::upstream::resolver::UpstreamResolver::from_config_validator`]).
    #[must_use]
    pub fn new(do_upstream: Arc<dyn Upstream>, cfg: &DnssecConfig) -> Self {
        Self {
            fetcher: UpstreamChainFetcher::new(do_upstream),
            anchors: RootTrustAnchors::iana(),
            cache: VerdictCache::new(cfg),
            cfg: cfg.clone(),
        }
    }

    /// Decide what to do with one positive answer. Off the hot path: may perform
    /// a chain walk (upstream fetches) on a cache miss, so it `.await`s — but
    /// each query is its own task, so this never serialises other queries.
    ///
    /// `is_negative` is the cached entry's negativity (NXDOMAIN / NODATA); we do
    /// not authenticate denial of existence yet, so negatives are served as-is.
    ///
    /// `rewrote` is `true` when a §4.12 / §4.53 rewrite fired on this query.
    pub async fn decide(
        &self,
        request: &Request,
        is_negative: bool,
        rewrote: bool,
    ) -> DnssecDecision {
        // Client CD bit (RFC 4035 §3.2.2): the client asked us not to validate.
        // Bypass entirely — no fetch, no walk, and never assert AD.
        if request.metadata.checking_disabled {
            return DnssecDecision::Serve;
        }
        // A rewrite fired: skip validation outright, before the fetch.
        //
        // `dnssec-validator-validates-unserved-name` — this used to walk the
        // chain and the *handler* discarded the result. Two things were wrong
        // with that, and only the second is a cost:
        //
        // 1. **The walk was of the wrong name.** The target came from
        //    `request.queries().first()`, i.e. the ORIGINAL pre-rewrite qname,
        //    while the records being served belong to the rewrite target. So
        //    the verdict — and the log line carrying it — described a name
        //    warden was not serving. A diagnostic that names the wrong zone is
        //    worse than no diagnostic, which is why "keep validating, the
        //    signal is still useful" was rejected as the third option.
        // 2. **No verdict is actionable here anyway.** AD is impossible: the
        //    answer is fronted by a CNAME *we* synthesized, unsigned by
        //    construction. SERVFAIL is wrong: a rewrite is operator policy,
        //    and failing closed would turn one Bogus verdict into a
        //    network-wide outage of `safe_search`. With both wire outcomes
        //    excluded, computing a verdict is pure cost — a full chain walk,
        //    with its upstream fetches, per rewritten query.
        //
        // Validating the rewrite *target* instead was the other candidate. It
        // fixes the wrong-name half but not the actionable half: the verdict
        // would still be discarded, for the same two reasons. So the walk goes.
        //
        // Logged at debug so the operator can see validation was skipped
        // rather than silently finding no verdict lines for these names.
        if rewrote {
            tracing::debug!(
                "DNSSEC validation skipped: a rewrite fired, so the served \
                 records belong to a name the client did not ask for and no \
                 verdict could be acted on"
            );
            return DnssecDecision::Serve;
        }
        // Negative answers: denial-of-existence authentication is out of §4.10-4b
        // scope (the engine has no leaf-NXDOMAIN entry point). Serve, no AD.
        if is_negative {
            return DnssecDecision::Serve;
        }
        let Some(query) = request.queries.queries().first() else {
            return DnssecDecision::Serve;
        };
        let name = Name::from(query.name().clone());
        let rtype = query.query_type();

        let verdict = self.classify(&name, rtype).await;
        self.log_verdict(&name, rtype, verdict);
        map_verdict(verdict, self.cfg.mode)
    }

    /// Pre-seed the verdict cache so a caller can drive [`Self::decide`] to a
    /// chosen `ChainResult` without a signed chain fetch. Test scaffolding: the
    /// only way an integration test can assert what the wire looks like for a
    /// `Secure` or `Bogus` verdict, since the real path needs a live DO upstream
    /// serving RRSIGs that chain to the IANA root anchors.
    ///
    /// Not `#[cfg(test)]`: integration tests compile against the library without
    /// `cfg(test)` set. Hidden from the docs instead.
    #[doc(hidden)]
    pub async fn seed_verdict(&self, name: &Name, rtype: RecordType, verdict: ChainResult) {
        self.cache.insert(name, rtype, verdict).await;
    }

    /// The cached-or-fresh verdict for a name. A cache hit skips the walk; a
    /// fresh stable verdict is cached (transient `Indeterminate` is not — caching
    /// it would extend a transient outage for `cache_ttl_secs`).
    async fn classify(&self, name: &Name, rtype: RecordType) -> ChainResult {
        if let Some(verdict) = self.cache.get(name, rtype).await {
            return verdict;
        }
        let verdict = self.walk(name, rtype).await;
        if is_cacheable(verdict) {
            self.cache.insert(name, rtype, verdict).await;
        }
        verdict
    }

    /// Fetch the signed answer via the DO upstream, then walk the chain of trust.
    async fn walk(&self, name: &Name, rtype: RecordType) -> ChainResult {
        let fetched = match self.fetcher.fetch(name, rtype).await {
            Ok(fetched) => fetched,
            // A transport / SERVFAIL failure of *our* fetch is not a verdict.
            Err(_) => return ChainResult::Indeterminate(Indeterminate::FetchFailed),
        };
        match fetched.rrsigs.first() {
            // The signed zone apex is the RRSIG's signer name, not the query name
            // (e.g. `www.x.org` is signed by `x.org`).
            Some(rrsig) => {
                validate_chain(
                    &self.fetcher,
                    &self.anchors,
                    &rrsig.input().signer_name,
                    Some((fetched.records.as_slice(), rrsig)),
                    now_unix_secs(),
                    &self.cfg,
                )
                .await
            }
            // No RRSIG on the DO answer: the answer is unsigned. Serve it without
            // AD (treated as Insecure). A stripped-signature downgrade is a
            // documented limitation — it degrades to unvalidated, never forged.
            None => ChainResult::Insecure(InsecureReason::UnsignedDelegation),
        }
    }

    /// Emit the verdict to the log (both `validate` and `log-only`). The level is
    /// chosen by [`log_level`]; the full verdict rides in a structured field.
    /// `tracing` levels are compile-time, so we branch on the computed level to
    /// reach the matching macro.
    fn log_verdict(&self, name: &Name, rtype: RecordType, verdict: ChainResult) {
        match log_level(verdict) {
            tracing::Level::WARN => tracing::warn!(
                %name, ?rtype, ?verdict, mode = %self.cfg.mode, "DNSSEC validation alarm"
            ),
            _ => tracing::debug!(%name, ?rtype, ?verdict, "DNSSEC validation"),
        }
    }
}

/// Whether an `Indeterminate` is a *transient* "could not obtain material"
/// failure (serve, no AD) versus a *structural* deterministic / abusive one
/// (SERVFAIL under `validate`). Single source of truth for the **serve-vs-SERVFAIL**
/// split — shared by [`map_verdict`] and [`log_level`] so they cannot drift.
fn is_transient(reason: Indeterminate) -> bool {
    matches!(
        reason,
        Indeterminate::FetchFailed | Indeterminate::NoAnchorMatch
    )
}

/// The tracing level for a verdict's log line. Pure + total so it is unit-testable
/// without a tracing subscriber, and the single source of truth `log_verdict` emits
/// at. Deliberately **decoupled** from [`is_transient`] (the serve-vs-SERVFAIL
/// predicate): a verdict can serve yet still warrant an operational alarm.
fn log_level(verdict: ChainResult) -> tracing::Level {
    match verdict {
        ChainResult::Bogus(_) => tracing::Level::WARN,
        // NoAnchorMatch warns even though `is_transient` lets it SERVE (so
        // `map_verdict` does NOT SERVFAIL it). Blast radius is total: while the
        // embedded anchors match no root DNSKEY, NO name can validate — DNSSEC is
        // silently OFF (stale anchors after a KSK rollover, or an upstream serving
        // a foreign root key). Failing open is deliberate: the anchors are static
        // (no RFC 5011 auto-update), so failing closed would blackhole ALL DNS for
        // every client on a legitimate rollover. WARN is therefore the ONLY way the
        // operator learns validation has stopped — it must not be buried at DEBUG
        // alongside the benign transient FetchFailed.
        ChainResult::Indeterminate(Indeterminate::NoAnchorMatch) => tracing::Level::WARN,
        // Structural Indeterminate (DoS-cap trips, DenialProofRequired): fail closed
        // → SERVFAIL in `map_verdict`, WARN here.
        ChainResult::Indeterminate(reason) if !is_transient(reason) => tracing::Level::WARN,
        // Benign transient (FetchFailed): a validator-upstream blip — served and
        // retried next query, not an alarm → DEBUG.
        ChainResult::Indeterminate(_) => tracing::Level::DEBUG,
        // Success / no-op outcomes are not alarms.
        ChainResult::Secure | ChainResult::Insecure(_) => tracing::Level::DEBUG,
    }
}

/// Whether a verdict is stable enough to cache. Only `Indeterminate` (all
/// variants) is excluded: it means "validation could not complete", and some
/// variants are transient — caching one would extend a transient outage.
fn is_cacheable(verdict: ChainResult) -> bool {
    !matches!(verdict, ChainResult::Indeterminate(_))
}

/// Map a chain verdict + mode to the wire decision. Pure — exhaustively tested.
fn map_verdict(verdict: ChainResult, mode: DnssecMode) -> DnssecDecision {
    match mode {
        // `log-only` never touches the wire: validate + log only.
        DnssecMode::LogOnly => DnssecDecision::Serve,
        // Defensive: a validator is only built when mode != Off, so this is
        // unreachable in practice. Serve unchanged rather than assert.
        DnssecMode::Off => DnssecDecision::Serve,
        DnssecMode::Validate => match verdict {
            ChainResult::Secure => DnssecDecision::SetAd,
            ChainResult::Insecure(_) => DnssecDecision::Serve,
            ChainResult::Bogus(_) => DnssecDecision::Servfail,
            ChainResult::Indeterminate(reason) => {
                if is_transient(reason) {
                    DnssecDecision::Serve
                } else {
                    DnssecDecision::Servfail
                }
            }
        },
    }
}

/// The validator's clock in Unix seconds, injected into [`crate::dnssec::chain::validate_chain`] for
/// RRSIG inception/expiration checks. Non-panicking: a pre-epoch clock is
/// impossible on real hardware, but we degrade to 0 rather than abort the task.
fn now_unix_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use hickory_net::xfer::Protocol;
    use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
    use hickory_proto::dnssec::Algorithm;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};

    use crate::dns::edns::EdnsClientSubnet;
    use crate::dns::error::DnsError;
    use crate::dnssec::ChainBogus;
    use crate::upstream::UpstreamResponse;

    // ── Test doubles ──────────────────────────────────────────────────────────

    /// Canned upstream that counts how many times it was queried (to assert the
    /// cache short-circuit and the CD bypass never hit the network).
    struct CountingUpstream {
        records: Vec<Record>,
        response_code: ResponseCode,
        fail: bool,
        calls: Arc<AtomicUsize>,
    }

    impl CountingUpstream {
        fn new(records: Vec<Record>) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    records,
                    response_code: ResponseCode::NoError,
                    fail: false,
                    calls: calls.clone(),
                },
                calls,
            )
        }

        fn failing() -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    records: vec![],
                    response_code: ResponseCode::NoError,
                    fail: true,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    #[async_trait]
    impl Upstream for CountingUpstream {
        async fn lookup(
            &self,
            _name: &Name,
            _record_type: RecordType,
            _ecs: Option<EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(DnsError::AllUpstreamsFailed);
            }
            Ok(UpstreamResponse {
                records: self.records.clone(),
                response_code: self.response_code,
                soa_minimum_ttl: None,
                authority: vec![],
            })
        }
    }

    fn a_record(name: &str) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        )
    }

    /// A throwaway RRSIG over `name` signed by `signer` — the bytes never verify,
    /// but it lets us reach the `validate_chain` path (which then fails the walk
    /// against the canned upstream, exercising the Bogus/Indeterminate mapping).
    #[allow(clippy::too_many_arguments)]
    fn rrsig_new(
        type_covered: RecordType,
        algorithm: Algorithm,
        num_labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: Name,
        sig: Vec<u8>,
    ) -> RRSIG {
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::rr::SerialNumber;
        RRSIG::from_sig(
            SigInput {
                type_covered,
                algorithm,
                num_labels,
                original_ttl,
                sig_expiration: SerialNumber::new(sig_expiration),
                sig_inception: SerialNumber::new(sig_inception),
                key_tag,
                signer_name,
            },
            sig,
        )
    }

    fn rrsig_record(name: &str, signer: &str) -> Record {
        let rrsig = rrsig_new(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            2,
            300,
            2_000_000_000,
            1_000_000_000,
            1234,
            signer.parse().unwrap(),
            vec![0u8; 8],
        );
        Record::from_rdata(
            name.parse().unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        )
    }

    fn validator(upstream: CountingUpstream, mode: DnssecMode) -> DnssecValidator {
        let mut cfg = DnssecConfig {
            mode,
            ..DnssecConfig::default()
        };
        // Short TTL is irrelevant here; default is fine. Keep caps default.
        cfg.cache_ttl_secs = 3600;
        DnssecValidator::new(Arc::new(upstream), &cfg)
    }

    fn query_request(name: &str, rtype: RecordType, cd: bool) -> Request {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.checking_disabled = cd;
        msg.add_query(Query::query(name.parse().unwrap(), rtype));
        let bytes = msg.to_vec().unwrap();
        Request::from_bytes(bytes, "127.0.0.1:53".parse().unwrap(), Protocol::Udp).unwrap()
    }

    // ── Pure mapping: the policy table ──────────────────────────────────────────

    #[test]
    fn map_verdict_validate_table() {
        use ChainResult::{Bogus, Insecure, Secure};
        let v = DnssecMode::Validate;
        assert_eq!(map_verdict(Secure, v), DnssecDecision::SetAd);
        assert_eq!(
            map_verdict(Insecure(InsecureReason::UnsignedDelegation), v),
            DnssecDecision::Serve
        );
        assert_eq!(
            map_verdict(Insecure(InsecureReason::OutOfScopeAlgorithm), v),
            DnssecDecision::Serve
        );
        assert_eq!(
            map_verdict(Bogus(ChainBogus::DsCoversNoKey), v),
            DnssecDecision::Servfail
        );
        // Transient Indeterminate → serve (availability).
        assert_eq!(
            map_verdict(ChainResult::Indeterminate(Indeterminate::FetchFailed), v),
            DnssecDecision::Serve
        );
        assert_eq!(
            map_verdict(ChainResult::Indeterminate(Indeterminate::NoAnchorMatch), v),
            DnssecDecision::Serve
        );
        // Structural Indeterminate → SERVFAIL (fail closed).
        for reason in [
            Indeterminate::MaxChainDepthExceeded,
            Indeterminate::MaxQueriesExceeded,
            Indeterminate::MaxNsec3IterationsExceeded,
            Indeterminate::MaxSignatureVerificationsExceeded,
            Indeterminate::DenialProofRequired,
        ] {
            assert_eq!(
                map_verdict(ChainResult::Indeterminate(reason), v),
                DnssecDecision::Servfail,
                "{reason:?} must SERVFAIL under validate"
            );
        }
    }

    #[test]
    fn map_verdict_log_only_never_alters() {
        use ChainResult::{Bogus, Insecure, Secure};
        let m = DnssecMode::LogOnly;
        // Every verdict serves unchanged under log-only — no AD, no SERVFAIL.
        for verdict in [
            Secure,
            Insecure(InsecureReason::UnsignedDelegation),
            Bogus(ChainBogus::DsCoversNoKey),
            ChainResult::Indeterminate(Indeterminate::FetchFailed),
            ChainResult::Indeterminate(Indeterminate::DenialProofRequired),
            ChainResult::Indeterminate(Indeterminate::MaxQueriesExceeded),
            ChainResult::Indeterminate(Indeterminate::MaxSignatureVerificationsExceeded),
        ] {
            assert_eq!(
                map_verdict(verdict, m),
                DnssecDecision::Serve,
                "{verdict:?} must serve unchanged under log-only"
            );
        }
    }

    #[test]
    fn log_level_decouples_alarm_from_serve_decision() {
        use tracing::Level;
        let na = ChainResult::Indeterminate(Indeterminate::NoAnchorMatch);
        let ff = ChainResult::Indeterminate(Indeterminate::FetchFailed);
        // Both SERVE (fail-open) under validate — the wire decision is identical …
        assert_eq!(map_verdict(na, DnssecMode::Validate), DnssecDecision::Serve);
        assert_eq!(map_verdict(ff, DnssecMode::Validate), DnssecDecision::Serve);
        // … but their LOG LEVELS diverge: a root-anchor mismatch silently disables
        // all validation (WARN, operator alarm); a fetch blip is benign (DEBUG).
        assert_eq!(log_level(na), Level::WARN);
        assert_eq!(log_level(ff), Level::DEBUG);
        // Structural Indeterminate and Bogus also warn.
        assert_eq!(
            log_level(ChainResult::Indeterminate(
                Indeterminate::MaxSignatureVerificationsExceeded
            )),
            Level::WARN
        );
        assert_eq!(
            log_level(ChainResult::Bogus(ChainBogus::DsCoversNoKey)),
            Level::WARN
        );
        // Success / no-op outcomes stay quiet.
        assert_eq!(log_level(ChainResult::Secure), Level::DEBUG);
        assert_eq!(
            log_level(ChainResult::Insecure(InsecureReason::UnsignedDelegation)),
            Level::DEBUG
        );
    }

    #[test]
    fn is_cacheable_excludes_all_indeterminate() {
        use ChainResult::{Bogus, Insecure, Secure};
        assert!(is_cacheable(Secure));
        assert!(is_cacheable(Insecure(InsecureReason::UnsignedDelegation)));
        assert!(is_cacheable(Bogus(ChainBogus::DnskeyMissing)));
        for reason in [
            Indeterminate::MaxChainDepthExceeded,
            Indeterminate::MaxQueriesExceeded,
            Indeterminate::MaxNsec3IterationsExceeded,
            Indeterminate::MaxSignatureVerificationsExceeded,
            Indeterminate::DenialProofRequired,
            Indeterminate::FetchFailed,
            Indeterminate::NoAnchorMatch,
        ] {
            assert!(
                !is_cacheable(ChainResult::Indeterminate(reason)),
                "{reason:?} must not be cached"
            );
        }
    }

    // ── decide(): bypasses ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn client_cd_bypasses_validation() {
        let (up, calls) = CountingUpstream::new(vec![a_record("example.com.")]);
        let v = validator(up, DnssecMode::Validate);
        let req = query_request("example.com.", RecordType::A, true);
        assert_eq!(v.decide(&req, false, false).await, DnssecDecision::Serve);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "CD must skip the fetch");
    }

    /// `dnssec-validator-validates-unserved-name`: a rewritten answer must skip
    /// validation entirely — no fetch, no chain walk, no verdict.
    ///
    /// The two arms differ **only** in the `rewrote` flag, and the assertion is
    /// on the fetch counter rather than on the returned decision. That matters:
    /// both arms return `Serve` here (the mock upstream yields an unsigned
    /// answer, so the non-rewritten arm reaches `Insecure` → `Serve`), so a
    /// test that asserted on `DnssecDecision` alone would be green whether or
    /// not the short-circuit exists. The counter is the only thing that
    /// discriminates — it is the whole point of the change, which was to stop
    /// paying for a walk whose verdict is discarded.
    #[tokio::test]
    async fn a_rewritten_answer_skips_validation_without_fetching() {
        // Arm A — rewrite fired: the walk must not happen at all.
        let (up, calls) = CountingUpstream::new(vec![a_record("safe.example.")]);
        let v = validator(up, DnssecMode::Validate);
        let req = query_request("www.example.", RecordType::A, false);
        assert_eq!(
            v.decide(&req, false, true).await,
            DnssecDecision::Serve,
            "a rewritten answer is served, never AD and never SERVFAIL"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a rewrite must short-circuit BEFORE the DO fetch — this walked the \
             pre-rewrite qname and then threw the verdict away"
        );

        // Arm B — control: same request, same mock, rewrite NOT fired. The
        // fetch happens, which is what proves arm A's zero is the flag's doing
        // and not a broken harness.
        let (up2, calls2) = CountingUpstream::new(vec![a_record("www.example.")]);
        let v2 = validator(up2, DnssecMode::Validate);
        assert_eq!(v2.decide(&req, false, false).await, DnssecDecision::Serve);
        assert!(
            calls2.load(Ordering::SeqCst) > 0,
            "without a rewrite the validator must still fetch — otherwise arm A \
             proves nothing"
        );
    }

    #[tokio::test]
    async fn negative_answer_is_served_unvalidated() {
        let (up, calls) = CountingUpstream::new(vec![a_record("example.com.")]);
        let v = validator(up, DnssecMode::Validate);
        let req = query_request("example.com.", RecordType::A, false);
        assert_eq!(v.decide(&req, true, false).await, DnssecDecision::Serve);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "negatives skip the fetch");
    }

    // ── classify()/walk(): the fetch + verdict plumbing ─────────────────────────

    #[tokio::test]
    async fn unsigned_answer_no_rrsig_is_insecure_served() {
        // DO answer with an A record but no RRSIG → Insecure → serve, no AD.
        let (up, _) = CountingUpstream::new(vec![a_record("plain.example.")]);
        let v = validator(up, DnssecMode::Validate);
        let req = query_request("plain.example.", RecordType::A, false);
        assert_eq!(v.decide(&req, false, false).await, DnssecDecision::Serve);
    }

    #[tokio::test]
    async fn fetch_failure_is_transient_served_and_not_cached() {
        let (up, calls) = CountingUpstream::failing();
        let v = validator(up, DnssecMode::Validate);
        // Direct classify: transport failure → Indeterminate(FetchFailed).
        let name: Name = "down.example.".parse().unwrap();
        let first = v.classify(&name, RecordType::A).await;
        assert_eq!(
            first,
            ChainResult::Indeterminate(Indeterminate::FetchFailed)
        );
        // Mapped under validate → Serve (availability, not SERVFAIL).
        assert_eq!(
            map_verdict(first, DnssecMode::Validate),
            DnssecDecision::Serve
        );
        // Not cached: a second classify re-fetches (transient must not stick).
        let _ = v.classify(&name, RecordType::A).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "transient verdict must not be cached"
        );
    }

    #[tokio::test]
    async fn signed_answer_with_broken_chain_is_not_secure() {
        // An RRSIG is present (so we enter validate_chain) but the canned
        // upstream cannot supply a valid root→zone chain, so the walk cannot
        // reach Secure. It must be Bogus or Indeterminate — never Secure.
        let (up, _) = CountingUpstream::new(vec![
            a_record("signed.example."),
            rrsig_record("signed.example.", "signed.example."),
        ]);
        let v = validator(up, DnssecMode::Validate);
        let name: Name = "signed.example.".parse().unwrap();
        let verdict = v.classify(&name, RecordType::A).await;
        assert!(
            !matches!(verdict, ChainResult::Secure),
            "a broken chain must never validate Secure, got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn stable_verdict_is_cached_skipping_refetch() {
        // The no-RRSIG path yields Insecure (stable, cacheable). The second
        // decide() for the same name must hit the verdict cache → no re-fetch.
        let (up, calls) = CountingUpstream::new(vec![a_record("cacheme.example.")]);
        let v = validator(up, DnssecMode::Validate);
        let req = query_request("cacheme.example.", RecordType::A, false);
        assert_eq!(v.decide(&req, false, false).await, DnssecDecision::Serve);
        assert_eq!(v.decide(&req, false, false).await, DnssecDecision::Serve);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a cached stable verdict must skip the second fetch"
        );
    }
}
