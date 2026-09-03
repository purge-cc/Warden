//! Upstream DNS forwarding (plain, DoH, DoT).
//!
//! All upstream implementations share the [`Upstream`] trait. The
//! [`UpstreamResolver`] wraps a primary + optional fallback with circuit
//! breakers, providing the single entry point used by the DNS handler.

pub mod circuit;
pub mod doh;
/// DNS-over-QUIC upstream (RFC 9250). Feature-gated (`doq`, default OFF) — the
/// quinn QUIC stack adds binary size, so the default + Raspberry Pi builds
/// exclude it.
#[cfg(feature = "doq")]
pub mod doq;
pub mod dot;
pub mod forwarding;
pub mod plain;
pub mod plain_raw;
pub mod resolver;
/// Pure, I/O-free shape validation for upstream server strings, shared by the
/// transport constructors (boot) and `config lint`. See the module doc for
/// the offline syntax-vs-resolvability boundary.
pub mod shape;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand_core::RngCore;

use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

pub use resolver::UpstreamResolver;

// ── Upstream trait ─────────────────────────────────────────────

/// Common interface for all upstream DNS resolvers.
///
/// The `ecs` parameter carries the per-query EDNS Client Subnet option
/// derived from the resolved profile's
/// [`crate::profiles::profile::EcsPolicy`] and the client IP. `None`
/// emits zero EDNS extensions. There is no construct-time ECS knob —
/// `self.ecs` does not exist on any concrete upstream; the handler builds
/// the option once per query and threads it through.
#[async_trait::async_trait]
pub trait Upstream: Send + Sync {
    /// Resolve a DNS name. Returns records and response code.
    /// NXDOMAIN / NODATA are valid responses (not errors).
    /// Errors indicate transport failures (timeout, connection refused, etc.).
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError>;

    /// Resolve with the already-lowercased domain string available as a
    /// routing hint. Routers that dispatch by suffix (e.g.
    /// `ForwardingRouter`) can match zones against this `&str` without
    /// re-stringifying the `Name`. Leaf upstreams ignore the hint —
    /// the default impl drops it on the floor and calls `lookup`.
    async fn lookup_domain(
        &self,
        _domain: &str,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.lookup(name, record_type, ecs).await
    }
}

/// Response from an upstream DNS resolver.
#[derive(Debug)]
pub struct UpstreamResponse {
    pub records: Vec<Record>,
    pub response_code: ResponseCode,
    /// SOA-derived negative TTL hint from the authority section, per RFC 2308.
    /// `min(soa_record.ttl(), soa.minimum())` when an SOA is present — the
    /// cache uses this as a floor for negative-cache TTL. `None` for positive
    /// responses and for upstreams that didn't return an SOA.
    pub soa_minimum_ttl: Option<u32>,
    /// The response's authority (name-server) section, verbatim and
    /// heterogeneous (NSEC/NSEC3 + their RRSIGs + SOA, as on the wire). Retained
    /// only under the `dnssec` feature, where the DNSSEC [`ChainFetcher`] adapter
    /// consumes it for NSEC/NSEC3 no-DS denial-of-existence proofs. The
    /// default and Raspberry Pi builds never allocate it — the field does not
    /// exist there, so `parse_response_bytes` stays byte-identical to baseline.
    ///
    /// [`ChainFetcher`]: crate::dnssec::ChainFetcher
    #[cfg(feature = "dnssec")]
    pub authority: Vec<Record>,
}

// ── Wire format helpers ────────────────────────────────────────

/// Generate a DNS transaction ID from the OS CSPRNG.
///
/// RFC 5452 §9.2 requires transaction IDs be *unpredictable*: together with
/// source-port randomisation they are the entropy that resists off-path answer
/// forgery / cache poisoning on the plain-UDP path (`PlainRawClient`). A
/// sequential counter is fully predictable, so we draw from `OsRng` — the
/// project's mandated CSPRNG (CLAUDE.md "Common Pitfalls"; same source as
/// `auth::token`). Over reliable transports (DoT/DoH) the ID is cosmetic, and
/// DoQ overrides it to 0 (RFC 9250 §4.2.1); the cost is one draw per upstream
/// query, all off the cached hot path.
fn next_query_id() -> u16 {
    rand_core::OsRng.next_u32() as u16
}

/// Build a DNS query message in wire format, discarding the question.
///
/// Identical construction to [`build_query`] — see it for the EDNS, DO and CD
/// rules — for callers with no use for the echoed-question check.
pub fn build_query_bytes(
    name: &Name,
    record_type: RecordType,
    ecs: Option<EdnsClientSubnet>,
    dnssec_ok: bool,
) -> Result<Vec<u8>, DnsError> {
    build_query(name, record_type, ecs, dnssec_ok).map(|(bytes, _)| bytes)
}

/// Build a DNS query message in wire format, with the question it carries.
///
/// The query contains QNAME + QTYPE with RD (Recursion Desired) set. An EDNS
/// OPT record is emitted only when there is something to put in it: the EDNS
/// Client Subnet option (RFC 7871, when `ecs` is `Some`) and/or the DNSSEC OK
/// (DO) bit (RFC 3225, when `dnssec_ok`). When **neither** is requested no EDNS
/// extension is emitted at all — byte-identical to the baseline with neither
/// feature enabled.
///
/// `dnssec_ok` is a global construction-time policy on the validator's
/// upstream; the client-facing upstream always passes `false`. When set it also
/// turns on the **CD (Checking Disabled)** header bit and advertises a 1232-byte
/// EDNS buffer, because the validator does its own validation:
/// - **CD (RFC 4035 §3.2.2):** without it a *validating* upstream resolver
///   returns SERVFAIL for a bogus zone before we ever see the data — we could
///   then never reach our own `Bogus` verdict. CD lets the raw (even bogus)
///   signed records through for us to judge.
/// - **1232-byte buffer (RFC 6891 / DNS flag-day 2020):** DNSKEY/RRSIG sets
///   routinely exceed the 512-byte default; advertising 1232 keeps them on UDP
///   instead of forcing a TCP fallback for every chain fetch.
///
/// The returned question comes back out of the encoded message rather than
/// being rebuilt, so the two can never describe different queries — which is
/// what lets [`parse_response_bytes`] treat it as the authority on what was
/// asked. It is fully qualified: a name decoded from a response always is, and
/// [`Name`] equality treats the relative and absolute forms as different names,
/// so an unqualified caller name would make every response look forged.
pub fn build_query(
    name: &Name,
    record_type: RecordType,
    ecs: Option<EdnsClientSubnet>,
    dnssec_ok: bool,
) -> Result<(Vec<u8>, Query), DnsError> {
    // 0.26: Message::new() gained (id, message_type, op_code) params; the flag
    // setters were removed in favour of public Metadata fields.
    let mut msg = Message::new(next_query_id(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    if dnssec_ok {
        // We validate ourselves — tell the upstream not to (see fn docs).
        msg.metadata.checking_disabled = true;
    }
    msg.add_query(Query::query(name.clone(), record_type));
    if ecs.is_some() || dnssec_ok {
        let mut edns = Edns::new();
        if dnssec_ok {
            edns.set_dnssec_ok(true);
            edns.set_max_payload(1232);
        }
        if let Some(ecs) = ecs {
            edns.options_mut()
                .insert(EdnsOption::Subnet(ecs.into_proto()));
        }
        msg.set_edns(edns);
    }
    let bytes = msg
        .to_vec()
        .map_err(|e| DnsError::WireFormatError(e.to_string()))?;
    let mut question = msg.queries.pop().expect("the query added above");
    question.name.set_fqdn(true);
    Ok((bytes, question))
}

/// Parse a DNS response from wire format bytes into an UpstreamResponse.
///
/// `expected` is the question that was sent (see [`build_query`]); a
/// response that does not echo it is rejected instead of parsed, per RFC 5452
/// §9.1. Warden filters the name it *queried*, so records delivered under some
/// other question would reach the cache and the client without the filter
/// engine ever having evaluated their name.
///
/// Name comparison is case-insensitive (RFC 4343), which is what upstreams
/// applying 0x20 randomisation to the echoed QNAME depend on. A response with
/// no question section is rejected: there is nothing to match against, and
/// failing closed costs nothing against conforming upstreams. Only the first
/// question is examined — a second one carries no records, so it can smuggle
/// nothing past the check.
pub fn parse_response_bytes(data: &[u8], expected: &Query) -> Result<UpstreamResponse, DnsError> {
    let msg = Message::from_vec(data).map_err(|e| DnsError::WireFormatError(e.to_string()))?;
    match msg.queries.first() {
        Some(echoed) if question_echoes(echoed, expected) => {}
        Some(echoed) => {
            return Err(DnsError::WireFormatError(format!(
                "response question [{echoed}] does not match the query sent [{expected}]"
            )))
        }
        None => {
            return Err(DnsError::WireFormatError(format!(
                "response carries no question section (sent [{expected}])"
            )))
        }
    }
    Ok(UpstreamResponse {
        records: msg.answers.to_vec(),
        response_code: msg.metadata.response_code,
        soa_minimum_ttl: extract_soa_minimum_ttl(&msg.authorities),
        #[cfg(feature = "dnssec")]
        authority: msg.authorities.to_vec(),
    })
}

/// Whether `echoed` is the question in `expected`.
///
/// All three fields must match: an upstream that returns the right name under
/// a different QTYPE or QCLASS is answering a question we did not ask.
fn question_echoes(echoed: &Query, expected: &Query) -> bool {
    echoed.name() == expected.name()
        && echoed.query_type() == expected.query_type()
        && echoed.query_class() == expected.query_class()
}

/// Extract the SOA-derived negative-cache TTL hint from an authority section.
///
/// Mirrors `hickory_proto::xfer::DnsResponse::negative_ttl()`: finds the first
/// SOA record in the authority section and returns `min(record.ttl(), soa.minimum())`
/// per RFC 2308 §5. Returns `None` if no SOA is present.
fn extract_soa_minimum_ttl(authorities: &[Record]) -> Option<u32> {
    authorities
        .iter()
        .filter_map(|record| {
            // 0.26 dropped RData's as_soa()/as_*() accessors — pattern-match.
            let RData::SOA(soa) = &record.data else {
                return None;
            };
            Some(record.ttl.min(soa.minimum))
        })
        .next()
}

// ── Shared rustls client TLS setup ─────────────────────────────
//
// DoT (always compiled) and DoQ (feature `doq`) share ONE rustls client path
// so the tree never grows a second TLS-config setup: same ring crypto provider,
// same bundled webpki root store. DoT builds a plain `ClientConfig`; DoQ takes
// the same config and sets the `doq` ALPN on top (RFC 9250).

/// Ensure a rustls [`CryptoProvider`](rustls::crypto::CryptoProvider) is
/// installed process-wide. rustls 0.23+ requires one before any
/// `ClientConfig::builder()` call. reqwest installs one for DoH, but a
/// standalone DoT/DoQ upstream needs it too.
///
/// Checks global state first — if a provider is already installed this
/// no-ops (matches reqwest-installed-first or a repeat init); only the
/// genuinely unexpected install race after a None-check is logged at warn.
pub(crate) fn install_ring_crypto_provider_once() {
    match rustls::crypto::CryptoProvider::get_default() {
        None => {
            if rustls::crypto::ring::default_provider()
                .install_default()
                .is_err()
            {
                tracing::warn!(
                    "rustls CryptoProvider install race — another thread installed first; \
                     the existing provider will be used"
                );
            }
        }
        Some(_) => {
            tracing::debug!(
                "rustls CryptoProvider already installed; the existing provider will be used"
            );
        }
    }
}

/// Build the shared client root-certificate store from the bundled webpki roots
/// ([`webpki_roots::TLS_SERVER_ROOTS`]). Same trust anchors for DoT and DoQ.
pub(crate) fn webpki_root_store() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{DNSClass, RData, Record};

    fn make_soa_record(ttl: u32, minimum: u32) -> Record {
        let name: Name = "example.com.".parse().unwrap();
        let mname: Name = "ns1.example.com.".parse().unwrap();
        let rname: Name = "admin.example.com.".parse().unwrap();
        let soa = SOA::new(mname, rname, 2026041600, 3600, 600, 86400, minimum);
        Record::from_rdata(name, ttl, RData::SOA(soa))
    }

    #[test]
    fn extract_soa_returns_none_when_no_soa() {
        assert_eq!(extract_soa_minimum_ttl(&[]), None);
    }

    #[test]
    fn extract_soa_uses_record_ttl_when_smaller() {
        let rec = make_soa_record(300, 3600);
        // min(300, 3600) = 300
        assert_eq!(extract_soa_minimum_ttl(&[rec]), Some(300));
    }

    #[test]
    fn extract_soa_uses_minimum_field_when_smaller() {
        let rec = make_soa_record(3600, 600);
        // min(3600, 600) = 600
        assert_eq!(extract_soa_minimum_ttl(&[rec]), Some(600));
    }

    #[test]
    fn parse_response_bytes_captures_soa_from_nxdomain() {
        // Build a NXDOMAIN response with an SOA in the authority section.
        let mut msg = Message::new(42, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_query(Query::query(
            "nonexistent.example.com.".parse().unwrap(),
            RecordType::A,
        ));
        msg.add_authority(make_soa_record(900, 600));
        let bytes = msg.to_vec().unwrap();

        let expected = question_sent("nonexistent.example.com.", RecordType::A);
        let parsed = parse_response_bytes(&bytes, &expected).unwrap();
        assert_eq!(parsed.response_code, ResponseCode::NXDomain);
        assert!(parsed.records.is_empty());
        // min(900, 600) = 600
        assert_eq!(parsed.soa_minimum_ttl, Some(600));
    }

    #[test]
    fn parse_response_bytes_no_soa_gives_none() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query("example.com.".parse().unwrap(), RecordType::A));
        let bytes = msg.to_vec().unwrap();

        let expected = question_sent("example.com.", RecordType::A);
        let parsed = parse_response_bytes(&bytes, &expected).unwrap();
        assert_eq!(parsed.soa_minimum_ttl, None);
    }

    /// Under the `dnssec` feature the authority (name-server) section is
    /// retained verbatim — the seam the DNSSEC `ChainFetcher` reads for NSEC/
    /// NSEC3 no-DS proofs. (Default builds drop the field entirely; that the
    /// non-dnssec parse stays byte-identical is covered by the SOA-TTL tests.)
    #[cfg(feature = "dnssec")]
    #[test]
    fn parse_response_bytes_retains_authority_section() {
        let mut msg = Message::new(7, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_query(Query::query(
            "absent.example.com.".parse().unwrap(),
            RecordType::A,
        ));
        msg.add_authority(make_soa_record(900, 600));
        let bytes = msg.to_vec().unwrap();

        let expected = question_sent("absent.example.com.", RecordType::A);
        let parsed = parse_response_bytes(&bytes, &expected).unwrap();
        assert_eq!(parsed.authority.len(), 1, "authority section retained");
        assert!(
            matches!(parsed.authority[0].data, RData::SOA(_)),
            "authority record carried verbatim"
        );
    }

    // ── RFC 5452 §9.1 question-section echo ────────────────────

    /// The question `build_query` would hand back for this name and type.
    fn question_sent(name: &str, record_type: RecordType) -> Query {
        let name: Name = name.parse().unwrap();
        build_query(&name, record_type, None, false).unwrap().1
    }

    fn response_with_question(question: Query, answer: Option<Record>) -> Vec<u8> {
        let mut msg = Message::new(9, MessageType::Response, OpCode::Query);
        msg.add_query(question);
        if let Some(rec) = answer {
            msg.add_answer(rec);
        }
        msg.to_vec().unwrap()
    }

    fn a_record(owner: &str) -> Record {
        Record::from_rdata(
            owner.parse().unwrap(),
            300,
            RData::A(A::new(203, 0, 113, 7)),
        )
    }

    /// The forgery this check exists to stop: a response carrying an A record
    /// for a name warden never asked about. It is refused outright, so the
    /// caller gets an `Err` and has no `UpstreamResponse` to cache or serve.
    #[test]
    fn parse_response_bytes_rejects_answer_under_unrelated_question() {
        let bytes = response_with_question(
            Query::query("attacker.example.net.".parse().unwrap(), RecordType::A),
            Some(a_record("attacker.example.net.")),
        );

        let expected = question_sent("example.com.", RecordType::A);
        let err = parse_response_bytes(&bytes, &expected).unwrap_err();
        assert!(
            matches!(&err, DnsError::WireFormatError(m) if m.contains("does not match")),
            "expected a question-mismatch rejection, got {err:?}"
        );
    }

    /// The right name under a question we did not ask is still a question we
    /// did not ask — all three fields are compared, not just the name.
    #[test]
    fn parse_response_bytes_rejects_mismatched_qtype() {
        let bytes = response_with_question(
            Query::query("example.com.".parse().unwrap(), RecordType::AAAA),
            None,
        );

        let expected = question_sent("example.com.", RecordType::A);
        assert!(parse_response_bytes(&bytes, &expected).is_err());
    }

    #[test]
    fn parse_response_bytes_rejects_mismatched_qclass() {
        let mut question = Query::query("example.com.".parse().unwrap(), RecordType::A);
        question.query_class = DNSClass::CH;
        let bytes = response_with_question(question, None);

        let expected = question_sent("example.com.", RecordType::A);
        assert!(parse_response_bytes(&bytes, &expected).is_err());
    }

    /// No question section means nothing to match against — fail closed.
    #[test]
    fn parse_response_bytes_rejects_missing_question() {
        let mut msg = Message::new(9, MessageType::Response, OpCode::Query);
        msg.add_answer(a_record("example.com."));
        let bytes = msg.to_vec().unwrap();

        let expected = question_sent("example.com.", RecordType::A);
        let err = parse_response_bytes(&bytes, &expected).unwrap_err();
        assert!(
            matches!(&err, DnsError::WireFormatError(m) if m.contains("no question section")),
            "expected a missing-question rejection, got {err:?}"
        );
    }

    /// Upstreams applying 0x20 randomisation echo the QNAME in mixed case.
    /// Rejecting those would break resolution outright, so the comparison is
    /// case-insensitive per RFC 4343.
    #[test]
    fn parse_response_bytes_accepts_case_differing_question() {
        let bytes = response_with_question(
            Query::query("ExAmPlE.CoM.".parse().unwrap(), RecordType::A),
            Some(a_record("ExAmPlE.CoM.")),
        );

        let expected = question_sent("example.com.", RecordType::A);
        let parsed = parse_response_bytes(&bytes, &expected).expect("0x20 echo accepted");
        assert_eq!(parsed.records.len(), 1);
    }

    /// The returned question must describe the bytes that went out, or every
    /// conforming response would be refused. The name without a trailing dot
    /// is the case that needs the fully-qualifying step: `Name` equality
    /// separates the relative and absolute forms.
    #[test]
    fn build_query_returns_the_question_it_serialised() {
        for name in ["example.com.", "example.com"] {
            let name: Name = name.parse().unwrap();
            let (bytes, question) = build_query(&name, RecordType::A, None, false).unwrap();
            let sent = Message::from_vec(&bytes).unwrap();
            let echoed = sent.queries.first().expect("query carries a question");

            assert!(
                question_echoes(echoed, &question),
                "returned question must match the wire bytes for {name}"
            );
        }
    }

    /// Sanity check on the ECS / DO injection hooks: passing `None` +
    /// `dnssec_ok=false` produces a wire packet with no EDNS / OPT record at
    /// all (additional count = 0). This is the LAN-only deploy path, the
    /// client-facing upstream, and the baseline we MUST NOT regress on.
    #[test]
    fn build_query_bytes_without_ecs_or_do_emits_no_opt_record() {
        let name: Name = "example.com.".parse().unwrap();
        let bytes = build_query_bytes(&name, RecordType::A, None, false).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_eq!(parsed.additionals.len(), 0, "expected no OPT record");
        assert!(parsed.edns.is_none(), "expected no EDNS extension");
        // The client path must NOT set CD — that bit is the validator's alone.
        assert!(
            !parsed.metadata.checking_disabled,
            "client path must not set CD"
        );
    }

    /// `dnssec_ok=true` is the validator's upstream query — it sets the
    /// DO bit (RFC 3225) so signed zones return RRSIG/NSEC/NSEC3 material, the
    /// CD bit (RFC 4035 §3.2.2) so a *validating* upstream returns raw bogus
    /// data for us to judge rather than pre-empting with SERVFAIL, and a
    /// 1232-byte EDNS buffer so DNSKEY/RRSIG sets arrive over UDP.
    #[test]
    fn build_query_bytes_with_dnssec_ok_sets_do_cd_and_buffer() {
        let name: Name = "example.com.".parse().unwrap();
        let bytes = build_query_bytes(&name, RecordType::A, None, true).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        assert!(parsed.metadata.checking_disabled, "expected CD bit set");
        let edns = parsed.edns.as_ref().expect("EDNS extension present");
        assert!(edns.flags().dnssec_ok, "expected DO bit set");
        assert_eq!(edns.max_payload(), 1232, "expected 1232-byte EDNS buffer");
    }

    /// ECS and DO can ride the same OPT record: the validator's upstream may
    /// also carry ECS. Both must be present together.
    #[test]
    fn build_query_bytes_ecs_and_do_together() {
        use crate::dns::edns::{AddressFamily, EdnsClientSubnet};
        use hickory_proto::rr::rdata::opt::EdnsCode;

        let name: Name = "example.com.".parse().unwrap();
        let ecs = EdnsClientSubnet::anonymous(AddressFamily::V4);
        let bytes = build_query_bytes(&name, RecordType::A, Some(ecs), true).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        let edns = parsed.edns.as_ref().expect("EDNS extension present");
        assert!(edns.flags().dnssec_ok, "expected DO bit set");
        assert!(
            edns.option(EdnsCode::Subnet).is_some(),
            "expected ECS option present alongside DO"
        );
    }

    /// When `Some(EdnsClientSubnet)` is passed, the wire packet MUST
    /// carry exactly one OPT record whose option code is 8 (ECS, RFC
    /// 7871 §6) — this is what the ECS smoke test on the CT will
    /// observe via tcpdump.
    #[test]
    fn build_query_bytes_with_ecs_emits_opt_code_8() {
        use crate::dns::edns::{AddressFamily, EdnsClientSubnet};
        use hickory_proto::rr::rdata::opt::EdnsCode;

        let name: Name = "example.com.".parse().unwrap();
        let ecs = EdnsClientSubnet::anonymous(AddressFamily::V4);
        let bytes = build_query_bytes(&name, RecordType::A, Some(ecs), false).unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();
        let edns = parsed.edns.as_ref().expect("EDNS extension present");
        let subnet = edns
            .option(EdnsCode::Subnet)
            .expect("ECS option (code 8) present");
        match subnet {
            EdnsOption::Subnet(cs) => {
                assert_eq!(cs.source_prefix(), 0, "anonymous form, source_prefix=0");
                assert_eq!(cs.scope_prefix(), 0, "query side scope_prefix=0");
            }
            _ => panic!("expected EdnsOption::Subnet, got {subnet:?}"),
        }
    }
}
