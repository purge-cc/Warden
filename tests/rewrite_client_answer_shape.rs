//! §4.12 / §4.53 — the **client-facing** answer shape of a rewritten query.
//!
//! A rewrite mutates the qname sent upstream, so the answer records come back
//! owned by the rewrite *target* while the response's Question section still
//! carries the original name. Until 2026-07-09 warden served exactly that, with
//! nothing bridging the two: glibc's stub resolver (`getanswer()`) walks the
//! CNAME chain outward from the question name and discards every record it
//! cannot reach, so `getaddrinfo` returned no addresses and `safe_search = true`
//! made Google / Bing / DuckDuckGo / YouTube unresolvable.
//!
//! `dig` prints such a response happily with exit 0. That is why the existing
//! rewrite tests — which assert only `upstream.last_query_name` — never saw it.
//! See `feedback_hot_path_name_mutation_tests`: a name-mutation test must assert
//! the records **the client receives**, not just the qname put on the wire.
//!
//! These tests drive the real `ForwardHandler` through the public
//! `RequestHandler::handle_request`, serialize the `MessageResponse` it produces,
//! and re-parse the bytes. Everything asserted here is the actual wire.
//!
//! Deliberately NOT a source-grep test. `integration_rewrite_post_fetch_block.rs`
//! and `integration_fwd_name_branch_disc1.rs` read `handler.rs` as a string; that
//! style is what let a wire-shape bug hide behind a correct-looking source shape.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{CacheConfig, RewriteRule};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ORIGINAL: &str = "www.google.example.";
const TARGET: &str = "forcesafesearch.google.example.";
const HOP: &str = "edge.cdn.example.";
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 120);
/// Comfortably above the 300 s cap the synthesized CNAME is clamped to, so the
/// clamp is observable rather than coincidental.
const UPSTREAM_TTL: u32 = 1995;

// ── mock upstream ───────────────────────────────────────────────────────────

/// Answers every query with records owned by **the name it was asked for**.
///
/// That echo is the point: it means the owner names in the response can only
/// have come from the name the handler actually forwarded, so an assertion on
/// the client-facing owner is a real assertion about the rewrite.
struct EchoUpstream {
    calls: AtomicUsize,
    last_query_name: Mutex<Option<String>>,
    /// Return a two-hop CNAME chain (`asked CNAME hop`, `hop A ip`) instead of a
    /// flat A record — the CDN-flattened shape a rewritten name routinely gets.
    chain: bool,
}

impl EchoUpstream {
    fn new(chain: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last_query_name: Mutex::new(None),
            chain,
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn last_query_name(&self) -> Option<String> {
        self.last_query_name.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Upstream for EchoUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_query_name.lock().unwrap() = Some(name.to_string());

        let records = if self.chain {
            let hop = Name::from_ascii(HOP).unwrap();
            vec![
                Record::from_rdata(name.clone(), UPSTREAM_TTL, RData::CNAME(CNAME(hop.clone()))),
                Record::from_rdata(hop, UPSTREAM_TTL, RData::A(A(ANSWER_IP))),
            ]
        } else {
            vec![Record::from_rdata(
                name.clone(),
                UPSTREAM_TTL,
                RData::A(A(ANSWER_IP)),
            )]
        };

        Ok(UpstreamResponse {
            records,
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

// ── record-capturing response handler ───────────────────────────────────────

/// The only `ResponseHandler` double in the tree (`CapturingHandler` in
/// `handler.rs`) drops every record set — it can see the header and nothing
/// else. `MessageResponse`'s answer/authority/additional iterators are private
/// with no getters, so the sole way to inspect them is to emit the response into
/// a `BinEncoder` and re-parse the wire bytes. hickory's own tests do this.
#[derive(Clone, Default)]
struct RecordingHandler {
    last: Arc<Mutex<Option<Message>>>,
}

impl RecordingHandler {
    fn response(&self) -> Message {
        self.last
            .lock()
            .unwrap()
            .clone()
            .expect("handler must have sent exactly one response")
    }
}

#[async_trait::async_trait]
impl ResponseHandler for RecordingHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, hickory_net::NetError> {
        let mut buf = Vec::with_capacity(1024);
        let info = {
            let mut encoder = BinEncoder::new(&mut buf);
            response
                .destructive_emit(&mut encoder)
                .expect("response must serialize")
        };
        *self.last.lock().unwrap() = Some(Message::from_bytes(&buf).expect("response must parse"));
        Ok(info)
    }
}

// ── fixture ─────────────────────────────────────────────────────────────────

fn request_for(qname: &str) -> Request {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(qname).unwrap(),
        RecordType::A,
    ));
    let bytes = msg.to_vec().unwrap();
    let src = SocketAddr::new(IpAddr::V4(CLIENT_IP), 40000);
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

/// A resolver mapping `CLIENT_IP` to a profile carrying `rules`.
fn resolver_with(rules: Vec<RewriteRule>) -> Arc<ProfileResolver> {
    let profile = Profile {
        display_name: "demo".into(),
        rewrite_rules: rules,
        ..Default::default()
    };
    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.allow_from = vec!["10.0.0.0/8".into()];
    config.server.default_profile = Some(Id::new("demo").unwrap());
    config.profiles.insert("demo".to_string(), profile);
    config.devices.push(Device {
        id: Id::new("test-dev").unwrap(),
        display_name: "test".into(),
        ip: Some(IpAddr::V4(CLIENT_IP)),
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
        network_name: None,
        network_name_wildcard: false,
    });
    Arc::new(ProfileResolver::build(
        &config,
        &SourceBitMap::default(),
        &purge_warden::config::custom_list::CustomListStore::new(),
    ))
}

fn handler_with(rules: Vec<RewriteRule>, upstream: Arc<EchoUpstream>) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver_with(rules)),
        None,
        None,
        None,
        None,
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled — it would spawn a second upstream call
        0.0,
        16,
    )
}

fn safesearch_rule() -> Vec<RewriteRule> {
    vec![RewriteRule {
        from: "www.google.example".into(),
        to: "forcesafesearch.google.example".into(),
        match_subdomains: false,
    }]
}

/// Drive one query end-to-end and return the parsed response.
async fn query(handler: &ForwardHandler, qname: &str) -> Message {
    let recorder = RecordingHandler::default();
    // 0.26 added the `T: Time` generic to handle_request; it's unused in the
    // arguments, so a direct call must name it. TokioTime is the only impl.
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &request_for(qname),
            recorder.clone(),
        )
        .await;
    recorder.response()
}

fn assert_bridged(response: &Message, expect_chain: bool) {
    let answers = &response.answers;
    let expected_len = if expect_chain { 3 } else { 2 };
    assert_eq!(
        answers.len(),
        expected_len,
        "answer section must be the synthesized bridge followed by the fetched \
         records, got: {answers:?}"
    );
    assert_eq!(
        response.answers.len(),
        answers.len(),
        "ANCOUNT must count the synthesized CNAME"
    );

    // The bridge itself: original CNAME target.
    let bridge = &answers[0];
    assert_eq!(
        &bridge.name,
        &Name::from_ascii(ORIGINAL).unwrap(),
        "the first answer must be owned by the ORIGINAL qname — this is the \
         record glibc's getanswer() needs to enter the chain"
    );
    assert_eq!(bridge.record_type(), RecordType::CNAME);
    match &bridge.data {
        RData::CNAME(CNAME(target)) => assert_eq!(
            target,
            &Name::from_ascii(TARGET).unwrap(),
            "the bridge must point at the rewrite target"
        ),
        other => panic!("first answer must be a CNAME, got {other:?}"),
    }

    // The fetched records, owner names untouched.
    assert_eq!(
        &answers[1].name,
        &Name::from_ascii(TARGET).unwrap(),
        "fetched records must keep their owner — relabelling would orphan a chain"
    );
    if expect_chain {
        assert_eq!(answers[1].record_type(), RecordType::CNAME);
        assert_eq!(
            &answers[2].name,
            &Name::from_ascii(HOP).unwrap(),
            "the second hop of the fetched chain must survive verbatim"
        );
        assert_eq!(answers[2].record_type(), RecordType::A);
    } else {
        assert_eq!(answers[1].record_type(), RecordType::A);
    }

    // The bridge must not outlive what it fronts.
    assert!(
        bridge.ttl <= answers[1].ttl,
        "synthesized CNAME TTL ({}) must not exceed the TTL of the records it \
         fronts ({})",
        bridge.ttl,
        answers[1].ttl
    );
    assert_eq!(
        bridge.ttl, 300,
        "the synthesized CNAME is config, not DNS data — its TTL is clamped so a \
         deleted rewrite rule drains from downstream caches promptly"
    );
}

// ── tests ───────────────────────────────────────────────────────────────────

/// Cache-MISS path: the client gets `original CNAME target` + the target's A.
#[tokio::test]
async fn rewritten_cache_miss_answer_is_bridged_by_synthesized_cname() {
    let upstream = Arc::new(EchoUpstream::new(false));
    let handler = handler_with(safesearch_rule(), upstream.clone());

    let response = query(&handler, ORIGINAL).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(TARGET),
        "the rewritten name must still be what goes upstream (§4.12 leak guard)"
    );
    assert_bridged(&response, false);
}

/// Cache-HIT path. The cache key is the *rewritten* name (DR9), so the serve
/// path re-derives the bridge from the cached entry rather than from anything
/// the forward path left behind. A fix that only touched the miss path would
/// pass the test above and fail here on the second query — i.e. in production,
/// immediately.
#[tokio::test]
async fn rewritten_cache_hit_answer_has_the_same_bridged_shape() {
    let upstream = Arc::new(EchoUpstream::new(false));
    let handler = handler_with(safesearch_rule(), upstream.clone());

    let first = query(&handler, ORIGINAL).await;
    assert_bridged(&first, false);
    assert_eq!(upstream.calls(), 1);

    let second = query(&handler, ORIGINAL).await;
    assert_eq!(
        upstream.calls(),
        1,
        "the second query must be served from cache — otherwise this test is not \
         exercising the cache-hit serve path at all"
    );
    assert_bridged(&second, false);

    assert_eq!(
        first.answers.len(),
        second.answers.len(),
        "cache-hit and cache-miss must produce the same answer shape"
    );
}

/// A rewritten answer that is itself a CNAME chain: the bridge goes in front,
/// every fetched owner name survives verbatim. Relabelling owners in place —
/// the rejected fix — would have orphaned `edge.cdn.example A` from the CNAME
/// that pointed at it.
#[tokio::test]
async fn rewritten_cname_chain_keeps_fetched_owner_names() {
    let upstream = Arc::new(EchoUpstream::new(true));
    let handler = handler_with(safesearch_rule(), upstream.clone());

    let response = query(&handler, ORIGINAL).await;
    assert_bridged(&response, true);
}

/// Passthrough: no rewrite rule matched, so the response must be exactly what it
/// was before this fix — one record, owned by the qname, no synthesized CNAME.
#[tokio::test]
async fn passthrough_answer_owner_matches_qname_and_adds_no_cname() {
    let upstream = Arc::new(EchoUpstream::new(false));
    let handler = handler_with(safesearch_rule(), upstream.clone());

    // `mail.google.example` does not match the (non-subdomain) rule.
    let response = query(&handler, "mail.google.example.").await;

    let answers = &response.answers;
    assert_eq!(answers.len(), 1, "passthrough must not gain a record");
    assert_eq!(answers[0].record_type(), RecordType::A);
    assert_eq!(
        &answers[0].name,
        &Name::from_ascii("mail.google.example.").unwrap(),
        "a non-rewritten answer is owned by the qname"
    );
    assert!(
        !answers.iter().any(|r| r.record_type() == RecordType::CNAME),
        "no CNAME may be synthesized when no rewrite fired"
    );
    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some("mail.google.example.")
    );
}

/// Passthrough on the cache-hit path too — the branch is in the shared serve
/// function, so both callers must stay clean.
#[tokio::test]
async fn passthrough_cache_hit_adds_no_cname() {
    let upstream = Arc::new(EchoUpstream::new(false));
    let handler = handler_with(safesearch_rule(), upstream.clone());

    let _ = query(&handler, "mail.google.example.").await;
    let second = query(&handler, "mail.google.example.").await;

    assert_eq!(upstream.calls(), 1, "second query must hit the cache");
    assert_eq!(second.answers.len(), 1);
    assert_eq!(
        &second.answers[0].name,
        &Name::from_ascii("mail.google.example.").unwrap()
    );
}
