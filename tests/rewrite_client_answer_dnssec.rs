//! §4.12 / §4.53 × §4.10-4b — what the AD bit does on a rewritten answer.
//!
//! A rewritten answer is fronted by a CNAME **we** synthesized. Nothing signed
//! it, so the response cannot honestly assert authenticated data — whatever the
//! validator concluded about the original name. And a rewrite is operator
//! policy, not a validation failure, so a Bogus verdict must not become a
//! SERVFAIL: that would turn `safe_search = true` into a network-wide outage.
//!
//! Both properties are asserted on the wire, through the real `ForwardHandler`.
//! The validator is driven by pre-seeding its verdict cache (`seed_verdict`),
//! because reaching `Secure` or `Bogus` for real needs a live DO upstream
//! serving RRSIGs that chain to the IANA root anchors.
//!
//! Companion to `rewrite_client_answer_shape.rs`, which pins the CNAME bridge
//! itself on the default build.

#![cfg(feature = "dnssec")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{CacheConfig, DnssecConfig, DnssecMode, RewriteRule};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::dnssec_validator::DnssecValidator;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::dnssec::{ChainBogus, ChainResult};
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ORIGINAL: &str = "www.google.example.";
const TARGET: &str = "forcesafesearch.google.example.";
const PLAIN: &str = "mail.google.example.";
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 120);

// ── mocks ───────────────────────────────────────────────────────────────────

/// Answers with a record owned by the name it was asked for. Doubles as the
/// validator's DO upstream, where it is never reached: every test seeds the
/// verdict cache first, so `classify` short-circuits before any fetch.
struct EchoUpstream;

#[async_trait::async_trait]
impl Upstream for EchoUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        Ok(UpstreamResponse {
            records: vec![Record::from_rdata(
                name.clone(),
                1995,
                RData::A(A(ANSWER_IP)),
            )],
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            authority: Vec::new(),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingHandler {
    last: Arc<std::sync::Mutex<Option<Message>>>,
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
    let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(qname).unwrap(),
        RecordType::A,
    ));
    let bytes = msg.to_vec().unwrap();
    let src = SocketAddr::new(IpAddr::V4(CLIENT_IP), 40000);
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

fn resolver() -> Arc<ProfileResolver> {
    let profile = Profile {
        display_name: "demo".into(),
        rewrite_rules: vec![RewriteRule {
            from: "www.google.example".into(),
            to: "forcesafesearch.google.example".into(),
            match_subdomains: false,
        }],
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

/// A handler in `dnssec.mode = validate` whose validator already holds `verdict`
/// for `seeded_name`/A — so `decide()` returns without touching the network.
///
/// Note `seeded_name` is always the *original* qname: `DnssecValidator::decide`
/// derives its target from the request, so it validates the pre-rewrite name
/// regardless of what was actually fetched. That is pre-existing behaviour, not
/// something these tests establish.
async fn handler_with_seeded_verdict(seeded_name: &str, verdict: ChainResult) -> ForwardHandler {
    let cfg = DnssecConfig {
        mode: DnssecMode::Validate,
        ..Default::default()
    };
    let validator = Arc::new(DnssecValidator::new(Arc::new(EchoUpstream), &cfg));
    validator
        .seed_verdict(
            &Name::from_ascii(seeded_name).unwrap(),
            RecordType::A,
            verdict,
        )
        .await;

    ForwardHandler::new(
        Arc::new(EchoUpstream),
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver()),
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
    .with_dnssec_validator(validator)
}

async fn query(handler: &ForwardHandler, qname: &str) -> Message {
    let recorder = RecordingHandler::default();
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &request_for(qname),
            recorder.clone(),
        )
        .await;
    recorder.response()
}

// ── tests ───────────────────────────────────────────────────────────────────

/// A `Secure` verdict on the original name must NOT raise AD once a rewrite has
/// fired: the answer the client gets is fronted by our unsigned synthesized
/// CNAME and carries records for a name the validator never examined.
#[tokio::test]
async fn rewritten_answer_never_carries_ad_even_when_secure() {
    let handler = handler_with_seeded_verdict(ORIGINAL, ChainResult::Secure).await;
    let response = query(&handler, ORIGINAL).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        !response.metadata.authentic_data,
        "a rewritten answer is fronted by an unsigned synthesized CNAME — AD must \
         stay clear even though the validator returned Secure for the original name"
    );
    // And it really is the rewritten+bridged answer we are talking about.
    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(
        &response.answers[1].name,
        &Name::from_ascii(TARGET).unwrap()
    );
}

/// A `Bogus` verdict must not SERVFAIL a rewritten query. The rewrite is
/// operator policy; failing closed here would blackhole every safe-search name.
#[tokio::test]
async fn rewritten_answer_never_servfails_when_bogus() {
    let handler =
        handler_with_seeded_verdict(ORIGINAL, ChainResult::Bogus(ChainBogus::DnskeyMissing)).await;
    let response = query(&handler, ORIGINAL).await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a Bogus verdict on the original name must not SERVFAIL a rewritten query"
    );
    assert!(!response.metadata.authentic_data);
    assert_eq!(
        response.answers.len(),
        2,
        "the client must still receive the bridged answer"
    );
}

/// Control: with no rewrite in play, `Secure` still sets AD. The suppression is
/// scoped to rewritten answers and changes nothing else.
#[tokio::test]
async fn non_rewritten_answer_still_sets_ad_when_secure() {
    let handler = handler_with_seeded_verdict(PLAIN, ChainResult::Secure).await;
    let response = query(&handler, PLAIN).await;

    assert!(
        response.metadata.authentic_data,
        "a passthrough answer's AD behaviour must be unchanged by the rewrite fix"
    );
    assert_eq!(response.answers.len(), 1);
    assert_eq!(&response.answers[0].name, &Name::from_ascii(PLAIN).unwrap());
}

/// Control: with no rewrite in play, `Bogus` still SERVFAILs under `validate`.
#[tokio::test]
async fn non_rewritten_answer_still_servfails_when_bogus() {
    let handler =
        handler_with_seeded_verdict(PLAIN, ChainResult::Bogus(ChainBogus::DnskeyMissing)).await;
    let response = query(&handler, PLAIN).await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "a passthrough answer's Bogus handling must be unchanged by the rewrite fix"
    );
}
