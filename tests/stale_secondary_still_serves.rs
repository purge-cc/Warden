#![cfg(feature = "cluster")]
//! Cluster S3 Task 5, step 4 — **a stale secondary keeps answering.**
//!
//! # The contract
//!
//! Design doc §9: *degrade audibly, never refuse.* Removing the domain-map
//! transfer in S1 softened the stale case materially — a stale secondary has
//! **fresh lists and old policy**, not a frozen map — so refusing to serve
//! would take the household's DNS offline to protect against policy being a few
//! hours old. The staleness work must therefore change what the node *says*,
//! and nothing about what it *answers*.
//!
//! # Read this before trusting a green run
//!
//! This test asserts a property the product is **designed to preserve through
//! the failure**, which is the classic blind assertion: `src/dns/handler.rs`
//! contains zero references to `cluster` today, so nothing here can fail unless
//! someone later couples the two — and then only at the layer this file drives.
//! It is a trip-wire, not a proof.
//!
//! What it does catch: a stale-gate added to the query path (`ForwardHandler`,
//! the filter engine it holds, or the profile resolution in between) — the one
//! place a "refuse while stale" would plausibly be written, because it is the
//! only place that can refuse.
//!
//! What it cannot catch: a refusal added at the listener (`dns/server.rs`
//! declining to bind or dropping datagrams before the handler), or one added to
//! the reload path so that a stale node ends up with an *empty* policy rather
//! than a refusing one. Those need the two-node smoke (Task 6, step 4).
//!
//! **Its discrimination is unproven at this layer, deliberately.** The way to
//! prove it would be to inject `if stale { REFUSED }` into `src/dns/handler.rs`
//! and watch these tests go red — but that file belongs to no lane in the S3
//! split, and a temporary write outside the lane's ownership is still a write.
//! So this is a trip-wire armed against a future change, not a measured
//! detector, and it should be read as exactly that
//! (`feedback_never_assert_on_state_the_product_preserves`: an assertion on
//! state the product is designed to preserve through the failure is blind by
//! construction).
//!
//! What *is* measured here: `upstream.calls()` proves the query really
//! traversed the handler rather than being answered by an inert fixture — a
//! test that never reached the code cannot fail for the right reason either.
//! The end-to-end proof is Task 6 step 4: boot the secondary with the primary's
//! `[api]` port blocked and `dig` it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use purge_warden::cluster::observe::{ClusterObserve, SyncHealth, SyncStatus};
use purge_warden::config::schema::{AdminRule, ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Denied by the replicated policy this node last managed to apply.
const BLOCKED: &str = "tracker.example.";
/// Not denied — must still reach the upstream.
const ALLOWED: &str = "shop.example.";
/// RFC 5737 TEST-NET-2, what the upstream answers with. Never a real address.
const UPSTREAM_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
/// RFC 5737 TEST-NET-1 — the primary this secondary cannot reach.
const PEER: &str = "https://192.0.2.10:8443";

// ── mock upstream ───────────────────────────────────────────────────────────

struct CountingUpstream {
    calls: AtomicUsize,
}

impl CountingUpstream {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Upstream for CountingUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(UpstreamResponse {
            records: vec![Record::from_rdata(
                name.clone(),
                300,
                RData::A(A(UPSTREAM_A)),
            )],
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

// ── record-capturing response handler ───────────────────────────────────────

/// `MessageResponse`'s iterators are private, so the only way to inspect the
/// answer is to emit it and re-parse the bytes. Copied from
/// `tests/integration_rewrite_post_fetch_block.rs`, which is where this harness
/// shape comes from.
#[derive(Clone, Default)]
struct RecordingHandler {
    last: Arc<Mutex<Option<Message>>>,
}

impl RecordingHandler {
    fn response(&self) -> Option<Message> {
        self.last.lock().unwrap().clone()
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

/// The policy a secondary would be left holding after its last successful
/// sync: one device, one profile, one deny rule.
fn resolver() -> Arc<ProfileResolver> {
    let profile = Profile {
        display_name: "replicated".into(),
        admin_rules: vec![Id::new("deny-tracker").unwrap()],
        ..Default::default()
    };
    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.allow_from = vec!["10.0.0.0/8".into()];
    config.server.default_profile = Some(Id::new("replicated").unwrap());
    config.admin_rules.push(AdminRule {
        id: Id::new("deny-tracker").unwrap(),
        rule: "||tracker.example^".into(),
    });
    config.profiles.insert("replicated".to_string(), profile);
    // `Device` has no `Default`; the field list is spelled out, exactly as the
    // sibling handler tests do.
    config.devices.push(Device {
        id: Id::new("test-dev").unwrap(),
        display_name: "test".into(),
        ip: Some(IpAddr::V4(CLIENT_IP)),
        mac: None,
        mac_aliases: vec![],
        profile: Some(Id::new("replicated").unwrap()),
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

fn handler(upstream: Arc<CountingUpstream>) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver()),
        None,
        None,
        None,
        None,
        None, // allow_from: accept every source
        60,
        None, // prefetch off — it would spawn a second upstream call
        0.0,
        16,
    )
}

async fn query(handler: &ForwardHandler, qname: &str) -> Option<Message> {
    let recorder = RecordingHandler::default();
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &request_for(qname),
            recorder.clone(),
        )
        .await;
    recorder.response()
}

/// A secondary whose polls have been failing for an hour: policy applied, no
/// confirmation since. Built through the real write-through path, and the
/// health is **asserted**, not assumed — otherwise this file would keep passing
/// against a node that is not actually stale.
fn stale_secondary() -> Arc<ClusterObserve> {
    let obs = Arc::new(ClusterObserve::new_secondary(
        Some("sec-a".into()),
        PEER.to_string(),
        45,
    ));
    let t0 = Instant::now();
    obs.store_sync(SyncStatus {
        last_config_hash: Some("hash-a".into()),
        last_sync: Some(t0),
        last_poll_ok: false,
        last_error: Some("heartbeat HTTP 502".into()),
        synced_at_least_once: true,
    });
    let view = obs
        .sync_view(t0 + Duration::from_secs(3600))
        .expect("a secondary has a view");
    assert_eq!(
        view.health,
        SyncHealth::Stale,
        "the fixture must actually be stale, or the tests below prove nothing"
    );
    assert_eq!(view.confirmed_secs_ago, Some(3600));
    obs
}

// ── tests ───────────────────────────────────────────────────────────────────

/// The denied name is still denied. A stale secondary keeps filtering with the
/// last policy it applied — that is the whole reason refusing would be the
/// wrong response.
#[tokio::test]
async fn a_stale_secondary_still_blocks_what_its_last_policy_denied() {
    let observe = stale_secondary();
    let upstream = Arc::new(CountingUpstream::new());
    let h = handler(Arc::clone(&upstream));

    let response = query(&h, BLOCKED).await.expect("a stale node must answer");

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a block is NOERROR + 0.0.0.0, never REFUSED — a REFUSED here means \
         staleness has been wired into the query path, which §9 forbids"
    );
    assert_eq!(response.answers.len(), 1, "got: {:?}", response.answers);
    assert_eq!(
        a_ip(&response.answers[0]),
        Ipv4Addr::UNSPECIFIED,
        "the canned block answer"
    );
    // Independent observation: a block must not have travelled upstream. One
    // response code reached by two different causes is not a discriminator.
    assert_eq!(
        upstream.calls(),
        0,
        "a blocked name is answered locally, stale or not"
    );

    // The node is still stale after serving — serving did not clear it, and
    // staleness did not stop the serving.
    assert_eq!(
        observe.sync_view(Instant::now()).expect("secondary").health,
        SyncHealth::Stale
    );
}

/// …and the allowed name still resolves. This is the half that a refusal would
/// break most visibly: the household's DNS.
#[tokio::test]
async fn a_stale_secondary_still_forwards_what_its_last_policy_allowed() {
    let _observe = stale_secondary();
    let upstream = Arc::new(CountingUpstream::new());
    let h = handler(Arc::clone(&upstream));

    let response = query(&h, ALLOWED).await.expect("a stale node must answer");

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        a_ip(&response.answers[0]),
        UPSTREAM_A,
        "the answer must be the upstream's, i.e. the query was really forwarded"
    );
    assert_eq!(
        upstream.calls(),
        1,
        "exactly one forward — the independent evidence that the handler did \
         not short-circuit on staleness and serve something cached or canned"
    );
}

/// The never-synced node is the harsher case: no policy has landed *this boot*.
/// It must still answer — §9 row 2 makes it a standalone warden, not a node
/// that refuses.
#[tokio::test]
async fn a_never_synced_secondary_still_answers() {
    let obs = ClusterObserve::new_secondary(Some("sec-a".into()), PEER.to_string(), 45);
    obs.store_sync(SyncStatus {
        last_config_hash: None,
        last_sync: None,
        last_poll_ok: false,
        last_error: Some("connection refused".into()),
        synced_at_least_once: false,
    });
    assert_eq!(
        obs.sync_view(Instant::now()).expect("secondary").health,
        SyncHealth::NeverSynced
    );

    let upstream = Arc::new(CountingUpstream::new());
    let h = handler(Arc::clone(&upstream));
    let response = query(&h, ALLOWED)
        .await
        .expect("a never-synced node must answer");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(upstream.calls(), 1);
}

fn a_ip(rr: &Record) -> Ipv4Addr {
    match &rr.data {
        RData::A(A(ip)) => *ip,
        other => panic!("expected an A record, got {other:?}"),
    }
}
