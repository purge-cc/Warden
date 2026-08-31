//! §4.29 h5 regression — post-fetch BLOCKED branches must echo the Question
//! section's qname, not the post-§4.12 rewrite target.
//!
//! ## The invariant
//!
//! When a §4.12 / §4.53 rewrite fires, `fwd_name` carries the rewritten target
//! while the response's Question section still carries the name the client
//! asked for. If the fetched answer is then blocked — because a CNAME in the
//! chain is denied, or because a resolved IP is on the IP blocklist — the
//! canned block record must be owned by the **original qname**. Owning it by
//! the rewrite target produces an answer record whose owner diverges from the
//! Question section, violating RFC 1035 §4.1.3: glibc's `getanswer()` walks
//! outward from the question name and discards every record it cannot reach,
//! so the client sees *no* answer rather than the intended 0.0.0.0.
//!
//! ## This file used to grep `handler.rs` as a string
//!
//! Until S1 the test here read `src/dns/handler.rs` with `fs::read_to_string`,
//! brace-matched the `Ok(entry)` arm and asserted `!arm.contains("&fwd_name")`.
//! Its own module doc argued that a real `handle_inner` fixture was "~300 lines
//! for a two-character regression class — not earning its keep", and deferred
//! to a manual CT `dig`.
//!
//! Two things falsified that:
//!
//! 1. `tests/rewrite_client_answer_shape.rs` built exactly such a fixture and
//!    proved it affordable — the harness below is most of this file and it is
//!    a copy of that one.
//! 2. The grep had already rotted. Those branches no longer call
//!    `send_block_response` inline; they build a `BlockDispatchCtx` and call
//!    `dispatch_cname_block` / `dispatch_ip_block`. The string `&fwd_name`
//!    could not appear in that arm whatever anyone wrote, so the assertion had
//!    become unfalsifiable while still reading like a regression guard.
//!
//! And `dig` cannot see this defect class at all — it prints an unreachable
//! answer happily with exit 0. `getent hosts` is what fails.
//!
//! The tests below drive the real `ForwardHandler` through the public
//! `RequestHandler::handle_request`, serialize the `MessageResponse` it
//! produces, and re-parse the bytes. Everything asserted is the actual wire.

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

use purge_warden::config::schema::{AdminRule, ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{CacheConfig, RewriteRule};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::filter::ip_filter::IpFilter;
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// What the client asks for — and therefore the only name the block record may
/// be owned by.
const ORIGINAL: &str = "shop.example.";
/// What the rewrite sends upstream. A block record owned by THIS is the bug.
const TARGET: &str = "tracker.example.";
/// The denied CNAME target that trips the post-fetch chain walk.
const EVIL: &str = "evil.example.";
/// The denied resolved address that trips the post-fetch IP filter.
const EVIL_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);

// ── mock upstream ───────────────────────────────────────────────────────────

/// Answers with a scripted record set owned by the name it was asked for, so
/// the owner names in the response can only have come from the name the handler
/// actually forwarded.
struct ScriptedUpstream {
    calls: AtomicUsize,
    last_query_name: Mutex<Option<String>>,
    /// `true` → `asked CNAME evil.example` + `evil.example A 203.0.113.9`
    /// (trips the CNAME-chain walk). `false` → `asked A 198.51.100.66`
    /// (trips the IP filter).
    chain: bool,
}

impl ScriptedUpstream {
    fn new(chain: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last_query_name: Mutex::new(None),
            chain,
        }
    }
    fn last_query_name(&self) -> Option<String> {
        self.last_query_name.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Upstream for ScriptedUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_query_name.lock().unwrap() = Some(name.to_string());

        let records = if self.chain {
            let evil = Name::from_ascii(EVIL).unwrap();
            vec![
                Record::from_rdata(name.clone(), 300, RData::CNAME(CNAME(evil.clone()))),
                Record::from_rdata(evil, 300, RData::A(A(Ipv4Addr::new(203, 0, 113, 9)))),
            ]
        } else {
            vec![Record::from_rdata(name.clone(), 300, RData::A(A(EVIL_IP)))]
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

/// `MessageResponse`'s record iterators are private with no getters, so the only
/// way to inspect them is to emit into a `BinEncoder` and re-parse the bytes.
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

/// A resolver mapping `CLIENT_IP` to a profile that rewrites `ORIGINAL` to
/// `TARGET` and denies `EVIL`.
///
/// The deny arrives through `admin_rules`: a simple exact `||evil.example^`
/// lands in `ResolvedProfile::deny_domains` at resolver build. That matters
/// because the post-fetch chain walk (`filter::cname::walk_response`) is
/// **profile-aware** — it evaluates each CNAME target against the resolved
/// profile, not through the flat `FilterEngine::is_blocked`. An empty engine is
/// therefore enough; no blocklist file is involved.
fn resolver_with_rewrite_and_deny() -> Arc<ProfileResolver> {
    let profile = Profile {
        display_name: "demo".into(),
        admin_rules: vec![Id::new("deny-evil").unwrap()],
        rewrite_rules: vec![RewriteRule {
            from: "shop.example".into(),
            to: "tracker.example".into(),
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
    config.admin_rules.push(AdminRule {
        id: Id::new("deny-evil").unwrap(),
        rule: "||evil.example^".into(),
    });
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

fn handler_with(
    upstream: Arc<ScriptedUpstream>,
    ip_filter: Option<Arc<IpFilter>>,
) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver_with_rewrite_and_deny()),
        None,
        None,
        None,
        ip_filter,
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled — it would spawn a second upstream call
        0.0,
        16,
    )
}

fn ip_filter_blocking(ip: Ipv4Addr) -> Arc<IpFilter> {
    let mut set = std::collections::HashSet::with_hasher(ahash::RandomState::new());
    set.insert(IpAddr::V4(ip));
    Arc::new(IpFilter::with_ips(set))
}

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

/// The assertion both tests share: the query was rewritten on the way out, the
/// answer came back blocked, and the block record is owned by the name the
/// client asked for.
fn assert_blocked_answer_owned_by_original(response: &Message, branch: &str) {
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "`block_response = zero` blocks with NOERROR + 0.0.0.0, not an rcode"
    );
    assert_eq!(
        response.queries.first().map(|q| q.name().clone()),
        Some(Name::from_ascii(ORIGINAL).unwrap()),
        "the Question section always echoes the client's qname"
    );
    assert_eq!(
        response.answers.len(),
        1,
        "a zero-block answers with exactly the canned record, got: {:?}",
        response.answers
    );

    let blocked = &response.answers[0];
    assert_eq!(
        &blocked.name,
        &Name::from_ascii(ORIGINAL).unwrap(),
        "§4.29 h5 ({branch}): the BLOCKED record must be owned by the ORIGINAL \
         qname. Owning it by the rewrite target `{TARGET}` leaves the client an \
         answer it cannot reach from the Question section — glibc's getanswer() \
         discards it and the block silently becomes a resolution failure instead \
         of a 0.0.0.0. Got owner `{}`.",
        blocked.name
    );
    assert_eq!(blocked.record_type(), RecordType::A);
    assert_eq!(
        a_ip(blocked),
        Ipv4Addr::UNSPECIFIED,
        "zero-block serves 0.0.0.0"
    );
}

fn a_ip(rr: &Record) -> Ipv4Addr {
    match &rr.data {
        RData::A(A(ip)) => *ip,
        other => panic!("expected an A record, got {other:?}"),
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

/// Post-fetch **CNAME-chain** block on a rewritten query
/// (`handler.rs` `Ok(entry)` arm → `dispatch_cname_block`).
#[tokio::test]
async fn post_fetch_cname_block_answer_is_owned_by_the_original_qname() {
    let upstream = Arc::new(ScriptedUpstream::new(true));
    let handler = handler_with(upstream.clone(), None);

    let response = query(&handler, ORIGINAL).await;

    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(TARGET),
        "the rewrite must have fired — otherwise `fwd_name` never diverges from \
         the qname and this test cannot observe the regression it guards"
    );
    assert_blocked_answer_owned_by_original(&response, "CNAME-chain block");
}

/// Post-fetch **IP** block on a rewritten query
/// (`handler.rs` `Ok(entry)` arm → `dispatch_ip_block`). The two branches share
/// a hoisted `qname` but are separate early returns, so a regression can land in
/// one and not the other.
#[tokio::test]
async fn post_fetch_ip_block_answer_is_owned_by_the_original_qname() {
    let upstream = Arc::new(ScriptedUpstream::new(false));
    let handler = handler_with(upstream.clone(), Some(ip_filter_blocking(EVIL_IP)));

    let response = query(&handler, ORIGINAL).await;

    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(TARGET),
        "the rewrite must have fired — otherwise `fwd_name` never diverges from \
         the qname and this test cannot observe the regression it guards"
    );
    assert_blocked_answer_owned_by_original(&response, "IP block");
}

/// **This one is a code-shape pin, not a behavioural test.** It asserts nothing
/// about the wire and cannot catch a wrong answer.
///
/// §4.29 h1-h4: the four post-block cache-invalidate sites must route through
/// `invalidate_current_bucket(...)` so `ecs_cache_prefix` is a positionally
/// required argument at every call. A contributor calling
/// `cache.invalidate_key(.., .., .., None)` directly from `handle_inner`
/// bypasses that safety and leaves the actually-bucketed entry live in cache
/// until natural TTL. The property is "one helper, no bypass" — a refactoring
/// invariant about how the code is *arranged*, which source text is a fair proxy
/// for. Reading the source is the point here, not a substitute for a fixture.
///
/// It is kept next to behavioural tests deliberately: if it ever starts failing
/// because the helper was intentionally reshaped, update the pin — do not treat
/// it as evidence of a wire regression.
#[test]
fn invalidate_current_bucket_helper_is_present_code_shape_pin() {
    let src = include_str!("../src/dns/handler.rs");
    assert!(
        src.contains("async fn invalidate_current_bucket("),
        "§4.29 h1-h4 code-shape pin: the `invalidate_current_bucket` helper was \
         removed. The post-block invalidate sites depend on it to make \
         `ecs_cache_prefix` positionally required (no `Option::None` \
         short-circuit)."
    );
    assert!(
        src.contains("ecs_cache_prefix: Option<EcsPrefix>,"),
        "§4.29 code-shape pin: expected `ecs_cache_prefix: Option<EcsPrefix>` arg \
         on `invalidate_current_bucket`."
    );
}
