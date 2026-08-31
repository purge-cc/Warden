//! S1 — the **answer-owner-name invariant at the wire** for local DNS records.
//!
//! ## The invariant
//!
//! Every answer RR's owner name must be reachable from the QNAME in the Question
//! section by following CNAME RDATA. A CNAME is owned by the qname; the target's
//! A record is owned by the target. Divergence violates RFC 1035 §4.1.3 and is
//! the exact defect class that shipped **twice** — `v0.22.1-localdns-wildcard-owner`
//! and `v0.22.2-safesearch-cname-bridge`. Both shipped for the same structural
//! reason: the value was correct one layer down and unverified at the boundary
//! the client sees.
//!
//! ⚠️ `dig` cannot see one variant of this bug. glibc's `getanswer()` walks the
//! chain outward from the question name and silently discards every record it
//! cannot reach, so `getent hosts` fails while `dig` prints the response happily
//! with exit 0. A clean `dig` is **not** proof of owner-name correctness.
//!
//! ## What was missing
//!
//! `src/dns/local.rs` and `src/dns/local_profile.rs` unit tests assert what
//! `lookup()` **returns**. Nothing asserted what `send_local` (handler.rs:1993)
//! actually puts **on the wire** through `handle_inner`'s two call sites —
//! profile-scoped `local_records` (handler.rs:983) and the global `local_dns`
//! table (handler.rs:1016). This file closes that.
//!
//! Fixture pattern copied from `tests/rewrite_client_answer_shape.rs`: drive the
//! real `ForwardHandler` through the public `RequestHandler::handle_request`,
//! serialize the `MessageResponse` it produces, re-parse the bytes. Everything
//! asserted here is the actual wire.
//!
//! Deliberately NOT a source-grep test — that style is what let a wire-shape bug
//! hide behind a correct-looking source shape.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use purge_warden::config::schema::{ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{
    CacheConfig, LocalDnsConfig, LocalDnsRecord, LocalDnsRecordType,
};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::dns::local::LocalRecords;
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Exact-match host. Profile scope and global scope resolve it to **different**
/// addresses so a shadowing test can tell which table answered.
const NAS: &str = "nas.home";
const NAS_IP_PROFILE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
const NAS_IP_GLOBAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 51);

/// CNAME pointing at a *local* target — the owner-split case.
const MEDIA: &str = "media.home";
/// Wildcard apex (`match_subdomains = true`).
const WILDCARD_APEX: &str = "example.test";
const WILDCARD_CHILD: &str = "app.example.test";
/// Two labels below the apex — a one-label descendant can pass a suffix walk
/// that stops too early, so the deep name is what actually exercises it.
const WILDCARD_DEEP_CHILD: &str = "api.v2.app.example.test";
const WILDCARD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
const V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

// ── mock upstream ───────────────────────────────────────────────────────────

/// Counts calls and answers with a record owned by the name it was asked for.
///
/// The echo shape is deliberate and is the whole reason `calls()` matters: a
/// correct local exact-match A record is **indistinguishable on the wire** from
/// this upstream's answer to the same query. Without asserting `calls() == 0` an
/// exact-match fixture would pass identically whether the local table served it
/// or the query leaked upstream — i.e. it would prove nothing.
struct TrapUpstream {
    calls: AtomicUsize,
    last_query_name: Mutex<Option<String>>,
}

impl TrapUpstream {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last_query_name: Mutex::new(None),
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
impl Upstream for TrapUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_query_name.lock().unwrap() = Some(name.to_string());
        Ok(UpstreamResponse {
            records: vec![Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
            )],
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

// ── record-capturing response handler ───────────────────────────────────────

/// `MessageResponse`'s answer iterators are private with no getters, so the only
/// way to inspect them is to emit into a `BinEncoder` and re-parse the wire
/// bytes. Same approach as `tests/rewrite_client_answer_shape.rs` and hickory's
/// own tests.
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

fn rec(
    domain: &str,
    record_type: LocalDnsRecordType,
    value: &str,
    match_subdomains: bool,
) -> LocalDnsRecord {
    LocalDnsRecord {
        domain: domain.into(),
        record_type,
        value: value.into(),
        match_subdomains,
        ttl_secs: None,
    }
}

fn request_for(qname: &str, record_type: RecordType) -> Request {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(qname).unwrap(), record_type));
    let bytes = msg.to_vec().unwrap();
    let src = SocketAddr::new(IpAddr::V4(CLIENT_IP), 40000);
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

/// A resolver mapping `CLIENT_IP` to a profile carrying `records` as its
/// profile-scoped `local_records` (DM4).
fn resolver_with(records: Vec<LocalDnsRecord>) -> Arc<ProfileResolver> {
    let profile = Profile {
        display_name: "demo".into(),
        local_records: records,
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

/// Build a handler with the two local-DNS tables wired independently, so each
/// `send_local` call site can be driven in isolation (`handler.rs:983` for the
/// profile scope, `handler.rs:1016` for the global one).
fn handler_with(
    profile_records: Vec<LocalDnsRecord>,
    global_records: Vec<LocalDnsRecord>,
    upstream: Arc<TrapUpstream>,
) -> ForwardHandler {
    let global = LocalRecords::build(&LocalDnsConfig {
        ttl_secs: 3600,
        dynamic_ttl_secs: 30,
        nodata_for_missing_types: true,
        records: global_records,
    });
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver_with(profile_records)),
        None,
        None,
        Some(Arc::new(global)),
        None,
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled
        0.0,
        16,
    )
}

/// Drive one query end-to-end and return the parsed response.
async fn query(handler: &ForwardHandler, qname: &str, record_type: RecordType) -> Message {
    let recorder = RecordingHandler::default();
    // 0.26 added the `T: Time` generic to handle_request; it's unused in the
    // arguments, so a direct call must name it. TokioTime is the only impl.
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &request_for(qname, record_type),
            recorder.clone(),
        )
        .await;
    recorder.response()
}

fn name(s: &str) -> Name {
    Name::from_ascii(format!("{s}.")).unwrap()
}

// ── the invariant, asserted generically ─────────────────────────────────────

/// **The invariant.** Starting from the QNAME in the response's own Question
/// section, follow CNAME RDATA transitively through the answer section and
/// assert every answer RR's owner lands in the reachable set.
///
/// Anchored on `response.queries` — the wire's Question section — not on a name
/// the test remembers, so a handler that answered a *different* question cannot
/// pass. This is the general form: it catches owner divergence the per-case
/// assertions below never enumerated.
fn assert_answers_reachable_from_qname(response: &Message) {
    let qname = response
        .queries
        .first()
        .expect("response must echo the Question section")
        .name()
        .clone();

    let mut reachable = vec![qname.clone()];
    loop {
        let mut grew = false;
        for rr in &response.answers {
            if !reachable.contains(&rr.name) {
                continue;
            }
            if let RData::CNAME(CNAME(target)) = &rr.data {
                if !reachable.contains(target) {
                    reachable.push(target.clone());
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    for (i, rr) in response.answers.iter().enumerate() {
        assert!(
            reachable.contains(&rr.name),
            "answer[{i}] is owned by `{}` ({:?}), which is NOT reachable from the \
             QNAME `{qname}` by following CNAMEs. Reachable set: {reachable:?}. \
             glibc's getanswer() discards such a record silently — `dig` shows it, \
             `getent hosts` returns nothing. Full answer section: {:?}",
            rr.name,
            rr.record_type(),
            response.answers,
        );
    }
}

/// Shared shape assertion for a served local answer: NOERROR, the Question
/// echoes the qname, nothing leaked upstream, and every owner is reachable.
fn assert_served_locally(response: &Message, upstream: &TrapUpstream, qname: &str) {
    assert_eq!(
        upstream.calls(),
        0,
        "local records must short-circuit before upstream — the query leaked to \
         `{:?}`. Until this holds, every owner-name assertion below is vacuous: \
         the mock upstream echoes the asked name, so its answer is shaped exactly \
         like a correct local exact-match hit.",
        upstream.last_query_name(),
    );
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        response.queries.first().map(|q| q.name().clone()),
        Some(name(qname)),
        "the response's Question section must echo the client's qname"
    );
    assert_answers_reachable_from_qname(response);
}

fn a_ip(rr: &Record) -> Ipv4Addr {
    match &rr.data {
        RData::A(A(ip)) => *ip,
        other => panic!("expected an A record, got {other:?}"),
    }
}

fn aaaa_ip(rr: &Record) -> Ipv6Addr {
    match &rr.data {
        RData::AAAA(AAAA(ip)) => *ip,
        other => panic!("expected an AAAA record, got {other:?}"),
    }
}

/// The owner **split**: a CNAME-follow answer carries two owners, not one.
///
/// `qname CNAME target` is owned by the qname (it is the client's entry point
/// into the chain); `target A ip` keeps the *target's* own name. Collapsing
/// both onto the qname — the intuitive-looking "fix" — orphans the A record
/// from the CNAME that points at it and is precisely the shape glibc discards.
/// Order is positional because `send_local` passes `records.iter()` straight
/// through, so the wire order is the lookup's order.
fn assert_cname_then_a_owner_split(
    response: &Message,
    qname: &str,
    target: &str,
    target_ip: Ipv4Addr,
) {
    assert_eq!(
        response.answers.len(),
        2,
        "CNAME-follow to a local target must answer with the CNAME AND the \
         target's A record, got: {:?}",
        response.answers
    );

    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(
        &response.answers[0].name,
        &name(qname),
        "the CNAME RR must be owned by the QNAME — it is the record the client's \
         stub resolver needs to enter the chain"
    );
    match &response.answers[0].data {
        RData::CNAME(CNAME(t)) => assert_eq!(
            t,
            &name(target),
            "the CNAME's RDATA target is config data and must survive verbatim"
        ),
        other => panic!("first answer must be a CNAME, got {other:?}"),
    }

    assert_eq!(response.answers[1].record_type(), RecordType::A);
    assert_eq!(
        &response.answers[1].name,
        &name(target),
        "the followed target's A RR keeps the TARGET's name, not the QNAME — \
         relabelling it orphans it from the CNAME above"
    );
    assert_eq!(a_ip(&response.answers[1]), target_ip);
}

// ── profile-scope call site (handler.rs:983) ────────────────────────────────

#[tokio::test]
async fn profile_scope_exact_match_a_is_owned_by_the_qname() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![rec(NAS, LocalDnsRecordType::A, "192.168.1.50", false)],
        vec![],
        upstream.clone(),
    );

    let response = query(&handler, "nas.home.", RecordType::A).await;

    assert_served_locally(&response, &upstream, "nas.home");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::A);
    assert_eq!(
        &response.answers[0].name,
        &name(NAS),
        "an exact-match A record is owned by the queried name"
    );
    assert_eq!(a_ip(&response.answers[0]), NAS_IP_PROFILE);
}

#[tokio::test]
async fn profile_scope_exact_match_aaaa_is_owned_by_the_qname() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![rec(NAS, LocalDnsRecordType::AAAA, "fd00::1", false)],
        vec![],
        upstream.clone(),
    );

    let response = query(&handler, "nas.home.", RecordType::AAAA).await;

    assert_served_locally(&response, &upstream, "nas.home");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::AAAA);
    assert_eq!(&response.answers[0].name, &name(NAS));
    assert_eq!(aaaa_ip(&response.answers[0]), V6);
}

/// `v0.22.1-localdns-wildcard-owner` at the wire. A wildcard record is stored
/// under its apex; the answer must be re-owned by the QNAME. Serving it owned
/// by `example.test` for a query on `app.example.test` is the shape glibc's
/// `getanswer()` throws away — `dig` prints it and exits 0.
#[tokio::test]
async fn profile_scope_wildcard_descendant_a_is_owned_by_the_qname_not_the_apex() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![rec(
            WILDCARD_APEX,
            LocalDnsRecordType::A,
            "192.0.2.60",
            true,
        )],
        vec![],
        upstream.clone(),
    );

    for qname in [WILDCARD_CHILD, WILDCARD_DEEP_CHILD] {
        let response = query(&handler, &format!("{qname}."), RecordType::A).await;

        assert_served_locally(&response, &upstream, qname);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        assert_eq!(
            &response.answers[0].name,
            &name(qname),
            "a wildcard-descendant answer must be owned by the QNAME, not the \
             configured apex `{WILDCARD_APEX}`"
        );
        assert_eq!(a_ip(&response.answers[0]), WILDCARD_IP);
    }
}

#[tokio::test]
async fn profile_scope_cname_follow_to_local_target_splits_owners() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![
            rec(NAS, LocalDnsRecordType::A, "192.168.1.50", false),
            rec(MEDIA, LocalDnsRecordType::CNAME, NAS, false),
        ],
        vec![],
        upstream.clone(),
    );

    let response = query(&handler, "media.home.", RecordType::A).await;

    assert_served_locally(&response, &upstream, MEDIA);
    assert_cname_then_a_owner_split(&response, MEDIA, NAS, NAS_IP_PROFILE);
}

/// Both defect classes at once: a *wildcard* CNAME followed to a local target.
/// The CNAME must be re-owned by the QNAME (wildcard rule) while the target's A
/// keeps its own name (chain rule). Getting either one wrong breaks resolution.
#[tokio::test]
async fn profile_scope_wildcard_cname_follow_splits_owners() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![
            rec(WILDCARD_APEX, LocalDnsRecordType::CNAME, NAS, true),
            rec(NAS, LocalDnsRecordType::A, "192.168.1.50", false),
        ],
        vec![],
        upstream.clone(),
    );

    let response = query(&handler, "app.example.test.", RecordType::A).await;

    assert_served_locally(&response, &upstream, WILDCARD_CHILD);
    assert_cname_then_a_owner_split(&response, WILDCARD_CHILD, NAS, NAS_IP_PROFILE);
}

// ── global call site (handler.rs:1016) ──────────────────────────────────────

#[tokio::test]
async fn global_scope_exact_match_a_is_owned_by_the_qname() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![],
        vec![rec(NAS, LocalDnsRecordType::A, "192.168.1.51", false)],
        upstream.clone(),
    );

    let response = query(&handler, "nas.home.", RecordType::A).await;

    assert_served_locally(&response, &upstream, "nas.home");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::A);
    assert_eq!(&response.answers[0].name, &name(NAS));
    assert_eq!(a_ip(&response.answers[0]), NAS_IP_GLOBAL);
}

#[tokio::test]
async fn global_scope_exact_match_aaaa_is_owned_by_the_qname() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![],
        vec![rec(NAS, LocalDnsRecordType::AAAA, "fd00::1", false)],
        upstream.clone(),
    );

    let response = query(&handler, "nas.home.", RecordType::AAAA).await;

    assert_served_locally(&response, &upstream, "nas.home");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].record_type(), RecordType::AAAA);
    assert_eq!(&response.answers[0].name, &name(NAS));
    assert_eq!(aaaa_ip(&response.answers[0]), V6);
}

#[tokio::test]
async fn global_scope_wildcard_descendant_a_is_owned_by_the_qname_not_the_apex() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![],
        vec![rec(
            WILDCARD_APEX,
            LocalDnsRecordType::A,
            "192.0.2.60",
            true,
        )],
        upstream.clone(),
    );

    for qname in [WILDCARD_CHILD, WILDCARD_DEEP_CHILD] {
        let response = query(&handler, &format!("{qname}."), RecordType::A).await;

        assert_served_locally(&response, &upstream, qname);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        assert_eq!(
            &response.answers[0].name,
            &name(qname),
            "a wildcard-descendant answer must be owned by the QNAME, not the \
             configured apex `{WILDCARD_APEX}`"
        );
        assert_eq!(a_ip(&response.answers[0]), WILDCARD_IP);
    }
}

#[tokio::test]
async fn global_scope_cname_follow_to_local_target_splits_owners() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![],
        vec![
            rec(NAS, LocalDnsRecordType::A, "192.168.1.51", false),
            rec(MEDIA, LocalDnsRecordType::CNAME, NAS, false),
        ],
        upstream.clone(),
    );

    let response = query(&handler, "media.home.", RecordType::A).await;

    assert_served_locally(&response, &upstream, MEDIA);
    assert_cname_then_a_owner_split(&response, MEDIA, NAS, NAS_IP_GLOBAL);
}

#[tokio::test]
async fn global_scope_wildcard_cname_follow_splits_owners() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![],
        vec![
            rec(WILDCARD_APEX, LocalDnsRecordType::CNAME, NAS, true),
            rec(NAS, LocalDnsRecordType::A, "192.168.1.51", false),
        ],
        upstream.clone(),
    );

    let response = query(&handler, "app.example.test.", RecordType::A).await;

    assert_served_locally(&response, &upstream, WILDCARD_CHILD);
    assert_cname_then_a_owner_split(&response, WILDCARD_CHILD, NAS, NAS_IP_GLOBAL);
}

// ── the two call sites are ordered, not interchangeable ─────────────────────

/// DR7: profile scope is probed first and shadows the global table silently
/// (handler.rs:939-945). With the same name in both tables, the wire must carry
/// the *profile's* value — this is what proves the two fixtures above drove two
/// genuinely different call sites rather than the same one twice.
#[tokio::test]
async fn profile_scope_shadows_the_global_table_on_the_wire() {
    let upstream = Arc::new(TrapUpstream::new());
    let handler = handler_with(
        vec![rec(NAS, LocalDnsRecordType::A, "192.168.1.50", false)],
        vec![rec(NAS, LocalDnsRecordType::A, "192.168.1.51", false)],
        upstream.clone(),
    );

    let response = query(&handler, "nas.home.", RecordType::A).await;

    assert_served_locally(&response, &upstream, NAS);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(
        a_ip(&response.answers[0]),
        NAS_IP_PROFILE,
        "profile-scoped local_records must shadow the global local_dns table"
    );
    assert_eq!(&response.answers[0].name, &name(NAS));
}
