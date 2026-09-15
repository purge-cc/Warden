//! Grants are issued for the original QNAME and uniformly reach answer checks.
use hickory_net::xfer::Protocol;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{A, CNAME},
        Name, RData, Record, RecordType,
    },
    serialize::binary::{BinDecodable, BinEncoder},
};
use hickory_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponse,
};
use purge_warden::{
    config::{
        schema::{ConfigV1, CustomList, Id, Profile, TARGET_SCHEMA_VERSION_V5},
        settings::{CacheConfig, RewriteRule},
    },
    dns::{cache::DnsCache, edns::EdnsClientSubnet, error::DnsError, handler::ForwardHandler},
    filter::{
        ip_filter::IpFilter,
        operator_rules::{
            CompileAdmission, CompiledOperatorRules, PackSource, ProfileMounts, RuleCompileLimits,
        },
        FilterEngine,
    },
    profiles::ProfileResolver,
    upstream::{Upstream, UpstreamResponse},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const Q: &str = "app.example.";
const EVIL: &str = "evil.example.";
const CLEAN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const BAD: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);
const FROM: &str = "shop.example.";
const TO: &str = "tracker.example.";
#[derive(Clone, Copy)]
enum Answer {
    Chain,
    Ip,
    Spoof,
}
struct Up {
    calls: AtomicUsize,
    last: Mutex<Option<String>>,
    answer: Answer,
}
impl Up {
    fn new(answer: Answer) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
            answer,
        }
    }
    fn last(&self) -> Option<String> {
        self.last.lock().unwrap().clone()
    }
}
#[async_trait::async_trait]
impl Upstream for Up {
    async fn lookup(
        &self,
        name: &Name,
        _: RecordType,
        _: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(name.to_string());
        let evil = Name::from_ascii(EVIL).unwrap();
        let records = match self.answer {
            Answer::Chain => vec![
                Record::from_rdata(name.clone(), 300, RData::CNAME(CNAME(evil.clone()))),
                Record::from_rdata(evil, 300, RData::A(A(CLEAN))),
            ],
            Answer::Ip => vec![Record::from_rdata(name.clone(), 300, RData::A(A(BAD)))],
            Answer::Spoof => vec![
                Record::from_rdata(
                    Name::from_ascii(Q).unwrap(),
                    300,
                    RData::CNAME(CNAME(Name::from_ascii("unrelated.example.").unwrap())),
                ),
                Record::from_rdata(name.clone(), 300, RData::CNAME(CNAME(evil.clone()))),
                Record::from_rdata(evil, 300, RData::A(A(CLEAN))),
            ],
        };
        Ok(UpstreamResponse {
            records,
            response_code: ResponseCode::NoError,
            generation: None,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}
#[derive(Clone, Default)]
struct Recorder {
    last: Arc<Mutex<Option<Message>>>,
}
impl Recorder {
    fn response(&self) -> Message {
        self.last.lock().unwrap().clone().expect("one response")
    }
}
#[async_trait::async_trait]
impl ResponseHandler for Recorder {
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
        let mut b = Vec::new();
        let info = {
            let mut e = BinEncoder::new(&mut b);
            response.destructive_emit(&mut e).expect("serialize")
        };
        *self.last.lock().unwrap() = Some(Message::from_bytes(&b).expect("parse"));
        Ok(info)
    }
}
fn resolver(rules: &str, rewrite: bool) -> Arc<ProfileResolver> {
    let mut p = Profile {
        custom_lists: vec![Id::new("rules").unwrap()],
        ..Profile::default()
    };
    if rewrite {
        p.rewrite_rules = vec![RewriteRule {
            from: FROM.trim_end_matches('.').into(),
            to: TO.trim_end_matches('.').into(),
            match_subdomains: false,
        }]
    }
    let mut c = ConfigV1 {
        schema_version: TARGET_SCHEMA_VERSION_V5,
        ..ConfigV1::default()
    };
    c.server.default_profile = Some(Id::new("demo").unwrap());
    c.custom_lists.push(CustomList {
        id: Id::new("rules").unwrap(),
        display_name: "rules".into(),
        description: String::new(),
    });
    c.profiles.insert("demo".into(), p);
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let compiled = Arc::new(
        CompiledOperatorRules::compile(
            &[PackSource {
                list_id: "rules",
                content: rules,
            }],
            &[ProfileMounts {
                profile_id: "demo",
                custom_lists: &["rules"],
                block_all: false,
            }],
            limits,
            &admission,
        )
        .unwrap(),
    );
    Arc::new(ProfileResolver::build_with_operator_rules(&c, compiled))
}
fn handler(up: Arc<Up>, r: Arc<ProfileResolver>, ip: Option<Arc<IpFilter>>) -> ForwardHandler {
    ForwardHandler::new(
        up,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(r),
        None,
        None,
        None,
        ip,
        None,
        60,
        None,
        0.0,
        16,
    )
}
fn ips(ip: Ipv4Addr) -> Arc<IpFilter> {
    let mut s = std::collections::HashSet::with_hasher(ahash::RandomState::new());
    s.insert(IpAddr::V4(ip));
    Arc::new(IpFilter::with_ips(s))
}
fn request(q: &str) -> Request {
    let mut m = Message::new(1, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(q).unwrap(), RecordType::A));
    Request::from_bytes(
        m.to_vec().unwrap(),
        SocketAddr::new(IpAddr::V4(CLIENT), 40000),
        Protocol::Udp,
    )
    .unwrap()
}
async fn query(h: &ForwardHandler, q: &str) -> Message {
    let r = Recorder::default();
    h.handle_request::<_, hickory_server::net::runtime::TokioTime>(&request(q), r.clone())
        .await;
    r.response()
}
fn addresses(m: &Message) -> Vec<Ipv4Addr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(A(ip)) => Some(*ip),
            _ => None,
        })
        .collect()
}
fn blocked(m: &Message) {
    assert_eq!(addresses(m), vec![Ipv4Addr::UNSPECIFIED])
}
fn forwarded(m: &Message, ip: Ipv4Addr) {
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(addresses(m).contains(&ip), "{:?}", m.answers);
    assert!(!addresses(m).contains(&Ipv4Addr::UNSPECIFIED))
}
#[tokio::test]
async fn ungranted_cname_target_deny_still_blocks() {
    blocked(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Chain)),
                resolver("evil.example", false),
                None,
            ),
            Q,
        )
        .await,
    )
}
#[tokio::test]
async fn ungranted_response_ip_still_blocks() {
    blocked(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Ip)),
                resolver("", false),
                Some(ips(BAD)),
            ),
            Q,
        )
        .await,
    )
}
#[tokio::test]
async fn ordinary_original_grant_passes_ordinary_cname_deny() {
    forwarded(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Chain)),
                resolver("@@app.example\nevil.example", false),
                None,
            ),
            Q,
        )
        .await,
        CLEAN,
    )
}
#[tokio::test]
async fn ordinary_original_grant_cannot_beat_important_cname_deny() {
    blocked(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Chain)),
                resolver("@@app.example\nevil.example$important", false),
                None,
            ),
            Q,
        )
        .await,
    )
}
#[tokio::test]
async fn original_grant_passes_response_ip_blocklist() {
    forwarded(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Ip)),
                resolver("@@app.example", false),
                Some(ips(BAD)),
            ),
            Q,
        )
        .await,
        BAD,
    )
}
#[tokio::test]
async fn grant_is_issued_before_rewrite() {
    let up = Arc::new(Up::new(Answer::Chain));
    let h = handler(
        up.clone(),
        resolver("@@shop.example\ntracker.example", true),
        None,
    );
    forwarded(&query(&h, FROM).await, CLEAN);
    assert_eq!(up.last().as_deref(), Some(TO))
}
#[tokio::test]
async fn response_owner_cannot_forge_original_qname_grant() {
    blocked(
        &query(
            &handler(
                Arc::new(Up::new(Answer::Spoof)),
                resolver("@@app.example\nevil.example", false),
                None,
            ),
            "victim.example.",
        )
        .await,
    )
}
