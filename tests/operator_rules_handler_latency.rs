//! Opt-in release-mode latency harness for the complete in-process DNS handler.
//!
//! This is deliberately separate from `operator_rules_perf_probe`: it measures
//! request handling plus cache and response encoding, not an isolated rule
//! lookup. The synthetic upstream is in-process and cannot open a socket.
//! Consequently the cold figures include deterministic mock-upstream work,
//! while the warm figures exercise the cache-hit path. Both include response
//! serialization, the handler's normal allocations, and sampling-clock /
//! scheduler noise. They are not an exact engine comparison or a DNS network
//! latency claim.
//!
//! The schema-4 compatibility evaluator is not equivalent to the schema-5
//! compiled resolver at the full handler boundary, so this harness does not
//! invent a percentage comparison. The exact-rule gate remains in the
//! lookup-only probe and Criterion benchmarks, where compatible evaluations
//! are isolated.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use purge_warden::config::schema::{ConfigV5, Id, TARGET_SCHEMA_VERSION_V5};
use purge_warden::config::target_v5::{compile_v5_operator_rules, PackBodiesV5};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::filter::operator_rules::CompileAdmission;
use purge_warden::filter::FilterEngine;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SAMPLES: usize = 2_000;
const WARMUP: usize = 200;
const QNAME: &str = "media.example.";
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const CONFIG: &str = include_str!("fixtures/target-v5/config.toml");
const STREAMING_PACK: &str = include_str!("fixtures/target-v5/packs/streaming.txt");
const ARCHIVE_PACK: &str = include_str!("fixtures/target-v5/packs/archive.txt");

fn require_release_mode() {
    if cfg!(debug_assertions) {
        panic!(
            "release mode is required: cargo test --release --test operator_rules_handler_latency -- --ignored --nocapture"
        );
    }
}

/// The handler's request path sees a normal `Upstream` implementation, but no
/// transport, timer, filesystem, or network is reachable from this fixture.
#[derive(Default)]
struct InProcessUpstream {
    calls: AtomicUsize,
}

impl InProcessUpstream {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl Upstream for InProcessUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let record = match record_type {
            RecordType::A => Record::from_rdata(
                name.clone(),
                300,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 42))),
            ),
            RecordType::AAAA => Record::from_rdata(
                name.clone(),
                300,
                RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42))),
            ),
            other => panic!("harness only issues A and AAAA requests, got {other:?}"),
        };
        Ok(UpstreamResponse {
            records: vec![record],
            response_code: ResponseCode::NoError,
            generation: None,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

/// Encodes the actual `MessageResponse` into a buffer reserved before timing.
/// This retains response serialization in the latency measurement without
/// adding a mutex or a fresh sink allocation to every sample.
#[derive(Clone)]
struct EncodingResponseHandler {
    wire: Vec<u8>,
}

impl EncodingResponseHandler {
    fn new() -> Self {
        Self {
            wire: Vec::with_capacity(512),
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for EncodingResponseHandler {
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
        self.wire.clear();
        let mut encoder = BinEncoder::new(&mut self.wire);
        let info = response
            .destructive_emit(&mut encoder)
            .expect("synthetic response must encode");
        black_box(self.wire.len());
        Ok(info)
    }
}

fn request(record_type: RecordType) -> Request {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(QNAME).unwrap(), record_type));
    Request::from_bytes(
        message.to_vec().unwrap(),
        SocketAddr::new(IpAddr::V4(CLIENT), 40_000),
        Protocol::Udp,
    )
    .unwrap()
}

fn schema5_resolver() -> Arc<ProfileResolver> {
    let config: ConfigV5 = toml::from_str(CONFIG).expect("schema-5 fixture parses");
    assert_eq!(config.schema_version, TARGET_SCHEMA_VERSION_V5);

    let mut bodies = PackBodiesV5::default();
    bodies.insert(
        Id::new("streaming").unwrap(),
        Arc::<str>::from(STREAMING_PACK),
    );
    bodies.insert(Id::new("archive").unwrap(), Arc::<str>::from(ARCHIVE_PACK));
    let admission = CompileAdmission::new(128 << 20, 1).unwrap();
    let compiled = Arc::new(
        compile_v5_operator_rules(&config, &bodies, &admission)
            .expect("target fixture compiles into a schema-5 rule snapshot"),
    );
    let projection = config
        .validation_projection()
        .expect("schema-5 fixture projects for the current resolver");
    Arc::new(ProfileResolver::build_with_operator_rules(
        &projection,
        compiled,
    ))
}

fn handler(upstream: Arc<InProcessUpstream>, resolver: Arc<ProfileResolver>) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&Default::default()),
        Some(resolver),
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
}

async fn handle_once(handler: &ForwardHandler, request: &Request) {
    let response_handler = EncodingResponseHandler::new();
    let info = handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(request, response_handler)
        .await;
    black_box(info);
}

async fn timed_request(handler: &ForwardHandler, request: &Request) -> u64 {
    let response_handler = EncodingResponseHandler::new();
    let start = Instant::now();
    let info = handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(request, response_handler)
        .await;
    black_box(info);
    start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn report(label: &str, mut samples: Vec<u64>) {
    samples.sort_unstable();
    let percentile = |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1];
    eprintln!(
        "handler-latency/{label}: samples={} warmup={} p50_ns={} p99_ns={}",
        samples.len(),
        WARMUP,
        percentile(50),
        percentile(99),
    );
}

async fn cold_samples(
    upstream: Arc<InProcessUpstream>,
    resolver: Arc<ProfileResolver>,
    request: &Request,
) -> Vec<u64> {
    let before = upstream.calls();
    for _ in 0..WARMUP {
        let handler = handler(Arc::clone(&upstream), Arc::clone(&resolver));
        handle_once(&handler, request).await;
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        // Handler and cache construction stay outside the measured request.
        // Each sample therefore reaches the controlled upstream on a cache miss.
        let handler = handler(Arc::clone(&upstream), Arc::clone(&resolver));
        samples.push(timed_request(&handler, request).await);
    }
    assert_eq!(
        upstream.calls() - before,
        WARMUP + SAMPLES,
        "every cold sample must use the in-process upstream exactly once"
    );
    samples
}

async fn warm_samples(
    upstream: Arc<InProcessUpstream>,
    resolver: Arc<ProfileResolver>,
    request: &Request,
) -> Vec<u64> {
    let handler = handler(Arc::clone(&upstream), resolver);
    let before = upstream.calls();
    handle_once(&handler, request).await;
    assert_eq!(
        upstream.calls() - before,
        1,
        "the unmeasured prime must populate this qtype's cache entry"
    );

    for _ in 0..WARMUP {
        handle_once(&handler, request).await;
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        samples.push(timed_request(&handler, request).await);
    }
    assert_eq!(
        upstream.calls() - before,
        1,
        "warm samples must remain on the cache-hit path"
    );
    samples
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "manual release-only handler latency harness; run --release --ignored --nocapture"]
async fn operator_rules_handler_latency() {
    require_release_mode();
    eprintln!(
        "handler-latency: schema=5 compiled-resolver; samples={SAMPLES}; warmup={WARMUP}; \
         load=single sequential task; allocator=jemalloc; upstream=in-process/no-network; \
         scope=ForwardHandler request handling plus response encoding; \
         includes clock/scheduling and normal handler/cache allocations; \
         exact +/-2% engine comparison remains in lookup-only/Criterion probes"
    );

    let resolver = schema5_resolver();
    let upstream = Arc::new(InProcessUpstream::default());
    for (label, record_type) in [("a", RecordType::A), ("aaaa", RecordType::AAAA)] {
        let request = request(record_type);
        report(
            &format!("schema5/{label}/cache-cold"),
            cold_samples(Arc::clone(&upstream), Arc::clone(&resolver), &request).await,
        );
        report(
            &format!("schema5/{label}/cache-warm"),
            warm_samples(Arc::clone(&upstream), Arc::clone(&resolver), &request).await,
        );
    }
}
