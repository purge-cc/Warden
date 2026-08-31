//! §4.8 Sprint 1/2 integration test: plain raw-socket upstream attaches
//! the EDNS Client Subnet option to outbound UDP queries.
//!
//! Spawns a one-shot UDP mock server that:
//!   1. waits for a single incoming DNS query;
//!   2. parses the wire bytes via `hickory_proto::op::Message`;
//!   3. asserts the EDNS extension is present and carries the ECS option
//!      (code 8) in its expected anonymous form (source_prefix=0, scope=0,
//!      zero address bytes — the privacy-safe Sprint 1 default);
//!   4. emits a minimal NOERROR response so the client lookup completes
//!      without surfacing an error.
//!
//! Mirrors the §4.12 Domain Rewrite hot-path mutation lesson (memory
//! `feedback_hot_path_name_mutation_tests`): asserts what is *actually
//! placed on the wire upstream*, not just what the client struct holds.

use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use purge_warden::dns::edns::{AddressFamily, EdnsClientSubnet};
use purge_warden::upstream::plain_raw::PlainRawClient;
use tokio::net::UdpSocket;

#[tokio::test]
async fn plain_raw_attaches_ecs_option_to_outbound_udp_query() {
    // Bind ephemeral UDP socket as the mock upstream.
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let server_addr = server.local_addr().expect("local addr");

    // Server task: receive one query, validate ECS, reply NOERROR.
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.expect("recv");
        buf.truncate(n);

        let parsed = Message::from_vec(&buf).expect("parse query");
        let edns = parsed
            .edns
            .as_ref()
            .expect("EDNS extension on outbound query");
        let opt = edns
            .option(EdnsCode::Subnet)
            .expect("ECS option (code 8) present");
        match opt {
            EdnsOption::Subnet(cs) => {
                assert_eq!(cs.source_prefix(), 0, "Sprint 1 default: anonymous form");
                assert_eq!(cs.scope_prefix(), 0, "query side: scope_prefix=0");
            }
            other => panic!("expected EdnsOption::Subnet, got {other:?}"),
        }

        // Emit a tiny NOERROR response echoing the query id + question.
        let mut resp = Message::new(parsed.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = ResponseCode::NoError;
        if let Some(q) = parsed.queries.first() {
            resp.add_query(q.clone());
        }
        let resp_bytes = resp.to_vec().expect("serialize response");
        server.send_to(&resp_bytes, peer).await.expect("send resp");
    });

    // Client: PlainRawClient gets per-query ECS via lookup arg (T4).
    let ecs = EdnsClientSubnet::anonymous(AddressFamily::V4);
    let client = PlainRawClient::new(&[server_addr.to_string()], Duration::from_secs(2), false)
        .expect("client");
    let qname: Name = "example.com.".parse().unwrap();
    let resp = client
        .lookup(&qname, RecordType::A, Some(ecs))
        .await
        .expect("lookup ok");
    assert_eq!(resp.response_code, ResponseCode::NoError);

    server_task.await.expect("server task");
}
