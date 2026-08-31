//! §4.30 m4 integration: per-server UDP socket pool reuse + msg-id rebind.
//!
//! Spawns a one-shot UDP mock server, makes a small batch of sequential
//! lookups via [`PlainRawClient`], and asserts:
//!
//!   1. With `pool_size = 4` (current `UDP_POOL_SIZE`), the round-robin
//!      slot pointer wraps after 4 queries, so the 5th query reuses the
//!      same ephemeral source port as the 1st (= same pooled UdpSocket).
//!   2. Two consecutive queries on different slots use different ports.
//!   3. A response carrying a wrong message id is rejected (slot
//!      poisoning kicks in; the rebind cannot be observed in this same
//!      test without running ≥5 queries against a server that ID-spoofs
//!      every reply — out of scope for this fixture).
//!
//! Pre-§4.30 the daemon `bind(2)+connect(2)`-ed a fresh ephemeral socket
//! per query (~10 µs syscall overhead). The pool keeps the same source
//! port across reused queries, which both removes that syscall cost and
//! lets stateful upstreams (none today, but a future LAN forwarder) see
//! consistent client identity.
//!
//! Mirrors the §4.8 ECS integration test (`integration_ecs_plain.rs`):
//! same `Message::from_vec`-based parse + reply pattern, same minimal
//! NOERROR echo response shape.

use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use purge_warden::upstream::plain_raw::PlainRawClient;
use tokio::net::UdpSocket;

const POOL_SIZE: usize = 4;

#[tokio::test]
async fn udp_socket_pool_reuses_slot_zero_after_round_robin_wrap() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let server_addr = server.local_addr().expect("local addr");

    // Server: echo NOERROR for the first POOL_SIZE+1 queries, recording
    // the source port of each incoming datagram so the test can assert
    // pool-slot reuse across the wrap.
    let (port_tx, mut port_rx) = tokio::sync::mpsc::unbounded_channel();
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        for _ in 0..=POOL_SIZE {
            let (n, peer) = server.recv_from(&mut buf).await.expect("recv");
            let parsed = Message::from_vec(&buf[..n]).expect("parse query");
            let mut resp = Message::new(parsed.metadata.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = parsed.queries.first() {
                resp.add_query(q.clone());
            }
            let resp_bytes = resp.to_vec().expect("serialize response");
            server.send_to(&resp_bytes, peer).await.expect("send resp");
            port_tx.send(peer.port()).expect("chan send");
        }
    });

    let client = PlainRawClient::new(&[server_addr.to_string()], Duration::from_secs(2), false)
        .expect("client");
    let qname: Name = "example.com.".parse().unwrap();

    let mut ports = Vec::with_capacity(POOL_SIZE + 1);
    for _ in 0..=POOL_SIZE {
        let resp = client
            .lookup(&qname, RecordType::A, None)
            .await
            .expect("lookup ok");
        assert_eq!(resp.response_code, ResponseCode::NoError);
        ports.push(port_rx.recv().await.expect("port from server"));
    }
    server_task.await.expect("server task");

    // The (POOL_SIZE+1)th query wraps the round-robin pointer back to
    // slot 0 → reuses the same pooled UdpSocket → same ephemeral port.
    assert_eq!(
        ports[0], ports[POOL_SIZE],
        "§4.30 m4: query at index POOL_SIZE must reuse slot 0's socket \
         (same ephemeral source port as query 0). Got ports = {ports:?}",
    );
    // First POOL_SIZE queries fan out across distinct slots → distinct
    // pooled sockets → distinct ephemeral ports.
    assert_ne!(
        ports[0], ports[1],
        "§4.30 m4: queries on different pool slots must use different ephemeral ports. \
         Got ports = {ports:?}",
    );
}

#[tokio::test]
async fn udp_socket_pool_rejects_msg_id_mismatch() {
    // §4.30 m4 correctness pin: with pooled sockets, a stray reply from
    // an out-of-order or spoofed source could land in a future query's
    // buffer. The msg-id check rejects mismatches and poisons the slot
    // so the next caller rebinds. Pre-§4.30 every query bound a fresh
    // socket, so this case never arose — but mismatched-id replies were
    // also silently consumed as if correct.
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let server_addr = server.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = server.recv_from(&mut buf).await.expect("recv");
        let parsed = Message::from_vec(&buf[..n]).expect("parse");
        // Deliberately send a WRONG msg-id.
        let mut resp = Message::new(
            parsed.metadata.id.wrapping_add(0xDEAD),
            MessageType::Response,
            OpCode::Query,
        );
        resp.metadata.response_code = ResponseCode::NoError;
        if let Some(q) = parsed.queries.first() {
            resp.add_query(q.clone());
        }
        let resp_bytes = resp.to_vec().expect("serialize");
        server.send_to(&resp_bytes, peer).await.expect("send");
    });

    let client = PlainRawClient::new(&[server_addr.to_string()], Duration::from_secs(2), false)
        .expect("client");
    let qname: Name = "example.com.".parse().unwrap();

    let result = client.lookup(&qname, RecordType::A, None).await;
    server_task.await.expect("server task");
    assert!(
        result.is_err(),
        "§4.30 m4: msg-id mismatch must fail the lookup, got {result:?}",
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("msg-id mismatch"),
        "expected msg-id mismatch error from PlainRawClient, got: {err}",
    );
}
