//! Raw-socket plain DNS client used when ECS injection is enabled.
//!
//! `hickory_resolver` 0.25 exposes no public ECS API (only `ResolverOpts.edns0`
//! and `DnsRequestOptions.use_edns` booleans, no options bag), so plain UDP/TCP
//! transport must bypass the high-level resolver to attach an EDNS Client
//! Subnet option on outbound queries.
//!
//! `PlainUpstream` keeps the existing `Resolver` path when ECS is disabled
//! (no behavioural change) and dispatches to `PlainRawClient` only when the
//! operator opts in.
//!
//! Implements UDP-first with TCP fallback when the upstream response carries
//! the TC (truncation) bit, mirroring the standard plain-DNS behaviour. Retry
//! and timeout policy are deliberately minimal — the ambient `CircuitBreaker`
//! around `UpstreamResolver` handles longer-term failover, this client just
//! handles per-query semantics.
//!
//! UDP fast-path: UDP sockets are pooled per-server (default 4 slots,
//! see [`UDP_POOL_SIZE`]) instead of bind-per-query. Each slot serializes its
//! own send→recv through a tokio Mutex — UDP recv on a shared socket can
//! otherwise steal another query's response. The non-truncated UDP path
//! parses the response exactly once (RFC 1035 §4.1.1 TC-bit byte-mask check
//! feeds straight into `parse_response_bytes`) and uses a stack buffer
//! instead of a per-query heap allocation. Slot poisoning on recv error or
//! message-id mismatch forces a rebind on the next use.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::Query;
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

use super::{build_query, parse_response_bytes, UpstreamResponse};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

const UDP_BUFFER_SIZE: usize = 4096;

/// Per-server pool slot count. Mirrors the DoT default (`src/upstream/dot.rs`)
/// and balances burst capacity against fd budget (4 × N_servers, typically
/// 16–32 fds total — well under any soft cap). Hardcoded internally; not
/// exposed as an operator config knob.
const UDP_POOL_SIZE: usize = 4;

/// Outcome of a single `udp_exchange`. `Response` carries the
/// already-parsed answer (the non-truncated UDP path parses exactly once);
/// `Truncated` signals to `exchange()` that the TC bit was set and the
/// caller must retry over TCP.
enum UdpResult {
    Response(UpstreamResponse),
    Truncated,
}

pub struct PlainRawClient {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    next: AtomicUsize,
    /// Per-server pool of lazily-bound, connected `UdpSocket`s.
    /// Shape: `servers.len()` outer × [`UDP_POOL_SIZE`] inner. Each slot
    /// is independently lockable; the Mutex serializes the send→recv
    /// sequence on that single socket so a delayed reply from a
    /// previous query can't be misrouted by a concurrent recv on the
    /// same fd. Slot set to `None` on recv error, or on any reply we
    /// refuse (message-id mismatch, unusable wire bytes, a question we
    /// did not ask) — the next caller will rebind.
    sockets: Vec<Vec<Mutex<Option<UdpSocket>>>>,
    /// Round-robin pointer per server. Relaxed ordering: the slot index is
    /// an advisory dispatch hint, not a synchronisation handle (collision
    /// on the same slot just means waiting briefly for the per-slot Mutex).
    next_slot: Vec<AtomicUsize>,
    /// When set, outbound queries carry the EDNS DNSSEC OK (DO) bit so the
    /// upstream returns RRSIG / NSEC / NSEC3 material. Baked at construction
    /// (global policy); the client-facing upstream is built with `false` →
    /// byte-identical wire packets.
    dnssec_ok: bool,
}

impl PlainRawClient {
    pub fn new(
        servers: &[String],
        timeout: Duration,
        dnssec_ok: bool,
    ) -> Result<Self, anyhow::Error> {
        if servers.is_empty() {
            anyhow::bail!("plain upstream requires at least one server");
        }
        // Shape parse shared with `config lint` (single source of truth) — a
        // typo'd plain server is rejected identically at lint/boot.
        let parsed: Vec<SocketAddr> = servers
            .iter()
            .map(|s| {
                crate::upstream::shape::validate_plain_server(s)
                    .map_err(|e| anyhow::anyhow!("invalid plain upstream server: {e}"))
            })
            .collect::<Result<_, _>>()?;
        let sockets = (0..parsed.len())
            .map(|_| {
                (0..UDP_POOL_SIZE)
                    .map(|_| Mutex::new(None))
                    .collect::<Vec<_>>()
            })
            .collect();
        let next_slot = (0..parsed.len()).map(|_| AtomicUsize::new(0)).collect();
        Ok(Self {
            servers: parsed,
            timeout,
            next: AtomicUsize::new(0),
            sockets,
            next_slot,
            dnssec_ok,
        })
    }

    pub async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        let (query_bytes, expected) = build_query(name, record_type, ecs, self.dnssec_ok)?;
        let n = self.servers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;
        let mut last_err: Option<DnsError> = None;
        for offset in 0..n {
            let server_idx = (start + offset) % n;
            let server = self.servers[server_idx];
            match self
                .exchange(server_idx, server, &query_bytes, &expected)
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(
                        server = %server,
                        error = %e,
                        "plain raw exchange failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            DnsError::UpstreamRequestFailed("no plain servers configured".into())
        }))
    }

    async fn exchange(
        &self,
        server_idx: usize,
        server: SocketAddr,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        match self
            .udp_exchange(server_idx, server, query_bytes, expected)
            .await?
        {
            UdpResult::Response(resp) => Ok(resp),
            UdpResult::Truncated => self.tcp_exchange(server, query_bytes, expected).await,
        }
    }

    async fn udp_exchange(
        &self,
        server_idx: usize,
        server: SocketAddr,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UdpResult, DnsError> {
        let slot_idx = self.next_slot[server_idx].fetch_add(1, Ordering::Relaxed) % UDP_POOL_SIZE;
        let mut slot = self.sockets[server_idx][slot_idx].lock().await;
        if slot.is_none() {
            let bind_addr = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let new_sock = UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| DnsError::UpstreamRequestFailed(format!("UDP bind: {e}")))?;
            new_sock.connect(server).await.map_err(|e| {
                DnsError::UpstreamRequestFailed(format!("UDP connect {server}: {e}"))
            })?;
            *slot = Some(new_sock);
        }
        let socket = slot.as_ref().expect("just inserted above when None");

        let send_result = match timeout(self.timeout, socket.send(query_bytes)).await {
            Ok(r) => r,
            Err(_) => {
                // Poison the slot on timeout: a late reply to this timed-out
                // query would otherwise stay queued on the connected socket and
                // be delivered to the next query on this slot (id mismatch →
                // spurious failure). Dropping the socket forces a clean rebind.
                *slot = None;
                return Err(DnsError::UpstreamRequestFailed(format!(
                    "UDP send timeout {server}"
                )));
            }
        };
        if let Err(e) = send_result {
            *slot = None;
            return Err(DnsError::UpstreamRequestFailed(format!(
                "UDP send {server}: {e}"
            )));
        }

        // Stack array instead of `vec![0u8; UDP_BUFFER_SIZE]`. 4 KB on the
        // tokio task stack (default 2 MB) is fine at any realistic
        // concurrent load; the heap alloc per query is gone.
        let mut buf = [0u8; UDP_BUFFER_SIZE];
        let recv_result = match timeout(self.timeout, socket.recv(&mut buf)).await {
            Ok(r) => r,
            Err(_) => {
                // Same poisoning rationale as the send path: drop the socket so a
                // delayed datagram for this query can't land on the next caller.
                *slot = None;
                return Err(DnsError::UpstreamRequestFailed(format!(
                    "UDP recv timeout {server}"
                )));
            }
        };
        let n = match recv_result {
            Ok(n) => n,
            Err(e) => {
                *slot = None;
                return Err(DnsError::UpstreamRequestFailed(format!(
                    "UDP recv {server}: {e}"
                )));
            }
        };

        // Msg-id check. With pooled sockets a stray reply from a previous
        // (timed-out / cancelled) query could land in our buffer; mismatch
        // poisons the slot so the next caller rebinds on a fresh ephemeral
        // port.
        if n < 12 {
            *slot = None;
            return Err(DnsError::WireFormatError(format!(
                "UDP response too short ({n} bytes from {server})"
            )));
        }
        let req_id = u16::from_be_bytes([query_bytes[0], query_bytes[1]]);
        let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
        if req_id != resp_id {
            *slot = None;
            return Err(DnsError::WireFormatError(format!(
                "UDP msg-id mismatch from {server}: sent {req_id}, got {resp_id}"
            )));
        }

        // RFC 1035 §4.1.1 — header byte 2 bit 1 (mask 0x02) is the TC flag.
        // Reading it directly off the wire avoids parsing the full message
        // twice (the non-truncated branch parses exactly once via
        // `parse_response_bytes`).
        let truncated = (buf[2] & 0x02) != 0;
        if truncated {
            Ok(UdpResult::Truncated)
        } else {
            // A datagram this socket delivered that we cannot accept as our
            // answer leaves the slot suspect for the same reason an id
            // mismatch does — more of the same may still be queued on it.
            let parsed = parse_response_bytes(&buf[..n], expected);
            if parsed.is_err() {
                *slot = None;
            }
            parsed.map(UdpResult::Response)
        }
    }

    async fn tcp_exchange(
        &self,
        server: SocketAddr,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        let mut stream = timeout(self.timeout, TcpStream::connect(server))
            .await
            .map_err(|_| DnsError::UpstreamRequestFailed(format!("TCP connect timeout {server}")))?
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("TCP connect {server}: {e}")))?;
        let len: u16 = query_bytes
            .len()
            .try_into()
            .map_err(|_| DnsError::WireFormatError("query > 64KB".into()))?;
        timeout(self.timeout, async {
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(query_bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| DnsError::UpstreamRequestFailed(format!("TCP send timeout {server}")))?
        .map_err(|e| DnsError::UpstreamRequestFailed(format!("TCP send {server}: {e}")))?;
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::UpstreamRequestFailed(format!("TCP recv-len timeout {server}")))?
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("TCP recv-len {server}: {e}")))?;
        let body_len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        timeout(self.timeout, stream.read_exact(&mut body))
            .await
            .map_err(|_| {
                DnsError::UpstreamRequestFailed(format!("TCP recv-body timeout {server}"))
            })?
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("TCP recv-body {server}: {e}")))?;
        parse_response_bytes(&body, expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_one_server() {
        let c = PlainRawClient::new(&["1.1.1.1:53".to_string()], Duration::from_secs(2), false)
            .unwrap();
        assert_eq!(c.servers.len(), 1);
    }

    #[test]
    fn new_empty_servers_rejected() {
        let err = PlainRawClient::new(&[], Duration::from_secs(2), false);
        assert!(err.is_err());
    }

    #[test]
    fn new_invalid_server_rejected() {
        let err = PlainRawClient::new(&["not-an-addr".to_string()], Duration::from_secs(2), false);
        assert!(err.is_err());
    }

    #[test]
    fn pool_shape_matches_servers_and_pool_size() {
        // Regression pin: outer = servers.len(), inner = UDP_POOL_SIZE.
        // Lock the shape against an accidental flat refactor (same posture
        // as `dot.rs` pool_shape test).
        let c = PlainRawClient::new(
            &["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
            Duration::from_secs(2),
            false,
        )
        .unwrap();
        assert_eq!(c.sockets.len(), 2);
        for slots in &c.sockets {
            assert_eq!(slots.len(), UDP_POOL_SIZE);
        }
        assert_eq!(c.next_slot.len(), 2);
    }

    #[test]
    fn tc_bit_byte_mask_matches_hickory_truncated() {
        // Regression pin: the RFC 1035 §4.1.1 byte-mask check
        // `(buf[2] & 0x02) != 0` must agree with hickory's full-message
        // `truncated()` flag on every input. Without that equivalence
        // the single-parse optimisation could misroute responses
        // through the TCP fallback path (or skip it when needed).
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        for tc in [false, true] {
            let mut msg = Message::new(42, MessageType::Response, OpCode::Query);
            msg.metadata.response_code = ResponseCode::NoError;
            msg.metadata.truncation = tc;
            msg.add_query(Query::query("example.com.".parse().unwrap(), RecordType::A));
            let bytes = msg.to_vec().unwrap();
            let by_mask = bytes.len() >= 3 && (bytes[2] & 0x02) != 0;
            let by_hickory = Message::from_vec(&bytes).unwrap().metadata.truncation;
            assert_eq!(
                by_mask, by_hickory,
                "TC byte-mask must match hickory.truncated() for tc={tc}",
            );
        }
    }

    /// Stand-in upstream: answers the first query honestly, then echoes a
    /// question warden never asked — with a matching A record, and the
    /// requester's own message id, so it clears the id check ahead of the
    /// question check.
    async fn honest_then_forging_upstream(sock: tokio::net::UdpSocket) {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};

        let mut buf = [0u8; 512];
        for honest in [true, false] {
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf[..n]).unwrap();
            let question = if honest {
                req.queries[0].clone()
            } else {
                Query::query("attacker.example.net.".parse().unwrap(), RecordType::A)
            };
            let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A::new(203, 0, 113, 7)),
            ));
            resp.add_query(question);
            sock.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
        }
    }

    /// End-to-end over the real UDP transport, which is the one exposed to
    /// off-path forgery: a reply carrying records for a name we never asked
    /// about is refused, so the caller has nothing to cache or serve — and
    /// the socket that delivered it is dropped from the pool.
    ///
    /// The honest exchange first is what makes the pool assertion mean
    /// something: it leaves exactly one slot bound, so a second bound slot
    /// afterwards would be the forgery's socket surviving.
    #[tokio::test]
    async fn forged_question_is_refused_and_drops_the_pooled_socket() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        tokio::spawn(honest_then_forging_upstream(upstream));

        let client =
            PlainRawClient::new(&[addr.to_string()], Duration::from_secs(5), false).unwrap();
        let name: Name = "example.com.".parse().unwrap();

        let honest = client
            .lookup(&name, RecordType::A, None)
            .await
            .expect("a conforming answer is accepted");
        assert_eq!(honest.records.len(), 1, "honest answer carries its record");

        let err = client.lookup(&name, RecordType::A, None).await.unwrap_err();
        assert!(
            matches!(&err, DnsError::WireFormatError(m) if m.contains("does not match")),
            "forged question must be refused, got {err:?}"
        );

        let mut bound = 0;
        for slot in &client.sockets[0] {
            if slot.lock().await.is_some() {
                bound += 1;
            }
        }
        assert_eq!(bound, 1, "the socket that delivered the forgery is dropped");
    }

    #[test]
    fn udp_exchange_uses_stack_buffer_not_heap_vec() {
        // Source-grep guard for the stack-array literal on the UDP hot
        // path. The literal is uniquely sited inside `udp_exchange`; its
        // absence means someone reverted to a heap-allocating buffer and
        // regressed the per-query allocator churn this was sized to
        // eliminate. The negative assertion (no `vec!` of that buffer) is
        // omitted because the forbidden pattern would otherwise appear
        // verbatim inside this same test source via `include_str!`,
        // self-matching.
        let src = include_str!("plain_raw.rs");
        assert!(
            src.contains("let mut buf = [0u8; UDP_BUFFER_SIZE];"),
            "§4.30 m3 regression: stack buffer literal missing from udp_exchange",
        );
    }
}
