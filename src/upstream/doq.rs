//! DNS-over-QUIC upstream (RFC 9250).
//!
//! Establishes and pools QUIC connections to upstream resolvers using the `doq`
//! ALPN (RFC 9250) and implements [`Upstream`] over them: each query opens a
//! fresh bidirectional stream carrying a length-prefixed DNS message
//! (RFC 9250 §4), reusing the pooled connection.
//!
//! Feature-gated behind `doq` (default OFF) so the quinn QUIC stack never
//! bloats the default or Raspberry Pi binary.
//!
//! TLS setup is shared with DoT (`super::install_ring_crypto_provider_once` +
//! `super::webpki_root_store`): same ring crypto provider, same bundled webpki
//! root store. DoQ only adds the `doq` ALPN on top — there is no second
//! TLS-config path.
//!
//! ## Connection model
//!
//! DoT runs a small pool of TCP+TLS streams per server because each stream
//! serialises queries behind a mutex. QUIC instead multiplexes many streams
//! over a single connection with no head-of-line blocking, so a DoQ "pool" is
//! ONE reusable `quinn::Connection` per server. The reuse / invalidate-on-close
//! semantics mirror DoT's per-slot logic; the N-slot/round-robin dimension is
//! intentionally dropped.
//!
//! `DoqUpstream::new` builds a `quinn::Endpoint`, which requires a Tokio runtime
//! context (quinn's tokio runtime supplies the I/O driver) — wired in during
//! async resolver construction.

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Query;
use hickory_proto::rr::{Name, RecordType};
use rustls::ClientConfig;

use super::{
    build_query, install_ring_crypto_provider_once, parse_response_bytes, webpki_root_store,
    Upstream, UpstreamResponse,
};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

/// ALPN protocol identifier for DNS-over-QUIC (RFC 9250 §3.2).
const DOQ_ALPN: &[u8] = b"doq";

/// A single DoQ server endpoint: resolved socket address + TLS server name
/// (SNI / certificate-validation name).
struct DoqServer {
    addr: SocketAddr,
    server_name: String,
}

/// DNS-over-QUIC upstream resolver.
///
/// Holds one client `quinn::Endpoint` shared across all servers, plus one
/// lazily-established, reusable `quinn::Connection` per server.
pub struct DoqUpstream {
    servers: Vec<DoqServer>,
    endpoint: quinn::Endpoint,
    timeout: Duration,
    /// One reuse slot per server, index-aligned with `servers`. QUIC
    /// multiplexes streams over a single connection, so one connection per
    /// server suffices.
    connections: Vec<tokio::sync::Mutex<Option<quinn::Connection>>>,
    /// When set, outbound queries carry the EDNS DNSSEC OK (DO) bit.
    /// Baked at construction (global policy); the client-facing upstream is
    /// built with `false` → byte-identical wire packets.
    dnssec_ok: bool,
}

impl DoqUpstream {
    /// Build a DoQ upstream. Servers may be:
    /// - `IP:port` (e.g. `192.0.2.53:853`) — IP used directly, SNI set to the IP
    /// - `hostname:port` (e.g. `dns.example.net:853`) — resolved via OS DNS at
    ///   startup, hostname used for TLS SNI (certificate validation)
    ///
    /// Must be called within a Tokio runtime context.
    pub fn new(
        servers: &[String],
        timeout: Duration,
        dnssec_ok: bool,
    ) -> Result<Self, anyhow::Error> {
        let parsed = Self::parse_servers(servers)?;
        Self::build(parsed, timeout, dnssec_ok, webpki_root_store())
    }

    /// Parse `host:port` server specs into resolved [`DoqServer`]s, mirroring
    /// the DoT parser (IP fast-path, else OS-resolve the hostname at startup).
    fn parse_servers(servers: &[String]) -> Result<Vec<DoqServer>, anyhow::Error> {
        if servers.is_empty() {
            anyhow::bail!("DoQ upstream requires at least one server");
        }

        let mut out = Vec::with_capacity(servers.len());
        for server in servers {
            // Shared host:port syntax gate (same check `config lint`
            // runs offline) before the resolve+TLS work — a malformed entry is
            // rejected identically at lint and at boot.
            crate::upstream::shape::validate_host_port_server(server)
                .map_err(|e| anyhow::anyhow!("invalid DoQ server: {e}"))?;
            // IP:port fast path — no DNS needed, SNI is the IP literal.
            if let Ok(addr) = server.parse::<SocketAddr>() {
                out.push(DoqServer {
                    addr,
                    server_name: addr.ip().to_string(),
                });
                continue;
            }

            // hostname:port — resolve via OS resolver (blocking, startup only).
            // The hostname is used for TLS SNI so the certificate is validated
            // against the correct name.
            let resolved = server
                .to_socket_addrs()
                .map_err(|e| anyhow::anyhow!("cannot resolve DoQ server \"{server}\": {e}"))?
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("DoQ server \"{server}\" resolved to no addresses")
                })?;
            let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);

            tracing::info!(server, resolved = %resolved, "DoQ server hostname resolved");

            out.push(DoqServer {
                addr: resolved,
                server_name: host.to_owned(),
            });
        }
        Ok(out)
    }

    /// Build the upstream from already-parsed servers and a client root store.
    /// `new` passes the shared webpki store; tests inject a store trusting a
    /// self-signed cert.
    fn build(
        servers: Vec<DoqServer>,
        timeout: Duration,
        dnssec_ok: bool,
        root_store: rustls::RootCertStore,
    ) -> Result<Self, anyhow::Error> {
        // Shared rustls client setup — identical to DoT's path, plus the doq ALPN.
        install_ring_crypto_provider_once();

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("DoQ TLS config has no TLS 1.3 cipher suite: {e}"))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        // One client endpoint shared across all servers, bound to an ephemeral
        // local UDPv4 port. Requires a Tokio runtime context.
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(|e| anyhow::anyhow!("DoQ client endpoint bind failed: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let connections = servers
            .iter()
            .map(|_| tokio::sync::Mutex::new(None))
            .collect();

        Ok(Self {
            servers,
            endpoint,
            timeout,
            connections,
            dnssec_ok,
        })
    }

    /// Establish a fresh QUIC connection to server `idx` — handshake + ALPN
    /// negotiation — bounded by `self.timeout`.
    pub async fn connect(&self, idx: usize) -> Result<quinn::Connection, DnsError> {
        let server = &self.servers[idx];
        let connecting = self
            .endpoint
            .connect(server.addr, &server.server_name)
            .map_err(|e| {
                DnsError::UpstreamRequestFailed(format!("DoQ connect to {}: {e}", server.addr))
            })?;

        match tokio::time::timeout(self.timeout, connecting).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(DnsError::UpstreamRequestFailed(format!(
                "DoQ handshake to {}: {e}",
                server.addr
            ))),
            Err(_) => Err(DnsError::UpstreamRequestFailed(format!(
                "DoQ handshake to {} timed out",
                server.addr
            ))),
        }
    }

    /// Return a live, reusable QUIC connection to server `idx`, establishing a
    /// new one only when there is no cached connection or the cached one has
    /// closed. Mirrors DoT's reuse / invalidate-on-failure semantics; a
    /// `quinn::Connection` is a cheap `Arc` handle, so the clone is shallow.
    pub async fn connection(&self, idx: usize) -> Result<quinn::Connection, DnsError> {
        let mut guard = self.connections[idx].lock().await;

        if let Some(conn) = guard.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            // Cached connection has closed — drop it and reconnect.
            *guard = None;
        }

        let conn = self.connect(idx).await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Send one DNS query over a fresh bidirectional QUIC stream and read the
    /// length-prefixed response (RFC 9250 §4.2). One query per stream: the send
    /// side is finished (FIN) immediately after the query so the server sees a
    /// complete message; the response is read back length-prefixed. The framing
    /// mirrors DoT's TCP framing ([`super::dot::DotUpstream`]) — the only
    /// difference is the QUIC bidirectional stream in place of the TLS stream.
    async fn exchange(
        conn: &quinn::Connection,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ open_bi: {e}")))?;

        // 2-byte big-endian length prefix + message (RFC 9250 §4.2).
        let len: u16 = query_bytes.len().try_into().map_err(|_| {
            DnsError::WireFormatError(format!(
                "DNS query too large for DoQ framing ({} bytes, max 65535)",
                query_bytes.len()
            ))
        })?;
        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ write len: {e}")))?;
        send.write_all(query_bytes)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ write body: {e}")))?;
        // FIN the send side — one query per stream (RFC 9250 §4.2). `finish` is
        // synchronous in quinn 0.11; the bytes flush as the connection is driven
        // by the subsequent read.
        send.finish()
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ finish: {e}")))?;

        // Response: 2-byte length prefix + message.
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ read len: {e}")))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        // DNS header is 12 bytes minimum; reject obviously malformed responses.
        if resp_len < 12 {
            return Err(DnsError::UpstreamRequestFailed(format!(
                "DoQ response too small ({resp_len} bytes)"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoQ read body: {e}")))?;

        parse_response_bytes(&resp_buf, expected)
    }

    /// Run one query against server `idx`, bounded by `self.timeout`. Uses the
    /// pooled connection and, on any failure, invalidates that slot and retries
    /// exactly once on a freshly established connection — so an idle-closed
    /// connection re-establishes transparently instead of surfacing as SERVFAIL
    /// (mirrors DoT's reuse-then-reconnect-once semantics).
    async fn try_server(
        &self,
        idx: usize,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        let conn = self.connection(idx).await?;
        match tokio::time::timeout(self.timeout, Self::exchange(&conn, query_bytes, expected)).await
        {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => {
                tracing::debug!(server = %self.servers[idx].addr, error = %e, "DoQ exchange failed, reconnecting");
            }
            Err(_) => {
                tracing::debug!(server = %self.servers[idx].addr, "DoQ query timed out, reconnecting");
            }
        }

        // Drop the cached connection so the next checkout reconnects.
        *self.connections[idx].lock().await = None;
        let conn = self.connection(idx).await?;
        tokio::time::timeout(self.timeout, Self::exchange(&conn, query_bytes, expected))
            .await
            .map_err(|_| DnsError::UpstreamRequestFailed("DoQ query timed out".into()))?
    }
}

#[async_trait::async_trait]
impl Upstream for DoqUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        // Build the standard query, then force the DNS message ID to 0. RFC 9250
        // §4.2.1 requires the ID be 0 on DoQ: correlation is per-stream, not by
        // ID, and a non-zero ID would leak into 0-RTT/connection-reuse handling.
        // The ID is the first two octets of the DNS header, always present.
        let (mut query_bytes, expected) = build_query(name, record_type, ecs, self.dnssec_ok)?;
        query_bytes[..2].fill(0);

        let mut last_err = None;
        for idx in 0..self.servers.len() {
            tracing::debug!(server = %self.servers[idx].addr, domain = %name, "DoQ lookup");
            match self.try_server(idx, &query_bytes, &expected).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(
                        server = %self.servers[idx].addr,
                        error = %e,
                        "DoQ server failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| DnsError::UpstreamRequestFailed("no DoQ servers configured".into())))
    }
}

/// The ALPN protocol negotiated on `conn`, if the TLS handshake completed. For
/// a DoQ connection this is `b"doq"` (RFC 9250 §3.2).
pub fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let data = conn.handshake_data()?;
    let handshake = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    handshake.protocol
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spin up an in-process DoQ server (self-signed cert for `localhost`, `doq`
    /// ALPN) bound to loopback. Returns `(endpoint, bound_addr, cert_der)`. The
    /// returned endpoint must be kept alive for the test's duration; a detached
    /// task accepts connections and holds them open so the client observes a
    /// completed handshake.
    fn start_test_server() -> (
        quinn::Endpoint,
        SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        install_ring_crypto_provider_once();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
            )
            .unwrap();
        server_crypto.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let addr = endpoint.local_addr().unwrap();

        // Accept loop: hold each accepted connection open so the client side
        // sees a live connection rather than an immediate close.
        let server = endpoint.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    held.push(conn);
                }
            }
        });

        (endpoint, addr, cert_der)
    }

    /// Build a `DoqUpstream` that trusts only `cert_der` and connects to `addr`
    /// with SNI `localhost` (matching the self-signed cert's SAN).
    fn client_for(
        addr: SocketAddr,
        cert_der: rustls::pki_types::CertificateDer<'static>,
    ) -> DoqUpstream {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let servers = vec![DoqServer {
            addr,
            server_name: "localhost".to_string(),
        }];
        DoqUpstream::build(servers, Duration::from_secs(5), false, roots).unwrap()
    }

    /// Build a canned NOERROR response for a received DNS query body: echoes the
    /// question (and the query ID — which for DoQ is 0) and adds one A record.
    fn echo_response(query_body: &[u8]) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};

        let query = Message::from_vec(query_body).expect("server received a valid DNS query");
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = ResponseCode::NoError;
        if let Some(q) = query.queries.first() {
            resp.add_query(q.clone());
            let rec = Record::from_rdata(
                q.name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
            );
            resp.add_answer(rec);
        }
        resp.to_vec().unwrap()
    }

    /// In-process DoQ server that serves length-prefixed responses (RFC 9250
    /// §4.2) over each bidirectional stream, mirroring a real DoQ resolver.
    /// Every received query body is forwarded on the returned channel so tests
    /// can assert on the wire bytes (e.g. the message ID). When `short` is set,
    /// the server replies with a deliberately-too-small (<12 byte) frame to
    /// exercise the malformed-response guard.
    #[allow(clippy::type_complexity)]
    fn start_echo_server(
        short: bool,
    ) -> (
        quinn::Endpoint,
        SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
        tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        install_ring_crypto_provider_once();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
            )
            .unwrap();
        server_crypto.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let quic_server_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let addr = endpoint.local_addr().unwrap();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let server = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    // One query per bidi stream; serve until the client hangs up.
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let Ok(raw) = recv.read_to_end(64 * 1024).await else {
                            break;
                        };
                        if raw.len() < 2 {
                            break;
                        }
                        let body = raw[2..].to_vec();
                        let _ = tx.send(body.clone());

                        let resp = if short {
                            vec![0u8; 5]
                        } else {
                            echo_response(&body)
                        };
                        let len = (resp.len() as u16).to_be_bytes();
                        if send.write_all(&len).await.is_err() {
                            break;
                        }
                        if send.write_all(&resp).await.is_err() {
                            break;
                        }
                        let _ = send.finish();
                    }
                });
            }
        });

        (endpoint, addr, cert_der, rx)
    }

    #[tokio::test]
    async fn framing_round_trip_returns_answer() {
        let (_server, addr, cert, _rx) = start_echo_server(false);
        let client = client_for(addr, cert);
        let name: Name = "example.com.".parse().unwrap();

        let resp = client
            .lookup(&name, RecordType::A, None)
            .await
            .expect("DoQ lookup should round-trip a response");

        assert_eq!(resp.response_code, hickory_proto::op::ResponseCode::NoError);
        assert_eq!(resp.records.len(), 1, "echo server returns one A record");
    }

    #[tokio::test]
    async fn query_id_is_zeroed() {
        let (_server, addr, cert, mut rx) = start_echo_server(false);
        let client = client_for(addr, cert);
        let name: Name = "example.com.".parse().unwrap();

        client.lookup(&name, RecordType::A, None).await.unwrap();

        let received = rx.recv().await.expect("server should receive the query");
        assert!(received.len() >= 12, "a DNS query has a 12-byte header");
        assert_eq!(
            &received[0..2],
            &[0, 0],
            "DoQ query message ID MUST be 0 (RFC 9250 §4.2.1)"
        );
    }

    #[tokio::test]
    async fn malformed_short_response_is_error() {
        let (_server, addr, cert, _rx) = start_echo_server(true);
        let client = client_for(addr, cert);
        let name: Name = "example.com.".parse().unwrap();

        let err = client
            .lookup(&name, RecordType::A, None)
            .await
            .expect_err("a sub-12-byte response must be rejected");
        assert!(
            matches!(err, DnsError::UpstreamRequestFailed(ref m) if m.contains("too small")),
            "expected a too-small error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn two_lookups_reuse_one_connection() {
        // Each query opens its own bidirectional stream multiplexed over the
        // single pooled QUIC connection — both must succeed.
        let (_server, addr, cert, _rx) = start_echo_server(false);
        let client = client_for(addr, cert);
        let name: Name = "example.com.".parse().unwrap();

        client.lookup(&name, RecordType::A, None).await.unwrap();
        client
            .lookup(&name, RecordType::A, None)
            .await
            .expect("second query reuses the pooled connection");
    }

    #[tokio::test]
    async fn handshake_succeeds_against_local_server() {
        let (_server, addr, cert) = start_test_server();
        let client = client_for(addr, cert);
        let conn = client.connect(0).await.expect("handshake should succeed");
        assert!(
            conn.close_reason().is_none(),
            "connection should be open after a successful handshake"
        );
    }

    #[tokio::test]
    async fn alpn_negotiated_is_doq() {
        let (_server, addr, cert) = start_test_server();
        let client = client_for(addr, cert);
        let conn = client.connect(0).await.unwrap();
        assert_eq!(
            negotiated_alpn(&conn).as_deref(),
            Some(DOQ_ALPN),
            "ALPN must negotiate to \"doq\" per RFC 9250"
        );
    }

    #[tokio::test]
    async fn pool_reuses_live_connection() {
        let (_server, addr, cert) = start_test_server();
        let client = client_for(addr, cert);
        let first = client.connection(0).await.unwrap();
        let second = client.connection(0).await.unwrap();
        assert_eq!(
            first.stable_id(),
            second.stable_id(),
            "a second checkout must reuse the cached connection, not reconnect"
        );
    }

    #[tokio::test]
    async fn pool_reconnects_after_close() {
        let (_server, addr, cert) = start_test_server();
        let client = client_for(addr, cert);

        let first = client.connection(0).await.unwrap();
        let first_id = first.stable_id();

        // Close it client-side and wait for the close to register, then the pool
        // must establish a fresh connection rather than hand back the dead one.
        first.close(0u32.into(), b"test");
        first.closed().await;

        let second = client.connection(0).await.unwrap();
        assert!(
            second.close_reason().is_none(),
            "reconnected connection should be open"
        );
        assert_ne!(
            first_id,
            second.stable_id(),
            "must be a new connection, not the closed one"
        );
    }

    #[test]
    fn parse_ip_port_sets_ip_sni() {
        let parsed = DoqUpstream::parse_servers(&["94.140.14.14:853".to_string()]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].addr, "94.140.14.14:853".parse().unwrap());
        assert_eq!(parsed[0].server_name, "94.140.14.14");
    }

    #[test]
    fn parse_empty_is_error() {
        assert!(DoqUpstream::parse_servers(&[]).is_err());
    }

    /// Real-upstream handshake — network-dependent, so `#[ignore]`d out of the
    /// default + `--features doq` hermetic suites. Run manually with:
    /// `cargo test --features doq -- --ignored real_upstream_handshake`.
    #[tokio::test]
    #[ignore = "requires network access to dns.adguard.com:853"]
    async fn real_upstream_handshake_adguard() {
        let client = DoqUpstream::new(
            &["dns.adguard.com:853".to_string()],
            Duration::from_secs(10),
            false,
        )
        .unwrap();
        let conn = client
            .connect(0)
            .await
            .expect("real DoQ handshake should succeed");
        assert_eq!(negotiated_alpn(&conn).as_deref(), Some(DOQ_ALPN));
    }
}
