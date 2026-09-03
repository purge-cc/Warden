//! DNS-over-TLS upstream (RFC 7858).
//!
//! Connects to upstream resolvers on port 853 via TLS. DNS messages use
//! standard TCP framing (2-byte big-endian length prefix + wire-format payload).
//! Connections are persistent and reconnected on failure.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Query;
use hickory_proto::rr::{Name, RecordType};
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::{
    build_query, install_ring_crypto_provider_once, parse_response_bytes, webpki_root_store,
    Upstream, UpstreamResponse,
};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

/// A single DoT server endpoint.
struct DotServer {
    addr: SocketAddr,
    /// TLS SNI hostname — either the original hostname (for certificate validation)
    /// or an IP address (for IP-based DoT servers like 192.0.2.53:853).
    hostname: rustls::pki_types::ServerName<'static>,
}

/// DNS-over-TLS upstream resolver with a small persistent-connection pool
/// per server. A single connection serialises concurrent queries since the
/// stream is guarded by a Mutex; a pool of 2–4 hides that serialisation
/// tax without blowing the fd budget on constrained hardware.
pub struct DotUpstream {
    servers: Vec<DotServer>,
    connector: TlsConnector,
    timeout: Duration,
    pool_size: usize,
    /// Shape: `servers.len()` outer × `pool_size` inner. Each inner slot
    /// is a persistent TLS connection, lazily created.
    connections: Vec<Vec<tokio::sync::Mutex<Option<TlsStream<TcpStream>>>>>,
    /// Round-robin pointer per server — `fetch_add % pool_size` picks the
    /// next slot. Contention is irrelevant since we only read/increment.
    next_slot: Vec<AtomicUsize>,
    /// When set, outbound queries carry the EDNS DNSSEC OK (DO) bit. Baked
    /// at construction (global policy); the client-facing upstream is built
    /// with `false` → byte-identical wire packets.
    dnssec_ok: bool,
}

impl DotUpstream {
    /// Create a new DoT upstream. Servers can be:
    /// - `IP:port` (e.g. `192.0.2.53:853`) — IP used directly, SNI set to IP
    /// - `hostname:port` (e.g. `dns.example.net:853`) — resolved via OS DNS at startup,
    ///   hostname used for TLS SNI (certificate validation)
    pub fn new(
        servers: &[String],
        timeout: Duration,
        pool_size: usize,
        dnssec_ok: bool,
    ) -> Result<Self, anyhow::Error> {
        if servers.is_empty() {
            anyhow::bail!("DoT upstream requires at least one server");
        }
        if pool_size == 0 {
            anyhow::bail!("DoT pool_size must be >= 1");
        }

        let mut dot_servers = Vec::with_capacity(servers.len());
        for server in servers {
            // Shared host:port syntax gate (same check `config lint` runs
            // offline) before the resolve+TLS work — a malformed entry is
            // rejected identically at lint and at boot. A syntactically-valid
            // host that fails to resolve still bails below.
            crate::upstream::shape::validate_host_port_server(server)
                .map_err(|e| anyhow::anyhow!("invalid DoT server: {e}"))?;
            // Try parsing as IP:port first (fast path, no DNS needed).
            if let Ok(addr) = server.parse::<SocketAddr>() {
                let hostname = rustls::pki_types::ServerName::IpAddress(
                    rustls::pki_types::IpAddr::from(addr.ip()),
                );
                dot_servers.push(DotServer { addr, hostname });
                continue;
            }

            // Not an IP:port — treat as hostname:port. Resolve via OS resolver
            // (blocking, but only at startup). The hostname is used for TLS SNI
            // so the server's certificate is validated against the correct name.
            let resolved_addr = server
                .to_socket_addrs()
                .map_err(|e| anyhow::anyhow!("cannot resolve DoT server \"{server}\": {e}"))?
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("DoT server \"{server}\" resolved to no addresses")
                })?;

            // Extract hostname (everything before the last :port).
            let host = server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server);
            let hostname = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid DoT hostname \"{host}\": {e}"))?;

            tracing::info!(
                server,
                resolved = %resolved_addr,
                "DoT server hostname resolved"
            );

            dot_servers.push(DotServer {
                addr: resolved_addr,
                hostname,
            });
        }

        // Shared rustls client setup (see `upstream::install_ring_crypto_provider_once`
        // / `webpki_root_store`) — DoT and DoQ use one TLS-config path.
        install_ring_crypto_provider_once();

        let tls_config = ClientConfig::builder()
            .with_root_certificates(webpki_root_store())
            .with_no_client_auth();

        let connections = (0..dot_servers.len())
            .map(|_| {
                (0..pool_size)
                    .map(|_| tokio::sync::Mutex::new(None))
                    .collect()
            })
            .collect();
        let next_slot = (0..dot_servers.len())
            .map(|_| AtomicUsize::new(0))
            .collect();

        Ok(Self {
            servers: dot_servers,
            connector: TlsConnector::from(Arc::new(tls_config)),
            timeout,
            pool_size,
            connections,
            next_slot,
            dnssec_ok,
        })
    }

    /// Connect (or reconnect) to a DoT server.
    async fn connect(&self, idx: usize) -> Result<TlsStream<TcpStream>, DnsError> {
        let server = &self.servers[idx];
        let tcp = TcpStream::connect(server.addr).await.map_err(|e| {
            DnsError::UpstreamRequestFailed(format!("DoT TCP to {}: {e}", server.addr))
        })?;

        self.connector
            .connect(server.hostname.clone(), tcp)
            .await
            .map_err(|e| {
                DnsError::UpstreamRequestFailed(format!("DoT TLS to {}: {e}", server.addr))
            })
    }

    /// Send a DNS query over a TLS stream using TCP framing and read the response.
    async fn exchange(
        stream: &mut TlsStream<TcpStream>,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        // TCP DNS framing: 2-byte big-endian length prefix + message
        let len: u16 = query_bytes.len().try_into().map_err(|_| {
            DnsError::WireFormatError(format!(
                "DNS query too large for TCP framing ({} bytes, max 65535)",
                query_bytes.len()
            ))
        })?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoT write: {e}")))?;
        stream
            .write_all(query_bytes)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoT write: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoT flush: {e}")))?;

        // Read response: 2-byte length prefix + message
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoT read length: {e}")))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        // DNS header is 12 bytes minimum; reject obviously malformed responses
        if resp_len < 12 {
            return Err(DnsError::UpstreamRequestFailed(format!(
                "DoT response too small ({resp_len} bytes)"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoT read body: {e}")))?;

        parse_response_bytes(&resp_buf, expected)
    }
}

#[async_trait::async_trait]
impl Upstream for DotUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        let (query_bytes, expected) = build_query(name, record_type, ecs, self.dnssec_ok)?;

        let mut last_err = None;
        for (idx, _server) in self.servers.iter().enumerate() {
            match self.try_server(idx, &query_bytes, &expected).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(
                        server = %self.servers[idx].addr,
                        error = %e,
                        "DoT query failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| DnsError::UpstreamRequestFailed("no DoT servers configured".into())))
    }
}

impl DotUpstream {
    /// Returns the number of configured servers (used in tests).
    #[cfg(test)]
    fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Try a single server, reusing or reconnecting the persistent connection.
    async fn try_server(
        &self,
        idx: usize,
        query_bytes: &[u8],
        expected: &Query,
    ) -> Result<UpstreamResponse, DnsError> {
        // Round-robin pick across the per-server pool. Relaxed ordering is
        // fine — `slot` is an advisory index, not a synchronisation handle.
        let slot = self.next_slot[idx].fetch_add(1, Ordering::Relaxed) % self.pool_size;
        let mut conn_guard = self.connections[idx][slot].lock().await;

        // Try existing connection first
        if let Some(stream) = conn_guard.as_mut() {
            match tokio::time::timeout(self.timeout, Self::exchange(stream, query_bytes, expected))
                .await
            {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "DoT connection broken, reconnecting");
                    *conn_guard = None;
                }
                Err(_) => {
                    tracing::debug!("DoT query timed out, reconnecting");
                    *conn_guard = None;
                }
            }
        }

        // Reconnect
        let mut stream = tokio::time::timeout(self.timeout, self.connect(idx))
            .await
            .map_err(|_| {
                DnsError::UpstreamRequestFailed(format!(
                    "DoT connect to {} timed out",
                    self.servers[idx].addr
                ))
            })??;

        let result = tokio::time::timeout(
            self.timeout,
            Self::exchange(&mut stream, query_bytes, expected),
        )
        .await
        .map_err(|_| DnsError::UpstreamRequestFailed("DoT query timed out".into()))?;

        match result {
            Ok(resp) => {
                // Store connection for reuse
                *conn_guard = Some(stream);
                Ok(resp)
            }
            Err(e) => {
                // Don't store broken connection
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_ip_port() {
        let dot = DotUpstream::new(
            &["1.1.1.1:853".into(), "8.8.8.8:853".into()],
            Duration::from_secs(5),
            4,
            false,
        )
        .unwrap();
        assert_eq!(dot.server_count(), 2);
    }

    #[test]
    fn new_empty_servers_rejected() {
        let err = DotUpstream::new(&[], Duration::from_secs(5), 4, false);
        assert!(err.is_err());
    }

    #[test]
    fn new_with_hostname_port() {
        // dns.google resolves via OS resolver — this test needs network.
        // Skip gracefully if resolution fails (e.g. CI without DNS).
        let result = DotUpstream::new(&["dns.google:853".into()], Duration::from_secs(5), 4, false);
        match result {
            Ok(dot) => assert_eq!(dot.server_count(), 1),
            Err(e) => {
                eprintln!("skipping hostname test (no DNS?): {e}");
            }
        }
    }

    #[test]
    fn new_zero_pool_size_rejected() {
        let err = DotUpstream::new(&["1.1.1.1:853".into()], Duration::from_secs(5), 0, false);
        assert!(
            err.is_err(),
            "pool_size == 0 must be rejected at construction"
        );
    }

    #[test]
    fn new_is_idempotent_with_existing_crypto_provider() {
        // Regression pin: an earlier version did `let _ = install_default()`,
        // swallowing every Err. Now `CryptoProvider::get_default()` is checked
        // first and install is only attempted when None, so re-construction
        // (test or operator restart) takes the well-defined "already
        // installed" branch instead of pretending to install. Pins that two
        // consecutive `new()` calls both succeed without panic — the second
        // one MUST hit the already-installed branch because the first
        // installed the provider.
        let _first =
            DotUpstream::new(&["1.1.1.1:853".into()], Duration::from_secs(5), 2, false).unwrap();
        let second =
            DotUpstream::new(&["8.8.8.8:853".into()], Duration::from_secs(5), 2, false).unwrap();
        assert_eq!(second.server_count(), 1);
        // After at least one construction, the global provider must be set.
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn pool_shape_matches_servers_and_pool_size() {
        // Pool layout: outer = servers.len(), inner = pool_size. Lock
        // the shape against an accidental flat refactor.
        let dot = DotUpstream::new(
            &["1.1.1.1:853".into(), "8.8.8.8:853".into()],
            Duration::from_secs(5),
            3,
            false,
        )
        .unwrap();
        assert_eq!(dot.connections.len(), 2);
        for slots in &dot.connections {
            assert_eq!(slots.len(), 3);
        }
        assert_eq!(dot.next_slot.len(), 2);
        assert_eq!(dot.pool_size, 3);
    }
}
