//! DNS-over-HTTPS upstream (RFC 8484).
//!
//! Uses the standard wire-format POST method: serialize DNS query as binary,
//! POST to the DoH URL with `Content-Type: application/dns-message`, parse
//! the binary response. Shares a single `reqwest::Client` with list downloads
//! for HTTP/2 connection pooling.

use std::time::Duration;

use hickory_proto::rr::{Name, RecordType};

use super::{build_query_bytes, parse_response_bytes, Upstream, UpstreamResponse};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

/// Hard ceiling on a DoH response body. A DNS message maxes out at 64 KB (the
/// TCP/DoH 2-byte length field), so anything larger is malformed or hostile.
const MAX_DOH_RESPONSE_BYTES: usize = 65535;

/// DNS-over-HTTPS upstream resolver.
///
/// §4.8 §2/2 (T4): Sprint 1 carried a constructor-time `ecs:
/// Option<EdnsClientSubnet>` field for a single fixed anonymous option;
/// Sprint 2 promotes ECS to a per-query knob driven by the resolved
/// profile's [`crate::profiles::profile::EcsPolicy`] and the client IP,
/// so the field is gone — the handler passes the option through
/// [`Upstream::lookup`].
pub struct DohUpstream {
    client: reqwest::Client,
    /// DoH endpoint URLs (e.g. "https://192.0.2.53/dns-query").
    urls: Vec<String>,
    timeout: Duration,
    /// §4.10: when set, outbound queries carry the EDNS DNSSEC OK (DO) bit.
    /// Baked at construction (global policy); the client-facing upstream is
    /// built with `false` → byte-identical wire packets.
    dnssec_ok: bool,
}

impl DohUpstream {
    /// Create a new DoH upstream. `urls` must be HTTPS endpoints accepting
    /// RFC 8484 wire-format POST (e.g. `https://192.0.2.53/dns-query`).
    pub fn new(
        client: reqwest::Client,
        urls: Vec<String>,
        timeout: Duration,
        dnssec_ok: bool,
    ) -> Result<Self, anyhow::Error> {
        if urls.is_empty() {
            anyhow::bail!("DoH upstream requires at least one URL");
        }
        for url in &urls {
            // rev-2606: the https:// gate is shared with `config lint` so the
            // same URL is accepted/rejected identically at lint and at boot.
            crate::upstream::shape::validate_doh_url(url)
                .map_err(|_| anyhow::anyhow!("DoH URL must start with https://: \"{url}\""))?;
        }
        Ok(Self {
            client,
            urls,
            timeout,
            dnssec_ok,
        })
    }
}

#[async_trait::async_trait]
impl Upstream for DohUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        let query_bytes = build_query_bytes(name, record_type, ecs, self.dnssec_ok)?;

        // Try each URL in order (round-robin would need shared state; sequential
        // failover is simpler and matches the plain upstream behavior).
        let mut last_err = None;
        for url in &self.urls {
            match self.do_request(url, &query_bytes).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(url, error = %e, "DoH request failed, trying next");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| DnsError::UpstreamRequestFailed("no DoH servers configured".into())))
    }
}

impl DohUpstream {
    async fn do_request(
        &self,
        url: &str,
        query_bytes: &[u8],
    ) -> Result<UpstreamResponse, DnsError> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_bytes.to_vec())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoH POST to {url}: {e}")))?;

        if !resp.status().is_success() {
            return Err(DnsError::UpstreamRequestFailed(format!(
                "DoH {url} returned HTTP {}",
                resp.status()
            )));
        }

        // Validate Content-Type (catch proxies/captive portals returning HTML)
        if let Some(ct) = resp.headers().get("content-type") {
            let ct_str = ct.to_str().unwrap_or("<non-ascii>");
            if !ct_str.starts_with("application/dns-message") {
                return Err(DnsError::UpstreamRequestFailed(format!(
                    "DoH {url} returned Content-Type {ct_str:?} (expected application/dns-message)"
                )));
            }
        }

        // doh-01: bound the body to MAX_DOH_RESPONSE_BYTES regardless of
        // transfer-encoding. The previous `content_length()` pre-check was
        // bypassable — a chunked / no-`Content-Length` response reports no
        // length, so the whole stream was buffered before the size was checked.
        // `read_capped_body` aborts the instant the streamed total exceeds the
        // cap, so a hostile upstream cannot exhaust memory with an unbounded body.
        let body = read_capped_body(resp).await?;
        parse_response_bytes(&body)
    }
}

/// Read a DoH response body bounded to [`MAX_DOH_RESPONSE_BYTES`] regardless of
/// transfer-encoding (doh-01). `Content-Length` is used only as a capacity HINT,
/// clamped to the cap so a dishonest server cannot force a huge pre-allocation;
/// the streamed running total is the real bound. Mirrors the in-tree idiom of
/// `lists::manager::read_bounded_body_bytes` (M-22) and cluster
/// `poll::read_body_capped` (poll-01) — `bytes_stream()` is unavailable (reqwest
/// is built without the `stream` feature), so chunks are pulled via `chunk()`.
async fn read_capped_body(mut resp: reqwest::Response) -> Result<Vec<u8>, DnsError> {
    let initial = resp
        .content_length()
        .and_then(|cl| usize::try_from(cl).ok())
        .map_or(0, |cl| cl.min(MAX_DOH_RESPONSE_BYTES));
    let mut body = Vec::with_capacity(initial);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| DnsError::UpstreamRequestFailed(format!("DoH response body: {e}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_DOH_RESPONSE_BYTES {
            return Err(DnsError::UpstreamRequestFailed(format!(
                "DoH response body too large (exceeds {MAX_DOH_RESPONSE_BYTES} bytes)"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    #[test]
    fn new_with_valid_https_url_succeeds() {
        let doh = DohUpstream::new(
            client(),
            vec!["https://1.1.1.1/dns-query".to_string()],
            Duration::from_secs(5),
            false,
        );
        assert!(doh.is_ok());
    }

    #[test]
    fn new_rejects_empty_url_list() {
        let err = DohUpstream::new(client(), vec![], Duration::from_secs(5), false);
        assert!(err.is_err());
    }

    #[test]
    fn new_rejects_non_https_url() {
        let err = DohUpstream::new(
            client(),
            vec!["http://1.1.1.1/dns-query".to_string()],
            Duration::from_secs(5),
            false,
        );
        assert!(err.is_err());
    }

    /// Spawn a one-shot raw-HTTP mock that writes `headers` then streams
    /// `body_len` bytes of `'a'` and closes. With no `Content-Length` header the
    /// client learns the size only at EOF — the streamed body doh-01 must bound.
    async fn spawn_stream_server(headers: &'static str, body_len: usize) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await; // drain the request line/headers
            if stream.write_all(headers.as_bytes()).await.is_err() {
                return;
            }
            let block = vec![b'a'; 64 * 1024];
            let mut sent = 0;
            while sent < body_len {
                let n = block.len().min(body_len - sent);
                // The client aborts early once the cap is hit and drops the
                // connection, so a broken-pipe write here is expected — stop.
                if stream.write_all(&block[..n]).await.is_err() {
                    return;
                }
                sent += n;
            }
        });
        addr
    }

    /// doh-01: an oversized body with NO `Content-Length` (the bypass vector)
    /// must trip the cap. The loop checks the projected size BEFORE extending the
    /// buffer, so the abort happens at ~cap+one-chunk — never after buffering the
    /// whole stream (the old `resp.bytes()` read-to-EOF behaviour).
    #[tokio::test]
    async fn read_capped_body_aborts_on_oversized_stream_no_content_length() {
        let addr = spawn_stream_server(
            "HTTP/1.1 200 OK\r\n\
             Connection: close\r\n\
             Content-Type: application/dns-message\r\n\
             \r\n",
            256 * 1024, // 4× the cap, no Content-Length
        )
        .await;
        let resp = client()
            .get(format!("http://{addr}/dns-query"))
            .send()
            .await
            .unwrap();
        match read_capped_body(resp).await {
            Err(DnsError::UpstreamRequestFailed(msg)) => {
                assert!(msg.contains("too large"), "unexpected message: {msg}");
            }
            other => panic!("expected UpstreamRequestFailed(too large), got {other:?}"),
        }
    }

    /// A normal small DoH answer passes through unchanged.
    #[tokio::test]
    async fn read_capped_body_accepts_small_body() {
        let addr = spawn_stream_server(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 512\r\n\
             Content-Type: application/dns-message\r\n\
             \r\n",
            512,
        )
        .await;
        let resp = client()
            .get(format!("http://{addr}/dns-query"))
            .send()
            .await
            .unwrap();
        let body = read_capped_body(resp).await.unwrap();
        assert_eq!(body.len(), 512);
    }
}
