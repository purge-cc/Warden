//! Hardened HTTP client for blocklist and catalog downloads (P0-1).
//!
//! This module builds the `reqwest::Client` used to fetch external lists and
//! the catalog. It enforces a strict SSRF policy:
//!
//! - Only `https://` URLs are permitted. `http://`, `file://`, and every other
//!   scheme is refused both for the initial request and any redirect target.
//! - Literal IP addresses in the URL host (or redirect target) are rejected
//!   if they fall in loopback, private (RFC1918), CGNAT, link-local, ULA
//!   (`fc00::/7`), IPv6 link-local (`fe80::/10`), multicast, or unspecified
//!   ranges — any class an attacker could use to pivot a redirect into the
//!   local network.
//! - Redirects are capped at 3 hops.
//!
//! Hostname-based attacks (attacker-controlled DNS pointing a public-looking
//! hostname at `127.0.0.1`) are out of scope here: the operator's DNS is
//! assumed honest for the narrow set of configured list URLs. If this becomes
//! a concern, the right fix is a custom `reqwest::dns::Resolve` that rejects
//! private IPs at connect time, not at URL-validation time.
//!
//! Body-size enforcement lives in `manager::read_bounded_body`, not here.
//!
//! # Timeouts: three limits, three different properties
//!
//! `reqwest`'s `ClientBuilder::timeout` is a deadline on the **whole
//! request, response body included** — not an idle timeout. Used alone on a
//! streaming download it silently becomes a size limit that scales with the
//! link: `max_downloadable = timeout × bandwidth`. A single 30s value here
//! meant a 31 MB ceiling on a 1 MB/s link, which is how four 100-180 MB
//! lists came to fail every refresh for days while the small ones passed.
//!
//! So a bulk download sets three, each expressing the property it can
//! actually express:
//!
//! | limit | property | constant |
//! |---|---|---|
//! | `connect_timeout` | the host is reachable | [`BULK_CONNECT_TIMEOUT`] |
//! | `read_timeout` | the peer is making progress | [`BULK_READ_TIMEOUT`] |
//! | `timeout` | an absolute wall-clock backstop | [`BULK_TOTAL_TIMEOUT`] |
//!
//! `read_timeout` is the one that matters: `reqwest` **resets it on every
//! body frame** (`async_impl::body::ReadTimeoutBody`), so a 180 MB transfer
//! that takes three minutes but keeps delivering never trips it, while a
//! peer that goes silent trips it in seconds.
//!
//! The total timeout stays anyway, and removing it is a security
//! regression: a peer that dribbles one byte just before each read window
//! expires resets the idle timer forever. `max_body_bytes` bounds bytes;
//! nothing else bounds wall-clock.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use reqwest::redirect::{Action, Attempt, Policy};
use reqwest::Url;

/// Errors from pre-flight URL validation.
#[derive(Debug, thiserror::Error)]
pub enum UrlGuardError {
    #[error("URL scheme must be https://, got: {0}")]
    InvalidScheme(String),
    #[error("URL host is missing")]
    MissingHost,
    #[error("URL host {0} is a disallowed address (loopback/private/link-local/ULA)")]
    DisallowedHost(String),
    /// rev-2606 §06 `manager-04b`: the URL carries embedded credentials
    /// (`user:pass@host`). Refused so the password never reaches a stored
    /// failure reason or log. `{0}` is the **redacted** URL (userinfo
    /// stripped) so the operator can still identify which source to fix.
    #[error("URL must not embed credentials (use auth_token_ref for authenticated lists): {0}")]
    ContainsUserinfo(String),
    #[error("URL parse error: {0}")]
    ParseError(String),
}

/// rev-2606 §06 `manager-04b`: return `url_str` with any userinfo
/// (`user:pass@`) stripped, so a credential embedded in a list URL never
/// reaches an operator-facing error string, status reason, or log.
///
/// Parses and clears the username/password when possible; falls back to a
/// best-effort manual strip of the `userinfo@` span in the authority for
/// a URL that does not parse. A URL with no userinfo is returned
/// unchanged (allocating only when a strip actually happens is not worth
/// the branch complexity here — this is an error/diagnostic path).
pub fn redact_userinfo(url_str: &str) -> String {
    if let Ok(mut url) = Url::parse(url_str) {
        if url.username().is_empty() && url.password().is_none() {
            return url_str.to_string();
        }
        // set_username / set_password only error for cannot-be-a-base URLs,
        // which never reach here (https is always a base). Ignore the Result.
        let _ = url.set_username("");
        let _ = url.set_password(None);
        return url.to_string();
    }
    // Unparseable: strip any `userinfo@` from the authority span manually.
    if let Some(scheme_end) = url_str.find("://") {
        let rest = &url_str[scheme_end + 3..];
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        if let Some(at) = rest[..authority_end].rfind('@') {
            return format!(
                "{}://{}{}",
                &url_str[..scheme_end],
                &rest[at + 1..authority_end],
                &rest[authority_end..]
            );
        }
    }
    url_str.to_string()
}

/// Build a hardened `reqwest::Client` for blocklist and catalog downloads.
///
/// Use this for every HTTP call that fetches external blocklist data. For DoH
/// upstreams — where the operator deliberately configures the endpoint and may
/// legitimately point at a private resolver — use a separate, permissive
/// `reqwest::Client` built directly in `start.rs`.
pub fn build_list_client(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let client = base_builder().timeout(timeout).build()?;
    Ok(client)
}

/// The user agent and SSRF redirect policy every list-fetching client must
/// carry, in one place.
///
/// Both constructors go through this so the redirect policy cannot be
/// forgotten in one of them, and so the two cannot drift apart when a
/// future hardening step is added.
/// # Why there is no `.gzip(true)` here
///
/// There is deliberately nothing to add. `reqwest`'s decompression is a
/// **compile-time feature, not a runtime switch**: with the `gzip` feature
/// off, `ClientBuilder::gzip` does not even exist and no `Accept-Encoding`
/// is ever sent; with it on, `ClientConfig::accepts.gzip` defaults to `true`
/// (`reqwest-0.12` `async_impl/client.rs:127`). Enabling the feature in
/// `Cargo.toml` is the entire change — a `.gzip(true)` call here would be a
/// no-op that reads like the load-bearing line, sending the next person
/// looking for the switch to the wrong file.
///
/// The inverse is NOT a no-op and is worth knowing: `.no_gzip()` exists
/// regardless of the feature, so a client that must not advertise
/// compression has to say so explicitly.
fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent("purge-warden/0.1")
        .redirect(list_redirect_policy())
}

/// Absolute wall-clock ceiling on one bulk list download.
///
/// **Not a tuning knob** — it exists only to bound the slow-drip peer that
/// [`BULK_READ_TIMEOUT`] cannot catch (one byte emitted just before every
/// read window expires resets the idle timer forever). Set generously so it
/// never fires on an honest transfer.
///
/// 600s covers ~600 MB at 1 MB/s. The largest list on the public catalog is
/// ~180 MB **decompressed**, but the wire is what this constant bounds and
/// the client now negotiates gzip (`Cargo.toml`), which the origin already
/// served: ~3.3× measured across the published corpus, so ~55 MB and ~55s on
/// that link — an ~11× margin where the pre-compression arithmetic gave 3.4×.
///
/// The margin therefore GREW, and that is the whole reason this number did
/// not move: compression only ever removes wire bytes, so a ceiling that was
/// generous before is more generous now. A source that legitimately needs
/// more than ten minutes has outgrown this constant, and the fix is to raise
/// it here (or expose a config key at that point), not to widen it
/// pre-emptively.
///
/// Note which axis this bounds. Wall-clock and wire bytes are what shrank;
/// the **decompressed** size is unchanged, and that is the one
/// `max_body_bytes` guards — see `manager::read_bounded_body_bytes`.
pub const BULK_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// How long a bulk download may go without receiving a body frame.
///
/// `reqwest` resets this on every frame, so it measures **silence**, not
/// duration: a slow-but-progressing transfer of any size survives, a peer
/// that stops talking is dropped. This is the limit that actually protects
/// the refresh loop; the total timeout is the backstop behind it.
///
/// It also bounds the connect+headers phase as a single deadline (reqwest
/// checks it in `PendingRequest::poll` before the body exists), which is why
/// [`BULK_CONNECT_TIMEOUT`] is set as well — to fail a dead host faster, and
/// under the `is_connect()` label that carries the better diagnostics.
pub const BULK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// TCP+TLS connect budget for a bulk list download.
pub const BULK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the hardened client used to download whole blocklist bodies.
///
/// Use this for every fetch whose response is a full list (the daemon's
/// refresh loop and `warden lists refresh`). For small probes — catalog
/// JSON, URL validation, TUI previews — use [`build_list_client`] with a
/// tight timeout instead: those want to fail fast, and a body big enough to
/// need an idle timeout is not what they are fetching.
pub fn build_bulk_list_client() -> anyhow::Result<reqwest::Client> {
    build_bulk_list_client_with(BULK_TOTAL_TIMEOUT, BULK_READ_TIMEOUT, BULK_CONNECT_TIMEOUT)
}

/// [`build_bulk_list_client`] with the three limits supplied explicitly.
///
/// Exists so tests can exercise the real constructor at millisecond scale
/// instead of asserting against a hand-rolled client that would not prove
/// anything about the one production uses.
pub fn build_bulk_list_client_with(
    total: Duration,
    read: Duration,
    connect: Duration,
) -> anyhow::Result<reqwest::Client> {
    let client = base_builder()
        .timeout(total)
        .read_timeout(read)
        .connect_timeout(connect)
        .build()?;
    Ok(client)
}

/// Redirect policy for list downloads.
///
/// Rejects any redirect that would send the request to a non-HTTPS URL or to
/// a literal private/loopback/link-local/ULA IP. Caps the redirect chain at
/// 3 hops.
fn list_redirect_policy() -> Policy {
    Policy::custom(|attempt: Attempt| -> Action {
        if attempt.previous().len() >= 3 {
            return attempt.error("list download: too many redirects");
        }
        if attempt.url().scheme() != "https" {
            return attempt.error("list download: non-HTTPS redirect refused");
        }
        if let Some(ip) = url_host_ip(attempt.url()) {
            if is_disallowed_ip(ip) {
                return attempt.error("list download: redirect to disallowed IP refused");
            }
        }
        attempt.follow()
    })
}

/// Validate a URL before an initial fetch.
///
/// The redirect policy handles downstream hops; this function handles the
/// first hop (which `reqwest` does not run through the redirect policy).
pub fn validate_list_url(url_str: &str) -> Result<(), UrlGuardError> {
    let url = Url::parse(url_str).map_err(|e| UrlGuardError::ParseError(e.to_string()))?;

    if url.scheme() != "https" {
        return Err(UrlGuardError::InvalidScheme(url.scheme().to_string()));
    }

    if url.host().is_none() {
        return Err(UrlGuardError::MissingHost);
    }

    // rev-2606 §06 manager-04b: refuse embedded credentials. The supported
    // path for an authenticated list is `auth_token_ref` (Bearer token from
    // secrets.toml), not a password baked into the URL where it would land
    // in stored failure reasons, IPC status, and logs.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlGuardError::ContainsUserinfo(redact_userinfo(url_str)));
    }

    if let Some(ip) = url_host_ip(&url) {
        if is_disallowed_ip(ip) {
            // `host_str()` returns a bracketed form for IPv6, which is fine
            // for error messages — users see exactly what they typed.
            return Err(UrlGuardError::DisallowedHost(
                url.host_str().unwrap_or("?").to_string(),
            ));
        }
    }

    Ok(())
}

/// Extract a literal IP from the URL's host, if the host is an IP literal.
///
/// `Url::host_str()` returns IPv6 literals bracketed (`[::1]`), which
/// `IpAddr::from_str` refuses. Strip brackets first, then parse. Domain
/// hosts produce `None` because the parse fails on dots/letters.
fn url_host_ip(url: &Url) -> Option<IpAddr> {
    let raw = url.host_str()?;
    let trimmed = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    trimmed.parse::<IpAddr>().ok()
}

/// True if the IP is in a range we refuse to connect to for list downloads.
fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => is_disallowed_ipv6(v6),
    }
}

fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_unspecified()
    {
        return true;
    }
    let [a, b, _, _] = v4.octets();
    // CGNAT: 100.64.0.0/10 — 100.64.0.0 through 100.127.255.255
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // "this network": 0.0.0.0/8
    if a == 0 {
        return true;
    }
    false
}

fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
        return true;
    }
    let segs = v6.segments();
    // ULA: fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local: fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped IPv6 (::ffff:0:0/96) — forward to IPv4 checks so that
    // ::ffff:127.0.0.1 is rejected just like 127.0.0.1.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_disallowed_ipv4(v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_disallowed_ip: IPv4 ---

    #[test]
    fn loopback_ipv4_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
            127, 255, 255, 254
        ))));
    }

    #[test]
    fn rfc1918_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
            172, 31, 255, 254
        ))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn ipv4_link_local_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
    }

    #[test]
    fn ipv4_broadcast_and_multicast_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 255
        ))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    }

    #[test]
    fn ipv4_unspecified_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(0, 255, 1, 2))));
    }

    #[test]
    fn cgnat_rejected() {
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 254
        ))));
    }

    #[test]
    fn cgnat_boundary_just_outside_allowed() {
        // 100.63.x.x and 100.128.x.x are not CGNAT — they're public.
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 63, 0, 1))));
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn public_ipv4_allowed() {
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
            185, 199, 108, 153
        ))));
    }

    // --- is_disallowed_ip: IPv6 ---

    #[test]
    fn loopback_ipv6_rejected() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn unspecified_ipv6_rejected() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn link_local_ipv6_rejected() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0xfebf, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn ula_rejected() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn multicast_ipv6_rejected() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn ipv4_mapped_loopback_rejected() {
        // ::ffff:127.0.0.1 must be rejected the same as 127.0.0.1.
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert!(is_disallowed_ip(ip));
    }

    #[test]
    fn ipv4_mapped_rfc1918_rejected() {
        // ::ffff:10.0.0.1
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
        assert!(is_disallowed_ip(ip));
    }

    #[test]
    fn public_ipv6_allowed() {
        // Google public DNS over IPv6
        assert!(!is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    // --- validate_list_url ---

    #[test]
    fn validates_https_public_url() {
        assert!(validate_list_url("https://lists.purge.cc/base_ads.txt").is_ok());
    }

    #[test]
    fn validates_https_public_ip_literal() {
        assert!(validate_list_url("https://1.1.1.1/list.txt").is_ok());
    }

    #[test]
    fn rejects_http_url() {
        assert!(matches!(
            validate_list_url("http://lists.purge.cc/base_ads.txt"),
            Err(UrlGuardError::InvalidScheme(_))
        ));
    }

    #[test]
    fn rejects_file_url() {
        assert!(matches!(
            validate_list_url("file:///etc/passwd"),
            Err(UrlGuardError::InvalidScheme(_))
        ));
    }

    #[test]
    fn rejects_ftp_url() {
        assert!(matches!(
            validate_list_url("ftp://lists.purge.cc/base_ads.txt"),
            Err(UrlGuardError::InvalidScheme(_))
        ));
    }

    #[test]
    fn rejects_loopback_literal_ipv4() {
        assert!(matches!(
            validate_list_url("https://127.0.0.1/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_rfc1918_literal() {
        assert!(matches!(
            validate_list_url("https://10.0.0.1/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
        assert!(matches!(
            validate_list_url("https://192.168.1.1/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_link_local_literal() {
        assert!(matches!(
            validate_list_url("https://169.254.254.1/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_ipv6_loopback_literal() {
        assert!(matches!(
            validate_list_url("https://[::1]/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_ula_literal() {
        assert!(matches!(
            validate_list_url("https://[fd00::1]/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_ipv6_link_local_literal() {
        assert!(matches!(
            validate_list_url("https://[fe80::1]/list.txt"),
            Err(UrlGuardError::DisallowedHost(_))
        ));
    }

    #[test]
    fn rejects_unparseable_url() {
        assert!(matches!(
            validate_list_url("not a url at all"),
            Err(UrlGuardError::ParseError(_))
        ));
    }

    #[test]
    fn build_list_client_succeeds() {
        let client = build_list_client(Duration::from_secs(10));
        assert!(client.is_ok());
    }

    // ── bulk-download timeouts ────────────────────────────────────────
    //
    // These three pin the split documented at the top of this module. They
    // exist because the property under test is not observable on the client
    // — `reqwest` exposes no getter for its configured timeouts — so the
    // only honest assertion is behavioural, against a real socket.
    //
    // Verified by mutation on 2026-08-11, because a green test that cannot
    // go red is decoration:
    //
    // | removed from the builder | caught by |
    // |---|---|
    // | `.timeout(total)` | `total_timeout_still_bounds_a_peer_that_drips_forever` — hangs, killed at 120s |
    // | `.read_timeout(read)` | `bulk_client_aborts_when_the_stream_goes_idle` — fails at 30.0s with "the 30s total fired" |
    //
    // Note what that table also says: the completion test below survived
    // BOTH mutations. It pins the regression's shape, not the presence of
    // the read window — see its own doc comment.

    /// Serve a body in `chunk`-sized frames with `delay` before each one, to
    /// every connection. `chunks: None` dribbles forever with no
    /// `Content-Length`, which is the slow-drip peer the total timeout
    /// exists for.
    async fn spawn_dribbling_server(
        chunk: &'static str,
        chunks: Option<usize>,
        delay: Duration,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let header = match chunks {
                        Some(n) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            chunk.len() * n
                        ),
                        None => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string(),
                    };
                    if stream.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut sent = 0usize;
                    while chunks.is_none_or(|n| sent < n) {
                        tokio::time::sleep(delay).await;
                        if stream.write_all(chunk.as_bytes()).await.is_err() {
                            return;
                        }
                        sent += 1;
                    }
                });
            }
        });
        addr
    }

    async fn fetch_all(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, reqwest::Error> {
        let resp = client.get(url).send().await?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// The regression itself, as an A/B against the old semantics.
    ///
    /// One body, streamed steadily for ~2s in 200ms frames. A single total
    /// deadline the size of the read window (500ms) kills it — that is the
    /// bug: the deadline was acting as a size limit. The bulk client, whose
    /// 500ms budget is per-frame instead, completes it.
    ///
    /// **What this does NOT prove:** that `read_timeout` is set. The bulk
    /// half passes on a client with no read timeout at all, because its 20s
    /// total alone covers a 2s transfer — and it cannot be made to
    /// discriminate, since a total smaller than the transfer would fail
    /// every configuration. The read window's presence is pinned by
    /// [`bulk_client_aborts_when_the_stream_goes_idle`]; the two are only
    /// complete together.
    #[tokio::test]
    async fn bulk_client_completes_a_transfer_longer_than_its_read_window() {
        let addr = spawn_dribbling_server("0123456789", Some(10), Duration::from_millis(200)).await;
        let url = format!("http://{addr}/list.txt");

        let total_deadline = build_list_client(Duration::from_millis(500)).unwrap();
        let err = fetch_all(&total_deadline, &url)
            .await
            .expect_err("a 500ms TOTAL deadline must not survive a 2s transfer");
        assert!(err.is_timeout(), "expected a timeout, got: {err}");

        let bulk = build_bulk_list_client_with(
            Duration::from_secs(20),
            Duration::from_millis(500),
            Duration::from_secs(5),
        )
        .unwrap();
        let body = fetch_all(&bulk, &url)
            .await
            .expect("steady 200ms frames must survive a 500ms read window");
        assert_eq!(body.len(), 100, "short read: {} bytes", body.len());
    }

    /// The liveness half: silence longer than the read window aborts, and
    /// aborts on the read timeout rather than sitting on the total.
    #[tokio::test]
    async fn bulk_client_aborts_when_the_stream_goes_idle() {
        let addr = spawn_dribbling_server("x", Some(10), Duration::from_secs(3)).await;
        let url = format!("http://{addr}/list.txt");

        let bulk = build_bulk_list_client_with(
            Duration::from_secs(30),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .unwrap();
        let start = std::time::Instant::now();
        let err = fetch_all(&bulk, &url)
            .await
            .expect_err("a 3s gap must not survive a 200ms read window");
        let elapsed = start.elapsed();

        assert!(err.is_timeout(), "expected a timeout, got: {err}");
        assert!(
            elapsed < Duration::from_secs(3),
            "took {elapsed:?} — the 30s total fired, not the read timeout"
        );
    }

    /// The backstop, and the reason `.timeout()` must not be dropped in
    /// favour of `read_timeout` alone: a peer dripping inside every read
    /// window resets the idle timer forever. Delete the `.timeout()` line in
    /// `build_bulk_list_client_with` and this test hangs.
    #[tokio::test]
    async fn total_timeout_still_bounds_a_peer_that_drips_forever() {
        let addr = spawn_dribbling_server("x", None, Duration::from_millis(100)).await;
        let url = format!("http://{addr}/list.txt");

        let bulk = build_bulk_list_client_with(
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .unwrap();
        let start = std::time::Instant::now();
        // The outer timeout is the point: libtest has no per-test deadline,
        // so without it a regression that removes `.timeout(total)` would
        // WEDGE the suite instead of failing it — a hung CI job reads as
        // infrastructure trouble, not as a broken invariant.
        let err = tokio::time::timeout(Duration::from_secs(10), fetch_all(&bulk, &url))
            .await
            .expect("the total ceiling did not fire — `.timeout()` is gone from the builder")
            .expect_err("an endless drip must be cut by the total ceiling");
        let elapsed = start.elapsed();

        assert!(err.is_timeout(), "expected a timeout, got: {err}");
        assert!(
            elapsed < Duration::from_secs(10),
            "took {elapsed:?} — nothing bounded the drip"
        );
    }

    // ── rev-2606 §06 manager-04b: userinfo refusal + redaction ────

    #[test]
    fn rejects_url_with_embedded_credentials() {
        let secret = "https://alice:s3cr3t@lists.example.com/list.txt";
        let err = validate_list_url(secret).unwrap_err();
        match &err {
            UrlGuardError::ContainsUserinfo(redacted) => {
                assert!(!redacted.contains("s3cr3t"), "password must not appear");
                assert!(!redacted.contains("alice"), "username must not appear");
                assert!(redacted.contains("lists.example.com"));
            }
            other => panic!("expected ContainsUserinfo, got {other:?}"),
        }
        // The Display string (what gets stored/logged) is also clean.
        let shown = err.to_string();
        assert!(
            !shown.contains("s3cr3t"),
            "Display leaked the password: {shown}"
        );
    }

    #[test]
    fn rejects_url_with_username_only() {
        assert!(matches!(
            validate_list_url("https://bob@lists.example.com/list.txt"),
            Err(UrlGuardError::ContainsUserinfo(_))
        ));
    }

    #[test]
    fn accepts_plain_https_url_without_userinfo() {
        assert!(validate_list_url("https://lists.purge.cc/ads.txt").is_ok());
    }

    #[test]
    fn redact_userinfo_strips_credentials() {
        assert_eq!(
            redact_userinfo("https://alice:s3cr3t@host.example/p?q=1"),
            "https://host.example/p?q=1"
        );
        // No userinfo → unchanged.
        assert_eq!(
            redact_userinfo("https://host.example/p"),
            "https://host.example/p"
        );
        // Unparseable but with an authority userinfo span → best-effort strip.
        let mangled = redact_userinfo("https://u:p@ho st.example/x");
        assert!(!mangled.contains("u:p@"), "got: {mangled}");
    }
}
