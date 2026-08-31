//! Plain DNS upstream forwarder.
//!
//! Two implementations live behind a single `PlainUpstream` facade:
//!
//! * **Resolver path (default, ECS off):** wraps a `hickory_resolver::Resolver`
//!   configured with the user's upstream servers (e.g. 192.0.2.53:53). Cache is
//!   disabled — purge-warden adds its own cache layer.
//! * **Raw-socket path (ECS on):** dispatches to [`crate::upstream::plain_raw::
//!   PlainRawClient`] when the operator enables `[upstream.ecs]`. Required
//!   because `hickory_resolver` 0.25 has no public ECS API.
//!
//! The Resolver path is preserved bit-for-bit when `ecs.enabled = false` —
//! LAN-only deploys see zero behavioural change vs the pre-§4.8 baseline.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::{DnsError as NetDnsError, NetError};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Name;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;

use super::plain_raw::PlainRawClient;
use super::{Upstream, UpstreamResponse};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

/// Forwards DNS queries to upstream servers via plain UDP with TCP fallback.
pub struct PlainUpstream {
    inner: PlainInner,
}

enum PlainInner {
    // Box: hickory's Resolver is ~584 bytes vs PlainRawClient ~72 bytes;
    // boxing keeps the enum compact (clippy::large_enum_variant) without
    // affecting hot-path latency since PlainUpstream is constructed once
    // per process.
    Resolver(Box<Resolver<TokioRuntimeProvider>>),
    Raw(PlainRawClient),
}

impl PlainUpstream {
    /// Create a new upstream resolver. Servers are parsed as `IP:port`
    /// strings.
    ///
    /// **§4.8 §2/2 (T4):** `ecs_enabled` is the global
    /// `[upstream.ecs].enabled` master kill-switch, not a per-query
    /// option. When `false`, this upstream uses the existing
    /// `hickory_resolver::Resolver` path: each server registers both
    /// UDP (primary) and TCP (fallback); truncated UDP responses retry
    /// over TCP automatically — the per-query `ecs` arg on
    /// [`Upstream::lookup`] is ignored by this branch (the resolver
    /// has no ECS API).
    ///
    /// When `true`, the upstream dispatches to [`PlainRawClient`] which
    /// builds outbound queries via the shared `build_query_bytes()` and
    /// honours the per-query ECS option. The dispatch decision happens
    /// once at construction time because the resolver path cannot inject
    /// ECS at all; we cannot mix-and-match per query. Operators who want
    /// per-profile ECS off-but-master-switch-on still pay the raw-socket
    /// price for the off-profile queries (the build_option returns
    /// `None`, the wire is byte-identical to baseline anyway).
    pub fn new(
        servers: &[String],
        timeout: Duration,
        ecs_enabled: bool,
        dnssec_ok: bool,
    ) -> Result<Self, anyhow::Error> {
        // §4.10: the hickory `Resolver` path has no DO-bit knob, so when DNSSEC
        // OK is required (the validator's upstream) we force the raw-socket
        // path — exactly as ECS injection already does. `dnssec_ok = false` (the
        // client-facing upstream) preserves the Resolver path bit-for-bit.
        let inner = if ecs_enabled || dnssec_ok {
            PlainInner::Raw(PlainRawClient::new(servers, timeout, dnssec_ok)?)
        } else {
            PlainInner::Resolver(Box::new(build_resolver(servers, timeout)?))
        };
        Ok(Self { inner })
    }

    /// Returns `true` when this upstream is dispatching to the raw-socket
    /// client (rather than hickory's `Resolver`). The raw path is selected
    /// when ECS injection (§4.8) **or** the DNSSEC DO bit (§4.10) is required.
    /// Useful for tests and operator introspection.
    pub fn uses_ecs(&self) -> bool {
        matches!(self.inner, PlainInner::Raw(_))
    }
}

/// Build the hickory `Resolver` used by the non-ECS, non-DNSSEC plain path.
///
/// **Single-retry-layer invariant M5/M6.** `opts.attempts` is deliberately
/// `1`: this resolver retries *nothing*, because warden already has exactly one
/// retry surface above it and stacking a second multiplies tail latency instead
/// of adding resilience.
///
/// That surface is [`crate::upstream::resolver::UpstreamResolver`], whose
/// `Upstream::lookup` impl dials the configured fallback on **any** primary
/// error — timeout included — with a
/// [`crate::upstream::circuit::CircuitBreaker`] in front of each.
///
/// The arithmetic that forces the choice: `attempts` multiplies `opts.timeout`,
/// which is `upstream.timeout_ms` and defaults to **5000** (`config/settings.rs`
/// `default_upstream_timeout_ms`). At `attempts = 2` a single call to a
/// black-holed upstream stalls ~10s before the breaker sees one failure, and
/// the breaker needs `FAILURE_THRESHOLD` (10) of them — roughly **100 seconds**
/// of frozen cache misses before the circuit opens and the fallback takes over.
/// At `attempts = 1` that halves, and the fallback is reached after one timeout
/// rather than two.
///
/// **The tradeoff, stated rather than hidden:** with no `[upstream.fallback]`
/// configured there is now no retry at all, so a single dropped UDP datagram
/// surfaces to the client as a failure instead of being papered over. That is
/// the intended shape — client stub resolvers retry, and warden's own retry
/// budget belongs in one place. If transient loss ever proves too costly, lower
/// `FAILURE_THRESHOLD` in `circuit.rs`; do **not** restore resolver-level
/// retry, which would silently re-create the multiplier.
fn build_resolver(
    servers: &[String],
    timeout: Duration,
) -> Result<Resolver<TokioRuntimeProvider>, anyhow::Error> {
    let mut resolver_config = ResolverConfig::default();
    for server in servers {
        // rev-2606: the shape parse is shared with `config lint` so a typo
        // is rejected identically at lint and at boot (single source of truth).
        let addr: SocketAddr = crate::upstream::shape::validate_plain_server(server)
            .map_err(|e| anyhow::anyhow!("invalid plain upstream server: {e}"))?;
        // 0.26: a single NameServerConfig per IP now carries a Vec of
        // ConnectionConfigs (0.25 registered UDP + TCP as two separate
        // NameServerConfigs). Same wire behaviour — UDP primary, TCP fallback.
        // `ConnectionConfig::udp()/tcp()` default to port 53, so set the parsed
        // port explicitly. `trust_negative_responses = true` matches the 0.26
        // default and the pre-bump behaviour (we cache upstream negatives).
        let mut udp = ConnectionConfig::udp();
        udp.port = addr.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = addr.port();
        resolver_config.add_name_server(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
    }

    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.timeout = timeout;
    // [M6] One attempt, not two — see the single-retry-layer invariant on this
    // function. Pinned by `build_resolver_uses_a_single_attempt`.
    opts.attempts = 1;

    let provider = TokioRuntimeProvider::default();
    // 0.26: ResolverBuilder::build() now returns Result (was infallible).
    Ok(Resolver::builder_with_config(resolver_config, provider)
        .with_options(opts)
        .build()?)
}

#[async_trait::async_trait]
impl Upstream for PlainUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: hickory_proto::rr::RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        match &self.inner {
            PlainInner::Raw(raw) => raw.lookup(name, record_type, ecs).await,
            PlainInner::Resolver(resolver) => {
                // §4.8 §2/2 (T4): hickory_resolver has no ECS injection
                // API; when the master switch is off, the per-query ecs
                // value is silently dropped. The handler's resolved-
                // profile + EcsPolicy chain guarantees `ecs.is_none()`
                // along this branch in practice — we drop the param
                // defensively rather than assert, because integration
                // shims (e.g. circuit-breaker probing) may exercise
                // mixed paths.
                let _ = ecs;
                match resolver.lookup(name.clone(), record_type).await {
                    Ok(lookup) => Ok(UpstreamResponse {
                        records: lookup.answers().to_vec(),
                        response_code: ResponseCode::NoError,
                        soa_minimum_ttl: None,
                        // Resolver path is never the validator's upstream
                        // (dnssec_ok forces the Raw path), so no authority is
                        // surfaced here; hickory's Resolver abstracts it away.
                        #[cfg(feature = "dnssec")]
                        authority: vec![],
                    }),
                    Err(ref e) if e.is_no_records_found() => {
                        let (response_code, soa_minimum_ttl) = extract_negative_meta(e);
                        Ok(UpstreamResponse {
                            records: vec![],
                            response_code: response_code.unwrap_or(ResponseCode::NXDomain),
                            soa_minimum_ttl,
                            #[cfg(feature = "dnssec")]
                            authority: vec![],
                        })
                    }
                    Err(e) => Err(DnsError::UpstreamError(e)),
                }
            }
        }
    }
}

/// Extract response code and SOA-derived negative TTL from a NoRecordsFound error.
///
/// hickory has already computed `negative_ttl = min(soa_ttl, soa.minimum())`
/// for us — see `hickory_net::NoRecords::negative_ttl` (RFC 2308 §5). 0.26 moved
/// this from `ProtoErrorKind::NoRecordsFound` to the nested
/// `NetError::Dns(DnsError::NoRecordsFound(NoRecords))`.
fn extract_negative_meta(err: &NetError) -> (Option<ResponseCode>, Option<u32>) {
    match err {
        NetError::Dns(NetDnsError::NoRecordsFound(no_records)) => {
            (Some(no_records.response_code), no_records.negative_ttl)
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §4.10: `dnssec_ok = true` forces the raw-socket path even with ECS off,
    /// because hickory's `Resolver` has no DO-bit knob. `dnssec_ok = false`
    /// keeps the Resolver path — the byte-identical client-facing baseline.
    #[test]
    fn dnssec_ok_forces_raw_path() {
        let servers = ["1.1.1.1:53".to_string()];
        let timeout = Duration::from_secs(2);

        let client = PlainUpstream::new(&servers, timeout, false, false).unwrap();
        assert!(!client.uses_ecs(), "ECS off + DNSSEC off → Resolver path");

        let validator = PlainUpstream::new(&servers, timeout, false, true).unwrap();
        assert!(
            validator.uses_ecs(),
            "DNSSEC OK forces the raw-socket path (Resolver can't set DO)"
        );
    }

    /// M6 Pins the single-retry-layer invariant documented on
    /// [`build_resolver`].
    ///
    /// `attempts` multiplies `timeout` *before* the circuit breaker above ever
    /// records one failure, so restoring `2` re-introduces a ~100s window of
    /// frozen cache misses against a black-holed upstream on default settings
    /// (5s timeout x 2 attempts x FAILURE_THRESHOLD 10). `Resolver::options()`
    /// is public in hickory 0.26, so this reads the value the resolver was
    /// actually built with rather than restating the literal.
    ///
    /// TEST-NET-1 (RFC 5737) — no packet is ever sent; the resolver is only
    /// constructed.
    #[test]
    fn build_resolver_uses_a_single_attempt() {
        let servers = ["192.0.2.1:53".to_string()];
        let timeout = Duration::from_secs(5);

        let resolver = build_resolver(&servers, timeout).unwrap();
        let opts = resolver.options();

        assert_eq!(
            opts.attempts, 1,
            "warden's only retry surface is UpstreamResolver's primary->fallback \
             chain; a resolver-level retry multiplies tail latency before the \
             circuit breaker can react"
        );
        assert_eq!(opts.timeout, timeout, "the configured timeout is honoured");
        assert_eq!(opts.cache_size, 0, "warden owns caching, hickory must not");
    }
}
