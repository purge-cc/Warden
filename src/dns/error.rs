//! DNS error types for the query handler pipeline.

use hickory_net::NetError;
use hickory_proto::op::ResponseCode;

/// Errors that can occur during DNS query processing.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("label exceeds 63 bytes")]
    LabelTooLong,
    #[error("name exceeds 253 bytes")]
    NameTooLong,
    #[error("name has more than 15 labels")]
    TooManyLabels,
    #[error("empty query name")]
    EmptyName,
    #[error("upstream error: {0}")]
    UpstreamError(#[from] NetError),
    #[error("upstream request failed: {0}")]
    UpstreamRequestFailed(String),
    #[error("DNS wire format error: {0}")]
    WireFormatError(String),
    #[error("all upstreams failed")]
    AllUpstreamsFailed,
    #[error("circuit breaker open")]
    CircuitBreakerOpen,
    #[error("server error: {0}")]
    ServerError(String),
    /// Upstream returned a non-cacheable response (SERVFAIL or Refused).
    /// Carried out of the `DnsCache::lookup_or_fetch` singleflight closure
    /// so the handler can forward the response_code to the client without
    /// caching it (T3.2.b M-12). Returning Err from the closure makes
    /// moka's `try_get_with` skip the insert; concurrent waiters all share
    /// this single fetch outcome instead of fanning out.
    #[error("uncacheable upstream response: {0}")]
    Uncacheable(ResponseCode),
}
