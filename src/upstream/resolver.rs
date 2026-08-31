//! Upstream resolver with fallback chain and circuit breakers.
//!
//! The [`UpstreamResolver`] is the single entry point used by the DNS handler.
//! It wraps primary + optional fallback upstream, each guarded by a circuit
//! breaker. Flow: primary → (circuit-break) → fallback → SERVFAIL.

use std::time::Duration;

use hickory_proto::rr::{Name, RecordType};

use super::circuit::CircuitBreaker;
use super::doh::DohUpstream;
use super::dot::DotUpstream;
use super::plain::PlainUpstream;
use super::{Upstream, UpstreamResponse};
use crate::config::settings::{UpstreamConfig, UpstreamMode};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

/// Top-level upstream resolver with primary + fallback chain.
pub struct UpstreamResolver {
    primary: CircuitBreaker,
    fallback: Option<CircuitBreaker>,
}

impl UpstreamResolver {
    /// Returns `true` if the primary upstream circuit breaker is not Open.
    /// Used by the `/healthz` endpoint to signal upstream availability.
    pub fn is_primary_healthy(&self) -> bool {
        self.primary.state() != super::circuit::State::Open
    }

    /// Build the resolver from configuration.
    ///
    /// The `client` is the shared reqwest::Client (used for DoH and list downloads).
    ///
    /// **§4.8 §2/2 (T4):** the per-profile ECS option is no longer
    /// baked into the upstream at construction time; the handler now
    /// derives it per query from the resolved profile and passes it
    /// through [`Upstream::lookup`]. The `[upstream.ecs].enabled`
    /// master switch still gates the plain-transport dispatch
    /// (Resolver vs Raw) because `hickory_resolver` has no ECS API.
    pub fn from_config(
        config: &UpstreamConfig,
        client: &reqwest::Client,
    ) -> Result<Self, anyhow::Error> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let dot_pool_size = config.dot.pool_size;
        let ecs_enabled = config.ecs.enabled;

        let primary = build_upstream(
            config.mode,
            &config.servers,
            timeout,
            client,
            dot_pool_size,
            ecs_enabled,
            // §4.10: the client-facing resolver never sets the DO bit — the
            // DNSSEC validator builds its own DO-on upstream (§4.10-4b).
            false,
        )?;
        let primary = CircuitBreaker::new(primary);

        let fallback = match &config.fallback {
            Some(fb) => {
                let fb_upstream = build_upstream(
                    fb.mode,
                    &fb.servers,
                    timeout,
                    client,
                    dot_pool_size,
                    ecs_enabled,
                    false,
                )?;
                Some(CircuitBreaker::new(fb_upstream))
            }
            None => None,
        };

        tracing::info!(
            mode = %config.mode,
            servers = ?config.servers,
            fallback = config.fallback.as_ref().map(|f| f.mode.to_string()),
            "upstream initialized"
        );

        Ok(Self { primary, fallback })
    }

    /// §4.10-4b — build a DNSSEC-validating sibling of the client-facing
    /// resolver: identical upstream targets (primary + fallback, same circuit
    /// breakers) but every leaf query carries the DO bit (`dnssec_ok = true`),
    /// so RRSIG / NSEC / NSEC3 material arrives for the chain walk. ECS is
    /// forced off — the validator queries by name and has no client subnet to
    /// attach. The caller wraps the result in a
    /// [`crate::dnssec::UpstreamChainFetcher`].
    #[cfg(feature = "dnssec")]
    pub fn from_config_validator(
        config: &UpstreamConfig,
        client: &reqwest::Client,
    ) -> Result<Self, anyhow::Error> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let dot_pool_size = config.dot.pool_size;

        let primary = CircuitBreaker::new(build_upstream(
            config.mode,
            &config.servers,
            timeout,
            client,
            dot_pool_size,
            false, // ecs_enabled — the validator queries by name, no client subnet
            true,  // dnssec_ok — DO + CD + 1232-byte EDNS buffer (§4.10-4a)
        )?);

        let fallback = match &config.fallback {
            Some(fb) => Some(CircuitBreaker::new(build_upstream(
                fb.mode,
                &fb.servers,
                timeout,
                client,
                dot_pool_size,
                false,
                true,
            )?)),
            None => None,
        };

        tracing::info!(
            mode = %config.mode,
            servers = ?config.servers,
            "DNSSEC validator upstream initialized (DO bit on)"
        );

        Ok(Self { primary, fallback })
    }
}

/// Build an upstream implementation from mode + servers.
///
/// `dnssec_ok` bakes the EDNS DO bit into the leaf transport (§4.10): the
/// client-facing resolver passes `false` (byte-identical wire packets); the
/// DNSSEC validator's upstream passes `true`. For `Plain` it forces the
/// raw-socket path, since hickory's `Resolver` has no DO knob.
pub(crate) fn build_upstream(
    mode: UpstreamMode,
    servers: &[String],
    timeout: Duration,
    client: &reqwest::Client,
    dot_pool_size: usize,
    ecs_enabled: bool,
    dnssec_ok: bool,
) -> Result<Box<dyn Upstream>, anyhow::Error> {
    match mode {
        UpstreamMode::Plain => {
            let upstream = PlainUpstream::new(servers, timeout, ecs_enabled, dnssec_ok)?;
            Ok(Box::new(upstream))
        }
        UpstreamMode::Doh => {
            // DoH + DoT have ECS injection at the wire-format layer
            // (build_query_bytes); they don't need a constructor-time
            // flag.
            let _ = ecs_enabled;
            let upstream = DohUpstream::new(client.clone(), servers.to_vec(), timeout, dnssec_ok)?;
            Ok(Box::new(upstream))
        }
        UpstreamMode::Dot => {
            let _ = ecs_enabled;
            let upstream = DotUpstream::new(servers, timeout, dot_pool_size, dnssec_ok)?;
            Ok(Box::new(upstream))
        }
        UpstreamMode::Doq => {
            // DoQ is feature-gated (the quinn QUIC stack). The `Doq` variant
            // always exists so a `mode = "doq"` config deserializes regardless
            // of build features; when the feature is off we fail *here* with an
            // actionable error rather than a panic or a generic serde rejection.
            #[cfg(feature = "doq")]
            {
                let _ = ecs_enabled;
                let upstream = super::doq::DoqUpstream::new(servers, timeout, dnssec_ok)?;
                Ok(Box::new(upstream))
            }
            #[cfg(not(feature = "doq"))]
            {
                anyhow::bail!(
                    "DoQ upstream (mode = \"doq\") requires building with `--features doq`"
                )
            }
        }
    }
}

#[async_trait::async_trait]
impl Upstream for UpstreamResolver {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        // Try primary
        match self.primary.lookup(name, record_type, ecs.clone()).await {
            Ok(resp) => return Ok(resp),
            Err(DnsError::CircuitBreakerOpen) => {
                tracing::debug!(domain = %name, "primary circuit-breaker open, trying fallback");
            }
            Err(e) => {
                tracing::warn!(domain = %name, error = %e, "primary upstream failed, trying fallback");
            }
        }

        // Try fallback
        if let Some(ref fallback) = self.fallback {
            match fallback.lookup(name, record_type, ecs).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::warn!(domain = %name, error = %e, "fallback upstream also failed");
                    return Err(DnsError::AllUpstreamsFailed);
                }
            }
        }

        Err(DnsError::AllUpstreamsFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hickory_proto::op::ResponseCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock upstream: counts calls and either fails or returns a tagged response
    /// (the tag rides in `soa_minimum_ttl` so a test can tell which level answered).
    struct CountingUpstream {
        hits: Arc<AtomicUsize>,
        ok: bool,
        tag: u32,
    }

    #[async_trait]
    impl Upstream for CountingUpstream {
        async fn lookup(
            &self,
            _name: &Name,
            _record_type: RecordType,
            _ecs: Option<EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            if self.ok {
                Ok(UpstreamResponse {
                    records: vec![],
                    response_code: ResponseCode::NoError,
                    soa_minimum_ttl: Some(self.tag),
                    #[cfg(feature = "dnssec")]
                    authority: vec![],
                })
            } else {
                Err(DnsError::UpstreamRequestFailed("mock failure".into()))
            }
        }
    }

    fn level(hits: &Arc<AtomicUsize>, ok: bool, tag: u32) -> CircuitBreaker {
        CircuitBreaker::new(Box::new(CountingUpstream {
            hits: hits.clone(),
            ok,
            tag,
        }))
    }

    fn name() -> Name {
        "example.com.".parse().unwrap()
    }

    #[tokio::test]
    async fn primary_success_short_circuits_fallback() {
        let p = Arc::new(AtomicUsize::new(0));
        let f = Arc::new(AtomicUsize::new(0));
        let resolver = UpstreamResolver {
            primary: level(&p, true, 1),
            fallback: Some(level(&f, true, 2)),
        };

        let resp = resolver.lookup(&name(), RecordType::A, None).await.unwrap();
        assert_eq!(resp.soa_minimum_ttl, Some(1), "primary answered");
        assert_eq!(p.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.load(Ordering::SeqCst),
            0,
            "fallback untouched on primary success"
        );
    }

    #[tokio::test]
    async fn failover_to_fallback_when_primary_fails() {
        let p = Arc::new(AtomicUsize::new(0));
        let f = Arc::new(AtomicUsize::new(0));
        let resolver = UpstreamResolver {
            primary: level(&p, false, 1),
            fallback: Some(level(&f, true, 2)),
        };

        let resp = resolver.lookup(&name(), RecordType::A, None).await.unwrap();
        assert_eq!(resp.soa_minimum_ttl, Some(2), "fallback answered");
        assert_eq!(p.load(Ordering::SeqCst), 1, "primary tried first");
        assert_eq!(
            f.load(Ordering::SeqCst),
            1,
            "fallback tried after primary failed"
        );
    }

    #[tokio::test]
    async fn both_fail_yields_all_upstreams_failed() {
        let p = Arc::new(AtomicUsize::new(0));
        let f = Arc::new(AtomicUsize::new(0));
        let resolver = UpstreamResolver {
            primary: level(&p, false, 1),
            fallback: Some(level(&f, false, 2)),
        };

        let err = resolver
            .lookup(&name(), RecordType::A, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::AllUpstreamsFailed));
    }

    #[tokio::test]
    async fn no_fallback_failure_is_all_upstreams_failed() {
        let p = Arc::new(AtomicUsize::new(0));
        let resolver = UpstreamResolver {
            primary: level(&p, false, 1),
            fallback: None,
        };

        let err = resolver
            .lookup(&name(), RecordType::A, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::AllUpstreamsFailed));
    }

    /// With the `doq` feature on, `mode = "doq"` builds a real DoQ upstream
    /// (endpoint bind only — no network). Needs a runtime for the quinn endpoint.
    #[cfg(feature = "doq")]
    #[tokio::test]
    async fn build_upstream_doq_constructs_when_feature_on() {
        let client = reqwest::Client::new();
        let up = build_upstream(
            UpstreamMode::Doq,
            &["1.1.1.1:853".to_string()],
            Duration::from_secs(2),
            &client,
            1,
            false,
            false,
        );
        assert!(up.is_ok(), "doq upstream should build: {:?}", up.err());
    }

    /// Without the `doq` feature, `mode = "doq"` is rejected with an actionable
    /// error (not a panic, not a generic serde failure).
    #[cfg(not(feature = "doq"))]
    #[tokio::test]
    async fn build_upstream_doq_errors_when_feature_off() {
        let client = reqwest::Client::new();
        // `Box<dyn Upstream>` is not `Debug`, so use let-else rather than
        // `unwrap_err()` to extract the error.
        let Err(err) = build_upstream(
            UpstreamMode::Doq,
            &["dns.quad9.net:853".to_string()],
            Duration::from_secs(2),
            &client,
            1,
            false,
            false,
        ) else {
            panic!("DoQ must be rejected when the `doq` feature is off");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("doq") && msg.contains("--features"),
            "expected an actionable feature-gate error, got: {msg}"
        );
    }
}
