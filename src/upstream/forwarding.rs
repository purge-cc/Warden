//! Conditional DNS forwarding (split DNS).
//!
//! Routes queries to different upstream resolvers based on domain suffix.
//! Longest-suffix match wins. Domains not matching any zone use the default upstream.

use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use hickory_proto::rr::{Name, RecordType};

use super::circuit::CircuitBreaker;
use super::{Upstream, UpstreamResponse};
use crate::config::settings::ForwardingZoneConfig;
use crate::dns::error::DnsError;

struct Zone {
    suffix: CompactString,
    /// Always a [`CircuitBreaker`], never a bare transport.
    ///
    /// The type is the concrete `Box<CircuitBreaker>` rather than
    /// `Box<dyn Upstream>` on purpose: it makes the invariant **structural**,
    /// so a future edit cannot store an unwrapped transport and quietly
    /// reintroduce the defect. A doc comment plus a test would have left that
    /// possible. Before this, a flaky zone resolver absorbed **every** query that
    /// matched its suffix, for as long as it stayed flaky: no open circuit, no
    /// short-circuit, nothing — while the default upstream next to it had two
    /// breakers. Zone-matched traffic is not less important than the rest; it
    /// is the traffic an operator deliberately routed somewhere specific.
    ///
    /// Note this only bounds the *stall*. There is deliberately no per-zone
    /// fallback: `[[forwarding]]` has no `fallback` field, and silently
    /// spilling a split-DNS zone onto the public default upstream would leak
    /// internal names — the exact thing conditional forwarding exists to
    /// prevent. An open zone circuit therefore fails fast with
    /// [`DnsError::CircuitBreakerOpen`] rather than resolving elsewhere.
    upstream: Box<CircuitBreaker>,
}

/// Forwarding router that wraps a default upstream and zone-specific overrides.
/// Implements `Upstream` so it drops in where the handler expects `Arc<dyn Upstream>`.
pub struct ForwardingRouter {
    /// Zones sorted by suffix length descending (longest match first).
    zones: Vec<Zone>,
    default: Arc<dyn Upstream>,
}

impl ForwardingRouter {
    /// Build from config. Zone upstreams are constructed via the shared
    /// `build_upstream` function. The `default` is the existing UpstreamResolver.
    pub fn new(
        zones: &[ForwardingZoneConfig],
        default: Arc<dyn Upstream>,
        client: &reqwest::Client,
        timeout: Duration,
        dot_pool_size: usize,
        ecs_enabled: bool,
    ) -> Result<Self, anyhow::Error> {
        let mut built_zones: Vec<Zone> = Vec::with_capacity(zones.len());

        for zone_cfg in zones {
            let suffix = zone_cfg.suffix.to_ascii_lowercase();
            let upstream = super::resolver::build_upstream(
                zone_cfg.mode,
                &zone_cfg.servers,
                timeout,
                client,
                dot_pool_size,
                ecs_enabled,
                // Forwarding zones are client-facing — no DO bit.
                false,
            )?;
            built_zones.push(Zone {
                // Wrap before storing — see the field doc. The breaker is
                // atomics-only (no lock), so this adds no lock site on the
                // DNS hot path.
                upstream: Box::new(CircuitBreaker::new(upstream)),
                suffix: CompactString::new(&suffix),
            });
        }

        // Sort by suffix length descending → longest match checked first
        built_zones.sort_by_key(|b| std::cmp::Reverse(b.suffix.len()));

        Ok(Self {
            zones: built_zones,
            default,
        })
    }

    /// Find which upstream handles a given domain.
    /// Returns the zone suffix if matched, or None for default.
    /// `domain` must be lowercase and without a trailing dot.
    fn find_zone(&self, domain: &str) -> Option<&Zone> {
        for zone in &self.zones {
            let suffix = zone.suffix.as_str();
            if domain == suffix || is_subzone_of(domain, suffix) {
                return Some(zone);
            }
        }
        None
    }
}

/// Zero-alloc suffix match: `domain` is a proper subzone of `suffix`
/// when it is strictly longer, ends with `suffix`, and the byte right
/// before the suffix is a dot. The dot check is what prevents
/// `notlocal` from matching zone `local`.
///
/// Empty-suffix early return. The config validator already rejects an
/// empty suffix on `[[forwarding]]`, so today's call sites cannot reach
/// this branch — but the helper is `pub(crate)`-grade and a future
/// caller passing a derived value should not get a "match every
/// dot-terminated domain" surprise. Pure contract pin.
fn is_subzone_of(domain: &str, suffix: &str) -> bool {
    if suffix.is_empty() || domain.len() <= suffix.len() {
        return false;
    }
    let boundary = domain.len() - suffix.len();
    domain.as_bytes()[boundary - 1] == b'.' && &domain[boundary..] == suffix
}

#[async_trait::async_trait]
impl Upstream for ForwardingRouter {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<crate::dns::edns::EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        // Fallback path for callers that don't have a pre-lowercased domain in
        // hand (tests mostly). Still allocates to derive it — the DNS hot path
        // MUST call `lookup_domain` (which takes the already-normalised domain)
        // and never this `lookup`, so a future caller does not silently
        // reintroduce a per-query allocation here.
        let domain_str = name.to_string();
        let domain = domain_str
            .strip_suffix('.')
            .unwrap_or(&domain_str)
            .to_ascii_lowercase();
        self.route(&domain, name, record_type, ecs).await
    }

    async fn lookup_domain(
        &self,
        domain: &str,
        name: &Name,
        record_type: RecordType,
        ecs: Option<crate::dns::edns::EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        // Hot path: the handler already normalised `domain`, so this
        // dispatches straight through.
        self.route(domain, name, record_type, ecs).await
    }
}

impl ForwardingRouter {
    async fn route(
        &self,
        domain: &str,
        name: &Name,
        record_type: RecordType,
        ecs: Option<crate::dns::edns::EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        if let Some(zone) = self.find_zone(domain) {
            tracing::debug!(
                domain = %domain,
                zone = %zone.suffix,
                "forwarding to zone upstream"
            );
            zone.upstream.lookup(name, record_type, ecs).await
        } else {
            self.default.lookup(name, record_type, ecs).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::UpstreamMode;
    use crate::upstream::UpstreamResponse;
    use hickory_proto::op::ResponseCode;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test upstream that counts how many lookups it receives.
    struct CountingUpstream {
        count: AtomicUsize,
    }

    impl CountingUpstream {
        fn new(_name: &str) -> Self {
            Self {
                count: AtomicUsize::new(0),
            }
        }
        fn count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl Upstream for CountingUpstream {
        async fn lookup(
            &self,
            _name: &Name,
            _record_type: RecordType,
            _ecs: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(UpstreamResponse {
                records: vec![],
                response_code: ResponseCode::NoError,
                soa_minimum_ttl: None,
                #[cfg(feature = "dnssec")]
                authority: vec![],
            })
        }
    }

    fn make_router(
        zone_suffixes: &[&str],
        zone_upstreams: Vec<Arc<CountingUpstream>>,
        default: Arc<CountingUpstream>,
    ) -> ForwardingRouter {
        let zones: Vec<Zone> = zone_suffixes
            .iter()
            .zip(zone_upstreams)
            .map(|(suffix, upstream)| Zone {
                suffix: CompactString::new(*suffix),
                // The field type forces the wrap here too, so every
                // routing test below also proves the breaker is
                // transparent on the healthy path.
                upstream: Box::new(CircuitBreaker::new(Box::new(UpstreamRef(upstream)))),
            })
            .collect();

        let mut sorted_zones = zones;
        sorted_zones.sort_by_key(|b| std::cmp::Reverse(b.suffix.len()));

        ForwardingRouter {
            zones: sorted_zones,
            default,
        }
    }

    /// Wrapper to use Arc<CountingUpstream> as Box<dyn Upstream>
    struct UpstreamRef(Arc<CountingUpstream>);

    #[async_trait::async_trait]
    impl Upstream for UpstreamRef {
        async fn lookup(
            &self,
            name: &Name,
            record_type: RecordType,
            ecs: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.0.lookup(name, record_type, ecs).await
        }
    }

    #[tokio::test]
    async fn default_upstream_when_no_zones() {
        let default = Arc::new(CountingUpstream::new("default"));
        let router = make_router(&[], vec![], default.clone());

        let name = Name::from_str("google.com.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(default.count(), 1);
    }

    #[tokio::test]
    async fn zone_match_by_suffix() {
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));

        let router = make_router(&["local"], vec![local_up.clone()], default.clone());

        let name = Name::from_str("printer.local.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(local_up.count(), 1);
        assert_eq!(default.count(), 0);
    }

    #[tokio::test]
    async fn exact_suffix_match() {
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));

        let router = make_router(&["local"], vec![local_up.clone()], default.clone());

        // Query for just "local" (the suffix itself)
        let name = Name::from_str("local.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(local_up.count(), 1);
    }

    #[tokio::test]
    async fn unmatched_domain_uses_default() {
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));

        let router = make_router(&["local"], vec![local_up.clone()], default.clone());

        let name = Name::from_str("google.com.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(default.count(), 1);
        assert_eq!(local_up.count(), 0);
    }

    #[tokio::test]
    async fn longest_suffix_wins() {
        let default = Arc::new(CountingUpstream::new("default"));
        let broad = Arc::new(CountingUpstream::new("example.com"));
        let narrow = Arc::new(CountingUpstream::new("corp.example.com"));

        let router = make_router(
            &["example.com", "corp.example.com"],
            vec![broad.clone(), narrow.clone()],
            default.clone(),
        );

        // "server.corp.example.com" should match the longer suffix
        let name = Name::from_str("server.corp.example.com.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(narrow.count(), 1);
        assert_eq!(broad.count(), 0);

        // "web.example.com" should match the shorter suffix
        let name = Name::from_str("web.example.com.").unwrap();
        router.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(broad.count(), 1);
        assert_eq!(narrow.count(), 1); // unchanged
    }

    #[tokio::test]
    async fn multiple_zones_independent() {
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));
        let vpn_up = Arc::new(CountingUpstream::new("vpn"));

        let router = make_router(
            &["local", "corp.vpn"],
            vec![local_up.clone(), vpn_up.clone()],
            default.clone(),
        );

        let name1 = Name::from_str("nas.local.").unwrap();
        let name2 = Name::from_str("server.corp.vpn.").unwrap();
        let name3 = Name::from_str("google.com.").unwrap();

        router.lookup(&name1, RecordType::A, None).await.unwrap();
        router.lookup(&name2, RecordType::A, None).await.unwrap();
        router.lookup(&name3, RecordType::A, None).await.unwrap();

        assert_eq!(local_up.count(), 1);
        assert_eq!(vpn_up.count(), 1);
        assert_eq!(default.count(), 1);
    }

    #[test]
    fn is_subzone_of_byte_compare() {
        // Proper subzones
        assert!(is_subzone_of("printer.local", "local"));
        assert!(is_subzone_of("a.b.c.local", "local"));
        assert!(is_subzone_of("server.corp.example.com", "corp.example.com"));
        // Exact match is NOT a subzone (handled separately in find_zone)
        assert!(!is_subzone_of("local", "local"));
        // Partial matches must not cross the label boundary — this is the
        // invariant that the old format!(".{suffix}") concat enforced and
        // the byte-offset check now replaces.
        assert!(!is_subzone_of("notlocal", "local"));
        assert!(!is_subzone_of("evilexample.com", "example.com"));
        // Empty / tiny edge cases
        assert!(!is_subzone_of("", "local"));
        assert!(!is_subzone_of("local", "longer"));
    }

    #[test]
    fn is_subzone_of_empty_suffix_returns_false() {
        // Regression pin: an empty suffix must not match every
        // dot-terminated domain. Today's validator rejects empty
        // suffixes on `[[forwarding]]`, so this is contract pinning
        // against a future caller passing a derived value.
        assert!(!is_subzone_of("printer.local", ""));
        assert!(!is_subzone_of("a.b.c.", ""));
        assert!(!is_subzone_of("", ""));
    }

    #[tokio::test]
    async fn lookup_domain_routes_via_suffix_hint() {
        // Hot-path variant: handler passes domain as &str, no Name.to_string
        // allocation inside ForwardingRouter.
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));
        let router = make_router(&["local"], vec![local_up.clone()], default.clone());

        let name = Name::from_str("printer.local.").unwrap();
        router
            .lookup_domain("printer.local", &name, RecordType::A, None)
            .await
            .unwrap();
        assert_eq!(local_up.count(), 1);
        assert_eq!(default.count(), 0);
    }

    #[test]
    fn find_zone_returns_none_for_partial_match() {
        // "notlocal" should NOT match zone "local"
        let default = Arc::new(CountingUpstream::new("default"));
        let local_up = Arc::new(CountingUpstream::new("local"));

        let router = make_router(&["local"], vec![local_up.clone()], default.clone());

        assert!(router.find_zone("notlocal").is_none());
        assert!(router.find_zone("printer.local").is_some());
        assert!(router.find_zone("local").is_some());
    }

    #[test]
    fn config_deserialization() {
        let toml = r#"
[[forwarding]]
suffix = "local"
mode = "plain"
servers = ["192.168.1.1:53"]

[[forwarding]]
suffix = "corp.example.com"
mode = "dot"
servers = ["vpn-dns.example.com:853"]
"#;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            forwarding: Vec<ForwardingZoneConfig>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.forwarding.len(), 2);
        assert_eq!(w.forwarding[0].suffix, "local");
        assert_eq!(w.forwarding[0].mode, UpstreamMode::Plain);
        assert_eq!(w.forwarding[1].suffix, "corp.example.com");
        assert_eq!(w.forwarding[1].mode, UpstreamMode::Dot);
    }

    /// Zone upstream that always fails, and counts the attempts that actually
    /// reached it.
    struct FailingZoneUpstream {
        count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Upstream for FailingZoneUpstream {
        async fn lookup(
            &self,
            _name: &Name,
            _record_type: RecordType,
            _ecs: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Err(DnsError::UpstreamRequestFailed("zone upstream down".into()))
        }
    }

    /// A flaky zone upstream must trip its own circuit breaker, exactly as
    /// the default upstream's primary/fallback pair already did.
    ///
    /// The two assertions are separate properties and both matter:
    ///
    /// 1. **The circuit opens.** After `FAILURE_THRESHOLD` failures the zone
    ///    stops being dialled and the router returns `CircuitBreakerOpen`
    ///    immediately. Without the wrap the zone absorbs every query forever
    ///    and the attempt counter keeps climbing.
    /// 2. **Nothing spills to the default upstream.** An open zone circuit must
    ///    fail fast, not silently re-route a split-DNS zone to the public
    ///    resolver — that would leak internal names.
    #[tokio::test]
    async fn failing_zone_upstream_trips_its_own_breaker() {
        use crate::upstream::circuit::State;

        let default = Arc::new(CountingUpstream::new("default"));
        let attempts = Arc::new(AtomicUsize::new(0));

        let zone = Zone {
            suffix: CompactString::new("corp.example.com"),
            upstream: Box::new(CircuitBreaker::new(Box::new(FailingZoneUpstream {
                count: attempts.clone(),
            }))),
        };
        let router = ForwardingRouter {
            zones: vec![zone],
            default: default.clone(),
        };

        let name = Name::from_str("db.corp.example.com.").unwrap();

        // Drive it to the threshold: every one of these reaches the transport.
        for _ in 0..10 {
            let err = router
                .lookup(&name, RecordType::A, None)
                .await
                .expect_err("failing zone upstream must surface an error");
            assert!(
                matches!(err, DnsError::UpstreamRequestFailed(_)),
                "before the threshold the transport error is what propagates, got {err:?}"
            );
        }
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            10,
            "every pre-threshold query should have reached the zone transport"
        );
        assert_eq!(router.zones[0].upstream.state(), State::Open);

        // Past the threshold the breaker answers instead of the transport.
        let err = router
            .lookup(&name, RecordType::A, None)
            .await
            .expect_err("an open circuit rejects");
        assert!(
            matches!(err, DnsError::CircuitBreakerOpen),
            "open zone circuit must short-circuit, got {err:?}"
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            10,
            "the open circuit must NOT have dialled the failing transport again"
        );

        assert_eq!(
            default.count(),
            0,
            "an open zone circuit must never spill onto the default upstream — \
             that would leak internal split-DNS names to the public resolver"
        );
    }
}
