//! Atomically replaceable upstream routing state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::rr::{Name, RecordType};

use super::forwarding::ForwardingRouter;
use super::{Upstream, UpstreamGenerationStamp, UpstreamResolver, UpstreamResponse};
use crate::config::settings::{DnssecConfig, ForwardingZoneConfig, UpstreamConfig, UpstreamMode};
use crate::dns::edns::EdnsClientSubnet;
use crate::dns::error::DnsError;

#[cfg(feature = "dnssec")]
use crate::config::settings::DnssecMode;
#[cfg(feature = "dnssec")]
use crate::dns::dnssec_validator::DnssecValidator;

static NEXT_UPSTREAM_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Immutable operator-facing description of the active upstream generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStatusSnapshot {
    pub mode: UpstreamMode,
    pub primary_count: usize,
    /// Primary servers followed by fallback servers, preserving config order.
    pub servers: Vec<(String, UpstreamMode)>,
}

#[derive(Clone, PartialEq, Eq)]
struct GenerationConfig {
    upstream: UpstreamConfig,
    forwarding: Vec<ForwardingZoneConfig>,
    #[cfg(feature = "dnssec")]
    dnssec: DnssecConfig,
}

impl GenerationConfig {
    fn new(
        upstream: &UpstreamConfig,
        forwarding: &[ForwardingZoneConfig],
        dnssec: &DnssecConfig,
    ) -> Self {
        #[cfg(not(feature = "dnssec"))]
        let _ = dnssec;

        Self {
            upstream: upstream.clone(),
            forwarding: forwarding.to_vec(),
            #[cfg(feature = "dnssec")]
            dnssec: dnssec.clone(),
        }
    }
}

struct UpstreamGeneration {
    id: u64,
    config: GenerationConfig,
    effective: Arc<dyn Upstream>,
    primary: Arc<UpstreamResolver>,
    status: UpstreamStatusSnapshot,
    #[cfg(feature = "dnssec")]
    dnssec_validator: Option<Arc<DnssecValidator>>,
}

impl UpstreamGeneration {
    fn build(
        upstream: &UpstreamConfig,
        forwarding: &[ForwardingZoneConfig],
        client: &reqwest::Client,
        dnssec: &DnssecConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let id = NEXT_UPSTREAM_GENERATION.fetch_add(1, Ordering::Relaxed);
        let primary = Arc::new(UpstreamResolver::from_config(upstream, client)?);
        let default: Arc<dyn Upstream> = primary.clone();
        let effective: Arc<dyn Upstream> = if forwarding.is_empty() {
            default
        } else {
            Arc::new(ForwardingRouter::new(
                forwarding,
                default,
                client,
                Duration::from_millis(upstream.timeout_ms),
                upstream.dot.pool_size,
                upstream.ecs.enabled,
            )?)
        };

        #[cfg(feature = "dnssec")]
        let dnssec_validator = if dnssec.mode == DnssecMode::Off {
            None
        } else {
            let do_upstream: Arc<dyn Upstream> =
                Arc::new(UpstreamResolver::from_config_validator(upstream, client)?);
            Some(Arc::new(DnssecValidator::new(do_upstream, dnssec)))
        };

        Ok(Arc::new(Self {
            id,
            config: GenerationConfig::new(upstream, forwarding, dnssec),
            effective,
            primary,
            status: UpstreamStatusSnapshot {
                mode: upstream.mode,
                primary_count: upstream.servers.len(),
                servers: upstream.server_list(),
            },
            #[cfg(feature = "dnssec")]
            dnssec_validator,
        }))
    }
}

/// Fully built upstream generation awaiting an infallible atomic install.
pub struct PreparedUpstream {
    generation: Arc<UpstreamGeneration>,
}

/// Upstream facade whose active resolver tree is replaced with one atomic store.
pub struct ReloadableUpstream {
    generation: ArcSwap<UpstreamGeneration>,
    current_generation: Arc<AtomicU64>,
}

impl ReloadableUpstream {
    /// Build and install the initial resolver generation.
    pub fn from_config(
        upstream: &UpstreamConfig,
        forwarding: &[ForwardingZoneConfig],
        client: &reqwest::Client,
        dnssec: &DnssecConfig,
    ) -> anyhow::Result<Self> {
        let generation = UpstreamGeneration::build(upstream, forwarding, client, dnssec)?;
        Ok(Self {
            current_generation: Arc::new(AtomicU64::new(generation.id)),
            generation: ArcSwap::new(generation),
        })
    }

    /// Build a replacement without changing live state.
    ///
    /// An identical effective configuration preserves the current circuit
    /// breakers, transport pools, and DNSSEC verdict cache.
    pub fn prepare(
        &self,
        upstream: &UpstreamConfig,
        forwarding: &[ForwardingZoneConfig],
        client: &reqwest::Client,
        dnssec: &DnssecConfig,
    ) -> anyhow::Result<Option<PreparedUpstream>> {
        let config = GenerationConfig::new(upstream, forwarding, dnssec);
        if self.generation.load().config == config {
            return Ok(None);
        }

        Ok(Some(PreparedUpstream {
            generation: UpstreamGeneration::build(upstream, forwarding, client, dnssec)?,
        }))
    }

    /// Publish a prepared generation with one lock-free pointer swap.
    pub fn install(&self, prepared: PreparedUpstream) {
        let id = prepared.generation.id;
        self.generation.store(prepared.generation);
        self.current_generation.store(id, Ordering::Release);
    }

    /// Return metadata from the same generation used for forwarding.
    pub fn status(&self) -> UpstreamStatusSnapshot {
        self.generation.load().status.clone()
    }

    /// Report the active primary resolver's circuit-breaker state.
    pub fn is_primary_healthy(&self) -> bool {
        self.generation.load().primary.is_primary_healthy()
    }

    fn stamp(&self, generation: &UpstreamGeneration) -> UpstreamGenerationStamp {
        UpstreamGenerationStamp::new(
            generation.id,
            Arc::clone(&self.current_generation),
            #[cfg(feature = "dnssec")]
            generation.dnssec_validator.clone(),
        )
    }
}

#[async_trait::async_trait]
impl Upstream for ReloadableUpstream {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        let generation = self.generation.load_full();
        let mut response = generation.effective.lookup(name, record_type, ecs).await?;
        response.generation = Some(self.stamp(&generation));
        Ok(response)
    }

    async fn lookup_domain(
        &self,
        domain: &str,
        name: &Name,
        record_type: RecordType,
        ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        let generation = self.generation.load_full();
        let mut response = generation
            .effective
            .lookup_domain(domain, name, record_type, ecs)
            .await?;
        response.generation = Some(self.stamp(&generation));
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use tokio::net::UdpSocket;

    use super::*;

    fn config(server: SocketAddr) -> UpstreamConfig {
        UpstreamConfig {
            servers: vec![server.to_string()],
            timeout_ms: 1_000,
            ..UpstreamConfig::default()
        }
    }

    async fn spawn_upstream(address: Ipv4Addr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let query = request.queries.first().unwrap();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.response_code = ResponseCode::NoError;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(address)),
                ));
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (server, task)
    }

    #[tokio::test]
    async fn identical_config_does_not_rebuild_generation() {
        let cfg = config("127.0.0.1:5301".parse().unwrap());
        let dnssec = DnssecConfig::default();
        let client = reqwest::Client::new();
        let upstream = ReloadableUpstream::from_config(&cfg, &[], &client, &dnssec).unwrap();

        assert!(upstream
            .prepare(&cfg, &[], &client, &dnssec)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn install_updates_status_and_lookup_generation() {
        let (first_server, first_task) = spawn_upstream(Ipv4Addr::new(192, 0, 2, 1)).await;
        let (second_server, second_task) = spawn_upstream(Ipv4Addr::new(192, 0, 2, 2)).await;
        let first = config(first_server);
        let second = config(second_server);
        let dnssec = DnssecConfig::default();
        let client = reqwest::Client::new();
        let upstream = ReloadableUpstream::from_config(&first, &[], &client, &dnssec).unwrap();
        let name = Name::from_ascii("reload.example.").unwrap();

        let response = upstream.lookup(&name, RecordType::A, None).await.unwrap();
        let first_stamp = response.generation.clone().unwrap();
        assert!(first_stamp.is_current());
        assert_eq!(
            response.records[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
        );

        let prepared = upstream
            .prepare(&second, &[], &client, &dnssec)
            .unwrap()
            .unwrap();
        upstream.install(prepared);
        assert!(!first_stamp.is_current());

        assert_eq!(
            upstream.status(),
            UpstreamStatusSnapshot {
                mode: UpstreamMode::Plain,
                primary_count: 1,
                servers: vec![(second_server.to_string(), UpstreamMode::Plain)],
            }
        );
        let response = upstream
            .lookup_domain("reload.example", &name, RecordType::A, None)
            .await
            .unwrap();
        assert!(response.generation.as_ref().unwrap().is_current());
        assert_eq!(
            response.records[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2)))
        );

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn rejected_generation_keeps_previous_resolver_active() {
        let (server, task) = spawn_upstream(Ipv4Addr::new(192, 0, 2, 3)).await;
        let active = config(server);
        let dnssec = DnssecConfig::default();
        let client = reqwest::Client::new();
        let upstream = ReloadableUpstream::from_config(&active, &[], &client, &dnssec).unwrap();
        let before = upstream.status();
        let mut invalid = active.clone();
        invalid.servers = vec!["not-a-socket-address".into()];

        assert!(upstream.prepare(&invalid, &[], &client, &dnssec).is_err());
        assert_eq!(upstream.status(), before);

        let name = Name::from_ascii("still-active.example.").unwrap();
        let response = upstream.lookup(&name, RecordType::A, None).await.unwrap();
        assert_eq!(
            response.records[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 3)))
        );
        task.abort();
    }

    #[test]
    fn forwarding_order_participates_in_equality() {
        let cfg = config("127.0.0.1:5301".parse().unwrap());
        let dnssec = DnssecConfig::default();
        let client = reqwest::Client::new();
        let zones = vec![
            ForwardingZoneConfig {
                suffix: "one.example".into(),
                mode: UpstreamMode::Plain,
                servers: vec!["127.0.0.1:5302".into()],
            },
            ForwardingZoneConfig {
                suffix: "two.example".into(),
                mode: UpstreamMode::Plain,
                servers: vec!["127.0.0.1:5303".into()],
            },
        ];
        let upstream = ReloadableUpstream::from_config(&cfg, &zones, &client, &dnssec).unwrap();
        let mut reordered = zones.clone();
        reordered.reverse();

        assert!(upstream
            .prepare(&cfg, &reordered, &client, &dnssec)
            .unwrap()
            .is_some());
    }

    #[test]
    fn status_preserves_primary_then_fallback_order() {
        let mut cfg = config("127.0.0.1:5301".parse().unwrap());
        cfg.servers.push("127.0.0.1:5302".into());
        cfg.fallback = Some(crate::config::settings::FallbackConfig {
            mode: UpstreamMode::Dot,
            servers: vec!["127.0.0.1:853".into(), "127.0.0.2:853".into()],
        });
        let upstream = ReloadableUpstream::from_config(
            &cfg,
            &[],
            &reqwest::Client::new(),
            &DnssecConfig::default(),
        )
        .unwrap();

        assert_eq!(
            upstream.status().servers,
            vec![
                ("127.0.0.1:5301".into(), UpstreamMode::Plain),
                ("127.0.0.1:5302".into(), UpstreamMode::Plain),
                ("127.0.0.1:853".into(), UpstreamMode::Dot),
                ("127.0.0.2:853".into(), UpstreamMode::Dot),
            ]
        );
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn dnssec_config_participates_in_equality() {
        let cfg = config("127.0.0.1:5301".parse().unwrap());
        let mut dnssec = DnssecConfig::default();
        dnssec.mode = DnssecMode::LogOnly;
        let client = reqwest::Client::new();
        let upstream = ReloadableUpstream::from_config(&cfg, &[], &client, &dnssec).unwrap();
        let first_generation = upstream.generation.load_full();
        let first_stamp = upstream.stamp(&first_generation);
        assert!(first_stamp.dnssec_validator().is_some());
        let mut changed = dnssec.clone();
        changed.max_queries += 1;

        let prepared = upstream
            .prepare(&cfg, &[], &client, &changed)
            .unwrap()
            .unwrap();
        let second_stamp = upstream.stamp(&prepared.generation);
        upstream.install(prepared);
        assert!(!first_stamp.is_current());
        assert!(first_stamp.dnssec_validator().is_some());
        assert!(second_stamp.is_current());
        assert!(second_stamp.dnssec_validator().is_some());
    }
}
