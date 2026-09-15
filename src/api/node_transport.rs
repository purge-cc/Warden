//! Dynamic HTTPS listeners for the Nodes control plane.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock};

use anyhow::{ensure, Context};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Router};
use tokio::task::JoinHandle;

use crate::cluster::node_control::{ListenerScope, NodeListenerControl, NodeListenerSpec};
use crate::config::settings::ApiConfig;

#[derive(Clone, PartialEq, Eq)]
struct TlsMaterial {
    certificate: Arc<[u8]>,
    private_key: Arc<[u8]>,
}

impl TlsMaterial {
    fn from_node(spec: &NodeListenerSpec) -> Self {
        Self {
            certificate: Arc::from(spec.certificate_pem.as_bytes()),
            private_key: Arc::from(spec.private_key_pem.0.as_bytes()),
        }
    }

    fn from_api(config: &ApiConfig) -> anyhow::Result<Option<Self>> {
        match (&config.tls_cert, &config.tls_key) {
            (Some(certificate), Some(private_key)) => Ok(Some(Self {
                certificate: Arc::from(std::fs::read(certificate).with_context(|| {
                    format!("failed to read API certificate {}", certificate.display())
                })?),
                private_key: Arc::from(std::fs::read(private_key).with_context(|| {
                    format!("failed to read API private key {}", private_key.display())
                })?),
            })),
            (None, None) => Ok(None),
            _ => anyhow::bail!("API TLS requires both certificate and private key"),
        }
    }
}

struct ApiBinding {
    endpoint: SocketAddr,
    tls: Option<TlsMaterial>,
}

#[derive(Default)]
struct NodeGate {
    scope: RwLock<Option<ListenerScope>>,
}

impl NodeGate {
    fn set(&self, scope: Option<ListenerScope>) {
        *self
            .scope
            .write()
            .unwrap_or_else(|error| error.into_inner()) = scope;
    }

    fn enabled(&self) -> bool {
        self.scope
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }
}

struct Listener {
    tls: Option<TlsMaterial>,
    api: bool,
    node_gate: Arc<NodeGate>,
    handle: JoinHandle<()>,
}

/// Owns API and Nodes listeners so compatible logical endpoints share a socket.
pub struct NodeTransport {
    api: Option<ApiBinding>,
    api_router: OnceLock<Router>,
    node_router: OnceLock<Router>,
    replication_router: OnceLock<Router>,
    listeners: tokio::sync::Mutex<BTreeMap<SocketAddr, Listener>>,
}

impl NodeTransport {
    pub fn new(api: Option<&ApiConfig>) -> anyhow::Result<Arc<Self>> {
        let api = api
            .filter(|config| config.enabled)
            .map(|config| -> anyhow::Result<ApiBinding> {
                Ok(ApiBinding {
                    endpoint: config.listen,
                    tls: TlsMaterial::from_api(config)?,
                })
            })
            .transpose()?;
        Ok(Arc::new(Self {
            api,
            api_router: OnceLock::new(),
            node_router: OnceLock::new(),
            replication_router: OnceLock::new(),
            listeners: tokio::sync::Mutex::new(BTreeMap::new()),
        }))
    }

    pub fn install_api_router(&self, router: Router) -> anyhow::Result<()> {
        self.api_router
            .set(router)
            .map_err(|_| anyhow::anyhow!("API router is already installed"))
    }

    pub fn install_node_router(&self, router: Router) -> anyhow::Result<()> {
        self.node_router
            .set(router)
            .map_err(|_| anyhow::anyhow!("Nodes router is already installed"))
    }

    pub fn install_replication_router(&self, router: Router) -> anyhow::Result<()> {
        self.replication_router
            .set(router)
            .map_err(|_| anyhow::anyhow!("replication router is already installed"))
    }

    /// Bind the configured administrative API endpoint with Nodes routes gated off.
    pub async fn start_api(&self) -> anyhow::Result<()> {
        let Some(api) = &self.api else {
            return Ok(());
        };
        let api_router = self
            .api_router
            .get()
            .context("API router is not installed")?
            .clone();
        let node_router = self
            .node_router
            .get()
            .context("Nodes router is not installed")?
            .clone();
        let gate = Arc::new(NodeGate::default());
        let router = api_router.merge(gated_nodes(node_router, Arc::clone(&gate)));
        let handle = spawn_router(api.endpoint, api.tls.clone(), router, "REST API").await?;
        let replaced = self.listeners.lock().await.insert(
            api.endpoint,
            Listener {
                tls: api.tls.clone(),
                api: true,
                node_gate: gate,
                handle,
            },
        );
        ensure!(replaced.is_none(), "API endpoint was bound twice");
        Ok(())
    }

    /// Stop every listener after request-producing controllers have retired.
    pub async fn shutdown(&self) {
        let mut guard = self.listeners.lock().await;
        let listeners = std::mem::take(&mut *guard);
        drop(guard);
        for (_, listener) in listeners {
            listener.handle.abort();
            let _ = listener.handle.await;
        }
    }

    #[cfg(test)]
    async fn listener_view(&self, endpoint: SocketAddr) -> Option<(bool, bool)> {
        self.listeners
            .lock()
            .await
            .get(&endpoint)
            .map(|listener| (listener.api, listener.node_gate.enabled()))
    }
}

#[async_trait]
impl NodeListenerControl for NodeTransport {
    async fn existing_material(
        &self,
        endpoint: SocketAddr,
    ) -> anyhow::Result<Option<NodeListenerSpec>> {
        let Some(api) = self.api.as_ref().filter(|api| api.endpoint == endpoint) else {
            return Ok(None);
        };
        let Some(tls) = &api.tls else {
            return Ok(None);
        };
        let certificate_pem = std::str::from_utf8(&tls.certificate)
            .context("configured API certificate is not UTF-8 PEM")?
            .to_owned();
        let private_key_pem = std::str::from_utf8(&tls.private_key)
            .context("configured API private key is not UTF-8 PEM")?
            .to_owned();
        Ok(Some(NodeListenerSpec {
            endpoint,
            certificate_pem,
            private_key_pem: crate::cluster::membership::SecretString(private_key_pem),
            scope: ListenerScope::Management,
        }))
    }

    async fn prepare(&self, spec: NodeListenerSpec) -> anyhow::Result<()> {
        let tls = Some(TlsMaterial::from_node(&spec));
        let mut listeners = self.listeners.lock().await;
        if let Some(listener) = listeners.get(&spec.endpoint) {
            ensure!(
                listener.tls == tls,
                "Nodes endpoint {} conflicts with a listener using different TLS material",
                spec.endpoint
            );
            listener.node_gate.set(Some(spec.scope));
            return Ok(());
        }

        let mut node_router = self
            .node_router
            .get()
            .context("Nodes router is not installed")?
            .clone();
        if let Some(replication) = self.replication_router.get() {
            node_router = node_router.merge(replication.clone());
        }
        let gate = Arc::new(NodeGate::default());
        gate.set(Some(spec.scope));
        let handle = spawn_router(
            spec.endpoint,
            tls.clone(),
            gated_nodes(node_router, Arc::clone(&gate)),
            "Nodes HTTPS",
        )
        .await?;
        listeners.insert(
            spec.endpoint,
            Listener {
                tls,
                api: false,
                node_gate: gate,
                handle,
            },
        );
        Ok(())
    }

    async fn retire(&self, endpoint: SocketAddr) -> anyhow::Result<()> {
        let mut listeners = self.listeners.lock().await;
        if listeners
            .get(&endpoint)
            .is_some_and(|listener| listener.api)
        {
            if let Some(listener) = listeners.get(&endpoint) {
                listener.node_gate.set(None);
            }
            return Ok(());
        }
        let listener = listeners.remove(&endpoint);
        drop(listeners);
        if let Some(listener) = listener {
            listener.handle.abort();
            let _ = listener.handle.await;
        }
        Ok(())
    }
}

fn gated_nodes(router: Router, gate: Arc<NodeGate>) -> Router {
    router.layer(middleware::from_fn_with_state(gate, node_gate))
}

async fn node_gate(
    State(gate): State<Arc<NodeGate>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if gate.enabled() {
        next.run(request).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn spawn_router(
    endpoint: SocketAddr,
    tls: Option<TlsMaterial>,
    router: Router,
    label: &'static str,
) -> anyhow::Result<JoinHandle<()>> {
    let handle = if let Some(tls) = tls {
        crate::upstream::install_ring_crypto_provider_once();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            tls.certificate.to_vec(),
            tls.private_key.to_vec(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to load TLS config: {error}"))?;
        let listener = std::net::TcpListener::bind(endpoint)?;
        listener.set_nonblocking(true)?;
        let server = axum_server::from_tcp_rustls(listener, config)?;
        tracing::info!(%endpoint, tls = true, service = label, "HTTPS listener ready");
        tokio::spawn(async move {
            match server
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                Ok(()) => tracing::error!(%endpoint, service = label, "listener stopped"),
                Err(error) => {
                    tracing::error!(%endpoint, service = label, %error, "listener failed")
                }
            }
        })
    } else {
        let listener = tokio::net::TcpListener::bind(endpoint).await?;
        tracing::info!(%endpoint, tls = false, service = label, "HTTP listener ready");
        tokio::spawn(async move {
            match axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                Ok(()) => tracing::error!(%endpoint, service = label, "listener stopped"),
                Err(error) => {
                    tracing::error!(%endpoint, service = label, %error, "listener failed")
                }
            }
        })
    };
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    fn node_spec(endpoint: SocketAddr, tag: &str) -> NodeListenerSpec {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        NodeListenerSpec {
            endpoint,
            certificate_pem: certificate.cert.pem(),
            private_key_pem: crate::cluster::membership::SecretString(
                certificate.key_pair.serialize_pem(),
            ),
            scope: if tag == "bootstrap" {
                ListenerScope::Bootstrap
            } else {
                ListenerScope::Management
            },
        }
    }

    fn free_endpoint() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        endpoint
    }

    #[tokio::test]
    async fn node_only_listener_can_be_prepared_and_retired() {
        let endpoint = free_endpoint();
        let transport = NodeTransport::new(None).unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        transport
            .prepare(node_spec(endpoint, "bootstrap"))
            .await
            .unwrap();
        assert_eq!(transport.listener_view(endpoint).await, Some((false, true)));
        transport.retire(endpoint).await.unwrap();
        assert_eq!(transport.listener_view(endpoint).await, None);
    }

    #[tokio::test]
    async fn dual_nodes_listeners_remain_independently_retirable() {
        let old_endpoint = free_endpoint();
        let new_endpoint = free_endpoint();
        let transport = NodeTransport::new(None).unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        transport
            .prepare(node_spec(old_endpoint, "management"))
            .await
            .unwrap();
        transport
            .prepare(node_spec(new_endpoint, "management"))
            .await
            .unwrap();

        transport.retire(old_endpoint).await.unwrap();
        assert_eq!(transport.listener_view(old_endpoint).await, None);
        assert_eq!(
            transport.listener_view(new_endpoint).await,
            Some((false, true))
        );
        tokio::net::TcpStream::connect(new_endpoint)
            .await
            .expect("new Nodes socket must remain bound");
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn occupied_endpoint_is_an_explicit_error() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = occupied.local_addr().unwrap();
        let transport = NodeTransport::new(None).unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        let error = transport
            .prepare(node_spec(endpoint, "bootstrap"))
            .await
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::AddrInUse)
        );
        assert_eq!(transport.listener_view(endpoint).await, None);
    }

    #[tokio::test]
    async fn same_endpoint_with_different_tls_is_refused() {
        let endpoint = free_endpoint();
        let transport = NodeTransport::new(None).unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        transport
            .prepare(node_spec(endpoint, "bootstrap"))
            .await
            .unwrap();
        let error = transport
            .prepare(node_spec(endpoint, "management"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different TLS material"));
        assert_eq!(transport.listener_view(endpoint).await, Some((false, true)));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn incompatible_nodes_tls_does_not_mutate_shared_api() {
        let endpoint = free_endpoint();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("api.crt");
        let private_key_path = directory.path().join("api.key");
        std::fs::write(&certificate_path, certificate.cert.pem()).unwrap();
        std::fs::write(&private_key_path, certificate.key_pair.serialize_pem()).unwrap();
        let api = ApiConfig {
            enabled: true,
            listen: endpoint,
            tls_cert: Some(certificate_path),
            tls_key: Some(private_key_path),
            ..Default::default()
        };
        let transport = NodeTransport::new(Some(&api)).unwrap();
        transport
            .install_api_router(Router::new().route("/api", get(|| async {})))
            .unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        transport.start_api().await.unwrap();

        let error = transport
            .prepare(node_spec(endpoint, "management"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different TLS material"));
        assert_eq!(transport.listener_view(endpoint).await, Some((true, false)));
        tokio::net::TcpStream::connect(endpoint)
            .await
            .expect("API socket must remain bound");
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn retiring_shared_nodes_routes_preserves_api_listener() {
        let endpoint = free_endpoint();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("api.crt");
        let private_key_path = directory.path().join("api.key");
        let certificate_pem = certificate.cert.pem();
        let private_key_pem = certificate.key_pair.serialize_pem();
        std::fs::write(&certificate_path, &certificate_pem).unwrap();
        std::fs::write(&private_key_path, &private_key_pem).unwrap();
        let api = ApiConfig {
            enabled: true,
            listen: endpoint,
            tls_cert: Some(certificate_path),
            tls_key: Some(private_key_path),
            ..Default::default()
        };
        let transport = NodeTransport::new(Some(&api)).unwrap();
        transport
            .install_api_router(Router::new().route("/api", get(|| async {})))
            .unwrap();
        transport
            .install_node_router(Router::new().route("/nodes", get(|| async {})))
            .unwrap();
        transport.start_api().await.unwrap();
        assert_eq!(transport.listener_view(endpoint).await, Some((true, false)));

        transport
            .prepare(NodeListenerSpec {
                endpoint,
                certificate_pem,
                private_key_pem: crate::cluster::membership::SecretString(private_key_pem),
                scope: ListenerScope::Management,
            })
            .await
            .unwrap();
        assert_eq!(transport.listener_view(endpoint).await, Some((true, true)));
        transport.retire(endpoint).await.unwrap();
        assert_eq!(transport.listener_view(endpoint).await, Some((true, false)));
        tokio::net::TcpStream::connect(endpoint)
            .await
            .expect("API socket must remain bound");
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn configured_api_material_is_reused_only_at_its_endpoint() {
        let endpoint = free_endpoint();
        let other_endpoint = free_endpoint();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("api.crt");
        let private_key_path = directory.path().join("api.key");
        let certificate_pem = certificate.cert.pem();
        let private_key_pem = certificate.key_pair.serialize_pem();
        std::fs::write(&certificate_path, &certificate_pem).unwrap();
        std::fs::write(&private_key_path, &private_key_pem).unwrap();
        let api = ApiConfig {
            enabled: true,
            listen: endpoint,
            tls_cert: Some(certificate_path),
            tls_key: Some(private_key_path),
            ..Default::default()
        };
        let transport = NodeTransport::new(Some(&api)).unwrap();

        let material = transport
            .existing_material(endpoint)
            .await
            .unwrap()
            .expect("matching API material");
        assert_eq!(material.endpoint, endpoint);
        assert_eq!(material.certificate_pem, certificate_pem);
        assert_eq!(material.private_key_pem.0, private_key_pem);
        assert!(transport
            .existing_material(other_endpoint)
            .await
            .unwrap()
            .is_none());
    }
}
