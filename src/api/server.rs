//! REST API HTTP/HTTPS server.
//!
//! Spawns an axum server on the configured listen address.
//! Uses plain HTTP for loopback, TLS (via axum-server + rustls) for non-loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::settings::ApiConfig;

use super::routes::build_router;
use super::state::ApiState;

/// Spawn the API server as a background tokio task. Returns the JoinHandle.
///
/// Both branches bind before announcing: the returned handle is only ever
/// aborted at shutdown, never awaited, so a failure raised inside the spawned
/// task is indistinguishable from a live listener. Everything that can fail
/// must fail here, where the caller sees it.
pub async fn spawn_api_server(
    config: &ApiConfig,
    state: Arc<ApiState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let addr: SocketAddr = config.listen;

    let router = build_router(state, config.metrics_enabled);

    if let (Some(cert), Some(key)) = (config.tls_cert.as_ref(), config.tls_key.as_ref()) {
        // TLS mode
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

        // `from_tcp_rustls` hands the socket to tokio, which requires it
        // non-blocking.
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let server = axum_server::from_tcp_rustls(listener, tls_config)?;

        tracing::info!(%addr, tls = true, "REST API listening");

        let handle = tokio::spawn(async move {
            match server
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                Ok(()) => tracing::error!("API server stopped accepting connections"),
                Err(e) => tracing::error!(error = %e, "API server error"),
            }
        });
        Ok(handle)
    } else {
        // Plain HTTP. Loopback-only by validator rule: `check_api`
        // (API_NONLOOPBACK_REQUIRES_TLS) rejects a non-loopback
        // `api.listen` without the TLS pair before we ever get here.
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, tls = false, "REST API listening");

        let handle = tokio::spawn(async move {
            match axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                Ok(()) => tracing::error!("API server stopped accepting connections"),
                Err(e) => tracing::error!(error = %e, "API server error"),
            }
        });
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a throwaway self-signed pair and return `(cert_path, key_path)`.
    /// `RustlsConfig::from_pem_file` runs before the bind, so a TLS test that
    /// wants to reach the bind needs a pair that actually parses.
    fn self_signed_pair(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("purge-warden-api-{}-{tag}.crt", std::process::id()));
        let key_path = dir.join(format!("purge-warden-api-{}-{tag}.key", std::process::id()));
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        (cert_path, key_path)
    }

    fn api_config(
        listen: SocketAddr,
        tls: Option<(std::path::PathBuf, std::path::PathBuf)>,
    ) -> ApiConfig {
        let (tls_cert, tls_key) = match tls {
            Some((c, k)) => (Some(c), Some(k)),
            None => (None, None),
        };
        ApiConfig {
            enabled: true,
            listen,
            tls_cert,
            tls_key,
            ..Default::default()
        }
    }

    /// Bind a socket and keep it, so `addr` is genuinely occupied for the
    /// lifetime of the returned listener.
    fn occupied_addr() -> (std::net::TcpListener, SocketAddr) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let addr = l.local_addr().expect("probe addr");
        (l, addr)
    }

    /// The TLS branch must fail the same way the plain branch does when the
    /// address is taken. Before the eager bind it returned `Ok(handle)` and
    /// logged "REST API listening" with no listener behind it.
    #[tokio::test]
    async fn tls_bind_failure_reaches_the_caller() {
        crate::upstream::install_ring_crypto_provider_once();
        let (_holder, addr) = occupied_addr();
        let (cert, key) = self_signed_pair("tls-inuse");

        let state = crate::api::handlers::tests::test_state_with_stats();
        let err = spawn_api_server(&api_config(addr, Some((cert.clone(), key.clone()))), state)
            .await
            .expect_err("TLS bind on an occupied port must not report success");

        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        assert!(
            err.to_string().to_lowercase().contains("in use"),
            "expected an address-in-use error, got: {err}"
        );
    }

    /// The symmetry the TLS fix restores: both branches surface the identical
    /// failure, so a caller cannot tell them apart.
    #[tokio::test]
    async fn plain_bind_failure_reaches_the_caller() {
        let (_holder, addr) = occupied_addr();
        let state = crate::api::handlers::tests::test_state_with_stats();
        let err = spawn_api_server(&api_config(addr, None), state)
            .await
            .expect_err("plain bind on an occupied port must not report success");
        assert!(
            err.to_string().to_lowercase().contains("in use"),
            "expected an address-in-use error, got: {err}"
        );
    }
}
