//! DNS server — UDP + TCP listener wrapping hickory-server's `Server`.
//!
//! Binds UDP and TCP sockets on the same address and delegates incoming queries
//! to the [`ForwardHandler`]. Shutdown is triggered externally via a oneshot
//! channel, allowing the caller to manage signal handling (SIGTERM, SIGHUP,
//! SIGUSR1) in a unified loop.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;

use super::handler::ForwardHandler;

/// UDP + TCP DNS server wrapping hickory-server's `Server`.
pub struct DnsServer {
    server_future: Server<ForwardHandler>,
}

impl DnsServer {
    /// Bind UDP and TCP sockets and prepare the server for incoming queries.
    ///
    /// `tcp_timeout` controls how long idle TCP connections are kept open
    /// before the server closes them.
    pub async fn new(
        handler: ForwardHandler,
        listen: SocketAddr,
        tcp_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let udp_socket = UdpSocket::bind(listen).await?;
        let tcp_listener = TcpListener::bind(listen).await?;
        tracing::info!(%listen, "DNS server listening (UDP + TCP)");

        let mut server_future = Server::new(handler);
        server_future.register_socket(udp_socket);
        // 0.26 added a required per-connection outgoing-response queue depth
        // (max messages buffered for sending before backpressure). 32 matches
        // hickory's own reference value; bounds per-connection memory (DoS
        // guard) and is irrelevant to normal single-response TCP queries.
        server_future.register_listener(tcp_listener, tcp_timeout, 32);

        Ok(Self { server_future })
    }

    /// Run the server until the shutdown receiver fires.
    ///
    /// The caller sends `()` on the oneshot to trigger graceful shutdown.
    /// This decouples signal handling from the server, letting `start.rs`
    /// own the full signal loop (SIGINT, SIGTERM, SIGHUP, SIGUSR1).
    pub async fn run(mut self, shutdown_rx: oneshot::Receiver<()>) -> anyhow::Result<()> {
        let token = self.server_future.shutdown_token().clone();

        tokio::spawn(async move {
            let _ = shutdown_rx.await;
            tracing::info!("shutdown signal received, stopping DNS server");
            token.cancel();
        });

        self.server_future.block_until_done().await?;
        Ok(())
    }
}
