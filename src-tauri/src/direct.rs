// Direct-IP listener, mirroring RustDesk's `direct_server` in
// rendezvous_mediator.rs. A controller told to connect to a bare IP dials TCP
// 21118 by default (`RELAY_PORT + 1`) and then speaks the *same* secure session
// as the relay path — no rendezvous signalling is involved. That is precisely
// why this module only needs to accept sockets and hand them over.
use crate::config;
use crate::connection;
use log::{error, info, warn};
use std::time::Duration;
use tokio::net::TcpListener;

/// Spawn the listener. No-op when direct access is switched off, so a build with
/// `RUSTDESK_DIRECT=N` keeps behaving exactly like the relay-only original.
pub fn spawn() {
    if !config::direct_enabled() {
        info!("direct IP access disabled (RUSTDESK_DIRECT != Y)");
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = run().await {
                error!("direct listener error: {e}");
            }
            // Port busy or a transient bind failure: back off and retry, the
            // same way the official implementation loops.
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

async fn run() -> anyhow::Result<()> {
    let port = config::direct_port();
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("direct server listening on 0.0.0.0:{port}");
    crate::set_direct_listening(true);

    loop {
        let (tcp, addr) = listener.accept().await?;
        // Matches the official direct server; interactive input latency benefits.
        let _ = tcp.set_nodelay(true);
        info!("direct access from {addr}");
        let cfg = config::load().clone();
        tokio::spawn(async move {
            if let Err(e) = connection::serve_direct(tcp, cfg, addr).await {
                warn!("direct session with {addr} ended: {e}");
            }
        });
    }
}
