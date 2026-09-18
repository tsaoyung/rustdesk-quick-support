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
        let port = config::direct_port();
        // Back off when the port is taken. A second instance of this app on the
        // same machine can never own the same port, and retrying every 3s just
        // floods the log without ever succeeding — so grow the interval and say
        // once per attempt what is actually wrong.
        let mut retry_secs = 3u64;
        loop {
            if let Err(e) = run().await {
                if is_addr_in_use(&e) {
                    crate::set_direct_listening(false);
                    warn!(
                        "direct port {port} is already in use (another instance of this app is \
                         probably running). Direct IP access is unavailable for this instance; \
                         the ID/relay path still works. Next retry in {retry_secs}s."
                    );
                    tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                    retry_secs = (retry_secs * 2).min(60);
                    continue;
                }
                retry_secs = 3;
                error!("direct listener error: {e}");
            }
            tokio::time::sleep(Duration::from_secs(retry_secs)).await;
        }
    });
}

/// True when the failure is "the port is already taken" rather than something
/// transient. `run()` returns `anyhow::Error`, so unwrap the io error first.
fn is_addr_in_use(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .map(|io| io.kind() == std::io::ErrorKind::AddrInUse)
        .unwrap_or(false)
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
