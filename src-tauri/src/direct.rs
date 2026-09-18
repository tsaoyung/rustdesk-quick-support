// Direct-IP listener, mirroring RustDesk's `direct_server` in
// rendezvous_mediator.rs. A controller told to connect to a bare IP dials TCP
// 21118 by default (`RELAY_PORT + 1`) and then speaks a *plaintext* session —
// the official direct path is the only `create_tcp_connection` call in the whole
// project that passes `secure = false`, so there is no Secure handshake and no
// `SignedId`; the first frame is the login `Hash`. That is precisely why this
// module only needs to accept sockets and hand them over.
//
// Because that session is unencrypted, the listener is the most exposed surface
// this client has: `RUSTDESK_DIRECT_WHITELIST` (optional) restricts which source
// addresses may connect.
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
    log_whitelist_state();
    crate::set_direct_listening(true);

    loop {
        let (tcp, addr) = listener.accept().await?;

        // Source-address filtering — the counterpart of the official `whitelist`
        // setting, and the only guard on an otherwise plaintext session. An empty
        // whitelist (the default) keeps the old behaviour: anyone who can route to
        // the port gets through.
        if !config::direct_ip_allowed(addr.ip()) {
            warn!("direct access from {addr} rejected: source not in RUSTDESK_DIRECT_WHITELIST");
            // Close without reading a single byte, so the controller sees the
            // connection drop instead of a login prompt it can never pass.
            drop(tcp);
            continue;
        }

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

/// Report which source addresses will be accepted. Worth stating explicitly
/// because the default (no whitelist configured) is "anyone who can reach the
/// port", and an unconfigured guard should not have to be inferred from silence.
fn log_whitelist_state() {
    let list = config::direct_whitelist();
    if list.is_empty() {
        info!("direct IP whitelist: not configured — any source address may connect");
        return;
    }
    info!(
        "direct IP whitelist: {} entr{} ({})",
        list.len(),
        plural(list.len()),
        list.join(", ")
    );
    let bad = config::direct_whitelist_invalid();
    if !bad.is_empty() {
        warn!(
            "direct IP whitelist: ignoring {} unparsable entr{}: {}",
            bad.len(),
            plural(bad.len()),
            bad.join(", ")
        );
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        "y"
    } else {
        "ies"
    }
}
