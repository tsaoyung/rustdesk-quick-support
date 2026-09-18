// Rendezvous mediator: registers the device with hbbs and listens on the same
// UDP socket for incoming connection attempts (PunchHole / RequestRelay /
// FetchLocalAddr), routing them all to the relay server for robust connectivity.
use crate::config::{self, DeviceConfig, RENDEZVOUS_PORT};
use crate::connection;
use crate::proto_gen::rendezvous::{
    register_pk_response::Result as PkResult, rendezvous_message::Union as ru, RelayResponse,
    RendezvousMessage,
};
use anyhow::Result;
use log::{error, info, warn};
use protobuf::Message as ProtoMessage;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

const RECV_BUF: usize = 2048;
const REG_INTERVAL_SECS: u64 = 12;

pub async fn run() {
    let cfg: &'static DeviceConfig = config::load();

    if let Err(e) = sodiumoxide::init() {
        warn!("sodiumoxide init: {:?}", e);
    }

    let (host, port) = config::split_host_port(&cfg.server, RENDEZVOUS_PORT);

    loop {
        // Resolve on every attempt so a transient DNS failure (or a server
        // change) can recover without restarting the app.
        match resolve(&host, port).await {
            Ok(server_addr) => {
                if let Err(e) = run_session(cfg, server_addr).await {
                    error!("rendezvous session error: {e}");
                }
            }
            Err(e) => error!("cannot resolve rendezvous server {host}:{port}: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Resolve `host:port` into a socket address.
///
/// `host` may be a literal IP *or* a domain name. A bare `SocketAddr::parse`
/// accepts only numeric addresses, so a hostname (e.g. the default
/// `rs-ny.rustdesk.com`) would fail and silently fall back to an unroutable
/// `0.0.0.0` — every registration datagram would then be dropped and the
/// device would never come online. Go through the system resolver instead; it
/// handles the literal-IP case too.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    let target = format!("{host}:{port}");
    // Collect eagerly: the lookup iterator borrows `target`, and returning it
    // directly would keep that borrow alive past the end of this block.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&target)
        .await
        .map_err(|e| anyhow::anyhow!("lookup {target}: {e}"))?
        .collect();
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address resolved for {target}"))
}

async fn run_session(cfg: &'static DeviceConfig, server_addr: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(server_addr).await?;
    info!("rendezvous UDP connected to {server_addr}");

    // Kick off registration, then keep re-registering + listening.
    register(&socket, cfg).await?;

    let mut last_reg = std::time::Instant::now();
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        tokio::select! {
            r = socket.recv(&mut buf) => {
                let n = r?;
                let msg = match RendezvousMessage::parse_from_bytes(&buf[..n]) {
                    Ok(m) => m,
                    Err(e) => { warn!("bad rendezvous msg: {e}"); continue; }
                };
                if let Err(e) = handle_msg(server_addr, cfg, msg).await {
                    warn!("handle rendezvous msg: {e}");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if last_reg.elapsed() >= Duration::from_secs(REG_INTERVAL_SECS) {
                    register(&socket, cfg).await.ok();
                    last_reg = std::time::Instant::now();
                }
            }
        }
    }
}

/// register_peer -> (request_pk?) -> register_pk -> result.
async fn register(socket: &UdpSocket, cfg: &DeviceConfig) -> Result<()> {
    send_msg(
        socket,
        register_peer_msg(&cfg.id, 0),
    )
    .await?;
    info!("RegisterPeer sent");

    let mut buf = vec![0u8; RECV_BUF];
    let mut request_pk = false;
    let mut got_response = false;
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
        if let Ok(resp) = RendezvousMessage::parse_from_bytes(&buf[..n]) {
            got_response = true;
            if let Some(ru::RegisterPeerResponse(r)) = resp.union {
                request_pk = r.request_pk;
            }
        }
    }

    if !got_response {
        warn!("no RegisterPeerResponse (timeout) - NOT registered with server");
        return Ok(());
    }

    if !request_pk {
        // Server accepted RegisterPeer and does not require pk registration;
        // the device is registered/online.
        info!("registered with rendezvous server");
        crate::set_server_online(true);
        return Ok(());
    }

    // RegisterPk with our Ed25519 public key + device uuid.
    send_msg(socket, register_pk_msg(&cfg.id, &cfg.sign_pk, &cfg.uuid)).await?;
    info!("RegisterPk sent");

    let mut buf2 = vec![0u8; RECV_BUF];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf2)).await {
        if let Ok(resp) = RendezvousMessage::parse_from_bytes(&buf2[..n]) {
            if let Some(ru::RegisterPkResponse(r)) = resp.union {
                match r.result.enum_value_or_default() {
                    PkResult::OK => {
                        info!("registered with rendezvous server (OK)");
                        crate::set_server_online(true);
                    }
                    PkResult::UUID_MISMATCH => warn!("UUID_MISMATCH: will re-register"),
                    other => {
                        info!("register_pk result: {:?}", other);
                        crate::set_server_online(true);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_msg(
    server_addr: SocketAddr,
    cfg: &'static DeviceConfig,
    msg: RendezvousMessage,
) -> Result<()> {
    match msg.union {
        // A controller is trying a direct connection -> fall back to relay.
        Some(ru::PunchHole(ph)) => {
            info!("PunchHole from controller, routing to relay");
            let relay_server = pick_relay(&ph.relay_server, cfg);
            let uuid = uuid::Uuid::new_v4().to_string();
            tokio::spawn(start_relay(
                cfg.clone(),
                server_addr,
                ph.socket_addr.clone(),
                relay_server,
                uuid,
                true,
            ));
        }
        // A controller explicitly wants the relay.
        Some(ru::RequestRelay(rr)) => {
            info!("RequestRelay from controller");
            let relay_server = pick_relay(&rr.relay_server, cfg);
            let uuid = if rr.uuid.is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                rr.uuid.clone()
            };
            tokio::spawn(start_relay(
                cfg.clone(),
                server_addr,
                rr.socket_addr.clone(),
                relay_server,
                uuid,
                false,
            ));
        }
        // Same-LAN probe -> also route to relay (keeps things simple & robust).
        Some(ru::FetchLocalAddr(fla)) => {
            info!("FetchLocalAddr from controller, routing to relay");
            let relay_server = pick_relay(&fla.relay_server, cfg);
            let uuid = uuid::Uuid::new_v4().to_string();
            tokio::spawn(start_relay(
                cfg.clone(),
                server_addr,
                fla.socket_addr.clone(),
                relay_server,
                uuid,
                true,
            ));
        }
        Some(ru::RegisterPkResponse(r)) => {
            // late register ack on the listening socket; ignore.
            info!("RegisterPkResponse on listener: {:?}", r.result.enum_value_or_default());
        }
        Some(ru::ConfigureUpdate(cu)) => {
            if !cu.rendezvous_servers.is_empty() {
                info!("server offered {} alt rendezvous servers", cu.rendezvous_servers.len());
            }
        }
        other => {
            let _ = other;
            info!("ignoring other rendezvous msg");
        }
    }
    Ok(())
}

/// Sends `RelayResponse` to hbbs (when initiate), then opens a relay TCP to
/// hbbr:21117 and runs the secure connection.
async fn start_relay(
    cfg: DeviceConfig,
    hbbs_addr: SocketAddr,
    peer_addr_bytes: bytes::Bytes,
    relay_server: String,
    uuid: String,
    initiate: bool,
) {
    if let Err(e) = run_relay(cfg, hbbs_addr, peer_addr_bytes, relay_server, uuid, initiate).await {
        error!("relay connection failed: {e}");
    }
}

async fn run_relay(
    cfg: DeviceConfig,
    hbbs_addr: SocketAddr,
    peer_addr_bytes: bytes::Bytes,
    relay_server: String,
    uuid: String,
    initiate: bool,
) -> Result<()> {
    // 1) Tell hbbs we accept relay (so it can forward to the controller).
    if initiate {
        let tcp = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::net::TcpStream::connect(hbbs_addr),
        )
        .await??;
        let mut halves = crate::codec::PeerHalves::from_tcp(tcp, hbbs_addr);
        let mut rr = RelayResponse::new();
        // socket_addr (the controller's mangled addr) is what hbbs uses to route
        // this response back to the controller; without it the relay never forms.
        rr.socket_addr = peer_addr_bytes.clone();
        rr.uuid = uuid.clone();
        rr.relay_server = relay_server.clone();
        rr.set_id(cfg.id.clone());
        // CRITICAL: hbbs only injects the signed pk (get_pk) when version is
        // non-empty; otherwise the controller gets an empty pk, the secure
        // handshake fails, and the controller closes the connection.
        rr.version = format!("qsp-{}", env!("CARGO_PKG_VERSION"));
        let mut msg = RendezvousMessage::new();
        msg.set_relay_response(rr);
        halves.writer.send_msg(&msg).await?;
        info!("RelayResponse sent to hbbs (uuid={uuid})");
    }

    // 2) Connect to the relay server (hbbr, default 21117) and run the session.
    let (rhost, rport) = config::split_host_port(&relay_server, config::RELAY_PORT);
    let relay_addr: SocketAddr = resolve(&rhost, rport).await?;
    info!("connecting to relay server {relay_addr} (uuid={uuid})");
    let tcp = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect(relay_addr),
    )
    .await??;

    // 3) RequestRelay + secure handshake + login + media (serve_relay handles
    //    RequestRelay internally on the split read/write halves).
    connection::serve_relay(tcp, cfg, uuid, relay_addr).await
}

fn pick_relay(field: &str, cfg: &DeviceConfig) -> String {
    if !field.is_empty() {
        return field.to_string();
    }
    // Default the relay host to the rendezvous server host.
    let (h, _) = config::split_host_port(&cfg.server, RENDEZVOUS_PORT);
    h
}

async fn send_msg(socket: &UdpSocket, msg: RendezvousMessage) -> Result<()> {
    // hbbs rendezvous speaks RAW protobuf over UDP (one datagram = one message);
    // the BytesCodec length-framing is only used on TCP.
    let bytes = msg.write_to_bytes()?;
    socket.send(&bytes).await?;
    Ok(())
}

fn register_peer_msg(id: &str, serial: i32) -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    let mut rp = crate::proto_gen::rendezvous::RegisterPeer::new();
    rp.id = id.to_string();
    rp.serial = serial;
    m.set_register_peer(rp);
    m
}

fn register_pk_msg(id: &str, pk: &[u8], uuid: &[u8]) -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    let mut rpk = crate::proto_gen::rendezvous::RegisterPk::new();
    rpk.id = id.to_string();
    rpk.uuid = bytes::Bytes::from(uuid.to_vec());
    rpk.pk = bytes::Bytes::from(pk.to_vec());
    m.set_register_pk(rpk);
    m
}
