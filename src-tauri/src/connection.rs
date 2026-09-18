// Connection handler: secure handshake, login, then a reader loop (input +
// control) that runs concurrently with a writer task (video + responses), so
// slow video writes can never starve incoming input or TestDelay pings.
use crate::codec::{Encrypt, PeerHalves, Reader, Writer};
use crate::config::DeviceConfig;
use crate::fs;
use crate::input;
use crate::proto_gen::message::{
    self, file_action::Union as fau, file_response::Union as fru, login_request::Union as lu,
    message::Union as mu, EncodedVideoFrame, EncodedVideoFrames, FileAction, FileResponse, Hash,
    IdPk, KeyEvent, LoginResponse, Message, MouseEvent, PeerInfo, SignedId, SupportedEncoding,
    TestDelay, VideoFrame,
};
use crate::proto_gen::rendezvous::{RequestRelay, RendezvousMessage};
use crate::video;
use anyhow::{bail, Result};
use log::{info, warn};
use protobuf::Message as ProtoMessage;
use rand::Rng;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{box_, sign};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

enum InputMsg {
    Mouse(MouseEvent),
    Key(KeyEvent),
}

/// Relay entry point. hbbr requires a `RequestRelay` envelope before any
/// controller traffic can flow, so send that first and then hand both halves to
/// the shared session body — which is byte-identical to what a direct (IP)
/// connection runs after `accept()`.
pub async fn serve_relay(tcp: TcpStream, cfg: DeviceConfig, uuid: String, peer_addr: SocketAddr) -> Result<()> {
    info!("new relay connection from {peer_addr}");
    let PeerHalves {
        reader,
        mut writer,
        peer_addr: _,
    } = PeerHalves::from_tcp(tcp, peer_addr);

    // First framed message on the relay connection: RequestRelay.
    let mut req = RequestRelay::new();
    req.licence_key = cfg.licence_key.clone();
    req.uuid = uuid.clone();
    let mut m = RendezvousMessage::new();
    m.set_request_relay(req);
    writer.send_msg(&m).await?;

    serve_session(reader, writer, cfg, peer_addr).await
}

/// Direct-IP entry point (RustDesk's "allow direct IP access"). Here the peer is
/// the controller itself rather than hbbr, so there is no relay envelope to
/// send: the accepted socket goes straight into the same secure session.
pub async fn serve_direct(tcp: TcpStream, cfg: DeviceConfig, peer_addr: SocketAddr) -> Result<()> {
    info!("new direct connection from {peer_addr}");
    let PeerHalves {
        reader,
        writer,
        peer_addr: _,
    } = PeerHalves::from_tcp(tcp, peer_addr);

    serve_session(reader, writer, cfg, peer_addr).await
}

/// Shared session body: secure handshake -> Hash -> reader/writer loop.
/// Reached from both `serve_relay` and `serve_direct`; nothing below this point
/// knows how the socket was obtained.
async fn serve_session(
    mut reader: Reader,
    mut writer: Writer,
    cfg: DeviceConfig,
    peer_addr: SocketAddr,
) -> Result<()> {
    // --- Secure handshake ---
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let mut idpk = IdPk::new();
    idpk.id = cfg.id.clone();
    idpk.pk = bytes::Bytes::copy_from_slice(&our_pk_b.0);
    let idpk_bytes = idpk.write_to_bytes()?;

    let mut sign_sk_arr = [0u8; sign::SECRETKEYBYTES];
    sign_sk_arr.copy_from_slice(&cfg.sign_sk);
    let sign_sk = sign::SecretKey(sign_sk_arr);
    let signed = sign::sign(&idpk_bytes, &sign_sk);

    let mut sid = SignedId::new();
    sid.id = bytes::Bytes::from(signed);
    let mut msg = Message::new();
    msg.set_signed_id(sid);
    writer.send_msg(&msg).await?;

    let bytes = match reader.next_msg().await {
        Some(Ok(b)) if !b.is_empty() => b,
        Some(Ok(_)) => bail!("handshake: empty frame"),
        Some(Err(e)) => bail!("handshake read error: {e}"),
        None => bail!("handshake: peer closed before PublicKey"),
    };
    let msg_in = Message::parse_from_bytes(&bytes)?;
    let pk = match msg_in.union {
        Some(mu::PublicKey(pk)) => pk,
        _ => bail!("expected PublicKey"),
    };
    let session_key = Encrypt::open_session_key(&pk.symmetric_value, &pk.asymmetric_value, &our_sk_b)?;
    writer.set_key(session_key.clone());
    reader.set_key(session_key);
    info!("secure stream established with {peer_addr}");

    // --- Send Hash (salt + challenge) ---
    // The salt is the PERMANENT device salt (stable across connections) so that
    // a controller using a remembered password — stored as SHA256(plain+salt) —
    // keeps validating. The challenge rotates per connection for freshness.
    let salt = cfg.password_salt.clone();
    let challenge = random_alnum(6);
    let mut hash = Hash::new();
    hash.salt = salt.clone();
    hash.challenge = challenge.clone();
    let mut hm = Message::new();
    hm.set_hash(hash);
    writer.send_msg(&hm).await?;

    // --- Outgoing channels + writer task ---
    // Two channels feed the single writer:
    //   * `out_tx` (unbounded): immediate control messages (login response,
    //     TestDelay, video frames, dir listings, transfer confirmations).
    //   * `ft_tx`  (bounded):   bulk file-transfer BLOCKS from read jobs, so a
    //     slow network backpressures the pump instead of buffering a whole file
    //     in memory. Ordering is preserved within each channel; the two never
    //     interleave for the same job (blocks + their Digest/Done all go via
    //     `ft_tx`, everything else via `out_tx`).
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let (ft_tx, mut ft_rx) = mpsc::channel::<Message>(16);
    let mut writer = writer;
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = out_rx.recv() => match msg {
                    Some(m) => {
                        if let Err(e) = writer.send_msg(&m).await {
                            warn!("writer send failed: {e}");
                            break;
                        }
                    }
                    None => break,
                },
                msg = ft_rx.recv() => match msg {
                    Some(m) => {
                        if let Err(e) = writer.send_msg(&m).await {
                            warn!("writer send failed: {e}");
                            break;
                        }
                    }
                    None => {}
                },
            }
        }
    });

    // --- Input thread (enigo calls are blocking; keep them off the async loop) ---
    let (in_tx, in_rx) = std_mpsc::sync_channel::<InputMsg>(128);
    std::thread::spawn(move || {
        for m in in_rx {
            match m {
                InputMsg::Mouse(e) => input::handle_mouse(&e),
                InputMsg::Key(e) => input::handle_key(&e),
            }
        }
    });

    // --- Video subscriber ---
    let (vtx, mut vrx) = mpsc::channel::<video::EncodedFrame>(5);
    let mut video_started = false;

    // --- File transfer state ---
    // `read_jobs` pump files to the peer (downloads); `write_jobs` receive
    // uploads. The read pump ticks every 1ms so outbound blocks flow even while
    // the reader branch is idle (the usual case during a download).
    let mut read_jobs: Vec<fs::TransferJob> = Vec::new();
    let mut write_jobs: Vec<fs::TransferJob> = Vec::new();
    let mut read_pump = tokio::time::interval(std::time::Duration::from_millis(1));
    read_pump.reset();

    crate::set_file_transfer(false, String::new());

    // --- Reader loop: incoming messages + video frames ---
    loop {
        tokio::select! {
            biased; // prioritize incoming input/pings over video
            r = reader.next_msg() => {
                match r {
                    Some(Ok(b)) => {
                        let m = match Message::parse_from_bytes(&b) {
                            Ok(m) => m,
                            Err(e) => { warn!("parse msg: {e}"); continue; }
                        };
                        match m.union {
                            Some(mu::LoginRequest(lr)) => {
                                // A dedicated file-transfer session carries the
                                // initial directory the controller wants to list.
                                let ft = match &lr.union {
                                    Some(lu::FileTransfer(ft)) => {
                                        Some((ft.dir.clone(), ft.show_hidden))
                                    }
                                    _ => None,
                                };
                                if verify_login(&cfg, &salt, &challenge, &lr.password) {
                                    info!("controller logged in: {}", lr.my_name);
                                    crate::set_peer_connected(true, Some(lr.my_name.clone()));
                                    let _ = out_tx.send(login_ok_msg(&cfg));
                                    if let Some((dir, show_hidden)) = ft {
                                        // File-transfer session: reply with the initial
                                        // directory listing (home dir when the controller
                                        // gave none or an invalid path) so the file manager
                                        // shows content immediately. Mirrors hbb_common's
                                        // read_dir fallback.
                                        let dir = if !dir.is_empty() && Path::new(&dir).is_dir() {
                                            dir.as_str()
                                        } else {
                                            ""
                                        };
                                        send_dir_listing(dir, show_hidden, &out_tx);
                                    } else if !video_started {
                                        video_started = true;
                                        video::set_subscriber(vtx.clone());
                                    }
                                } else if lr.password.is_empty() {
                                    info!("empty password -> prompting controller");
                                    let _ = out_tx.send(login_err_msg("Empty Password"));
                                } else {
                                    warn!("login rejected (bad password)");
                                    let _ = out_tx.send(login_err_msg("Wrong Password"));
                                }
                            }
                            Some(mu::MouseEvent(me)) => { let _ = in_tx.send(InputMsg::Mouse(me)); }
                            Some(mu::KeyEvent(ke)) => { let _ = in_tx.send(InputMsg::Key(ke)); }
                            Some(mu::TestDelay(td)) => {
                                let mut out = TestDelay::new();
                                out.from_client = false;
                                out.last_delay = td.last_delay;
                                let mut o = Message::new();
                                o.set_test_delay(out);
                                let _ = out_tx.send(o);
                            }
                            Some(mu::Misc(misc)) => {
                                if misc.has_close_reason() {
                                    info!("controller closed connection");
                                    break;
                                }
                            }
                            Some(mu::FileAction(fa)) => {
                                handle_file_action(fa, &mut read_jobs, &mut write_jobs, &out_tx)
                                    .await;
                                update_transfer_status(&read_jobs, &write_jobs);
                            }
                            Some(mu::FileResponse(fr)) => {
                                handle_file_response(fr, &mut write_jobs, &out_tx).await;
                                update_transfer_status(&read_jobs, &write_jobs);
                            }
                            Some(other) => {
                                warn!("unhandled message: {:?}", other);
                            }
                            None => {}
                        }
                    }
                    Some(Err(e)) => { warn!("stream read error: {e}"); break; }
                    None => { info!("controller disconnected"); break; }
                }
            }
            f = vrx.recv() => {
                if let Some(frame) = f {
                    let _ = out_tx.send(video_frame_msg(frame));
                }
            }
            _ = read_pump.tick() => {
                if !read_jobs.is_empty() {
                    pump_read_jobs(&mut read_jobs, &ft_tx).await;
                    update_transfer_status(&read_jobs, &write_jobs);
                }
            }
        }
    }

    crate::set_peer_connected(false, None);
    crate::set_file_transfer(false, String::new());
    video::clear_subscriber();
    writer_task.abort();
    Ok(())
}

// ---------------------------------------------------------------------------
// file transfer glue
// ---------------------------------------------------------------------------

/// Drive every active read (download) job by one step: send the next digest /
/// block / done message. Done jobs are evicted. Outbound goes through the
/// bounded `ft_tx` (slow-network backpressure); when it's full the unsent
/// block is re-buffered onto the job and we yield so the reader branch can
/// still process e.g. an incoming Cancel.
async fn pump_read_jobs(jobs: &mut Vec<fs::TransferJob>, ft_tx: &mpsc::Sender<Message>) {
    let mut finished = Vec::new();
    let mut channel_full = false;
    for idx in 0..jobs.len() {
        loop {
            let msg = match jobs[idx].next_read_outbound().await {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) => {
                    let (id, file_num) = (jobs[idx].id, jobs[idx].file_num);
                    warn!("read job {id}: {e}");
                    finished.push(id);
                    let _ = ft_tx.try_send(fs::new_error_msg(id, e, file_num));
                    break;
                }
            };
            match ft_tx.try_send(msg) {
                Ok(()) => {
                    if jobs[idx].is_done() && jobs[idx].pending.is_none() {
                        finished.push(jobs[idx].id);
                        break;
                    }
                }
                Err(mpsc::error::TrySendError::Full(m)) => {
                    // Re-buffer; yield this tick so the reader stays responsive.
                    jobs[idx].pending = Some(m);
                    channel_full = true;
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!("file-transfer writer gone");
                    return;
                }
            }
        }
        if channel_full {
            break;
        }
    }
    for id in finished {
        fs::remove_job(id, jobs);
    }
}

/// Read a directory and send the listing back as a `FileResponse::Dir` with
/// `id = 0` (the id used for browsing, since `ReadDir` carries no id). An empty
/// path falls back to the user's home directory, matching hbb_common's
/// `read_dir`. Note: no `is_dir` pre-check here, so a Windows `/` reaches
/// `fs::read_dir` which lists the drives.
fn send_dir_listing(dir: &str, include_hidden: bool, out_tx: &mpsc::UnboundedSender<Message>) {
    let path = if dir.is_empty() {
        dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/"))
    } else {
        fs::get_path(dir)
    };
    match fs::read_dir(&path, include_hidden) {
        Ok(fd) => {
            let _ = out_tx.send(fs::new_dir_msg(0, fd.path, fd.entries.into()));
        }
        Err(e) => {
            warn!("read_dir({}): {e}", path.display());
            let _ = out_tx.send(fs::new_error_msg(0, e, 0));
        }
    }
}

async fn handle_file_action(
    fa: FileAction,
    read_jobs: &mut Vec<fs::TransferJob>,
    write_jobs: &mut Vec<fs::TransferJob>,
    out_tx: &mpsc::UnboundedSender<Message>,
) {
    // Overwrite-detection digest handshake is intentionally disabled: we report
    // a pre-1.1.10 version (CARGO_PKG_VERSION), so the official controller also
    // skips it, guaranteeing the two sides agree and there is never a deadlock
    // waiting for a digest/confirm that the other side won't send.
    let od = false;
    match fa.union {
        Some(fau::ReadDir(rd)) => {
            send_dir_listing(&rd.path, rd.include_hidden, out_tx);
        }
        Some(fau::AllFiles(f)) => match fs::get_recursive_files(&f.path, f.include_hidden) {
            Ok(files) => {
                let _ = out_tx.send(fs::new_dir_msg(f.id, f.path, files));
            }
            Err(e) => {
                let _ = out_tx.send(fs::new_error_msg(f.id, e, -1));
            }
        },
        // Controller wants to download from us -> we read local files.
        Some(fau::Send(s)) => {
            let base = fs::get_path(&s.path);
            let files = match fs::get_recursive_files(&s.path, s.include_hidden) {
                Ok(v) => v,
                Err(e) => {
                    let _ = out_tx.send(fs::new_error_msg(s.id, e, -1));
                    return;
                }
            };
            if files.is_empty() {
                let _ = out_tx.send(fs::new_error_msg(s.id, "no files", -1));
                return;
            }
            let job = fs::TransferJob::new_read(s.id, s.path, base, files, od);
            read_jobs.push(job);
        }
        // Controller wants to upload to us -> we write local files.
        Some(fau::Receive(r)) => {
            let base = fs::get_path(&r.path);
            match fs::TransferJob::new_write(r.id, r.path, base, r.files.to_vec(), od) {
                Ok(job) => write_jobs.push(job),
                Err(e) => {
                    let _ = out_tx.send(fs::new_error_msg(r.id, e, r.file_num));
                }
            }
        }
        Some(fau::SendConfirm(sc)) => {
            if let Some(job) = read_jobs.iter_mut().find(|j| j.id == sc.id) {
                job.on_send_confirm(&sc).await;
            }
        }
        Some(fau::Cancel(c)) => {
            if let Some(mut job) = fs::remove_job(c.id, read_jobs) {
                job.cancel();
            }
            if let Some(mut job) = fs::remove_job(c.id, write_jobs) {
                job.cancel();
                // best-effort: drop the partial download
                job.finish().await;
            }
        }
        // Remove a directory (recursive flag controls depth).
        Some(fau::RemoveDir(d)) => {
            info!("file op: remove_dir id={} path={} recursive={}", d.id, d.path, d.recursive);
            let path = fs::get_path(&d.path);
            let res = if d.recursive {
                std::fs::remove_dir_all(&path).map_err(anyhow::Error::from)
            } else {
                std::fs::remove_dir(&path).map_err(anyhow::Error::from)
            };
            reply_fs_result(res, d.id, 0, out_tx);
        }
        // Remove a single file.
        Some(fau::RemoveFile(f)) => {
            info!("file op: remove_file id={} path={} file_num={}", f.id, f.path, f.file_num);
            reply_fs_result(fs::remove_file(&f.path), f.id, f.file_num, out_tx);
        }
        // Create a directory (mkdir -p).
        Some(fau::Create(c)) => {
            info!("file op: create_dir id={} path={}", c.id, c.path);
            reply_fs_result(fs::create_dir(&c.path), c.id, 0, out_tx);
        }
        // Rename a file / directory within its parent.
        Some(fau::Rename(r)) => {
            info!("file op: rename id={} path={} new_name={}", r.id, r.path, r.new_name);
            reply_fs_result(fs::rename_file(&r.path, &r.new_name), r.id, 0, out_tx);
        }
        Some(other) => {
            warn!("ignoring file action: {:?}", other);
        }
        None => {}
    }
}

/// Report a controller-driven filesystem mutation back to the controller:
/// `FileResponse::Done` on success, `FileResponse::Error` on failure. Matches
/// hbb_common's `handle_result` (ui_cm_interface.rs).
fn reply_fs_result(
    res: anyhow::Result<()>,
    id: i32,
    file_num: i32,
    out_tx: &mpsc::UnboundedSender<Message>,
) {
    match res {
        Ok(()) => {
            info!("file op job {id} ok -> reply Done");
            let _ = out_tx.send(fs::new_done_msg(id, file_num));
        }
        Err(e) => {
            warn!("file op job {id} failed: {e} -> reply Error");
            let _ = out_tx.send(fs::new_error_msg(id, e, file_num));
        }
    }
}

async fn handle_file_response(
    fr: FileResponse,
    write_jobs: &mut Vec<fs::TransferJob>,
    out_tx: &mpsc::UnboundedSender<Message>,
) {
    match fr.union {
        Some(fru::Block(block)) => {
            if let Some(job) = write_jobs.iter_mut().find(|j| j.id == block.id) {
                if let Err(e) = job.write_block(&block).await {
                    warn!("write job {}: {}", job.id, e);
                    let _ = out_tx.send(fs::new_error_msg(job.id, e, block.file_num));
                }
            }
        }
        Some(fru::Digest(d)) => {
            if let Some(job) = write_jobs.iter().find(|j| j.id == d.id) {
                let _ = out_tx.send(job.build_confirm_for_digest(&d));
            }
        }
        Some(fru::Done(d)) => {
            let job_id = d.id;
            let file_num = d.file_num;
            // The sender's `Done` means "I finished sending". We must finalize
            // the file AND reply with our own `Done` so the sender knows the
            // data was saved — otherwise its progress bar stalls near the end
            // waiting for this acknowledgment (hbb_common ui_cm_interface does
            // the same: `send_raw(fs::new_done(id, file_num), tx)`).
            if let Some(mut job) = fs::remove_job(job_id, write_jobs) {
                job.finish().await;
                let _ = out_tx.send(fs::new_done_msg(job_id, file_num));
            }
        }
        Some(fru::Error(err)) => {
            // Peer reported a transfer error; drop matching jobs.
            fs::remove_job(err.id, write_jobs);
        }
        _ => {}
    }
}

/// Refresh the shared transfer indicator shown in the UI.
fn update_transfer_status(read_jobs: &[fs::TransferJob], write_jobs: &[fs::TransferJob]) {
    let active = read_jobs
        .iter()
        .chain(write_jobs.iter())
        .find(|j| !j.is_done());
    match active {
        Some(j) => {
            let arrow = if j.is_read { "↑" } else { "↓" };
            let name = j.current_name();
            let pct = if j.total_size > 0 {
                (j.finished_size * 100 / j.total_size).min(100)
            } else {
                0
            };
            crate::set_file_transfer(
                true,
                format!("{arrow} {name}  {pct}%  {}", fmt_size(j.finished_size)),
            );
        }
        None => crate::set_file_transfer(false, String::new()),
    }
}

fn fmt_size(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn verify_login(cfg: &DeviceConfig, salt: &str, challenge: &str, got: &[u8]) -> bool {
    if got.is_empty() {
        return false;
    }
    let mut h1 = Sha256::new();
    h1.update(cfg.password.as_bytes());
    h1.update(salt.as_bytes());
    let h1 = h1.finalize();
    let mut h2 = Sha256::new();
    h2.update(h1);
    h2.update(challenge.as_bytes());
    let h2 = h2.finalize();
    constant_eq(&h2[..], got)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn login_ok_msg(cfg: &DeviceConfig) -> Message {
    let mut pi = PeerInfo::new();
    pi.username = whoami::username();
    pi.hostname = whoami::devicename();
    pi.platform = platform_str().to_string();
    pi.current_display = 0;
    pi.sas_enabled = cfg!(target_os = "windows");
    pi.version = env!("CARGO_PKG_VERSION").to_string();
    if let Ok(monitors) = xcap::Monitor::all() {
        if let Some(m) = monitors.into_iter().next() {
            let mut di = message::DisplayInfo::new();
            di.x = 0;
            di.y = 0;
            di.width = m.width().unwrap_or(0) as i32;
            di.height = m.height().unwrap_or(0) as i32;
            di.name = m.name().unwrap_or_default();
            di.online = true;
            pi.displays.push(di);
        }
    }
    let mut enc = SupportedEncoding::new();
    enc.h264 = true;
    pi.encoding = Some(enc).into();
    let mut res = LoginResponse::new();
    res.set_peer_info(pi);
    let mut m = Message::new();
    m.set_login_response(res);
    m
}

fn login_err_msg(err: &str) -> Message {
    let mut res = LoginResponse::new();
    res.set_error(err.to_string());
    let mut m = Message::new();
    m.set_login_response(res);
    m
}

fn video_frame_msg(frame: video::EncodedFrame) -> Message {
    let mut evf = EncodedVideoFrame::new();
    evf.data = bytes::Bytes::from(frame.data);
    evf.key = frame.key;
    evf.pts = frame.pts;
    let mut evfs = EncodedVideoFrames::new();
    evfs.frames.push(evf);
    let mut vf = VideoFrame::new();
    vf.set_h264s(evfs);
    vf.display = 0;
    let mut m = Message::new();
    m.set_video_frame(vf);
    m
}

fn platform_str() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Windows"
    }
    #[cfg(target_os = "linux")]
    {
        "Linux"
    }
    #[cfg(target_os = "macos")]
    {
        "Mac OS"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "Unknown"
    }
}

fn random_alnum(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            let b = rng.gen_range(0..36);
            if b < 10 {
                (b'0' + b) as char
            } else {
                (b'a' + b - 10) as char
            }
        })
        .collect()
}
