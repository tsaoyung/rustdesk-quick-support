// Persistent device config: id, password, Ed25519 signing keypair, uuid, and
// server settings baked into the binary at compile time (see build.rs + option_env!).
use anyhow::Result;
use log::{info, warn};
use rand::Rng;
use sodiumoxide::crypto::sign;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub const DEFAULT_RENDEZVOUS_SERVERS: &[&str] = &[
    "rs-ny.rustdesk.com",
    "rs-sg.rustdesk.com",
    "rs-cn.rustdesk.com",
];
pub const RENDEZVOUS_PORT: u16 = 21116;
pub const RELAY_PORT: u16 = 21117;
/// Default port for direct (IP) access. Matches RustDesk's own default of
/// `RENDEZVOUS_PORT + 2`; a controller dials `RELAY_PORT + 1` to reach it.
pub const DIRECT_PORT: u16 = RENDEZVOUS_PORT + 2;

#[derive(Clone)]
pub struct DeviceConfig {
    pub id: String,
    pub password: String,
    /// Permanent salt for the login password hash. Must stay stable across
    /// connections so the controller's *remembered* password (which it stores
    /// as `SHA256(plain + salt)`) keeps validating. Matches hbb_common's
    /// `get_effective_permanent_password_salt` semantics.
    pub password_salt: String,
    pub server: String,
    pub licence_key: String,
    pub socks5: String,
    pub sign_sk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub uuid: Vec<u8>,
}

fn config_dir() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("com.rustdesk.quicksupport")
    }
    #[cfg(target_os = "linux")]
    {
        home.join(".config").join("rustdesk-client")
    }
    #[cfg(target_os = "windows")]
    {
        home.join("AppData").join("Roaming").join("RustDeskClient")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home.join(".rustdesk-client")
    }
}

fn config_file() -> PathBuf {
    let dir = config_dir();
    fs::create_dir_all(&dir).ok();
    dir.join("config.txt")
}

/// Lowest/highest 9-digit device ID (RustDesk shows IDs as nine digits).
const ID_MIN: u64 = 100_000_000;
const ID_MAX: u64 = 999_999_999;

/// A fresh 9-digit device ID.
///
/// Generated once on first run and then persisted, so a machine keeps the same
/// ID for as long as its config file survives — the ID is deliberately **not**
/// derived from the hardware any more. The previous MAC-based version caused two
/// avoidable collisions, both of which make two devices fight over one ID on
/// hbbs (whichever registered last wins, so a controller reaching that ID may
/// land on the wrong machine):
///
///   * it built a 32-bit value from the MAC's last four bytes and then masked it
///     with `& 0x1FFFFFFF`, keeping only 29 bits. Two genuinely different MACs
///     such as `00:11:00:AA:BB:CC` and `00:11:E0:AA:BB:CC` mapped to the same ID.
///   * `mac_address::get_mac_address()` returns the *first* interface, so
///     machines cloned from an image, or using a shared/virtual/VPN adapter,
///     reported identical MACs and therefore an identical ID.
///
/// Randomising keeps the ID unique per installation; persisting keeps it stable.
fn generate_id() -> String {
    let mut rng = rand::thread_rng();
    rng.gen_range(ID_MIN..=ID_MAX).to_string()
}

fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| CHARS[rng.gen::<usize>() % CHARS.len()])
        .collect()
}

fn random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

static CONFIG: OnceLock<DeviceConfig> = OnceLock::new();

pub fn load() -> &'static DeviceConfig {
    CONFIG.get_or_init(|| build_config().expect("failed to build config"))
}

fn build_config() -> Result<DeviceConfig> {
    // 服务器/密钥等配置由 build.rs 在编译期从 .env 内置（见 option_env!()）。
    //
    // 这里一律用 baked_str()（空值视为未设置）而不是 option_env!(..).is_some()：
    // build.rs 会把 `.env` 里写成 `KEY=` 的空值也固化进去，于是 option_env! 返回
    // Some("")，is_some() 为真 —— 日志就会打印 `password=fixed (baked)`，而实际
    // 生效的是一次性随机密码。日志说假话比没日志更费时间。
    let baked_server = baked_str(option_env!("RUSTDESK_SERVER"));
    let baked_key = baked_str(option_env!("RUSTDESK_KEY"));
    let baked_id_env = baked_str(option_env!("RUSTDESK_ID"));
    let baked_password_env = baked_str(option_env!("RUSTDESK_PASSWORD"));
    log::info!(
        "baked config: server={:?}, key={} ({} bytes), id={:?}, password={}",
        baked_server.as_deref(),
        if baked_key.is_some() { "set" } else { "empty" },
        baked_key.as_deref().map(|v| v.len()).unwrap_or(0),
        baked_id_env.as_deref(),
        if baked_password_env.is_some() {
            "fixed (baked)"
        } else {
            "one-time (regenerated each launch)"
        },
    );

    // sodiumoxide needs global init for keypair generation.
    sodiumoxide::init().ok();

    let config_path = config_file();
    let mut saved_id = String::new();
    let mut saved_salt = String::new();
    let mut saved_sk = String::new();
    let mut saved_pk = String::new();
    let mut saved_uuid = String::new();

    if let Ok(content) = fs::read_to_string(&config_path) {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "id" => saved_id = v.trim().to_string(),
                    "salt" => saved_salt = v.trim().to_string(),
                    "sk" => saved_sk = v.trim().to_string(),
                    "pk" => saved_pk = v.trim().to_string(),
                    "uuid" => saved_uuid = v.trim().to_string(),
                    // A legacy `password=` line may exist from older builds; it is
                    // ignored on purpose (see the password comment below).
                    _ => {}
                }
            }
        }
    }

    // ID: stable per installation. A baked value wins (deliberately supported
    // for unattended machines), otherwise reuse what we persisted, otherwise
    // mint a fresh one.
    if baked_id_env.is_some() {
        warn!(
            "RUSTDESK_ID is baked into this binary: EVERY client will report the same ID \
             and they will overwrite each other on the server. Only use it for a single \
             unattended machine."
        );
    }
    let id = baked_id_env
        .or_else(|| if saved_id.is_empty() { None } else { Some(saved_id.clone()) })
        .unwrap_or_else(generate_id);

    // Password: a one-time password, regenerated on every launch.
    //
    // This matches the official client, where the temporary password "refreshes
    // automatically, so there is no lasting open door after the session ends".
    // Two reasons it is not persisted:
    //   * a shipped support tool must not keep a permanent credential valid
    //     forever after a customer has read it out loud once;
    //   * a fixed password shared by every client would blur them together.
    // Bake `RUSTDESK_PASSWORD` for the "permanent password" use case instead.
    let password = baked_password_env.unwrap_or_else(generate_password);

    // Permanent password salt. Reuse the saved one if present so already-paired
    // controllers keep validating; otherwise generate and persist it once.
    let password_salt = if saved_salt.is_empty() {
        random_hex(16)
    } else {
        saved_salt.clone()
    };

    // Ed25519 signing keypair (registered with the rendezvous server as the
    // device public key). Persist so the server sees a stable identity.
    let (sign_sk, sign_pk) = match (hex::decode(&saved_sk), hex::decode(&saved_pk)) {
        (Ok(sk), Ok(pk))
            if sk.len() == sign::SECRETKEYBYTES && pk.len() == sign::PUBLICKEYBYTES =>
        {
            (sk, pk)
        }
        _ => {
            let (pk, sk) = sign::gen_keypair();
            (
                sk.0.to_vec(),
                pk.0.to_vec(),
            )
        }
    };

    let uuid = if saved_uuid.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        saved_uuid.clone()
    };

    // Persist the identity for next run. The password is deliberately NOT
    // written: it is a one-time credential, so keeping it on disk would both
    // leak it and silently turn it back into a permanent one.
    let content = format!(
        "id={}\nsalt={}\nsk={}\npk={}\nuuid={}\n",
        id,
        password_salt,
        hex::encode(&sign_sk),
        hex::encode(&sign_pk),
        uuid,
    );
    let _ = fs::write(&config_path, content);

    let uuid_bytes = uuid::Uuid::parse_str(&uuid)
        .map(|u| u.as_bytes().to_vec())
        .unwrap_or_default();

    let server = baked_server.unwrap_or_else(|| DEFAULT_RENDEZVOUS_SERVERS[0].to_string());

    let cfg = DeviceConfig {
        id,
        password,
        password_salt,
        server,
        licence_key: baked_key.unwrap_or_default(),
        socks5: baked_str(option_env!("RUSTDESK_SOCKS5")).unwrap_or_default(),
        sign_sk,
        sign_pk,
        uuid: uuid_bytes,
    };

    info!(
        "Device config: id={}, server={}, pk={}.., uuid={}",
        cfg.id,
        cfg.server,
        &hex::encode(&cfg.sign_pk)[..8],
        uuid,
    );

    Ok(cfg)
}

/// 编译期内置值（来自 build.rs 的 cargo:rustc-env）→ 空值视为未设置。
fn baked_str(v: Option<&'static str>) -> Option<String> {
    v.map(|s| s.to_string()).filter(|s| !s.is_empty())
}

pub fn get_id() -> String {
    load().id.clone()
}

pub fn get_password() -> String {
    load().password.clone()
}

/// `host` or `host:port` -> `(host, port)` defaulting to `default_port`.
pub fn split_host_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = addr.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (addr.to_string(), default_port)
}

/// Whether the direct-IP listener should run.
///
/// Defaults to ON: IP direct access is the reason this fork exists, and the
/// relay path keeps working alongside it, so enabling it costs nothing beyond a
/// listening socket. Build with `RUSTDESK_DIRECT=N` for a relay-only client.
pub fn direct_enabled() -> bool {
    match option_env!("RUSTDESK_DIRECT") {
        None => true,
        Some(v) => {
            let v = v.trim();
            v.is_empty() || matches!(v.to_ascii_uppercase().as_str(), "Y" | "YES" | "TRUE" | "1")
        }
    }
}

/// Port the direct listener binds. Falls back to `DIRECT_PORT` when unset or
/// unparsable, mirroring the official `get_direct_port()`.
pub fn direct_port() -> u16 {
    option_env!("RUSTDESK_DIRECT_PORT")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(DIRECT_PORT)
}

/// Source addresses allowed to use IP direct access, from the baked
/// `RUSTDESK_DIRECT_WHITELIST` — a comma separated list of addresses
/// (`10.0.0.7`) and/or CIDR blocks (`10.0.0.0/24`, `192.168.1.0/24`).
///
/// Empty list ⇒ no restriction, i.e. exactly the behaviour before this option
/// existed: any source that can route to the port may connect. Note the direct
/// socket carries no encryption of its own (see `direct.rs`), so set this when
/// the machine sits on a network you do not fully trust.
pub fn direct_whitelist() -> Vec<String> {
    baked_str(option_env!("RUSTDESK_DIRECT_WHITELIST"))
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a direct-IP connection coming from `ip` may proceed.
pub fn direct_ip_allowed(ip: std::net::IpAddr) -> bool {
    let list = direct_whitelist();
    // Short-circuit the common case: nothing configured ⇒ allow everything.
    list.is_empty() || list.iter().any(|entry| ip_matches(ip, entry))
}

/// Entries of the whitelist that do not parse. Reported at startup so that a
/// typo is visible in the log instead of silently narrowing nothing.
pub fn direct_whitelist_invalid() -> Vec<String> {
    direct_whitelist()
        .into_iter()
        .filter(|e| !is_valid_entry(e))
        .collect()
}

/// One whitelist entry against one source address. A malformed entry never
/// matches, so a typo cannot silently widen access.
pub fn ip_matches(ip: std::net::IpAddr, entry: &str) -> bool {
    use std::net::IpAddr;
    match entry.split_once('/') {
        Some((base, prefix)) => {
            let (Ok(base), Ok(prefix)) = (
                base.trim().parse::<IpAddr>(),
                prefix.trim().parse::<u32>(),
            ) else {
                return false;
            };
            match (ip, base) {
                (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
                    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                    (u32::from(a) & mask) == (u32::from(b) & mask)
                }
                (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
                    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                    (u128::from(a) & mask) == (u128::from(b) & mask)
                }
                _ => false,
            }
        }
        None => entry
            .trim()
            .parse::<IpAddr>()
            .map(|e| e == ip)
            .unwrap_or(false),
    }
}

fn is_valid_entry(entry: &str) -> bool {
    use std::net::IpAddr;
    match entry.split_once('/') {
        Some((base, prefix)) => {
            let (Ok(base), Ok(prefix)) = (
                base.trim().parse::<IpAddr>(),
                prefix.trim().parse::<u32>(),
            ) else {
                return false;
            };
            match base {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            }
        }
        None => entry.trim().parse::<IpAddr>().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exact_address_matches_only_itself() {
        assert!(ip_matches(ip("10.0.0.7"), "10.0.0.7"));
        assert!(!ip_matches(ip("10.0.0.8"), "10.0.0.7"));
        // A bare address must not behave like a prefix.
        assert!(!ip_matches(ip("10.0.0.7"), "10.0.0.0"));
    }

    #[test]
    fn cidr_matches_the_block_and_nothing_more() {
        assert!(ip_matches(ip("192.168.1.5"), "192.168.1.0/24"));
        assert!(ip_matches(ip("192.168.1.255"), "192.168.1.0/24"));
        assert!(!ip_matches(ip("192.168.2.5"), "192.168.1.0/24"));
        // /0 spans the whole family, and must not trap on the shift.
        assert!(ip_matches(ip("8.8.8.8"), "0.0.0.0/0"));
        // /32 is the single host itself.
        assert!(ip_matches(ip("10.1.2.3"), "10.1.2.3/32"));
        assert!(!ip_matches(ip("10.1.2.4"), "10.1.2.3/32"));
    }

    #[test]
    fn families_and_malformed_entries_never_match() {
        assert!(!ip_matches(ip("10.0.0.1"), "2001:db8::/32"));
        assert!(!ip_matches(ip("10.0.0.1"), "10.0.0.0/33"));
        assert!(!ip_matches(ip("10.0.0.1"), "not-an-ip"));
        assert!(!ip_matches(ip("10.0.0.1"), "10.0.0.0/"));
        assert!(ip_matches(ip("2001:db8::1"), "2001:db8::1"));
        assert!(ip_matches(ip("2001:db8::5"), "2001:db8::/32"));
    }

    #[test]
    fn entry_validation_flags_typos() {
        assert!(is_valid_entry("10.0.0.1"));
        assert!(is_valid_entry("10.0.0.0/24"));
        assert!(is_valid_entry("10.0.0.0/32"));
        assert!(is_valid_entry("2001:db8::/128"));
        assert!(!is_valid_entry("10.0.0.0/33"));
        assert!(!is_valid_entry("2001:db8::/129"));
        assert!(!is_valid_entry("garbage"));
    }
}
