use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

mod bytes_codec;
mod codec;
mod config;
mod connection;
mod direct;
mod fs;
mod input;
mod netinfo;
mod proto_gen;
mod rendezvous;
mod video;
#[cfg(target_os = "windows")]
mod win_hide;

static APP_STATE: Lazy<Mutex<AppState>> = Lazy::new(|| {
    Mutex::new(AppState {
        server_online: false,
        peer_connected: false,
        peer_name: String::new(),
        file_transfer_active: false,
        file_transfer_label: String::new(),
        direct_listening: false,
    })
});

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    server_online: bool,
    peer_connected: bool,
    peer_name: String,
    file_transfer_active: bool,
    file_transfer_label: String,
    direct_listening: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionStatus {
    server_online: bool,
    connected: bool,
    peer_name: String,
    server: String,
    id: String,
    password: String,
    file_transfer_active: bool,
    file_transfer_label: String,
    /// Port the direct-IP listener is bound to (shown in the UI so the person
    /// being helped can read out a dialable address).
    direct_port: u16,
    direct_listening: bool,
    /// Local IPv4 addresses, most-likely-reachable first.
    local_ips: Vec<String>,
}

pub fn set_server_online(online: bool) {
    if let Ok(mut s) = APP_STATE.lock() {
        s.server_online = online;
    }
}

pub fn set_peer_connected(connected: bool, name: Option<String>) {
    if let Ok(mut s) = APP_STATE.lock() {
        s.peer_connected = connected;
        s.peer_name = name.unwrap_or_default();
    }
}

pub fn set_file_transfer(active: bool, label: String) {
    if let Ok(mut s) = APP_STATE.lock() {
        s.file_transfer_active = active;
        s.file_transfer_label = label;
    }
}

pub fn set_direct_listening(listening: bool) {
    if let Ok(mut s) = APP_STATE.lock() {
        s.direct_listening = listening;
    }
}

#[tauri::command]
fn get_id() -> String {
    config::get_id()
}

#[tauri::command]
fn get_password() -> String {
    config::get_password()
}

#[tauri::command]
fn get_status() -> ConnectionStatus {
    // Copy the snapshot out and release the lock before touching the network
    // stack: enumerating interfaces is I/O and must not block the setters.
    let (server_online, connected, peer_name, ft_active, ft_label, direct_listening) = {
        let s = APP_STATE.lock().unwrap();
        (
            s.server_online,
            s.peer_connected,
            s.peer_name.clone(),
            s.file_transfer_active,
            s.file_transfer_label.clone(),
            s.direct_listening,
        )
    };
    let cfg = config::load();
    ConnectionStatus {
        server_online,
        connected,
        peer_name,
        server: cfg.server.clone(),
        id: config::get_id(),
        password: config::get_password(),
        file_transfer_active: ft_active,
        file_transfer_label: ft_label,
        direct_port: config::direct_port(),
        direct_listening,
        local_ips: netinfo::local_ips(),
    }
}

#[tauri::command]
fn get_version(app: tauri::AppHandle) -> String {
    // 版本号取自 `tauri.conf.json`（编译期写进 PackageInfo），**不是** Cargo.toml
    // —— 这样界面上显示的版本与安装包文件名（bundle 命名同样来自该字段）永远
    // 一致。见 tauri-codegen/src/context.rs：config.version 存在时用它，否则回落到
    // CARGO_PKG_VERSION。
    let version = app.package_info().version.to_string();
    // 构建指纹：CI 注入 `<run_number>.<sha7>`。同一个版本号会被构建很多次，
    // 光看版本分不出是哪一次 —— 让客户截图就能定位到具体构建。
    // 注意用"非空"判断而不是 is_some()：build.rs 会把 `.env` 里的空值也固化进去。
    match option_env!("RUSTDESK_BUILD") {
        Some(b) if !b.is_empty() => format!("{version} · build {b}"),
        _ => version,
    }
}

pub fn run() {
    // Default to INFO logging even when RUST_LOG is not set, so `cargo run`
    // shows the rendezvous connection progress in the terminal.
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .on_window_event(|window, event| {
            // Restore an offscreen-hidden window when it regains focus (e.g. the
            // user clicks our taskbar button after another app took foreground).
            #[cfg(target_os = "windows")]
            if let tauri::WindowEvent::Focused(focused) = event {
                if *focused {
                    if let Some((x, y)) = win_hide::take_restore() {
                        let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
                    }
                }
            }
        })
        .setup(|app| {
            let _app_handle = app.handle().clone();
            video::start_global();
            // Install the minimize interceptor on the main window so that
            // clicking minimize hides it offscreen (taskbar icon preserved)
            // instead of entering WS_MINIMIZE state.
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                if let Some(win) = app.get_webview_window("main") {
                    if let Ok(h) = win.hwnd() {
                        // `h` is `windows::Win32::Foundation::HWND`; bridge to
                        // the windows-sys isize handle via its raw `.0` pointer.
                        let raw = h.0 as isize;
                        win_hide::install(raw);
                    }
                }
            }
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    // The direct-IP listener runs alongside the rendezvous task:
                    // two independent entry points into the same session body.
                    direct::spawn();
                    rendezvous::run().await;
                });
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_id,
            get_password,
            get_status,
            get_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
