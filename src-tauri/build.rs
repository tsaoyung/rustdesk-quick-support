use std::env;
use std::path::Path;

// 配置项在编译期读取 .env / 环境变量，内置进二进制。
// 运行时无需 .env，分发后双击即可用。
const BAKED_KEYS: &[&str] = &[
    "RUSTDESK_SERVER",
    "RUSTDESK_KEY",
    "RUSTDESK_SOCKS5",
    "RUSTDESK_ID",
    "RUSTDESK_PASSWORD",
    "RUSTDESK_DIRECT",
    "RUSTDESK_DIRECT_PORT",
];

fn bake_env_config() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = Path::new(&manifest_dir);
    let workspace = manifest_path.parent().unwrap_or(manifest_path);
    let env_file = workspace.join(".env");

    // .env 变化时重新编译
    println!("cargo:rerun-if-changed={}", env_file.display());

    let mut values: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // 1) 从 .env 读取基础值（支持 KEY=value、KEY="value"、# 注释、空行）
    if let Ok(content) = std::fs::read_to_string(&env_file) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                if BAKED_KEYS.contains(&k) {
                    let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    values.insert(k.to_string(), v);
                }
            }
        }
    }

    // 2) 进程环境变量（非空）覆盖 .env；同时声明 env 变化触发重编
    for key in BAKED_KEYS {
        println!("cargo:rerun-if-env-changed={}", key);
        if let Ok(v) = env::var(key) {
            if !v.is_empty() {
                values.insert(key.to_string(), v);
            }
        }
    }

    // 3) 把最终值固化为编译期环境变量，源码用 option_env!() 读取
    for key in BAKED_KEYS {
        if let Some(v) = values.get(*key) {
            println!("cargo:rustc-env={}={}", key, v);
        }
    }
}

fn main() {
    bake_env_config();
    tauri_build::build();

    // Generate Rust code from the vendored RustDesk proto files.
    let out_dir = format!("{}/protos", env::var("OUT_DIR").unwrap());
    std::fs::create_dir_all(&out_dir).unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("protobuf codegen failed");

    println!("cargo:rerun-if-changed=protos/rendezvous.proto");
    println!("cargo:rerun-if-changed=protos/message.proto");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "gnu" {
        return;
    }

    let profile = env::var("PROFILE").unwrap();
    let target = env::var("TARGET").unwrap();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let workspace = manifest_dir.parent().unwrap_or(manifest_dir);
    let dll_src = workspace
        .join("target")
        .join(&target)
        .join(&profile)
        .join("WebView2Loader.dll");

    if dll_src.exists() {
        let out_dir = env::var("OUT_DIR").unwrap();
        let dll_dst = Path::new(&out_dir).join("WebView2Loader.dll");
        std::fs::copy(&dll_src, &dll_dst).expect("Failed to copy WebView2Loader.dll to OUT_DIR");
        println!("cargo:rerun-if-changed={}", dll_src.display());
    }
}
