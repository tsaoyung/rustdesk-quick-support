# RustDesk QuickSupport

一键运行的远程协助客户端（受控端），类似 TeamViewer QuickSupport。对方双击打开即可看到 ID 和密码，你用 RustDesk 控制端输入 ID 即可连接。

## 下载与运行

到 [Releases](https://github.com/lu9944/rustdesk-quick-support/releases) 下载对应平台的产物（服务器配置已内置，无需再设置）。

### Windows

下载 `RustDesk-QuickSupport-windows-x86_64.exe`，**双击直接运行**（单文件，无需安装；调用系统 WebView2，Win10+ 自带）。

### Linux

下载 `.AppImage`，加可执行权限后双击运行：

```bash
chmod +x RustDesk-QuickSupport-*.AppImage
./RustDesk-QuickSupport-*.AppImage
```

### macOS

> macOS 产物做了 ad-hoc 签名但**未做 Apple 公证**，从网页下载首次打开会被 Gatekeeper 拦截。按下面任一方式解锁即可（app 名无空格，命令无需加引号）。

1. 下载 `.dmg`（Apple 芯片用 `_aarch64.dmg`，Intel 用 `_x86_64.dmg`），打开后把 `RustDeskQuickSupport.app` 拖入 `应用程序`（Applications）。
2. **清除隔离属性**（推荐，一次即可）：

   ```bash
   xattr -cr /Applications/RustDeskQuickSupport.app
   ```

   或者不用终端：在 `访达 → 应用程序` 里**右键** `RustDeskQuickSupport` → `打开` → `打开`。
3. 之后**双击**即可正常运行。

> 提示：要彻底免 `xattr`、下载即双击零提示，需用付费 Apple Developer 账号做签名 + 公证；当前为免证书方案。

---

## 配置服务器（给构建者）

编辑项目根目录下的 `.env` 文件：

```env
# 中继服务器地址（域名或 IP，默认端口 21116）
RUSTDESK_SERVER=rs-ny.rustdesk.com

# 服务器密钥（服务器未开启认证则留空）
RUSTDESK_KEY=

# Socks5 代理（可选，格式 host:port）
RUSTDESK_SOCKS5=

# 预设设备 ID（留空即可，见下方说明）
RUSTDESK_ID=

# 预设「固定密码」（留空即为每次启动随机的一次性密码，见下方说明）
RUSTDESK_PASSWORD=

# 直接 IP 访问（默认 Y；设为 N 则为纯中继客户端）
RUSTDESK_DIRECT=Y

# 直接 IP 访问端口（默认 21118）
RUSTDESK_DIRECT_PORT=21118
```

| 变量 | 说明 | 必填 |
|------|------|------|
| `RUSTDESK_SERVER` | 自建服务器地址，默认 `rs-ny.rustdesk.com` | 否 |
| `RUSTDESK_KEY` | 服务器认证密钥 | 否 |
| `RUSTDESK_SOCKS5` | 代理地址 | 否 |
| `RUSTDESK_ID` | 预设设备 ID，**留空即可**（见下方「设备 ID 与密码」） | 否 |
| `RUSTDESK_PASSWORD` | 预设**固定**密码；留空 = 每次启动随机的一次性密码 | 否 |
| `RUSTDESK_DIRECT` | 允许直接 IP 访问，默认 `Y` | 否 |
| `RUSTDESK_DIRECT_PORT` | 直接 IP 访问端口，默认 `21118` | 否 |

修改 `.env` 后需重新编译。

---

## 设备 ID 与密码

**ID：每台机器固定、互不重复。** 首次运行时随机生成一个 9 位 ID 并保存到本机配置文件，之后一直沿用（只有删掉配置文件才会变）。

> ⚠ **不要为批量分发预设 `RUSTDESK_ID`。** 所有顶着同一个 ID 的客户端会在服务器上互相覆盖，控制端按 ID 连接时可能连到**错误的机器**。留空即可。

**密码：默认是一次性密码，每次启动重新生成，且不写入磁盘。** 这与官方客户端一致（官方原文：*the temporary password refreshes automatically, so there is no lasting open door after the session ends*）。程序关闭后旧密码立即失效，适合"发给客户做一次性协助"的场景。

只有**无人值守 / 需要固定密码**时，才在编译期设 `RUSTDESK_PASSWORD`。

| 行为 | 默认（留空） | 编译期设死 |
|---|---|---|
| ID | 首次随机生成并持久化，每台机器各不相同 | 所有客户端共用同一 ID（仅适合单台无人值守机器） |
| 密码 | 每次启动重新随机，不落盘 | 固定不变，永久有效 |

> 同一台机器**同时开两个实例**时，两者共用同一个 ID，且第二个实例无法监听直连端口——日志会提示 `direct port 21118 is already in use`，该实例的直连不可用（中继仍可用）。需要多实例请分别部署到不同机器。

---

## 直接 IP 访问（不走服务器）

被控端除中继链路外，还会监听一个 TCP 端口（默认 **21118**），控制端可以直接输入 IP 连接，**完全不需要 ID 服务器或中继服务器**：

1. 被控端打开后，主界面 `Direct IP access` 一栏显示本机 IP，点击右侧按钮可复制。
2. 控制端打开新连接，在 ID 输入框里填**对端 IP**；改过端口则填 `IP:端口`。
3. 输入被控端显示的密码即可连上。

要点：

- **网络必须可达**：同局域网直接可用；跨公网要求被控端有公网 IP 或做过端口映射（把 TCP 21118 映射到被控端）。NAT 后无映射时这条路不通，请改用中继模式。
- **防火墙**需放行 TCP 21118 入站（Windows 首次运行会弹窗，选择允许即可）。
- 界面显示的 IP 已做优先级排序：**默认路由出口地址排第一**，虚拟网卡（Parallels / VPN 等）排在下面的 `Also:` 里。第一行连不上时再试备选地址。
- 直连与中继**可同时工作**：服务器不可达时直连依然可用，主界面会给出提示。只想保留中继模式，把 `RUSTDESK_DIRECT` 设为 `N` 重新编译。

---

## CI 一键编译（GitHub Actions）

仓库内置 `.github/workflows/build.yml`，会同时在 Windows / Linux / macOS 三个平台的官方 runner 上**原生编译**（比交叉编译更稳），产物双击即用：

| 平台 | 产物 | 双击行为 |
|------|------|----------|
| Windows | `RustDesk-QuickSupport-windows-x86_64.exe` | **单文件便携 exe，双击直接运行**（调用系统 WebView2，无需安装） |
| Linux | `.AppImage` + `.deb` | AppImage 单文件可直接运行（需 `chmod +x`） |
| macOS | `.dmg`（arm64 / x86_64 各一份） | 挂载后拖入 Applications |

**触发方式：**

1. **手动**：GitHub 仓库 → Actions → `Build` → Run workflow。手动触发时会弹出输入框，直接填写即可把服务器配置**编译期内置**到产物里：
   - `server`：中继服务器地址（域名或 IP，留空用默认 `rs-ny.rustdesk.com`）
   - `key`：服务器密钥（未开启认证则留空）
   - `socks5`：Socks5 代理 `host:port`（可选）
   - `direct`：是否允许直接 IP 访问（默认 `Y`）
   - `direct_port`：直接 IP 访问端口（默认 `21118`）
   - `publish`：是否发布到 Release（默认 `true`，自动生成预发布 tag `v0.1.0-ci.<run>-<sha7>`）

   构建完成后产物既在该 run 的 Artifacts 里，也会（默认）发布为一条 **Pre-release**。
2. **自动发布正式版**：推送 `v*` 形式的 tag，构建完成后自动创建正式 GitHub Release 并挂上全部产物（tag 触发时从[Repository Secrets](#secrets)读取配置）：
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

<a name="secrets"></a>**通过 Secrets 配置（用于 tag 自动发布）**：在仓库 Settings → Secrets and variables → Actions 添加 `RUSTDESK_SERVER`、`RUSTDESK_KEY`、`RUSTDESK_SOCKS5`（可选再加 `RUSTDESK_DIRECT`、`RUSTDESK_DIRECT_PORT`），tag 触发时会读取并内置；未设置的项按默认值处理（`direct=Y`、`port=21118`）。

> ✅ 配置是在**编译期**内置进二进制的：`src-tauri/build.rs` 读取 `.env`/环境变量，通过 `cargo:rustc-env` 固化，源码用 `option_env!()` 读取（见 `src-tauri/src/config.rs`）。因此通过 AppImage/DMG/便携 exe 分发的客户端**无需 `.env` 即可连接你指定的服务器**，双击即用。

> macOS 产物的运行方式见顶部[下载与运行](#macos)；CI 已对 `.app` 做 ad-hoc 签名（`tauri.conf.json` 里 `bundle.macOS.signingIdentity = "-"`）。

---

## 前置依赖

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install tauri-cli --version "^2"
```

---

## 构建

### macOS

```bash
./build-macos.sh
```

产物：`src-tauri/target/{aarch64,x86_64}-apple-darwin/release/bundle/dmg/`

### Windows

在 macOS 上交叉编译（静态链接 WebView2，单文件 exe）：

```bash
brew install lld
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
./build-windows.sh
```

产物：`target/x86_64-pc-windows-msvc/release/rustdesk-client.exe`

> 单文件 `.exe`，无需 DLL，双击即可运行。Windows 10+ 自带 WebView2。

在 Windows 上原生构建：

```bash
rustup target add x86_64-pc-windows-msvc
cargo tauri build --target x86_64-pc-windows-msvc
```

### Linux

```bash
./build-linux.sh
```

产物：`target/x86_64-unknown-linux-gnu/release/bundle/{deb,appimage}/`
