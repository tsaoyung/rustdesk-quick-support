const { invoke } = window.__TAURI__?.core ?? {};

if (!invoke) {
    document.addEventListener("DOMContentLoaded", () => {
        document.getElementById("statusText").textContent = "Tauri API not loaded";
        document.getElementById("deviceId").textContent = "Error";
        document.getElementById("password").textContent = "------";
    });
}

let deviceId = "--- --- ---";
let password = "------";
let localIp = "---.---.---.---";

function formatId(id) {
    if (id.length >= 9) {
        return id.slice(0, 3) + " " + id.slice(3, 6) + " " + id.slice(6);
    }
    return id;
}

function updateDisplay(data) {
    deviceId = data.id;
    password = data.password;
    document.getElementById("deviceId").textContent = formatId(deviceId);
    document.getElementById("password").textContent = password;

    const statusDot = document.getElementById("statusDot");
    const statusText = document.getElementById("statusText");
    const statusMessage = document.getElementById("statusMessage");

    if (data.connected) {
        statusDot.className = "status-dot connected";
        statusText.textContent = "Remote session active";
        if (data.peer_name) {
            statusText.textContent += " - " + data.peer_name;
        }
        statusMessage.innerHTML = "<p>Your device is currently being controlled remotely.</p>";
    } else if (data.server_online) {
        statusDot.className = "status-dot waiting";
        statusText.textContent = "Waiting for connection";
        statusMessage.innerHTML = "<p>Connected to server. Share your ID and password with your supporter to allow remote control.</p>";
    } else {
        statusDot.className = "status-dot offline";
        statusText.textContent = "Connecting to server...";
        statusMessage.innerHTML = data.direct_listening
            ? "<p>Rendezvous server unreachable &#8212; direct IP access is still available using the address above.</p>"
            : "<p>Connecting to the rendezvous server. Check your <code>.env</code> and network.</p>";
    }

    // Direct-IP readout: the address the supporter should dial. The backend puts
    // the default-route address first, since that is the one that actually
    // routes on a LAN; any others are shown as fallbacks (virtual adapters, VPN).
    const ips = Array.isArray(data.local_ips) ? data.local_ips : [];
    localIp = ips.length ? ips[0] : "";
    document.getElementById("localIp").textContent = localIp || "unavailable";

    const ipHint = document.getElementById("ipHint");
    if (data.direct_listening) {
        ipHint.textContent = "Port " + data.direct_port + " \u00b7 listening";
        ipHint.classList.remove("off");
    } else {
        ipHint.textContent = "Direct access not listening";
        ipHint.classList.add("off");
    }

    const ipOthers = document.getElementById("ipOthers");
    if (ips.length > 1) {
        ipOthers.style.display = "";
        ipOthers.textContent = "Also: " + ips.slice(1).join(", ");
    } else {
        ipOthers.style.display = "none";
    }

    const serverDot = document.getElementById("serverDot");
    const serverText = document.getElementById("serverText");
    if (data.server_online) {
        serverDot.className = "server-dot online";
        serverText.textContent = "Connected to server: " + (data.server || "—");
    } else {
        serverDot.className = "server-dot offline";
        serverText.textContent = "Server: " + (data.server || "—") + " (connecting...)";
    }

    const transferInfo = document.getElementById("transferInfo");
    const transferText = document.getElementById("transferText");
    if (data.file_transfer_active) {
        transferInfo.style.display = "";
        transferText.textContent = data.file_transfer_label || "Transferring files...";
    } else {
        transferInfo.style.display = "none";
    }
}

let pollHandle = null;
function schedulePoll(intervalMs) {
    if (pollHandle) clearInterval(pollHandle);
    pollHandle = setInterval(refreshStatus, intervalMs);
}

async function refreshStatus() {
    try {
        const status = await invoke("get_status");
        updateDisplay(status);
        // Refresh faster while a transfer is in progress for live progress.
        schedulePoll(status.file_transfer_active ? 1000 : 5000);
    } catch (e) {
        console.error("Failed to get status:", e);
        document.getElementById("statusText").textContent = "Error: " + e;
    }
}

async function copyToClipboard(field) {
    let text = "";
    if (field === "deviceId") {
        text = deviceId;
    } else if (field === "password") {
        text = password;
    } else if (field === "localIp") {
        text = localIp;
    }

    try {
        await navigator.clipboard.writeText(text);
        showToast("Copied!");
    } catch (e) {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        showToast("Copied!");
    }
}

function showToast(message) {
    let toast = document.querySelector(".copied-toast");
    if (!toast) {
        toast = document.createElement("div");
        toast.className = "copied-toast";
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 1500);
}

async function init() {
    try {
        const version = await invoke("get_version");
        document.getElementById("version").textContent = "v" + version;
    } catch (e) {
        console.error("Failed to get version:", e);
        document.getElementById("version").textContent = "err";
    }

    await refreshStatus();
}

window.addEventListener("DOMContentLoaded", init);
window.copyToClipboard = copyToClipboard;
