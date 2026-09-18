// Local address discovery for the direct-IP workflow. The person being helped
// has to read an address out to the supporter, so the address most likely to be
// reachable is surfaced first (the default-route egress address) and the rest
// follow.
//
// Why ordering matters here specifically: a host running Parallels, another
// hypervisor, or a VPN exposes extra private IPv4s — on this machine that is
// 10.211.55.2 and 10.37.129.2. Naively taking the first non-loopback address can
// therefore hand out one that only exists on a virtual bridge and can never be
// dialled from the LAN.
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Primary address: the source address the kernel would pick for outbound
/// traffic, i.e. whichever interface holds the default route.
///
/// The socket is `connect`ed but never sent on — `connect` on a UDP socket only
/// records the peer address and emits no packets — so this also works offline
/// as long as a default route exists.
pub fn primary_ip() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("8.8.8.8", 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_usable(ip) => Some(ip),
        _ => None,
    }
}

/// Every usable IPv4 on the machine: primary first, then RFC1918 addresses
/// (the ones that actually route on a LAN), then anything else. Deduplicated.
pub fn local_ips() -> Vec<String> {
    let primary = primary_ip();
    let mut others: Vec<Ipv4Addr> = Vec::new();

    if let Ok(ifas) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in ifas {
            if let IpAddr::V4(ip) = ip {
                if !is_usable(ip) || Some(ip) == primary || others.contains(&ip) {
                    continue;
                }
                others.push(ip);
            }
        }
    }

    // Stable sort keeps the interface order within each group.
    others.sort_by_key(|ip| if is_rfc1918(*ip) { 0 } else { 1 });

    let mut out = Vec::new();
    if let Some(p) = primary {
        out.push(p.to_string());
    }
    out.extend(others.iter().map(|ip| ip.to_string()));
    out
}

fn is_usable(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() && !ip.is_broadcast()
}

fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}
