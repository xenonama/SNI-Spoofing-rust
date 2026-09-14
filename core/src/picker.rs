//! Endpoint / SNI picking + WinDivert filter builders.
//!
//! Ports `main.py::pick_endpoints/pick_sni/ep_key` + filter strings.
//! Pure + sync so unit tests (Phase 5) exercise it without Tokio.

use crate::config::Endpoint;
use parking_lot::Mutex;
use rand::seq::SliceRandom;

/// Round-robin endpoint picker.
/// Mirrors `_endpoint_cycle = itertools.cycle(range(len))` + `_cycle_lock`.
pub struct EndpointPicker {
    endpoints: Vec<Endpoint>,
    next: Mutex<usize>,
}

impl EndpointPicker {
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        Self {
            endpoints,
            next: Mutex::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Return endpoints ordered for this connection (round-robin start).
    /// Mirrors: `start = next(cycle); [ENDPOINTS[(start+i)%n]]`.
    pub fn pick_ordered(&self) -> Vec<Endpoint> {
        let n = self.endpoints.len();
        if n == 0 {
            return vec![];
        }
        let start = {
            let mut g = self.next.lock();
            let s = *g % n;
            *g = g.wrapping_add(1);
            s
        };
        (0..n)
            .map(|i| self.endpoints[(start + i) % n].clone())
            .collect()
    }
}

/// Random SNI per connection. Mirrors `random.choice(FAKE_SNIS)`.
pub fn pick_sni(snis: &[String]) -> Option<String> {
    snis.choose(&mut rand::thread_rng()).cloned()
}

/// `"ip:port"` key for scoreboard + dict. Mirrors `ep_key()`.
pub fn ep_key(ep: &Endpoint) -> String {
    format!("{}:{}", ep.ip, ep.port)
}

/// FIX #8: IPv6 drop filter. Matches any IPv6 TCP on the endpoint
/// ports. Used when ip_mode is "ipv4" or "both" to force the
/// browser to fall back to IPv4.
pub fn build_ipv6_drop_filter(endpoints: &[Endpoint]) -> String {
    if endpoints.is_empty() {
        return "false".to_string();
    }
    let ports: Vec<String> = endpoints
        .iter()
        .map(|e| format!("tcp.DstPort == {} or tcp.SrcPort == {}", e.port, e.port))
        .collect();
    format!("tcp and ipv6 and ({})", ports.join(" or "))
}

/// TCP filter covering ALL endpoints (both directions).
/// Mirrors `main.py` filt construction exactly.
/// FIX P3/P4: scope to the endpoint ports so non-handshake traffic (80/8080/
/// probe/relay data) doesn't hit DPI; guard empty to avoid `tcp and ()`
/// syntax error.
pub fn build_tcp_filter(
    interface_ipv4: &str,
    endpoints: &[Endpoint],
    ip_mode: &str,
) -> String {
    if endpoints.is_empty() {
        return "tcp and false".to_string();
    }
    // FIX #8: "ipv6" mode uses only the IPv6 drop filter; IPv4
    // traffic is forwarded untouched by the absence of a handle.
    if ip_mode == "ipv6" {
        return build_ipv6_drop_filter(endpoints);
    }
    let parts: Vec<String> = endpoints
        .iter()
        .map(|e| {
            format!(
                "((ip.SrcAddr == {} and ip.DstAddr == {} and tcp.DstPort == {}) or (ip.SrcAddr == {} and ip.DstAddr == {} and tcp.SrcPort == {}))",
                interface_ipv4, e.ip, e.port, e.ip, interface_ipv4, e.port
            )
        })
        .collect();
    format!("tcp and ({})", parts.join(" or "))
}

/// Narrow UDP filter around the interface IP. Mirrors `quic_filt`.
/// FIX P3: cover common QUIC ports (443/80/8443), not just 443, so block
/// can't be bypassed by Alt-Svc on a non-443 port.
pub fn build_quic_filter(interface_ipv4: &str) -> String {
    format!(
        "udp and ((ip.SrcAddr == {} and (udp.DstPort == 443 or udp.DstPort == 80 or udp.DstPort == 8443)) or ((udp.SrcPort == 443 or udp.SrcPort == 80 or udp.SrcPort == 8443) and ip.DstAddr == {}))",
        interface_ipv4, interface_ipv4
    )
}
