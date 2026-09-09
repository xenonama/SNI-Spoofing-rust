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

/// TCP filter covering ALL endpoints (both directions).
/// Mirrors `main.py` filt construction exactly.
pub fn build_tcp_filter(interface_ipv4: &str, endpoints: &[Endpoint]) -> String {
    let parts: Vec<String> = endpoints
        .iter()
        .map(|e| {
            format!(
                "(ip.SrcAddr == {} and ip.DstAddr == {}) or (ip.SrcAddr == {} and ip.DstAddr == {})",
                interface_ipv4, e.ip, e.ip, interface_ipv4
            )
        })
        .collect();
    format!("tcp and ({})", parts.join(" or "))
}

/// Narrow UDP/443 filter around the interface IP. Mirrors `quic_filt`.
pub fn build_quic_filter(interface_ipv4: &str) -> String {
    format!(
        "udp and ((ip.SrcAddr == {} and udp.DstPort == 443) or (udp.SrcPort == 443 and ip.DstAddr == {}))",
        interface_ipv4, interface_ipv4
    )
}
