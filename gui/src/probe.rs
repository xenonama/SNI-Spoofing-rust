//! Latency / reachability probes: port of `utils/smart.py` hot paths.
//!
//! Std-only TCP connect timing (no new deps). Each endpoint is dialed with
//! `connect_timeout(3s)` on its own thread; results are ranked fastest-first.
//! Mirrors Smart Tools "rank endpoints by TCP latency" + "local relay health".

use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub endpoint: String,
    pub latency_ms: Option<u128>,
    pub reachable: bool,
}

/// Probe all `ip:port` endpoints concurrently (one thread each, 3s timeout).
/// Never panics; unreachable entries get `latency_ms=None`.
pub fn probe_endpoints(endpoints: &[String], timeout: Duration) -> Vec<ProbeResult> {
    let mut handles = vec![];
    for ep in endpoints {
        let ep = ep.clone();
        handles.push(std::thread::spawn(move || {
            let start = Instant::now();
            let reachable = dial(&ep, timeout);
            ProbeResult {
                endpoint: ep,
                latency_ms: if reachable {
                    Some(start.elapsed().as_millis())
                } else {
                    None
                },
                reachable,
            }
        }));
    }
    let mut out: Vec<ProbeResult> = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .collect();
    // Reachable first, fastest first (mirrors smart.rank + use-fastest).
    out.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.endpoint.cmp(&b.endpoint),
    });
    out
}

fn dial(ep: &str, timeout: Duration) -> bool {
    // Accept "ip:port" only (strict like parse_host_list; garbage = unreachable).
    let addr: Option<SocketAddr> = ep.parse().ok();
    match addr {
        Some(a) => TcpStream::connect_timeout(&a, timeout).is_ok(),
        None => false,
    }
}

/// Local relay health: can we open the listen port?
pub fn probe_relay(host: &str, port: u16) -> bool {
    let ep = format!("{}:{}", host, port);
    dial(&ep, Duration::from_secs(2))
}
