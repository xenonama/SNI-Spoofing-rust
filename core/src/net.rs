//! Network helpers: replaces `utils/network_tools.py`.
//!
//! `get_default_interface_ipv4` binds a UDP socket and "connects" it to the
//! target (no packets sent for UDP) then reads the local address — identical
//! technique to the Python version.

use std::net::{IpAddr, UdpSocket};

/// Local IPv4 used to reach `addr` (default 8.8.8.8). Empty string on failure
/// would be Python behavior; Rust returns `None` instead (no sentinel strings).
pub fn get_default_interface_ipv4(addr: &str) -> Option<String> {
    let target = format!("{}:53", addr);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(target).ok()?;
    let local = sock.local_addr().ok()?;
    match local.ip() {
        IpAddr::V4(v4) => Some(v4.to_string()),
        IpAddr::V6(_) => None,
    }
}

/// IPv6 counterpart (mirrors `get_default_interface_ipv6`).
pub fn get_default_interface_ipv6(addr: &str) -> Option<String> {
    let target = format!("[{}]:53", addr);
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect(target).ok()?;
    let local = sock.local_addr().ok()?;
    match local.ip() {
        IpAddr::V6(v6) => Some(v6.to_string()),
        IpAddr::V4(_) => None,
    }
}
