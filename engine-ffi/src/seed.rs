//! First-launch config seeding from `ip_list.txt` / `sni_list.txt`.
//!
//! WP0.2: when `config.json` does not exist, the default config is built by
//! reading two text files from the SAME directory as the exe (never CWD):
//! `ip_list.txt` (one CIDR per line) and `sni_list.txt` (one domain per
//! line). All parsers are total: I/O or parse failures yield an empty vec,
//! never a panic. No new dependencies (std only).

use std::net::Ipv4Addr;
use std::path::Path;

/// Max endpoints derived from `ip_list.txt` (keeps the default config small
/// and the probe table responsive).
pub const MAX_SEED_ENDPOINTS: usize = 8;
/// Max SNIs derived from `sni_list.txt` (mirrors `MAX_SNIS` in `config.rs`).
pub const MAX_SEED_SNIS: usize = 200;

/// Parse a text file where each non-empty line is a CIDR block.
/// Returns the first usable IP of each block (`/24` → `.1`) with port 443.
/// Skips invalid lines silently. Dedupes. Caps at 8 entries.
pub fn parse_ip_list(path: &Path) -> Vec<(String, u16)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<(String, u16)> = Vec::new();
    for raw in text.lines() {
        if out.len() >= MAX_SEED_ENDPOINTS {
            break;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split "a.b.c.d/n" — bare IPs (no slash) are accepted as /32.
        let (ip_part, _prefix) = match line.split_once('/') {
            Some((ip, _pfx)) => (ip.trim(), Some(())),
            None => (line, None),
        };
        let net: Ipv4Addr = match ip_part.parse() {
            Ok(ip) => ip,
            Err(_) => continue, // FIX(WP0.2): skip invalid lines silently
        };
        // First usable = network + 1 (e.g. 104.16.0.0/24 → 104.16.0.1).
        // For a /32 host address the address itself is usable.
        let first = if line.contains('/') {
            let n = u32::from(net).wrapping_add(1);
            Ipv4Addr::from(n)
        } else {
            net
        };
        let entry = (first.to_string(), 443u16);
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

/// Parse a text file where each non-empty line is a hostname.
/// Lowercase, strip trailing dot, dedupe, cap at 200.
pub fn parse_sni_list(path: &Path) -> Vec<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for raw in text.lines() {
        if out.len() >= MAX_SEED_SNIS {
            break;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut norm = line.to_lowercase();
        while norm.ends_with('.') {
            norm.pop();
        }
        if norm.is_empty() || out.contains(&norm) {
            continue;
        }
        out.push(norm);
    }
    out
}
