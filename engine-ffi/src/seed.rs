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
        // FIX 5: parse the /prefix correctly — compute network = ip & mask,
        // then first usable per RFC (32 → itself, 31 → network per RFC 3021,
        // <=30 → network + 1). Bare IPs behave as /32. Invalid prefixes are
        // skipped silently.
        // Split "a.b.c.d/n" — bare IPs (no slash) are accepted as /32.
        let (ip_part, prefix): (&str, u8) = match line.split_once('/') {
            Some((ip, pfx)) => {
                let p: u8 = match pfx.trim().parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if p > 32 {
                    continue;
                }
                (ip.trim(), p)
            }
            None => (line, 32),
        };
        let addr: Ipv4Addr = match ip_part.parse() {
            Ok(ip) => ip,
            Err(_) => continue, // FIX(WP0.2): skip invalid lines silently
        };
        let ip_u32 = u32::from(addr);
        let mask: u32 = if prefix == 0 {
            0
        } else {
            (!0u32) << (32 - prefix)
        };
        let network = ip_u32 & mask;
        // First usable = network + 1 (e.g. 104.16.0.0/24 → 104.16.0.1).
        // For a /32 host address the address itself is usable.
        let first = if prefix == 32 {
            addr
        } else if prefix == 31 {
            Ipv4Addr::from(network)
        } else {
            Ipv4Addr::from(network.wrapping_add(1))
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
