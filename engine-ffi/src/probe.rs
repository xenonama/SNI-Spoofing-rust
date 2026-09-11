//! Latency / reachability probes: port of `utils/smart.py` hot paths.
//!
//! Std-only TCP connect timing + minimal TLS ClientHello probing (no new deps).
//! Each endpoint is dialed with `connect_timeout` on its own thread; results
//! are ranked fastest-first. TLS version is extracted from the ServerHello
//! (including TLS 1.3 via `supported_versions`), errors are mapped to short
//! strings (`timeout`, `refused`, ...). SNI ranking dials one endpoint with
//! different SNI values in the ClientHello for per-SNI breakdown.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub endpoint: String,
    pub latency_ms: Option<u128>,
    pub reachable: bool,
    /// Negotiated TLS version, e.g. "TLSv1.3". `None` when the handshake
    /// did not complete (non-TLS port, timeout, alert, ...).
    pub tls_version: Option<String>,
    /// TLS alert code when the server answered with an alert (e.g. 109).
    pub tls_alert: Option<u8>,
    /// Human name for `tls_alert` (see `classify_tls_alert`).
    pub tls_alert_name: Option<String>,
    /// Short error string when unreachable or TLS failed:
    /// "timeout" | "refused" | "unreachable" | "bad address" | ...
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SniProbeResult {
    pub sni: String,
    pub endpoint: String,
    pub latency_ms: Option<u128>,
    pub tls_version: Option<String>,       // "TLSv1.3" | "TLSv1.2" | None
    pub tls_alert: Option<u8>,             // e.g. Some(109)
    pub tls_alert_name: Option<String>,    // e.g. Some("unrecognized_name")
    pub reachable: bool,
    pub error: Option<String>,             // only for real failures (timeout, refused)
}

/// Outcome of one TLS handshake attempt against an endpoint.
/// Exactly one of `version` / `alert_code` / `error` is `Some` in practice:
/// a TLS alert proves the server is alive and speaking TLS, so it is NOT
/// lumped in with transport errors.
#[derive(Debug, Clone, Default)]
pub struct TlsProbe {
    /// Negotiated version, e.g. "TLSv1.3". `Some` ⟺ full handshake.
    pub version: Option<String>,
    /// Alert code when the server answered with a TLS alert (e.g. 109).
    pub alert_code: Option<u8>,
    /// Human name for `alert_code` (see `classify_tls_alert`).
    pub alert_name: Option<String>,
    /// Real transport failure ("timeout", "refused", ...). `None` whenever
    /// the server spoke TLS at all (ServerHello OR alert).
    pub error: Option<String>,
}

// FIX(B2): canonical TLS alert names (RFC 8446 §6). Note 112 is an alias
// some stacks send for unrecognized_name.
pub fn classify_tls_alert(code: u8) -> &'static str {
    match code {
        0   => "close_notify",
        10  => "unexpected_message",
        20  => "bad_record_mac",
        22  => "record_overflow",
        40  => "handshake_failure",
        42  => "bad_certificate",
        43  => "unsupported_certificate",
        44  => "certificate_revoked",
        45  => "certificate_expired",
        46  => "certificate_unknown",
        47  => "illegal_parameter",
        48  => "unknown_ca",
        49  => "access_denied",
        50  => "decode_error",
        51  => "decrypt_error",
        60  => "export_restriction",
        70  => "protocol_version",
        71  => "insufficient_security",
        80  => "internal_error",
        86  => "inappropriate_fallback",
        90  => "user_canceled",
        100 => "no_renegotiation",
        109 => "unrecognized_name",
        110 => "bad_certificate_status_response",
        112 => "unrecognized_name", // alias used by some stacks
        113 => "certificate_required",
        115 => "unknown_psk_identity",
        _   => "tls_alert",
    }
}

/// Probe all `ip:port` endpoints concurrently (one thread each).
/// Never panics; unreachable entries get `latency_ms=None` + `error`.
pub fn probe_endpoints(endpoints: &[String], timeout: Duration) -> Vec<ProbeResult> {
    let mut handles = vec![];
    for ep in endpoints {
        let ep = ep.clone();
        handles.push(std::thread::spawn(move || probe_one_endpoint(&ep, timeout)));
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

fn probe_one_endpoint(ep: &str, timeout: Duration) -> ProbeResult {
    let addr: SocketAddr = match ep.parse() {
        Ok(a) => a,
        Err(_) => {
            return ProbeResult {
                endpoint: ep.to_string(),
                latency_ms: None,
                reachable: false,
                tls_version: None,
                tls_alert: None,
                tls_alert_name: None,
                error: Some("bad address".to_string()),
            }
        }
    };
    // --- TCP RTT (accurate connect timing) ---
    let start = Instant::now();
    let tcp_ok = TcpStream::connect_timeout(&addr, timeout).is_ok();
    let rtt = start.elapsed().as_millis();
    if !tcp_ok {
        // Re-dial to classify the error string (cheap, same timeout).
        let err = classify_connect_error(&addr, timeout);
        return ProbeResult {
            endpoint: ep.to_string(),
            latency_ms: None,
            reachable: false,
            tls_version: None,
            tls_alert: None,
            tls_alert_name: None,
            error: Some(err),
        };
    }
    // --- TLS version (best-effort, fresh connection) ---
    // Use a generic SNI for endpoint ranking; per-SNI detail lives in probe_snis.
    // FIX(B): an alert is classified, not an error — the server is alive.
    let t = detect_tls_version(addr, "example.com", timeout);
    ProbeResult {
        endpoint: ep.to_string(),
        latency_ms: Some(rtt),
        reachable: true,
        tls_version: t.version,
        tls_alert: t.alert_code,
        tls_alert_name: t.alert_name,
        error: t.error,
    }
}

/// Per-SNI breakdown: dial `endpoint` once per SNI with that SNI in the
/// ClientHello, measuring time-to-ServerHello + negotiated version.
/// `snis` capped by caller (GUI passes <= 32).
pub fn probe_snis(snis: &[String], endpoint: &str, timeout: Duration) -> Vec<SniProbeResult> {
    let addr: Option<SocketAddr> = endpoint.parse().ok();
    let mut handles = vec![];
    for sni in snis {
        let sni = sni.clone();
        let ep = endpoint.to_string();
        let a = addr;
        handles.push(std::thread::spawn(move || {
            let Some(a) = a else {
                return SniProbeResult {
                    sni,
                    endpoint: ep,
                    latency_ms: None,
                    tls_version: None,
                    tls_alert: None,
                    tls_alert_name: None,
                    reachable: false,
                    error: Some("bad endpoint".to_string()),
                };
            };
            let start = Instant::now();
            let t = detect_tls_version(a, &sni, timeout);
            let ms = start.elapsed().as_millis();
            // FIX(B): a TLS alert proves the server is alive and speaking TLS
            // (e.g. alert 109 = SNI rejected) — for SNI probing that counts as
            // a response, not a failure.
            let alive = t.version.is_some() || t.alert_code.is_some();
            SniProbeResult {
                sni,
                endpoint: ep,
                latency_ms: if alive { Some(ms) } else { None },
                tls_version: t.version,
                tls_alert: t.alert_code,
                tls_alert_name: t.alert_name,
                reachable: alive,
                error: t.error,
            }
        }));
    }
    let mut out: Vec<SniProbeResult> = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .collect();
    // Full handshakes first, then alert responses (server alive), then
    // failures; fastest first inside each band (mirrors smart.rank).
    out.sort_by(|a, b| {
        let rank = |r: &SniProbeResult| {
            if r.tls_version.is_some() {
                0
            } else if r.tls_alert.is_some() {
                1
            } else {
                2
            }
        };
        (rank(a), a.latency_ms, &a.sni).cmp(&(rank(b), b.latency_ms, &b.sni))
    });
    out
}

fn classify_connect_error(addr: &SocketAddr, timeout: Duration) -> String {
    match TcpStream::connect_timeout(addr, timeout) {
        Ok(_) => "ok".to_string(),
        Err(e) => io_error_string(&e),
    }
}

pub(crate) fn io_error_string(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => "timeout".to_string(),
        ConnectionRefused => "refused".to_string(),
        HostUnreachable | NetworkUnreachable | NetworkDown => "unreachable".to_string(),
        ConnectionReset => "reset".to_string(),
        ConnectionAborted => "aborted".to_string(),
        AddrNotAvailable | InvalidInput | InvalidData => "bad address".to_string(),
        UnexpectedEof => "closed".to_string(),
        _ => {
            let s = e.to_string().to_lowercase();
            if s.contains("timed out") || s.contains("timeout") {
                "timeout".to_string()
            } else if s.contains("refused") {
                "refused".to_string()
            } else if s.contains("certificate") || s.contains("tls") || s.contains("ssl") {
                format!("certificate error ({})", truncate(&s, 48))
            } else {
                truncate(&s, 64)
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

// ---------------------------------------------------------------------------
// Minimal TLS ClientHello / ServerHello parsing (std-only, no new deps)
// ---------------------------------------------------------------------------

fn is_dns_name(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    !s.is_empty() && s.contains('.') && !s.contains(' ') && !s.contains('/') && s.len() <= 253
}

/// Build a minimal TLS record carrying a ClientHello offering TLS 1.3/1.2.
/// Lengths are computed, so the encoding is always self-consistent.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(256);
    body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2 (compat)

    // random: 32 bytes derived from wall-clock (no rand dep needed).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9ABC_DEF0);
    for i in 0..32u32 {
        let b = ((now >> ((i % 8) * 8)) as u8)
            .wrapping_add(i as u8)
            .wrapping_mul(31)
            .wrapping_add(0xA5);
        body.push(b);
    }
    body.push(0x00); // session_id_len = 0

    // cipher_suites (10 modern suites incl. TLS 1.3 + ECDHE/GCM).
    let suites: [u16; 10] = [
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC030, 0x009E, 0x009C, 0x003C, 0x003D,
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.push(0x01); // compression_methods_len
    body.push(0x00); // null

    // --- extensions ---
    let mut exts: Vec<u8> = Vec::new();
    // server_name (SNI) — DNS names only.
    if is_dns_name(sni) {
        let name = sni.as_bytes();
        let name_len = name.len().min(255) as u16;
        let list_len = 1 + 2 + name_len as usize; // type(1) + len(2) + name
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&[0x00, 0x00]); // ext_type = server_name
        e.extend_from_slice(&((2 + list_len) as u16).to_be_bytes());
        e.extend_from_slice(&(list_len as u16).to_be_bytes());
        e.push(0x00); // host_name
        e.extend_from_slice(&name_len.to_be_bytes());
        e.extend_from_slice(&name[..name_len as usize]);
        exts.extend_from_slice(&e);
    }
    // supported_versions = [TLS1.3, TLS1.2]
    {
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&[0x00, 0x2B]);
        e.extend_from_slice(&[0x00, 0x05]);
        e.push(0x04); // versions byte-len
        e.extend_from_slice(&[0x03, 0x04, 0x03, 0x03]);
        exts.extend_from_slice(&e);
    }
    // supported_groups = x25519, secp256r1, secp384r1
    {
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&[0x00, 0x0A]);
        e.extend_from_slice(&[0x00, 0x08]);
        e.extend_from_slice(&[0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x1E]);
        exts.extend_from_slice(&e);
    }
    // signature_algorithms = ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
    {
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(&[0x00, 0x0D]);
        e.extend_from_slice(&[0x00, 0x08]);
        e.extend_from_slice(&[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);
        exts.extend_from_slice(&e);
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // handshake message: ClientHello(1) + uint24 length + body
    let mut hs: Vec<u8> = Vec::with_capacity(4 + body.len());
    hs.push(0x01);
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xFF) as u8);
    hs.push(((blen >> 8) & 0xFF) as u8);
    hs.push((blen & 0xFF) as u8);
    hs.extend_from_slice(&body);

    // record: Handshake(22) + legacy version 0x0301 + uint16 length + hs
    let mut rec: Vec<u8> = Vec::with_capacity(5 + hs.len());
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Open a fresh connection, send `build_client_hello(sni)`, parse ServerHello.
/// FIX(B): returns a `TlsProbe` — a TLS alert is classified via
/// `classify_tls_alert` instead of being flattened into `error`.
fn detect_tls_version(addr: SocketAddr, sni: &str, timeout: Duration) -> TlsProbe {
    let err = |s: String| TlsProbe {
        error: Some(s),
        ..Default::default()
    };
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => return err(io_error_string(&e)),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let hello = build_client_hello(sni);
    if let Err(e) = stream.write_all(&hello) {
        return err(io_error_string(&e));
    }
    let mut hdr = [0u8; 5];
    if let Err(e) = stream.read_exact(&mut hdr) {
        return err(io_error_string(&e));
    }
    // TLS Alert (21): the server spoke TLS — classify, don't error out.
    // (Alert 109/112 = SNI rejected: the handshake reached the server.)
    if hdr[0] == 0x15 {
        let mut alert = [0u8; 2];
        if stream.read_exact(&mut alert).is_ok() {
            let code = alert[1];
            return TlsProbe {
                alert_code: Some(code),
                alert_name: Some(classify_tls_alert(code).to_string()),
                ..Default::default()
            };
        }
        return err("tls alert".to_string());
    }
    if hdr[0] != 0x16 {
        return err("non-TLS response".to_string());
    }
    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if rec_len == 0 || rec_len > 16384 {
        return err("bad record".to_string());
    }
    let mut rec = vec![0u8; rec_len];
    if let Err(e) = stream.read_exact(&mut rec) {
        return err(io_error_string(&e));
    }
    if rec.is_empty() || rec[0] != 0x02 {
        return err("no ServerHello".to_string());
    }
    match parse_serverhello_version(&rec) {
        Some(v) => TlsProbe {
            version: Some(v),
            ..Default::default()
        },
        None => err("parse failed".to_string()),
    }
}

/// Parse a ServerHello handshake message (incl. 4-byte hs header).
/// Handles TLS 1.3 via `supported_versions` extension.
fn parse_serverhello_version(msg: &[u8]) -> Option<String> {
    // hs header: type(1) + len(3)
    if msg.len() < 4 + 2 + 32 + 1 + 2 + 1 {
        return None;
    }
    let body = &msg[4..];
    if body.len() < 2 {
        return None;
    }
    let server_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 2 + 32; // version + random
    if body.len() < pos + 1 {
        return None;
    }
    let sess_len = body[pos] as usize;
    pos += 1 + sess_len;
    if body.len() < pos + 2 + 1 {
        return None;
    }
    pos += 2; // cipher_suite
    pos += 1; // compression
    if body.len() < pos + 2 {
        // No extensions: legacy version mapping.
        return Some(tls_version_name(server_version).to_string());
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let end = pos.saturating_add(ext_total).min(body.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        // supported_versions (43): selected_version uint16.
        if ext_type == 0x002B && ext_len >= 2 {
            let selected = u16::from_be_bytes([body[pos], body[pos + 1]]);
            return Some(tls_version_name(selected).to_string());
        }
        pos += ext_len;
    }
    Some(tls_version_name(server_version).to_string())
}

fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "TLSv1.3",
        0x0303 => "TLSv1.2",
        0x0302 => "TLSv1.1",
        0x0301 => "TLSv1.0",
        0x0300 => "SSLv3.0",
        0x0002 => "SSLv2.0",
        _ => "TLS(unknown)",
    }
}
