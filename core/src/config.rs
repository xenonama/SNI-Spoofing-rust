//! Config schema: replaces `utils/config_manager.py` + `main.py::load_config`.
//!
//! Python `migrate()` = fill defaults + derive ENDPOINTS/FAKE_SNIS from
//! legacy single values. Python `validate()` = range/shape checks.
//! Rust splits this into typed `Config` + `ConfigError` (no exceptions).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_SNIS: usize = 200;
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

pub const SUPPORTED_METHODS: &[&str] = &[
    "auto",
    "wrong_seq",
    "wrong_seq_ttl",
    "split_seq",
    "fragmented",
    "padding",
    "delayed_retry",
    "double_sni",
    "hostfakesplit",
    "fakedsplit",
];

pub const SUPPORTED_FINGERPRINTS: &[&str] = &[
    "legacy",
    "chrome_120",
    "chrome_124",
    "firefox_122",
    "firefox_124",
    "custom",
];

pub const SUPPORTED_QUIC_MODES: &[&str] = &["block", "spoof", "passthrough"];
pub const SUPPORTED_MODES: &[&str] = &["SNI Only", "Trojan + Xray"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_host: String,
    pub listen_port: u16,
    pub endpoints: Vec<Endpoint>,
    pub fake_snis: Vec<String>,
    pub bypass_method: String,
    pub handshake_timeout: f64,
    pub max_connections: usize,
    pub fake_delay: f64,
    pub seq_overlap: u8,
    pub tls_fingerprint: String,
    pub padding_size: u8,
    pub quic_mode: String,
    pub mode: String,
    // GUI extras (live in config.json.full.json on Python side).
    #[serde(default = "default_probe_tries")]
    pub probe_tries: u32,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout: f64,
    #[serde(default = "default_socks_port")]
    pub socks5_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
}

fn default_probe_tries() -> u32 {
    2
}
fn default_probe_timeout() -> f64 {
    3.0
}
fn default_socks_port() -> u16 {
    10808
}
fn default_http_port() -> u16 {
    10809
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // FIX(WP0.1): loopback-only by default; the user can still type
            // "0.0.0.0" to expose the relay on LAN (validation allows it).
            listen_host: "127.0.0.1".to_string(),
            listen_port: 40443,
            endpoints: vec![],
            fake_snis: vec![],
            bypass_method: "auto".to_string(),
            handshake_timeout: 2.0,
            max_connections: 200,
            fake_delay: 0.001,
            seq_overlap: 3,
            tls_fingerprint: "legacy".to_string(),
            padding_size: 0,
            quic_mode: "block".to_string(),
            mode: "SNI Only".to_string(),
            probe_tries: 2,
            probe_timeout: 3.0,
            socks5_port: 10808,
            http_port: 10809,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config file: {0}")]
    Parse(String),
    #[error("config validation failed: {0}")]
    Validation(String),
}

/// Load `config.json` + merge `config.json.full.json` (Python parity).
///
/// Rules (mirrors `main.py::load_config` + `config_manager::load`):
/// - `config.json` wins; `.full.json` only fills missing keys (e.g. MODE).
/// - Size-capped read (MAX_CONFIG_BYTES). Root must be a JSON object.
/// - Legacy `CONNECT_IP`/`CONNECT_PORT` and `FAKE_SNI` derive the lists.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let raw = read_capped_json(path)?;
    let merged = merge_full_json(path, raw);
    let cfg = migrate(merged)?;
    validate(&cfg)?;
    Ok(cfg)
}

fn read_capped_json(path: &Path) -> Result<serde_json::Value, ConfigError> {
    let meta = std::fs::metadata(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Parse(format!(
            "config larger than {} bytes",
            MAX_CONFIG_BYTES
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    if !v.is_object() {
        return Err(ConfigError::Parse(
            "config root must be a JSON object".to_string(),
        ));
    }
    Ok(v)
}

fn merge_full_json(path: &Path, mut base: serde_json::Value) -> serde_json::Value {
    // `<path>.full.json` — same convention as Python (`path + ".full.json"`).
    let full_path = format!("{}.full.json", path.display());
    let text = match std::fs::read_to_string(&full_path) {
        Ok(t) => t,
        Err(_) => return base,
    };
    let extra: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return base,
    };
    let base_obj = match base.as_object_mut() {
        Some(o) => o,
        None => return base,
    };
    if let Some(extra_obj) = extra.as_object() {
        for (k, v) in extra_obj {
            base_obj.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    base
}

/// Fill defaults + normalize legacy keys. Mirrors `config_manager.migrate()`.
pub fn migrate(v: serde_json::Value) -> Result<Config, ConfigError> {
    let mut cfg = Config::default();
    let obj = v.as_object().cloned().unwrap_or_default();

    let get_str = |key: &str| -> Option<String> {
        obj.get(key)
            .and_then(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
    };
    let get_u16 = |key: &str| -> Option<u16> {
        obj.get(key).and_then(|x| {
            x.as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .or_else(|| x.as_str()?.trim().parse::<u16>().ok())
        })
    };
    let get_f64 = |key: &str| -> Option<f64> {
        obj.get(key).and_then(|x| {
            x.as_f64().or_else(|| {
                x.as_str()
                    .and_then(|s| s.trim().parse::<f64>().ok())
                    .or_else(|| x.as_u64().map(|n| n as f64))
            })
        })
    };

    if let Some(s) = get_str("LISTEN_HOST") {
        cfg.listen_host = s;
    }
    if let Some(p) = get_u16("LISTEN_PORT") {
        cfg.listen_port = p;
    }
    // Endpoints: ENDPOINTS[] else CONNECT_IP/CONNECT_PORT fallback.
    let mut endpoints: Vec<Endpoint> = vec![];
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    if let Some(arr) = obj.get("ENDPOINTS").and_then(|x| x.as_array()) {
        let default_port = get_u16("CONNECT_PORT").unwrap_or(443);
        for e in arr {
            let (ip, port) = if let Some(o) = e.as_object() {
                let ip = o
                    .get("ip")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let port = o
                    .get("port")
                    .and_then(|x| {
                        x.as_u64()
                            .and_then(|n| u16::try_from(n).ok())
                            .or_else(|| x.as_str()?.trim().parse::<u16>().ok())
                    })
                    .unwrap_or(default_port);
                (ip, port)
            } else if let Some(s) = e.as_str() {
                // Tolerate "ip:port" strings (backend compat).
                let s = s.trim();
                if let Some((a, b)) = s.rsplit_once(':') {
                    if !a.contains('/') {
                        match b.trim().parse::<u16>() {
                            Ok(p) => (a.trim().to_string(), p),
                            Err(_) => (s.to_string(), default_port),
                        }
                    } else {
                        (s.to_string(), default_port)
                    }
                } else {
                    (s.to_string(), default_port)
                }
            } else {
                continue;
            };
            if ip.is_empty() || !seen.insert((ip.clone(), port)) {
                continue;
            }
            endpoints.push(Endpoint { ip, port });
        }
    }
    if endpoints.is_empty() {
        if let Some(ip) = get_str("CONNECT_IP") {
            let port = get_u16("CONNECT_PORT").unwrap_or(443);
            endpoints.push(Endpoint { ip, port });
        }
    }
    cfg.endpoints = endpoints;

    // SNIs: FAKE_SNIS[] else FAKE_SNI fallback. Lowercase, strip trailing dot.
    let mut snis: Vec<String> = vec![];
    let mut seen_sni: HashSet<String> = HashSet::new();
    if let Some(arr) = obj.get("FAKE_SNIS").and_then(|x| x.as_array()) {
        for s in arr {
            if let Some(raw) = s.as_str() {
                let mut norm = raw.trim().to_lowercase();
                if norm.ends_with('.') {
                    norm.pop();
                }
                if !norm.is_empty() && seen_sni.insert(norm.clone()) {
                    snis.push(norm);
                }
            }
        }
    }
    if snis.is_empty() {
        if let Some(s) = get_str("FAKE_SNI").or_else(|| get_str("FAKE_SNIS")) {
            let mut norm = s.trim().to_lowercase();
            if norm.ends_with('.') {
                norm.pop();
            }
            if !norm.is_empty() {
                snis.push(norm);
            }
        }
    }
    cfg.fake_snis = snis;

    if let Some(m) = get_str("BYPASS_METHOD") {
        cfg.bypass_method = m;
    }
    if let Some(t) = get_f64("HANDSHAKE_TIMEOUT") {
        cfg.handshake_timeout = t;
    }
    if let Some(m) = obj.get("MAX_CONNECTIONS").and_then(|x| {
        x.as_u64()
            .map(|n| n as usize)
            .or_else(|| x.as_str()?.trim().parse::<usize>().ok())
    }) {
        cfg.max_connections = m;
    }
    if let Some(d) = get_f64("FAKE_DELAY") {
        cfg.fake_delay = d;
    }
    if let Some(o) = obj.get("SEQ_OVERLAP").and_then(|x| {
        x.as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .or_else(|| x.as_str()?.trim().parse::<u8>().ok())
    }) {
        cfg.seq_overlap = o.min(16);
    }
    if let Some(f) = get_str("TLS_FINGERPRINT") {
        cfg.tls_fingerprint = f.to_lowercase();
    }
    if let Some(p) = obj.get("PADDING_SIZE").and_then(|x| {
        x.as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .or_else(|| x.as_str()?.trim().parse::<u8>().ok())
    }) {
        cfg.padding_size = p;
    }
    if let Some(q) = get_str("QUIC_MODE") {
        cfg.quic_mode = q.to_lowercase();
    }
    if let Some(m) = get_str("MODE") {
        cfg.mode = m;
    }
    if let Some(n) = obj
        .get("PROBE_TRIES")
        .and_then(|x| x.as_u64().map(|v| v as u32))
    {
        cfg.probe_tries = n;
    }
    if let Some(t) = get_f64("PROBE_TIMEOUT") {
        cfg.probe_timeout = t;
    }
    if let Some(p) = get_u16("SOCKS5_PORT") {
        cfg.socks5_port = p;
    }
    if let Some(p) = get_u16("HTTP_PORT") {
        cfg.http_port = p;
    }
    Ok(cfg)
}

/// Strict checks. Mirrors `config_manager.validate()` + `main.load_config` ranges.
pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let mut errs: Vec<String> = vec![];
    if cfg.listen_host != "0.0.0.0" && !is_valid_ipv4(&cfg.listen_host) {
        errs.push(format!("LISTEN_HOST invalid: {}", truncate(&cfg.listen_host, 64)));
    }
    if cfg.listen_port == 0 {
        errs.push("LISTEN_PORT must be 1-65535".to_string());
    }
    if cfg.endpoints.is_empty() {
        errs.push("No endpoints (set CONNECT_IP or ENDPOINTS)".to_string());
    } else if cfg.endpoints.len() > MAX_ENDPOINTS {
        errs.push(format!("Too many endpoints (max {})", MAX_ENDPOINTS));
    } else {
        for e in &cfg.endpoints {
            if !is_valid_ipv4(&e.ip) {
                errs.push(format!("Bad endpoint IP: {}", truncate(&e.ip, 64)));
            }
            if e.port == 0 {
                errs.push(format!("Bad endpoint port for {}", truncate(&e.ip, 32)));
            }
        }
    }
    if cfg.fake_snis.is_empty() {
        errs.push("No FAKE_SNI set".to_string());
    } else if cfg.fake_snis.len() > MAX_SNIS {
        errs.push(format!("Too many SNIs (max {})", MAX_SNIS));
    } else {
        for s in &cfg.fake_snis {
            if !is_valid_sni(s) {
                errs.push(format!("Bad SNI: {}", truncate(s, 64)));
            }
        }
    }
    if !SUPPORTED_METHODS.contains(&cfg.bypass_method.as_str()) {
        errs.push(format!("BYPASS_METHOD must be one of {:?}", SUPPORTED_METHODS));
    }
    if !(0.5..=10.0).contains(&cfg.handshake_timeout) {
        errs.push("HANDSHAKE_TIMEOUT should be 0.5..10s".to_string());
    }
    if !(10..=2000).contains(&cfg.max_connections) {
        errs.push("MAX_CONNECTIONS should be 10..2000".to_string());
    }
    if !(0.0..=5.0).contains(&cfg.fake_delay) {
        errs.push("FAKE_DELAY should be 0..5s".to_string());
    }
    if cfg.seq_overlap > 16 {
        errs.push("SEQ_OVERLAP should be 0..16".to_string());
    }
    if !SUPPORTED_FINGERPRINTS.contains(&cfg.tls_fingerprint.as_str()) {
        errs.push(format!(
            "TLS_FINGERPRINT must be one of {:?}",
            SUPPORTED_FINGERPRINTS
        ));
    }
    if !SUPPORTED_QUIC_MODES.contains(&cfg.quic_mode.as_str()) {
        errs.push(format!(
            "QUIC_MODE must be one of {:?}",
            SUPPORTED_QUIC_MODES
        ));
    }
    if !SUPPORTED_MODES.contains(&cfg.mode.as_str()) {
        errs.push(format!("MODE must be one of {:?}", SUPPORTED_MODES));
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Validation(errs.join("; ")))
    }
}

pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u8>().is_ok()
    })
}

pub fn is_valid_sni(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.contains('.') && !s.contains(' ') && !s.contains('/') && s.len() <= 253
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
