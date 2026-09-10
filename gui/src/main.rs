//! sni-gui: unified single-executable (GUI + backend in one process).
//!
//! Port of `gui.py` + `main.py` combined. The old two-binary design spawned
//! `sni-backend` as a child and parsed JSON `Snapshot` lines; this binary
//! runs the Tokio relay engine (`worker.rs`) on a background runtime thread
//! and the WinDivert captures on blocking threads (`engine.rs`), all sharing
//! one `Arc<Stats>` that the GUI polls every 500ms.
//!
//! Release builds hide the terminal window (Windows subsystem); debug builds
//! keep it so `--self-test` output is visible. `--self-test` also tries to
//! attach to the parent console so it works from a terminal even in release.

// Hide the console window in release (Windows only). Debug keeps it for
// `--self-test` / driver-hint visibility.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod probe;
mod worker;

use clap::Parser;
use eframe::egui;
use engine::EngineHandle;
use probe::{probe_endpoints, probe_relay, ProbeResult};
use sni_core::{
    config::{self, Config},
    stats::{Snapshot, Stats},
};
use std::{
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    time::Duration,
};
use tracing_subscriber::EnvFilter;

const METHODS: &[&str] = &[
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
const FINGERPRINTS: &[&str] = &[
    "legacy",
    "chrome_120",
    "chrome_124",
    "firefox_122",
    "firefox_124",
    "custom",
];
const QUIC_MODES: &[&str] = &["block", "spoof", "passthrough"];

/// Mirrors the old `backend` CLI (`main.py::parse_args`).
#[derive(Debug, Parser)]
#[command(name = "sni-gui", version, about = "SNI spoofing injector + relay (unified GUI)")]
struct Args {
    /// Path to config.json (default: next to executable)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Log verbosity (mirrors --log-level + SNI_LOG env)
    #[arg(long, default_value = "INFO", value_parser = ["DEBUG", "INFO", "WARNING", "ERROR"])]
    log_level: String,

    /// Offline self-test (no Admin/WinDivert needed), prints JSON and exits
    #[arg(long, default_value_t = false)]
    self_test: bool,
}

fn exe_dir() -> PathBuf {
    // Mirrors `get_exe_dir()`: frozen exe -> exe dir, else file dir.
    match std::env::current_exe() {
        Ok(p) => p.parent().map(|x| x.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
}

/// Single-instance guard per listen port (Windows).
/// Mirrors `CreateMutexW("SNI-Spoofer-Backend-PORT")` + ERROR_ALREADY_EXISTS.
/// The only `unsafe` in this crate, confined here.
#[cfg(windows)]
fn acquire_single_instance(port: u16) -> anyhow::Result<()> {
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateMutexW,
        },
    };
    let name = format!("SNI-Spoofer-Backend-{}\0", port);
    let wide: Vec<u16> = name.encode_utf16().collect();
    // SAFETY: `wide` outlives the call; string copied by OS.
    let res = unsafe { CreateMutexW(None, true, PCWSTR(wide.as_ptr())) };
    match res {
        Ok(handle) => {
            // SAFETY: GetLastError immediately after the call is valid.
            let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            if already {
                return Err(anyhow::anyhow!(
                    "another SNI backend is already running for port {}. Stop it first.",
                    port
                ));
            }
            // Hold until process exit (mirrors Python keeping the handle open).
            std::mem::forget(handle);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("single-instance mutex failed: {:?}", e)),
    }
}

/// Attach to the parent terminal so `--self-test` output is visible even in
/// release (windows_subsystem hides the console otherwise). Best-effort.
#[cfg(windows)]
fn attach_parent_console() {
    use windows::Win32::System::Console::AttachConsole;
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

/// Atomic JSON write (crash-safe): tmp + rename. Mirrors `atomic_write_json`.
fn atomic_write_json(path: &str, value: &serde_json::Value) -> std::io::Result<()> {
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, serde_json::to_string_pretty(value).unwrap_or_default())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    for u in UNITS {
        if v < 1024.0 || *u == "TB" {
            return if *u == "B" {
                format!("{} {}", v as u64, u)
            } else {
                format!("{:.1} {}", v, u)
            };
        }
        v /= 1024.0;
    }
    format!("{:.1} TB", v)
}

/// Strict-parse the endpoints editor (same rules as backend validate).
fn parse_endpoints_text(text: &str) -> Vec<serde_json::Value> {
    text.replace([',', ';'], " ")
        .split_whitespace()
        .take(64)
        .filter_map(|tok| {
            if let Some((ip, port)) = tok.rsplit_once(':') {
                // Guard against "a/b:443"-style garbage: treat as bare host.
                if ip.contains('/') {
                    return Some(serde_json::json!({"ip": tok, "port": 443}));
                }
                let port: u16 = port.trim().parse().ok()?;
                Some(serde_json::json!({"ip": ip.trim(), "port": port}))
            } else {
                Some(serde_json::json!({"ip": tok, "port": 443}))
            }
        })
        .collect()
}

fn parse_snis_text(text: &str) -> Vec<String> {
    text.replace([',', ';'], " ")
        .split_whitespace()
        .take(200)
        .map(|s| s.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Page {
    #[default]
    Bypass,
    Proxy,
    Tools,
}

struct SpooferApp {
    page: Page,
    // Config editor state (mirrors gui.py StringVars).
    listen_host: String,
    listen_port: String,
    endpoints_text: String,
    snis_text: String,
    method: String,
    fingerprint: String,
    quic: String,
    timeout: String,
    maxconn: String,
    // Values present in config.json but not edited in the GUI — carried
    // through so Save never clobbers them.
    extra_fake_delay: f64,
    extra_seq_overlap: u8,
    extra_padding: u8,
    extra_mode: String,
    extra_probe_tries: u32,
    extra_probe_timeout: f64,
    extra_socks_port: u16,
    extra_http_port: u16,
    // Live state polled from the shared Stats (no child pipe anymore).
    stats: Arc<Stats>,
    snap: Option<Snapshot>,
    prev_up: u64,
    prev_down: u64,
    up_rate: f64,
    down_rate: f64,
    // Probes (Smart Tools) — threaded, collected without blocking update().
    probes: Vec<ProbeResult>,
    probe_rx: Option<Receiver<Vec<ProbeResult>>>,
    probing: bool,
    relay_rx: Option<Receiver<bool>>,
    relay_checking: bool,
    relay_health: Option<bool>,
    // Console + engine.
    log: Vec<String>,
    log_tx: Sender<String>,
    log_rx: Receiver<String>,
    engine: Option<EngineHandle>,
    cfg_path: String,
    held_port: Option<u16>,
}

impl SpooferApp {
    fn new_with(stats: Arc<Stats>, cfg_path: String, held_port: Option<u16>) -> Self {
        let (log_tx, log_rx) = mpsc::channel::<String>();
        let mut app = Self {
            page: Page::Bypass,
            listen_host: "0.0.0.0".into(),
            listen_port: "40443".into(),
            endpoints_text: String::new(),
            snis_text: String::new(),
            method: "auto".into(),
            fingerprint: "legacy".into(),
            quic: "block".into(),
            timeout: "2.0".into(),
            maxconn: "200".into(),
            extra_fake_delay: 0.001,
            extra_seq_overlap: 3,
            extra_padding: 0,
            extra_mode: "SNI Only".into(),
            extra_probe_tries: 2,
            extra_probe_timeout: 3.0,
            extra_socks_port: 10808,
            extra_http_port: 10809,
            stats,
            snap: None,
            prev_up: 0,
            prev_down: 0,
            up_rate: 0.0,
            down_rate: 0.0,
            probes: vec![],
            probe_rx: None,
            probing: false,
            relay_rx: None,
            relay_checking: false,
            relay_health: None,
            log: vec!["sni-gui ready (unified single-exe)".into()],
            log_tx,
            log_rx,
            engine: None,
            cfg_path,
            held_port,
        };
        app.reload_config();
        app.push_log(format!("config: {}", app.cfg_path));
        app
    }

    fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > 400 {
            let drain = self.log.len() - 400;
            self.log.drain(..drain);
        }
    }

    fn reload_config(&mut self) {
        let path = std::path::Path::new(&self.cfg_path);
        let Ok(cfg) = config::load(path) else {
            self.push_log(format!("no valid config at {} (using editor defaults)", self.cfg_path));
            return;
        };
        self.apply_config(&cfg);
        self.push_log(format!(
            "reloaded {} ({} endpoint(s), {} SNI(s))",
            self.cfg_path,
            cfg.endpoints.len(),
            cfg.fake_snis.len()
        ));
    }

    fn apply_config(&mut self, cfg: &Config) {
        self.listen_host = cfg.listen_host.clone();
        self.listen_port = cfg.listen_port.to_string();
        self.endpoints_text = cfg
            .endpoints
            .iter()
            .map(|e| format!("{}:{}", e.ip, e.port))
            .collect::<Vec<_>>()
            .join("\n");
        self.snis_text = cfg.fake_snis.join("\n");
        self.method = cfg.bypass_method.clone();
        self.fingerprint = cfg.tls_fingerprint.clone();
        self.quic = cfg.quic_mode.clone();
        self.timeout = cfg.handshake_timeout.to_string();
        self.maxconn = cfg.max_connections.to_string();
        self.extra_fake_delay = cfg.fake_delay;
        self.extra_seq_overlap = cfg.seq_overlap;
        self.extra_padding = cfg.padding_size;
        self.extra_mode = cfg.mode.clone();
        self.extra_probe_tries = cfg.probe_tries;
        self.extra_probe_timeout = cfg.probe_timeout;
        self.extra_socks_port = cfg.socks5_port;
        self.extra_http_port = cfg.http_port;
    }

    /// Build a `Config` from the editor fields, preserving non-edited extras.
    fn build_config(&self) -> Result<Config, String> {
        let endpoints: Vec<serde_json::Value> = parse_endpoints_text(&self.endpoints_text);
        let snis = parse_snis_text(&self.snis_text);
        let val = serde_json::json!({
            "LISTEN_HOST": self.listen_host.trim(),
            "LISTEN_PORT": self.listen_port.trim().parse::<u16>().map_err(|_| "LISTEN_PORT must be 1-65535")?,
            "ENDPOINTS": endpoints,
            "FAKE_SNIS": snis,
            "BYPASS_METHOD": self.method,
            "HANDSHAKE_TIMEOUT": self.timeout.trim().parse::<f64>().map_err(|_| "HANDSHAKE_TIMEOUT must be a number")?,
            "MAX_CONNECTIONS": self.maxconn.trim().parse::<u64>().map_err(|_| "MAX_CONNECTIONS must be a number")?,
            "FAKE_DELAY": self.extra_fake_delay,
            "SEQ_OVERLAP": self.extra_seq_overlap,
            "TLS_FINGERPRINT": self.fingerprint,
            "PADDING_SIZE": self.extra_padding,
            "QUIC_MODE": self.quic,
            "MODE": self.extra_mode,
            "PROBE_TRIES": self.extra_probe_tries,
            "PROBE_TIMEOUT": self.extra_probe_timeout,
            "SOCKS5_PORT": self.extra_socks_port,
            "HTTP_PORT": self.extra_http_port,
        });
        config::migrate(val).map_err(|e| e.to_string())
    }

    fn save_config(&mut self) {
        match self.build_config() {
            Ok(cfg) => {
                if let Err(e) = config::validate(&cfg) {
                    self.push_log(format!("save failed (invalid): {}", e));
                    return;
                }
                // Write back the same JSON shape `config::load` accepts.
                let val = serde_json::json!({
                    "LISTEN_HOST": cfg.listen_host,
                    "LISTEN_PORT": cfg.listen_port,
                    "ENDPOINTS": cfg.endpoints.iter().map(|e| serde_json::json!({"ip": e.ip, "port": e.port})).collect::<Vec<_>>(),
                    "FAKE_SNIS": cfg.fake_snis,
                    "BYPASS_METHOD": cfg.bypass_method,
                    "HANDSHAKE_TIMEOUT": cfg.handshake_timeout,
                    "MAX_CONNECTIONS": cfg.max_connections,
                    "FAKE_DELAY": cfg.fake_delay,
                    "SEQ_OVERLAP": cfg.seq_overlap,
                    "TLS_FINGERPRINT": cfg.tls_fingerprint,
                    "PADDING_SIZE": cfg.padding_size,
                    "QUIC_MODE": cfg.quic_mode,
                    "MODE": cfg.mode,
                    "PROBE_TRIES": cfg.probe_tries,
                    "PROBE_TIMEOUT": cfg.probe_timeout,
                    "SOCKS5_PORT": cfg.socks5_port,
                    "HTTP_PORT": cfg.http_port,
                });
                match atomic_write_json(&self.cfg_path, &val) {
                    Ok(()) => self.push_log(format!("saved {}", self.cfg_path)),
                    Err(e) => self.push_log(format!("save failed: {}", e)),
                }
            }
            Err(e) => self.push_log(format!("save failed: {}", e)),
        }
    }

    fn is_running(&self) -> bool {
        self.engine.as_ref().map(|e| e.is_running()).unwrap_or(false)
    }

    fn start_engine(&mut self) {
        if self.engine.is_some() {
            self.push_log("already running".into());
            return;
        }
        let cfg = match self.build_config() {
            Ok(c) => c,
            Err(e) => {
                self.push_log(format!("start failed: {}", e));
                return;
            }
        };
        if let Err(e) = config::validate(&cfg) {
            self.push_log(format!("start failed (invalid config): {}", e));
            return;
        }
        // Persist what we are about to run (parity with old Save-on-Start).
        self.save_config();
        // Single-instance guard for the new port (skip when unchanged: the
        // mutex is already held by this process and re-acquiring would read
        // ERROR_ALREADY_EXISTS from ourselves).
        #[cfg(windows)]
        {
            if self.held_port != Some(cfg.listen_port) {
                if let Err(e) = acquire_single_instance(cfg.listen_port) {
                    self.push_log(format!("start failed: {}", e));
                    return;
                }
                self.held_port = Some(cfg.listen_port);
            }
        }
        self.push_log("starting engine (Admin + WinDivert required)...".into());
        match EngineHandle::start(cfg, Arc::clone(&self.stats), self.log_tx.clone()) {
            Ok(h) => {
                self.engine = Some(h);
                self.push_log("engine RUNNING".into());
            }
            Err(e) => self.push_log(format!("start failed: {}", e)),
        }
    }

    fn stop_engine(&mut self) {
        if let Some(mut h) = self.engine.take() {
            h.shutdown();
            self.push_log("engine stopped".into());
        } else {
            self.push_log("engine not running".into());
        }
    }

    /// Drain engine log lines + probe results + refresh stats snapshot.
    /// Never blocks `update()`.
    fn poll(&mut self) {
        for _ in 0..64 {
            match self.log_rx.try_recv() {
                Ok(line) => self.push_log(line),
                Err(_) => break,
            }
        }
        if let Some(rx) = self.probe_rx.take() {
            match rx.try_recv() {
                Ok(res) => {
                    let n = res.len();
                    self.probes = res;
                    self.probing = false;
                    self.push_log(format!("probed {} endpoint(s)", n));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.probe_rx = Some(rx);
                }
                Err(_) => {
                    self.probing = false;
                    self.push_log("probe failed (worker died)".into());
                }
            }
        }
        if let Some(rx) = self.relay_rx.take() {
            match rx.try_recv() {
                Ok(ok) => {
                    self.relay_checking = false;
                    self.relay_health = Some(ok);
                    self.push_log(format!(
                        "relay {}:{} {}",
                        self.listen_host,
                        self.listen_port.trim(),
                        if ok { "reachable" } else { "unreachable" }
                    ));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.relay_rx = Some(rx);
                }
                Err(_) => {
                    self.relay_checking = false;
                }
            }
        }
        if self.engine.is_some() {
            let s = self.stats.snapshot();
            if let Some(prev) = self.snap.as_ref() {
                let dt = (s.uptime - prev.uptime).max(0.1);
                self.up_rate = (s.up_bytes.saturating_sub(self.prev_up) as f64) / dt;
                self.down_rate = (s.down_bytes.saturating_sub(self.prev_down) as f64) / dt;
            }
            self.prev_up = s.up_bytes;
            self.prev_down = s.down_bytes;
            self.snap = Some(s);
        }
    }

    fn run_probes(&mut self) {
        if self.probing {
            return;
        }
        self.probing = true;
        let eps: Vec<String> = self
            .endpoints_text
            .replace([',', ';'], " ")
            .split_whitespace()
            .take(16)
            .map(|s| s.to_string())
            .collect();
        if eps.is_empty() {
            self.probing = false;
            self.push_log("no endpoints to probe".into());
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.probe_rx = Some(rx);
        std::thread::Builder::new()
            .name("probe".into())
            .spawn(move || {
                let res = probe_endpoints(&eps, Duration::from_secs(3));
                let _ = tx.send(res);
            })
            .ok();
        self.push_log("probing endpoints in background...".into());
    }

    fn check_relay(&mut self) {
        if self.relay_checking {
            return;
        }
        self.relay_checking = true;
        let host = self.listen_host.trim().to_string();
        let port = self.listen_port.trim().parse::<u16>().unwrap_or(40443);
        let (tx, rx) = mpsc::channel();
        self.relay_rx = Some(rx);
        std::thread::Builder::new()
            .name("relay-health".into())
            .spawn(move || {
                let ok = probe_relay(&host, port);
                let _ = tx.send(ok);
            })
            .ok();
    }
}

impl eframe::App for SpooferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        // Keep polling while running (real-time stats).
        if self.engine.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        } else if self.probing || self.relay_checking {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        let (active, total, ok, fail, rate, best_ep, best_m, up, down) = match &self.snap {
            Some(s) => (
                s.active,
                s.total,
                s.success,
                s.failed,
                s.success_rate,
                s.best_endpoint.clone(),
                s.best_method.clone(),
                s.up_bytes,
                s.down_bytes,
            ),
            None => (0, 0, 0, 0, 0.0, String::new(), String::new(), 0, 0),
        };
        let running = self.is_running() || self.engine.is_some();

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("SNI Spoofer");
                ui.label(format!(" — {}", if running { "RUNNING" } else { "stopped" }));
            });
        });

        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.selectable_value(&mut self.page, Page::Bypass, "DPI Bypass");
            ui.selectable_value(&mut self.page, Page::Proxy, "Proxy-Xray");
            ui.selectable_value(&mut self.page, Page::Tools, "Smart Tools");
            ui.separator();
            ui.label(format!("Active: {}", active));
            ui.label(format!("OK/Fail: {}/{}", ok, fail));
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Bypass => {
                ui.horizontal(|ui| {
                    if self.engine.is_none() {
                        if ui.button("▶ Start").clicked() {
                            self.start_engine();
                        }
                    } else if ui.button("■ Stop").clicked() {
                        self.stop_engine();
                    }
                    if ui.button("💾 Save").clicked() {
                        self.save_config();
                    }
                    if ui.button("↻ Reload").clicked() {
                        self.reload_config();
                    }
                });
                ui.separator();
                egui::Grid::new("stats").num_columns(4).show(ui, |ui| {
                    ui.label("Active:");
                    ui.monospace(active.to_string());
                    ui.label("Total:");
                    ui.monospace(total.to_string());
                    ui.end_row();
                    ui.label("OK / Fail:");
                    ui.monospace(format!("{} / {}", ok, fail));
                    ui.label("Rate:");
                    ui.monospace(format!("{:.1}%", rate * 100.0));
                    ui.end_row();
                    ui.label("Up:");
                    ui.monospace(format!(
                        "{} ({}/s)",
                        human_bytes(up),
                        human_bytes(self.up_rate as u64)
                    ));
                    ui.label("Down:");
                    ui.monospace(format!(
                        "{} ({}/s)",
                        human_bytes(down),
                        human_bytes(self.down_rate as u64)
                    ));
                    ui.end_row();
                    ui.label("Best EP:");
                    ui.monospace(if best_ep.is_empty() { "—" } else { &best_ep });
                    ui.label("Best method:");
                    ui.monospace(if best_m.is_empty() { "—" } else { &best_m });
                    ui.end_row();
                });
                ui.separator();
                egui::Grid::new("cfg").num_columns(2).show(ui, |ui| {
                    ui.label("Listen:");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.listen_host);
                        ui.text_edit_singleline(&mut self.listen_port);
                    });
                    ui.end_row();
                    ui.label("Timeout / MaxConn:");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.timeout);
                        ui.text_edit_singleline(&mut self.maxconn);
                    });
                    ui.end_row();
                    ui.label("Method:");
                    egui::ComboBox::from_id_source("method")
                        .selected_text(&self.method)
                        .show_ui(ui, |ui| {
                            for m in METHODS {
                                ui.selectable_value(&mut self.method, m.to_string(), *m);
                            }
                        });
                    ui.end_row();
                    ui.label("Fingerprint:");
                    egui::ComboBox::from_id_source("fp")
                        .selected_text(&self.fingerprint)
                        .show_ui(ui, |ui| {
                            for f in FINGERPRINTS {
                                ui.selectable_value(&mut self.fingerprint, f.to_string(), *f);
                            }
                        });
                    ui.end_row();
                    ui.label("QUIC:");
                    egui::ComboBox::from_id_source("quic")
                        .selected_text(&self.quic)
                        .show_ui(ui, |ui| {
                            for q in QUIC_MODES {
                                ui.selectable_value(&mut self.quic, q.to_string(), *q);
                            }
                        });
                    ui.end_row();
                });
                ui.label("Endpoints (ip:port per line):");
                ui.text_edit_multiline(&mut self.endpoints_text);
                ui.label("Fake SNIs (one per line):");
                ui.text_edit_multiline(&mut self.snis_text);
                ui.separator();
                ui.label("Console:");
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.monospace(line);
                        }
                    });
            }
            Page::Proxy => {
                ui.heading("Proxy-Xray (Trojan + Xray)");
                ui.label("xray.exe supervision is manual: set MODE=Trojan + Xray via config.json.full.json, then launch xray.exe yourself.");
                ui.label("In Trojan + Xray mode the QUIC injector passes HTTP/3 through.");
                ui.separator();
                ui.monospace(format!(
                    "SOCKS5 :{}   HTTP :{}  (from config)",
                    self.extra_socks_port, self.extra_http_port
                ));
            }
            Page::Tools => {
                ui.heading("Smart Tools");
                ui.horizontal(|ui| {
                    if ui.button("⚡ Rank endpoints").clicked() {
                        self.run_probes();
                    }
                    if ui.button("✓ Use fastest").clicked() {
                        if let Some(first) = self.probes.iter().find(|p| p.reachable) {
                            self.endpoints_text = first.endpoint.clone();
                            self.push_log(format!("using fastest: {}", first.endpoint));
                        } else {
                            self.push_log("no reachable endpoint to use".into());
                        }
                    }
                    if ui.button("♥ Relay health").clicked() {
                        self.check_relay();
                    }
                });
                if self.probing {
                    ui.label("probing...");
                }
                if self.relay_checking {
                    ui.label("checking relay...");
                }
                if let Some(h) = self.relay_health {
                    ui.label(format!("Relay health: {}", if h { "OK" } else { "unreachable" }));
                }
                ui.separator();
                egui::Grid::new("probes").num_columns(3).show(ui, |ui| {
                    ui.label("Endpoint");
                    ui.label("Latency");
                    ui.label("Status");
                    ui.end_row();
                    for p in &self.probes {
                        ui.monospace(&p.endpoint);
                        ui.monospace(match p.latency_ms {
                            Some(ms) => format!("{} ms", ms),
                            None => "—".into(),
                        });
                        ui.monospace(if p.reachable { "OK" } else { "FAIL" });
                        ui.end_row();
                    }
                    if self.probes.is_empty() {
                        ui.label("—");
                        ui.label("press Rank");
                        ui.label("—");
                        ui.end_row();
                    }
                });
            }
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_engine();
    }
}

fn main() -> eframe::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(format!(
            "warn,sni_gui={},sni_core={},sni_windivert={}",
            args.log_level.to_lowercase(),
            args.log_level.to_lowercase(),
            args.log_level.to_lowercase()
        )))
        .with_target(false)
        .compact()
        .init();

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| exe_dir().join("config.json"));

    if args.self_test {
        #[cfg(windows)]
        attach_parent_console();
        // Offline suite (no Admin/WinDivert): mirrors run_self_test JSON shape.
        let (ok, report) = sni_core::selftest::run(&config_path);
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Single-instance guard before opening the GUI (Windows only).
    // Best-effort port read: fall back to 40443 when the config is missing;
    // the exact port is re-guarded on Start.
    let port = config::load(&config_path).map(|c| c.listen_port).unwrap_or(40443);
    #[cfg(windows)]
    if let Err(e) = acquire_single_instance(port) {
        eprintln!("FATAL: {}", e);
        std::process::exit(2);
    }

    // NOTE: no WinDivert pre-flight here (unlike the old backend): the GUI
    // must open even without Admin so the user can edit config / run Smart
    // Tools. Driver errors surface in the console on Start instead.
    let stats = Arc::new(Stats::new());
    let cfg_path = config_path.display().to_string();

    // Privacy parity: never log raw SNIs/endpoints — counts only.
    if let Ok(cfg) = config::load(&config_path) {
        println!("Fake SNIs: {} configured", cfg.fake_snis.len());
        println!("Endpoints: {} configured", cfg.endpoints.len());
        println!(
            "Bypass method: {} (timeout={}s, max_conn={})",
            cfg.bypass_method, cfg.handshake_timeout, cfg.max_connections
        );
    }

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "SNI Spoofer",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(SpooferApp::new_with(stats, cfg_path, Some(port))) as Box<dyn eframe::App>)
        }),
    )
}
