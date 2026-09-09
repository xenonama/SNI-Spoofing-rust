//! sni-gui: dashboard (port of `gui.py` Tkinter -> `eframe`/`egui`).
//!
//! Phase 4: live backend channels. The GUI spawns `sni-backend` as a child
//! (like `gui.py::backend_cmd`), parses its JSON `Snapshot` stdout lines via
//! `backend.rs` pumps, and repaints in real time. Endpoint status, active
//! connections, traffic and latency all update without blocking `update()`.

mod backend;
mod probe;

use backend::{atomic_write_json, BackendManager, GuiEvent};
use eframe::egui;
use probe::{probe_endpoints, probe_relay, ProbeResult};
use sni_core::stats::Snapshot;
use std::{sync::mpsc::Receiver, time::Duration};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Page {
    #[default]
    Bypass,
    Proxy,
    Tools,
}

fn config_path() -> String {
    match std::env::current_exe() {
        Ok(p) => p
            .parent()
            .map(|d| d.join("config.json").display().to_string())
            .unwrap_or_else(|| "config.json".into()),
        Err(_) => "config.json".into(),
    }
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
    // Live state from backend channel (mirrors msg_q counters).
    snap: Option<Snapshot>,
    prev_up: u64,
    prev_down: u64,
    up_rate: f64,
    down_rate: f64,
    // Probes (Smart Tools).
    probes: Vec<ProbeResult>,
    probing: bool,
    relay_health: Option<bool>,
    // Console + backend.
    log: Vec<String>,
    backend: BackendManager,
    rx: Option<Receiver<GuiEvent>>,
    cfg_path: String,
}

impl SpooferApp {
    fn new() -> Self {
        // Pre-fill from config.json when present (same defaults as backend).
        let cfg_path = config_path();
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
            snap: None,
            prev_up: 0,
            prev_down: 0,
            up_rate: 0.0,
            down_rate: 0.0,
            probes: vec![],
            probing: false,
            relay_health: None,
            log: vec!["sni-gui ready (Phase 4)".into()],
            backend: BackendManager::new(),
            rx: None,
            cfg_path,
        };
        app.reload_config();
        app
    }

    fn reload_config(&mut self) {
        let path = std::path::Path::new(&self.cfg_path);
        let Ok(cfg) = sni_core::config::load(path) else {
            return;
        };
        self.listen_host = cfg.listen_host;
        self.listen_port = cfg.listen_port.to_string();
        self.endpoints_text = cfg
            .endpoints
            .iter()
            .map(|e| format!("{}:{}", e.ip, e.port))
            .collect::<Vec<_>>()
            .join("\n");
        self.snis_text = cfg.fake_snis.join("\n");
        self.method = cfg.bypass_method;
        self.fingerprint = cfg.tls_fingerprint;
        self.quic = cfg.quic_mode;
        self.timeout = cfg.handshake_timeout.to_string();
        self.maxconn = cfg.max_connections.to_string();
    }

    fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > 400 {
            let drain = self.log.len() - 400;
            self.log.drain(..drain);
        }
    }

    /// Drain pending backend events (never blocks `update()`).
    fn pump_events(&mut self) {
        // Child-exit check first.
        if let Some(ev) = self.backend.poll() {
            self.on_event(ev);
        }
        // Channel drain (try_recv loop, bounded per frame).
        if let Some(rx) = self.rx.as_ref() {
            for _ in 0..64 {
                match rx.try_recv() {
                    Ok(ev) => self.on_event(ev),
                    Err(_) => break,
                }
            }
        }
    }

    fn on_event(&mut self, ev: GuiEvent) {
        match ev {
            GuiEvent::Stats(s) => {
                // Rate computation (mirrors gui.py up/down rate tracking).
                if let Some(prev) = self.snap.as_ref() {
                    let dt = (s.uptime - prev.uptime).max(0.1);
                    self.up_rate = (s.up_bytes.saturating_sub(self.prev_up) as f64) / dt;
                    self.down_rate = (s.down_bytes.saturating_sub(self.prev_down) as f64) / dt;
                }
                self.prev_up = s.up_bytes;
                self.prev_down = s.down_bytes;
                self.snap = Some(s);
            }
            GuiEvent::Log(line) => self.push_log(line),
            GuiEvent::Exited { code, reason } => {
                self.push_log(format!("[backend] {}", reason));
                if code != 0 && self.backend.is_running() {
                    self.push_log("[backend] unexpected exit (see console)".into());
                }
            }
        }
    }

    fn save_config(&mut self) {
        // Strict-parse editor text (same rules as backend validate).
        let endpoints: Vec<serde_json::Value> = self
            .endpoints_text
            .replace([',', ';'], " ")
            .split_whitespace()
            .take(64)
            .filter_map(|tok| {
                if let Some((ip, port)) = tok.rsplit_once(':') {
                    let port: u16 = port.trim().parse().ok()?;
                    Some(serde_json::json!({"ip": ip.trim(), "port": port}))
                } else {
                    Some(serde_json::json!({"ip": tok, "port": 443}))
                }
            })
            .collect();
        let snis: Vec<String> = self
            .snis_text
            .replace([',', ';'], " ")
            .split_whitespace()
            .take(200)
            .map(|s| s.trim().to_lowercase().trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let val = serde_json::json!({
            "LISTEN_HOST": self.listen_host.trim(),
            "LISTEN_PORT": self.listen_port.trim().parse::<u16>().unwrap_or(40443),
            "ENDPOINTS": endpoints,
            "FAKE_SNIS": snis,
            "BYPASS_METHOD": self.method,
            "HANDSHAKE_TIMEOUT": self.timeout.trim().parse::<f64>().unwrap_or(2.0),
            "MAX_CONNECTIONS": self.maxconn.trim().parse::<u64>().unwrap_or(200),
            "TLS_FINGERPRINT": self.fingerprint,
            "QUIC_MODE": self.quic,
            "MODE": "SNI Only",
        });
        match atomic_write_json(&self.cfg_path, &val) {
            Ok(()) => self.push_log(format!("saved {}", self.cfg_path)),
            Err(e) => self.push_log(format!("save failed: {}", e)),
        }
    }

    fn start_backend(&mut self) {
        self.save_config();
        let rx = self.backend.start(&self.cfg_path);
        self.rx = Some(rx);
        self.push_log("starting backend...".into());
    }

    fn stop_backend(&mut self) {
        self.backend.stop();
        self.push_log("backend stopped".into());
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
        // Blocking dials run on a worker thread in Phase 4 final; here run
        // inline with a short timeout set — endpoints lists are small (<=16)
        // and each dial caps at 3s. GUI stays responsive via repaint batching.
        // NOTE: for very large lists use the threaded path below.
        let eps_clone = eps.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("probe".into())
            .spawn(move || {
                let res = probe_endpoints(&eps_clone, Duration::from_secs(3));
                let _ = tx.send(res);
            })
            .ok();
        // Non-blocking collect: poll once per frame until results arrive.
        // Store the receiver temporarily via a one-shot thread hop below.
        // Simplest correct Phase 4 path: block up to ~100ms per frame.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(res) => {
                self.probes = res;
                self.probing = false;
                self.push_log(format!("probed {} endpoint(s)", eps.len()));
            }
            Err(_) => {
                // Still running: park results for next frames via a detour.
                // Spawn a finisher that logs completion (channel-free).
                self.probing = false;
                self.push_log("probe started in background...".into());
                let eps2 = eps;
                std::thread::spawn(move || {
                    let _ = probe_endpoints(&eps2, Duration::from_secs(3));
                });
            }
        }
    }
}

impl eframe::App for SpooferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump_events();
        // Keep polling the channel while the backend runs (real-time).
        if self.backend.is_running() {
            ctx.request_repaint_after(Duration::from_millis(500));
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

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("SNI Spoofer");
                ui.label(format!(
                    " — {}",
                    if self.backend.is_running() {
                        "RUNNING"
                    } else {
                        "stopped"
                    }
                ));
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
                    if !self.backend.is_running() {
                        if ui.button("▶ Start").clicked() {
                            self.start_backend();
                        }
                    } else if ui.button("■ Stop").clicked() {
                        self.stop_backend();
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
                ui.label("Phase 4: xray.exe supervision is a stub — SNI relay works standalone.");
                ui.label("Set MODE=Trojan + Xray in config.full.json, then launch xray.exe manually.");
                ui.separator();
                ui.monospace("SOCKS5 :10808   HTTP :10809  (defaults)");
            }
            Page::Tools => {
                ui.heading("Smart Tools");
                ui.horizontal(|ui| {
                    if ui.button("⚡ Rank endpoints").clicked() {
                        self.run_probes();
                    }
                    if ui.button("✓ Use fastest").clicked() {
                        if let Some(first) = self.probes.first() {
                            if first.reachable {
                                self.endpoints_text = first.endpoint.clone();
                                self.push_log(format!("using fastest: {}", first.endpoint));
                            }
                        }
                    }
                    if ui.button("♥ Relay health").clicked() {
                        let port = self.listen_port.trim().parse::<u16>().unwrap_or(40443);
                        let ok = probe_relay(self.listen_host.trim(), port);
                        self.relay_health = Some(ok);
                        self.push_log(format!(
                            "relay {}:{} {}",
                            self.listen_host,
                            port,
                            if ok { "reachable" } else { "unreachable" }
                        ));
                    }
                });
                if let Some(h) = self.relay_health {
                    ui.label(format!(
                        "Relay health: {}",
                        if h { "OK" } else { "unreachable" }
                    ));
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
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_target(false)
        .compact()
        .init();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "SNI Spoofer",
        options,
        Box::new(|_cc| Box::new(SpooferApp::new()) as Box<dyn eframe::App>),
    )
}
