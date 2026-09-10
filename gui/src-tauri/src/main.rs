//! sni-gui: Tauri 2 application — Rust engine + WebView2 frontend.
//!
//! Backend preserved from the eframe version: the Tokio relay engine
//! (`worker.rs`) plus WinDivert captures (`engine.rs`) run in-process and
//! share one `Arc<Stats>`. The old mpsc log channel and 1Hz GUI poll are
//! replaced by Tauri events (`log_line`, `stats_update`, `engine_status`,
//! `probe_results`, `sni_results`, `probe_progress`).
//!
//! Preserved behaviors: `--config <path>`, `--self-test` (offline, prints
//! JSON and exits), `--log-level`, per-port single-instance mutex,
//! `windows_subsystem = "windows"` in release, atomic config writes,
//! `sni_log_YYYYMMDD_HHMMSS.txt` export next to the exe.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod probe;
mod state;

use engine::EngineHandle;
use sni_core::{
    config::{self, Config},
    stats::Stats,
};
use state::AppState;
use std::{
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tauri::{Emitter, Manager};
use tracing_subscriber::{
    layer::{Context, Layer},
    prelude::*,
    EnvFilter,
};

// ---------------------------------------------------------------------------
// DTOs (JSON-friendly shapes for the React frontend)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointDto {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConfigDto {
    pub listen_host: String,
    pub listen_port: u16,
    pub endpoints: Vec<EndpointDto>,
    pub fake_snis: Vec<String>,
    pub bypass_method: String,
    pub handshake_timeout: f64,
    pub max_connections: u64,
    pub fake_delay: f64,
    pub seq_overlap: u8,
    pub tls_fingerprint: String,
    pub padding_size: u8,
    pub quic_mode: String,
    pub mode: String,
    pub probe_tries: u32,
    pub probe_timeout: f64,
    pub socks5_port: u16,
    pub http_port: u16,
}

impl From<&Config> for ConfigDto {
    fn from(c: &Config) -> Self {
        Self {
            listen_host: c.listen_host.clone(),
            listen_port: c.listen_port,
            endpoints: c
                .endpoints
                .iter()
                .map(|e| EndpointDto {
                    ip: e.ip.clone(),
                    port: e.port,
                })
                .collect(),
            fake_snis: c.fake_snis.clone(),
            bypass_method: c.bypass_method.clone(),
            handshake_timeout: c.handshake_timeout,
            max_connections: c.max_connections as u64,
            fake_delay: c.fake_delay,
            seq_overlap: c.seq_overlap,
            tls_fingerprint: c.tls_fingerprint.clone(),
            padding_size: c.padding_size,
            quic_mode: c.quic_mode.clone(),
            mode: c.mode.clone(),
            probe_tries: c.probe_tries,
            probe_timeout: c.probe_timeout,
            socks5_port: c.socks5_port,
            http_port: c.http_port,
        }
    }
}

impl ConfigDto {
    /// Reuse the canonical migrate+validate pipeline via a JSON value, so
    /// frontend edits get exactly the same rules as the old GUI editor.
    fn into_config(self) -> Result<Config, String> {
        let val = serde_json::json!({
            "LISTEN_HOST": self.listen_host,
            "LISTEN_PORT": self.listen_port,
            "ENDPOINTS": self.endpoints.iter().map(|e| serde_json::json!({"ip": e.ip, "port": e.port})).collect::<Vec<_>>(),
            "FAKE_SNIS": self.fake_snis,
            "BYPASS_METHOD": self.bypass_method,
            "HANDSHAKE_TIMEOUT": self.handshake_timeout,
            "MAX_CONNECTIONS": self.max_connections,
            "FAKE_DELAY": self.fake_delay,
            "SEQ_OVERLAP": self.seq_overlap,
            "TLS_FINGERPRINT": self.tls_fingerprint,
            "PADDING_SIZE": self.padding_size,
            "QUIC_MODE": self.quic_mode,
            "MODE": self.mode,
            "PROBE_TRIES": self.probe_tries,
            "PROBE_TIMEOUT": self.probe_timeout,
            "SOCKS5_PORT": self.socks5_port,
            "HTTP_PORT": self.http_port,
        });
        config::migrate(val)
            .and_then(|c| config::validate(&c).map(|_| c))
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SnapshotDto {
    pub active: u64,
    pub total: u64,
    pub success: u64,
    pub failed: u64,
    pub success_rate: f64,
    pub best_endpoint: String,
    pub best_method: String,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub uptime: f64,
}

impl From<sni_core::stats::Snapshot> for SnapshotDto {
    fn from(s: sni_core::stats::Snapshot) -> Self {
        Self {
            active: s.active,
            total: s.total,
            success: s.success,
            failed: s.failed,
            success_rate: s.success_rate,
            best_endpoint: s.best_endpoint,
            best_method: s.best_method,
            up_bytes: s.up_bytes,
            down_bytes: s.down_bytes,
            uptime: s.uptime,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProbeResultDto {
    pub endpoint: String,
    pub latency_ms: Option<u64>,
    pub reachable: bool,
    pub tls_version: Option<String>,
    pub tls_alert: Option<u8>,
    pub tls_alert_name: Option<String>,
    pub error: Option<String>,
}

impl From<&probe::ProbeResult> for ProbeResultDto {
    fn from(r: &probe::ProbeResult) -> Self {
        Self {
            endpoint: r.endpoint.clone(),
            latency_ms: r.latency_ms.map(|v| v as u64),
            reachable: r.reachable,
            tls_version: r.tls_version.clone(),
            tls_alert: r.tls_alert,
            tls_alert_name: r.tls_alert_name.clone(),
            error: r.error.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SniProbeResultDto {
    pub sni: String,
    pub endpoint: String,
    pub latency_ms: Option<u64>,
    pub reachable: bool,
    pub tls_version: Option<String>,
    pub tls_alert: Option<u8>,
    pub tls_alert_name: Option<String>,
    pub error: Option<String>,
}

impl From<&probe::SniProbeResult> for SniProbeResultDto {
    fn from(r: &probe::SniProbeResult) -> Self {
        Self {
            sni: r.sni.clone(),
            endpoint: r.endpoint.clone(),
            latency_ms: r.latency_ms.map(|v| v as u64),
            reachable: r.reachable,
            tls_version: r.tls_version.clone(),
            tls_alert: r.tls_alert,
            tls_alert_name: r.tls_alert_name.clone(),
            error: r.error.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineStatus {
    pub running: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeProgress {
    pub done: usize,
    pub total: usize,
    pub kind: String,
}

// ---------------------------------------------------------------------------
// tracing -> Tauri event bridge (replaces the old GuiLogLayer mpsc channel)
// ---------------------------------------------------------------------------

struct TauriLogLayer {
    app: tauri::AppHandle,
}

struct LogFieldVisitor {
    message: String,
}

impl tracing::field::Visit for LogFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if !value.is_empty() {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&format!("{}={}", field.name(), value));
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{:?}", value);
        if field.name() == "message" {
            self.message = s;
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

impl<S> Layer<S> for TauriLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let tag = match *event.metadata().level() {
            tracing::Level::ERROR => "[ERR ]",
            tracing::Level::WARN => "[WARN]",
            tracing::Level::INFO => "[INFO]",
            tracing::Level::DEBUG => "[DEBUG]",
            tracing::Level::TRACE => "[TRACE]",
        };
        let mut v = LogFieldVisitor {
            message: String::new(),
        };
        event.record(&mut v);
        let target = event.metadata().target();
        let body = v.message.trim();
        let line = if body.is_empty() {
            format!("{} {}", tag, target)
        } else if target.starts_with("sni") {
            format!("{} {}", tag, body)
        } else {
            format!("{} {}: {}", tag, target, body)
        };
        // Mirror the old push_log timestamp + bound: stamp here, store in
        // state (bounded), then emit to the frontend console.
        let stamped = format!("[{}] {}", timestamp_hhmmss(), line);
        if let Some(state) = self.app.try_state::<AppState>() {
            let mut logs = state.logs.lock();
            logs.push(stamped.clone());
            if logs.len() > 2000 {
                let drain = logs.len() - 2000;
                logs.drain(..drain);
            }
        }
        let _ = self.app.emit("log_line", stamped);
    }
}

// ---------------------------------------------------------------------------
// Helpers preserved from the eframe version
// ---------------------------------------------------------------------------

fn exe_dir() -> PathBuf {
    match std::env::current_exe() {
        Ok(p) => p
            .parent()
            .map(|x| x.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
}

/// Single-instance guard per listen port (Windows).
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
            let _ = handle;
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

/// Atomic JSON write (crash-safe): tmp + rename.
fn atomic_write_json(path: &std::path::Path, value: &serde_json::Value) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(value).unwrap_or_default())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn timestamp_hhmmss() -> String {
    let s = unix_secs_now() % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn push_state_log(state: &AppState, app: &tauri::AppHandle, line: String) {
    let stamped = format!("[{}] {}", timestamp_hhmmss(), line);
    {
        let mut logs = state.logs.lock();
        logs.push(stamped.clone());
        if logs.len() > 2000 {
            let drain = logs.len() - 2000;
            logs.drain(..drain);
        }
    }
    let _ = app.emit("log_line", stamped);
}

fn spawn_stats_emitter(app: tauri::AppHandle, stats: Arc<Stats>) {
    // 1s stats emitter while the engine is running (mirrors the old 1Hz poll).
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let running = app
                .try_state::<AppState>()
                .map(|s| s.engine.lock().is_some())
                .unwrap_or(false);
            if !running {
                break;
            }
            let dto = SnapshotDto::from(stats.snapshot());
            let _ = app.emit("stats_update", dto);
        }
    });
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn start_engine(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    if state.engine.lock().is_some() {
        return Err("already running".to_string());
    }
    let cfg = config::load(&state.config_path).map_err(|e| e.to_string())?;
    config::validate(&cfg).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        if state.held_port.lock().as_ref() != Some(&cfg.listen_port) {
            acquire_single_instance(cfg.listen_port).map_err(|e| e.to_string())?;
            *state.held_port.lock() = Some(cfg.listen_port);
        }
    }
    push_state_log(
        &state,
        &app,
        "[INFO] starting engine (Admin + WinDivert required)...".to_string(),
    );
    let stats = Arc::clone(&state.stats);
    let handle = EngineHandle::start(cfg, Arc::clone(&stats), Some(app.clone()))?;
    *state.engine.lock() = Some(handle);
    let _ = app.emit("engine_status", EngineStatus { running: true });
    // Immediate snapshot so the dashboard is live on the first frame.
    let _ = app.emit("stats_update", SnapshotDto::from(stats.snapshot()));
    push_state_log(&state, &app, "[INFO] engine RUNNING".to_string());
    spawn_stats_emitter(app, stats);
    Ok(())
}

#[tauri::command]
fn stop_engine(state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    if let Some(mut h) = state.engine.lock().take() {
        h.shutdown();
        push_state_log(&state, &app, "[WARN] engine stopped".to_string());
    }
    state.stats.reset();
    let _ = app.emit("engine_status", EngineStatus { running: false });
    Ok(())
}

#[tauri::command]
fn get_config(state: tauri::State<'_, AppState>) -> Result<ConfigDto, String> {
    let cfg = config::load(&state.config_path).map_err(|e| e.to_string())?;
    Ok(ConfigDto::from(&cfg))
}

#[tauri::command]
fn save_config(state: tauri::State<'_, AppState>, cfg: ConfigDto) -> Result<(), String> {
    let parsed = cfg.into_config()?;
    let val = serde_json::json!({
        "LISTEN_HOST": parsed.listen_host,
        "LISTEN_PORT": parsed.listen_port,
        "ENDPOINTS": parsed.endpoints.iter().map(|e| serde_json::json!({"ip": e.ip, "port": e.port})).collect::<Vec<_>>(),
        "FAKE_SNIS": parsed.fake_snis,
        "BYPASS_METHOD": parsed.bypass_method,
        "HANDSHAKE_TIMEOUT": parsed.handshake_timeout,
        "MAX_CONNECTIONS": parsed.max_connections,
        "FAKE_DELAY": parsed.fake_delay,
        "SEQ_OVERLAP": parsed.seq_overlap,
        "TLS_FINGERPRINT": parsed.tls_fingerprint,
        "PADDING_SIZE": parsed.padding_size,
        "QUIC_MODE": parsed.quic_mode,
        "MODE": parsed.mode,
        "PROBE_TRIES": parsed.probe_tries,
        "PROBE_TIMEOUT": parsed.probe_timeout,
        "SOCKS5_PORT": parsed.socks5_port,
        "HTTP_PORT": parsed.http_port,
    });
    atomic_write_json(&state.config_path, &val).map_err(|e| e.to_string())
}

#[tauri::command]
fn reload_config(state: tauri::State<'_, AppState>) -> Result<ConfigDto, String> {
    get_config(state)
}

#[tauri::command]
fn get_stats_snapshot(state: tauri::State<'_, AppState>) -> Result<SnapshotDto, String> {
    Ok(SnapshotDto::from(state.stats.snapshot()))
}

#[tauri::command]
fn run_probe_endpoints(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    endpoints: Vec<String>,
) -> Result<(), String> {
    let eps: Vec<String> = endpoints.into_iter().take(16).collect();
    if eps.is_empty() {
        return Err("no endpoints to probe".to_string());
    }
    let total = eps.len();
    push_state_log(
        &state,
        &app,
        format!("[INFO] probing {} endpoint(s) ...", total),
    );
    let _ = app.emit(
        "probe_progress",
        ProbeProgress {
            done: 0,
            total,
            kind: "endpoints".to_string(),
        },
    );
    std::thread::Builder::new()
        .name("probe".into())
        .spawn(move || {
            let res = probe::probe_endpoints(&eps, Duration::from_secs(3));
            for r in &res {
                let line = if r.reachable {
                    match (&r.latency_ms, &r.tls_version) {
                        (Some(ms), Some(tls)) => {
                            format!("[INFO] {} → {} ms ({})", r.endpoint, ms, tls)
                        }
                        (Some(ms), None) => match (r.tls_alert, r.tls_alert_name.as_deref()) {
                            (Some(code), Some(name)) => format!(
                                "[INFO] {} → {} ms (SNI rejected ({}, alert {}))",
                                r.endpoint, ms, name, code
                            ),
                            _ => {
                                let why = r
                                    .error
                                    .clone()
                                    .unwrap_or_else(|| "no TLS version".into());
                                format!("[INFO] {} → {} ms (TLS probe: {})", r.endpoint, ms, why)
                            }
                        },
                        _ => format!("[INFO] {} → reachable", r.endpoint),
                    }
                } else {
                    format!(
                        "[WARN] {} → {}",
                        r.endpoint,
                        r.error.clone().unwrap_or_else(|| "unreachable".into())
                    )
                };
                if let Some(st) = app.try_state::<AppState>() {
                    push_state_log(&st, &app, line);
                }
            }
            if let Some(best) = res.iter().find(|p| p.reachable) {
                if let Some(st) = app.try_state::<AppState>() {
                    push_state_log(
                        &st,
                        &app,
                        format!(
                            "[OK] best: {} ({} ms)",
                            best.endpoint,
                            best.latency_ms.unwrap_or(0)
                        ),
                    );
                }
            } else if let Some(st) = app.try_state::<AppState>() {
                push_state_log(&st, &app, "[WARN] no reachable endpoint".to_string());
            }
            if let Some(st) = app.try_state::<AppState>() {
                *st.probe_results.lock() = res.clone();
            }
            let dtos: Vec<ProbeResultDto> = res.iter().map(ProbeResultDto::from).collect();
            let _ = app.emit("probe_results", dtos);
            let _ = app.emit(
                "probe_progress",
                ProbeProgress {
                    done: total,
                    total,
                    kind: "endpoints".to_string(),
                },
            );
            if let Some(st) = app.try_state::<AppState>() {
                push_state_log(
                    &st,
                    &app,
                    format!("[INFO] endpoint ranking complete: {} result(s)", total),
                );
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn run_probe_snis(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    snis: Vec<String>,
    endpoint: String,
) -> Result<(), String> {
    let snis: Vec<String> = snis.into_iter().take(32).collect();
    if snis.is_empty() {
        return Err("no SNIs to probe".to_string());
    }
    if endpoint.trim().is_empty() {
        return Err("no endpoint available for SNI probe".to_string());
    }
    let total = snis.len();
    push_state_log(
        &state,
        &app,
        format!("[INFO] ranking {} SNI(s) via {} ...", total, endpoint),
    );
    let _ = app.emit(
        "probe_progress",
        ProbeProgress {
            done: 0,
            total,
            kind: "snis".to_string(),
        },
    );
    std::thread::Builder::new()
        .name("probe-sni".into())
        .spawn(move || {
            let res = probe::probe_snis(&snis, &endpoint, Duration::from_secs(3));
            for r in &res {
                let line = if let Some(tls) = &r.tls_version {
                    format!(
                        "[OK] {} via {} → {} ms ({})",
                        r.sni,
                        r.endpoint,
                        r.latency_ms.unwrap_or(0),
                        tls
                    )
                } else if let Some(code) = r.tls_alert {
                    let name = r.tls_alert_name.as_deref().unwrap_or("tls_alert");
                    format!(
                        "[INFO] {} via {} → SNI rejected ({}, alert {})",
                        r.sni, r.endpoint, name, code
                    )
                } else {
                    format!(
                        "[WARN] {} via {} → {}",
                        r.sni,
                        r.endpoint,
                        r.error.clone().unwrap_or_else(|| "unreachable".into())
                    )
                };
                if let Some(st) = app.try_state::<AppState>() {
                    push_state_log(&st, &app, line);
                }
            }
            if let Some(st) = app.try_state::<AppState>() {
                *st.sni_results.lock() = res.clone();
            }
            let dtos: Vec<SniProbeResultDto> = res.iter().map(SniProbeResultDto::from).collect();
            let _ = app.emit("sni_results", dtos);
            let _ = app.emit(
                "probe_progress",
                ProbeProgress {
                    done: total,
                    total,
                    kind: "snis".to_string(),
                },
            );
            if let Some(st) = app.try_state::<AppState>() {
                push_state_log(
                    &st,
                    &app,
                    format!("[INFO] SNI ranking complete: {} result(s)", total),
                );
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn get_probe_results(state: tauri::State<'_, AppState>) -> Vec<ProbeResultDto> {
    state
        .probe_results
        .lock()
        .iter()
        .map(ProbeResultDto::from)
        .collect()
}

#[tauri::command]
fn get_sni_results(state: tauri::State<'_, AppState>) -> Vec<SniProbeResultDto> {
    state
        .sni_results
        .lock()
        .iter()
        .map(SniProbeResultDto::from)
        .collect()
}

#[tauri::command]
fn clear_logs(state: tauri::State<'_, AppState>) {
    state.logs.lock().clear();
}

#[tauri::command]
fn export_logs(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let logs = state.logs.lock();
    let now = unix_secs_now();
    let (y, m, d) = civil_from_days((now / 86400) as i64);
    let s = now % 86400;
    let path = exe_dir().join(format!(
        "sni_log_{:04}{:02}{:02}_{:02}{:02}{:02}.txt",
        y,
        m,
        d,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    ));
    std::fs::write(&path, logs.join("\n")).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
fn pick_fastest_endpoint(state: tauri::State<'_, AppState>) -> Result<String, String> {
    state
        .probe_results
        .lock()
        .iter()
        .find(|p| p.reachable)
        .map(|p| p.endpoint.clone())
        .ok_or_else(|| "no reachable endpoint to use".to_string())
}

#[tauri::command]
fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // `net session` exits 0 only when elevated. No new deps, no unsafe.
        std::process::Command::new("net")
            .arg("session")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[tauri::command]
fn open_logs_folder(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let folder = state
        .config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(windows)]
    {
        std::process::Command::new("explorer")
            .arg(&folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open")
            .arg(&folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn run_self_test_cmd(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let (ok, report) = sni_core::selftest::run(&state.config_path);
    if !ok {
        return Err(serde_json::to_string(&report).unwrap_or_else(|_| "self-test failed".into()));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn parse_arg(flag: &str) -> Option<String> {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == flag {
            return it.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{}=", flag)) {
            return Some(v.to_string());
        }
    }
    None
}

fn has_flag(flag: &str) -> bool {
    std::env::args().skip(1).any(|a| a == flag)
}

fn main() {
    // --self-test runs BEFORE any window is built (offline, no Admin needed).
    let config_path = parse_arg("--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_dir().join("config.json"));
    if has_flag("--self-test") {
        #[cfg(windows)]
        attach_parent_console();
        let (ok, report) = sni_core::selftest::run(&config_path);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        if !ok {
            std::process::exit(1);
        }
        return;
    }

    // Single-instance guard before opening the GUI (Windows only).
    let port = config::load(&config_path)
        .map(|c| c.listen_port)
        .unwrap_or(40443);
    #[cfg(windows)]
    if let Err(e) = acquire_single_instance(port) {
        eprintln!("FATAL: {}", e);
        std::process::exit(2);
    }

    // Privacy parity: never log raw SNIs/endpoints — counts only.
    if let Ok(cfg) = config::load(&config_path) {
        println!("Fake SNIs: {} configured", cfg.fake_snis.len());
        println!("Endpoints: {} configured", cfg.endpoints.len());
        println!(
            "Bypass method: {} (timeout={}s, max_conn={})",
            cfg.bypass_method, cfg.handshake_timeout, cfg.max_connections
        );
    }

    let lvl = parse_arg("--log-level").unwrap_or_else(|| "INFO".to_string());
    let lvl = lvl.to_lowercase();
    let cfg_path = config_path.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(move |app| {
            let filter = EnvFilter::new(format!(
                "warn,sni_gui={},sni_core={},sni_windivert={}",
                lvl, lvl, lvl
            ));
            let handle = app.handle().clone();
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(false)
                        .compact(),
                )
                .with(TauriLogLayer {
                    app: handle.clone(),
                });
            let _ = tracing::subscriber::set_global_default(subscriber);
            app.manage(AppState::new(cfg_path.clone()));
            tracing::info!("sni-gui ready (tauri single-exe)");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_engine,
            stop_engine,
            get_config,
            save_config,
            reload_config,
            get_stats_snapshot,
            run_probe_endpoints,
            run_probe_snis,
            get_probe_results,
            get_sni_results,
            clear_logs,
            export_logs,
            pick_fastest_endpoint,
            is_admin,
            open_logs_folder,
            run_self_test_cmd
        ])
        .run(tauri::generate_context!())
        .expect("tauri runtime failed");
}
