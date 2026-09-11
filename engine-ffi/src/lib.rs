//! C ABI surface for the `sni_engine` cdylib.
//!
//! Go (Wails) loads this library at runtime via purego (`dlopen`, no CGO)
//! and calls the functions below. Every function that returns data returns
//! a `*mut c_char` JSON string allocated with `CString::into_raw()`; the
//! caller MUST free it with [`sni_free_string`].
//!
//! The Tokio runtime is owned by [`crate::engine::EngineHandle`] (spawned
//! on the first [`sni_start_engine`] call). Event emission from the old
//! Tauri/Slint builds is replaced by pushes to the shared log / probe
//! buffers in [`crate::state`], which the Go layer polls.
//!
//! This is the ONLY crate in the workspace that contains `unsafe` blocks,
//! confined to raw C pointer handling and the Windows single-instance
//! mutex.

pub mod engine;
pub mod probe;
pub mod seed;
pub mod state;
mod worker;

use sni_core::config::{self, Config};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use std::time::Duration;

// FIX(D1): start/stop are serialized through this mutex so rapid
// Start/Stop clicks cannot interleave a blocking `EngineHandle::start`
// (bind + driver open) with a concurrent `take()` + shutdown.
static START_STOP_MTX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

// FIX(B4): cooperative probe cancellation. Blocking `connect_timeout`
// calls cannot be preempted, but the flag (set by `sni_cancel_probe`,
// invoked from Go `ServiceShutdown` on window close) stops result
// storage and reports `{ok:false, error:"cancelled"}` instead of
// publishing stale rows after the UI is gone.
static PROBE_CANCEL: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Tracing -> shared log buffer
// ---------------------------------------------------------------------------

static TRACING_ONCE: Once = Once::new();

struct FfiLogLayer;

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

impl<S> tracing_subscriber::layer::Layer<S> for FfiLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
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
        state::push_log(line);
    }
}

fn ensure_tracing() {
    use tracing_subscriber::prelude::*;
    TRACING_ONCE.call_once(|| {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("warn,sni_engine_ffi=info,sni_core=info,sni_windivert=info"))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .compact(),
            )
            .with(FfiLogLayer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

// ---------------------------------------------------------------------------
// C string helpers (unsafe confined here)
// ---------------------------------------------------------------------------

/// Read a `*const c_char` (UTF-8, NUL-terminated) into a Rust String.
/// Returns empty string for null pointers.
unsafe fn c_str_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: caller guarantees NUL-terminated UTF-8 per C ABI contract.
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

/// Allocate a JSON string for return across FFI. Never returns null.
fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("{}").unwrap().into_raw(),
    }
}

fn json_to_c(v: &serde_json::Value) -> *mut c_char {
    string_to_c(serde_json::to_string(v).unwrap_or_else(|_| "{}".into()))
}

fn ok_json(extra: Option<serde_json::Value>) -> *mut c_char {
    let mut m = serde_json::Map::new();
    m.insert("ok".into(), serde_json::Value::Bool(true));
    if let Some(serde_json::Value::Object(o)) = extra {
        for (k, v) in o {
            m.insert(k, v);
        }
    }
    json_to_c(&serde_json::Value::Object(m))
}

fn err_json(msg: impl Into<String>) -> *mut c_char {
    json_to_c(&serde_json::json!({"ok": false, "error": msg.into()}))
}

// ---------------------------------------------------------------------------
// Single-instance mutex + admin check (Windows)
// ---------------------------------------------------------------------------

/// Single-instance guard per listen port (Windows).
/// The only OS-handle `unsafe` in this crate besides C string handling.
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
        Ok(_handle) => {
            // Intentionally leaked: the mutex must live for the process
            // lifetime. (Old Slint build did the same via `let _ = handle`.)
            std::mem::forget(_handle);
            // SAFETY: GetLastError immediately after the call is valid.
            let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            if already {
                return Err(anyhow::anyhow!(
                    "another SNI backend is already running for port {}. Stop it first.",
                    port
                ));
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("single-instance mutex failed: {:?}", e)),
    }
}

#[cfg(not(windows))]
fn acquire_single_instance(_port: u16) -> anyhow::Result<()> {
    Ok(())
}

fn is_admin_inner() -> bool {
    #[cfg(windows)]
    {
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

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn config_to_json(cfg: &Config) -> serde_json::Value {
    // FIX(D3): saves normalize to this canonical schema by design — unknown
    // extra keys from hand-edited files are dropped rather than preserved.
    serde_json::json!({
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
    })
}

fn parse_and_validate(cfg_json: &str) -> Result<Config, String> {
    let val: serde_json::Value =
        serde_json::from_str(cfg_json).map_err(|e| format!("invalid config JSON: {}", e))?;
    config::migrate(val)
        .and_then(|c| config::validate(&c).map(|_| c))
        .map_err(|e| e.to_string())
}

fn probe_to_json(r: &probe::ProbeResult) -> serde_json::Value {
    serde_json::json!({
        "endpoint": r.endpoint,
        "latency_ms": r.latency_ms.map(|v| v as u64),
        "reachable": r.reachable,
        "tls_version": r.tls_version,
        "tls_alert": r.tls_alert,
        "tls_alert_name": r.tls_alert_name,
        "error": r.error,
    })
}

fn sni_to_json(r: &probe::SniProbeResult) -> serde_json::Value {
    serde_json::json!({
        "sni": r.sni,
        "endpoint": r.endpoint,
        "latency_ms": r.latency_ms.map(|v| v as u64),
        "tls_version": r.tls_version,
        "tls_alert": r.tls_alert,
        "tls_alert_name": r.tls_alert_name,
        "reachable": r.reachable,
        "error": r.error,
    })
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Start the engine from a config JSON string.
/// Returns `{"ok":true}` or `{"ok":false,"error":"..."}`.
#[no_mangle]
pub extern "C" fn sni_start_engine(config_json: *const c_char) -> *mut c_char {
    ensure_tracing();
    // FIX(D1): serialize with stop so double-clicks cannot overlap.
    let _guard = START_STOP_MTX.lock();
    // SAFETY: null checked inside; valid NUL-terminated string per contract.
    let cfg_json = unsafe { c_str_to_string(config_json) };
    let res = std::panic::catch_unwind(|| {
        let cfg = parse_and_validate(&cfg_json)?;
        // Single-instance guard per port (preserved from Slint build).
        // Check under lock, then drop the lock before the blocking start.
        let already_running = { state::global().lock().engine.is_some() };
        if already_running {
            return Err("already running".to_string());
        }
        let port = cfg.listen_port;
        let need_mutex = {
            let st = state::global().lock();
            st.held_port != Some(port)
        };
        if need_mutex {
            #[cfg(windows)]
            {
                acquire_single_instance(port).map_err(|e| e.to_string())?;
            }
        }
        let stats = { std::sync::Arc::clone(&state::global().lock().stats) };
        match engine::EngineHandle::start(cfg, stats) {
            Ok(h) => {
                let mut st = state::global().lock();
                st.engine = Some(h);
                st.engine_started = Some(std::time::Instant::now());
                st.held_port = Some(port);
                Ok(())
            }
            Err(e) => Err(e),
        }
    });
    match res {
        Ok(Ok(())) => {
            state::push_log("[INFO] engine RUNNING".to_string());
            ok_json(None)
        }
        Ok(Err(e)) => {
            state::push_log(format!("[ERR ] start failed: {}", e));
            err_json(e)
        }
        Err(_) => err_json("start panicked"),
    }
}

/// Stop the engine. Idempotent.
/// FIX(B1): the handle is moved out of global state via `take()` (→ `None`)
/// so the Tokio runtime + WinDivert handles drop exactly once; stats reset
/// so the next Start begins at zero (T1) and uptime restarts.
#[no_mangle]
pub extern "C" fn sni_stop_engine() -> *mut c_char {
    ensure_tracing();
    // FIX(D1): serialize with start (see above).
    let _guard = START_STOP_MTX.lock();
    let res = std::panic::catch_unwind(|| {
        let mut st = state::global().lock();
        // FIX(C2): only report "stopped" when a handle actually existed;
        // an idle Stop stays silent (debug) instead of misleading.
        if let Some(mut h) = st.engine.take() {
            h.shutdown();
            st.engine_started = None;
            st.stats.reset();
            true
        } else {
            st.engine_started = None;
            false
        }
    });
    match res {
        Ok(true) => {
            state::push_log("[WARN] engine stopped".to_string());
            ok_json(None)
        }
        Ok(false) => {
            state::push_log("[DEBUG] stop ignored (not running)".to_string());
            ok_json(None)
        }
        Err(_) => err_json("stop panicked"),
    }
}

/// Current traffic / scoreboard snapshot as JSON.
/// FIX(B3): safe before Start — a fresh `Stats` snapshots to zero values,
/// never an error, so the 1Hz poller needs no engine check.
#[no_mangle]
pub extern "C" fn sni_get_stats() -> *mut c_char {
    ensure_tracing();
    let snap = state::global().lock().stats.snapshot();
    match serde_json::to_value(&snap) {
        Ok(v) => json_to_c(&v),
        Err(e) => err_json(e.to_string()),
    }
}

/// All buffered log lines as a JSON array of strings.
#[no_mangle]
pub extern "C" fn sni_get_logs() -> *mut c_char {
    ensure_tracing();
    let logs = state::global().lock().logs.clone();
    json_to_c(&serde_json::Value::Array(
        logs.into_iter().map(serde_json::Value::String).collect(),
    ))
}

/// Clear the log buffer.
#[no_mangle]
pub extern "C" fn sni_clear_logs() -> *mut c_char {
    ensure_tracing();
    state::global().lock().logs.clear();
    ok_json(None)
}

/// Export logs to `sni_log_YYYYMMDD_HHMMSS.txt` next to the exe.
/// Returns `{"ok":true,"path":"..."}`.
#[no_mangle]
pub extern "C" fn sni_export_logs() -> *mut c_char {
    ensure_tracing();
    let logs = state::global().lock().logs.clone();
    let now = state::unix_secs_now();
    let (y, m, d) = state::civil_from_days((now / 86400) as i64);
    let s = now % 86400;
    let path = state::exe_dir().join(format!(
        "sni_log_{:04}{:02}{:02}_{:02}{:02}{:02}.txt",
        y,
        m,
        d,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    ));
    match std::fs::write(&path, logs.join("\n")) {
        Ok(()) => {
            state::push_log(format!("[OK] console exported to {}", path.display()));
            json_to_c(&serde_json::json!({"ok": true, "path": path.display().to_string()}))
        }
        Err(e) => err_json(format!("export failed: {}", e)),
    }
}

/// Probe `["ip:port", ...]` for reachability / TLS version.
/// Blocks (up to ~timeout each, concurrent threads) and stores results.
#[no_mangle]
pub extern "C" fn sni_run_probe_endpoints(endpoints_json: *const c_char) -> *mut c_char {
    ensure_tracing();
    // SAFETY: valid NUL-terminated string per contract.
    let eps_json = unsafe { c_str_to_string(endpoints_json) };
    let res = std::panic::catch_unwind(|| {
        // FIX(B4): a new run clears any stale cancel from window-close.
        PROBE_CANCEL.store(false, Ordering::Relaxed);
        let mut eps: Vec<String> = serde_json::from_str(&eps_json).unwrap_or_default();
        eps.truncate(16);
        if eps.is_empty() {
            return Err("no endpoints to probe".to_string());
        }
        state::push_log(format!("[INFO] probing {} endpoint(s) ...", eps.len()));
        let out = probe::probe_endpoints(&eps, Duration::from_secs(3));
        // FIX(B4): window closed mid-probe → discard instead of publishing.
        if PROBE_CANCEL.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let n = out.len();
        // FIX(H2): log ordinals ("endpoint #i"), never raw IPs — full
        // values stay in the in-memory result tables only.
        for (i, r) in out.iter().enumerate() {
            let line = if r.reachable {
                match (&r.latency_ms, &r.tls_version) {
                    (Some(ms), Some(tls)) => format!("[INFO] endpoint #{} → {} ms ({})", i + 1, ms, tls),
                    (Some(ms), None) => match (r.tls_alert, r.tls_alert_name.as_deref()) {
                        (Some(code), Some(name)) => format!(
                            "[INFO] endpoint #{} → {} ms (SNI rejected ({}, alert {}))",
                            i + 1, ms, name, code
                        ),
                        _ => {
                            let why = r.error.clone().unwrap_or_else(|| "no TLS version".into());
                            format!("[INFO] endpoint #{} → {} ms (TLS probe: {})", i + 1, ms, why)
                        }
                    },
                    _ => format!("[INFO] endpoint #{} → reachable", i + 1),
                }
            } else {
                format!(
                    "[WARN] endpoint #{} → {}",
                    i + 1,
                    r.error.clone().unwrap_or_else(|| "unreachable".into())
                )
            };
            state::push_log(line);
        }
        if let Some(best) = out.iter().position(|p| p.reachable) {
            state::push_log(format!(
                "[OK] best: endpoint #{} ({} ms)",
                best + 1,
                out[best].latency_ms.unwrap_or(0)
            ));
        } else {
            state::push_log("[WARN] no reachable endpoint".to_string());
        }
        state::global().lock().probe_results = out;
        Ok(n)
    });
    match res {
        Ok(Ok(n)) => json_to_c(&serde_json::json!({"ok": true, "count": n})),
        Ok(Err(e)) => err_json(e),
        Err(_) => err_json("probe panicked"),
    }
}

/// Probe `["sni", ...]` via `endpoint` (`"ip:port"`).
#[no_mangle]
pub extern "C" fn sni_run_probe_snis(snis_json: *const c_char, endpoint: *const c_char) -> *mut c_char {
    ensure_tracing();
    // SAFETY: valid NUL-terminated strings per contract.
    let (snis_json, endpoint) = unsafe { (c_str_to_string(snis_json), c_str_to_string(endpoint)) };
    let res = std::panic::catch_unwind(|| {
        // FIX(B4): a new run clears any stale cancel from window-close.
        PROBE_CANCEL.store(false, Ordering::Relaxed);
        let mut snis: Vec<String> = serde_json::from_str(&snis_json).unwrap_or_default();
        snis.truncate(32);
        if snis.is_empty() {
            return Err("no SNIs to probe".to_string());
        }
        if endpoint.trim().is_empty() {
            return Err("no endpoint available for SNI probe".to_string());
        }
        // FIX(H2): log ordinals ("sni #j"), never raw SNIs or the raw
        // endpoint — full values stay in the in-memory result tables.
        state::push_log(format!("[INFO] ranking {} SNI(s) ...", snis.len()));
        let out = probe::probe_snis(&snis, &endpoint, Duration::from_secs(3));
        // FIX(B4): window closed mid-probe → discard instead of publishing.
        if PROBE_CANCEL.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let n = out.len();
        for (j, r) in out.iter().enumerate() {
            let line = if let Some(tls) = &r.tls_version {
                format!(
                    "[OK] sni #{} → {} ms ({})",
                    j + 1,
                    r.latency_ms.unwrap_or(0),
                    tls
                )
            } else if let Some(code) = r.tls_alert {
                let name = r.tls_alert_name.as_deref().unwrap_or("tls_alert");
                format!(
                    "[INFO] sni #{} → SNI rejected ({}, alert {})",
                    j + 1, name, code
                )
            } else {
                format!(
                    "[WARN] sni #{} → {}",
                    j + 1,
                    r.error.clone().unwrap_or_else(|| "unreachable".into())
                )
            };
            state::push_log(line);
        }
        state::global().lock().sni_results = out;
        Ok(n)
    });
    match res {
        Ok(Ok(n)) => json_to_c(&serde_json::json!({"ok": true, "count": n})),
        Ok(Err(e)) => err_json(e),
        Err(_) => err_json("probe panicked"),
    }
}

/// Stored endpoint probe results as a JSON array.
#[no_mangle]
pub extern "C" fn sni_get_probe_results() -> *mut c_char {
    ensure_tracing();
    let rows = state::global().lock().probe_results.clone();
    let arr: Vec<serde_json::Value> = rows.iter().map(probe_to_json).collect();
    json_to_c(&serde_json::Value::Array(arr))
}

/// Stored SNI probe results as a JSON array.
#[no_mangle]
pub extern "C" fn sni_get_sni_results() -> *mut c_char {
    ensure_tracing();
    let rows = state::global().lock().sni_results.clone();
    let arr: Vec<serde_json::Value> = rows.iter().map(sni_to_json).collect();
    json_to_c(&serde_json::Value::Array(arr))
}

/// Elevated-privileges check. `true` (1) when Admin.
#[no_mangle]
pub extern "C" fn sni_is_admin() -> c_uchar {
    if is_admin_inner() {
        1
    } else {
        0
    }
}

/// Engine liveness probe (A3). Returns 1 while an engine handle exists and
/// reports running, else 0. Never errors — safe to poll at any time.
#[no_mangle]
pub extern "C" fn sni_is_running() -> c_uchar {
    let alive = state::global()
        .lock()
        .engine
        .as_ref()
        .map(|h| h.is_running())
        .unwrap_or(false);
    if alive {
        1
    } else {
        0
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn sni_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: pointer came from `CString::into_raw` in this library.
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// Offline self-test (no Admin / WinDivert / network needed).
/// `config_path` may be null/empty to use `<exe>/config.json`.
/// Returns the report JSON (`{"checks":{...},"ok":bool}`).
#[no_mangle]
pub extern "C" fn sni_self_test(config_path: *const c_char) -> *mut c_char {
    ensure_tracing();
    // SAFETY: valid NUL-terminated string per contract.
    let cp = unsafe { c_str_to_string(config_path) };
    let path = if cp.trim().is_empty() {
        state::EngineState::default_config_path()
    } else {
        std::path::PathBuf::from(cp)
    };
    let (_ok, report) = sni_core::selftest::run(&path);
    json_to_c(&report)
}

/// Save config JSON (migrate + validate + atomic write).
/// FIX(B6): the write itself is tmp + rename inside
/// `state::atomic_write_json`, so Save racing Start can never leave a
/// half-written `config.json` behind (D1).
#[no_mangle]
pub extern "C" fn sni_save_config(config_json: *const c_char) -> *mut c_char {
    ensure_tracing();
    // SAFETY: valid NUL-terminated string per contract.
    let cfg_json = unsafe { c_str_to_string(config_json) };
    match parse_and_validate(&cfg_json) {
        Ok(cfg) => {
            // FIX(H1): config.json inherits the OS user-profile ACLs; no
            // secrets are stored in it (endpoints/SNIs only), so explicit
            // lockdown is deliberately not applied.
            let path = state::global().lock().config_path.clone();
            let val = config_to_json(&cfg);
            match state::atomic_write_json(&path, &val) {
                Ok(()) => {
                    state::push_log(format!("[INFO] saved {}", path.display()));
                    json_to_c(&serde_json::json!({"ok": true, "path": path.display().to_string()}))
                }
                Err(e) => err_json(format!("save failed: {}", e)),
            }
        }
        Err(e) => err_json(format!("save failed: {}", e)),
    }
}

/// Load config from disk, normalized to canonical JSON.
/// FIX(WP0.2): on first launch (`config.json` missing) the default config
/// is seeded from `ip_list.txt` / `sni_list.txt`, written atomically, and
/// returned — the caller cannot tell first launch apart from a reload.
/// FIX(D4): a corrupted file yields a recoverable `{"ok":false}` error;
/// the frontend keeps its last good config instead of crashing.
#[no_mangle]
pub extern "C" fn sni_load_config() -> *mut c_char {
    ensure_tracing();
    let path = state::global().lock().config_path.clone();
    if !path.exists() {
        // FIX(WP0.2): first launch — seed, persist, return.
        let seeded = build_default_config();
        let val = config_to_json(&seeded);
        match state::atomic_write_json(&path, &val) {
            Ok(()) => {
                state::push_log(format!("[INFO] seeded default {}", path.display()));
                let mut v = val;
                if let Some(o) = v.as_object_mut() {
                    o.insert("ok".into(), serde_json::Value::Bool(true));
                }
                return json_to_c(&v);
            }
            Err(e) => {
                // Disk unwritable: still hand the config to the UI so the
                // app stays usable this session.
                state::push_log(format!("[WARN] seed write failed: {}", e));
                let mut v = config_to_json(&seeded);
                if let Some(o) = v.as_object_mut() {
                    o.insert("ok".into(), serde_json::Value::Bool(true));
                }
                return json_to_c(&v);
            }
        }
    }
    match config::load(&path) {
        Ok(cfg) => {
            let mut v = config_to_json(&cfg);
            if let Some(o) = v.as_object_mut() {
                o.insert("ok".into(), serde_json::Value::Bool(true));
            }
            json_to_c(&v)
        }
        Err(e) => err_json(e.to_string()),
    }
}

/// Absolute path of `config.json`.
#[no_mangle]
pub extern "C" fn sni_config_path() -> *mut c_char {
    ensure_tracing();
    let path = state::global().lock().config_path.clone();
    json_to_c(&serde_json::json!({"ok": true, "path": path.display().to_string()}))
}

/// Build the first-launch default config (WP0.2).
/// `listen_host` is loopback-only (WP0.1); endpoints/SNIs come from
/// `ip_list.txt` / `sni_list.txt` next to the exe (never CWD).
fn build_default_config() -> Config {
    let dir = state::exe_dir();
    let mut cfg = Config::default();
    // FIX(WP0.1): belt-and-braces — `Config::default()` already yields
    // loopback, but the FFI default must not depend on that implicitly.
    cfg.listen_host = "127.0.0.1".to_string();
    let seeded_eps = seed::parse_ip_list(&dir.join("ip_list.txt"));
    if !seeded_eps.is_empty() {
        cfg.endpoints = seeded_eps
            .into_iter()
            .map(|(ip, port)| sni_core::config::Endpoint { ip, port })
            .collect();
    }
    let seeded_snis = seed::parse_sni_list(&dir.join("sni_list.txt"));
    if !seeded_snis.is_empty() {
        cfg.fake_snis = seeded_snis;
    }
    cfg
}

/// Seeded default config as canonical JSON (WP0.2).
/// Used by the frontend when `config.json` cannot be loaded at all.
#[no_mangle]
pub extern "C" fn sni_get_default_config() -> *mut c_char {
    ensure_tracing();
    let mut v = config_to_json(&build_default_config());
    if let Some(o) = v.as_object_mut() {
        o.insert("ok".into(), serde_json::Value::Bool(true));
    }
    json_to_c(&v)
}

/// Cooperative probe cancellation (B4). Called from Go `ServiceShutdown`
/// on window close; the running probe discards its results (T3: no stale
/// publish, no use-after-close).
#[no_mangle]
pub extern "C" fn sni_cancel_probe() {
    ensure_tracing();
    PROBE_CANCEL.store(true, Ordering::Relaxed);
}

/// Live relay sessions for the U5 Active Connections view.
/// Always a JSON array (empty when stopped) — never an error.
#[no_mangle]
pub extern "C" fn sni_get_active_connections() -> *mut c_char {
    ensure_tracing();
    let rows: Vec<serde_json::Value> = state::global()
        .lock()
        .engine
        .as_ref()
        .map(|h| h.active_connections())
        .unwrap_or_default()
        .iter()
        .filter_map(|c| serde_json::to_value(c).ok())
        .collect();
    json_to_c(&serde_json::Value::Array(rows))
}

