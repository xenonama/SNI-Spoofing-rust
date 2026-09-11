//! Shared FFI engine state.
//!
//! Holds the running [`crate::engine::EngineHandle`], traffic [`Stats`],
//! bounded log buffer, probe results and config path behind a single
//! global `OnceLock<Mutex<EngineState>>`. All C ABI entry points in
//! `lib.rs` lock this state briefly and never hold it across blocking
//! calls into the engine.

use crate::probe::{ProbeResult, SniProbeResult};
use parking_lot::Mutex;
use sni_core::stats::Stats;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// Complete mutable backend state for the cdylib.
/// FIX(B1): the running engine lives behind `Mutex<...>` as
/// `Option<EngineHandle>`; `sni_stop_engine` takes it (`take()` → `None`)
/// and shuts it down, so START → STOP → START releases the WinDivert
/// handle and restarts counters/uptime cleanly.
/// FIX(D1): every engine-handle mutation goes through this single Mutex;
/// start/stop are additionally serialized by `START_STOP_MTX` in lib.rs.
pub struct EngineState {
    pub stats: Arc<Stats>,
    pub engine: Option<crate::engine::EngineHandle>,
    pub config_path: PathBuf,
    pub held_port: Option<u16>,
    pub probe_results: Vec<ProbeResult>,
    pub sni_results: Vec<SniProbeResult>,
    pub logs: Vec<String>,
    pub engine_started: Option<Instant>,
}

impl EngineState {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            stats: Arc::new(Stats::new()),
            engine: None,
            config_path,
            held_port: None,
            probe_results: Vec::new(),
            sni_results: Vec::new(),
            logs: Vec::new(),
            engine_started: None,
        }
    }

    pub fn default_config_path() -> PathBuf {
        exe_dir().join("config.json")
    }
}

static GLOBAL: OnceLock<Mutex<EngineState>> = OnceLock::new();

fn init_global() -> Mutex<EngineState> {
    Mutex::new(EngineState::new(EngineState::default_config_path()))
}

/// Global engine state. Initialized once on first use.
pub fn global() -> &'static Mutex<EngineState> {
    GLOBAL.get_or_init(init_global)
}

/// Override the config path (used by `--config` / `sni_self_test`).
pub fn set_config_path(p: PathBuf) {
    global().lock().config_path = p;
}

// ---------------------------------------------------------------------------
// Helpers shared with lib.rs
// ---------------------------------------------------------------------------

pub fn exe_dir() -> PathBuf {
    match std::env::current_exe() {
        Ok(p) => p
            .parent()
            .map(|x| x.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
}

pub fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn timestamp_hhmmss() -> String {
    let s = unix_secs_now() % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// Full UTC date-time stamp for log prefixes.
/// FIX(E3): timestamps are UTC by construction (std has no local tz without
/// new deps) — the `UTC` suffix and date make that explicit and consistent
/// everywhere, including export filenames.
pub fn timestamp_utc() -> String {
    let now = unix_secs_now();
    let (y, m, d) = civil_from_days((now / 86400) as i64);
    let s = now % 86400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, m, d,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

/// Single choke point for Rust-side log lines: stamps `[HH:MM:SS]` and
/// bounds the buffer to 2000 entries.
/// FIX(B2/D2/U6): FIFO eviction at the 2000 cap keeps idle memory flat;
/// probe result vecs are likewise *replaced* (never appended) per run.
pub fn push_log(line: String) {
    let stamped = if line.starts_with('[') && line.len() > 10 && line.as_bytes()[9] == b']' {
        line
    } else {
        // FIX(E3): explicit UTC date-time prefix (see timestamp_utc).
        format!("[{}] {}", timestamp_utc(), line)
    };
    let mut st = global().lock();
    st.logs.push(stamped);
    if st.logs.len() > 2000 {
        let drain = st.logs.len() - 2000;
        st.logs.drain(..drain);
    }
}

/// Atomic JSON write (crash-safe): tmp + rename.
/// FIX(B6): never a direct write, so a crash mid-save cannot corrupt
/// `config.json` (readers only ever see the old or the new file).
pub fn atomic_write_json(
    path: &std::path::Path,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, serde_json::to_string_pretty(value).unwrap_or_default()) {
        // FIX(D6): never leave a stray tmp file behind on failure.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // FIX(D6): rename failure (e.g. locked destination) must not leave
        // `config.json.tmp` behind either.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
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
