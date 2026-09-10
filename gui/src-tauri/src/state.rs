use crate::engine::EngineHandle;
use parking_lot::Mutex;
use sni_core::stats::Stats;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub stats: Arc<Stats>,
    pub engine: Mutex<Option<EngineHandle>>,
    pub config_path: PathBuf,
    pub held_port: Mutex<Option<u16>>,
    pub probe_results: Mutex<Vec<crate::probe::ProbeResult>>,
    pub sni_results: Mutex<Vec<crate::probe::SniProbeResult>>,
    pub logs: Mutex<Vec<String>>,
    pub log_started: std::time::Instant,
}

impl AppState {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            stats: Arc::new(Stats::new()),
            engine: Mutex::new(None),
            config_path,
            held_port: Mutex::new(None),
            probe_results: Mutex::new(Vec::new()),
            sni_results: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
            log_started: std::time::Instant::now(),
        }
    }
}
