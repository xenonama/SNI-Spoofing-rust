//! Stats + scoreboard: replaces `monitor_connection.py`.
//!
//! Python used module globals + `threading.Lock`. Rust uses a `Stats`
//! struct holding `parking_lot::Mutex<Inner>` so both Tokio tasks and
//! WinDivert callback threads share one instance via `Arc<Stats>`.
//! SNI board keys are hashed (privacy parity); endpoint keys stay literal.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const BOARD_CAP: usize = 200;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
struct Cell {
    ok: u32,
    fail: u32,
}

impl Cell {
    fn rate(&self) -> f64 {
        let tot = self.ok as f64 + self.fail as f64;
        if tot == 0.0 {
            0.0
        } else {
            self.ok as f64 / tot
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    active: u64,
    total: u64,
    success: u64,
    failed: u64,
    up_bytes: u64,
    down_bytes: u64,
    endpoints: HashMap<String, Cell>,
    snis: HashMap<String, Cell>,
    methods: HashMap<String, Cell>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ranked {
    pub key: String,
    pub ok: u32,
    pub fail: u32,
    pub rate: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Snapshot {
    #[serde(rename = "type")]
    pub kind: String,
    pub active: u64,
    pub total: u64,
    pub success: u64,
    pub failed: u64,
    pub uptime: f64,
    pub success_rate: f64,
    pub best_endpoint: String,
    pub best_method: String,
    pub methods: Vec<Ranked>,
    pub up_bytes: u64,
    pub down_bytes: u64,
}

pub struct Stats {
    inner: Mutex<Inner>,
    started: Instant,
    // Hot counters duplicated as atomics so relay fast-path avoids lock.
    active_a: AtomicU64,
    up_a: AtomicU64,
    down_a: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            started: Instant::now(),
            active_a: AtomicU64::new(0),
            up_a: AtomicU64::new(0),
            down_a: AtomicU64::new(0),
        }
    }

    pub fn increment_active(&self) {
        self.active_a.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().active += 1;
    }

    pub fn increment_total(&self) {
        self.inner.lock().total += 1;
    }

    pub fn finish_success(&self) {
        self.decrement_active_inner();
        self.inner.lock().success += 1;
    }

    pub fn finish_failed(&self) {
        self.decrement_active_inner();
        self.inner.lock().failed += 1;
    }

    pub fn increment_failed(&self) {
        self.inner.lock().failed += 1;
    }

    /// Release one active slot without counting success/fail (relay teardown).
    /// Phase 3 needs this so handshake success isn't double-counted.
    pub fn decrement_active(&self) {
        self.decrement_active_inner();
    }

    fn decrement_active_inner(&self) {
        let prev = self.active_a.load(Ordering::Relaxed);
        if prev > 0 {
            self.active_a.fetch_sub(1, Ordering::Relaxed);
        }
        let mut g = self.inner.lock();
        if g.active > 0 {
            g.active -= 1;
        }
    }

    pub fn add_traffic(&self, up: u64, down: u64) {
        self.up_a.fetch_add(up, Ordering::Relaxed);
        self.down_a.fetch_add(down, Ordering::Relaxed);
        let mut g = self.inner.lock();
        g.up_bytes = g.up_bytes.saturating_add(up);
        g.down_bytes = g.down_bytes.saturating_add(down);
    }

    /// Mirrors `record_result(endpoint, sni, ok, method)`.
    pub fn record_result(&self, endpoint: &str, sni: &str, ok: bool, method: &str) {
        let mut g = self.inner.lock();
        if !endpoint.is_empty() {
            let c = g.endpoints.entry(endpoint.to_string()).or_default();
            if ok {
                c.ok += 1;
            } else {
                c.fail += 1;
            }
            prune(&mut g.endpoints);
        }
        if !sni.is_empty() {
            let key = hash_sni(sni);
            let c = g.snis.entry(key).or_default();
            if ok {
                c.ok += 1;
            } else {
                c.fail += 1;
            }
            prune(&mut g.snis);
        }
        if !method.is_empty() {
            let c = g.methods.entry(method.to_string()).or_default();
            if ok {
                c.ok += 1;
            } else {
                c.fail += 1;
            }
            prune(&mut g.methods);
        }
    }

    /// Mirrors `get_snapshot()` — serialized as one JSON line for the GUI.
    pub fn snapshot(&self) -> Snapshot {
        let g = self.inner.lock();
        let tot = g.success + g.failed;
        let eps = ranked(&g.endpoints, 5);
        let methods = ranked(&g.methods, 3);
        Snapshot {
            kind: "stats".to_string(),
            active: g.active,
            total: g.total,
            success: g.success,
            failed: g.failed,
            uptime: self.started.elapsed().as_secs_f64(),
            success_rate: if tot == 0 {
                0.0
            } else {
                g.success as f64 / tot as f64
            },
            best_endpoint: eps.first().map(|r| r.key.clone()).unwrap_or_default(),
            best_method: methods.first().map(|r| r.key.clone()).unwrap_or_default(),
            methods,
            up_bytes: g.up_bytes,
            down_bytes: g.down_bytes,
        }
    }

    pub fn reset(&self) {
        let mut g = self.inner.lock();
        g.active = 0;
        g.total = 0;
        g.success = 0;
        g.failed = 0;
        g.up_bytes = 0;
        g.down_bytes = 0;
        g.endpoints.clear();
        g.snis.clear();
        g.methods.clear();
        self.active_a.store(0, Ordering::Relaxed);
        self.up_a.store(0, Ordering::Relaxed);
        self.down_a.store(0, Ordering::Relaxed);
    }
}

fn prune(board: &mut HashMap<String, Cell>) {
    while board.len() > BOARD_CAP {
        if let Some(k) = board.keys().next().cloned() {
            board.remove(&k);
        } else {
            break;
        }
    }
}

fn ranked(board: &HashMap<String, Cell>, limit: usize) -> Vec<Ranked> {
    let mut v: Vec<Ranked> = board
        .iter()
        .map(|(k, c)| Ranked {
            key: k.clone(),
            ok: c.ok,
            fail: c.fail,
            rate: (c.rate() * 1000.0).round() / 1000.0,
        })
        .collect();
    v.sort_by(|a, b| {
        b.rate
            .partial_cmp(&a.rate)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| (b.ok + b.fail).cmp(&(a.ok + a.fail)))
            .then_with(|| a.key.cmp(&b.key))
    });
    v.truncate(limit);
    v
}

/// One-way SNI tag for the board (parity with `utils.security.hash_sni`).
/// Phase 0 uses a non-crypto FNV tag; Phase 3 swaps in SHA-256 truncation.
fn hash_sni(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("sni#{:016x}", h)
}
