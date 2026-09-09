//! Backend child-proc supervisor: port of `gui.py` proc launch + stdout pump.
//!
//! The Rust backend prints one JSON `Snapshot` line every 2s (see
//! `Worker::reporter`, mirroring `stats_reporter`). This module spawns
//! `sni-backend(.exe)`, pumps stdout/stderr on std threads, and forwards
//! `GuiEvent`s over `std::sync::mpsc` so the eframe thread never blocks.
//! Noise lines (asyncio overlapped spam equivalents) are filtered like
//! `gui.py::_is_noise_line`.

use sni_core::stats::Snapshot;
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread::JoinHandle,
};

/// Events delivered to the eframe `update()` loop.
#[derive(Debug)]
pub enum GuiEvent {
    Stats(Snapshot),
    Log(String),
    Exited { code: i32, reason: String },
}

fn is_noise_line(line: &str) -> bool {
    let low = line.to_lowercase();
    // Rust backend is quieter than Python, but keep the same filter spirit:
    // drop driver-level chatter, keep FATAL/startup/stats.
    low.contains("cancelling an overlapped future failed")
        || (low.contains("_overlappedfuture") && low.contains("winerror 6"))
        || (low.contains("reinject ") && low.contains("failed") && low.len() < 120)
}

/// Resolve the backend binary: sibling of the GUI exe first
/// (frozen-layout parity with `gui.py::backend_cmd`), then PATH.
pub fn backend_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["sni-backend.exe", "sni-backend"] {
                let p = dir.join(name);
                if p.is_file() {
                    return p;
                }
            }
        }
    }
    PathBuf::from(if cfg!(windows) {
        "sni-backend.exe"
    } else {
        "sni-backend"
    })
}

/// Running backend + pump threads. `stop()` kills; `Drop` guarantees cleanup.
pub struct BackendManager {
    child: Option<Child>,
    _pumps: Vec<JoinHandle<()>>,
    running: bool,
}

impl BackendManager {
    pub fn new() -> Self {
        Self {
            child: None,
            _pumps: vec![],
            running: false,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Spawn `backend_path --config <path>`. Returns the event channel.
    /// Previous instance (if any) is stopped first.
    pub fn start(&mut self, config_path: &str) -> Receiver<GuiEvent> {
        self.stop();
        let (tx, rx) = mpsc::channel::<GuiEvent>();
        let path = backend_path();
        let tx_clone = tx.clone();
        match Command::new(&path)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                // Stdout pump: stats JSON vs startup/log lines.
                if let Some(out) = child.stdout.take() {
                    let tx = tx.clone();
                    self._pumps.push(
                        std::thread::Builder::new()
                            .name("backend-stdout".into())
                            .spawn(move || {
                                let br = BufReader::new(out);
                                for line in br.lines().map_while(Result::ok) {
                                    let t = line.trim();
                                    if t.is_empty() || is_noise_line(t) {
                                        continue;
                                    }
                                    // Stats lines are exact Snapshot JSON.
                                    if t.starts_with('{') {
                                        if let Ok(v) =
                                            serde_json::from_str::<serde_json::Value>(t)
                                        {
                                            if v.get("type").and_then(|x| x.as_str())
                                                == Some("stats")
                                            {
                                                match serde_json::from_value::<Snapshot>(v) {
                                                    Ok(s) => {
                                                        let _ = tx.send(GuiEvent::Stats(s));
                                                        continue;
                                                    }
                                                    Err(_) => {}
                                                }
                                            }
                                        }
                                    }
                                    let _ = tx.send(GuiEvent::Log(line));
                                }
                            })
                            .unwrap(),
                    );
                }
                // Stderr pump: tracing logs -> console (filtered).
                if let Some(err) = child.stderr.take() {
                    let tx = tx.clone();
                    self._pumps.push(
                        std::thread::Builder::new()
                            .name("backend-stderr".into())
                            .spawn(move || {
                                let br = BufReader::new(err);
                                for line in br.lines().map_while(Result::ok) {
                                    if line.trim().is_empty() || is_noise_line(&line) {
                                        continue;
                                    }
                                    let _ = tx.send(GuiEvent::Log(line));
                                }
                            })
                            .unwrap(),
                    );
                }
                // Waiter: report exit so the GUI can auto-restart or toast.
                let txw = tx_clone;
                self._pumps.push(
                    std::thread::Builder::new()
                        .name("backend-wait".into())
                        .spawn(move || {
                            // Note: we cannot join `child` here (moved); the
                            // exit code is reported by `poll()` below via
                            // `try_wait` on the manager side. This thread
                            // exists to keep pump handles grouped.
                            let _ = txw.send(GuiEvent::Log(format!(
                                "backend started: {}",
                                path.display()
                            )));
                        })
                        .unwrap(),
                );
                self.child = Some(child);
                self.running = true;
                let _ = tx.send(GuiEvent::Log(format!(
                    "spawned {} --config {}",
                    path.display(),
                    config_path
                )));
            }
            Err(e) => {
                let _ = tx.send(GuiEvent::Exited {
                    code: -1,
                    reason: format!("spawn failed ({}): {}", path.display(), e),
                });
                self.running = false;
            }
        }
        rx
    }

    /// Non-blocking exit check; call each frame while running.
    /// Returns an `Exited` event when the child just died.
    pub fn poll(&mut self) -> Option<GuiEvent> {
        if !self.running {
            return None;
        }
        let exited = match self.child.as_mut() {
            Some(c) => match c.try_wait() {
                Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
                Ok(None) => None,
                Err(_) => Some(-1),
            },
            None => Some(-1),
        };
        if let Some(code) = exited {
            self.running = false;
            self.child = None;
            return Some(GuiEvent::Exited {
                code,
                reason: format!("backend exited with code {}", code),
            });
        }
        None
    }

    pub fn stop(&mut self) {
        self.running = false;
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Pump threads end on EOF once pipes close; handles join on Drop.
        self._pumps.clear();
    }
}

impl Default for BackendManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BackendManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Atomic JSON write (crash-safe): tmp + rename. Mirrors `atomic_write_json`.
pub fn atomic_write_json(path: &str, value: &serde_json::Value) -> std::io::Result<()> {
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, serde_json::to_string_pretty(value).unwrap_or_default())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
