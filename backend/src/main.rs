//! sni-backend: async relay + injector entry point (port of `main.py`).
//!
//! Phase 3: Tokio `Worker` wiring — CLI + config + interface resolve +
//! WinDivert pre-flight + accept loop + reaper + reporter + signals.
//! No `unsafe` here except the tiny single-instance mutex shim (Windows).

mod worker;

use clap::Parser;
use std::{path::PathBuf, sync::Arc, time::Duration};
use worker::Worker;

/// Mirrors `main.py::parse_args`.
#[derive(Debug, Parser)]
#[command(name = "sni-backend", version, about = "SNI spoofing injector + relay")]
struct Args {
    /// Path to config.json (default: next to executable)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Log verbosity (mirrors --log-level + SNI_LOG env)
    #[arg(long, default_value = "INFO", value_parser = ["DEBUG", "INFO", "WARNING", "ERROR"])]
    log_level: String,

    /// Offline self-test (no Admin/WinDivert needed) — full suite in Phase 5
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
/// Safe wrapper: the only `unsafe` in this crate, confined here.
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
    // SAFETY: `wide` outlives the call; WinDivert-style FFI, string copied by OS.
    let res = unsafe { CreateMutexW(None, true.into(), PCWSTR(wide.as_ptr())) };
    match res {
        Ok(handle) => {
            // ERROR_ALREADY_EXISTS means another backend holds the mutex.
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(format!("warn,sni_backend={}", args.log_level.to_lowercase()))
        .with_target(false)
        .compact()
        .init();

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| exe_dir().join("config.json"));

    if args.self_test {
        // Offline suite (no Admin/WinDivert): mirrors run_self_test JSON shape.
        let (ok, report) = sni_core::selftest::run(&config_path);
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    let cfg = sni_core::config::load(&config_path).map_err(|e| {
        anyhow::anyhow!("FATAL: cannot load config {}: {}", config_path.display(), e)
    })?;

    // Single-instance guard before binding (Windows only).
    #[cfg(windows)]
    if let Err(e) = acquire_single_instance(cfg.listen_port) {
        eprintln!("FATAL: {}", e);
        std::process::exit(2);
    }

    let stats = Arc::new(sni_core::Stats::new());
    let worker = Arc::new(Worker::new(cfg.clone(), Arc::clone(&stats)).map_err(|e| {
        anyhow::anyhow!("FATAL: {}", e)
    })?);
    // Re-read for startup lines (Worker holds Arc<Config> internally).
    let cfg = worker.config.clone();

    // Privacy parity: never print raw SNIs/endpoints — counts only.
    println!("Server started on {}:{}", cfg.listen_host, cfg.listen_port);
    println!("Fake SNIs: {} configured", cfg.fake_snis.len());
    println!("Endpoints: {} configured", cfg.endpoints.len());
    println!(
        "Bypass method: {} (timeout={}s, max_conn={})",
        cfg.bypass_method, cfg.handshake_timeout, cfg.max_connections
    );
    println!(
        "TLS fingerprint: {} (frag overlap={}, pad={})",
        cfg.tls_fingerprint, cfg.seq_overlap, cfg.padding_size
    );
    println!("QUIC mode: {} (MODE={})", cfg.quic_mode, cfg.mode);

    // Pre-flight WinDivert open: fail fast instead of relaying with a dead
    // injector thread (mirrors main.py). Passthrough threads below reuse it.
    let tcp_filter = worker.tcp_filter();
    let tcp_handle = match sni_windivert::WindivertHandle::open(tcp_filter.clone()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("FATAL: WinDivert open failed: {}", e);
            eprintln!("Hints: run as Administrator, keep WinDivert.dll + WinDivert64.sys next to the exe,");
            eprintln!("`sc qc WinDivert` must not be DISABLED, reboot after first install.");
            std::process::exit(2);
        }
    };
    // Capture thread (blocking Recv): Phase 3 passthrough reinject.
    // Full DPI dispatch (parse -> HandshakeState -> plan_fake -> build_fake_tcp
    // -> send) plugs into this closure without changing Worker.
    let h = tcp_handle.clone();
    std::thread::Builder::new()
        .name("windivert-tcp".into())
        .spawn(move || {
            h.run(|pkt| {
                if let Err(e) = h.send(&pkt) {
                    tracing::debug!("tcp reinject failed (surviving): {}", e);
                }
            });
        })
        .ok();

    // QUIC/UDP-443 thread (block/spoof modes only; passthrough skips it).
    let qm = cfg.quic_mode.clone();
    if qm == "block" || qm == "spoof" {
        let qf = worker.quic_filter();
        match sni_windivert::WindivertHandle::open(qf) {
            Ok(qh) => {
                let trojan = cfg.mode.trim() == "Trojan + Xray";
                std::thread::Builder::new()
                    .name("windivert-quic".into())
                    .spawn(move || {
                        qh.run(|pkt| {
                            if trojan {
                                // Trojan+Xray proxy mode passes HTTP/3 through.
                                let _ = qh.send(&pkt);
                                return;
                            }
                            if qm == "block" {
                                // Drop: do NOT reinject (browser falls back to TCP).
                                return;
                            }
                            // spoof: same-length SNI swap lives in Phase 2 quic
                            // helpers; until wired, forward untouched (fail-open).
                            let _ = qh.send(&pkt);
                        });
                    })
                    .ok();
            }
            Err(e) => {
                tracing::warn!("QUIC injector unavailable ({}); continuing TCP-only", e);
            }
        }
    }

    // Listener (mirrors mother_sock bind/listen; bind failure = fatal exit 2).
    let bind_addr = format!("{}:{}", cfg.listen_host, cfg.listen_port);
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FATAL: cannot bind {}: {}", bind_addr, e);
            std::process::exit(2);
        }
    };

    // Background tasks (mirrors asyncio.create_task reporter + reaper).
    {
        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.reporter(Duration::from_secs(2)).await });
    }
    {
        let w = Arc::clone(&worker);
        tokio::spawn(async move {
            w.reaper(Duration::from_secs(60), Duration::from_secs(120)).await
        });
    }
    // Ctrl-C -> graceful shutdown (mirrors SIGINT/SIGTERM handler).
    {
        let w = Arc::clone(&worker);
        let th = tcp_handle.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                println!("\nShutting down...");
                th.stop();
                w.request_shutdown();
            }
        });
    }

    let _ = tcp_handle; // held until exit; Drop closes driver
    worker.run(listener).await
}
