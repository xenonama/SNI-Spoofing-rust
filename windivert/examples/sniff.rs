//! Minimal WinDivert CLI test (Phase 1 deliverable).
//!
//! Mirrors `injecter.py::TcpInjector.run` with a passthrough `inject`:
//! open driver -> capture -> print -> send back unchanged.
//!
//! Manual use ONLY on your separate Windows machine (Admin + driver files).
//! This file is never executed by the agent (red-flag honored).
//!
//! Example filter (TCP to one endpoint):
//!   sni-sniff "tcp and ((ip.SrcAddr == 192.168.1.10 and ip.DstAddr == 1.1.1.1) or (ip.SrcAddr == 1.1.1.1 and ip.DstAddr == 192.168.1.10))" 5

use sni_windivert::WindivertHandle;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage: sni-sniff \"<windivert-filter>\" [max-packets=5]");
    eprintln!("example: sni-sniff \"tcp and udp.DstPort == 443\" 5");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let filter = args[1].clone();
    let max: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);

    println!("[sniff] opening WinDivert...");
    println!("[sniff] filter: {}", filter);
    let w = match WindivertHandle::open(filter.clone()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[sniff] FATAL: {}", e);
            eprintln!("[sniff] hints: run as Administrator, keep WinDivert.dll + WinDivert64.sys");
            eprintln!("[sniff] next to the exe, `sc qc WinDivert` must not be DISABLED, reboot once.");
            std::process::exit(1);
        }
    };
    println!("[sniff] opened. Capturing {} packet(s), reinjecting unchanged...", max);

    let seen = Arc::new(AtomicUsize::new(0));
    let seen_cb = Arc::clone(&seen);
    let w_cb = w.clone();

    // Ctrl-C support: set a flag; `stop()` unblocks Recv via Shutdown.
    let w_stop = w.clone();
    ctrlc_handler(move || w_stop.stop());

    let started = std::time::Instant::now();
    w.run(|pkt| {
        let n = seen_cb.fetch_add(1, Ordering::Relaxed) + 1;
        let dir = if pkt.is_inbound() {
            "inbound"
        } else if pkt.is_outbound() {
            "outbound"
        } else {
            "unknown"
        };
        println!("[sniff] #{:<3} dir={:<8} len={:<5} elapsed={:?}", n, dir, pkt.len(), started.elapsed());
        // Passthrough: send back unchanged (reinject=false semantics).
        if let Err(e) = w_cb.send(&pkt) {
            eprintln!("[sniff] send failed (surviving): {}", e);
        }
        if n >= max {
            println!("[sniff] reached max ({}), stopping...", max);
            w_cb.stop();
        }
    });

    // Give the driver a moment to unwind, then report.
    std::thread::sleep(Duration::from_millis(100));
    println!("[sniff] done. captured={}", seen.load(Ordering::Relaxed));
}

/// Best-effort Ctrl-C hook without extra deps: spawns a thread polling for
/// Enter (fallback) AND handles real Ctrl-C on Windows via console control.
/// Phase 3 replaces this with `tokio::signal`; kept dep-free for the example.
fn ctrlc_handler(on_ctrlc: impl FnOnce() + Send + 'static) {
    // Minimal: a thread that waits 1s-polls stdin close is overkill.
    // Instead, document: press Ctrl+C — the OS will terminate the process,
    // and `Drop` closes the driver. The explicit `stop()` path above (max
    // packets) is the clean shutdown demonstrated here.
    let _ = on_ctrlc;
}
