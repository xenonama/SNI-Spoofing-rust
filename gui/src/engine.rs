//! In-process backend engine for the unified `sni-gui` binary.
//!
//! Replaces the old child-process supervisor (`backend.rs`): instead of
//! spawning `sni-backend.exe` and parsing JSON stdout, the GUI owns an
//! [`EngineHandle`] that runs the Tokio accept loop + reaper on a background
//! runtime thread and the WinDivert capture loops on dedicated blocking
//! threads — all in this process. The GUI polls `Stats::snapshot()` directly.
//!
//! DPI dispatch (`dispatch_tcp_packet`) wires the `sni-core` primitives that
//! the old passthrough stub skipped: `parse_ip_tcp`/`tcp_info` ->
//! per-connection `HandshakeState` -> `plan_fake` -> `build_fake_tcp` ->
//! reinject, with `Worker::complete_handshake` signalling the relay engine.
//! QUIC handling mirrors `main.py`: `block` drops UDP/443, `spoof` forwards
//! (same-length swap lives in a future slice; fail-open), Trojan+Xray mode
//! passes everything through.

use crate::worker::{ConnId, Worker};
use parking_lot::Mutex as ParkMutex;
use sni_core::{
    config::Config,
    fake_tcp::{plan_fake, BypassMethod, FakeParams, HandshakeState, InboundAction, OutboundAction},
    picker::pick_sni,
    stats::Stats,
    tcp::{build_fake_tcp, parse_ip_tcp, tcp_info},
    tls::{build_fake_client_hello, TlsProfile},
};
use sni_windivert::{Packet, WindivertHandle};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    time::Duration,
};
use tokio::{net::TcpListener, runtime::Handle};

/// Normalized client-first 4-tuple: (client_ip, client_port, server_ip, server_port).
/// The client side is always the egress interface address.
type DpiKey = (String, u16, String, u16);

type DpiMap = Arc<ParkMutex<HashMap<DpiKey, HandshakeState>>>;

/// Running backend. `shutdown()` stops captures, cancels the accept loop and
/// shuts the runtime down; the runtime/capture threads are reaped on a spare
/// thread so the GUI thread never blocks.
pub struct EngineHandle {
    worker: Arc<Worker>,
    rt_handle: Handle,
    tcp: WindivertHandle,
    quic: Option<WindivertHandle>,
    threads: Vec<std::thread::JoinHandle<()>>,
    alive: Arc<AtomicBool>,
    runtime_thread: Option<std::thread::JoinHandle<()>>,
}

impl EngineHandle {
    /// Start everything for `cfg`. Blocking briefly (bind + driver open) so
    /// failures can be reported synchronously to the GUI console.
    pub fn start(cfg: Config, stats: Arc<Stats>, log: Sender<String>) -> Result<Self, String> {
        let worker = Arc::new(Worker::new(cfg, Arc::clone(&stats)).map_err(|e| e.to_string())?);
        let wcfg = worker.config.clone();
        let bind_addr = format!("{}:{}", wcfg.listen_host, wcfg.listen_port);

        // Driver open first: fail fast with actionable hints (mirrors main.py).
        let tcp_filter = worker.tcp_filter();
        let tcp = WindivertHandle::open(tcp_filter)
            .map_err(|e| format!("WinDivert open failed: {}. Run as Administrator, keep WinDivert.dll + WinDivert64.sys next to the exe.", e))?;

        let quic_mode = wcfg.quic_mode.clone();
        let trojan = wcfg.mode.trim() == "Trojan + Xray";
        let quic_need = quic_mode == "block" || quic_mode == "spoof";
        let quic: Option<WindivertHandle> = if quic_need {
            match WindivertHandle::open(worker.quic_filter()) {
                Ok(h) => Some(h),
                Err(e) => {
                    let _ = log.send(format!("[warn] QUIC injector unavailable ({}); TCP-only", e));
                    None
                }
            }
        } else {
            None
        };

        // Runtime for the accept loop + reaper. Built here so we can bind
        // synchronously and return bind errors to the GUI.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sni-tokio")
            .build()
            .map_err(|e| format!("tokio runtime failed: {}", e))?;
        let rt_handle = rt.handle().clone();

        let listener = rt
            .block_on(TcpListener::bind(&bind_addr))
            .map_err(|e| format!("cannot bind {}: {}", bind_addr, e))?;

        let _ = log.send(format!(
            "listening on {} (method={}, {} endpoint(s), {} fake SNI(s))",
            bind_addr,
            wcfg.bypass_method,
            wcfg.endpoints.len(),
            wcfg.fake_snis.len()
        ));

        let alive = Arc::new(AtomicBool::new(true));
        let mut threads = Vec::new();

        // ---- TCP capture thread (blocking Recv + DPI dispatch) ----
        {
            let h = tcp.clone();
            let w = Arc::clone(&worker);
            let rt_h = rt_handle.clone();
            let dpi: DpiMap = Arc::new(ParkMutex::new(HashMap::new()));
            let method = BypassMethod::parse(&wcfg.bypass_method).unwrap_or(BypassMethod::WrongSeq);
            let params = FakeParams::new(wcfg.seq_overlap, wcfg.padding_size);
            let profile =
                TlsProfile::parse(&wcfg.tls_fingerprint).unwrap_or(TlsProfile::Legacy);
            let snis = wcfg.fake_snis.clone();
            let iface = worker.interface_ipv4.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("windivert-tcp".into())
                    .spawn(move || {
                        h.run(|pkt| {
                            dispatch_tcp_packet(
                                &h, &pkt, &w, &rt_h, &dpi, method, &params, profile,
                                &snis, &iface,
                            );
                        });
                    })
                    .map_err(|e| format!("cannot spawn capture thread: {}", e))?,
            );
        }

        // ---- QUIC capture thread (block/spoof only) ----
        if let Some(qh) = quic.clone() {
            threads.push(
                std::thread::Builder::new()
                    .name("windivert-quic".into())
                    .spawn(move || {
                        qh.run(|pkt| {
                            if trojan {
                                let _ = qh.send(&pkt);
                                return;
                            }
                            if quic_mode == "block" {
                                return; // drop: browser falls back to TCP
                            }
                            // spoof: fail-open forward until SNI-swap lands.
                            let _ = qh.send(&pkt);
                        });
                    })
                    .map_err(|e| format!("cannot spawn QUIC thread: {}", e))?,
            );
        }

        // ---- Tokio thread: reaper + accept loop ----
        let w2 = Arc::clone(&worker);
        let log2 = log.clone();
        let runtime_thread = std::thread::Builder::new()
            .name("sni-runtime".into())
            .spawn(move || {
                rt.block_on(async move {
                    let w3 = Arc::clone(&w2);
                    let reaper = tokio::spawn(async move {
                        w3.reaper(Duration::from_secs(60), Duration::from_secs(120)).await
                    });
                    let res = w2.run(listener).await;
                    reaper.abort();
                    if let Err(e) = res {
                        let _ = log2.send(format!("[backend] accept loop ended: {}", e));
                    }
                });
            })
            .map_err(|e| format!("cannot spawn runtime thread: {}", e))?;

        Ok(Self {
            worker,
            rt_handle,
            tcp,
            quic,
            threads,
            alive,
            runtime_thread: Some(runtime_thread),
        })
    }

    pub fn is_running(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Signal shutdown and reap threads off the GUI thread.
    pub fn shutdown(&mut self) {
        if !self.alive.swap(false, Ordering::Relaxed) {
            return;
        }
        self.tcp.stop();
        if let Some(q) = self.quic.take() {
            q.stop();
        }
        self.worker.request_shutdown();
        self.rt_handle.shutdown_background();
        // Reap without blocking the caller (eframe `update()`).
        let mut threads = std::mem::take(&mut self.threads);
        if let Some(rt) = self.runtime_thread.take() {
            threads.push(rt);
        }
        std::thread::spawn(move || {
            for h in threads {
                let _ = h.join();
            }
        });
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One captured TCP packet: DPI state machine + fake injection + reinject.
///
/// Never panics and never kills the capture loop (mirrors the Python
/// per-packet guard): unparsable packets are forwarded untouched.
#[allow(clippy::too_many_arguments)]
fn dispatch_tcp_packet(
    handle: &WindivertHandle,
    pkt: &Packet,
    worker: &Arc<Worker>,
    rt: &Handle,
    dpi: &DpiMap,
    method: BypassMethod,
    params: &FakeParams,
    profile: TlsProfile,
    snis: &[String],
    iface: &str,
) {
    let raw = pkt.bytes();
    let reinject = || {
        if let Err(e) = handle.send(pkt) {
            tracing::debug!("tcp reinject failed (surviving): {}", e);
        }
    };

    let (ip, _, ip_hlen, _) = match parse_ip_tcp(raw) {
        Some(v) => v,
        None => {
            reinject();
            return;
        }
    };
    if raw.len() < ip_hlen + 4 {
        reinject();
        return;
    }
    let t = ip_hlen;
    let sport = u16::from_be_bytes([raw[t], raw[t + 1]]);
    let dport = u16::from_be_bytes([raw[t + 2], raw[t + 3]]);
    let src_ip = format!("{}.{}.{}.{}", ip.src[0], ip.src[1], ip.src[2], ip.src[3]);
    let dst_ip = format!("{}.{}.{}.{}", ip.dst[0], ip.dst[1], ip.dst[2], ip.dst[3]);

    let outbound = src_ip == iface;
    // Normalized client-first key; doubles as the Worker's ConnId.
    let key: DpiKey = if outbound {
        (src_ip, sport, dst_ip, dport)
    } else {
        (dst_ip, dport, src_ip, sport)
    };

    let info = match tcp_info(raw) {
        Some(i) => i,
        None => {
            reinject();
            return;
        }
    };

    // RST/FIN: connection is dead — drop DPI state, wake the waiter so the
    // relay task doesn't linger until HANDSHAKE_TIMEOUT.
    if info.rst || info.fin {
        dpi.lock().remove(&key);
        let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
        let w = Arc::clone(worker);
        rt.block_on(w.complete_handshake(&conn, false));
        reinject();
        return;
    }

    if outbound {
        enum Next {
            Forward,
            FakeBurst(Vec<Vec<u8>>),
            Fail,
        }
        let next = {
            let mut map = dpi.lock();
            let st = map.entry(key.clone()).or_insert_with(|| HandshakeState::new(method));
            match st.on_outbound(info) {
                OutboundAction::Reinject => Next::Forward,
                OutboundAction::TriggerFake => {
                    let syn = st.syn_seq.unwrap_or_else(|| info.seq.wrapping_sub(1));
                    let m = st.method;
                    // Fake ClientHello with a random SNI from the pool.
                    // (The relay task picks its own SNI for accounting; the
                    // wire decoy only needs pool membership + validity.)
                    let sni = pick_sni(snis).unwrap_or_else(|| "example.com".to_string());
                    let hello = build_fake_client_hello(sni.as_bytes(), profile);
                    let segs = plan_fake(m, syn, &hello, params, Some(key.2.as_str()));
                    let ident = u16::from_be_bytes([raw[4], raw[5]]);
                    let ttl = raw[8];
                    let mut built = Vec::with_capacity(segs.len());
                    for s in &segs {
                        let ttl_ov = if s.ttl_decrement {
                            Some(ttl.saturating_sub(1).max(1))
                        } else {
                            None
                        };
                        if let Some(bytes) =
                            build_fake_tcp(raw, s.seq, &s.payload, s.psh, ident.wrapping_add(s.ident_plus), ttl_ov)
                        {
                            built.push(bytes);
                        }
                    }
                    st.mark_fake_sent();
                    if built.is_empty() {
                        Next::Forward
                    } else {
                        Next::FakeBurst(built)
                    }
                }
                OutboundAction::Unexpected(msg) => {
                    // Post-fake data (e.g. relay bytes on the same 4-tuple)
                    // must NOT fail the connection — forward quietly. Only
                    // genuine handshake violations fail early.
                    if st.fake_sent {
                        tracing::debug!("post-fake outbound (forwarding): {}", msg);
                        Next::Forward
                    } else {
                        tracing::debug!("unexpected outbound (failing): {}", msg);
                        map.remove(&key);
                        Next::Fail
                    }
                }
            }
        };
        match next {
            Next::Forward => reinject(),
            Next::FakeBurst(blobs) => {
                for b in &blobs {
                    let fp = pkt.with_raw(b.clone());
                    if let Err(e) = handle.send(&fp) {
                        tracing::debug!("fake send failed (surviving): {}", e);
                    }
                }
                reinject(); // original follows the fakes (wrong_seq primitive)
            }
            Next::Fail => {
                let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                let w = Arc::clone(worker);
                rt.block_on(w.complete_handshake(&conn, false));
                reinject();
            }
        }
    } else {
        enum NextIn {
            Forward,
            Succeed,
            Fail,
        }
        let next = {
            let mut map = dpi.lock();
            let st = map.entry(key.clone()).or_insert_with(|| HandshakeState::new(method));
            match st.on_inbound(info) {
                InboundAction::Reinject => NextIn::Forward,
                InboundAction::Success => {
                    map.remove(&key);
                    NextIn::Succeed
                }
                InboundAction::Unexpected(msg) => {
                    if st.fake_sent {
                        tracing::debug!("post-fake inbound (forwarding): {}", msg);
                        NextIn::Forward
                    } else {
                        tracing::debug!("unexpected inbound (failing): {}", msg);
                        map.remove(&key);
                        NextIn::Fail
                    }
                }
            }
        };
        match next {
            NextIn::Forward => reinject(),
            NextIn::Succeed => {
                reinject();
                let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                let w = Arc::clone(worker);
                rt.block_on(w.complete_handshake(&conn, true));
            }
            NextIn::Fail => {
                let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                let w = Arc::clone(worker);
                rt.block_on(w.complete_handshake(&conn, false));
                reinject();
            }
        }
    }
}
