//! In-process backend engine for the `sni_engine` cdylib.
//!
//! Moved verbatim from `gui/src/engine.rs` (Slint frontend). The Wails/Go
//! frontend in `gui/` loads this crate at runtime via purego and polls
//! `Stats::snapshot()` through the C ABI in `lib.rs`.
//!
//! DPI dispatch (`dispatch_tcp_packet`) wires the `sni-core` primitives:
//! `parse_ip_tcp`/`tcp_info` -> per-connection `HandshakeState` ->
//! `plan_fake` -> `build_fake_tcp` -> reinject, with
//! `Worker::complete_handshake` signalling the relay engine.
//! QUIC handling mirrors `main.py`: `block` drops UDP/443, `spoof`
//! forwards (same-length swap lives in a future slice; fail-open),
//! Trojan+Xray mode passes everything through.

use crate::worker::{ConnId, Worker};
use parking_lot::Mutex as ParkMutex;
use sni_core::{
    config::Config,
    fake_tcp::{plan_delayed_retry_second, plan_fake, BypassMethod, FakeParams, HandshakeState, InboundAction, OutboundAction},
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
/// thread so the caller never blocks.
pub struct EngineHandle {
    worker: Arc<Worker>,
    tcp: WindivertHandle,
    quic: Option<WindivertHandle>,
    // FIX #8: IPv6 drop handle (only when ip_mode is "ipv4" or
    // "both"). Drops all IPv6 TCP to the endpoints so the browser
    // falls back to IPv4.
    ipv6: Option<WindivertHandle>,
    threads: Vec<std::thread::JoinHandle<()>>,
    alive: Arc<AtomicBool>,
    runtime_thread: Option<std::thread::JoinHandle<()>>,
}

impl EngineHandle {
    /// Start everything for `cfg`. Blocking briefly (bind + driver open) so
    /// failures can be reported synchronously to the caller.
    /// Logs flow through the global tracing layer into the shared
    /// log buffer (drained by the frontend 1Hz poll). All capture/relay
    /// logic below is unchanged from the Slint build.
    pub fn start(cfg: Config, stats: Arc<Stats>) -> Result<Self, String> {
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
        // FIX P3: fail-closed QUIC. If the user asked to block/spoof QUIC and
        // the driver can't open, return an error instead of silently
        // continuing TCP-only (which would leak QUIC around the bypass).
        let quic: Option<WindivertHandle> = if quic_need {
            match WindivertHandle::open(worker.quic_filter()) {
                Ok(h) => Some(h),
                Err(e) => {
                    return Err(format!(
                        "WinDivert QUIC open failed (quic_mode={}): {}. Run as Administrator, keep WinDivert.dll + WinDivert64.sys next to the exe.",
                        quic_mode, e
                    ));
                }
            }
        } else {
            None
        };

        // FIX #8: open the IPv6 drop handle when the user wants IPv4-only
        // bypass (or "both"). Failures are non-fatal — log and continue.
        let ip_mode = wcfg.ip_mode.clone();
        let need_ipv6_drop = ip_mode == "ipv4" || ip_mode == "both";
        let ipv6: Option<WindivertHandle> = if need_ipv6_drop {
            match WindivertHandle::open(worker.ipv6_drop_filter()) {
                Ok(h) => {
                    tracing::info!("IPv6 drop handle opened (mode={})", ip_mode);
                    Some(h)
                }
                Err(e) => {
                    tracing::warn!(
                        "IPv6 drop handle failed to open ({}). Continuing with IPv4 only.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Runtime for the accept loop + reaper. Built here so we can bind
        // synchronously and return bind errors to the caller.
        // FIX(D): worker_threads(4) exactly per spec (accept loop + reaper +
        // relay tasks); capture threads stay on their own blocking threads.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sni-tokio")
            .worker_threads(4)
            .max_blocking_threads(2)
            .build()
            .map_err(|e| format!("tokio runtime failed: {}", e))?;
        let rt_handle = rt.handle().clone();

        let listener = rt
            .block_on(TcpListener::bind(&bind_addr))
            .map_err(|e| format!("cannot bind {}: {}", bind_addr, e))?;

        tracing::info!(
            "listening on {} (method={}, {} endpoint(s), {} fake SNI(s))",
            bind_addr,
            wcfg.bypass_method,
            wcfg.endpoints.len(),
            wcfg.fake_snis.len()
        );

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
            let fake_delay = wcfg.fake_delay;
            threads.push(
                std::thread::Builder::new()
                    .name("windivert-tcp".into())
                    .spawn(move || {
                        h.run(|pkt| {
                            dispatch_tcp_packet(
                                &h, &pkt, &w, &rt_h, &dpi, method, &params, profile,
                                &snis, &iface, fake_delay,
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
                            // FIX P3: trojan passthrough must not override an
                            // explicit block. Only passthrough mode (no QUIC
                            // thread) allows QUIC; block/spoof always drop.
                            // FIX P3: spoof has no crypto (QUIC Initial is
                            // encrypted) so fail-closed as drop, not forward.
                            // Trojan+Xray with block still drops here; with
                            // passthrough there is no thread by construction.
                            if trojan && quic_mode != "block" && quic_mode != "spoof" {
                                let _ = qh.send(&pkt);
                                return;
                            }
                            // block + spoof (no SNI-swap yet): drop so the
                            // browser falls back to TCP instead of leaking.
                            let _ = quic_mode;
                            return;
                        });
                    })
                    .map_err(|e| format!("cannot spawn QUIC thread: {}", e))?,
            );
        }

        // ---- IPv6 drop thread (ipv4 / both modes) ----
        // FIX #8: drop IPv6 silently. Not reinjecting means WinDivert
        // swallows the packet, forcing the browser to retry on IPv4.
        if let Some(ih) = ipv6.clone() {
            threads.push(
                std::thread::Builder::new()
                    .name("windivert-ipv6".into())
                    .spawn(move || {
                        ih.run(|_pkt| {
                            // FIX #8: drop IPv6 silently. Not reinjecting
                            // means WinDivert swallows the packet, forcing
                            // the browser to retry on IPv4.
                        });
                    })
                    .map_err(|e| format!("cannot spawn IPv6 thread: {}", e))?,
            );
        }

        // ---- Tokio thread: reaper + accept loop ----
        let w2 = Arc::clone(&worker);
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
                        tracing::warn!("accept loop ended: {}", e);
                    }
                });
            })
            .map_err(|e| format!("cannot spawn runtime thread: {}", e))?;

        Ok(Self {
            worker,
            tcp,
            quic,
            // FIX #8: IPv6 drop handle.
            ipv6,
            threads,
            alive,
            runtime_thread: Some(runtime_thread),
        })
    }

    pub fn is_running(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Live relay sessions for the U5 Active Connections view.
    /// Delegates to the worker's sync snapshot (no runtime needed).
    pub fn active_connections(&self) -> Vec<crate::worker::ActiveConn> {
        self.worker.snapshot_active()
    }

    /// Signal shutdown and reap threads off the caller thread.
    /// Also resets shared traffic counters so the next Start begins at zero
    /// (the frontend calls `Stats::reset()` too; double-reset is harmless).
    pub fn shutdown(&mut self) {
        if !self.alive.swap(false, Ordering::Relaxed) {
            return;
        }
        self.tcp.stop();
        if let Some(q) = self.quic.take() {
            q.stop();
        }
        // FIX #8: stop the IPv6 drop handle.
        if let Some(h) = self.ipv6.take() {
            h.stop();
        }
        self.worker.request_shutdown();
        // Reset traffic + scoreboard so stale values never flash on next Start.
        self.worker.stats.reset();
        // In tokio 1.40, Handle does not have shutdown_background().
        // The runtime thread will exit naturally when the accept loop and
        // reaper finish because we called worker.request_shutdown().
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
    fake_delay: f64,
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

    // FIX P4: use WinDivert direction when known; IP compare breaks on
    // VPN / multi-route where the socket local IP != interface_ipv4.
    let outbound = match pkt.direction {
        sni_windivert::Direction::Outbound => true,
        sni_windivert::Direction::Inbound => false,
        sni_windivert::Direction::Unknown => src_ip == iface,
    };
    // FIX(diag): per-packet entry log (direction + endpoints + length).
    // FIX(perf): demoted to debug — info here fires for EVERY packet
    // (hundreds of thousands of lines/sec) and saturates the log buffer.
    tracing::debug!(
        "DPI pkt dir={} {}:{} -> {}:{} len={}",
        if outbound { "OUT" } else { "IN" },
        src_ip,
        sport,
        dst_ip,
        dport,
        raw.len()
    );
    // Normalized client-first key; doubles as the Worker's ConnId.
    let key: DpiKey = if outbound {
        (src_ip, sport, dst_ip, dport)
    } else {
        (dst_ip, dport, src_ip, sport)
    };

    // FIX(perf): tcp_info moved UP so the fast-path guard below can test
    // is_handshake_pkt before touching any DPI state.
    let info = match tcp_info(raw) {
        Some(i) => i,
        None => {
            reinject();
            return;
        }
    };

    // FIX(perf): only run the DPI state machine for tuples that belong
    // to a connection the Worker actually created (client side matched
    // by (client_ip, client_port, endpoint_ip, endpoint_port)). Any
    // other traffic that happens to share the endpoint IP is forwarded
    // untouched — this prevents the DPI filter from acting on the
    // system's normal Cloudflare traffic.
    // FIX(perf): sync check via active_relays (parking_lot, no runtime
    // needed). `conns` is a tokio Mutex and is evicted before relay, so
    // it cannot be used here.
    // FIX(perf): fast-path guard. The DPI filter matches traffic by
    // (client IP, endpoint IP, port 443) and can capture unrelated
    // system traffic when the endpoint is a shared anycast IP (e.g.
    // Cloudflare). Only run the state machine for tuples we actually
    // own.
    // FIX: `dpi_conns` mirrors `conns` (short-lived: evicted before relay),
    // so a ClientHello sent after evict would miss it. Also accept
    // `is_known_relay` (active_relays, lives for the whole relay) as a
    // fallback — otherwise the bypass silently disables. Either hit means
    // "our connection"; anything else is forwarded untouched.
    // FIX(#2b): after FIX(#2a) the outgoing tuple is seeded in
    // dpi_conns before the SYN leaves the socket, so we no longer
    // need to exempt SYN / SYN-ACK / RST / FIN. Only process tuples
    // the Worker actually owns.
    let known = worker
        .dpi_conns
        .lock()
        .contains(&(key.0.clone(), key.1, key.2.clone(), key.3));
    let known = known || worker.is_known_relay(&key);
    if !known {
        reinject();
        return;
    }

    // RST/FIN: connection is dead — drop DPI state, wake the waiter so the
    // relay task doesn't linger until HANDSHAKE_TIMEOUT.
    // FIX: RST/FIN before fake = real failure; after fake = server
    // rejecting our old-seq segment, which is EXPECTED. Do not fail
    // the connection in that case — let the relay continue; the real
    // ClientHello may still succeed.
    if info.rst || info.fin {
        let should_fail = {
            let map = dpi.lock();
            map.get(&key).map(|st| !st.fake_sent).unwrap_or(true)
        };
        if should_fail {
            dpi.lock().remove(&key);
            let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
            // FIX(perf): spawn instead of block_on — the capture thread
            // must not stall waiting for the runtime.
            let w = Arc::clone(worker);
            rt.spawn(async move {
                w.complete_handshake(&conn, false).await;
            });
        }
        reinject();
        return;
    }

    if outbound {
        enum Next {
            Forward,
            FakeBurst(Vec<Vec<u8>>, Option<RetryCtx>),
            Fail,
        }
        struct RetryCtx {
            syn: u32,
            hello: Vec<u8>,
            ident_base: u16,
            ttl: u8,
            template: Vec<u8>,
        }
        // FIX P4: narrow DPI lock scope — only touch state under lock,
        // build fake bytes outside so other connections don't head-of-line
        // block on pick_sni / ClientHello / checksums.
        // FIX P0: bound DpiMap so a Success-never-arrives regression can't
        // grow it without limit (removal still happens on Success/Fail/RST).
        enum OutNext {
            Forward,
            Fail,
            NeedFake(u32, BypassMethod),
        }
        let out_next: OutNext = {
            let mut map = dpi.lock();
            if map.len() > 4096 {
                map.clear();
            }
            // FIX(#7): ask the Worker for the sticky method when config is
            // "auto". For a concrete config this returns the same method
            // every time, so behaviour is unchanged.
            let conn_method = worker.resolve_method_for_connection(method);
            let st = map.entry(key.clone()).or_insert_with(|| HandshakeState::new(conn_method));
            match st.on_outbound(info) {
                OutboundAction::Reinject => OutNext::Forward,
                OutboundAction::TriggerFake => {
                    let syn = st.syn_seq.unwrap_or_else(|| info.seq.wrapping_sub(1));
                    let m = st.method;
                    OutNext::NeedFake(syn, m)
                }
                OutboundAction::Unexpected(msg) => {
                    // Post-fake data (e.g. relay bytes on the same 4-tuple)
                    // must NOT fail the connection — forward quietly. Only
                    // genuine handshake violations fail early.
                    if st.fake_sent {
                        tracing::debug!("post-fake outbound (forwarding): {}", msg);
                        OutNext::Forward
                    } else {
                        tracing::debug!("unexpected outbound (failing): {}", msg);
                        map.remove(&key);
                        OutNext::Fail
                    }
                }
            }
        };
        let next = match out_next {
            OutNext::Forward => Next::Forward,
            OutNext::Fail => Next::Fail,
            OutNext::NeedFake(syn, m) => {
            // Fake ClientHello with a random SNI from the pool.
            let sni = pick_sni(snis).unwrap_or_else(|| "example.com".to_string());
            let hello = build_fake_client_hello(sni.as_bytes(), profile);
            // FIX P2: empty hello (SNI too long) must not emit a bare ACK;
            // forward the original so bypass doesn't silently disable.
            if hello.is_empty() {
                tracing::debug!("empty fake hello (SNI too long), forwarding");
                Next::Forward
            } else {
                let segs = plan_fake(m, syn, &hello, params, Some(key.2.as_str()));
                // FIX(#6): tell the worker which actual method the DPI committed
                // to. When config is "auto", the DPI resolved it to `m` (a real
                // method). Stats will rank this real method, not "auto".
                {
                    let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                    worker.record_resolved_method(&conn, m.as_str());
                }
                let ident = u16::from_be_bytes([raw[4], raw[5]]);
                let ttl = raw[8];
                let mut built = Vec::with_capacity(segs.len());
                for s in &segs {
                    // FIX P1: wrong_seq_ttl ttl-1 never expires (64->63 still
                    // reaches server). Use low TTL so local DPI sees it but
                    // it dies before the server (classic TTL trick).
                    let ttl_ov = if s.ttl_decrement {
                        Some(ttl.min(8).max(1))
                    } else {
                        None
                    };
                    if let Some(bytes) =
                        build_fake_tcp(raw, s.seq, &s.payload, s.psh, ident.wrapping_add(s.ident_plus), ttl_ov)
                    {
                        built.push(bytes);
                    }
                }
                // Mark sent under lock (entry must still exist; TriggerFake
                // created it above).
                {
                    let mut map = dpi.lock();
                    if let Some(st) = map.get_mut(&key) {
                        st.mark_fake_sent();
                    }
                }
                if built.is_empty() {
                    Next::Forward
                } else {
                    // FIX P1: retain retry context so delayed_retry can emit
                    // its split_seq second burst after 1.5s (previously the
                    // planner existed but was never called -> == wrong_seq).
                    let retry = if m == BypassMethod::DelayedRetry {
                        Some(RetryCtx {
                            syn,
                            hello: hello.clone(),
                            ident_base: ident,
                            ttl,
                            template: raw.to_vec(),
                        })
                    } else {
                        None
                    };
                    Next::FakeBurst(built, retry)
                }
            }
            }
        };
        match next {
            Next::Forward => reinject(),
            Next::FakeBurst(blobs, retry) => {
                // FIX 4: honor cfg.fake_delay (Python sleeps fake_delay secs
                // before sending fake segments); blocking capture thread so
                // std::thread::sleep is correct. No sleep when 0.0.
                if fake_delay > 0.0 {
                    std::thread::sleep(std::time::Duration::from_secs_f64(
                        fake_delay.clamp(0.0, 5.0),
                    ));
                }
                // FIX(diag): fake burst size/method visibility.
                // FIX(perf): demoted to debug to avoid per-handshake info spam.
                tracing::debug!(
                    "DPI: sending {} fake segment(s) method={}",
                    blobs.len(),
                    method.as_str()
                );
                for b in &blobs {
                    let fp = pkt.with_raw(b.clone());
                    if let Err(e) = handle.send(&fp) {
                        tracing::debug!("fake send failed (surviving): {}", e);
                    }
                }
                // FIX P1: delayed_retry second burst (split_seq after 1.5s).
                // Off the capture thread so other connections don't stall.
                if let Some(ctx) = retry {
                    let h2 = handle.clone();
                    let pkt2 = pkt.clone();
                    let dpi2 = Arc::clone(dpi);
                    let key2 = key.clone();
                    let params2 = *params;
                    std::thread::Builder::new()
                        .name("delayed-retry".into())
                        .spawn(move || {
                            std::thread::sleep(std::time::Duration::from_millis(1500));
                            let still_monitored = {
                                let map = dpi2.lock();
                                matches!(map.get(&key2), Some(st) if st.fake_sent && st.monitor)
                            };
                            if !still_monitored {
                                return;
                            }
                            let segs = plan_delayed_retry_second(ctx.syn, &ctx.hello, true);
                            for s in &segs {
                                if let Some(bytes) = build_fake_tcp(
                                    &ctx.template,
                                    s.seq,
                                    &s.payload,
                                    s.psh,
                                    ctx.ident_base.wrapping_add(s.ident_plus).wrapping_add(10),
                                    None,
                                ) {
                                    let fp = pkt2.with_raw(bytes);
                                    if let Err(e) = h2.send(&fp) {
                                        tracing::debug!("delayed retry send failed: {}", e);
                                    }
                                }
                            }
                            let _ = (params2, ctx.ttl);
                        })
                        .ok();
                }
                reinject(); // original follows the fakes (wrong_seq primitive)
                // Cooperative yield: injection bursts are hot paths; yielding
                // avoids starving the 2-thread Tokio runtime.
                std::thread::yield_now();
            }
            Next::Fail => {
                let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                // FIX(perf): spawn instead of block_on — the capture thread
                // must not stall waiting for the runtime.
                let w = Arc::clone(worker);
                rt.spawn(async move {
                    w.complete_handshake(&conn, false).await;
                });
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
            // FIX(#7): ask the Worker for the sticky method when config is
            // "auto". For a concrete config this returns the same method
            // every time, so behaviour is unchanged.
            let conn_method = worker.resolve_method_for_connection(method);
            let st = map.entry(key.clone()).or_insert_with(|| HandshakeState::new(conn_method));
            match st.on_inbound(info) {
                InboundAction::Reinject => NextIn::Forward,
                InboundAction::Success => {
                    // FIX(diag): visible success path (pure ACK vs ServerHello payload).
                    tracing::info!("DPI: inbound SUCCESS key={:?}", key);
                    map.remove(&key);
                    NextIn::Succeed
                }
                InboundAction::Unexpected(msg) => {
                    if st.fake_sent {
                        // FIX(diag): inbound UNEXPECTED after fake_sent (forward path).
                        tracing::info!("DPI: inbound UNEXPECTED fake_sent={}: {}", st.fake_sent, msg);
                        tracing::debug!("post-fake inbound (forwarding): {}", msg);
                        NextIn::Forward
                    } else {
                        // FIX(diag): inbound UNEXPECTED before fake_sent (fail path).
                        tracing::info!("DPI: inbound UNEXPECTED fake_sent={}: {}", st.fake_sent, msg);
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
                // FIX(perf): spawn instead of block_on — the capture thread
                // must not stall waiting for the runtime.
                let w = Arc::clone(worker);
                rt.spawn(async move {
                    w.complete_handshake(&conn, true).await;
                });
            }
            NextIn::Fail => {
                let conn: ConnId = (key.0.clone(), key.1, key.2.clone(), key.3);
                // FIX(perf): spawn instead of block_on — the capture thread
                // must not stall waiting for the runtime.
                let w = Arc::clone(worker);
                rt.spawn(async move {
                    w.complete_handshake(&conn, false).await;
                });
                reinject();
            }
        }
    }
}
