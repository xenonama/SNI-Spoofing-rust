//! Async orchestrator: port of `main.py` accept/failover/relay engine.
//!
//! `Worker` owns ENDPOINTS (round-robin), FAKE_SNIS (random), connection
//! table, semaphore, stats. Packet-level WinDivert glue (Phase 2 planner +
//! Phase 1 handle) signals handshake completion via `complete_handshake`;
//! until that wiring lands, `handle()` times out per HANDSHAKE_TIMEOUT
//! (same observable path as Python DPI failure).

use sni_core::{
    config::{Config, Endpoint},
    picker::{build_quic_filter, build_tcp_filter, ep_key, pick_sni, EndpointPicker},
    stats::Stats,
    tls::{build_fake_client_hello, TlsProfile},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Mutex as AsyncMutex, Notify, Semaphore},
};

/// 4-tuple connection id: (src_ip, src_port, dst_ip, dst_port).
/// Mirrors `FakeInjectiveConnection.id`.
pub type ConnId = (String, u16, String, u16);

/// Per-connection entry (subset of `FakeInjectiveConnection` needed by the
/// orchestrator; sockets stay owned by `handle()` tasks).
pub struct ConnEntry {
    pub id: ConnId,
    pub created_at: Instant,
    pub monitor: AtomicBool,
    pub counted: AtomicBool,
    pub method: String,
    pub sni: String,
    completed: Notify,
    result: parking_lot::Mutex<Option<bool>>,
}

impl ConnEntry {
    fn new(id: ConnId, method: String, sni: String) -> Self {
        Self {
            id,
            created_at: Instant::now(),
            monitor: AtomicBool::new(true),
            counted: AtomicBool::new(false),
            method,
            sni,
            completed: Notify::new(),
            result: parking_lot::Mutex::new(None),
        }
    }

    fn signal(&self, ok: bool) {
        *self.result.lock() = Some(ok);
        self.completed.notify_one();
    }

    async fn wait(&self) -> Option<bool> {
        self.completed.notified().await;
        *self.result.lock()
    }
}

/// Tokio orchestrator. Share via `Arc<Worker>` across accept/reaper/reporter
/// tasks (mirrors module-level globals + `_cycle_lock` in main.py).
pub struct Worker {
    pub config: Arc<Config>,
    pub picker: Arc<EndpointPicker>,
    pub stats: Arc<Stats>,
    pub conns: Arc<AsyncMutex<HashMap<ConnId, Arc<ConnEntry>>>>,
    pub sem: Arc<Semaphore>,
    pub shutdown: Arc<Notify>,
    pub interface_ipv4: String,
}

impl Worker {
    /// Resolve interface IPv4 from the first endpoint (mirrors
    /// `get_default_interface_ipv4(ENDPOINTS[0])`; fatal when unroutable).
    pub fn new(config: Config, stats: Arc<Stats>) -> anyhow::Result<Self> {
        if config.endpoints.is_empty() {
            anyhow::bail!("No endpoints configured");
        }
        let probe = config.endpoints[0].ip.clone();
        let iface = sni_core::net::get_default_interface_ipv4(&probe)
            .ok_or_else(|| anyhow::anyhow!("cannot determine default interface IPv4 (no route?)"))?;
        let max = config.max_connections.clamp(10, 2000);
        Ok(Self {
            picker: Arc::new(EndpointPicker::new(config.endpoints.clone())),
            config: Arc::new(config),
            stats,
            conns: Arc::new(AsyncMutex::new(HashMap::new())),
            sem: Arc::new(Semaphore::new(max)),
            shutdown: Arc::new(Notify::new()),
            interface_ipv4: iface,
        })
    }

    /// Round-robin ordered endpoints for one connection.
    pub fn pick_endpoints(&self) -> Vec<Endpoint> {
        self.picker.pick_ordered()
    }

    /// Random SNI per connection.
    pub fn pick_sni(&self) -> String {
        pick_sni(&self.config.fake_snis).unwrap_or_default()
    }

    pub fn tcp_filter(&self) -> String {
        build_tcp_filter(&self.interface_ipv4, &self.config.endpoints)
    }

    pub fn quic_filter(&self) -> String {
        build_quic_filter(&self.interface_ipv4)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Called by WinDivert injector threads on handshake outcome.
    /// Mirrors `t2a_event.set()` with `t2a_msg` success/failure.
    pub async fn complete_handshake(&self, id: &ConnId, ok: bool) {
        let entry = { self.conns.lock().await.get(id).cloned() };
        if let Some(e) = entry {
            e.monitor.store(false, Ordering::Relaxed);
            e.signal(ok);
        }
    }

    /// Accept loop. Mirrors `main()` while-not-shutdown accept + spawn.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        tracing::info!("accept loop started");
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                res = listener.accept() => {
                    match res {
                        Ok((sock, addr)) => {
                            let w = Arc::clone(&self);
                            tokio::spawn(async move { w.handle(sock, addr).await });
                        }
                        Err(e) => {
                            tracing::warn!("accept failed: {}", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        tracing::info!("accept loop stopped");
        Ok(())
    }

    /// One client connection. Mirrors `main.handle()` stages:
    /// pick SNI -> fake hello -> bind -> failover connect -> register ->
    /// handshake wait (timeout) -> relay. Early errors close + `note_fail`.
    async fn handle(self: Arc<Self>, incoming: TcpStream, _peer: SocketAddr) {
        // Non-blocking semaphore (mirrors `acquire(blocking=False)`).
        let _permit = match self.sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("connection limit reached, dropping client");
                self.stats.increment_failed();
                return;
            }
        };

        let sni = self.pick_sni();
        if sni.is_empty() {
            self.stats.increment_failed();
            return;
        }
        let profile = TlsProfile::parse(&self.config.tls_fingerprint).unwrap_or(TlsProfile::Legacy);
        let _fake_hello = build_fake_client_hello(sni.as_bytes(), profile);

        let ordered = self.pick_endpoints();
        if ordered.is_empty() {
            self.stats.increment_failed();
            return;
        }
        let first_key = ep_key(&ordered[0]);

        // Failover connect (fresh socket per attempt; Python reused one fd —
        // same observable behavior, avoids consumed-socket reuse).
        let (outgoing, connected_ep) = match self.try_connect(&ordered).await {
            Some(v) => v,
            None => {
                // Mirrors `note_fail(None, ep_key(first), sni)`.
                self.stats.record_result(&first_key, &sni, false, "");
                self.stats.increment_failed();
                return;
            }
        };
        let cur_key = ep_key(&connected_ep);

        // Register under the REAL endpoint (mirrors re-key on failover).
        let method = self.config.bypass_method.clone();
        let local: SocketAddr = match outgoing.local_addr() {
            Ok(a) => a,
            Err(_) => {
                self.stats.record_result(&cur_key, &sni, false, &method);
                self.stats.increment_failed();
                return;
            }
        };
        let (local_ip, local_port) = match local {
            SocketAddr::V4(v) => (v.ip().to_string(), v.port()),
            SocketAddr::V6(_) => {
                self.stats.record_result(&cur_key, &sni, false, &method);
                self.stats.increment_failed();
                return;
            }
        };
        let id: ConnId = (
            self.interface_ipv4.clone(),
            local_port,
            connected_ep.ip.clone(),
            connected_ep.port,
        );
        let _ = local_ip; // (kept for future bind-verify logging)
        let entry = Arc::new(ConnEntry::new(id.clone(), method.clone(), sni.clone()));
        // Injector owns active/total counting once wired; Phase 3 counts here
        // so the dashboard stays correct with passthrough threads.
        self.stats.increment_total();
        self.stats.increment_active();
        entry.counted.store(true, Ordering::Relaxed);
        {
            // Pre-register with FIRST then re-key (mirrors main.py two-step).
            let mut map = self.conns.lock().await;
            let first_id: ConnId = (
                self.interface_ipv4.clone(),
                local_port,
                ordered[0].ip.clone(),
                ordered[0].port,
            );
            map.insert(first_id.clone(), Arc::clone(&entry));
            if first_id != id {
                map.remove(&first_id);
            }
            map.insert(id.clone(), Arc::clone(&entry));
        }

        // Handshake wait (mirrors `wait_for(t2a_event.wait(), TIMEOUT)`).
        let timeout = Duration::from_secs_f64(self.config.handshake_timeout.clamp(0.5, 10.0));
        let ok = match tokio::time::timeout(entry.wait(), timeout).await {
            Ok(Some(true)) => true,
            Ok(Some(false)) => false,
            Ok(None) => false,
            Err(_) => false, // timeout — same path as `t2a_msg != fake_data_ack_recv`
        };
        if !ok {
            self.note_fail(&entry, &cur_key).await;
            self.evict(&id).await;
            return;
        }
        // Success (mirrors `record_result(..., True, method)`).
        self.stats
            .record_result(&cur_key, &sni, true, &entry.method);
        // Handshake done: injector already cleared monitor; drop table entry
        // before relay (mirrors `monitor=False; pop` before relay loops).
        entry.monitor.store(false, Ordering::Relaxed);
        if entry.counted.swap(false, Ordering::Relaxed) {
            self.stats.finish_success();
            // finish_success decrements active AND counts success; we already
            // incremented active above, so re-increment active to keep relay
            // accounting simple (relay close does not touch handshake stats).
            self.stats.increment_active();
        }
        self.evict(&id).await;

        // Bidirectional relay (mirrors two `relay_main_loop` tasks + peer cancel).
        relay_bidirectional(incoming, outgoing, Arc::clone(&self.stats)).await;
        // Relay finished: release the slot (handshake success already counted).
        self.stats.decrement_active();
        // Permit (`_permit`) drops here (mirrors `conn_sem.release()`).
    }

    /// Try endpoints in order with 5s per-attempt timeout. Mirrors `try_connect`.
    async fn try_connect(&self, ordered: &[Endpoint]) -> Option<(TcpStream, Endpoint)> {
        for ep in ordered {
            // Last-mile guard (mirrors `sanitize_for_socket`).
            let ip: std::net::IpAddr = match ep.ip.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            if ep.port == 0 {
                continue;
            }
            let target = SocketAddr::new(ip, ep.port);
            // Fresh socket per attempt, bound to the egress interface.
            let sock = match TcpSocket::new_v4() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let bind_addr: SocketAddr = format!("{}:0", self.interface_ipv4).parse().ok()?;
            if sock.bind(bind_addr).is_err() {
                continue;
            }
            match tokio::time::timeout(Duration::from_secs(5), sock.connect(target)).await {
                Ok(Ok(stream)) => return Some((stream, ep.clone())),
                _ => continue,
            }
        }
        tracing::debug!("all endpoints failed");
        None
    }

    /// Failure accounting without double-count (mirrors `note_fail`).
    async fn note_fail(&self, entry: &ConnEntry, endpoint_key: &str) {
        self.stats
            .record_result(endpoint_key, &entry.sni, false, &entry.method);
        if entry.counted.swap(false, Ordering::Relaxed) {
            // Injector already counted via finish_failed when it saw the
            // unexpected packet; here the engine owns it.
            entry.monitor.store(false, Ordering::Relaxed);
            self.stats.finish_failed();
        } else {
            self.stats.increment_failed();
        }
    }

    async fn evict(&self, id: &ConnId) {
        self.conns.lock().await.remove(id);
    }

    /// Safety net: evict stale `monitor=false` entries older than max_age.
    /// Mirrors `connection_reaper(interval=60, max_age=120)`.
    pub async fn reaper(self: Arc<Self>, interval: Duration, max_age: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tick.tick() => {
                    let now = Instant::now();
                    let mut map = self.conns.lock().await;
                    let before = map.len();
                    map.retain(|_, e| {
                        e.monitor.load(Ordering::Relaxed) || now.duration_since(e.created_at) <= max_age
                    });
                    let reaped = before - map.len();
                    if reaped > 0 {
                        tracing::debug!("reaped {} stale connection(s)", reaped);
                    }
                }
            }
        }
    }

    /// JSON snapshot line every 2s for the GUI pipe. Mirrors `stats_reporter`.
    pub async fn reporter(self: Arc<Self>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tick.tick() => {
                    let snap = self.stats.snapshot();
                    match serde_json::to_string(&snap) {
                        Ok(line) => println!("{}", line),
                        Err(_) => {}
                    }
                }
            }
        }
    }
}

/// Bidirectional copy with per-direction traffic accounting.
/// Mirrors two `relay_main_loop` tasks (`up` clients->net, `down` net->clients)
/// with peer-cancel on EOF/error.
async fn relay_bidirectional(incoming: TcpStream, outgoing: TcpStream, stats: Arc<Stats>) {
    let (mut ri, mut wi) = incoming.into_split();
    let (mut ro, mut wo) = outgoing.into_split();
    let s_up = Arc::clone(&stats);
    let s_down = Arc::clone(&stats);
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 65575];
        loop {
            match ri.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    s_up.add_traffic(n as u64, 0);
                    if wo.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 65575];
        loop {
            match ro.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    s_down.add_traffic(0, n as u64);
                    if wi.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    // First direction to finish wins (mirrors peer_task.cancel()).
    tokio::select! {
        _ = up => {},
        _ = down => {},
    }
}
