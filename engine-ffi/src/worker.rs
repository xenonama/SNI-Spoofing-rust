//! Async orchestrator: port of `main.py` accept/failover/relay engine.
//!
//! Moved verbatim from `backend/src/worker.rs` into the unified `sni-gui`
//! binary. `Worker` owns ENDPOINTS (round-robin), FAKE_SNIS (random),
//! connection table, semaphore, stats. Packet-level WinDivert glue
//! (`engine.rs` DPI dispatch) signals handshake completion via
//! `complete_handshake`; until a packet matches, `handle()` times out per
//! HANDSHAKE_TIMEOUT (same observable path as Python DPI failure).
//!
//! One deliberate change vs the old backend: `reporter()` no longer prints
//! JSON to stdout (there is no GUI pipe anymore — the GUI polls
//! `Stats::snapshot()` directly (throttled to 1Hz). It now emits at `debug` level
//! and is unused by default; kept for parity/debugging.

use sni_core::{
    config::{Config, Endpoint},
    fake_tcp::BypassMethod,
    picker::{build_ipv6_drop_filter, build_quic_filter, build_tcp_filter, ep_key, pick_sni, EndpointPicker},
    stats::Stats,
};
use parking_lot::Mutex as ParkMutex;
use serde::Serialize;
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

/// One live relay session for the Active Connections view (U5).
/// `uptime_secs` is computed at snapshot time; `started` never crosses FFI.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveConn {
    pub local_port: u16,
    pub remote: String,
    pub method: String,
    pub uptime_secs: u64,
}

/// Internal relay-session record (holds the start `Instant`).
struct ActiveRelay {
    local_port: u16,
    remote: String,
    method: String,
    started: Instant,
}

/// FIX(#3b): guarantees `decrement_active` and `active_relays.remove`
/// run even if `handle()` panics or is cancelled mid-relay. Armed
/// once, right after the `increment_active` / `active_relays.insert`,
/// so any subsequent `.await` is protected.
struct ActiveGuard {
    stats: Arc<Stats>,
    relays: Arc<ParkMutex<HashMap<ConnId, ActiveRelay>>>,
    // FIX(#6): per-connection resolved-method record, cleaned on drop.
    resolved_methods: Arc<ParkMutex<HashMap<ConnId, String>>>,
    id: ConnId,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.stats.decrement_active();
        self.relays.lock().remove(&self.id);
        // FIX(#6): also drop the per-connection resolved-method record.
        self.resolved_methods.lock().remove(&self.id);
    }
}

/// FIX(#7): adaptive method selection for the "auto" config.
/// Starts on a random real method and sticks to it for a window
/// of connections or time. Rotates when the current method is
/// failing or a budget is exhausted, so the engine can discover
/// which method works on the current network without paying the
/// old "random per connection" penalty.
pub struct AutoState {
    pub current: BypassMethod,
    pub attempts: u32,
    pub failures: u32,
    pub started_at: Instant,
}

impl AutoState {
    /// Rotate after this many connections on the same method.
    pub const MAX_ATTEMPTS: u32 = 10;
    /// Rotate after this many failures on the same method.
    pub const MAX_FAILURES: u32 = 3;
    /// Rotate after this many seconds on the same method.
    pub const MAX_SECS: u64 = 60;

    pub fn new() -> Self {
        // BypassMethod::Auto.resolve() returns a random real method
        // (see core/src/fake_tcp.rs). We reuse that pool so the
        // two systems stay in sync.
        Self {
            current: BypassMethod::Auto.resolve(),
            attempts: 0,
            failures: 0,
            started_at: Instant::now(),
        }
    }

    /// Record one connection outcome. Returns `true` when the
    /// caller should rotate the current method.
    pub fn record(&mut self, success: bool) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        if !success {
            self.failures = self.failures.saturating_add(1);
        }
        self.failures >= Self::MAX_FAILURES
            || self.attempts >= Self::MAX_ATTEMPTS
            || self.started_at.elapsed().as_secs() >= Self::MAX_SECS
    }

    /// Pick a fresh random real method, avoiding `self.current`.
    /// A couple of retries is enough — the pool has 9 entries.
    pub fn rotate(&mut self) {
        let previous = self.current;
        let mut next = BypassMethod::Auto.resolve();
        for _ in 0..3 {
            if next != previous {
                break;
            }
            next = BypassMethod::Auto.resolve();
        }
        tracing::info!(
            "auto: rotating method {} -> {} (attempts={} failures={} elapsed={}s)",
            previous.as_str(),
            next.as_str(),
            self.attempts,
            self.failures,
            self.started_at.elapsed().as_secs()
        );
        self.current = next;
        self.attempts = 0;
        self.failures = 0;
        self.started_at = Instant::now();
    }
}

/// Per-connection entry (subset of `FakeInjectiveConnection` needed by the
/// orchestrator; sockets stay owned by `handle()` tasks).
pub struct ConnEntry {
    #[allow(dead_code)]
    pub id: ConnId,
    pub created_at: Instant,
    pub monitor: AtomicBool,
    // FIX(dedup): dead `counted` flag removed (write-only after the
    // note_fail cleanup; verdict comes from bytes moved, not a flag).
    pub method: String,
    // FIX(dedup): `sni` lost its only reader with note_fail; kept as
    // debug state under allow(dead_code), same as `id` above.
    #[allow(dead_code)]
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

/// Tokio orchestrator. Share via `Arc<Worker>` across accept/reaper tasks
/// (mirrors module-level globals + `_cycle_lock` in main.py).
pub struct Worker {
    pub config: Arc<Config>,
    pub picker: Arc<EndpointPicker>,
    pub stats: Arc<Stats>,
    pub conns: Arc<AsyncMutex<HashMap<ConnId, Arc<ConnEntry>>>>,
    pub sem: Arc<Semaphore>,
    pub shutdown: Arc<Notify>,
    pub interface_ipv4: String,
    // IMPROVE(U5): sync relay-session table for the Active Connections view.
    // `parking_lot` (sync) instead of the async `conns` map so the sync FFI
    // layer can snapshot without a Tokio runtime. Inserted before relay,
    // removed after; replaced per connection, never appended (D2: no leak).
    active_relays: Arc<ParkMutex<HashMap<ConnId, ActiveRelay>>>,
    // FIX(perf): sync mirror of `conns` for the DPI fast-path guard.
    // The capture thread (std::thread) cannot await the tokio Mutex,
    // and try_lock() on it was unreliable under contention. A
    // parking_lot Mutex<HashSet<ConnId>> is lock-free enough for the
    // read-heavy fast path.
    pub dpi_conns: Arc<ParkMutex<std::collections::HashSet<ConnId>>>,
    /// FIX(#7): adaptive state for the "auto" config. Unused when
    /// bypass_method is a concrete method, but always constructed so
    /// a live config change can flip into auto without a restart.
    pub auto_state: Arc<ParkMutex<AutoState>>,
    /// FIX(#6): resolved method per active connection. When config is
    /// "auto", the DPI state machine resolved it to one of the real
    /// methods per connection. This map records that choice so stats
    /// can rank the actual method instead of the useless "auto"
    /// placeholder. Cleaned up by ActiveGuard.
    pub resolved_methods: Arc<ParkMutex<HashMap<ConnId, String>>>,
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
            active_relays: Arc::new(ParkMutex::new(HashMap::new())),
            // FIX: init sync mirror for DPI fast-path guard.
            dpi_conns: Arc::new(ParkMutex::new(std::collections::HashSet::new())),
            // FIX(#7): sticky-auto state + per-connection resolved methods.
            auto_state: Arc::new(ParkMutex::new(AutoState::new())),
            resolved_methods: Arc::new(ParkMutex::new(HashMap::new())),
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
        // FIX #8: pass ip_mode so "ipv6" mode returns the IPv6 drop filter.
        build_tcp_filter(
            &self.interface_ipv4,
            &self.config.endpoints,
            &self.config.ip_mode,
        )
    }

    pub fn quic_filter(&self) -> String {
        build_quic_filter(&self.interface_ipv4)
    }

    /// FIX #8: IPv6 drop filter. Only used when ip_mode is "ipv4" or
    /// "both" — forces the browser to fall back to IPv4 so the fake
    /// burst keeps working.
    pub fn ipv6_drop_filter(&self) -> String {
        build_ipv6_drop_filter(&self.config.endpoints)
    }

    // FIX(perf): sync fast-path check for the DPI dispatch guard. Uses the
    // existing `active_relays` table (sync parking_lot, lives for the whole
    // relay) so the capture thread can test membership without a Tokio
    // runtime. `conns` cannot be used here: it is a tokio Mutex (no sync
    // lock from a std thread) and it is evicted before relay starts.
    pub fn is_known_relay(&self, id: &ConnId) -> bool {
        self.active_relays.lock().contains_key(id)
    }

    /// FIX(#7): returns the concrete method this connection should
    /// use. For a non-auto config this is just the config method. For
    /// "auto" it is the current sticky method from `auto_state`.
    pub fn resolve_method_for_connection(&self, cfg_method: BypassMethod) -> BypassMethod {
        match cfg_method {
            BypassMethod::Auto => self.auto_state.lock().current,
            other => other,
        }
    }

    /// FIX(#7): record a connection outcome and rotate the sticky
    /// method if the auto budget is spent. No-op when the config is
    /// not "auto".
    pub fn record_connection_result(&self, cfg_method: BypassMethod, success: bool) {
        if !matches!(cfg_method, BypassMethod::Auto) {
            return;
        }
        let mut st = self.auto_state.lock();
        if st.record(success) {
            st.rotate();
        }
    }

    /// FIX(#6): called by the DPI dispatch when it commits to a fake
    /// burst, so stats later record the actual resolved method.
    pub fn record_resolved_method(&self, id: &ConnId, method: &str) {
        self.resolved_methods
            .lock()
            .insert(id.clone(), method.to_string());
    }

    /// Sync snapshot of live relay sessions for the U5 Active Connections
    /// view. Lock-free w.r.t. Tokio (parking_lot only), so the sync C ABI
    /// can call it directly. Sorted by uptime, longest first.
    pub fn snapshot_active(&self) -> Vec<ActiveConn> {
        let map = self.active_relays.lock();
        let now = Instant::now();
        let mut out: Vec<ActiveConn> = map
            .values()
            .map(|r| ActiveConn {
                local_port: r.local_port,
                remote: r.remote.clone(),
                method: r.method.clone(),
                uptime_secs: now.duration_since(r.started).as_secs(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.uptime_secs
                .cmp(&a.uptime_secs)
                .then_with(|| a.local_port.cmp(&b.local_port))
        });
        out
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
        // FIX P2: wire decoy is built in engine.rs DPI path; building another
        // hello here was dead code (never sent) with independent randomness,
        // causing stats-vs-wire SNI mismatch. Accounting SNI only.

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
                // FIX: use the configured method so the method scoreboard
                // sees this failure. Previously empty "" was skipped by
                // Stats::record_result.
                let m = self.config.bypass_method.clone();
                self.stats.record_result(&first_key, &sni, false, &m);
                self.stats.increment_failed();
                return;
            }
        };
        let cur_key = ep_key(&connected_ep);

        // Register under the REAL endpoint (mirrors re-key on failover).
        let method = self.config.bypass_method.clone();
        // FIX(#7): parsed method is used for both the sticky resolver
        // and the outcome recorder.
        let cfg_method = BypassMethod::parse(&self.config.bypass_method)
            .unwrap_or(BypassMethod::WrongSeq);
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
        // FIX P4: use the actual socket local IP, not interface_ipv4. On
        // multi-route/VPN the egress IP for this endpoint can differ from the
        // route to endpoints[0]; using iface breaks ConnId<->DpiKey matching
        // (engine now uses WinDivert direction, so IDs must be real).
        let id: ConnId = (
            local_ip.clone(),
            local_port,
            connected_ep.ip.clone(),
            connected_ep.port,
        );
        let _ = local_ip; // (kept for future bind-verify logging)
        let entry = Arc::new(ConnEntry::new(id.clone(), method.clone(), sni.clone()));
        // Injector owns active/total counting once wired; counts here so the
        // dashboard stays correct with passthrough threads.
        self.stats.increment_total();
        self.stats.increment_active();
        // FIX: pre-register was a no-op (immediately removed). Just
        // register the real connection id under the actual connected
        // endpoint, which is what the DPI dispatch uses.
        // (Preserved history: pre-register with FIRST then re-key mirrored
        // main.py two-step, but first_id was removed right after insert.)
        {
            let mut map = self.conns.lock().await;
            map.insert(id.clone(), Arc::clone(&entry));
        }
        // FIX(perf): mirror to the sync-side set for the DPI fast path.
        self.dpi_conns.lock().insert(id.clone());

        // FIX(deadlock): start the relay IMMEDIATELY. The handshake signal
        // (Path B: payload > 0) cannot fire before the client's real
        // ClientHello reaches the server, which is impossible until the
        // relay is running. Run the handshake wait CONCURRENTLY as a
        // quality signal for stats only.
        // (Preserved history: Handshake wait mirrors
        // `wait_for(t2a_event.wait(), TIMEOUT)`; previously gated relay.)
        // Register the relay session BEFORE waiting so it appears live
        // in the Active Connections view.
        // IMPROVE(U5): register the relay session so the sync FFI snapshot
        // sees live connections (kept here, before relay, so the view is live
        // during the concurrent handshake wait).
        let relay_id = id.clone();
        self.active_relays.lock().insert(
            relay_id.clone(),
            ActiveRelay {
                local_port,
                remote: cur_key.clone(),
                method: entry.method.clone(),
                started: Instant::now(),
            },
        );

        // FIX(#3b): arm the drop guard so every exit path (return, panic,
        // cancellation) decrements active and clears the relay row.
        let _active_guard = ActiveGuard {
            stats: Arc::clone(&self.stats),
            relays: Arc::clone(&self.active_relays),
            // FIX(#6): guard also owns the resolved-method cleanup.
            resolved_methods: Arc::clone(&self.resolved_methods),
            id: relay_id.clone(),
        };

        // FIX(stats): the handshake signal is advisory — record it in a
        // shared flag, but do NOT decide success/fail here. The final
        // verdict comes from the relay outcome below.
        // FIX(deadlock): history preserved — the handshake wait previously
        // gated relay and did stats inline; now it only sets the advisory
        // flag while the relay runs concurrently.
        let hs_ok = Arc::new(AtomicBool::new(false));
        let hs_ok_bg = Arc::clone(&hs_ok);
        let entry_for_hs = Arc::clone(&entry);
        let timeout = Duration::from_secs_f64(self.config.handshake_timeout.clamp(0.5, 10.0));
        let hs_task = tokio::spawn(async move {
            match tokio::time::timeout(timeout, entry_for_hs.wait()).await {
                Ok(Some(true)) => {
                    hs_ok_bg.store(true, Ordering::Relaxed);
                    entry_for_hs.monitor.store(false, Ordering::Relaxed);
                }
                _ => {
                    // Timeout or explicit fail: nothing to record here.
                    // The relay will decide the final verdict.
                }
            }
        });

        // FIX(deadlock): evict the handshake conns entry (the DPI state machine
        // no longer needs it). The spawned task holds its own Arc<ConnEntry>.
        // (Preserved history: handshake done drops table entry before relay,
        // mirrors `monitor=False; pop` before relay loops.)
        self.evict(&id).await;
        // FIX(perf): remove from the sync-side mirror as well.
        // FIX: evict() already removes from dpi_conns; this second remove
        // is a harmless no-op that keeps the prompt-specified symmetry.
        self.dpi_conns.lock().remove(&id);

        // FIX(stats): snapshot byte counters BEFORE the relay so we can
        // measure how much actually flowed through this connection.
        let bytes_before = {
            let snap = self.stats.snapshot();
            snap.up_bytes + snap.down_bytes
        };

        // Bidirectional relay (mirrors two `relay_main_loop` tasks + peer cancel).
        // FIX(deadlock): run the relay unconditionally.
        // FIX(stats): run the relay unconditionally (already the case).
        relay_bidirectional(incoming, outgoing, Arc::clone(&self.stats)).await;

        // FIX(deadlock): relay done — cancel the pending handshake wait if still running.
        hs_task.abort();
        let _ = hs_task.await;

        // FIX(stats): final verdict — bytes actually moved?
        let bytes_after = {
            let snap = self.stats.snapshot();
            snap.up_bytes + snap.down_bytes
        };
        let bytes_moved = bytes_after.saturating_sub(bytes_before);
        // Minimum threshold: a real TLS session will move at least a few
        // hundred bytes. Below that, the endpoint never answered.
        let relay_ok = bytes_moved >= 100;

        // FIX(#6): prefer the DPI-resolved method (real one) over the
        // config string. Falls back to the config string if the DPI
        // never committed to a fake burst.
        let method_for_stats: String = self
            .resolved_methods
            .lock()
            .get(&id)
            .cloned()
            .unwrap_or_else(|| entry.method.clone());

        if relay_ok {
            self.stats
                .record_result(&cur_key, &sni, true, &method_for_stats);
            self.stats.increment_success();
            // Handshake signal may or may not have fired — both are fine.
            let _ = hs_ok.load(Ordering::Relaxed);
        } else {
            self.stats
                .record_result(&cur_key, &sni, false, &method_for_stats);
            self.stats.increment_failed();
        }

        // FIX(#7): tell the auto state machine about this outcome. No-op
        // unless config is "auto".
        self.record_connection_result(cfg_method, relay_ok);

        // Clean up the per-connection method record for this id.
        self.resolved_methods.lock().remove(&id);

        // FIX(stats): single active decrement for this connection, in both
        // branches. The success path no longer needs a compensating
        // increment_active because we never call finish_success().
        // Relay finished: release the slot (handshake stats already counted).
        // FIX(#3b): explicit decrement_active + active_relays.remove removed;
        // the ActiveGuard above handles both on scope exit (all paths).
        // IMPROVE(U5): always evict the relay record, even on early return
        // paths above this point the insert never happened, so remove is a
        // no-op there; here it prevents stale rows (D2: no leak).
        // (Preserved: guard now performs this eviction.)
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
            // FIX P4: a stale interface_ipv4 must skip this endpoint, not abort
            // all remaining endpoints (previously `ok()?` returned None).
            let bind_addr: SocketAddr = match format!("{}:0", self.interface_ipv4).parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            if sock.bind(bind_addr).is_err() {
                continue;
            }
            // FIX(#2a): pre-seed the outgoing tuple in dpi_conns. The WinDivert
            // capture thread runs concurrently and will see the SYN this
            // socket is about to send; without the seed the fast path cannot
            // distinguish it from foreign traffic to the same anycast IP.
            let seeded_key: Option<ConnId> = match sock.local_addr() {
                Ok(SocketAddr::V4(v4)) => {
                    let k: ConnId = (
                        v4.ip().to_string(),
                        v4.port(),
                        ep.ip.clone(),
                        ep.port,
                    );
                    self.dpi_conns.lock().insert(k.clone());
                    Some(k)
                }
                _ => None,
            };
            match tokio::time::timeout(Duration::from_secs(5), sock.connect(target)).await {
                Ok(Ok(stream)) => return Some((stream, ep.clone())),
                _ => {
                    // FIX(#2a): drop the seed if the connect failed.
                    if let Some(k) = seeded_key {
                        self.dpi_conns.lock().remove(&k);
                    }
                    continue;
                }
            }
        }
        // Visible at INFO (not debug) so Smart Tools / console users see
        // failover exhaustion without --log-level DEBUG. Forwarded to the
        // GUI console by the tracing bridge in main.rs (no raw SNI logged).
        tracing::warn!("all endpoints failed");
        None
    }

    // FIX(dedup): dead note_fail helper removed (the concurrent hs_task
    // inlines its own accounting); ConnEntry.counted went with it.
    async fn evict(&self, id: &ConnId) {
        self.conns.lock().await.remove(id);
        // FIX(perf): keep the sync mirror in lockstep.
        self.dpi_conns.lock().remove(id);
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
                    // FIX(#3c): mirror cleanup. dpi_conns is the sync-side read set
                    // for the DPI fast path; active_relays drives the U5 view. Both
                    // can accumulate stale rows if the guard path was skipped.
                    // `active_relays` should always be paired with a live `conns`
                    // entry (the guard removes it), so any orphan is a leak.
                    drop(map); // release conns lock before taking dpi_conns / relays
                    {
                        let live: std::collections::HashSet<ConnId> = {
                            let map = self.conns.lock().await;
                            map.keys().cloned().collect()
                        };
                        // Also keep any ConnId that still appears in active_relays as
                        // long as the relay is young (< max_age). We do not have a
                        // started-at here; instead we treat "present in active_relays"
                        // as still-live and only remove dpi_conns entries that are
                        // absent from both.
                        let live_relays: std::collections::HashSet<ConnId> = {
                            self.active_relays.lock().keys().cloned().collect()
                        };
                        let mut dpi = self.dpi_conns.lock();
                        let before = dpi.len();
                        dpi.retain(|k| live.contains(k) || live_relays.contains(k));
                        let reaped = before - dpi.len();
                        if reaped > 0 {
                            tracing::debug!("reaped {} stale dpi_conns entry(ies)", reaped);
                        }
                    }
                }
            }
        }
    }

    /// In-process status tick. The old backend printed one JSON `Snapshot`
    /// line per interval for the GUI pipe; the unified binary polls
    /// `Stats::snapshot()` directly, so this only logs at debug level.
    /// Kept so background-task wiring stays identical.
    #[allow(dead_code)]
    pub async fn reporter(self: Arc<Self>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tick.tick() => {
                    let snap = self.stats.snapshot();
                    tracing::debug!(
                        active = snap.active,
                        total = snap.total,
                        ok = snap.success,
                        fail = snap.failed,
                        "stats tick"
                    );
                }
            }
        }
    }
}

/// Bidirectional copy with per-direction traffic accounting.
/// Mirrors two `relay_main_loop` tasks (`up` clients->net, `down` net->clients)
/// with peer-cancel on EOF/error.
async fn relay_bidirectional(incoming: TcpStream, outgoing: TcpStream, stats: Arc<Stats>) {
    // FIX(#3a): read-idle timeout (5 minutes). Without it a half-open or
    // keep-alive connection with no traffic pins handle() forever and leaks Active.
    const RELAY_IDLE_SECS: u64 = 300;
    let (mut ri, mut wi) = incoming.into_split();
    let (mut ro, mut wo) = outgoing.into_split();
    let s_up = Arc::clone(&stats);
    let s_down = Arc::clone(&stats);
    // FIX P4: 16k buffers (was 64k x2 per conn, ~25MB churn at 200 conns);
    // still well above MSS, far less allocator pressure.
    // FIX P4: propagate FIN via shutdown(Write) on clean EOF so teardown is
    // graceful instead of RST-prone drop.
    // FIX(#3a): read-idle timeout. A half-open peer or keep-alive
    // with no traffic for RELAY_IDLE_SECS ends the relay so the
    // handler can decrement_active and clear active_relays.
    let mut up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let idle = Duration::from_secs(RELAY_IDLE_SECS);
        loop {
            match tokio::time::timeout(idle, ri.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    let _ = wo.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    s_up.add_traffic(n as u64, 0);
                    if wo.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
    });
    // FIX(#3a): read-idle timeout. A half-open peer or keep-alive
    // with no traffic for RELAY_IDLE_SECS ends the relay so the
    // handler can decrement_active and clear active_relays.
    let mut down = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let idle = Duration::from_secs(RELAY_IDLE_SECS);
        loop {
            match tokio::time::timeout(idle, ro.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    let _ = wi.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    s_down.add_traffic(0, n as u64);
                    if wi.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
    });
    // FIX 3: abort the loser task as soon as one direction ends so half-open
    // sockets and tasks cannot leak under load (mirrors peer_task.cancel()).
    // First direction to finish wins (mirrors peer_task.cancel()).
    tokio::select! {
        _ = &mut up => {
            down.abort();
            let _ = down.await;
        }
        _ = &mut down => {
            up.abort();
            let _ = up.await;
        }
    }
}
