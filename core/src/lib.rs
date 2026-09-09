//! sni-core: safe core logic ported from Python.
//!
//! Phase 0: module scaffolding only. No `unsafe` blocks.
//!
//! Python origins:
//! - `config` <- `utils/config_manager.py` + `main.py::load_config`
//! - `stats`  <- `monitor_connection.py`
//! - `fake_tcp` <- `fake_tcp.py` (pure helpers fully ported; wire sends in Phase 2)
//! - `tls`    <- `utils/packet_templates.py` + `utils/tls_fingerprint.py` (stubs)
//! - `quic`   <- `utils/quic.py` + `fake_tcp.QuicInjector` (mode enum only)
//! - `net`    <- `utils/network_tools.py`

pub mod config;
pub mod fake_tcp;
pub mod net;
pub mod picker;
pub mod quic;
pub mod selftest;
pub mod stats;
pub mod tcp;
pub mod tls;

// Re-exports for backend/gui convenience (mirrors `from X import Y` in main.py).
pub use config::{Config, Endpoint};
pub use fake_tcp::{BypassMethod, REAL_METHODS, SUPPORTED_METHODS};
pub use quic::{QuicMode, SUPPORTED_QUIC_MODES};
pub use stats::Stats;
