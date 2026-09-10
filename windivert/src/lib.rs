//! Safe WinDivert wrapper: replaces `injecter.py::TcpInjector`.
//!
//! Phase 1: real `windows-rs` bindings (`ffi.rs`, dynamic `LoadLibrary`) +
//! safe owner (`handle.rs`). `unsafe` is confined to those two modules and
//! never escapes — all other crates use `WindivertHandle` + `Packet`.
//!
//! Layout:
//! - `ffi` — raw `WinDivertOpen/Recv/Send/Close/Shutdown` + `WINDIVERT_ADDRESS`
//! - `handle` — safe `WindivertHandle::open/recv/send/run/stop` (port of `TcpInjector`)

pub mod ffi;
pub mod handle;

pub use handle::WindivertHandle;

use bytes::BytesMut;

#[derive(Debug, thiserror::Error)]
pub enum WindivertError {
    #[error("WinDivert not available on this platform (Windows + Admin + driver required)")]
    UnsupportedPlatform,
    #[error("driver open failed: {0}")]
    OpenFailed(String),
    #[error("recv failed: {0}")]
    RecvFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("empty filter")]
    EmptyFilter,
}

/// Direction bit carried alongside each captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// Captured packet: raw bytes + direction + (Windows) WinDivert address.
/// Phase 2 adds IPv4/TCP field parsing on top of `raw` (no extra FFI).
#[derive(Debug, Clone)]
pub struct Packet {
    pub direction: Direction,
    pub raw: BytesMut,
    #[cfg(windows)]
    pub(crate) addr: Option<crate::ffi::WindivertAddress>,
    #[cfg(not(windows))]
    pub(crate) addr: Option<crate::ffi::WindivertAddress>,
}

impl Packet {
    pub fn new(direction: Direction, raw: Vec<u8>) -> Self {
        Self {
            direction,
            raw: BytesMut::from(&raw[..]),
            addr: None,
        }
    }

    /// Raw packet bytes (IPv4 + TCP/UDP).
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Clone this packet with replaced raw bytes, preserving direction and
    /// the WinDivert address (interface/loopback/impostor bits).
    ///
    /// Needed by the unified GUI's DPI dispatch (`engine.rs`): fake segments
    /// built with `sni_core::tcp::build_fake_tcp` must be reinjected with the
    /// *original* packet's address, which lives in `pub(crate) addr` and is
    /// otherwise unreachable from downstream crates.
    pub fn with_raw(&self, raw: Vec<u8>) -> Self {
        Self {
            direction: self.direction,
            raw: BytesMut::from(&raw[..]),
            addr: self.addr,
        }
    }

    pub fn is_inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }

    pub fn is_outbound(&self) -> bool {
        self.direction == Direction::Outbound
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

/// Injector behavior shared by TCP (`FakeTcpInjector`, Phase 2) and UDP
/// (`QuicInjector`, Phase 2). Mirrors `TcpInjector.inject` abstract method.
pub trait Injector: Send + Sync {
    fn inject(&self, packet: Packet);
    fn filter(&self) -> &str;
}
