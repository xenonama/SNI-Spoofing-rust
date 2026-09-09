//! Safe handle: owns the driver HANDLE, exposes `open/recv/send/run/stop`.
//!
//! Mirrors `injecter.py::TcpInjector`:
//! - `__init__(w_filter)` -> `WindivertHandle::open(filter)`
//! - `run()` recv loop with 10ms backoff (no hot-spin)
//! - `stop()` signals + unblocks Recv + `Drop` closes (never panics)
//!
//! `unsafe` here is limited to delegating to `ffi::WinDivertDll` (which
//! already wraps the raw syscalls). No raw pointer escapes this module.

use crate::ffi;
use crate::{Direction, Packet, WindivertError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;

const RECV_BUF: usize = 65575; // mirrors `w.recv(65575)` in injecter.py
const RETRY_DELAY_MS: u64 = 10;

/// Shared ownership of the driver resources so `stop()` can be called from
/// another thread while `run()` blocks in `Recv`.
struct Inner {
    #[cfg(windows)]
    dll: ffi::WinDivertDll,
    #[cfg(windows)]
    raw: HANDLE,
    filter: String,
}

// WinDivert handles support concurrent Recv (one thread) + Send (pool threads)
// per docs; pydivert relies on this (`w.send` from fake-send pool while the
// capture thread blocks in `recv`). Mark accordingly with justification.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            // Never panics: close errors are ignored (mirrors `try: w.close()`).
            self.dll.close(self.raw);
        }
    }
}

/// Safe, threadsafe WinDivert session. Clone shares the session (like
/// sharing pydivert's `self.w` across the fake-send pool).
#[derive(Clone)]
pub struct WindivertHandle {
    inner: Arc<Inner>,
    stop: Arc<AtomicBool>,
}

impl WindivertHandle {
    /// Open the driver. Priority 0 / flags 0 match pydivert defaults.
    /// Returns rich hints on 1058/5/missing-DLL (see `ffi::open_error_hint`).
    pub fn open(filter: impl Into<String>) -> Result<Self, WindivertError> {
        let filter = filter.into();
        if filter.trim().is_empty() {
            return Err(WindivertError::EmptyFilter);
        }
        #[cfg(windows)]
        {
            let dll = ffi::WinDivertDll::load()?;
            // Priority 0, flags 0: plain intercept (not SNIFF/DROP).
            let raw = dll.open(&filter, 0, 0)?;
            tracing::info!(filter = %filter, "WinDivert opened");
            Ok(Self {
                inner: Arc::new(Inner {
                    dll,
                    raw,
                    filter,
                }),
                stop: Arc::new(AtomicBool::new(false)),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = filter;
            Err(WindivertError::UnsupportedPlatform)
        }
    }

    pub fn filter(&self) -> &str {
        &self.inner.filter
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        #[cfg(windows)]
        {
            // Unblock a thread parked in WinDivertRecv so `run()` exits promptly.
            // Best-effort: ignore errors (handle may already be closed).
            self.inner
                .dll
                .shutdown(self.inner.raw, ffi::WINDIVERT_SHUTDOWN_RECV);
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Blocking single-packet receive. Callers run this on a dedicated thread
    /// (WinDivertRecv has no async flavor; Phase 3 wraps with spawn_blocking).
    pub fn recv(&self) -> Result<Packet, WindivertError> {
        #[cfg(windows)]
        {
            if self.is_stopped() {
                return Err(WindivertError::RecvFailed("handle stopped".to_string()));
            }
            let mut buf = vec![0u8; RECV_BUF];
            let mut addr = ffi::WindivertAddress::default();
            let n = self.inner.dll.recv(self.inner.raw, &mut buf, &mut addr)?;
            buf.truncate(n as usize);
            Ok(Packet::from_address(buf, &addr))
        }
        #[cfg(not(windows))]
        {
            Err(WindivertError::UnsupportedPlatform)
        }
    }

    /// Reinject a packet. `reinject=true` = modified (recalc'd by driver);
    /// `false` = forward untouched. Mirrors `w.send(packet, reinject)`.
    pub fn send(&self, packet: &Packet) -> Result<(), WindivertError> {
        #[cfg(windows)]
        {
            if self.is_stopped() {
                return Err(WindivertError::SendFailed("handle stopped".to_string()));
            }
            let addr = packet.to_address();
            self.inner.dll.send(self.inner.raw, &packet.raw, &addr)?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = packet;
            Err(WindivertError::UnsupportedPlatform)
        }
    }

    /// Capture loop. Mirrors `TcpInjector.run()`:
    /// `with self.w: while not stop: recv -> inject; on error: break if
    /// stopping else sleep 10ms and continue (no hot-spin, no thread death)`.
    pub fn run(&self, mut inject: impl FnMut(Packet)) {
        tracing::info!(filter = %self.filter(), "capture loop started");
        while !self.is_stopped() {
            match self.recv() {
                Ok(pkt) => inject(pkt),
                Err(e) => {
                    if self.is_stopped() {
                        break;
                    }
                    tracing::debug!("recv error (surviving): {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                    continue;
                }
            }
        }
        tracing::info!("capture loop stopped");
    }
}

impl Packet {
    #[cfg(windows)]
    pub(crate) fn from_address(raw: Vec<u8>, addr: &ffi::WindivertAddress) -> Self {
        let direction = match addr.direction {
            ffi::WINDIVERT_DIRECTION_INBOUND => Direction::Inbound,
            ffi::WINDIVERT_DIRECTION_OUTBOUND => Direction::Outbound,
            _ => Direction::Unknown,
        };
        Self {
            direction,
            raw: bytes::BytesMut::from(&raw[..]),
            #[cfg(windows)]
            addr: Some(*addr),
            #[cfg(not(windows))]
            addr: None,
        }
    }

    #[cfg(windows)]
    pub(crate) fn to_address(&self) -> ffi::WindivertAddress {
        self.addr.unwrap_or_default()
    }
}
