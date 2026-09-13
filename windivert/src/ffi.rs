//! Raw WinDivert FFI via `windows-rs` types + dynamic `LoadLibrary`.
//!
//! This is the ONLY module allowed `unsafe` in the workspace (plus
//! `handle.rs` which wraps it immediately). All other crates use the safe
//! `WindivertHandle` API.
//!
//! Why dynamic load instead of `#[link(name = "WinDivert")]`:
//! - Compiles without `WinDivert.lib` at link time (review machines).
//! - Fails gracefully at runtime with actionable hints (1058/disabled,
//!   access-denied/Admin, missing DLL) mirroring `gui.py` +
//!   `main.py::_windivert_hint`.

#[cfg(windows)]
pub use inner::*;

#[cfg(windows)]
mod inner {
    use crate::WindivertError;
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::os::raw::{c_int, c_ushort};
    use windows::core::PCSTR;
    use windows::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    /// WinDivert network layer (we intercept at NETWORK, like pydivert default).
    pub const WINDIVERT_LAYER_NETWORK: c_int = 0;
    /// Shutdown modes for `WinDivertShutdown` (used to unblock a blocking Recv).
    pub const WINDIVERT_SHUTDOWN_RECV: c_int = 0;
    #[allow(dead_code)]
    pub const WINDIVERT_SHUTDOWN_SEND: c_int = 1;
    pub const WINDIVERT_SHUTDOWN_BOTH: c_int = 2;

    // FIX: WINDIVERT_DIRECTION_* are deprecated — direction now comes from
    // `addr.outbound()` (bit 17 of layer_event_bits). Kept for compat only.
    #[allow(dead_code)]
    pub const WINDIVERT_DIRECTION_OUTBOUND: u8 = 0;
    #[allow(dead_code)]
    pub const WINDIVERT_DIRECTION_INBOUND: u8 = 1;

    /// WinDivert 2.2 `WINDIVERT_ADDRESS` (NETWORK layer view).
    /// The bitfield UINT32 at offset 8 packs Layer/Event/Sniffed/Outbound/
    /// Loopback/Impostor/IPv6/checksum bits. Direction is bit 17
    /// (`Outbound`). The union at offset 12 carries IfIdx/SubIfIdx for
    /// the NETWORK layer.
    // FIX: corrected struct layout to match WinDivert 2.2 windivert.h
    // (Timestamp:INT64 + Layer/Event bitfield:UINT32 + IfIdx + SubIfIdx).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WindivertAddress {
        /// Wall-clock timestamp in nanoseconds (WinDivert 2.2).
        pub timestamp: i64,
        /// Packed bitfield: Layer:8 | Event:8 | Sniffed:1 | Outbound:1 |
        /// Loopback:1 | Impostor:1 | IPv6:1 | IPChecksum:1 | TCPChecksum:1 |
        /// UDPChecksum:1 | Reserved1:8 | Reserved2:16.
        pub layer_event_bits: u32,
        /// Interface index (NETWORK layer union member).
        pub if_idx: u32,
        /// Sub-interface index (NETWORK layer union member).
        pub sub_if_idx: u32,
    }

    impl WindivertAddress {
        #[inline]
        pub fn layer(&self) -> u8 {
            (self.layer_event_bits & 0xFF) as u8
        }
        #[inline]
        pub fn event(&self) -> u8 {
            ((self.layer_event_bits >> 8) & 0xFF) as u8
        }
        #[inline]
        pub fn sniffed(&self) -> bool {
            (self.layer_event_bits >> 16) & 1 != 0
        }
        #[inline]
        pub fn outbound(&self) -> bool {
            (self.layer_event_bits >> 17) & 1 != 0
        }
        #[inline]
        pub fn loopback(&self) -> bool {
            (self.layer_event_bits >> 18) & 1 != 0
        }
        #[inline]
        pub fn impostor(&self) -> bool {
            (self.layer_event_bits >> 19) & 1 != 0
        }
        #[inline]
        pub fn ipv6(&self) -> bool {
            (self.layer_event_bits >> 20) & 1 != 0
        }
    }

    // Function-pointer types (WinDivert.dll exports are `__cdecl` / extern "C").
    type FnOpen = unsafe extern "C" fn(*const c_char, c_int, i16, u64) -> HANDLE;
    type FnRecv = unsafe extern "C" fn(
        HANDLE,
        *mut c_void,
        u32,
        *mut u32,
        *mut WindivertAddress,
    ) -> i32; // BOOL as i32
    type FnSend = unsafe extern "C" fn(
        HANDLE,
        *const c_void,
        u32,
        *mut u32,
        *const WindivertAddress,
    ) -> i32;
    type FnClose = unsafe extern "C" fn(HANDLE) -> i32;
    type FnShutdown = unsafe extern "C" fn(HANDLE, c_int) -> i32;

    /// Dynamically loaded WinDivert.dll. Owns the HMODULE; `Drop` frees it.
    pub struct WinDivertDll {
        lib: HMODULE,
        open: FnOpen,
        recv: FnRecv,
        send: FnSend,
        close: FnClose,
        shutdown: FnShutdown,
    }

    // HMODULE/HANDLE are raw handles: safe to move across threads here because
    // all use is serialized through `WindivertHandle` (Send+Sync).
    unsafe impl Send for WinDivertDll {}
    unsafe impl Sync for WinDivertDll {}

    impl WinDivertDll {
        /// Load `WinDivert.dll` from EXE dir / PATH (same search as pydivert's
        /// `windivert_dll` folder once copied next to the binary).
        ///
        /// # Safety boundary
        /// `unsafe` is confined to `LoadLibrary`/`GetProcAddress`/fn-pointer
        /// calls. Callers get safe `Result` + hint strings, never raw pointers.
        pub fn load() -> Result<Self, WindivertError> {
            unsafe {
                let name: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
                let lib = match LoadLibraryW(windows::core::PCWSTR(name.as_ptr())) {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(WindivertError::OpenFailed(format!(
                            "LoadLibrary WinDivert.dll failed ({:?}). \
                             Copy WinDivert.dll + WinDivert64.sys next to the exe \
                             (same as pydivert windivert_dll) and run as Administrator.",
                            e
                        )));
                    }
                };
                // Helper: resolve one export or unload + error.
                unsafe fn sym<T>(lib: HMODULE, name: &str) -> Result<T, String> {
                    let c = CString::new(name).map_err(|e| e.to_string())?;
                    let addr = GetProcAddress(lib, PCSTR(c.as_ptr() as *const u8));
                    match addr {
                        Some(f) => Ok(std::mem::transmute_copy::<_, T>(&f)),
                        None => Err(format!("export {} not found", name)),
                    }
                }
                macro_rules! load_sym {
                    ($n:expr) => {
                        match sym(lib, $n) {
                            Ok(f) => f,
                            Err(e) => {
                                let _ = FreeLibrary(lib);
                                return Err(WindivertError::OpenFailed(format!(
                                    "WinDivert.dll is present but broken: {}. Reinstall pydivert's driver files.",
                                    e
                                )));
                            }
                        }
                    };
                }
                Ok(Self {
                    lib,
                    open: load_sym!("WinDivertOpen"),
                    recv: load_sym!("WinDivertRecv"),
                    send: load_sym!("WinDivertSend"),
                    close: load_sym!("WinDivertClose"),
                    shutdown: load_sym!("WinDivertShutdown"),
                })
            }
        }

        pub fn open(
            &self,
            filter: &str,
            priority: i16,
            flags: u64,
        ) -> Result<HANDLE, WindivertError> {
            let c = CString::new(filter).map_err(|_| WindivertError::EmptyFilter)?;
            // SAFETY: `c` outlives the call; WinDivert copies the filter string.
            let h = unsafe { (self.open)(c.as_ptr(), WINDIVERT_LAYER_NETWORK, priority, flags) };
            if h == INVALID_HANDLE_VALUE {
                let code = unsafe { GetLastError().0 };
                return Err(WindivertError::OpenFailed(open_error_hint(code)));
            }
            Ok(h)
        }

        pub fn recv(
            &self,
            handle: HANDLE,
            buf: &mut [u8],
            addr: &mut WindivertAddress,
        ) -> Result<u32, WindivertError> {
            let mut len: u32 = 0;
            // SAFETY: buf is valid for buf.len(), addr is valid. WinDivertRecv is
            // blocking; callers run it on a dedicated thread (see handle.rs).
            let ok = unsafe {
                (self.recv)(
                    handle,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    &mut len,
                    addr,
                )
            };
            if ok == 0 {
                let code = unsafe { GetLastError().0 };
                return Err(WindivertError::RecvFailed(format!(
                    "code {} — {}",
                    code,
                    recv_error_hint(code)
                )));
            }
            Ok(len)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn send(
            &self,
            handle: HANDLE,
            buf: &[u8],
            addr: &WindivertAddress,
        ) -> Result<u32, WindivertError> {
            let mut sent: u32 = 0;
            // SAFETY: buf valid for buf.len(), addr valid for the call.
            let ok = unsafe {
                (self.send)(
                    handle,
                    buf.as_ptr() as *const c_void,
                    buf.len() as u32,
                    &mut sent,
                    addr,
                )
            };
            if ok == 0 {
                let code = unsafe { GetLastError().0 };
                return Err(WindivertError::SendFailed(format!("code {}", code)));
            }
            Ok(sent)
        }

        pub fn shutdown(&self, handle: HANDLE, how: c_int) {
            // Best-effort unblock of a blocking Recv during `stop()`. Ignore errors.
            unsafe {
                let _ = (self.shutdown)(handle, how);
            }
        }

        pub fn close(&self, handle: HANDLE) {
            // Never panics; called from `Drop`.
            unsafe {
                let _ = (self.close)(handle);
            }
        }

        /// Expose raw CStr helper for tests (avoids unused-import warnings).
        #[allow(dead_code)]
        pub fn _cstr_len(s: &CStr) -> usize {
            s.to_bytes().len()
        }

        #[allow(dead_code)]
        pub fn _u16_size(_v: c_ushort) -> usize {
            std::mem::size_of::<c_ushort>()
        }
    }

    impl Drop for WinDivertDll {
        fn drop(&mut self) {
            unsafe {
                let _ = FreeLibrary(self.lib);
            }
        }
    }

    /// Actionable hints mirroring `main.py::_windivert_hint` +
    /// `gui.py::windivert_hint_for_error`. `code` is `GetLastError()`.
    pub fn open_error_hint(code: u32) -> String {
        match code {
            5 => "Access denied (code 5) — relaunch as Administrator. If already Admin, \
                  the driver is blocked (antivirus / GPO / Memory-integrity) or another \
                  WinDivert handle holds it. Reboot and retry."
                .to_string(),
            1058 => "Driver service cannot start (1058) — driver DISABLED/BLOCKED, not just rights. \
                      Fix in Admin cmd: `sc qc WinDivert` must not be DISABLED; \
                      `sc config WinDivert start= demand`; keep WinDivert64.sys next to the exe; \
                      reboot after first install; disable VPN/AV filtering or Core-isolation \
                      Memory-integrity; match bitness (64-bit on 64-bit Windows)."
                .to_string(),
            2 => "WinDivert.dll/.sys not found (code 2) — copy WinDivert.dll + WinDivert64.sys \
                  next to sni-backend.exe (same layout as pydivert windivert_dll)."
                .to_string(),
            _ => format!(
                "WinDivertOpen failed (code {}). Run as Administrator, keep driver files \
                 next to the exe, reboot after first install.",
                code
            ),
        }
    }

    fn recv_error_hint(code: u32) -> &'static str {
        match code {
            // ERROR_INSUFFICIENT_BUFFER or graceful shutdown during stop().
            122 => "buffer too small or shutting down",
            995 | 996 | 997 => "I/O cancelled (stopping?)",
            _ => "transient recv failure",
        }
    }
}

#[cfg(not(windows))]
pub mod stub {
    //! Non-Windows stub so `cargo check` passes on review machines.
    //! Every operation returns `UnsupportedPlatform` (mirrors Python's
    //! `RuntimeError: pydivert/WinDivert not available`).

    /// WinDivert 2.2 `WINDIVERT_ADDRESS` (NETWORK layer view).
    /// The bitfield UINT32 at offset 8 packs Layer/Event/Sniffed/Outbound/
    /// Loopback/Impostor/IPv6/checksum bits. Direction is bit 17
    /// (`Outbound`). The union at offset 12 carries IfIdx/SubIfIdx for
    /// the NETWORK layer.
    // FIX: corrected stub layout to mirror WinDivert 2.2 windivert.h
    // (same fields as the Windows real struct so review builds typecheck).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WindivertAddress {
        /// Wall-clock timestamp in nanoseconds (WinDivert 2.2).
        pub timestamp: i64,
        /// Packed bitfield: Layer:8 | Event:8 | Sniffed:1 | Outbound:1 |
        /// Loopback:1 | Impostor:1 | IPv6:1 | IPChecksum:1 | TCPChecksum:1 |
        /// UDPChecksum:1 | Reserved1:8 | Reserved2:16.
        pub layer_event_bits: u32,
        /// Interface index (NETWORK layer union member).
        pub if_idx: u32,
        /// Sub-interface index (NETWORK layer union member).
        pub sub_if_idx: u32,
    }

    impl WindivertAddress {
        #[inline]
        pub fn layer(&self) -> u8 {
            (self.layer_event_bits & 0xFF) as u8
        }
        #[inline]
        pub fn event(&self) -> u8 {
            ((self.layer_event_bits >> 8) & 0xFF) as u8
        }
        #[inline]
        pub fn sniffed(&self) -> bool {
            (self.layer_event_bits >> 16) & 1 != 0
        }
        #[inline]
        pub fn outbound(&self) -> bool {
            (self.layer_event_bits >> 17) & 1 != 0
        }
        #[inline]
        pub fn loopback(&self) -> bool {
            (self.layer_event_bits >> 18) & 1 != 0
        }
        #[inline]
        pub fn impostor(&self) -> bool {
            (self.layer_event_bits >> 19) & 1 != 0
        }
        #[inline]
        pub fn ipv6(&self) -> bool {
            (self.layer_event_bits >> 20) & 1 != 0
        }
    }

    pub const WINDIVERT_LAYER_NETWORK: i32 = 0;
    pub const WINDIVERT_SHUTDOWN_RECV: i32 = 0;
    pub const WINDIVERT_SHUTDOWN_BOTH: i32 = 2;
    // FIX: WINDIVERT_DIRECTION_* are deprecated — direction now comes from
    // `addr.outbound()` (bit 17 of layer_event_bits). Kept for compat only.
    #[allow(dead_code)]
    pub const WINDIVERT_DIRECTION_OUTBOUND: u8 = 0;
    #[allow(dead_code)]
    pub const WINDIVERT_DIRECTION_INBOUND: u8 = 1;
}
#[cfg(not(windows))]
pub use stub::*;