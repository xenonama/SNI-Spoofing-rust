//! QUIC modes: replaces `fake_tcp.resolve_quic_mode` + `utils/quic.py` stubs.
//!
//! Phase 0: mode enum + validator. Packet helpers
//! (`is_quic_packet`, SNI swap) arrive in Phase 2 alongside TCP builders.

pub const SUPPORTED_QUIC_MODES: &[&str] = &["block", "spoof", "passthrough"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicMode {
    /// Drop UDP/443 so browsers fall back to HTTP/2 (default).
    Block,
    /// Same-length SNI swap in QUIC Initial (cleartext/stub only).
    Spoof,
    /// Forward QUIC untouched (Trojan+Xray HTTP/3 proxy mode).
    Passthrough,
}

impl QuicMode {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "spoof" => Ok(Self::Spoof),
            "passthrough" => Ok(Self::Passthrough),
            other => Err(format!(
                "unsupported QUIC mode: {:?} (expected one of {:?})",
                other, SUPPORTED_QUIC_MODES
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Spoof => "spoof",
            Self::Passthrough => "passthrough",
        }
    }
}
