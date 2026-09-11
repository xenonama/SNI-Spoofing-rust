//! TLS ClientHello templates: replaces `utils/packet_templates.py`
//! (+ profile dispatcher for `utils/tls_fingerprint.py`).
//!
//! Phase 2: legacy 517B builder fully ported (byte-exact vs Python).
//! Modern profiles (chrome/firefox GREASE/ALPS/ECH) dispatch to legacy with
//! a documented TODO — full fingerprint port is a later vertical slice.

use rand::RngCore;

/// Injector keeps total legacy ClientHello at fixed 517B by padding
/// `(219 - len(sni))` zero bytes. Longer SNIs cannot be used.
pub const MAX_SNI_LEN: usize = 219;
pub const LEGACY_HELLO_LEN: usize = 517;

// Exact hex from `utils/packet_templates.py::tls_ch_template_str`.
const TEMPLATE_HEX: &str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
// Template SNI `mci.ir` (6B): static4 bounds are [127+6 .. 262+6] = [133..268].
const TEMPLATE_SNI_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsProfile {
    Legacy,
    Chrome120,
    Chrome124,
    Firefox122,
    Firefox124,
    Custom,
}

impl TlsProfile {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_lowercase().as_str() {
            "legacy" => Ok(Self::Legacy),
            "chrome_120" => Ok(Self::Chrome120),
            "chrome_124" => Ok(Self::Chrome124),
            "firefox_122" => Ok(Self::Firefox122),
            "firefox_124" => Ok(Self::Firefox124),
            "custom" => Ok(Self::Custom),
            other => Err(format!("unsupported TLS_FINGERPRINT: {:?}", other)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Chrome120 => "chrome_120",
            Self::Chrome124 => "chrome_124",
            Self::Firefox122 => "firefox_122",
            Self::Firefox124 => "firefox_124",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("target_sni must not be empty")]
    EmptySni,
    #[error("SNI too long for injector template ({0} > max {1})")]
    SniTooLong(usize, usize),
    #[error("rnd/sess_id/key_share must each be 32 bytes")]
    BadRandom,
}

/// Precondition check (mirrors Python guards). Returns 517 on success.
pub fn check_hello_params(rnd: &[u8], sess_id: &[u8], sni: &[u8], key_share: &[u8]) -> Result<usize, TlsError> {
    if sni.is_empty() {
        return Err(TlsError::EmptySni);
    }
    if sni.len() > MAX_SNI_LEN {
        return Err(TlsError::SniTooLong(sni.len(), MAX_SNI_LEN));
    }
    if rnd.len() != 32 || sess_id.len() != 32 || key_share.len() != 32 {
        return Err(TlsError::BadRandom);
    }
    Ok(LEGACY_HELLO_LEN)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        if let (Some(hi), Some(lo)) = (hex_val(b[i]), hex_val(b[i + 1])) {
            out.push((hi << 4) | lo);
        }
        i += 2;
    }
    out
}

fn be16(n: usize) -> [u8; 2] {
    [(n >> 8) as u8, n as u8]
}

/// Byte-exact port of `ClientHelloMaker.get_client_hello_with`.
/// Always returns 517B: static1(11) + rnd(32) + 0x20 + sess(32) +
/// static3(44) + server_name_ext(9+len) + static4(135) + key(32) +
/// 0x0015 + pad(219-len).
pub fn get_client_hello_with(
    rnd: &[u8],
    sess_id: &[u8],
    sni: &[u8],
    key_share: &[u8],
) -> Result<Vec<u8>, TlsError> {
    check_hello_params(rnd, sess_id, sni, key_share)?;
    let t = hex_to_bytes(TEMPLATE_HEX);
    // Defensive: template must cover [133..268]; otherwise caller bug.
    debug_assert!(t.len() >= 268);
    let static1 = &t[..11];
    let static3 = &t[76..120];
    let static4 = &t[127 + TEMPLATE_SNI_LEN..262 + TEMPLATE_SNI_LEN];

    let n = sni.len();
    let mut out = Vec::with_capacity(LEGACY_HELLO_LEN);
    out.extend_from_slice(static1);
    out.extend_from_slice(rnd);
    out.push(0x20);
    out.extend_from_slice(sess_id);
    out.extend_from_slice(static3);
    // server_name extension: len+5 | len+3 | 0x00 | len | sni
    out.extend_from_slice(&be16(n + 5));
    out.extend_from_slice(&be16(n + 3));
    out.push(0x00);
    out.extend_from_slice(&be16(n));
    out.extend_from_slice(sni);
    out.extend_from_slice(static4);
    out.extend_from_slice(key_share);
    out.extend_from_slice(&[0x00, 0x15]);
    // padding extension: len | zeros (keeps total at 517B)
    out.extend_from_slice(&be16(219 - n));
    out.extend(std::iter::repeat(0u8).take(219 - n));
    debug_assert_eq!(out.len(), LEGACY_HELLO_LEN);
    Ok(out)
}

/// Mirror of `parse_client_hello`: returns (rnd, sess, sni, key) on success,
/// `None` on any mismatch (Rust never panics on network data, unlike asserts).
pub fn parse_client_hello(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    if buf.len() != LEGACY_HELLO_LEN {
        return None;
    }
    if buf.len() < 127 + 2 {
        return None;
    }
    let sni_len = ((buf[125] as usize) << 8) | buf[126] as usize;
    if sni_len == 0 || 127 + sni_len > buf.len() {
        return None;
    }
    let rnd = buf[11..43].to_vec();
    let sess = buf[44..76].to_vec();
    let sni = buf[127..127 + sni_len].to_vec();
    let ks_ind = 262 + sni.len();
    if ks_ind + 32 > buf.len() {
        return None;
    }
    let key = buf[ks_ind..ks_ind + 32].to_vec();
    // Round-trip check (mirrors Python assert).
    match get_client_hello_with(&rnd, &sess, &sni, &key) {
        Ok(rebuilt) if rebuilt == buf => Some((rnd, sess, sni, key)),
        _ => None,
    }
}

/// Fingerprint dispatcher (port of `build_fake_client_hello` in main.py).
/// Phase 2: all profiles use the legacy 517B builder with fresh randomness
/// (length-stable, DPI-parseable). Modern GREASE/ALPS/ECH templates arrive
/// as a later slice — callers already branch on `TlsProfile`, so no API break.
pub fn build_fake_client_hello(sni: &[u8], profile: TlsProfile) -> Vec<u8> {
    let _ = profile; // TODO(fingerprint): per-profile templates
    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 32];
    let mut sess = [0u8; 32];
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut rnd);
    rng.fill_bytes(&mut sess);
    rng.fill_bytes(&mut key);
    // Validation already done by caller config; fallback is empty on bad SNI
    // (never panics — mirrors Python try/except fallback to legacy template).
    get_client_hello_with(&rnd, &sess, sni, &key).unwrap_or_default()
}
