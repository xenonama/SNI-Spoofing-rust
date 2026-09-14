//! TLS ClientHello templates: replaces `utils/packet_templates.py`
//! (+ profile dispatcher for `utils/tls_fingerprint.py`).
//!
//! Phase 2: legacy 517B builder fully ported (byte-exact vs Python).
//! FIX(firefox): Chrome 120/124 use build_chrome_hello (GREASE,
//! ALPS, compress_certificate). Firefox 122/124 use
//! build_firefox_hello (no GREASE, delegated_credentials,
//! record_size_limit). Legacy keeps the byte-exact 517B template.

use rand::{Rng, RngCore};

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

// FIX #2: GREASE table (RFC 8701).
const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// FIX #2: random GREASE value.
fn pick_grease(rng: &mut impl Rng) -> u16 {
    GREASE[rng.gen_range(0..GREASE.len())]
}

// FIX #2: write a uint16 length prefix.
fn push_u16(out: &mut Vec<u8>, v: usize) {
    out.push(((v >> 8) & 0xFF) as u8);
    out.push((v & 0xFF) as u8);
}

// FIX #2: append an extension TLV.
fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    push_u16(out, body.len());
    out.extend_from_slice(body);
}

/// FIX #2: real Chrome 124 ClientHello. Uses GREASE + Chrome's
/// cipher-suite and extension order. Total length is variable
/// (padded to a 512-byte minimum with the standard padding ext).
/// `version` is accepted for future Chrome 120 vs 124 tweaks; both
/// currently produce the same wire bytes.
fn build_chrome_hello(
    sni: &[u8],
    rnd: &[u8; 32],
    sess: &[u8; 32],
    key_share: &[u8; 32],
    _version: u16,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // ---- body ----
    let mut body: Vec<u8> = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(rnd);
    body.push(32); // session_id length
    body.extend_from_slice(sess);

    // cipher_suites: GREASE + 15 real (16 total)
    let grease_cipher = pick_grease(&mut rng);
    let suites: [u16; 16] = [
        grease_cipher,
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D,
        0x002F, 0x0035,
    ];
    push_u16(&mut body, suites.len() * 2);
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    // compression_methods
    body.push(1);
    body.push(0);

    // ---- extensions ----
    let mut exts: Vec<u8> = Vec::new();

    // 1. GREASE extension (empty)
    let grease_ext_a = pick_grease(&mut rng);
    push_ext(&mut exts, grease_ext_a, &[]);

    // 2. server_name (SNI)
    {
        let name = sni;
        let name_len = name.len().min(255) as u16;
        let list_len = 1 + 2 + name_len as usize;
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, list_len);
        e.push(0x00);
        push_u16(&mut e, name_len as usize);
        e.extend_from_slice(&name[..name_len as usize]);
        push_ext(&mut exts, 0x0000, &e);
    }

    // 3. extended_master_secret (empty)
    push_ext(&mut exts, 0x0017, &[]);

    // 4. renegotiation_info (1 byte 0x00)
    push_ext(&mut exts, 0xff01, &[0x00]);

    // 5. supported_groups: GREASE, x25519, secp256r1, secp384r1
    {
        let grease_g = pick_grease(&mut rng);
        let groups: [u16; 4] = [grease_g, 0x001d, 0x0017, 0x0018];
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, groups.len() * 2);
        for g in groups {
            e.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, 0x000a, &e);
    }

    // 6. ec_point_formats: [uncompressed]
    push_ext(&mut exts, 0x000b, &[0x01, 0x00]);

    // 7. session_ticket (empty)
    push_ext(&mut exts, 0x0023, &[]);

    // 8. ALPN: h2, http/1.1
    {
        let mut e: Vec<u8> = Vec::new();
        let protos: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let list_len: usize = protos.iter().map(|p| 1 + p.len()).sum();
        push_u16(&mut e, list_len);
        for p in protos {
            e.push(p.len() as u8);
            e.extend_from_slice(p);
        }
        push_ext(&mut exts, 0x0010, &e);
    }

    // 9. status_request (OCSP)
    {
        // type=ocsp(1), responder_id_list_len=0, extensions_len=0
        let e: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x00];
        push_ext(&mut exts, 0x0005, &e);
    }

    // 10. signature_algorithms
    {
        // Chrome's order (simplified but valid)
        let sigs: [u16; 10] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
            0x0501, 0x0806, 0x0601, 0x0201, 0x0203,
        ];
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, sigs.len() * 2);
        for s in sigs {
            e.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut exts, 0x000d, &e);
    }

    // 11. signed_certificate_timestamp (empty)
    push_ext(&mut exts, 0x0012, &[]);

    // 12. key_share: GREASE + x25519
    {
        let grease_ks = pick_grease(&mut rng);
        let mut e: Vec<u8> = Vec::new();
        // total client_shares_len: 4 for GREASE entry + 36 for x25519
        push_u16(&mut e, 4 + 36);
        // GREASE entry: group + empty key_exchange
        e.extend_from_slice(&grease_ks.to_be_bytes());
        push_u16(&mut e, 0);
        // x25519 entry: group + 32-byte key
        e.extend_from_slice(&0x001du16.to_be_bytes());
        push_u16(&mut e, 32);
        e.extend_from_slice(key_share);
        push_ext(&mut exts, 0x0033, &e);
    }

    // 13. psk_key_exchange_modes: [psk_dhe_ke]
    push_ext(&mut exts, 0x002d, &[0x01, 0x01]);

    // 14. supported_versions: GREASE, 1.3, 1.2
    {
        let grease_v = pick_grease(&mut rng);
        let versions: [u16; 3] = [grease_v, 0x0304, 0x0303];
        let mut e: Vec<u8> = Vec::new();
        e.push((versions.len() * 2) as u8);
        for v in versions {
            e.extend_from_slice(&v.to_be_bytes());
        }
        push_ext(&mut exts, 0x002b, &e);
    }

    // 15. compress_certificate: brotli, zlib, zstd
    push_ext(&mut exts, 0x001b, &[0x04, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02]);

    // 16. application_settings (ALPS), Chrome-specific 0x4469
    {
        let mut e: Vec<u8> = Vec::new();
        e.extend_from_slice(b"h2"); // protocol
        push_u16(&mut e, 0); // settings len
        push_ext(&mut exts, 0x4469, &e);
    }

    // 17. GREASE extension (different from #1)
    let grease_ext_b = pick_grease(&mut rng);
    push_ext(&mut exts, grease_ext_b, &[]);

    // 18. padding: pad the final ClientHello to at least 512 bytes.
    // We can only decide the padding size AFTER knowing the length
    // of everything above PLUS the handshake+record headers.
    // Compute current total with a placeholder padding extension
    // (4 bytes header + 0 body), then pad the difference.
    {
        // 4 bytes = padding extension header + length field
        let current = 5 /* record */ + 4 /* hs */ + body.len() + 2 /* exts total len */ + exts.len() + 4;
        let target = 512usize;
        if current < target {
            let pad_len = target - current;
            // padding body: pad_len zero bytes
            let pad_body = vec![0u8; pad_len];
            push_ext(&mut exts, 0x0015, &pad_body);
        }
    }

    // append extensions block to body
    push_u16(&mut body, exts.len());
    body.extend_from_slice(&exts);

    // ---- handshake header ----
    let mut hs: Vec<u8> = Vec::with_capacity(4 + body.len());
    hs.push(0x01);
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xFF) as u8);
    hs.push(((blen >> 8) & 0xFF) as u8);
    hs.push((blen & 0xFF) as u8);
    hs.extend_from_slice(&body);

    // ---- record header ----
    let mut rec: Vec<u8> = Vec::with_capacity(5 + hs.len());
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    push_u16(&mut rec, hs.len());
    rec.extend_from_slice(&hs);
    rec
}

/// FIX(firefox): Firefox 122/124 ClientHello. No GREASE, no
/// ALPS, no compress_certificate. Uses Firefox's cipher order,
/// extension order, and key_share shape (x25519 only).
///
/// `version` is accepted for future 122 vs 124 tweaks; both
/// currently produce the same wire bytes.
fn build_firefox_hello(
    sni: &[u8],
    rnd: &[u8; 32],
    sess: &[u8; 32],
    key_share: &[u8; 32],
    _version: u16,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(512);

    // legacy_version = TLS 1.2
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(rnd);

    // session_id: 32 bytes
    body.push(32);
    body.extend_from_slice(sess);

    // ---- cipher_suites (Firefox order, no GREASE) ----
    // TLS 1.3 first, then ECDHE, then legacy RSA.
    let suites: [u16; 16] = [
        0x1301, 0x1303, 0x1302,
        0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
        0xC02C, 0xC030,
        0x009E, 0x009C,
        0x0035, 0x002F,
        0x000A, 0x00FF,
        0x0100,
    ];
    push_u16(&mut body, suites.len() * 2);
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }

    // compression_methods: [null]
    body.push(1);
    body.push(0);

    // ---- extensions (Firefox order, no GREASE) ----
    let mut exts: Vec<u8> = Vec::new();

    // 1. server_name (SNI)
    {
        let name = sni;
        let name_len = name.len().min(255) as u16;
        let list_len = 1 + 2 + name_len as usize;
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, list_len);
        e.push(0x00);
        push_u16(&mut e, name_len as usize);
        e.extend_from_slice(&name[..name_len as usize]);
        push_ext(&mut exts, 0x0000, &e);
    }

    // 2. extended_master_secret (empty)
    push_ext(&mut exts, 0x0017, &[]);

    // 3. renegotiation_info
    push_ext(&mut exts, 0xff01, &[0x00]);

    // 4. supported_groups: x25519, secp256r1, secp384r1,
    //    secp521r1, ffdhe2048, ffdhe3072. No GREASE.
    {
        let groups: [u16; 6] = [
            0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101,
        ];
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, groups.len() * 2);
        for g in groups {
            e.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, 0x000a, &e);
    }

    // 5. ec_point_formats: [uncompressed]
    push_ext(&mut exts, 0x000b, &[0x01, 0x00]);

    // 6. session_ticket (empty)
    push_ext(&mut exts, 0x0023, &[]);

    // 7. ALPN: h2, http/1.1
    {
        let mut e: Vec<u8> = Vec::new();
        let protos: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let list_len: usize = protos.iter().map(|p| 1 + p.len()).sum();
        push_u16(&mut e, list_len);
        for p in protos {
            e.push(p.len() as u8);
            e.extend_from_slice(p);
        }
        push_ext(&mut exts, 0x0010, &e);
    }

    // 8. status_request (OCSP)
    push_ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // 9. delegated_credentials (Firefox-specific, 0x0022)
    //    Body: sig_algs_list_len + a couple of algorithms.
    {
        let algs: [u16; 2] = [0x0403, 0x0503];
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, algs.len() * 2);
        for a in algs {
            e.extend_from_slice(&a.to_be_bytes());
        }
        push_ext(&mut exts, 0x0022, &e);
    }

    // 10. key_share: x25519 ONLY (no GREASE, no secp256r1)
    {
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, 4 + 32); // one entry: 2 group + 2 len + 32 key
        e.extend_from_slice(&0x001du16.to_be_bytes());
        push_u16(&mut e, 32);
        e.extend_from_slice(key_share);
        push_ext(&mut exts, 0x0033, &e);
    }

    // 11. supported_versions: [TLS 1.3, TLS 1.2] — no GREASE
    {
        let mut e: Vec<u8> = Vec::new();
        e.push(4); // 2 versions × 2 bytes
        e.extend_from_slice(&0x0304u16.to_be_bytes());
        e.extend_from_slice(&0x0303u16.to_be_bytes());
        push_ext(&mut exts, 0x002b, &e);
    }

    // 12. signature_algorithms (Firefox order)
    {
        let sigs: [u16; 12] = [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0809,
        ];
        let mut e: Vec<u8> = Vec::new();
        push_u16(&mut e, sigs.len() * 2);
        for s in sigs {
            e.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut exts, 0x000d, &e);
    }

    // 13. psk_key_exchange_modes: [psk_dhe_ke]
    push_ext(&mut exts, 0x002d, &[0x01, 0x01]);

    // 14. record_size_limit: 0x4001 (16385)
    push_ext(&mut exts, 0x001c, &[0x40, 0x01]);

    // Append extension block to body.
    push_u16(&mut body, exts.len());
    body.extend_from_slice(&exts);

    // Handshake header.
    let mut hs: Vec<u8> = Vec::with_capacity(4 + body.len());
    hs.push(0x01);
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xFF) as u8);
    hs.push(((blen >> 8) & 0xFF) as u8);
    hs.push((blen & 0xFF) as u8);
    hs.extend_from_slice(&body);

    // Record header.
    let mut rec: Vec<u8> = Vec::with_capacity(5 + hs.len());
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    push_u16(&mut rec, hs.len());
    rec.extend_from_slice(&hs);
    rec
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
/// FIX #2: Legacy/Custom use the legacy 517B builder; Chrome 120/124
/// use the realistic Chrome builder with GREASE, ALPS,
/// compress_certificate and a 512-byte padding floor.
/// FIX(firefox): Firefox 122/124 use the dedicated Firefox builder with
/// no GREASE, delegated_credentials and record_size_limit.
pub fn build_fake_client_hello(sni: &[u8], profile: TlsProfile) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut rnd = [0u8; 32];
    let mut sess = [0u8; 32];
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut rnd);
    rng.fill_bytes(&mut sess);
    rng.fill_bytes(&mut key);
    // Validation already done by caller config; fallback is empty on bad SNI
    // (never panics — mirrors Python try/except fallback to legacy template).
    match profile {
        TlsProfile::Legacy | TlsProfile::Custom => {
            get_client_hello_with(&rnd, &sess, sni, &key).unwrap_or_default()
        }
        TlsProfile::Chrome120 | TlsProfile::Chrome124 => {
            build_chrome_hello(sni, &rnd, &sess, &key, 0x0304)
        }
        TlsProfile::Firefox122 | TlsProfile::Firefox124 => {
            // FIX(firefox): dedicated Firefox template.
            build_firefox_hello(sni, &rnd, &sess, &key, 0x0304)
        }
    }
}
