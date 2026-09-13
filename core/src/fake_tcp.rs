//! Bypass methods + pure split math + fake planner + handshake state machine.
//!
//! Replaces `fake_tcp.py`:
//! - enums + `split_plan`/`overlap_plan`/SNI helpers (pure, tested)
//! - `plan_fake` (pure `fake_send_thread` branching — no I/O, fully testable)
//! - `HandshakeState` (pure `on_outbound/inbound_packet` validation)
//! - Wire I/O (`WinDivert send`, delays, executor pool) arrives in Phase 3.
//!
//! All sequence arithmetic uses `wrapping_*` (= Python `& 0xFFFFFFFF`).

use crate::tcp::TcpInfo;
use rand::seq::SliceRandom;
use rand::Rng;

pub const SUPPORTED_METHODS: &[&str] = &[
    "auto",
    "wrong_seq",
    "wrong_seq_ttl",
    "split_seq",
    "fragmented",
    "padding",
    "delayed_retry",
    "double_sni",
    "hostfakesplit",
    "fakedsplit",
];

pub const REAL_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_seq_ttl",
    "split_seq",
    "fragmented",
    "padding",
    "delayed_retry",
    "double_sni",
    "hostfakesplit",
    "fakedsplit",
];

/// Wire method. `Auto` rotates one of the real methods per connection
/// (mirrors `resolve_method("auto") == random.choice(REAL_METHODS)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BypassMethod {
    Auto,
    WrongSeq,
    WrongSeqTtl,
    SplitSeq,
    Fragmented,
    Padding,
    DelayedRetry,
    DoubleSni,
    HostFakeSplit,
    FakeSplit,
}

impl BypassMethod {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim() {
            "auto" => Ok(Self::Auto),
            "wrong_seq" => Ok(Self::WrongSeq),
            "wrong_seq_ttl" => Ok(Self::WrongSeqTtl),
            "split_seq" => Ok(Self::SplitSeq),
            "fragmented" => Ok(Self::Fragmented),
            "padding" => Ok(Self::Padding),
            "delayed_retry" => Ok(Self::DelayedRetry),
            "double_sni" => Ok(Self::DoubleSni),
            "hostfakesplit" => Ok(Self::HostFakeSplit),
            "fakedsplit" => Ok(Self::FakeSplit),
            other => Err(format!(
                "unsupported bypass method: {:?} (expected one of {:?})",
                other, SUPPORTED_METHODS
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::WrongSeq => "wrong_seq",
            Self::WrongSeqTtl => "wrong_seq_ttl",
            Self::SplitSeq => "split_seq",
            Self::Fragmented => "fragmented",
            Self::Padding => "padding",
            Self::DelayedRetry => "delayed_retry",
            Self::DoubleSni => "double_sni",
            Self::HostFakeSplit => "hostfakesplit",
            Self::FakeSplit => "fakedsplit",
        }
    }

    /// Resolve to a wire method for one connection.
    pub fn resolve(&self) -> Self {
        match self {
            Self::Auto => {
                let mut rng = rand::thread_rng();
                let pool = [
                    Self::WrongSeq,
                    Self::WrongSeqTtl,
                    Self::SplitSeq,
                    Self::Fragmented,
                    Self::Padding,
                    Self::DelayedRetry,
                    Self::DoubleSni,
                    Self::HostFakeSplit,
                    Self::FakeSplit,
                ];
                *pool.choose(&mut rng).unwrap_or(&Self::WrongSeq)
            }
            other => *other,
        }
    }
}

/// Python-parity free function: `resolve_method("auto")`, etc.
pub fn resolve_method(name: &str) -> Result<BypassMethod, String> {
    BypassMethod::parse(name).map(|m| m.resolve())
}

/// Pure helper: wrong-seq base offsets for a 2-segment split send.
///
/// Both segments live in 'old' sequence space so the real server ignores
/// them while DPI still parses the fake SNI. Returns (seq1, seq2).
/// Mirrors `fake_tcp.split_plan` exactly (wrapping `& 0xFFFFFFFF`).
pub fn split_plan(syn_seq: u32, total_len: u32, first_len: u32) -> (u32, u32) {
    let base = syn_seq.wrapping_add(1).wrapping_sub(total_len);
    (base, base.wrapping_add(first_len))
}

/// Pure helper for `fragmented` (split-seqovl). Mirrors `overlap_plan`:
/// piece 1 covers [0:len1], pieces 2/3 rewind by overlap so DPI reassembly
/// desyncs while the real server (old-seq drop) is unaffected.
pub fn overlap_plan(
    total_len: i64,
    len1: i64,
    len2: i64,
    overlap: i64,
) -> ((i64, i64, i64), (i64, i64)) {
    let mut ov = if overlap < 0 { 0 } else { overlap };
    let (mut off3, mut ov2);
    let ov1 = if len1 > 1 && len2 > 1 {
        let cap = (len1 - 1).min(len2 - 1).max(0);
        ov = ov.min(cap);
        ov
    } else {
        0
    };
    let off2 = len1 - ov1;
    ov2 = if len2 > 1 { ov.min((len2 - 1).max(0)) } else { 0 };
    off3 = off2 + len2 - ov2;
    if total_len > 0 && off3 >= total_len {
        ov2 = (off2 + len2 - (total_len - 1)).max(0);
        off3 = off2 + len2 - ov2;
    }
    if off3 < 0 {
        off3 = off2;
        ov2 = 0;
    }
    ((0, off2, off3), (ov1, ov2))
}

/// Best-effort SNI extraction from a raw ClientHello record.
pub fn extract_sni_from_hello(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 50 || data[0] != 0x16 {
        return None;
    }
    let end = data.len().saturating_sub(10);
    let mut i = 5usize;
    while i < end.max(6) && i + 9 < data.len() {
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            let ext_len = ((data[i + 2] as usize) << 8) | data[i + 3] as usize;
            if (7..=260).contains(&ext_len) && i + 4 + ext_len <= data.len() {
                let lst_len = ((data[i + 4] as usize) << 8) | data[i + 5] as usize;
                if lst_len == ext_len - 2 && data[i + 6] == 0x00 {
                    let sni_len = ((data[i + 7] as usize) << 8) | data[i + 8] as usize;
                    if (1..=253).contains(&sni_len) && sni_len == ext_len - 5 {
                        let cand = &data[i + 9..i + 9 + sni_len];
                        if cand.contains(&b'.') {
                            return Some(cand.to_vec());
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Same-length decoy hostname (keeps ClientHello length identical).
/// FIX P1: preserve dots, emit only valid hostname chars ([a-z0-9-]),
/// never start/end a label with '-', and avoid trivial xxx.com patterns.
pub fn same_length_fake_sni(sni: &[u8]) -> Vec<u8> {
    let n = sni.len();
    if n == 0 {
        return b"a.example.com".to_vec();
    }
    let mut rng = rand::thread_rng();
    // Try random valid labels preserving dot positions (up to 8 attempts).
    for _ in 0..8 {
        let mut cand = Vec::with_capacity(n);
        for &b in sni {
            if b == b'.' {
                cand.push(b'.');
            } else if b.is_ascii_digit() {
                cand.push(b'0' + (rng.gen_range(0..10) as u8));
            } else {
                cand.push(b'a' + (rng.gen_range(0..26) as u8));
            }
        }
        // Must differ, keep dots, stay valid: no leading/trailing '-' in a
        // label (we only emit alnum + '.', so valid by construction), must
        // still contain a dot and not equal the original.
        if cand != sni && cand.contains(&b'.') {
            return cand;
        }
    }
    if n >= 5 {
        let mut cand = vec![b'q'; n - 4];
        cand.extend_from_slice(b".com");
        if cand != sni {
            return cand;
        }
    }
    let mut m = sni.to_vec();
    let dot = m.iter().rposition(|&b| b == b'.');
    for idx in 0..m.len() {
        if Some(idx) == dot {
            continue;
        }
        let c = m[idx];
        // Only emit valid hostname chars: rotate within alnum, never 0x01.
        if c.is_ascii_lowercase() {
            m[idx] = if c == b'z' { b'a' } else { c + 1 };
            break;
        } else if c.is_ascii_uppercase() {
            m[idx] = if c == b'Z' { b'A' } else { c + 1 };
            break;
        } else if c.is_ascii_digit() {
            m[idx] = if c == b'9' { b'0' } else { c + 1 };
            break;
        } else if c == b'-' {
            m[idx] = b'a';
            break;
        }
    }
    if m != sni {
        m
    } else {
        sni.to_vec()
    }
}

/// MD5-signed fake payload for `fakedsplit`: md5(data) ++ data.
/// Mirrors `_md5_fake_payload` (never panics; empty -> 16B digest).
pub fn md5_fake_payload(data: &[u8]) -> Vec<u8> {
    let digest = md5::compute(data);
    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&digest.0);
    out.extend_from_slice(data);
    out
}

/// Decoy hello for `hostfakesplit` (same length, other SNI).
/// Mirrors `_build_hostfake_variant` in-place path: extract SNI, derive
/// same-length decoy, byte-replace once. Fresh-template path (per-profile
/// regeneration) is a Phase 3 slice; in-place keeps framing always valid.
/// FIX P1: prefer the known SNI offset (127 for our 517B template) before
/// falling back to a blind byte search, so random rnd/sess/key collisions
/// can't cause a splice in the wrong field.
pub fn build_hostfake_variant(data: &[u8]) -> Vec<u8> {
    if data.len() < 2 {
        return data.to_vec();
    }
    if let Some(sni) = extract_sni_from_hello(data) {
        let decoy = same_length_fake_sni(&sni);
        if !decoy.is_empty() && decoy != sni && decoy.len() == sni.len() {
            // Known template layout: SNI starts at 127. Prefer it.
            if data.len() >= 127 + sni.len() && &data[127..127 + sni.len()] == sni.as_slice() {
                let mut out = Vec::with_capacity(data.len());
                out.extend_from_slice(&data[..127]);
                out.extend_from_slice(&decoy);
                out.extend_from_slice(&data[127 + sni.len()..]);
                return out;
            }
            // Find first occurrence and splice (== `orig.replace(sni, decoy, 1)`).
            if let Some(pos) = data.windows(sni.len()).position(|w| w == sni.as_slice()) {
                let mut out = Vec::with_capacity(data.len());
                out.extend_from_slice(&data[..pos]);
                out.extend_from_slice(&decoy);
                out.extend_from_slice(&data[pos + sni.len()..]);
                return out;
            }
        }
    }
    data.to_vec()
}

// ---------------------------------------------------------------------------
// Pure fake planner (no I/O): port of `fake_send_thread` branching.
// ---------------------------------------------------------------------------

/// Tunables (mirrors `FakeTcpInjector(fake_delay, seq_overlap, pad_size)`).
/// `fake_delay` is timing-only (handled by the sender), so the pure planner
/// carries only `seq_overlap` + `pad_size`.
#[derive(Debug, Clone, Copy)]
pub struct FakeParams {
    pub seq_overlap: u8,
    pub pad_size: u8,
}

impl Default for FakeParams {
    fn default() -> Self {
        Self {
            seq_overlap: 3,
            pad_size: 0,
        }
    }
}

impl FakeParams {
    pub fn new(seq_overlap: u8, pad_size: u8) -> Self {
        Self {
            seq_overlap: seq_overlap.min(16),
            pad_size: pad_size.min(255) as u8,
        }
    }
}

/// One TCP segment to emit: `seq` + `payload` + PSH + ident step.
/// `ttl_decrement` implements `wrong_seq_ttl` (sender does `ttl - 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSegment {
    pub seq: u32,
    pub payload: Vec<u8>,
    pub psh: bool,
    pub ident_plus: u16,
    pub ttl_decrement: bool,
}

impl FakeSegment {
    fn single(seq: u32, payload: Vec<u8>, psh: bool, ident_plus: u16) -> Self {
        Self {
            seq,
            payload,
            psh,
            ident_plus,
            ttl_decrement: false,
        }
    }
}

fn wrong_seq(syn_seq: u32, data: &[u8], ident_plus: u16) -> FakeSegment {
    let seq = syn_seq.wrapping_add(1).wrapping_sub(data.len() as u32);
    FakeSegment::single(seq, data.to_vec(), true, ident_plus)
}

/// Pure plan for one method. Mirrors `fake_send_thread` branch-for-branch,
/// including tiny-packet fallbacks and the hostfakesplit length-mismatch
/// fallback to single `wrong_seq`. `dst_ip_hint` feeds `double_sni`.
pub fn plan_fake(
    method: BypassMethod,
    syn_seq: u32,
    data: &[u8],
    params: &FakeParams,
    dst_ip_hint: Option<&str>,
) -> Vec<FakeSegment> {
    let n = data.len();
    match method {
        BypassMethod::Auto => plan_fake(BypassMethod::WrongSeq, syn_seq, data, params, dst_ip_hint),
        BypassMethod::WrongSeq => vec![wrong_seq(syn_seq, data, 1)],
        BypassMethod::WrongSeqTtl => {
            let mut s = wrong_seq(syn_seq, data, 1);
            s.ttl_decrement = true;
            vec![s]
        }
        BypassMethod::SplitSeq => {
            if n == 0 {
                return vec![wrong_seq(syn_seq, data, 1)];
            }
            let half = (n / 2).max(1);
            let (seq1, seq2) = split_plan(syn_seq, n as u32, half as u32);
            vec![
                FakeSegment::single(seq1, data[..half.min(n)].to_vec(), false, 1),
                FakeSegment::single(seq2, data[half.min(n)..].to_vec(), true, 2),
            ]
        }
        BypassMethod::Fragmented => {
            if n < 3 {
                return vec![wrong_seq(syn_seq, data, 1)];
            }
            let mut len1 = ((n * 40) / 100).max(1);
            let mut len2 = ((n * 30) / 100).max(1);
            if len1 + len2 >= n {
                len2 = ((n - len1) / 2).max(1);
            }
            let ((_, off2, mut off3), _) =
                overlap_plan(n as i64, len1 as i64, len2 as i64, params.seq_overlap as i64);
            let (off2, _) = (off2 as usize, 0);
            let mut len3 = n.saturating_sub(off3 as usize);
            if len3 < 1 {
                len3 = 1;
                off3 = (n - 1) as i64;
            }
            // Clamp to valid slicing (defensive; mirrors Python guards).
            len1 = len1.min(n);
            let off2 = off2.min(n);
            let off3 = (off3 as usize).min(n.saturating_sub(1));
            let l2 = len2.min(n.saturating_sub(off2));
            let l3 = len3.min(n.saturating_sub(off3));
            let base = syn_seq.wrapping_add(1).wrapping_sub(n as u32);
            vec![
                FakeSegment::single(base, data[0..len1].to_vec(), false, 1),
                FakeSegment::single(
                    base.wrapping_add(off2 as u32),
                    data[off2..off2 + l2].to_vec(),
                    false,
                    2,
                ),
                FakeSegment::single(
                    base.wrapping_add(off3 as u32),
                    data[off3..off3 + l3].to_vec(),
                    true,
                    3,
                ),
            ]
        }
        BypassMethod::Padding => {
            let pad_len = if params.pad_size != 0 {
                (params.pad_size as usize).clamp(1, 256)
            } else {
                rand::thread_rng().gen_range(16..=64usize)
            };
            // FIX P1: padding must be a suffix, not a prefix. A zero prefix
            // breaks the TLS record header (DPI expects 0x16 at offset 0 and
            // skips the fake entirely). Suffix keeps the hello parseable
            // while the old-seq window still hides it from the server.
            let mut padded = Vec::with_capacity(data.len() + pad_len);
            padded.extend_from_slice(data);
            padded.extend(std::iter::repeat(0u8).take(pad_len));
            let seq = syn_seq.wrapping_add(1).wrapping_sub(padded.len() as u32);
            vec![FakeSegment::single(seq, padded, true, 1)]
        }
        BypassMethod::DoubleSni => {
            // FIX P1: hello + b'|' + ip exceeds the TLS record length and
            // appends an invalid trailing record, so strict DPI drops it as
            // malformed. Until a valid dual-SNI extension is built, send the
            // hello as a plain wrong_seq (parseable, old-seq) rather than a
            // guaranteed-malformed burst.
            let _ = dst_ip_hint;
            vec![wrong_seq(syn_seq, data, 1)]
        }
        BypassMethod::HostFakeSplit => {
            if n < 2 {
                return vec![wrong_seq(syn_seq, data, 1)];
            }
            let decoy = build_hostfake_variant(data);
            if decoy.len() != n {
                // Length mismatch -> single wrong_seq fallback (Python parity).
                return vec![wrong_seq(syn_seq, data, 1)];
            }
            let total = (decoy.len() + n) as u32;
            let (seq1, seq2) = split_plan(syn_seq, total, decoy.len() as u32);
            vec![
                FakeSegment::single(seq1, decoy, false, 1),
                FakeSegment::single(seq2, data.to_vec(), true, 2),
            ]
        }
        BypassMethod::FakeSplit => {
            if n < 1 {
                let seq = syn_seq.wrapping_add(1).wrapping_sub(1);
                return vec![FakeSegment::single(seq, data.to_vec(), true, 1)];
            }
            let signed = md5_fake_payload(data);
            // FIX P1: 0x10000 (64k) can sit inside a window-scaled receive
            // window, so the "bad" segment might be accepted. Push it 1M back
            // to guarantee out-of-window while staying in u32 space.
            let badseq = syn_seq
                .wrapping_add(1)
                .wrapping_sub(signed.len() as u32)
                .wrapping_sub(0x100000);
            let seq_ok = syn_seq.wrapping_add(1).wrapping_sub(n as u32);
            vec![
                FakeSegment::single(badseq, signed, false, 1),
                FakeSegment::single(seq_ok, data.to_vec(), true, 2),
            ]
        }
        BypassMethod::DelayedRetry => {
            // First attempt is wrong_seq now; the split_seq retry after 1.5s
            // (if still monitored) is planned separately — see below.
            vec![wrong_seq(syn_seq, data, 1)]
        }
    }
}

/// Second attempt for `delayed_retry` (split_seq retry after 1.5s).
/// Returns empty when the first attempt was never sent (caller checks
/// `fake_sent`, mirroring the Python `if not connection.fake_sent: return`).
pub fn plan_delayed_retry_second(
    syn_seq: u32,
    data: &[u8],
    fake_sent: bool,
) -> Vec<FakeSegment> {
    if !fake_sent || data.is_empty() {
        return vec![];
    }
    let half = (data.len() / 2).max(1);
    let (seq1, seq2) = split_plan(syn_seq, data.len() as u32, half as u32);
    vec![
        FakeSegment::single(seq1, data[..half.min(data.len())].to_vec(), false, 1),
        FakeSegment::single(seq2, data[half.min(data.len())..].to_vec(), true, 2),
    ]
}

// ---------------------------------------------------------------------------
// Handshake state machine (pure `on_outbound/inbound_packet` validation).
// ---------------------------------------------------------------------------

/// Connection handshake state (subset of `FakeInjectiveConnection` relevant
/// to TCP validation; sockets/stats live in Phase 3).
#[derive(Debug, Clone)]
pub struct HandshakeState {
    pub method: BypassMethod,
    pub syn_seq: Option<u32>,
    pub syn_ack_seq: Option<u32>,
    pub sch_fake_sent: bool,
    pub fake_sent: bool,
    pub monitor: bool,
}

impl HandshakeState {
    pub fn new(method: BypassMethod) -> Self {
        Self {
            method: method.resolve(),
            syn_seq: None,
            syn_ack_seq: None,
            sch_fake_sent: false,
            fake_sent: false,
            monitor: true,
        }
    }

    pub fn mark_fake_sent(&mut self) {
        self.fake_sent = true;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundAction {
    /// Forward unchanged (`w.send(packet, False)`).
    Reinject,
    /// SYN-ACK handshake done on our side: emit `plan_fake(...)`.
    TriggerFake,
    /// Protocol violation: close + `w.send(packet, False)` (Python
    /// `on_unexpected_packet` always reinjects after closing).
    Unexpected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundAction {
    Reinject,
    /// Bypass complete: `monitor=false`, stats success, wake `t2a_event`.
    Success,
    Unexpected(String),
}

impl HandshakeState {
    /// Port of `on_outbound_packet`.
    pub fn on_outbound(&mut self, info: TcpInfo) -> OutboundAction {
        if self.sch_fake_sent {
            return OutboundAction::Unexpected(
                "unexpected outbound packet, recv packet after fake sent!".to_string(),
            );
        }
        // Outbound SYN (no ACK/RST/FIN, no payload).
        if info.syn && !info.ack_flag && !info.rst && !info.fin && info.payload_len == 0 {
            if info.ack != 0 {
                return OutboundAction::Unexpected(
                    "unexpected outbound syn packet, ack_num is not zero!".to_string(),
                );
            }
            if let Some(s) = self.syn_seq {
                if s != info.seq {
                    return OutboundAction::Unexpected(format!(
                        "unexpected outbound syn packet, seq not matched! {} {}",
                        info.seq, s
                    ));
                }
            }
            self.syn_seq = Some(info.seq);
            return OutboundAction::Reinject;
        }
        // Outbound ACK (completes local handshake, triggers fake send).
        if info.ack_flag && !info.syn && !info.rst && !info.fin && info.payload_len == 0 {
            match self.syn_seq {
                Some(s) if info.seq == s.wrapping_add(1) => {}
                _ => {
                    return OutboundAction::Unexpected(format!(
                        "unexpected outbound ack packet, seq not matched! {} {:?}",
                        info.seq, self.syn_seq
                    ))
                }
            }
            match self.syn_ack_seq {
                Some(sa) if info.ack == sa.wrapping_add(1) => {}
                _ => {
                    return OutboundAction::Unexpected(format!(
                        "unexpected outbound ack packet, ack not matched! {} {:?}",
                        info.ack, self.syn_ack_seq
                    ))
                }
            }
            self.sch_fake_sent = true;
            return OutboundAction::TriggerFake;
        }
        OutboundAction::Unexpected("unexpected outbound packet".to_string())
    }

    /// Port of `on_inbound_packet`.
    pub fn on_inbound(&mut self, info: TcpInfo) -> InboundAction {
        // FIX(diag): tracing at every inbound decision point.
        tracing::trace!(
            "HS in: syn={} ack={} rst={} fin={} pay={} fake_sent={} syn_ack_seq={:?}",
            info.syn,
            info.ack_flag,
            info.rst,
            info.fin,
            info.payload_len,
            self.fake_sent,
            self.syn_ack_seq
        );
        let syn_seq = match self.syn_seq {
            Some(s) => s,
            None => {
                return InboundAction::Unexpected(
                    "unexpected inbound packet, no syn sent!".to_string(),
                )
            }
        };
        // Inbound SYN-ACK.
        if info.syn && info.ack_flag && !info.rst && !info.fin && info.payload_len == 0 {
            if let Some(sa) = self.syn_ack_seq {
                if sa != info.seq {
                    return InboundAction::Unexpected(format!(
                        "unexpected inbound syn-ack packet, seq change! {} {}",
                        info.seq, sa
                    ));
                }
            }
            if info.ack != syn_seq.wrapping_add(1) {
                return InboundAction::Unexpected(format!(
                    "unexpected inbound syn-ack packet, ack not matched! {} {}",
                    info.ack, syn_seq
                ));
            }
            self.syn_ack_seq = Some(info.seq);
            return InboundAction::Reinject;
        }
        // Inbound data after our fake burst = SUCCESS.
        // The server drops old-seq fakes without ACKing them, so a pure ACK
        // for the fake never arrives. The first ServerHello / data bytes
        // prove DPI let the handshake through (bypass complete).
        // FIX P0: previously only a pure ACK counted, which never happens
        // in a real flow -> every connection timed out via HANDSHAKE_TIMEOUT.
        if self.fake_sent && info.payload_len > 0 && !info.syn && !info.rst && !info.fin {
            self.monitor = false;
            return InboundAction::Success;
        }
        // Inbound ACK for our fake data = SUCCESS (synthetic pure-ACK path,
        // kept for selftest + stacks that ACK old-seq).
        if info.ack_flag && !info.syn && !info.rst && !info.fin && info.payload_len == 0 && self.fake_sent
        {
            match self.syn_ack_seq {
                Some(sa) if info.seq == sa.wrapping_add(1) => {}
                _ => {
                    return InboundAction::Unexpected(format!(
                        "unexpected inbound ack packet, seq not matched! {} {:?}",
                        info.seq, self.syn_ack_seq
                    ))
                }
            }
            if info.ack != syn_seq.wrapping_add(1) {
                return InboundAction::Unexpected(format!(
                    "unexpected inbound ack packet, ack not matched! {} {}",
                    info.ack, syn_seq
                ));
            }
            self.monitor = false;
            return InboundAction::Success;
        }
        InboundAction::Unexpected("unexpected inbound packet".to_string())
    }
}
