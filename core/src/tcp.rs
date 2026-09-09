//! Raw IPv4/TCP parsing + crafting with `bytes` + `byteorder`.
//!
//! Replaces `pydivert.Packet` mutation used throughout `fake_tcp.py`:
//! `packet.tcp.seq_num`, `packet.tcp.payload`, `packet.tcp.psh`,
//! `packet.ip.packet_len`, `packet.ipv4.ident`, `packet.ipv4.ttl`.
//!
//! Phase 2 provides:
//! - `parse_ip_tcp` / `tcp_info` (for handshake validation = `build_ack` side)
//! - `build_fake_tcp` (single old-seq segment = core `wrong_seq` primitive)
//! - `apply_plan` (multi-segment send for split/fragmented/hostfakesplit/...)
//! - IP + TCP checksum recalculation (pydivert did this implicitly on `send`).

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;

pub const RECV_MAX: usize = 65575;
const IP_MIN: usize = 20;
const TCP_MIN: usize = 20;

#[derive(Debug, Clone)]
pub struct IpMeta {
    pub header_len: usize,
    pub total_len: usize,
    pub ident: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct TcpMeta {
    pub header_len: usize,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// Lightweight TCP view for handshake validation (`build_ack` logic).
#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub rst: bool,
    pub fin: bool,
    pub psh: bool,
    pub payload_len: usize,
}

/// Parse IPv4 + TCP. Returns (ip, tcp, ip_hlen, tcp_hlen).
/// `None` = not IPv4/TCP or truncated (caller forwards untouched, like
/// Python's per-packet guard that never kills the injector thread).
pub fn parse_ip_tcp(raw: &[u8]) -> Option<(IpMeta, TcpMeta, usize, usize)> {
    if raw.len() < IP_MIN + TCP_MIN {
        return None;
    }
    if raw[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((raw[0] & 0x0F) as usize) * 4;
    if ihl < IP_MIN || raw.len() < ihl + TCP_MIN {
        return None;
    }
    let total_len = BigEndian::read_u16(&raw[2..4]) as usize;
    if total_len < ihl + TCP_MIN || raw.len() < total_len {
        // Truncated capture: fall back to raw.len() if header claims more.
        if raw.len() < ihl + TCP_MIN {
            return None;
        }
    }
    let protocol = raw[9];
    if protocol != 6 {
        return None;
    }
    let ident = BigEndian::read_u16(&raw[4..6]);
    let ttl = raw[8];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&raw[12..16]);
    dst.copy_from_slice(&raw[16..20]);
    let ip = IpMeta {
        header_len: ihl,
        total_len: total_len.min(raw.len()),
        ident,
        ttl,
        protocol,
        src,
        dst,
    };
    let t = ihl;
    let data_off = ((raw[t + 12] >> 4) as usize) * 4;
    if data_off < TCP_MIN || raw.len() < t + data_off {
        return None;
    }
    let seq = BigEndian::read_u32(&raw[t + 4..t + 8]);
    let ack = BigEndian::read_u32(&raw[t + 8..t + 12]);
    let flags = raw[t + 13];
    let window = BigEndian::read_u16(&raw[t + 14..t + 16]);
    let tcp = TcpMeta {
        header_len: data_off,
        seq,
        ack,
        flags,
        window,
    };
    Some((ip, tcp, ihl, data_off))
}

/// Extract flag/payload view used by the handshake state machine.
pub fn tcp_info(raw: &[u8]) -> Option<TcpInfo> {
    let (_, tcp, ip_hlen, tcp_hlen) = parse_ip_tcp(raw)?;
    let flags = tcp.flags;
    let payload_len = raw.len().saturating_sub(ip_hlen + tcp_hlen);
    Some(TcpInfo {
        seq: tcp.seq,
        ack: tcp.ack,
        syn: flags & 0x02 != 0,
        ack_flag: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
        fin: flags & 0x01 != 0,
        psh: flags & 0x08 != 0,
        payload_len,
    })
}

/// Core primitive: rebuild `orig` (an outbound ACK template) as one fake
/// segment in old-seq space.
///
/// Mirrors the `wrong_seq` branch:
/// `seq = (syn_seq + 1 - len(payload)) & 0xFFFFFFFF`, `psh` set,
/// `ident + 1`, `total_len` adjusted, checksums recalculated.
/// `ttl_override` implements `wrong_seq_ttl` (`ttl - 1`, clamped 1..255).
pub fn build_fake_tcp(
    orig: &[u8],
    new_seq: u32,
    payload: &[u8],
    psh: bool,
    new_ident: u16,
    ttl_override: Option<u8>,
) -> Option<Vec<u8>> {
    let (ip, _tcp, ip_hlen, tcp_hlen) = parse_ip_tcp(orig)?;
    let new_total = ip_hlen.checked_add(tcp_hlen)?.checked_add(payload.len())?;
    if new_total > 65535 || new_total < ip_hlen + tcp_hlen {
        return None;
    }
    // `bytes` backing (satisfies `bytes` requirement) then freeze to Vec.
    let mut out = BytesMut::with_capacity(new_total);
    out.extend_from_slice(&orig[..ip_hlen + tcp_hlen]);
    out.extend_from_slice(payload);
    let mut pkt = out.to_vec();

    // IPv4 header updates via `byteorder` (big-endian network order).
    BigEndian::write_u16(&mut pkt[2..4], new_total as u16);
    BigEndian::write_u16(&mut pkt[4..6], new_ident);
    if let Some(ttl) = ttl_override {
        pkt[8] = ttl;
    }
    // Zero + recalc IP checksum.
    pkt[10] = 0;
    pkt[11] = 0;
    let csum = ip_checksum(&pkt[..ip_hlen]);
    BigEndian::write_u16(&mut pkt[10..12], csum);

    // TCP updates: seq + PSH bit (preserve ACK/SYN/RST/FIN).
    BigEndian::write_u32(&mut pkt[ip_hlen + 4..ip_hlen + 8], new_seq);
    if psh {
        pkt[ip_hlen + 13] |= 0x08;
    } else {
        pkt[ip_hlen + 13] &= !0x08;
    }
    // Zero + recalc TCP checksum over pseudo-header + segment.
    pkt[ip_hlen + 16] = 0;
    pkt[ip_hlen + 17] = 0;
    let tcp_seg = pkt[ip_hlen..].to_vec();
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    let _ = ip; // (kept for future ECN/options handling)
    let tsum = tcp_checksum(&src, &dst, &tcp_seg);
    BigEndian::write_u16(&mut pkt[ip_hlen + 16..ip_hlen + 18], tsum);
    Some(pkt)
}

/// One-shot IP checksum (RFC 791): sum BE words, fold carries, complement.
pub fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += BigEndian::read_u16(&header[i..i + 2]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum with IPv4 pseudo-header (RFC 793).
pub fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src + dst + zero + protocol(6) + tcp_len.
    sum += BigEndian::read_u16(&src[0..2]) as u32;
    sum += BigEndian::read_u16(&src[2..4]) as u32;
    sum += BigEndian::read_u16(&dst[0..2]) as u32;
    sum += BigEndian::read_u16(&dst[2..4]) as u32;
    sum += 6u32; // protocol TCP
    sum += segment.len() as u32;
    let mut i = 0;
    while i + 1 < segment.len() {
        // Skip the checksum field itself (offset 16 within TCP header).
        if i == 16 {
            i += 2;
            continue;
        }
        sum += BigEndian::read_u16(&segment[i..i + 2]) as u32;
        i += 2;
    }
    if i < segment.len() {
        // Odd tail: last byte is high-order (padded with zero).
        if i != 16 {
            sum += (segment[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let c = !(sum as u16);
    if c == 0 {
        0xFFFF // zero checksum is transmitted as all-ones
    } else {
        c
    }
}
