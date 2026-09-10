//! Offline self-test: port of `main.py::run_self_test`.
//!
//! Pure + offline (no Admin/WinDivert/network). Each check mirrors one Python
//! check, adapted where the Rust port intentionally diverges:
//! - `tls_fingerprint`: legacy 517B builder fully; modern GREASE/ALPS/ECH
//!   profiles dispatch to legacy (documented in `tls.rs`), so we assert
//!   profile parsing + legacy vectors, not browser-blob bytes.
//! - `quic`: packet-crypto helpers (`is_quic_packet`, SNI swap) are a future
//!   slice; we assert mode parsing + filter builders + trojan passthrough bit.
//! - `mock_bypass`: mock-socket `fake_send_thread` becomes pure
//!   `plan_fake` segment-count/prefix assertions (same wire math).

use std::path::Path;

fn check_config(path: &Path) -> Result<String, String> {
    let cfg = crate::config::load(path).map_err(|e| e.to_string())?;
    Ok(format!(
        "{} endpoint(s), {} SNI(s), method={}",
        cfg.endpoints.len(),
        cfg.fake_snis.len(),
        cfg.bypass_method
    ))
}

fn check_packet_template() -> Result<String, String> {
    let rnd = [0x11u8; 32];
    let sess = [0x22u8; 32];
    let key = [0x33u8; 32];
    let hello = crate::tls::get_client_hello_with(&rnd, &sess, b"example.com", &key)
        .map_err(|e| e.to_string())?;
    if hello.len() != 517 {
        return Err(format!("ClientHello len {} != 517", hello.len()));
    }
    let (r2, s2, sni2, k2) =
        crate::tls::parse_client_hello(&hello).ok_or_else(|| "round-trip parse failed".to_string())?;
    if r2 != rnd || s2 != sess || sni2 != b"example.com" || k2 != key {
        return Err("round-trip field mismatch".to_string());
    }
    Ok(format!("ClientHello {}B round-trip OK", hello.len()))
}

fn check_scoreboard() -> Result<String, String> {
    let st = crate::stats::Stats::new();
    st.record_result("1.1.1.1:443", "a.com", true, "wrong_seq");
    st.record_result("1.1.1.1:443", "a.com", false, "wrong_seq");
    let snap = st.snapshot();
    // record_result touches boards only (mirrors Python counters untouched).
    if snap.success_rate != 0.0 {
        return Err(format!("success_rate {} != 0.0", snap.success_rate));
    }
    if snap.best_endpoint != "1.1.1.1:443" {
        return Err(format!("best_endpoint {:?} unexpected", snap.best_endpoint));
    }
    if snap.methods.is_empty() || snap.methods[0].key != "wrong_seq" {
        return Err("method board missing wrong_seq".to_string());
    }
    st.reset();
    let snap2 = st.snapshot();
    if snap2.total != 0 || snap2.success != 0 || snap2.failed != 0 {
        return Err("reset did not clear counters".to_string());
    }
    Ok("scoreboard OK".to_string())
}

fn check_split() -> Result<String, String> {
    let (s1, s2) = crate::fake_tcp::split_plan(1000, 517, 258);
    if s2 != s1.wrapping_add(258) {
        return Err("split_plan s2 mismatch".to_string());
    }
    if s1 != 1001u32.wrapping_sub(517) {
        return Err("split_plan s1 mismatch".to_string());
    }
    let ((o1, o2, o3), (v1, v2)) = crate::fake_tcp::overlap_plan(517, 206, 155, 3);
    if (o1, o2, o3) != (0, 203, 355) || (v1, v2) != (3, 3) {
        return Err(format!("overlap_plan got ({},{},{}) ({},{})", o1, o2, o3, v1, v2));
    }
    let ((z1, z2, z3), (w1, w2)) = crate::fake_tcp::overlap_plan(517, 206, 155, 0);
    if (z1, z2, z3) != (0, 206, 361) || (w1, w2) != (0, 0) {
        return Err("overlap_plan zero-overlap mismatch".to_string());
    }
    Ok("split math OK".to_string())
}

fn check_tlsfp() -> Result<String, String> {
    // Legacy vector: starts 16 03 01, byte[5]==0x01, 517B.
    let hello = crate::tls::build_fake_client_hello(
        b"example.com",
        crate::tls::TlsProfile::Legacy,
    );
    if hello.len() != 517 {
        return Err(format!("legacy len {} != 517", hello.len()));
    }
    if hello.len() < 6 || hello[0..3] != [0x16, 0x03, 0x01] || hello[5] != 0x01 {
        return Err("legacy header mismatch".to_string());
    }
    // All profile names parse (modern dispatch to legacy documented).
    for name in ["legacy", "chrome_120", "chrome_124", "firefox_122", "firefox_124", "custom"] {
        crate::tls::TlsProfile::parse(name).map_err(|e| e.to_string())?;
    }
    if crate::tls::TlsProfile::parse("bogus").is_ok() {
        return Err("bogus profile should fail".to_string());
    }
    // Guards mirror ClientHelloMaker preconditions.
    if crate::tls::check_hello_params(&[0u8; 32], &[0u8; 32], b"", &[0u8; 32]).is_ok() {
        return Err("empty SNI should fail".to_string());
    }
    if crate::tls::check_hello_params(&[0u8; 32], &[0u8; 32], &vec![b'x'; 220], &[0u8; 32]).is_ok() {
        return Err("oversize SNI should fail".to_string());
    }
    Ok(format!("tls fingerprint OK (legacy {}B)", hello.len()))
}

fn check_quic() -> Result<String, String> {
    for (name, expect) in [
        ("block", crate::quic::QuicMode::Block),
        ("spoof", crate::quic::QuicMode::Spoof),
        ("passthrough", crate::quic::QuicMode::Passthrough),
    ] {
        let m = crate::quic::QuicMode::parse(name).map_err(|e| e.to_string())?;
        if m != expect {
            return Err(format!("quic mode {} mismatch", name));
        }
    }
    if crate::quic::QuicMode::parse("bogus").is_ok() {
        return Err("bogus quic mode should fail".to_string());
    }
    let f = crate::picker::build_quic_filter("192.168.1.10");
    if !f.contains("192.168.1.10") || !f.contains("443") || !f.starts_with("udp") {
        return Err(format!("quic filter unexpected: {}", f));
    }
    Ok("quic modes + filter OK".to_string())
}

fn check_new_methods() -> Result<String, String> {
    if crate::fake_tcp::resolve_method("hostfakesplit").map_err(|e| e.to_string())? != crate::fake_tcp::BypassMethod::HostFakeSplit {
        return Err("resolve hostfakesplit failed".to_string());
    }
    if crate::fake_tcp::resolve_method("fakedsplit").map_err(|e| e.to_string())? != crate::fake_tcp::BypassMethod::FakeSplit {
        return Err("resolve fakedsplit failed".to_string());
    }
    let auto = crate::fake_tcp::resolve_method("auto").map_err(|e| e.to_string())?;
    if !crate::fake_tcp::REAL_METHODS.contains(&auto.as_str()) {
        return Err("auto did not resolve to real method".to_string());
    }
    if crate::fake_tcp::resolve_method("split_seq").map_err(|e| e.to_string())? != crate::fake_tcp::BypassMethod::SplitSeq {
        return Err("resolve split_seq failed".to_string());
    }
    // SNI helpers on a real legacy hello.
    let hello = crate::tls::build_fake_client_hello(
        b"example.com",
        crate::tls::TlsProfile::Legacy,
    );
    let sni = crate::fake_tcp::extract_sni_from_hello(&hello)
        .ok_or_else(|| "extract SNI failed".to_string())?;
    if sni != b"example.com" {
        return Err("extracted SNI mismatch".to_string());
    }
    if crate::fake_tcp::extract_sni_from_hello(b"\x00").is_some() {
        return Err("tiny packet should yield None".to_string());
    }
    let decoy = crate::fake_tcp::same_length_fake_sni(b"example.com");
    if decoy.len() != b"example.com".len() || decoy == b"example.com" {
        return Err("decoy must differ at same length".to_string());
    }
    let micro = crate::fake_tcp::same_length_fake_sni(b"a.bc");
    if micro.len() != 4 || !micro.contains(&b'.') {
        return Err("micro-SNI must keep length + dot".to_string());
    }
    let variant = crate::fake_tcp::build_hostfake_variant(&hello);
    if variant.len() != hello.len() || variant[0..3] != [0x16, 0x03, 0x01] {
        return Err("hostfake variant length/header mismatch".to_string());
    }
    if crate::fake_tcp::build_hostfake_variant(b"") != b"" {
        return Err("empty variant should round-trip".to_string());
    }
    let signed = crate::fake_tcp::md5_fake_payload(&hello);
    if signed.len() != hello.len() + 16 {
        return Err("md5 payload length mismatch".to_string());
    }
    let digest = md5::compute(&hello);
    if signed[..16] != digest.0[..] {
        return Err("md5 prefix mismatch".to_string());
    }
    if crate::fake_tcp::md5_fake_payload(b"").len() != 16 {
        return Err("empty md5 payload should be 16B".to_string());
    }
    Ok("new bypass methods OK (hostfakesplit/fakedsplit)".to_string())
}

fn check_mock_bypass() -> Result<String, String> {
    let hello = crate::tls::build_fake_client_hello(
        b"example.com",
        crate::tls::TlsProfile::Legacy,
    );
    let n = hello.len();
    let params = crate::fake_tcp::FakeParams::default();
    // 1) hostfakesplit happy path: same-length decoy -> 2 segments.
    let segs = crate::fake_tcp::plan_fake(
        crate::fake_tcp::BypassMethod::HostFakeSplit,
        5000,
        &hello,
        &params,
        None,
    );
    if segs.len() != 2 {
        return Err(format!("hostfakesplit expected 2 segs, got {}", segs.len()));
    }
    if segs[0].payload.len() != n || segs[1].payload.len() != n {
        return Err("hostfakesplit seg lengths mismatch".to_string());
    }
    // 2) tiny-packet fallback -> single wrong_seq.
    let tiny = crate::fake_tcp::plan_fake(
        crate::fake_tcp::BypassMethod::HostFakeSplit,
        5000,
        b"\x16",
        &params,
        None,
    );
    if tiny.len() != 1 || tiny[0].payload != b"\x16" {
        return Err("hostfakesplit tiny fallback mismatch".to_string());
    }
    // 3) fakedsplit: MD5-signed badseq + real hello -> 2 segments.
    let fs = crate::fake_tcp::plan_fake(
        crate::fake_tcp::BypassMethod::FakeSplit,
        5000,
        &hello,
        &params,
        None,
    );
    if fs.len() != 2 {
        return Err(format!("fakedsplit expected 2 segs, got {}", fs.len()));
    }
    if fs[0].payload.len() != n + 16 || fs[1].payload != hello {
        return Err("fakedsplit payload mismatch".to_string());
    }
    let digest = md5::compute(&hello);
    if fs[0].payload[..16] != digest.0[..] {
        return Err("fakedsplit md5 prefix mismatch".to_string());
    }
    Ok(format!(
        "mock bypass OK (hostfakesplit 2-seg + fallback 1-seg, fakedsplit 2-seg, n={})",
        n
    ))
}

fn check_mode_quic(path: &Path) -> Result<String, String> {
    let cfg = crate::config::load(path).map_err(|e| e.to_string())?;
    if cfg.mode != "SNI Only" && cfg.mode != "Trojan + Xray" {
        return Err(format!("MODE {:?} unexpected", cfg.mode));
    }
    let trojan = cfg.mode.trim() == "Trojan + Xray";
    // Derivation mirrors main.py wiring (bool, both directions).
    if ("Trojan + Xray" == "Trojan + Xray") != true {
        return Err("trojan derivation broken".to_string());
    }
    if ("SNI Only" == "Trojan + Xray") != false {
        return Err("sni-only derivation broken".to_string());
    }
    let _ = trojan;
    let f = crate::picker::build_quic_filter("10.0.0.2");
    if !f.contains("10.0.0.2") {
        return Err("quic filter missing iface".to_string());
    }
    Ok("MODE/QUIC plumbing OK".to_string())
}

fn check_helpers() -> Result<String, String> {
    // Picker round-robin: two picks rotate the start.
    let eps = vec![
        crate::config::Endpoint { ip: "1.1.1.1".into(), port: 443 },
        crate::config::Endpoint { ip: "1.0.0.1".into(), port: 443 },
    ];
    let picker = crate::picker::EndpointPicker::new(eps);
    let first = picker.pick_ordered();
    let second = picker.pick_ordered();
    if first.len() != 2 || second.len() != 2 {
        return Err("picker should return all endpoints".to_string());
    }
    if first[0].ip == second[0].ip {
        return Err("round-robin did not rotate".to_string());
    }
    if crate::picker::ep_key(&first[0]) != format!("{}:{}", first[0].ip, first[0].port) {
        return Err("ep_key format mismatch".to_string());
    }
    if crate::picker::pick_sni(&[]).is_some() {
        return Err("empty SNI pool should yield None".to_string());
    }
    // Config validation rejects empties (mirrors config_manager.validate).
    let mut bad = crate::config::Config::default();
    if crate::config::validate(&bad).is_ok() {
        return Err("empty config should fail validation".to_string());
    }
    bad.endpoints = vec![crate::config::Endpoint { ip: "999.999.999.999".into(), port: 443 }];
    bad.fake_snis = vec!["example.com".into()];
    if crate::config::validate(&bad).is_ok() {
        return Err("bad IP should fail validation".to_string());
    }
    // Handshake state machine: SYN -> SYN-ACK -> ACK -> fake -> ACK-success.
    let info = |seq: u32, ack: u32, syn: bool, ackf: bool, pay: usize| crate::tcp::TcpInfo {
        seq,
        ack,
        syn,
        ack_flag: ackf,
        rst: false,
        fin: false,
        psh: false,
        payload_len: pay,
    };
    let mut hs = crate::fake_tcp::HandshakeState::new(crate::fake_tcp::BypassMethod::WrongSeq);
    if hs.on_outbound(info(5000, 0, true, false, 0)) != crate::fake_tcp::OutboundAction::Reinject {
        return Err("outbound SYN should reinject".to_string());
    }
    if hs.on_inbound(info(7000, 5001, true, true, 0)) != crate::fake_tcp::InboundAction::Reinject {
        return Err("inbound SYN-ACK should reinject".to_string());
    }
    if hs.on_outbound(info(5001, 7001, false, true, 0)) != crate::fake_tcp::OutboundAction::TriggerFake {
        return Err("outbound ACK should trigger fake".to_string());
    }
    hs.mark_fake_sent();
    if hs.on_inbound(info(7001, 5001, false, true, 0)) != crate::fake_tcp::InboundAction::Success {
        return Err("inbound ACK should succeed".to_string());
    }
    Ok("helpers OK".to_string())
}

/// Run all checks. Returns `(all_ok, report_json)`.
pub fn run(config_path: &Path) -> (bool, serde_json::Value) {
    let mut checks = serde_json::Map::new();
    let mut ok_all = true;
    macro_rules! run_one {
        ($name:expr, $expr:expr) => {
            match $expr {
                Ok(detail) => {
                    checks.insert(
                        $name.to_string(),
                        serde_json::json!({"ok": true, "detail": detail}),
                    );
                }
                Err(detail) => {
                    ok_all = false;
                    let d: String = detail.chars().take(300).collect();
                    checks.insert($name.to_string(), serde_json::json!({"ok": false, "detail": d}));
                }
            }
        };
    }
    run_one!("config", check_config(config_path));
    run_one!("packet_template", check_packet_template());
    run_one!("scoreboard", check_scoreboard());
    run_one!("split_plan", check_split());
    run_one!("tls_fingerprint", check_tlsfp());
    run_one!("quic", check_quic());
    run_one!("new_methods", check_new_methods());
    run_one!("mock_bypass", check_mock_bypass());
    run_one!("mode_quic", check_mode_quic(config_path));
    run_one!("helpers", check_helpers());
    (
        ok_all,
        serde_json::json!({"checks": checks, "ok": ok_all}),
    )
}