export interface Endpoint {
  ip: string;
  port: number;
}

export interface AppConfig {
  LISTEN_HOST: string;
  LISTEN_PORT: number;
  ENDPOINTS: Endpoint[];
  FAKE_SNIS: string[];
  BYPASS_METHOD: string;
  HANDSHAKE_TIMEOUT: number;
  MAX_CONNECTIONS: number;
  FAKE_DELAY: number;
  SEQ_OVERLAP: number;
  TLS_FINGERPRINT: string;
  PADDING_SIZE: number;
  QUIC_MODE: string;
  MODE: string;
  PROBE_TRIES: number;
  PROBE_TIMEOUT: number;
  SOCKS5_PORT: number;
  HTTP_PORT: number;
  // Lowercase aliases accepted by the Rust migrate() layer.
  listen_host?: string;
  listen_port?: number;
  endpoints?: Endpoint[];
  fake_snis?: string[];
  [key: string]: unknown;
}

export interface StatsSnapshot {
  type: string;
  active: number;
  total: number;
  success: number;
  failed: number;
  uptime: number;
  success_rate: number;
  best_endpoint: string;
  best_method: string;
  up_bytes: number;
  down_bytes: number;
}

export interface ProbeResult {
  endpoint: string;
  latency_ms: number | null;
  reachable: boolean;
  tls_version: string | null;
  tls_alert: number | null;
  tls_alert_name: string | null;
  error: string | null;
}

export interface SniProbeResult {
  sni: string;
  endpoint: string;
  latency_ms: number | null;
  tls_version: string | null;
  tls_alert: number | null;
  tls_alert_name: string | null;
  reachable: boolean;
  error: string | null;
}

// IMPROVE(U5): one live relay session from sni_get_active_connections().
export interface ActiveConn {
  local_port: number;
  remote: string;
  method: string;
  uptime_secs: number;
}

// IMPROVE(U3): table sort state persisted in the Zustand store so sort +
// filter survive page switches.
export type SortDir = "asc" | "desc" | null;
export type TableSortKey = "name" | "latency" | "tls" | "status";

export const METHODS = [
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
] as const;

export const FINGERPRINTS = [
  "legacy",
  "chrome_120",
  "chrome_124",
  "firefox_122",
  "firefox_124",
  "custom",
] as const;

export const QUIC_MODES = ["block", "spoof", "passthrough"] as const;

export const PROXY_MODES = ["SNI Only", "Trojan + Xray"] as const;

export function defaultConfig(): AppConfig {
  return {
    // FIX(WP0.1): loopback-only by default; set to "0.0.0.0" to expose on LAN.
    LISTEN_HOST: "127.0.0.1",
    LISTEN_PORT: 40443,
    ENDPOINTS: [{ ip: "1.1.1.1", port: 443 }],
    FAKE_SNIS: ["example.com"],
    BYPASS_METHOD: "auto",
    HANDSHAKE_TIMEOUT: 2.0,
    MAX_CONNECTIONS: 200,
    FAKE_DELAY: 0.001,
    SEQ_OVERLAP: 3,
    TLS_FINGERPRINT: "legacy",
    PADDING_SIZE: 0,
    QUIC_MODE: "block",
    MODE: "SNI Only",
    PROBE_TRIES: 2,
    PROBE_TIMEOUT: 3.0,
    SOCKS5_PORT: 10808,
    HTTP_PORT: 10809,
  };
}

/** Normalize a Rust config payload (ok-wrapped or bare) into AppConfig. */
export function normalizeConfig(raw: any): AppConfig {
  const base = defaultConfig();
  if (!raw || typeof raw !== "object") return base;
  const get = (upper: string, lower: string, fb: any) =>
    raw[upper] ?? raw[lower] ?? fb;
  return {
    LISTEN_HOST: String(get("LISTEN_HOST", "listen_host", base.LISTEN_HOST)),
    LISTEN_PORT: Number(get("LISTEN_PORT", "listen_port", base.LISTEN_PORT)),
    ENDPOINTS: (get("ENDPOINTS", "endpoints", base.ENDPOINTS) as Endpoint[]) ?? base.ENDPOINTS,
    FAKE_SNIS: (get("FAKE_SNIS", "fake_snis", base.FAKE_SNIS) as string[]) ?? base.FAKE_SNIS,
    BYPASS_METHOD: String(get("BYPASS_METHOD", "bypass_method", base.BYPASS_METHOD)),
    HANDSHAKE_TIMEOUT: Number(get("HANDSHAKE_TIMEOUT", "handshake_timeout", base.HANDSHAKE_TIMEOUT)),
    MAX_CONNECTIONS: Number(get("MAX_CONNECTIONS", "max_connections", base.MAX_CONNECTIONS)),
    FAKE_DELAY: Number(get("FAKE_DELAY", "fake_delay", base.FAKE_DELAY)),
    SEQ_OVERLAP: Number(get("SEQ_OVERLAP", "seq_overlap", base.SEQ_OVERLAP)),
    TLS_FINGERPRINT: String(get("TLS_FINGERPRINT", "tls_fingerprint", base.TLS_FINGERPRINT)),
    PADDING_SIZE: Number(get("PADDING_SIZE", "padding_size", base.PADDING_SIZE)),
    QUIC_MODE: String(get("QUIC_MODE", "quic_mode", base.QUIC_MODE)),
    MODE: String(get("MODE", "mode", base.MODE)),
    PROBE_TRIES: Number(get("PROBE_TRIES", "probe_tries", base.PROBE_TRIES)),
    PROBE_TIMEOUT: Number(get("PROBE_TIMEOUT", "probe_timeout", base.PROBE_TIMEOUT)),
    SOCKS5_PORT: Number(get("SOCKS5_PORT", "socks5_port", base.SOCKS5_PORT)),
    HTTP_PORT: Number(get("HTTP_PORT", "http_port", base.HTTP_PORT)),
  };
}
