export type ConfigDto = {
  listen_host: string;
  listen_port: number;
  endpoints: { ip: string; port: number }[];
  fake_snis: string[];
  bypass_method: string;
  handshake_timeout: number;
  max_connections: number;
  fake_delay: number;
  seq_overlap: number;
  tls_fingerprint: string;
  padding_size: number;
  quic_mode: string;
  mode: string;
  probe_tries: number;
  probe_timeout: number;
  socks5_port: number;
  http_port: number;
};

export type SnapshotDto = {
  active: number;
  total: number;
  success: number;
  failed: number;
  success_rate: number;
  best_endpoint: string;
  best_method: string;
  up_bytes: number;
  down_bytes: number;
  uptime: number;
};

export type ProbeResultDto = {
  endpoint: string;
  latency_ms: number | null;
  reachable: boolean;
  tls_version: string | null;
  tls_alert: number | null;
  tls_alert_name: string | null;
  error: string | null;
};

export type SniProbeResultDto = ProbeResultDto & { sni: string };

export type EngineStatus = { running: boolean };

export type ProbeProgress = { done: number; total: number; kind: string };

export type Page = "bypass" | "proxy" | "tools";

export const BYPASS_METHODS = [
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
