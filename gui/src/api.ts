import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  ConfigDto,
  EngineStatus,
  ProbeProgress,
  ProbeResultDto,
  SniProbeResultDto,
  SnapshotDto,
} from "./types";

export const startEngine = () => invoke<void>("start_engine");
export const stopEngine = () => invoke<void>("stop_engine");
export const getConfig = () => invoke<ConfigDto>("get_config");
export const saveConfig = (c: ConfigDto) => invoke<void>("save_config", { cfg: c });
export const reloadConfig = () => invoke<ConfigDto>("reload_config");
export const getStats = () => invoke<SnapshotDto>("get_stats_snapshot");
export const runProbeEp = (eps: string[]) =>
  invoke<void>("run_probe_endpoints", { endpoints: eps });
export const runProbeSni = (snis: string[], ep: string) =>
  invoke<void>("run_probe_snis", { snis, endpoint: ep });
export const getProbeRes = () => invoke<ProbeResultDto[]>("get_probe_results");
export const getSniRes = () => invoke<SniProbeResultDto[]>("get_sni_results");
export const clearLogs = () => invoke<void>("clear_logs");
export const exportLogs = () => invoke<string>("export_logs");
export const pickFastest = () => invoke<string>("pick_fastest_endpoint");
export const isAdmin = () => invoke<boolean>("is_admin");
export const openLogs = () => invoke<void>("open_logs_folder");

export const onStats = (cb: (s: SnapshotDto) => void) =>
  listen<SnapshotDto>("stats_update", (e) => cb(e.payload));
export const onLog = (cb: (l: string) => void) =>
  listen<string>("log_line", (e) => cb(e.payload));
export const onEngine = (cb: (s: EngineStatus) => void) =>
  listen<EngineStatus>("engine_status", (e) => cb(e.payload));
export const onProbeRes = (cb: (r: ProbeResultDto[]) => void) =>
  listen<ProbeResultDto[]>("probe_results", (e) => cb(e.payload));
export const onSniRes = (cb: (r: SniProbeResultDto[]) => void) =>
  listen<SniProbeResultDto[]>("sni_results", (e) => cb(e.payload));
export const onProbeProgress = (cb: (p: ProbeProgress) => void) =>
  listen<ProbeProgress>("probe_progress", (e) => cb(e.payload));
