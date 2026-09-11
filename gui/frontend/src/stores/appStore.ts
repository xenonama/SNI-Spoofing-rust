import { create } from "zustand";
import * as api from "../api";
import {
  normalizeConfig,
  defaultConfig,
  type ActiveConn,
  type AppConfig,
  type ProbeResult,
  type SniProbeResult,
  type SortDir,
  type TableSortKey,
} from "../types";

interface AppState {
  running: boolean;
  active: number;
  total: number;
  ok: number;
  fail: number;
  successRate: number;
  bestEndpoint: string;
  bestMethod: string;
  upBytes: number;
  downBytes: number;
  lastUpdated: string;
  logs: string[];
  probeResults: ProbeResult[];
  sniResults: SniProbeResult[];
  probing: boolean;
  probeKind: string | null;
  probeDone: number;
  probeTotal: number;
  page: number;
  config: AppConfig;
  admin: boolean | null;
  // FIX(B1): engine-start wall clock (null = stopped). Header derives the
  // uptime display from this; the backend snapshot uptime (process start)
  // is deliberately NOT used.
  engineStartedAt: number | null;
  // FIX(B7): measured poll rate (EMA), replaces the hardcoded "60 fps".
  pollHz: number;
  // FIX(B3): global transient notice (e.g. Space-toggle failures).
  notice: string | null;
  // IMPROVE(U5): live relay sessions polled at the same 1Hz cadence.
  activeConns: ActiveConn[];
  // IMPROVE(U3): table sort + filter persisted here so they survive page switches.
  epSort: { key: TableSortKey; dir: SortDir };
  epFilter: string;
  sniSort: { key: TableSortKey; dir: SortDir };
  sniFilter: string;
  actions: {
    setPage: (p: number) => void;
    setConfig: (c: AppConfig) => void;
    notify: (msg: string | null) => void;
    setEpSort: (key: TableSortKey) => void;
    setEpFilter: (f: string) => void;
    setSniSort: (key: TableSortKey) => void;
    setSniFilter: (f: string) => void;
    start: () => Promise<void>;
    stop: () => Promise<void>;
    save: () => Promise<void>;
    load: () => Promise<void>;
    refreshStats: () => Promise<void>;
    refreshLogs: () => Promise<void>;
    refreshActive: () => Promise<void>;
    // FIX(A3): slow-cadence liveness resync against the backend.
    refreshAlive: () => Promise<void>;
    clearLogs: () => Promise<void>;
    exportLogs: () => Promise<void>;
    runProbeEndpoints: () => Promise<void>;
    runProbeSnis: () => Promise<void>;
    useFastest: () => void;
  };
}

function fmtUptime(secs: number): string {
  const s = Math.floor(secs);
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${h}:${m}:${ss}`;
}

// FIX(B1): shared uptime formatter — Header computes display from
// engineStartedAt, never from the backend snapshot.
export function formatUptime(secs: number): string {
  return fmtUptime(secs);
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v.toFixed(1)} ${units[u]}`;
}

export function formatBytes(n: number): string {
  return fmtBytes(n);
}

async function unwrapCall(p: Promise<unknown>): Promise<any> {
  const raw = await p;
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }
  return raw;
}

// IMPROVE(U6): last applied signatures — the 1Hz poller skips `set()` when
// nothing changed so idle ticks cause no re-render (no coil whine, <3% CPU).
let lastStatsSig = "";
let lastLogSig = "";
// FIX(B7): last tick wall-clock for the measured poll-rate EMA.
let lastTickAt = 0;

export const useAppStore = create<AppState>((set, get) => ({
  running: false,
  active: 0,
  total: 0,
  ok: 0,
  fail: 0,
  successRate: 0,
  bestEndpoint: "",
  bestMethod: "",
  upBytes: 0,
  downBytes: 0,
  lastUpdated: "Last updated —",
  logs: [],
  probeResults: [],
  sniResults: [],
  probing: false,
  probeKind: null,
  probeDone: 0,
  probeTotal: 0,
  page: 0,
  config: defaultConfig(),
  admin: null,
  engineStartedAt: null,
  pollHz: 0,
  notice: null,
  activeConns: [],
  epSort: { key: "latency", dir: null },
  epFilter: "",
  sniSort: { key: "latency", dir: null },
  sniFilter: "",
  actions: {
    setPage: (p) => set({ page: p }),
    setConfig: (c) => set({ config: c }),
    // IMPROVE(U3): click cycles asc → desc → none (unsorted).
    setEpSort: (key) =>
      set((s) => ({
        epSort:
          s.epSort.key !== key
            ? { key, dir: "asc" as SortDir }
            : s.epSort.dir === "asc"
              ? { key, dir: "desc" as SortDir }
              : { key, dir: null as SortDir },
      })),
    setEpFilter: (f) => set({ epFilter: f }),
    setSniSort: (key) =>
      set((s) => ({
        sniSort:
          s.sniSort.key !== key
            ? { key, dir: "asc" as SortDir }
            : s.sniSort.dir === "asc"
              ? { key, dir: "desc" as SortDir }
              : { key, dir: null as SortDir },
      })),
    setSniFilter: (f) => set({ sniFilter: f }),
    notify: (msg) => set({ notice: msg }),
    start: async () => {
      const cfg = JSON.stringify(get().config);
      const res = await unwrapCall(api.startEngine(cfg) as Promise<unknown>);
      if (res && res.ok === false) throw new Error(res.error ?? "start failed");
      // FIX(B1): anchor engine uptime to the successful start call.
      set({ running: true, engineStartedAt: Date.now() });
    },
    stop: async () => {
      await unwrapCall(api.stopEngine() as Promise<unknown>);
      lastStatsSig = "";
      // FIX(A5): clear derived scoreboard state so no stale Best/rate
      // lingers after Stop; FIX(B1): release the uptime anchor.
      set({
        running: false,
        active: 0,
        total: 0,
        ok: 0,
        fail: 0,
        successRate: 0,
        bestEndpoint: "",
        bestMethod: "",
        upBytes: 0,
        downBytes: 0,
        lastUpdated: "Last updated —",
        activeConns: [],
        engineStartedAt: null,
      });
    },
    save: async () => {
      const cfg = JSON.stringify(get().config);
      const res = await unwrapCall(api.configSave(cfg) as Promise<unknown>);
      if (res && res.ok === false) throw new Error(res.error ?? "save failed");
    },
    // FIX(WP0.2G): configLoad seeds + persists on first launch (Rust side),
    // so it only fails when the backend is unreachable or the file is
    // corrupt — then fall back to seeded defaults instead of blanks.
    // FIX(D4): corrupt JSON never crashes; last good config is kept.
    load: async () => {
      try {
        const raw = await unwrapCall(api.configLoad() as Promise<unknown>);
        if (raw && typeof raw === "object" && (raw as any).ok === false) {
          throw new Error((raw as any).error ?? "load failed");
        }
        if (raw && typeof raw === "object") {
          set({ config: normalizeConfig(raw) });
        } else {
          const fb = await unwrapCall(api.getDefaultConfig() as Promise<unknown>);
          set({ config: normalizeConfig(fb) });
        }
      } catch {
        try {
          const fb = await unwrapCall(api.getDefaultConfig() as Promise<unknown>);
          set({ config: normalizeConfig(fb) });
        } catch {
          // Backend DLL unavailable (dev browser) — keep built-in defaults.
        }
      }
      try {
        const admin = (await api.isAdmin()) as unknown as boolean;
        set({ admin: !!admin });
      } catch {
        set({ admin: null });
      }
    },
    refreshStats: async () => {
      try {
        const raw = await unwrapCall(api.getStats() as Promise<unknown>);
        const snap = typeof raw === "string" ? JSON.parse(raw) : raw;
        if (!snap || typeof snap !== "object" || snap.ok === false) return;
        // FIX(B7): measured poll-rate EMA (replaces the hardcoded badge).
        // Only stored when it moves visibly, so idle ticks stay silent.
        const nowMs = Date.now();
        if (lastTickAt > 0) {
          const dt = (nowMs - lastTickAt) / 1000;
          if (dt > 0 && dt < 10) {
            const hz = 1 / dt;
            const prev = get().pollHz;
            const next = prev <= 0 ? hz : prev * 0.8 + hz * 0.2;
            if (Math.abs(next - prev) > 0.05) set({ pollHz: next });
          }
        }
        lastTickAt = nowMs;
        // IMPROVE(U6): skip the store update (and re-render) when the
        // signature is unchanged — idle polling stays allocation-light.
        // FIX(B1): backend `uptime` (process start) is excluded on purpose;
        // the Header derives uptime from `engineStartedAt` instead.
        const sig = [
          snap.active, snap.total, snap.success, snap.failed,
          snap.success_rate, snap.best_endpoint, snap.best_method,
          snap.up_bytes, snap.down_bytes,
        ].join("|");
        if (sig === lastStatsSig) return;
        lastStatsSig = sig;
        set({
          active: snap.active ?? 0,
          total: snap.total ?? 0,
          ok: snap.success ?? 0,
          fail: snap.failed ?? 0,
          successRate: snap.success_rate ?? 0,
          bestEndpoint: snap.best_endpoint ?? "",
          bestMethod: snap.best_method ?? "",
          upBytes: snap.up_bytes ?? 0,
          downBytes: snap.down_bytes ?? 0,
          lastUpdated: "Last updated just now",
        });
      } catch {
        // Backend unavailable — leave last values in place (no layout shift).
      }
    },
    refreshLogs: async () => {
      try {
        const raw = await unwrapCall(api.getLogs() as Promise<unknown>);
        const arr = Array.isArray(raw) ? raw : typeof raw === "string" ? JSON.parse(raw) : [];
        if (!Array.isArray(arr)) return;
        const lines = arr.map(String);
        // IMPROVE(U6): skip when unchanged (length + last line fingerprint).
        const sig = `${lines.length}|${lines[lines.length - 1] ?? ""}`;
        if (sig === lastLogSig) return;
        lastLogSig = sig;
        set({ logs: lines });
      } catch {
        // ignore
      }
    },
    // IMPROVE(U5): polled at 1Hz alongside stats; empty when stopped.
    refreshActive: async () => {
      if (!get().running) {
        if (get().activeConns.length > 0) set({ activeConns: [] });
        return;
      }
      try {
        const raw = await unwrapCall(api.getActiveConns() as Promise<unknown>);
        const arr = Array.isArray(raw) ? raw : [];
        // FIX(F5): keep the full list in store (bounded by max_connections);
        // the view renders the first 50 with a "… and N more" footer.
        set({ activeConns: arr as ActiveConn[] });
      } catch {
        // ignore — table keeps last snapshot
      }
    },
    // FIX(A3): slow-cadence liveness resync — if the backend reports the
    // engine gone while the UI thinks it runs, drop to idle + notice
    // instead of showing a stuck "running" state.
    refreshAlive: async () => {
      if (!get().running) return;
      try {
        const alive = (await api.isEngineAlive()) as unknown as boolean;
        if (!alive) {
          lastStatsSig = "";
          set({
            running: false,
            active: 0,
            total: 0,
            ok: 0,
            fail: 0,
            successRate: 0,
            bestEndpoint: "",
            bestMethod: "",
            upBytes: 0,
            downBytes: 0,
            lastUpdated: "Last updated —",
            activeConns: [],
            engineStartedAt: null,
            notice: "Engine stopped unexpectedly",
          });
        }
      } catch {
        // Backend unreachable — leave state; next tick retries.
      }
    },
    clearLogs: async () => {
      try {
        await api.clearLogs();
      } catch {
        // ignore
      }
      lastLogSig = "";
      set({ logs: [] });
    },
    exportLogs: async () => {
      await unwrapCall(api.exportLogs() as Promise<unknown>);
    },
    runProbeEndpoints: async () => {
      const eps = get().config.ENDPOINTS.map((e) => `${e.ip}:${e.port}`);
      set({ probing: true, probeKind: "endpoints", probeDone: 0, probeTotal: eps.length });
      try {
        await unwrapCall(api.runProbeEp(JSON.stringify(eps)) as Promise<unknown>);
        const r = await unwrapCall(api.getProbeRes() as Promise<unknown>);
        const arr = Array.isArray(r) ? r : [];
        set({ probeResults: arr, probing: false, probeDone: eps.length });
      } catch {
        set({ probing: false });
        throw new Error("endpoint probe failed");
      }
    },
    runProbeSnis: async () => {
      const snis = get().config.FAKE_SNIS;
      const ep =
        get().probeResults.find((p) => p.reachable)?.endpoint ||
        get().config.ENDPOINTS.map((e) => `${e.ip}:${e.port}`)[0] ||
        "";
      set({ probing: true, probeKind: "snis", probeDone: 0, probeTotal: snis.length });
      try {
        await unwrapCall(api.runProbeSni(JSON.stringify(snis), ep) as Promise<unknown>);
        const r = await unwrapCall(api.getSniRes() as Promise<unknown>);
        const arr = Array.isArray(r) ? r : [];
        set({ sniResults: arr, probing: false, probeDone: snis.length });
      } catch {
        set({ probing: false });
        throw new Error("SNI probe failed");
      }
    },
    useFastest: () => {
      const fastest = get().probeResults.find((p) => p.reachable);
      if (fastest) {
        const [ip, portStr] = fastest.endpoint.split(":");
        // FIX(F3): destructive overwrite — confirm first so a misclick
        // can't silently discard the hand-tuned endpoint list.
        if (
          get().config.ENDPOINTS.length > 0 &&
          !window.confirm(`Replace endpoints with fastest (${fastest.endpoint})?`)
        ) {
          return;
        }
        const cfg = { ...get().config };
        cfg.ENDPOINTS = [{ ip, port: parseInt(portStr, 10) || 443 }];
        set({ config: cfg });
      }
    },
  },
}));
