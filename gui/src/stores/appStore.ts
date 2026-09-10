import { create } from "zustand";
import {
  onEngine,
  onLog,
  onProbeProgress,
  onProbeRes,
  onSniRes,
  onStats,
} from "../api";
import type {
  ConfigDto,
  Page,
  ProbeResultDto,
  SnapshotDto,
  SniProbeResultDto,
} from "../types";

type ProbingState = {
  active: boolean;
  kind: "endpoints" | "snis" | null;
  done: number;
  total: number;
};

type AppState = {
  page: Page;
  config: ConfigDto | null;
  snapshot: SnapshotDto | null;
  lastUpdatedAt: number | null;
  logs: string[];
  engineRunning: boolean;
  probeResults: ProbeResultDto[];
  sniResults: SniProbeResultDto[];
  probing: ProbingState;
  fastestEndpoint: string | null;
  listenersReady: boolean;
  setPage: (p: Page) => void;
  setConfig: (c: ConfigDto | null) => void;
  setSnapshot: (s: SnapshotDto | null) => void;
  pushLog: (l: string) => void;
  clearLogsLocal: () => void;
  setEngineRunning: (b: boolean) => void;
  setProbeResults: (r: ProbeResultDto[]) => void;
  setSniResults: (r: SniProbeResultDto[]) => void;
  setProbing: (p: Partial<ProbingState>) => void;
  setFastestEndpoint: (e: string | null) => void;
  initListeners: () => Promise<void>;
};

const MAX_LOGS = 2000;

export const useAppStore = create<AppState>((set) => ({
  page: "bypass",
  config: null,
  snapshot: null,
  lastUpdatedAt: null,
  logs: [],
  engineRunning: false,
  probeResults: [],
  sniResults: [],
  probing: { active: false, kind: null, done: 0, total: 0 },
  fastestEndpoint: null,
  listenersReady: false,
  setPage: (page) => set({ page }),
  setConfig: (config) => set({ config }),
  setSnapshot: (snapshot) => set({ snapshot, lastUpdatedAt: Date.now() }),
  pushLog: (line) =>
    set((s) => {
      const logs = [...s.logs, line];
      if (logs.length > MAX_LOGS) logs.splice(0, logs.length - MAX_LOGS);
      return { logs };
    }),
  clearLogsLocal: () => set({ logs: [] }),
  setEngineRunning: (engineRunning) => set({ engineRunning }),
  setProbeResults: (probeResults) => set({ probeResults }),
  setSniResults: (sniResults) => set({ sniResults }),
  setProbing: (p) => set((s) => ({ probing: { ...s.probing, ...p } })),
  setFastestEndpoint: (fastestEndpoint) => set({ fastestEndpoint }),
  initListeners: async () => {
    const already = useAppStore.getState().listenersReady;
    if (already) return;
    useAppStore.setState({ listenersReady: true });
    await onStats((snapshot) =>
      useAppStore.setState({ snapshot, lastUpdatedAt: Date.now() }),
    );
    await onLog((line) => useAppStore.getState().pushLog(line));
    await onEngine((st) =>
      useAppStore.setState({ engineRunning: st.running }),
    );
    await onProbeRes((probeResults) =>
      useAppStore.setState({
        probeResults,
        probing: { active: false, kind: null, done: 0, total: 0 },
      }),
    );
    await onSniRes((sniResults) =>
      useAppStore.setState({
        sniResults,
        probing: { active: false, kind: null, done: 0, total: 0 },
      }),
    );
    await onProbeProgress((p) =>
      useAppStore.setState({
        probing: {
          active: p.done < p.total,
          kind: p.kind === "snis" ? "snis" : "endpoints",
          done: p.done,
          total: p.total,
        },
      }),
    );
  },
}));
