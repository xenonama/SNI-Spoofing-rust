// ===== FILE: frontend/src/api.ts =====
// Wrappers around the auto-generated Wails v3 bindings.
// The bindings use Call.ByID (numeric IDs), not string names, so
// Call.ByName would fail with "unknown bound method name" at runtime.
// TODO(titlebar): run `wails3 generate bindings -ts` from gui/
// after adding the Window* methods to EngineService. Without
// this, the three calls below will throw "method not found".
import { Events } from "@wailsio/runtime";
import * as EngineService from "../bindings/sni-spoofer/engineservice";

// FIX(B9): every Invoke goes through `call()` so backend failures surface
// as contextual Errors instead of unhandled rejections. Callers display
// them in the console / page error slots.
async function call<T>(label: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e: any) {
    throw new Error(`${label} failed: ${e?.message ?? String(e)}`);
  }
}

export const startEngine   = (cfg: string) => call("Start engine", () => EngineService.StartEngine(cfg));
export const stopEngine    = ()                   => call("Stop engine", () => EngineService.StopEngine());
export const getStats      = ()                   => call("Get stats", () => EngineService.GetStats());
export const getLogs       = ()                   => call("Get logs", () => EngineService.GetLogs());
export const clearLogs     = ()                   => call("Clear logs", () => EngineService.ClearLogs());
export const exportLogs    = ()                   => call("Export logs", () => EngineService.ExportLogs());
export const runProbeEp    = (eps: string)        => call("Rank endpoints", () => EngineService.RunProbeEndpoints(eps));
export const runProbeSni   = (snis: string, ep: string) => call("Rank SNIs", () => EngineService.RunProbeSnis(snis, ep));
export const getProbeRes   = ()                   => call("Get probe results", () => EngineService.GetProbeResults());
export const getSniRes     = ()                   => call("Get SNI results", () => EngineService.GetSniResults());
export const isAdmin       = ()                   => call("Admin check", () => EngineService.IsAdmin());
// FIX(A3): backend liveness probe for the UI resync tick.
export const isEngineAlive = ()                   => call("Engine alive check", () => EngineService.IsRunning());
export const configSave    = (cfg: string)        => call("Save config", () => EngineService.ConfigSave(cfg));
export const configLoad    = ()                   => call("Load config", () => EngineService.ConfigLoad());
export const configPath    = ()                   => call("Config path", () => EngineService.ConfigPath());
// FIX(WP0.2F): seeded first-launch defaults.
export const getDefaultConfig = ()               => call("Default config", () => EngineService.GetDefaultConfig());
// IMPROVE(U5): live relay sessions for the Active Connections view.
export const getActiveConns = ()                 => call("Active connections", () => EngineService.GetActiveConnections());
// FIX(B4): cooperative probe cancellation (window close).
export const cancelProbe   = ()                   => EngineService.CancelProbe();

// FIX(titlebar): window controls for the custom title bar.
// NOTE: `as any` keeps tsc green before `wails build` regenerates the
// bindings (new methods get new Call.ByID numbers). After regeneration
// these resolve to the strongly-typed exports.
export const windowMinimise       = () => call("Window minimise",        () => (EngineService as any).WindowMinimise());
export const windowToggleMaximise = () => call("Window toggle maximise", () => (EngineService as any).WindowToggleMaximise());
export const windowClose          = () => call("Window close",           () => (EngineService as any).WindowClose());
export const isMaximised          = () => call("Window is maximised",    () => (EngineService as any).IsMaximised() as Promise<boolean>);
// FIX(#1): manual-drag title bar bindings (frameless window).
export const windowStartDrag      = () => call("Window start drag",      () => (EngineService as any).WindowStartDrag());
export const windowIsMaximised    = () => call("Window is maximised",    () => (EngineService as any).WindowIsMaximised() as Promise<boolean>);
// FIX(tray-rewrite): runtime tray toggle — saves AND applies without
// restart. Bound to the regenerated Wails bindings (34 methods).
export const setTrayEnabled       = (enabled: boolean) => call("Set tray enabled", () => EngineService.SetTrayEnabled(enabled));
// FIX(tray-rewrite): split runtime vs persisted probes for reconcile.
export const trayRuntimeActive = () =>
  call("Tray runtime state", () => EngineService.TrayRuntimeActive());
export const trayPersistedEnabled = async (): Promise<boolean | null> => {
  try {
    return await call("Tray persisted state", () => EngineService.TrayPersistedEnabled());
  } catch {
    // fall through to configLoad fallback
  }
  try {
    const raw = await configLoad();
    const obj = typeof raw === "string" ? JSON.parse(raw) : (raw as any);
    const v = obj?.TRAY_ENABLED ?? obj?.tray_enabled;
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    if (typeof v === "string") {
      const s = v.trim().toLowerCase();
      if (["true", "1", "yes", "y", "on"].includes(s)) return true;
      if (["false", "0", "no", "n", "off"].includes(s)) return false;
    }
    return null;
  } catch {
    return null;
  }
};

// Event listeners (pushed from Go via application.Get().Event.Emit).
// FIX(B5): each returns the unsubscribe function so callers can clean up
// (React useEffect return) instead of leaking listeners on remount.
export const onStats    = (cb: (s: string) => void): (() => void) =>
  Events.On("stats", (e) => cb(e.data as string));
export const onLogs     = (cb: (l: string) => void): (() => void) =>
  Events.On("logs", (e) => cb(e.data as string));
export const onProbeRes = (cb: (r: string) => void): (() => void) =>
  Events.On("probe-results", (e) => cb(e.data as string));
export const onSniRes   = (cb: (r: string) => void): (() => void) =>
  Events.On("sni-results", (e) => cb(e.data as string));
