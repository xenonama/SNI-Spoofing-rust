// ===== FILE: frontend/src/api.ts =====
// Wrappers around the auto-generated Wails v3 bindings.
// The bindings use Call.ByID (numeric IDs), not string names, so
// Call.ByName would fail with "unknown bound method name" at runtime.
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
