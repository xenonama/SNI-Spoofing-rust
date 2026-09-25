import { useEffect, useRef } from "react";
import { useAppStore } from "./stores/appStore";
// FIX(config-persist): flush-on-hide needs the save binding.
import * as api from "./api";
// FIX(design): TitleBar now owns status pill, Sidebar owns system stats.
import TitleBar from "./components/TitleBar";
import Sidebar from "./components/Sidebar";
import Console from "./components/Console";
import ConfirmModal from "./components/ConfirmModal";
import BypassPage from "./pages/BypassPage";
import ProxyPage from "./pages/ProxyPage";
import ToolsPage from "./pages/ToolsPage";

// IMPROVE(U1): single global keydown listener for keyboard shortcuts.
// Skipped while typing in inputs/textareas/selects or contentEditable.
function useShortcuts() {
  // FIX(B3): serialize Space-toggles so rapid presses can't overlap
  // start/stop calls.
  const busyRef = useRef(false);
  useEffect(() => {
    const fail = (msg: string) => {
      // FIX(B3): shortcut failures surface as a global notice instead of
      // vanishing into a swallowed rejection.
      const st = useAppStore.getState();
      st.actions.notify(msg);
      window.setTimeout(() => {
        if (useAppStore.getState().notice === msg) st.actions.notify(null);
      }, 3000);
    };
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement as HTMLElement | null;
      const typing =
        el &&
        (el.tagName === "INPUT" ||
          el.tagName === "TEXTAREA" ||
          el.tagName === "SELECT" ||
          el.isContentEditable);
      const st = useAppStore.getState();
      const save = () => st.actions.save().catch((err) => fail(String(err?.message ?? err)));
      const reload = () => st.actions.load().catch(() => {});
      const toggle = () => {
        if (busyRef.current) return;
        busyRef.current = true;
        const s = useAppStore.getState();
        (s.running ? s.actions.stop() : s.actions.start())
          .catch((err) => fail(String(err?.message ?? err)))
          .finally(() => {
            busyRef.current = false;
          });
      };

      if (e.key === "Escape") {
        // IMPROVE(U1): Esc closes any open dropdown/modal (blur select).
        if (el && el.tagName === "SELECT") el.blur();
        return;
      }
      if (typing) return;
      if (e.code === "Space" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        // IMPROVE(U1): Space toggles Start/Stop when no input is focused.
        e.preventDefault();
        toggle();
        return;
      }
      if (e.ctrlKey || e.metaKey) {
        switch (e.key.toLowerCase()) {
          case "s":
            e.preventDefault();
            save();
            break;
          case "r":
            e.preventDefault();
            reload();
            break;
          case "l":
            e.preventDefault();
            st.actions.clearLogs().catch(() => {});
            break;
          case "e":
            e.preventDefault();
            st.actions.exportLogs().catch((err) => fail(String(err?.message ?? err)));
            break;
          case "1":
            e.preventDefault();
            st.actions.setPage(0);
            break;
          case "2":
            e.preventDefault();
            st.actions.setPage(1);
            break;
          case "3":
            e.preventDefault();
            st.actions.setPage(2);
            break;
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}

// FIX(B3): global transient notice for background/shortcut failures.
function Notice() {
  const notice = useAppStore((s) => s.notice);
  const notify = useAppStore((s) => s.actions.notify);
  if (!notice) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-sm px-4 py-2.5 rounded-lg bg-danger/15 border border-danger/50 text-sm text-white shadow-lg">
      <span className="mr-3">{notice}</span>
      <button
        onClick={() => notify(null)}
        className="font-bold text-danger hover:text-white transition-colors focus:outline-none"
        aria-label="Dismiss"
      >
        ✕
      </button>
    </div>
  );
}

export default function App() {
  const page = useAppStore((s) => s.page);
  // FIX(B8): guard against React StrictMode double-mount running the
  // startup effect twice (load + duplicate pollers) in dev.
  const mounted = useRef(false);

  useShortcuts();

  // FIX(config-persist): save the current config on every hide/
  // unload so no edit is lost when the window closes or is hidden
  // to the tray within the debounce window.
  // FIX(config-race): await the Go-side FlushConfig barrier after the
  // save so process exit cannot drop an in-flight write.
  useEffect(() => {
    const flush = async () => {
      try {
        await api.flushConfig();
      } catch (e) {
        console.error("[flush] failed:", e);
      }
    };
    const saveThenFlush = () => {
      const st = useAppStore.getState();
      // FIX(tray-rewrite): never flush while the tray toggle owns the
      // disk write — visibilitychange fires on hide-to-tray itself and
      // would otherwise clobber the Go-owned TRAY_ENABLED value.
      if (st.trayBusy) return;
      const cfg = st.config;
      if (!cfg) {
        void flush();
        return;
      }
      // fire-and-forget save, then barrier; errors go to console only
      api.configSave(JSON.stringify(cfg)).catch((e) =>
        console.error("[flush] config save failed:", e)
      ).finally(() => { void flush(); });
    };
    const onBeforeUnload = () => { void saveThenFlush(); };
    window.addEventListener("beforeunload", onBeforeUnload);
    const onVis = () => {
      if (document.visibilityState === "hidden") void saveThenFlush();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, []);

  // FIX(perf): adaptive polling. Stops when hidden, slows down
  // when idle, snaps back when activity returns.
  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;

    const st = useAppStore.getState();
    st.actions.load().finally(() => {
      console.log("[startup] TRAY_ENABLED on disk =", useAppStore.getState().config.TRAY_ENABLED);
    });

    // FIX(perf): battery-aware polling. Doubles intervals when
    // on battery to extend runtime.
    let onBattery = false;
    const refreshBatteryState = async () => {
      try {
        // @ts-ignore: experimental API
        const b: any = await navigator.getBattery?.();
        if (b) {
          onBattery = !b.charging;
        }
      } catch {
        onBattery = false;
      }
    };
    void refreshBatteryState();
    // Recheck every 30s
    const batteryTimer = window.setInterval(refreshBatteryState, 30000);

    let timerId: number | null = null;
    let currentInterval = 1000; // ms
    let lastStatSig = "";
    let idleStreak = 0;         // how many ticks with no change
    let tickCount = 0;

    const scheduleNext = () => {
      if (timerId !== null) window.clearTimeout(timerId);
      timerId = window.setTimeout(tick, currentInterval);
    };

    const tick = async () => {
      if (document.visibilityState !== "visible") {
        // Paused — don't reschedule.
        timerId = null;
        return;
      }

      const s = useAppStore.getState();
      // FIX(perf): single IPC round-trip instead of 3 separate calls.
      await s.actions.refreshAll();
      tickCount += 1;
      if (tickCount % 5 === 0) s.actions.refreshAlive();

      // Adaptive: compare signature
      const after = useAppStore.getState();
      const sig = `${after.active}|${after.total}|${after.ok}|${after.fail}`;
      if (sig === lastStatSig) {
        idleStreak += 1;
      } else {
        idleStreak = 0;
        lastStatSig = sig;
      }

      // Choose next interval based on idle streak
      let next = 1000;
      if (idleStreak >= 300) next = 30000;     // 5 min idle -> 30s
      else if (idleStreak >= 120) next = 10000; // 2 min idle -> 10s
      else if (idleStreak >= 30) next = 3000;   // 30s idle -> 3s

      // FIX(perf): battery-aware multiplier
      if (onBattery) {
        next = Math.min(next * 2, 60000);
      }

      // FIX(perf): engine stopped → stats/active are frozen, only log
      // lines can change (user actions). Floor at 2s so an idle
      // stopped app costs ~1 tiny IPC per 2s instead of 1Hz.
      if (!after.running) {
        next = Math.max(next, 2000);
      }

      if (next !== currentInterval) {
        currentInterval = next;
        console.log(`[poll] adaptive rate -> ${next}ms (idle ${idleStreak})`);
      }

      scheduleNext();
    };

    const onVis = () => {
      if (document.visibilityState === "visible") {
        // Snap back to fast polling and refresh immediately.
        currentInterval = 1000;
        idleStreak = 0;
        const s = useAppStore.getState();
        // FIX(perf): single IPC round-trip instead of 3 separate calls.
        s.actions.refreshAll();
        scheduleNext();
      } else {
        // Pause.
        if (timerId !== null) {
          window.clearTimeout(timerId);
          timerId = null;
        }
      }
    };

    document.addEventListener("visibilitychange", onVis);
    scheduleNext();

    return () => {
      document.removeEventListener("visibilitychange", onVis);
      window.clearInterval(batteryTimer);
      if (timerId !== null) window.clearTimeout(timerId);
      mounted.current = false;
    };
  }, []);

  // FIX(design): loading gate — keep simple.
  const loaded = useAppStore((s) => s.loaded);
  if (!loaded) {
    return (
      <div className="flex items-center justify-center h-screen bg-bg text-white">
        <span className="text-sm text-muted">Loading…</span>
      </div>
    );
  }

  // FIX(design): new layout — TitleBar + Sidebar + centered content + Console
  return (
    <div className="flex flex-col h-full bg-bg text-white">
      <TitleBar />
      <div className="flex flex-1 min-h-0">
        <Sidebar />
        <main className="flex-1 min-w-0 flex flex-col bg-bg">
          <div className="flex-1 min-h-0 overflow-y-auto">
            <div className="max-w-[1200px] mx-auto px-6 py-5">
              {page === 0 && <BypassPage />}
              {page === 1 && <ProxyPage />}
              {page === 2 && <ToolsPage />}
            </div>
          </div>
          <Console />
        </main>
      </div>
      <Notice />
      <ConfirmModal />
    </div>
  );
}
