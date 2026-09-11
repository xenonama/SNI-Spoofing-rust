import { useEffect, useRef } from "react";
import { useAppStore } from "./stores/appStore";
import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import Console from "./components/Console";
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

  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    const st = useAppStore.getState();
    st.actions.load();
    let ticks = 0;
    const interval = setInterval(() => {
      const s = useAppStore.getState();
      // FIX(B5): single interval cleared on unmount; no listener leaks
      // (api.ts event helpers return unsubscribe functions).
      s.actions.refreshStats();
      s.actions.refreshLogs();
      s.actions.refreshActive();
      // FIX(A3): liveness resync at ~1/5 cadence (cheap boolean FFI call).
      ticks += 1;
      if (ticks % 5 === 0) s.actions.refreshAlive();
    }, 1000);
    return () => {
      clearInterval(interval);
      mounted.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="flex flex-col h-full bg-bg">
      <Header />
      <div className="flex flex-1 min-h-0">
        <Sidebar />
        <main className="flex-1 min-w-0 flex flex-col">
          <div className="flex-1 min-h-0 overflow-y-auto p-6">
            {page === 0 && <BypassPage />}
            {page === 1 && <ProxyPage />}
            {page === 2 && <ToolsPage />}
          </div>
          <Console />
        </main>
      </div>
      <Notice />
    </div>
  );
}
