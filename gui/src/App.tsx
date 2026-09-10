import { useEffect } from "react";
import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import Console from "./components/Console";
import BypassPage from "./pages/BypassPage";
import ProxyPage from "./pages/ProxyPage";
import ToolsPage from "./pages/ToolsPage";
import { getConfig, getProbeRes, getSniRes, getStats } from "./api";
import { useAppStore } from "./stores/appStore";

export default function App() {
  const page = useAppStore((s) => s.page);
  const initListeners = useAppStore((s) => s.initListeners);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await initListeners();
      try {
        const [cfg, snap, probes, snis] = await Promise.all([
          getConfig().catch(() => null),
          getStats().catch(() => null),
          getProbeRes().catch(() => []),
          getSniRes().catch(() => []),
        ]);
        if (cancelled) return;
        const st = useAppStore.getState();
        if (cfg) st.setConfig(cfg);
        if (snap) st.setSnapshot(snap);
        st.setProbeResults(probes ?? []);
        st.setSniResults(snis ?? []);
      } catch {
        // Backend may be unreachable in dev; pages render empty states.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [initListeners]);

  return (
    <div className="flex h-full flex-col bg-bg text-white">
      <Header />
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <main className="flex min-w-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-y-auto p-6">
            {page === "bypass" && <BypassPage />}
            {page === "proxy" && <ProxyPage />}
            {page === "tools" && <ToolsPage />}
          </div>
          <Console />
        </main>
      </div>
    </div>
  );
}
