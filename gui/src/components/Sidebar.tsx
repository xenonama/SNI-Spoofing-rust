import { useAppStore } from "../stores/appStore";
import type { Page } from "../types";

const NAV: { id: Page; icon: string; label: string }[] = [
  { id: "bypass", icon: "◉", label: "DPI Bypass" },
  { id: "proxy", icon: "⇄", label: "Proxy-Xray" },
  { id: "tools", icon: "⚡", label: "Smart Tools" },
];

export default function Sidebar() {
  const page = useAppStore((s) => s.page);
  const setPage = useAppStore((s) => s.setPage);
  const snapshot = useAppStore((s) => s.snapshot);
  const engineRunning = useAppStore((s) => s.engineRunning);

  const active = snapshot?.active ?? 0;
  const ok = snapshot?.success ?? 0;
  const fail = snapshot?.failed ?? 0;

  return (
    <aside className="flex w-[200px] shrink-0 flex-col border-r border-card-edge bg-surface">
      <p className="px-4 pb-1 pt-4 text-[10px] font-semibold uppercase tracking-[0.18em] text-faint">
        Navigate
      </p>
      <nav className="flex flex-col">
        {NAV.map((item) => {
          const selected = page === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`relative flex h-12 items-center gap-2 px-4 text-left text-sm transition-all duration-150 ${
                selected
                  ? "bg-accent/10 font-semibold text-white"
                  : "text-muted hover:bg-white/5 hover:text-white"
              } focus:outline-none focus:ring-2 focus:ring-inset focus:ring-accent/50`}
            >
              {selected && (
                <span className="absolute left-0 top-0 h-full w-[3px] bg-accent" />
              )}
              <span className="w-5 text-center text-lg leading-none">
                {item.icon}
              </span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
      <div className="mt-6 px-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-faint">
          System
        </p>
        <p className="mt-2 text-xs text-muted">
          Active: {active} · OK: {ok} / Fail: {fail}
        </p>
        <p className={`mt-1 text-xs ${engineRunning ? "text-success" : "text-faint"}`}>
          {engineRunning ? "● live" : "○ idle"}
        </p>
      </div>
      <p className="mt-auto px-4 pb-3 text-[10px] text-faint">v2.0</p>
    </aside>
  );
}
