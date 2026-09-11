import { useAppStore } from "../stores/appStore";

const NAV = [
  { label: "DPI Bypass", icon: "◈" },
  { label: "Proxy-Xray", icon: "⬢" },
  { label: "Smart Tools", icon: "⚒" },
];

export default function Sidebar() {
  const page = useAppStore((s) => s.page);
  const setPage = useAppStore((s) => s.actions.setPage);
  const running = useAppStore((s) => s.running);
  const active = useAppStore((s) => s.active);
  const ok = useAppStore((s) => s.ok);
  const fail = useAppStore((s) => s.fail);

  return (
    <aside className="w-[200px] shrink-0 bg-surface border-r border-card-edge flex flex-col py-4">
      <div className="px-5 mb-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-faint">
        Navigate
      </div>
      <nav className="flex flex-col gap-1 px-2">
        {NAV.map((item, i) => {
          const isActive = page === i;
          return (
            <button
              key={item.label}
              onClick={() => setPage(i)}
              className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-accent/60 hover:bg-white/5 active:bg-white/10 ${
                isActive ? "bg-accent/10 text-white" : "text-muted"
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-full bg-accent" />
              )}
              <span className="text-base leading-none w-5 text-center">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="px-5 mt-6 mb-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-faint">
        System
      </div>
      <div className="px-5 text-sm space-y-1.5">
        <div className={running ? "text-success" : "text-faint"}>
          {running ? "● live" : "○ idle"}
        </div>
        <div className="font-mono text-xs text-muted tabular-nums">
          active {active} · ok {ok} · fail {fail}
        </div>
      </div>

      <div className="mt-auto px-5 text-xs text-faint">v2.0</div>
    </aside>
  );
}
