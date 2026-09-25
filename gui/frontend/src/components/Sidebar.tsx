// FIX(layout): sidebar with attached header toggle — 60px collapsed, 220px expanded.
import { useAppStore } from "../stores/appStore";
import { Shield, Network, Wrench, ChevronLeft, ChevronRight } from "lucide-react";

const NAV = [
  { label: "DPI Bypass", icon: Shield },
  { label: "Proxy-Xray", icon: Network },
  { label: "Smart Tools", icon: Wrench },
];

export default function Sidebar() {
  const page = useAppStore((s) => s.page);
  const setPage = useAppStore((s) => s.actions.setPage);
  const active = useAppStore((s) => s.active);
  const ok = useAppStore((s) => s.ok);
  const fail = useAppStore((s) => s.fail);
  const collapsed = useAppStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useAppStore((s) => s.actions.toggleSidebar);

  return (
    <aside
      className={`shrink-0 bg-[#0F1319] border-r border-[#1A1F28] flex flex-col transition-all duration-200 ease-out ${
        collapsed ? "w-[60px]" : "w-[220px]"
      }`}
    >
      {/* FIX(layout): sidebar header with the collapse toggle.
          This button is glued to the top of the sidebar so it
          moves with it when the sidebar collapses/expands. */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center h-10 w-full text-[#8B95A7] hover:text-white hover:bg-white/5 transition-colors focus:outline-none shrink-0"
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>

      {/* separator */}
      <div className="h-px bg-[#1A1F28] mx-2 shrink-0" />

      {/* existing nav items */}
      <nav className="flex flex-col gap-1 px-2 mt-3">
        {NAV.map((item, i) => {
          const isActive = page === i;
          const Icon = item.icon;
          if (collapsed) {
            return (
              <button
                key={item.label}
                onClick={() => setPage(i)}
                className={`relative w-10 h-10 mx-auto flex items-center justify-center rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60 hover:bg-white/5 ${
                  isActive ? "bg-accent/10 text-white" : "text-muted"
                }`}
                title={item.label}
              >
                {isActive && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-full bg-accent" />}
                <Icon size={18} />
              </button>
            );
          }
          return (
            <button
              key={item.label}
              onClick={() => setPage(i)}
              className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-accent/60 hover:bg-white/5 active:bg-white/10 ${
                isActive ? "bg-accent/10 text-white" : "text-muted"
              }`}
            >
              {isActive && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-full bg-accent" />}
              <Icon size={18} className="shrink-0" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* FIX(layout): numeric stats only — duplicate live/idle line removed,
          TitleBar pill is the single status source. */}
      {/* FIX(layout): hide the entire System block when collapsed. */}
      {!collapsed && (
        <div className="px-4 mt-4">
          <div className="text-[10px] uppercase tracking-[0.15em] text-faint mb-1">System</div>
          <div className="font-mono text-[11px] text-muted tabular-nums">
            active {active} · ok {ok} · fail {fail}
          </div>
        </div>
      )}

      {/* version footer */}
      <div className="mt-auto px-4 py-3 text-[10px] text-faint shrink-0">{collapsed ? "v2" : "v2.0.1"}</div>
    </aside>
  );
}
