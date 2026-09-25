// FIX(design): collapsible bottom panel — header always visible, body toggles 0↔200px.
import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useAppStore } from "../stores/appStore";
import { ChevronDown, ChevronUp } from "lucide-react";

type Filter = 0 | 1 | 2 | 3; // all | info | warn | error

// FIX(B10/U6): hard cap on rendered lines — the store buffer stays at 2000
// FIX(perf): bumped to 2000 — contentVisibility handles off-screen cost.
const RENDER_CAP = 2000;

function lineKind(line: string): "info" | "warn" | "err" | "ok" {
  if (line.includes("[ERR ]")) return "err";
  if (line.includes("[WARN]")) return "warn";
  if (line.includes("[OK]")) return "ok";
  return "info";
}

const KIND_CLASS: Record<string, string> = {
  info: "text-muted",
  warn: "text-warning",
  err: "text-danger",
  ok: "text-success",
};

// IMPROVE(U6): memoized line — re-renders are O(changed), not O(all).
const LogLine = memo(function LogLine({ line }: { line: string }) {
  return (
    <div
      className={`${KIND_CLASS[lineKind(line)]} whitespace-pre-wrap break-all`}
      style={{
        // FIX(perf): let the browser skip layout/paint for
        // lines outside the viewport. Works in WebView2
        // (Chromium). Zero JS overhead.
        contentVisibility: "auto",
        containIntrinsicSize: "auto 20px",
      } as React.CSSProperties}
    >
      {line}
    </div>
  );
});

export default function Console() {
  const logs = useAppStore((s) => s.logs);
  const clearLogs = useAppStore((s) => s.actions.clearLogs);
  const exportLogs = useAppStore((s) => s.actions.exportLogs);
  const [filter, setFilter] = useState<Filter>(0);
  const [search, setSearch] = useState("");
  const [follow, setFollow] = useState(true);
  const [collapsed, setCollapsed] = useState(true);
  const [height, setHeight] = useState(200);
  const bodyRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ startY: number; startH: number } | null>(null);

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return logs.filter((line) => {
      const kind = lineKind(line);
      if (filter === 1 && kind !== "info" && kind !== "ok") return false;
      if (filter === 2 && kind !== "warn") return false;
      if (filter === 3 && kind !== "err") return false;
      if (needle && !line.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [logs, filter, search]);

  useEffect(() => {
    if (follow && bodyRef.current && !collapsed) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [shown, follow, collapsed]);

  const onDragStart = (e: React.MouseEvent) => {
    if (collapsed) return;
    dragRef.current = { startY: e.clientY, startH: height };
    const onMove = (ev: MouseEvent) => {
      if (!dragRef.current) return;
      const dh = dragRef.current.startY - ev.clientY;
      setHeight(Math.min(420, Math.max(90, dragRef.current.startH + dh)));
    };
    const onUp = () => {
      dragRef.current = null;
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const filters: { id: Filter; label: string }[] = [
    { id: 0, label: "All" },
    { id: 1, label: "Info" },
    { id: 2, label: "Warn" },
    { id: 3, label: "Error" },
  ];

  return (
    <section className="shrink-0 border-t border-[#1A1F28] bg-[#0F1319]">
      <div
        onMouseDown={onDragStart}
        className="h-1.5 cursor-ns-resize hover:bg-accent/30 active:bg-accent/50 transition-colors"
        title="Drag to resize console"
      />
      {/* FIX(design): 32px header with collapse toggle */}
      <div className="flex items-center gap-2 px-4 h-8">
        {/* FIX(ui): no chevron prefix here — right-side button is the single toggle. */}
        <span className="text-[11px] font-semibold uppercase tracking-[0.15em] text-[#5C6575]">
          Live console ({shown.length})
        </span>
        <div className="flex gap-1 ml-2">
          {filters.map((f) => (
            <button
              key={f.id}
              onClick={() => setFilter(f.id)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60 hover:bg-white/10 active:bg-white/15 ${
                filter === f.id ? "bg-accent/15 text-white" : "text-muted"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search…"
          className="input !w-40 !py-1 !px-2.5 !text-xs ml-1"
        />
        <div className="ml-auto flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-muted cursor-pointer select-none hover:text-white">
            <input
              type="checkbox"
              checked={follow}
              onChange={(e) => setFollow(e.target.checked)}
              className="accent-[#00B4D8]"
            />
            Follow
          </label>
          <button
            onClick={() => clearLogs()}
            className="px-3 py-1.5 rounded-md text-xs font-semibold text-white border border-white/10 hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
          >
            Clear
          </button>
          <button
            onClick={() => exportLogs()}
            className="px-3 py-1.5 rounded-md text-xs font-semibold text-white border border-white/10 hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
          >
            Export
          </button>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="w-7 h-7 flex items-center justify-center rounded-md hover:bg-white/5 text-muted hover:text-white transition-colors focus:outline-none"
            title={collapsed ? "Expand console" : "Collapse console"}
          >
            {collapsed ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>
      <div
        ref={bodyRef}
        style={{ height: collapsed ? 0 : height }}
        className="overflow-y-auto px-4 pb-3 font-mono text-xs leading-relaxed transition-all duration-200"
      >
        {!collapsed &&
          shown.slice(-RENDER_CAP).map((line, i) => (
            <LogLine key={`${i}-${line.length}`} line={line} />
          ))}
        {!collapsed && shown.length === 0 && (
          <div className="text-faint">No log lines match the current filter.</div>
        )}
      </div>
    </section>
  );
}
