import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useAppStore } from "../stores/appStore";

type Filter = 0 | 1 | 2 | 3; // all | info | warn | error

// FIX(B10/U6): hard cap on rendered lines — the store buffer stays at 2000
// (Rust side evicts FIFO) but only the visible window renders.
const RENDER_CAP = 500;

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
    <div className={`${KIND_CLASS[lineKind(line)]} whitespace-pre-wrap break-all`}>
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
  const [height, setHeight] = useState(180);
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
    if (follow && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [shown, follow]);

  const onDragStart = (e: React.MouseEvent) => {
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
    <section className="shrink-0 border-t border-card-edge bg-surface">
      <div
        onMouseDown={onDragStart}
        className="h-1.5 cursor-ns-resize hover:bg-accent/30 active:bg-accent/50 transition-colors"
        title="Drag to resize console"
      />
      <div className="flex items-center gap-2 px-4 py-2 flex-wrap">
        <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
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
            className="px-3 py-1.5 rounded-md text-xs font-semibold text-white border border-card-edge hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
          >
            Clear
          </button>
          <button
            onClick={() => exportLogs()}
            className="px-3 py-1.5 rounded-md text-xs font-semibold text-white border border-card-edge hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
          >
            Export
          </button>
        </div>
      </div>
      <div
        ref={bodyRef}
        style={{ height }}
        className="overflow-y-auto px-4 pb-3 font-mono text-xs leading-relaxed"
      >
        {shown.slice(-RENDER_CAP).map((line, i) => (
          <LogLine key={`${i}-${line.length}`} line={line} />
        ))}
        {shown.length === 0 && (
          <div className="text-faint">No log lines match the current filter.</div>
        )}
      </div>
    </section>
  );
}
