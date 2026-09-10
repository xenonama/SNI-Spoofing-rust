import { useEffect, useMemo, useRef, useState } from "react";
import { clearLogs, exportLogs } from "../api";
import { useAppStore } from "../stores/appStore";

type Filter = "all" | "info" | "warn" | "err";

function passes(line: string, f: Filter, needle: string): boolean {
  const levelOk =
    f === "all"
      ? true
      : f === "info"
        ? !(line.includes("[WARN]") || line.includes("[ERR ]"))
        : f === "warn"
          ? line.includes("[WARN]")
          : line.includes("[ERR ]");
  if (!levelOk) return false;
  if (needle.trim() === "") return true;
  return line.toLowerCase().includes(needle.toLowerCase());
}

function lineColor(line: string): string {
  if (line.includes("[ERR ]") || line.includes("[ERROR]")) return "text-danger";
  if (line.includes("[WARN]")) return "text-warning";
  if (line.includes("[OK]")) return "text-success";
  if (line.includes("[DEBUG]") || line.includes("[TRACE]")) return "text-faint";
  return "text-white/90";
}

export default function Console() {
  const logs = useAppStore((s) => s.logs);
  const clearLogsLocal = useAppStore((s) => s.clearLogsLocal);
  const pushLog = useAppStore((s) => s.pushLog);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [follow, setFollow] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [height, setHeight] = useState(220);
  const scrollRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<number | null>(null);

  const visible = useMemo(
    () => logs.filter((l) => passes(l, filter, search)),
    [logs, filter, search],
  );

  useEffect(() => {
    if (follow && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [visible.length, follow]);

  useEffect(() => {
    const move = (e: MouseEvent) => {
      if (dragRef.current == null) return;
      const delta = dragRef.current - e.clientY;
      dragRef.current = e.clientY;
      setHeight((h) => Math.min(500, Math.max(120, h + delta)));
    };
    const up = () => {
      dragRef.current = null;
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
  }, []);

  return (
    <div className="shrink-0 border-t border-card-edge bg-surface">
      <div
        className="h-1.5 cursor-ns-resize hover:bg-accent/30"
        onMouseDown={(e) => {
          dragRef.current = e.clientY;
        }}
      />
      <div className="flex h-9 items-center gap-2 px-4">
        <button
          className="text-muted hover:text-white"
          onClick={() => setCollapsed((c) => !c)}
          title={collapsed ? "Expand console" : "Collapse console"}
        >
          {collapsed ? "▶" : "▼"}
        </button>
        <span className="text-sm font-semibold">LIVE CONSOLE ({logs.length})</span>
        <div className="ml-auto flex items-center gap-2">
          <button
            className="rounded px-2 py-1 text-xs text-muted hover:bg-white/5 hover:text-white"
            title="Export console to file"
            onClick={async () => {
              try {
                const path = await exportLogs();
                pushLog(`[OK] console exported to ${path}`);
              } catch (e) {
                pushLog(`[ERR ] export failed: ${String(e)}`);
              }
            }}
          >
            ⬇
          </button>
          <button
            className="rounded px-2 py-1 text-xs text-muted hover:bg-white/5 hover:text-white"
            title="Clear console"
            onClick={async () => {
              clearLogsLocal();
              try {
                await clearLogs();
              } catch {
                // Local clear is enough if backend is unreachable.
              }
            }}
          >
            🗑
          </button>
        </div>
      </div>
      {!collapsed && (
        <>
          <div className="flex items-center gap-2 px-4 pb-2">
            {(["all", "info", "warn", "err"] as Filter[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded-md px-2.5 py-1 text-xs capitalize transition-colors ${
                  filter === f
                    ? "bg-accent/20 font-semibold text-accent"
                    : "text-muted hover:bg-white/5 hover:text-white"
                }`}
              >
                {f === "all" ? "All" : f === "info" ? "Info" : f === "warn" ? "Warn" : "Err"}
              </button>
            ))}
            <span className="ml-2 text-xs text-muted">Search:</span>
            <input
              className="input max-w-48 py-1 text-xs"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="filter…"
            />
            <label className="ml-auto flex items-center gap-1.5 text-xs text-muted">
              <input
                type="checkbox"
                checked={follow}
                onChange={(e) => setFollow(e.target.checked)}
                className="accent-[#00B4D8]"
              />
              Follow
            </label>
          </div>
          <div
            ref={scrollRef}
            className="overflow-y-auto px-4 pb-3 font-mono text-xs leading-5"
            style={{ height }}
          >
            {visible.map((line, i) => (
              <div key={i} className={`whitespace-pre-wrap break-all ${lineColor(line)}`}>
                {line}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
