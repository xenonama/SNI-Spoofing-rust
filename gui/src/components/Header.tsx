import { useEffect, useState } from "react";
import { useAppStore } from "../stores/appStore";

function formatUptime(uptime: number): string {
  const s = Math.floor(uptime);
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const sec = String(s % 60).padStart(2, "0");
  return `${h}:${m}:${sec}`;
}

export default function Header() {
  const snapshot = useAppStore((s) => s.snapshot);
  const lastUpdatedAt = useAppStore((s) => s.lastUpdatedAt);
  const engineRunning = useAppStore((s) => s.engineRunning);
  const [ago, setAgo] = useState("Last updated —");

  useEffect(() => {
    if (lastUpdatedAt == null) {
      setAgo("Last updated —");
      return;
    }
    const update = () =>
      setAgo(`Last updated ${Math.floor((Date.now() - lastUpdatedAt) / 1000)}s ago`);
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, [lastUpdatedAt]);

  return (
    <header className="h-16 shrink-0 border-b border-card-edge bg-surface px-5">
      <div className="flex h-9 items-center gap-3">
        <span className="relative flex h-4 w-4">
          {engineRunning && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-40" />
          )}
          <span
            className={`relative inline-flex h-4 w-4 rounded-full ${
              engineRunning ? "bg-success" : "bg-faint"
            }`}
          />
        </span>
        <h1 className="text-xl font-bold tracking-tight">SNI Spoofer</h1>
        <span
          className={`rounded-lg px-3 py-1 text-[10px] font-bold uppercase tracking-wider ${
            engineRunning ? "bg-success/20 text-success" : "bg-white/5 text-muted"
          }`}
        >
          {engineRunning ? "RUNNING" : "stopped"}
        </span>
        <span className="font-mono text-[11px] text-muted">
          Uptime {snapshot ? formatUptime(snapshot.uptime) : "—"}
        </span>
        <span className="ml-auto font-mono text-[11px] text-faint">
          WebView2 · no coil whine
        </span>
      </div>
      <div className="flex h-5 items-center justify-between">
        <p className="text-xs text-muted">DPI bypass · failover · scoreboard</p>
        <p className="text-[11px] text-muted">{ago}</p>
      </div>
    </header>
  );
}
