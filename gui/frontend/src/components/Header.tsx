import { useEffect, useState } from "react";
import { useAppStore, formatUptime } from "../stores/appStore";

export default function Header() {
  const running = useAppStore((s) => s.running);
  // FIX(B1): uptime derives ONLY from engineStartedAt (null = stopped).
  const engineStartedAt = useAppStore((s) => s.engineStartedAt);
  const lastUpdated = useAppStore((s) => s.lastUpdated);
  const admin = useAppStore((s) => s.admin);
  // FIX(B7): measured poll rate instead of a hardcoded badge.
  const pollHz = useAppStore((s) => s.pollHz);
  const [now, setNow] = useState(() => Date.now());

  // FIX(B1): the 1Hz display tick advances only while an engine start is
  // anchored; otherwise the display is frozen at "--:--:--".
  useEffect(() => {
    if (engineStartedAt == null) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [engineStartedAt]);

  const uptime =
    engineStartedAt != null ? formatUptime((now - engineStartedAt) / 1000) : "--:--:--";

  return (
    <header className="h-16 shrink-0 flex items-center justify-between px-6 bg-surface border-b border-card-edge relative">
      {/* gradient bottom border */}
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-accent/60 to-transparent" />
      <div className="flex items-center gap-3 min-w-0">
        <span
          className={`w-2.5 h-2.5 rounded-full shrink-0 ${
            running ? "bg-success pulse-dot" : "bg-faint"
          }`}
        />
        <h1 className="text-xl font-bold tracking-tight">SNI Spoofer</h1>
        <span
          className={`text-[11px] font-semibold uppercase tracking-widest px-2.5 py-1 rounded-full border ${
            running
              ? "text-success border-success/40 bg-success/10"
              : "text-muted border-card-edge bg-white/[0.03]"
          }`}
        >
          {running ? "running" : "idle"}
        </span>
        {admin === false && (
          <span className="text-[11px] font-semibold uppercase tracking-widest px-2.5 py-1 rounded-full border text-warning border-warning/40 bg-warning/10">
            not admin
          </span>
        )}
      </div>
      <div className="font-mono text-sm text-muted tabular-nums hidden sm:block">
        {uptime}
      </div>
      <div className="flex items-center gap-4">
        <span className="text-xs text-faint hidden md:block">{lastUpdated}</span>
        <span
          className="font-mono text-xs text-faint tabular-nums"
          title="Measured backend poll rate"
        >
          {pollHz > 0 ? `${pollHz.toFixed(1)} Hz` : "—"}
        </span>
      </div>
    </header>
  );
}
