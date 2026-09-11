import { memo } from "react";
import { useAppStore } from "../stores/appStore";
import type { ActiveConn } from "../types";

function fmtDur(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// IMPROVE(U5/U6): memoized row for the live relay-session table.
const Row = memo(function Row({ c }: { c: ActiveConn }) {
  return (
    <tr className="border-b border-card-edge/50 hover:bg-white/[0.03] transition-colors">
      <td className="py-2 pr-4 text-white tabular-nums">{c.local_port}</td>
      <td className="py-2 pr-4 text-muted">{c.remote}</td>
      <td className="py-2 pr-4 text-muted">{c.method}</td>
      <td className="py-2 text-muted tabular-nums">{fmtDur(c.uptime_secs)}</td>
    </tr>
  );
});

// IMPROVE(U5/F5): live relay sessions below LIVE METRICS on the Bypass page.
// Rows capped at 50 with a "… and N more" footer.
export default function ActiveConnections() {
  const conns = useAppStore((s) => s.activeConns);
  const running = useAppStore((s) => s.running);

  if (!running || conns.length === 0) {
    return <div className="text-sm text-faint">No active connections</div>;
  }
  const shown = conns.slice(0, 50);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-[11px] uppercase tracking-widest text-faint border-b border-card-edge">
            <th className="py-2 pr-4 font-semibold">Local port</th>
            <th className="py-2 pr-4 font-semibold">Remote endpoint</th>
            <th className="py-2 pr-4 font-semibold">Method</th>
            <th className="py-2 font-semibold">Uptime</th>
          </tr>
        </thead>
        <tbody className="font-mono text-[13px]">
          {shown.map((c) => (
            <Row key={`${c.local_port}-${c.remote}`} c={c} />
          ))}
        </tbody>
      </table>
      {conns.length > shown.length && (
        <div className="text-xs text-faint py-2">… and {conns.length - shown.length} more</div>
      )}
    </div>
  );
}
