// FIX(layout): fixed-height container with sticky header for high-count tables.
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
    <tr className="border-b border-white/5 hover:bg-white/[0.02]">
      <td className="py-1.5 pr-3 text-white tabular-nums text-xs font-mono">{c.local_port}</td>
      <td className="py-1.5 pr-3 text-muted truncate max-w-[180px] text-xs">{c.remote}</td>
      <td className="py-1.5 pr-3 text-xs">
        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-white/5 text-muted">{c.method}</span>
      </td>
      <td className="py-1.5 text-muted tabular-nums text-xs">{fmtDur(c.uptime_secs)}</td>
    </tr>
  );
});

// IMPROVE(U5/F5): live relay sessions below LIVE METRICS on the Bypass page.
// FIX(layout): capped at 500 with max-h-280 + sticky header/footer.
export default function ActiveConnections() {
  const conns = useAppStore((s) => s.activeConns);
  const running = useAppStore((s) => s.running);

  if (!running || conns.length === 0) {
    return <div className="text-sm text-faint">No active connections</div>;
  }
  const SHOWN_CAP = 500;
  const shown = conns.slice(0, SHOWN_CAP);
  return (
    <div className="max-h-[280px] overflow-y-auto scroll-thin rounded-lg border border-white/5">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-[#12161D] z-10">
          <tr className="text-left text-[10px] uppercase tracking-wider text-faint border-b border-white/10">
            <th className="py-2 px-3 font-semibold">Port</th>
            <th className="py-2 px-3 font-semibold">Remote</th>
            <th className="py-2 px-3 font-semibold">Method</th>
            <th className="py-2 px-3 font-semibold">Uptime</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((c) => (
            <Row key={`${c.local_port}-${c.remote}`} c={c} />
          ))}
        </tbody>
      </table>
      {conns.length > shown.length && (
        <div className="sticky bottom-0 bg-[#12161D] text-center text-[10px] text-faint py-1.5 border-t border-white/10">
          {conns.length - shown.length} more…
        </div>
      )}
    </div>
  );
}
