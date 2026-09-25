// FIX(tools): redesigned EndpointTable — rank, latency bar, status pill, highlight fastest.
import { memo, useMemo, useState } from "react";
import { useAppStore } from "../stores/appStore";
import type { ProbeResult } from "../types";

// FIX(tools): latency helpers for visualization
function latencyColor(ms: number | null): string {
  if (ms == null) return "bg-faint";
  if (ms < 150) return "bg-success";
  if (ms < 300) return "bg-warning";
  return "bg-danger";
}

function latencyWidth(ms: number | null, max: number): number {
  if (ms == null) return 0;
  return Math.max(20, Math.min(100, (ms / Math.max(max, 1)) * 100));
}

function statusOf(r: ProbeResult): { text: string; cls: string; rank: number } {
  if (r.tls_version) return { text: r.tls_version, cls: "text-success border-success/30 bg-success/10", rank: 0 };
  if (r.tls_alert != null) return { text: `refused`, cls: "text-warning border-warning/30 bg-warning/10", rank: 1 };
  if (r.error === "timeout") return { text: "timeout", cls: "text-warning border-warning/30 bg-warning/10", rank: 1 };
  if (r.error) return { text: r.error, cls: "text-danger border-danger/30 bg-danger/10", rank: 2 };
  return { text: "fail", cls: "text-danger border-danger/30 bg-danger/10", rank: 2 };
}

function tlsOf(r: ProbeResult): string {
  return r.tls_version ?? (r.tls_alert != null ? `alert ${r.tls_alert}` : "");
}

function StatusPill({ status }: { status: { text: string; cls: string } }) {
  return (
    <span className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border ${status.cls}`}>
      {status.text}
    </span>
  );
}

// IMPROVE(U6): memoized row — probe refreshes re-render only changed rows.
const Row = memo(function Row({
  r,
  rank,
  maxLatency,
  fastest,
  onCopy,
}: {
  r: ProbeResult;
  rank: number;
  maxLatency: number;
  fastest: boolean;
  onCopy: (t: string) => void;
}) {
  const st = statusOf(r);
  return (
    <tr className={fastest ? "bg-accent/[0.04]" : "hover:bg-white/[0.02]"}>
      <td className="py-2 pr-3 text-faint tabular-nums w-8">{rank}</td>
      <td className="py-2 pr-3 text-white truncate max-w-[200px]">{r.endpoint}</td>
      <td className="py-2 pr-3">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs tabular-nums w-12">
            {r.latency_ms != null ? `${r.latency_ms}ms` : "—"}
          </span>
          <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden min-w-[80px]">
            <div
              className={`h-full rounded-full ${latencyColor(r.latency_ms)}`}
              style={{ width: `${latencyWidth(r.latency_ms, maxLatency)}%` }}
            />
          </div>
        </div>
      </td>
      <td className="py-2 pr-3 text-muted text-xs">{tlsOf(r) || "—"}</td>
      <td className="py-2 pr-3">
        <StatusPill status={st} />
      </td>
      <td className="py-2 w-8">
        <button
          onClick={() => onCopy(r.endpoint)}
          title="Copy ip:port"
          className="px-2 py-1 rounded text-[11px] font-sans font-semibold text-muted border border-card-edge hover:text-white hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
        >
          ⧉
        </button>
      </td>
    </tr>
  );
});

const COLS = [
  { key: "name", label: "Endpoint" },
  { key: "latency", label: "Latency" },
  { key: "tls", label: "TLS" },
  { key: "status", label: "Status" },
] as const;

export default function EndpointTable({ rows }: { rows: ProbeResult[] }) {
  const sort = useAppStore((s) => s.epSort);
  const setSort = useAppStore((s) => s.actions.setEpSort);
  const filter = useAppStore((s) => s.epFilter);
  const setFilter = useAppStore((s) => s.actions.setEpFilter);
  // IMPROVE(U4): short toast confirming copies, no dependency.
  const [toast, setToast] = useState<string | null>(null);

  const copy = (text: string, msg: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setToast(msg);
    window.setTimeout(() => setToast(null), 1500);
  };

  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    let out = needle
      ? rows.filter((r) => r.endpoint.toLowerCase().includes(needle))
      : [...rows];
    if (sort.dir) {
      const mul = sort.dir === "asc" ? 1 : -1;
      out = [...out].sort((a, b) => {
        switch (sort.key) {
          case "name":
            return mul * a.endpoint.localeCompare(b.endpoint);
          case "latency":
            return mul * ((a.latency_ms ?? Infinity) - (b.latency_ms ?? Infinity));
          case "tls":
            return mul * tlsOf(a).localeCompare(tlsOf(b));
          case "status":
            return mul * (statusOf(a).rank - statusOf(b).rank);
        }
      });
    }
    return out;
  }, [rows, sort, filter]);

  if (rows.length === 0) {
    // FIX(tools): empty state moved to parent step, keep fallback for standalone use
    return <div className="text-sm text-faint">No endpoint results yet — run “Rank endpoints”.</div>;
  }
  const fastest = rows.find((r) => r.reachable)?.endpoint;
  const maxLatency = Math.max(...rows.map((r) => r.latency_ms ?? 0), 1);

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter endpoints…"
          title="Filter by substring"
          className="input !w-52 !py-1.5 !px-3 !text-xs"
        />
        {toast && <span className="text-xs text-success">{toast}</span>}
      </div>
      {/* FIX(layout): fixed-height with internal scroll */}
      <div className="max-h-[320px] overflow-y-auto scroll-thin rounded-lg border border-white/5">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-widest text-faint border-b border-card-edge">
              <th className="py-2 pr-3 w-8 font-semibold">#</th>
              {COLS.map((c) => (
                <th key={c.key} className="py-2 pr-3 font-semibold">
                  <button
                    onClick={() => setSort(c.key)}
                    title={`Sort by ${c.label} (asc → desc → none)`}
                    className="uppercase tracking-widest hover:text-white active:text-accent transition-colors focus:outline-none"
                  >
                    {c.label}
                    {sort.key === c.key && sort.dir === "asc" && " ▲"}
                    {sort.key === c.key && sort.dir === "desc" && " ▼"}
                  </button>
                </th>
              ))}
              <th className="py-2 font-semibold">Copy</th>
            </tr>
          </thead>
          <tbody className="font-mono text-[13px]">
            {shown.map((r, i) => (
              <Row key={r.endpoint} r={r} rank={i + 1} maxLatency={maxLatency} fastest={r.endpoint === fastest} onCopy={(t) => copy(t, "Copied 1 line")} />
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <div className="text-sm text-faint py-2">No rows match the current filter.</div>
        )}
      </div>
    </div>
  );
}
