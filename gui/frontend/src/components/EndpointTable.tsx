import { memo, useMemo, useState } from "react";
import { useAppStore } from "../stores/appStore";
import type { ProbeResult } from "../types";

function statusOf(r: ProbeResult): { text: string; cls: string; rank: number } {
  if (r.tls_version) return { text: "● OK", cls: "text-success", rank: 0 };
  if (r.tls_alert != null) return { text: "● SNI rej.", cls: "text-warning", rank: 1 };
  if (r.error === "timeout") return { text: "● timeout", cls: "text-warning", rank: 1 };
  if (r.error) return { text: `● ${r.error}`, cls: "text-danger", rank: 2 };
  return { text: "● FAIL", cls: "text-danger", rank: 2 };
}

function tlsOf(r: ProbeResult): string {
  return r.tls_version ?? (r.tls_alert != null ? `alert ${r.tls_alert}` : "");
}

// IMPROVE(U6): memoized row — probe refreshes re-render only changed rows.
const Row = memo(function Row({
  r,
  fastest,
  onCopy,
}: {
  r: ProbeResult;
  fastest: boolean;
  onCopy: (t: string) => void;
}) {
  const st = statusOf(r);
  return (
    <tr className="border-b border-card-edge/50 hover:bg-white/[0.03] transition-colors">
      <td className="py-2 pr-4 text-white">
        {r.endpoint}
        {fastest && (
          <span className="ml-2 text-[10px] font-sans font-bold uppercase tracking-widest text-success bg-success/10 border border-success/30 rounded px-1.5 py-0.5">
            fastest
          </span>
        )}
      </td>
      <td className="py-2 pr-4 text-muted tabular-nums">
        {r.latency_ms != null ? `${r.latency_ms} ms` : "—"}
      </td>
      <td className="py-2 pr-4 text-muted">{tlsOf(r) || "—"}</td>
      <td className={`py-2 pr-4 font-sans font-semibold ${st.cls}`}>{st.text}</td>
      <td className="py-2">
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
    return <div className="text-sm text-faint">No endpoint results yet — run “Rank endpoints”.</div>;
  }
  const fastest = rows.find((r) => r.reachable)?.endpoint;

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
        <button
          onClick={() => copy(shown.map((r) => r.endpoint).join("\n"), `Copied ${shown.length} lines`)}
          title="Copy all visible endpoints, one per line"
          className="px-2.5 py-1.5 rounded-md text-xs font-semibold text-muted border border-card-edge hover:text-white hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
        >
          Copy all
        </button>
        {toast && <span className="text-xs text-success">{toast}</span>}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-widest text-faint border-b border-card-edge">
              {COLS.map((c) => (
                <th key={c.key} className="py-2 pr-4 font-semibold">
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
            {shown.map((r) => (
              <Row key={r.endpoint} r={r} fastest={r.endpoint === fastest} onCopy={(t) => copy(t, "Copied 1 line")} />
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
