import { memo, useMemo, useState } from "react";
import { useAppStore } from "../stores/appStore";
import type { SniProbeResult } from "../types";

function statusOf(r: SniProbeResult): { text: string; cls: string; rank: number } {
  if (r.tls_version) return { text: "● OK", cls: "text-success", rank: 0 };
  if (r.tls_alert != null) return { text: "● SNI rej.", cls: "text-warning", rank: 1 };
  if (r.error === "timeout") return { text: "● timeout", cls: "text-warning", rank: 1 };
  if (r.error) return { text: `● ${r.error}`, cls: "text-danger", rank: 2 };
  return { text: "● FAIL", cls: "text-danger", rank: 2 };
}

function tlsOf(r: SniProbeResult): string {
  return r.tls_version ?? (r.tls_alert != null ? `alert ${r.tls_alert}` : "");
}

// IMPROVE(U6): memoized row — probe refreshes re-render only changed rows.
const Row = memo(function Row({
  r,
  onCopy,
}: {
  r: SniProbeResult;
  onCopy: (t: string) => void;
}) {
  const st = statusOf(r);
  return (
    <tr className="border-b border-card-edge/50 hover:bg-white/[0.03] transition-colors">
      <td className="py-2 pr-4 text-white">
        {r.sni} <span className="text-faint">@ {r.endpoint}</span>
      </td>
      <td className="py-2 pr-4 text-muted tabular-nums">
        {r.latency_ms != null ? `${r.latency_ms} ms` : "—"}
      </td>
      <td className="py-2 pr-4 text-muted">{tlsOf(r) || "—"}</td>
      <td className={`py-2 pr-4 font-sans font-semibold ${st.cls}`}>{st.text}</td>
      <td className="py-2">
        <button
          onClick={() => onCopy(`${r.sni}@${r.endpoint}`)}
          title="Copy sni@endpoint"
          className="px-2 py-1 rounded text-[11px] font-sans font-semibold text-muted border border-card-edge hover:text-white hover:bg-white/5 active:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60"
        >
          ⧉
        </button>
      </td>
    </tr>
  );
});

const COLS = [
  { key: "name", label: "SNI @ Endpoint" },
  { key: "latency", label: "Latency" },
  { key: "tls", label: "TLS" },
  { key: "status", label: "Status" },
] as const;

export default function SniTable({ rows }: { rows: SniProbeResult[] }) {
  const sort = useAppStore((s) => s.sniSort);
  const setSort = useAppStore((s) => s.actions.setSniSort);
  const filter = useAppStore((s) => s.sniFilter);
  const setFilter = useAppStore((s) => s.actions.setSniFilter);
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
      ? rows.filter(
          (r) =>
            r.sni.toLowerCase().includes(needle) ||
            r.endpoint.toLowerCase().includes(needle)
        )
      : [...rows];
    if (sort.dir) {
      const mul = sort.dir === "asc" ? 1 : -1;
      out = [...out].sort((a, b) => {
        switch (sort.key) {
          case "name":
            return mul * `${a.sni}@${a.endpoint}`.localeCompare(`${b.sni}@${b.endpoint}`);
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
    return <div className="text-sm text-faint">No SNI results yet — run “Rank SNIs”.</div>;
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter SNIs…"
          title="Filter by SNI or endpoint substring"
          className="input !w-52 !py-1.5 !px-3 !text-xs"
        />
        <button
          onClick={() =>
            copy(shown.map((r) => `${r.sni}@${r.endpoint}`).join("\n"), `Copied ${shown.length} lines`)
          }
          title="Copy all visible rows as sni@endpoint, one per line"
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
              <Row key={`${r.sni}@${r.endpoint}`} r={r} onCopy={(t) => copy(t, "Copied 1 line")} />
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
