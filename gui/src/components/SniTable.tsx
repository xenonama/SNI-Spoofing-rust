import type { SniProbeResultDto } from "../types";
import { statusOf } from "./EndpointTable";

export default function SniTable({ rows }: { rows: SniProbeResultDto[] }) {
  if (rows.length === 0) {
    return <p className="py-4 text-center text-sm text-faint">Press Rank SNIs</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wider text-muted">
            <th className="px-2 py-2 font-medium">SNI</th>
            <th className="px-2 py-2 font-medium">Latency</th>
            <th className="px-2 py-2 font-medium">TLS</th>
            <th className="px-2 py-2 font-medium">Status</th>
            <th className="px-2 py-2 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const st = statusOf(r);
            const tip =
              r.tls_version ?? r.tls_alert_name ?? r.error ?? r.endpoint;
            const full = `${r.sni} @ ${r.endpoint}`;
            return (
              <tr
                key={`${r.sni}@${r.endpoint}`}
                className="h-10 border-t border-card-edge odd:bg-white/[0.02] hover:bg-white/[0.04]"
              >
                <td className="px-2 py-2 font-mono text-xs" title={full}>
                  {full}
                </td>
                <td className="px-2 py-2 font-mono text-xs">
                  {r.latency_ms != null ? `${r.latency_ms} ms` : "—"}
                </td>
                <td className="px-2 py-2 font-mono text-xs">
                  {r.tls_version ?? (r.tls_alert != null ? `alert ${r.tls_alert}` : "—")}
                </td>
                <td className="px-2 py-2 text-xs" title={tip}>
                  <span className={`font-semibold ${st.cls}`}>● {st.text}</span>
                </td>
                <td className="px-2 py-2">
                  <button
                    className="rounded px-1.5 py-0.5 text-xs text-muted hover:bg-white/10 hover:text-white"
                    title="Copy SNI@endpoint"
                    onClick={() =>
                      navigator.clipboard.writeText(`${r.sni}@${r.endpoint}`)
                    }
                  >
                    ⧉
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
