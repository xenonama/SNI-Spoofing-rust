import type { ProbeResultDto } from "../types";

export function statusOf(r: {
  tls_version: string | null;
  tls_alert: number | null;
  error: string | null;
}): { text: string; cls: string } {
  if (r.tls_version) return { text: "OK", cls: "text-success" };
  if (r.tls_alert != null) return { text: "SNI rej.", cls: "text-warning" };
  if (r.error === "timeout") return { text: "timeout", cls: "text-faint" };
  if (r.error) return { text: r.error, cls: "text-danger" };
  return { text: "FAIL", cls: "text-danger" };
}

export default function EndpointTable({
  rows,
  fastest,
  emptyHint,
}: {
  rows: ProbeResultDto[];
  fastest?: string | null;
  emptyHint: string;
}) {
  if (rows.length === 0) {
    return <p className="py-4 text-center text-sm text-faint">{emptyHint}</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wider text-muted">
            <th className="px-2 py-2 font-medium">Endpoint</th>
            <th className="px-2 py-2 font-medium">Latency</th>
            <th className="px-2 py-2 font-medium">TLS</th>
            <th className="px-2 py-2 font-medium">Status</th>
            <th className="px-2 py-2 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const st = statusOf(r);
            const isFastest = fastest != null && fastest === r.endpoint;
            const tip = r.error ?? r.tls_version ?? r.tls_alert_name ?? r.endpoint;
            return (
              <tr
                key={r.endpoint}
                className="h-10 border-t border-card-edge odd:bg-white/[0.02] hover:bg-white/[0.04]"
              >
                <td
                  className={`px-2 py-2 font-mono text-xs ${isFastest ? "font-bold text-success" : ""}`}
                  title={r.endpoint}
                >
                  {r.endpoint}
                  {isFastest && "  [fastest]"}
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
                    title="Copy endpoint"
                    onClick={() => navigator.clipboard.writeText(r.endpoint)}
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
