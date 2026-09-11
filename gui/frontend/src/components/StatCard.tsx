import { memo } from "react";

interface Props {
  label: string;
  value: string;
  extra?: string;
  accent?: "accent" | "success" | "danger" | "warning" | "muted";
  flashKey?: string | number;
}

const ACCENT_CLASS: Record<string, string> = {
  accent: "text-accent",
  success: "text-success",
  danger: "text-danger",
  warning: "text-warning",
  muted: "text-white",
};

// IMPROVE(U6): memoized — the 1Hz stats tick re-renders only changed cards.
export default memo(function StatCard({ label, value, extra, accent = "muted", flashKey }: Props) {
  return (
    <div className="card !p-4 min-h-[96px] flex flex-col justify-between">
      <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted">
        {label}
      </div>
      <div key={String(flashKey ?? value)} className={`kpi-value flash ${ACCENT_CLASS[accent]} truncate`}>
        {value}
      </div>
      {extra && <div className="text-xs text-faint truncate">{extra}</div>}
    </div>
  );
});
