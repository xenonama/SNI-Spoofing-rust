// FIX(design): simplified StatCard — mono value, tighter card, no flash animation.
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

export default memo(function StatCard({ label, value, extra, accent = "muted" }: Props) {
  return (
    <div className="rounded-lg bg-[#0F1319] border border-[#1A1F28] px-4 py-3">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-[#5C6575] mb-1">
        {label}
      </div>
      <div className={`text-2xl font-mono font-semibold tabular-nums truncate ${ACCENT_CLASS[accent]}`}>
        {value}
      </div>
      {extra && <div className="text-[10px] text-[#5C6575] mt-0.5 truncate">{extra}</div>}
    </div>
  );
});
