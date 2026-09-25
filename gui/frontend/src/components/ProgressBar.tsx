// FIX(tools): more informative ProgressBar with label slot.
export default function ProgressBar({
  done,
  total,
  label,
}: {
  done: number;
  total: number;
  label?: string;
}) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
        {total > 0 ? (
          <div
            className="h-full rounded-full bg-accent transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        ) : (
          <div className="h-full w-2/5 rounded-full bg-accent progress-indeterminate" />
        )}
      </div>
      <span className="text-[11px] font-mono tabular-nums text-faint min-w-[60px] text-right">
        {label ?? (total > 0 ? `${done}/${total}` : "…")}
      </span>
    </div>
  );
}
