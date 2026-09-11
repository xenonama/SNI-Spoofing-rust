export default function ProgressBar({ done, total }: { done: number; total: number }) {
  if (total > 0) {
    const pct = Math.min(100, Math.round((done / total) * 100));
    return (
      <div className="h-1.5 rounded-full bg-surface border border-card-edge overflow-hidden">
        <div
          className="h-full rounded-full bg-accent transition-all duration-300"
          style={{ width: `${pct}%` }}
        />
      </div>
    );
  }
  return (
    <div className="h-1.5 rounded-full bg-surface border border-card-edge overflow-hidden">
      <div className="h-full w-2/5 rounded-full bg-accent progress-indeterminate" />
    </div>
  );
}
