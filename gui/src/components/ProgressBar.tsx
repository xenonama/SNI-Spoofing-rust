export default function ProgressBar({ label }: { label: string }) {
  return (
    <div>
      <div className="h-2 overflow-hidden rounded-full bg-surface">
        <div className="progress-indeterminate h-full w-2/5 rounded-full bg-accent" />
      </div>
      <p className="mt-1 text-xs text-muted">{label}</p>
    </div>
  );
}
