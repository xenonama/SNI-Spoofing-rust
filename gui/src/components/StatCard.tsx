import { useEffect, useRef, useState } from "react";

type Props = {
  label: string;
  value: string;
  extra?: string;
  flashKey?: string | number;
};

export default function StatCard({ label, value, extra, flashKey }: Props) {
  const [flash, setFlash] = useState(false);
  const first = useRef(true);

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    setFlash(true);
    const t = setTimeout(() => setFlash(false), 400);
    return () => clearTimeout(t);
  }, [flashKey]);

  return (
    <div
      className={`min-h-[76px] flex-1 rounded-lg border border-card-edge bg-surface p-3 ${
        flash ? "stat-flash" : ""
      }`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted">
        {label}
      </p>
      <p className="kpi-value mt-1 truncate" title={value}>
        {value}
      </p>
      {extra != null && extra !== "" && (
        <p className="mt-0.5 truncate text-xs text-muted" title={extra}>
          {extra}
        </p>
      )}
    </div>
  );
}
