import type { ReactNode } from "react";

export default function Section({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <section className="card">
      <h3 className="card-title">{title}</h3>
      {subtitle != null && <p className="mb-3 -mt-2 text-xs text-muted">{subtitle}</p>}
      {children}
    </section>
  );
}
