// FIX(design): card-with-header Section — cleaner hierarchy, subtle borders.
import type { ReactNode } from "react";

export default function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-xl bg-[#12161D] border border-[#1A1F28]">
      <header className="flex items-center justify-between px-5 py-3.5 border-b border-[#1A1F28]">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.15em] text-[#5C6575]">
          {title}
        </h2>
        {action && <div>{action}</div>}
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}
