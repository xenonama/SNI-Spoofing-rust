import { useEffect, useRef } from "react";
import { useConfirmStore } from "../stores/confirmStore";

export default function ConfirmModal() {
  const open = useConfirmStore((s) => s.open);
  const title = useConfirmStore((s) => s.title);
  const message = useConfirmStore((s) => s.message);
  const confirmLabel = useConfirmStore((s) => s.confirmLabel);
  const cancelLabel = useConfirmStore((s) => s.cancelLabel);
  const danger = useConfirmStore((s) => s.danger);
  const onlyConfirm = useConfirmStore((s) => s.onlyConfirm);
  const resolve = useConfirmStore((s) => s.resolve);
  const cancel = useConfirmStore((s) => s.cancel);

  const cancelRef = useRef<HTMLButtonElement>(null);
  const okRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    // Focus starts on Cancel for safety (or OK in alert mode).
    (onlyConfirm ? okRef : cancelRef).current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        cancel();
      } else if (e.key === "Enter") {
        const el = document.activeElement as HTMLElement | null;
        // Let native button activation handle Enter when focus is on a
        // button; otherwise Enter confirms.
        if (el && el.tagName === "BUTTON") return;
        e.preventDefault();
        resolve(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onlyConfirm, cancel, resolve]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.6)" }}
      onClick={() => cancel()}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="w-full max-w-md bg-card border border-card-edge rounded-xl p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold text-white">{title}</h2>
        <p className="mt-2 text-sm text-muted whitespace-pre-wrap">{message}</p>
        <div className="mt-5 flex justify-end gap-3">
          {!onlyConfirm && (
            <button ref={cancelRef} className="btn-ghost" onClick={() => cancel()}>
              {cancelLabel}
            </button>
          )}
          <button
            ref={okRef}
            className={danger ? "btn-danger" : "btn-primary"}
            onClick={() => resolve(true)}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
