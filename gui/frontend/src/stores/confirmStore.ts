import { create } from "zustand";

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  /** Single OK button (alert replacement) instead of Cancel + Confirm. */
  onlyConfirm?: boolean;
}

interface ConfirmState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
  danger: boolean;
  onlyConfirm: boolean;
  resolver: ((value: boolean) => void) | null;
  /** Open the modal and await the user's choice (true = confirm/OK). */
  confirm: (opts: ConfirmOptions) => Promise<boolean>;
  resolve: (value: boolean) => void;
  cancel: () => void;
}

export const useConfirmStore = create<ConfirmState>((set, get) => ({
  open: false,
  title: "",
  message: "",
  confirmLabel: "Confirm",
  cancelLabel: "Cancel",
  danger: false,
  onlyConfirm: false,
  resolver: null,
  confirm: (opts) => {
    // If a dialog is already open, dismiss it as cancelled before opening
    // the new one so callers never hang on a stale promise.
    const prev = get().resolver;
    if (get().open && prev) prev(false);
    return new Promise<boolean>((resolve) => {
      set({
        open: true,
        title: opts.title,
        message: opts.message,
        confirmLabel: opts.onlyConfirm ? (opts.confirmLabel ?? "OK") : (opts.confirmLabel ?? "Confirm"),
        cancelLabel: opts.cancelLabel ?? "Cancel",
        danger: opts.danger ?? false,
        onlyConfirm: opts.onlyConfirm ?? false,
        resolver: resolve,
      });
    });
  },
  resolve: (value) => {
    const r = get().resolver;
    if (r) r(value);
    set({ open: false, resolver: null });
  },
  cancel: () => {
    const r = get().resolver;
    if (r) r(false);
    set({ open: false, resolver: null });
  },
}));
