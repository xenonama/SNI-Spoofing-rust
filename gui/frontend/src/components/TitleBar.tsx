// FIX(layout): title bar without hamburger — toggle lives in the sidebar header.
// FIX(#1): manual drag + double-click title bar (no WebkitAppRegion CSS).
import { useEffect, useRef, useState } from "react";
import { Minus, Square, X, Copy } from "lucide-react";
import * as api from "../api";
import appIcon from "../assets/app.png";
import { useAppStore } from "../stores/appStore";

export default function TitleBar() {
  const [maximised, setMaximised] = useState(false);
  const lastClickRef = useRef<number>(0);
  const running = useAppStore((s) => s.running);

  // FIX(#1): manual drag + double-click detection.
  const onMouseDown = async (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    const target = e.target as HTMLElement;
    if (target.closest("[data-nodrag]")) return;

    const now = Date.now();
    const delta = now - lastClickRef.current;
    lastClickRef.current = now;

    if (delta < 300) {
      lastClickRef.current = 0;
      try {
        await api.windowToggleMaximise();
      } catch (err) {
        console.error("[titlebar] toggle maximise failed:", err);
      }
      return;
    }

    try {
      await api.windowStartDrag();
    } catch (err) {
      console.error("[titlebar] start drag failed:", err);
    }
  };

  // FIX(#1): poll maximize state so the button icon reflects reality.
  // FIX(perf): 2s cadence (was 500ms) + skip while hidden — the icon
  // can only change via user action, so a 2Hz Wails IPC forever was
  // pure idle waste. State is also refreshed right after the toggle
  // click (see onMax), so the slower cadence is not noticeable.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (!alive) return;
      if (document.visibilityState !== "visible") return;
      try {
        const m = await api.windowIsMaximised();
        setMaximised((prev) => {
          const next = !!m;
          return prev === next ? prev : next;
        });
      } catch {
        // ignore
      }
    };
    const t = window.setInterval(tick, 2000);
    tick();
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  // FIX(titlebar): confirm the bindings exist so a missing binding
  // shows up in the console immediately.
  useEffect(() => {
    console.log("[titlebar] minimise =", typeof api.windowMinimise);
    console.log("[titlebar] maximise =", typeof api.windowToggleMaximise);
    console.log("[titlebar] close    =", typeof api.windowClose);
  }, []);

  const onMin = () => {
    api.windowMinimise().catch((e) => console.error("[titlebar] minimise failed:", e));
  };
  const onMax = () => {
    // FIX(perf): refresh the icon immediately after toggling so the
    // 2s poller cadence above never shows a stale icon.
    api.windowToggleMaximise()
      .then(() => api.windowIsMaximised().then((m) => setMaximised(!!m)).catch(() => {}))
      .catch((e) => console.error("[titlebar] maximise failed:", e));
  };
  const onClose = () => {
    api.windowClose().catch((e) => console.error("[titlebar] close failed:", e));
  };

  return (
    // FIX(layout): 40px height, bg #0F1319, status pill, no hamburger
    <div
      onMouseDown={onMouseDown}
      className="flex items-center justify-between h-10 bg-[#0F1319] border-b border-[#1A1F28] select-none shrink-0 cursor-default"
    >
      {/* Left: logo + app name (draggable area) */}
      <div className="flex items-center gap-2 px-3 h-full">
        <img src={appIcon} alt="" className="w-[18px] h-[18px] rounded-sm" draggable={false} />
        <span className="text-[13px] font-medium text-white tracking-tight">SNI Spoofer</span>
      </div>

      {/* Right: status pill + window controls */}
      <div className="flex items-center h-full">
        {/* FIX(layout): single status pill — tinted background */}
        <div
          className={`hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium mr-2 ${
            running ? "bg-success/10 text-success" : "bg-white/5 text-muted"
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${running ? "bg-success" : "bg-[#5C6575]"}`} />
          {running ? "running" : "idle"}
        </div>
        <button
          data-nodrag
          onClick={onMin}
          className="h-10 w-10 flex items-center justify-center text-muted hover:bg-white/5 hover:text-white transition-colors focus:outline-none"
          title="Minimize"
        >
          <Minus size={14} />
        </button>
        <button
          data-nodrag
          onClick={onMax}
          className="h-10 w-10 flex items-center justify-center text-muted hover:bg-white/5 hover:text-white transition-colors focus:outline-none"
          title={maximised ? "Restore" : "Maximize"}
        >
          {maximised ? <Copy size={12} /> : <Square size={12} />}
        </button>
        <button
          data-nodrag
          onClick={onClose}
          className="h-10 w-10 flex items-center justify-center text-muted hover:bg-[#EF476F] hover:text-white transition-colors focus:outline-none"
          title="Close"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
