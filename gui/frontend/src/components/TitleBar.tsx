// FIX(#1): manual drag + double-click title bar (no WebkitAppRegion CSS).
// WebView2 swallows mouse events under WebkitAppRegion:'drag', so the
// bar drives the window through Wails bindings instead:
//   - single mousedown starts a native drag via windowStartDrag
//   - two mousedowns within 300ms toggle maximize/restore
//   - elements marked [data-nodrag] never start a drag.
import { useEffect, useRef, useState } from "react";
import { Minus, Square, X, Copy } from "lucide-react";
import * as api from "../api";
import appIcon from "../assets/app.png";

export default function TitleBar() {
  const [maximised, setMaximised] = useState(false);
  const lastClickRef = useRef<number>(0);

  // FIX(#1): manual drag + double-click detection.
  // WebView2 swallows mouse events under WebkitAppRegion:'drag',
  // so we no longer use that CSS. Instead:
  //   - single click on the bar starts a native window drag
  //   - two clicks within 300ms toggles maximize/restore
  //   - clicks on [data-nodrag] elements are ignored
  const onMouseDown = async (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    const target = e.target as HTMLElement;
    if (target.closest("[data-nodrag]")) return;

    const now = Date.now();
    const delta = now - lastClickRef.current;
    lastClickRef.current = now;

    if (delta < 300) {
      // double click
      lastClickRef.current = 0;
      try {
        await api.windowToggleMaximise();
      } catch (err) {
        console.error("[titlebar] toggle maximise failed:", err);
      }
      return;
    }

    // single click → start drag
    try {
      await api.windowStartDrag();
    } catch (err) {
      console.error("[titlebar] start drag failed:", err);
    }
  };

  // FIX(#1): poll maximize state so the button icon reflects reality.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (!alive) return;
      try {
        const m = await api.windowIsMaximised();
        setMaximised(!!m);
      } catch {
        // ignore — button still works for min/close
      }
    };
    const t = window.setInterval(tick, 500);
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
    api.windowToggleMaximise().catch((e) => console.error("[titlebar] maximise failed:", e));
  };
  const onClose = () => {
    api.windowClose().catch((e) => console.error("[titlebar] close failed:", e));
  };

  return (
    <div
      onMouseDown={onMouseDown}
      className="flex items-center justify-between h-9 bg-[#181C24] border-b border-[#252B36] select-none shrink-0 cursor-default"
    >
      {/* Left: logo + app name (draggable area) */}
      <div className="flex items-center gap-2 px-3 h-full">
        <img src={appIcon} alt="" className="w-5 h-5" draggable={false} />
        <span className="text-xs font-semibold text-[#8B95A7] tracking-wide">
          SNI Spoofer
        </span>
      </div>

      {/* Right: window controls — data-nodrag so they never start a drag */}
      <div className="flex items-center h-full">
        <button
          data-nodrag
          onClick={onMin}
          className="h-full w-11 flex items-center justify-center text-[#8B95A7] hover:bg-white/5 hover:text-white transition-colors focus:outline-none"
          title="Minimize"
        >
          <Minus size={14} />
        </button>
        <button
          data-nodrag
          onClick={onMax}
          className="h-full w-11 flex items-center justify-center text-[#8B95A7] hover:bg-white/5 hover:text-white transition-colors focus:outline-none"
          title={maximised ? "Restore" : "Maximize"}
        >
          {maximised ? <Copy size={12} /> : <Square size={12} />}
        </button>
        <button
          data-nodrag
          onClick={onClose}
          className="h-full w-11 flex items-center justify-center text-[#8B95A7] hover:bg-[#EF476F] hover:text-white transition-colors focus:outline-none"
          title="Close"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
