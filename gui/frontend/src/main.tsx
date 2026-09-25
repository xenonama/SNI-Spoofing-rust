import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// FIX(ui): block the WebView2 default context menu everywhere,
// including inputs and textareas. Users can still use Ctrl+C/V/X/A
// for copy/paste/select-all; the native right-click menu (Inspect,
// Reload, Back, Save as, ...) is not wanted in this app.
window.addEventListener(
  "contextmenu",
  (e) => {
    e.preventDefault();
    return false;
  },
  { capture: true }
);

// FIX(ui): some WebView2 builds trigger the menu on mousedown+contextmenu.
// Consume the event in capture phase so nothing downstream sees it.
document.addEventListener(
  "contextmenu",
  (e) => { e.stopImmediatePropagation(); e.preventDefault(); },
  { capture: true }
);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
