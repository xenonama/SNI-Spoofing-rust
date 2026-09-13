import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// Fallback in case the native WebView2 default context menu is not fully
// suppressed via WebviewWindowOptions: block it everywhere except editable
// fields so copy/paste still works in <input>/<textarea>.
window.addEventListener("contextmenu", (e) => {
  const t = e.target as HTMLElement | null;
  const isEditable =
    t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
  if (!isEditable) e.preventDefault();
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
