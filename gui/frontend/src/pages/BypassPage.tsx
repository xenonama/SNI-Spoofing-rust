// FIX(design): redesigned BypassPage — card-with-header Sections, grouped config subsections.
import { useState } from "react";
import { useAppStore, formatBytes } from "../stores/appStore";
// FIX #8: IP mode selector options.
import { IP_MODES, normalizeConfig } from "../types";
import { useConfirmStore } from "../stores/confirmStore";
import * as api from "../api";
import Section from "../components/Section";
import StatCard from "../components/StatCard";
import Button from "../components/Button";
import MethodPicker from "../components/MethodPicker";
import ActiveConnections from "../components/ActiveConnections";

function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  // IMPROVE(U2): inline help — hover the label or (?) for a hint.
  hint?: string;
}) {
  return (
    <label className="flex flex-col gap-1.5 min-w-0" title={hint}>
      <span className="label">
        {label}
        {hint && <span className="ml-1 text-faint cursor-help">(?)</span>}
      </span>
      {children}
    </label>
  );
}

function SubLabel({ children }: { children: string }) {
  return <div className="text-[11px] font-semibold uppercase tracking-[0.15em] text-[#5C6575] mb-3">{children}</div>;
}

export default function BypassPage() {
  const cfg = useAppStore((s) => s.config);
  const setConfig = useAppStore((s) => s.actions.setConfig);
  const running = useAppStore((s) => s.running);
  const active = useAppStore((s) => s.active);
  const total = useAppStore((s) => s.total);
  const ok = useAppStore((s) => s.ok);
  const fail = useAppStore((s) => s.fail);
  const successRate = useAppStore((s) => s.successRate);
  const bestEndpoint = useAppStore((s) => s.bestEndpoint);
  const bestMethod = useAppStore((s) => s.bestMethod);
  const upBytes = useAppStore((s) => s.upBytes);
  const downBytes = useAppStore((s) => s.downBytes);
  // FIX(F5): section title counts relay sessions, not handshake slots.
  const activeConns = useAppStore((s) => s.activeConns);
  // FIX(layout): top methods for mini-list
  const topMethods = useAppStore((s) => s.topMethods);
  const start = useAppStore((s) => s.actions.start);
  const stop = useAppStore((s) => s.actions.stop);
  const save = useAppStore((s) => s.actions.save);
  const load = useAppStore((s) => s.actions.load);
  const trayBusy = useAppStore((s) => s.trayBusy);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const patch = (p: Partial<typeof cfg>) => setConfig({ ...cfg, ...p });

  const run = async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    setErr(null);
    try {
      await fn();
    } catch (e: any) {
      setErr(e?.message ?? "operation failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Row 1: Control */}
      {/* FIX(layout): no status pill here — TitleBar pill is the single source. */}
      <Section title="Engine control">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-6">
          <div>
            <SubLabel>Power</SubLabel>
            {!running ? (
              <Button variant="primary" disabled={busy != null} onClick={() => run("start", start)} title="Start engine (Space)">
                {busy === "start" ? "Starting…" : "▶ Start"}
              </Button>
            ) : (
              <Button variant="danger" disabled={busy != null} onClick={() => run("stop", stop)} title="Stop engine (Space)">
                {busy === "stop" ? "Stopping…" : "■ Stop"}
              </Button>
            )}
          </div>
          <div>
            <SubLabel>Persistence</SubLabel>
            <div className="flex gap-2">
              <Button disabled={busy != null} onClick={() => run("save", save)} title="Save config (Ctrl+S)">
                Save
              </Button>
              <Button disabled={busy != null} onClick={() => run("load", load)} title="Reload config (Ctrl+R)">
                Reload
              </Button>
            </div>
          </div>
          <div>
            <SubLabel>Maintenance</SubLabel>
            <div className="flex gap-2">
              <Button
                disabled={busy != null || !running}
                onClick={() =>
                  run("resetstats", async () => {
                    const ok = await useConfirmStore.getState().confirm({
                      title: "Reset statistics",
                      message: "Zero all counters (Active, Total, OK, Fail, Up, Down) without restarting the engine. Continue?",
                      confirmLabel: "Reset",
                      danger: true,
                    });
                    if (!ok) return;
                    await useAppStore.getState().actions.resetStats();
                  })
                }
                title="Reset counters without restarting the engine"
              >
                {busy === "resetstats" ? "Resetting…" : "Reset Stats"}
              </Button>
              <Button
                variant="danger"
                disabled={busy != null}
                onClick={() =>
                  run("reset", async () => {
                    const ok = await useConfirmStore.getState().confirm({
                      title: "Reset configuration",
                      message: "This will reset all configuration to defaults and save immediately. Continue?",
                      confirmLabel: "Reset",
                      danger: true,
                    });
                    if (!ok) return;
                    const defaults = await api.getDefaultConfig();
                    const parsed = typeof defaults === "string" ? JSON.parse(defaults) : defaults;
                    setConfig(normalizeConfig(parsed));
                    await api.configSave(JSON.stringify(normalizeConfig(parsed)));
                  })
                }
                title="Reset all configuration to defaults"
              >
                {busy === "reset" ? "Resetting…" : "Reset All"}
              </Button>
            </div>
          </div>
        </div>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Section>

      {/* Row 2: Live Metrics */}
      <Section title="Live metrics">
        <div className="grid grid-cols-3 gap-3">
          <StatCard label="Active" value={String(active)} flashKey={active} accent="accent" />
          <StatCard label="Total" value={String(total)} flashKey={total} />
          <StatCard label="OK" value={String(ok)} flashKey={ok} accent="success" />
          <StatCard label="Fail" value={String(fail)} flashKey={fail} accent="danger" />
          <StatCard label="Up" value={formatBytes(upBytes)} flashKey={upBytes} />
          <StatCard label="Down" value={formatBytes(downBytes)} flashKey={downBytes} />
        </div>
      </Section>

      {/* Row 3: Best + Active connections side by side on wide */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Section title="Best performer">
          <div className="grid grid-cols-3 gap-3 mb-4">
            <StatCard label="Best endpoint" value={bestEndpoint || "—"} extra="ranked by success rate" />
            <StatCard label="Best method" value={bestMethod || "—"} extra="ranked by success rate" />
            <StatCard
              label="Success rate"
              value={`${(successRate * 100).toFixed(1)}%`}
              flashKey={successRate}
              accent="success"
            />
          </div>
          {/* FIX(layout): Top methods mini-list — visible without expanding */}
          {topMethods.length > 1 && (
            <div className="border-t border-white/5 pt-3">
              <div className="text-[10px] uppercase tracking-wider text-faint mb-2">Top methods</div>
              <div className="flex flex-wrap gap-1.5">
                {topMethods.slice(0, 5).map((m) => (
                  <span
                    key={m.key}
                    className="text-[11px] px-2 py-1 rounded-md bg-white/5 text-muted"
                    title={`${m.ok} ok / ${m.fail} fail`}
                  >
                    {m.key} <span className="text-faint">· {Math.round(m.rate * 100)}%</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>
        <Section title={`Active connections (${activeConns.length})`}>
          <ActiveConnections />
        </Section>
      </div>

      {/* Row 4: Configuration */}
      <Section title="Configuration">
        <div className="flex flex-col gap-6">
          <div>
            <SubLabel>Network</SubLabel>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Field label="Listen host" hint="Interface to listen on. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces (LAN).">
                <input
                  className="input"
                  value={cfg.LISTEN_HOST}
                  title="Interface to listen on. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces (LAN)."
                  onChange={(e) => patch({ LISTEN_HOST: e.target.value })}
                />
              </Field>
              <Field label="Listen port" hint="The port the relay listens on. 1–65535.">
                <input
                  className="input font-mono"
                  inputMode="numeric"
                  value={cfg.LISTEN_PORT}
                  title="The port the relay listens on. 1–65535."
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (!Number.isNaN(n)) patch({ LISTEN_PORT: n });
                  }}
                />
              </Field>
              <Field label="Handshake timeout (s)" hint="Seconds to wait for the DPI handshake signal. 0.5–10.">
                <input
                  className="input font-mono"
                  inputMode="decimal"
                  value={cfg.HANDSHAKE_TIMEOUT}
                  title="Seconds to wait for the DPI handshake signal. 0.5–10."
                  onChange={(e) => {
                    const n = parseFloat(e.target.value);
                    if (!Number.isNaN(n)) patch({ HANDSHAKE_TIMEOUT: n });
                  }}
                />
              </Field>
            </div>
          </div>

          <div>
            <SubLabel>Bypass</SubLabel>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* FIX(#7): auto is sticky with rotation budget; Best method shows the real winner. */}
              <Field label="Bypass method" hint="auto = the engine sticks to one real method for up to 10 connections / 60s, then rotates if it sees 3+ failures. The Best method panel shows the real winning method, not 'auto'. Pick a specific method to disable rotation.">
                <MethodPicker value={cfg.BYPASS_METHOD} onChange={(m) => patch({ BYPASS_METHOD: m })} />
              </Field>
              {/* FIX(#5a): honesty — only legacy differs today (see audit #5). */}
              <Field label="TLS fingerprint" hint="Which browser ClientHello to mimic. Only 'legacy' produces a distinct template today; chrome_* and firefox_* currently reuse the legacy 517B template (see audit #5).">
                <select
                  className="input cursor-pointer"
                  value={cfg.TLS_FINGERPRINT}
                  title="Which browser ClientHello to mimic. Only 'legacy' produces a distinct template today; chrome_* and firefox_* currently reuse the legacy 517B template (see audit #5)."
                  onChange={(e) => patch({ TLS_FINGERPRINT: e.target.value })}
                >
                  {["legacy", "chrome_120", "chrome_124", "firefox_122", "firefox_124", "custom"].map((f) => (
                    <option key={f} value={f} className="bg-surface">
                      {f}
                    </option>
                  ))}
                </select>
              </Field>
              {/* FIX(#4a): honesty — spoof == block until QUIC Initial crypto lands (see audit #4). */}
              <Field label="QUIC mode" hint="block = drop UDP/443. spoof = same as block until QUIC Initial crypto lands (see audit #4). passthrough = forward untouched.">
                <select
                  className="input cursor-pointer"
                  value={cfg.QUIC_MODE}
                  title="block = drop UDP/443. spoof = same as block until QUIC Initial crypto lands (see audit #4). passthrough = forward untouched."
                  onChange={(e) => patch({ QUIC_MODE: e.target.value })}
                >
                  {["block", "spoof", "passthrough"].map((f) => (
                    <option key={f} value={f} className="bg-surface">
                      {f}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              {/* FIX #8: IP mode selector — forces IPv4 fallback via IPv6 drop. */}
              <Field
                label="IP mode"
                hint="ipv4 = bypass IPv4, drop IPv6 so the browser falls back. ipv6 = bypass IPv6 only (IPv4 passes through). both = bypass IPv4 and drop IPv6 (full IPv6 bypass is coming)."
              >
                <div className="flex gap-1 p-1 rounded-lg bg-[#0F1319] border border-[#1F2530]">
                  {IP_MODES.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => patch({ IP_MODE: m })}
                      className={`flex-1 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60 ${
                        cfg.IP_MODE === m ? "bg-accent/15 text-white" : "text-muted hover:text-white hover:bg-white/5"
                      }`}
                      title={
                        m === "ipv4"
                          ? "Bypass IPv4, drop IPv6"
                          : m === "ipv6"
                            ? "Bypass IPv6 only"
                            : "Bypass IPv4, drop IPv6 (IPv6 fake burst TBD)"
                      }
                    >
                      {m.toUpperCase()}
                    </button>
                  ))}
                </div>
              </Field>
              {/* FIX(#B): system tray runtime toggle. */}
              <Field
                label="System tray"
                hint="Runtime toggle: enabling or disabling takes effect immediately for both the tray icon and the window close behavior (hide vs quit)."
              >
                <div className="flex items-center justify-between gap-3">
                  <button
                    type="button"
                    role="switch"
                    aria-checked={cfg.TRAY_ENABLED}
                    disabled={trayBusy || busy != null}
                    onClick={() =>
                      run("tray", async () => {
                        // FIX(tray-rewrite): Go owns the disk write. Claim the
                        // trayBusy guard so autosave + flush-on-hide skip their
                        // saves until the resync below lands. Read the fresh
                        // value (not the render closure) so a rapid double-click
                        // cannot reuse a stale cfg.
                        const st = useAppStore.getState();
                        st.actions.setTrayBusy(true);
                        try {
                          const next = !useAppStore.getState().config.TRAY_ENABLED;
                          await api.setTrayEnabled(next);
                          const raw = await api.configLoad();
                          useAppStore.getState().actions.setConfigLocal(
                            normalizeConfig(typeof raw === "string" ? JSON.parse(raw) : raw)
                          );
                        } finally {
                          useAppStore.getState().actions.setTrayBusy(false);
                        }
                      })
                    }
                    className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border transition-colors focus:outline-none focus:ring-2 focus:ring-accent/60 ${
                      cfg.TRAY_ENABLED ? "bg-accent/30 border-accent" : "bg-[#0F1319] border-[#1F2530]"
                    }`}
                    title={cfg.TRAY_ENABLED ? "Disable system tray" : "Enable system tray"}
                  >
                    <span
                      className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
                        cfg.TRAY_ENABLED ? "translate-x-5" : "translate-x-0.5"
                      }`}
                    />
                  </button>
                  <span className={`text-xs font-mono ${cfg.TRAY_ENABLED ? "text-success" : "text-muted"}`}>
                    {cfg.TRAY_ENABLED ? "enabled" : "disabled"}
                  </span>
                </div>
              </Field>
            </div>
          </div>

          <div>
            <SubLabel>Sources</SubLabel>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="Endpoints (one ip:port per line)" hint="One ip:port per line. Up to 64. Lines starting with # are ignored.">
                <textarea
                  className="input font-mono min-h-[110px] resize-y"
                  title="One ip:port per line. Up to 64. Lines starting with # are ignored."
                  value={cfg.ENDPOINTS.map((e) => `${e.ip}:${e.port}`).join("\n")}
                  onChange={(e) => {
                    const eps = e.target.value
                      .split("\n")
                      .map((l) => l.trim())
                      // FIX(D1): '#' comment lines are skipped instead of
                      // becoming garbage entries that fail validation at Start.
                      .filter((l) => l !== "" && !l.startsWith("#"))
                      .slice(0, 64)
                      .map((tok) => {
                        const idx = tok.lastIndexOf(":");
                        if (idx > 0) {
                          const port = parseInt(tok.slice(idx + 1), 10);
                          if (!Number.isNaN(port)) return { ip: tok.slice(0, idx), port };
                        }
                        return { ip: tok, port: 443 };
                      });
                    patch({ ENDPOINTS: eps });
                  }}
                />
              </Field>
              <Field label="Fake SNIs (one per line)" hint="One domain per line. Up to 200. Lines starting with # are ignored.">
                <textarea
                  className="input font-mono min-h-[110px] resize-y"
                  title="One domain per line. Up to 200. Lines starting with # are ignored."
                  value={cfg.FAKE_SNIS.join("\n")}
                  onChange={(e) => {
                    const snis = e.target.value
                      .split("\n")
                      // FIX(D2): '#' comment lines are skipped instead of
                      // becoming invalid SNIs that fail validation at Start.
                      .map((s) => s.trim())
                      .filter((s) => s !== "" && !s.startsWith("#"))
                      .map((s) => s.toLowerCase().replace(/\.+$/, ""))
                      .filter(Boolean)
                      .slice(0, 200);
                    patch({ FAKE_SNIS: snis });
                  }}
                />
              </Field>
            </div>
          </div>

          <div>
            <SubLabel>Tuning</SubLabel>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Field label="Max connections" hint="Concurrent connection cap. 10–2000; excess is rejected with a log line.">
                <input
                  className="input font-mono"
                  inputMode="numeric"
                  value={cfg.MAX_CONNECTIONS}
                  title="Concurrent connection cap. 10–2000; excess is rejected with a log line."
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (!Number.isNaN(n)) patch({ MAX_CONNECTIONS: n });
                  }}
                />
              </Field>
              <Field label="Fake delay (s)" hint="Delay before the fake burst. 0–5s.">
                <input
                  className="input font-mono"
                  inputMode="decimal"
                  value={cfg.FAKE_DELAY}
                  title="Delay before the fake burst. 0–5s."
                  onChange={(e) => {
                    const n = parseFloat(e.target.value);
                    if (!Number.isNaN(n)) patch({ FAKE_DELAY: n });
                  }}
                />
              </Field>
              <Field label="Seq overlap" hint="Overlapping bytes for split methods. 0–16.">
                <input
                  className="input font-mono"
                  inputMode="numeric"
                  value={cfg.SEQ_OVERLAP}
                  title="Overlapping bytes for split methods. 0–16."
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (!Number.isNaN(n)) patch({ SEQ_OVERLAP: n });
                  }}
                />
              </Field>
              <Field label="Padding size" hint="Extra padding bytes on fake segments.">
                <input
                  className="input font-mono"
                  inputMode="numeric"
                  value={cfg.PADDING_SIZE}
                  title="Extra padding bytes on fake segments."
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (!Number.isNaN(n)) patch({ PADDING_SIZE: n });
                  }}
                />
              </Field>
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
}
