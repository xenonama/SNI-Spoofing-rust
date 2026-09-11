import { useState } from "react";
import { useAppStore, formatBytes } from "../stores/appStore";
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
  const start = useAppStore((s) => s.actions.start);
  const stop = useAppStore((s) => s.actions.stop);
  const save = useAppStore((s) => s.actions.save);
  const load = useAppStore((s) => s.actions.load);
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
    <div className="flex flex-col gap-5 max-w-[980px]">
      <Section title="Control">
        <div className="flex gap-3 flex-wrap">
          {!running ? (
            <Button variant="primary" disabled={busy != null} onClick={() => run("start", start)} title="Start engine (Space)">
              {busy === "start" ? "Starting…" : "Start"}
            </Button>
          ) : (
            <Button variant="danger" disabled={busy != null} onClick={() => run("stop", stop)} title="Stop engine (Space)">
              {busy === "stop" ? "Stopping…" : "Stop"}
            </Button>
          )}
          <Button disabled={busy != null} onClick={() => run("save", save)} title="Save config (Ctrl+S)">
            Save
          </Button>
          <Button disabled={busy != null} onClick={() => run("load", load)} title="Reload config (Ctrl+R)">
            Reload
          </Button>
        </div>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Section>

      <Section title="Live metrics">
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          <StatCard label="Active" value={String(active)} flashKey={active} accent="accent" />
          <StatCard label="Total" value={String(total)} flashKey={total} />
          <StatCard label="OK" value={String(ok)} flashKey={ok} accent="success" />
          <StatCard label="Fail" value={String(fail)} flashKey={fail} accent="danger" />
          <StatCard label="Up" value={formatBytes(upBytes)} flashKey={upBytes} />
          <StatCard label="Down" value={formatBytes(downBytes)} flashKey={downBytes} />
        </div>
      </Section>

      <Section title="Best">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <StatCard label="Best endpoint" value={bestEndpoint || "—"} extra="ranked by success rate" />
          <StatCard label="Best method" value={bestMethod || "—"} extra="ranked by success rate" />
          <StatCard
            label="Success rate"
            value={`${(successRate * 100).toFixed(1)}%`}
            flashKey={successRate}
            accent="success"
          />
        </div>
      </Section>

      <Section title={`Active connections (${activeConns.length})`}>
        <ActiveConnections />
      </Section>

      <Section title="Configuration">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="Network — listen host" hint="Interface to listen on. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces (LAN).">
            <input
              className="input"
              value={cfg.LISTEN_HOST}
              title="Interface to listen on. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces (LAN)."
              onChange={(e) => patch({ LISTEN_HOST: e.target.value })}
            />
          </Field>
          <div className="grid grid-cols-2 gap-4">
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
            <Field label="Bypass method">
              <MethodPicker value={cfg.BYPASS_METHOD} onChange={(m) => patch({ BYPASS_METHOD: m })} />
            </Field>
          </div>
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
          <Field label="TLS fingerprint" hint="Which browser ClientHello to mimic.">
            <select
              className="input cursor-pointer"
              value={cfg.TLS_FINGERPRINT}
              title="Which browser ClientHello to mimic."
              onChange={(e) => patch({ TLS_FINGERPRINT: e.target.value })}
            >
              {["legacy", "chrome_120", "chrome_124", "firefox_122", "firefox_124", "custom"].map((f) => (
                <option key={f} value={f} className="bg-surface">
                  {f}
                </option>
              ))}
            </select>
          </Field>
          <Field label="QUIC mode" hint="block = drop UDP/443; spoof = SNI swap; passthrough.">
            <select
              className="input cursor-pointer"
              value={cfg.QUIC_MODE}
              title="block = drop UDP/443; spoof = SNI swap; passthrough."
              onChange={(e) => patch({ QUIC_MODE: e.target.value })}
            >
              {["block", "spoof", "passthrough"].map((f) => (
                <option key={f} value={f} className="bg-surface">
                  {f}
                </option>
              ))}
            </select>
          </Field>
          <div className="grid grid-cols-2 gap-4">
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
          </div>
          <div className="grid grid-cols-3 gap-4">
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
      </Section>
    </div>
  );
}
