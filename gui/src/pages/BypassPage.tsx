import { useEffect, useState } from "react";
import Button from "../components/Button";
import MethodPicker from "../components/MethodPicker";
import Section from "../components/Section";
import StatCard from "../components/StatCard";
import { getConfig, reloadConfig, saveConfig, startEngine, stopEngine } from "../api";
import { useAppStore } from "../stores/appStore";
import { FINGERPRINTS, QUIC_MODES } from "../types";

function humanBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  for (const u of units) {
    if (v < 1024 || u === "TB") {
      return u === "B" ? `${Math.floor(v)} ${u}` : `${v.toFixed(1)} ${u}`;
    }
    v /= 1024;
  }
  return `${v.toFixed(1)} TB`;
}

export default function BypassPage() {
  const config = useAppStore((s) => s.config);
  const setConfig = useAppStore((s) => s.setConfig);
  const snapshot = useAppStore((s) => s.snapshot);
  const engineRunning = useAppStore((s) => s.engineRunning);
  const setEngineRunning = useAppStore((s) => s.setEngineRunning);
  const pushLog = useAppStore((s) => s.pushLog);
  const [busy, setBusy] = useState(false);
  const [advanced, setAdvanced] = useState(false);

  useEffect(() => {
    if (!config) {
      getConfig()
        .then(setConfig)
        .catch((e) => pushLog(`[WARN] no valid config (${String(e)})`));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const active = snapshot?.active ?? 0;
  const total = snapshot?.total ?? 0;
  const ok = snapshot?.success ?? 0;
  const fail = snapshot?.failed ?? 0;
  const rate = snapshot ? snapshot.success_rate * 100 : 0;
  const up = snapshot?.up_bytes ?? 0;
  const down = snapshot?.down_bytes ?? 0;

  const mutate = (patch: Partial<NonNullable<typeof config>>) => {
    if (config) setConfig({ ...config, ...patch });
  };

  const doStart = async () => {
    setBusy(true);
    try {
      if (config) await saveConfig(config);
      await startEngine();
      setEngineRunning(true);
    } catch (e) {
      pushLog(`[ERR ] start failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const doStop = async () => {
    setBusy(true);
    try {
      await stopEngine();
      setEngineRunning(false);
    } catch (e) {
      pushLog(`[ERR ] stop failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex min-h-[60px] flex-wrap items-center gap-3">
        {engineRunning ? (
          <Button variant="danger" className="h-12 w-44" disabled={busy} onClick={doStop}>
            ■ Stop
          </Button>
        ) : (
          <Button variant="primary" className="h-12 w-44" disabled={busy} onClick={doStart}>
            ▶ Start
          </Button>
        )}
        <Button
          variant="ghost"
          disabled={busy || !config}
          onClick={async () => {
            if (!config) return;
            try {
              await saveConfig(config);
              pushLog("[INFO] config saved");
            } catch (e) {
              pushLog(`[ERR ] save failed: ${String(e)}`);
            }
          }}
        >
          💾 Save
        </Button>
        <Button
          variant="ghost"
          disabled={busy}
          onClick={async () => {
            try {
              setConfig(await reloadConfig());
              pushLog("[INFO] config reloaded");
            } catch (e) {
              pushLog(`[ERR ] reload failed: ${String(e)}`);
            }
          }}
        >
          ↻ Reload
        </Button>
        <span
          className={`ml-auto rounded-lg px-3 py-1 text-[10px] font-bold uppercase tracking-wider ${
            engineRunning ? "bg-success/20 text-success" : "bg-white/5 text-muted"
          }`}
        >
          {engineRunning ? "RUNNING" : "stopped"}
        </span>
      </div>

      <div className="flex gap-3">
        <StatCard label="Active" value={String(active)} extra="sessions" flashKey={active} />
        <StatCard
          label="Total"
          value={String(total)}
          extra={`OK ${ok} · Fail ${fail}`}
          flashKey={total}
        />
        <StatCard
          label="Success rate"
          value={`${rate.toFixed(1)}%`}
          extra={`${ok}/${total} ok`}
          flashKey={rate}
        />
        <StatCard
          label="Traffic"
          value={`▲ ${humanBytes(up)} ▼ ${humanBytes(down)}`}
          extra="up · down"
          flashKey={up + down}
        />
      </div>

      <div className="flex gap-3">
        <StatCard
          label="Best endpoint"
          value={snapshot?.best_endpoint || "—"}
          extra="from stats"
          flashKey={snapshot?.best_endpoint}
        />
        <StatCard
          label="Best method"
          value={snapshot?.best_method || "—"}
          extra="from stats"
          flashKey={snapshot?.best_method}
        />
        <StatCard
          label="Bypass method"
          value={config?.bypass_method ?? "—"}
          extra="live config"
          flashKey={config?.bypass_method}
        />
      </div>

      <Section title="Configuration" subtitle="saved to config.json on Start/Save">
        {!config ? (
          <p className="text-sm text-muted">Loading config…</p>
        ) : (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <div className="flex flex-col gap-3">
              <p className="label">Network</p>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Listen host</span>
                <input
                  className="input"
                  value={config.listen_host}
                  onChange={(e) => mutate({ listen_host: e.target.value })}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Listen port</span>
                <input
                  className="input"
                  value={config.listen_port}
                  onChange={(e) =>
                    mutate({ listen_port: Number(e.target.value) || 0 })
                  }
                />
              </label>
              <p className="label mt-2">Endpoints (ip:port per line)</p>
              <textarea
                className="input min-h-28 font-mono"
                rows={6}
                value={config.endpoints.map((e) => `${e.ip}:${e.port}`).join("\n")}
                onChange={(e) => {
                  const endpoints = e.target.value
                    .split("\n")
                    .map((l) => l.trim())
                    .filter(Boolean)
                    .map((tok) => {
                      const idx = tok.lastIndexOf(":");
                      if (idx > 0) {
                        const port = Number(tok.slice(idx + 1)) || 443;
                        return { ip: tok.slice(0, idx), port };
                      }
                      return { ip: tok, port: 443 };
                    });
                  mutate({ endpoints });
                }}
              />
              <p className="label mt-2">Fake SNIs (one per line)</p>
              <textarea
                className="input min-h-28 font-mono"
                rows={6}
                value={config.fake_snis.join("\n")}
                onChange={(e) =>
                  mutate({
                    fake_snis: e.target.value
                      .split("\n")
                      .map((l) => l.trim().toLowerCase().replace(/\.+$/, ""))
                      .filter(Boolean),
                  })
                }
              />
            </div>
            <div className="flex flex-col gap-3">
              <p className="label">Bypass</p>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Method</span>
                <MethodPicker
                  value={config.bypass_method}
                  onChange={(bypass_method) => mutate({ bypass_method })}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">TLS fingerprint</span>
                <select
                  className="input"
                  value={config.tls_fingerprint}
                  onChange={(e) => mutate({ tls_fingerprint: e.target.value })}
                >
                  {FINGERPRINTS.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">QUIC mode</span>
                <select
                  className="input"
                  value={config.quic_mode}
                  onChange={(e) => mutate({ quic_mode: e.target.value })}
                >
                  {QUIC_MODES.map((q) => (
                    <option key={q} value={q}>
                      {q}
                    </option>
                  ))}
                </select>
              </label>
              <p className="label mt-2">Limits</p>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Handshake timeout (s)</span>
                <input
                  className="input"
                  value={config.handshake_timeout}
                  onChange={(e) =>
                    mutate({ handshake_timeout: Number(e.target.value) || 0 })
                  }
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Max connections</span>
                <input
                  className="input"
                  value={config.max_connections}
                  onChange={(e) =>
                    mutate({ max_connections: Number(e.target.value) || 0 })
                  }
                />
              </label>
              <button
                className="mt-2 text-left text-sm text-muted hover:text-white"
                onClick={() => setAdvanced((a) => !a)}
              >
                {advanced ? "▼ Advanced" : "▶ Advanced"}
              </button>
              {advanced && (
                <div className="flex flex-col gap-3 rounded-lg border border-card-edge p-3">
                  <label className="flex flex-col gap-1 text-sm">
                    <span className="text-muted">Fake delay (s)</span>
                    <input
                      className="input"
                      type="number"
                      step={0.001}
                      value={config.fake_delay}
                      onChange={(e) =>
                        mutate({ fake_delay: Number(e.target.value) || 0 })
                      }
                    />
                  </label>
                  <label className="flex flex-col gap-1 text-sm">
                    <span className="text-muted">Sequence overlap</span>
                    <input
                      className="input"
                      type="number"
                      value={config.seq_overlap}
                      onChange={(e) =>
                        mutate({ seq_overlap: Number(e.target.value) || 0 })
                      }
                    />
                  </label>
                  <label className="flex flex-col gap-1 text-sm">
                    <span className="text-muted">Padding size</span>
                    <input
                      className="input"
                      type="number"
                      value={config.padding_size}
                      onChange={(e) =>
                        mutate({ padding_size: Number(e.target.value) || 0 })
                      }
                    />
                  </label>
                </div>
              )}
            </div>
          </div>
        )}
      </Section>
      <div className="h-10" />
    </div>
  );
}
