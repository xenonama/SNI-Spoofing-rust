import { useEffect } from "react";
import Section from "../components/Section";
import { getConfig } from "../api";
import { useAppStore } from "../stores/appStore";

export default function ProxyPage() {
  const config = useAppStore((s) => s.config);
  const setConfig = useAppStore((s) => s.setConfig);
  const pushLog = useAppStore((s) => s.pushLog);

  useEffect(() => {
    if (!config) {
      getConfig()
        .then(setConfig)
        .catch((e) => pushLog(`[WARN] no valid config (${String(e)})`));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const mode = config?.mode ?? "SNI Only";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-xl font-bold">Proxy-Xray</h2>
        <p className="text-sm text-muted">
          Local proxy output + external xray transport.
        </p>
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <div className="flex flex-col gap-6 lg:col-span-3">
          <Section title="Mode" subtitle="applies on Start/Save">
            <div className="flex gap-3">
              {(["SNI Only", "Trojan + Xray"] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => config && setConfig({ ...config, mode: m })}
                  className={`h-12 flex-1 rounded-lg border text-sm font-semibold transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-accent/60 ${
                    mode === m
                      ? "border-accent bg-accent/10 text-white shadow-glow"
                      : "border-card-edge text-muted hover:bg-white/5 hover:text-white"
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
            <p className="mt-3 text-xs text-muted">
              {mode === "Trojan + Xray"
                ? "Trojan + Xray: QUIC passes through, xray.exe handles proxying."
                : "SNI Only: built-in DPI bypass, no external proxy."}
            </p>
          </Section>
          <Section title="Proxy output">
            <div className="flex gap-6">
              <div>
                <p className="label">SOCKS5 port</p>
                <p className="mt-1 font-mono text-sm">
                  {config?.socks5_port ?? "—"}
                </p>
              </div>
              <div>
                <p className="label">HTTP port</p>
                <p className="mt-1 font-mono text-sm">
                  {config?.http_port ?? "—"}
                </p>
              </div>
            </div>
            <p className="mt-3 text-xs text-muted">
              Ports are config-driven; edit them in config.json.
            </p>
          </Section>
        </div>
        <div className="lg:col-span-2">
          <Section
            title="Trojan transport"
            subtitle="managed via config.json.full.json"
          >
            <p className="text-sm text-muted">
              xray.exe supervision is manual: set MODE=Trojan + Xray via
              config.json.full.json, then launch xray.exe yourself.
            </p>
            <p className="mt-2 text-sm text-muted">
              In Trojan + Xray mode the QUIC injector passes HTTP/3 through.
            </p>
            <div className="mt-3 flex flex-col gap-2 text-sm">
              {(
                [
                  ["Password", "set in config.json.full.json"],
                  ["Transport", "set in config.json.full.json"],
                  ["WS path", "set in config.json.full.json"],
                  ["WS host", "set in config.json.full.json"],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2">
                  <span className="w-24 text-muted">{k}:</span>
                  <span className="font-mono">—</span>
                  <span className="text-xs text-faint">({v})</span>
                </div>
              ))}
            </div>
          </Section>
        </div>
      </div>
      <div className="h-10" />
    </div>
  );
}
