import { useAppStore } from "../stores/appStore";
import Section from "../components/Section";

export default function ProxyPage() {
  const cfg = useAppStore((s) => s.config);
  const setConfig = useAppStore((s) => s.actions.setConfig);
  const patch = (p: Partial<typeof cfg>) => setConfig({ ...cfg, ...p });

  return (
    <div className="flex flex-col gap-5 max-w-[980px]">
      <Section title="Mode">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {(["SNI Only", "Trojan + Xray"] as const).map((m) => {
            const selected = cfg.MODE === m;
            return (
              <button
                key={m}
                onClick={() => patch({ MODE: m as string })}
                className={`text-left rounded-xl border p-4 transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-accent/60 hover:border-accent/60 active:scale-[0.99] ${
                  selected
                    ? "border-accent bg-accent/10 shadow-glow"
                    : "border-card-edge bg-surface"
                }`}
              >
                <div className="font-semibold">{m}</div>
                <div className="text-sm text-muted mt-1">
                  {m === "SNI Only"
                    ? "Direct DPI bypass — no external proxy process."
                    : "Route through an external xray.exe Trojan transport."}
                </div>
              </button>
            );
          })}
        </div>
      </Section>

      <Section title="Proxy output">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="flex flex-col gap-1.5">
            <span className="label">SOCKS5 port</span>
            <input
              className="input font-mono"
              inputMode="numeric"
              value={cfg.SOCKS5_PORT}
              onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                if (!Number.isNaN(n)) patch({ SOCKS5_PORT: n });
              }}
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="label">HTTP port</span>
            <input
              className="input font-mono"
              inputMode="numeric"
              value={cfg.HTTP_PORT}
              onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                if (!Number.isNaN(n)) patch({ HTTP_PORT: n });
              }}
            />
          </label>
        </div>
      </Section>

      <Section title="Trojan transport">
        <p className="text-sm text-muted leading-relaxed">
          In <span className="text-white font-medium">Trojan + Xray</span> mode the engine
          hands established flows to an external{" "}
          <span className="font-mono text-white">xray.exe</span> process using your Trojan
          transport file next to the app. Keep <span className="font-mono text-white">WinDivert.dll</span> and{" "}
          <span className="font-mono text-white">WinDivert64.sys</span> next to the exe and run as
          Administrator — otherwise the driver open fails and the console explains why.
        </p>
      </Section>
    </div>
  );
}
