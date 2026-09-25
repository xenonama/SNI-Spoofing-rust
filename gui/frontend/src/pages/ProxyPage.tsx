// FIX(design): ProxyPage — wrapped in Section cards for unified look.
import { useAppStore } from "../stores/appStore";
import Section from "../components/Section";

export default function ProxyPage() {
  const cfg = useAppStore((s) => s.config);
  const setConfig = useAppStore((s) => s.actions.setConfig);
  const patch = (p: Partial<typeof cfg>) => setConfig({ ...cfg, ...p });

  return (
    <div className="flex flex-col gap-4">
      <Section title="Mode">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {(["SNI Only", "Trojan + Xray"] as const).map((m) => {
            const selected = cfg.MODE === m;
            return (
              <button
                key={m}
                onClick={() => patch({ MODE: m as string })}
                className={`text-left rounded-xl border p-4 transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-accent/60 hover:border-accent/60 active:scale-[0.99] ${
                  selected ? "border-accent bg-accent/10 shadow-glow" : "border-[#1A1F28] bg-[#0F1319]"
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

      {/* FIX(#1b): engine is raw TCP; Xray owns SOCKS5/HTTP. Static text replaces dead inputs. */}
      <Section title="Proxy output">
        <p className="text-sm text-muted leading-relaxed">
          The engine listens on a single raw TCP port
          (<span className="font-mono text-white">LISTEN_PORT</span>, default 40443). Point your external Xray / Trojan client at that port; Xray
          exposes the SOCKS5 and HTTP listeners on the ports configured in its own inbound. The engine does not speak SOCKS5 or HTTP CONNECT
          itself.
        </p>
      </Section>

      <Section title="Trojan transport">
        <p className="text-sm text-muted leading-relaxed">
          In <span className="text-white font-medium">Trojan + Xray</span> mode the engine hands established flows to an external{" "}
          <span className="font-mono text-white">xray.exe</span> process using your Trojan transport file next to the app. Keep{" "}
          <span className="font-mono text-white">WinDivert.dll</span> and <span className="font-mono text-white">WinDivert64.sys</span> next to the exe and run as
          Administrator — otherwise the driver open fails and the console explains why.
        </p>
      </Section>
    </div>
  );
}
