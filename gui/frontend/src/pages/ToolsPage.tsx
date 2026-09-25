// FIX(tools): redesigned ToolsPage — guided 3-step workflow with visual feedback.
import { useRef, useState } from "react";
import { useAppStore } from "../stores/appStore";
import Section from "../components/Section";
import Button from "../components/Button";
import EndpointTable from "../components/EndpointTable";
import SniTable from "../components/SniTable";
import ProgressBar from "../components/ProgressBar";
import { Zap, Search } from "lucide-react";

export default function ToolsPage() {
  const probing = useAppStore((s) => s.probing);
  const probeKind = useAppStore((s) => s.probeKind);
  const probeDone = useAppStore((s) => s.probeDone);
  const probeTotal = useAppStore((s) => s.probeTotal);
  const probeResults = useAppStore((s) => s.probeResults);
  const sniResults = useAppStore((s) => s.sniResults);
  const cfg = useAppStore((s) => s.config);
  const runProbeEndpoints = useAppStore((s) => s.actions.runProbeEndpoints);
  const runProbeSnis = useAppStore((s) => s.actions.runProbeSnis);
  const useFastest = useAppStore((s) => s.actions.useFastest);
  const useTopSnis = useAppStore((s) => s.actions.useTopSnis);
  const clearProbeResults = useAppStore((s) => s.actions.clearProbeResults);
  const [err, setErr] = useState<string | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>("");
  // FIX(F1): synchronous re-entry guard — the store `probing` flag flips
  // asynchronously across awaits, so same-tick double-clicks could
  // otherwise spawn two overlapping probes (last result wins).
  const busyRef = useRef(false);

  const run = async (fn: () => Promise<void>) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setErr(null);
    try {
      await fn();
    } catch (e: any) {
      setErr(e?.message ?? "probe failed");
    } finally {
      busyRef.current = false;
    }
  };

  const endpointOptions = (() => {
    const fromProbe = probeResults.filter((r) => r.reachable).map((r) => r.endpoint);
    const fromConfig = cfg.ENDPOINTS.map((e) => `${e.ip}:${e.port}`);
    const merged = [...new Set([...fromProbe, ...fromConfig])];
    return merged.length > 0 ? merged : [""];
  })();

  const effectiveEndpoint = selectedEndpoint || endpointOptions[0] || "";

  const reachableEndpoints = probeResults.filter((r) => r.reachable).length;
  const timeoutEndpoints = probeResults.length - reachableEndpoints;
  const reachableSnis = sniResults.filter((r) => r.reachable).length;
  const timeoutSnis = sniResults.length - reachableSnis;

  return (
    <div className="flex flex-col gap-4">
      {/* Intro */}
      <div className="rounded-xl bg-[#12161D] border border-[#1A1F28] p-5">
        <h2 className="text-sm font-semibold text-white">Smart Tools</h2>
        <p className="text-sm text-muted mt-1 leading-relaxed">
          Automatically find the fastest endpoint and the best fake SNI for your network.
        </p>
      </div>

      {/* STEP 1 — Rank endpoints */}
      <Section
        title="Step 1 — Rank endpoints"
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              disabled={probing}
              onClick={() => run(runProbeEndpoints)}
              title="Probe every endpoint with a TCP+TLS handshake and measures latency."
            >
              <Zap size={14} />
              Rank endpoints
            </Button>
            <Button disabled={probeResults.length === 0 && !probing} onClick={() => clearProbeResults()} title="Clear results">
              Clear
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted leading-relaxed mb-3">
          Probes every endpoint with a TCP+TLS handshake and measures latency.
        </p>

        {probing && probeKind === "endpoints" && (
          <div className="mb-3">
            <ProgressBar done={probeDone} total={probeTotal} />
          </div>
        )}

        {probeResults.length === 0 ? (
          <div className="text-sm text-faint py-6 text-center border border-dashed border-[#1A1F28] rounded-lg">
            Run &apos;Rank endpoints&apos; to find the fastest relay.
          </div>
        ) : (
          <>
            <div className="text-xs text-faint mb-2">
              Results ({reachableEndpoints} reachable, {timeoutEndpoints} timeout)
            </div>
            <EndpointTable rows={probeResults} />
            <div className="mt-3">
              <Button
                variant="primary"
                disabled={probing || probeResults.length === 0}
                onClick={() => void useFastest()}
                title="Replace the endpoints list with the fastest reachable one"
              >
                Use fastest →
              </Button>
            </div>
          </>
        )}
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Section>

      {/* STEP 2 — Rank fake SNIs */}
      <Section
        title="Step 2 — Rank fake SNIs"
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              disabled={probing}
              onClick={() => run(runProbeSnis)}
              title="Probe each fake SNI through the fastest endpoint to find which decoy the DPI accepts."
            >
              <Search size={14} />
              Rank SNIs
            </Button>
            <Button disabled={sniResults.length === 0 && !probing} onClick={() => clearProbeResults()} title="Clear results">
              Clear
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted leading-relaxed mb-3">
          Probes each fake SNI through the fastest endpoint to find which decoy the DPI accepts.
        </p>

        <div className="mb-3">
          <label className="label">Probe endpoint</label>
          <select
            value={effectiveEndpoint}
            onChange={(e) => setSelectedEndpoint(e.target.value)}
            className="input !w-auto min-w-[220px]"
          >
            {endpointOptions.map((ep) => (
              <option key={ep} value={ep} className="bg-[#0F1319]">
                {ep || "—"}
              </option>
            ))}
          </select>
        </div>

        {probing && probeKind === "snis" && (
          <div className="mb-3">
            <ProgressBar done={probeDone} total={probeTotal} />
          </div>
        )}

        {sniResults.length === 0 ? (
          <div className="text-sm text-faint py-6 text-center border border-dashed border-[#1A1F28] rounded-lg">
            Run &apos;Rank SNIs&apos; to test which decoys work.
          </div>
        ) : (
          <>
            <div className="text-xs text-faint mb-2">
              Results ({reachableSnis} reachable, {timeoutSnis} timeout)
            </div>
            <SniTable rows={sniResults} />
            <div className="mt-3">
              <Button
                variant="primary"
                disabled={sniResults.length === 0}
                onClick={() => void useTopSnis(10)}
                title="Reorder FAKE_SNIS to put the top 10 fastest first"
              >
                Use top 10 →
              </Button>
            </div>
          </>
        )}
      </Section>
    </div>
  );
}
