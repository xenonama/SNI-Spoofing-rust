import { useRef, useState } from "react";
import { useAppStore } from "../stores/appStore";
import Section from "../components/Section";
import Button from "../components/Button";
import EndpointTable from "../components/EndpointTable";
import SniTable from "../components/SniTable";
import ProgressBar from "../components/ProgressBar";

export default function ToolsPage() {
  const probing = useAppStore((s) => s.probing);
  const probeKind = useAppStore((s) => s.probeKind);
  const probeDone = useAppStore((s) => s.probeDone);
  const probeTotal = useAppStore((s) => s.probeTotal);
  const probeResults = useAppStore((s) => s.probeResults);
  const sniResults = useAppStore((s) => s.sniResults);
  const runProbeEndpoints = useAppStore((s) => s.actions.runProbeEndpoints);
  const runProbeSnis = useAppStore((s) => s.actions.runProbeSnis);
  const useFastest = useAppStore((s) => s.actions.useFastest);
  const [err, setErr] = useState<string | null>(null);
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

  return (
    <div className="flex flex-col gap-5 max-w-[980px]">
      <Section title="Actions">
        <div className="flex gap-3 flex-wrap">
          <Button disabled={probing} onClick={() => run(runProbeEndpoints)} title="Probe all endpoints for latency and TLS version">
            Rank endpoints
          </Button>
          <Button disabled={probing} onClick={() => run(runProbeSnis)} title="Probe each fake SNI through the fastest endpoint">
            Rank SNIs
          </Button>
          <Button
            variant="primary"
            disabled={probing || probeResults.length === 0}
            onClick={() => useFastest()}
            title="Replace the endpoints list with the fastest reachable one"
          >
            Use fastest
          </Button>
        </div>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Section>

      {probing && (
        <div className="card">
          <div className="text-sm text-muted mb-2">
            Probing {probeKind}… {probeTotal > 0 ? `${probeDone}/${probeTotal}` : ""}
          </div>
          <ProgressBar done={probeDone} total={probeTotal} />
        </div>
      )}

      <Section title="Endpoint results">
        <EndpointTable rows={probeResults} />
      </Section>

      <Section title="SNI results">
        <SniTable rows={sniResults} />
      </Section>
    </div>
  );
}
