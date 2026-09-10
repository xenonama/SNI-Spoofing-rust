import Button from "../components/Button";
import EndpointTable from "../components/EndpointTable";
import ProgressBar from "../components/ProgressBar";
import Section from "../components/Section";
import SniTable from "../components/SniTable";
import { pickFastest, runProbeEp, runProbeSni } from "../api";
import { useAppStore } from "../stores/appStore";

function parseLines(text: string): string[] {
  return text
    .replace(/[,;]/g, " ")
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function ToolsPage() {
  const config = useAppStore((s) => s.config);
  const probeResults = useAppStore((s) => s.probeResults);
  const sniResults = useAppStore((s) => s.sniResults);
  const probing = useAppStore((s) => s.probing);
  const setProbing = useAppStore((s) => s.setProbing);
  const fastestEndpoint = useAppStore((s) => s.fastestEndpoint);
  const setFastestEndpoint = useAppStore((s) => s.setFastestEndpoint);
  const pushLog = useAppStore((s) => s.pushLog);

  const endpointsText = (config?.endpoints ?? [])
    .map((e) => `${e.ip}:${e.port}`)
    .join("\n");
  const snisText = (config?.fake_snis ?? []).join("\n");

  const rankEndpoints = async () => {
    const eps = parseLines(endpointsText).slice(0, 16);
    if (eps.length === 0) {
      pushLog("[WARN] no endpoints to probe");
      return;
    }
    setProbing({ active: true, kind: "endpoints", done: 0, total: eps.length });
    try {
      await runProbeEp(eps);
    } catch (e) {
      pushLog(`[ERR ] probe failed: ${String(e)}`);
      setProbing({ active: false, kind: null, done: 0, total: 0 });
    }
  };

  const rankSnis = async () => {
    const snis = parseLines(snisText)
      .map((s) => s.toLowerCase().replace(/\.+$/, ""))
      .slice(0, 32);
    if (snis.length === 0) {
      pushLog("[WARN] no SNIs to probe");
      return;
    }
    const endpoint =
      probeResults.find((p) => p.reachable)?.endpoint ??
      parseLines(endpointsText)[0];
    if (!endpoint) {
      pushLog("[WARN] no endpoint available for SNI probe");
      return;
    }
    setProbing({ active: true, kind: "snis", done: 0, total: snis.length });
    try {
      await runProbeSni(snis, endpoint);
    } catch (e) {
      pushLog(`[ERR ] SNI probe failed: ${String(e)}`);
      setProbing({ active: false, kind: null, done: 0, total: 0 });
    }
  };

  const useFastest = async () => {
    try {
      const ep = await pickFastest();
      setFastestEndpoint(ep);
      pushLog(`[INFO] using fastest: ${ep}`);
    } catch (e) {
      setFastestEndpoint(null);
      pushLog(`[WARN] ${String(e)}`);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-xl font-bold">Smart Tools</h2>
        <p className="text-sm text-muted">
          Rank endpoints and SNIs, then use the fastest.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="primary"
          className="h-11 px-6"
          style={{ width: 200 }}
          disabled={probing.active && probing.kind === "endpoints"}
          onClick={rankEndpoints}
        >
          ⚡ Rank endpoints
        </Button>
        <Button
          variant="primary"
          style={{ width: 200 }}
          className="h-11 px-6"
          disabled={probing.active && probing.kind === "snis"}
          onClick={rankSnis}
        >
          ⚡ Rank SNIs
        </Button>
        <Button
          variant="primary"
          style={{ width: 200 }}
          className="h-11 px-6"
          onClick={useFastest}
        >
          ✓ Use fastest
        </Button>
        {probing.active && (
          <span className="text-sm text-warning">
            Probing {probing.done} / {probing.total} …
          </span>
        )}
      </div>

      {probing.active && (
        <Section title="Progress">
          <ProgressBar
            label={`Probing ${probing.done} / ${probing.total} ${
              probing.kind === "snis" ? "SNIs" : "endpoints"
            } …`}
          />
        </Section>
      )}

      <Section title={`Endpoint results (${probeResults.length})`}>
        <EndpointTable
          rows={probeResults}
          fastest={fastestEndpoint}
          emptyHint="Press Rank endpoints"
        />
      </Section>

      <Section title={`SNI results (${sniResults.length})`}>
        <SniTable rows={sniResults} />
      </Section>
      <div className="h-10" />
    </div>
  );
}
