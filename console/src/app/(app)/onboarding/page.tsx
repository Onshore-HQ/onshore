"use client";
import { tr } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ErrorLine, Page, ShownOnce } from "@/components/ui";
import { control, n } from "@/lib/api";

const STEPS = ["Create a test vault", "Connect your logs", "Watch"];
const UPSTREAM: Record<string, string> = { Datadog: "https://http-intake.logs.datadoghq.eu", Sentry: "https://sentry.example.com", "Grafana Cloud": "https://otlp-gateway.grafana.net/otlp", Elastic: "https://elastic.example.com" };

export default function Onboarding() {
    const router = useRouter();
  const [step, setStep] = useState(1);
  const [templates, setTemplates] = useState<Record<string, { label: string; description: string; fields: { name: string }[] }>>({});
  const [template, setTemplate] = useState("wallet_psp");
  const [vaultId, setVaultId] = useState<string | null>(null);
  const [source, setSource] = useState<"otlp" | "fluentbit" | "vector">("otlp");
  const [destination, setDestination] = useState("Datadog");
  const [upstream, setUpstream] = useState(UPSTREAM.Datadog!);
  const [created, setCreated] = useState<{ id: string; ingest_key: string; setup: string } | null>(null);
  const [detections, setDetections] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    control("/v1/templates").then(setTemplates).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (step !== 3 || !created) return;
    const poll = async () => {
      const { pipelines } = await control<{ pipelines: { id: string; sparkline: { count: number }[] }[] }>("/v1/log-pipelines");
      const p = pipelines.find((x) => x.id === created.id);
      setDetections(p?.sparkline.reduce((s, d) => s + Number(d.count), 0) ?? 0);
    };
    poll();
    const t = setInterval(poll, 5000);
    return () => clearInterval(t);
  }, [step, created]);

  const createVault = async () => {
    setBusy(true);
    setError(null);
    try {
      const v = await control<{ id: string }>("/v1/vaults", { body: { name: "Test vault", environment: "sandbox", template: "packs", seed: true } });
      setVaultId(v.id);
      setStep(2);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed");
    } finally {
      setBusy(false);
    }
  };
  const createPipeline = async () => {
    setBusy(true);
    setError(null);
    try {
      setCreated(await control("/v1/log-pipelines", { body: { vault_id: vaultId, name: `${destination} logs`, source_type: source, destination, upstream_url: upstream } }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page title={tr("Setup guide")} sub={tr("Three short steps to a test vault and your first connection. Nothing changes in your logs until you turn protection on.")}>
      <div className="steps">{STEPS.map((s, i) => <span key={s} className={i + 1 === step ? "on" : ""}>{i + 1}. {s}</span>)}</div>
      {step === 1 && (
        <div className="stack">
          <p className="muted small">{tr("This creates a test vault in your install’s country, with fields for that country’s identifiers, and two starter access rules you can change:")} <code>backend-services</code> and <code>console-access</code>.</p>
          <ErrorLine error={error} />
          <div className="row"><button className="primary" disabled={busy} onClick={createVault}>{busy ? tr("Creating…") : tr("Create test vault")}</button></div>
        </div>
      )}
      {step === 2 && (
        <div className="stack" style={{ maxWidth: 760 }}>
          {!created ? (
            <div className="card">
              <h2>{tr("Connect your log collector")}</h2>
              <div className="row">
                {(["otlp", "fluentbit", "vector"] as const).map((s) => (
                  <label key={s} className="row small"><input type="radio" name="src" checked={source === s} onChange={() => setSource(s)} />{{ otlp: "OpenTelemetry", fluentbit: "Fluent Bit", vector: "Vector" }[s]}</label>
                ))}
              </div>
              <label className="field"><span>{tr("Where logs go today")}</span>
                <select value={destination} onChange={(e) => { setDestination(e.target.value); setUpstream(UPSTREAM[e.target.value] ?? ""); }}>
                  {Object.keys(UPSTREAM).map((d) => <option key={d}>{d}</option>)}
                </select>
              </label>
              <label className="field"><span>{tr("Destination URL")}</span><input value={upstream} onChange={(e) => setUpstream(e.target.value)} /></label>
              <ErrorLine error={error} />
              <div className="row"><button className="primary" disabled={busy || !upstream} onClick={createPipeline}>{tr("Connect, watching only")}</button><button onClick={() => router.push("/overview")}>{tr("Skip for now")}</button></div>
            </div>
          ) : (
            <div className="card">
              <h2>{tr("Add this to your collector")}</h2>
              <ShownOnce items={[{ label: tr("Collector settings"), value: created.setup, block: true }]} />
              <div className="row"><button className="primary" onClick={() => setStep(3)}>{tr("I have added it")}</button></div>
            </div>
          )}
        </div>
      )}
      {step === 3 && (
        <div className="card" style={{ maxWidth: 560 }}>
          <h2>{tr("Watching. Nothing has changed yet")}</h2>
          <div className="stat">{n(detections)}</div>
          <p className="muted">{tr("sensitive values found so far. Your logs pass through unchanged for now. Leave this running for a week, then see what you were sending abroad.")}</p>
          <div className="row"><button className="primary" onClick={() => router.push("/overview")}>{tr("Go to Home")}</button></div>
        </div>
      )}
    </Page>
  );
}
