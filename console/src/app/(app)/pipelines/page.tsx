"use client";
import { tr } from "@/lib/i18n";
import { entityLabel } from "@/lib/labels";
import { useState } from "react";
import { Sparkline } from "@/components/CaughtChart";
import { Badge, Copy, Empty, ErrorLine, Loading, Modal, Page, TypedConfirm, ShownOnce } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { AiRoutes } from "./ai";
import { ProxyRoutes } from "./proxy";
import Link from "next/link";
import { useEffect } from "react";
import { SupportTools } from "./support";
import { modeLabel } from "@/lib/labels";
import { ConnectionsOverview } from "./overview";
import { ConnectCatalog } from "@/components/ConnectCatalog";

const ENTITIES = ["bvn", "nin", "vnin", "ng_11_digit_id", "nuban", "phone_ng", "card_pan", "email", "person_name", "amount_ngn", "date", "payment_ref"];
const SAMPLE = 'level=error msg="transfer failed" account=0123456789 bvn=22123456789 phone=+2348031234567 amount=N250,000 name="Chioma Okafor"';

const SOURCE: Record<string, string> = { otlp: "OpenTelemetry Collector", fluentbit: "Fluent Bit", vector: "Vector", http: "HTTP" };

interface Pipeline { id: string; vault_id: string; name: string; source_type: string; destination: string; upstream_url: string; mode: string; failure_mode: string; action_per_type: Record<string, string>; entity_types: string[]; sensitive_paths: string[]; transfer_basis: string; setup: string; sparkline: { day: string; count: number }[] }

function PipelineCard({ p, reload }: { p: Pipeline; reload: () => void }) {
  const [tab, setTab] = useState<"rules" | "preview" | "setup">("rules");
  const [sample, setSample] = useState(SAMPLE);
  const [after, setAfter] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const update = async (patch: object) => {
    setError(null);
    try {
      await control(`/v1/log-pipelines/${p.id}`, { method: "PATCH", body: patch });
      reload();
    } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
  };
  return (
    <div className="card">
      <div className="spread">
        <div><h2>{p.name}</h2><span className="small muted">{tr("From")} {SOURCE[p.source_type] ?? p.source_type} to {p.destination}</span></div>
        <div className="row">
          <Sparkline points={p.sparkline} />
          <Badge tone={p.mode === "enforcing" ? "good" : "warn"}>{modeLabel(p.mode)}</Badge>
          {p.mode === "shadow" ? <button className="primary" onClick={() => setConfirm(true)}>{tr("Turn protection on")}</button> : <button onClick={() => setConfirm(true)}>{tr("Back to watch only")}</button>}
        </div>
      </div>
      <div className="tabs">
        {(["rules", "preview", "setup"] as const).map((t) => <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>{{ rules: "Rules", preview: "Before and after", setup: "Setup" }[t]}</button>)}
      </div>
      {tab === "rules" && (
        <div className="stack">
          <div className="tablewrap" style={{ maxHeight: 340 }}>
            <table>
              <thead><tr><th>{tr("Type of data")}</th><th>{tr("What to do with it")}</th></tr></thead>
              <tbody>
                {ENTITIES.filter((e) => p.entity_types.includes(e)).map((e) => (
                  <tr key={e}>
                    <td><div className="font-medium">{entityLabel(e)}</div>{entityLabel(e) !== e && <code className="text-xs text-muted-foreground">{e}</code>}</td>
                    <td>
                      <select aria-label={tr("Action for {0}", { 0: e })} value={p.action_per_type[e] ?? (e === "card_pan" ? "mask" : "tokenize")} onChange={(ev) => update({ action_per_type: { ...p.action_per_type, [e]: ev.target.value } })}>
                        {e !== "card_pan" && <option value="tokenize">{tr("Tokenize")}</option>}
                        <option value="mask">{tr("Mask")}</option><option value="drop">{tr("Drop the line")}</option><option value="pass">{tr("Pass and count")}</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <label className="field" style={{ maxWidth: 420 }}><span>{tr("If the vault is unreachable")}</span>
            <select value={p.failure_mode} onChange={(e) => update({ failure_mode: e.target.value })}><option value="buffer">{tr("Buffer in your collector and retry")}</option><option value="drop">{tr("Drop the logs")}</option></select>
          </label>
          <label className="field" style={{ maxWidth: 420 }}><span>{tr("Legal ground for sending this data abroad (recorded in the residency report)")}</span>
            <select value={p.transfer_basis} onChange={(e) => update({ transfer_basis: e.target.value })}>
              <option value="not_assessed">{tr("Not assessed yet")}</option><option value="tokens_only">{tr("Tokens only: counsel advises no personal data leaves")}</option><option value="adequacy">{tr("Adequacy decision")}</option><option value="approved_instrument">{tr("Instrument approved by your data protection authority")}</option><option value="section_43">{tr("Another lawful ground for transfer")}</option>
            </select>
          </label>
          <label className="row small"><input type="checkbox" checked={p.entity_types.includes("payment_ref")} onChange={(e) => update({ entity_types: e.target.checked ? [...p.entity_types, "payment_ref"] : p.entity_types.filter((x) => x !== "payment_ref") })} />{tr("Also treat payment references as sensitive. Some regulators count them as payment data; check what yours says.")}</label>
          <p className="small muted">{tr("Unredacted logs are never forwarded when protecting, in either case. Card numbers are never vaulted.")}</p>
          <label className="field"><span>{tr("Always-sensitive JSON paths, one per line, as")} <code>{tr("$.customer.bvn:bvn")}</code></span>
            <textarea className="code" defaultValue={p.sensitive_paths.join("\n")} onBlur={(e) => { const next = e.target.value.split("\n").map((s) => s.trim()).filter(Boolean); if (next.join() !== p.sensitive_paths.join()) update({ sensitive_paths: next }); }} />
          </label>
        </div>
      )}
      {tab === "preview" && (
        <div className="stack">
          <label className="field"><span>{tr("Paste a sample line. Use synthetic data.")}</span><textarea className="code" value={sample} onChange={(e) => setSample(e.target.value)} /></label>
          <div className="row"><button className="primary" onClick={async () => {
            setError(null);
            try {
              const r = await control("/v1/log-pipelines/preview", { body: { sample, action_per_type: p.action_per_type, entity_types: p.entity_types, sensitive_paths: p.sensitive_paths, vault_id: p.vault_id } });
              setAfter(r.after);
            } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
          }}>{tr("Show what would be forwarded")}</button></div>
          {after !== null && <><span className="small muted">{tr("Forwarded once protection is on. Tokens here are examples; nothing was stored.")}</span><pre className="pre">{after}</pre></>}
        </div>
      )}
      {tab === "setup" && (
        <div className="stack">
          <div className="spread"><span className="small muted">{tr("Forwards to")} <code>{p.upstream_url}</code></span><Copy text={p.setup} /></div>
          <pre className="pre">{p.setup}</pre>
          <div className="row"><button onClick={async () => { const r = await control(`/v1/log-pipelines/${p.id}/rotate-key`, { method: "POST" }); setNewKey(r.ingest_key); }}>{tr("Rotate pipeline key")}</button></div>
          {newKey && <div className="note warn">{tr("New key, shown once:")} <code style={{ overflowWrap: "anywhere" }}>{newKey}</code></div>}
        </div>
      )}
      <ErrorLine error={error} />
      {confirm && (
        <TypedConfirm title={p.mode === "shadow" ? tr("Turn protection on") : tr("Go back to watch only")} word={p.mode === "shadow" ? "protect" : "watch"} onClose={() => setConfirm(false)} onConfirm={() => update({ mode: p.mode === "shadow" ? "enforcing" : "shadow" })}>
          {p.mode === "shadow" ? tr("From now on, identifiers are replaced before logs leave. Check the before and after tab with your own formats first.") : tr("Logs will again pass through unredacted, and the residency report will show this.")}
        </TypedConfirm>
      )}
    </div>
  );
}

function NewPipeline({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [f, setF] = useState({ vault_id: "", name: "", source_type: "otlp", destination: "", upstream_url: "" });
  const [created, setCreated] = useState<{ ingest_key: string; setup: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  if (created) {
    return (
      <Modal title={tr("Connected, watching only")} onClose={onDone}>
        <p className="muted">{tr("Add these settings to your log collector. Logs pass through unchanged until you turn protection on.")}</p>
        <ShownOnce items={[{ label: tr("Collector settings"), value: created.setup, block: true }]} />
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onDone}>{tr("Done")}</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={tr("Connect logs")} onClose={onClose}>
      <label className="field"><span>{tr("Vault")}</span><select value={f.vault_id} onChange={set("vault_id")}><option value="">{tr("Choose a vault")}</option>{vaults.value?.vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
      <label className="field"><span>{tr("Name")}</span><input value={f.name} onChange={set("name")} /></label>
      <label className="field"><span>{tr("Source")}</span><select value={f.source_type} onChange={set("source_type")}><option value="otlp">{tr("OpenTelemetry Collector")}</option><option value="fluentbit">{tr("Fluent Bit")}</option><option value="vector">{tr("Vector")}</option></select></label>
      <label className="field"><span>{tr("Destination name")}</span><input placeholder={tr("Datadog")} value={f.destination} onChange={set("destination")} /></label>
      <label className="field"><span>{tr("Destination URL")}</span><input placeholder={tr("https://…")} value={f.upstream_url} onChange={set("upstream_url")} /></label>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!f.vault_id || !f.name || !f.destination || !f.upstream_url} onClick={async () => {
          try { setCreated(await control("/v1/log-pipelines", { body: f })); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Create")}</button>
      </div>
    </Modal>
  );
}

export default function Pipelines() {
  const { value, error, loading, reload } = useLoad<{ pipelines: Pipeline[] }>(() => control("/v1/log-pipelines"));
  const [creating, setCreating] = useState(false);
  const [view, setView] = useState<"all" | "logs" | "ai" | "proxy" | "support">("all");
  const [adding, setAdding] = useState(false);
  const [startNew, setStartNew] = useState(false);
  // The Connect catalogue sends people straight to the right form.
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const tab = q.get("tab");
    if (tab === "logs" || tab === "ai" || tab === "proxy" || tab === "support") setView(tab);
    if (q.get("new")) { if (!tab || tab === "logs") { setView("logs"); setCreating(true); } else setStartNew(true); }
  }, []);
  return (
    <Page title={tr("Connections")} sub={tr("Everything that sends data through Onshore on its way out.")} actions={<button className="primary" onClick={() => setAdding(true)}>{tr("Add a connection")}</button>}>
      <div className="tabs">
        {(["all", "logs", "ai", "proxy", "support"] as const).map((t) => <button key={t} className={view === t ? "on" : ""} onClick={() => setView(t)}>{{ all: "All", logs: "Logs", ai: "AI", proxy: "Web APIs", support: "Support tools" }[t]}</button>)}
        <Link className="tab-link" href="/page-protection">{tr("Page protection")}</Link>
      </div>
      {view === "all" && <ConnectionsOverview onOpen={(t) => setView(t as typeof view)} />}
      {adding && <ConnectCatalog onClose={() => setAdding(false)} />}
      {view === "ai" && <AiRoutes startNew={startNew} />}
      {view === "proxy" && <ProxyRoutes startNew={startNew} />}
      {view === "support" && <SupportTools startNew={startNew} />}
      {view === "logs" && <>
      <Loading error={error} loading={loading && !value} />
      {value?.pipelines.length === 0 && <Empty title={tr("No log connections yet")} action={<button className="primary" onClick={() => setCreating(true)}>{tr("Connect logs")}</button>}>{tr("It starts as watch only: it counts what would have left the country, and changes nothing.")}</Empty>}
      <div className="stack">{value?.pipelines.map((p) => <PipelineCard key={p.id} p={p} reload={reload} />)}</div>
      {creating && <NewPipeline onClose={() => setCreating(false)} onDone={() => { setCreating(false); reload(); }} />}
      </>}
    </Page>
  );
}
