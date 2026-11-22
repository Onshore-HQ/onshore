"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, Checks, ErrorLine, Modal, ShownOnce, TypedConfirm } from "@/components/ui";
import { control, useLoad, when } from "@/lib/api";
import { saveFile } from "@/lib/csv";

interface Step { type: string; name: string; action: string; note?: string; shown_once?: Record<string, string> }
const WORD: Record<string, [string, "good" | "info" | "warn" | "bad" | ""]> = { create: ["Will add", "info"], update: ["Will update", "info"], same: ["No change", ""], skip: ["Won't change", "warn"], failed: ["Failed", "bad"] };
const DONE: Record<string, string> = { create: "Added", update: "Updated" };

/** Move a tested setup to another vault. A file holds no keys, secrets, people or customer data. */
export function MoveSetupCard() {
  const vaults = useLoad<{ vaults: { id: string; name: string; environment: string }[] }>(() => control("/v1/vaults"));
  const list = vaults.value?.vaults ?? [];
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [config, setConfig] = useState<unknown>(null);
  const [fileName, setFileName] = useState("");
  const [plan, setPlan] = useState<Step[] | null>(null);
  const [applied, setApplied] = useState<Step[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const src = from || list[0]?.id || "";
  const dst = to || list[0]?.id || "";
  const run = async (dry_run: boolean) => {
    setBusy(true); setErr(null);
    try {
      const r = await control<{ steps: Step[] }>("/v1/config/import", { body: { vault_id: dst, dry_run, config } });
      if (dry_run) setPlan(r.steps); else { setApplied(r.steps); setPlan(null); }
    } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } finally { setBusy(false); }
  };
  const steps = applied ?? plan;
  const secrets = (applied ?? []).filter((s) => s.shown_once);
  const changes = (plan ?? []).filter((s) => s.action === "create" || s.action === "update").length;
  return (
    <>
      <div className="card">
        <h2>{tr("Copy setup from a file")}</h2>
        <p className="small muted">{tr("Test your setup in one vault, then copy it to another. The file holds fields, data types, access rules, networks and connections. It never holds keys, secrets, people or customer data.")}</p>
        <ErrorLine error={err} />
        <h3>{tr("Export")}</h3>
        <div className="row">
          <select aria-label={tr("Vault to export")} value={src} onChange={(e) => setFrom(e.target.value)}>{list.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
          <button disabled={!src} onClick={async () => { setErr(null); try { const c = await control(`/v1/config/export?vault_id=${src}`); saveFile([JSON.stringify(c, null, 2)], "onshore-setup.json", "application/json"); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } }}>{tr("Download setup file")}</button>
        </div>
        <h3>{tr("Import")}</h3>
        <div className="row">
          <select aria-label={tr("Vault to import into")} value={dst} onChange={(e) => { setTo(e.target.value); setPlan(null); setApplied(null); }}>{list.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
          <input type="file" aria-label={tr("Setup file")} accept=".json,application/json" onChange={async (e) => {
            const f = e.target.files?.[0]; setPlan(null); setApplied(null); setErr(null);
            if (!f) return;
            try { setConfig(JSON.parse(await f.text())); setFileName(f.name); } catch { setConfig(null); setErr("That file isn't valid JSON."); }
          }} />
          <button disabled={!config || busy} onClick={() => run(true)}>{tr("See what would change")}</button>
        </div>
        <p className="small muted">{tr("Nothing goes live by itself. Access rules become drafts for a second person to publish, and new connections start as watch only. A live connection is never redirected or weakened.")}</p>
        {steps && (
          <>
            <h3>{applied ? tr("What happened") : tr("What importing {0} would do", { 0: fileName })}</h3>
            <div className="tablewrap" style={{ maxHeight: 360 }}>
              <table>
                <thead><tr><th>{tr("Item")}</th><th>{tr("Name")}</th><th>{tr("Result")}</th><th>{tr("Note")}</th></tr></thead>
                <tbody>{steps.map((s, i) => <tr key={i}><td className="small">{s.type}</td><td className="small"><code>{s.name}</code></td><td><Badge tone={WORD[s.action]?.[1] ?? ""}>{applied ? DONE[s.action] ?? WORD[s.action]?.[0] : WORD[s.action]?.[0]}</Badge></td><td className="small muted">{s.note}</td></tr>)}</tbody>
              </table>
            </div>
            {plan && <div className="row"><button className="primary" disabled={busy || changes === 0} onClick={() => run(false)}>{changes === 0 ? tr("Nothing to change") : tr("Apply {0} change{1}", { 0: changes, 1: changes === 1 ? "" : "s" })}</button></div>}
          </>
        )}
        {secrets.length > 0 && <ShownOnce items={secrets.flatMap((s) => Object.entries(s.shown_once!).map(([k, v]) => ({ label: `${s.name}: ${k}`, value: v, block: v.includes("\n") })))} />}
      </div>
      <ApiKeysCard />
    </>
  );
}

function ApiKeysCard() {
  const keys = useLoad<{ keys: any[] }>(() => control("/v1/api-keys"));
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ name: "", scopes: ["export", "import"], days: "90" });
  const [made, setMade] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const close = () => { setAdding(false); setMade(null); setErr(null); setF({ name: "", scopes: ["export", "import"], days: "90" }); keys.reload(); };
  return (
    <div className="card">
      <div className="spread"><h2>{tr("Keys for pipelines")}</h2><button onClick={() => setAdding(true)}>{tr("New key")}</button></div>
      <p className="small muted">{tr("Let a CI/CD pipeline export or import setup. A key can do only that, and acts as you, so it stops working if you lose your admin role. It can't read customer data.")}</p>
      {keys.value?.keys.length === 0 ? <p className="small muted">{tr("No keys yet.")}</p> : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Name")}</th><th>{tr("Can")}</th><th>{tr("Expires")}</th><th>{tr("Last used")}</th><th></th></tr></thead>
            <tbody>{keys.value?.keys.map((k) => (
              <tr key={k.id}><td className="small">{k.name}</td><td className="small">{k.scopes.map((s: string) => s.replace("config:", "")).join(", ")}</td><td className="small">{k.expires_at ? when(k.expires_at) : tr("Never")}</td><td className="small">{k.last_used_at ? when(k.last_used_at) : tr("Never")}</td>
                <td>{k.revoked_at ? <Badge>{tr("Revoked")}</Badge> : <button onClick={() => setRevoking(k.id)}>{tr("Revoke")}</button>}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {adding && (
        <Modal title={made ? tr("Key created") : tr("New key for a pipeline")} onClose={close}>
          {made ? (
            <>
              <ShownOnce items={[{ label: "Key", value: made }]} />
              <pre className="pre">{`curl -H "Authorization: Bearer $ONSHORE_KEY" \\\n  "${window.location.origin}/control/v1/config/export?vault_id=VAULT_ID"`}</pre>
              <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={close}>{tr("Done")}</button></div>
            </>
          ) : (
            <>
              <label className="field"><span>{tr("Name")}</span><input autoFocus placeholder="staging-to-live" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
              <div className="field"><span>{tr("What it can do")}</span><Checks options={["export", "import"]} value={f.scopes} onChange={(scopes) => setF({ ...f, scopes })} /></div>
              <label className="field"><span>{tr("Expires")}</span><select value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })}><option value="30">{tr("In 30 days")}</option><option value="90">{tr("In 90 days")}</option><option value="365">{tr("In a year")}</option><option value="">{tr("Never")}</option></select></label>
              <ErrorLine error={err} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={close}>{tr("Cancel")}</button><button className="primary" disabled={!f.name || !f.scopes.length} onClick={async () => { try { const r = await control("/v1/api-keys", { body: { name: f.name, scopes: f.scopes.map((s) => `config:${s}`), expires_in_days: f.days ? Number(f.days) : null } }); setMade(r.key); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } }}>{tr("Create key")}</button></div>
            </>
          )}
        </Modal>
      )}
      {revoking && <TypedConfirm title={tr("Revoke this key?")} word="revoke" onClose={() => setRevoking(null)} onConfirm={async () => { await control(`/v1/api-keys/${revoking}/revoke`, { method: "POST" }); keys.reload(); }}>{tr("Anything using it stops working straight away.")}</TypedConfirm>}
    </div>
  );
}
