"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, Empty, ErrorLine, Loading, Modal, TypedConfirm, ShownOnce } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { modeLabel } from "@/lib/labels";

const KINDS: Record<string, { label: string; url: string; token: string }> = {
  freshdesk: { label: "Freshdesk", url: "https://yourdomain.freshdesk.com", token: "API key" },
  intercom: { label: "Intercom", url: "https://api.intercom.io", token: "Access token" },
  zoho_desk: { label: "Zoho Desk", url: "https://desk.zoho.com", token: "OAuth token" },
  salesforce: { label: "Salesforce Service Cloud", url: "https://yourorg.my.salesforce.com", token: "OAuth access token" },
};

function NewAdapter({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [f, setF] = useState({ vault_id: "", name: "", kind: "freshdesk", base_url: KINDS.freshdesk!.url, token: "", client_secret: "", admin_id: "", org_id: "" });
  const [made, setMade] = useState<{ webhook_url: string; webhook_secret?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  if (made) {
    return (
      <Modal title={tr("Connected, watching only")} onClose={onDone}>
        <p className="muted">{tr("Point the tool's webhook at this address.")}{made.webhook_secret ? tr(" Send the secret in the X-RV-Webhook-Secret header.") : ""}</p>
        <ShownOnce items={[{ label: tr("Webhook address"), value: made.webhook_url }, ...(made.webhook_secret ? [{ label: tr("Webhook secret"), value: made.webhook_secret }] : [])]} />
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onDone}>{tr("Done")}</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={tr("Connect a support tool")} onClose={onClose}>
      <label className="field"><span>{tr("Vault")}</span><select value={f.vault_id} onChange={set("vault_id")}><option value="">{tr("Choose a vault")}</option>{vaults.value?.vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
      <label className="field"><span>{tr("Name")}</span><input value={f.name} onChange={set("name")} /></label>
      <label className="field"><span>{tr("Tool")}</span><select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value, base_url: KINDS[e.target.value]!.url })}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select></label>
      <label className="field"><span>{tr("Base URL")}</span><input value={f.base_url} onChange={set("base_url")} /></label>
      <label className="field"><span>{KINDS[f.kind]!.token}</span><input type="password" value={f.token} onChange={set("token")} /></label>
      {f.kind === "intercom" && <>
        <label className="field"><span>{tr("App client secret, which signs webhooks")}</span><input type="password" value={f.client_secret} onChange={set("client_secret")} /></label>
        <label className="field"><span>{tr("Admin ID for notes")}</span><input value={f.admin_id} onChange={set("admin_id")} /></label>
      </>}
      {f.kind === "zoho_desk" && <label className="field"><span>{tr("Organisation ID")}</span><input value={f.org_id} onChange={set("org_id")} /></label>}
      <div className="note warn small">{tr("Not yet tested against a live")} {KINDS[f.kind]!.label} {tr("account. Try it as watch only and on a test ticket first.")}</div>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!f.vault_id || !f.name || !f.token} onClick={async () => {
          try { setMade(await control("/v1/adapters", { body: { ...f, client_secret: f.client_secret || undefined, admin_id: f.admin_id || undefined, org_id: f.org_id || undefined } })); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Connect")}</button>
      </div>
    </Modal>
  );
}

export function SupportTools({ startNew = false }: { startNew?: boolean }) {
  const { value, error, loading, reload } = useLoad<{ adapters: { id: string; name: string; kind: string; mode: string }[] }>(() => control("/v1/adapters"));
  const [adding, setAdding] = useState(startNew);
  const [toggle, setToggle] = useState<{ id: string; mode: string } | null>(null);
  return (
    <div className="stack">
      <p className="small muted">{tr("Tickets arrive by webhook, and tokenized text is written back. A ticket already passed through the tool once on arrival, so this protects what stays there afterwards, not the first delivery.")}</p>
      <div className="row"><button className="primary" onClick={() => setAdding(true)}>{tr("Connect a support tool")}</button></div>
      <Loading error={error} loading={loading && !value} />
      {value?.adapters.length === 0 && <Empty title={tr("No support tools connected")}>{tr("Connect one to stop customers' BVNs and card numbers reaching tickets and chats held abroad.")}</Empty>}
      {value?.adapters.map((a) => (
        <div className="card" key={a.id}>
          <div className="spread">
            <div><h2>{a.name}</h2><span className="small muted">{KINDS[a.kind]?.label}</span></div>
            <div className="row"><Badge tone={a.mode === "enforcing" ? "good" : "warn"}>{modeLabel(a.mode)}</Badge><button onClick={() => setToggle(a)}>{a.mode === "shadow" ? tr("Turn protection on") : tr("Back to watch only")}</button></div>
          </div>
        </div>
      ))}
      {adding && <NewAdapter onClose={() => setAdding(false)} onDone={() => { setAdding(false); reload(); }} />}
      {toggle && <TypedConfirm title={tr("Change mode")} word={toggle.mode === "shadow" ? "protect" : "watch"} onClose={() => setToggle(null)} onConfirm={async () => { await control(`/v1/adapters/${toggle.id}`, { method: "PATCH", body: { mode: toggle.mode === "shadow" ? "enforcing" : "shadow" } }); reload(); }}>{toggle.mode === "shadow" ? tr("Ticket text will be overwritten with tokens in the support tool. This cannot be undone from here.") : tr("Tickets will stay as written, and only be counted.")}</TypedConfirm>}
    </div>
  );
}
