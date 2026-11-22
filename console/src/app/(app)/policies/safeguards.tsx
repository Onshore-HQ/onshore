"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { useMe } from "@/components/Shell";
import { Badge, ErrorLine } from "@/components/ui";
import { control, day, useLoad, when } from "@/lib/api";
import { Person } from "@/lib/people";

export function Networks() {
  const nets = useLoad<{ networks: { id: string; name: string; cidrs: string[] }[] }>(() => control("/v1/networks"));
  const [net, setNet] = useState({ name: "", cidrs: "" });
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } };
  return (
    <div className="card">
      <h2>{tr("Approved networks")}</h2>
      <p className="small muted">{tr("Your office ranges, the company VPN's exit addresses, or private links. Access rules can require someone to be on one of these. Looking up a country from an IP address is easy to fool with a VPN, so Onshore doesn't rely on it.")}</p>
      <ErrorLine error={error} />
      {nets.value?.networks.map((x) => (
        <div key={x.id} className="spread small"><span><code>{x.name}</code>: {x.cidrs.join(", ")}</span><button className="link" onClick={() => act(async () => { await control(`/v1/networks/${x.id}`, { method: "DELETE" }); nets.reload(); })}>{tr("Remove")}</button></div>
      ))}
      <div className="row">
        <input aria-label={tr("Network name")} placeholder="lagos_office" value={net.name} onChange={(e) => setNet({ ...net, name: e.target.value })} />
        <input aria-label={tr("CIDR ranges")} placeholder="102.89.0.0/24, 41.58.0.0/24" style={{ minWidth: 260 }} value={net.cidrs} onChange={(e) => setNet({ ...net, cidrs: e.target.value })} />
        <button disabled={!net.name || !net.cidrs} onClick={() => act(async () => { await control("/v1/networks", { body: { name: net.name, cidrs: net.cidrs.split(",").map((s) => s.trim()).filter(Boolean) } }); setNet({ name: "", cidrs: "" }); nets.reload(); })}>{tr("Add network")}</button>
      </div>
    </div>
  );
}

export function EmergencyAccess() {
  const me = useMe();
  const grants = useLoad<{ grants: any[] }>(() => control("/v1/break-glass"));
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [bg, setBg] = useState({ vault_id: "", reason: "", duration_minutes: 30 });
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } };
  return (
    <div className="card">
      <h2>{tr("Emergency access")}</h2>
      <p className="small muted">{tr("Extra permission for a short time during an incident, sometimes called break-glass. A second person must approve it, it ends by itself, and every report flags it.")}</p>
      <ErrorLine error={error ?? grants.error} />
      <div className="row">
        <select aria-label={tr("Vault")} value={bg.vault_id} onChange={(e) => setBg({ ...bg, vault_id: e.target.value })}><option value="">{tr("Choose a vault")}</option>{vaults.value?.vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
        <input aria-label={tr("Reason")} placeholder={tr("Reason, e.g. incident 412")} style={{ minWidth: 240 }} value={bg.reason} onChange={(e) => setBg({ ...bg, reason: e.target.value })} />
        <label className="row small"><input aria-label={tr("Minutes")} type="number" min={5} max={240} style={{ width: 70 }} value={bg.duration_minutes} onChange={(e) => setBg({ ...bg, duration_minutes: Number(e.target.value) })} /> minutes</label>
        <button disabled={!bg.vault_id || bg.reason.length < 5} onClick={() => act(async () => { await control("/v1/break-glass", { body: bg }); setBg({ ...bg, reason: "" }); grants.reload(); })}>{tr("Request for myself")}</button>
      </div>
      {grants.value?.grants.map((g) => (
        <div key={g.id} className="spread small">
          <span className="row"><Badge tone={g.status === "active" ? "warn" : g.status === "pending" ? "info" : ""}>{g.status}</Badge><Person id={g.requested_by} />: {g.reason}, {g.duration_minutes} {tr("min,")} {day(g.created_at)}{g.expires_at ? tr(", expires {0}", { 0: when(g.expires_at) }) : ""}</span>
          <span className="row">
            {g.status === "pending" && g.requested_by !== me?.id && <><button onClick={() => act(async () => { await control(`/v1/break-glass/${g.id}/approve`, { method: "POST" }); grants.reload(); })}>{tr("Approve")}</button><button onClick={() => act(async () => { await control(`/v1/break-glass/${g.id}/deny`, { method: "POST" }); grants.reload(); })}>{tr("Deny")}</button></>}
            {g.status === "pending" && g.requested_by === me?.id && <span className="faint">{tr("Needs a second approver")}</span>}
            {g.status === "active" && <button className="danger" onClick={() => act(async () => { await control(`/v1/break-glass/${g.id}/revoke`, { method: "POST" }); grants.reload(); })}>{tr("Revoke")}</button>}
          </span>
        </div>
      ))}
    </div>
  );
}
