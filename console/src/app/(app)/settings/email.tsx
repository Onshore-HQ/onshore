"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { Badge, ErrorLine, Loading, TypedConfirm } from "@/components/ui";
import { control, useLoad, when } from "@/lib/api";

const PORTS: Record<string, number> = { starttls: 587, tls: 465, none: 25 };

/** Onshore sends through the organisation's own mail server. There is no Onshore mail service. */
export function EmailCard() {
  const s = useLoad(() => control("/v1/settings/mail"));
  const [f, setF] = useState({ host: "", port: 587, tls_mode: "starttls", username: "", password: "", from_address: "", from_name: "Onshore", console_url: "", alerts_enabled: true });
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(false);
  useEffect(() => {
    const v = s.value;
    if (v?.configured) setF({ host: v.host, port: v.port, tls_mode: v.tls_mode, username: v.username ?? "", password: "", from_address: v.from_address, from_name: v.from_name, console_url: v.console_url, alerts_enabled: v.alerts_enabled });
    else if (v) setF((x) => ({ ...x, console_url: window.location.origin }));
  }, [s.value]);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const save = async () => {
    await control("/v1/settings/mail", { method: "PUT", body: { ...f, port: Number(f.port), username: f.username || null, password: f.password || undefined } });
    setF((x) => ({ ...x, password: "" }));
    s.reload();
  };
  const run = async (fn: () => Promise<string>) => {
    setBusy(true); setErr(null); setMsg(null);
    try { setMsg(await fn()); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } finally { setBusy(false); }
  };
  const v = s.value;
  return (
    <div className="card">
      <div className="spread">
        <h2>{tr("Email")}</h2>
        {v?.configured ? (v.verified_at ? <Badge tone="good">{tr("Working, tested")} {when(v.verified_at)}</Badge> : <Badge tone="warn">{tr("Not tested yet")}</Badge>) : <Badge>{tr("Not set up")}</Badge>}
      </div>
      <p className="small muted">{tr("Invitations, password resets and alerts go through your own mail server. These emails hold staff names and links, and never customer data. Use a server in the same country as your vaults if your policy asks for it.")}</p>
      <Loading error={s.error} loading={s.loading && !v} />
      {msg && <div className="note good">{msg}</div>}
      <ErrorLine error={err} />
      <div className="row flex-wrap items-end">
        <label className="field min-w-56 flex-1"><span>{tr("Mail server")}</span><input placeholder="smtp.yourbank.example" value={f.host} onChange={set("host")} /></label>
        <label className="field w-48"><span>{tr("Security")}</span>
          <select value={f.tls_mode} onChange={(e) => setF({ ...f, tls_mode: e.target.value, port: PORTS[e.target.value]!, ...(e.target.value === "none" ? { username: "", password: "" } : {}) })}>
            <option value="starttls">{tr("STARTTLS (usual)")}</option><option value="tls">{tr("TLS from the start")}</option><option value="none">{tr("None, internal relay only")}</option>
          </select>
        </label>
        <label className="field w-24"><span>{tr("Port")}</span><input type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></label>
      </div>
      {f.tls_mode === "none" && <div className="note warn small">{tr("Without a secure connection, anyone on the network between Onshore and your relay can read these emails, including their sign-in links.")}</div>}
      {f.tls_mode !== "none" && (
        <div className="row flex-wrap">
          <label className="field min-w-56 flex-1"><span>{tr("Username (optional)")}</span><input autoComplete="off" value={f.username} onChange={set("username")} /></label>
          <label className="field min-w-56 flex-1"><span>{tr("Password")}{v?.has_password ? tr(", leave empty to keep it") : ""}</span><input type="password" autoComplete="new-password" value={f.password} onChange={set("password")} /></label>
        </div>
      )}
      <div className="row flex-wrap">
        <label className="field min-w-56 flex-1"><span>{tr("Send from")}</span><input type="email" placeholder={tr("onshore@yourbank.example")} value={f.from_address} onChange={set("from_address")} /></label>
        <label className="field min-w-56 flex-1"><span>{tr("Sender name")}</span><input value={f.from_name} onChange={set("from_name")} /></label>
      </div>
      <label className="field"><span>{tr("This console's address, used in email links")}</span><input type="url" value={f.console_url} onChange={set("console_url")} /></label>
      <label className="row small"><input type="checkbox" checked={f.alerts_enabled} onChange={(e) => setF({ ...f, alerts_enabled: e.target.checked })} />{tr("Email new alerts to admins and DPOs")}</label>
      <div className="row">
        <button className="primary" disabled={busy || !f.host || !f.from_address || !f.console_url} onClick={() => run(async () => { await save(); return "Saved. Send a test to check it works."; })}>{tr("Save")}</button>
        <button disabled={busy || !v?.configured} onClick={() => run(async () => { const r = await control("/v1/settings/mail/test", { method: "POST" }); s.reload(); return tr("Test email sent to {0}.", { 0: r.sent_to }); })}>{tr("Send a test")}</button>
        {v?.configured && <button className="link" onClick={() => setRemoving(true)}>{tr("Remove")}</button>}
      </div>
      {removing && <TypedConfirm title={tr("Stop sending email?")} word="remove" onClose={() => setRemoving(false)} onConfirm={async () => { await control("/v1/settings/mail", { method: "DELETE" }); setF((x) => ({ ...x, host: "", username: "", password: "", from_address: "" })); s.reload(); }}>{tr("Invitations and resets will give you a link to pass on instead, and people won't be able to reset their own passwords.")}</TypedConfirm>}
    </div>
  );
}
