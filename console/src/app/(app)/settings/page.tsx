"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { Badge, ErrorLine, Loading, Page } from "@/components/ui";
import { control, day, useLoad } from "@/lib/api";
import { EmailCard } from "./email";
import { LocationsCard } from "./locations";
import { MoveSetupCard } from "./setup";
import { SsoCard } from "./sso";
import { GroupRolesCard, LdapCard, ScimCard, type Identity } from "./identity";
import { TwoFactorCard } from "./two-factor";

export default function Settings() {
  const { value, error, loading, reload } = useLoad(() => control("/v1/settings"));
  const [t, setT] = useState({ name: "", hosting_facility: "", hosting_country: "" });
  const [pw, setPw] = useState({ current: "", next: "" });
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [siem, setSiem] = useState<string | null>(null);
  const [tab, setTab] = useState<"org" | "locations" | "signin" | "email" | "setup" | "audit">("org");
  useEffect(() => { const t = new URLSearchParams(window.location.search).get("tab"); if (t === "locations" || t === "signin" || t === "email" || t === "setup" || t === "audit") setTab(t); }, []);
  useEffect(() => {
    if (value?.tenant) setT({ name: value.tenant.name ?? "", hosting_facility: value.tenant.hosting_facility ?? "", hosting_country: value.tenant.hosting_country ?? "" });
  }, [value]);
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setErr(null); setMsg(null);
    try { await fn(); setMsg(done); reload(); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); }
  };
  return (
    <Page title={tr("Settings")} sub={tr("Your organisation, where your data lives and which laws apply, how people sign in, email, and how long audit records are kept.")}>
      <Loading error={error} loading={loading && !value} />
      <div className="stack" style={{ maxWidth: 720 }}>
        {msg && <div className="note good">{msg}</div>}
        <ErrorLine error={err} />
        <div className="tabs" role="tablist">
          {([["org", tr("Organisation")], ["locations", tr("Locations and laws")], ["signin", tr("Sign-in")], ["email", tr("Email")], ["setup", tr("Copy setup")], ["audit", tr("Audit records")]] as const).map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
        </div>
        {tab === "org" && <>
        <div className="card">
          <h2>{tr("Organisation and hosting")}</h2>
          <p className="small muted">{tr("The facility appears in the residency report as stated here. Record the real one.")}</p>
          <label className="field"><span>{tr("Organisation")}</span><input value={t.name} onChange={(e) => setT({ ...t, name: e.target.value })} /></label>
          <label className="field"><span>{tr("Hosting facility")}</span><input placeholder={tr("Facility name and city")} value={t.hosting_facility} onChange={(e) => setT({ ...t, hosting_facility: e.target.value })} /></label>
          <p className="small m-0">{tr("Country:")} <b>{t.hosting_country || tr("not set yet")}</b>. <span className="muted">{tr("Set when this install was installed, and fixed: every vault on it keeps data there. See")} <button type="button" className="link" onClick={() => setTab("locations")}>{tr("Locations and laws")}</button>.</span></p>
          <div className="row"><button className="primary" onClick={() => run(() => control("/v1/settings", { method: "PATCH", body: { name: t.name, hosting_facility: t.hosting_facility } }), "Saved.")}>{tr("Save")}</button></div>
        </div>
        <div className="card">
          <h2>{tr("Licence")}</h2>
          {value?.licence ? (value.licence.valid === false ? <Badge tone="bad">{tr("licence signature is invalid")}</Badge> : <div className="row"><Badge tone={value.licence.expired ? "warn" : "good"}>{value.licence.expired ? tr("expired") : tr("valid")}</Badge><span className="small">{value.licence.customer}{tr(", until")} {day(value.licence.expires_at)}. {value.licence.expired ? tr("The product keeps running; upgrades stop.") : ""}</span></div>) : <p className="small muted">{tr("No licence is recorded here. Hosted accounts do not need one; self-hosted installs set it with")} <code>{tr("rv init --license")}</code>.</p>}
        </div>
        </>}
        {tab === "signin" && <>
        <div className="card">
          <h2>{tr("Change password")}</h2>
          <label className="field"><span>{tr("Current password")}</span><input type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></label>
          <label className="field"><span>{tr("New password, at least 12 characters")}</span><input type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></label>
          <div className="row"><button disabled={pw.next.length < 12} onClick={() => run(async () => { await control("/v1/auth/change-password", { body: pw }); await fetch("/api/session", { method: "DELETE" }); window.location.href = "/login"; }, "Password changed.")}>{tr("Change password")}</button></div>
        </div>
        <TwoFactorCard />
        <IdentityCards />
        </>}
        {tab === "locations" && <LocationsCard />}
        {tab === "email" && <EmailCard />}
        {tab === "setup" && <MoveSetupCard />}
        {tab === "audit" && (
        <div className="card">
          <h2>{tr("Audit retention and SIEM")}</h2>
          <p className="small muted">{tr("Events older than this are removed, and only once a signed checkpoint covers them. A SIEM is your own security monitoring tool, and sending it a copy keeps the log provable outside this database. That copy is itself data leaving Onshore, so point it at a destination in the same country as your vaults.")}</p>
          <label className="field"><span>{tr("Keep audit events for, in days")}</span><input type="number" min={365} defaultValue={value?.tenant?.audit_retention_days ?? 2557} onBlur={(e) => run(() => control("/v1/settings", { method: "PATCH", body: { audit_retention_days: Number(e.target.value) } }), "Retention saved.")} /></label>
          <label className="field"><span>{tr("SIEM endpoint, https")}</span><input defaultValue={value?.tenant?.siem_url ?? ""} onBlur={(e) => { if (e.target.value !== (value?.tenant?.siem_url ?? "")) run(async () => { const r = await control("/v1/settings", { method: "PATCH", body: { siem_url: e.target.value || null } }); if (r.siem_secret) setSiem(r.siem_secret); }, "SIEM endpoint saved."); }} /></label>
          {siem && <div className="note warn small">{tr("Signing secret, shown once. Each batch carries")} <code>{tr("X-RV-Signature: sha256=…")}</code> {tr("over its body:")} <code style={{ overflowWrap: "anywhere" }}>{siem}</code></div>}
        </div>
        )}
      </div>
    </Page>
  );
}

/** Single sign-on, groups and roles, SCIM and LDAP: how the organisation's people get in. */
function IdentityCards() {
  const id = useLoad<Identity>(() => control("/v1/settings/identity"));
  const roles = useLoad<{ roles: string[] }>(() => control("/v1/roles"));
  if (!id.value) return id.error ? null : <Loading error={null} loading />;
  return (
    <>
      {!id.value.allowed && <div className="note small">{tr("Single sign-on and SCIM come with Onshore Business, and LDAP with Enterprise. Groups and roles, passwords and authenticator codes work in every edition.")}</div>}
      <SsoCard allowed={id.value.allowed} />
      <GroupRolesCard id={id.value} roles={roles.value?.roles ?? []} onChange={id.reload} />
      <ScimCard id={id.value} onChange={id.reload} />
      <LdapCard id={id.value} onChange={id.reload} />
    </>
  );
}
