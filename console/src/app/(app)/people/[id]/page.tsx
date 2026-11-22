"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { Badge, DecisionBadge, Loading, Page, TypedConfirm } from "@/components/ui";
import { control, useLoad, when } from "@/lib/api";
import { useMe } from "@/components/Shell";
import { AccountLink, InviteLink } from "../invite-link";
import { Modal } from "@/components/ui";

export default function PersonPage() {
  const { id } = useParams<{ id: string }>();
  const { value: d, error, loading, reload } = useLoad(() => control(`/v1/principals/${id}`), [id]);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [suspending, setSuspending] = useState(false);
  const me = useMe();
  const [confirm, setConfirm] = useState<"password" | "mfa" | null>(null);
  const [sent, setSent] = useState<{ title: string; link?: AccountLink; note: string } | null>(null);
  if (!d) return <Page title={tr("Person")}><Loading error={error} loading={loading} /></Page>;
  const p = d.principal;
  return (
    <Page
      title={p.display_name}
      sub={<>{p.email ?? tr("Service account")} · {p.roles.join(", ")} · <Link href="/people">{tr("Back to people")}</Link></>}
      actions={<><Badge tone={p.status === "active" ? "good" : "bad"}>{p.status}</Badge><button className={p.status === "active" ? "danger" : ""} onClick={() => setSuspending(true)}>{p.status === "active" ? "Suspend" : "Reactivate"}</button></>}
    >
      <div className="stack">
        {p.kind === "user" && p.id !== me?.id && me?.roles.includes("admin") && (
          <div className="card">
            <h2>{tr("Account access")}</h2>
            {p.invite_pending ? (
              <>
                <p className="small muted">{tr("Invited, and hasn't accepted yet.")}</p>
                <div className="row">
                  <button onClick={async () => { const r = await control(`/v1/principals/${id}/invite`, { method: "POST" }); setSent({ title: r.emailed ? "Invitation sent again" : "Pass on this invitation", link: r, note: tr("{0} can use this link once, within 7 days.", { 0: p.display_name }) }); reload(); }}>{tr("Send again")}</button>
                  <button onClick={async () => { await control(`/v1/principals/${id}/invite/revoke`, { method: "POST" }); reload(); }}>{tr("Cancel the invitation")}</button>
                </div>
              </>
            ) : (
              <>
                <p className="small muted">{tr("If")} {p.display_name} {tr("is locked out, or you suspect a compromise.")}</p>
                <div className="row"><button onClick={() => setConfirm("password")}>{tr("Reset password")}</button><button onClick={() => setConfirm("mfa")}>{tr("Reset two-factor")}</button></div>
              </>
            )}
          </div>
        )}
        {d.alerts.filter((a: any) => !a.acknowledged_at).map((a: any) => (
          <div className="note bad" key={a.id}>
            <div className="spread"><span><b>{tr("Reveal spike.")}</b> {a.detail.last_hour} {tr("reveals in an hour, against a usual")} {a.detail.hourly_average}{tr(". Raised")} {when(a.raised_at)}.</span>
            <button onClick={async () => { await control(`/v1/alerts/${a.id}/acknowledge`, { method: "POST" }); reload(); }}>{tr("Acknowledge")}</button></div>
          </div>
        ))}
        <div className="card">
          <h2>{tr("Policies that apply, computed live")}</h2>
          {d.applicable.length === 0 ? <p className="muted">{tr("No published rule names this person or their roles, so everything is denied.")}</p> : (
            <div className="tablewrap">
              <table>
                <thead><tr><th>{tr("Policy")}</th><th>{tr("Rule")}</th><th>{tr("Actions")}</th><th>{tr("Fields")}</th><th>{tr("Networks")}</th><th>{tr("Returns")}</th></tr></thead>
                <tbody>{d.applicable.map((a: any, i: number) => (
                  <tr key={i}><td><code>{a.policy}@v{a.version}</code></td><td><code>{a.rule}</code></td><td className="small">{a.actions.join(", ")}</td><td className="small">{a.what.join(", ") || "all"}</td><td className="small">{a.networks.join(", ") || "any"}</td><td><DecisionBadge value={a.returns} /></td></tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </div>
        {p.kind === "service_account" && (
          <div className="card">
            <h2>{tr("Keys")}</h2>
            <div className="tablewrap">
              <table>
                <thead><tr><th>{tr("Fingerprint")}</th><th>{tr("IP allowlist")}</th><th>{tr("Last used")}</th><th>{tr("State")}</th><th></th></tr></thead>
                <tbody>{p.keys.map((k: any) => (
                  <tr key={k.id}><td><code>{k.fingerprint}</code></td><td className="small">{k.ip_allowlist.join(", ") || "any"}</td><td className="small">{when(k.last_used_at)}</td><td><Badge tone={k.revoked_at ? "bad" : "good"}>{k.revoked_at ? tr("revoked") : tr("active")}</Badge></td><td>{!k.revoked_at && <button className="danger" onClick={() => setRevoking(k.id)}>{tr("Revoke")}</button>}</td></tr>
                ))}</tbody>
              </table>
            </div>
          </div>
        )}
        <div className="card">
          <h2>{tr("Recent reveals")}</h2>
          {d.reveals.length === 0 ? <p className="muted">{tr("None recorded.")}</p> : (
            <div className="tablewrap" style={{ maxHeight: 320 }}>
              <table>
                <thead><tr><th>{tr("When")}</th><th>{tr("Decision")}</th><th>{tr("Field")}</th><th>{tr("Network")}</th><th>{tr("Purpose")}</th></tr></thead>
                <tbody>{d.reveals.map((e: any) => <tr key={e.seq}><td className="small">{when(e.occurred_at)}</td><td><DecisionBadge value={e.decision} /></td><td className="small mono">{e.field_id}</td><td className="small">{e.network ?? "none"}</td><td className="small">{e.purpose}</td></tr>)}</tbody>
              </table>
            </div>
          )}
        </div>
        <div className="card">
          <h2>{tr("Recent denials")}</h2>
          {d.denials.length === 0 ? <p className="muted">{tr("None recorded.")}</p> : d.denials.map((e: any) => <div key={e.seq} className="small muted">{when(e.occurred_at)} · {e.action} · {e.field_id} · {e.purpose}</div>)}
        </div>
        <div className="card">
          <h2>{tr("Break-glass grants")}</h2>
          {d.grants.length === 0 ? <p className="muted">{tr("None.")}</p> : d.grants.map((g: any) => <div key={g.id} className="row small"><Badge tone={g.status === "active" ? "warn" : ""}>{g.status}</Badge>{g.reason}, {g.duration_minutes} {tr("minutes,")} {when(g.created_at)}</div>)}
        </div>
      </div>
      {confirm === "password" && (
        <TypedConfirm title={tr("Reset {0}'s password", { 0: p.display_name })} word="reset" onClose={() => setConfirm(null)} onConfirm={async () => { const r = await control(`/v1/principals/${id}/reset-password`, { method: "POST" }); setSent({ title: r.emailed ? "Reset link sent" : "Pass on this reset link", link: r, note: tr("{0} can use this link once, within an hour.", { 0: p.display_name }) }); }}>
          {tr("Their current password stops working now, and they are signed out. They'll choose a new one from a link, and still need their two-factor code. This is recorded in the audit log.")}
        </TypedConfirm>
      )}
      {confirm === "mfa" && (
        <TypedConfirm title={tr("Reset {0}'s two-factor", { 0: p.display_name })} word="reset" onClose={() => setConfirm(null)} onConfirm={async () => { const r = await control(`/v1/principals/${id}/reset-mfa`, { method: "POST" }); setSent({ title: tr("Two-factor reset"), note: tr("{0} is signed out, and sets up two-factor again at next sign-in.{1}", { 0: p.display_name, 1: r.notified ? tr(" They have been told by email.") : tr(" Email isn't set up, so tell them yourself.") }) }); }}>
          {tr("Do this only once you're sure it really is them asking. Until they set it up again, their password alone gets them to the setup screen. This is recorded in the audit log, and they'll be told by email if email is set up.")}
        </TypedConfirm>
      )}
      {sent && (
        <Modal title={sent.title} onClose={() => setSent(null)}>
          {sent.link && !sent.link.emailed ? <InviteLink token={sent.link.token!} message={sent.link.message} what={sent.note} /> : <p className="muted">{sent.note}</p>}
          <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={() => setSent(null)}>{tr("Done")}</button></div>
        </Modal>
      )}
      {revoking && (
        <TypedConfirm title={tr("Revoke key")} word="revoke" onClose={() => setRevoking(null)} onConfirm={async () => { await control(`/v1/principals/${id}/keys/${revoking}/revoke`, { method: "POST" }); reload(); }}>
          {tr("Tokens issued with this key stop working within seconds. This cannot be undone.")}
        </TypedConfirm>
      )}
      {suspending && (
        <TypedConfirm title={p.status === "active" ? tr("Suspend {0}", { 0: p.display_name }) : tr("Reactivate {0}", { 0: p.display_name })} word={p.status === "active" ? "suspend" : "reactivate"} onClose={() => setSuspending(false)} onConfirm={async () => { await control(`/v1/principals/${id}`, { method: "PATCH", body: { status: p.status === "active" ? "suspended" : "active" } }); reload(); }}>
          {p.status === "active" ? tr("All access stops within seconds.") : tr("Access returns as their roles allow.")}
        </TypedConfirm>
      )}
    </Page>
  );
}
