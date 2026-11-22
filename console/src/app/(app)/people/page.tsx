"use client";
import { tr } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { AccountLink, InviteLink } from "./invite-link";
import { Badge, Checks, ErrorLine, Loading, Modal, Page, rowKeys } from "@/components/ui";
import { control, n, useLoad, when } from "@/lib/api";

interface Person { id: string; kind: string; display_name: string; email: string | null; status: string; source?: string; mfa_enabled: boolean; approved_network: string | null; last_active_at: string | null; roles: string[]; reveals_7d: number; reveals_30d: number; denied_30d: number; anomaly: boolean }

function NewPerson({ roles, onClose, onDone }: { roles: string[]; onClose: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<"user" | "service_account">("user");
  const [f, setF] = useState({ display_name: "", email: "", public_key: "", allow: "", roles: [] as string[] });
  const [invite, setInvite] = useState<AccountLink | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (invite) {
    return (
      <Modal title={invite.emailed ? tr("Invitation sent") : tr("Pass on this invitation")} onClose={onDone}>
        {invite.emailed ? <p className="muted">{f.display_name} {tr("has an email with a link to choose a password. It works for 7 days. They set up two-factor authentication at first sign-in.")}</p> : <InviteLink token={invite.token!} message={invite.message} what={tr("{0} can use this link once, within 7 days, to choose a password.", { 0: f.display_name })} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onDone}>{tr("Done")}</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={tr("Add a person or service account")} onClose={onClose}>
      <div className="row">
        <label className="row small"><input type="radio" checked={kind === "user"} onChange={() => setKind("user")} />{tr("Person")}</label>
        <label className="row small"><input type="radio" checked={kind === "service_account"} onChange={() => setKind("service_account")} />{tr("Service account")}</label>
      </div>
      <label className="field"><span>{tr("Name")}</span><input value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></label>
      {kind === "user" ? (
        <label className="field"><span>{tr("Email")}</span><input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
      ) : (
        <>
          <label className="field"><span>{tr("Public key, from")} <code>{tr("rv sa-keygen")}</code>{tr(". The private key stays with you.")}</span><input className="mono" value={f.public_key} onChange={(e) => setF({ ...f, public_key: e.target.value })} /></label>
          <label className="field"><span>{tr("IP allowlist, comma-separated (optional)")}</span><input value={f.allow} onChange={(e) => setF({ ...f, allow: e.target.value })} /></label>
        </>
      )}
      <div className="field"><span>{tr("Roles")}</span><Checks options={roles} value={f.roles} onChange={(r) => setF({ ...f, roles: r })} /></div>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!f.display_name || f.roles.length === 0} onClick={async () => {
          try {
            const body = kind === "user" ? { kind, display_name: f.display_name, email: f.email, roles: f.roles, invite: true } : { kind, display_name: f.display_name, public_key: f.public_key, ip_allowlist: f.allow.split(",").map((s) => s.trim()).filter(Boolean), roles: f.roles };
            const r = await control("/v1/principals", { body });
            if (r.invite) setInvite(r.invite);
            else onDone();
          } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{kind === "user" ? tr("Send invitation") : tr("Add")}</button>
      </div>
    </Modal>
  );
}

export default function People() {
  const router = useRouter();
  const { value, error, loading, reload } = useLoad<{ principals: Person[] }>(() => control("/v1/principals"));
  const roles = useLoad<{ roles: string[] }>(() => control("/v1/roles"));
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [kind, setKind] = useState("");
  const [flagged, setFlagged] = useState(false);
  const [adding, setAdding] = useState(false);
  const rows = useMemo(() => (value?.principals ?? []).filter((p) => (!q || `${p.display_name} ${p.email ?? ""}`.toLowerCase().includes(q.toLowerCase())) && (!role || p.roles.includes(role)) && (!kind || p.kind === kind) && (!flagged || p.anomaly)), [value, q, role, kind, flagged]);
  return (
    <Page title={tr("People")} sub={tr("Everyone who can sign in, the programs that call Onshore, what each has viewed, and anything unusual.")} actions={<button className="primary" onClick={() => setAdding(true)}>{tr("Add a person")}</button>}>
      <div className="row" style={{ marginBottom: 10 }}>
        <input aria-label={tr("Search people")} placeholder={tr("Name or email")} value={q} onChange={(e) => setQ(e.target.value)} />
        <select aria-label={tr("Role")} value={role} onChange={(e) => setRole(e.target.value)}><option value="">{tr("Any role")}</option>{roles.value?.roles.map((r) => <option key={r}>{r}</option>)}</select>
        <select aria-label={tr("Kind")} value={kind} onChange={(e) => setKind(e.target.value)}><option value="">{tr("People and service accounts")}</option><option value="user">{tr("People")}</option><option value="service_account">{tr("Service accounts")}</option></select>
        <label className="row small"><input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} />{tr("Anomaly only")}</label>
      </div>
      <Loading error={error} loading={loading && !value} />
      {value && (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Name")}</th><th>{tr("Roles")}</th><th>{tr("Two-factor")}</th><th>{tr("Status")}</th><th>{tr("Last active")}</th><th className="num">{tr("Viewed, 7 days")}</th><th className="num">{tr("Viewed, 30 days")}</th><th className="num">{tr("Refused, 30 days")}</th><th>{tr("Flag")}</th></tr></thead>
            <tbody>
              {rows.map((p) => {
                const open = () => router.push(`/people/${p.id}`);
                return (
                  <tr key={p.id} className="click" tabIndex={0} onClick={open} onKeyDown={(e) => rowKeys(e, open)}>
                    <td>{p.display_name}<div className="small faint">{p.email ?? tr("service account")}{p.source && p.source !== "local" ? ` · ${p.source === "sso" ? tr("added by single sign-on") : p.source === "scim" ? tr("synced by SCIM") : tr("from LDAP")}` : ""}</div></td>
                    <td className="small">{p.roles.join(", ")}</td>
                    <td>{p.kind === "service_account" ? <span className="small faint">key</span> : <Badge tone={p.mfa_enabled ? "good" : "warn"}>{p.mfa_enabled ? "on" : tr("pending")}</Badge>}</td>
                    <td><Badge tone={p.status === "active" ? "" : "bad"}>{p.status === "active" ? tr("active") : p.status === "suspended" ? tr("suspended") : tr("removed")}</Badge></td>
                    <td className="small">{when(p.last_active_at)}</td>
                    <td className="num">{n(p.reveals_7d)}</td><td className="num">{n(p.reveals_30d)}</td><td className="num">{n(p.denied_30d)}</td>
                    <td>{p.anomaly && <Badge tone="bad">anomaly</Badge>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {adding && roles.value && <NewPerson roles={roles.value.roles} onClose={() => setAdding(false)} onDone={() => { setAdding(false); reload(); }} />}
    </Page>
  );
}
