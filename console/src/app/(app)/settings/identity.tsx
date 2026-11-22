"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { Badge, Checks, ErrorLine, Modal, ShownOnce, TypedConfirm } from "@/components/ui";
import { control, day, when } from "@/lib/api";

export interface Identity {
  edition: string; allowed: boolean;
  mappings: { group: string; roles: string[] }[];
  scim: { base_url: string; tokens: { id: string; name: string; created_at: string; last_used_at: string | null }[] };
  ldap: null | { url: string; start_tls: boolean; ca_cert: string | null; bind_dn: string; base_dn: string; user_filter: string; group_base_dn: string | null; group_filter: string; email_domains: string[]; jit_provisioning: boolean };
  people_by_source: Record<string, number>;
}
const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");

/** Groups at the identity provider decide roles here: for single sign-on, SCIM and LDAP alike. */
export function GroupRolesCard({ id, roles, onChange }: { id: Identity; roles: string[]; onChange: () => void }) {
  const [rows, setRows] = useState(id.mappings);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => setRows(id.mappings), [id.mappings]);
  const dirty = JSON.stringify(rows) !== JSON.stringify(id.mappings);
  return (
    <div className="card">
      <h2>{tr("Groups and roles")}</h2>
      <p className="small muted">{tr("Map a group at your identity provider to roles here. Once any group is mapped, people's roles follow their groups each time they sign in or are synced, and someone with no mapped group can't get in. The last admin is never removed this way. With no mappings, you set roles by hand.")}</p>
      {rows.length === 0 && <p className="small">{tr("No groups mapped. Roles are set by hand on the People page.")}</p>}
      {rows.map((r, i) => (
        <div key={i} className="grid gap-2 rounded-md border p-3" style={{ borderColor: "var(--border)" }}>
          <div className="row"><input style={{ flex: 1 }} value={r.group} placeholder={tr("Group name, or ID for Entra")} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)))} /><button onClick={() => setRows(rows.filter((_, j) => j !== i))}>{tr("Remove")}</button></div>
          <Checks options={roles} value={r.roles} onChange={(v) => setRows(rows.map((x, j) => (j === i ? { ...x, roles: v } : x)))} />
        </div>
      ))}
      <ErrorLine error={err} />
      {saved && !dirty && <div className="note good small">{tr("Saved.")}</div>}
      <div className="row">
        <button onClick={() => { setSaved(false); setRows([...rows, { group: "", roles: [] }]); }}>{tr("Add a group")}</button>
        <button className="primary" disabled={!dirty || rows.some((r) => !r.group.trim() || !r.roles.length)} onClick={async () => {
          setErr(null);
          try { await control("/v1/settings/group-roles", { method: "PUT", body: { mappings: rows.map((r) => ({ group: r.group.trim(), roles: r.roles })) } }); setSaved(true); onChange(); } catch (e) { setErr(errText(e)); }
        }}>{tr("Save mappings")}</button>
      </div>
    </div>
  );
}

/** SCIM: the identity provider creates, updates and removes people here. */
export function ScimCard({ id, onChange }: { id: Identity; onChange: () => void }) {
  const [making, setMaking] = useState(false);
  const [name, setName] = useState("");
  const [made, setMade] = useState<{ token: string; base_url: string } | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const synced = id.people_by_source.scim ?? 0;
  return (
    <div className="card">
      <div className="spread"><h2>{tr("Directory sync (SCIM)")}</h2>{!id.allowed && <Badge tone="warn">{tr("Enterprise and Cloud")}</Badge>}</div>
      <p className="small muted">{tr("Your identity provider adds people, updates them and removes them here, so access ends the moment someone leaves. Works with Entra ID, Okta, OneLogin, JumpCloud, authentik and any SCIM 2.0 client. Removed people are kept for the audit trail and can't sign in.")}</p>
      <div className="grid gap-1 small"><span className="muted">{tr("SCIM URL")}</span><code style={{ overflowWrap: "anywhere" }}>{id.scim.base_url}</code></div>
      <p className="small m-0">{synced === 1 ? tr("1 person synced so far.") : tr("{0} people synced so far.", { 0: synced })}</p>
      {id.scim.tokens.length > 0 && (
        <div className="tablewrap"><table><thead><tr><th>{tr("Token")}</th><th>{tr("Made")}</th><th>{tr("Last used")}</th><th /></tr></thead>
          <tbody>{id.scim.tokens.map((t) => <tr key={t.id}><td>{t.name}</td><td className="small">{day(t.created_at)}</td><td className="small">{t.last_used_at ? when(t.last_used_at) : tr("never")}</td><td><button className="danger" onClick={() => setRevoking(t.id)}>{tr("Revoke")}</button></td></tr>)}</tbody></table></div>
      )}
      <ErrorLine error={err} />
      <div className="row"><button className="primary" disabled={!id.allowed} onClick={() => setMaking(true)}>{tr("Make a SCIM token")}</button></div>
      {making && (
        <Modal title={tr("Make a SCIM token")} onClose={() => { setMaking(false); setMade(null); setName(""); onChange(); }}>
          {made ? (
            <>
              <ShownOnce items={[{ label: tr("SCIM URL"), value: made.base_url }, { label: tr("Token"), value: made.token, block: true }]} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={() => { setMaking(false); setMade(null); setName(""); onChange(); }}>{tr("Done")}</button></div>
            </>
          ) : (
            <>
              <label className="field"><span>{tr("Name, such as the provider it's for")}</span><input value={name} autoFocus onChange={(e) => setName(e.target.value)} placeholder={tr("Entra ID")} /></label>
              <ErrorLine error={err} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={() => setMaking(false)}>{tr("Cancel")}</button><button className="primary" disabled={!name.trim()} onClick={async () => { setErr(null); try { setMade(await control("/v1/settings/scim/tokens", { body: { name } })); } catch (e) { setErr(errText(e)); } }}>{tr("Make token")}</button></div>
            </>
          )}
        </Modal>
      )}
      {revoking && <TypedConfirm title={tr("Revoke this SCIM token")} word="revoke" onClose={() => setRevoking(null)} onConfirm={async () => { await control(`/v1/settings/scim/tokens/${revoking}`, { method: "DELETE" }); setRevoking(null); onChange(); }}>{tr("Your identity provider stops syncing until you give it a new token. People already synced keep their access.")}</TypedConfirm>}
    </div>
  );
}

const ldapBlank = { url: "ldaps://", start_tls: false, ca_cert: "", bind_dn: "", bind_password: "", base_dn: "", user_filter: "(&(objectClass=person)(mail={email}))", group_base_dn: "", group_filter: "(&(objectClass=groupOfNames)(member={dn}))", email_domains: "", jit_provisioning: false };
const AD = { user_filter: "(&(objectClass=user)(mail={email}))", group_base_dn: "", group_filter: "(&(objectClass=group)(member={dn}))" };

/** LDAP: passwords checked against your directory. Onshore's own second factor still applies. */
export function LdapCard({ id, onChange }: { id: Identity; onChange: () => void }) {
  const [f, setF] = useState(ldapBlank);
  const [editing, setEditing] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [test, setTest] = useState<{ user: null | { email: string; name: string; groups: string[]; dn: string } } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const c = id.ldap;
  useEffect(() => { if (c && editing) setF({ ...ldapBlank, ...c, ca_cert: c.ca_cert ?? "", group_base_dn: c.group_base_dn ?? "", bind_password: "", email_domains: c.email_domains.join(", ") }); }, [c, editing]);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const body = () => ({ ...f, ca_cert: f.ca_cert || null, group_base_dn: f.group_base_dn || null, bind_password: f.bind_password || undefined, email_domains: f.email_domains.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) });
  return (
    <div className="card">
      <div className="spread"><h2>{tr("LDAP directory")}</h2>{!id.allowed && <Badge tone="warn">{tr("Enterprise and Cloud")}</Badge>}</div>
      {c && !editing ? (
        <>
          <p className="small">{tr("Passwords for {0} are checked against {1}. People still use their authenticator app or passkey here.", { 0: c.email_domains.join(", "), 1: c.url })} {c.jit_provisioning ? tr("New people get an account on first sign-in when one of their groups maps to a role.") : tr("People must be added here first.")}</p>
          <div className="row"><button onClick={() => setEditing(true)} disabled={!id.allowed}>{tr("Edit")}</button><button className="danger" onClick={() => setRemoving(true)}>{tr("Remove")}</button></div>
          {removing && <TypedConfirm title={tr("Remove the LDAP directory")} word="remove" onClose={() => setRemoving(false)} onConfirm={async () => { await control("/v1/settings/ldap", { method: "DELETE" }); setRemoving(false); onChange(); }}>{tr("People from the directory won't be able to sign in until an admin sets them a password.")}</TypedConfirm>}
        </>
      ) : !id.allowed ? (
        <p className="small muted">{tr("Check passwords against Active Directory, OpenLDAP or FreeIPA, with roles from directory groups. It comes with Enterprise and Onshore Cloud.")}</p>
      ) : (
        <>
          <p className="small muted">{tr("For directories without single sign-on. Only encrypted connections are allowed: ldaps://, or ldap:// with StartTLS. Local accounts, such as your own, keep their password.")}</p>
          <div className="row"><button onClick={() => setF({ ...f, ...AD })}>{tr("Use Active Directory defaults")}</button></div>
          <label className="field"><span>{tr("Directory URL")}</span><input value={f.url} onChange={set("url")} placeholder="ldaps://dc1.yourbank.example:636" /></label>
          <label className="row small"><input type="checkbox" checked={f.start_tls} onChange={(e) => setF({ ...f, start_tls: e.target.checked })} />{tr("Upgrade ldap:// with StartTLS")}</label>
          <label className="field"><span>{tr("CA certificate, if your directory uses a private one (PEM)")}</span><textarea className="code" rows={3} value={f.ca_cert} onChange={set("ca_cert")} /></label>
          <label className="field"><span>{tr("Service account DN")}</span><input value={f.bind_dn} onChange={set("bind_dn")} placeholder={tr("CN=svc-onshore,OU=Service,DC=yourbank,DC=example")} /></label>
          <label className="field"><span>{c ? tr("Service account password (leave empty to keep the saved one)") : tr("Service account password")}</span><input type="password" value={f.bind_password} onChange={set("bind_password")} /></label>
          <label className="field"><span>{tr("Where to look for people (base DN)")}</span><input value={f.base_dn} onChange={set("base_dn")} placeholder={tr("OU=Staff,DC=yourbank,DC=example")} /></label>
          <label className="field"><span>{tr("User filter, with {email} where the address goes")}</span><input className="mono" value={f.user_filter} onChange={set("user_filter")} /></label>
          <label className="field"><span>{tr("Where to look for groups (optional; memberOf is read either way)")}</span><input value={f.group_base_dn} onChange={set("group_base_dn")} placeholder={tr("OU=Groups,DC=yourbank,DC=example")} /></label>
          <label className="field"><span>{tr("Group filter, with {dn} for the person")}</span><input className="mono" value={f.group_filter} onChange={set("group_filter")} /></label>
          <label className="field"><span>{tr("Email domains, comma-separated")}</span><input value={f.email_domains} onChange={set("email_domains")} placeholder="yourbank.example" /></label>
          <label className="row small"><input type="checkbox" checked={f.jit_provisioning} onChange={(e) => setF({ ...f, jit_provisioning: e.target.checked })} />{tr("Create an account on first sign-in when one of the person's groups maps to a role")}</label>
          <div className="grid gap-2 rounded-md border p-3" style={{ borderColor: "var(--border)" }}>
            <div className="row"><input style={{ flex: 1 }} value={testEmail} onChange={(e) => setTestEmail(e.target.value)} placeholder={tr("Someone's email, to look them up")} /><button onClick={async () => { setErr(null); setTest(null); try { setTest(await control("/v1/settings/ldap/test", { body: { email: testEmail || undefined, config: body() } })); } catch (e) { setErr(errText(e)); } }}>{tr("Test connection")}</button></div>
            {test && <div className="note good small">{test.user ? tr("Connected. Found {0} ({1}), in groups: {2}.", { 0: test.user.name, 1: test.user.email, 2: test.user.groups.join(", ") || tr("none") }) : testEmail ? tr("Connected, but nobody matched that email.") : tr("Connected, and the service account signed in.")}</div>}
          </div>
          <ErrorLine error={err} />
          <div className="row">
            {editing && <button onClick={() => { setEditing(false); setErr(null); }}>{tr("Cancel")}</button>}
            <button className="primary" onClick={async () => { setErr(null); try { await control("/v1/settings/ldap", { method: "PUT", body: body() }); setEditing(false); onChange(); } catch (e) { setErr(errText(e)); } }}>{tr("Save")}</button>
          </div>
        </>
      )}
    </div>
  );
}
