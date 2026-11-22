"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useState } from "react";
import { Badge, Copy, ErrorLine, TypedConfirm } from "@/components/ui";
import { control, useLoad } from "@/lib/api";

type Kind = "oidc" | "saml";
interface Provider { id: string; name: string; kinds: Kind[]; issuer?: string; scopes?: string; groups?: string; steps: string[]; scim: string }

/** How to set up each identity provider. Built at render so the console's language applies. */
function providers(): Provider[] {
  return [
    { id: "entra", name: "Microsoft Entra ID", kinds: ["oidc", "saml"], issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0", groups: "groups",
      steps: [tr("In Entra, open Enterprise applications and create your own application, or register an app for OIDC."), tr("Use the callback URL below as the redirect URI (OIDC) or the reply URL (SAML)."), tr("Under Token configuration, add a groups claim. Entra sends group IDs, so map those IDs to roles below.")],
      scim: tr("Supported: open the app's Provisioning page, choose Automatic, and paste the SCIM URL and a token from below.") },
    { id: "okta", name: "Okta", kinds: ["oidc", "saml"], issuer: "https://<your-org>.okta.com", groups: "groups",
      steps: [tr("In Okta, create an app integration: OIDC web application, or SAML 2.0."), tr("Use the callback URL below as the sign-in redirect URI (OIDC) or the single sign-on URL (SAML)."), tr("Add a groups claim (OIDC) or a groups attribute statement (SAML) with a filter for the groups you'll map.")],
      scim: tr("Supported: turn on SCIM provisioning for the app and paste the SCIM URL and a token from below.") },
    { id: "google", name: "Google Workspace", kinds: ["saml", "oidc"], issuer: "https://accounts.google.com",
      steps: [tr("In the Google Admin console, add a custom SAML app. OIDC works too, but sends no groups."), tr("Use the callback URL below as the ACS URL, and our entity ID below."), tr("Under attribute mapping, add Group membership and name the attribute groups.")],
      scim: tr("Google doesn't push SCIM to custom apps. Use groups from SAML, or set roles by hand.") },
    { id: "onelogin", name: "OneLogin", kinds: ["oidc", "saml"], issuer: "https://<subdomain>.onelogin.com/oidc/2", groups: "groups",
      steps: [tr("In OneLogin, add the OpenID Connect or SAML custom connector app."), tr("Use the callback URL below as the redirect URI or ACS URL."), tr("Add a groups parameter so people's groups are sent.")],
      scim: tr("Supported with OneLogin's SCIM provisioner app: paste the SCIM URL and a token from below.") },
    { id: "jumpcloud", name: "JumpCloud", kinds: ["saml", "oidc"], groups: "groups",
      steps: [tr("In JumpCloud, add a custom SSO application (SAML) or a custom OIDC app."), tr("Use the callback URL below as the ACS URL or redirect URI."), tr("Turn on the group attribute and name it groups.")],
      scim: tr("Supported: turn on Identity Management for the app and paste the SCIM URL and a token from below.") },
    { id: "keycloak", name: "Keycloak", kinds: ["oidc", "saml"], issuer: "https://<host>/realms/<realm>", groups: "groups",
      steps: [tr("In your realm, create a client: OpenID Connect with client authentication on, or SAML."), tr("Use the callback URL below as a valid redirect URI, or the assertion consumer URL."), tr("Add a Group Membership mapper named groups, with full group path off.")],
      scim: tr("Keycloak has no built-in SCIM. Use groups at sign-in instead.") },
    { id: "authentik", name: "authentik", kinds: ["oidc", "saml"], issuer: "https://<host>/application/o/<slug>/", groups: "groups",
      steps: [tr("In authentik, create an OAuth2/OpenID provider or a SAML provider, and an application for it."), tr("Use the callback URL below as the redirect URI or ACS URL."), tr("The profile scope sends groups by default.")],
      scim: tr("Supported: add a SCIM provider with the SCIM URL and a token from below, and attach it as a backchannel provider.") },
    { id: "authelia", name: "Authelia", kinds: ["oidc"], issuer: "https://<auth-host>", scopes: "openid email profile groups", groups: "groups",
      steps: [tr("Add an OpenID Connect client in Authelia's configuration, with the callback URL below as a redirect URI."), tr("Include the groups scope so people's groups are sent."), tr("Authelia doesn't do SAML.")],
      scim: tr("Authelia has no SCIM. Use groups at sign-in instead.") },
    { id: "duo", name: "Duo", kinds: ["saml", "oidc"], groups: "groups",
      steps: [tr("In the Duo Admin Panel, protect an application as a Generic SAML Service Provider or Generic OIDC Relying Party."), tr("Use the callback URL below as the ACS URL or redirect URI."), tr("Map a groups attribute if you want roles to follow groups.")],
      scim: tr("Duo doesn't push SCIM to custom apps. Use groups at sign-in, or set roles by hand.") },
    { id: "other", name: tr("Other SAML 2.0 or OIDC provider"), kinds: ["oidc", "saml"],
      steps: [tr("Create an OIDC client or a SAML app at your provider."), tr("Use the callback URL below as the redirect URI or ACS URL."), tr("Send people's groups if you want roles to follow them.")],
      scim: tr("If your provider supports SCIM 2.0, paste the SCIM URL and a token from below.") },
  ];
}

const blank = { provider: "entra", kind: "oidc" as Kind, email_domains: "", issuer: "", client_id: "", client_secret: "", idp_sso_url: "", idp_cert: "", sp_entity_id: "", scopes: "openid email profile", groups_attribute: "", idp_enforces_mfa: false, sso_only: false, jit_provisioning: false };

export function SsoCard({ allowed }: { allowed: boolean }) {
  const { value, reload } = useLoad<{ config: any; sp: { callback_url: string; entity_id: string; metadata_url: string } }>(() => control("/v1/settings/sso"));
  const [f, setF] = useState(blank);
  const [editing, setEditing] = useState(false);
  const [metadata, setMetadata] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const c = value?.config;
  const list = providers();
  const p = list.find((x) => x.id === f.provider) ?? list[list.length - 1]!;
  useEffect(() => {
    if (c && editing) setF({ ...blank, ...c, provider: c.provider ?? "other", email_domains: c.email_domains.join(", "), client_secret: "", issuer: c.issuer ?? "", client_id: c.client_id ?? "", idp_sso_url: c.idp_sso_url ?? "", idp_cert: c.idp_cert ?? "", sp_entity_id: c.sp_entity_id ?? "", groups_attribute: c.groups_attribute ?? "" });
  }, [c, editing]);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const choose = (id: string) => {
    const x = list.find((y) => y.id === id)!;
    setF({ ...f, provider: id, kind: x.kinds.includes(f.kind) ? f.kind : x.kinds[0]!, scopes: x.scopes ?? "openid email profile", groups_attribute: x.groups ?? "", issuer: f.issuer || "" });
  };
  const sp = value?.sp;
  return (
    <div className="card">
      <div className="spread"><h2>{tr("Single sign-on")}</h2>{!allowed && <Badge tone="warn">{tr("Business and above")}</Badge>}</div>
      {c && !editing ? (
        <>
          <p className="small">{tr("{0} with {1}, for {2}.", { 0: c.kind.toUpperCase(), 1: list.find((x) => x.id === c.provider)?.name ?? tr("your provider"), 2: c.email_domains.join(", ") })} {c.sso_only ? tr("Passwords are off.") : tr("Passwords still work.")} {c.jit_provisioning ? tr("New people get an account on first sign-in when one of their groups maps to a role.") : tr("People must be added here first.")}</p>
          <div className="row"><button onClick={() => setEditing(true)} disabled={!allowed}>{tr("Edit")}</button><button className="danger" onClick={() => setRemoving(true)}>{tr("Remove")}</button></div>
          {removing && <TypedConfirm title={tr("Remove single sign-on")} word="remove" onClose={() => setRemoving(false)} onConfirm={async () => { await control("/v1/settings/sso", { method: "DELETE" }); reload(); }}>{tr("People will sign in with a password and an authenticator code again.")}</TypedConfirm>}
        </>
      ) : !allowed ? (
        <p className="small muted">{tr("Single sign-on with SAML 2.0 or OIDC works with Microsoft Entra ID, Okta, Google, OneLogin, JumpCloud, Keycloak, authentik, Authelia, Duo and other providers. It comes with Enterprise and Onshore Cloud.")}</p>
      ) : (
        <>
          <label className="field"><span>{tr("Identity provider")}</span><select value={f.provider} onChange={(e) => choose(e.target.value)}>{list.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
          <ol className="small" style={{ paddingLeft: 18, margin: 0 }}>{p.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          {sp && (
            <div className="grid gap-2 rounded-md border p-3 small" style={{ borderColor: "var(--border)" }}>
              <div className="spread"><span className="muted">{tr("Callback URL (redirect URI, ACS URL)")}</span><Copy text={sp.callback_url} /></div><code style={{ overflowWrap: "anywhere" }}>{sp.callback_url}</code>
              {f.kind === "saml" && <><div className="spread"><span className="muted">{tr("Our entity ID")}</span><Copy text={sp.entity_id} /></div><code style={{ overflowWrap: "anywhere" }}>{sp.entity_id}</code>
                <span className="muted">{tr("Our SAML metadata, once saved:")} <a href={sp.metadata_url} target="_blank" rel="noreferrer">{tr("download")}</a></span></>}
            </div>
          )}
          {p.kinds.length > 1 && <label className="field"><span>{tr("Protocol")}</span><select value={f.kind} onChange={set("kind")}>{p.kinds.map((k) => <option key={k} value={k}>{k === "oidc" ? tr("OIDC") : tr("SAML 2.0")}</option>)}</select></label>}
          <label className="field"><span>{tr("Email domains, comma-separated")}</span><input value={f.email_domains} onChange={set("email_domains")} placeholder="yourhost.example" /></label>
          {f.kind === "oidc" ? (
            <>
              <label className="field"><span>{tr("Issuer URL")}</span><input value={f.issuer} onChange={set("issuer")} placeholder={p.issuer} /></label>
              <label className="field"><span>{tr("Client ID")}</span><input value={f.client_id} onChange={set("client_id")} /></label>
              <label className="field"><span>{c?.has_client_secret ? tr("Client secret (leave empty to keep the saved one)") : tr("Client secret")}</span><input type="password" value={f.client_secret} onChange={set("client_secret")} /></label>
              <label className="field"><span>{tr("Scopes")}</span><input value={f.scopes} onChange={set("scopes")} /></label>
            </>
          ) : (
            <>
              <label className="field"><span>{tr("Paste your provider's metadata XML (optional)")}</span><textarea className="code" rows={3} value={metadata} onChange={(e) => setMetadata(e.target.value)} placeholder={tr("<EntityDescriptor …>")} /></label>
              {metadata.length > 50 && <div className="row"><button onClick={async () => { setError(null); try { const r = await control("/v1/settings/sso/parse-metadata", { body: { xml: metadata } }); setF({ ...f, idp_sso_url: r.idp_sso_url, idp_cert: r.idp_cert }); setMetadata(""); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Fill in from metadata")}</button></div>}
              <label className="field"><span>{tr("Identity provider sign-in URL")}</span><input value={f.idp_sso_url} onChange={set("idp_sso_url")} /></label>
              <label className="field"><span>{tr("Identity provider signing certificate")}</span><textarea className="code" value={f.idp_cert} onChange={set("idp_cert")} /></label>
              <label className="field"><span>{tr("Our entity ID (optional)")}</span><input value={f.sp_entity_id} onChange={set("sp_entity_id")} placeholder={sp?.entity_id} /></label>
            </>
          )}
          <label className="field"><span>{tr("Groups claim or attribute (optional)")}</span><input value={f.groups_attribute} onChange={set("groups_attribute")} placeholder={f.kind === "oidc" ? "groups" : tr("found automatically")} /></label>
          <p className="small muted m-0">{p.scim}</p>
          <label className="row small"><input type="checkbox" checked={f.jit_provisioning} onChange={(e) => setF({ ...f, jit_provisioning: e.target.checked })} />{tr("Create an account on first sign-in when one of the person's groups maps to a role")}</label>
          <label className="row small"><input type="checkbox" checked={f.idp_enforces_mfa} onChange={(e) => setF({ ...f, idp_enforces_mfa: e.target.checked })} />{tr("My identity provider enforces MFA for these people")}</label>
          <label className="row small"><input type="checkbox" checked={f.sso_only} onChange={(e) => setF({ ...f, sso_only: e.target.checked })} />{tr("Turn passwords off")}</label>
          <ErrorLine error={error} />
          <div className="row">
            {editing && <button onClick={() => { setEditing(false); setError(null); }}>{tr("Cancel")}</button>}
            <button className="primary" onClick={async () => {
              setError(null);
              try {
                const { client_secret, ...rest } = f;
                await control("/v1/settings/sso", { method: "PUT", body: { ...rest, ...(client_secret ? { client_secret } : {}), groups_attribute: f.groups_attribute || null, email_domains: f.email_domains.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) } });
                setEditing(false); reload();
              } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
            }}>{tr("Save")}</button>
          </div>
        </>
      )}
    </div>
  );
}
