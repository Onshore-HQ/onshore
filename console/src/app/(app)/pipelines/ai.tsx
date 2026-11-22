"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, Copy, Empty, ErrorLine, Loading, Modal, TypedConfirm, ShownOnce } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { modeLabel } from "@/lib/labels";

interface Route { id: string; vault_id: string; name: string; provider: string; upstream_base_url: string; allowed_models: string[]; restore_in_response: boolean; mode: string; transfer_basis: string; setup: string; cloak_profile_id: string | null; twin_days: number }
interface Choice { value: string; label: string; example: string }
interface Category { key: string; label: string; default: string; choices: Choice[]; packs?: string[] }
interface Profile { id: string; vault_id: string; name: string; options: Record<string, string>; routes: { id: string; name: string }[] }
interface Vault { id: string; name: string; packs?: string[] }

const SAMPLE = "Customer Sarah Johnson (DOB 1988-03-14) of Brooklyn says $8,500 left her account without her approval. Her SSN is 123-45-6789, her IBAN is GB82 WEST 1234 5698 7654 32 and her number is +1 212 555 0100. Please draft a reply.";
const TWIN_DAYS = [0, 7, 30, 90];
const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");

/** A short line for a setting: what changes from the default. */
function summary(cats: Category[], options: Record<string, string>) {
  const changed = cats.filter((c) => (options[c.key] ?? c.default) !== c.default);
  if (changed.length === 0) return "Placeholders for everything";
  return changed.map((c) => `${c.label}: ${c.choices.find((ch) => ch.value === options[c.key])?.label.toLowerCase() ?? options[c.key]}`).join(" · ");
}

function useCloak() {
  const cats = useLoad<{ categories: Category[] }>(() => control("/v1/cloak-options"));
  const profiles = useLoad<{ profiles: Profile[] }>(() => control("/v1/cloak-profiles"));
  return { cats: cats.value?.categories ?? [], catsError: cats.error, profiles: profiles.value?.profiles ?? [], reloadProfiles: profiles.reload, loading: (cats.loading && !cats.value) || (profiles.loading && !profiles.value), error: cats.error ?? profiles.error };
}

function Grid({ cats: all, packs, value, onChange }: { cats: Category[]; packs: string[]; value: Record<string, string>; onChange: (v: Record<string, string>) => void }) {
  // Only the kinds this vault's country packs can find.
  const cats = all.filter((c) => !c.packs || c.packs.some((p) => packs.includes(p)));
  return (
    <div className="tablewrap" style={{ maxHeight: 420 }}>
      <table>
        <thead><tr><th>{tr("Kind of data")}</th><th>{tr("Before it leaves, it becomes")}</th></tr></thead>
        <tbody>
          {cats.map((c) => {
            const v = value[c.key] ?? c.default;
            const ch = c.choices.find((x) => x.value === v);
            return (
              <tr key={c.key}>
                <td><div className="font-medium">{c.label}</div></td>
                <td>
                  <select aria-label={tr("What {0} become", { 0: c.label })} value={v} onChange={(e) => onChange({ ...value, [c.key]: e.target.value })}>
                    {c.choices.map((x) => <option key={x.value} value={x.value}>{x.label}</option>)}
                  </select>
                  <div className="small muted" style={{ marginTop: 4 }}>{ch?.example}{ch && (ch.value === "placeholder" || ch.value === "synthetic") ? tr(", comes back in replies") : ""}</div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ProfileEditor({ cats, vaults, profile, onClose, onDone }: { cats: Category[]; vaults: Vault[]; profile: Profile | null; onClose: () => void; onDone: () => void }) {
  const [vault, setVault] = useState(profile?.vault_id ?? vaults[0]?.id ?? "");
  const [name, setName] = useState(profile?.name ?? "");
  const [options, setOptions] = useState<Record<string, string>>(profile?.options ?? { person_name: "synthetic", amount: "band", date: "age_band", address: "state" });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // Only what differs from a kind's default is stored, so later defaults still apply.
  const changed = Object.fromEntries(Object.entries(options).filter(([k, v]) => cats.find((c) => c.key === k)?.default !== v));
  return (
    <Modal title={profile ? tr("Change “{0}”", { 0: profile.name }) : tr("New cloak setting")} onClose={onClose}>
      <p className="small muted">{tr("Placeholders and stand-in names are swapped back in replies, for people whose policy lets them see the real value. Ranges, states and last digits stay as they are, so they suit analysis where nobody needs the exact value.")}</p>
      {!profile && (
        <label className="field"><span>{tr("Vault")}</span><select value={vault} onChange={(e) => setVault(e.target.value)}>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
      )}
      <label className="field"><span>{tr("Name")}</span><input value={name} placeholder={tr("Support chatbot")} onChange={(e) => setName(e.target.value)} /></label>
      <Grid cats={cats} packs={vaults.find((v) => v.id === vault)?.packs ?? ["everywhere"]} value={options} onChange={setOptions} />
      <p className="small muted">{tr("Rows follow the vault’s country packs. Add a pack in Settings, Locations and laws, to cloak another country’s IDs.")}</p>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!name.trim() || !vault || saving} onClick={async () => {
          setError(null);
          setSaving(true);
          try {
            if (profile) await control(`/v1/cloak-profiles/${profile.id}`, { method: "PATCH", body: { name: name.trim(), options: changed } });
            else await control("/v1/cloak-profiles", { body: { vault_id: vault, name: name.trim(), options: changed } });
            onDone();
          } catch (e) { setError(errText(e)); } finally { setSaving(false); }
        }}>{profile ? tr("Save") : tr("Create")}</button>
      </div>
    </Modal>
  );
}

function CloakSettings({ cats, profiles, vaults, reload }: { cats: Category[]; profiles: Profile[]; vaults: Vault[]; reload: () => void }) {
  const [editing, setEditing] = useState<Profile | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const vaultName = (id: string) => vaults.find((v) => v.id === id)?.name ?? id;
  return (
    <div className="card">
      <div className="spread">
        <div>
          <h2>{tr("Cloak settings")}</h2>
          <p className="small muted">{tr("Choose what each kind of data becomes before a prompt leaves the country: a placeholder, a realistic stand-in name, or a less specific value such as an amount range, an age range or a state. The AI can still reason about it, and nothing identifies the person.")}</p>
        </div>
        <button className="primary" disabled={vaults.length === 0} onClick={() => setEditing("new")}>{tr("New cloak setting")}</button>
      </div>
      {profiles.length === 0 ? (
        <p className="small muted">{tr("No settings yet. Without one, every value becomes a placeholder and places are sent as they are.")}</p>
      ) : (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Name")}</th><th>{tr("What changes")}</th><th>{tr("Used by")}</th><th></th></tr></thead>
            <tbody>
              {profiles.map((p) => (
                <tr key={p.id}>
                  <td><div className="font-medium">{p.name}</div><span className="small muted">{vaultName(p.vault_id)}</span></td>
                  <td className="small">{summary(cats, p.options)}</td>
                  <td className="small">{p.routes.length ? p.routes.map((r) => r.name).join(", ") : <span className="muted">{tr("No routes yet")}</span>}</td>
                  <td>
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <button onClick={() => setEditing(p)}>{tr("Change")}</button>
                      <button disabled={p.routes.length > 0} title={p.routes.length ? tr("Move its routes to another setting first") : undefined} onClick={async () => {
                        setError(null);
                        try { await control(`/v1/cloak-profiles/${p.id}`, { method: "DELETE" }); reload(); } catch (e) { setError(errText(e)); }
                      }}>{tr("Delete")}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ErrorLine error={error} />
      {editing && <ProfileEditor cats={cats} vaults={vaults} profile={editing === "new" ? null : editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); reload(); }} />}
    </div>
  );
}

function Playground({ vaults, profiles }: { vaults: Vault[]; profiles: Profile[] }) {
  const [vault, setVault] = useState("");
  const [profile, setProfile] = useState("");
  const [prompt, setPrompt] = useState(SAMPLE);
  const [res, setRes] = useState<{ provider_receives: string; user_sees: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const usable = profiles.filter((p) => !vault || p.vault_id === vault);
  return (
    <div className="card">
      <h2>{tr("Playground")}</h2>
      <p className="small muted">{tr("Type a prompt, using synthetic data. Nothing is sent to any provider or stored.")}</p>
      <div className="row">
        <label className="field"><span>{tr("Detection rules from")}</span><select value={vault} onChange={(e) => { setVault(e.target.value); setProfile(""); }}><option value="">{tr("Built-in entities only")}</option>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
        <label className="field"><span>{tr("Cloak setting")}</span><select value={profile} onChange={(e) => setProfile(e.target.value)}><option value="">{tr("Placeholders for everything")}</option>{usable.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
      </div>
      <textarea className="code" aria-label={tr("Prompt")} value={prompt} onChange={(e) => setPrompt(e.target.value)} />
      <div className="row"><button className="primary" onClick={async () => {
        setError(null);
        try { setRes(await control("/v1/ai-routes/preview", { body: { prompt, ...(vault ? { vault_id: vault } : {}), ...(profile ? { profile_id: profile } : {}) } })); } catch (e) { setError(errText(e)); }
      }}>{tr("Show both sides")}</button></div>
      <ErrorLine error={error} />
      {res && (
        <div className="cards">
          <div className="slot"><b>{tr("The provider receives")}</b><pre className="pre">{res.provider_receives}</pre></div>
          <div className="slot"><b>{tr("The user gets back, with no reveal permission")}</b><pre className="pre">{res.user_sees}</pre></div>
        </div>
      )}
    </div>
  );
}

function RouteCard({ r, profiles, cats, reload }: { r: Route; profiles: Profile[]; cats: Category[]; reload: () => void }) {
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const update = async (patch: object) => {
    setError(null);
    try { await control(`/v1/ai-routes/${r.id}`, { method: "PATCH", body: patch }); reload(); } catch (e) { setError(errText(e)); }
  };
  const mine = profiles.filter((p) => p.vault_id === r.vault_id);
  const current = mine.find((p) => p.id === r.cloak_profile_id);
  return (
    <div className="card">
      <div className="spread">
        <div><h2>{r.name}</h2><span className="small muted">{r.provider}, {r.allowed_models.join(", ")}</span></div>
        <div className="row">
          <Badge tone={r.mode === "enforcing" ? "good" : "warn"}>{modeLabel(r.mode)}</Badge>
          <button className={r.mode === "shadow" ? "primary" : ""} onClick={() => setConfirm(true)}>{r.mode === "shadow" ? tr("Turn protection on") : tr("Back to watch only")}</button>
        </div>
      </div>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <label className="field" style={{ maxWidth: 320 }}><span>{tr("Cloak setting")}</span>
          <select value={r.cloak_profile_id ?? ""} onChange={(e) => update({ cloak_profile_id: e.target.value || null })}>
            <option value="">{tr("Placeholders for everything")}</option>
            {mine.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <span className="small muted">{current ? summary(cats, current.options) : tr("Every value becomes a placeholder; places are sent as they are.")}</span>
        </label>
        <label className="field" style={{ maxWidth: 320 }}><span>{tr("Digital twin")}</span>
          <select value={r.twin_days} onChange={(e) => update({ twin_days: Number(e.target.value) })}>
            {TWIN_DAYS.map((d) => <option key={d} value={d}>{d === 0 ? tr("Off: the map is forgotten after each reply") : tr("Keep for {0} days", { 0: d })}</option>)}
          </select>
          <span className="small muted">{r.twin_days > 0 ? tr("Each request's map is sealed in the vault, and its id comes back in the X-RV-Cloak-Id header. Your app swaps values back later with the uncloak API, as far as policy allows.") : tr("Turn on to swap values back later, for example in a saved conversation.")}</span>
        </label>
      </div>
      <label className="row small"><input type="checkbox" checked={r.restore_in_response} onChange={(e) => update({ restore_in_response: e.target.checked })} />{tr("Restore real values in replies, for callers whose policy allows plaintext. Everyone else gets masked values.")}</label>
      <label className="field" style={{ maxWidth: 420 }}><span>{tr("Legal ground for sending this data abroad")}</span>
        <select value={r.transfer_basis} onChange={(e) => update({ transfer_basis: e.target.value })}>
          <option value="not_assessed">{tr("Not assessed yet")}</option><option value="tokens_only">{tr("Tokens only: counsel advises no personal data leaves")}</option><option value="adequacy">{tr("Adequacy decision")}</option><option value="approved_instrument">{tr("Instrument approved by your data protection authority")}</option><option value="section_43">{tr("Another lawful ground for transfer")}</option>
        </select>
      </label>
      <div className="spread"><span className="small muted">{tr("Setup")}</span><Copy text={r.setup} /></div>
      <pre className="pre">{r.setup}</pre>
      <ErrorLine error={error} />
      {confirm && (
        <TypedConfirm title={r.mode === "shadow" ? tr("Turn protection on") : tr("Go back to watch only")} word={r.mode === "shadow" ? "protect" : "watch"} onClose={() => setConfirm(false)} onConfirm={() => update({ mode: r.mode === "shadow" ? "enforcing" : "shadow" })}>
          {r.mode === "shadow" ? tr("Identifiers are cloaked before prompts leave, using this route's cloak setting. Images, audio and files are refused, because they cannot be scanned.") : tr("Prompts will again reach the provider unredacted, and the residency report will show this.")}
        </TypedConfirm>
      )}
    </div>
  );
}

function NewRoute({ vaults, onClose, onDone }: { vaults: Vault[]; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ vault_id: "", name: "", provider: "OpenAI", upstream_base_url: "https://api.openai.com/v1", models: "" });
  const [created, setCreated] = useState<{ setup: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  if (created) {
    return (
      <Modal title={tr("Route created, watching only")} onClose={onDone}>
        <p className="muted">{tr("Point your app at this address. Prompts pass through unchanged until you turn protection on.")}</p>
        <ShownOnce items={[{ label: "Setup", value: created.setup, block: true }]} />
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onDone}>{tr("Done")}</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={tr("New AI route")} onClose={onClose}>
      <label className="field"><span>{tr("Vault")}</span><select value={f.vault_id} onChange={set("vault_id")}><option value="">{tr("Choose a vault")}</option>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
      <label className="field"><span>{tr("Name")}</span><input value={f.name} onChange={set("name")} /></label>
      <label className="field"><span>{tr("Provider")}</span><input value={f.provider} onChange={set("provider")} /></label>
      <label className="field"><span>{tr("Provider base URL")}</span><input value={f.upstream_base_url} onChange={set("upstream_base_url")} /></label>
      <label className="field"><span>{tr("Allowed models, comma-separated")}</span><input value={f.models} onChange={set("models")} /></label>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!f.vault_id || !f.name || !f.models} onClick={async () => {
          try { setCreated(await control("/v1/ai-routes", { body: { vault_id: f.vault_id, name: f.name, provider: f.provider, upstream_base_url: f.upstream_base_url, allowed_models: f.models.split(",").map((s) => s.trim()).filter(Boolean) } })); } catch (e) { setError(errText(e)); }
        }}>{tr("Create")}</button>
      </div>
    </Modal>
  );
}

export function AiRoutes({ startNew = false }: { startNew?: boolean }) {
  const { value, error, loading, reload } = useLoad<{ routes: Route[] }>(() => control("/v1/ai-routes"));
  const vaults = useLoad<{ vaults: Vault[] }>(() => control("/v1/vaults"));
  const ck = useCloak();
  const [creating, setCreating] = useState(startNew);
  const vs = vaults.value?.vaults ?? [];
  const reloadAll = () => { reload(); ck.reloadProfiles(); };
  return (
    <div className="stack">
      <div className="row"><button className="primary" onClick={() => setCreating(true)}>{tr("New AI route")}</button></div>
      <Loading error={error ?? ck.error} loading={(loading && !value) || ck.loading} />
      {value?.routes.length === 0 && <Empty title={tr("No AI tools connected yet")}>{tr("Send your AI requests through a route, and sensitive values are cloaked before prompts leave.")}</Empty>}
      {value?.routes.map((r) => <RouteCard key={r.id} r={r} profiles={ck.profiles} cats={ck.cats} reload={reloadAll} />)}
      {ck.cats.length > 0 && <CloakSettings cats={ck.cats} profiles={ck.profiles} vaults={vs} reload={reloadAll} />}
      <Playground vaults={vs} profiles={ck.profiles} />
      {creating && <NewRoute vaults={vs} onClose={() => setCreating(false)} onDone={() => { setCreating(false); reload(); }} />}
    </div>
  );
}
