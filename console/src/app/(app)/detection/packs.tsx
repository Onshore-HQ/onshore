"use client";
import { countryName, tr } from "@/lib/i18n";
import { Globe2, Upload } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { Badge, Empty, ErrorLine, Loading, Modal } from "@/components/ui";
import { control, day, useLoad } from "@/lib/api";

export interface PackSummary { id: string; country: string; country_name: string; name: string; description: string; version: number; data_types: number; laws: number; origin: string; imported_from: { organisation: string; fingerprint: string; signed_at: string } | null; updated_at: string }
interface Preview { country: string; country_name: string; name: string; description: string; data_types: { slug: string; name: string; kind: string }[]; laws: { name: string; source: string }[]; signed_by: { organisation: string; fingerprint: string; signed_at: string } }
const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");

/** Your own country packs: data types and laws for a country, applied to vaults like a built-in pack. */
export function CountryPacks({ canManage }: { canManage: boolean }) {
  const packs = useLoad<{ packs: PackSummary[] }>(() => control("/v1/packs"));
  const cat = useLoad<{ all_countries: { code: string; name: string; built_in: boolean }[] }>(() => control("/v1/catalog"));
  const [making, setMaking] = useState(false);
  const [f, setF] = useState({ country: "", name: "", description: "" });
  const [file, setFile] = useState<Record<string, unknown> | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const countries = (cat.value?.all_countries ?? []).map((c) => ({ ...c, name: countryName(c.code, c.name) })).sort((a, b) => a.name.localeCompare(b.name));
  return (
    <div className="stack">
      <div className="card">
        <div className="spread">
          <div><h2 className="m-0">{tr("Country packs")}</h2><p className="small muted m-0">{tr("A pack holds a country's ID formats, cue words and laws. Make one for a country without a built-in pack, or to add to one that has it. Applying a pack to a vault creates its data types there; each is tested and needs a second person's approval before it protects anything.")}</p></div>
          {canManage && <div className="row"><button onClick={() => { setErr(null); input.current?.click(); }}><Upload size={15} aria-hidden /> {tr("Import a pack file")}</button><button className="primary" onClick={() => setMaking(true)}>{tr("New country pack")}</button></div>}
        </div>
        <input ref={input} type="file" accept=".json,application/json" hidden onChange={async (e) => {
          const fl = e.target.files?.[0]; e.target.value = "";
          if (!fl) return;
          setErr(null);
          try {
            const parsed = JSON.parse(await fl.text());
            const r = await control("/v1/packs/import", { body: { file: parsed, preview: true } });
            setFile(parsed); setPreview(r.preview);
          } catch (x) { setErr(x instanceof SyntaxError ? tr("That file isn't valid JSON.") : errText(x)); }
        }} />
        <ErrorLine error={err} />
      </div>
      <Loading loading={packs.loading} error={packs.error} />
      {packs.value && packs.value.packs.length === 0 && (
        <Empty title={tr("No country packs yet")}><p>{tr("Every country can have a vault. For one without a built-in pack, add its ID formats and laws here, or import a pack file a partner or the community shares.")}</p></Empty>
      )}
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}>
        {(packs.value?.packs ?? []).map((p) => (
          <Link key={p.id} href={`/detection/pack?id=${p.id}`} className="card" style={{ textDecoration: "none", color: "inherit" }}>
            <div className="spread"><span className="flex items-center gap-2"><code className="badge">{p.country}</code><b>{p.name}</b></span><Badge>{tr("v{0}", { 0: p.version })}</Badge></div>
            <span className="small muted">{countryName(p.country, p.country_name)} · {p.data_types === 1 ? tr("1 data type") : tr("{0} data types", { 0: p.data_types })} · {p.laws === 1 ? tr("1 law") : tr("{0} laws", { 0: p.laws })}</span>
            {p.imported_from ? <span className="small">{tr("Imported, signed by {0}", { 0: p.imported_from.organisation || tr("an unnamed organisation") })}</span> : <span className="small muted">{tr("Updated {0}", { 0: day(p.updated_at) })}</span>}
          </Link>
        ))}
      </div>
      {making && (
        <Modal title={tr("New country pack")} onClose={() => setMaking(false)}>
          <label className="field"><span>{tr("Country")}</span>
            <select value={f.country} onChange={(e) => { const c = countries.find((x) => x.code === e.target.value); setF({ ...f, country: e.target.value, name: f.name || (c ? c.name : "") }); }}>
              <option value="" disabled>{tr("Choose a country")}</option>
              {countries.map((c) => <option key={c.code} value={c.code}>{c.name}{c.built_in ? ` · ${tr("has a built-in pack")}` : ""}</option>)}
            </select>
          </label>
          <label className="field"><span>{tr("Name")}</span><input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
          <label className="field"><span>{tr("What it covers (optional)")}</span><textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
          <ErrorLine error={err} />
          <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={() => setMaking(false)}>{tr("Cancel")}</button><button className="primary" disabled={!f.country || f.name.trim().length < 2} onClick={async () => {
            setErr(null);
            try { const r = await control("/v1/packs", { body: f }); window.location.href = `/detection/pack?id=${r.id}`; } catch (x) { setErr(errText(x)); }
          }}>{tr("Create pack")}</button></div>
        </Modal>
      )}
      {preview && file && (
        <Modal title={tr("Import this country pack?")} onClose={() => { setPreview(null); setFile(null); }}>
          <p className="m-0"><b>{preview.name}</b> · {countryName(preview.country, preview.country_name)}</p>
          {preview.description && <p className="small muted m-0">{preview.description}</p>}
          <div className="note small"><Globe2 size={14} aria-hidden /> {tr("Signed by {0} on {1}. The file hasn't changed since. Check this fingerprint with them another way, such as a call, before you rely on it:", { 0: preview.signed_by.organisation || tr("an unnamed organisation"), 1: day(preview.signed_by.signed_at) })}<br /><code>{preview.signed_by.fingerprint}</code></div>
          <div className="small"><b>{tr("Data types")}</b>: {preview.data_types.map((t) => t.name).join(", ") || tr("none")}</div>
          <div className="small"><b>{tr("Laws")}</b>: {preview.laws.map((l) => l.name).join(", ") || tr("none")}</div>
          <p className="small muted m-0">{tr("Importing changes nothing in traffic. You'll apply the pack to a vault, and each data type still needs a second person's approval.")}</p>
          <ErrorLine error={err} />
          <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={() => { setPreview(null); setFile(null); }}>{tr("Cancel")}</button><button className="primary" onClick={async () => {
            setErr(null);
            try { const r = await control("/v1/packs/import", { body: { file } }); window.location.href = `/detection/pack?id=${r.id}`; } catch (x) { setErr(errText(x)); }
          }}>{tr("Import")}</button></div>
        </Modal>
      )}
    </div>
  );
}
