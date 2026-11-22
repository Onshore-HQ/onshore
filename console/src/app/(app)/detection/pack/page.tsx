"use client";
import { countryName, tr } from "@/lib/i18n";
import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useMe } from "@/components/Shell";
import { Badge, ErrorLine, Loading, Page, TypedConfirm } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { Chips, ValidatorFields, type Definition, type Validator } from "../shared";

interface DataType {
  slug: string; kind: string; name: string; definition: Definition; validator?: Validator | null;
  context_positive: string[]; context_negative: string[]; threshold: number;
  token_kind: string; token_format: string; mask_rule: { type: string; n?: number; text?: string }; actions: Record<string, string>;
  tests: { sample: string; expect_match: boolean }[];
  /** A key for React only; never saved. */
  _k?: string;
}
interface Law { name: string; effect: string; source: string; checked_on: string }
interface Detail { pack: { id: string; country: string; country_name: string; name: string; description: string; version: number; origin: string; imported_from: { organisation: string; fingerprint: string } | null; data_types: DataType[]; laws: Law[] }; vaults: { id: string; name: string; country: string; data_types: number; up_to_date: boolean }[] }
type TestResult = { results: { slug: string; name: string; passed: number; failed: { sample: string; expect_match: boolean }[]; enough_samples: boolean }[]; ready: boolean };
type ApplyResult = { results: { slug: string; outcome: string; request?: string; error?: string }[]; country_matches: boolean; vault_country: string };

const MANAGE = ["admin", "detection_manager"];
const KIND_OPTIONS: [string, string][] = [["pattern", "Pattern"], ["after_keyword", "Value after a word"], ["keyword_list", "Keyword list"], ["json_path", "JSON field"]];
const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");
const today = () => new Date().toISOString().slice(0, 10);

function blankType(country: string, n: number): DataType {
  return { _k: Math.random().toString(36).slice(2), slug: `c_${country.toLowerCase()}_id${n ? `_${n + 1}` : ""}`, kind: "pattern", name: "", definition: { regex: "" }, validator: null, context_positive: [], context_negative: [], threshold: 0.7, token_kind: "deterministic", token_format: "opaque", mask_rule: { type: "last_n", n: 4 }, actions: {}, tests: [] };
}
const lines = (t: DataType, match: boolean) => t.tests.filter((x) => x.expect_match === match).map((x) => x.sample).join("\n");
const withLines = (t: DataType, match: boolean, text: string): DataType => ({ ...t, tests: [...t.tests.filter((x) => x.expect_match !== match), ...text.split("\n").map((s) => s.trim()).filter(Boolean).map((sample) => ({ sample, expect_match: match }))] });

function TypeEditor({ t, onChange, onRemove, readOnly }: { t: DataType; onChange: (t: DataType) => void; onRemove: () => void; readOnly: boolean }) {
  const defn = (d: Partial<Definition>) => onChange({ ...t, definition: { ...t.definition, ...d } });
  return (
    <fieldset disabled={readOnly} className="grid gap-2 rounded-lg border p-4" style={{ borderColor: "var(--border)" }}>
      <div className="row">
        <label className="field" style={{ flex: 2 }}><span>{tr("Name")}</span><input value={t.name} onChange={(e) => onChange({ ...t, name: e.target.value })} placeholder={tr("National ID card number")} /></label>
        <label className="field" style={{ flex: 1 }}><span>{tr("Slug")}</span><input className="mono" value={t.slug} onChange={(e) => onChange({ ...t, slug: e.target.value.toLowerCase() })} /></label>
      </div>
      <label className="field"><span>{tr("How to find it")}</span>
        <select value={t.kind} onChange={(e) => onChange({ ...t, kind: e.target.value, definition: {}, validator: null })}>{KIND_OPTIONS.map(([k, l]) => <option key={k} value={k}>{tr(l)}</option>)}</select>
      </label>
      {t.kind === "pattern" && (
        <>
          <label className="field"><span>{tr("Pattern (RE2)")}</span><input className="mono" value={t.definition.regex ?? ""} onChange={(e) => defn({ regex: e.target.value })} placeholder="\b[A-Z]{1,2}\d{5,6}\b" /></label>
          <ValidatorFields value={t.validator} onChange={(validator) => onChange({ ...t, validator })} />
        </>
      )}
      {t.kind === "after_keyword" && <Chips label={tr("Cue words")} value={t.definition.cues ?? []} onChange={(cues) => defn({ cues })} placeholder={tr("CIN, Cédula, RUT")} />}
      {t.kind === "keyword_list" && <Chips label={tr("Terms")} value={t.definition.terms ?? []} onChange={(terms) => defn({ terms })} />}
      {t.kind === "json_path" && <Chips label={tr("JSON paths")} value={t.definition.paths ?? []} onChange={(paths) => defn({ paths })} placeholder={tr("$.customer.national_id")} />}
      <Chips label={tr("Words nearby that make a match more likely, in any language")} value={t.context_positive} onChange={(context_positive) => onChange({ ...t, context_positive })} />
      <div className="row" style={{ alignItems: "stretch" }}>
        <label className="field" style={{ flex: 1 }}><span>{tr("Must match, one made-up example per line (at least 3)")}</span><textarea className="code" rows={4} defaultValue={lines(t, true)} onBlur={(e) => onChange(withLines(t, true, e.target.value))} /></label>
        <label className="field" style={{ flex: 1 }}><span>{tr("Must not match, one per line (at least 3)")}</span><textarea className="code" rows={4} defaultValue={lines(t, false)} onBlur={(e) => onChange(withLines(t, false, e.target.value))} /></label>
      </div>
      {!readOnly && <div className="row" style={{ justifyContent: "flex-end" }}><button className="danger" type="button" onClick={onRemove}>{tr("Remove this data type")}</button></div>}
    </fieldset>
  );
}

function PackEditor() {
  const id = useSearchParams().get("id") ?? "";
  const me = useMe();
  const canManage = (me?.roles ?? []).some((r) => MANAGE.includes(r));
  const d = useLoad<Detail>(() => control(`/v1/packs/${id}`), [id]);
  const vaults = useLoad<{ vaults: { id: string; name: string; country: string }[] }>(() => control("/v1/vaults"));
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [types, setTypes] = useState<DataType[]>([]);
  const [laws, setLaws] = useState<Law[]>([]);
  const [dirty, setDirty] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const [target, setTarget] = useState("");
  const [applied, setApplied] = useState<ApplyResult | null>(null);
  const [archiving, setArchiving] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!d.value) return;
    const p = d.value.pack;
    setName(p.name); setDescription(p.description); setTypes(p.data_types.map((t) => ({ ...t, _k: Math.random().toString(36).slice(2) }))); setLaws(p.laws); setDirty(false);
  }, [d.value]);
  const p = d.value?.pack;
  const change = <T,>(fn: (v: T) => void) => (v: T) => { fn(v); setDirty(true); setMsg(null); };
  const run = async (fn: () => Promise<void>) => { setErr(null); setMsg(null); setBusy(true); try { await fn(); } catch (e) { setErr(errText(e)); } finally { setBusy(false); } };
  const save = () => run(async () => {
    const r = await control(`/v1/packs/${id}`, { method: "PUT", body: { name, description, data_types: types.map(({ _k, ...t }) => t), laws } });
    setDirty(false); setMsg(tr("Saved as version {0}.", { 0: r.version })); setTest(null); d.reload();
  });
  return (
    <Page title={p ? p.name : tr("Country pack")} sub={p ? tr("{0} · version {1}. Your own data types and laws for this country.", { 0: countryName(p.country, p.country_name), 1: p.version }) : undefined}
      actions={<Link className="btn" href="/detection?tab=packs">{tr("All country packs")}</Link>}>
      <Loading loading={d.loading && !d.value} error={d.error} />
      {p && (
        <div className="stack" style={{ maxWidth: 860 }}>
          {p.imported_from && <div className="note small">{tr("Imported from a file signed by {0}. Fingerprint:", { 0: p.imported_from.organisation || tr("an unnamed organisation") })} <code>{p.imported_from.fingerprint}</code></div>}
          {msg && <div className="note good">{msg}</div>}
          <ErrorLine error={err} />
          <div className="card">
            <h2>{tr("About this pack")}</h2>
            <label className="field"><span>{tr("Name")}</span><input disabled={!canManage} value={name} onChange={(e) => change(setName)(e.target.value)} /></label>
            <label className="field"><span>{tr("What it covers")}</span><textarea disabled={!canManage} rows={2} value={description} onChange={(e) => change(setDescription)(e.target.value)} /></label>
          </div>

          <div className="card">
            <div className="spread"><h2 className="m-0">{tr("Data types")}</h2>{canManage && <button onClick={() => change(setTypes)([...types, blankType(p.country, types.length)])}>{tr("Add a data type")}</button>}</div>
            <p className="small muted m-0">{tr("Names, emails, cards, amounts and phone numbers with a country code are found everywhere already. Add this country's IDs and account numbers. Use made-up examples only.")}</p>
            {types.length === 0 && <p className="small">{tr("None yet.")}</p>}
            {types.map((t, i) => <TypeEditor key={t._k ?? i} t={t} readOnly={!canManage} onChange={(v) => change(setTypes)(types.map((x, j) => (j === i ? v : x)))} onRemove={() => change(setTypes)(types.filter((_, j) => j !== i))} />)}
          </div>

          <div className="card">
            <div className="spread"><h2 className="m-0">{tr("Laws")}</h2>{canManage && <button onClick={() => change(setLaws)([...laws, { name: "", effect: "", source: "https://", checked_on: today() }])}>{tr("Add a law")}</button>}</div>
            <p className="small muted m-0">{tr("Shown in Settings under Locations and laws, with the source and the date you checked it. A summary, not legal advice.")}</p>
            {laws.map((l, i) => (
              <fieldset key={i} disabled={!canManage} className="grid gap-2 rounded-lg border p-3" style={{ borderColor: "var(--border)" }}>
                <label className="field"><span>{tr("Name")}</span><input value={l.name} onChange={(e) => change(setLaws)(laws.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} /></label>
                <label className="field"><span>{tr("What it asks of you")}</span><textarea rows={2} value={l.effect} onChange={(e) => change(setLaws)(laws.map((x, j) => (j === i ? { ...x, effect: e.target.value } : x)))} /></label>
                <div className="row">
                  <label className="field" style={{ flex: 3 }}><span>{tr("Source (https)")}</span><input value={l.source} onChange={(e) => change(setLaws)(laws.map((x, j) => (j === i ? { ...x, source: e.target.value } : x)))} /></label>
                  <label className="field" style={{ flex: 1 }}><span>{tr("Checked on")}</span><input type="date" value={l.checked_on} onChange={(e) => change(setLaws)(laws.map((x, j) => (j === i ? { ...x, checked_on: e.target.value } : x)))} /></label>
                </div>
                {canManage && <div className="row" style={{ justifyContent: "flex-end" }}><button className="danger" type="button" onClick={() => change(setLaws)(laws.filter((_, j) => j !== i))}>{tr("Remove")}</button></div>}
              </fieldset>
            ))}
          </div>

          {canManage && <div className="row"><button className="primary" disabled={!dirty || busy} onClick={save}>{tr("Save pack")}</button>{dirty && <span className="small muted">{tr("Unsaved changes")}</span>}</div>}

          <div className="card">
            <h2>{tr("Test")}</h2>
            <p className="small muted m-0">{tr("Runs each data type's examples, without a vault. Every data type needs at least 3 of each, all passing, before it can be published.")}</p>
            <div className="row"><button disabled={dirty || busy || !p.data_types.length} onClick={() => run(async () => setTest(await control(`/v1/packs/${id}/test`, { body: {} })))}>{tr("Test the saved pack")}</button></div>
            {test && (
              <div className="grid gap-1 small">
                {test.results.map((r) => (
                  <div key={r.slug}><Badge tone={r.failed.length || !r.enough_samples ? "bad" : "good"}>{r.failed.length || !r.enough_samples ? tr("fix") : tr("ready")}</Badge> <b>{r.name}</b> · {tr("{0} passed", { 0: r.passed })}{r.failed.length ? ` · ${tr("{0} failed: {1}", { 0: r.failed.length, 1: r.failed.map((f) => `${f.expect_match ? tr("missed") : tr("wrongly matched")} “${f.sample}”`).join("; ") })}` : ""}{!r.enough_samples ? ` · ${tr("needs at least 3 examples of each kind")}` : ""}</div>
                ))}
                {test.ready && <div className="note good">{tr("Every data type passes. Apply the pack to a vault.")}</div>}
              </div>
            )}
          </div>

          <div className="card">
            <h2>{tr("Use it in a vault")}</h2>
            <p className="small muted m-0">{tr("Creates or updates this pack's data types in the vault and asks to publish each one. A second person approves them under Data types → Your own; until then nothing changes in traffic. They start in Watch only.")}</p>
            {d.value!.vaults.length > 0 && <ul className="small m-0">{d.value!.vaults.map((v) => <li key={v.id}>{v.name} · {v.data_types === 1 ? tr("1 data type") : tr("{0} data types", { 0: v.data_types })} {v.up_to_date ? <Badge tone="good">{tr("up to date")}</Badge> : <Badge tone="warn">{tr("older version")}</Badge>}</li>)}</ul>}
            {canManage && (
              <div className="row">
                <select aria-label={tr("Vault")} value={target} onChange={(e) => { setTarget(e.target.value); setApplied(null); }}><option value="" disabled>{tr("Choose a vault")}</option>{(vaults.value?.vaults ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
                <button className="primary" disabled={!target || dirty || busy || !p.data_types.length} onClick={() => run(async () => { setApplied(await control(`/v1/packs/${id}/apply`, { body: { vault: target } })); d.reload(); })}>{tr("Apply to this vault")}</button>
              </div>
            )}
            {applied && (
              <div className="grid gap-1 small">
                {!applied.country_matches && <div className="note warn small">{tr("This vault keeps data in {0}, not {1}. That's fine if its customers include people from {1}.", { 0: applied.vault_country, 1: countryName(p.country, p.country_name) })}</div>}
                {applied.results.map((r) => <div key={r.slug}><code>{r.slug}</code>: {r.outcome === "created" ? tr("created") : r.outcome === "updated" ? tr("updated") : r.outcome === "unchanged" ? tr("already up to date") : tr("skipped")}{r.request ? ` · ${tr("waiting for approval")}` : ""}{r.error ? ` · ${r.error}` : ""}</div>)}
                <Link href="/detection?tab=custom" className="small">{tr("Go to Your own to approve them")}</Link>
              </div>
            )}
          </div>

          {canManage && (
            <div className="card">
              <h2>{tr("Share")}</h2>
              <p className="small muted m-0">{tr("Download the saved pack as a file signed by your organisation. Another organisation can import it, and see whether it was changed after you signed it.")}</p>
              <div className="row">
                <button disabled={dirty || busy} onClick={() => run(async () => {
                  const file = await control(`/v1/packs/${id}/export`);
                  const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: "application/json" }));
                  const a = document.createElement("a"); a.href = url; a.download = `${p.country.toLowerCase()}-${p.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-v${p.version}.onshore-pack.json`; a.click(); URL.revokeObjectURL(url);
                })}>{tr("Download signed file")}</button>
                <button className="danger" onClick={() => setArchiving(true)}>{tr("Archive pack")}</button>
              </div>
            </div>
          )}
          {archiving && <TypedConfirm title={tr("Archive this pack")} word="archive" onClose={() => setArchiving(false)} onConfirm={async () => { await control(`/v1/packs/${id}`, { method: "DELETE" }); window.location.href = "/detection?tab=packs"; }}>{tr("Data types already in vaults stay as they are. You can't apply this pack again.")}</TypedConfirm>}
        </div>
      )}
    </Page>
  );
}

export default function PackPage() {
  return <Suspense><PackEditor /></Suspense>;
}
