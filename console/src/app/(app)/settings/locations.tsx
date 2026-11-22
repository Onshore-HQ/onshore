"use client";
import { countryName, formatPreview, setLanguage, tr } from "@/lib/i18n";
import { Lock, MapPin, Plus, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Badge, ErrorLine, Loading, Modal } from "@/components/ui";
import { useMe } from "@/components/Shell";
import { control, useLoad } from "@/lib/api";
import { InstallsCard } from "./installs";

// Settings → Locations and laws. Everything chosen at first-time setup can be
// changed here, except a vault's country, which is final.

interface Country { code: string; name: string; city: string; laws: string[]; pack: string; market?: string; format: string }
interface Law { name: string; effect: string; note?: string; sources: string[] }
interface Market { id: string; label: string; laws: string[]; pack: string }
interface Pack { name: string; ready: boolean; examples: [string, string][] }
interface Catalog { checked: string; countries: Country[]; all_countries?: { code: string; name: string; built_in: boolean }[]; laws: Record<string, Law>; markets: Market[]; packs: Record<string, Pack>; sectors: { id: string; label: string }[]; cloud_regions: string[] }
interface Vault { id: string; name: string; country: string; packs: string[]; environment: string; time_zone: string | null }
interface State {
  pack_laws?: { pack: string; pack_name: string; country_name: string; laws: { name: string; effect: string; source: string; checked_on: string }[] }[];
  edition: "free" | "business" | "enterprise" | "cloud" | "development"; install_country: string | null;
  home_country: string | null; sector: string | null; console_language: "en" | "fr"; console_format: string | null; time_zone: string;
  laws: string[]; markets: string[]; planned_countries: string[];
  suggested_laws: Record<string, string[]>; suggested_packs: string[];
  vaults: Vault[]; catalog: Catalog; waitlist?: { country: string; since: string; open: boolean }[];
}

const EDITION = { free: "Onshore Community", business: "Onshore Business", enterprise: "Onshore Enterprise", cloud: "Onshore Cloud", development: "Development build, for development and testing only" };
const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");
const toggled = (xs: string[], x: string) => (xs.includes(x) ? xs.filter((y) => y !== x) : [...xs, x]);
const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; } };
// Every IANA zone the browser knows, with the current one kept even if it does not.
const zones = (current: string) => {
  let all: string[] = [];
  try { all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? []; } catch { all = []; }
  return [...new Set(["UTC", current, ...all])];
};
const same = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

function Sources({ law }: { law: Law }) {
  return <span className="text-xs">{tr("Sources:")} {law.sources.map((s, i) => <a key={s} href={s} target="_blank" rel="noreferrer">{i > 0 ? ", " : ""}{host(s)}</a>)}</span>;
}

function PacksEditor({ vault, c, onClose, onSaved }: { vault: Vault; c: Catalog; onClose: () => void; onSaved: () => void }) {
  const [packs, setPacks] = useState(vault.packs);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const home = c.countries.find((x) => x.code === vault.country)?.pack;
  // The vault's own country first, then ready packs, then the rest.
  const order = Object.keys(c.packs).sort((a, b) => Number(b === "everywhere") - Number(a === "everywhere") || Number(b === home) - Number(a === home) || Number(c.packs[b]!.ready) - Number(c.packs[a]!.ready) || c.packs[a]!.name.localeCompare(c.packs[b]!.name));
  return (
    <Modal title={tr("Country packs for {0}", { 0: vault.name })} onClose={onClose}>
      <p className="small muted">{tr("Packs decide which ID numbers, phone and account formats this vault detects. Adding one starts detecting it in watch-only connections straight away; removing one stops it.")}</p>
      <div className="grid gap-2">
        {order.map((id) => {
          const p = c.packs[id]!, locked = id === "everywhere", on = locked || packs.includes(id);
          return (
            <label key={id} className="flex cursor-pointer items-start gap-3 rounded-lg border p-3" style={{ borderColor: "var(--border)" }}>
              <input type="checkbox" className="mt-1 size-4" checked={on} disabled={locked} onChange={() => setPacks(toggled(packs, id))} />
              <span className="grid gap-1">
                <span className="flex flex-wrap items-center gap-2"><b>{p.name}</b>{id === home && <Badge>{tr("This vault’s country")}</Badge>}<Badge tone={p.ready ? "good" : undefined}>{p.ready ? tr("Full support") : tr("Not built yet")}</Badge></span>
                <span className="small muted">{p.examples.map((e) => e[0]).join(", ")}</span>
              </span>
            </label>
          );
        })}
      </div>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={busy || same(packs, vault.packs)} onClick={async () => {
          setBusy(true); setError(null);
          try { await control(`/v1/vaults/${vault.id}/packs`, { method: "PATCH", body: { packs } }); onSaved(); } catch (e) { setError(errText(e)); setBusy(false); }
        }}>{tr("Save packs")}</button>
      </div>
    </Modal>
  );
}

export function LocationsCard() {
  const me = useMe();
  const admin = !!me?.roles.includes("admin");
  const { value, error, loading, reload } = useLoad<State>(() => control("/v1/settings/locations"));
  const [laws, setLaws] = useState<string[]>([]);
  const [markets, setMarkets] = useState<string[]>([]);
  const [prefs, setPrefs] = useState({ home_country: "", sector: "", console_language: "en" as "en" | "fr", console_format: "", time_zone: "UTC" });
  const [editing, setEditing] = useState<Vault | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!value) return;
    setLaws(value.laws);
    setMarkets(value.markets);
    setPrefs({ home_country: value.home_country ?? value.install_country ?? "", sector: value.sector ?? "other", console_language: value.console_language, console_format: value.console_format ?? value.home_country ?? value.install_country ?? "", time_zone: value.time_zone });
  }, [value]);

  const c = useMemo(() => {
    const cat = value?.catalog;
    if (!cat) return cat;
    // Every country, so a vault in a country without a built-in pack still shows its name.
    const built = new Set(cat.countries.map((x: { code: string }) => x.code));
    const others = (cat.all_countries ?? []).filter((x: { code: string; built_in: boolean }) => !built.has(x.code)).map((x: { code: string; name: string }) => ({ code: x.code, name: countryName(x.code, x.name), region: "Other countries", city: "", laws: [], pack: "", format: "" }));
    return { ...cat, countries: [...cat.countries, ...others] };
  }, [value]);
  const by = useMemo(() => Object.fromEntries((c?.countries ?? []).map((x) => [x.code, x])), [c]);

  // Suggestions follow the markets as edited here, before saving.
  const suggested = useMemo(() => {
    const out = new Map<string, string[]>(Object.entries(value?.suggested_laws ?? {}));
    if (!c || !value) return out;
    for (const m of c.markets) {
      const why = tr("You serve {0}", { 0: m.label.replace("People in ", "people in ") });
      for (const l of m.laws) {
        const w = (out.get(l) ?? []).filter((x) => x !== why);
        if (markets.includes(m.id)) w.push(why);
        if (w.length) out.set(l, w); else out.delete(l);
      }
    }
    return out;
  }, [c, value, markets]);

  if (!value || !c) return <Loading error={error} loading={loading} />;

  const dirty = !same(laws, value.laws) || !same(markets, value.markets) || prefs.home_country !== (value.home_country ?? value.install_country ?? "") || prefs.sector !== (value.sector ?? "other") || prefs.console_language !== value.console_language || prefs.console_format !== (value.console_format ?? value.home_country ?? value.install_country ?? "") || prefs.time_zone !== value.time_zone;
  const missing = [...suggested.keys()].filter((id) => !laws.includes(id));
  const save = async (body: object, done: string) => {
    setBusy(true); setErr(null); setMsg(null);
    try { await control("/v1/settings/locations", { method: "PATCH", body }); setMsg(done); reload(); } catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };

  return (
    <div className="stack">
      {msg && <div className="note good">{msg}</div>}
      <ErrorLine error={err} />
      {!admin && <div className="note">{tr("Only an admin can change these. You can see them.")}</div>}

      <div className="card">
        <h2>{tr("Where your data lives")}</h2>
        <p className="small muted">{tr(EDITION[value.edition])}{value.edition !== "cloud" ? (value.install_country ? tr(". This install keeps data in {0}, set when it was installed.", { 0: by[value.install_country]?.name ?? value.install_country }) : tr(". This install's country has not been set yet.")) : "."} {tr("A vault’s country is final: moving data means a new vault.")}</p>
        <div className="grid gap-2">
          {value.vaults.map((v) => (
            <div key={v.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3" style={{ borderColor: "var(--border)" }}>
              <div className="grid gap-1">
                <span className="flex flex-wrap items-center gap-2"><b>{v.name}</b>{v.environment === "sandbox" && <Badge>{tr("Sandbox")}</Badge>}</span>
                <span className="small muted flex items-center gap-1.5"><Lock size={13} aria-label={tr("Fixed")} />{by[v.country]?.name ?? v.country} {tr("· Packs:")} {v.packs.map((p) => c.packs[p]?.name ?? p).join(", ")}</span>
              </div>
              <div className="row">
                <label className="sr-only" htmlFor={`tz-${v.id}`}>{tr("Time zone for")} {v.name}</label>
                <select id={`tz-${v.id}`} disabled={!admin || busy} value={v.time_zone ?? ""} title={tr("Where this vault's day ends in charts and the residency map")} onChange={async (e) => {
                  setErr(null); setMsg(null);
                  try { await control(`/v1/vaults/${v.id}/time-zone`, { method: "PATCH", body: { time_zone: e.target.value || null } }); setMsg(tr("{0} now counts days in {1}.", { 0: v.name, 1: e.target.value || "the organisation's time zone" })); reload(); } catch (x) { setErr(errText(x)); }
                }}>
                  <option value="">{tr("Organisation’s zone (")}{value.time_zone.replace(/_/g, " ")})</option>
                  {zones(v.time_zone ?? value.time_zone).filter((z) => z !== "UTC" || v.time_zone === "UTC").map((z) => <option key={z} value={z}>{z.replace(/_/g, " ")}</option>)}
                </select>
                {admin && <button onClick={() => setEditing(v)}>{tr("Change packs")}</button>}
              </div>
            </div>
          ))}
        </div>
      </div>

      <InstallsCard edition={value.edition} countries={c.countries} admin={admin} waitlist={value.waitlist ?? []} onChange={reload} />

      <div className="card">
        <h2>{tr("Where your customers live")}</h2>
        <p className="small muted">{tr("This changes which laws we suggest and which packs new vaults start with.")}</p>
        <div className="flex flex-wrap gap-2">
          {c.markets.map((m) => {
            const on = markets.includes(m.id);
            return <button key={m.id} type="button" disabled={!admin} aria-pressed={on} onClick={() => setMarkets(toggled(markets, m.id))} className="min-h-9 rounded-full border px-3.5 text-sm font-medium" style={{ borderColor: on ? "var(--primary)" : "var(--input)", background: on ? "var(--primary)" : "var(--card)", color: on ? "var(--primary-foreground)" : "var(--foreground)" }}>{tr(m.label)}</button>;
          })}
        </div>
      </div>

      <div className="card">
        <h2>{tr("Laws that apply")}</h2>
        <p className="small muted">{tr("They set up your reports and the grounds you can record for sending data abroad. This is not legal advice: confirm the list with your lawyer or data protection officer. Summaries last checked")} {new Date(c.checked).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" })}.</p>
        {laws.length === 0 && <p className="small muted">{tr("No laws on your list yet.")}</p>}
        <div className="grid gap-2">
          {laws.map((id) => {
            const l = c.laws[id];
            if (!l) return null;
            return (
              <div key={id} className="flex items-start justify-between gap-3 rounded-lg border p-3.5" style={{ borderColor: "var(--border)" }}>
                <span className="grid min-w-0 gap-1.5">
                  <b>{l.name}</b>
                  {(suggested.get(id) ?? []).length > 0 ? <span className="flex flex-wrap gap-1.5">{suggested.get(id)!.map((w) => <Badge key={w} tone="info">{w}</Badge>)}</span> : <span><Badge>{tr("Added by you")}</Badge></span>}
                  <span className="small muted">{l.effect}</span>
                  {l.note && <span className="text-[13px]" style={{ color: "var(--warn)" }}>{l.note}</span>}
                  <Sources law={l} />
                </span>
                {admin && <button aria-label={tr("Remove {0}", { 0: l.name })} title={tr("Remove")} onClick={() => setLaws(laws.filter((x) => x !== id))}><X size={15} aria-hidden /></button>}
              </div>
            );
          })}
        </div>
        {missing.length > 0 && (
          <div className="grid gap-2">
            <h3 className="m-0 mt-2 text-sm font-semibold">{tr("Suggested, not on your list")}</h3>
            {missing.map((id) => {
              const l = c.laws[id]!;
              return (
                <div key={id} className="flex items-start justify-between gap-3 rounded-lg border border-dashed p-3.5" style={{ borderColor: "var(--input)" }}>
                  <span className="grid min-w-0 gap-1.5"><b>{l.name}</b><span className="flex flex-wrap gap-1.5">{suggested.get(id)!.map((w) => <Badge key={w} tone="info">{w}</Badge>)}</span><span className="small muted">{l.effect}</span><Sources law={l} /></span>
                  {admin && <button onClick={() => setLaws([...laws, id])}><Plus size={15} aria-hidden /> {tr("Add")}</button>}
                </div>
              );
            })}
          </div>
        )}
        {(value?.pack_laws ?? []).length > 0 && (
          <div className="grid gap-2">
            <h3 className="m-0 text-sm font-semibold">{tr("From your country packs")}</h3>
            {(value?.pack_laws ?? []).map((p) => p.laws.map((l) => (
              <div key={`${p.pack}-${l.name}`} className="rounded-lg border px-4 py-3 small" style={{ borderColor: "var(--border)" }}>
                <b>{l.name}</b> <span className="muted">· {p.country_name} · {tr("{0} pack", { 0: p.pack_name })}</span>
                {l.effect && <div>{l.effect}</div>}
                <div className="muted"><a href={l.source} target="_blank" rel="noreferrer">{tr("Source")}</a> · {tr("checked {0}", { 0: l.checked_on })}</div>
              </div>
            )))}
          </div>
        )}
        {admin && (
          <label className="field" style={{ maxWidth: 420 }}><span>{tr("Add another law")}</span>
            <select value="" onChange={(e) => { if (e.target.value) setLaws([...laws, e.target.value]); }}>
              <option value="">{tr("Choose a law")}</option>
              {Object.entries(c.laws).filter(([id]) => !laws.includes(id)).map(([id, l]) => <option key={id} value={id}>{l.name}</option>)}
            </select>
          </label>
        )}
      </div>

      <div className="card">
        <h2>{tr("Organisation and display")}</h2>
        <div className="flex flex-wrap gap-4">
          <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Your country")}</span>
            <select disabled={!admin} value={prefs.home_country} onChange={(e) => setPrefs({ ...prefs, home_country: e.target.value })}>{c.countries.map((x) => <option key={x.code} value={x.code}>{x.name}</option>)}</select>
          </label>
          <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Sector")}</span>
            <select disabled={!admin} value={prefs.sector} onChange={(e) => setPrefs({ ...prefs, sector: e.target.value })}>{c.sectors.map((s) => <option key={s.id} value={s.id}>{tr(s.label)}</option>)}</select>
          </label>
        </div>
        <div className="flex flex-wrap gap-4">
          <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Console language")}</span>
            <select disabled={!admin} value={prefs.console_language} onChange={(e) => setPrefs({ ...prefs, console_language: e.target.value as "en" | "fr" })}><option value="en">{tr("English")}</option><option value="fr">{tr("Français")}</option></select>
          </label>
          <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Dates and numbers like")}</span>
            <select disabled={!admin} value={prefs.console_format} onChange={(e) => setPrefs({ ...prefs, console_format: e.target.value })}>{c.countries.map((x) => <option key={x.code} value={x.code}>{x.name}</option>)}</select>
          </label>
        </div>
        <label className="field" style={{ maxWidth: 460 }}><span>{tr("Your organisation’s time zone")}</span>
          <select disabled={!admin} value={prefs.time_zone} onChange={(e) => setPrefs({ ...prefs, time_zone: e.target.value })}>{zones(prefs.time_zone).map((z) => <option key={z} value={z}>{z.replace(/_/g, " ")}</option>)}</select>
          <span className="small muted">{tr("Decides where a day ends in usage charts, the residency map and the signed daily audit checkpoints. A change applies from the next day.")}</span>
        </label>
        <p className="small muted m-0"><MapPin size={13} aria-hidden className="mr-1 inline align-[-2px]" />{tr("Preview:")} <code>{formatPreview(prefs.console_format, by[prefs.console_format]?.format)}</code>{tr(". Display only: it doesn’t decide where data is kept or which laws apply.")}</p>
      </div>

      {admin && (
        <div className="row" style={{ position: "sticky", bottom: 12, justifyContent: "flex-end", gap: 10 }}>
          {dirty && <span className="small" style={{ color: "var(--warn)" }}>{tr("Unsaved changes")}</span>}
          <button disabled={!dirty || busy} onClick={() => { if (value) { setLaws(value.laws); setMarkets(value.markets); reload(); } }}>{tr("Discard")}</button>
          <button className="primary" disabled={!dirty || busy} onClick={async () => { await save({ laws, markets, ...prefs }, tr("Locations and laws saved.")); setLanguage(prefs.console_language); }}>{tr("Save changes")}</button>
        </div>
      )}

      {editing && <PacksEditor vault={editing} c={c} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); setMsg("Packs saved. Detection updates within a few seconds."); reload(); }} />}
    </div>
  );
}
