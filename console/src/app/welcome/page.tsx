"use client";
import { countryName, formatPreview, tr } from "@/lib/i18n";
import { Check, Eye, MapPin, Server, TriangleAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { Logo } from "@/components/Logo";
import { control } from "@/lib/api";

// First-time setup: who the organisation is, where its data must stay, which laws
// apply and what personal data it handles. Everything is pre-filled for the
// person's country and confirmed by them; a vault's country is final.

interface Country { code: string; name: string; region: string; city: string; laws: string[]; pack: string; market?: string; eu?: boolean; format: string }
interface Law { name: string; effect: string; note?: string; sources: string[] }
interface Market { id: string; label: string; laws: string[]; pack: string }
interface Pack { name: string; ready: boolean; examples: [string, string][] }
interface Catalog { checked: string; countries: Country[]; all_countries?: { code: string; name: string; built_in: boolean }[]; laws: Record<string, Law>; markets: Market[]; packs: Record<string, Pack>; sectors: { id: string; label: string }[]; cloud_regions: string[] }
interface SetupState { needed: boolean; edition: "free" | "enterprise" | "cloud"; install_country: string | null; organisation: string; catalog: Catalog }
interface Result { vaults: { id: string; country: string }[]; planned: { country: string; reason: "enterprise_install" | "cloud_region" | "cloud_waitlist" }[]; links: { country: string; command?: string }[] }

const STEPS = ["Your organisation", "Where data stays", "Laws", "Personal data", "Check and create"];
const REGIONS = ["All", "Africa", "Middle East", "Europe", "Americas", "Asia-Pacific", "Other countries"];
const EDITION: Record<SetupState["edition"], { name: string; text: string }> = {
  free: { name: "Self-hosted, free", text: "Open source. This install keeps data in one country." },
  enterprise: { name: "Self-hosted Enterprise", text: "Vaults in other countries run on their own installs, linked to this console." },
  cloud: { name: "Onshore Cloud", text: "We run a vault for you in each country where we have a region." },
};

// The browser's time zone suggests a country. A guess only: the person confirms it.
const TZ: Record<string, string> = {
  "Africa/Lagos": "NG", "Africa/Accra": "GH", "Africa/Nairobi": "KE", "Africa/Johannesburg": "ZA", "Africa/Cairo": "EG",
  "Asia/Dubai": "AE", "Asia/Riyadh": "SA", "Asia/Qatar": "QA", "Europe/London": "GB", "Europe/Berlin": "DE", "Europe/Paris": "FR",
  "Europe/Dublin": "IE", "Europe/Amsterdam": "NL", "America/Toronto": "CA", "America/Vancouver": "CA", "America/Montreal": "CA",
  "America/Sao_Paulo": "BR", "Asia/Kolkata": "IN", "Asia/Calcutta": "IN", "Asia/Singapore": "SG",
};
// No country is assumed: the time zone, then the browser's language region, then
// the install's own country; otherwise the person picks.
function detect(install: string | null, known: Set<string>): { code: string; note: string } {
  let tz = "";
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? ""; } catch { /* older browsers */ }
  const code = TZ[tz] ?? (tz.startsWith("America/") ? "US" : null);
  if (code) return { code, note: tr("Your browser's time zone is {0}.", { 0: tz }) };
  for (const l of typeof navigator !== "undefined" ? navigator.languages ?? [] : []) {
    const region = l.split("-")[1]?.toUpperCase();
    if (region && known.has(region)) return { code: region, note: tr("Your browser's language is {0}.", { 0: l }) };
  }
  if (install) return { code: install, note: "This install keeps data there." };
  return { code: "", note: "We could not tell where you are." };
}

const browserZone = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch { return "UTC"; } };
const toggled = (xs: string[], x: string) => (xs.includes(x) ? xs.filter((y) => y !== x) : [...xs, x]);
const errText = (e: unknown) => (e instanceof Error ? e.message : "something went wrong");

function Pill({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick} className="min-h-10 rounded-full border px-4 text-sm font-medium" style={{ borderColor: on ? "var(--primary)" : "var(--input)", background: on ? "var(--primary)" : "var(--card)", color: on ? "var(--primary-foreground)" : "var(--foreground)" }}>
      {children}
    </button>
  );
}

export default function Welcome() {
  const router = useRouter();
  const [state, setState] = useState<SetupState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [step, setStep] = useState(0);
  const [detectNote, setDetectNote] = useState("");
  const [org, setOrg] = useState("");
  const [home, setHome] = useState("");
  const [installPick, setInstallPick] = useState("");
  const [sector, setSector] = useState("banking");
  const [lang, setLang] = useState<"en" | "fr">("en");
  const [fmt, setFmt] = useState("");
  const [countries, setCountries] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [region, setRegion] = useState("All");
  const [confirmed, setConfirmed] = useState(false);
  const [markets, setMarkets] = useState<string[]>([]);
  const [lawOff, setLawOff] = useState<string[]>([]);
  const [lawAdded, setLawAdded] = useState<string[]>([]);
  const [packOff, setPackOff] = useState<string[]>([]);
  const [packAdded, setPackAdded] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  // What a country choice fills in. Applied at the start and whenever the person changes it.
  const applyCountry = (code: string, s: SetupState) => {
    setHome(code);
    if (!code) return;
    setFmt(code);
    setLang(code === "FR" ? "fr" : "en");
    setMarkets([]);
    setConfirmed(false);
    // With no country set at install, the person's own country is the first guess for it.
    const inst = s.install_country ?? code;
    if (!s.install_country) setInstallPick(code);
    setCountries(s.edition === "cloud" ? [code] : [inst]);
  };

  useEffect(() => {
    control<SetupState>("/v1/setup").then((s) => {
      if (!s.needed) { router.replace("/overview"); return; }
      // Every country can be chosen. Those without a built-in pack are listed under
      // "Other countries"; the organisation can make its own pack after setup.
      const others = (s.catalog.all_countries ?? []).filter((x) => !x.built_in).map((x) => ({ code: x.code, name: countryName(x.code, x.name), region: "Other countries", city: "", laws: [], pack: "", format: "" }));
      s.catalog.countries = [...s.catalog.countries, ...others];
      setState(s);
      setOrg(s.organisation);
      const d = detect(s.install_country, new Set(s.catalog.countries.map((x) => x.code)));
      setDetectNote(d.note);
      applyCountry(d.code, s);
    }).catch((e) => setLoadError(errText(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const c = state?.catalog;
  const by = useMemo(() => Object.fromEntries((c?.countries ?? []).map((x) => [x.code, x])), [c]);
  const self = state?.edition !== "cloud";
  const install = state?.install_country ?? installPick;

  const laws = useMemo(() => {
    const out = new Map<string, string[]>();
    if (!c) return out;
    const add = (id: string, why: string) => { if (!c.laws[id]) return; const w = out.get(id) ?? []; if (!w.includes(why)) w.push(why); out.set(id, w); };
    for (const k of countries) for (const l of by[k]?.laws ?? []) add(l, tr("Data kept in {0}", { 0: by[k]!.name }));
    const servesEU = markets.includes("eu") || countries.some((k) => by[k]?.eu);
    if (sector === "banking" && countries.includes("NG")) add("cbn", "Payments data in Nigeria");
    if (sector === "banking" && servesEU) add("dora", "Financial services in the EU");
    if (sector === "banking" && countries.includes("US")) add("glba", "Financial services in the US");
    if (sector === "health" && countries.includes("US")) add("hipaa", "Health data in the US");
    for (const m of c.markets) if (markets.includes(m.id)) for (const l of m.laws) add(l, tr("You serve {0}", { 0: tr(m.label).replace(/^./, (x) => x.toLowerCase()) }));
    for (const l of lawAdded) add(l, "Added by you");
    return out;
  }, [c, by, countries, markets, sector, lawAdded]);

  const packs = useMemo(() => {
    const out = new Map<string, string>([["everywhere", "Always on, for every vault"]]);
    if (!c) return out;
    for (const k of countries) { const p = by[k]?.pack; if (p && !out.has(p)) out.set(p, tr("Vault in {0}", { 0: by[k]!.name })); }
    for (const m of c.markets) if (markets.includes(m.id) && !out.has(m.pack)) out.set(m.pack, tr("You serve {0}", { 0: tr(m.label).replace(/^./, (x) => x.toLowerCase()) }));
    for (const p of packAdded) if (!out.has(p)) out.set(p, "Added by you");
    return out;
  }, [c, by, countries, markets, packAdded]);

  if (loadError) return <main className="grid min-h-screen place-items-center p-8"><p className="err" role="alert">{loadError}</p></main>;
  if (!state || !c) return <main className="grid min-h-screen place-items-center p-8"><p className="muted">{tr("Loading setup…")}</p></main>;

  const lawsOn = [...laws.keys()].filter((id) => !lawOff.includes(id));
  const packsOn = [...packs.keys()].filter((id) => id === "everywhere" || !packOff.includes(id));
  const vaultNote = (code: string): [string, boolean] => {
    const x = by[code]!;
    if (self && code === install) return [tr("Created on this install, in {0}", { 0: x.city }), false];
    if (state.edition === "free") return ["The free edition keeps one country per install", true];
    if (self) return [tr("Needs its own Enterprise install in {0}, linked to this console. You get its join command next.", { 0: x.name }), true];
    if (code === install) return [tr("Hosted by Onshore Cloud in {0}", { 0: x.name }), false];
    if (c.cloud_regions.includes(code)) return [tr("An Onshore Cloud region in {0}, set up for you", { 0: x.name }), false];
    return [tr("Onshore Cloud has no {0} region yet: saved on the waitlist", { 0: x.name }), true];
  };
  const tooMany = state.edition === "free" && countries.length > 1;
  let blocker = "";
  if (step === 0 && !home) blocker = "Choose your country.";
  if (step === 0 && org.trim().length < 2) blocker = "Give your organisation a name.";
  if (step === 1) {
    if (self && !install) blocker = "Say which country this install keeps data in.";
    else if (countries.length === 0) blocker = "Pick at least one country.";
    else if (tooMany) blocker = "The free edition keeps one country per install. Remove the others to continue.";
    else if (!confirmed) blocker = "Confirm the warning above to continue.";
  }
  const q = query.trim().toLowerCase();
  const visible = c.countries.filter((x) => (region === "All" || x.region === region) && (!q || x.name.toLowerCase().includes(q) || x.code.toLowerCase() === q));
  const createCount = countries.filter((k) => k === install || (!self && c.cloud_regions.includes(k)) || state.edition === "enterprise").length;

  const finish = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await control<Result>("/v1/setup/complete", { body: { organisation: org.trim(), home_country: home, sector, console_language: lang, console_format: fmt, countries, markets, laws: lawsOn, packs: packsOn, confirm_countries_final: true, time_zone: browserZone(), ...(self && !state.install_country ? { install_country: install } : {}) } }));
      setStep(5);
    } catch (e) { setError(errText(e)); } finally { setBusy(false); }
  };

  const h1 = "m-0 text-[30px] font-semibold tracking-tight";
  const lead = "m-0 max-w-[660px] text-[15px]";
  return (
    <div className="min-h-screen" style={{ background: "var(--background)" }}>
      <header className="border-b" style={{ background: "var(--card)", borderColor: "var(--border)" }}>
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center justify-between gap-3 px-6 py-3">
          <div className="flex items-center gap-3"><Logo size={26} /><span className="muted border-l pl-3 text-sm" style={{ borderColor: "var(--border)" }}>{tr("First-time setup")}</span></div>
          <div className="muted flex items-center gap-4 text-sm"><span>{tr(EDITION[state.edition].name)}</span>{step < 5 && <b style={{ color: "var(--foreground)" }}>{tr("Step")} {step + 1} {tr("of 5")}</b>}</div>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1240px] flex-wrap items-start gap-8 px-6 py-8">
        <nav aria-label={tr("Setup steps")} className="grid gap-1.5" style={{ flex: "1 1 220px", maxWidth: 280 }}>
          {STEPS.map((title, i) => {
            const current = i === step, done = i < step || step === 5;
            const sub = [`${org || tr("Unnamed")} · ${by[home]?.name ?? ""}`, countries.map((k) => by[k]?.name).join(", ") || tr("Not chosen yet"), tr("{0} law{1}", { 0: lawsOn.length, 1: lawsOn.length === 1 ? "" : "s" }), tr("{0} data pack{1}", { 0: packsOn.length, 1: packsOn.length === 1 ? "" : "s" }), step === 5 ? "Done" : "Nothing created yet"][i];
            return (
              <button key={tr(title)} type="button" disabled={step === 5} aria-current={current ? "step" : undefined} onClick={() => setStep(i)} className="flex min-h-14 items-center justify-start gap-3 rounded-lg border px-3 py-2 text-left" style={{ borderColor: current ? "var(--primary)" : "transparent", background: current ? "var(--card)" : "transparent" }}>
                <span className="grid size-7 flex-none place-items-center rounded-full text-sm font-semibold" style={{ background: current ? "var(--primary)" : done ? "var(--good-soft)" : "var(--muted)", color: current ? "var(--primary-foreground)" : done ? "var(--good)" : "var(--foreground)" }}>{done ? <Check size={15} aria-label={tr("Done")} /> : i + 1}</span>
                <span className="grid min-w-0 gap-0.5"><span className="text-sm font-semibold">{title}</span><span className="muted truncate text-xs">{sub}</span></span>
              </button>
            );
          })}
          <p className="muted mt-3 px-1 text-xs">{tr("You can change all of this later in Settings, except where a vault lives.")}</p>
        </nav>

        <main className="card gap-6 p-8" style={{ flex: "999 1 560px", minWidth: 0 }}>
          {step === 0 && (
            <>
              <div className="grid gap-2"><h1 className={h1}>{tr("Your organisation")}</h1><p className={`${lead} muted`}>{tr("Tell us who you are. Your sector decides which industry rules we suggest later, such as a central bank's data rules for payment companies.")}</p></div>
              <div className="flex flex-wrap items-end justify-between gap-4 rounded-lg border p-4" style={{ background: "var(--info-soft)", borderColor: "var(--border)" }}>
                <div className="flex gap-3" style={{ flex: "1 1 320px" }}><MapPin size={20} className="mt-0.5 flex-none" style={{ color: "var(--primary)" }} aria-hidden /><div className="grid gap-0.5"><b>{home ? tr("We set things up for {0}", { 0: by[home]?.name }) : tr("Where are you?")}</b><span className="text-sm">{detectNote} {home ? tr("Every step is filled in to suit it, and you can change any of it.") : tr("Choose your country and every step is filled in to suit it.")}</span></div></div>
                <label className="field" style={{ flex: "0 1 240px" }}><span>{tr("Your country")}</span>
                  <select value={home} onChange={(e) => { setDetectNote("You chose this."); applyCountry(e.target.value, state); }}><option value="" disabled>{tr("Choose your country")}</option>{c.countries.map((x) => <option key={x.code} value={x.code}>{x.name}</option>)}</select>
                </label>
              </div>
              <label className="field max-w-[420px]"><span>{tr("Organisation name")}</span><input value={org} onChange={(e) => setOrg(e.target.value)} /></label>
              <fieldset className="grid gap-2"><legend className="mb-2 text-sm font-semibold">{tr("Sector")}</legend><div className="flex flex-wrap gap-2">{c.sectors.map((s) => <Pill key={s.id} on={sector === s.id} onClick={() => setSector(s.id)}>{tr(s.label)}</Pill>)}</div></fieldset>
              <div className="grid gap-3 rounded-lg border p-4" style={{ borderColor: "var(--border)", background: "var(--muted)" }}>
                <div className="grid gap-0.5"><b>{tr("How the console looks to you")}</b><span className="muted text-sm">{tr("Display only: it does not decide where data is kept or which laws apply.")}</span></div>
                <div className="flex flex-wrap gap-4">
                  <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Language")}</span>
                    <select value={lang} onChange={(e) => setLang(e.target.value as "en" | "fr")}><option value="en">{tr("English")}</option><option value="fr">{tr("Français")}</option><option disabled>{tr("Português (coming)")}</option><option disabled>{tr("العربية, right to left (coming)")}</option></select>
                  </label>
                  <label className="field" style={{ flex: "1 1 220px" }}><span>{tr("Dates and numbers like")}</span>
                    <select value={fmt} onChange={(e) => setFmt(e.target.value)}>{c.countries.map((x) => <option key={x.code} value={x.code}>{x.name}</option>)}</select>
                  </label>
                </div>
                <code className="text-sm">{tr("Preview:")} {formatPreview(fmt, by[fmt]?.format)}</code>
              </div>
            </>
          )}

          {step === 1 && (
            <>
              <div className="grid gap-2"><h1 className={h1}>{tr("Where must your customers’ data stay?")}</h1><p className={`${lead} muted`}>{tr("Each country you pick becomes a vault. Data stored in a vault never leaves that country. Pick where your customers’ data must live, which is not always where your company is based.")}</p></div>
              <div className="flex items-start gap-3 rounded-lg border p-4" style={{ borderColor: "var(--border)", background: "var(--muted)" }}>
                <Server size={20} className="mt-0.5 flex-none" style={{ color: "var(--primary)" }} aria-hidden />
                <div className="grid gap-0.5">
                  <b>{tr(EDITION[state.edition].name)}{self && install ? tr(": this install runs in {0}", { 0: by[install]?.name }) : ""}</b>
                  <span className="muted text-sm">{tr(EDITION[state.edition].text)}{self ? (state.install_country ? tr(" The install's country was set when it was installed and cannot change.") : tr(" Its country was not set at install, so say it here. It cannot change later.")) : ""}</span>
                  {self && !state.install_country && (
                    <label className="field mt-2" style={{ maxWidth: 320 }}><span>{tr("This install keeps data in")}</span>
                      <select value={installPick} onChange={(e) => { const v = e.target.value; setCountries([v, ...countries.filter((k) => k !== installPick && k !== v)]); setInstallPick(v); setConfirmed(false); }}>
                        <option value="" disabled>{tr("Choose a country")}</option>{c.countries.map((x) => <option key={x.code} value={x.code}>{x.name}</option>)}
                      </select>
                    </label>
                  )}
                </div>
              </div>
              <div className="grid gap-3">
                <div className="flex flex-wrap items-end gap-3">
                  <label className="field" style={{ flex: "1 1 260px" }}><span>{state.edition === "free" ? tr("Countries") : tr("Add a country")}</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={tr("Search, for example Kenya or Germany")} /></label>
                  <div role="tablist" aria-label={tr("Region")} className="flex flex-wrap gap-1.5">{REGIONS.map((r) => <Pill key={r} on={region === r} onClick={() => setRegion(r)}>{tr(r)}</Pill>)}</div>
                </div>
                <div className="grid gap-2.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))" }}>
                  {visible.map((x) => {
                    const on = countries.includes(x.code), locked = self && x.code === install, ready = c.packs[x.pack]?.ready;
                    return (
                      <button key={x.code} type="button" aria-pressed={on} aria-disabled={locked || undefined} title={locked ? tr("This install's country is always included") : undefined} onClick={() => { if (!locked) setCountries(toggled(countries, x.code)); }} className={`card pick ${on ? "on" : ""}`} style={{ minHeight: 96, justifyContent: "stretch", cursor: locked ? "default" : "pointer" }}>
                        <span className="flex items-center justify-between"><code className="badge">{x.code}</code>{on && <Check size={17} style={{ color: "var(--primary)" }} aria-hidden />}</span>
                        <b>{x.name}</b>
                        <span className={`badge ${ready || locked ? "good" : ""}`} style={{ justifySelf: "start" }}>{locked ? tr("This install") : ready ? tr("Full data pack") : !x.pack ? tr("No built-in pack: make your own") : tr("Basic: pack not built yet")}</span>
                      </button>
                    );
                  })}
                </div>
                {visible.length === 0 && <p className="muted m-0 text-sm">{tr("No country matches that search.")}</p>}
              </div>
              <div className="grid gap-2.5">
                <h2 className="m-0 text-lg font-semibold">{tr("Your vaults (")}{countries.length})</h2>
                {countries.map((k) => {
                  const [note, warn] = vaultNote(k);
                  return (
                    <div key={k} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3" style={{ borderColor: "var(--border)" }}>
                      <div className="flex items-center gap-3"><code className="badge">{k}</code><div className="grid"><b>{org} · {by[k]?.name}</b><span className="text-sm" style={{ color: warn ? "var(--warn)" : "var(--muted-foreground)" }}>{note}</span></div></div>
                      {!(self && k === install) && <button type="button" onClick={() => setCountries(countries.filter((y) => y !== k))}>{tr("Remove")}</button>}
                    </div>
                  );
                })}
              </div>
              {countries.some((k) => by[k] && !by[k]!.pack) && (
                <p className="m-0 rounded-lg border p-4 text-sm" style={{ borderColor: "var(--border)", background: "var(--muted)" }}>{tr("{0} has no built-in pack yet. Its vault still finds names, emails, cards, amounts and phone numbers. After setup, add its ID formats and laws as your own country pack, under Data types → Country packs, or import a pack file someone shares with you.", { 0: countries.filter((k) => by[k] && !by[k]!.pack).map((k) => by[k]!.name).join(", ") })}</p>
              )}
              {tooMany && (
                <div className="grid gap-2 rounded-lg border p-4" style={{ borderColor: "var(--primary)", background: "var(--info-soft)" }}>
                  <b>{tr("More than one country needs Enterprise or Onshore Cloud")}</b>
                  <span className="text-sm">{tr("The free edition keeps one country per install. Enterprise links installs in several countries under one console and one audit trail; Onshore Cloud runs them for you.")}</span>
                  <div className="flex flex-wrap gap-2"><a className="btn primary" href="https://onshorevault.com/contact" target="_blank" rel="noreferrer">{tr("Talk to us about Enterprise")}</a><button type="button" onClick={() => setCountries([install])}>{tr("Keep only")} {by[install]?.name}</button></div>
                </div>
              )}
              <label className="flex cursor-pointer items-start gap-3 rounded-lg border p-4" style={{ background: "var(--warn-soft)", borderColor: "var(--border)" }}>
                <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-1 size-5 flex-none" />
                <span className="grid gap-0.5" style={{ color: "var(--warn)" }}><b>{tr("I understand a vault’s country can’t be changed later")}</b><span className="text-sm">{tr("Moving data to another country means creating a new vault and copying it across, with its own audit trail.")}</span></span>
              </label>
            </>
          )}

          {step === 2 && (
            <>
              <div className="grid gap-2"><h1 className={h1}>{tr("These laws probably apply. Check them.")}</h1><p className={`${lead} muted`}>{tr("We picked them from where you keep data, your sector and where your customers are. They set up your reports and the grounds you can record for sending data abroad. This is not legal advice: confirm the list with your lawyer or data protection officer.")}</p></div>
              <div className="grid gap-2"><span className="text-sm font-semibold">{tr("Do you also serve people who live somewhere else?")}</span>
                <div className="flex flex-wrap gap-2">{c.markets.filter((m) => m.id !== by[home]?.market).map((m) => <Pill key={m.id} on={markets.includes(m.id)} onClick={() => setMarkets(toggled(markets, m.id))}>{tr(m.label)}</Pill>)}</div>
              </div>
              {countries.includes("US") && <p className="m-0 rounded-lg border p-4 text-sm" style={{ borderColor: "var(--border)", background: "var(--muted)" }}>{tr("The United States has no general federal privacy law. Which laws apply depends on your sector and the states your customers live in, so pick them from the list below.")}</p>}
              <div className="grid gap-2.5">
                {[...laws.entries()].map(([id, why]) => {
                  const l = c.laws[id]!, on = !lawOff.includes(id);
                  return (
                    <label key={id} className="flex cursor-pointer items-start gap-3.5 rounded-lg border p-4" style={{ borderColor: "var(--border)", opacity: on ? 1 : 0.65 }}>
                      <input type="checkbox" checked={on} onChange={() => setLawOff(toggled(lawOff, id))} className="mt-1 size-5 flex-none" />
                      <span className="grid min-w-0 gap-1.5">
                        <b>{l.name}</b>
                        <span className="flex flex-wrap gap-1.5">{why.map((w) => <span key={w} className="badge info">{w}</span>)}</span>
                        <span className="muted text-sm">{l.effect}</span>
                        {l.note && <span className="text-[13px]" style={{ color: "var(--warn)" }}>{l.note}</span>}
                        <span className="text-xs">{tr("Sources:")} {l.sources.map((s, i) => <a key={s} href={s} target="_blank" rel="noreferrer">{i > 0 ? ", " : ""}{new URL(s).hostname.replace(/^www\./, "")}</a>)}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
              <label className="field max-w-[420px]"><span>{tr("Add another law")}</span>
                <select value="" onChange={(e) => { const v = e.target.value; if (v) { setLawAdded([...lawAdded, v]); setLawOff(lawOff.filter((x) => x !== v)); } }}>
                  <option value="">{tr("Choose a law")}</option>{Object.entries(c.laws).filter(([id]) => !laws.has(id)).map(([id, l]) => <option key={id} value={id}>{l.name}</option>)}
                </select>
              </label>
              <p className="muted m-0 text-xs">{tr("Law summaries last checked")} {new Date(c.checked).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" })}.</p>
            </>
          )}

          {step === 3 && (
            <>
              <div className="grid gap-2"><h1 className={h1}>{tr("What personal data do you handle?")}</h1><p className={`${lead} muted`}>{tr("Each country pack teaches Onshore that country’s ID numbers, phone numbers and bank account formats, with their check digits where the issuer publishes them. We switched on the packs for your vaults and customers. Add any others your systems see.")}</p></div>
              <div className="flex items-start gap-3 rounded-lg border p-3.5 text-sm" style={{ background: "var(--good-soft)", borderColor: "var(--border)", color: "var(--good)" }}><Eye size={18} className="mt-0.5 flex-none" aria-hidden /><span>{tr("Everything starts in")} <b>{tr("watch only")}</b>{tr(": Onshore counts what it finds and changes nothing until you turn protection on for each connection.")}</span></div>
              <div className="grid gap-3.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))" }}>
                {[...packs.entries()].map(([id, why]) => {
                  const p = c.packs[id]!, locked = id === "everywhere", on = locked || !packOff.includes(id);
                  return (
                    <div key={id} className="card gap-3" style={{ opacity: on ? 1 : 0.7 }}>
                      <div className="flex items-start justify-between gap-3">
                        <div className="grid gap-1.5"><b className="text-base">{p.name}</b><span className={`badge ${p.ready ? "good" : ""}`} style={{ justifySelf: "start" }}>{p.ready ? tr("Full support") : tr("Community pack, not built yet")}</span></div>
                        <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm"><input type="checkbox" checked={on} disabled={locked} onChange={() => setPackOff(toggled(packOff, id))} className="size-5" />{locked ? tr("Always on") : on ? tr("On") : tr("Off")}</label>
                      </div>
                      <div className="grid gap-1.5">{p.examples.map(([label, ex]) => <div key={label} className="flex justify-between gap-3 border-t pt-1.5 text-sm" style={{ borderColor: "var(--border)" }}><span>{label}</span><code className="text-right text-[13px]">{ex}</code></div>)}</div>
                      {!p.ready && <p className="m-0 text-[13px]" style={{ color: "var(--warn)" }}>{tr("Not built yet. Until it is, this vault still catches the “everywhere” types.")}</p>}
                      <span className="muted text-xs">{why}</span>
                    </div>
                  );
                })}
              </div>
              <p className="muted m-0 text-xs">{tr("Examples show each format with made-up numbers, not real people.")}</p>
              <label className="field max-w-[420px]"><span>{tr("Add another country pack")}</span>
                <select value="" onChange={(e) => { const v = e.target.value; if (v) { setPackAdded([...packAdded, v]); setPackOff(packOff.filter((x) => x !== v)); } }}>
                  <option value="">{tr("Choose a country")}</option>{Object.entries(c.packs).filter(([id]) => !packs.has(id)).map(([id, p]) => <option key={id} value={id}>{p.name}</option>)}
                </select>
              </label>
            </>
          )}

          {step === 4 && (
            <>
              <div className="grid gap-2"><h1 className={h1}>{tr("Check and create")}</h1><p className={`${lead} muted`}>{tr("Nothing is created until you press the button. Vault countries are final; everything else can change later in Settings.")}</p></div>
              {[
                { title: "Organisation", go: 0, lines: [[org, c.sectors.find((s) => s.id === sector)?.label ?? ""], [tr("Console"), `${lang === "fr" ? "Français" : "English"} · ${by[fmt]?.format}`]] },
                { title: tr("Vaults ({0})", { 0: countries.length }), go: 1, lines: [[tr("How you run Onshore"), tr(EDITION[state.edition].name)], ...countries.map((k) => [`${org} · ${by[k]?.name}`, vaultNote(k)[0]])] },
                { title: tr("Laws ({0})", { 0: lawsOn.length }), go: 2, lines: lawsOn.map((id) => [c.laws[id]!.name, ""]) },
                { title: tr("Data packs ({0})", { 0: packsOn.length }), go: 3, lines: packsOn.map((id) => [c.packs[id]!.name, c.packs[id]!.ready ? "Full support" : "Basic until the pack is built"]) },
              ].map((s) => (
                <section key={s.title} className="grid gap-2.5 rounded-lg border px-5 py-4" style={{ borderColor: "var(--border)" }}>
                  <div className="flex items-center justify-between"><h2 className="m-0 text-base font-semibold">{s.title}</h2><button type="button" onClick={() => setStep(s.go)}>{tr("Change")}</button></div>
                  {s.lines.map(([a, b2]) => <div key={a} className="flex flex-wrap justify-between gap-x-4 gap-y-1 text-[15px]"><span>{a}</span><span className="muted">{b2}</span></div>)}
                </section>
              ))}
              {error && <p className="err m-0" role="alert">{error}</p>}
            </>
          )}

          {step === 5 && result && (
            <>
              <div className="grid gap-2">
                <span className="badge good" style={{ justifySelf: "start" }}><Check size={13} aria-hidden /> {tr("Set up")}</span>
                <h1 className={h1}>{org} {tr("is ready")}</h1>
                <p className={`${lead} muted`}>{tr("Your vaults are watching only. Connect the first tool that sends customer data abroad, and Onshore will show what it carries.")}</p>
              </div>
              {result.vaults.map((v) => <div key={v.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-5 py-4" style={{ borderColor: "var(--border)" }}><b>{org} · {by[v.country]?.name}</b><span className="badge good">{tr("Watching only")}</span></div>)}
              {result.planned.map((p) => (
                <div key={p.country} className="grid gap-1.5 rounded-lg border px-5 py-4" style={{ borderColor: "var(--border)" }}>
                  <div className="flex flex-wrap items-center justify-between gap-3"><b>{org} · {by[p.country]?.name}</b><span className="badge warn">{p.reason === "cloud_waitlist" ? tr("On the waitlist") : p.reason === "cloud_region" ? tr("Being set up") : tr("Waiting for its install")}</span></div>
                  <span className="muted text-sm">{p.reason === "cloud_waitlist" ? tr("We'll tell you when Onshore Cloud opens in {0}. Until then, its data has no vault.", { 0: by[p.country]?.name }) : p.reason === "cloud_region" ? tr("Onshore is setting up your {0} region. Its vault is created there as soon as it is ready.", { 0: by[p.country]?.name }) : tr("Run this on a server in {0}. The code works once, for 24 hours; its vault is created there as soon as the install joins. You can get a new code in Settings, Locations and laws.", { 0: by[p.country]?.name })}</span>
                  {result.links.find((l) => l.country === p.country)?.command && <pre className="pre m-0" style={{ overflowX: "auto" }}>{result.links.find((l) => l.country === p.country)!.command}</pre>}
                </div>
              ))}
              <div className="flex flex-wrap gap-3"><button type="button" className="primary" onClick={() => router.push("/connect")}>{tr("Connect your first tool")}</button><button type="button" onClick={() => router.push("/people")}>{tr("Invite your team")}</button></div>
            </>
          )}

          {step < 5 && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-5" style={{ borderColor: "var(--border)" }}>
              <div>{step > 0 && <button type="button" onClick={() => setStep(step - 1)}>{tr("Back")}</button>}</div>
              <div className="flex flex-wrap items-center justify-end gap-3">
                {blocker && <span className="flex max-w-[440px] items-center gap-1.5 text-right text-sm" style={{ color: "var(--warn)" }}><TriangleAlert size={15} aria-hidden />{blocker}</span>}
                {step < 4
                  ? <button type="button" className="primary" disabled={!!blocker} onClick={() => setStep(step + 1)}>{tr("Continue")}</button>
                  : <button type="button" className="primary" disabled={busy || createCount === 0} onClick={finish}>{busy ? tr("Creating…") : tr("Create {0} vault{1}", { 0: createCount, 1: createCount === 1 ? "" : "s" })}</button>}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
