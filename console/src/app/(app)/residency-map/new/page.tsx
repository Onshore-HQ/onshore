"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft, Check, Plus, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { FilterCombo, FilterSelect } from "@/components/table-tools";
import { Badge, ErrorLine } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { control, useLoad } from "@/lib/api";
import { entityLabel } from "@/lib/labels";
import { usePeople } from "@/lib/people";
import { countryName, COUNTRY_OPTIONS, flag, MapFrame, Region, StatusChip, Vendor } from "../shared";

const KINDS: [string, string, string][] = [["database", "Database", "Postgres, MySQL, a core ledger"], ["service", "Service", "An application or API you run"], ["warehouse", "Data warehouse", "Snowflake, BigQuery, Redshift"], ["saas_account", "SaaS account", "Your account with a vendor"], ["file_store", "File store", "Buckets, shares, document stores"]];
const BUILT_IN = ["bvn", "nin", "vnin", "nuban", "phone_ng", "card_pan", "email", "person_name", "amount_ngn"];
const STEPS = ["What is it?", "Where is it hosted?", "What does it hold?", "Where does it send data?", "Who owns it?"];

interface Out { key: string; vendor?: Vendor; system?: { id: string; name: string }; region: string; entities: string[] }

/** What the engine will say, before saving, using the same order of rules. */
function predict(country: string | null, home: string | null, entities: string[], scope: boolean) {
  if (country && country === home) return "in_country";
  if (country && scope && entities.length > 0) return "leaking";
  return "unverified";
}

function Builder({ vault }: { vault: string }) {
  const router = useRouter();
  const people = usePeople();
  const [step, setStep] = useState(0);
  const [kind, setKind] = useState("");
  const [name, setName] = useState("");
  const [vendorQ, setVendorQ] = useState("");
  const [vendor, setVendor] = useState<Vendor | null>(null);
  const [region, setRegion] = useState("");
  const [country, setCountry] = useState("");
  const [facility, setFacility] = useState("");
  const [entities, setEntities] = useState<string[]>([]);
  const [scope, setScope] = useState(true);
  const [outs, setOuts] = useState<Out[]>([]);
  const [owner, setOwner] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const vendors = useLoad<{ vendors: Vendor[] }>(() => control(`/v1/map/vendors${vendorQ ? `?q=${encodeURIComponent(vendorQ)}` : ""}`), [vendorQ]);
  const all = useLoad<{ vendors: Vendor[] }>(() => control("/v1/map/vendors"));
  const systems = useLoad<{ systems: { id: string; name: string; kind: string }[] }>(() => control(`/v1/map/systems?vault_id=${vault}`), [vault]);
  const vaults = useLoad<{ vaults: { id: string; country: string }[] }>(() => control("/v1/vaults"));
  const home = vaults.value?.vaults.find((v) => v.id === vault)?.country ?? null;
  const settings = useLoad<{ scope_definition: { version: number; body: string } | null }>(() => control(`/v1/map/settings?vault_id=${vault}`), [vault]);
  const custom = useLoad<{ entities: { slug: string; name: string }[] }>(() => control(`/v1/vaults/${vault}/custom-entities`).catch(() => ({ entities: [] })), [vault]);
  const regionOf = (v: { regions: Region[] }, code: string) => v.regions.find((r) => r.code === code);
  const pinCountry = vendor && region ? regionOf(vendor, region)?.country ?? null : country || null;
  const label = useMemo(() => new Map((custom.value?.entities ?? []).map((e) => [e.slug, e.name])), [custom.value]);
  const entityOptions = [...BUILT_IN, ...(custom.value?.entities ?? []).map((e) => e.slug)];
  const nameOf = (e: string) => label.get(e) ?? entityLabel(e);
  const canNext = [kind && (kind !== "saas_account" || vendor) && name, true, true, true, true][step];
  const toggleEntity = (e: string, list: string[], set: (v: string[]) => void) => set(list.includes(e) ? list.filter((x) => x !== e) : [...list, e]);

  const save = async () => {
    setBusy(true); setError(null);
    try {
      const { id } = await control<{ id: string }>("/v1/map/systems", { body: { vault_id: vault, name, kind, ...(vendor ? { vendor_id: vendor.id } : {}), ...(region ? { vendor_region: region } : {}), ...(country ? { hosting_country: country } : {}), ...(facility ? { hosting_facility: facility } : {}), ...(owner ? { owner_id: owner } : {}), entity_types: entities } });
      for (const o of outs) await control("/v1/map/flows", { body: { source_system_id: id, ...(o.vendor ? { dest_vendor_id: o.vendor.id, ...(o.region ? { dest_region: o.region } : {}) } : { dest_system_id: o.system!.id }), entity_types: o.entities, in_scope: scope, ...(owner ? { owner_id: owner } : {}) } });
      router.push(`/residency-map/systems/${id}`);
    } catch (e) { setError(e instanceof Error ? e.message : "failed"); setBusy(false); }
  };

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
      <div className="card grid content-start gap-4">
        <ol className="row flex-wrap" aria-label={tr("Steps")}>{STEPS.map((s, i) => <li key={s} className="row"><span className={`step-dot ${i <= step ? "on" : ""}`} aria-current={i === step ? "step" : undefined}>{i < step ? <Check className="size-3" /> : i + 1}</span><span className={`hidden text-[12.5px] sm:inline ${i === step ? "font-medium" : "text-muted-foreground"}`}>{s}</span></li>)}</ol>
        <h2>{STEPS[step]}</h2>
        {step === 0 && (
          <div className="grid gap-3">
            <div className="grid gap-2 sm:grid-cols-2">{KINDS.map(([k, t, d]) => <button type="button" key={k} className="builder-card" aria-pressed={kind === k} onClick={() => { setKind(k); if (k !== "saas_account") { setVendor(null); setRegion(""); } }}><b>{t}</b><span>{d}</span></button>)}</div>
            {kind === "saas_account" && (
              <div className="grid gap-2">
                <label className="field"><span>{tr("Find the vendor")}</span><Input value={vendorQ} placeholder={tr("Datadog, Freshdesk, Snowflake")} onChange={(e) => setVendorQ(e.target.value)} /></label>
                <div className="flex max-h-44 flex-wrap gap-1.5 overflow-auto">{(vendors.value?.vendors ?? []).slice(0, 30).map((v) => <button type="button" key={v.id} className="status-filter" aria-pressed={vendor?.id === v.id} onClick={() => { setVendor(v); setRegion(""); if (!name) setName(v.name); }}>{v.name}</button>)}</div>
              </div>
            )}
            <label className="field"><span>{tr("Name")}</span><Input value={name} placeholder={tr("Core ledger")} onChange={(e) => setName(e.target.value)} /></label>
          </div>
        )}
        {step === 1 && (
          <div className="grid gap-3">
            {vendor && vendor.regions.length > 0 ? (
              <>
                <p className="muted">{tr("Check which region your")} {vendor.name} {tr("account uses. The catalogue comes from public information, so confirm it against your account.")}</p>
                <div className="grid gap-2 sm:grid-cols-2">{vendor.regions.map((r) => <button type="button" key={r.code} className="builder-card" aria-pressed={region === r.code} onClick={() => setRegion(r.code)}><b>{r.name ?? r.code}</b><span>{r.country ? `${flag(r.country)} ${countryName(r.country)}` : tr("Location varies: declare it below")}</span></button>)}</div>
              </>
            ) : <>
              {vendor && <p className="muted">{tr("The catalogue states no hosting location for")} {vendor.name}{tr(". Ask them, then declare it here.")}</p>}
              <label className="field"><span>{tr("Country")}</span><FilterSelect label={tr("Country")} all={tr("Not known yet")} value={country} onChange={setCountry} options={COUNTRY_OPTIONS} className="w-full" /></label>
              <label className="field"><span>{tr("Facility, if you know it")}</span><Input value={facility} placeholder={tr("Facility name and city")} onChange={(e) => setFacility(e.target.value)} /></label>
            </>}
          </div>
        )}
        {step === 2 && (
          <div className="grid gap-3">
            <div className="flex flex-wrap gap-1.5">{entityOptions.map((e) => <button type="button" key={e} className="status-filter" aria-pressed={entities.includes(e)} onClick={() => toggleEntity(e, entities, setEntities)}>{nameOf(e)}</button>)}</div>
            <div className="spread"><span className="text-[13px] font-medium">{tr("In scope for your residency definition")}</span><Switch aria-label={tr("In scope")} checked={scope} onCheckedChange={setScope} /></div>
            <div className="note text-[13px]">{settings.value?.scope_definition ? <><b>{tr("Your adopted definition, version")} {settings.value.scope_definition.version}:</b> {settings.value.scope_definition.body}</> : tr("You have not recorded a scope definition yet. Add one in Reports. Laws rarely say exactly which data must stay in the country, so this is your organisation's call.")}</div>
          </div>
        )}
        {step === 3 && (
          <div className="grid gap-3">
            {outs.map((o, i) => (
              <div key={o.key} className="rounded-lg border p-3">
                <div className="spread"><b className="text-[13.5px]">{o.vendor?.name ?? o.system?.name}</b><Button size="icon" variant="ghost" aria-label={tr("Remove")} onClick={() => setOuts(outs.filter((_, j) => j !== i))}><X /></Button></div>
                {o.vendor && o.vendor.regions.length > 0 && <div className="mt-1"><FilterSelect label={tr("Region")} all={tr("Region not confirmed")} value={o.region} onChange={(v) => setOuts(outs.map((x, j) => (j === i ? { ...x, region: v } : x)))} options={o.vendor.regions.map((r) => [r.code, `${r.name ?? r.code}${r.country ? `, ${countryName(r.country)}` : ""}`])} /></div>}
                <div className="mt-2 flex flex-wrap gap-1">{(entities.length ? entities : entityOptions).map((e) => <button type="button" key={e} className="status-filter" aria-pressed={o.entities.includes(e)} onClick={() => toggleEntity(e, o.entities, (v) => setOuts(outs.map((x, j) => (j === i ? { ...x, entities: v } : x))))}>{nameOf(e)}</button>)}</div>
              </div>
            ))}
            <div className="row flex-wrap">
              <FilterCombo label={tr("Add a vendor")} all={tr("Add a vendor")} value="" onChange={(id) => { const v = all.value?.vendors.find((x) => x.id === id); if (v) setOuts([...outs, { key: `${id}-${outs.length}`, vendor: v, region: "", entities }]); }} placeholder={tr("Find a vendor")} options={(all.value?.vendors ?? []).map((v) => [v.id, v.name] as [string, string])} />
              <FilterCombo label={tr("Add a system")} all={tr("Add one of your systems")} value="" onChange={(id) => { const s = systems.value?.systems.find((x) => x.id === id); if (s) setOuts([...outs, { key: `${id}-${outs.length}`, system: s, region: "", entities }]); }} placeholder={tr("Find a system")} options={(systems.value?.systems ?? []).map((s) => [s.id, s.name] as [string, string])} />
            </div>
            {outs.length === 0 && <p className="muted"><Plus className="mr-1 inline size-3" />{tr("Skip this if it sends nothing onward. You can add flows later.")}</p>}
          </div>
        )}
        {step === 4 && <label className="field"><span>{tr("Owner")}</span><FilterCombo label={tr("Owner")} all={tr("No owner yet")} value={owner} onChange={setOwner} placeholder={tr("Find a person")} options={[...people.entries()].map(([id, n]) => [id, n] as [string, string])} /></label>}
        <ErrorLine error={error} />
        <div className="row justify-between">
          <Button variant="outline" disabled={step === 0} onClick={() => setStep(step - 1)}>{tr("Back")}</Button>
          {step < 4 ? <Button disabled={!canNext} onClick={() => setStep(step + 1)}>{tr("Next")}</Button> : <Button disabled={busy} onClick={save}>{tr("Save to the map")}</Button>}
        </div>
      </div>
      <aside className="card grid content-start gap-3" aria-label={tr("Preview")}>
        <h3>{tr("Preview")}</h3>
        <div className="rounded-lg border p-3"><div className="text-[13.5px] font-medium">{name || tr("New system")}</div><div className="mt-0.5 text-[12px] text-muted-foreground">{pinCountry ? `${flag(pinCountry)} ${countryName(pinCountry)}${facility ? `, ${facility}` : ""}` : tr("Location not declared")}</div><div className="mt-1.5 flex flex-wrap gap-1">{entities.slice(0, 6).map((e) => <Badge key={e}>{nameOf(e)}</Badge>)}</div></div>
        {outs.map((o) => {
          const c = o.vendor ? (o.region ? regionOf(o.vendor, o.region)?.country ?? null : null) : null;
          return <div key={o.key} className="rounded-lg border p-3 text-[13px]"><div className="text-[12px] text-muted-foreground">{tr("Sends to")}</div><div className="font-medium">{o.vendor?.name ?? o.system?.name}</div><div className="mt-1 text-[12px] text-muted-foreground">{c ? `${flag(c)} ${countryName(c)}` : tr("Location not confirmed")}</div><div className="mt-1.5"><StatusChip status={predict(c, home, o.entities, scope)} /></div></div>;
        })}
        <p className="text-[12px] text-muted-foreground">{tr("These statuses are a prediction. After saving, Onshore works them out from what you declared, and labels them as declared.")}</p>
      </aside>
    </div>
  );
}

export default function NewSystem() {
  return (
    <MapFrame title={tr("Add a system")} sub={tr("For anything that holds or receives data and does not pass through Onshore. Your connections appear on the map by themselves.")} actions={() => <Button variant="outline" size="sm" asChild><Link href="/residency-map"><ArrowLeft /> {tr("Back to the map")}</Link></Button>}>
      {(vault) => <Builder key={vault} vault={vault} />}
    </MapFrame>
  );
}
