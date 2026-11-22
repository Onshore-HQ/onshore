"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { useMe } from "@/components/Shell";
import { FilterCombo, FilterSelect } from "@/components/table-tools";
import { Badge, Empty, ErrorLine, Loading, Page, rowKeys, TypedConfirm } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { control, useLoad, when } from "@/lib/api";
import { entityLabel, modeLabel } from "@/lib/labels";
import { Person, usePeople } from "@/lib/people";
import { age, Country, countryName, COUNTRY_OPTIONS, Flow, MAP_EDIT, Region, StatusChip } from "../../shared";

interface System { id: string; name: string; kind: string; vendor_id: string | null; vendor: { name: string; regions: Region[]; category: string } | null; vendor_region: string | null; hosting_country: string | null; hosting_facility: string | null; host: string | null; owner_id: string | null; entity_types: string[]; managed_by_onshore: boolean; route_mode: string | null; retired_at: string | null; outbound: Flow[]; inbound: Flow[]; history: { seq: string; occurred_at: string; kind: string; detail: Record<string, unknown>; actor_id: string | null }[] }
const HISTORY: Record<string, string> = { declared: "Declared", declaration_changed: "Declaration changed", region_confirmed: "Region confirmed", route_mode: "Route mode changed" };

function Flows({ title, rows, far }: { title: string; rows: Flow[]; far: (f: Flow) => string }) {
  const router = useRouter();
  return (
    <div className="grid gap-2">
      <h2>{title}</h2>
      {rows.length === 0 ? <p className="muted">{tr("None.")}</p> : (
        <div className="data-table"><Table><TableHeader><TableRow><TableHead>{tr("System")}</TableHead><TableHead>{tr("Country")}</TableHead><TableHead>{tr("Data types")}</TableHead><TableHead>{tr("Status")}</TableHead><TableHead>{tr("Owner")}</TableHead></TableRow></TableHeader>
          <TableBody>{rows.map((f) => { const go = () => router.push(`/residency-map/flows/${f.id}`); return (
            <TableRow key={f.id} className="click" tabIndex={0} onClick={go} onKeyDown={(e) => rowKeys(e, go)}><TableCell className="font-medium">{far(f)}</TableCell><TableCell><Country code={f.dest_country} source={f.dest_country_source} /></TableCell><TableCell>{f.entity_types.slice(0, 3).map(entityLabel).join(", ")}{f.entity_types.length > 3 ? ` +${f.entity_types.length - 3}` : ""}</TableCell><TableCell><StatusChip status={f.status} flow={f} /><span className="ml-1 text-[12px] text-muted-foreground">{age(f.status_since)}</span></TableCell><TableCell>{f.owner_name ?? tr("No owner")}</TableCell></TableRow>
          ); })}</TableBody></Table></div>
      )}
    </div>
  );
}

export default function SystemPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const me = useMe();
  const people = usePeople();
  const canEdit = (me?.roles ?? []).some((r) => MAP_EDIT.includes(r));
  const s = useLoad<System>(() => control(`/v1/map/systems/${id}`), [id]);
  const [country, setCountry] = useState<string | null>(null);
  const [facility, setFacility] = useState<string | null>(null);
  const [region, setRegion] = useState("");
  const [retire, setRetire] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const v = s.value;
  const save = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); s.reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } };
  return (
    <Page title={v?.name ?? tr("System")} sub={v ? `${v.kind.replaceAll("_", " ")}${v.managed_by_onshore ? tr(", managed by Onshore") : ""}` : undefined} actions={<Button variant="outline" size="sm" asChild><Link href="/residency-map"><ArrowLeft /> {tr("Back to the map")}</Link></Button>}>
      <Loading error={s.error} loading={s.loading && !v} />
      {v && (
        <div className="grid gap-5">
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="card grid content-start gap-3">
              <h2>{tr("Where it is")}</h2>
              {v.vendor ? (
                <>
                  <p className="muted">{v.vendor.name}. {v.vendor_region ? tr("Your account uses {0}.", { 0: v.vendor_region }) : tr("Which region your account uses is not confirmed, so it counts as offshore.")}</p>
                  {v.vendor.regions.length > 0 ? canEdit && (
                    <div className="row flex-wrap">
                      <FilterSelect label={tr("Vendor region")} all={tr("Pick a region")} value={region || v.vendor_region || ""} onChange={setRegion} options={v.vendor.regions.map((r) => [r.code, `${r.name ?? r.code}${r.country ? `, ${countryName(r.country)}` : ""}`])} />
                      <Button size="sm" disabled={!region} onClick={() => save(() => control(`/v1/map/systems/${id}/confirm-region`, { body: { region } }))}>{tr("Confirm region")}</Button>
                    </div>
                  ) : <p className="muted">{tr("The catalogue states no hosting location for this vendor. Ask them, then declare it below.")}</p>}
                </>
              ) : v.host && <p className="mono text-[13px]">{v.host}</p>}
              {!v.managed_by_onshore && (!v.vendor || v.vendor.regions.length === 0 || v.hosting_country) && (
                <>
                  <label className="field"><span>{tr("Hosting country, as you declare it")}</span>{canEdit ? <FilterSelect label={tr("Hosting country")} all={tr("Not declared")} value={country ?? v.hosting_country ?? ""} onChange={setCountry} options={COUNTRY_OPTIONS} className="w-full" /> : <span>{countryName(v.hosting_country)}</span>}</label>
                  <label className="field"><span>{tr("Facility")}</span><Input disabled={!canEdit} value={facility ?? v.hosting_facility ?? ""} onChange={(e) => setFacility(e.target.value)} /></label>
                  {canEdit && <div><Button size="sm" disabled={country === null && facility === null} onClick={() => save(async () => { await control(`/v1/map/systems/${id}`, { method: "PATCH", body: { ...(country !== null ? { hosting_country: country || null } : {}), ...(facility !== null ? { hosting_facility: facility || null } : {}) } }); setCountry(null); setFacility(null); })}>{tr("Save declaration")}</Button></div>}
                </>
              )}
              {v.managed_by_onshore && <p className="muted">{tr("This is an Onshore route, currently")} {modeLabel(v.route_mode ?? "shadow")}. <Link className="underline" href="/pipelines">{tr("Change it in Pipelines")}</Link>.</p>}
              <ErrorLine error={error} />
            </div>
            <div className="card grid content-start gap-3">
              <h2>{tr("What it holds")}</h2>
              <div className="flex flex-wrap gap-1">{v.entity_types.length ? v.entity_types.map((e) => <Badge key={e}>{entityLabel(e)}</Badge>) : <span className="muted">{tr("Nothing declared")}</span>}</div>
              <label className="field"><span>{tr("Owner")}</span>{canEdit ? <FilterCombo label={tr("Owner")} all={tr("No owner")} value={v.owner_id ?? ""} onChange={(o) => save(() => control(`/v1/map/systems/${id}`, { method: "PATCH", body: { owner_id: o || null } }))} placeholder={tr("Find a person")} options={[...people.entries()].map(([pid, name]) => [pid, name] as [string, string])} /> : <span><Person id={v.owner_id} fallback="No owner" /></span>}</label>
              {canEdit && !v.managed_by_onshore && !v.retired_at && <div><Button size="sm" variant="ghost" onClick={() => setRetire(true)}>{tr("Retire this system")}</Button></div>}
            </div>
          </div>
          <Flows title={tr("Sends data to")} rows={v.outbound} far={(f) => f.dest.name} />
          <Flows title={tr("Receives data from")} rows={v.inbound} far={(f) => f.source.name} />
          <div className="grid gap-2">
            <h2>{tr("History")}</h2>
            {v.history.length === 0 ? <Empty title={tr("No changes yet")} /> : <ul className="card grid gap-1.5 text-[13px]">{v.history.map((h) => <li key={h.seq}><b>{HISTORY[h.kind] ?? h.kind}</b> <span className="text-muted-foreground">{when(h.occurred_at)}, {h.actor_id ? <Person id={h.actor_id} /> : tr("Onshore")}</span> <span className="mono text-[12px] text-muted-foreground">{Object.entries(h.detail).filter(([, x]) => x !== null).map(([k, x]) => `${k.replaceAll("_", " ")}: ${Array.isArray(x) ? x.join(", ") : String(x)}`).join("; ")}</span></li>)}</ul>}
          </div>
        </div>
      )}
      {retire && <TypedConfirm title={tr("Retire this system")} word="retire" onClose={() => setRetire(false)} onConfirm={async () => { await control(`/v1/map/systems/${id}`, { method: "PATCH", body: { retired: true } }); s.reload(); }}>{tr("Its flows are retired with it. The history stays.")}</TypedConfirm>}
    </Page>
  );
}
