"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft, FileDown, Wrench } from "lucide-react";
import Link from "next/link";
import { use, useState } from "react";
import { useMe } from "@/components/Shell";
import { Badge, Empty, ErrorLine, Loading, Modal, Page, TypedConfirm } from "@/components/ui";
import { ExceptionsTable } from "../../exceptions-table";
import { FilterCombo, FilterSelect } from "@/components/table-tools";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { control, day, n, useLoad, when } from "@/lib/api";
import { entityLabel, modeLabel } from "@/lib/labels";
import { Person, usePeople } from "@/lib/people";
import { age, CAUSES, Country, countryName, COUNTRY_OPTIONS, Flow, flowSentence, MAP_EDIT, PLANS, Region, STATUS, StatusChip } from "../../shared";

interface Action { id: string; plan: string; description: string | null; owner_id: string; due_date: string; status: string; evidence: Record<string, string> | null; evidence_files: { name: string; size: number; sha256: string }[]; completed_at: string | null; completed_by: string | null }
interface Exception { id: string; reason: string; compensating_controls: string | null; requested_by: string; approved_by: string | null; approved_at: string | null; expires_at: string; status: string }
type Fix = { kind: string; title: string; body: string; route_type?: string; route_id?: string; entities?: string[]; system_id?: string; regions?: Region[]; suggested?: string | null };
type Detail = Flow & { fix: Fix | null; by_entity: { entity_type: string; protected: number; passed: number }[]; actions: Action[]; exceptions: Exception[] };
interface Timeline { events: { seq: string; occurred_at: string; from_status: string | null; to_status: string; cause: string; evidence: Record<string, unknown> | null; actor_id: string | null }[]; observations: { day: string; entity_type: string; protected: number; passed: number; ruleset_version: number | null }[]; route_modes: { occurred_at: string; detail: { mode: string; was?: string } }[] }

function Evidence({ t, f }: { t: Timeline; f: Detail }) {
  const days = [...new Set(t.observations.map((o) => String(o.day).slice(0, 10)))].sort();
  const totals = days.map((d) => { const r = t.observations.filter((o) => String(o.day).slice(0, 10) === d); return { d, p: r.reduce((s, x) => s + x.protected, 0), u: r.reduce((s, x) => s + x.passed, 0) }; });
  const max = Math.max(1, ...totals.map((x) => x.p + x.u));
  const ruleset = t.observations.reduce<number | null>((m, o) => (o.ruleset_version && (!m || o.ruleset_version > m) ? o.ruleset_version : m), null);
  if (f.basis === "declared" && days.length === 0) return <Empty title={tr("No traffic evidence")}>{tr("Onshore cannot see this flow. Its status rests on what was declared. Put it behind a route to get evidence.")}</Empty>;
  return (
    <div className="grid gap-4">
      <div className="card">
        <h3 className="mb-3">{tr("Protected and passed, by day")}</h3>
        {days.length === 0 ? <p className="muted">{tr("No detections in the last 90 days.")}</p> : (
          <div className="flex h-32 items-end gap-[3px] overflow-x-auto" role="img" aria-label={tr("Daily detections: protected and passed")}>
            {totals.map((x) => (
              <div key={x.d} className="flex w-3 shrink-0 flex-col justify-end" style={{ height: "100%" }} title={tr("{0}: {1} protected, {2} passed", { 0: x.d, 1: n(x.p), 2: n(x.u) })}>
                <div style={{ height: `${(x.u / max) * 100}%`, background: "var(--map-leaking)" }} />
                <div style={{ height: `${(x.p / max) * 100}%`, background: "var(--map-protected)" }} />
              </div>
            ))}
          </div>
        )}
        <div className="row mt-2 text-[12px] text-muted-foreground"><span><i className="mr-1 inline-block size-2" style={{ background: "var(--map-protected)" }} />{tr("Protected")}</span><span><i className="mr-1 inline-block size-2" style={{ background: "var(--map-leaking)" }} />{tr("Passed unchanged")}</span>{ruleset && <span>{tr("Rule set version")} {ruleset}</span>}</div>
      </div>
      {f.by_entity.length > 0 && (
        <div className="data-table"><Table><TableHeader><TableRow><TableHead>{tr("Data type, last 30 days")}</TableHead><TableHead className="num text-right">{tr("Protected")}</TableHead><TableHead className="num text-right">{tr("Passed")}</TableHead></TableRow></TableHeader>
          <TableBody>{f.by_entity.map((e) => <TableRow key={e.entity_type}><TableCell>{entityLabel(e.entity_type)}</TableCell><TableCell className="num text-right">{n(e.protected)}</TableCell><TableCell className="num text-right">{n(e.passed)}</TableCell></TableRow>)}</TableBody></Table></div>
      )}
      {t.route_modes.length > 0 && (
        <div className="card"><h3 className="mb-2">{tr("Route mode history")}</h3><ul className="grid gap-1 text-[13px]">{t.route_modes.map((m, i) => <li key={i}><b>{modeLabel(m.detail.mode)}</b> <span className="text-muted-foreground">{when(m.occurred_at)}</span></li>)}</ul></div>
      )}
    </div>
  );
}

function TimelineTab({ t }: { t: Timeline }) {
  if (t.events.length === 0) return <Empty title={tr("No status changes yet")} />;
  return (
    <div className="data-table"><Table><TableHeader><TableRow><TableHead>{tr("When")}</TableHead><TableHead>{tr("Change")}</TableHead><TableHead>{tr("Why")}</TableHead><TableHead>{tr("Evidence")}</TableHead><TableHead>{tr("By")}</TableHead></TableRow></TableHeader>
      <TableBody>{t.events.map((e) => {
        const ev = e.evidence ?? {};
        const bits = [ev.unprotected_7d !== undefined && `${n(ev.unprotected_7d)} unprotected in 7 days`, ev.route_mode && `route ${modeLabel(String(ev.route_mode))}`, ev.ruleset_version && `rule set ${ev.ruleset_version}`].filter(Boolean).join(", ");
        return <TableRow key={e.seq}><TableCell className="whitespace-nowrap">{when(e.occurred_at)}</TableCell><TableCell>{e.from_status ? `${STATUS[e.from_status]?.label ?? e.from_status} to ` : ""}<b>{STATUS[e.to_status]?.label ?? e.to_status}</b></TableCell><TableCell>{CAUSES[e.cause] ?? e.cause}</TableCell><TableCell className="text-[12px] text-muted-foreground">{bits}</TableCell><TableCell>{e.actor_id ? <Person id={e.actor_id} /> : tr("Onshore")}</TableCell></TableRow>;
      })}</TableBody></Table></div>
  );
}

function AddAction({ flow, onDone, onClose }: { flow: string; onDone: () => void; onClose: () => void }) {
  const me = useMe();
  const people = usePeople();
  const [plan, setPlan] = useState("route_via_proxy");
  const [owner, setOwner] = useState(me?.id ?? "");
  const [due, setDue] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={tr("Add a fix")} onClose={onClose}>
      <label className="field"><span>{tr("Plan")}</span><FilterSelect label={tr("Plan")} all="" value={plan} onChange={(v) => v && setPlan(v)} options={Object.entries(PLANS)} className="w-full" /></label>
      <label className="field"><span>{tr("Details, if useful")}</span><Textarea value={description} onChange={(e) => setDescription(e.target.value)} /></label>
      <label className="field"><span>{tr("Owner")}</span><FilterCombo label={tr("Owner")} all={tr("Pick an owner")} value={owner} onChange={setOwner} placeholder={tr("Find a person")} options={[...people.entries()].map(([id, name]) => [id, name] as [string, string])} /></label>
      <label className="field"><span>{tr("Due date")}</span><Input type="date" value={due} onChange={(e) => setDue(e.target.value)} /></label>
      <ErrorLine error={error} />
      <div className="row justify-end"><Button variant="outline" onClick={onClose}>{tr("Cancel")}</Button><Button disabled={!owner || !due} onClick={async () => { try { await control(`/v1/map/flows/${flow}/actions`, { body: { plan, owner_id: owner, due_date: due, ...(description ? { description } : {}) } }); onDone(); onClose(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Add")}</Button></div>
    </Modal>
  );
}

function CompleteAction({ a, onDone, onClose }: { a: Action; onDone: (note: string) => void; onClose: () => void }) {
  const routes = useLoad<[{ pipelines: { id: string; name: string }[] }, { routes: { id: string; name: string }[] }, { routes: { id: string; name: string }[] }]>(() => Promise.all([control("/v1/log-pipelines"), control("/v1/ai-routes"), control("/v1/proxy-routes")]));
  const [kind, setKind] = useState(a.plan === "route_via_proxy" ? "route" : a.plan === "move_in_country" ? "declaration" : "change");
  const [route, setRoute] = useState("");
  const [country, setCountry] = useState("");
  const [facility, setFacility] = useState("");
  const [reference, setReference] = useState("");
  const [file, setFile] = useState<{ name: string; type: string; content_b64: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const options = routes.value ? [...routes.value[2].routes, ...routes.value[0].pipelines, ...routes.value[1].routes].map((r) => [r.id, r.name] as [string, string]) : [];
  const readFile = (f?: File) => { if (!f) return; if (f.size > 2_000_000) { setError("A file can be at most 2 MB."); return; } const r = new FileReader(); r.onload = () => setFile({ name: f.name, type: f.type || "application/octet-stream", content_b64: String(r.result).split(",")[1] ?? "" }); r.readAsDataURL(f); };
  const evidence = kind === "route" ? (route ? { type: "route", route_id: route } : null) : kind === "declaration" ? { type: "declaration", hosting_country: country, ...(facility ? { hosting_facility: facility } : {}) } : reference.length >= 3 ? { type: "change", reference } : null;
  return (
    <Modal title={tr("Mark this fix as done")} onClose={onClose}>
      <p className="muted">{tr("A fix needs evidence. Linking a route or declaring a new location also updates the flow. A change reference or a file is kept as proof, and does not change the status alone.")}</p>
      <label className="field"><span>{tr("What changed?")}</span><FilterSelect label={tr("Evidence")} all="" value={kind} onChange={(v) => v && setKind(v)} className="w-full" options={[["route", tr("It now passes through an Onshore route")], ["declaration", tr("It moved to a new location")], ["change", tr("Another change, with a reference")]]} /></label>
      {kind === "route" && <label className="field"><span>{tr("Route")}</span><FilterCombo label={tr("Route")} all={tr("Pick a route")} value={route} onChange={setRoute} placeholder={tr("Find a route")} options={options} /></label>}
      {kind === "declaration" && <><label className="field"><span>{tr("Country")}</span><FilterSelect label={tr("Country")} all="" value={country} onChange={(v) => v && setCountry(v)} options={COUNTRY_OPTIONS} className="w-full" /></label><label className="field"><span>{tr("Facility, if known")}</span><Input value={facility} onChange={(e) => setFacility(e.target.value)} /></label></>}
      {kind === "change" && <label className="field"><span>{tr("Reference, such as a change ticket")}</span><Input value={reference} onChange={(e) => setReference(e.target.value)} /></label>}
      <label className="field"><span>{tr("Attach proof (optional, up to 2 MB)")}</span><Input type="file" onChange={(e) => readFile(e.target.files?.[0])} /></label>
      <ErrorLine error={error} />
      <div className="row justify-end"><Button variant="outline" onClick={onClose}>{tr("Cancel")}</Button><Button disabled={!evidence && !file} onClick={async () => { try { const r = await control<{ note: string }>(`/v1/map/actions/${a.id}`, { method: "PATCH", body: { status: "done", ...(evidence ? { evidence } : {}), ...(file ? { files: [file] } : {}) } }); onDone(r.note); onClose(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Mark as done")}</Button></div>
    </Modal>
  );
}

function Remediation({ f, canEdit, reload }: { f: Detail; canEdit: boolean; reload: () => void }) {
  const [adding, setAdding] = useState(false);
  const [completing, setCompleting] = useState<Action | null>(null);
  const [note, setNote] = useState<string | null>(null);
  return (
    <div className="grid gap-3">
      {note && <div className="note">{note}</div>}
      {canEdit && <div><Button size="sm" onClick={() => setAdding(true)}>{tr("Add a fix")}</Button></div>}
      {f.actions.length === 0 ? <Empty title={tr("No fixes yet")}>{tr("Add one when Onshore cannot fix this flow by itself.")}</Empty> : (
        <div className="data-table"><Table><TableHeader><TableRow><TableHead>{tr("Plan")}</TableHead><TableHead>{tr("Owner")}</TableHead><TableHead>{tr("Due")}</TableHead><TableHead>{tr("Status")}</TableHead><TableHead>{tr("Evidence")}</TableHead><TableHead /></TableRow></TableHeader>
          <TableBody>{f.actions.map((a) => {
            const live = a.status === "open" || a.status === "in_progress";
            const late = live && new Date(a.due_date) < new Date(new Date().toDateString());
            return (
              <TableRow key={a.id}>
                <TableCell><div className="font-medium">{PLANS[a.plan] ?? a.plan}</div>{a.description && <div className="text-[12px] text-muted-foreground">{a.description}</div>}</TableCell>
                <TableCell><Person id={a.owner_id} /></TableCell>
                <TableCell className="whitespace-nowrap">{day(a.due_date)}{late && <div><Badge tone="bad">{tr("Overdue")}</Badge></div>}</TableCell>
                <TableCell>{a.status === "done" ? <Badge tone="good">{tr("Done")} {day(a.completed_at)}</Badge> : a.status === "cancelled" ? <Badge>{tr("Cancelled")}</Badge> : <Badge tone="info">{a.status === "open" ? tr("Open") : tr("In progress")}</Badge>}</TableCell>
                <TableCell className="text-[12px]">
                  {a.evidence?.type === "route" && <span>{tr("Linked route")}</span>}{a.evidence?.type === "declaration" && <span>{tr("Moved to")} {countryName(a.evidence.hosting_country)}</span>}{a.evidence?.type === "change" && <span>{a.evidence.reference}</span>}
                  {a.evidence_files.map((file, i) => <div key={i}><a className="inline-flex items-center gap-1 underline" href={`/api/proxy/control/v1/map/actions/${a.id}/files/${i}`}><FileDown className="size-3" />{file.name}</a></div>)}
                </TableCell>
                <TableCell>{canEdit && live && <span className="row"><Button size="sm" variant="outline" onClick={() => setCompleting(a)}>{tr("Mark as done")}</Button>{a.status === "open" && <Button size="sm" variant="ghost" onClick={async () => { await control(`/v1/map/actions/${a.id}`, { method: "PATCH", body: { status: "in_progress" } }); reload(); }}>{tr("Start")}</Button>}</span>}</TableCell>
              </TableRow>
            );
          })}</TableBody></Table></div>
      )}
      {adding && <AddAction flow={f.id} onDone={reload} onClose={() => setAdding(false)} />}
      {completing && <CompleteAction a={completing} onDone={(t) => { setNote(t); reload(); }} onClose={() => setCompleting(null)} />}
    </div>
  );
}

function RequestException({ flow, max, onDone, onClose }: { flow: string; max: number; onDone: () => void; onClose: () => void }) {
  const [reason, setReason] = useState("");
  const [controls, setControls] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={tr("Request an exception")} onClose={onClose}>
      <p className="muted">{tr("This accepts a risk for a limited time. Someone other than you must approve it, and it can last at most")} {max} days.</p>
      <label className="field"><span>{tr("Why accept this risk?")}</span><Textarea value={reason} onChange={(e) => setReason(e.target.value)} /></label>
      <label className="field"><span>{tr("Compensating controls")}</span><Textarea value={controls} onChange={(e) => setControls(e.target.value)} /></label>
      <label className="field"><span>{tr("Expires on")}</span><Input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} /></label>
      <ErrorLine error={error} />
      <div className="row justify-end"><Button variant="outline" onClick={onClose}>{tr("Cancel")}</Button><Button disabled={reason.length < 5 || !expires} onClick={async () => { try { await control(`/v1/map/flows/${flow}/exceptions`, { body: { reason, expires_at: expires, ...(controls ? { compensating_controls: controls } : {}) } }); onDone(); onClose(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Request")}</Button></div>
    </Modal>
  );
}

function FixIt({ f, canEdit, reload }: { f: Detail; canEdit: boolean; reload: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const fix = f.fix;
  const [region, setRegion] = useState(fix?.suggested ?? "");
  const [country, setCountry] = useState("");
  if (!fix) return <Empty title={tr("Nothing to fix")}>{tr("This flow needs no action now.")}</Empty>;
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } };
  const path = fix.route_type === "ai_route" ? "ai-routes" : "log-pipelines";
  return (
    <div className="card grid gap-3">
      <div className="flex items-start gap-3"><span className="tile blue" aria-hidden><Wrench className="size-[18px]" /></span><div><h3>{fix.title}</h3><p className="muted mt-0.5">{fix.body}</p></div></div>
      {!canEdit && <p className="muted">{tr("Ask someone who can edit the map to do this.")}</p>}
      {canEdit && fix.kind === "enforce" && <div><Button onClick={() => setConfirm(true)}>{tr("Switch to Protecting")}</Button></div>}
      {canEdit && fix.kind === "entity_action" && fix.route_type === "log_pipeline" && <div><Button onClick={() => act(async () => { const { pipelines } = await control<{ pipelines: { id: string; action_per_type: Record<string, string> }[] }>("/v1/log-pipelines"); const p = pipelines.find((x) => x.id === fix.route_id); await control(`/v1/log-pipelines/${fix.route_id}`, { method: "PATCH", body: { action_per_type: { ...p?.action_per_type, ...Object.fromEntries((fix.entities ?? []).map((e) => [e, "tokenize"])) } } }); })}>{tr("Tokenize")} {(fix.entities ?? []).map(entityLabel).join(", ")}</Button></div>}
      {canEdit && fix.kind === "entity_action" && fix.route_type !== "log_pipeline" && <div><Button asChild variant="outline"><Link href="/pipelines">{tr("Open this route")}</Link></Button></div>}
      {canEdit && fix.kind === "confirm_region" && (
        <div className="row flex-wrap">
          <FilterSelect label={tr("Region")} all={tr("Pick a region")} value={region} onChange={setRegion} options={(fix.regions ?? []).map((r) => [r.code, `${r.name ?? r.code}${r.country ? `, ${countryName(r.country)}` : ""}`])} />
          <Button disabled={!region} onClick={() => act(() => control(`/v1/map/systems/${fix.system_id}/confirm-region`, { body: { region } }))}>{tr("Confirm region")}</Button>
          {fix.suggested && <span className="text-[12px] text-muted-foreground">{tr("The address looks like")} {fix.regions?.find((r) => r.code === fix.suggested)?.name ?? fix.suggested}{tr(". Check this against your account.")}</span>}
        </div>
      )}
      {canEdit && fix.kind === "declare_hosting" && (
        <div className="row flex-wrap">
          <FilterSelect label={tr("Country")} all={tr("Pick a country")} value={country} onChange={setCountry} options={COUNTRY_OPTIONS} />
          <Button disabled={!country} onClick={() => act(() => control(`/v1/map/systems/${fix.system_id}`, { method: "PATCH", body: { hosting_country: country } }))}>{tr("Save location")}</Button>
        </div>
      )}
      {canEdit && fix.kind === "route_via_proxy" && <div><Button asChild variant="outline"><Link href="/pipelines">{tr("Create a proxy route")}</Link></Button></div>}
      <ErrorLine error={error} />
      {confirm && <TypedConfirm title={tr("Switch {0} to Protecting", { 0: f.route?.name })} word="protect" onClose={() => setConfirm(false)} onConfirm={async () => { await control(`/v1/${path}/${fix.route_id}`, { method: "PATCH", body: { mode: "enforcing" } }); reload(); }}>{tr("Detected values will be changed before they reach")} {f.dest.name}{tr(". Check first that the destination can work with tokens.")}</TypedConfirm>}
    </div>
  );
}

export default function FlowPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const me = useMe();
  const people = usePeople();
  const canEdit = (me?.roles ?? []).some((r) => MAP_EDIT.includes(r));
  const f = useLoad<Detail>(() => control(`/v1/map/flows/${id}`), [id]);
  const t = useLoad<Timeline>(() => control(`/v1/map/flows/${id}/timeline`), [id, f.value?.status]);
  const settings = useLoad<{ exception_max_days: number }>(() => (f.value ? control(`/v1/map/settings?vault_id=${f.value.vault_id}`) : Promise.resolve({ exception_max_days: 180 })), [f.value?.vault_id]);
  const [excOpen, setExcOpen] = useState(false);
  const [retire, setRetire] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const v = f.value;
  const patch = async (body: Record<string, unknown>) => { setError(null); try { await control(`/v1/map/flows/${id}`, { method: "PATCH", body }); f.reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } };
  return (
    <Page title={v ? `${v.source.name} → ${v.dest.name}` : tr("Data flow")} sub={v ? flowSentence(v) : undefined} actions={<Button variant="outline" size="sm" asChild><Link href="/residency-map"><ArrowLeft /> {tr("Back to the map")}</Link></Button>}>
      <Loading error={f.error} loading={f.loading && !v} />
      {v && (
        <Tabs defaultValue={v.fix ? "fix" : "overview"}>
          <TabsList className="flex-wrap"><TabsTrigger value="overview">{tr("Overview")}</TabsTrigger>{v.fix && <TabsTrigger value="fix">{tr("Fix it")}</TabsTrigger>}<TabsTrigger value="evidence">{tr("Evidence")}</TabsTrigger><TabsTrigger value="timeline">{tr("Timeline")}</TabsTrigger><TabsTrigger value="remediation">{tr("Fixes (")}{v.actions.length})</TabsTrigger><TabsTrigger value="exceptions">{tr("Exceptions (")}{v.exceptions.length})</TabsTrigger></TabsList>
          <TabsContent value="overview">
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="card">
                <dl className="kv-list">
                  <div className="kv"><dt>{tr("Status")}</dt><dd><StatusChip status={v.status} flow={v} /> <span className="text-muted-foreground">{age(v.status_since)}</span><div className="mt-1 text-[12px] text-muted-foreground">{v.proving ? tr("Protecting since {0}. It turns green after 7 clean days.", { 0: day(v.route?.since) }) : STATUS[v.status]?.hint}</div></dd></div>
                  <div className="kv"><dt>{tr("Basis")}</dt><dd>{v.basis === "observed" ? <Badge tone="info">{tr("Seen by Onshore")}</Badge> : <Badge>{tr("Declared by you, not verified evidence")}</Badge>}</dd></div>
                  <div className="kv"><dt>{tr("Destination")}</dt><dd>{v.dest.name}{v.dest.region ? `, ${v.dest.region}` : ""}{v.dest.host && <div className="mono text-[12px] text-muted-foreground">{v.dest.host}</div>}</dd></div>
                  <div className="kv"><dt>{tr("Country")}</dt><dd><Country code={v.dest_country} source={v.dest_country_source} /> {v.dest_country && <span className="text-muted-foreground">({v.dest_country_source === "vendor_region" ? tr("confirmed vendor region") : tr("declared")})</span>}{v.ip_hint && <div className="text-[12px] text-muted-foreground">{tr("An IP lookup suggests")} {countryName(v.ip_hint)}{tr(". This is a hint, and is not used.")}</div>}</dd></div>
                  <div className="kv"><dt>{tr("Route")}</dt><dd>{v.route ? `${v.route.name}, ${modeLabel(v.route.mode)}` : tr("Does not pass through Onshore")}</dd></div>
                  <div className="kv"><dt>{tr("Added")}</dt><dd>{day(v.created_at)}, {v.origin === "observed" ? tr("when Onshore first saw the traffic") : tr("by a person")}</dd></div>
                </dl>
              </div>
              <div className="card grid content-start gap-3">
                <label className="field"><span>{tr("Owner")}</span>{canEdit ? <FilterCombo label={tr("Owner")} all={tr("No owner")} value={v.owner_id ?? ""} onChange={(o) => patch({ owner_id: o || null })} placeholder={tr("Find a person")} options={[...people.entries()].map(([pid, name]) => [pid, name] as [string, string])} /> : <span><Person id={v.owner_id} fallback="No owner" /></span>}</label>
                <div className="spread"><span className="text-[13px] font-medium">{tr("In scope for your residency definition")}</span><Switch aria-label={tr("In scope")} disabled={!canEdit} checked={v.in_scope} onCheckedChange={(c) => patch({ in_scope: c })} /></div>
                <div><div className="mb-1 text-[13px] font-medium">{tr("Data types")}</div><div className="flex flex-wrap gap-1">{v.entity_types.length ? v.entity_types.map((e) => <Badge key={e}>{entityLabel(e)}</Badge>) : <span className="muted">{tr("None recorded")}</span>}</div></div>
                {canEdit && v.status !== "retired" && <div className="row"><Button size="sm" variant="outline" disabled={!!v.exception} onClick={() => setExcOpen(true)}>{tr("Request an exception")}</Button><Button size="sm" variant="ghost" onClick={() => setRetire(true)}>{tr("Retire this flow")}</Button></div>}
                <ErrorLine error={error} />
              </div>
            </div>
          </TabsContent>
          {v.fix && <TabsContent value="fix"><FixIt f={v} canEdit={canEdit} reload={f.reload} /></TabsContent>}
          <TabsContent value="evidence">{t.value ? <Evidence t={t.value} f={v} /> : <Loading error={t.error} loading={t.loading} />}</TabsContent>
          <TabsContent value="timeline">{t.value ? <TimelineTab t={t.value} /> : <Loading error={t.error} loading={t.loading} />}</TabsContent>
          <TabsContent value="remediation"><Remediation f={v} canEdit={canEdit} reload={f.reload} /></TabsContent>
          <TabsContent value="exceptions">{v.exceptions.length === 0 ? <Empty title={tr("No exceptions on this flow")} /> : <ExceptionsTable rows={v.exceptions} reload={f.reload} />}</TabsContent>
        </Tabs>
      )}
      {excOpen && v && <RequestException flow={v.id} max={settings.value?.exception_max_days ?? 180} onDone={f.reload} onClose={() => setExcOpen(false)} />}
      {retire && <TypedConfirm title={tr("Retire this flow")} word="retire" onClose={() => setRetire(false)} onConfirm={async () => { await control(`/v1/map/flows/${id}/retire`, { method: "POST" }); f.reload(); }}>{tr("Use this when the flow no longer exists. If Onshore sees this traffic again, a new flow appears.")}</TypedConfirm>}
    </Page>
  );
}
