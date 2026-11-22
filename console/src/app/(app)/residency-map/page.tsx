"use client";
import { tr } from "@/lib/i18n";
import { CircleAlert, Download, Plus, ShieldCheck, Waves } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { useMe } from "@/components/Shell";
import { FilterChips, FilterCombo, FilterSelect, PageBar, SortHead } from "@/components/table-tools";
import { Badge, Empty, ErrorLine, Loading, Stat, rowKeys } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { control, n, useLoad, when } from "@/lib/api";
import { entityLabel } from "@/lib/labels";
import { usePeople } from "@/lib/people";
import { age, Country, countryName, flag, Flow, MAP_EDIT, MapFrame, Spark, SplitBar, STATUS, STATUS_ORDER, StatusChip, Summary } from "./shared";

interface Filters { status: string; entity_type: string; owner: string; in_scope: string; dest_country: string; origin: string; q: string; open_work: string }
const BLANK: Filters = { status: "", entity_type: "", owner: "", in_scope: "", dest_country: "", origin: "", q: "", open_work: "" };
const VIEWS_KEY = "onshore.map.views";

function Header({ s, status, onStatus }: { s: Summary; status: string; onStatus: (v: string) => void }) {
  const fmt = (v: number | null) => (v === null ? "n/a" : `${Math.round(v * 10) / 10}%`);
  const exc = s.counts.exception ?? 0;
  // Alerts are open work too, so this card and the alert list below never disagree.
  const alerts = useLoad<{ alerts: unknown[] }>(() => control("/v1/map/alerts")).value?.alerts.length ?? 0;
  const open = s.needs_attention.total + alerts;
  return (
    <div className="grid gap-3">
      <div className="grid gap-3 md:grid-cols-3">
        <Stat icon={ShieldCheck} tone="blue" label={tr("Flow score")} value={fmt(s.flow_score)} hint={exc ? tr("{0} accepted {1} counted; {2} without", { 0: exc, 1: exc === 1 ? tr("risk") : tr("risks"), 2: fmt(s.flow_score_without_exceptions) }) : tr("Share of in-scope flows that are safe")}><Spark values={s.series.map((x) => x.flow)} label={tr("Flow score")} /></Stat>
        <Stat icon={Waves} tone="teal" label={tr("Volume score")} value={fmt(s.volume_score)} hint={tr("Share of in-scope detections protected or kept in the vault's country, last 30 days")}><Spark values={s.series.map((x) => x.volume)} label={tr("Volume score")} /></Stat>
        <Stat icon={CircleAlert} tone={open ? "amber" : "teal"} label={tr("Open work")} value={n(open)} hint={tr("{0} {1} to review, {2} locations to confirm, {3} fixes overdue, {4} exceptions expiring soon", { 0: alerts, 1: alerts === 1 ? tr("alert") : tr("alerts"), 2: s.needs_attention.unconfirmed_regions, 3: s.needs_attention.overdue_actions, 4: s.needs_attention.exceptions_expiring })} />
      </div>
      <div className="row flex-wrap" role="group" aria-label={tr("Filter by status")}>
        {STATUS_ORDER.map((k) => (
          <button key={k} type="button" className="status-filter" title={STATUS[k]!.hint} aria-pressed={status === k} onClick={() => onStatus(status === k ? "" : k)} style={{ "--chip": `var(--map-${k})` } as React.CSSProperties}>
            <i aria-hidden />{STATUS[k]!.label} <b>{n(s.counts[k] ?? 0)}</b>
          </button>
        ))}
      </div>
    </div>
  );
}

// ---- map view ---------------------------------------------------------------
const DENSE = 120;
const ROW = 46, BOX_W = 230, BOX_H = 36, COLS = [0, 400, 790];
function trim(t: string, max = 28) { return t.length > max ? `${t.slice(0, max - 1)}…` : t; }

function MapView({ flows }: { flows: Flow[] }) {
  const router = useRouter();
  const [hover, setHover] = useState<string | null>(null);
  const [hoverNode, setHoverNode] = useState<string | null>(null);
  // Hundreds of lines cannot be read, so a large map draws only those of the box in focus.
  const dense = flows.length > DENSE;
  const layout = useMemo(() => {
    const sources = new Map<string, { id: string; name: string; kind: string }>();
    const destKey = (f: Flow) => f.dest.system_id ?? f.dest.host ?? f.dest.name;
    const here = new Map<string, Flow>();
    const groups = new Map<string, Map<string, Flow>>();
    for (const f of flows) {
      sources.set(f.source.id, f.source);
      const inCountry = !!f.dest_country && f.dest_country === f.home_country && f.dest_country_source !== "unconfirmed";
      if (inCountry) here.set(destKey(f), f);
      else {
        const g = f.dest_country_source === "unconfirmed" || !f.dest_country ? "?" : f.dest_country;
        if (!groups.has(g)) groups.set(g, new Map());
        groups.get(g)!.set(destKey(f), f);
      }
    }
    const pos = new Map<string, { x: number; y: number }>();
    let y0 = 34;
    for (const id of sources.keys()) { pos.set(`s:${id}`, { x: COLS[0]!, y: y0 }); y0 += ROW; }
    let y1 = 34;
    for (const k of here.keys()) { pos.set(`d:${k}`, { x: COLS[1]!, y: y1 }); y1 += ROW; }
    let y2 = 34;
    const headers: { label: string; y: number }[] = [];
    const ordered = [...groups.entries()].sort((a, b) => (a[0] === "?" ? 1 : b[0] === "?" ? -1 : countryName(a[0]).localeCompare(countryName(b[0]))));
    for (const [g, dests] of ordered) {
      headers.push({ label: g === "?" ? "Location not confirmed" : `${flag(g)} ${countryName(g)}`, y: y2 + 12 });
      y2 += 20;
      for (const k of dests.keys()) { pos.set(`d:${k}`, { x: COLS[2]!, y: y2 }); y2 += ROW; }
      y2 += 6;
    }
    return { sources: [...sources.values()], here: [...here.entries()], groups: ordered, pos, headers, height: Math.max(y0, y1, y2, 160) + 10, destKey };
  }, [flows]);
  const maxV = Math.max(1, ...flows.map((f) => f.protected_30d + f.passed_30d));
  const open = (href: string) => router.push(href);
  const nodeProps = (href: string, label: string, node: string) => ({ onMouseEnter: () => setHoverNode(node), onMouseLeave: () => setHoverNode(null), onFocus: () => setHoverNode(node), onBlur: () => setHoverNode(null), className: "map-node", role: "link", tabIndex: 0, "aria-label": label, onClick: () => open(href), onKeyDown: (e: React.KeyboardEvent) => { if (e.key === "Enter") open(href); } });
  if (flows.length === 0) return <Empty title={tr("No flows match")}>{tr("Traffic through a connection appears here by itself. To add something Onshore cannot see, add a system.")}</Empty>;
  return (
    <div className="card map-canvas">
      {dense && <p className="mb-2 text-[13px] text-muted-foreground">{n(flows.length)} {tr("flows are too many lines to read at once. Point at a box to see its flows, use the filters above, or open the Flows tab.")}</p>}
      <svg viewBox={`-2 0 ${COLS[2]! + BOX_W + 4} ${layout.height}`} role="group" aria-label={tr("Map of data flows. The Flows tab has the same data as a table.")}>
        <text className="map-col" x={COLS[0]} y={16}>{tr("YOUR SYSTEMS")}</text>
        <text className="map-col" x={COLS[1]} y={16}>{tr("IN THE VAULT'S COUNTRY")}</text>
        <text className="map-col" x={COLS[2]} y={16}>{tr("OFFSHORE")}</text>
        {flows.map((f) => {
          const a = layout.pos.get(`s:${f.source.id}`), b = layout.pos.get(`d:${layout.destKey(f)}`);
          if (!a || !b) return null;
          if (dense && hoverNode !== `s:${f.source.id}` && hoverNode !== `d:${layout.destKey(f)}`) return null;
          const x1 = a.x + BOX_W, y1 = a.y + BOX_H / 2, x2 = b.x, y2 = b.y + BOX_H / 2, mx = (x1 + x2) / 2;
          const d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
          const vol = f.protected_30d + f.passed_30d;
          const width = 1.4 + (vol ? (Math.log10(vol + 1) / Math.log10(maxV + 1)) * 4 : 0);
          const dim = hover && hover !== f.id ? 0.18 : 1;
          const label = `${f.source.name} to ${f.dest.name}, ${STATUS[f.status]?.label}`;
          return (
            <g key={f.id}>
              <path className="map-line" d={d} stroke={`var(--map-${f.status})`} strokeWidth={width} opacity={dim} strokeDasharray={f.basis === "declared" ? "5 4" : undefined} />
              <path className="map-hit" d={d} role="link" tabIndex={0} aria-label={label} onMouseEnter={() => setHover(f.id)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(f.id)} onBlur={() => setHover(null)} onClick={() => open(`/residency-map/flows/${f.id}`)} onKeyDown={(e) => { if (e.key === "Enter") open(`/residency-map/flows/${f.id}`); }}><title>{label}</title></path>
              {f.onshore_managed && <g opacity={dim} pointerEvents="none"><rect x={mx - 8} y={(y1 + y2) / 2 - 8} width={16} height={16} rx={4} fill="var(--primary)" /><text x={mx} y={(y1 + y2) / 2 + 3.5} textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--primary-foreground)">O</text></g>}
            </g>
          );
        })}
        {layout.sources.map((s) => { const p = layout.pos.get(`s:${s.id}`)!; return (
          <g key={s.id} {...nodeProps(`/residency-map/systems/${s.id}`, tr("System {0}", { 0: s.name }), `s:${s.id}`)}><rect className="map-box" x={p.x} y={p.y} width={BOX_W} height={BOX_H} rx={8} /><text x={p.x + 12} y={p.y + 15}>{trim(s.name)}</text><text className="sub" x={p.x + 12} y={p.y + 29}>{s.kind.replaceAll("_", " ")}</text></g>
        ); })}
        {layout.headers.map((h) => <text key={h.label} className="map-group" x={COLS[2]} y={h.y}>{h.label}</text>)}
        {[...layout.here, ...layout.groups.flatMap(([, d]) => [...d.entries()])].map(([k, f]) => { const p = layout.pos.get(`d:${k}`)!; const href = f.dest.system_id ? `/residency-map/systems/${f.dest.system_id}` : `/residency-map/flows/${f.id}`; return (
          <g key={k} {...nodeProps(href, tr("Destination {0}", { 0: f.dest.name }), `d:${k}`)}><rect className="map-box" x={p.x} y={p.y} width={BOX_W} height={BOX_H} rx={8} /><text x={p.x + 12} y={p.y + 15}>{trim(f.dest.name)}</text><text className="sub" x={p.x + 12} y={p.y + 29}>{trim(f.dest.region ?? (f.dest.host === "host.docker.internal" ? null : f.dest.host) ?? f.dest.category ?? "", 34)}</text></g>
        ); })}
      </svg>
      <div className="row mt-2 flex-wrap text-[12px] text-muted-foreground">
        <span>{tr("Line thickness shows 30-day volume.")}</span><span>{tr("Dashed lines are declared by you, not seen by Onshore.")}</span><span><b className="text-primary">O</b> {tr("means the flow passes through Onshore.")}</span>
      </div>
    </div>
  );
}

// ---- table ------------------------------------------------------------------
function FlowsTable({ flows, total, picked, setPicked, canEdit, offset, size, setOffset, setSize, sort, setSort, vault, reload }: { flows: Flow[]; total: number; picked: Set<string>; setPicked: (s: Set<string>) => void; canEdit: boolean; offset: number; size: number; setOffset: (n: number) => void; setSize: (n: number) => void; sort: string; setSort: (s: string) => void; vault: string; reload: () => void }) {
  const router = useRouter();
  const people = usePeople();
  const [error, setError] = useState<string | null>(null);
  const page = flows.slice(offset, offset + size);
  const toggle = (id: string) => { const s = new Set(picked); if (s.has(id)) s.delete(id); else s.add(id); setPicked(s); };
  const bulk = async (body: Record<string, unknown>) => {
    setError(null);
    try { await control("/v1/map/flows/bulk", { body: { ids: [...picked], ...body } }); setPicked(new Set()); reload(); }
    catch (e) { setError(e instanceof Error ? e.message : "failed"); }
  };
  if (flows.length === 0) return <Empty title={tr("No flows match")}>{tr("Try removing a filter.")}</Empty>;
  return (
    <div className="grid gap-2">
      {picked.size > 0 && (
        <div className="row flex-wrap rounded-lg border bg-accent px-3 py-2 text-[13px]">
          <b>{picked.size} selected</b>
          {canEdit && <FilterCombo label={tr("Assign an owner")} all={tr("Assign an owner")} value="" onChange={(v) => v && bulk({ owner_id: v })} placeholder={tr("Find a person")} options={[...people.entries()].map(([id, name]) => [id, name])} />}
          {canEdit && <Button size="sm" variant="outline" onClick={() => bulk({ in_scope: true })}>{tr("Mark in scope")}</Button>}
          {canEdit && <Button size="sm" variant="outline" onClick={() => bulk({ in_scope: false })}>{tr("Mark out of scope")}</Button>}
          <Button size="sm" variant="outline" asChild><a href={`/api/proxy/control/v1/map/export?vault_id=${vault}&format=csv&ids=${[...picked].join(",")}`}>{tr("Export selection")}</a></Button>
          <ErrorLine error={error} />
        </div>
      )}
      <div className="data-table">
        <Table>
          <TableHeader><TableRow>
            <TableHead className="w-8"><Checkbox aria-label={tr("Select all on this page")} checked={page.length > 0 && page.every((f) => picked.has(f.id))} onCheckedChange={(c) => { const s = new Set(picked); page.forEach((f) => (c ? s.add(f.id) : s.delete(f.id))); setPicked(s); }} /></TableHead>
            <TableHead>{tr("Source to destination")}</TableHead><TableHead>{tr("Country")}</TableHead><TableHead>{tr("Data types")}</TableHead>
            <SortHead label={tr("Status")} col="status" first="asc" sort={{ key: sort, dir: sort === "status" ? "asc" : "desc" }} onSort={(s) => setSort(s.key)} />
            <SortHead label={tr("30-day volume")} col="passed" sort={{ key: sort, dir: "desc" }} onSort={(s) => setSort(s.key)} />
            <TableHead>{tr("Owner")}</TableHead><TableHead>{tr("Open work")}</TableHead><TableHead>{tr("Seen by")}</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {page.map((f) => { const go = () => router.push(`/residency-map/flows/${f.id}`); return (
              <TableRow key={f.id} className="click" tabIndex={0} onClick={go} onKeyDown={(e) => rowKeys(e, go)}>
                <TableCell onClick={(e) => e.stopPropagation()}><Checkbox aria-label={tr("Select {0} to {1}", { 0: f.source.name, 1: f.dest.name })} checked={picked.has(f.id)} onCheckedChange={() => toggle(f.id)} /></TableCell>
                <TableCell><div className="font-medium">{f.source.name} <span className="text-muted-foreground">→</span> {f.dest.name}</div><div className="text-[12px] text-muted-foreground">{f.dest.region ?? f.dest.host ?? ""}{!f.in_scope && " · Out of scope"}</div></TableCell>
                <TableCell><Country code={f.dest_country} source={f.dest_country_source} /></TableCell>
                <TableCell><div className="flex max-w-[210px] flex-wrap gap-1">{f.entity_types.slice(0, 3).map((e) => <Badge key={e}>{entityLabel(e)}</Badge>)}{f.entity_types.length > 3 && <Badge>+{f.entity_types.length - 3}</Badge>}</div></TableCell>
                <TableCell><StatusChip status={f.status} flow={f} /><div className="text-[12px] text-muted-foreground">{age(f.status_since)}</div></TableCell>
                <TableCell className="min-w-[90px]"><SplitBar p={f.protected_30d} u={f.passed_30d} /></TableCell>
                <TableCell>{f.owner_name ?? <span className="text-muted-foreground">{tr("No owner")}</span>}</TableCell>
                <TableCell>{f.overdue_actions > 0 ? <Badge tone="bad">{f.overdue_actions} overdue</Badge> : f.open_actions > 0 ? <Badge tone="info">{f.open_actions} open</Badge> : null}{f.exception && <div className="text-[12px] text-muted-foreground">{f.exception.status === "pending" ? tr("Exception pending") : tr("Accepted until {0}", { 0: String(f.exception.expires_at).slice(0, 10) })}</div>}</TableCell>
                <TableCell>{f.basis === "observed" ? tr("Onshore") : tr("Declared")}</TableCell>
              </TableRow>
            ); })}
          </TableBody>
        </Table>
      </div>
      <PageBar offset={offset} size={size} total={total} noun="flows" onOffset={setOffset} onSize={(s) => { setSize(s); setOffset(0); }} />
    </div>
  );
}

function Alerts({ reloadKey }: { reloadKey: number }) {
  const a = useLoad<{ alerts: { id: string; kind: string; detail: { message?: string; flow_id?: string }; raised_at: string }[] }>(() => control("/v1/map/alerts"), [reloadKey]);
  const list = a.value?.alerts ?? [];
  if (list.length === 0) return null;
  return (
    <details className="card">
      <summary className="cursor-pointer text-[13px] font-medium">{list.length} {list.length === 1 ? tr("alert") : tr("alerts")} {tr("to review")}</summary>
      <ul className="mt-2 grid gap-1.5 text-[13px]">
        {list.slice(0, 20).map((x) => (
          <li key={x.id} className="spread gap-3">
            <span>{x.detail.flow_id ? <Link className="underline" href={`/residency-map/flows/${x.detail.flow_id}`}>{x.detail.message}</Link> : x.detail.message} <span className="text-muted-foreground">{when(x.raised_at)}</span></span>
            <Button size="sm" variant="ghost" onClick={async () => { await control(`/v1/alerts/${x.id}/acknowledge`, { method: "POST" }); a.reload(); }}>{tr("Dismiss")}</Button>
          </li>
        ))}
      </ul>
    </details>
  );
}

function Body({ vault }: { vault: string }) {
  const me = useMe();
  const canEdit = (me?.roles ?? []).some((r) => MAP_EDIT.includes(r));
  const [f, setF] = useState<Filters>(BLANK);
  const [sort, setSort] = useState("status");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [size, setSize] = useState(50);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [tab, setTab] = useState("map");
  const [views, setViews] = useState<{ name: string; f: Filters }[]>([]);
  useEffect(() => { try { setViews(JSON.parse(localStorage.getItem(VIEWS_KEY) ?? "[]")); } catch { /* private window */ } }, []);
  useEffect(() => { const t = setTimeout(() => { setF((x) => (x.q === q ? x : { ...x, q })); setOffset(0); }, 250); return () => clearTimeout(t); }, [q]);
  const qs = useMemo(() => { const p = new URLSearchParams({ vault_id: vault, sort, limit: "2000" }); for (const [k, v] of Object.entries(f)) if (v) p.set(k, v); return p.toString(); }, [vault, f, sort]);
  const [changes, setChanges] = useState(1);
  const flows = useLoad<{ flows: Flow[]; total: number }>(() => control(`/v1/map/flows?${qs}`), [qs]);
  const summary = useLoad<Summary>(() => control(`/v1/map/summary?vault_id=${vault}`), [vault, flows.value === null || flows.value === undefined ? 0 : changes]);
  const entities = useMemo(() => [...new Set((flows.value?.flows ?? []).flatMap((x) => x.entity_types))].sort(), [flows.value]);
  const countries = useMemo(() => [...new Set((flows.value?.flows ?? []).map((x) => x.dest_country).filter(Boolean) as string[])].sort(), [flows.value]);
  const people = usePeople();
  const change = (p: Partial<Filters>) => { setF((x) => ({ ...x, ...p })); setOffset(0); setPicked(new Set()); };
  const chips = [
    f.status && { key: "status", label: STATUS[f.status]?.label, clear: () => change({ status: "" }) },
    f.entity_type && { key: "entity", label: entityLabel(f.entity_type), clear: () => change({ entity_type: "" }) },
    f.owner && { key: "owner", label: f.owner === "none" ? "No owner" : people.get(f.owner) ?? "A teammate", clear: () => change({ owner: "" }) },
    f.in_scope && { key: "scope", label: f.in_scope === "true" ? "In scope" : "Out of scope", clear: () => change({ in_scope: "" }) },
    f.dest_country && { key: "country", label: f.dest_country === "unconfirmed" ? "Not confirmed" : countryName(f.dest_country), clear: () => change({ dest_country: "" }) },
    f.origin && { key: "origin", label: f.origin === "observed" ? "Seen by Onshore" : "Declared by you", clear: () => change({ origin: "" }) },
    f.open_work && { key: "open", label: tr("Only open work"), clear: () => change({ open_work: "" }) },
    f.q && { key: "q", label: `"${f.q}"`, clear: () => { setQ(""); change({ q: "" }); } },
  ].filter(Boolean) as { key: string; label: React.ReactNode; clear: () => void }[];
  const list = flows.value?.flows ?? [];
  const presets: { name: string; f: Partial<Filters> }[] = [{ name: "Leaking, in scope", f: { status: "leaking", in_scope: "true" } }, { name: "My flows", f: { owner: me?.id ?? "" } }, { name: "Exceptions", f: { status: "exception" } }];
  if (flows.value && flows.value.total === 0 && chips.length === 0) {
    return (
      <Empty title={tr("Nothing on the map yet")} action={<><Button asChild><Link href="/connect">{tr("Connect something")}</Link></Button>{canEdit && <Button variant="outline" asChild><Link href="/residency-map/new">{tr("Add a system")}</Link></Button>}</>}>
        {tr("The map fills in by itself when data passes through Onshore. Add a system for anything Onshore can’t see, such as a warehouse in a foreign cloud.")}
      </Empty>
    );
  }
  return (
    <div className="grid gap-4">
      {summary.value && <Header s={summary.value} status={f.status} onStatus={(v) => change({ status: v })} />}
      <Alerts reloadKey={0} />
      <div className="row flex-wrap">
        <Input className="w-56" aria-label={tr("Search flows")} placeholder={tr("Search system, vendor, host, owner")} value={q} onChange={(e) => setQ(e.target.value)} />
        <FilterSelect label={tr("Data type")} all={tr("Any data type")} value={f.entity_type} onChange={(v) => change({ entity_type: v })} options={entities.map((e) => [e, entityLabel(e)])} />
        <FilterCombo label={tr("Owner")} all={tr("Any owner")} value={f.owner} onChange={(v) => change({ owner: v })} placeholder={tr("Find a person")} options={[["none", tr("No owner")], ...[...people.entries()].map(([id, name]) => [id, name] as [string, string])]} />
        <FilterSelect label={tr("Scope")} all={tr("Any scope")} value={f.in_scope} onChange={(v) => change({ in_scope: v })} options={[["true", tr("In scope")], ["false", tr("Out of scope")]]} />
        <FilterSelect label={tr("Country")} all={tr("Any country")} value={f.dest_country} onChange={(v) => change({ dest_country: v })} options={[["unconfirmed", tr("Not confirmed")], ...countries.map((c) => [c, countryName(c)] as [string, string])]} />
        <FilterSelect label={tr("Seen by")} all={tr("Seen or declared")} value={f.origin} onChange={(v) => change({ origin: v })} options={[["observed", tr("Seen by Onshore")], ["manual", tr("Declared by you")]]} />
        <label className="row text-[13px]"><Checkbox checked={f.open_work === "true"} onCheckedChange={(c) => change({ open_work: c ? "true" : "" })} /> {tr("Only open work")}</label>
        <DropdownMenu>
          <DropdownMenuTrigger asChild><Button variant="outline" size="sm">{tr("Saved views")}</Button></DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {presets.map((p) => <DropdownMenuItem key={p.name} onSelect={() => { setQ(""); setF({ ...BLANK, ...p.f }); setOffset(0); }}>{p.name}</DropdownMenuItem>)}
            {views.map((v) => <DropdownMenuItem key={v.name} onSelect={() => { setQ(v.f.q); setF(v.f); setOffset(0); }}>{v.name}</DropdownMenuItem>)}
            <DropdownMenuItem disabled={chips.length === 0} onSelect={() => {
              const name = tr("View {0}: {1}", { 0: views.length + 1, 1: chips.map((c) => String(c.label)).join(", ") }).slice(0, 60);
              const next = [...views, { name, f }];
              setViews(next);
              try { localStorage.setItem(VIEWS_KEY, JSON.stringify(next)); } catch { /* private window */ }
            }}>{tr("Save these filters")}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <FilterChips chips={chips} onClear={() => { setQ(""); change(BLANK); }} />
      <Loading error={flows.error} loading={flows.loading && !flows.value} />
      {flows.value && (
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList><TabsTrigger value="map">{tr("Map")}</TabsTrigger><TabsTrigger value="table">{tr("Flows (")}{n(flows.value.total)})</TabsTrigger></TabsList>
          <TabsContent value="map"><MapView flows={list} /></TabsContent>
          <TabsContent value="table"><FlowsTable flows={list} total={list.length} picked={picked} setPicked={setPicked} canEdit={canEdit} offset={offset} size={size} setOffset={setOffset} setSize={setSize} sort={sort} setSort={setSort} vault={vault} reload={() => { flows.reload(); setChanges((c) => c + 1); }} /></TabsContent>
        </Tabs>
      )}
    </div>
  );
}

export default function ResidencyMap() {
  const me = useMe();
  const canEdit = (me?.roles ?? []).some((r) => MAP_EDIT.includes(r));
  return (
    <MapFrame title={tr("Residency map")} sub={tr("Every system and vendor that holds or receives payment and identity data. A flow turns green only when Onshore is protecting it, or it is shown to stay in the vault's country.")}
      actions={(vault) => <>
        <Button variant="outline" size="sm" asChild><Link href="/residency-map/exceptions">{tr("Exceptions")}</Link></Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild><Button variant="outline" size="sm"><Download /> {tr("Export")}</Button></DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {[["flows", tr("Flows")], ["systems", tr("Systems")], ["exceptions", tr("Exceptions")], ["actions", tr("Fixes")]].map(([t, l]) => <DropdownMenuItem key={t} asChild><a href={`/api/proxy/control/v1/map/export?vault_id=${vault}&format=csv&table=${t}`}>{l} {tr("(CSV)")}</a></DropdownMenuItem>)}
            <DropdownMenuItem asChild><a href={`/api/proxy/control/v1/map/export?vault_id=${vault}&format=json`}>{tr("Everything (JSON)")}</a></DropdownMenuItem>
            <DropdownMenuItem asChild><a href={`/api/proxy/control/v1/map/export?vault_id=${vault}&format=csv&signed=true`}>{tr("Signed, with a manifest")}</a></DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        {canEdit && <Button size="sm" asChild><Link href="/residency-map/new"><Plus /> {tr("Add system")}</Link></Button>}
      </>}>
      {(vault) => <Body key={vault} vault={vault} />}
    </MapFrame>
  );
}
