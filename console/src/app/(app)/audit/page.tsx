"use client";
import { tr } from "@/lib/i18n";
import { Bookmark, Columns3, Trash2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { FilterChips, FilterCombo, FilterSelect, SortHead, SortState } from "@/components/table-tools";
import { Badge, DecisionBadge, Empty, ErrorLine, Loading, Page, rowKeys } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { control, n, useLoad, when } from "@/lib/api";
import { actionLabel, areaLabel, DECISION_VALUES, decisionLabel, reasonLabel } from "@/lib/labels";
import { personName, usePeople } from "@/lib/people";

const BLANK = { range: "", from: "", to: "", principal: "", action: "", decision: "", module: "", network: "", field: "" };
type Filters = typeof BLANK;
const VIEWS_KEY = "rv-audit-views";
const COLUMNS_KEY = "rv-audit-columns";
const PAGE = 100;

const RANGES: Record<string, { label: string; hours?: number }> = { "24h": { label: "Last 24 hours", hours: 24 }, "7d": { label: "Last 7 days", hours: 168 }, "30d": { label: "Last 30 days", hours: 720 }, custom: { label: "Choose dates" } };

/** A saved "last 7 days" stays relative: the window is worked out when it is used. */
function qs(f: Filters, extra: Record<string, string> = {}) {
  const p = new URLSearchParams(extra);
  const hours = RANGES[f.range]?.hours;
  if (hours) p.set("from", new Date(Date.now() - hours * 3_600_000).toISOString());
  if (f.range === "custom") {
    if (f.from) p.set("from", new Date(f.from).toISOString());
    if (f.to) p.set("to", new Date(f.to).toISOString());
  }
  for (const k of ["principal", "action", "decision", "module", "network", "field"] as const) if (f[k]) p.set(k, f[k]);
  return p.toString();
}

function stored<T>(key: string, fallback: T): T {
  try { return JSON.parse(localStorage.getItem(key) ?? "null") ?? fallback; } catch { return fallback; }
}
function store(key: string, value: unknown) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage may be blocked */ }
}

const OPTIONAL: [string, string][] = [["module", "Area"], ["field", "Field"], ["purpose", "Reason given"], ["policy", "Policy"], ["network", "Network"], ["ip", "IP address"], ["seq", "Entry number"]];
const DEFAULT_COLUMNS = ["module", "field", "purpose"];

export default function Audit() {
  const [f, setF] = useState<Filters>(BLANK);
  const [sort, setSort] = useState<SortState<"time">>({ key: "time", dir: "desc" });
  const [events, setEvents] = useState<any[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [views, setViews] = useState<Record<string, Filters>>({});
  const [viewName, setViewName] = useState("");
  const [columns, setColumns] = useState<string[]>(DEFAULT_COLUMNS);
  const [selected, setSelected] = useState<any | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const latest = useRef(0);
  const chain = useLoad(() => control("/v1/audit-events/verify", { method: "POST" }));
  const vaults = useLoad<{ vaults: { name: string; vault_fields: { id: string; name: string }[] }[] }>(() => control("/v1/vaults"));
  const summary = useLoad<{ total: number; actions: string[]; modules: string[]; networks: string[]; principals: string[] }>(() => control(`/v1/audit-events/summary?${qs(f)}`), [f]);
  const names = usePeople();
  const allFields = vaults.value?.vaults.flatMap((v) => v.vault_fields.map((x) => [x.id, x.name, v.name] as const)) ?? [];
  const fieldNames = new Map(allFields.map(([id, name]) => [id, name] as const));
  const order = sort.dir === "asc" ? "oldest" : "newest";
  const load = async (cursor?: string) => {
    const mine = ++latest.current;
    setErr(null);
    setLoading(true);
    try {
      const page = cursor ? { [order === "oldest" ? "after_seq" : "before_seq"]: cursor } : {};
      const r = await control<{ events: any[] }>(`/v1/audit-events?${qs(f, { limit: String(PAGE), order, ...page })}`);
      if (mine !== latest.current) return;
      setEvents((cur) => (cursor ? [...cur, ...r.events] : r.events));
      setMore(r.events.length === PAGE);
    } catch (e) {
      if (mine === latest.current) setErr(e instanceof Error ? e.message : "failed");
    } finally {
      if (mine === latest.current) setLoading(false);
    }
  };
  useEffect(() => { load(); }, [f, order]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setViews(stored(VIEWS_KEY, {})); setColumns(stored(COLUMNS_KEY, DEFAULT_COLUMNS)); }, []);
  const change = (k: keyof Filters) => (v: string) => setF({ ...f, [k]: v });
  const saveViews = (next: Record<string, Filters>) => { setViews(next); store(VIEWS_KEY, next); };
  const show = (c: string) => columns.includes(c);
  const c = chain.value;
  const s = summary.value;
  const active = Object.entries(f).some(([k, v]) => v && k !== "from" && k !== "to");
  const chip = (key: keyof Filters, label: string) => ({ key, label, clear: () => setF(key === "range" ? { ...f, range: "", from: "", to: "" } : { ...f, [key]: "" }) });
  const chips = [
    ...(f.range ? [chip("range", f.range === "custom" ? `${f.from ? when(f.from) : "Start"} to ${f.to ? when(f.to) : "now"}` : RANGES[f.range]!.label)] : []),
    ...(f.principal ? [chip("principal", tr("Person: {0}", { 0: personName(names, f.principal) }))] : []),
    ...(f.action ? [chip("action", tr("Action: {0}", { 0: actionLabel(f.action) }))] : []),
    ...(f.decision ? [chip("decision", tr("Result: {0}", { 0: decisionLabel(f.decision) }))] : []),
    ...(f.module ? [chip("module", tr("Area: {0}", { 0: areaLabel(f.module) }))] : []),
    ...(f.field ? [chip("field", tr("Field: {0}", { 0: fieldNames.get(f.field) ?? f.field }))] : []),
    ...(f.network ? [chip("network", tr("Network: {0}", { 0: f.network }))] : []),
  ];
  return (
    <Page
      title={tr("Audit log")}
      sub={tr("Everything anyone does with protected data is recorded here. Past entries cannot be changed without it showing, and no entry holds a sensitive value.")}
      actions={
        <>
          {c && <span title={c.ok ? tr("Checked up to {0}, against {1} signed daily checkpoints", { 0: c.verified_to ? when(c.verified_to) : tr("the start"), 1: c.checkpoints_checked }) : undefined}><Badge tone={c.ok ? "good" : "bad"}>{c.ok ? tr("Log intact, {0} entries checked", { 0: n(c.events_checked) }) : tr("Log has been altered: {0}", { 0: c.reason })}</Badge></span>}
          <Button variant="outline" size="sm" disabled={verifying} onClick={async () => { setVerifying(true); await chain.reload(); setVerifying(false); }}>{verifying ? "Checking…" : "Check again"}</Button>
          <Button variant="outline" size="sm" asChild><a href={`/api/proxy/control/v1/audit-events/export?${qs(f)}`}>{tr("Export CSV")}</a></Button>
          <Button variant="outline" size="sm" asChild><a href={`/api/proxy/control/v1/audit-events/export.pdf?${qs(f)}`}>{tr("Signed PDF")}</a></Button>
        </>
      }
    >
      <div className="toolbar">
        <FilterSelect label={tr("When")} all={tr("Any time")} value={f.range} onChange={(v) => setF({ ...f, range: v, from: "", to: "" })} options={Object.entries(RANGES).map(([k, r]) => [k, r.label])} />
        {f.range === "custom" && <>
          <label className="filter-date">{tr("From")} <Input type="datetime-local" value={f.from} onChange={(e) => change("from")(e.target.value)} /></label>
          <label className="filter-date">to <Input type="datetime-local" value={f.to} onChange={(e) => change("to")(e.target.value)} /></label>
        </>}
        <FilterCombo label={tr("Person")} all={tr("Anyone")} placeholder={tr("Find a person…")} value={f.principal} onChange={change("principal")} options={(s?.principals ?? []).map((id) => [id, personName(names, id)] as [string, string]).sort((a, b) => a[1].localeCompare(b[1]))} />
        <FilterCombo label={tr("Action")} all={tr("Any action")} placeholder={tr("Find an action…")} value={f.action} onChange={change("action")} options={(s?.actions ?? []).map((a) => [a, actionLabel(a)] as [string, string]).sort((a, b) => a[1].localeCompare(b[1]))} />
        <FilterSelect label={tr("Result")} all={tr("Any result")} value={f.decision} onChange={change("decision")} options={DECISION_VALUES.map((d) => [d, decisionLabel(d)])} />
        <FilterSelect label={tr("Area")} all={tr("Any area")} value={f.module} onChange={change("module")} options={(s?.modules ?? []).map((m) => [m, areaLabel(m)])} />
        <FilterCombo label={tr("Field")} all={tr("Any field")} placeholder={tr("Find a field…")} value={f.field} onChange={change("field")} options={allFields.map(([id, name, vault]) => [id, `${name} (${vault})`])} />
        {(s?.networks.length ?? 0) > 0 && <FilterSelect label={tr("Network")} all={tr("Any network")} value={f.network} onChange={change("network")} options={s!.networks.map((x) => [x, x])} />}
        <span className="ml-auto flex flex-wrap gap-2">
          <Popover>
            <PopoverTrigger asChild><Button variant="outline" size="sm"><Bookmark />{tr("Saved views")}{Object.keys(views).length > 0 && ` (${Object.keys(views).length})`}</Button></PopoverTrigger>
            <PopoverContent align="end" className="grid w-72 gap-2">
              {Object.keys(views).length === 0 && <p className="text-[13px] text-muted-foreground">{tr("Save the filters you use often. Saved views stay in this browser.")}</p>}
              {Object.entries(views).map(([name, v]) => (
                <div key={name} className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" className="flex-1 justify-start truncate" onClick={() => setF({ ...BLANK, ...v })}>{name}</Button>
                  <Button variant="ghost" size="icon-sm" aria-label={tr("Delete view {0}", { 0: name })} onClick={() => { const { [name]: _gone, ...rest } = views; saveViews(rest); }}><Trash2 /></Button>
                </div>
              ))}
              <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (viewName.trim()) { saveViews({ ...views, [viewName.trim()]: f }); setViewName(""); } }}>
                <Input aria-label={tr("View name")} placeholder={tr("Name these filters")} value={viewName} onChange={(e) => setViewName(e.target.value)} />
                <Button type="submit" size="sm" disabled={!viewName.trim() || !active}>{tr("Save")}</Button>
              </form>
            </PopoverContent>
          </Popover>
          <DropdownMenu>
            <DropdownMenuTrigger asChild><Button variant="outline" size="sm"><Columns3 />{tr("Columns")}</Button></DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {OPTIONAL.map(([k, label]) => (
                <DropdownMenuCheckboxItem key={k} checked={show(k)} onSelect={(e) => e.preventDefault()} onCheckedChange={(on) => { const next = on ? [...columns, k] : columns.filter((x) => x !== k); setColumns(next); store(COLUMNS_KEY, next); }}>{label}</DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </span>
      </div>
      <FilterChips chips={chips} onClear={() => setF(BLANK)} />
      <ErrorLine error={err} />
      <Loading error={chain.error} loading={false} />
      {!loading && !err && events.length === 0 && <Empty title={tr("No entries match")}>{active ? <p>{tr("Try a wider date range or remove a filter.")}</p> : <p>{tr("Entries appear as soon as anyone uses the vault.")}</p>}</Empty>}
      {events.length > 0 && (
        <>
          <div className={`data-table${loading ? " busy" : ""}`}>
            <Table>
              <TableHeader>
                <TableRow>
                  {show("seq") && <TableHead className="num">{tr("Entry")}</TableHead>}
                  <SortHead label={tr("Time (organisation's zone)")} col="time" sort={sort} onSort={setSort} />
                  <TableHead>{tr("Person")}</TableHead>
                  <TableHead>{tr("Action")}</TableHead>
                  {show("module") && <TableHead>{tr("Area")}</TableHead>}
                  {show("field") && <TableHead>{tr("Field")}</TableHead>}
                  <TableHead>{tr("Result")}</TableHead>
                  {show("purpose") && <TableHead>{tr("Reason given")}</TableHead>}
                  {show("policy") && <TableHead>{tr("Policy")}</TableHead>}
                  {show("network") && <TableHead>{tr("Network")}</TableHead>}
                  {show("ip") && <TableHead>{tr("IP address")}</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e) => {
                  const open = () => setSelected(e);
                  return (
                    <TableRow key={e.seq} className="click" tabIndex={0} onClick={open} onKeyDown={(k) => rowKeys(k, open)}>
                      {show("seq") && <TableCell className="num">{e.seq}</TableCell>}
                      <TableCell>{when(e.occurred_at)}</TableCell>
                      <TableCell title={e.principal_id ?? undefined}>{personName(names, e.principal_id)}</TableCell>
                      <TableCell title={e.action}>{actionLabel(e.action, e.decision)}{e.break_glass && <> <Badge tone="warn">{tr("Emergency access")}</Badge></>}</TableCell>
                      {show("module") && <TableCell>{areaLabel(e.module)}</TableCell>}
                      {show("field") && <TableCell>{e.field_id ? fieldNames.get(e.field_id) ?? e.field_id : ""}</TableCell>}
                      <TableCell>{e.decision ? <DecisionBadge value={e.decision} /> : null}</TableCell>
                      {show("purpose") && <TableCell className="cell-wrap">{reasonLabel(e.purpose)}</TableCell>}
                      {show("policy") && <TableCell title={e.policy_id ?? ""}>{e.policy_id ? tr("Version {0}", { 0: e.policy_version }) : ""}</TableCell>}
                      {show("network") && <TableCell>{e.network}</TableCell>}
                      {show("ip") && <TableCell className="mono">{e.source_ip}</TableCell>}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <div className="spread mt-2 text-[13px] text-muted-foreground">
            <span>{tr("Showing")} {n(events.length)}{s ? ` of ${n(s.total)}` : ""} entries</span>
            {more && <Button variant="outline" size="sm" disabled={loading} onClick={() => load(events[events.length - 1].seq)}>{order === "oldest" ? tr("Load newer") : tr("Load older")}</Button>}
          </div>
        </>
      )}
      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="audit-sheet w-full overflow-auto sm:max-w-md">
          {selected && <EntryDetail e={selected} fieldName={fieldNames.get(selected.field_id)} name={personName(names, selected.principal_id)} />}
        </SheetContent>
      </Sheet>
    </Page>
  );
}

function EntryDetail({ e, fieldName, name }: { e: any; fieldName?: string; name: string }) {
  const row = (label: string, value: React.ReactNode, mono?: boolean) => value === null || value === undefined || value === "" ? null : <div className="kv"><dt>{label}</dt><dd className={mono ? "mono" : undefined}>{value}</dd></div>;
  const isPerson = e.principal_id?.startsWith("usr_") || e.principal_id?.startsWith("sa_");
  return (
    <>
      <SheetHeader>
        <SheetTitle>{actionLabel(e.action, e.decision)}</SheetTitle>
        <SheetDescription>{when(e.occurred_at)}{tr(", organisation's time zone")}</SheetDescription>
      </SheetHeader>
      <div className="grid gap-5 px-4 pb-6">
        <dl className="kv-list">
          {row("Person", isPerson ? <Link href={`/people/${e.principal_id}`}>{name}</Link> : name)}
          {row("Result", e.decision ? <DecisionBadge value={e.decision} /> : null)}
          {row("Area", areaLabel(e.module))}
          {row("Field", e.field_id ? fieldName ?? e.field_id : null)}
          {row("Reason given", reasonLabel(e.purpose))}
          {row("Policy", e.policy_id ? tr("Version {0}", { 0: e.policy_version }) : null)}
          {row("Network", e.network)}
          {row("IP address", e.source_ip, true)}
          {row("Country", e.geo_country)}
          {row("Emergency access", e.break_glass ? "Yes" : null)}
          {row("Took", e.latency_ms != null ? `${e.latency_ms} ms` : null)}
        </dl>
        <div>
          <h2 className="mb-2">{tr("For investigators")}</h2>
          <dl className="kv-list">
            {row("Entry number", e.seq)}
            {row("Exact action name", e.action, true)}
            {row("Person ID", e.principal_id, true)}
            {row("Vault ID", e.vault_id, true)}
            {row("Record ID", e.record_id, true)}
            {row("Request ID", e.request_id, true)}
            {row("Entry fingerprint", e.hash, true)}
            {row("Previous fingerprint", e.prev_hash, true)}
            {row("More detail", e.detail, true)}
          </dl>
        </div>
      </div>
    </>
  );
}
