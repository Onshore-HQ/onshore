"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { Search, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { FilterChips, FilterSelect, PageBar, SortHead, SortState } from "@/components/table-tools";
import { Badge, Empty, Loading, Page, rowKeys } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { control, data, day, n, useLoad, when } from "@/lib/api";
import { entityLabel } from "@/lib/labels";

interface Subject { id: string; ref: string; field_count: number; created_at: string; last_accessed: string | null; reveals_30d: number; restricted: boolean }
type SortKey = "created_at" | "field_count" | "last_accessed" | "reveals_30d";

const BLANK = { field_type: "", has_reveals: false, flagged: false, created_after: "", created_before: "" };

export default function Records() {
  const router = useRouter();
  const vaults = useLoad<{ vaults: { id: string; name: string; environment: string; vault_fields: { data_type: string }[] }[] }>(() => control("/v1/vaults"));
  const [vault, setVault] = useState("");
  const [typed, setTyped] = useState("");
  const [query, setQuery] = useState("");
  const [f, setF] = useState(BLANK);
  const [sort, setSort] = useState<SortState<SortKey>>({ key: "created_at", dir: "desc" });
  const [size, setSize] = useState(50);
  const [offset, setOffset] = useState(0);
  const list = vaults.value?.vaults ?? [];
  useEffect(() => {
    if (!vault && list[0]) setVault(list[0].id);
  }, [list, vault]);
  const change = (next: Partial<typeof BLANK>) => { setF({ ...f, ...next }); setOffset(0); };
  const types = [...new Set(list.find((v) => v.id === vault)?.vault_fields.map((x) => x.data_type) ?? [])];
  // POST, so that a searched value never appears in a URL or an access log.
  const res = useLoad<{ subjects: Subject[]; total: number } | null>(
    () => (vault ? data(`/v1/vaults/${vault}/subjects/search`, { body: {
      query, field_type: f.field_type, has_reveals: f.has_reveals, flagged: f.flagged,
      created_after: f.created_after ? `${f.created_after}T00:00:00+01:00` : "",
      created_before: f.created_before ? `${f.created_before}T23:59:59+01:00` : "",
      sort: sort.key, dir: sort.dir, limit: size, offset,
    } }) : Promise.resolve(null)),
    [vault, query, f, sort, size, offset],
  );
  const clearAll = () => { setF(BLANK); setTyped(""); setQuery(""); setOffset(0); };
  const chips = [
    ...(query ? [{ key: "q", label: tr("Search applied"), clear: () => { setTyped(""); setQuery(""); setOffset(0); } }] : []),
    ...(f.field_type ? [{ key: "t", label: tr("Holds: {0}", { 0: entityLabel(f.field_type) }), clear: () => change({ field_type: "" }) }] : []),
    ...(f.created_after ? [{ key: "a", label: tr("Added from {0}", { 0: day(f.created_after) }), clear: () => change({ created_after: "" }) }] : []),
    ...(f.created_before ? [{ key: "b", label: tr("Added until {0}", { 0: day(f.created_before) }), clear: () => change({ created_before: "" }) }] : []),
    ...(f.has_reveals ? [{ key: "r", label: tr("Revealed in last 30 days"), clear: () => change({ has_reveals: false }) }] : []),
    ...(f.flagged ? [{ key: "f", label: "Restricted", clear: () => change({ flagged: false }) }] : []),
  ];
  const onSort = (s: SortState<SortKey>) => { setSort(s); setOffset(0); };
  const head = { sort, onSort };
  return (
    <Page title={tr("Customer records")} sub={tr("The customers who have data in this vault. Search by customer reference, a token, or an exact value such as a BVN. What you type is never stored or logged.")} actions={<Link className="btn" href="/records/import">{tr("Import existing data")}</Link>}>
      <div className="toolbar">
        <FilterSelect label={tr("Vault")} all="" value={vault} onChange={(v) => { if (v) { setVault(v); setF(BLANK); setOffset(0); } }} options={list.map((v) => [v.id, v.name])} />
        {/* Searching runs only on request: a typed value counts towards the lookup limit. */}
        <form className="search-form" onSubmit={(e) => { e.preventDefault(); setOffset(0); setQuery(typed.trim()); }}>
          <span className="search">
            <Search aria-hidden />
            <Input aria-label={tr("Search")} autoComplete="off" placeholder={tr("Customer reference, token or exact value")} value={typed} onChange={(e) => setTyped(e.target.value)} />
            {typed && <button type="button" data-slot="search-clear" aria-label={tr("Clear search")} onClick={() => { setTyped(""); setQuery(""); setOffset(0); }}><X aria-hidden /></button>}
          </span>
          <Button type="submit">{tr("Search")}</Button>
        </form>
        <FilterSelect label={tr("Holds this kind of data")} all={tr("Any kind of data")} value={f.field_type} onChange={(v) => change({ field_type: v })} options={types.map((t) => [t, entityLabel(t)])} />
        <span className="filter-dates">
          <label className="filter-date">{tr("Added from")} <Input type="date" value={f.created_after} max={f.created_before || undefined} onChange={(e) => change({ created_after: e.target.value })} /></label>
          <label className="filter-date">to <Input type="date" value={f.created_before} min={f.created_after || undefined} onChange={(e) => change({ created_before: e.target.value })} /></label>
        </span>
        <label className="filter-check"><Checkbox checked={f.has_reveals} onCheckedChange={(c) => change({ has_reveals: c === true })} />{tr("Revealed in last 30 days")}</label>
        <label className="filter-check"><Checkbox checked={f.flagged} onCheckedChange={(c) => change({ flagged: c === true })} />{tr("Restricted")}</label>
      </div>
      <FilterChips chips={chips} onClear={clearAll} />
      <Loading error={res.error} loading={res.loading && !res.value} />
      {res.value && res.value.subjects.length === 0 && (
        chips.length > 0
          ? <Empty title={tr("No one matches")}><p>{tr("Try removing a filter. A search must be the whole value, not part of it.")}</p><Button variant="outline" className="mt-3" onClick={clearAll}>{tr("Clear all filters")}</Button></Empty>
          : <Empty title={tr("No one here yet")}>{tr("People appear once your systems protect a value with a customer reference. Sandbox vaults come with made-up people to try things on.")}</Empty>
      )}
      {res.value && res.value.subjects.length > 0 && (
        <>
          <div className={`data-table${res.loading ? " busy" : ""}`}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{tr("Customer reference")}</TableHead>
                  <SortHead {...head} label={tr("Values held")} col="field_count" num />
                  <SortHead {...head} label={tr("Added")} col="created_at" />
                  <SortHead {...head} label={tr("Last viewed")} col="last_accessed" />
                  <SortHead {...head} label={tr("Viewed, 30 days")} col="reveals_30d" num />
                  <TableHead>{tr("Status")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {res.value.subjects.map((s) => {
                  const open = () => router.push(`/records/${vault}/${s.id}`);
                  return (
                    <TableRow key={s.id} className="click" tabIndex={0} onClick={open} onKeyDown={(e) => rowKeys(e, open)}>
                      <TableCell><code>{s.ref}</code></TableCell>
                      <TableCell className="num">{s.field_count}</TableCell>
                      <TableCell>{day(s.created_at)}</TableCell>
                      <TableCell>{s.last_accessed ? when(s.last_accessed) : <span className="text-muted-foreground">{tr("Never")}</span>}</TableCell>
                      <TableCell className="num">{n(s.reveals_30d)}</TableCell>
                      <TableCell>{s.restricted && <Badge tone="warn">{tr("Restricted")}</Badge>}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <PageBar offset={offset} size={size} total={res.value.total} noun={res.value.total === 1 ? "person" : "people"} onOffset={setOffset} onSize={(s) => { setSize(s); setOffset(0); }} />
        </>
      )}
    </Page>
  );
}
