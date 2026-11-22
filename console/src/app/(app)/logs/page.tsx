"use client";
import { tr } from "@/lib/i18n";
import { Download, RefreshCw, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Copy, DecisionBadge, Empty, Loading, Modal, Page } from "@/components/ui";
import { Button } from "@/components/ui/button";
import { control, n, useLoad, when } from "@/lib/api";
import { actionLabel, serviceLabel } from "@/lib/labels";

interface Event { seq: string; occurred_at: string; module: string; action: string; decision: string | null; latency_ms: number | null; request_id: string | null; principal_id: string | null; principal_kind: string | null; source_ip: string | null; network: string | null; vault_id: string | null; field_id: string | null; purpose: string | null; policy_id: string | null; detail: string | null }

const iso = (d: Date) => d.toISOString().slice(0, 10);
const RESULTS = [{ v: "", l: "Any result" }, { v: "plaintext", l: "Real value shown" }, { v: "masked", l: "Masked" }, { v: "denied", l: "Refused" }];

export default function ServiceLogs() {
  const [f, setF] = useState(() => ({ service: "", decision: "", request: "", from: iso(new Date(Date.now() - 6 * 86400_000)), to: iso(new Date()) }));
  const [typed, setTyped] = useState("");
  const [pages, setPages] = useState<string[]>([]);
  const [open, setOpen] = useState<Event | null>(null);
  // Usage links here with ?service=…, so a slow service is one click from its requests.
  useEffect(() => { const s = new URLSearchParams(window.location.search).get("service"); if (s) setF((x) => ({ ...x, service: s })); }, []);
  const qs = useMemo(() => {
    const p = new URLSearchParams();
    if (f.service) p.set("module", f.service);
    if (f.decision) p.set("decision", f.decision);
    if (f.request) p.set("request", f.request);
    p.set("from", new Date(`${f.from}T00:00:00+01:00`).toISOString());
    p.set("to", new Date(`${f.to}T23:59:59+01:00`).toISOString());
    return p;
  }, [f]);
  const before = pages[pages.length - 1];
  const list = useLoad<{ events: Event[] }>(() => control(`/v1/audit-events?${qs}&limit=50${before ? `&before_seq=${before}` : ""}`), [qs.toString(), before]);
  const summary = useLoad<{ total: number; modules: string[] }>(() => control(`/v1/audit-events/summary?${qs}`), [qs.toString()]);
  const set = (patch: Partial<typeof f>) => { setPages([]); setF({ ...f, ...patch }); };
  const events = list.value?.events ?? [];

  return (
    <Page title={tr("Service logs")} sub={tr("Every request each part of Onshore handled, with its result and how long it took. Use a request ID from an error message to find the exact call.")} actions={<Button variant="outline" asChild><a href={`/api/proxy/control/v1/audit-events/export?${qs}`}><Download />{tr("Download CSV")}</a></Button>}>
      <div className="card mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="field m-0"><span>{tr("Service")}</span>
            <select value={f.service} onChange={(e) => set({ service: e.target.value })}>
              <option value="">{tr("All services")}</option>
              {summary.value?.modules.map((m) => <option key={m} value={m}>{serviceLabel(m)}</option>)}
            </select>
          </label>
          <label className="field m-0"><span>{tr("Result")}</span><select value={f.decision} onChange={(e) => set({ decision: e.target.value })}>{RESULTS.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}</select></label>
          <label className="field m-0"><span>{tr("From")}</span><input type="date" value={f.from} max={f.to} onChange={(e) => set({ from: e.target.value })} /></label>
          <label className="field m-0"><span>{tr("To")}</span><input type="date" value={f.to} min={f.from} max={iso(new Date())} onChange={(e) => set({ to: e.target.value })} /></label>
          <form className="field m-0 min-w-[16rem] flex-1" onSubmit={(e) => { e.preventDefault(); set({ request: typed.trim() }); }}>
            <span>{tr("Request ID")}</span>
            <div className="row gap-1.5">
              <input className="flex-1" placeholder={tr("req_…")} value={typed} onChange={(e) => setTyped(e.target.value)} />
              <button type="submit" aria-label={tr("Find request")}><Search className="size-4" /></button>
              {f.request && <button type="button" aria-label={tr("Clear request ID")} onClick={() => { setTyped(""); set({ request: "" }); }}><X className="size-4" /></button>}
            </div>
          </form>
          <button type="button" onClick={() => { list.reload(); summary.reload(); }} aria-label={tr("Refresh")}><RefreshCw className="size-4" /></button>
        </div>
        {summary.value && <div className="text-[13px] text-muted-foreground">{n(summary.value.total)} {summary.value.total === 1 ? tr("request matches") : tr("requests match")}{tr(". Newest first.")}</div>}
      </div>
      <Loading error={list.error} loading={list.loading && !list.value} />
      {list.value && events.length === 0 && <Empty title={tr("No requests match")}>{tr("Try a wider date range, or another service.")}</Empty>}
      {events.length > 0 && (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Time")}</th><th>{tr("Service")}</th><th>{tr("What happened")}</th><th>{tr("Result")}</th><th className="num">{tr("Took")}</th><th>{tr("Request ID")}</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.seq} tabIndex={0} className="cursor-pointer" onClick={() => setOpen(e)} onKeyDown={(k) => k.key === "Enter" && setOpen(e)}>
                  <td className="whitespace-nowrap">{when(e.occurred_at)}</td>
                  <td>{serviceLabel(e.module)}</td>
                  <td>{actionLabel(e.action, e.decision)}</td>
                  <td>{e.decision ? <DecisionBadge value={e.decision} /> : <span className="text-muted-foreground">{tr("Done")}</span>}</td>
                  <td className="num">{e.latency_ms === null ? "—" : `${e.latency_ms} ms`}</td>
                  <td><code className="text-xs">{e.request_id ?? "—"}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="row mt-3 justify-end">
        <button disabled={pages.length === 0} onClick={() => setPages(pages.slice(0, -1))}>{tr("Newer")}</button>
        <button disabled={events.length < 50} onClick={() => setPages([...pages, events[events.length - 1]!.seq])}>{tr("Older")}</button>
      </div>
      {open && (
        <Modal title={actionLabel(open.action, open.decision)} onClose={() => setOpen(null)}>
          <dl className="kv">
            <dt>{tr("When")}</dt><dd>{when(open.occurred_at)}</dd>
            <dt>{tr("Service")}</dt><dd>{serviceLabel(open.module)} <code className="text-xs text-muted-foreground">{open.module}</code></dd>
            <dt>{tr("Action")}</dt><dd><code>{open.action}</code></dd>
            <dt>{tr("Result")}</dt><dd>{open.decision ? <DecisionBadge value={open.decision} /> : tr("Done")}</dd>
            <dt>{tr("Took")}</dt><dd>{open.latency_ms === null ? tr("Not recorded") : `${open.latency_ms} ms`}</dd>
            <dt>{tr("Request ID")}</dt><dd className="row">{open.request_id ? <><code>{open.request_id}</code><Copy text={open.request_id} /></> : "—"}</dd>
            <dt>{tr("By")}</dt><dd>{open.principal_kind ?? "—"} <code className="text-xs">{open.principal_id ?? ""}</code></dd>
            {open.network && <><dt>{tr("Network")}</dt><dd>{open.network}</dd></>}
            {open.source_ip && <><dt>{tr("From address")}</dt><dd><code>{open.source_ip}</code></dd></>}
            {open.vault_id && <><dt>{tr("Vault")}</dt><dd><code>{open.vault_id}</code></dd></>}
            {open.field_id && <><dt>{tr("Field")}</dt><dd><code>{open.field_id}</code></dd></>}
            {open.purpose && <><dt>{tr("Reason given")}</dt><dd>{open.purpose}</dd></>}
            {open.detail && <><dt>{tr("Detail")}</dt><dd><pre className="pre text-xs">{prettify(open.detail)}</pre></dd></>}
          </dl>
          <p className="text-[13px] text-muted-foreground">{tr("Logs never hold a sensitive value. The same entry is in the audit log, where it can't be changed without it showing.")}</p>
        </Modal>
      )}
    </Page>
  );
}

function prettify(s: string) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } }
