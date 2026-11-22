"use client";
import { tr } from "@/lib/i18n";
import { Database, Eye, Gauge, LockKeyhole, ShieldX } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { DailyBars, Donut } from "@/components/UsageCharts";
import { Empty, Loading, Page, Stat } from "@/components/ui";
import { control, n, useLoad } from "@/lib/api";
import { entityLabel, serviceLabel } from "@/lib/labels";

interface Usage {
  from: string; to: string;
  operations: { protected: number; revealed: number; masked: number; refused: number; admin: number; other: number };
  daily: { day: string; protected: number; revealed: number; refused: number }[];
  services: { module: string; n: number; p50: number | null; p95: number | null }[];
  caught: { module: string; entity_type: string; n: number }[];
  latency: { p50: number | null; p95: number | null };
  held: { records: number; subjects: number };
}

const PRESETS = [{ days: 1, label: "24 hours" }, { days: 7, label: "7 days" }, { days: 30, label: "30 days" }, { days: 90, label: "90 days" }];
const iso = (d: Date) => d.toISOString().slice(0, 10);
const SOURCE: Record<string, string> = { logs: "Logs", ai: "AI tools", proxy: "Web APIs", support: "Support tools", check: "Checked jobs", api: "Your apps", files: "Files" };

export default function UsagePage() {
  const [range, setRange] = useState(() => { const to = new Date(); return { from: iso(new Date(to.getTime() - 29 * 86400_000)), to: iso(to), preset: 30 }; });
  const { value: u, error, loading } = useLoad<Usage>(() => {
    const to = new Date(`${range.to}T23:59:59+01:00`), from = new Date(`${range.from}T00:00:00+01:00`);
    return control(`/v1/usage?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`);
  }, [range.from, range.to]);
  const days = useMemo(() => {
    if (!u) return [];
    const out: { day: string; values: Record<string, number> }[] = [];
    const start = new Date(`${range.from}T00:00:00Z`), end = new Date(`${range.to}T00:00:00Z`);
    for (let d = start; d <= end; d = new Date(d.getTime() + 86400_000)) out.push({ day: iso(d), values: {} });
    for (const r of u.daily) {
      const slot = out.find((x) => x.day === new Date(r.day).toISOString().slice(0, 10));
      if (slot) slot.values = { protected: r.protected, revealed: r.revealed, refused: r.refused };
    }
    return out;
  }, [u, range.from, range.to]);
  const caughtByType = useMemo(() => {
    const m = new Map<string, number>();
    // Different sources name the same thing differently ("phone", "phone_ng"), so they are added up by their plain name.
    for (const c of u?.caught ?? []) { const k = entityLabel(c.entity_type); m.set(k, (m.get(k) ?? 0) + c.n); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [u]);
  const caughtBySource = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of u?.caught ?? []) m.set(c.module, (m.get(c.module) ?? 0) + c.n);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [u]);
  const caughtTotal = caughtByType.reduce((s, [, v]) => s + v, 0);
  const o = u?.operations;
  const ops = o ? o.protected + o.revealed + o.masked + o.refused : 0;

  return (
    <Page title={tr("Usage")} sub={tr("What Onshore did for you over a period: values protected, values shown, requests refused and how fast it answered.")}>
      <div className="card mb-4 flex-row flex-wrap items-end gap-3" style={{ display: "flex" }}>
        <div className="tabs m-0 w-fit">
          {PRESETS.map((p) => <button key={p.days} type="button" className={range.preset === p.days ? "on" : ""} onClick={() => { const to = new Date(); setRange({ from: iso(new Date(to.getTime() - (p.days - 1) * 86400_000)), to: iso(to), preset: p.days }); }}>{p.label}</button>)}
        </div>
        <label className="field m-0"><span>{tr("From")}</span><input type="date" value={range.from} max={range.to} onChange={(e) => setRange({ ...range, from: e.target.value, preset: 0 })} /></label>
        <label className="field m-0"><span>{tr("To")}</span><input type="date" value={range.to} min={range.from} max={iso(new Date())} onChange={(e) => setRange({ ...range, to: e.target.value, preset: 0 })} /></label>
        <span className="ml-auto self-center text-[13px] text-muted-foreground">{tr("Times are in your organisation's time zone.")}</span>
      </div>
      <Loading error={error} loading={loading && !u} />
      {u && o && (
        <div className="stack">
          <div className="grid-4">
            <Stat icon={LockKeyhole} tone="teal" label={tr("Values protected")} value={n(o.protected)} hint={tr("Swapped for a token before being stored or sent on")} />
            <Stat icon={Eye} tone="amber" label={tr("Values shown")} value={n(o.revealed + o.masked)} hint={tr("{0} in full · {1} masked", { 0: n(o.revealed), 1: n(o.masked) })} />
            <Stat icon={ShieldX} tone="rose" label={tr("Requests refused")} value={n(o.refused)} hint={tr("Someone asked for a value an access rule doesn't allow")} />
            <Stat icon={Gauge} label={tr("Response time")} value={u.latency.p95 === null ? "No traffic" : `${u.latency.p95} ms`} hint={u.latency.p50 === null ? tr("95% of requests were this fast") : tr("95% this fast · typical {0} ms", { 0: u.latency.p50 })} />
          </div>
          {ops === 0 && caughtTotal === 0 ? (
            <Empty title={tr("No activity in this period")} action={<Link className="btn primary" href="/connect">{tr("Connect something")}</Link>}>{tr("Once a connection or your app sends data through Onshore, its work shows here.")}</Empty>
          ) : (
            <>
              <div className="usage-grid">
                <div className="card">
                  <div><h2>{tr("Operations")}</h2><p className="text-[13px] text-muted-foreground">{tr("Every request to protect or show a value, with its result.")}</p></div>
                  <Donut caption="operations" total={ops} slices={[
                    { key: "protected", label: "Protected", value: o.protected, color: "var(--series-2)", hint: tr("Value replaced with a token") },
                    { key: "revealed", label: tr("Shown in full"), value: o.revealed, color: "var(--series-4)", hint: tr("Allowed by an access rule, with a reason") },
                    { key: "masked", label: tr("Shown masked"), value: o.masked, color: "var(--series-1)", hint: tr("Only part of the value was shown") },
                    { key: "refused", label: "Refused", value: o.refused, color: "var(--bad)", hint: tr("No access rule allowed it") },
                  ]} />
                </div>
                <div className="card">
                  <div><h2>{tr("Each day")}</h2><p className="text-[13px] text-muted-foreground">{tr("Hover a day for its numbers.")}</p></div>
                  <DailyBars days={days} series={[{ key: "protected", label: "Protected", color: "var(--series-2)" }, { key: "revealed", label: "Shown", color: "var(--series-4)" }, { key: "refused", label: "Refused", color: "var(--bad)" }]} />
                </div>
              </div>
              <div className="usage-grid">
                <div className="card">
                  <div><h2>{tr("Sensitive values caught")}</h2><p className="text-[13px] text-muted-foreground">{tr("Found on the way out, including on watch-only connections, which count but change nothing.")}</p></div>
                  {caughtTotal === 0 ? <p className="text-muted-foreground">{tr("Nothing caught in this period.")}</p> : (
                    <div className="grid gap-1.5">
                      {caughtByType.slice(0, 8).map(([k, v]) => <Bar key={k} label={k} value={v} max={caughtByType[0]![1]} />)}
                      <div className="mt-1 text-[13px] text-muted-foreground">{n(caughtTotal)} {tr("in all")}</div>
                    </div>
                  )}
                </div>
                <div className="card">
                  <div><h2>{tr("Where they were caught")}</h2><p className="text-[13px] text-muted-foreground">{tr("By kind of connection.")}</p></div>
                  {caughtTotal === 0 ? <p className="text-muted-foreground">{tr("Nothing caught in this period.")}</p> : (
                    <div className="grid gap-1.5">
                      {caughtBySource.map(([k, v]) => <Bar key={k} label={SOURCE[k] ?? k} value={v} max={caughtBySource[0]![1]} />)}
                      <Link className="mt-1 text-[13px]" href="/pipelines">{tr("See connections")}</Link>
                    </div>
                  )}
                </div>
              </div>
              <div className="card">
                <div className="spread"><div><h2>{tr("By service")}</h2><p className="text-[13px] text-muted-foreground">{tr("How many requests each part of Onshore handled, and how fast.")}</p></div><Link className="btn" href="/logs">{tr("Open service logs")}</Link></div>
                <div className="tablewrap">
                  <table>
                    <thead><tr><th>{tr("Service")}</th><th className="num">{tr("Requests")}</th><th className="num">{tr("Typical")}</th><th className="num">{tr("95% under")}</th></tr></thead>
                    <tbody>{u.services.map((s) => (
                      <tr key={s.module}><td><Link href={`/logs?service=${s.module}`}>{serviceLabel(s.module)}</Link></td><td className="num">{n(s.n)}</td><td className="num">{s.p50 === null ? "—" : `${s.p50} ms`}</td><td className="num">{s.p95 === null ? "—" : `${s.p95} ms`}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
            </>
          )}
          <div className="card flex-row items-center gap-3" style={{ display: "flex" }}>
            <span className="tile blue" aria-hidden><Database className="size-[18px]" /></span>
            <div className="min-w-0 flex-1"><div className="font-medium">{n(u.held.records)} {tr("values held for")} {n(u.held.subjects)} {u.held.subjects === 1 ? tr("person") : tr("people")}</div><div className="text-[13px] text-muted-foreground">{tr("Right now, across all vaults. Held values don't depend on the period above.")}</div></div>
            <Link className="btn" href="/records">{tr("Customer records")}</Link>
          </div>
        </div>
      )}
    </Page>
  );
}

function Bar({ label, value, max }: { label: string; value: number; max: number }) {
  return (
    <div className="grid grid-cols-[minmax(0,11rem)_1fr_auto] items-center gap-3">
      <span className="truncate text-[13.5px]">{label}</span>
      <span className="h-2 overflow-hidden rounded-full bg-muted"><span className="block h-full rounded-full bg-primary" style={{ width: `${Math.max((value / max) * 100, 1.5)}%` }} /></span>
      <span className="text-[13px] text-muted-foreground tabular-nums">{n(value)}</span>
    </div>
  );
}
