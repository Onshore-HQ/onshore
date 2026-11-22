"use client";
import { tr } from "@/lib/i18n";
import { Bot, ClipboardCheck, Globe, Headset, LucideIcon, MapIcon, Plus, ScrollText, ShieldCheck, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { ConnectCatalog } from "@/components/ConnectCatalog";
import { Badge, Empty, Loading } from "@/components/ui";
import { compact } from "@/components/UsageCharts";
import { control, n, useLoad, when } from "@/lib/api";

interface Conn { id: string; kind: string; name: string; detail: string; state: string; href: string; caught_30d: number; sparkline: { day: string; count: number }[]; last_seen: string | null }
interface Summary { connections: Conn[]; map: { flows: number; leaking: number; not_protected: number } }

const KIND: Record<string, { icon: LucideIcon; label: string }> = {
  logs: { icon: ScrollText, label: "Logs" }, ai: { icon: Bot, label: "AI tool" }, proxy: { icon: Globe, label: "Web API" }, support: { icon: Headset, label: "Support tool" },
  page: { icon: ShieldCheck, label: "Protected page" }, check: { icon: ClipboardCheck, label: "Checked job" },
};
const STATE: Record<string, { tone: "good" | "warn" | "bad" | "info" | ""; label: string }> = {
  protecting: { tone: "good", label: "Protecting" }, watching: { tone: "warn", label: "Watch only" }, checked: { tone: "good", label: "Checked each batch" }, waiting: { tone: "", label: "Waiting for first report" }, proving: { tone: "warn", label: "Proving a clean week" }, leaking: { tone: "bad", label: "Leaking" },
};

/** Everything switched on, at a glance. Detail and settings stay one click away, under each kind's tab. */
export function ConnectionsOverview({ onOpen }: { onOpen: (tab: string) => void }) {
  const { value, error, loading } = useLoad<Summary>(() => control("/v1/connections/summary"));
  const [adding, setAdding] = useState(false);
  if (!value) return <Loading error={error} loading={loading} />;
  const c = value.connections;
  const protecting = c.filter((x) => x.state === "protecting" || x.state === "checked").length;
  const watching = c.filter((x) => x.state === "watching" || x.state === "proving").length;
  const caught = c.reduce((s, x) => s + x.caught_30d, 0);
  return (
    <div className="stack">
      {c.length === 0 ? (
        <Empty title={tr("Nothing connected yet")} action={<button className="primary" onClick={() => setAdding(true)}><Plus className="size-4" />{tr("Add a connection")}</button>}>{tr("Connect your logs, an AI tool or a vendor's API. Each one starts by only watching, so nothing changes until you say so.")}</Empty>
      ) : (
        <>
          <div className="conn-summary">
            <div><b>{c.length}</b><span>{c.length === 1 ? tr("connection") : tr("connections")}</span></div>
            <div><b className="text-good">{protecting}</b><span>protecting</span></div>
            <div><b className={watching ? "text-warn" : ""}>{watching}</b><span>{tr("watch only")}</span></div>
            <div><b>{compact(caught)}</b><span>{tr("values caught, 30 days")}</span></div>
            <Link href="/residency-map" className="ml-auto"><MapIcon className="size-4" />{n(value.map.flows)} {tr("flows on the map")}</Link>
          </div>
          {value.map.not_protected > 0 && (
            <Link href="/residency-map" className="note warn row">
              <TriangleAlert className="size-4 shrink-0" />
              <span><b>{value.map.not_protected} {value.map.not_protected === 1 ? tr("flow on your map doesn't") : tr("flows on your map don't")} {tr("pass through Onshore.")}</b> {value.map.leaking > 0 ? tr("{0} {1} leaking. ", { 0: value.map.leaking, 1: value.map.leaking === 1 ? tr("is") : tr("are") }) : ""}{tr("Connect them, or record why they are safe.")}</span>
            </Link>
          )}
          <div className="conn-grid">
            {c.map((x) => {
              const k = KIND[x.kind] ?? KIND.logs!;
              const s = STATE[x.state] ?? { tone: "", label: x.state };
              const tab = x.href.match(/tab=(\w+)/)?.[1];
              const body = (
                <>
                  <div className="spread items-start">
                    <span className="tile blue" aria-hidden><k.icon className="size-[18px]" /></span>
                    <Badge tone={s.tone}>{s.label}</Badge>
                  </div>
                  <div className="min-w-0">
                    <div className="truncate font-medium">{x.name}</div>
                    <div className="truncate text-[13px] text-muted-foreground" title={x.detail}>{k.label} · {x.detail}</div>
                  </div>
                  <Spark points={x.sparkline} />
                  <div className="spread text-[12.5px] text-muted-foreground">
                    <span><b className="text-foreground tabular-nums">{n(x.caught_30d)}</b> {tr("caught in 30 days")}</span>
                    <span>{x.last_seen ? tr("Last {0}", { 0: when(x.last_seen) }) : tr("No traffic yet")}</span>
                  </div>
                </>
              );
              return tab
                ? <button key={x.id} type="button" className="conn-card" onClick={() => onOpen(tab)}>{body}</button>
                : <Link key={x.id} href={x.href} className="conn-card">{body}</Link>;
            })}
            <button type="button" className="conn-card add" onClick={() => setAdding(true)}>
              <span className="flex size-10 items-center justify-center rounded-full bg-accent text-accent-foreground"><Plus className="size-5" /></span>
              <span className="font-medium">{tr("Add a connection")}</span>
              <span className="text-[13px] text-muted-foreground">{tr("Logs, AI, error tools, vendor APIs, support tools, pages or a database copy")}</span>
            </button>
          </div>
        </>
      )}
      {adding && <ConnectCatalog onClose={() => setAdding(false)} />}
    </div>
  );
}

function Spark({ points }: { points: { day: string; count: number }[] }) {
  const w = 240, h = 44;
  const max = Math.max(1, ...points.map((p) => p.count));
  const xy = points.map((p, i) => [(i / Math.max(points.length - 1, 1)) * (w - 4) + 2, h - 4 - (p.count / max) * (h - 10)] as const);
  const line = xy.map(([x, y]) => `${x},${y}`).join(" ");
  const total = points.reduce((s, p) => s + p.count, 0);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="block h-11 w-full" preserveAspectRatio="none" role="img" aria-label={tr("{0} values caught in 14 days", { 0: total })}>
      <polygon points={`2,${h - 2} ${line} ${w - 2},${h - 2}`} fill="var(--series-1)" opacity={0.1} />
      <polyline points={line} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
