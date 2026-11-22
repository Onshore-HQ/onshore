"use client";
import { tr } from "@/lib/i18n";
import { ArrowRight, Check, ChevronRight, Eye, HeartPulse, LockKeyhole, Plug, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { CaughtChart } from "@/components/CaughtChart";
import { Badge, Loading, Page, Stat } from "@/components/ui";
import { Progress } from "@/components/ui/progress";
import { control, n, useLoad } from "@/lib/api";

const HIDE_KEY = "onshore.home.checklist.hidden";
const plural = (c: number, one: string, many: string) => `${n(c)} ${c === 1 ? one : many}`;

/** The steps from nothing to a first report. Each one is worked out from real data, never ticked by hand. */
function steps(s: any, values: number) {
  return [
    { done: s.vaults > 0, title: tr("Create a vault"), why: tr("This is where real values live, on your servers in your vault's country."), href: "/onboarding", cta: tr("Open the setup guide") },
    { done: s.connections > 0, title: tr("Connect your first source"), why: tr("Send logs, AI prompts or vendor calls through Onshore. It starts by only watching, so nothing changes."), href: "/connect", cta: tr("Connect something") },
    { done: s.detected, title: tr("See what is leaving"), why: tr("Let traffic flow for a while. Onshore counts every sensitive value it finds on the way out."), href: "/pipelines", cta: tr("Check your connections") },
    { done: s.protecting > 0, title: tr("Turn protection on"), why: tr("Once you trust what you see, sensitive values get replaced before they leave the country."), href: "/pipelines", cta: tr("Go to connections") },
    { done: values > 0, title: tr("Load your existing customers"), why: tr("Move the data you already hold into the vault, and get tokens to put back in your own database."), href: "/records/import", cta: tr("Import data") },
    { done: s.flows > 0 && s.unverified === 0, title: tr("Complete your residency map"), why: tr("Add systems Onshore can't see, such as a warehouse abroad, so the map is the whole picture."), href: "/residency-map", cta: tr("Open the map") },
    { done: s.own_rules > 0, title: tr("Decide who can see real values"), why: tr("Nobody can until a published rule says so. Publishing needs a second person."), href: "/policies", cta: tr("Write an access rule") },
    { done: s.report_generated, title: tr("Download your first report"), why: tr("Signed evidence of where your data lives, for your compliance officer."), href: "/reports", cta: tr("Go to reports") },
  ];
}

function Checklist({ setup, values }: { setup: any; values: number }) {
  const [hidden, setHidden] = useState(false);
  useEffect(() => { try { setHidden(localStorage.getItem(HIDE_KEY) === "1"); } catch { /* private window */ } }, []);
  const list = steps(setup, values);
  const done = list.filter((x) => x.done).length;
  if (done === list.length || hidden) return null;
  const next = list.findIndex((x) => !x.done);
  return (
    <div className="card">
      <div className="spread">
        <h2>{tr("Get set up")}</h2>
        <button className="link small" onClick={() => { setHidden(true); try { localStorage.setItem(HIDE_KEY, "1"); } catch { /* private window */ } }}>{tr("Hide this")}</button>
      </div>
      <div className="row"><Progress value={(done / list.length) * 100} className="h-2 flex-1" aria-label={tr("Setup progress")} /><span className="small muted">{done} of {list.length} done</span></div>
      <ol className="grid gap-1">
        {list.map((x, i) => (
          <li key={x.title} data-slot="setup-step" className={`flex items-start gap-3 rounded-lg px-3 py-2.5 ${i === next ? "border border-primary bg-accent/40" : ""}`}>
            <span aria-hidden className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${x.done ? "bg-good-soft text-good" : i === next ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}>{x.done ? <Check className="size-3.5" /> : i + 1}</span>
            <span className="min-w-0 flex-1">
              <span className={`block font-medium ${x.done ? "text-muted-foreground" : ""}`}>{x.title}{x.done && <span className="sr-only"> {tr("(done)")}</span>}</span>
              {i === next && <span className="block text-[13px] text-muted-foreground">{x.why}</span>}
            </span>
            {i === next && <Link className="btn primary shrink-0" href={x.href}>{x.cta}<ArrowRight className="size-4" /></Link>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function Home() {
  const { value: o, error, loading } = useLoad(() => control("/v1/overview"));
  if (!o) return <Page title={tr("Home")}><Loading error={error} loading={loading} /></Page>;
  const s = o.setup;
  const rev = (d: string) => Number(o.reveals.find((r: { decision: string }) => r.decision === d)?.n ?? 0);
  // Most urgent first: data leaving now, then anything blocking protection, then things to review.
  const attention = [
    ...(s.leaking > 0 ? [{ icon: ShieldAlert, tone: "rose", href: "/residency-map", text: tr("{0} leaking", { 0: plural(s.leaking, tr("data flow is"), tr("data flows are")) }), why: tr("Sensitive values are leaving the country unprotected on these paths.") }] : []),
    ...(o.health.key_service !== "ok" ? [{ icon: TriangleAlert, tone: "rose", href: "/keys", text: tr("The key service is unavailable"), why: tr("Values cannot be protected or revealed until it is back.") }] : []),
    ...(o.open_alerts > 0 ? [{ icon: ShieldAlert, tone: "rose", href: "/people", text: tr("{0} to review", { 0: plural(o.open_alerts, tr("unusual access alert"), tr("unusual access alerts")) }), why: tr("Someone viewed more real values than is normal for them.") }] : []),
    ...(s.map_alerts > 0 ? [{ icon: TriangleAlert, tone: "amber", href: "/residency-map", text: tr("{0} to review", { 0: plural(s.map_alerts, tr("map alert"), tr("map alerts")) }), why: tr("A flow changed status, or something on the map needs a decision.") }] : []),
    ...(s.watching > 0 ? [{ icon: TriangleAlert, tone: "amber", href: "/pipelines", text: tr("{0} only watching", { 0: plural(s.watching, tr("connection is"), tr("connections are")) }), why: tr("Sensitive values are counted but still leave. Turn on protection when you are ready.") }] : []),
  ];
  const totalAlerts = o.open_alerts + s.map_alerts;
  const live = s.connections > 0 || o.protected.records > 0;
  return (
    <Page title={tr("Home")} sub={tr("What to do next, and what needs your attention.")}>
      <div className="stack">
        {attention.length > 0 ? (
          <div className="card">
            <h2>{tr("Needs your attention")}</h2>
            <div className="grid gap-2">
              {attention.map((a) => (
                <Link key={a.text} href={a.href} data-slot="attention" className="group flex items-center gap-3 rounded-lg border px-3 py-2.5 transition-colors hover:border-primary hover:bg-accent/50">
                  <span className={`tile ${a.tone}`} aria-hidden><a.icon className="size-[18px]" /></span>
                  <span className="min-w-0 flex-1"><span className="block font-medium">{a.text}</span><span className="block text-[13px] text-muted-foreground">{a.why}</span></span>
                  <ChevronRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                </Link>
              ))}
            </div>
          </div>
        ) : live && (
          <div className="note good row"><ShieldCheck className="size-4" /><span><b>{tr("Nothing needs you right now.")}</b> {tr("No leaks, and no alerts to review.")}</span></div>
        )}
        <Checklist setup={s} values={o.protected.records} />
        {live && (
          <div className="grid-4">
            <Stat icon={Plug} label={tr("Connections")} value={n(s.connections)} hint={s.flows > s.connections ? tr("Going through Onshore. Your map has {0} flows; the others are checked by their jobs or not connected yet.", { 0: n(s.flows) }) : tr("Logs, AI, web APIs and support tools going through Onshore")}>
              {s.watching > 0 && <Badge tone="warn">{s.watching} {tr("watching only")}</Badge>}<Badge tone="good">{s.protecting} {tr("protecting")}</Badge>
            </Stat>
            <Stat icon={LockKeyhole} tone="teal" label={tr("Values protected")} value={n(o.protected.records)} hint={tr("Held in the vault, for {0} {1}", { 0: n(o.protected.subjects), 1: o.protected.subjects === 1 ? tr("person") : tr("people") })} />
            <Stat icon={Eye} tone="amber" label={tr("Real values viewed, last 7 days")} value={n(rev("plaintext"))} hint={tr("{0} shown masked · {1} refused", { 0: n(rev("masked")), 1: n(rev("denied")) })}>
              {totalAlerts > 0 ? <Link href="/monitoring"><Badge tone="bad">{plural(totalAlerts, tr("open alert"), tr("open alerts"))}</Badge></Link> : <Badge tone="good">{tr("No open alerts")}</Badge>}
            </Stat>
            <Stat icon={HeartPulse} tone={o.health.key_service === "ok" ? "teal" : "rose"} label={tr("Response time")} value={o.health.api_p95_ms === null ? tr("No traffic yet") : `${o.health.api_p95_ms} ms`} hint={tr("95% of requests were this fast, last hour")}>
              <Badge tone={o.health.key_service === "ok" ? "good" : "bad"}>{tr("Keys")} {o.health.key_service === "ok" ? tr("healthy") : tr("unavailable")}</Badge>
            </Stat>
          </div>
        )}
        {o.caught.length > 0 && (
          <div className="card">
            <div>
              <h2>{tr("Caught before leaving the country")}</h2>
              <p className="mt-0.5 text-[13px] text-muted-foreground">{tr("Sensitive values found each day over the last 14 days. This includes values from watch-only connections, which were counted but not changed.")}</p>
            </div>
            <CaughtChart rows={o.caught} customNames={o.custom_names} />
          </div>
        )}
        {o.top_revealers.length > 0 && (
          <div className="card">
            <h2>{tr("Who viewed real values most, last 7 days")}</h2>
            <div className="grid gap-1">
              {o.top_revealers.map((t: { principal_id: string; display_name: string; n: number }) => {
                const max = Math.max(...o.top_revealers.map((x: { n: number }) => x.n), 1);
                return (
                  <div key={t.principal_id} className="grid grid-cols-[minmax(0,14rem)_1fr_auto] items-center gap-3 py-1">
                    <Link className="truncate" href={`/people/${t.principal_id}`}>{t.display_name ?? t.principal_id}</Link>
                    <span className="h-2 overflow-hidden rounded-full bg-muted"><span className="block h-full rounded-full bg-primary" style={{ width: `${(t.n / max) * 100}%` }} /></span>
                    <span className="text-muted-foreground tabular-nums">{n(t.n)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </Page>
  );
}
