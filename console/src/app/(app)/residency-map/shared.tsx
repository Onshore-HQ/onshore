"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { ReactNode, useEffect, useState } from "react";
import { FilterSelect } from "@/components/table-tools";
import { Button } from "@/components/ui/button";
import { useMe } from "@/components/Shell";
import { Empty, ErrorLine, Loading, Page } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { entityLabel } from "@/lib/labels";

export interface Flow {
  home_country?: string | null;
  id: string; vault_id: string; source: { id: string; name: string; kind: string };
  dest: { name: string; system_id: string | null; vendor_id: string | null; vendor: string | null; category: string | null; region: string | null; host: string | null; kind: string | null };
  dest_country: string | null; dest_country_source: string; ip_hint: string | null; region_unconfirmed: boolean; entity_types: string[]; in_scope: boolean; origin: "observed" | "manual"; basis: "observed" | "declared"; onshore_managed: boolean;
  route: { system_id: string; name: string; mode: string; since: string; type: string; id: string } | null;
  status: string; status_since: string; proving: { day: number; of: number } | null; remediation_in_progress: boolean; owner_id: string | null; owner_name: string | null; protected_30d: number; passed_30d: number; open_actions: number; overdue_actions: number;
  exception: { id: string; status: string; expires_at: string } | null; created_at: string; retired_at: string | null;
}
export interface Summary { flow_score: number | null; flow_score_without_exceptions: number | null; volume_score: number | null; series: { day: string; flow: number | null; volume: number | null }[]; counts: Record<string, number>; needs_attention: { unconfirmed_regions: number; overdue_actions: number; exceptions_expiring: number; total: number }; open_actions: number }
export interface Region { code: string; name?: string; country: string | null; hosts?: string[] }
export interface Vendor { id: string; name: string; category: string; hostnames: string[]; regions: Region[]; custom: boolean }

export const STATUS: Record<string, { label: string; hint: string }> = {
  leaking: { label: "Leaking", hint: "Real data reaches an offshore destination unprotected" },
  shadow: { label: "Watch only", hint: "Onshore counts this traffic and has not changed it yet, or is proving a clean week" },
  protected: { label: "Protected", hint: "Protecting, with nothing unprotected in the last 7 days" },
  verified: { label: "Verified", hint: "Protected for 30 days in a row" },
  in_country: { label: "In country", hint: "The destination is hosted in the vault's own country, as declared or confirmed" },
  exception: { label: "Accepted risk", hint: "A named approver accepted this until a set date" },
  unverified: { label: "Unverified", hint: "Declared by you, with no traffic evidence either way" },
  retired: { label: "Retired", hint: "This flow no longer exists" },
};
export const STATUS_ORDER = ["leaking", "shadow", "unverified", "exception", "protected", "verified", "in_country"];

export function StatusChip({ status, flow }: { status: string; flow?: Pick<Flow, "proving" | "remediation_in_progress"> }) {
  const s = STATUS[status] ?? { label: status, hint: "" };
  const extra = flow?.proving ? tr(", day {0} of {1}", { 0: flow.proving.day, 1: flow.proving.of }) : flow?.remediation_in_progress ? ", fix in progress" : "";
  return <span className="flow-chip" title={s.hint} style={{ "--chip": `var(--map-${status})` } as React.CSSProperties}><i aria-hidden />{flow?.proving ? tr("Proving clean") : s.label}{extra}</span>;
}

const NAMES: Record<string, string> = { NG: "Nigeria", US: "United States", GB: "United Kingdom", IE: "Ireland", DE: "Germany", FR: "France", NL: "Netherlands", BE: "Belgium", EU: "European Union", ZA: "South Africa", KE: "Kenya", GH: "Ghana", IN: "India", SG: "Singapore", JP: "Japan", AU: "Australia", CA: "Canada", AE: "United Arab Emirates" };
export const COUNTRY_OPTIONS: [string, string][] = Object.entries(NAMES).sort((a, b) => a[1].localeCompare(b[1]));
export const countryName = (c?: string | null) => (c ? NAMES[c] ?? c : "Not confirmed");
export const flag = (c?: string | null) => (c && /^[A-Z]{2}$/.test(c) ? String.fromCodePoint(...[...c].map((x) => 0x1f1e6 + x.charCodeAt(0) - 65)) : "");
export function Country({ code, source }: { code: string | null; source?: string }) {
  if (!code || source === "unconfirmed") return <span className="badge warn" title={tr("Counted as offshore until someone confirms it")}>{tr("Not confirmed")}</span>;
  return <span title={countryName(code)}><span aria-hidden>{flag(code)} </span>{code}</span>;
}

export const age = (d: string) => {
  const days = Math.floor((Date.now() - new Date(d).getTime()) / 86400000);
  return days < 1 ? "since today" : days === 1 ? "for 1 day" : tr("for {0} days", { 0: days });
};

export function Spark({ values, label }: { values: (number | null)[]; label: string }) {
  const v = values.filter((x): x is number => x !== null);
  if (v.length < 2) return null;
  const w = 90, h = 26;
  const pts = v.map((y, i) => `${(i / (v.length - 1)) * w},${h - 2 - (y / 100) * (h - 4)}`).join(" ");
  return <svg width={w} height={h} role="img" aria-label={tr("{0}: {1} to {2} over 90 days", { 0: label, 1: v[0], 2: v[v.length - 1] })}><polyline points={pts} fill="none" stroke="var(--primary)" strokeWidth="1.6" /></svg>;
}

/** The plain sentence at the top of a flow's page. */
export function flowSentence(f: Flow) {
  const names = f.entity_types.slice(0, 3).map(entityLabel);
  const what = !names.length ? "Data" : names.length === 1 ? names[0] : tr("{0} and {1}", { 0: names.slice(0, -1).join(", "), 1: names[names.length - 1] });
  const more = f.entity_types.length > 3 ? tr(" and {0} more", { 0: f.entity_types.length - 3 }) : "";
  const where = f.region_unconfirmed || !f.dest_country ? "in a location that is not confirmed" : `in ${countryName(f.dest_country)}`;
  return tr("{0}{1} from {2} {3} {4} {5}.", { 0: what, 1: more, 2: f.source.name, 3: f.status === "retired" ? tr("used to reach") : tr("reach"), 4: f.dest.name, 5: where });
}

export function SplitBar({ p, u }: { p: number; u: number }) {
  const t = p + u;
  if (t === 0) return <span className="text-[12px] text-muted-foreground">{tr("No traffic")}</span>;
  return (
    <div title={tr("{0} protected, {1} passed", { 0: p.toLocaleString("en-NG"), 1: u.toLocaleString("en-NG") })}>
      <div className="split-bar" role="img" aria-label={tr("{0} protected, {1} passed", { 0: p, 1: u })}><div className="p" style={{ width: `${(p / t) * 100}%` }} /><div className="u" style={{ width: `${(u / t) * 100}%` }} /></div>
    </div>
  );
}

const KEY = "onshore.map.vault";
/** The screen's frame: picks a vault, and offers to turn the map on when it is off. */
export function MapFrame({ title, sub, actions, children }: { title: string; sub?: ReactNode; actions?: (vault: string) => ReactNode; children: (vault: string) => ReactNode }) {
  const me = useMe();
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [vault, setVault] = useState("");
  useEffect(() => {
    const list = vaults.value?.vaults ?? [];
    if (!list.length) return;
    let saved: string | null = null;
    try { saved = localStorage.getItem(KEY); } catch { /* private window */ }
    setVault((v) => v || (list.some((x) => x.id === saved) ? saved! : list[0]!.id));
  }, [vaults.value]);
  const settings = useLoad<{ enabled: boolean }>(() => (vault ? control(`/v1/map/settings?vault_id=${vault}`) : Promise.resolve({ enabled: false })), [vault]);
  const [error, setError] = useState<string | null>(null);
  const pick = (v: string) => { if (!v) return; setVault(v); try { localStorage.setItem(KEY, v); } catch { /* private window */ } };
  const list = vaults.value?.vaults ?? [];
  const on = settings.value?.enabled;
  return (
    <Page title={title} sub={sub} actions={<>
      {list.length > 1 && <FilterSelect label={tr("Vault")} all="" value={vault} onChange={pick} options={list.map((v) => [v.id, v.name])} />}
      {on && vault && actions?.(vault)}
    </>}>
      <Loading error={vaults.error ?? settings.error} loading={vaults.loading || (settings.loading && !settings.value)} />
      {vaults.value && list.length === 0 && <Empty title={tr("No vault yet")} action={<Link className="btn primary" href="/onboarding">{tr("Open the setup guide")}</Link>}>{tr("Create a vault first, and your connections will appear here.")}</Empty>}
      {vault && settings.value && !on && (
        <Empty title={tr("The residency map is off for this vault")}>
          {tr("It lists every system and vendor that holds or receives payment and identity data, and works out each flow’s status from what Onshore actually sees.")}
          {me?.roles.includes("admin") ? <div className="mt-3"><Button onClick={async () => { setError(null); try { await control("/v1/map/settings", { method: "PATCH", body: { vault_id: vault, enabled: true } }); settings.reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Turn on the residency map")}</Button><ErrorLine error={error} /></div> : <p className="mt-2">{tr("Ask an admin to turn it on.")}</p>}
        </Empty>
      )}
      {vault && on && children(vault)}
    </Page>
  );
}

export const MAP_EDIT = ["admin", "compliance", "map_editor"];
export const MAP_APPROVE = ["admin", "exception_approver"];
export const PLANS: Record<string, string> = { move_in_country: "Move it into the vault's country", route_via_proxy: "Put it behind the Onshore proxy", tokenize_at_source: "Tokenize at the source", delete_data: "Delete the data", other: "Something else" };
export const CAUSES: Record<string, string> = { detections_passed: "Unprotected data reached the destination", declared_offshore: "Declared as offshore, holding in-scope data", route_shadow: "The route is in Watch only", route_enforcing: "The route was switched to Protecting", no_leak_7d: "Seven days with nothing unprotected", verified_30d: "Thirty days protected", declared_in_country: "Declared or confirmed as in the vault's country", exception_approved: "An exception was approved", exception_expired: "An exception expired", exception_revoked: "An exception was revoked", remediation_completed: "A fix was completed", route_deleted: "The route was deleted", manual: "Changed by a person" };
