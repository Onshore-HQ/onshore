// The residency map's rules, with no database, so that they can be tested alone.
import { COUNTRIES as CATALOG_COUNTRIES, countryName as catalogName, isCountry } from "../../catalog.js";

export type FlowStatus = "unverified" | "leaking" | "shadow" | "protected" | "verified" | "in_country" | "exception" | "retired";
export const FLOW_STATUSES: FlowStatus[] = ["leaking", "shadow", "protected", "verified", "in_country", "exception", "unverified", "retired"];
export const DAY = 86_400_000;
export const CLEAN_DAYS = 7;
export const VERIFIED_DAYS = 30;

export interface FlowFacts {
  retired: boolean;
  exceptionActive: boolean;
  destCountry: string | null;
  /** The country the vault keeps data in: a destination there is in-country. */
  homeCountry: string;
  destCountrySource: "vendor_region" | "declared" | "unconfirmed";
  /** The mode of the Onshore route carrying this flow; null when no route carries it. */
  routeMode: "shadow" | "enforcing" | null;
  routeModeSince: Date | null;
  inScope: boolean;
  entityCount: number;
  /** In-scope detections that reached the destination unchanged since the later of 7 days ago and the switch to enforcing. */
  unprotected: number;
  current: FlowStatus;
  statusSince: Date;
  now: Date;
}

export interface Computed {
  status: FlowStatus;
  cause: string;
  /** Plain extra state that is not a status: how far through its clean week a flow is. */
  proving?: { day: number; of: number };
}

/** The spec's rule order. The first match wins. */
export function computeStatus(f: FlowFacts): Computed {
  if (f.retired) return { status: "retired", cause: "manual" };
  if (f.exceptionActive) return { status: "exception", cause: "exception_approved" };
  if (f.destCountry && f.destCountry === f.homeCountry && f.destCountrySource !== "unconfirmed") return { status: "in_country", cause: "declared_in_country" };
  if (f.routeMode === "shadow") return { status: "shadow", cause: "route_shadow" };
  if (f.routeMode === "enforcing") {
    const unprotected = f.inScope ? f.unprotected : 0;
    if (unprotected > 0) return { status: "leaking", cause: "detections_passed" };
    const since = f.routeModeSince ?? f.now;
    const age = f.now.getTime() - since.getTime();
    // Passes from before the switch are not leaks. The flow stays amber until it has
    // shown a clean week, which is what "enforcing with no leaks for 7 days" asks.
    if (age < CLEAN_DAYS * DAY) return { status: "shadow", cause: "route_enforcing", proving: { day: Math.floor(age / DAY) + 1, of: CLEAN_DAYS } };
    if (f.current === "verified") return { status: "verified", cause: "verified_30d" };
    if (f.current === "protected") {
      if (f.now.getTime() - f.statusSince.getTime() >= VERIFIED_DAYS * DAY) return { status: "verified", cause: "verified_30d" };
      return { status: "protected", cause: "no_leak_7d" };
    }
    return { status: "protected", cause: "no_leak_7d" };
  }
  const declared = f.destCountrySource !== "unconfirmed" && f.destCountry;
  if (declared && f.inScope && f.entityCount > 0) return { status: "leaking", cause: "declared_offshore" };
  return { status: "unverified", cause: "manual" };
}

export const isCompliant = (s: string) => ["protected", "verified", "in_country", "exception"].includes(s);

export function scores(flows: { status: string; in_scope: boolean; protected_30d: number; passed_30d: number }[]) {
  const inScope = flows.filter((f) => f.in_scope && f.status !== "retired");
  const pct = (a: number, b: number) => (b === 0 ? null : Math.round((a / b) * 10000) / 100);
  const good = inScope.filter((f) => isCompliant(f.status)).length;
  const noEx = inScope.filter((f) => isCompliant(f.status) && f.status !== "exception").length;
  let safe = 0, total = 0;
  for (const f of inScope) {
    total += f.protected_30d + f.passed_30d;
    safe += f.protected_30d + (f.status === "in_country" ? f.passed_30d : 0);
  }
  return { flow_score: pct(good, inScope.length), flow_score_without_exceptions: pct(noEx, inScope.length), volume_score: pct(safe, total), in_scope_flows: inScope.length };
}

function hostPattern(p: string): RegExp {
  const esc = (s: string) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  if (p.startsWith("*.")) return new RegExp(`^(?:.+\\.)?${esc(p.slice(2)).replaceAll("*", "[^.]+")}$`, "i");
  return new RegExp(`^${esc(p).replaceAll("*", "[^.]+")}$`, "i");
}

export interface VendorLike { id: string; hostnames: string[]; regions: Region[] }
export interface Region { code: string; name?: string; country: string | null; hosts?: string[] }

/** The most specific catalogue entry for a host. An address is matched, not trusted: a match never confirms a region. */
export function matchVendor<T extends VendorLike>(host: string, vendors: T[]): T | null {
  let best: T | null = null, bestLen = -1;
  for (const v of vendors) {
    for (const p of v.hostnames) {
      if (hostPattern(p).test(host) && p.length > bestLen) { best = v; bestLen = p.length; }
    }
  }
  return best;
}

/** A region the host looks like, offered to the person confirming. Never applied by itself. */
export function suggestRegion(host: string, regions: Region[]): string | null {
  for (const r of regions) if ((r.hosts ?? []).some((p) => hostPattern(p).test(host))) return r.code;
  return null;
}

export function resolveCountry(input: { flowRegion: string | null; systemRegion: string | null; hostingCountry: string | null; regions: Region[] }): { country: string | null; source: "vendor_region" | "declared" | "unconfirmed" } {
  const code = input.flowRegion ?? input.systemRegion;
  if (code) {
    const r = input.regions.find((x) => x.code === code);
    if (r?.country) return { country: r.country, source: "vendor_region" };
  }
  if (input.hostingCountry) return { country: input.hostingCountry, source: "declared" };
  return { country: null, source: "unconfirmed" };
}

/** The UUID an alert gets, so that raising the same one twice is harmless. */
export function stableUuid(bytes: Buffer): string {
  const h = bytes.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const EXTRA: Record<string, string> = { EU: "European Union", JP: "Japan", AU: "Australia", CN: "China", CH: "Switzerland", ES: "Spain", IT: "Italy", BE: "Belgium", SE: "Sweden", NO: "Norway", HK: "Hong Kong" };
const COUNTRIES: Record<string, string> = { ...EXTRA, ...Object.fromEntries(CATALOG_COUNTRIES.map((c) => [c.code, c.name])) };
export const countryName = (c: string | null | undefined) => (c ? COUNTRIES[c] ?? (isCountry(c) ? catalogName(c) : c) : "an unconfirmed location");
