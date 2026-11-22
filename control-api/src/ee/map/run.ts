// Keeps the map current: routes become systems, traffic becomes flows, counts roll up,
// and every flow's status is recomputed from that evidence. Each step is safe to repeat.
import crypto from "node:crypto";
import dns from "node:dns/promises";
import { db, newId, vault } from "../../lib.js";
import { CLEAN_DAYS, computeStatus, countryName, FlowStatus, matchVendor, Region, resolveCountry, scores, stableUuid } from "./engine.js";

const q = <T = Record<string, any>>(sql: string, ...args: unknown[]) => db.$queryRawUnsafe<T[]>(sql, ...args);
const x = (sql: string, ...args: unknown[]) => db.$executeRawUnsafe(sql, ...args);
const num = (v: unknown) => Number(v ?? 0);
export interface Hint { flowId?: string; cause?: string; actorId?: string; evidence?: Record<string, unknown> }

// A person's change and the engine run it triggers are two steps, and the background run can
// land between them. Saying why first means the status event names the right cause either way.
const expected = new Map<string, Hint>();
export function expectCause(flowId: string, hint: Omit<Hint, "flowId">) { expected.set(flowId, { flowId, ...hint }); }

export async function raiseAlert(tenantId: string, kind: string, key: string, detail: Record<string, unknown>) {
  const id = stableUuid(crypto.createHash("sha256").update(`${tenantId}|${kind}|${key}`).digest());
  await x(`INSERT INTO events.alerts(id,tenant_id,kind,detail,event_at) VALUES ($1::uuid,$2,$3,$4::jsonb,now()) ON CONFLICT DO NOTHING`, id, tenantId, kind, JSON.stringify(detail));
}

const ROUTE_HOST = `lower(substring(%s from '^[a-zA-Z]+://(?:[^/@]*@)?([^/:?#]+)'))`;

/** Every pipeline and route is a system. A route that has gone retires its system and flows. */
async function syncRoutes(vaultId: string, tenantId: string) {
  const routes = await q<{ type: string; id: string; name: string; mode: string; host: string | null; created_at: Date }>(`
    SELECT 'log_pipeline' AS type, id, name, mode, upstream_host AS host, created_at FROM control.log_pipelines WHERE vault_id=$1
    UNION ALL SELECT 'ai_route', id, name, mode, ${ROUTE_HOST.replace("%s", "upstream_base_url")}, created_at FROM control.ai_routes WHERE vault_id=$1
    UNION ALL SELECT 'proxy_route', id, name, 'enforcing', ${ROUTE_HOST.replace("%s", "upstream_url")}, created_at FROM control.proxy_routes WHERE vault_id=$1`, vaultId);
  const existing = await q<{ id: string; ref: string; name: string; route_mode: string | null; retired_at: Date | null }>(
    `SELECT id, source_ref->>'id' AS ref, name, route_mode, retired_at FROM control.systems WHERE vault_id=$1 AND source_ref IS NOT NULL AND source_ref->>'type'<>'check'`, vaultId);
  const byRef = new Map(existing.map((s) => [s.ref, s]));
  for (const r of routes) {
    const s = byRef.get(r.id);
    if (!s) {
      const id = newId("sys");
      // A route already enforcing when the map first sees it has shown nothing yet, so its
      // clean week starts now. A proxy route has no watch mode: it has applied its rules since it was made.
      const since = r.type === "proxy_route" ? r.created_at : new Date();
      await x(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,managed_by_onshore,source_ref,route_mode,route_mode_since) VALUES ($1,$2,$3,$4,$5,true,$6::jsonb,$7,$8) ON CONFLICT DO NOTHING`,
        id, tenantId, vaultId, r.name, r.type, JSON.stringify({ type: r.type, id: r.id }), r.mode, since);
      const table = r.type === "log_pipeline" ? "log_pipelines" : r.type === "ai_route" ? "ai_routes" : "proxy_routes";
      await x(`UPDATE control.${table} SET system_id=$1 WHERE id=$2 AND system_id IS NULL`, id, r.id);
      await x(`INSERT INTO control.system_history(system_id,kind,detail) VALUES ($1,'route_mode',$2::jsonb)`, id, JSON.stringify({ mode: r.mode }));
      continue;
    }
    if (s.name !== r.name) await x(`UPDATE control.systems SET name=$1 WHERE id=$2`, r.name, s.id);
    if (s.route_mode !== r.mode) {
      const n = await x(`UPDATE control.systems SET route_mode=$1, route_mode_since=now() WHERE id=$2 AND route_mode IS DISTINCT FROM $1`, r.mode, s.id);
      if (n) await x(`INSERT INTO control.system_history(system_id,kind,detail) VALUES ($1,'route_mode',$2::jsonb)`, s.id, JSON.stringify({ mode: r.mode, was: s.route_mode }));
    }
    // A route now sending somewhere else has ended its old flow.
    if (r.host) await x(`UPDATE control.data_flows SET retired_at=now() WHERE route_source_id=$1 AND dest_host IS DISTINCT FROM $2 AND origin='observed' AND retired_at IS NULL`, r.id, r.host);
  }
  const live = new Set(routes.map((r) => r.id));
  for (const s of existing) {
    if (live.has(s.ref) || s.retired_at) continue;
    await x(`UPDATE control.systems SET retired_at=now() WHERE id=$1`, s.id);
    await x(`UPDATE control.data_flows SET retired_at=now() WHERE (source_system_id=$1 OR via_system_id=$1) AND retired_at IS NULL`, s.id);
  }
}

interface VendorRow { id: string; name: string; hostnames: string[]; regions: Region[] }
const vendorsFor = (tenantId: string) => q<VendorRow>(`SELECT id,name,hostnames,regions FROM control.vendors WHERE tenant_id IS NULL OR tenant_id=$1`, tenantId);

export async function ensureVendorAccount(tenantId: string, vaultId: string, v: { id: string; name: string }): Promise<string> {
  const id = newId("sys");
  await x(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,vendor_id) VALUES ($1,$2,$3,$4,'saas_account',$5) ON CONFLICT DO NOTHING`, id, tenantId, vaultId, v.name, v.id);
  const r = await q<{ id: string }>(`SELECT id FROM control.systems WHERE vault_id=$1 AND vendor_id=$2 AND kind='saas_account' AND retired_at IS NULL`, vaultId, v.id);
  return r[0]!.id;
}

export async function ensureHostSystem(tenantId: string, vaultId: string, host: string, hostingCountry?: string | null): Promise<string> {
  const id = newId("sys");
  await x(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,host,hosting_country) VALUES ($1,$2,$3,$4,'other',$4,$5) ON CONFLICT DO NOTHING`, id, tenantId, vaultId, host, hostingCountry ?? null);
  const r = await q<{ id: string }>(`SELECT id FROM control.systems WHERE vault_id=$1 AND host=$2 AND retired_at IS NULL`, vaultId, host);
  return r[0]!.id;
}

/** The hint beside a declared location. Failure to look it up is not interesting. */
async function ipHint(host: string): Promise<string | null> {
  try {
    const { address } = await dns.lookup(host);
    return (await vault<{ country: string }>("/internal/geo/country", { ip: address })).country || null;
  } catch {
    return null;
  }
}

async function syncObservedFlows(vaultId: string, tenantId: string, lookback: string) {
  const unseen = await q<{ source_id: string; dest_host: string; entities: string[]; system_id: string; system_name: string; route_host: string | null }>(`
    SELECT d.source_id, d.dest_host, array_agg(DISTINCT d.entity_type) AS entities, s.id AS system_id, s.name AS system_name, max(d.occurred_at) AS last
    FROM events.detection_events d JOIN control.systems s ON s.source_ref->>'id'=d.source_id AND s.retired_at IS NULL
    WHERE d.vault_id=$1 AND d.dest_host IS NOT NULL AND d.occurred_at>now()-$2::interval
      AND NOT EXISTS (SELECT 1 FROM control.data_flows f WHERE f.route_source_id=d.source_id AND f.dest_host=d.dest_host AND f.retired_at IS NULL)
    GROUP BY 1,2,4,5
    HAVING NOT EXISTS (SELECT 1 FROM control.data_flows f WHERE f.route_source_id=d.source_id AND f.dest_host=d.dest_host AND f.retired_at>=max(d.occurred_at))`, vaultId, lookback);
  if (unseen.length === 0) return;
  const vendors = await vendorsFor(tenantId);
  for (const u of unseen) {
    // Traffic to an address the route no longer uses is history, and not a new flow.
    const current = await q<{ host: string | null }>(`
      SELECT upstream_host AS host FROM control.log_pipelines WHERE id=$1
      UNION ALL SELECT ${ROUTE_HOST.replace("%s", "upstream_base_url")} FROM control.ai_routes WHERE id=$1
      UNION ALL SELECT ${ROUTE_HOST.replace("%s", "upstream_url")} FROM control.proxy_routes WHERE id=$1`, u.source_id);
    if (current[0]?.host && current[0].host !== u.dest_host) continue;
    const v = matchVendor(u.dest_host, vendors);
    const dest = v ? await ensureVendorAccount(tenantId, vaultId, v) : await ensureHostSystem(tenantId, vaultId, u.dest_host);
    const id = newId("flw");
    const created = await q<{ id: string }>(`INSERT INTO control.data_flows(id,tenant_id,vault_id,source_system_id,dest_system_id,dest_vendor_id,dest_host,dest_ip_hint,entity_types,origin,route_source_id,via_system_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'observed',$10,$4) ON CONFLICT DO NOTHING RETURNING id`, id, tenantId, vaultId, u.system_id, dest, v?.id ?? null, u.dest_host, await ipHint(u.dest_host), u.entities, u.source_id);
    if (!created[0]) continue;
    await raiseAlert(tenantId, "map_new_offshore_flow", id, { flow_id: id, host: u.dest_host, source: u.system_name, vendor: v?.name ?? null, audience: ["admin", "compliance"], message: `${u.system_name} sends data to ${v?.name ?? u.dest_host}, and its location is not confirmed` });
  }
}

/** A job checking its batches through Onshore makes the flow one Onshore can see. */
async function linkCheckedFlows(vaultId: string, tenantId: string) {
  const flows = await q<{ id: string; source_name: string; dest_host: string | null }>(`
    SELECT f.id, s.name AS source_name, f.dest_host FROM control.data_flows f JOIN control.systems s ON s.id=f.source_system_id
    WHERE f.vault_id=$1 AND f.route_source_id IS NULL AND f.retired_at IS NULL
      AND EXISTS (SELECT 1 FROM events.detection_events d WHERE d.vault_id=$1 AND d.module='check' AND d.source_id=f.id)`, vaultId);
  for (const f of flows) {
    const id = newId("sys");
    await x(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,managed_by_onshore,source_ref,route_mode,route_mode_since) VALUES ($1,$2,$3,$4,'service',true,$5::jsonb,'enforcing',
      -- The first check is evidence too, so the clock starts just before it. Counts are stamped to the minute.
      (SELECT min(d.occurred_at) - interval '1 second' FROM events.detection_events d WHERE d.source_id=$6 AND d.module='check'))`,
      id, tenantId, vaultId, `Batch check: ${f.source_name}`, JSON.stringify({ type: "check", id: f.id }), f.id);
    await x(`INSERT INTO control.system_history(system_id,kind,detail) VALUES ($1,'route_mode',$2::jsonb)`, id, JSON.stringify({ mode: "enforcing" }));
    await x(`UPDATE control.data_flows SET via_system_id=$1, route_source_id=$2, dest_host=coalesce(dest_host,'check') WHERE id=$2`, id, f.id);
  }
}

/** Counts per flow per day. The last two days are replaced each time, as they can still change. */
async function rollup(vaultId: string) {
  await x(`UPDATE events.detection_events d SET flow_id=f.id FROM control.data_flows f
    WHERE d.vault_id=$1 AND d.flow_id IS NULL AND f.vault_id=$1 AND f.route_source_id=d.source_id AND f.dest_host=d.dest_host AND f.retired_at IS NULL AND d.occurred_at>now()-interval '3 days'`, vaultId);
  await x(`INSERT INTO control.flow_observations_daily(flow_id,day,entity_type,protected_count,passed_count,ruleset_version)
    SELECT f.id, (d.occurred_at AT TIME ZONE control.vault_tz($1))::date, d.entity_type,
      coalesce(sum(d.count) FILTER (WHERE d.action IN ('tokenized','masked','dropped')),0),
      coalesce(sum(d.count) FILTER (WHERE d.action IN ('passed','shadow')),0),
      max(d.ruleset_version)
    FROM control.data_flows f JOIN events.detection_events d ON d.source_id=f.route_source_id AND d.dest_host=f.dest_host
    WHERE f.vault_id=$1 AND d.occurred_at>=date_trunc('day', now() AT TIME ZONE control.vault_tz($1)) - interval '1 day' - interval '1 hour'
    GROUP BY 1,2,3
    ON CONFLICT (flow_id,day,entity_type) DO UPDATE SET protected_count=EXCLUDED.protected_count, passed_count=EXCLUDED.passed_count, ruleset_version=EXCLUDED.ruleset_version`, vaultId);
  // What a route actually carries becomes what its flow says it carries.
  await x(`UPDATE control.data_flows f SET entity_types=(SELECT array_agg(DISTINCT e) FROM unnest(f.entity_types || o.entities) e)
    FROM (SELECT flow_id, array_agg(DISTINCT entity_type) AS entities FROM control.flow_observations_daily WHERE day>=current_date-1 GROUP BY 1) o
    WHERE o.flow_id=f.id AND f.vault_id=$1 AND NOT f.entity_types @> o.entities`, vaultId);
}

async function resolveCountries(vaultId: string) {
  const rows = await q<{ id: string; dest_region: string | null; dest_country: string | null; dest_country_source: string; vendor_region: string | null; hosting_country: string | null; regions: Region[] | null }>(`
    SELECT f.id, f.dest_region, f.dest_country, f.dest_country_source, s.vendor_region, s.hosting_country, v.regions
    FROM control.data_flows f LEFT JOIN control.systems s ON s.id=f.dest_system_id LEFT JOIN control.vendors v ON v.id=coalesce(f.dest_vendor_id,s.vendor_id)
    WHERE f.vault_id=$1 AND f.retired_at IS NULL`, vaultId);
  for (const r of rows) {
    const c = resolveCountry({ flowRegion: r.dest_region, systemRegion: r.vendor_region, hostingCountry: r.hosting_country, regions: r.regions ?? [] });
    if (c.country !== r.dest_country || c.source !== r.dest_country_source) await x(`UPDATE control.data_flows SET dest_country=$1, dest_country_source=$2 WHERE id=$3`, c.country, c.source, r.id);
  }
}

async function expireExceptions(vaultId: string, tenantId: string): Promise<Map<string, string>> {
  const expired = await q<{ id: string; flow_id: string; owner_id: string | null }>(`
    UPDATE control.flow_exceptions e SET status='expired' FROM control.data_flows f
    WHERE f.id=e.flow_id AND f.vault_id=$1 AND e.status='active' AND e.expires_at<(now() AT TIME ZONE control.vault_tz($1))::date
    RETURNING e.id, e.flow_id, f.owner_id`, vaultId);
  const out = new Map<string, string>();
  for (const e of expired) {
    out.set(e.flow_id, e.id);
    await raiseAlert(tenantId, "map_exception_expired", e.id, { flow_id: e.flow_id, exception_id: e.id, principal: e.owner_id, audience: ["owner", "compliance"], message: "An accepted risk has expired, so its flow is back to its real status" });
  }
  return out;
}

interface Row {
  id: string; status: FlowStatus; status_since: Date; dest_country: string | null; home_country: string; dest_country_source: "vendor_region" | "declared" | "unconfirmed";
  in_scope: boolean; entity_types: string[]; retired_at: Date | null; owner_id: string | null; route_mode: "shadow" | "enforcing" | null; route_mode_since: Date | null;
  exception_id: string | null; open_action: string | null; unprotected: bigint | null; protected: bigint | null; ruleset: bigint | null; retired_system: Date | null; source_name: string; dest_name: string | null;
}

async function recompute(vaultId: string, tenantId: string, hint?: Hint, expired?: Map<string, string>) {
  const rows = await q<Row>(`
    SELECT f.id, f.status, f.status_since, f.dest_country, (SELECT v.country FROM control.vaults v WHERE v.id=f.vault_id) AS home_country, f.dest_country_source, f.in_scope, f.entity_types, f.retired_at, f.owner_id,
      r.route_mode, r.route_mode_since, r.retired_at AS retired_system, src.name AS source_name, coalesce(ds.name, f.dest_host) AS dest_name,
      (SELECT e.id FROM control.flow_exceptions e WHERE e.flow_id=f.id AND e.status='active' AND e.expires_at>=(now() AT TIME ZONE control.vault_tz($1))::date LIMIT 1) AS exception_id,
      (SELECT a.id FROM control.remediation_actions a WHERE a.flow_id=f.id AND a.status IN ('open','in_progress') LIMIT 1) AS open_action,
      c.unprotected, c.protected, c.ruleset
    FROM control.data_flows f
    JOIN control.systems src ON src.id=f.source_system_id
    LEFT JOIN control.systems ds ON ds.id=f.dest_system_id
    LEFT JOIN control.systems r ON r.id=f.via_system_id
    LEFT JOIN LATERAL (
      SELECT sum(d.count) FILTER (WHERE d.action IN ('passed','shadow')) AS unprotected, sum(d.count) FILTER (WHERE d.action IN ('tokenized','masked','dropped')) AS protected, max(d.ruleset_version) AS ruleset
      FROM events.detection_events d
      WHERE f.route_source_id IS NOT NULL AND d.source_id=f.route_source_id AND d.dest_host=f.dest_host AND d.occurred_at>GREATEST(now()-interval '${CLEAN_DAYS} days', coalesce(r.route_mode_since, now()-interval '${CLEAN_DAYS} days'))
    ) c ON true
    WHERE f.vault_id=$1`, vaultId);
  const now = new Date();
  for (const f of rows) {
    const c = computeStatus({
      retired: !!f.retired_at, exceptionActive: !!f.exception_id,
      destCountry: f.dest_country, homeCountry: f.home_country, destCountrySource: f.dest_country_source,
      routeMode: f.route_mode, routeModeSince: f.route_mode_since,
      inScope: f.in_scope, entityCount: f.entity_types.length, unprotected: num(f.unprotected),
      current: f.status, statusSince: f.status_since, now,
    });
    if (c.status === f.status) continue;
    const person = expected.get(f.id);
    const active = person ?? hint;
    const forThis = active && (!active.flowId || active.flowId === f.id);
    const cause = expired?.has(f.id) ? "exception_expired" : (forThis && active?.cause) || (f.retired_at && f.retired_system ? "route_deleted" : c.cause);
    const evidence = { unprotected_7d: num(f.unprotected), protected_7d: num(f.protected), ruleset_version: f.ruleset === null ? null : num(f.ruleset), route_mode: f.route_mode, route_mode_since: f.route_mode_since, exception_id: f.exception_id ?? expired?.get(f.id) ?? null, action_id: f.open_action, dest_country: f.dest_country, dest_country_source: f.dest_country_source, ...(forThis ? active?.evidence : {}) };
    // The status check is what stops two runs at once from logging the same change twice.
    const changed = await q<{ seq: bigint }>(`
      WITH u AS (UPDATE control.data_flows SET status=$2, status_since=now() WHERE id=$1 AND status=$3 RETURNING id)
      INSERT INTO control.flow_status_events(flow_id,from_status,to_status,cause,evidence,actor_id) SELECT id,$3,$2,$4,$5::jsonb,$6 FROM u RETURNING seq`,
      f.id, c.status, f.status, cause, JSON.stringify(evidence), forThis ? active?.actorId ?? null : null);
    if (changed[0] && c.status === "leaking") {
      await raiseAlert(tenantId, "map_flow_leaking", `${f.id}:${changed[0].seq}`, { flow_id: f.id, principal: f.owner_id, audience: ["owner", "compliance"], message: `${f.source_name} to ${f.dest_name ?? "a destination"} in ${countryName(f.dest_country)} is sending data unprotected` });
    }
  }
}

async function dueDates(vaultId: string, tenantId: string) {
  const soon = await q<{ id: string; flow_id: string; requested_by: string; approved_by: string | null; expires_at: Date }>(`
    UPDATE control.flow_exceptions e SET expiry_warned=true FROM control.data_flows f
    WHERE f.id=e.flow_id AND f.vault_id=$1 AND e.status='active' AND NOT e.expiry_warned AND e.expires_at<=(now() AT TIME ZONE control.vault_tz($1))::date+14
    RETURNING e.id, e.flow_id, e.requested_by, e.approved_by, e.expires_at`, vaultId);
  for (const e of soon) await raiseAlert(tenantId, "map_exception_expiring", e.id, { flow_id: e.flow_id, exception_id: e.id, expires_at: e.expires_at, principals: [e.requested_by, e.approved_by], message: "An accepted risk expires within 14 days" });
  const late = await q<{ id: string; flow_id: string; owner_id: string; due_date: Date }>(`
    UPDATE control.remediation_actions a SET overdue_warned=true FROM control.data_flows f
    WHERE f.id=a.flow_id AND f.vault_id=$1 AND a.status IN ('open','in_progress') AND NOT a.overdue_warned AND a.due_date<(now() AT TIME ZONE control.vault_tz($1))::date
    RETURNING a.id, a.flow_id, a.owner_id, a.due_date`, vaultId);
  for (const a of late) await raiseAlert(tenantId, "map_action_overdue", a.id, { flow_id: a.flow_id, action_id: a.id, principal: a.owner_id, due_date: a.due_date, audience: ["owner", "compliance"], message: "A remediation action is past its due date" });
}

export async function storeScores(vaultId: string) {
  const rows = await q<{ status: string; in_scope: boolean; protected_30d: bigint; passed_30d: bigint }>(`
    SELECT f.status, f.in_scope, coalesce(o.p,0) AS protected_30d, coalesce(o.u,0) AS passed_30d
    FROM control.data_flows f LEFT JOIN (SELECT flow_id, sum(protected_count) AS p, sum(passed_count) AS u FROM control.flow_observations_daily WHERE day>=current_date-30 GROUP BY 1) o ON o.flow_id=f.id
    WHERE f.vault_id=$1`, vaultId);
  const s = scores(rows.map((r) => ({ status: r.status, in_scope: r.in_scope, protected_30d: num(r.protected_30d), passed_30d: num(r.passed_30d) })));
  const counts: Record<string, number> = {};
  for (const r of rows) if (r.in_scope) counts[r.status] = (counts[r.status] ?? 0) + 1;
  await x(`INSERT INTO control.map_scores_daily(vault_id,day,flow_score,flow_score_without_exceptions,volume_score,counts) VALUES ($1,(now() AT TIME ZONE control.vault_tz($1))::date,$2::numeric,$3::numeric,$4::numeric,$5::jsonb)
    ON CONFLICT (vault_id,day) DO UPDATE SET flow_score=EXCLUDED.flow_score, flow_score_without_exceptions=EXCLUDED.flow_score_without_exceptions, volume_score=EXCLUDED.volume_score, counts=EXCLUDED.counts`,
    vaultId, s.flow_score, s.flow_score_without_exceptions, s.volume_score, JSON.stringify(counts));
}

export async function runVault(vaultId: string, tenantId: string, opts: { hint?: Hint; lookback?: string } = {}) {
  await syncRoutes(vaultId, tenantId);
  await syncObservedFlows(vaultId, tenantId, opts.lookback ?? "2 hours");
  await linkCheckedFlows(vaultId, tenantId);
  await rollup(vaultId);
  await resolveCountries(vaultId);
  const expired = await expireExceptions(vaultId, tenantId);
  await recompute(vaultId, tenantId, opts.hint, expired);
  await dueDates(vaultId, tenantId);
  await storeScores(vaultId);
}

/** Called the moment something changes the answer: a mode switch, an approval, a declaration. */
export async function mapChanged(vaultId: string, hint?: Hint) {
  const v = await q<{ tenant_id: string; residency_map_enabled: boolean }>(`SELECT tenant_id,residency_map_enabled FROM control.vaults WHERE id=$1`, vaultId);
  if (!v[0]?.residency_map_enabled) return;
  try { await runVault(vaultId, v[0].tenant_id, { hint }); }
  finally { if (hint?.flowId) expected.delete(hint.flowId); }
}

export async function mapTick() {
  const vaults = await q<{ id: string; tenant_id: string }>(`SELECT id,tenant_id FROM control.vaults WHERE residency_map_enabled`);
  for (const v of vaults) await runVault(v.id, v.tenant_id);
}
