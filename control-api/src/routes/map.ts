import crypto from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, decryptSecret, encryptSecret, newId, notFound, READ_AUDIT, READ_CONFIG, redactText, requireRole, vault, WRITE } from "../lib.js";
import { CLEAN_DAYS, countryName, DAY, FLOW_STATUSES, Region, suggestRegion } from "../map/engine.js";
import { ensureHostSystem, ensureVendorAccount, expectCause, mapChanged, runVault } from "../map/run.js";

const VIEW = [...READ_CONFIG, "map_editor", "exception_approver"];
const EDIT = ["admin", "compliance", "map_editor"];
const APPROVE = ["admin", "exception_approver"];

const q = <T = Record<string, any>>(sql: string, ...args: unknown[]) => db.$queryRawUnsafe<T[]>(sql, ...args);
const x = (sql: string, ...args: unknown[]) => db.$executeRawUnsafe(sql, ...args);
const num = (v: unknown) => Number(v ?? 0);

const entityTypes = z.array(z.string().regex(/^[a-z0-9_]{2,60}$/, "use an entity id such as bvn or c_loan_id")).max(40);
const country = z.string().regex(/^[A-Z]{2}$/, "use a two-letter country code");
const USER_KINDS = ["database", "service", "warehouse", "saas_account", "file_store", "other"] as const;
const hostname = z.string().regex(/^[a-z0-9*]([a-z0-9.*-]{0,250}[a-z0-9])?$/i, "use a hostname such as api.example.com").transform((h) => h.toLowerCase());
const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "use a date such as 2027-01-31");
const lagosToday = () => new Date(Date.now() + 3_600_000).toISOString().slice(0, 10);

/** Statuses only ever change through the engine, whatever a request says. */
function refuseStatus(req: FastifyRequest) {
  if (req.body && typeof req.body === "object" && "status" in (req.body as object)) throw new ApiError(422, "status_read_only", "a flow's status is worked out from evidence and cannot be set");
}

async function enabledVault(tenantId: string, vaultId: string) {
  const v = await q<{ id: string; residency_map_enabled: boolean }>(`SELECT id,residency_map_enabled FROM control.vaults WHERE id=$1 AND tenant_id=$2`, vaultId, tenantId);
  if (!v[0]) throw notFound();
  if (!v[0].residency_map_enabled) throw new ApiError(403, "feature_disabled", "the residency map is not turned on for this vault");
}
async function checkOwner(tenantId: string, id?: string | null) {
  if (!id) return;
  const p = await q(`SELECT 1 FROM control.principals WHERE id=$1 AND tenant_id=$2`, id, tenantId);
  if (!p[0]) throw badRequest("that owner is not in this organisation");
}
async function ownFlow(tenantId: string, id: string) {
  const f = await q<{ id: string; vault_id: string; status: string; dest_system_id: string | null; dest_vendor_id: string | null; origin: string; owner_id: string | null; retired_at: Date | null }>(
    `SELECT f.id,f.vault_id,f.status,f.dest_system_id,f.dest_vendor_id,f.origin,f.owner_id,f.retired_at FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE f.id=$1 AND f.tenant_id=$2 AND v.residency_map_enabled`, id, tenantId);
  if (!f[0]) throw notFound();
  return f[0];
}
async function ownSystem(tenantId: string, id: string) {
  const s = await q<Record<string, any>>(`SELECT s.* FROM control.systems s JOIN control.vaults v ON v.id=s.vault_id WHERE s.id=$1 AND s.tenant_id=$2 AND v.residency_map_enabled`, id, tenantId);
  if (!s[0]) throw notFound();
  return s[0];
}
async function visibleVendor(tenantId: string, id: string) {
  const v = await q<{ id: string; name: string; regions: Region[]; tenant_id: string | null }>(`SELECT id,name,regions,tenant_id FROM control.vendors WHERE id=$1 AND (tenant_id IS NULL OR tenant_id=$2)`, id, tenantId);
  if (!v[0]) throw badRequest("that vendor is not in the catalogue");
  return v[0];
}

/** Everything a list row or an export needs about a flow, in one query. */
const FLOW_SELECT = `
  SELECT f.id, f.vault_id, v.country AS home_country, f.source_system_id, src.name AS source_name, src.kind AS source_kind, f.dest_system_id, ds.name AS dest_system_name, ds.kind AS dest_kind,
    f.dest_vendor_id, ven.name AS vendor_name, ven.category AS vendor_category, coalesce(f.dest_region, ds.vendor_region) AS dest_region, f.dest_host, f.dest_country, f.dest_country_source, f.dest_ip_hint,
    f.entity_types, f.in_scope, f.origin, f.via_system_id, r.route_mode, r.route_mode_since, r.source_ref AS route_ref, r.name AS route_name, f.status, f.status_since, f.owner_id, own.display_name AS owner_name,
    f.created_at, f.retired_at,
    coalesce(o.p,0)::float8 AS protected_30d, coalesce(o.u,0)::float8 AS passed_30d,
    coalesce(a.open,0)::int AS open_actions, a.overdue::int AS overdue_actions,
    e.id AS exception_id, e.status AS exception_status, e.expires_at AS exception_expires
  FROM control.data_flows f
  JOIN control.vaults v ON v.id=f.vault_id AND v.residency_map_enabled
  JOIN control.systems src ON src.id=f.source_system_id
  LEFT JOIN control.systems ds ON ds.id=f.dest_system_id
  LEFT JOIN control.systems r ON r.id=f.via_system_id
  LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id, ds.vendor_id)
  LEFT JOIN control.principals own ON own.id=f.owner_id
  LEFT JOIN (SELECT flow_id, sum(protected_count) AS p, sum(passed_count) AS u FROM control.flow_observations_daily WHERE day>=current_date-30 GROUP BY 1) o ON o.flow_id=f.id
  LEFT JOIN (SELECT flow_id, count(*) AS open, count(*) FILTER (WHERE due_date<current_date) AS overdue FROM control.remediation_actions WHERE status IN ('open','in_progress') GROUP BY 1) a ON a.flow_id=f.id
  LEFT JOIN LATERAL (SELECT id,status,expires_at FROM control.flow_exceptions WHERE flow_id=f.id AND status IN ('pending','active') LIMIT 1) e ON true`;

function flowView(f: Record<string, any>) {
  const destName = f.vendor_name ?? f.dest_system_name ?? f.dest_host;
  const enforcing = f.route_mode === "enforcing";
  const proving = f.status === "shadow" && enforcing && f.route_mode_since ? { day: Math.floor((Date.now() - new Date(f.route_mode_since).getTime()) / DAY) + 1, of: CLEAN_DAYS } : null;
  return {
    id: f.id, vault_id: f.vault_id, home_country: f.home_country,
    source: { id: f.source_system_id, name: f.source_name, kind: f.source_kind },
    dest: { name: destName, system_id: f.dest_system_id, vendor_id: f.dest_vendor_id, vendor: f.vendor_name, category: f.vendor_category, region: f.dest_region, host: f.dest_host === "check" ? null : f.dest_host, kind: f.dest_kind },
    dest_country: f.dest_country, dest_country_source: f.dest_country_source, ip_hint: f.dest_ip_hint, region_unconfirmed: f.dest_country_source === "unconfirmed",
    entity_types: f.entity_types, in_scope: f.in_scope, origin: f.origin,
    // Whether Onshore has seen this traffic, or the customer told us about it.
    basis: f.via_system_id && f.status !== "in_country" ? "observed" : "declared",
    onshore_managed: !!f.via_system_id,
    route: f.via_system_id ? { system_id: f.via_system_id, name: f.route_name, mode: f.route_mode, since: f.route_mode_since, type: f.route_ref?.type, id: f.route_ref?.id } : null,
    status: f.status, status_since: f.status_since, proving, remediation_in_progress: f.status === "leaking" && f.open_actions > 0,
    owner_id: f.owner_id, owner_name: f.owner_name,
    protected_30d: f.protected_30d, passed_30d: f.passed_30d, open_actions: f.open_actions, overdue_actions: f.overdue_actions ?? 0,
    exception: f.exception_id ? { id: f.exception_id, status: f.exception_status, expires_at: f.exception_expires } : null,
    created_at: f.created_at, retired_at: f.retired_at,
  };
}
type FlowView = ReturnType<typeof flowView>;

const SORTS: Record<string, string> = {
  passed: "coalesce(o.u,0) DESC, f.id",
  age: "f.status_since ASC, f.id",
  status: "array_position(ARRAY['leaking','shadow','unverified','exception','protected','verified','in_country','retired'], f.status), coalesce(o.u,0) DESC, f.id",
  source: "src.name, f.id",
};
const listQuery = z.object({
  vault_id: z.string().optional(), status: z.string().optional(), entity_type: z.string().optional(), dest_country: z.string().optional(), vendor: z.string().optional(), owner: z.string().optional(),
  origin: z.enum(["observed", "manual"]).optional(), in_scope: z.enum(["true", "false"]).optional(), q: z.string().max(100).optional(), sort: z.enum(["passed", "age", "status", "source"]).default("status"),
  open_work: z.enum(["true", "false"]).optional(), ids: z.string().optional(), limit: z.coerce.number().int().min(1).max(2000).default(500), offset: z.coerce.number().int().min(0).default(0), include_retired: z.enum(["true", "false"]).optional(),
});
function flowWhere(tenantId: string, p: z.infer<typeof listQuery>) {
  const args: unknown[] = [tenantId];
  const w = ["f.tenant_id=$1"];
  const add = (sql: string, v: unknown) => { args.push(v); w.push(sql.replaceAll("?", `$${args.length}`)); };
  if (p.vault_id) add("f.vault_id=?", p.vault_id);
  if (p.status) add("f.status=ANY(string_to_array(?,','))", p.status);
  else if (p.include_retired !== "true") w.push("f.status<>'retired'");
  if (p.entity_type) add("?=ANY(f.entity_types)", p.entity_type);
  if (p.dest_country === "unconfirmed") w.push("f.dest_country_source='unconfirmed'");
  else if (p.dest_country) add("f.dest_country=?", p.dest_country);
  if (p.vendor) add("coalesce(f.dest_vendor_id, ds.vendor_id)=?", p.vendor);
  if (p.owner === "none") w.push("f.owner_id IS NULL");
  else if (p.owner) add("f.owner_id=?", p.owner);
  if (p.origin) add("f.origin=?", p.origin);
  if (p.in_scope) add("f.in_scope=?::boolean", p.in_scope);
  if (p.open_work === "true") w.push("f.status IN ('leaking','shadow','unverified')");
  if (p.ids) add("f.id=ANY(string_to_array(?,','))", p.ids);
  if (p.q) add("(src.name ILIKE ? OR ds.name ILIKE ? OR ven.name ILIKE ? OR f.dest_host ILIKE ? OR own.display_name ILIKE ?)", `%${p.q.replace(/[%_\\]/g, "\\$&")}%`);
  return { where: w.join(" AND "), args };
}

async function flowsFor(tenantId: string, p: z.infer<typeof listQuery>): Promise<{ rows: FlowView[]; total: number }> {
  const { where, args } = flowWhere(tenantId, p);
  const rows = await q(`${FLOW_SELECT} WHERE ${where} ORDER BY ${SORTS[p.sort]} LIMIT ${p.limit} OFFSET ${p.offset}`, ...args);
  const total = await q<{ n: bigint }>(`SELECT count(*) AS n FROM (${FLOW_SELECT} WHERE ${where}) t`, ...args);
  return { rows: rows.map(flowView), total: num(total[0]?.n) };
}
async function oneFlow(tenantId: string, id: string): Promise<FlowView> {
  const r = await q(`${FLOW_SELECT} WHERE f.id=$1 AND f.tenant_id=$2`, id, tenantId);
  if (!r[0]) throw notFound();
  return flowView(r[0]);
}

/** The concrete next step for a flow, which the console offers as a shortcut. */
async function fixFor(f: FlowView, tenantId: string) {
  if (["retired", "in_country", "exception", "verified"].includes(f.status) && !f.region_unconfirmed) return null;
  if (f.region_unconfirmed && f.dest.system_id) {
    const dest = await q<{ regions: Region[] | null }>(`SELECT v.regions FROM control.systems s LEFT JOIN control.vendors v ON v.id=s.vendor_id WHERE s.id=$1`, f.dest.system_id);
    const regions = dest[0]?.regions ?? [];
    if (regions.length) return { kind: "confirm_region", system_id: f.dest.system_id, regions, suggested: f.dest.host ? suggestRegion(f.dest.host, regions) : null, title: `Confirm which ${f.dest.name} region your account uses`, body: "Until then this flow counts as offshore. The address it uses is shown as a hint only." };
    if (!f.route || f.route.mode === "enforcing") return { kind: "declare_hosting", system_id: f.dest.system_id, title: `Say where ${f.dest.name} is hosted`, body: "Onshore cannot tell this from the address alone." };
  }
  if (f.route?.mode === "shadow") return { kind: "enforce", route_type: f.route.type, route_id: f.route.id, title: `Switch ${f.route.name} to Protecting`, body: "Detected values will be changed before they leave. The flow turns green after a clean week." };
  if (f.status === "leaking" && f.route?.type === "check") return { kind: "batch_check", title: "This job is still sending identifiers", body: "Its last batches held real values. Tokenize them at the source, and the next clean batches start the clean week." };
  if (f.status === "leaking" && f.route) {
    const passed = await q<{ entity_type: string }>(`SELECT DISTINCT entity_type FROM control.flow_observations_daily WHERE flow_id=$1 AND day>=current_date-7 AND passed_count>0`, f.id);
    return { kind: "entity_action", route_type: f.route.type, route_id: f.route.id, entities: passed.map((p) => p.entity_type), title: "Stop these data types passing through", body: `${passed.map((p) => p.entity_type).join(", ") || "Some data types"} reached the destination unchanged. Set them to tokenize.` };
  }
  if (f.status === "leaking" || f.status === "unverified") return { kind: "route_via_proxy", title: "Put this flow behind the Onshore proxy", body: "Create a proxy route to this destination, then link it from a remediation action. If the data can move into the vault's country instead, record that." };
  return null;
}

async function summary(tenantId: string, vaultId?: string) {
  const filter = vaultId ? ` AND f.vault_id=$2` : "";
  const args = vaultId ? [tenantId, vaultId] : [tenantId];
  const [counts, unconfirmed, overdue, expiring, open] = await Promise.all([
    q<{ status: string; n: bigint }>(`SELECT f.status, count(*) AS n FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id AND v.residency_map_enabled WHERE f.tenant_id=$1${filter} AND f.in_scope GROUP BY 1`, ...args),
    q<{ n: bigint }>(`SELECT count(*) AS n FROM control.data_flows f WHERE f.tenant_id=$1${filter} AND f.status<>'retired' AND f.dest_country_source='unconfirmed'`, ...args),
    q<{ n: bigint }>(`SELECT count(*) AS n FROM control.remediation_actions a JOIN control.data_flows f ON f.id=a.flow_id WHERE f.tenant_id=$1${filter} AND a.status IN ('open','in_progress') AND a.due_date<current_date`, ...args),
    q<{ n: bigint }>(`SELECT count(*) AS n FROM control.flow_exceptions e JOIN control.data_flows f ON f.id=e.flow_id WHERE f.tenant_id=$1${filter} AND e.status='active' AND e.expires_at<=current_date+14`, ...args),
    q<{ n: bigint }>(`SELECT count(*) AS n FROM control.remediation_actions a JOIN control.data_flows f ON f.id=a.flow_id WHERE f.tenant_id=$1${filter} AND a.status IN ('open','in_progress')`, ...args),
  ]);
  const series = await q<{ day: Date; flow_score: unknown; flow_score_without_exceptions: unknown; volume_score: unknown; n: bigint }>(`
    SELECT day, avg(flow_score)::float8 AS flow_score, avg(flow_score_without_exceptions)::float8 AS flow_score_without_exceptions, avg(volume_score)::float8 AS volume_score
    FROM control.map_scores_daily m JOIN control.vaults v ON v.id=m.vault_id WHERE v.tenant_id=$1 ${vaultId ? "AND m.vault_id=$2" : ""} AND day>=current_date-90 GROUP BY 1 ORDER BY 1`, ...args);
  const latest = series[series.length - 1];
  const need = { unconfirmed_regions: num(unconfirmed[0]?.n), overdue_actions: num(overdue[0]?.n), exceptions_expiring: num(expiring[0]?.n) };
  return {
    flow_score: latest?.flow_score ?? null, flow_score_without_exceptions: latest?.flow_score_without_exceptions ?? null, volume_score: latest?.volume_score ?? null,
    series: series.map((s) => ({ day: s.day, flow: s.flow_score, volume: s.volume_score })),
    counts: Object.fromEntries(FLOW_STATUSES.map((s) => [s, num(counts.find((c) => c.status === s)?.n)])),
    needs_attention: { ...need, total: need.unconfirmed_regions + need.overdue_actions + need.exceptions_expiring },
    open_actions: num(open[0]?.n),
  };
}

const csvCell = (v: unknown) => {
  let s = v === null || v === undefined ? "" : Array.isArray(v) ? v.join(";") : v instanceof Date ? v.toISOString() : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};
const csv = (rows: unknown[][]) => rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";

async function exportData(tenantId: string, vaultId?: string, ids?: string) {
  const flows = (await flowsFor(tenantId, listQuery.parse({ vault_id: vaultId, limit: 2000, include_retired: "true", sort: "source", ids }))).rows;
  const idList = flows.map((f) => f.id);
  const systems = await q<Record<string, any>>(`SELECT s.id,s.vault_id,s.name,s.kind,s.vendor_id,s.vendor_region,s.hosting_country,s.hosting_facility,s.host,s.owner_id,s.entity_types,s.managed_by_onshore,s.created_at,s.retired_at FROM control.systems s JOIN control.vaults v ON v.id=s.vault_id AND v.residency_map_enabled WHERE s.tenant_id=$1 ${vaultId ? "AND s.vault_id=$2" : ""} ORDER BY s.name`, ...(vaultId ? [tenantId, vaultId] : [tenantId]));
  const exceptions = await q<Record<string, any>>(`SELECT id,flow_id,reason,compensating_controls,requested_by,requested_at,approved_by,approved_at,expires_at,status FROM control.flow_exceptions WHERE flow_id=ANY($1)`, idList);
  const actions = await q<Record<string, any>>(`SELECT id,flow_id,plan,description,owner_id,due_date,status,evidence,completed_at,completed_by FROM control.remediation_actions WHERE flow_id=ANY($1)`, idList);
  return { generated_at: new Date().toISOString(), flows, systems, exceptions, actions };
}
function exportCsv(d: Awaited<ReturnType<typeof exportData>>) {
  const f = [["flow_id", "vault_id", "source_system_id", "source", "destination", "vendor_id", "region", "host", "destination_country", "country_source", "entity_types", "in_scope", "origin", "basis", "status", "status_since", "owner_id", "protected_30d", "passed_30d", "open_actions", "exception_id", "exception_expires", "retired_at"],
    ...d.flows.map((x) => [x.id, x.vault_id, x.source.id, x.source.name, x.dest.name, x.dest.vendor_id, x.dest.region, x.dest.host, x.dest_country ?? "unconfirmed", x.dest_country_source, x.entity_types, x.in_scope, x.origin, x.basis, x.status, x.status_since, x.owner_id, x.protected_30d, x.passed_30d, x.open_actions, x.exception?.id, x.exception?.expires_at, x.retired_at])];
  const obj = (rows: Record<string, any>[], cols: string[]) => [cols, ...rows.map((r) => cols.map((c) => (typeof r[c] === "object" && r[c] !== null && !Array.isArray(r[c]) && !(r[c] instanceof Date) ? JSON.stringify(r[c]) : r[c])))];
  return {
    "flows.csv": csv(f),
    "systems.csv": csv(obj(d.systems, ["id", "vault_id", "name", "kind", "vendor_id", "vendor_region", "hosting_country", "hosting_facility", "host", "owner_id", "entity_types", "managed_by_onshore", "created_at", "retired_at"])),
    "exceptions.csv": csv(obj(d.exceptions, ["id", "flow_id", "reason", "compensating_controls", "requested_by", "requested_at", "approved_by", "approved_at", "expires_at", "status"])),
    "actions.csv": csv(obj(d.actions, ["id", "flow_id", "plan", "description", "owner_id", "due_date", "status", "evidence", "completed_at", "completed_by"])),
  };
}
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

export async function mapRoutes(app: FastifyInstance) {
  app.get("/v1/map/settings", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ vault_id: z.string() }).parse(req.query);
    const v = await q<{ residency_map_enabled: boolean }>(`SELECT residency_map_enabled FROM control.vaults WHERE id=$1 AND tenant_id=$2`, p.vault_id, a.tenantId);
    if (!v[0]) throw notFound();
    const t = await q<{ map_exception_max_days: number }>(`SELECT map_exception_max_days FROM control.tenants WHERE id=$1`, a.tenantId);
    const scope = await db.scope_definitions.findFirst({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" }, select: { version: true, body: true } });
    return { enabled: v[0].residency_map_enabled, exception_max_days: t[0]?.map_exception_max_days ?? 180, scope_definition: scope };
  });

  app.patch("/v1/map/settings", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ vault_id: z.string(), enabled: z.boolean().optional(), exception_max_days: z.number().int().min(1).max(730).optional() }).strict().parse(req.body);
    const v = await q(`SELECT id FROM control.vaults WHERE id=$1 AND tenant_id=$2`, b.vault_id, a.tenantId);
    if (!v[0]) throw notFound();
    if (b.enabled !== undefined) await x(`UPDATE control.vaults SET residency_map_enabled=$1 WHERE id=$2`, b.enabled, b.vault_id);
    if (b.exception_max_days !== undefined) await x(`UPDATE control.tenants SET map_exception_max_days=$1 WHERE id=$2`, b.exception_max_days, a.tenantId);
    await audit(a, "map_settings", { vaultId: b.vault_id, detail: b });
    // Turning it on reads back over recent traffic, so the map starts with what is known.
    if (b.enabled) await runVault(b.vault_id, a.tenantId, { lookback: "30 days" });
    return { ok: true };
  });

  app.get("/v1/map/summary", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ vault_id: z.string().optional() }).parse(req.query);
    return summary(a.tenantId, p.vault_id);
  });

  app.get("/v1/map/flows", async (req) => {
    const a = requireRole(req, ...VIEW);
    const { rows, total } = await flowsFor(a.tenantId, listQuery.parse(req.query));
    return { flows: rows, total };
  });

  app.get<{ Params: { id: string } }>("/v1/map/flows/:id", async (req) => {
    const a = requireRole(req, ...VIEW);
    const f = await oneFlow(a.tenantId, req.params.id);
    const [actions, exceptions, entities] = await Promise.all([
      q<Record<string, any>>(`SELECT id,plan,description,owner_id,due_date,status,evidence,evidence_files,created_at,completed_at,completed_by FROM control.remediation_actions WHERE flow_id=$1 ORDER BY created_at DESC`, f.id),
      q(`SELECT id,reason,compensating_controls,requested_by,requested_at,approved_by,approved_at,revoked_by,revoked_at,expires_at,status FROM control.flow_exceptions WHERE flow_id=$1 ORDER BY requested_at DESC`, f.id),
      q<{ entity_type: string; p: unknown; u: unknown }>(`SELECT entity_type, sum(protected_count)::float8 AS p, sum(passed_count)::float8 AS u FROM control.flow_observations_daily WHERE flow_id=$1 AND day>=current_date-30 GROUP BY 1 ORDER BY 2 DESC`, f.id),
    ]);
    return { ...f, fix: await fixFor(f, a.tenantId), by_entity: entities.map((e) => ({ entity_type: e.entity_type, protected: e.p, passed: e.u })),
      actions: actions.map((x) => ({ ...x, evidence_files: (x.evidence_files ?? []).map(({ enc: _enc, ...m }: { enc: string }) => m) })), exceptions };
  });

  app.patch<{ Params: { id: string } }>("/v1/map/flows/:id", async (req) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({ owner_id: z.string().nullable().optional(), entity_types: entityTypes.optional(), in_scope: z.boolean().optional() }).strict().parse(req.body);
    const f = await ownFlow(a.tenantId, req.params.id);
    await checkOwner(a.tenantId, b.owner_id);
    if (b.owner_id !== undefined) await x(`UPDATE control.data_flows SET owner_id=$1 WHERE id=$2`, b.owner_id, f.id);
    if (b.entity_types) await x(`UPDATE control.data_flows SET entity_types=$1 WHERE id=$2`, b.entity_types, f.id);
    if (b.in_scope !== undefined) await x(`UPDATE control.data_flows SET in_scope=$1 WHERE id=$2`, b.in_scope, f.id);
    await audit(a, "flow_update", { vaultId: f.vault_id, detail: { flow: f.id, ...b } });
    await mapChanged(f.vault_id, { flowId: f.id, actorId: a.id, cause: b.in_scope !== undefined || b.entity_types ? "manual" : undefined });
    return oneFlow(a.tenantId, f.id);
  });

  app.post<{ Params: { id: string } }>("/v1/map/flows/:id/retire", async (req) => {
    const a = requireRole(req, ...EDIT);
    const f = await ownFlow(a.tenantId, req.params.id);
    expectCause(f.id, { actorId: a.id, cause: "manual" });
    await x(`UPDATE control.data_flows SET retired_at=coalesce(retired_at,now()) WHERE id=$1`, f.id);
    await audit(a, "flow_retire", { vaultId: f.vault_id, detail: { flow: f.id } });
    await mapChanged(f.vault_id, { flowId: f.id, actorId: a.id, cause: "manual" });
    return oneFlow(a.tenantId, f.id);
  });

  app.post("/v1/map/flows/bulk", async (req) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({ ids: z.array(z.string()).min(1).max(500), owner_id: z.string().nullable().optional(), in_scope: z.boolean().optional() }).strict().parse(req.body);
    await checkOwner(a.tenantId, b.owner_id);
    const rows = await q<{ id: string; vault_id: string }>(`SELECT id,vault_id FROM control.data_flows WHERE id=ANY($1) AND tenant_id=$2`, b.ids, a.tenantId);
    const ids = rows.map((r) => r.id);
    if (b.owner_id !== undefined) await x(`UPDATE control.data_flows SET owner_id=$1 WHERE id=ANY($2)`, b.owner_id, ids);
    if (b.in_scope !== undefined) await x(`UPDATE control.data_flows SET in_scope=$1 WHERE id=ANY($2)`, b.in_scope, ids);
    await audit(a, "flow_update", { detail: { flows: ids.length, owner_id: b.owner_id, in_scope: b.in_scope } });
    for (const v of new Set(rows.map((r) => r.vault_id))) await mapChanged(v, { actorId: a.id, cause: "manual" });
    return { updated: ids.length };
  });

  app.post("/v1/map/flows", async (req, reply) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({
      source_system_id: z.string(), dest_system_id: z.string().optional(), dest_vendor_id: z.string().optional(), dest_host: hostname.optional(), dest_region: z.string().max(60).optional(), dest_country: country.optional(),
      entity_types: entityTypes.default([]), in_scope: z.boolean().default(true), owner_id: z.string().optional(),
    }).strict().parse(req.body);
    const src = await ownSystem(a.tenantId, b.source_system_id);
    await checkOwner(a.tenantId, b.owner_id);
    if ([b.dest_system_id, b.dest_vendor_id, b.dest_host].filter(Boolean).length !== 1) throw badRequest("name one destination: a system, a vendor or a host");
    let destSystem = b.dest_system_id ?? null;
    let vendorId: string | null = null;
    if (b.dest_system_id) {
      const d = await ownSystem(a.tenantId, b.dest_system_id);
      if (d.id === src.id) throw badRequest("a flow needs a different destination");
      if (d.vault_id !== src.vault_id) throw badRequest("both ends of a flow must be in one vault");
      vendorId = d.vendor_id;
    } else if (b.dest_vendor_id) {
      const v = await visibleVendor(a.tenantId, b.dest_vendor_id);
      if (b.dest_region && !v.regions.some((r) => r.code === b.dest_region)) throw badRequest(`${v.name} has no region called ${b.dest_region}`);
      vendorId = v.id;
      destSystem = await ensureVendorAccount(a.tenantId, src.vault_id, v);
    } else if (b.dest_host) {
      destSystem = await ensureHostSystem(a.tenantId, src.vault_id, b.dest_host, b.dest_country);
    }
    const dup = await q(`SELECT id FROM control.data_flows WHERE source_system_id=$1 AND coalesce(dest_vendor_id,dest_system_id,dest_host)=$2 AND coalesce(dest_region,'')=$3 AND retired_at IS NULL`, src.id, vendorId ?? destSystem ?? b.dest_host, b.dest_region ?? "");
    if (dup[0]) throw new ApiError(409, "flow_exists", "this source, destination and region are already on the map");
    const id = newId("flw");
    await x(`INSERT INTO control.data_flows(id,tenant_id,vault_id,source_system_id,dest_system_id,dest_vendor_id,dest_region,entity_types,in_scope,origin,owner_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'manual',$10)`,
      id, a.tenantId, src.vault_id, src.id, destSystem, vendorId, b.dest_region ?? null, b.entity_types, b.in_scope, b.owner_id ?? null);
    await x(`INSERT INTO control.flow_status_events(flow_id,to_status,cause,actor_id) VALUES ($1,'unverified','manual',$2)`, id, a.id);
    await audit(a, "system_declare", { vaultId: src.vault_id, detail: { flow: id, source: src.id } });
    await mapChanged(src.vault_id, { flowId: id, actorId: a.id });
    const f = await oneFlow(a.tenantId, id);
    return reply.status(201).send({ ...f });
  });

  app.get<{ Params: { id: string } }>("/v1/map/flows/:id/timeline", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ from: date.optional(), to: date.optional() }).parse(req.query);
    const f = await ownFlow(a.tenantId, req.params.id);
    const from = p.from ?? new Date(Date.now() - 90 * DAY).toISOString().slice(0, 10);
    const to = p.to ?? lagosToday();
    const [events, observations, modes] = await Promise.all([
      q(`SELECT e.seq::text AS seq, e.occurred_at, e.from_status, e.to_status, e.cause, e.evidence, e.actor_id FROM control.flow_status_events e WHERE e.flow_id=$1 ORDER BY e.seq DESC`, f.id),
      q(`SELECT day, entity_type, protected_count::float8 AS protected, passed_count::float8 AS passed, ruleset_version::float8 AS ruleset_version FROM control.flow_observations_daily WHERE flow_id=$1 AND day BETWEEN $2::date AND $3::date ORDER BY day`, f.id, from, to),
      q(`SELECT h.occurred_at, h.detail, h.actor_id FROM control.system_history h JOIN control.data_flows f ON f.via_system_id=h.system_id WHERE f.id=$1 AND h.kind='route_mode' ORDER BY h.seq DESC`, f.id),
    ]);
    return { events, observations, route_modes: modes };
  });

  // ---- systems --------------------------------------------------------------
  app.get("/v1/map/systems", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ vault_id: z.string().optional() }).parse(req.query);
    const rows = await q(`SELECT s.id,s.vault_id,s.name,s.kind,s.vendor_id,ven.name AS vendor_name,s.vendor_region,s.hosting_country,s.hosting_facility,s.host,s.owner_id,s.entity_types,s.managed_by_onshore,s.route_mode,s.created_at,s.retired_at,
        (SELECT count(*)::int FROM control.data_flows f WHERE f.source_system_id=s.id AND f.status<>'retired') AS outbound, (SELECT count(*)::int FROM control.data_flows f WHERE f.dest_system_id=s.id AND f.status<>'retired') AS inbound
      FROM control.systems s JOIN control.vaults v ON v.id=s.vault_id AND v.residency_map_enabled LEFT JOIN control.vendors ven ON ven.id=s.vendor_id
      WHERE s.tenant_id=$1 AND s.retired_at IS NULL ${p.vault_id ? "AND s.vault_id=$2" : ""} ORDER BY s.name`, ...(p.vault_id ? [a.tenantId, p.vault_id] : [a.tenantId]));
    return { systems: rows };
  });

  app.get<{ Params: { id: string } }>("/v1/map/systems/:id", async (req) => {
    const a = requireRole(req, ...VIEW);
    const s = await ownSystem(a.tenantId, req.params.id);
    const vendor = s.vendor_id ? (await q<{ name: string; regions: Region[]; category: string }>(`SELECT name,regions,category FROM control.vendors WHERE id=$1`, s.vendor_id))[0] : null;
    const flows = await q(`${FLOW_SELECT} WHERE f.tenant_id=$1 AND (f.source_system_id=$2 OR f.dest_system_id=$2) ORDER BY f.status_since`, a.tenantId, s.id);
    const history = await q(`SELECT h.seq::text AS seq, h.occurred_at, h.kind, h.detail, h.actor_id FROM control.system_history h WHERE h.system_id=$1 ORDER BY h.seq DESC`, s.id);
    const views = flows.map(flowView);
    return { ...s, vendor, outbound: views.filter((f) => f.source.id === s.id), inbound: views.filter((f) => f.dest.system_id === s.id), history };
  });

  app.post("/v1/map/systems", async (req, reply) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({
      vault_id: z.string(), name: z.string().min(1).max(120), kind: z.enum(USER_KINDS), vendor_id: z.string().optional(), vendor_region: z.string().max(60).optional(),
      hosting_country: country.optional(), hosting_facility: z.string().max(200).optional(), owner_id: z.string().optional(), entity_types: entityTypes.default([]),
    }).strict().parse(req.body);
    await enabledVault(a.tenantId, b.vault_id);
    await checkOwner(a.tenantId, b.owner_id);
    if (b.vendor_id) {
      const v = await visibleVendor(a.tenantId, b.vendor_id);
      if (b.vendor_region && !v.regions.some((r) => r.code === b.vendor_region)) throw badRequest(`${v.name} has no region called ${b.vendor_region}`);
    }
    if (b.vendor_id && b.kind === "saas_account") {
      const dup = await q(`SELECT id FROM control.systems WHERE vault_id=$1 AND vendor_id=$2 AND kind='saas_account' AND retired_at IS NULL`, b.vault_id, b.vendor_id);
      if (dup[0]) throw new ApiError(409, "system_exists", "this vendor account is already on the map");
    }
    const id = newId("sys");
    await x(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,vendor_id,vendor_region,hosting_country,hosting_facility,owner_id,entity_types) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      id, a.tenantId, b.vault_id, b.name, b.kind, b.vendor_id ?? null, b.vendor_region ?? null, b.hosting_country ?? null, b.hosting_facility ?? null, b.owner_id ?? null, b.entity_types);
    await x(`INSERT INTO control.system_history(system_id,kind,detail,actor_id) VALUES ($1,'declared',$2::jsonb,$3)`, id, JSON.stringify({ hosting_country: b.hosting_country ?? null, hosting_facility: b.hosting_facility ?? null, vendor_region: b.vendor_region ?? null, entity_types: b.entity_types }), a.id);
    await audit(a, "system_declare", { vaultId: b.vault_id, detail: { system: id, kind: b.kind, hosting_country: b.hosting_country } });
    return reply.status(201).send({ id });
  });

  app.patch<{ Params: { id: string } }>("/v1/map/systems/:id", async (req) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({ name: z.string().min(1).max(120).optional(), hosting_country: country.nullable().optional(), hosting_facility: z.string().max(200).nullable().optional(), owner_id: z.string().nullable().optional(), entity_types: entityTypes.optional(), retired: z.literal(true).optional() }).strict().parse(req.body);
    const s = await ownSystem(a.tenantId, req.params.id);
    await checkOwner(a.tenantId, b.owner_id);
    if (s.managed_by_onshore && (b.name || b.retired)) throw badRequest("this system is an Onshore route: change the route itself");
    const sets: string[] = [];
    const args: unknown[] = [s.id];
    for (const k of ["name", "hosting_country", "hosting_facility", "owner_id", "entity_types"] as const) {
      if (b[k] !== undefined) { args.push(b[k]); sets.push(`${k}=$${args.length}`); }
    }
    if (b.retired) sets.push("retired_at=now()");
    if (sets.length) await x(`UPDATE control.systems SET ${sets.join(",")} WHERE id=$1`, ...args);
    if (b.retired) await x(`UPDATE control.data_flows SET retired_at=now() WHERE (source_system_id=$1 OR dest_system_id=$1) AND retired_at IS NULL`, s.id);
    await x(`INSERT INTO control.system_history(system_id,kind,detail,actor_id) VALUES ($1,'declaration_changed',$2::jsonb,$3)`, s.id, JSON.stringify(b), a.id);
    await audit(a, "system_declare", { vaultId: s.vault_id, detail: { system: s.id, ...b } });
    const home = (await db.vaults.findUnique({ where: { id: s.vault_id }, select: { country: true } }))?.country;
    const declared = b.hosting_country !== undefined && b.hosting_country === home;
    await mapChanged(s.vault_id, { actorId: a.id, cause: declared ? "declared_in_country" : "manual" });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/map/systems/:id/confirm-region", async (req) => {
    const a = requireRole(req, ...EDIT);
    const b = z.object({ region: z.string().max(60) }).strict().parse(req.body);
    const s = await ownSystem(a.tenantId, req.params.id);
    if (!s.vendor_id) throw badRequest("only a vendor account has a region: declare a hosting country for this system");
    const v = await visibleVendor(a.tenantId, s.vendor_id);
    const r = v.regions.find((x) => x.code === b.region);
    if (!r) throw badRequest(`${v.name} has no region called ${b.region}`);
    await x(`UPDATE control.systems SET vendor_region=$1 WHERE id=$2`, b.region, s.id);
    await x(`INSERT INTO control.system_history(system_id,kind,detail,actor_id) VALUES ($1,'region_confirmed',$2::jsonb,$3)`, s.id, JSON.stringify({ region: b.region, country: r.country, was: s.vendor_region }), a.id);
    await audit(a, "system_declare", { vaultId: s.vault_id, detail: { system: s.id, region: b.region } });
    const home = (await db.vaults.findUnique({ where: { id: s.vault_id }, select: { country: true } }))?.country;
    await mapChanged(s.vault_id, { actorId: a.id, cause: r.country === home ? "declared_in_country" : "manual" });
    return { ok: true, country: r.country };
  });

  // ---- vendors --------------------------------------------------------------
  app.get("/v1/map/vendors", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ q: z.string().max(80).optional(), category: z.string().max(40).optional() }).parse(req.query);
    const args: unknown[] = [a.tenantId];
    let w = "(tenant_id IS NULL OR tenant_id=$1)";
    if (p.q) { args.push(`%${p.q.replace(/[%_\\]/g, "\\$&")}%`); w += ` AND (name ILIKE $${args.length} OR array_to_string(hostnames,' ') ILIKE $${args.length})`; }
    if (p.category) { args.push(p.category); w += ` AND category=$${args.length}`; }
    return { vendors: await q(`SELECT id,name,category,hostnames,regions,tenant_id IS NOT NULL AS custom FROM control.vendors WHERE ${w} ORDER BY name LIMIT 200`, ...args) };
  });

  app.post("/v1/map/vendors", async (req, reply) => {
    const a = requireRole(req, ...EDIT);
    const b = z.object({
      name: z.string().min(1).max(80), category: z.string().min(1).max(40).default("other"), hostnames: z.array(hostname).min(1).max(20),
      regions: z.array(z.object({ code: z.string().min(1).max(60), name: z.string().max(60).optional(), country: country.nullable(), hosts: z.array(hostname).max(20).default([]) }).strict()).max(30).default([]),
    }).strict().parse(req.body);
    const dup = await q(`SELECT id FROM control.vendors WHERE (tenant_id=$1 OR tenant_id IS NULL) AND lower(name)=lower($2)`, a.tenantId, b.name);
    if (dup[0]) throw new ApiError(409, "vendor_exists", "a vendor with this name is already in the catalogue");
    const id = newId("ven");
    await x(`INSERT INTO control.vendors(id,tenant_id,name,category,hostnames,regions) VALUES ($1,$2,$3,$4,$5,$6::jsonb)`, id, a.tenantId, b.name, b.category, b.hostnames, JSON.stringify(b.regions));
    await audit(a, "vendor_create", { detail: { vendor: id, name: b.name } });
    return reply.status(201).send({ id });
  });

  // ---- exceptions -----------------------------------------------------------
  app.get("/v1/map/exceptions", async (req) => {
    const a = requireRole(req, ...VIEW);
    const p = z.object({ vault_id: z.string().optional(), status: z.string().optional(), expiring_days: z.coerce.number().int().min(0).max(730).optional() }).parse(req.query);
    const args: unknown[] = [a.tenantId];
    let w = "f.tenant_id=$1";
    if (p.vault_id) { args.push(p.vault_id); w += ` AND f.vault_id=$${args.length}`; }
    if (p.status) { args.push(p.status); w += ` AND e.status=$${args.length}`; }
    if (p.expiring_days !== undefined) { args.push(p.expiring_days); w += ` AND e.status='active' AND e.expires_at<=current_date+$${args.length}::int`; }
    const rows = await q(`SELECT e.id,e.flow_id,e.reason,e.compensating_controls,e.requested_by,e.requested_at,e.approved_by,e.approved_at,e.expires_at,e.status, src.name AS source_name, coalesce(ven.name,ds.name,f.dest_host) AS dest_name
      FROM control.flow_exceptions e JOIN control.data_flows f ON f.id=e.flow_id JOIN control.systems src ON src.id=f.source_system_id LEFT JOIN control.systems ds ON ds.id=f.dest_system_id LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id,ds.vendor_id)
      WHERE ${w} ORDER BY e.requested_at DESC LIMIT 1000`, ...args);
    return { exceptions: rows };
  });

  app.post<{ Params: { id: string } }>("/v1/map/flows/:id/exceptions", async (req, reply) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({ reason: z.string().min(5).max(2000), compensating_controls: z.string().max(2000).optional(), expires_at: date }).strict().parse(req.body);
    const f = await ownFlow(a.tenantId, req.params.id);
    if (f.retired_at) throw badRequest("this flow is retired");
    const t = await q<{ map_exception_max_days: number }>(`SELECT map_exception_max_days FROM control.tenants WHERE id=$1`, a.tenantId);
    const max = t[0]?.map_exception_max_days ?? 180;
    const days = (Date.parse(b.expires_at) - Date.parse(lagosToday())) / DAY;
    if (Number.isNaN(days) || days < 1) throw badRequest("the expiry must be a future date");
    if (days > max) throw new ApiError(422, "expiry_too_long", `an exception can last at most ${max} days`);
    const live = await q(`SELECT 1 FROM control.flow_exceptions WHERE flow_id=$1 AND status IN ('pending','active')`, f.id);
    if (live[0]) throw new ApiError(409, "exception_exists", "this flow already has a pending or active exception");
    const id = newId("exc");
    // Free text is stored and exported, so identifiers typed into it are removed first.
    await x(`INSERT INTO control.flow_exceptions(id,flow_id,reason,compensating_controls,requested_by,expires_at) VALUES ($1,$2,$3,$4,$5,$6::date)`, id, f.id, await redactText(b.reason), b.compensating_controls ? await redactText(b.compensating_controls) : null, a.id, b.expires_at);
    await audit(a, "flow_exception_request", { vaultId: f.vault_id, detail: { flow: f.id, exception: id, expires_at: b.expires_at } });
    return reply.status(201).send({ id, status: "pending" });
  });

  const ownException = async (tenantId: string, id: string) => {
    const e = await q<{ id: string; flow_id: string; vault_id: string; status: string; requested_by: string; expires_at: Date }>(`SELECT e.id,e.flow_id,f.vault_id,e.status,e.requested_by,e.expires_at FROM control.flow_exceptions e JOIN control.data_flows f ON f.id=e.flow_id WHERE e.id=$1 AND f.tenant_id=$2`, id, tenantId);
    if (!e[0]) throw notFound();
    return e[0];
  };

  app.post<{ Params: { id: string } }>("/v1/map/exceptions/:id/approve", async (req) => {
    const a = requireRole(req, ...APPROVE);
    const e = await ownException(a.tenantId, req.params.id);
    if (e.requested_by === a.id) throw new ApiError(403, "approval_required", "someone other than the requester must approve this");
    if (e.status !== "pending") throw new ApiError(409, "not_pending", "this exception is not waiting for approval");
    expectCause(e.flow_id, { actorId: a.id, cause: "exception_approved", evidence: { exception_id: e.id } });
    await x(`UPDATE control.flow_exceptions SET status='active', approved_by=$1, approved_at=now() WHERE id=$2 AND status='pending'`, a.id, e.id);
    await audit(a, "flow_exception_approve", { vaultId: e.vault_id, detail: { flow: e.flow_id, exception: e.id } });
    await mapChanged(e.vault_id, { flowId: e.flow_id, actorId: a.id, cause: "exception_approved", evidence: { exception_id: e.id } });
    return { ok: true, flow_status: (await ownFlow(a.tenantId, e.flow_id)).status };
  });

  app.post<{ Params: { id: string } }>("/v1/map/exceptions/:id/revoke", async (req) => {
    const a = requireRole(req, ...APPROVE);
    const e = await ownException(a.tenantId, req.params.id);
    if (!["pending", "active"].includes(e.status)) throw new ApiError(409, "not_live", "this exception has already ended");
    expectCause(e.flow_id, { actorId: a.id, cause: "exception_revoked", evidence: { exception_id: e.id } });
    await x(`UPDATE control.flow_exceptions SET status='revoked', revoked_by=$1, revoked_at=now() WHERE id=$2`, a.id, e.id);
    await audit(a, "flow_exception_revoke", { vaultId: e.vault_id, detail: { flow: e.flow_id, exception: e.id } });
    await mapChanged(e.vault_id, { flowId: e.flow_id, actorId: a.id, cause: "exception_revoked", evidence: { exception_id: e.id } });
    return { ok: true, flow_status: (await ownFlow(a.tenantId, e.flow_id)).status };
  });

  // ---- remediation ----------------------------------------------------------
  app.post<{ Params: { id: string } }>("/v1/map/flows/:id/actions", async (req, reply) => {
    refuseStatus(req);
    const a = requireRole(req, ...EDIT);
    const b = z.object({ plan: z.enum(["move_in_country", "route_via_proxy", "tokenize_at_source", "delete_data", "other"]), description: z.string().max(2000).optional(), owner_id: z.string(), due_date: date }).strict().parse(req.body);
    const f = await ownFlow(a.tenantId, req.params.id);
    await checkOwner(a.tenantId, b.owner_id);
    const id = newId("act");
    await x(`INSERT INTO control.remediation_actions(id,flow_id,plan,description,owner_id,due_date) VALUES ($1,$2,$3,$4,$5,$6::date)`, id, f.id, b.plan, b.description ? await redactText(b.description) : null, b.owner_id, b.due_date);
    await audit(a, "remediation_create", { vaultId: f.vault_id, detail: { flow: f.id, action: id, plan: b.plan } });
    return reply.status(201).send({ id, status: "open" });
  });

  const fileSchema = z.object({ name: z.string().min(1).max(200), type: z.string().max(100).default("application/octet-stream"), content_b64: z.string().max(2_800_000, "a file can be at most 2 MB") }).strict();
  const evidenceSchema = z.discriminatedUnion("type", [
    z.object({ type: z.literal("route"), route_id: z.string().optional(), proxy_route_id: z.string().optional() }).strict(),
    z.object({ type: z.literal("declaration"), hosting_country: country, hosting_facility: z.string().max(200).optional() }).strict(),
    z.object({ type: z.literal("change"), reference: z.string().min(3).max(300) }).strict(),
  ]);

  app.patch<{ Params: { id: string } }>("/v1/map/actions/:id", async (req) => {
    const a = requireRole(req, ...EDIT);
    const b = z.object({ status: z.enum(["open", "in_progress", "done", "cancelled"]).optional(), evidence: evidenceSchema.optional(), files: z.array(fileSchema).max(3).optional(), due_date: date.optional(), owner_id: z.string().optional() }).strict().parse(req.body);
    const rows = await q<{ id: string; flow_id: string; plan: string; status: string; evidence_files: unknown[] | null }>(`SELECT r.id,r.flow_id,r.plan,r.status,r.evidence_files FROM control.remediation_actions r JOIN control.data_flows f ON f.id=r.flow_id WHERE r.id=$1 AND f.tenant_id=$2`, req.params.id, a.tenantId);
    const act = rows[0];
    if (!act) throw notFound();
    const f = await ownFlow(a.tenantId, act.flow_id);
    await checkOwner(a.tenantId, b.owner_id);
    if (act.status === "done") throw new ApiError(409, "already_done", "a completed action cannot be changed");
    const files = [...(act.evidence_files ?? [])];
    for (const file of b.files ?? []) {
      const raw = Buffer.from(file.content_b64, "base64");
      files.push({ name: file.name.replace(/[^\w. -]/g, "_"), type: file.type, size: raw.length, sha256: crypto.createHash("sha256").update(raw).digest("hex"), enc: encryptSecret(file.content_b64), added_by: a.id, added_at: new Date().toISOString() });
    }
    if (files.length > 5) throw badRequest("an action can hold at most 5 files");
    if (b.status === "done" && !b.evidence && files.length === 0) throw new ApiError(422, "evidence_required", "marking this done needs evidence: a linked route, a new location, a change reference or a file");
    let hint: { cause?: string; evidence?: Record<string, unknown> } = {};
    let note = "Saved.";
    if (b.status === "done") expectCause(f.id, { actorId: a.id, cause: "remediation_completed", evidence: { action_id: act.id } });
    if (b.status === "done" && b.evidence?.type === "route") {
      const routeId = b.evidence.proxy_route_id ?? b.evidence.route_id;
      if (!routeId) throw new ApiError(422, "evidence_required", "name the route this flow now passes through");
      await runVault(f.vault_id, a.tenantId);
      const sys = await q<{ id: string; route_mode: string; retired_at: Date | null }>(`SELECT id,route_mode,retired_at FROM control.systems WHERE vault_id=$1 AND source_ref->>'id'=$2`, f.vault_id, routeId);
      if (!sys[0] || sys[0].retired_at) throw new ApiError(422, "evidence_required", "that route does not exist in this vault");
      const host = await q<{ host: string | null }>(`
        SELECT upstream_host AS host FROM control.log_pipelines WHERE id=$1
        UNION ALL SELECT lower(substring(upstream_base_url from '^[a-zA-Z]+://(?:[^/@]*@)?([^/:?#]+)')) FROM control.ai_routes WHERE id=$1
        UNION ALL SELECT lower(substring(upstream_url from '^[a-zA-Z]+://(?:[^/@]*@)?([^/:?#]+)')) FROM control.proxy_routes WHERE id=$1`, routeId);
      await x(`UPDATE control.data_flows SET via_system_id=$1, route_source_id=$2, dest_host=$3 WHERE id=$4`, sys[0].id, routeId, host[0]?.host ?? null, f.id);
      note = sys[0].route_mode === "shadow"
        ? "This flow now passes through Onshore. Switch the route to Protecting; its status moves to protected after a clean week."
        : "This flow now passes through Onshore. Its status moves to protected once it has run clean for 7 days.";
    } else if (b.status === "done" && b.evidence?.type === "declaration") {
      if (!f.dest_system_id) throw badRequest("this flow has no destination system to declare");
      await x(`UPDATE control.systems SET hosting_country=$1, hosting_facility=coalesce($2,hosting_facility), vendor_region=NULL WHERE id=$3`, b.evidence.hosting_country, b.evidence.hosting_facility ?? null, f.dest_system_id);
      await x(`UPDATE control.data_flows SET dest_region=NULL WHERE id=$1`, f.id);
      await x(`INSERT INTO control.system_history(system_id,kind,detail,actor_id) VALUES ($1,'declaration_changed',$2::jsonb,$3)`, f.dest_system_id, JSON.stringify({ hosting_country: b.evidence.hosting_country, hosting_facility: b.evidence.hosting_facility ?? null, action: act.id }), a.id);
      const home = (await db.vaults.findUnique({ where: { id: f.vault_id }, select: { country: true } }))?.country;
      note = b.evidence.hosting_country === home ? `Recorded. This flow now counts as in ${countryName(home)}, on your declaration.` : `Recorded: this destination is in ${countryName(b.evidence.hosting_country)}, outside ${countryName(home)}.`;
    } else if (b.status === "done" && act.plan === "delete_data") {
      await x(`UPDATE control.data_flows SET retired_at=now() WHERE id=$1`, f.id);
      note = "Recorded. This flow is retired, as the data is gone.";
    } else if (b.status === "done") {
      note = "Recorded. Onshore cannot see this change, so the status stays until a route is linked, a location is declared, the flow's data types change or an exception is approved.";
    }
    const newStatus = b.status ?? null;
    await x(`UPDATE control.remediation_actions SET status=coalesce($1,status), evidence=coalesce($2::jsonb,evidence), evidence_files=$3::jsonb, due_date=coalesce($4::date,due_date), owner_id=coalesce($5,owner_id),
      completed_at=CASE WHEN $1='done' THEN now() ELSE completed_at END, completed_by=CASE WHEN $1='done' THEN $6 ELSE completed_by END WHERE id=$7`,
      newStatus, b.evidence ? JSON.stringify(b.evidence) : null, JSON.stringify(files), b.due_date ?? null, b.owner_id ?? null, a.id, act.id);
    if (b.status === "done") {
      await audit(a, "remediation_complete", { vaultId: f.vault_id, detail: { flow: f.id, action: act.id, plan: act.plan, evidence: b.evidence?.type ?? "file" } });
      hint = { cause: "remediation_completed", evidence: { action_id: act.id } };
      await mapChanged(f.vault_id, { flowId: f.id, actorId: a.id, ...hint });
    } else {
      await audit(a, "remediation_update", { vaultId: f.vault_id, detail: { flow: f.id, action: act.id, status: b.status } });
    }
    return { id: act.id, status: b.status ?? act.status, flow_status: (await ownFlow(a.tenantId, f.id)).status, note };
  });

  app.get<{ Params: { id: string; n: string } }>("/v1/map/actions/:id/files/:n", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT, "map_editor");
    const rows = await q<{ flow_id: string; vault_id: string; evidence_files: { name: string; type: string; enc: string }[] | null }>(`SELECT r.flow_id,f.vault_id,r.evidence_files FROM control.remediation_actions r JOIN control.data_flows f ON f.id=r.flow_id WHERE r.id=$1 AND f.tenant_id=$2`, req.params.id, a.tenantId);
    const file = rows[0]?.evidence_files?.[Number(req.params.n)];
    if (!file) throw notFound();
    await audit(a, "export", { vaultId: rows[0]!.vault_id, detail: { what: "remediation_evidence", action: req.params.id, file: file.name } });
    // Sent as a download whatever it claims to be, so that an upload cannot run in the console's origin.
    return reply.header("content-type", "application/octet-stream").header("x-content-type-options", "nosniff").header("content-disposition", `attachment; filename="${file.name.replace(/"/g, "")}"`).send(Buffer.from(decryptSecret(file.enc), "base64"));
  });

  // The map's own alerts. Acknowledging one uses the same call as any other alert.
  app.get("/v1/map/alerts", async (req) => {
    const a = requireRole(req, ...VIEW);
    const rows = await q(`SELECT id,kind,detail,raised_at FROM events.alerts WHERE tenant_id=$1 AND kind LIKE 'map\\_%' AND acknowledged_at IS NULL ORDER BY raised_at DESC LIMIT 100`, a.tenantId);
    return { alerts: rows };
  });

  // ---- export ---------------------------------------------------------------
  app.get("/v1/map/export", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT, "map_editor");
    const p = z.object({ vault_id: z.string().optional(), format: z.enum(["csv", "json"]).default("json"), table: z.enum(["flows", "systems", "exceptions", "actions"]).default("flows"), signed: z.enum(["true", "false"]).optional(), ids: z.string().optional() }).parse(req.query);
    const d = await exportData(a.tenantId, p.vault_id, p.ids);
    await audit(a, "export", { vaultId: p.vault_id ?? "", detail: { what: "residency_map", format: p.format, signed: p.signed === "true", flows: d.flows.length } });
    if (p.signed === "true") {
      const files = p.format === "csv" ? exportCsv(d) : { "map.json": JSON.stringify(d) };
      const manifest = { algorithm: "sha256", generated_at: d.generated_at, files: Object.fromEntries(Object.entries(files).map(([k, v]) => [k, sha256(v)])) };
      const digest = crypto.createHash("sha256").update(JSON.stringify(manifest)).digest();
      const { signature, public_key } = await vault<{ signature: string; public_key: string }>("/internal/audit/sign", { tenant_id: a.tenantId, message_b64: digest.toString("base64") });
      return reply.header("content-disposition", 'attachment; filename="residency-map-signed.json"').send({ manifest, signature, public_key, files });
    }
    if (p.format === "csv") return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", `attachment; filename="residency-map-${p.table}.csv"`).send(exportCsv(d)[`${p.table}.csv`]);
    return reply.header("content-disposition", 'attachment; filename="residency-map.json"').send(d);
  });
}
