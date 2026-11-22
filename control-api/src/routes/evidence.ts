import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Prisma } from "../generated/prisma/client.js";
import { actor, audit, badRequest, checkUpstreamUrl, db, encryptSecret, newId, notFound, READ_AUDIT, READ_CONFIG, requireRole, vault, WRITE } from "../lib.js";


// A cell beginning with these can run as a formula in a spreadsheet.
export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : v instanceof Date ? v.toISOString() : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

const AUDIT_COLUMNS = ["seq", "occurred_at", "principal_id", "principal_kind", "module", "action", "vault_id", "field_id", "decision", "policy_id", "policy_version", "purpose", "source_ip", "network", "break_glass", "request_id", "hash"] as const;

export const auditFilter = z.object({
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
  principal: z.string().optional(),
  action: z.string().optional(),
  decision: z.string().optional(),
  module: z.string().optional(),
  field: z.string().optional(),
  vault: z.string().optional(),
  network: z.string().optional(),
  request: z.string().max(100).optional(),
  records: z.string().regex(/^[0-9a-f-]{36}(,[0-9a-f-]{36})*$/, "must be record ids").optional(),
  before_seq: z.coerce.number().int().positive().optional(),
  after_seq: z.coerce.number().int().positive().optional(),
  order: z.enum(["newest", "oldest"]).default("newest"),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

export function auditWhere(tenantId: string, q: z.infer<typeof auditFilter>): Prisma.audit_eventsWhereInput {
  const when: Prisma.DateTimeFilter = {};
  if (q.from) when.gte = new Date(q.from);
  if (q.to) when.lte = new Date(q.to);
  return {
    tenant_id: tenantId,
    ...(q.from || q.to ? { occurred_at: when } : {}),
    ...(q.principal ? { principal_id: q.principal } : {}),
    ...(q.action ? { action: q.action } : {}),
    ...(q.decision ? { decision: q.decision } : {}),
    ...(q.module ? { module: q.module } : {}),
    ...(q.field ? { field_id: q.field } : {}),
    ...(q.vault ? { vault_id: q.vault } : {}),
    ...(q.network ? { network: q.network } : {}),
    ...(q.request ? { request_id: q.request } : {}),
    ...(q.records ? { record_id: { in: q.records.split(",") } } : {}),
    ...(q.before_seq || q.after_seq ? { seq: { ...(q.before_seq ? { lt: BigInt(q.before_seq) } : {}), ...(q.after_seq ? { gt: BigInt(q.after_seq) } : {}) } } : {}),
  };
}


export async function evidenceRoutes(app: FastifyInstance) {
  app.get("/v1/audit-events", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const events = await db.audit_events.findMany({ where: auditWhere(a.tenantId, q), orderBy: { seq: q.order === "oldest" ? "asc" : "desc" }, take: q.limit });
    return { events };
  });

  // How many events match, and which values exist, so filters offer only what can match.
  app.get("/v1/audit-events/summary", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const tenant = { tenant_id: a.tenantId };
    const [total, actions, modules, networks, principals] = await Promise.all([
      db.audit_events.count({ where: auditWhere(a.tenantId, q) }),
      db.audit_events.findMany({ where: tenant, distinct: ["action"], select: { action: true }, orderBy: { action: "asc" } }),
      db.audit_events.findMany({ where: tenant, distinct: ["module"], select: { module: true }, orderBy: { module: "asc" } }),
      db.audit_events.findMany({ where: { ...tenant, network: { not: null } }, distinct: ["network"], select: { network: true }, orderBy: { network: "asc" } }),
      db.audit_events.findMany({ where: { ...tenant, principal_id: { not: null } }, distinct: ["principal_id"], select: { principal_id: true } }),
    ]);
    return { total, actions: actions.map((x) => x.action), modules: modules.map((x) => x.module), networks: networks.map((x) => x.network), principals: principals.map((x) => x.principal_id) };
  });

  app.get("/v1/audit-events/export", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const events = await db.audit_events.findMany({ where: auditWhere(a.tenantId, q), orderBy: { seq: "desc" }, take: 100_000 });
    await audit(a, "export", { detail: { what: "audit_events", rows: events.length } });
    const csv = [AUDIT_COLUMNS.join(","), ...events.map((e) => AUDIT_COLUMNS.map((c) => csvCell(e[c] as unknown)).join(","))].join("\r\n");
    return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", 'attachment; filename="audit-events.csv"').send(csv);
  });

  app.post("/v1/audit-events/verify", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    return vault("/internal/audit/verify", { tenant_id: a.tenantId });
  });

  app.get("/v1/alerts", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    return { alerts: await db.alerts.findMany({ where: { tenant_id: a.tenantId }, orderBy: { raised_at: "desc" }, take: 100 }) };
  });

  app.post<{ Params: { id: string } }>("/v1/alerts/:id/acknowledge", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const r = await db.alerts.updateMany({ where: { id: req.params.id, tenant_id: a.tenantId }, data: { acknowledged_at: new Date() } });
    if (r.count === 0) throw notFound();
    await audit(a, "alert_acknowledge", { detail: { alert: req.params.id } });
    return { ok: true };
  });

  app.get("/v1/overview", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const pipelines = await db.log_pipelines.findMany({ where: { vaults: { tenant_id: a.tenantId } }, select: { mode: true } });
    const daily = await db.$queryRaw<{ day: Date; entity_type: string; destination: string; n: bigint }[]>`
      SELECT date_trunc('day', d.occurred_at AT TIME ZONE control.vault_tz(d.vault_id)) AS day, d.entity_type, d.destination, sum(d.count)::bigint AS n
      FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${a.tenantId} AND d.occurred_at>now()-interval '14 days' GROUP BY 1,2,3 ORDER BY 1`;
    const reveals = await db.$queryRaw<{ decision: string | null; n: bigint }[]>`
      SELECT decision, count(*)::bigint AS n FROM events.audit_events
      WHERE tenant_id=${a.tenantId} AND occurred_at>now()-interval '7 days' AND action IN ('detokenize','reveal_denied') GROUP BY 1`;
    const top = await db.$queryRaw<{ principal_id: string; display_name: string | null; n: bigint }[]>`
      SELECT e.principal_id, p.display_name, count(*)::bigint AS n FROM events.audit_events e LEFT JOIN control.principals p ON p.id=e.principal_id
      WHERE e.tenant_id=${a.tenantId} AND e.occurred_at>now()-interval '7 days' AND e.action='detokenize' AND e.decision='plaintext'
      GROUP BY 1,2 ORDER BY 3 DESC LIMIT 5`;
    const p95 = await db.$queryRaw<{ p95: number | null }[]>`
      SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95 FROM events.audit_events
      WHERE tenant_id=${a.tenantId} AND occurred_at>now()-interval '1 hour' AND action IN ('tokenize','detokenize')`;
    const keys = await vault<{ backend: string; health: string }>("/internal/keys/status", { tenant_id: a.tenantId });
    // Map alerts are reviewed on the map. This number sends people to the anomaly list.
    const openAlerts = await db.alerts.count({ where: { tenant_id: a.tenantId, acknowledged_at: null, NOT: { kind: { startsWith: "map_" } } } });
    const stats = await vault<{ records: number; subjects: number }>("/internal/stats", { tenant_id: a.tenantId });
    // What the home page's checklist and problem list are worked out from. Nothing here is ticked by hand.
    const [setup] = await db.$queryRaw<Record<string, bigint | boolean>[]>`
      SELECT
        (SELECT count(*) FROM control.vaults v WHERE v.tenant_id=${a.tenantId}) AS vaults,
        (SELECT count(*) FROM control.ai_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS ai,
        (SELECT count(*) FROM control.ai_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId} AND r.mode='enforcing') AS ai_on,
        (SELECT count(*) FROM control.proxy_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS proxy,
        (SELECT count(*) FROM control.adapters r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS adapters,
        (SELECT count(*) FROM control.adapters r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId} AND r.mode='enforcing') AS adapters_on,
        (SELECT count(*) FROM control.protected_pages r WHERE r.tenant_id=${a.tenantId}) AS pages,
        EXISTS (SELECT 1 FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id WHERE v.tenant_id=${a.tenantId}) AS detected,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL) AS flows,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL AND f.status='leaking') AS leaking,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL AND f.status='unverified') AS unverified,
        (SELECT count(*) FROM events.alerts x WHERE x.tenant_id=${a.tenantId} AND x.acknowledged_at IS NULL AND x.kind LIKE 'map\_%') AS map_alerts,
        (SELECT count(*) FROM control.policies p WHERE p.tenant_id=${a.tenantId} AND p.status='active' AND p.name NOT IN ('backend-services','console-access')) AS own_rules,
        EXISTS (SELECT 1 FROM events.audit_events e WHERE e.tenant_id=${a.tenantId} AND e.action='export' AND e.detail LIKE '%residency_report%' AND e.detail NOT LIKE '%json%') AS report_generated`;
    const num = (k: string) => Number(setup![k] ?? 0);
    const enforcing = pipelines.filter((p) => p.mode === "enforcing").length;
    const watching = pipelines.filter((p) => p.mode === "shadow").length;
    return {
      setup: {
        vaults: num("vaults"), connections: pipelines.length + num("ai") + num("proxy") + num("adapters") + num("pages"),
        // Proxy routes have no watch mode: a route either applies its rules or doesn't exist.
        protecting: enforcing + num("ai_on") + num("proxy") + num("adapters_on"),
        watching: watching + (num("ai") - num("ai_on")) + (num("adapters") - num("adapters_on")),
        detected: Boolean(setup!.detected), flows: num("flows"), leaking: num("leaking"), unverified: num("unverified"),
        map_alerts: num("map_alerts"), own_rules: num("own_rules"), report_generated: Boolean(setup!.report_generated),
      },
      residency: { connected: pipelines.length, shadow: pipelines.filter((p) => p.mode === "shadow").length, enforcing: pipelines.filter((p) => p.mode === "enforcing").length },
      caught: daily,
      custom_names: Object.fromEntries((await db.custom_entities.findMany({ where: { tenant_id: a.tenantId, version: { gt: 0 } }, select: { slug: true, name: true } })).map((e) => [e.slug, e.name])),
      reveals,
      top_revealers: top,
      health: { api_p95_ms: p95[0]?.p95 ?? null, key_backend: keys.backend, key_service: keys.health },
      open_alerts: openAlerts,
      protected: stats,
    };
  });

  app.get("/v1/scope-definitions", async (req) => {
    const a = actor(req);
    return { definitions: await db.scope_definitions.findMany({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" } }) };
  });

  // Lawyers advise fixing this definition in writing; each change is a new version.
  app.post("/v1/scope-definitions", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const b = z.object({ body: z.string().min(10).max(20000) }).parse(req.body);
    const latest = await db.scope_definitions.findFirst({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" } });
    const version = (latest?.version ?? 0) + 1;
    await db.scope_definitions.create({ data: { id: newId("scope"), tenant_id: a.tenantId, version, body: b.body, created_by: a.id } });
    await audit(a, "scope_definition", { detail: { version } });
    return { version };
  });

  app.get("/v1/keys", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const status = await vault("/internal/keys/status", { tenant_id: a.tenantId });
    const rotations = await db.audit_events.findMany({ where: { tenant_id: a.tenantId, action: "key_rotate" }, orderBy: { seq: "desc" }, take: 20, select: { occurred_at: true, principal_id: true, detail: true, vault_id: true } });
    return { ...status, rotations };
  });

  app.post("/v1/keys/rotate", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ kind: z.enum(["kek", "dek"]), vault_id: z.string().optional(), reencrypt: z.boolean().default(false) }).parse(req.body);
    if (b.kind === "dek") {
      if (!b.vault_id) throw badRequest("vault_id is required for a data key");
      if (!(await db.vaults.findFirst({ where: { id: b.vault_id, tenant_id: a.tenantId } }))) throw notFound("unknown vault");
    }
    return vault("/internal/keys/rotate", { tenant_id: a.tenantId, principal_id: a.id, kind: b.kind, vault_id: b.vault_id ?? "", reencrypt: b.reencrypt });
  });

  app.get("/v1/settings", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    const lic = await vault<{ installed: boolean; valid?: boolean; expires_at?: string; modules?: string[]; seats?: number; expired?: boolean; customer?: string }>("/internal/licence", {});
    const { siem_secret_enc: _s, ...tenant } = t!;
    return { tenant, licence: lic.installed ? lic : null };
  });

  app.patch("/v1/settings", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().min(2).max(120).optional(), hosting_facility: z.string().max(200).optional(), hosting_country: z.string().length(2).optional(), kek_rotation_days: z.union([z.literal(30), z.literal(60), z.literal(180), z.literal(360), z.null()]).optional(), audit_retention_days: z.number().int().min(365).max(36500).optional(), siem_url: z.string().nullish() }).parse(req.body);
    // The install's country is where every vault on it keeps data; once a vault exists it is fixed.
    if (b.hosting_country) {
      const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
      if (b.hosting_country.toUpperCase() !== t?.hosting_country && (await db.vaults.count({ where: { tenant_id: a.tenantId } })) > 0) throw badRequest("this install's country is fixed once a vault exists");
      b.hosting_country = b.hosting_country.toUpperCase();
    }
    const data: Record<string, unknown> = { ...b };
    let siemSecret: string | undefined;
    if (b.siem_url) {
      checkUpstreamUrl(b.siem_url);
      siemSecret = `rvs_${crypto.randomBytes(24).toString("base64url")}`;
      data.siem_secret_enc = encryptSecret(siemSecret);
    }
    await db.tenants.update({ where: { id: a.tenantId }, data });
    await audit(a, "settings_update", { detail: { ...b, siem_url: b.siem_url ? "set" : b.siem_url } });
    return { ok: true, siem_secret: siemSecret };
  });
}
