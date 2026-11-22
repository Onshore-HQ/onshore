import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, checkUpstreamUrl, db, encryptSecret, newId, notFound, READ_CONFIG, requireRole, WRITE } from "../../lib.js";
import { renderMetrics, snapshot } from "../../monitoring.js";
import { enqueue, EVENT_TYPES, type EventType } from "../webhooks.js";

const MAX_ENDPOINTS = 20;
const ROTATE_OVERLAP_MS = 24 * 3600_000;
const eventTypes = z.array(z.enum(Object.keys(EVENT_TYPES) as [EventType, ...EventType[]])).min(1).max(Object.keys(EVENT_TYPES).length);
const newSecret = () => `rvwh_${crypto.randomBytes(32).toString("base64url")}`;
const hashKey = (k: string) => crypto.createHash("sha256").update(k).digest("hex");

/** A URL's path and query can hold a receiver's own secret: only admins see those. */
const safeUrl = (url: string, admin: boolean) => (admin ? url : new URL(url).origin);

type Endpoint = NonNullable<Awaited<ReturnType<typeof db.webhook_endpoints.findUnique>>>;
const view = (e: Endpoint, admin: boolean) => ({
  id: e.id, url: safeUrl(e.url, admin), description: e.description, event_types: e.event_types, enabled: e.enabled, disabled_reason: e.disabled_reason,
  consecutive_failures: e.consecutive_failures, last_success_at: e.last_success_at, last_failure_at: e.last_failure_at, created_at: e.created_at,
});

export async function webhookRoutes(app: FastifyInstance) {
  async function owned(tenantId: string, id: string) {
    const e = await db.webhook_endpoints.findFirst({ where: { id, tenant_id: tenantId } });
    if (!e) throw notFound("unknown webhook endpoint");
    return e;
  }

  app.get("/v1/webhooks/event-types", async (req) => {
    requireRole(req, ...READ_CONFIG);
    return { event_types: Object.entries(EVENT_TYPES).map(([type, description]) => ({ type, description })) };
  });

  app.get("/v1/webhooks", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const endpoints = await db.webhook_endpoints.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "desc" } });
    return { endpoints: endpoints.map((e) => view(e, a.roles.includes("admin"))) };
  });

  app.post("/v1/webhooks", async (req, reply) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ url: z.string().max(2000), description: z.string().max(200).default(""), event_types: eventTypes }).strict().parse(req.body);
    checkUpstreamUrl(b.url);
    if ((await db.webhook_endpoints.count({ where: { tenant_id: a.tenantId } })) >= MAX_ENDPOINTS) throw new ApiError(409, "too_many_endpoints", `up to ${MAX_ENDPOINTS} endpoints`);
    const secret = newSecret();
    // Starts from now: a new endpoint is not sent the tenant's whole history.
    const tip = await db.audit_events.aggregate({ where: { tenant_id: a.tenantId }, _max: { seq: true } });
    const e = await db.webhook_endpoints.create({ data: { id: newId("wh"), tenant_id: a.tenantId, url: b.url, description: b.description, event_types: b.event_types, secret_enc: encryptSecret(secret), audit_cursor: tip._max.seq ?? 0n, created_by: a.id } });
    await audit(a, "webhook_create", { detail: { endpoint: e.id, host: new URL(b.url).host, event_types: b.event_types } });
    reply.code(201);
    return { ...view(e, true), secret };
  });

  app.patch<{ Params: { id: string } }>("/v1/webhooks/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const e = await owned(a.tenantId, req.params.id);
    const b = z.object({ url: z.string().max(2000).optional(), description: z.string().max(200).optional(), event_types: eventTypes.optional(), enabled: z.boolean().optional() }).strict().parse(req.body);
    if (b.url) checkUpstreamUrl(b.url);
    const reviving = b.enabled === true && !e.enabled;
    const u = await db.webhook_endpoints.update({ where: { id: e.id }, data: { ...b, ...(reviving ? { consecutive_failures: 0, disabled_reason: null } : {}), ...(b.enabled === false ? { disabled_reason: "turned off by an admin" } : {}) } });
    await audit(a, "webhook_update", { detail: { endpoint: e.id, host: new URL(u.url).host, event_types: u.event_types, enabled: u.enabled } });
    return view(u, true);
  });

  app.delete<{ Params: { id: string } }>("/v1/webhooks/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const e = await owned(a.tenantId, req.params.id);
    await db.webhook_endpoints.delete({ where: { id: e.id } });
    await audit(a, "webhook_delete", { detail: { endpoint: e.id, host: new URL(e.url).host } });
    return { ok: true };
  });

  // The old secret keeps signing alongside the new one for a day, so a rotation has no gap.
  app.post<{ Params: { id: string } }>("/v1/webhooks/:id/rotate-secret", async (req) => {
    const a = requireRole(req, ...WRITE);
    const e = await owned(a.tenantId, req.params.id);
    const secret = newSecret();
    await db.webhook_endpoints.update({ where: { id: e.id }, data: { secret_enc: encryptSecret(secret), secret_prev_enc: e.secret_enc, secret_prev_until: new Date(Date.now() + ROTATE_OVERLAP_MS) } });
    await audit(a, "webhook_secret_rotate", { detail: { endpoint: e.id } });
    return { secret };
  });

  app.post<{ Params: { id: string } }>("/v1/webhooks/:id/test", async (req) => {
    const a = requireRole(req, ...WRITE);
    const e = await owned(a.tenantId, req.params.id);
    const eventId = `test_${crypto.randomUUID()}`;
    await enqueue(e, eventId, "test.ping", { note: "a test you asked for" });
    return { event_id: eventId };
  });

  app.get<{ Params: { id: string }; Querystring: { limit?: string; status?: string } }>("/v1/webhooks/:id/deliveries", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const e = await owned(a.tenantId, req.params.id);
    const status = ["pending", "delivered", "dead"].includes(req.query.status ?? "") ? req.query.status : undefined;
    const deliveries = await db.webhook_deliveries.findMany({ where: { endpoint_id: e.id, ...(status ? { status } : {}) }, orderBy: { created_at: "desc" }, take: Math.min(Number(req.query.limit) || 50, 200) });
    return { deliveries };
  });

  app.post<{ Params: { id: string; delivery: string } }>("/v1/webhooks/:id/deliveries/:delivery/redeliver", async (req) => {
    const a = requireRole(req, ...WRITE);
    const e = await owned(a.tenantId, req.params.id);
    if (!z.string().uuid().safeParse(req.params.delivery).success) throw notFound("unknown delivery");
    const r = await db.webhook_deliveries.updateMany({ where: { id: req.params.delivery, endpoint_id: e.id }, data: { status: "pending", attempts: 0, next_attempt_at: new Date(), delivered_at: null } });
    if (r.count === 0) throw notFound("unknown delivery");
    await audit(a, "webhook_redeliver", { detail: { endpoint: e.id, delivery: req.params.delivery } });
    return { ok: true };
  });

  app.get("/v1/monitoring", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId }, select: { metrics_key_hash: true } });
    return { ...(await snapshot(a.tenantId)), metrics_key_set: Boolean(t?.metrics_key_hash) };
  });

  app.post("/v1/monitoring/metrics-key", async (req) => {
    const a = requireRole(req, ...WRITE);
    const key = `rvm_${crypto.randomBytes(32).toString("base64url")}`;
    await db.tenants.update({ where: { id: a.tenantId }, data: { metrics_key_hash: hashKey(key) } });
    await audit(a, "metrics_key_rotate");
    return { key };
  });

  app.delete("/v1/monitoring/metrics-key", async (req) => {
    const a = requireRole(req, ...WRITE);
    await db.tenants.update({ where: { id: a.tenantId }, data: { metrics_key_hash: null } });
    await audit(a, "metrics_key_revoke");
    return { ok: true };
  });

  // For a scraper, which holds a key that can read these numbers and do nothing else.
  const cache = new Map<string, { at: number; text: string }>();
  app.get("/v1/monitoring/metrics", async (req, reply) => {
    const key = /^Bearer (rvm_[\w-]+)$/.exec(req.headers.authorization ?? "")?.[1];
    const t = key ? await db.tenants.findFirst({ where: { metrics_key_hash: hashKey(key) }, select: { id: true } }) : null;
    if (!t) {
      reply.code(401);
      return { error: { code: "unauthorized", message: "a metrics key is required" } };
    }
    let hit = cache.get(t.id);
    if (!hit || Date.now() - hit.at > 15_000) {
      hit = { at: Date.now(), text: renderMetrics(await snapshot(t.id)) };
      cache.set(t.id, hit);
    }
    reply.header("content-type", "text/plain; version=0.0.4; charset=utf-8");
    return hit.text;
  });
}
