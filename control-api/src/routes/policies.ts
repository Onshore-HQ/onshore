import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, forbidden, newId, notFound, READ_CONFIG, requireRole, vault, WRITE } from "../lib.js";

const NAME = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "use lower-case-with-dashes");

export async function policyRoutes(app: FastifyInstance) {
  app.get("/v1/policies", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.policies.findMany({ where: { tenant_id: a.tenantId }, orderBy: [{ name: "asc" }, { version: "desc" }] });
    return { policies: rows.map(({ compiled_cel: _c, ...r }) => r) };
  });

  app.get<{ Params: { id: string } }>("/v1/policies/:id", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const p = await db.policies.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!p) throw notFound();
    const previous = await db.policies.findFirst({ where: { tenant_id: a.tenantId, name: p.name, status: "active", NOT: { id: p.id } } });
    const readable = (await vault<{ readable: string }>("/internal/policy/compile", { name: p.name, version: p.version, source: p.source })).readable;
    const previousReadable = previous ? (await vault<{ readable: string }>("/internal/policy/compile", { name: previous.name, version: previous.version, source: previous.source })).readable : null;
    return { policy: p, readable, previous_readable: previousReadable, previous_version: previous?.version ?? null };
  });

  // Validates without saving, so the builder can show errors and readable text live.
  app.post("/v1/policies/compile", async (req) => {
    requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().default("draft"), version: z.number().int().default(1), source: z.object({}).loose() }).parse(req.body);
    return vault("/internal/policy/compile", b);
  });

  app.post("/v1/policies", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: NAME, source: z.object({}).loose() }).parse(req.body);
    const latest = await db.policies.findFirst({ where: { tenant_id: a.tenantId, name: b.name }, orderBy: { version: "desc" } });
    const version = (latest?.version ?? 0) + 1;
    const { compiled } = await vault<{ compiled: object }>("/internal/policy/compile", { name: b.name, version, source: b.source });
    const id = newId("pol");
    await db.policies.create({ data: { id, tenant_id: a.tenantId, name: b.name, version, source: b.source as object, compiled_cel: compiled, status: "draft", created_by: a.id } });
    await audit(a, "policy_draft", { policyId: id, policyVersion: version, detail: { name: b.name } });
    return { id, version };
  });

  // Simulator: a person, a field, a context; which rule decided, and why others lost.
  app.post("/v1/policies/preview", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const b = z
      .object({
        action: z.string().default("detokenize"),
        principal_id: z.string().optional(),
        roles: z.array(z.string()).optional(),
        networks: z.array(z.string()).optional(),
        source_ip: z.string().optional(),
        field_name: z.string().default(""),
        data_type: z.string().default(""),
        purpose: z.string().default(""),
        hour: z.number().int().min(0).max(23).optional(),
        mfa: z.boolean().optional(),
        draft: z.object({ name: z.string(), version: z.number().int(), source: z.object({}).loose() }).optional(),
      })
      .parse(req.body);
    let roles = b.roles ?? [];
    let mfa = b.mfa ?? true;
    if (b.principal_id) {
      const p = await db.principals.findFirst({ where: { id: b.principal_id, tenant_id: a.tenantId }, include: { role_assignments: { include: { roles: true } } } });
      if (!p) throw notFound("unknown principal");
      roles = p.role_assignments.map((r) => r.roles.name);
      mfa = p.mfa_enabled;
    }
    // Now, in the organisation's own time zone, unless the simulation names an hour.
    const zone = (await db.tenants.findUnique({ where: { id: a.tenantId }, select: { time_zone: true } }))?.time_zone ?? "UTC";
    const hour = b.hour ?? Number(new Intl.DateTimeFormat("en-GB", { hour: "numeric", hourCycle: "h23", timeZone: zone }).format(new Date()));
    return vault("/internal/policy/simulate", { tenant_id: a.tenantId, action: b.action, principal_id: b.principal_id ?? "", roles, mfa, networks: b.networks ?? [], source_ip: b.source_ip ?? "", field_name: b.field_name, data_type: b.data_type, purpose: b.purpose, hour, draft: b.draft });
  });

  // Two-person rule: the author can never publish their own draft. The database
  // enforces this too, with a CHECK constraint.
  app.post<{ Params: { id: string } }>("/v1/policies/:id/publish", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await db.policies.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!p) throw notFound();
    if (p.status !== "draft") throw badRequest("only a draft can be published");
    if (p.created_by === a.id) throw forbidden("publishing needs a second admin: you wrote this draft");
    const { compiled } = await vault<{ compiled: object }>("/internal/policy/compile", { name: p.name, version: p.version, source: p.source });
    await db.$transaction([
      db.policies.updateMany({ where: { tenant_id: a.tenantId, name: p.name, status: "active" }, data: { status: "archived" } }),
      db.policies.update({ where: { id: p.id }, data: { status: "active", approved_by: a.id, published_at: new Date(), compiled_cel: compiled } }),
    ]);
    await audit(a, "policy_publish", { policyId: p.id, policyVersion: p.version, detail: { name: p.name, author: p.created_by } });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/policies/:id/archive", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await db.policies.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!p) throw notFound();
    if (p.status === "archived") throw new ApiError(409, "conflict", "already archived");
    await db.policies.update({ where: { id: p.id }, data: { status: "archived" } });
    await audit(a, "policy_archive", { policyId: p.id, policyVersion: p.version, detail: { name: p.name } });
    return { ok: true };
  });
}
