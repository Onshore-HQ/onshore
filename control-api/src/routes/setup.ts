import crypto from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, forbidden, issueToken, newId, notFound, requireRole, WRITE, type Actor } from "../lib.js";

const FORMAT = "onshore-setup";
const SCOPES = ["config:export", "config:import"] as const;
const hash = (k: string) => crypto.createHash("sha256").update(k).digest("hex");

export async function apiKeyFrom(key: string) {
  const k = await db.api_keys.findUnique({ where: { key_hash: hash(key) } });
  if (!k || k.revoked_at || (k.expires_at && k.expires_at <= new Date())) return null;
  await db.api_keys.update({ where: { id: k.id }, data: { last_used_at: new Date() } });
  return { id: k.id, tenantId: k.tenant_id, scopes: k.scopes, createdBy: k.created_by };
}

/** An admin in the console, or a key with this scope. A key acts as the admin who made it, so it stops working if they lose that role. */
async function caller(req: FastifyRequest, scope: (typeof SCOPES)[number]): Promise<{ a: Pick<Actor, "tenantId" | "id" | "ip">; auth: string }> {
  if (req.apiKey) {
    if (!req.apiKey.scopes.includes(scope)) throw forbidden("this key doesn't have that permission");
    return { a: { tenantId: req.apiKey.tenantId, id: req.apiKey.createdBy, ip: req.ip }, auth: `Bearer ${issueToken(req.apiKey.createdBy, req.apiKey.tenantId)}` };
  }
  const a = requireRole(req, ...WRITE);
  return { a, auth: req.headers.authorization! };
}

/** No credentials in a URL may leave in a file. */
const cleanUrl = (u: string) => { try { const x = new URL(u); x.username = ""; x.password = ""; return x.toString().replace(/\/$/, u.endsWith("/") ? "/" : ""); } catch { return u; } };

const same = (a: unknown, b: unknown) => {
  const norm = (v: unknown): unknown => Array.isArray(v) ? v.map(norm) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).sort(([x], [y]) => x.localeCompare(y)).map(([k, x]) => [k, norm(x)])) : v;
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
};

interface Step { type: string; name: string; action: "create" | "update" | "same" | "skip" | "failed"; note?: string; shown_once?: Record<string, string> }

const ACTION_STRENGTH: Record<string, number> = { pass: 0, mask: 1, tokenize: 1, drop: 2 };

const exportSchema = z.object({
  format: z.literal(FORMAT, "this isn't an Onshore setup file"),
  version: z.literal(1, "this file is from a newer version of Onshore"),
  vault: z.object({ custom_entities_enabled: z.boolean().optional(), detection_thresholds: z.record(z.string(), z.number()).optional(), embed_origins: z.array(z.string()).optional(), residency_map_enabled: z.boolean().optional() }),
  fields: z.array(z.object({ name: z.string() }).loose()).default([]),
  column_groups: z.array(z.object({ name: z.string() }).loose()).default([]),
  policies: z.array(z.object({ name: z.string(), source: z.object({}).loose() })).default([]),
  networks: z.array(z.object({ name: z.string(), cidrs: z.array(z.string()) })).default([]),
  log_pipelines: z.array(z.object({ name: z.string(), upstream_url: z.string() }).loose()).default([]),
  ai_routes: z.array(z.object({ name: z.string(), upstream_base_url: z.string() }).loose()).default([]),
  proxy_routes: z.array(z.object({ name: z.string(), upstream_url: z.string() }).loose()).default([]),
  custom_entities: z.array(z.object({ slug: z.string(), kind: z.string() }).loose()).default([]),
});
type Setup = z.infer<typeof exportSchema>;

export async function setupRoutes(app: FastifyInstance) {
  const own = async (tenantId: string, id: string) => {
    const v = await db.vaults.findFirst({ where: { id, tenant_id: tenantId }, include: { vault_fields: true, column_groups: true } });
    if (!v) throw notFound("unknown vault");
    return v;
  };
  const inject = async (auth: string, method: "GET" | "POST" | "PATCH", url: string, payload?: object) => {
    const r = await app.inject({ method, url, headers: { authorization: auth, ...(payload ? { "content-type": "application/json" } : {}) }, ...(payload ? { payload: JSON.stringify(payload) } : {}) });
    const body = r.body ? JSON.parse(r.body) : {};
    if (r.statusCode >= 400) throw new ApiError(r.statusCode, body.error?.code ?? "error", body.error?.message ?? "failed");
    return body;
  };

  // ---- Export: only what is written here leaves. No keys, secrets, people or customer data.
  app.get("/v1/config/export", async (req) => {
    const { a, auth } = await caller(req, "config:export");
    const q = z.object({ vault_id: z.string() }).parse(req.query);
    const v = await own(a.tenantId, q.vault_id);
    const [policies, networks, pipelines, ai, proxy] = await Promise.all([
      db.policies.findMany({ where: { tenant_id: a.tenantId, status: "active" }, orderBy: { name: "asc" } }),
      db.approved_networks.findMany({ where: { tenant_id: a.tenantId }, orderBy: { name: "asc" } }),
      db.log_pipelines.findMany({ where: { vault_id: v.id }, orderBy: { name: "asc" } }),
      db.ai_routes.findMany({ where: { vault_id: v.id }, orderBy: { name: "asc" } }),
      db.proxy_routes.findMany({ where: { vault_id: v.id }, orderBy: { name: "asc" } }),
    ]);
    const entities = v.custom_entities_enabled ? (await inject(auth, "GET", `/v1/vaults/${v.id}/custom-entities/export`)).entities : [];
    const slugById = new Map((await db.custom_entities.findMany({ where: { vault_id: v.id }, select: { id: true, slug: true } })).map((e) => [e.id, e.slug]));
    const groupById = new Map(v.column_groups.map((g) => [g.id, g.name]));
    await audit(a, "config_export", { vaultId: v.id, detail: req.apiKey ? { via_key: req.apiKey.id } : {} });
    return {
      format: FORMAT, version: 1, exported_at: new Date().toISOString(), source: { vault_name: v.name, environment: v.environment },
      vault: { custom_entities_enabled: v.custom_entities_enabled, detection_thresholds: v.detection_thresholds, embed_origins: v.embed_origins, residency_map_enabled: v.residency_map_enabled },
      fields: v.vault_fields.map((f) => ({ name: f.name, data_type: f.data_type, token_kind: f.token_kind, token_format: f.token_format, ttl_days: f.ttl_days, searchable: f.searchable, unique_values: f.unique_values, mask_rule: f.mask_rule, in_payment_scope: f.in_payment_scope, column_group: f.column_group_id ? groupById.get(f.column_group_id) : undefined, custom_entity: f.custom_entity_id ? slugById.get(f.custom_entity_id) : undefined })),
      column_groups: v.column_groups.map((g) => ({ name: g.name, token_kind: g.token_kind, token_format: g.token_format })),
      policies: policies.map((p) => ({ name: p.name, source: p.source })),
      networks: networks.map((n) => ({ name: n.name, cidrs: n.cidrs })),
      log_pipelines: pipelines.map((p) => ({ name: p.name, source_type: p.source_type, destination: p.destination, upstream_url: cleanUrl(p.upstream_url), action_per_type: p.action_per_type, sensitive_paths: p.sensitive_paths, sample_rate: p.sample_rate, failure_mode: p.failure_mode, transfer_basis: p.transfer_basis })),
      ai_routes: ai.map((r) => ({ name: r.name, provider: r.provider, upstream_base_url: cleanUrl(r.upstream_base_url), allowed_models: r.allowed_models, entity_types: r.entity_types, restore_in_response: r.restore_in_response, transfer_basis: r.transfer_basis })),
      proxy_routes: proxy.map(({ id: _i, vault_id: _v, route_key_hash: _k, created_at: _c, system_id: _s, ...r }) => ({ ...r, upstream_url: cleanUrl(r.upstream_url) })),
      custom_entities: entities,
    };
  });

  // ---- Import: nothing goes live by itself. Rules become drafts, connections start watch only.
  app.post("/v1/config/import", async (req) => {
    const { a, auth } = await caller(req, "config:import");
    const b = z.object({ vault_id: z.string(), dry_run: z.boolean().default(true), config: z.unknown() }).parse(req.body);
    const parsed = exportSchema.safeParse(b.config);
    if (!parsed.success) throw badRequest(parsed.error.issues[0]?.message ?? "this isn't an Onshore setup file");
    const c: Setup = parsed.data;
    const v = await own(a.tenantId, b.vault_id);
    const steps: Step[] = [];
    const apply = async (step: Step, fn: () => Promise<unknown>) => {
      if (!b.dry_run && (step.action === "create" || step.action === "update")) {
        try { await fn(); } catch (e) { step.action = "failed"; step.note = e instanceof Error ? e.message : "failed"; }
      }
      steps.push(step);
    };

    // Data types first, as fields may depend on them.
    const existingEntities = await db.custom_entities.findMany({ where: { vault_id: v.id } });
    if (c.vault.custom_entities_enabled && !v.custom_entities_enabled) await apply({ type: "Setting", name: "Your own data types", action: "update", note: "Turned on" }, () => inject(auth, "PATCH", `/v1/vaults/${v.id}/detection`, { enabled: true }));
    for (const e of c.custom_entities) {
      if (existingEntities.some((x) => x.slug === e.slug)) { steps.push({ type: "Data type", name: String(e.name ?? e.slug), action: "same", note: "Already here. Change it on the Data types page" }); continue; }
      const note = e.kind === "value_list" ? "Created as a draft. Upload its values here, and have someone approve it" : "Created as a draft, for someone to test and approve";
      const { name, definition, validator, context_positive, context_negative, threshold, token_kind, token_format, mask_rule, actions, slug, kind } = e as Record<string, unknown>;
      await apply({ type: "Data type", name: String(name ?? slug), action: "create", note }, () => inject(auth, "POST", `/v1/vaults/${v.id}/custom-entities`, { name, definition, validator, context_positive, context_negative, threshold, token_kind, token_format, mask_rule, actions, slug, kind }));
    }
    if (c.vault.detection_thresholds && !same(c.vault.detection_thresholds, v.detection_thresholds)) await apply({ type: "Setting", name: "Detection thresholds", action: "update" }, () => inject(auth, "PATCH", `/v1/vaults/${v.id}/detection`, { thresholds: c.vault.detection_thresholds }));

    // Fields. How a token is made can't change once values exist, so that is only reported.
    const groups = new Map(v.column_groups.map((g) => [g.name, g.id]));
    for (const g of c.column_groups) {
      if (groups.has(g.name)) continue;
      await apply({ type: "Field group", name: g.name, action: "create" }, async () => { groups.set(g.name, (await inject(auth, "POST", `/v1/vaults/${v.id}/column-groups`, { name: g.name, token_kind: g.token_kind, token_format: g.token_format })).id); });
    }
    for (const f of c.fields as Record<string, any>[]) {
      const now = v.vault_fields.find((x) => x.name === f.name);
      if (!now) {
        await apply({ type: "Field", name: f.name, action: "create" }, async () => {
          const entity = f.custom_entity ? (await db.custom_entities.findFirst({ where: { vault_id: v.id, slug: f.custom_entity } }))?.id : undefined;
          await inject(auth, "POST", `/v1/vaults/${v.id}/fields`, { name: f.name, data_type: f.data_type, token_kind: f.token_kind, token_format: f.token_format, ttl_days: f.ttl_days ?? undefined, searchable: f.searchable, unique_values: f.unique_values, mask_rule: f.mask_rule, in_payment_scope: f.in_payment_scope, ...(f.column_group ? { column_group_id: groups.get(f.column_group) } : {}), ...(entity ? { custom_entity_id: entity } : {}) });
        });
        continue;
      }
      if (now.data_type !== f.data_type || now.token_kind !== f.token_kind || now.token_format !== f.token_format) { steps.push({ type: "Field", name: f.name, action: "skip", note: "Its token type differs here, and that can't change once a field exists" }); continue; }
      const patch = { mask_rule: f.mask_rule, searchable: f.searchable, in_payment_scope: f.in_payment_scope };
      if (same(patch, { mask_rule: now.mask_rule, searchable: now.searchable, in_payment_scope: now.in_payment_scope })) { steps.push({ type: "Field", name: f.name, action: "same" }); continue; }
      await apply({ type: "Field", name: f.name, action: "update" }, () => inject(auth, "PATCH", `/v1/vaults/${v.id}/fields/${now.id}`, patch));
    }

    // Networks. Changing a live range could lock people out, or let others in, so that stays manual.
    const nets = await db.approved_networks.findMany({ where: { tenant_id: a.tenantId } });
    for (const n of c.networks) {
      const now = nets.find((x) => x.name === n.name);
      if (!now) await apply({ type: "Approved network", name: n.name, action: "create" }, () => inject(auth, "POST", "/v1/networks", n));
      else if (same([...now.cidrs].sort(), [...n.cidrs].sort())) steps.push({ type: "Approved network", name: n.name, action: "same" });
      else steps.push({ type: "Approved network", name: n.name, action: "skip", note: "Its ranges differ here. Change them by hand on Access rules" });
    }

    // Access rules become drafts. Going live still takes a second person.
    const policies = await db.policies.findMany({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" } });
    for (const p of c.policies) {
      const live = policies.find((x) => x.name === p.name && x.status === "active");
      if (live && same(live.source, p.source)) { steps.push({ type: "Access rule", name: p.name, action: "same" }); continue; }
      const namesPeople = ((p.source as { rules?: { who?: { principals?: string[] } }[] }).rules ?? []).some((r) => r.who?.principals?.length);
      await apply({ type: "Access rule", name: p.name, action: live ? "update" : "create", note: `Saved as a draft, for a second person to publish${namesPeople ? ". It names specific people, who may not exist here" : ""}` }, () => inject(auth, "POST", "/v1/policies", p));
    }

    // Connections. New ones start watch only with new keys. A live one is never pointed somewhere new.
    const pipelines = await db.log_pipelines.findMany({ where: { vault_id: v.id } });
    for (const p of c.log_pipelines as Record<string, any>[]) {
      const now = pipelines.find((x) => x.name === p.name);
      if (!now) {
        const step: Step = { type: "Log connection", name: p.name, action: "create", note: "Starts as watch only, with a new key" };
        await apply(step, async () => { const r = await inject(auth, "POST", "/v1/log-pipelines", { vault_id: v.id, name: p.name, source_type: p.source_type, destination: p.destination, upstream_url: p.upstream_url, action_per_type: p.action_per_type, sensitive_paths: p.sensitive_paths, sample_rate: p.sample_rate, failure_mode: p.failure_mode, transfer_basis: p.transfer_basis }); step.shown_once = { "Collector settings": r.setup }; });
        continue;
      }
      if (cleanUrl(now.upstream_url) !== p.upstream_url) { steps.push({ type: "Log connection", name: p.name, action: "skip", note: "It sends to a different address here. Importing never redirects a connection" }); continue; }
      const nowA = now.action_per_type as Record<string, string>, wantA = (p.action_per_type ?? {}) as Record<string, string>;
      const weaker = now.mode === "enforcing" && Object.entries(wantA).some(([k, x]) => (ACTION_STRENGTH[x] ?? 1) < (ACTION_STRENGTH[nowA[k] ?? "tokenize"] ?? 1));
      if (weaker) { steps.push({ type: "Log connection", name: p.name, action: "skip", note: "This would protect less on a live connection. Change it by hand if you mean to" }); continue; }
      const patch = { action_per_type: wantA, sensitive_paths: p.sensitive_paths, sample_rate: p.sample_rate, failure_mode: p.failure_mode };
      if (same(patch, { action_per_type: nowA, sensitive_paths: now.sensitive_paths, sample_rate: now.sample_rate, failure_mode: now.failure_mode })) { steps.push({ type: "Log connection", name: p.name, action: "same" }); continue; }
      await apply({ type: "Log connection", name: p.name, action: "update", note: "Its mode isn't changed" }, () => inject(auth, "PATCH", `/v1/log-pipelines/${now.id}`, patch));
    }
    const routes = await db.ai_routes.findMany({ where: { vault_id: v.id } });
    for (const r of c.ai_routes as Record<string, any>[]) {
      const now = routes.find((x) => x.name === r.name);
      if (!now) {
        const step: Step = { type: "AI connection", name: r.name, action: "create", note: "Starts as watch only, with a new key" };
        await apply(step, async () => { const x = await inject(auth, "POST", "/v1/ai-routes", { vault_id: v.id, name: r.name, provider: r.provider, upstream_base_url: r.upstream_base_url, allowed_models: r.allowed_models, entity_types: r.entity_types, restore_in_response: r.restore_in_response, transfer_basis: r.transfer_basis }); step.shown_once = { Setup: x.setup }; });
        continue;
      }
      if (cleanUrl(now.upstream_base_url) !== r.upstream_base_url) { steps.push({ type: "AI connection", name: r.name, action: "skip", note: "It sends to a different address here. Importing never redirects a connection" }); continue; }
      const patch = { allowed_models: r.allowed_models, entity_types: r.entity_types, restore_in_response: r.restore_in_response };
      if (same(patch, { allowed_models: now.allowed_models, entity_types: now.entity_types, restore_in_response: now.restore_in_response })) { steps.push({ type: "AI connection", name: r.name, action: "same" }); continue; }
      if (now.mode === "enforcing" && (r.entity_types as string[]).length < now.entity_types.length) { steps.push({ type: "AI connection", name: r.name, action: "skip", note: "This would protect less on a live connection. Change it by hand if you mean to" }); continue; }
      await apply({ type: "AI connection", name: r.name, action: "update", note: "Its mode isn't changed" }, () => inject(auth, "PATCH", `/v1/ai-routes/${now.id}`, patch));
    }
    const prx = await db.proxy_routes.findMany({ where: { vault_id: v.id } });
    for (const r of c.proxy_routes as Record<string, any>[]) {
      if (prx.some((x) => x.name === r.name)) { steps.push({ type: "Web API connection", name: r.name, action: "skip", note: "Already here. Importing doesn't change an existing route" }); continue; }
      const step: Step = { type: "Web API connection", name: r.name, action: "create", note: "Has a new key, so nothing uses it until you say" };
      await apply(step, async () => { const x = await inject(auth, "POST", "/v1/proxy-routes", { ...r, vault_id: v.id }); step.shown_once = { "Route key": x.route_key, Address: x.url }; });
    }

    if (!b.dry_run) await audit(a, "config_import", { vaultId: v.id, detail: { applied: steps.filter((s) => s.action === "create" || s.action === "update").length, skipped: steps.filter((s) => s.action === "skip").length, failed: steps.filter((s) => s.action === "failed").length, ...(req.apiKey ? { via_key: req.apiKey.id } : {}) } });
    return { dry_run: b.dry_run, steps };
  });

  // ---- Keys for pipelines -------------------------------------------------------------
  app.get("/v1/api-keys", async (req) => {
    const a = requireRole(req, ...WRITE);
    const rows = await db.api_keys.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "desc" } });
    return { keys: rows.map(({ key_hash: _h, ...k }) => k) };
  });

  app.post("/v1/api-keys", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().min(1).max(80), scopes: z.array(z.enum(SCOPES)).min(1), expires_in_days: z.number().int().min(1).max(3650).nullish() }).parse(req.body);
    const key = `onsk_${crypto.randomBytes(32).toString("base64url")}`;
    const id = newId("key");
    await db.api_keys.create({ data: { id, tenant_id: a.tenantId, name: b.name, key_hash: hash(key), scopes: b.scopes, created_by: a.id, expires_at: b.expires_in_days ? new Date(Date.now() + b.expires_in_days * 86_400_000) : null } });
    await audit(a, "api_key_create", { detail: { key: id, name: b.name, scopes: b.scopes } });
    return { id, key };
  });

  app.post<{ Params: { id: string } }>("/v1/api-keys/:id/revoke", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.api_keys.updateMany({ where: { id: req.params.id, tenant_id: a.tenantId, revoked_at: null }, data: { revoked_at: new Date() } });
    if (!r.count) throw notFound();
    await audit(a, "api_key_revoke", { detail: { key: req.params.id } });
    return { ok: true };
  });
}
