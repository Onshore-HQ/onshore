import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, checkUpstreamUrl, db, newId, notFound, READ_AUDIT, READ_CONFIG, redactText, requireRole, vault, WRITE } from "../../lib.js";
import { TRANSFER_BASIS } from "./pipelines.js";
import { ownedVault } from "../../routes/vaults.js";
import { checkOptions, cloakOptions, ownedProfile } from "../../routes/ai-routes.js";
import { mapChanged } from "../map/run.js";

// The HTTP proxy and shared cloak profiles. Onshore Commercial Licence (ee/LICENSE).
// AI routes and their own cloak settings are community edition: routes/ai-routes.ts.

const newKey = () => `rvr_${crypto.randomBytes(24).toString("base64url")}`;
const hashKey = (k: string) => crypto.createHash("sha256").update(k).digest("hex");

// The same subset as the proxy's matcher: $.a.b and $.items[*].id
const jsonPath = z.string().regex(/^\$(\.@?[A-Za-z0-9_-]+(\[\*\])?)*$/, "use a path like $.customer.bvn, $.items[*].id or, for XML, $.customer.@id");
// Framing and this product's own headers are not values, and rewriting them could smuggle a request.
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "content-type", "content-encoding", "te", "trailer", "upgrade"]);
const headerName = z.string().regex(/^[A-Za-z0-9-]{1,100}$/, "use a header name like X-Customer-BVN").refine((h) => !FORBIDDEN_HEADERS.has(h.toLowerCase()) && !h.toLowerCase().startsWith("x-rv-"), "this header cannot be rewritten");
const headerRule = z.object({ header: headerName, field: z.string().max(63).optional() });
const pathRule = z.object({ path: jsonPath, field: z.string().max(63).optional() });
const queryRule = z.object({ param: z.string().min(1).max(100), field: z.string().max(63).optional() });

function proxyView<T extends { route_key_hash: string }>(r: T) {
  const { route_key_hash: _h, ...rest } = r;
  return rest;
}

export async function gatewayRoutes(app: FastifyInstance) {
  app.get("/v1/cloak-profiles", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.cloak_profiles.findMany({ where: { vaults: { tenant_id: a.tenantId } }, orderBy: { created_at: "asc" }, include: { ai_routes: { select: { id: true, name: true } } } });
    return { profiles: rows.map(({ ai_routes, ...p }) => ({ ...p, routes: ai_routes })) };
  });

  app.post("/v1/cloak-profiles", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ vault_id: z.string(), name: z.string().trim().min(1).max(80), options: cloakOptions }).parse(req.body);
    await ownedVault(a.tenantId, b.vault_id);
    await checkOptions(b.options);
    if (await db.cloak_profiles.findFirst({ where: { vault_id: b.vault_id, name: b.name } })) throw new ApiError(409, "conflict", "a cloak setting with that name already exists in this vault");
    const id = newId("clk");
    await db.cloak_profiles.create({ data: { id, vault_id: b.vault_id, name: b.name, options: b.options, created_by: a.id } });
    await audit(a, "cloak_profile_create", { vaultId: b.vault_id, detail: { profile: id, options: b.options } });
    return { id };
  });

  app.patch<{ Params: { id: string } }>("/v1/cloak-profiles/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().trim().min(1).max(80).optional(), options: z.record(z.string(), z.string()).optional() }).parse(req.body);
    const p = await ownedProfile(a.tenantId, req.params.id);
    if (b.options) await checkOptions(b.options);
    if (b.name && b.name !== p.name && (await db.cloak_profiles.findFirst({ where: { vault_id: p.vault_id, name: b.name } }))) throw new ApiError(409, "conflict", "a cloak setting with that name already exists in this vault");
    await db.cloak_profiles.update({ where: { id: p.id }, data: { ...b, updated_at: new Date() } });
    await audit(a, "cloak_profile_update", { vaultId: p.vault_id, detail: { profile: p.id, before: p.options, ...b } });
    return { ok: true };
  });

  app.delete<{ Params: { id: string } }>("/v1/cloak-profiles/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await ownedProfile(a.tenantId, req.params.id);
    const used = await db.ai_routes.count({ where: { cloak_profile_id: p.id } });
    if (used > 0) throw new ApiError(409, "in_use", `${used} AI route${used === 1 ? " uses" : "s use"} this setting; move ${used === 1 ? "it" : "them"} to another first`);
    await db.cloak_profiles.delete({ where: { id: p.id } });
    await audit(a, "cloak_profile_delete", { vaultId: p.vault_id, detail: { profile: p.id } });
    return { ok: true };
  });

  // ---- proxy routes ----------------------------------------------------------
  const proxyFields = {
    name: z.string().min(1).max(80),
    direction: z.enum(["inbound", "outbound"]).default("inbound"),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    path_pattern: z.string().regex(/^\/[A-Za-z0-9_\-./*]*$/, "use a path like /v1/kyc, /v1/* or /v1/**"),
    upstream_url: z.string(),
    mode: z.enum(["process_and_store", "process_only"]).default("process_and_store"),
    redact_paths: z.array(pathRule).default([]),
    unredact_paths: z.array(pathRule).default([]),
    response_redact_paths: z.array(pathRule).default([]),
    response_unredact_paths: z.array(pathRule).default([]),
    redact_query: z.array(queryRule).default([]),
    dlp: z.boolean().default(true),
    dlp_excluded_paths: z.array(jsonPath).default([]),
    redact_headers: z.array(headerRule).max(64).default([]),
    unredact_headers: z.array(headerRule).max(64).default([]),
    response_redact_headers: z.array(headerRule).max(64).default([]),
    response_unredact_headers: z.array(headerRule).max(64).default([]),
    dlp_excluded_headers: z.array(headerName).max(64).default([]),
    dlp_excluded_params: z.array(z.string().min(1).max(100)).max(64).default([]),
    file_policy: z.enum(["refuse", "redact", "pass"]).default("refuse"),
    transfer_basis: TRANSFER_BASIS.default("not_assessed"),
  };

  app.get("/v1/proxy-routes", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.proxy_routes.findMany({ where: { vaults: { tenant_id: a.tenantId } }, orderBy: { created_at: "asc" } });
    return { routes: rows.map(proxyView) };
  });

  app.post("/v1/proxy-routes", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ vault_id: z.string(), ...proxyFields }).parse(req.body);
    await ownedVault(a.tenantId, b.vault_id);
    checkUpstreamUrl(b.upstream_url);
    const id = newId("prx");
    const key = newKey();
    await db.proxy_routes.create({ data: { id, ...b, route_key_hash: hashKey(key) } });
    await audit(a, "proxy_route_create", { vaultId: b.vault_id, detail: { route: id, method: b.method, path: b.path_pattern, direction: b.direction } });
    return { id, route_key: key, url: `https://${process.env.RV_HOST ?? "vault.example.com"}/proxy/${id}${b.path_pattern.replace(/\/\*+$/, "")}` };
  });

  app.delete<{ Params: { id: string } }>("/v1/proxy-routes/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.proxy_routes.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!r) throw notFound();
    await db.proxy_routes.delete({ where: { id: r.id } });
    await audit(a, "proxy_route_delete", { vaultId: r.vault_id, detail: { route: r.id } });
    await mapChanged(r.vault_id);
    return { ok: true };
  });

  // Paste a sample, click fields, see the transformed payload. Nothing is stored.
  app.post("/v1/proxy-routes/preview", async (req) => {
    const a = requireRole(req, ...WRITE, "engineer");
    const b = z.object({ route: z.object({ ...proxyFields, name: z.string().default("preview"), method: z.string().default("POST"), path_pattern: z.string().default("/"), upstream_url: z.string().default("") }), request: z.string().max(65536), response: z.string().max(65536), vault_id: z.string().optional() }).parse(req.body);
    if (b.vault_id) await ownedVault(a.tenantId, b.vault_id);
    return vault("/internal/gateway/proxy-preview", { route: { ...b.route, id: "preview", vault_id: "preview", transfer_basis: undefined }, request: b.request, response: b.response, vault_id: b.vault_id });
  });
}
