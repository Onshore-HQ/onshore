import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, encryptSecret, newId, notFound, requireRole, WRITE } from "../lib.js";
import { ROLES } from "../templates.js";
import { IDENTITY_EDITIONS, publicOrigin, requireIdentityEdition } from "../identity.js";
import { ldapTest } from "../ldap.js";
import { edition } from "./locations.js";

export const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const dn = z.string().min(3).max(500);
const domains = z.array(z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/)).min(1).max(20);

export async function identityRoutes(app: FastifyInstance) {
  // Everything the Sign-in settings show, in one call.
  app.get("/v1/settings/identity", async (req) => {
    const a = requireRole(req, ...WRITE);
    const ed = await edition();
    const [mappings, tokens, ldap, counts] = await Promise.all([
      db.group_role_mappings.findMany({ where: { tenant_id: a.tenantId }, orderBy: { group_name: "asc" } }),
      db.scim_tokens.findMany({ where: { tenant_id: a.tenantId, revoked_at: null }, orderBy: { created_at: "asc" } }),
      db.ldap_configs.findUnique({ where: { tenant_id: a.tenantId } }),
      db.principals.groupBy({ by: ["source"], where: { tenant_id: a.tenantId, kind: "user" }, _count: true }),
    ]);
    const { bind_password_enc: _p, ...ldapRest } = ldap ?? ({} as Record<string, unknown>);
    return {
      edition: ed, allowed: IDENTITY_EDITIONS.includes(ed),
      mappings: mappings.map((m) => ({ group: m.group_name, roles: m.roles })),
      scim: { base_url: `${publicOrigin()}/control/scim/v2`, tokens: tokens.map((t) => ({ id: t.id, name: t.name, created_at: t.created_at, last_used_at: t.last_used_at })) },
      ldap: ldap ? ldapRest : null,
      people_by_source: Object.fromEntries(counts.map((c) => [c.source, c._count])),
    };
  });

  // ---- Groups to roles ----------------------------------------------------------
  app.put("/v1/settings/group-roles", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ mappings: z.array(z.object({ group: z.string().trim().min(1).max(256), roles: z.array(z.enum(ROLES as [string, ...string[]])).min(1).max(20) })).max(200) }).parse(req.body);
    const seen = new Set<string>();
    for (const m of b.mappings) { const g = m.group.toLowerCase(); if (seen.has(g)) throw badRequest(`the group "${m.group}" is listed twice`); seen.add(g); }
    await db.$transaction(async (tx) => {
      await tx.group_role_mappings.deleteMany({ where: { tenant_id: a.tenantId } });
      for (const m of b.mappings) await tx.group_role_mappings.create({ data: { tenant_id: a.tenantId, group_name: m.group.toLowerCase(), roles: [...new Set(m.roles)], created_by: a.id } });
    });
    await audit(a, "group_roles_set", { detail: { mappings: b.mappings.map((m) => ({ group: m.group.toLowerCase(), roles: m.roles })) } });
    return { ok: true };
  });

  // ---- SCIM tokens --------------------------------------------------------------
  app.post("/v1/settings/scim/tokens", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body);
    await requireIdentityEdition();
    if ((await db.scim_tokens.count({ where: { tenant_id: a.tenantId, revoked_at: null } })) >= 5) throw badRequest("revoke an old token first; five can be active");
    const token = `rvscim_${crypto.randomBytes(32).toString("base64url")}`;
    const id = newId("scim");
    await db.scim_tokens.create({ data: { id, tenant_id: a.tenantId, name: b.name, token_hash: sha(token), created_by: a.id } });
    await audit(a, "scim_token_create", { detail: { id, name: b.name } });
    return { id, token, base_url: `${publicOrigin()}/control/scim/v2` };
  });

  app.delete<{ Params: { id: string } }>("/v1/settings/scim/tokens/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.scim_tokens.updateMany({ where: { id: req.params.id, tenant_id: a.tenantId, revoked_at: null }, data: { revoked_at: new Date() } });
    if (!r.count) throw notFound();
    await audit(a, "scim_token_revoke", { detail: { id: req.params.id } });
    return { ok: true };
  });

  // ---- LDAP ---------------------------------------------------------------------
  const ldapBody = z.object({
    url: z.string().regex(/^ldaps?:\/\/[^\s/]+(:\d+)?\/?$/, "use ldaps://host:636 or ldap://host:389 with StartTLS"),
    start_tls: z.boolean().default(false),
    ca_cert: z.string().max(20_000).nullish(),
    bind_dn: dn, bind_password: z.string().max(500).optional(),
    base_dn: dn,
    user_filter: z.string().max(500).refine((f) => f.includes("{email}"), "the user filter must contain {email}").default("(&(objectClass=person)(mail={email}))"),
    group_base_dn: dn.nullish(),
    group_filter: z.string().max(500).default("(&(objectClass=groupOfNames)(member={dn}))"),
    email_domains: domains,
    jit_provisioning: z.boolean().default(false),
  });

  const ldapData = async (tenantId: string, raw: unknown) => {
    const b = ldapBody.parse(raw);
    if (b.url.startsWith("ldap://") && !b.start_tls) throw badRequest("an unencrypted directory connection is refused; use ldaps:// or turn on StartTLS");
    if (b.ca_cert && !/-----BEGIN CERTIFICATE-----/.test(b.ca_cert)) throw badRequest("the CA certificate must be in PEM form");
    const existing = await db.ldap_configs.findUnique({ where: { tenant_id: tenantId } });
    if (!b.bind_password && !existing) throw badRequest("the service account's password is needed");
    const { bind_password, ...rest } = b;
    return { ...rest, url: rest.url.replace(/\/$/, ""), ca_cert: rest.ca_cert || null, group_base_dn: rest.group_base_dn || null, bind_password_enc: bind_password ? encryptSecret(bind_password) : existing!.bind_password_enc };
  };

  app.put("/v1/settings/ldap", async (req) => {
    const a = requireRole(req, ...WRITE);
    await requireIdentityEdition();
    const data = await ldapData(a.tenantId, req.body);
    // A domain can belong to only one directory across the install.
    const clash = await db.ldap_configs.findFirst({ where: { tenant_id: { not: a.tenantId }, email_domains: { hasSome: data.email_domains } } });
    if (clash) throw new ApiError(409, "conflict", "one of those domains already has a directory on this install");
    await db.ldap_configs.upsert({ where: { tenant_id: a.tenantId }, create: { tenant_id: a.tenantId, ...data }, update: data });
    await audit(a, "ldap_configure", { detail: { url: data.url, base_dn: data.base_dn, domains: data.email_domains, jit: data.jit_provisioning } });
    return { ok: true };
  });

  // Tries the settings as typed (or as saved), without saving them.
  app.post("/v1/settings/ldap/test", async (req) => {
    const a = requireRole(req, ...WRITE);
    const body = (req.body ?? {}) as { email?: string; config?: unknown };
    const email = body.email ? z.email().parse(body.email).toLowerCase() : undefined;
    const saved = await db.ldap_configs.findUnique({ where: { tenant_id: a.tenantId } });
    const cfg = body.config ? await ldapData(a.tenantId, body.config) : saved;
    if (!cfg) throw badRequest("fill in the directory settings first");
    const r = await ldapTest(cfg, email, (await edition()) === "cloud");
    return { ok: true, user: r.user ? { email: r.user.email, name: r.user.name, groups: r.user.groups, dn: r.user.dn } : null };
  });

  app.delete("/v1/settings/ldap", async (req) => {
    const a = requireRole(req, ...WRITE);
    await db.ldap_configs.deleteMany({ where: { tenant_id: a.tenantId } });
    await audit(a, "ldap_remove");
    return { ok: true };
  });
}
