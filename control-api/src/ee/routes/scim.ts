// SCIM 2.0 (RFC 7643/7644): an identity provider such as Entra ID, Okta, OneLogin or
// JumpCloud creates, updates and removes people and groups here. Removing someone
// ends their access at once. Groups become roles through the group-to-role mappings.

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { audit, db, newId } from "../../lib.js";
import { isLastAdmin, provision, publicOrigin, rolesForGroups, setRoles } from "../../identity.js";
import { sha } from "../../routes/identity.js";

const SCIM_JSON = "application/scim+json";
const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

class ScimError extends Error {
  constructor(public status: number, public detail: string, public scimType?: string) { super(detail); }
}
type Ctx = { tenantId: string; tokenId: string; ip: string };
type Body = Record<string, unknown>;

const base = () => `${publicOrigin()}/control/scim/v2`;
const lastSeen = new Map<string, number>();

async function auth(req: FastifyRequest): Promise<Ctx> {
  const h = req.headers.authorization ?? "";
  const tok = h.startsWith("Bearer rvscim_") ? h.slice(7) : "";
  const row = tok ? await db.scim_tokens.findUnique({ where: { token_hash: sha(tok) } }) : null;
  if (!row || row.revoked_at) throw new ScimError(401, "a valid SCIM token is needed");
  // Recorded at most once a minute, so a busy sync doesn't write on every call.
  if ((lastSeen.get(row.id) ?? 0) < Date.now() - 60_000) { lastSeen.set(row.id, Date.now()); await db.scim_tokens.update({ where: { id: row.id }, data: { last_used_at: new Date() } }); }
  return { tenantId: row.tenant_id, tokenId: row.id, ip: req.ip };
}
const who = (c: Ctx) => ({ tenantId: c.tenantId, id: `scim:${c.tokenId}`, ip: c.ip });

function send(reply: FastifyReply, status: number, body: unknown) {
  return reply.status(status).type(SCIM_JSON).send(body);
}

/** `userName eq "x"`, the only filter form identity providers use for matching. */
function parseFilter(f: string | undefined, allowed: string[]): { attr: string; value: string } | null {
  if (!f) return null;
  const m = f.match(/^\s*([\w.]+(?:\[[^\]]*\])?(?:\.\w+)?)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i);
  if (!m) throw new ScimError(400, "only `attribute eq \"value\"` filters are supported", "invalidFilter");
  const attr = m[1]!.replace(/\[type eq "work"\]/i, "");
  if (!allowed.includes(attr.toLowerCase())) throw new ScimError(400, `filtering on ${m[1]} is not supported`, "invalidFilter");
  return { attr: attr.toLowerCase(), value: JSON.parse(`"${m[2]}"`) as string };
}

function page(q: Record<string, string | undefined>) {
  const start = Math.max(1, Number(q.startIndex ?? 1) || 1);
  const count = Math.min(200, Math.max(0, Number(q.count ?? 100) || 0));
  return { start, count };
}

const bool = (v: unknown) => (typeof v === "string" ? v.toLowerCase() === "true" : Boolean(v));

// ---- Users ----------------------------------------------------------------------

type Principal = NonNullable<Awaited<ReturnType<typeof db.principals.findUnique>>>;

async function userJson(p: Principal) {
  const groups = await db.scim_groups.findMany({ where: { members: { some: { principal_id: p.id } } }, select: { id: true, display_name: true } });
  const parts = p.display_name.split(" ");
  return {
    schemas: [USER], id: p.id, ...(p.external_id ? { externalId: p.external_id } : {}),
    userName: p.email, displayName: p.display_name,
    name: { formatted: p.display_name, givenName: parts[0], familyName: parts.slice(1).join(" ") || undefined },
    emails: p.email ? [{ value: p.email, type: "work", primary: true }] : [],
    active: p.status === "active",
    groups: groups.map((g) => ({ value: g.id, display: g.display_name, $ref: `${base()}/Groups/${g.id}` })),
    meta: { resourceType: "User", created: p.created_at.toISOString(), lastModified: (p.last_active_at ?? p.created_at).toISOString(), location: `${base()}/Users/${p.id}` },
  };
}

/** The fields an identity provider may set, from a full or partial user. */
function userFields(b: Body) {
  const emails = Array.isArray(b.emails) ? (b.emails as Body[]) : [];
  const primary = (emails.find((e) => e.primary === true || e.primary === "true") ?? emails[0])?.value;
  const userName = typeof b.userName === "string" ? b.userName : undefined;
  const email = (userName?.includes("@") ? userName : typeof primary === "string" ? primary : undefined)?.toLowerCase();
  const name = b.name as Body | undefined;
  const display = typeof b.displayName === "string" ? b.displayName : name ? (typeof name.formatted === "string" ? name.formatted : [name.givenName, name.familyName].filter((x) => typeof x === "string").join(" ")) : undefined;
  return { email, display: display || undefined, externalId: typeof b.externalId === "string" ? b.externalId : undefined, active: b.active === undefined ? undefined : bool(b.active) };
}

async function findUser(c: Ctx, id: string) {
  const p = await db.principals.findFirst({ where: { id, tenant_id: c.tenantId, kind: "user", status: { not: "deprovisioned" } } });
  if (!p) throw new ScimError(404, "no such user");
  return p;
}

/** Applies a change of name, email, external id or active state. */
async function updateUser(c: Ctx, p: Principal, f: ReturnType<typeof userFields>) {
  const data: Record<string, unknown> = {};
  if (f.display && f.display !== p.display_name) data.display_name = f.display.slice(0, 120);
  if (f.externalId !== undefined && f.externalId !== p.external_id) data.external_id = f.externalId;
  if (f.email && f.email !== p.email) {
    const other = await db.principals.findUnique({ where: { email: f.email } });
    if (other && other.id !== p.id) throw new ScimError(409, "another account has that email", "uniqueness");
    data.email = f.email;
  }
  if (f.active !== undefined && f.active !== (p.status === "active")) {
    if (!f.active && (await isLastAdmin(c.tenantId, p.id))) throw new ScimError(400, "this is the organisation's last admin; give someone else the admin role first", "mutability");
    data.status = f.active ? "active" : "suspended";
    if (!f.active) data.sessions_valid_after = new Date();
  }
  if (Object.keys(data).length) {
    await db.principals.update({ where: { id: p.id }, data });
    await audit(who(c), f.active === false ? "scim_user_deactivate" : f.active === true && data.status ? "scim_user_activate" : "scim_user_update", { detail: { principal: p.id, fields: Object.keys(data).filter((k) => k !== "sessions_valid_after") } });
  }
  return db.principals.findUniqueOrThrow({ where: { id: p.id } });
}

/** A PATCH body's operations, applied to a plain object the way SCIM describes. */
function patchToUser(ops: Body[]): Body {
  const out: Body = {};
  for (const op of ops) {
    const kind = String(op.op ?? "").toLowerCase();
    if (!["add", "replace", "remove"].includes(kind)) throw new ScimError(400, `unknown operation ${String(op.op)}`, "invalidSyntax");
    const path = typeof op.path === "string" ? op.path : undefined;
    const value = kind === "remove" ? undefined : op.value;
    const put = (k: string, v: unknown) => {
      const key = k.replace(/^urn:ietf:params:scim:schemas:core:2\.0:User:/, "");
      if (/^emails(\[.*\])?(\.value)?$/i.test(key)) { out.emails = [{ value: Array.isArray(v) ? (v[0] as Body)?.value : v, primary: true }]; return; }
      if (/^name\.\w+$/i.test(key)) { out.name = { ...(out.name as Body | undefined), [key.split(".")[1]!]: v }; return; }
      out[key] = v;
    };
    if (path) put(path, value);
    else if (value && typeof value === "object") for (const [k, v] of Object.entries(value as Body)) put(k, v);
  }
  return out;
}

// ---- Groups ---------------------------------------------------------------------

async function groupJson(id: string, withMembers = true) {
  const g = await db.scim_groups.findUniqueOrThrow({ where: { id }, include: { members: true } });
  const people = withMembers ? await db.principals.findMany({ where: { id: { in: g.members.map((m) => m.principal_id) } }, select: { id: true, display_name: true } }) : [];
  return {
    schemas: [GROUP], id: g.id, displayName: g.display_name, ...(g.external_id ? { externalId: g.external_id } : {}),
    ...(withMembers ? { members: people.map((p) => ({ value: p.id, display: p.display_name, $ref: `${base()}/Users/${p.id}` })) } : {}),
    meta: { resourceType: "Group", created: g.created_at.toISOString(), lastModified: g.updated_at.toISOString(), location: `${base()}/Groups/${g.id}` },
  };
}

/** Sets each person's roles from the SCIM groups they're in, when groups map to roles. */
async function syncRoles(c: Ctx, principalIds: string[]) {
  for (const id of new Set(principalIds)) {
    const groups = await db.scim_groups.findMany({ where: { tenant_id: c.tenantId, members: { some: { principal_id: id } } }, select: { display_name: true, external_id: true } });
    const names = groups.flatMap((g) => [g.display_name, ...(g.external_id ? [g.external_id] : [])]);
    const roles = await rolesForGroups(c.tenantId, names);
    if (roles === null) return;
    const r = await setRoles(c.tenantId, id, roles);
    await audit(who(c), "scim_roles_sync", { detail: { principal: id, roles: r.roles, kept_admin: r.keptAdmin } });
  }
}

async function memberIds(c: Ctx, v: unknown): Promise<string[]> {
  const ids = (Array.isArray(v) ? v : v ? [v] : []).map((m) => (typeof m === "string" ? m : String((m as Body).value ?? ""))).filter(Boolean);
  if (!ids.length) return [];
  const found = await db.principals.findMany({ where: { id: { in: ids }, tenant_id: c.tenantId, kind: "user" }, select: { id: true } });
  if (found.length !== new Set(ids).size) throw new ScimError(400, "a member is not a user here", "invalidValue");
  return found.map((f) => f.id);
}

async function findGroup(c: Ctx, id: string) {
  const g = await db.scim_groups.findFirst({ where: { id, tenant_id: c.tenantId } });
  if (!g) throw new ScimError(404, "no such group");
  return g;
}

// ---- Routes ---------------------------------------------------------------------

export async function scimRoutes(app: FastifyInstance) {
  app.addContentTypeParser(SCIM_JSON, { parseAs: "string" }, (_req, body, done) => {
    try { done(null, body ? JSON.parse(body as string) : {}); } catch { done(new ScimError(400, "the body is not valid JSON", "invalidSyntax")); }
  });

  // Errors in SCIM's own shape, which identity providers show to their admins.
  type Req = FastifyRequest<{ Params: Record<string, string>; Querystring: Record<string, string | undefined> }>;
  const route = (fn: (req: Req, reply: FastifyReply, c: Ctx) => Promise<unknown>) =>
    async (raw: FastifyRequest, reply: FastifyReply) => {
      const req = raw as Req;
      try {
        const c = await auth(req);
        return await fn(req, reply, c);
      } catch (e) {
        const err = e instanceof ScimError ? e : new ScimError(500, "internal error");
        if (!(e instanceof ScimError)) req.log.error({ kind: (e as Error)?.name }, "scim error");
        return send(reply, err.status, { schemas: [ERROR], status: String(err.status), detail: err.detail, ...(err.scimType ? { scimType: err.scimType } : {}) });
      }
    };

  app.get("/scim/v2/ServiceProviderConfig", route(async (_q, reply) => send(reply, 200, {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 }, filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false }, sort: { supported: false }, etag: { supported: false },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "A token made in Onshore's Sign-in settings", primary: true }],
  })));
  app.get("/scim/v2/ResourceTypes", route(async (_q, reply) => send(reply, 200, { schemas: [LIST], totalResults: 2, Resources: [
    { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: USER },
    { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: GROUP },
  ] })));
  app.get("/scim/v2/Schemas", route(async (_q, reply) => send(reply, 200, { schemas: [LIST], totalResults: 2, Resources: [{ id: USER, name: "User" }, { id: GROUP, name: "Group" }] })));

  app.get("/scim/v2/Users", route(async (req, reply, c) => {
    const f = parseFilter(req.query.filter, ["username", "externalid", "emails.value", "emails"]);
    const where = { tenant_id: c.tenantId, kind: "user", status: { not: "deprovisioned" }, ...(f ? (f.attr === "externalid" ? { external_id: f.value } : { email: f.value.toLowerCase() }) : {}) };
    const { start, count } = page(req.query);
    const [total, rows] = await Promise.all([db.principals.count({ where }), db.principals.findMany({ where, orderBy: { created_at: "asc" }, skip: start - 1, take: count })]);
    return send(reply, 200, { schemas: [LIST], totalResults: total, startIndex: start, itemsPerPage: rows.length, Resources: await Promise.all(rows.map(userJson)) });
  }));

  app.get("/scim/v2/Users/:id", route(async (req, reply, c) => send(reply, 200, await userJson(await findUser(c, req.params.id!)))));

  app.post("/scim/v2/Users", route(async (req, reply, c) => {
    const f = userFields((req.body ?? {}) as Body);
    if (!f.email) throw new ScimError(400, "userName or a primary email must be an email address", "invalidValue");
    const existing = await db.principals.findUnique({ where: { email: f.email } });
    if (existing) {
      if (existing.tenant_id !== c.tenantId || existing.kind !== "user") throw new ScimError(409, "that email is in use", "uniqueness");
      // Someone removed earlier and pushed again comes back as the same account.
      if (existing.status === "deprovisioned") {
        await db.principals.update({ where: { id: existing.id }, data: { status: f.active === false ? "suspended" : "active", external_id: f.externalId ?? existing.external_id, display_name: (f.display ?? existing.display_name).slice(0, 120) } });
        await audit(who(c), "scim_user_create", { detail: { principal: existing.id, restored: true } });
        return send(reply, 201, await userJson(await db.principals.findUniqueOrThrow({ where: { id: existing.id } })));
      }
      throw new ScimError(409, "a user with that userName already exists", "uniqueness");
    }
    const id = await provision(c.tenantId, { email: f.email, displayName: f.display ?? f.email, source: "scim", externalId: f.externalId, roles: [] });
    if (f.active === false) await db.principals.update({ where: { id }, data: { status: "suspended" } });
    await audit(who(c), "scim_user_create", { detail: { principal: id } });
    return send(reply, 201, await userJson(await db.principals.findUniqueOrThrow({ where: { id } })));
  }));

  app.put("/scim/v2/Users/:id", route(async (req, reply, c) => {
    const p = await findUser(c, req.params.id!);
    return send(reply, 200, await userJson(await updateUser(c, p, userFields((req.body ?? {}) as Body))));
  }));

  app.patch("/scim/v2/Users/:id", route(async (req, reply, c) => {
    const p = await findUser(c, req.params.id!);
    const b = (req.body ?? {}) as Body;
    if (!Array.isArray(b.Operations)) throw new ScimError(400, `a PATCH needs Operations (${PATCH_OP})`, "invalidSyntax");
    return send(reply, 200, await userJson(await updateUser(c, p, userFields(patchToUser(b.Operations as Body[])))));
  }));

  // Removal keeps the account for the audit trail, but it never signs in again.
  app.delete("/scim/v2/Users/:id", route(async (req, reply, c) => {
    const p = await findUser(c, req.params.id!);
    if (await isLastAdmin(c.tenantId, p.id)) throw new ScimError(400, "this is the organisation's last admin; give someone else the admin role first", "mutability");
    await db.$transaction([
      db.principals.update({ where: { id: p.id }, data: { status: "deprovisioned", sessions_valid_after: new Date() } }),
      db.scim_group_members.deleteMany({ where: { principal_id: p.id } }),
      db.role_assignments.deleteMany({ where: { principal_id: p.id } }),
      db.webauthn_credentials.deleteMany({ where: { principal_id: p.id } }),
    ]);
    await audit(who(c), "scim_user_delete", { detail: { principal: p.id } });
    return reply.status(204).send();
  }));

  app.get("/scim/v2/Groups", route(async (req, reply, c) => {
    const f = parseFilter(req.query.filter, ["displayname", "externalid"]);
    const where = { tenant_id: c.tenantId, ...(f ? (f.attr === "externalid" ? { external_id: f.value } : { display_name: { equals: f.value, mode: "insensitive" as const } }) : {}) };
    const { start, count } = page(req.query);
    const withMembers = !/members/i.test(req.query.excludedAttributes ?? "");
    const [total, rows] = await Promise.all([db.scim_groups.count({ where }), db.scim_groups.findMany({ where, orderBy: { created_at: "asc" }, skip: start - 1, take: count, select: { id: true } })]);
    return send(reply, 200, { schemas: [LIST], totalResults: total, startIndex: start, itemsPerPage: rows.length, Resources: await Promise.all(rows.map((r) => groupJson(r.id, withMembers))) });
  }));

  app.get("/scim/v2/Groups/:id", route(async (req, reply, c) => {
    const g = await findGroup(c, req.params.id!);
    return send(reply, 200, await groupJson(g.id, !/members/i.test(req.query.excludedAttributes ?? "")));
  }));

  app.post("/scim/v2/Groups", route(async (req, reply, c) => {
    const b = (req.body ?? {}) as Body;
    const name = typeof b.displayName === "string" ? b.displayName.trim().slice(0, 256) : "";
    if (!name) throw new ScimError(400, "displayName is required", "invalidValue");
    if (await db.scim_groups.findFirst({ where: { tenant_id: c.tenantId, display_name: { equals: name, mode: "insensitive" } } })) throw new ScimError(409, "a group with that displayName already exists", "uniqueness");
    const members = await memberIds(c, b.members);
    const id = newId("grp");
    await db.scim_groups.create({ data: { id, tenant_id: c.tenantId, display_name: name, external_id: typeof b.externalId === "string" ? b.externalId : null, members: { create: members.map((m) => ({ principal_id: m })) } } });
    await audit(who(c), "scim_group_create", { detail: { group: id, name, members: members.length } });
    await syncRoles(c, members);
    return send(reply, 201, await groupJson(id));
  }));

  const replaceGroup = async (c: Ctx, id: string, name: string | undefined, externalId: string | undefined, members: string[] | undefined) => {
    const before = (await db.scim_group_members.findMany({ where: { group_id: id } })).map((m) => m.principal_id);
    await db.$transaction(async (tx) => {
      await tx.scim_groups.update({ where: { id }, data: { ...(name ? { display_name: name.slice(0, 256) } : {}), ...(externalId !== undefined ? { external_id: externalId } : {}), updated_at: new Date() } });
      if (members) {
        await tx.scim_group_members.deleteMany({ where: { group_id: id } });
        for (const m of members) await tx.scim_group_members.create({ data: { group_id: id, principal_id: m } });
      }
    });
    await syncRoles(c, [...before, ...(members ?? before)]);
  };

  app.put("/scim/v2/Groups/:id", route(async (req, reply, c) => {
    const g = await findGroup(c, req.params.id!);
    const b = (req.body ?? {}) as Body;
    await replaceGroup(c, g.id, typeof b.displayName === "string" ? b.displayName : undefined, typeof b.externalId === "string" ? b.externalId : undefined, await memberIds(c, b.members));
    await audit(who(c), "scim_group_update", { detail: { group: g.id } });
    return send(reply, 200, await groupJson(g.id));
  }));

  app.patch("/scim/v2/Groups/:id", route(async (req, reply, c) => {
    const g = await findGroup(c, req.params.id!);
    const b = (req.body ?? {}) as Body;
    if (!Array.isArray(b.Operations)) throw new ScimError(400, `a PATCH needs Operations (${PATCH_OP})`, "invalidSyntax");
    const current = new Set((await db.scim_group_members.findMany({ where: { group_id: g.id } })).map((m) => m.principal_id));
    const touched = new Set<string>();
    let name: string | undefined, externalId: string | undefined;
    for (const op of b.Operations as Body[]) {
      const kind = String(op.op ?? "").toLowerCase();
      const path = typeof op.path === "string" ? op.path : "";
      if (/^members/i.test(path) || (!path && op.value && typeof op.value === "object" && "members" in (op.value as Body))) {
        const v = path ? op.value : (op.value as Body).members;
        const filtered = path.match(/^members\[value eq "([^"]+)"\]$/i)?.[1];
        const ids = filtered ? [filtered] : kind === "remove" && !v ? [...current] : await memberIds(c, v);
        if (kind === "add") for (const i of ids) { current.add(i); touched.add(i); }
        else if (kind === "remove") for (const i of ids) { current.delete(i); touched.add(i); }
        else if (kind === "replace") { for (const i of current) touched.add(i); current.clear(); for (const i of ids) { current.add(i); touched.add(i); } }
        else throw new ScimError(400, `unknown operation ${String(op.op)}`, "invalidSyntax");
      } else if (/^displayName$/i.test(path) || (!path && op.value && typeof op.value === "object")) {
        const v = path ? op.value : (op.value as Body).displayName;
        if (typeof v === "string") name = v;
        const ext = !path ? (op.value as Body).externalId : undefined;
        if (typeof ext === "string") externalId = ext;
      } else if (/^externalId$/i.test(path)) {
        if (typeof op.value === "string") externalId = op.value;
      }
    }
    await replaceGroup(c, g.id, name, externalId, [...current]);
    await audit(who(c), "scim_group_update", { detail: { group: g.id, changed_members: touched.size } });
    // Entra and Okta accept 204 here; returning the group helps others.
    return send(reply, 200, await groupJson(g.id));
  }));

  app.delete("/scim/v2/Groups/:id", route(async (req, reply, c) => {
    const g = await findGroup(c, req.params.id!);
    const members = (await db.scim_group_members.findMany({ where: { group_id: g.id } })).map((m) => m.principal_id);
    await db.scim_groups.delete({ where: { id: g.id } });
    await syncRoles(c, members);
    await audit(who(c), "scim_group_delete", { detail: { group: g.id, name: g.display_name } });
    return reply.status(204).send();
  }));
}
