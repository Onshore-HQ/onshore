import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { actor, ApiError, audit, badRequest, db, forbidden, hashPassword, newId, notFound, READ_CONFIG, redactText, requireRole, WRITE } from "../lib.js";
import { ROLES } from "../templates.js";
import { deliverAccountLink, issueAccountToken } from "./accounts.js";

const cidr = z.string().regex(/^[0-9a-fA-F:.]+\/\d{1,3}$/, "use CIDR notation");
const ipOrCidr = z.string().regex(/^[0-9a-fA-F:.]+(\/\d{1,3})?$/, "use an IP or CIDR");

interface PersonStats {
  principal_id: string;
  reveals_7d: bigint;
  reveals_30d: bigint;
  denied_30d: bigint;
}

export async function peopleRoutes(app: FastifyInstance) {
  app.get("/v1/roles", async () => ({ roles: ROLES }));

  app.get("/v1/principals", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.principals.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "asc" }, include: { role_assignments: { include: { roles: true } }, service_account_keys: true } });
    const stats = await db.$queryRaw<PersonStats[]>`
      SELECT principal_id,
        count(*) FILTER (WHERE action='detokenize' AND decision='plaintext' AND occurred_at>now()-interval '7 days') AS reveals_7d,
        count(*) FILTER (WHERE action='detokenize' AND decision='plaintext') AS reveals_30d,
        count(*) FILTER (WHERE action='reveal_denied') AS denied_30d
      FROM events.audit_events WHERE tenant_id=${a.tenantId} AND occurred_at>now()-interval '30 days' AND principal_id IS NOT NULL GROUP BY principal_id`;
    const byId = new Map(stats.map((s) => [s.principal_id, s]));
    const pending = new Set((await db.account_tokens.findMany({ where: { tenant_id: a.tenantId, kind: "invite", used_at: null, revoked_at: null, expires_at: { gt: new Date() } }, select: { principal_id: true } })).map((t) => t.principal_id));
    const flagged = await db.alerts.findMany({ where: { tenant_id: a.tenantId, acknowledged_at: null }, select: { principal_id: true } });
    const flags = new Set(flagged.map((f) => f.principal_id));
    return {
      principals: rows.map((p) => ({
        id: p.id,
        kind: p.kind,
        display_name: p.display_name,
        email: p.email,
        status: p.status,
        source: p.source,
        mfa_enabled: p.mfa_enabled,
        invite_pending: pending.has(p.id),
        approved_network: p.approved_network,
        last_active_at: p.last_active_at,
        created_at: p.created_at,
        roles: p.role_assignments.map((r) => r.roles.name),
        reveals_7d: byId.get(p.id)?.reveals_7d ?? 0,
        reveals_30d: byId.get(p.id)?.reveals_30d ?? 0,
        denied_30d: byId.get(p.id)?.denied_30d ?? 0,
        anomaly: flags.has(p.id),
        keys: p.service_account_keys.map((k) => ({ id: k.id, fingerprint: k.fingerprint, ip_allowlist: k.ip_allowlist, last_used_at: k.last_used_at, expires_at: k.expires_at, revoked_at: k.revoked_at })),
      })),
    };
  });

  app.get<{ Params: { id: string } }>("/v1/principals/:id", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const p = await db.principals.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId }, include: { role_assignments: { include: { roles: true } }, service_account_keys: true } });
    if (!p) throw notFound();
    const roles = p.role_assignments.map((r) => r.roles.name);
    const reveals = await db.audit_events.findMany({ where: { tenant_id: a.tenantId, principal_id: p.id, action: "detokenize" }, orderBy: { seq: "desc" }, take: 50 });
    const denials = await db.audit_events.findMany({ where: { tenant_id: a.tenantId, principal_id: p.id, decision: "denied" }, orderBy: { seq: "desc" }, take: 20 });
    const grants = await db.break_glass_grants.findMany({ where: { principal_id: p.id, tenant_id: a.tenantId }, orderBy: { created_at: "desc" }, take: 20 });
    const alerts = await db.alerts.findMany({ where: { tenant_id: a.tenantId, principal_id: p.id }, orderBy: { raised_at: "desc" }, take: 20 });
    // Computed live from the published policies.
    const active = await db.policies.findMany({ where: { tenant_id: a.tenantId, status: "active" } });
    const applicable = active.flatMap((pol) => {
      const src = pol.source as { rules?: { id?: string; actions: string[]; who?: { roles?: string[]; principals?: string[]; networks?: string[] }; what?: { fields?: string[]; data_types?: string[] }; returns: string }[] };
      return (src.rules ?? [])
        .filter((r) => r.who?.roles?.some((x) => roles.includes(x)) || r.who?.principals?.includes(p.id))
        .map((r) => ({ policy: pol.name, version: pol.version, rule: r.id, actions: r.actions, what: [...(r.what?.fields ?? []), ...(r.what?.data_types ?? [])], networks: r.who?.networks ?? [], returns: r.returns }));
    });
    return {
      principal: { id: p.id, kind: p.kind, display_name: p.display_name, email: p.email, status: p.status, mfa_enabled: p.mfa_enabled, invite_pending: (await db.account_tokens.count({ where: { principal_id: p.id, kind: "invite", used_at: null, revoked_at: null, expires_at: { gt: new Date() } } })) > 0, last_active_at: p.last_active_at, created_at: p.created_at, roles, keys: p.service_account_keys.map((k) => ({ id: k.id, fingerprint: k.fingerprint, ip_allowlist: k.ip_allowlist, last_used_at: k.last_used_at, expires_at: k.expires_at, revoked_at: k.revoked_at })) },
      reveals,
      denials,
      grants,
      alerts,
      applicable,
    };
  });

  app.post("/v1/principals", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .discriminatedUnion("kind", [
        z.object({ kind: z.literal("user"), display_name: z.string().min(2).max(120), email: z.email(), roles: z.array(z.enum(ROLES as [string, ...string[]])).min(1), invite: z.boolean().default(false) }),
        z.object({ kind: z.literal("service_account"), display_name: z.string().min(2).max(120), roles: z.array(z.enum(ROLES as [string, ...string[]])).min(1), public_key: z.string(), ip_allowlist: z.array(ipOrCidr).default([]) }),
      ])
      .parse(req.body);
    const id = newId(b.kind === "user" ? "usr" : "sa");
    // Scripts may still ask for a temporary password. The console always invites.
    const inviting = b.kind === "user" && b.invite;
    const temporary = b.kind === "user" && !inviting ? crypto.randomBytes(15).toString("base64url") : undefined;
    let keyId: string | undefined;
    await db.$transaction(async (tx) => {
      await tx.principals.create({ data: { id, tenant_id: a.tenantId, kind: b.kind, display_name: b.display_name, email: b.kind === "user" ? b.email.toLowerCase() : null, password_hash: temporary ? hashPassword(temporary) : null, must_change_password: Boolean(temporary) } });
      for (const r of b.roles) await tx.role_assignments.create({ data: { role_id: `${a.tenantId}:${r}`, principal_id: id } });
      if (b.kind === "service_account") keyId = (await addKey(tx, id, b.public_key, b.ip_allowlist)).id;
    });
    await audit(a, "principal_create", { detail: { principal: id, kind: b.kind, roles: b.roles } });
    if (inviting) {
      const token = await issueAccountToken(a.tenantId, id, "invite", a.id);
      return { id, invite: await deliverAccountLink(a.tenantId, b.email.toLowerCase(), "invite", token, b.display_name) };
    }
    return { id, key_id: keyId, temporary_password: temporary };
  });

  app.patch<{ Params: { id: string } }>("/v1/principals/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ status: z.enum(["active", "suspended"]).optional(), roles: z.array(z.enum(ROLES as [string, ...string[]])).optional(), approved_network: z.string().nullish() }).parse(req.body);
    const p = await db.principals.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!p) throw notFound();
    if (p.id === a.id && (b.status === "suspended" || (b.roles && !b.roles.includes("admin")))) throw badRequest("you cannot suspend yourself or drop your own admin role");
    await db.$transaction(async (tx) => {
      await tx.principals.update({ where: { id: p.id }, data: { status: b.status, approved_network: b.approved_network } });
      if (b.roles) {
        await tx.role_assignments.deleteMany({ where: { principal_id: p.id } });
        for (const r of b.roles) await tx.role_assignments.create({ data: { role_id: `${a.tenantId}:${r}`, principal_id: p.id } });
      }
    });
    await audit(a, "principal_update", { detail: { principal: p.id, ...b } });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/principals/:id/keys", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ public_key: z.string(), ip_allowlist: z.array(ipOrCidr).default([]) }).parse(req.body);
    const p = await db.principals.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId, kind: "service_account" } });
    if (!p) throw notFound();
    const k = await addKey(db, p.id, b.public_key, b.ip_allowlist);
    await audit(a, "key_create", { detail: { principal: p.id, key: k.id, fingerprint: k.fingerprint } });
    return { id: k.id, fingerprint: k.fingerprint };
  });

  app.post<{ Params: { id: string; kid: string } }>("/v1/principals/:id/keys/:kid/revoke", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await db.principals.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!p) throw notFound();
    const r = await db.service_account_keys.updateMany({ where: { id: req.params.kid, principal_id: p.id, revoked_at: null }, data: { revoked_at: new Date() } });
    if (r.count === 0) throw notFound("unknown or already revoked key");
    await audit(a, "key_revoke", { detail: { principal: p.id, key: req.params.kid } });
    return { ok: true };
  });

  // ---- approved networks: what "in the country" means for a reveal --------------

  app.get("/v1/networks", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    return { networks: await db.approved_networks.findMany({ where: { tenant_id: a.tenantId }, orderBy: { name: "asc" } }) };
  });

  app.post("/v1/networks", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().regex(/^[a-z0-9_-]{1,40}$/), cidrs: z.array(cidr).min(1) }).parse(req.body);
    const id = newId("net");
    await db.approved_networks.create({ data: { id, tenant_id: a.tenantId, ...b } });
    await audit(a, "network_create", { detail: b });
    return { id };
  });

  app.delete<{ Params: { id: string } }>("/v1/networks/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.approved_networks.deleteMany({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (r.count === 0) throw notFound();
    await audit(a, "network_delete", { detail: { id: req.params.id } });
    return { ok: true };
  });

  // ---- break-glass: time-boxed, second approver, flagged in every report ----

  app.get("/v1/break-glass", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    return { grants: await db.break_glass_grants.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "desc" }, take: 100 }) };
  });

  app.post("/v1/break-glass", async (req) => {
    const a = actor(req);
    const b = z.object({ vault_id: z.string(), reason: z.string().min(5).max(500), duration_minutes: z.number().int().min(5).max(240) }).parse(req.body);
    const v = await db.vaults.findFirst({ where: { id: b.vault_id, tenant_id: a.tenantId } });
    if (!v) throw notFound("unknown vault");
    const id = newId("brk");
    await db.break_glass_grants.create({ data: { id, tenant_id: a.tenantId, principal_id: a.id, vault_id: b.vault_id, reason: await redactText(b.reason), requested_by: a.id, duration_minutes: b.duration_minutes } });
    await audit(a, "break_glass_request", { vaultId: b.vault_id, breakGlass: true, detail: { grant: id, minutes: b.duration_minutes } });
    return { id };
  });

  app.post<{ Params: { id: string; decision: string } }>("/v1/break-glass/:id/:decision", async (req) => {
    const a = requireRole(req, ...WRITE, "dpo");
    const decision = z.enum(["approve", "deny", "revoke"]).parse(req.params.decision);
    const g = await db.break_glass_grants.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!g) throw notFound();
    if (decision === "revoke") {
      if (g.status !== "active") throw badRequest("the grant is not active");
      await db.break_glass_grants.update({ where: { id: g.id }, data: { status: "revoked" } });
    } else {
      if (g.status !== "pending") throw badRequest("the grant is not pending");
      if (g.requested_by === a.id) throw forbidden("break-glass needs a second approver");
      await db.break_glass_grants.update({ where: { id: g.id }, data: decision === "approve" ? { status: "active", approved_by: a.id, expires_at: new Date(Date.now() + g.duration_minutes * 60_000) } : { status: "denied", approved_by: a.id } });
    }
    await audit(a, `break_glass_${decision}`, { vaultId: g.vault_id, breakGlass: true, detail: { grant: g.id } });
    return { ok: true };
  });
}

async function addKey(tx: Pick<typeof db, "service_account_keys">, principalId: string, publicKey: string, allow: string[]) {
  const raw = Buffer.from(publicKey, "base64");
  if (raw.length !== 32) throw new ApiError(400, "invalid_request", "public_key must be a base64 Ed25519 public key (use `rv sa-keygen`)");
  const fingerprint = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
  const id = newId("key");
  await tx.service_account_keys.create({ data: { id, principal_id: principalId, public_key: publicKey, fingerprint, ip_allowlist: allow } });
  return { id, fingerprint };
}
